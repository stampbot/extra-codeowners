"""Durable evaluation queue and delivery de-duplication storage."""

from __future__ import annotations

import hashlib
import os
import re
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    case,
    create_engine,
    delete,
    exists,
    func,
    inspect,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import NullPool

SCHEMA_VERSION = 2
DATABASE_MIGRATION_HEAD = "0003_shared_head_epochs"
DATABASE_CONNECT_TIMEOUT_SECONDS = 3
DATABASE_POOL_TIMEOUT_SECONDS = 2
DATABASE_STATEMENT_TIMEOUT_MILLISECONDS = 3_000
MAX_BASE_SCOPED_AUTHORITY_JOBS_PER_REPOSITORY = 100


def isolated_postgresql_connect_args(database_url: str) -> dict[str, object]:
    """Pin every libpq route selector that could otherwise fall back to the environment."""

    if "PGSERVICE" in os.environ:
        raise ValueError("ambient PGSERVICE is not allowed")
    parsed = make_url(database_url)
    allowed_query_parameters = {"host", "hostaddr", "sslmode", "sslrootcert"}
    if set(parsed.query) - allowed_query_parameters:
        raise ValueError("PostgreSQL URL contains unsupported connection parameters")
    query_host = parsed.query.get("host")
    hostaddr = parsed.query.get("hostaddr")
    sslmode = parsed.query.get("sslmode")
    sslrootcert = parsed.query.get("sslrootcert")
    if (
        parsed.drivername != "postgresql+psycopg"
        or (query_host is not None and not isinstance(query_host, str))
        or (hostaddr is not None and not isinstance(hostaddr, str))
        or (sslmode is not None and not isinstance(sslmode, str))
        or (sslrootcert is not None and not isinstance(sslrootcert, str))
        or (query_host is not None and parsed.host is not None)
        or (isinstance(sslrootcert, str) and (not sslrootcert or not sslrootcert.startswith("/")))
    ):
        raise ValueError("PostgreSQL URL has an ambiguous or unsupported route")
    host = query_host if isinstance(query_host, str) else parsed.host
    if (
        not host
        or "," in host
        or (hostaddr is not None and (not hostaddr or "," in hostaddr))
        or not parsed.database
        or not parsed.username
        or not parsed.password
    ):
        raise ValueError("PostgreSQL URL must pin one route, database, username, and password")
    local = host in {"localhost", "127.0.0.1", "::1"} or host.startswith("/")
    arguments: dict[str, object] = {
        "dbname": parsed.database,
        "host": host,
        # An explicit empty value suppresses PGHOSTADDR fallback. Ambient
        # PGSERVICE is rejected above because libpq has no safe empty override.
        "hostaddr": hostaddr or "",
        "password": parsed.password,
        "port": parsed.port or 5432,
        "sslmode": sslmode or ("disable" if local and not hostaddr else "verify-full"),
        "user": parsed.username,
    }
    if sslrootcert is not None:
        arguments["sslrootcert"] = sslrootcert
    return arguments


def normalize_repository_full_name(value: str) -> str:
    """Return the case-insensitive canonical key for ``owner/repository``."""
    if (
        not value
        or value != value.strip()
        or len(value) > 512
        or value.count("/") != 1
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("repository_full_name must be a valid owner/repository name")
    return value.lower()


def validate_head_sha(value: str) -> str:
    """Return a canonical Git object ID suitable for a durable key."""
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("head_sha must be exactly 40 or 64 lowercase ASCII hexadecimal characters")
    return value


def utcnow() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


class SchemaMetadata(Base):
    """Explicit compatibility marker for the durable database schema."""

    __tablename__ = "schema_metadata"

    singleton_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=False,
        default=1,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class EvaluationJob(Base):
    """Latest requested evaluation for one pull request."""

    __tablename__ = "evaluation_jobs"
    __table_args__ = (
        UniqueConstraint(
            "installation_id",
            "repository_full_name",
            "pull_number",
            name="uq_evaluation_job_pr",
        ),
        Index("ix_evaluation_jobs_claim", "state", "available_at", "lease_until"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    installation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    repository_full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    pull_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha_hint: Mapped[str | None] = mapped_column(String(64))
    last_delivery_id: Mapped[str | None] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    authority_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    shared_head_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(2000))


class WebhookDelivery(Base):
    """A GitHub delivery ID retained for replay-safe ingestion."""

    __tablename__ = "webhook_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event: Mapped[str] = mapped_column(String(128), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    invalidation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    invalidation_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    installation_id: Mapped[int | None] = mapped_column(Integer)
    repository_full_name: Mapped[str | None] = mapped_column(String(512))
    pull_number: Mapped[int | None] = mapped_column(Integer)
    head_sha: Mapped[str | None] = mapped_column(String(64))
    shared_head_generation: Mapped[int | None] = mapped_column(Integer)


class EvaluationAudit(Base):
    """Most recent evaluation evidence for operations and debugging."""

    __tablename__ = "evaluation_audits"
    __table_args__ = (
        UniqueConstraint("repository_full_name", "pull_number", name="uq_evaluation_audit_pr"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repository_full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    pull_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    conclusion: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ServiceLease(Base):
    """A database-coordinated singleton lease such as the reconciler."""

    __tablename__ = "service_leases"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner: Mapped[str] = mapped_column(String(128), nullable=False)
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuthorityJob(Base):
    """Coalesced repository or installation authority-change fan-out."""

    __tablename__ = "authority_jobs"
    __table_args__ = (
        UniqueConstraint(
            "installation_id",
            "scope_key",
            "base_ref",
            name="uq_authority_job_scope",
        ),
        Index("ix_authority_jobs_claim", "state", "available_at", "lease_until"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    installation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    scope_key: Mapped[str] = mapped_column(String(512), nullable=False)
    base_ref: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(2000))


class AuthorityEpoch(Base):
    """Monotonic installation fence for broad authority/identity changes."""

    __tablename__ = "authority_epochs"

    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class SharedHeadEpoch(Base):
    """Monotonic fence shared by every pull request on one head commit."""

    __tablename__ = "shared_head_epochs"
    __table_args__ = (
        CheckConstraint(
            "generation >= 1",
            name="ck_shared_head_epochs_generation_positive",
        ),
        CheckConstraint(
            "invalidated_generation >= 0 AND invalidated_generation <= generation",
            name="ck_shared_head_epochs_invalidation_bounds",
        ),
        CheckConstraint(
            "attempts >= 0",
            name="ck_shared_head_epochs_attempts_nonnegative",
        ),
        Index("ix_shared_head_epochs_changed_at", "changed_at"),
        Index(
            "ix_shared_head_epochs_claim",
            "available_at",
            "lease_until",
            postgresql_where=text("invalidated_generation < generation"),
            sqlite_where=text("invalidated_generation < generation"),
        ),
    )

    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_full_name: Mapped[str] = mapped_column(String(512), primary_key=True)
    head_sha: Mapped[str] = mapped_column(String(64), primary_key=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    invalidated_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(2000))


@dataclass(frozen=True, slots=True)
class JobRequest:
    """Input used to enqueue or coalesce an evaluation."""

    installation_id: int
    repository_full_name: str
    pull_number: int
    reason: str
    head_sha_hint: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "repository_full_name",
            normalize_repository_full_name(self.repository_full_name),
        )


@dataclass(frozen=True, slots=True)
class AuthorityRequest:
    """An authority change that must re-evaluate a repository or installation."""

    installation_id: int
    repository_full_name: str | None
    base_ref: str | None
    reason: str

    def __post_init__(self) -> None:
        if self.repository_full_name is not None:
            object.__setattr__(
                self,
                "repository_full_name",
                normalize_repository_full_name(self.repository_full_name),
            )

    @property
    def scope_key(self) -> str:
        """Return a non-null key suitable for database uniqueness."""
        return self.repository_full_name or "*"


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    """Leased immutable view of an evaluation job."""

    id: int
    installation_id: int
    repository_full_name: str
    pull_number: int
    reason: str
    head_sha_hint: str | None
    last_delivery_id: str | None
    generation: int
    authority_generation: int
    shared_head_generation: int
    attempts: int
    lease_owner: str


@dataclass(frozen=True, slots=True)
class ClaimedAuthorityJob:
    """Leased immutable authority fan-out job."""

    id: int
    installation_id: int
    repository_full_name: str | None
    base_ref: str | None
    reason: str
    generation: int
    attempts: int
    lease_owner: str


@dataclass(frozen=True, slots=True)
class ClaimedSharedHeadInvalidation:
    """Leased immutable work item for one exact commit-scoped check."""

    installation_id: int
    repository_full_name: str
    head_sha: str
    generation: int
    attempts: int
    lease_owner: str


@dataclass(frozen=True, slots=True)
class DeliveryAcceptance:
    """Durable acceptance result and exact shared-head generation token."""

    accepted: bool
    shared_head_generation: int | None = None

    def __bool__(self) -> bool:
        """Preserve boolean acceptance checks at internal call sites."""
        return self.accepted


@dataclass(frozen=True, slots=True)
class CheckWriteGuard:
    """Held per-pull-request GitHub check writer guard."""

    key: int
    connection: Connection | None = None
    local_lock: threading.Lock | None = None
    shared: bool = False


class _EvaluationJobAlreadyPresentError(Exception):
    """Abort reconciliation so a tentative shared-head epoch bump rolls back."""


class _EvaluationJobBindingLostError(Exception):
    """Abort a hintless bind so its tentative exact-head bump rolls back."""


_SCHEMA_EXPRESSION_TOKEN = re.compile(
    r'\s*(>=|<=|=|<|>|\(|\)|"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_]*|[0-9]+)'
)


def _normalize_schema_expression(value: object) -> tuple[object, ...] | None:
    """Parse the deliberately small SQL predicate grammar used by this schema."""

    if value is None:
        return None
    source = str(value).strip()
    tokens: list[str] = []
    position = 0
    while position < len(source):
        match = _SCHEMA_EXPRESSION_TOKEN.match(source, position)
        if match is None:
            raise RuntimeError("database schema contains an unsupported SQL expression")
        tokens.append(match.group(1))
        position = match.end()
    cursor = 0

    def operand() -> str:
        nonlocal cursor
        if cursor >= len(tokens):
            raise RuntimeError("database schema contains an incomplete SQL expression")
        token = tokens[cursor]
        if token.startswith('"') and token.endswith('"'):
            token = token[1:-1].replace('""', '"')
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+", token) is None:
            raise RuntimeError("database schema contains an unsupported SQL operand")
        cursor += 1
        return token.lower()

    def comparison() -> tuple[object, ...]:
        nonlocal cursor
        left = operand()
        if cursor >= len(tokens) or tokens[cursor] not in {">=", "<=", "=", "<", ">"}:
            raise RuntimeError("database schema contains an unsupported SQL comparison")
        operator = tokens[cursor]
        cursor += 1
        return ("comparison", left, operator, operand())

    def term() -> tuple[object, ...]:
        nonlocal cursor
        if cursor < len(tokens) and tokens[cursor] == "(":
            cursor += 1
            result = expression()
            if cursor >= len(tokens) or tokens[cursor] != ")":
                raise RuntimeError("database schema contains unbalanced SQL parentheses")
            cursor += 1
            return result
        return comparison()

    def expression() -> tuple[object, ...]:
        nonlocal cursor
        terms = [term()]
        while cursor < len(tokens) and tokens[cursor].lower() == "and":
            cursor += 1
            terms.append(term())
        return terms[0] if len(terms) == 1 else ("and", *terms)

    contract = expression()
    if cursor != len(tokens):
        raise RuntimeError("database schema contains an unsupported SQL expression")
    return contract


def _empty_index_option(value: object) -> bool:
    return value is None or value is False or value == [] or value == () or value == {}


def _expected_index_contract(
    table_name: str,
    index: Index,
    dialect_name: str,
) -> tuple[tuple[str, ...], bool, tuple[object, ...] | None]:
    raw_columns = tuple(column.name for column in index.columns)
    if (
        not index.name
        or not raw_columns
        or any(not isinstance(column, str) or not column for column in raw_columns)
    ):
        raise RuntimeError(f"application index contract is invalid for table {table_name!r}")
    columns = tuple(str(column) for column in raw_columns)
    predicate = index.dialect_options[dialect_name].get("where")
    return columns, bool(index.unique), _normalize_schema_expression(predicate)


def _inspected_index_contract(
    table_name: str,
    index: Mapping[str, object],
    dialect_name: str,
) -> tuple[
    str,
    tuple[tuple[str, ...], bool, tuple[object, ...] | None],
]:
    name = index.get("name")
    columns = index.get("column_names")
    unique = index.get("unique")
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(columns, list)
        or not columns
        or any(not isinstance(column, str) or not column for column in columns)
        or not isinstance(unique, (bool, int))
        or int(unique) not in (0, 1)
        or not _empty_index_option(index.get("include_columns"))
        or bool(index.get("column_sorting"))
        or bool(index.get("expressions"))
    ):
        raise RuntimeError(
            f"database table {table_name!r} contains an unsupported index definition"
        )
    dialect_options = index.get("dialect_options")
    if dialect_options is None:
        options: Mapping[str, object] = {}
    elif isinstance(dialect_options, Mapping):
        options = dialect_options
    else:
        raise RuntimeError(
            f"database table {table_name!r} contains an unsupported index definition"
        )
    where_key = f"{dialect_name}_where"
    for option_name, option_value in options.items():
        if option_name == where_key or _empty_index_option(option_value):
            continue
        raise RuntimeError(
            f"database index {name!r} on table {table_name!r} has unsupported options"
        )
    predicate = _normalize_schema_expression(options.get(where_key))
    return name, (tuple(columns), bool(unique), predicate)


@contextmanager
def _schema_connection(bind: Engine | Connection) -> Iterator[Connection]:
    if isinstance(bind, Connection):
        yield bind
    else:
        with bind.connect() as connection:
            yield connection


def validate_database_schema(bind: Engine | Connection) -> None:
    """Validate the required release schema contract using a supplied bind."""

    inspector = inspect(bind)
    dialect_name = bind.dialect.name
    tables = set(inspector.get_table_names())
    if "alembic_version" not in tables:
        raise RuntimeError(
            "database has not been migrated; run `extra-codeowners database migrate`"
        )
    with _schema_connection(bind) as connection:
        revisions = connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
        current_revisions = tuple(revisions)
    if current_revisions != (DATABASE_MIGRATION_HEAD,):
        raise RuntimeError(
            f"database migration revision {current_revisions!r} is incompatible with "
            f"required revision {DATABASE_MIGRATION_HEAD!r}; run "
            "`extra-codeowners database migrate`"
        )
    actual_serials: dict[tuple[str, str], str | None] = {}
    actual_sequence_states: dict[
        tuple[str, str],
        tuple[str, int, int, int, int, int, bool] | None,
    ] = {}
    if dialect_name == "postgresql":
        with _schema_connection(bind) as connection:
            for table in Base.metadata.sorted_tables:
                generated_column = table.autoincrement_column
                if generated_column is not None:
                    key = (table.name, generated_column.name)
                    serial_name = connection.scalar(
                        text("SELECT pg_get_serial_sequence(:table_name, :column_name)"),
                        {
                            "table_name": table.name,
                            "column_name": generated_column.name,
                        },
                    )
                    actual_serials[key] = serial_name
                    sequence_row = None
                    if serial_name is not None:
                        sequence_row = connection.execute(
                            text(
                                """
                                SELECT
                                    seqtypid::regtype::text,
                                    seqstart,
                                    seqincrement,
                                    seqmax,
                                    seqmin,
                                    seqcache,
                                    seqcycle
                                FROM pg_sequence
                                WHERE seqrelid = CAST(:sequence_name AS regclass)
                                """
                            ),
                            {"sequence_name": serial_name},
                        ).one_or_none()
                    actual_sequence_states[key] = (
                        None
                        if sequence_row is None
                        else (
                            str(sequence_row[0]),
                            int(sequence_row[1]),
                            int(sequence_row[2]),
                            int(sequence_row[3]),
                            int(sequence_row[4]),
                            int(sequence_row[5]),
                            bool(sequence_row[6]),
                        )
                    )
    for table in Base.metadata.sorted_tables:
        if table.name not in tables:
            raise RuntimeError(f"database schema is missing table {table.name!r}")
        inspected_columns = inspector.get_columns(table.name)
        actual_columns = {column["name"] for column in inspected_columns}
        expected_columns = {column.name for column in table.columns}
        missing = expected_columns - actual_columns
        unexpected = actual_columns - expected_columns
        if missing or unexpected:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible columns; "
                f"missing {sorted(missing)!r}, unexpected {sorted(unexpected)!r}"
            )
        actual_by_name = {column["name"]: column for column in inspected_columns}
        for expected_column in table.columns:
            actual_column = actual_by_name[expected_column.name]
            actual_type = actual_column["type"]
            expected_affinity = expected_column.type._type_affinity
            if expected_affinity is None or not isinstance(actual_type, expected_affinity):
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    f"type {actual_type!s}; expected {expected_column.type!s}"
                )
            expected_length = getattr(expected_column.type, "length", None)
            actual_length = getattr(actual_type, "length", None)
            if expected_length != actual_length:
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    f"length {actual_length!r}; expected {expected_length!r}"
                )
            if bool(actual_column["nullable"]) != bool(expected_column.nullable):
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    f"nullable={actual_column['nullable']!r}; expected "
                    f"nullable={expected_column.nullable!r}"
                )
            expected_timezone = getattr(expected_column.type, "timezone", None)
            actual_timezone = getattr(actual_type, "timezone", None)
            if (
                dialect_name == "postgresql"
                and expected_timezone is not None
                and actual_timezone != expected_timezone
            ):
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    f"timezone={actual_timezone!r}; expected timezone={expected_timezone!r}"
                )
            actual_default = actual_column.get("default")
            actual_identity = actual_column.get("identity")
            actual_computed = actual_column.get("computed")
            actual_autoincrement = bool(actual_column.get("autoincrement"))
            expected_generated = expected_column is table.autoincrement_column
            generation_matches = (
                actual_default is None
                and actual_identity is None
                and actual_computed is None
                and not actual_autoincrement
            )
            if dialect_name == "postgresql" and expected_generated:
                sequence_name = f"{table.name}_{expected_column.name}_seq"
                default_schema = inspector.default_schema_name
                expected_serial = (
                    f"{default_schema}.{sequence_name}" if default_schema else sequence_name
                )
                allowed_defaults = {
                    f"nextval('{sequence_name}'::regclass)",
                    f"nextval('{expected_serial}'::regclass)",
                }
                generation_matches = (
                    actual_serials[(table.name, expected_column.name)] == expected_serial
                    and actual_sequence_states[(table.name, expected_column.name)]
                    == ("integer", 1, 1, 2_147_483_647, 1, 1, False)
                    and actual_default in allowed_defaults
                    and actual_identity is None
                    and actual_computed is None
                    and actual_autoincrement
                )
            elif dialect_name == "sqlite" and expected_generated:
                generation_matches = (
                    actual_default is None and actual_identity is None and actual_computed is None
                )
            if not generation_matches:
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    "default, owned sequence configuration, identity, computed value, "
                    "or autoincrement behavior"
                )
        expected_primary_key = tuple(column.name for column in table.primary_key.columns)
        inspected_primary_key = inspector.get_pk_constraint(table.name)
        actual_primary_key = tuple(inspected_primary_key["constrained_columns"])
        if actual_primary_key != expected_primary_key:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible primary key "
                f"{actual_primary_key!r}; expected {expected_primary_key!r}"
            )
        primary_key_name = inspected_primary_key.get("name")
        if dialect_name == "postgresql" and primary_key_name != f"{table.name}_pkey":
            raise RuntimeError(
                f"database table {table.name!r} has incompatible primary-key constraint name"
            )
        expected_uniques = {
            str(constraint.name): tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint) and constraint.name is not None
        }
        actual_uniques: dict[str, tuple[str, ...]] = {}
        for unique_constraint in inspector.get_unique_constraints(table.name):
            name = unique_constraint.get("name")
            columns = unique_constraint.get("column_names")
            if (
                not isinstance(name, str)
                or not name
                or name in actual_uniques
                or not isinstance(columns, list)
                or not columns
                or any(not isinstance(column, str) or not column for column in columns)
            ):
                raise RuntimeError(
                    f"database table {table.name!r} has an unsupported unique constraint"
                )
            actual_uniques[name] = tuple(columns)
        if actual_uniques != expected_uniques:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible unique constraints; "
                f"found {actual_uniques!r}, expected {expected_uniques!r}"
            )
        expected_indexes = {
            str(index.name): _expected_index_contract(table.name, index, dialect_name)
            for index in table.indexes
            if index.name is not None
        }
        actual_indexes: dict[
            str,
            tuple[tuple[str, ...], bool, tuple[object, ...] | None],
        ] = {}
        for index in inspector.get_indexes(table.name):
            duplicate = index.get("duplicates_constraint")
            if duplicate is not None:
                if not isinstance(duplicate, str) or duplicate not in actual_uniques:
                    raise RuntimeError(
                        f"database table {table.name!r} has an unsupported constraint index"
                    )
                continue
            name, contract = _inspected_index_contract(table.name, index, dialect_name)
            if name in actual_indexes:
                raise RuntimeError(f"database table {table.name!r} has duplicate index names")
            actual_indexes[name] = contract
        if actual_indexes != expected_indexes:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible indexes; "
                f"found {actual_indexes!r}, expected {expected_indexes!r}"
            )
        if dialect_name == "sqlite":
            with _schema_connection(bind) as connection:
                rows = connection.exec_driver_sql(f'PRAGMA index_list("{table.name}")').all()
            explicit_index_names = {str(row[1]) for row in rows if len(row) >= 4 and row[3] == "c"}
            if explicit_index_names != set(expected_indexes):
                raise RuntimeError(
                    f"database table {table.name!r} has incompatible explicit indexes"
                )
        expected_checks = {
            str(constraint.name): _normalize_schema_expression(constraint.sqltext)
            for constraint in table.constraints
            if isinstance(constraint, CheckConstraint) and constraint.name is not None
        }
        actual_checks: dict[str, tuple[object, ...] | None] = {}
        for check_constraint in inspector.get_check_constraints(table.name):
            name = check_constraint.get("name")
            if (
                not isinstance(name, str)
                or not name
                or name in actual_checks
                or check_constraint.get("sqltext") is None
            ):
                raise RuntimeError(
                    f"database table {table.name!r} has an unsupported check constraint"
                )
            actual_checks[name] = _normalize_schema_expression(check_constraint["sqltext"])
        if actual_checks != expected_checks:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible check constraints; "
                f"found {actual_checks!r}, expected {expected_checks!r}"
            )
        if dialect_name == "postgresql":
            with _schema_connection(bind) as connection:
                constraint_rows = connection.execute(
                    text(
                        """
                        SELECT
                            conname,
                            contype::text,
                            condeferrable,
                            condeferred,
                            convalidated,
                            connoinherit
                        FROM pg_constraint
                        WHERE conrelid = CAST(:table_name AS regclass)
                          AND contype IN ('p', 'u', 'c')
                        """
                    ),
                    {"table_name": table.name},
                ).all()
                index_rows = connection.execute(
                    text(
                        """
                        SELECT
                            index_class.relname,
                            index_state.indisunique,
                            index_state.indisprimary,
                            index_state.indimmediate,
                            index_state.indisvalid,
                            index_state.indisready,
                            index_state.indislive,
                            index_state.indisexclusion,
                            access_method.amname,
                            pg_get_expr(index_state.indpred, index_state.indrelid)
                        FROM pg_index AS index_state
                        JOIN pg_class AS table_class
                          ON table_class.oid = index_state.indrelid
                        JOIN pg_class AS index_class
                          ON index_class.oid = index_state.indexrelid
                        JOIN pg_am AS access_method
                          ON access_method.oid = index_class.relam
                        WHERE table_class.oid = CAST(:table_name AS regclass)
                        """
                    ),
                    {"table_name": table.name},
                ).all()
            expected_constraint_states = dict.fromkeys(
                expected_uniques,
                # PostgreSQL reports connoinherit=true for UNIQUE constraints.
                # The flag is meaningful only for CHECK constraints, so require
                # the canonical catalog value instead of treating it as unsafe.
                ("u", False, False, True, True),
            )
            expected_constraint_states.update(
                dict.fromkeys(
                    expected_checks,
                    ("c", False, False, True, False),
                )
            )
            assert isinstance(primary_key_name, str)
            expected_constraint_states[primary_key_name] = (
                "p",
                False,
                False,
                True,
                True,
            )
            actual_constraint_states = {
                str(row[0]): (
                    str(row[1]),
                    bool(row[2]),
                    bool(row[3]),
                    bool(row[4]),
                    bool(row[5]),
                )
                for row in constraint_rows
            }
            if actual_constraint_states != expected_constraint_states:
                raise RuntimeError(
                    f"database table {table.name!r} has unsafe PostgreSQL constraint state"
                )
            reflected_index_states = {
                str(row[0]): (
                    bool(row[1]),
                    bool(row[2]),
                    bool(row[3]),
                    bool(row[4]),
                    bool(row[5]),
                    bool(row[6]),
                    bool(row[7]),
                    str(row[8]),
                    _normalize_schema_expression(row[9]),
                )
                for row in index_rows
            }
            expected_index_states = {
                name: (
                    unique,
                    False,
                    True,
                    True,
                    True,
                    True,
                    False,
                    "btree",
                    predicate,
                )
                for name, (_columns, unique, predicate) in expected_indexes.items()
            }
            expected_index_states.update(
                dict.fromkeys(
                    expected_uniques,
                    (
                        True,
                        False,
                        True,
                        True,
                        True,
                        True,
                        False,
                        "btree",
                        None,
                    ),
                )
            )
            expected_index_states[primary_key_name] = (
                True,
                True,
                True,
                True,
                True,
                True,
                False,
                "btree",
                None,
            )
            actual_index_states = {
                name: reflected_index_states.get(name) for name in expected_index_states
            }
            if actual_index_states != expected_index_states:
                raise RuntimeError(
                    f"database table {table.name!r} has unsafe PostgreSQL index state"
                )
        if inspector.get_foreign_keys(table.name):
            raise RuntimeError(
                f"database table {table.name!r} has unsupported foreign-key constraints"
            )
    with _schema_connection(bind) as connection:
        version = connection.scalar(
            select(SchemaMetadata.version).where(SchemaMetadata.singleton_id == 1)
        )
    if version != SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {version!r} is incompatible with required version "
            f"{SCHEMA_VERSION}"
        )


class QueueStore:
    """Database-backed latest-wins work queue.

    A job is unique per installation/repository/pull request. New triggers bump
    its generation, so a worker cannot delete work that arrived during an
    earlier evaluation.
    """

    def __init__(self, database_url: str) -> None:
        is_postgresql = database_url.startswith("postgresql")
        connect_args: dict[str, Any]
        engine_options: dict[str, Any] = {"pool_pre_ping": True}
        if database_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
        elif is_postgresql:
            # Webhook ingestion is time-bounded. A dead database endpoint or an
            # exhausted application pool must fail within that budget so GitHub
            # can redeliver instead of holding a request indefinitely.
            connect_args = {
                **isolated_postgresql_connect_args(database_url),
                "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
                "options": (
                    f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MILLISECONDS} "
                    "-c search_path=public"
                ),
            }
            engine_options["pool_timeout"] = DATABASE_POOL_TIMEOUT_SECONDS
        else:
            connect_args = {}
        self.engine = create_engine(
            database_url,
            connect_args=connect_args,
            **engine_options,
        )
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)
        self._lock_engine: Engine | None = None
        if self.engine.dialect.name == "postgresql":
            # Advisory locks must never return to a reusable connection pool:
            # an uncertain unlock would otherwise poison that pooled session.
            self._lock_engine = create_engine(
                database_url,
                connect_args={
                    **isolated_postgresql_connect_args(database_url),
                    "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
                    "options": (
                        f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MILLISECONDS} "
                        "-c search_path=public"
                    ),
                },
                poolclass=NullPool,
                pool_pre_ping=True,
            )
        # SQLite is development/test-only. A bounded stripe set provides
        # in-process ordering there; production PostgreSQL uses exact advisory
        # locks shared by every replica.
        self._check_write_locks = tuple(threading.Lock() for _ in range(256))
        # Authority publication guards can be nested around check-writer
        # guards. A distinct local namespace prevents deterministic stripe
        # self-deadlocks in SQLite development and tests.
        self._authority_locks = tuple(threading.Lock() for _ in range(256))

    def initialize(self) -> None:
        """Reject a database that has not been explicitly migrated to this release."""
        self.validate_schema()

    def validate_schema(self) -> None:
        """Validate the Alembic head, compatibility marker, and required schema."""
        validate_database_schema(self.engine)

    def close(self) -> None:
        """Dispose pooled connections."""
        self.engine.dispose()
        if self._lock_engine is not None:
            self._lock_engine.dispose()

    @staticmethod
    def _check_write_key(repository: str, scope: str | int) -> int:
        digest = hashlib.blake2b(
            f"extra-codeowners\0{repository}\0{scope}".encode(),
            digest_size=8,
        ).digest()
        return int.from_bytes(digest, byteorder="big", signed=True)

    def acquire_check_write_guard(
        self,
        repository: str,
        scope: str | int,
        timeout_seconds: float = 30.0,
    ) -> CheckWriteGuard | None:
        """Become the sole check writer, returning ``None`` after a bounded wait.

        PostgreSQL session advisory locks are released by the server if a
        process or connection dies, closing the publish/revoke crash window.
        """
        key = self._check_write_key(repository, scope)
        return self._acquire_guard(
            key,
            timeout_seconds=timeout_seconds,
            shared=False,
            local_locks=self._check_write_locks,
        )

    def acquire_authority_guard(
        self,
        installation_id: int,
        *,
        shared: bool,
        timeout_seconds: float = 30.0,
    ) -> CheckWriteGuard | None:
        """Acquire the installation authority publication/ingress guard.

        PostgreSQL publishers take a shared lock, so normal evaluations remain
        concurrent. Authority webhook ingestion takes the exclusive variant,
        ordering its durable fence before or after every final Check Run write.
        SQLite uses the same exclusive local lock for both modes.
        """
        key = self._check_write_key(
            "__extra_codeowners_authority__", f"installation:{installation_id}"
        )
        return self._acquire_guard(
            key,
            timeout_seconds=timeout_seconds,
            shared=shared,
            local_locks=self._authority_locks,
        )

    def _acquire_guard(
        self,
        key: int,
        *,
        timeout_seconds: float,
        shared: bool,
        local_locks: tuple[threading.Lock, ...],
    ) -> CheckWriteGuard | None:
        """Acquire one exact advisory/local lock key."""
        if self._lock_engine is not None:
            connection = self._lock_engine.connect()
            try:
                connection.execute(
                    text("SELECT set_config('statement_timeout', :timeout, false)"),
                    {"timeout": f"{max(1, int(timeout_seconds * 1000))}ms"},
                )
                lock_function = "pg_advisory_lock_shared" if shared else "pg_advisory_lock"
                connection.execute(text(f"SELECT {lock_function}(:key)"), {"key": key})
                # PostgreSQL advisory locks are session-scoped, so committing
                # here retains the lock while preventing a network/API wait
                # from leaving an idle transaction open on the database.
                connection.commit()
                return CheckWriteGuard(key=key, connection=connection, shared=shared)
            except Exception:
                connection.invalidate()
                connection.close()
                raise

        local_lock = local_locks[key % len(local_locks)]
        if not local_lock.acquire(timeout=max(0.0, timeout_seconds)):
            return None
        return CheckWriteGuard(key=key, local_lock=local_lock)

    @staticmethod
    def release_check_write_guard(guard: CheckWriteGuard) -> None:
        """Release a guard acquired by :meth:`acquire_check_write_guard`."""
        if guard.connection is not None:
            try:
                unlock_function = (
                    "pg_advisory_unlock_shared" if guard.shared else "pg_advisory_unlock"
                )
                unlocked = guard.connection.execute(
                    text(f"SELECT {unlock_function}(:key)"), {"key": guard.key}
                ).scalar_one()
                if unlocked is not True:
                    raise RuntimeError("PostgreSQL advisory guard was not held by this session")
                guard.connection.commit()
            except Exception:
                # Physically discard an uncertain session; PostgreSQL releases
                # its advisory locks when that connection is terminated.
                guard.connection.invalidate()
                raise
            finally:
                guard.connection.close()
            return
        if guard.local_lock is None:  # pragma: no cover - dataclass is internal
            raise RuntimeError("check write guard has no lock")
        guard.local_lock.release()

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Open a transactional session."""
        with self._sessions.begin() as session:
            yield session

    @staticmethod
    def _shared_head_generation_in_session(
        session: Session,
        installation_id: int,
        repository_full_name: str,
        head_sha: str | None,
    ) -> int:
        if head_sha is None:
            return 0
        return int(
            session.scalar(
                select(SharedHeadEpoch.generation).where(
                    SharedHeadEpoch.installation_id == installation_id,
                    SharedHeadEpoch.repository_full_name == repository_full_name,
                    SharedHeadEpoch.head_sha == head_sha,
                )
            )
            or 0
        )

    @staticmethod
    def _advance_shared_head_epoch_in_session(
        session: Session,
        request: JobRequest,
    ) -> int:
        head_sha = validate_head_sha(request.head_sha_hint or "")
        now = utcnow()
        key = (
            SharedHeadEpoch.installation_id == request.installation_id,
            SharedHeadEpoch.repository_full_name == request.repository_full_name,
            SharedHeadEpoch.head_sha == head_sha,
        )
        updated = session.execute(
            update(SharedHeadEpoch)
            .where(*key)
            .values(
                generation=SharedHeadEpoch.generation + 1,
                changed_at=now,
                available_at=now,
                attempts=0,
                lease_owner=None,
                lease_until=None,
                last_error=None,
            )
        )
        if getattr(updated, "rowcount", 0) == 1:
            generation = session.scalar(select(SharedHeadEpoch.generation).where(*key))
            if generation is None:  # pragma: no cover - protected by this transaction
                raise RuntimeError("shared-head epoch disappeared during advancement")
            return int(generation)
        epoch = SharedHeadEpoch(
            installation_id=request.installation_id,
            repository_full_name=request.repository_full_name,
            head_sha=head_sha,
            generation=1,
            invalidated_generation=0,
            changed_at=now,
            available_at=now,
        )
        session.add(epoch)
        # Preserve the shared-head -> evaluation-job lock order even when this
        # transaction creates the epoch. Without an explicit flush, SQLAlchemy
        # may defer the INSERT until a later evaluation-job statement.
        session.flush((epoch,))
        return 1

    @staticmethod
    def _enqueue_in_session(
        session: Session,
        request: JobRequest,
        delivery_id: str | None = None,
        shared_head_generation: int | None = None,
        *,
        preserve_different_head: bool = False,
    ) -> None:
        now = utcnow()
        authority_generation = (
            session.scalar(
                select(AuthorityEpoch.generation).where(
                    AuthorityEpoch.installation_id == request.installation_id
                )
            )
            or 0
        )
        if shared_head_generation is None:
            shared_head_generation = QueueStore._shared_head_generation_in_session(
                session,
                request.installation_id,
                request.repository_full_name,
                request.head_sha_hint,
            )
        values: dict[str, Any] = {
            "generation": EvaluationJob.generation + 1,
            "authority_generation": authority_generation,
            "shared_head_generation": shared_head_generation,
            "reason": request.reason,
            "head_sha_hint": request.head_sha_hint,
            "requested_at": now,
            "available_at": now,
            "state": "pending",
            "attempts": 0,
            "last_error": None,
        }
        if delivery_id is not None:
            values["last_delivery_id"] = delivery_id
        key = (
            EvaluationJob.installation_id == request.installation_id,
            EvaluationJob.repository_full_name == request.repository_full_name,
            EvaluationJob.pull_number == request.pull_number,
        )
        update_conditions = list(key)
        if preserve_different_head:
            update_conditions.append(
                or_(
                    EvaluationJob.head_sha_hint.is_(None),
                    EvaluationJob.head_sha_hint == request.head_sha_hint,
                )
            )
        updated = session.execute(update(EvaluationJob).where(*update_conditions).values(**values))
        if getattr(updated, "rowcount", 0) == 1:
            return
        if preserve_different_head:
            existing_id = session.scalar(select(EvaluationJob.id).where(*key))
            if existing_id is not None:
                return
        session.add(
            EvaluationJob(
                installation_id=request.installation_id,
                repository_full_name=request.repository_full_name,
                pull_number=request.pull_number,
                reason=request.reason,
                head_sha_hint=request.head_sha_hint,
                last_delivery_id=delivery_id,
                authority_generation=authority_generation,
                shared_head_generation=shared_head_generation,
                requested_at=now,
                available_at=now,
            )
        )

    def enqueue(self, request: JobRequest) -> None:
        """Enqueue an evaluation, fencing a known head in the same transaction.

        Known-head callers must not be able to create an evaluation that
        references an epoch concurrently removed by pruning. Hintless work has
        no exact head to fence and retains the ordinary coalescing path.
        """
        if request.head_sha_hint is not None:
            self.enqueue_shared_head_trigger(request)
            return
        for _ in range(5):
            try:
                with self.session() as session:
                    self._enqueue_in_session(session, request)
                return
            except IntegrityError:
                # A concurrent first trigger inserted the unique PR job. Retry
                # as an update after the losing transaction has rolled back.
                continue
        raise RuntimeError("could not enqueue evaluation after concurrent inserts")

    def enqueue_shared_head_trigger(self, request: JobRequest) -> None:
        """Atomically advance a live-head fence and enqueue its evaluation."""
        for _ in range(5):
            try:
                with self.session() as session:
                    shared_head_generation = self._advance_shared_head_epoch_in_session(
                        session,
                        request,
                    )
                    self._enqueue_in_session(
                        session,
                        request,
                        shared_head_generation=shared_head_generation,
                    )
                return
            except IntegrityError:
                # Roll back the tentative epoch when another transaction wins
                # either first insert, then retry in the common lock order.
                continue
        raise RuntimeError("could not enqueue shared-head trigger after concurrent inserts")

    def enqueue_for_shared_head_generation(
        self,
        request: JobRequest,
        shared_head_generation: int,
    ) -> bool:
        """Bind fan-out work to one still-current head generation.

        A different-head row for the same pull request is preserved. GitHub's
        commit-to-pulls response is eventually consistent, while a directly
        accepted newer head is durable evidence that must not be overwritten
        by stale fan-out.
        """
        head_sha = validate_head_sha(request.head_sha_hint or "")
        if shared_head_generation <= 0:
            raise ValueError("shared_head_generation must be positive")
        for _ in range(5):
            try:
                with self.session() as session:
                    current_generation = session.scalar(
                        select(SharedHeadEpoch.generation)
                        .where(
                            SharedHeadEpoch.installation_id == request.installation_id,
                            SharedHeadEpoch.repository_full_name == request.repository_full_name,
                            SharedHeadEpoch.head_sha == head_sha,
                        )
                        .with_for_update()
                    )
                    if current_generation != shared_head_generation:
                        return False
                    existing_head = session.scalar(
                        select(EvaluationJob.head_sha_hint)
                        .where(
                            EvaluationJob.installation_id == request.installation_id,
                            EvaluationJob.repository_full_name == request.repository_full_name,
                            EvaluationJob.pull_number == request.pull_number,
                        )
                        .with_for_update()
                    )
                    if existing_head is not None and existing_head != head_sha:
                        return True
                    self._enqueue_in_session(
                        session,
                        request,
                        shared_head_generation=shared_head_generation,
                        preserve_different_head=True,
                    )
                return True
            except IntegrityError:
                # A direct trigger can insert the pull row between the two
                # reads. Retry so a different current head remains preserved.
                continue
        raise RuntimeError("could not enqueue shared-head fan-out after concurrent inserts")

    def enqueue_if_absent(self, request: JobRequest) -> bool:
        """Atomically fence and enqueue genuinely missing reconciliation work."""
        for _ in range(5):
            try:
                with self.session() as session:
                    shared_head_generation = 0
                    if request.head_sha_hint is not None:
                        shared_head_generation = self._advance_shared_head_epoch_in_session(
                            session,
                            request,
                        )
                    now = utcnow()
                    authority_generation = (
                        session.scalar(
                            select(AuthorityEpoch.generation).where(
                                AuthorityEpoch.installation_id == request.installation_id
                            )
                        )
                        or 0
                    )
                    values: dict[str, Any] = {
                        "installation_id": request.installation_id,
                        "repository_full_name": request.repository_full_name,
                        "pull_number": request.pull_number,
                        "reason": request.reason,
                        "head_sha_hint": request.head_sha_hint,
                        "generation": 1,
                        "authority_generation": authority_generation,
                        "shared_head_generation": shared_head_generation,
                        "state": "pending",
                        "attempts": 0,
                        "requested_at": now,
                        "available_at": now,
                    }
                    index_elements = (
                        "installation_id",
                        "repository_full_name",
                        "pull_number",
                    )
                    dialect_name = session.get_bind().dialect.name
                    if dialect_name == "postgresql":
                        inserted_id = session.scalar(
                            postgresql_insert(EvaluationJob)
                            .values(**values)
                            .on_conflict_do_nothing(index_elements=index_elements)
                            .returning(EvaluationJob.id)
                        )
                    elif dialect_name == "sqlite":
                        inserted_id = session.scalar(
                            sqlite_insert(EvaluationJob)
                            .values(**values)
                            .on_conflict_do_nothing(index_elements=index_elements)
                            .returning(EvaluationJob.id)
                        )
                    else:  # pragma: no cover - QueueStore supports SQLite and PostgreSQL
                        raise RuntimeError(
                            f"reconciliation insert does not support {dialect_name!r}"
                        )
                    if inserted_id is None:
                        # Raising inside the context rolls back the epoch
                        # increment that preceded this conflicting insert.
                        raise _EvaluationJobAlreadyPresentError
                return True
            except _EvaluationJobAlreadyPresentError:
                return False
            except IntegrityError:
                # Different pull requests can race to create the same
                # shared-head epoch. Retry the complete atomic insert so the
                # losing epoch transaction is not mistaken for durable work.
                continue
        raise RuntimeError("could not reconcile evaluation after concurrent inserts")

    @staticmethod
    def _enqueue_authority_in_session(
        session: Session,
        request: AuthorityRequest,
    ) -> None:
        now = utcnow()
        scope_key = request.scope_key
        base_ref = request.base_ref or ""
        if request.repository_full_name is not None:
            if not base_ref:
                # A repository-wide authority event covers every pending base
                # push and should collapse a contributor-created branch queue.
                session.execute(
                    delete(AuthorityJob).where(
                        AuthorityJob.installation_id == request.installation_id,
                        AuthorityJob.scope_key == scope_key,
                        AuthorityJob.base_ref != "",
                    )
                )
            else:
                same_base_exists = session.scalar(
                    select(AuthorityJob.id).where(
                        AuthorityJob.installation_id == request.installation_id,
                        AuthorityJob.scope_key == scope_key,
                        AuthorityJob.base_ref == base_ref,
                    )
                )
                repository_wide_exists = session.scalar(
                    select(AuthorityJob.id).where(
                        AuthorityJob.installation_id == request.installation_id,
                        AuthorityJob.scope_key == scope_key,
                        AuthorityJob.base_ref == "",
                    )
                )
                base_scoped_count = int(
                    session.scalar(
                        select(func.count())
                        .select_from(AuthorityJob)
                        .where(
                            AuthorityJob.installation_id == request.installation_id,
                            AuthorityJob.scope_key == scope_key,
                            AuthorityJob.base_ref != "",
                        )
                    )
                    or 0
                )
                if repository_wide_exists is not None or (
                    same_base_exists is None
                    and base_scoped_count >= MAX_BASE_SCOPED_AUTHORITY_JOBS_PER_REPOSITORY
                ):
                    # Once the bounded set overflows, one repository-wide job
                    # is safer and cheaper than an attacker-controlled number
                    # of unique branch rows. It conservatively reevaluates all
                    # open pull requests in the repository.
                    session.execute(
                        delete(AuthorityJob).where(
                            AuthorityJob.installation_id == request.installation_id,
                            AuthorityJob.scope_key == scope_key,
                            AuthorityJob.base_ref != "",
                        )
                    )
                    base_ref = ""
        updated = session.execute(
            update(AuthorityJob)
            .where(
                AuthorityJob.installation_id == request.installation_id,
                AuthorityJob.scope_key == scope_key,
                AuthorityJob.base_ref == base_ref,
            )
            .values(
                generation=AuthorityJob.generation + 1,
                reason=request.reason,
                requested_at=now,
                available_at=now,
                state="pending",
                attempts=0,
                last_error=None,
            )
        )
        if getattr(updated, "rowcount", 0) == 1:
            return
        session.add(
            AuthorityJob(
                installation_id=request.installation_id,
                scope_key=scope_key,
                base_ref=base_ref,
                reason=request.reason,
                requested_at=now,
                available_at=now,
            )
        )

    @staticmethod
    def _bump_authority_epoch_in_session(session: Session, installation_id: int) -> None:
        now = utcnow()
        updated = session.execute(
            update(AuthorityEpoch)
            .where(AuthorityEpoch.installation_id == installation_id)
            .values(
                generation=AuthorityEpoch.generation + 1,
                changed_at=now,
            )
        )
        if getattr(updated, "rowcount", 0) == 0:
            session.add(
                AuthorityEpoch(
                    installation_id=installation_id,
                    generation=1,
                    changed_at=now,
                )
            )

    def accept_delivery(
        self,
        delivery_id: str,
        event: str,
        request: JobRequest | AuthorityRequest | None,
        authority_guard_timeout_seconds: float = 5.0,
    ) -> DeliveryAcceptance:
        """Record and enqueue one webhook atomically.

        The returned generation binds synchronous invalidation to the exact
        head fence accepted in this transaction. A duplicate delivery returns
        its original token instead of borrowing a newer head generation.
        """
        authority_guard: CheckWriteGuard | None = None
        if isinstance(request, AuthorityRequest):
            authority_guard = self.acquire_authority_guard(
                request.installation_id,
                shared=False,
                timeout_seconds=authority_guard_timeout_seconds,
            )
            if authority_guard is None:
                raise RuntimeError("timed out waiting to record an authority change")
        try:
            for _ in range(5):
                try:
                    with self.session() as session:
                        existing_delivery = session.get(WebhookDelivery, delivery_id)
                        if existing_delivery is not None:
                            if existing_delivery.event != event:
                                raise RuntimeError(
                                    "accepted delivery ID was replayed with a different event"
                                )
                            if isinstance(request, JobRequest):
                                expected_identity = (
                                    request.installation_id,
                                    request.repository_full_name,
                                    request.pull_number,
                                    request.head_sha_hint,
                                )
                                stored_identity = (
                                    existing_delivery.installation_id,
                                    existing_delivery.repository_full_name,
                                    existing_delivery.pull_number,
                                    existing_delivery.head_sha,
                                )
                                legacy_identity = (
                                    existing_delivery.invalidation_required
                                    and all(value is None for value in stored_identity)
                                    and existing_delivery.shared_head_generation is None
                                )
                                if not legacy_identity and stored_identity != expected_identity:
                                    raise RuntimeError(
                                        "accepted delivery ID was replayed with different "
                                        "pull-request identity"
                                    )
                            return DeliveryAcceptance(
                                accepted=False,
                                shared_head_generation=existing_delivery.shared_head_generation,
                            )
                        delivery = WebhookDelivery(
                            delivery_id=delivery_id,
                            event=event,
                            invalidation_required=isinstance(request, JobRequest),
                        )
                        session.add(delivery)
                        shared_head_generation: int | None = None
                        if isinstance(request, JobRequest):
                            shared_head_generation = self._advance_shared_head_epoch_in_session(
                                session, request
                            )
                            delivery.installation_id = request.installation_id
                            delivery.repository_full_name = request.repository_full_name
                            delivery.pull_number = request.pull_number
                            delivery.head_sha = request.head_sha_hint
                            delivery.shared_head_generation = shared_head_generation
                            self._enqueue_in_session(
                                session,
                                request,
                                delivery_id,
                                shared_head_generation,
                            )
                        elif isinstance(request, AuthorityRequest):
                            if request.repository_full_name is None:
                                self._bump_authority_epoch_in_session(
                                    session, request.installation_id
                                )
                            self._enqueue_authority_in_session(session, request)
                    return DeliveryAcceptance(
                        accepted=True,
                        shared_head_generation=shared_head_generation,
                    )
                except IntegrityError:
                    # This may be either the same delivery racing or a different
                    # delivery racing to create the unique PR job. Retry so the
                    # latter delivery and its trigger are not silently discarded.
                    continue
            raise RuntimeError("could not accept webhook delivery after concurrent inserts")
        finally:
            if authority_guard is not None:
                self.release_check_write_guard(authority_guard)

    def enqueue_authority(self, request: AuthorityRequest) -> None:
        """Coalesce internal installation-to-repository authority fan-out."""
        for _ in range(5):
            try:
                with self.session() as session:
                    self._enqueue_authority_in_session(session, request)
                return
            except IntegrityError:
                continue
        raise RuntimeError("could not enqueue authority work after concurrent inserts")

    def delivery_needs_invalidation(self, delivery_id: str) -> bool:
        """Return whether an accepted PR trigger still needs check revocation."""
        with self._sessions() as session:
            delivery = session.get(WebhookDelivery, delivery_id)
            return bool(
                delivery is not None
                and delivery.invalidation_required
                and delivery.invalidation_completed_at is None
            )

    def mark_delivery_invalidated(self, delivery_id: str) -> bool:
        """Record successful check revocation for replay-safe webhook retries."""
        with self.session() as session:
            result = session.execute(
                update(WebhookDelivery)
                .where(
                    WebhookDelivery.delivery_id == delivery_id,
                    WebhookDelivery.invalidation_required.is_(True),
                    WebhookDelivery.invalidation_completed_at.is_(None),
                )
                .values(invalidation_completed_at=utcnow())
            )
            return getattr(result, "rowcount", 0) == 1

    def is_current_generation(self, job: ClaimedJob) -> bool:
        """Return whether no newer trigger has superseded a claimed evaluation."""
        with self._sessions() as session:
            generation = session.scalar(
                select(EvaluationJob.generation).where(EvaluationJob.id == job.id)
            )
            return generation == job.generation

    def bind_claim_to_head(self, job: ClaimedJob, head_sha: str) -> ClaimedJob | None:
        """Bind a hintless internal claim to the head observed from GitHub.

        Direct webhook work is already bound transactionally at acceptance.
        Internal fan-out can lack a trustworthy head until it fetches current
        state, so binding advances that head and creates durable invalidation
        work in the same transaction.
        """
        head_sha = validate_head_sha(head_sha)
        if job.head_sha_hint is not None:
            return job if job.head_sha_hint == head_sha else None
        try:
            with self.session() as session:
                shared_head_generation = self._advance_shared_head_epoch_in_session(
                    session,
                    JobRequest(
                        installation_id=job.installation_id,
                        repository_full_name=job.repository_full_name,
                        pull_number=job.pull_number,
                        reason=job.reason,
                        head_sha_hint=head_sha,
                    ),
                )
                bound = session.execute(
                    update(EvaluationJob)
                    .where(
                        EvaluationJob.id == job.id,
                        EvaluationJob.generation == job.generation,
                        EvaluationJob.lease_owner == job.lease_owner,
                        EvaluationJob.state == "pending",
                        EvaluationJob.head_sha_hint.is_(None),
                    )
                    .values(
                        head_sha_hint=head_sha,
                        shared_head_generation=shared_head_generation,
                    )
                )
                if getattr(bound, "rowcount", 0) != 1:
                    raise _EvaluationJobBindingLostError
        except _EvaluationJobBindingLostError:
            return None
        return replace(
            job,
            head_sha_hint=head_sha,
            shared_head_generation=shared_head_generation,
        )

    def shared_head_generation_is_current(self, job: ClaimedJob, head_sha: str) -> bool:
        """Return whether no accepted trigger superseded this head evidence."""
        head_sha = validate_head_sha(head_sha)
        if job.head_sha_hint != head_sha:
            return False
        with self._sessions() as session:
            current = self._shared_head_generation_in_session(
                session,
                job.installation_id,
                job.repository_full_name,
                head_sha,
            )
        return current == job.shared_head_generation

    def shared_head_generation_is_publishable(self, job: ClaimedJob, head_sha: str) -> bool:
        """Return whether this exact head generation was durably invalidated."""
        head_sha = validate_head_sha(head_sha)
        if job.head_sha_hint != head_sha:
            return False
        with self._sessions() as session:
            row = session.execute(
                select(
                    SharedHeadEpoch.generation,
                    SharedHeadEpoch.invalidated_generation,
                ).where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == head_sha,
                )
            ).one_or_none()
        if row is None:
            return job.shared_head_generation == 0
        return bool(
            row.generation == job.shared_head_generation
            and row.invalidated_generation == job.shared_head_generation
        )

    def shared_head_invalidation_is_pending(
        self,
        installation_id: int,
        repository_full_name: str,
        head_sha: str,
        generation: int,
    ) -> bool:
        """Bind a synchronous reset to one exact still-pending generation."""
        repository_full_name = normalize_repository_full_name(repository_full_name)
        head_sha = validate_head_sha(head_sha)
        with self._sessions() as session:
            row = session.execute(
                select(
                    SharedHeadEpoch.generation,
                    SharedHeadEpoch.invalidated_generation,
                ).where(
                    SharedHeadEpoch.installation_id == installation_id,
                    SharedHeadEpoch.repository_full_name == repository_full_name,
                    SharedHeadEpoch.head_sha == head_sha,
                )
            ).one_or_none()
        return bool(
            row is not None
            and row.generation == generation
            and row.invalidated_generation < generation
        )

    def shared_head_generation(
        self,
        installation_id: int,
        repository_full_name: str,
        head_sha: str,
    ) -> int:
        """Return the current durable generation for one commit-scoped check."""
        repository_full_name = normalize_repository_full_name(repository_full_name)
        head_sha = validate_head_sha(head_sha)
        with self._sessions() as session:
            return self._shared_head_generation_in_session(
                session,
                installation_id,
                repository_full_name,
                head_sha,
            )

    def shared_head_invalidation_generation(
        self,
        installation_id: int,
        repository_full_name: str,
        head_sha: str,
    ) -> int:
        """Return the latest generation whose exact-head reset completed."""
        repository_full_name = normalize_repository_full_name(repository_full_name)
        head_sha = validate_head_sha(head_sha)
        with self._sessions() as session:
            return int(
                session.scalar(
                    select(SharedHeadEpoch.invalidated_generation).where(
                        SharedHeadEpoch.installation_id == installation_id,
                        SharedHeadEpoch.repository_full_name == repository_full_name,
                        SharedHeadEpoch.head_sha == head_sha,
                    )
                )
                or 0
            )

    def has_superseding_job(self, job: ClaimedJob) -> bool:
        """Return whether a newer generation still needs evaluation."""
        with self._sessions() as session:
            return bool(
                session.scalar(
                    select(EvaluationJob.id).where(
                        EvaluationJob.id == job.id,
                        EvaluationJob.generation > job.generation,
                        EvaluationJob.state == "pending",
                    )
                )
            )

    def has_blocking_authority(self, job: ClaimedJob, base_ref: str) -> bool:
        """Return whether unresolved authority work can affect this pull request.

        Authority rows remain present while pending, leased, retrying, or dead.
        Every such state blocks publication because the evaluation may have
        collected membership, policy, label, CODEOWNERS, or merge-base evidence
        from before the accepted authority change.
        """
        with self._sessions() as session:
            return bool(
                session.scalar(
                    select(AuthorityJob.id)
                    .where(
                        AuthorityJob.installation_id == job.installation_id,
                        AuthorityJob.scope_key.in_(("*", job.repository_full_name)),
                        AuthorityJob.base_ref.in_(("", base_ref)),
                    )
                    .limit(1)
                )
            )

    def is_current_claim(self, job: ClaimedJob) -> bool:
        """Return whether a claim still owns the current, unexpired generation."""
        now = utcnow()
        with self._sessions() as session:
            row = session.execute(
                select(
                    EvaluationJob.generation,
                    EvaluationJob.authority_generation,
                    EvaluationJob.lease_owner,
                    EvaluationJob.lease_until,
                ).where(EvaluationJob.id == job.id)
            ).one_or_none()
            if row is None or row.lease_until is None:
                return False
            current_authority_generation = (
                session.scalar(
                    select(AuthorityEpoch.generation).where(
                        AuthorityEpoch.installation_id == job.installation_id
                    )
                )
                or 0
            )
            expiry = row.lease_until
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            return bool(
                row.generation == job.generation
                and row.authority_generation == job.authority_generation
                and current_authority_generation == job.authority_generation
                and row.lease_owner == job.lease_owner
                and expiry >= now
            )

    def renew_claim(self, job: ClaimedJob, lease_seconds: int) -> bool:
        """Extend a current claim without reviving a superseded generation."""
        with self.session() as session:
            renewed = session.execute(
                update(EvaluationJob)
                .where(
                    EvaluationJob.id == job.id,
                    EvaluationJob.generation == job.generation,
                    EvaluationJob.lease_owner == job.lease_owner,
                    EvaluationJob.state == "pending",
                )
                .values(lease_until=utcnow() + timedelta(seconds=lease_seconds))
            )
            return getattr(renewed, "rowcount", 0) == 1

    def claim_shared_head_invalidation(
        self,
        owner: str,
        lease_seconds: int,
    ) -> ClaimedSharedHeadInvalidation | None:
        """Lease the oldest exact-head reset that has not completed."""
        now = utcnow()
        lease_until = now + timedelta(seconds=lease_seconds)
        for _ in range(3):
            with self.session() as session:
                candidate = session.scalar(
                    select(SharedHeadEpoch)
                    .where(
                        SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation,
                        SharedHeadEpoch.available_at <= now,
                        or_(
                            SharedHeadEpoch.lease_until.is_(None),
                            SharedHeadEpoch.lease_until < now,
                        ),
                    )
                    .order_by(
                        SharedHeadEpoch.available_at,
                        SharedHeadEpoch.changed_at,
                        SharedHeadEpoch.installation_id,
                        SharedHeadEpoch.repository_full_name,
                        SharedHeadEpoch.head_sha,
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if candidate is None:
                    return None
                claimed_attempts = int(candidate.attempts) + 1
                claimed = session.execute(
                    update(SharedHeadEpoch)
                    .where(
                        SharedHeadEpoch.installation_id == candidate.installation_id,
                        SharedHeadEpoch.repository_full_name == candidate.repository_full_name,
                        SharedHeadEpoch.head_sha == candidate.head_sha,
                        SharedHeadEpoch.generation == candidate.generation,
                        SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation,
                        or_(
                            SharedHeadEpoch.lease_until.is_(None),
                            SharedHeadEpoch.lease_until < now,
                        ),
                    )
                    .values(
                        lease_owner=owner,
                        lease_until=lease_until,
                        attempts=SharedHeadEpoch.attempts + 1,
                    )
                    .execution_options(synchronize_session=False)
                )
                if getattr(claimed, "rowcount", 0) != 1:
                    continue
                return ClaimedSharedHeadInvalidation(
                    installation_id=candidate.installation_id,
                    repository_full_name=candidate.repository_full_name,
                    head_sha=candidate.head_sha,
                    generation=candidate.generation,
                    attempts=claimed_attempts,
                    lease_owner=owner,
                )
        return None

    def is_current_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
    ) -> bool:
        """Return whether an unexpired lease still owns this pending generation."""
        now = utcnow()
        with self._sessions() as session:
            row = session.execute(
                select(
                    SharedHeadEpoch.generation,
                    SharedHeadEpoch.invalidated_generation,
                    SharedHeadEpoch.lease_owner,
                    SharedHeadEpoch.lease_until,
                ).where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                )
            ).one_or_none()
        if row is None or row.lease_until is None:
            return False
        lease_until = row.lease_until
        if lease_until.tzinfo is None:
            lease_until = lease_until.replace(tzinfo=UTC)
        return bool(
            row.generation == job.generation
            and row.invalidated_generation < job.generation
            and row.lease_owner == job.lease_owner
            and lease_until >= now
        )

    def renew_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
        lease_seconds: int,
    ) -> bool:
        """Renew only an unexpired lease for the same pending generation."""
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(SharedHeadEpoch)
                .where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                    SharedHeadEpoch.generation == job.generation,
                    SharedHeadEpoch.invalidated_generation < job.generation,
                    SharedHeadEpoch.lease_owner == job.lease_owner,
                    SharedHeadEpoch.lease_until >= now,
                )
                .values(lease_until=now + timedelta(seconds=lease_seconds))
            )
            return getattr(result, "rowcount", 0) == 1

    def complete_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
    ) -> bool:
        """Mark the claimed generation reset only while its lease is valid."""
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(SharedHeadEpoch)
                .where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                    SharedHeadEpoch.generation == job.generation,
                    SharedHeadEpoch.invalidated_generation < job.generation,
                    SharedHeadEpoch.lease_owner == job.lease_owner,
                    SharedHeadEpoch.lease_until >= now,
                )
                .values(
                    invalidated_generation=job.generation,
                    lease_owner=None,
                    lease_until=None,
                    last_error=None,
                )
            )
            return getattr(result, "rowcount", 0) == 1

    def fail_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
        error: str,
        max_delay_seconds: int,
    ) -> bool:
        """Retry an exact-head reset indefinitely with bounded backoff."""
        delay_seconds = max(1, min(max_delay_seconds, 2 ** min(job.attempts, 30)))
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(SharedHeadEpoch)
                .where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                    SharedHeadEpoch.generation == job.generation,
                    SharedHeadEpoch.invalidated_generation < job.generation,
                    SharedHeadEpoch.lease_owner == job.lease_owner,
                    SharedHeadEpoch.lease_until >= now,
                )
                .values(
                    available_at=now + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            return getattr(result, "rowcount", 0) == 1

    def defer_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
        error: str,
        delay_seconds: int,
    ) -> bool:
        """Release a rate-limited reset without consuming its retry budget."""
        delay_seconds = max(1, min(delay_seconds, 86_400))
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(SharedHeadEpoch)
                .where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                    SharedHeadEpoch.generation == job.generation,
                    SharedHeadEpoch.invalidated_generation < job.generation,
                    SharedHeadEpoch.lease_owner == job.lease_owner,
                    SharedHeadEpoch.lease_until >= now,
                )
                .values(
                    attempts=case(
                        (SharedHeadEpoch.attempts > 0, SharedHeadEpoch.attempts - 1),
                        else_=0,
                    ),
                    available_at=now + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            return getattr(result, "rowcount", 0) == 1

    def claim(self, owner: str, lease_seconds: int) -> ClaimedJob | None:
        """Atomically lease the oldest available job."""
        now = utcnow()
        lease_until = now + timedelta(seconds=lease_seconds)
        for _ in range(3):
            with self.session() as session:
                candidate = session.scalar(
                    select(EvaluationJob.id)
                    .where(
                        EvaluationJob.state == "pending",
                        EvaluationJob.available_at <= now,
                        or_(EvaluationJob.lease_until.is_(None), EvaluationJob.lease_until < now),
                        ~exists(
                            select(AuthorityJob.id).where(
                                AuthorityJob.installation_id == EvaluationJob.installation_id,
                                or_(
                                    AuthorityJob.scope_key == "*",
                                    AuthorityJob.scope_key == EvaluationJob.repository_full_name,
                                ),
                            )
                        ),
                    )
                    .order_by(EvaluationJob.available_at, EvaluationJob.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if candidate is None:
                    return None
                claimed = session.execute(
                    update(EvaluationJob)
                    .where(
                        EvaluationJob.id == candidate,
                        EvaluationJob.state == "pending",
                        or_(EvaluationJob.lease_until.is_(None), EvaluationJob.lease_until < now),
                    )
                    .values(
                        lease_owner=owner,
                        lease_until=lease_until,
                        attempts=EvaluationJob.attempts + 1,
                        # Reclaiming an expired lease fences the previous
                        # worker even when no webhook generation changed.
                        generation=case(
                            (
                                EvaluationJob.lease_owner.is_not(None),
                                EvaluationJob.generation + 1,
                            ),
                            else_=EvaluationJob.generation,
                        ),
                    )
                )
                if getattr(claimed, "rowcount", 0) != 1:
                    continue
                row = session.get(EvaluationJob, candidate)
                if row is None:  # pragma: no cover - protected by the transaction
                    continue
                return ClaimedJob(
                    id=row.id,
                    installation_id=row.installation_id,
                    repository_full_name=row.repository_full_name,
                    pull_number=row.pull_number,
                    reason=row.reason,
                    head_sha_hint=row.head_sha_hint,
                    last_delivery_id=row.last_delivery_id,
                    generation=row.generation,
                    authority_generation=row.authority_generation,
                    shared_head_generation=row.shared_head_generation,
                    attempts=row.attempts,
                    lease_owner=owner,
                )
        return None

    def claim_authority(self, owner: str, lease_seconds: int) -> ClaimedAuthorityJob | None:
        """Atomically lease the oldest authority fan-out job."""
        now = utcnow()
        lease_until = now + timedelta(seconds=lease_seconds)
        for _ in range(3):
            with self.session() as session:
                candidate = session.scalar(
                    select(AuthorityJob.id)
                    .where(
                        AuthorityJob.state == "pending",
                        AuthorityJob.available_at <= now,
                        or_(AuthorityJob.lease_until.is_(None), AuthorityJob.lease_until < now),
                    )
                    .order_by(
                        case(
                            (AuthorityJob.scope_key == "*", 0),
                            (AuthorityJob.base_ref == "", 1),
                            else_=2,
                        ),
                        AuthorityJob.available_at,
                        AuthorityJob.id,
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if candidate is None:
                    return None
                claimed = session.execute(
                    update(AuthorityJob)
                    .where(
                        AuthorityJob.id == candidate,
                        AuthorityJob.state == "pending",
                        or_(AuthorityJob.lease_until.is_(None), AuthorityJob.lease_until < now),
                    )
                    .values(
                        lease_owner=owner,
                        lease_until=lease_until,
                        attempts=AuthorityJob.attempts + 1,
                        generation=case(
                            (
                                AuthorityJob.lease_owner.is_not(None),
                                AuthorityJob.generation + 1,
                            ),
                            else_=AuthorityJob.generation,
                        ),
                    )
                )
                if getattr(claimed, "rowcount", 0) != 1:
                    continue
                row = session.get(AuthorityJob, candidate)
                if row is None:  # pragma: no cover - protected by transaction
                    continue
                return ClaimedAuthorityJob(
                    id=row.id,
                    installation_id=row.installation_id,
                    repository_full_name=(None if row.scope_key == "*" else row.scope_key),
                    base_ref=row.base_ref or None,
                    reason=row.reason,
                    generation=row.generation,
                    attempts=row.attempts,
                    lease_owner=owner,
                )
        return None

    def renew_authority_claim(self, job: ClaimedAuthorityJob, lease_seconds: int) -> bool:
        """Extend a current authority claim without reviving stale work."""
        with self.session() as session:
            result = session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == job.lease_owner,
                    AuthorityJob.state == "pending",
                )
                .values(lease_until=utcnow() + timedelta(seconds=lease_seconds))
            )
            return getattr(result, "rowcount", 0) == 1

    def complete_authority(self, job: ClaimedAuthorityJob, owner: str) -> None:
        """Delete completed authority work or release a superseded generation."""
        with self.session() as session:
            removed = session.execute(
                delete(AuthorityJob).where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == owner,
                )
            )
            if getattr(removed, "rowcount", 0) == 0:
                session.execute(
                    update(AuthorityJob)
                    .where(AuthorityJob.id == job.id, AuthorityJob.lease_owner == owner)
                    .values(lease_owner=None, lease_until=None)
                )

    def fail_authority(
        self,
        job: ClaimedAuthorityJob,
        owner: str,
        error: str,
        max_delay_seconds: int,
    ) -> None:
        """Retry authority fan-out indefinitely with bounded exponential backoff."""
        delay_seconds = max(1, min(max_delay_seconds, 2 ** min(job.attempts, 30)))
        with self.session() as session:
            result = session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == owner,
                )
                .values(
                    state="pending",
                    available_at=utcnow() + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            if getattr(result, "rowcount", 0) == 0:
                session.execute(
                    update(AuthorityJob)
                    .where(AuthorityJob.id == job.id, AuthorityJob.lease_owner == owner)
                    .values(lease_owner=None, lease_until=None)
                )

    def defer_authority(
        self,
        job: ClaimedAuthorityJob,
        owner: str,
        error: str,
        delay_seconds: int,
    ) -> bool:
        """Defer a rate-limited fan-out without consuming its retry budget."""
        delay_seconds = max(1, min(delay_seconds, 86_400))
        with self.session() as session:
            result = session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == owner,
                )
                .values(
                    attempts=case(
                        (AuthorityJob.attempts > 0, AuthorityJob.attempts - 1),
                        else_=0,
                    ),
                    available_at=utcnow() + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            updated = getattr(result, "rowcount", 0) == 1
            if not updated:
                session.execute(
                    update(AuthorityJob)
                    .where(AuthorityJob.id == job.id, AuthorityJob.lease_owner == owner)
                    .values(lease_owner=None, lease_until=None)
                )
            return updated

    def complete(self, job: ClaimedJob, owner: str) -> None:
        """Delete completed work or release a superseded generation."""
        with self.session() as session:
            removed = session.execute(
                delete(EvaluationJob).where(
                    EvaluationJob.id == job.id,
                    EvaluationJob.generation == job.generation,
                    EvaluationJob.lease_owner == owner,
                )
            )
            if getattr(removed, "rowcount", 0) == 0:
                session.execute(
                    update(EvaluationJob)
                    .where(EvaluationJob.id == job.id, EvaluationJob.lease_owner == owner)
                    .values(lease_owner=None, lease_until=None)
                )

    def fail(
        self,
        job: ClaimedJob,
        owner: str,
        error: str,
        max_delay_seconds: int,
    ) -> None:
        """Retry evaluation indefinitely with bounded exponential backoff."""
        delay_seconds = max(1, min(max_delay_seconds, 2 ** min(job.attempts, 30)))
        with self.session() as session:
            result = session.execute(
                update(EvaluationJob)
                .where(
                    EvaluationJob.id == job.id,
                    EvaluationJob.generation == job.generation,
                    EvaluationJob.lease_owner == owner,
                )
                .values(
                    state="pending",
                    available_at=utcnow() + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            if getattr(result, "rowcount", 0) == 0:
                session.execute(
                    update(EvaluationJob)
                    .where(EvaluationJob.id == job.id, EvaluationJob.lease_owner == owner)
                    .values(lease_owner=None, lease_until=None)
                )

    def defer(self, job: ClaimedJob, owner: str, error: str, delay_seconds: int) -> bool:
        """Release a claim until a provider-supplied retry time without spending an attempt."""
        delay_seconds = max(1, min(delay_seconds, 86_400))
        with self.session() as session:
            result = session.execute(
                update(EvaluationJob)
                .where(
                    EvaluationJob.id == job.id,
                    EvaluationJob.generation == job.generation,
                    EvaluationJob.lease_owner == owner,
                )
                .values(
                    attempts=case(
                        (EvaluationJob.attempts > 0, EvaluationJob.attempts - 1),
                        else_=0,
                    ),
                    available_at=utcnow() + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            updated = getattr(result, "rowcount", 0) == 1
            if not updated:
                session.execute(
                    update(EvaluationJob)
                    .where(EvaluationJob.id == job.id, EvaluationJob.lease_owner == owner)
                    .values(lease_owner=None, lease_until=None)
                )
            return updated

    def acquire_service_lease(self, name: str, owner: str, lease_seconds: int) -> bool:
        """Atomically acquire or renew a named cross-process lease."""
        for _ in range(3):
            now = utcnow()
            lease_until = now + timedelta(seconds=lease_seconds)
            try:
                with self.session() as session:
                    renewed = session.execute(
                        update(ServiceLease)
                        .where(
                            ServiceLease.name == name,
                            or_(ServiceLease.owner == owner, ServiceLease.lease_until <= now),
                        )
                        .values(owner=owner, lease_until=lease_until)
                    )
                    if getattr(renewed, "rowcount", 0) == 1:
                        return True

                    existing = session.scalar(
                        select(ServiceLease.name).where(ServiceLease.name == name)
                    )
                    if existing is not None:
                        return False
                    session.add(ServiceLease(name=name, owner=owner, lease_until=lease_until))
                return True
            except IntegrityError:
                # Two first-time contenders may race to insert the primary key.
                # Retry through the conditional UPDATE after the winner commits.
                continue
        return False

    def release_service_lease(self, name: str, owner: str) -> bool:
        """Release a named lease only while it still belongs to the caller."""
        with self.session() as session:
            released = session.execute(
                delete(ServiceLease).where(
                    ServiceLease.name == name,
                    ServiceLease.owner == owner,
                )
            )
            return getattr(released, "rowcount", 0) == 1

    def pending_count(self) -> int:
        """Return queued and leased pending work count."""
        with self._sessions() as session:
            evaluations = int(
                session.scalar(
                    select(func.count())
                    .select_from(EvaluationJob)
                    .where(EvaluationJob.state == "pending")
                )
                or 0
            )
            authorities = int(
                session.scalar(
                    select(func.count())
                    .select_from(AuthorityJob)
                    .where(AuthorityJob.state == "pending")
                )
                or 0
            )
            shared_heads = int(
                session.scalar(
                    select(func.count())
                    .select_from(SharedHeadEpoch)
                    .where(SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation)
                )
                or 0
            )
            return evaluations + authorities + shared_heads

    def pending_shared_head_invalidation_count(self) -> int:
        """Return exact-head generations still awaiting a durable reset."""
        with self._sessions() as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(SharedHeadEpoch)
                    .where(SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation)
                )
                or 0
            )

    def dead_count(self) -> int:
        """Return legacy terminal rows, which startup normally reactivates."""
        with self._sessions() as session:
            evaluations = int(
                session.scalar(
                    select(func.count())
                    .select_from(EvaluationJob)
                    .where(EvaluationJob.state == "dead")
                )
                or 0
            )
            authorities = int(
                session.scalar(
                    select(func.count())
                    .select_from(AuthorityJob)
                    .where(AuthorityJob.state == "dead")
                )
                or 0
            )
            return evaluations + authorities

    def requeue_dead(self, limit: int = 100) -> int:
        """Recover legacy/manual terminal rows, prioritizing authority work."""
        with self.session() as session:
            authority_ids = tuple(
                session.scalars(
                    select(AuthorityJob.id)
                    .where(AuthorityJob.state == "dead")
                    .order_by(AuthorityJob.requested_at, AuthorityJob.id)
                    .limit(limit)
                )
            )
            authority_count = 0
            if authority_ids:
                authority_result = session.execute(
                    update(AuthorityJob)
                    .where(AuthorityJob.id.in_(authority_ids))
                    .values(
                        state="pending",
                        attempts=0,
                        available_at=utcnow(),
                        last_error=None,
                        lease_owner=None,
                        lease_until=None,
                    )
                )
                authority_count = int(getattr(authority_result, "rowcount", 0) or 0)
            remaining = max(0, limit - authority_count)
            ids = tuple(
                session.scalars(
                    select(EvaluationJob.id)
                    .where(EvaluationJob.state == "dead")
                    .order_by(EvaluationJob.requested_at, EvaluationJob.id)
                    .limit(remaining)
                )
            )
            evaluation_count = 0
            if ids:
                result = session.execute(
                    update(EvaluationJob)
                    .where(EvaluationJob.id.in_(ids))
                    .values(
                        state="pending",
                        attempts=0,
                        available_at=utcnow(),
                        last_error=None,
                        lease_owner=None,
                        lease_until=None,
                    )
                )
                evaluation_count = int(getattr(result, "rowcount", 0) or 0)
            return evaluation_count + authority_count

    def prune_deliveries(self, older_than: datetime) -> int:
        """Remove delivery de-duplication records older than a retention boundary."""
        with self.session() as session:
            result = session.execute(
                delete(WebhookDelivery).where(WebhookDelivery.received_at < older_than)
            )
            return int(getattr(result, "rowcount", 0) or 0)

    def prune_shared_head_epochs(self, older_than: datetime) -> int:
        """Remove old head fences after every referencing job has finished."""
        with self.session() as session:
            referenced = exists(
                select(EvaluationJob.id).where(
                    EvaluationJob.installation_id == SharedHeadEpoch.installation_id,
                    EvaluationJob.repository_full_name == SharedHeadEpoch.repository_full_name,
                    EvaluationJob.head_sha_hint == SharedHeadEpoch.head_sha,
                )
            )
            result = session.execute(
                delete(SharedHeadEpoch).where(
                    SharedHeadEpoch.changed_at < older_than,
                    SharedHeadEpoch.invalidated_generation == SharedHeadEpoch.generation,
                    SharedHeadEpoch.lease_owner.is_(None),
                    SharedHeadEpoch.lease_until.is_(None),
                    ~referenced,
                )
            )
            return int(getattr(result, "rowcount", 0) or 0)

    def record_audit(
        self,
        repository_full_name: str,
        pull_number: int,
        head_sha: str,
        conclusion: str,
        details: dict[str, Any],
    ) -> None:
        """Upsert the most recent evaluation evidence."""
        with self.session() as session:
            row = session.scalar(
                select(EvaluationAudit).where(
                    EvaluationAudit.repository_full_name == repository_full_name,
                    EvaluationAudit.pull_number == pull_number,
                )
            )
            if row is None:
                session.add(
                    EvaluationAudit(
                        repository_full_name=repository_full_name,
                        pull_number=pull_number,
                        head_sha=head_sha,
                        conclusion=conclusion,
                        details=details,
                    )
                )
            else:
                row.head_sha = head_sha
                row.conclusion = conclusion
                row.details = details
                row.evaluated_at = utcnow()

    def database_available(self) -> bool:
        """Test connectivity and schema compatibility for readiness checks."""
        try:
            with self._sessions() as session:
                revision = session.scalar(text("SELECT version_num FROM alembic_version"))
                if revision != DATABASE_MIGRATION_HEAD:
                    return False
                version = session.scalar(
                    select(SchemaMetadata.version).where(SchemaMetadata.singleton_id == 1)
                )
                if version != SCHEMA_VERSION:
                    return False
                session.execute(
                    select(
                        EvaluationJob.id,
                        EvaluationJob.generation,
                        EvaluationJob.shared_head_generation,
                        EvaluationJob.lease_owner,
                        AuthorityJob.generation,
                        SharedHeadEpoch.generation,
                        SharedHeadEpoch.invalidated_generation,
                        SharedHeadEpoch.lease_owner,
                        SharedHeadEpoch.lease_until,
                        WebhookDelivery.invalidation_required,
                        WebhookDelivery.invalidation_completed_at,
                        WebhookDelivery.shared_head_generation,
                    )
                    .select_from(EvaluationJob)
                    .join(
                        WebhookDelivery,
                        EvaluationJob.last_delivery_id == WebhookDelivery.delivery_id,
                        isouter=True,
                    )
                    .join(AuthorityJob, AuthorityJob.id == EvaluationJob.id, isouter=True)
                    .join(
                        SharedHeadEpoch,
                        (SharedHeadEpoch.installation_id == EvaluationJob.installation_id)
                        & (
                            SharedHeadEpoch.repository_full_name
                            == EvaluationJob.repository_full_name
                        )
                        & (SharedHeadEpoch.head_sha == EvaluationJob.head_sha_hint),
                        isouter=True,
                    )
                    .limit(1)
                )
            return True
        except Exception:
            return False
