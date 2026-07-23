"""Durable evaluation queue and delivery de-duplication storage."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
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
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import NullPool

SCHEMA_VERSION = 2
DATABASE_MIGRATION_HEAD = "0003_shared_head_epochs"
DATABASE_CONNECT_TIMEOUT_SECONDS = 3
DATABASE_POOL_TIMEOUT_SECONDS = 2
DATABASE_STATEMENT_TIMEOUT_MILLISECONDS = 3_000
MAX_BASE_SCOPED_AUTHORITY_JOBS_PER_REPOSITORY = 100


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
    __table_args__ = (Index("ix_shared_head_epochs_changed_at", "changed_at"),)

    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_full_name: Mapped[str] = mapped_column(String(512), primary_key=True)
    head_sha: Mapped[str] = mapped_column(String(64), primary_key=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


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
class CheckWriteGuard:
    """Held per-pull-request GitHub check writer guard."""

    key: int
    connection: Connection | None = None
    local_lock: threading.Lock | None = None
    shared: bool = False


class _EvaluationJobAlreadyPresentError(Exception):
    """Abort reconciliation so a tentative shared-head epoch bump rolls back."""


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
                "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
                "options": f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MILLISECONDS}",
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
                    "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
                    "options": f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MILLISECONDS}",
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
        inspector = inspect(self.engine)
        dialect_name = self.engine.dialect.name
        tables = set(inspector.get_table_names())
        if "alembic_version" not in tables:
            raise RuntimeError(
                "database has not been migrated; run `extra-codeowners database migrate`"
            )
        with self.engine.connect() as connection:
            revisions = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalars()
            current_revisions = tuple(revisions)
        if current_revisions != (DATABASE_MIGRATION_HEAD,):
            raise RuntimeError(
                f"database migration revision {current_revisions!r} is incompatible with "
                f"required revision {DATABASE_MIGRATION_HEAD!r}; run "
                "`extra-codeowners database migrate`"
            )
        actual_serials: dict[tuple[str, str], str | None] = {}
        if dialect_name == "postgresql":
            with self.engine.connect() as connection:
                for table in Base.metadata.sorted_tables:
                    generated_column = table.autoincrement_column
                    if generated_column is not None:
                        actual_serials[(table.name, generated_column.name)] = connection.scalar(
                            text("SELECT pg_get_serial_sequence(:table_name, :column_name)"),
                            {
                                "table_name": table.name,
                                "column_name": generated_column.name,
                            },
                        )
        for table in Base.metadata.sorted_tables:
            if table.name not in tables:
                raise RuntimeError(f"database schema is missing table {table.name!r}")
            inspected_columns = inspector.get_columns(table.name)
            actual_columns = {column["name"] for column in inspected_columns}
            expected_columns = {column.name for column in table.columns}
            missing = expected_columns - actual_columns
            if missing:
                raise RuntimeError(
                    f"database table {table.name!r} is missing columns {sorted(missing)!r}"
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
                        and actual_default in allowed_defaults
                        and actual_identity is None
                        and actual_computed is None
                        and actual_autoincrement
                    )
                elif dialect_name == "sqlite" and expected_generated:
                    generation_matches = (
                        actual_default is None
                        and actual_identity is None
                        and actual_computed is None
                    )
                if not generation_matches:
                    raise RuntimeError(
                        f"database column {table.name}.{expected_column.name} has incompatible "
                        "default, owned sequence, identity, computed value, or autoincrement "
                        "behavior"
                    )
            expected_primary_key = {column.name for column in table.primary_key.columns}
            actual_primary_key = set(inspector.get_pk_constraint(table.name)["constrained_columns"])
            if actual_primary_key != expected_primary_key:
                raise RuntimeError(
                    f"database table {table.name!r} has incompatible primary key "
                    f"{sorted(actual_primary_key)!r}; expected {sorted(expected_primary_key)!r}"
                )
            expected_indexes = {
                str(index.name) for index in table.indexes if index.name is not None
            }
            actual_indexes = {
                str(index["name"])
                for index in inspector.get_indexes(table.name)
                if index["name"] is not None
            }
            missing_indexes = expected_indexes - actual_indexes
            if missing_indexes:
                raise RuntimeError(
                    f"database table {table.name!r} is missing indexes {sorted(missing_indexes)!r}"
                )
            expected_uniques = {
                str(constraint.name)
                for constraint in table.constraints
                if isinstance(constraint, UniqueConstraint) and constraint.name is not None
            }
            actual_uniques = {
                str(constraint["name"])
                for constraint in inspector.get_unique_constraints(table.name)
                if constraint["name"] is not None
            }
            missing_uniques = expected_uniques - actual_uniques
            if missing_uniques:
                raise RuntimeError(
                    f"database table {table.name!r} is missing unique constraints "
                    f"{sorted(missing_uniques)!r}"
                )
        with self._sessions() as session:
            version = session.scalar(
                select(SchemaMetadata.version).where(SchemaMetadata.singleton_id == 1)
            )
        if version != SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {version!r} is incompatible with required version "
                f"{SCHEMA_VERSION}"
            )

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
            changed_at=now,
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
        updated = session.execute(
            update(EvaluationJob)
            .where(
                EvaluationJob.installation_id == request.installation_id,
                EvaluationJob.repository_full_name == request.repository_full_name,
                EvaluationJob.pull_number == request.pull_number,
            )
            .values(**values)
        )
        if getattr(updated, "rowcount", 0) == 1:
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
        """Enqueue an evaluation, coalescing repeated triggers."""
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
        """Atomically advance a live-head fence and enqueue an internal trigger."""
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
    ) -> bool:
        """Record and enqueue one webhook atomically.

        Returns ``False`` for a previously accepted GitHub delivery.
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
                        if session.get(WebhookDelivery, delivery_id) is not None:
                            return False
                        session.add(
                            WebhookDelivery(
                                delivery_id=delivery_id,
                                event=event,
                                invalidation_required=isinstance(request, JobRequest),
                            )
                        )
                        if isinstance(request, JobRequest):
                            shared_head_generation = self._advance_shared_head_epoch_in_session(
                                session, request
                            )
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
                    return True
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
        Reconciliation and internal fan-out can lack a trustworthy webhook
        head, so they capture the durable epoch after fetching current state.
        """
        head_sha = validate_head_sha(head_sha)
        if job.head_sha_hint is not None:
            return job if job.head_sha_hint == head_sha else None
        with self.session() as session:
            shared_head_generation = self._shared_head_generation_in_session(
                session,
                job.installation_id,
                job.repository_full_name,
                head_sha,
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
            return evaluations + authorities

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
                        WebhookDelivery.invalidation_required,
                        WebhookDelivery.invalidation_completed_at,
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
