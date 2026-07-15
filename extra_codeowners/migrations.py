"""Explicit, lock-serialized Alembic database migration orchestration."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import (
    JSON,
    Boolean,
    Connection,
    DateTime,
    Engine,
    Integer,
    String,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.pool import NullPool

from extra_codeowners import __version__
from extra_codeowners.database import (
    DATABASE_CONNECT_TIMEOUT_SECONDS,
    DATABASE_MIGRATION_HEAD,
)

# Signed BLAKE2b-64 of ``extra-codeowners\0database-migrations``. Keep this
# stable across every release so different migrator versions serialize.
MIGRATION_LOCK_KEY = 4_177_414_672_904_750_600
MIGRATION_STATEMENT_TIMEOUT_MILLISECONDS = 60_000
BASELINE_REVISION = "0001_initial_schema"
PRE_ALEMBIC_ADOPTION_RELEASE = "0.1.0"
PRE_ALEMBIC_SCHEMA_MARKER = 1
_LOCAL_MIGRATION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _BaselineColumn:
    """One immutable column in the pre-Alembic 0.1 schema contract."""

    name: str
    type_affinity: type[object]
    length: int | None
    nullable: bool
    timezone: bool | None
    generated_sequence: str | None


@dataclass(frozen=True, slots=True)
class _BaselineKey:
    """One immutable named index or unique constraint."""

    name: str
    columns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _BaselineTable:
    """One immutable table in the pre-Alembic 0.1 schema contract."""

    name: str
    columns: tuple[_BaselineColumn, ...]
    primary_key: frozenset[str]
    indexes: tuple[_BaselineKey, ...] = ()
    unique_constraints: tuple[_BaselineKey, ...] = ()


def _column(
    name: str,
    type_affinity: type[object],
    *,
    length: int | None = None,
    nullable: bool = False,
    timezone: bool | None = None,
    generated_sequence: str | None = None,
) -> _BaselineColumn:
    return _BaselineColumn(
        name,
        type_affinity,
        length,
        nullable,
        timezone,
        generated_sequence,
    )


# Do not derive this contract from Base.metadata. This is the exact schema made
# by pre-Alembic 0.1 builds and represented by revision 0001. Future ORM or
# migration changes must not silently broaden the one-time adoption boundary.
_PRE_ALEMBIC_0_1_BASELINE = (
    _BaselineTable(
        "schema_metadata",
        (
            _column("singleton_id", Integer),
            _column("version", Integer),
        ),
        frozenset({"singleton_id"}),
    ),
    _BaselineTable(
        "evaluation_jobs",
        (
            _column("id", Integer, generated_sequence="evaluation_jobs_id_seq"),
            _column("installation_id", Integer),
            _column("repository_full_name", String, length=512),
            _column("pull_number", Integer),
            _column("head_sha_hint", String, length=64, nullable=True),
            _column("last_delivery_id", String, length=128, nullable=True),
            _column("reason", String, length=255),
            _column("generation", Integer),
            _column("authority_generation", Integer),
            _column("state", String, length=16),
            _column("attempts", Integer),
            _column("requested_at", DateTime, timezone=True),
            _column("available_at", DateTime, timezone=True),
            _column("lease_owner", String, length=128, nullable=True),
            _column("lease_until", DateTime, nullable=True, timezone=True),
            _column("last_error", String, length=2000, nullable=True),
        ),
        frozenset({"id"}),
        (_BaselineKey("ix_evaluation_jobs_claim", ("state", "available_at", "lease_until")),),
        (
            _BaselineKey(
                "uq_evaluation_job_pr",
                ("installation_id", "repository_full_name", "pull_number"),
            ),
        ),
    ),
    _BaselineTable(
        "webhook_deliveries",
        (
            _column("delivery_id", String, length=128),
            _column("event", String, length=128),
            _column("received_at", DateTime, timezone=True),
            _column("invalidation_required", Boolean),
            _column("invalidation_completed_at", DateTime, nullable=True, timezone=True),
        ),
        frozenset({"delivery_id"}),
        (_BaselineKey("ix_webhook_deliveries_received_at", ("received_at",)),),
    ),
    _BaselineTable(
        "evaluation_audits",
        (
            _column("id", Integer, generated_sequence="evaluation_audits_id_seq"),
            _column("repository_full_name", String, length=512),
            _column("pull_number", Integer),
            _column("head_sha", String, length=64),
            _column("conclusion", String, length=32),
            _column("details", JSON),
            _column("evaluated_at", DateTime, timezone=True),
        ),
        frozenset({"id"}),
        unique_constraints=(
            _BaselineKey(
                "uq_evaluation_audit_pr",
                ("repository_full_name", "pull_number"),
            ),
        ),
    ),
    _BaselineTable(
        "service_leases",
        (
            _column("name", String, length=128),
            _column("owner", String, length=128),
            _column("lease_until", DateTime, timezone=True),
        ),
        frozenset({"name"}),
    ),
    _BaselineTable(
        "authority_jobs",
        (
            _column("id", Integer, generated_sequence="authority_jobs_id_seq"),
            _column("installation_id", Integer),
            _column("scope_key", String, length=512),
            _column("base_ref", String, length=255),
            _column("reason", String, length=255),
            _column("generation", Integer),
            _column("state", String, length=16),
            _column("attempts", Integer),
            _column("requested_at", DateTime, timezone=True),
            _column("available_at", DateTime, timezone=True),
            _column("lease_owner", String, length=128, nullable=True),
            _column("lease_until", DateTime, nullable=True, timezone=True),
            _column("last_error", String, length=2000, nullable=True),
        ),
        frozenset({"id"}),
        (_BaselineKey("ix_authority_jobs_claim", ("state", "available_at", "lease_until")),),
        (
            _BaselineKey(
                "uq_authority_job_scope",
                ("installation_id", "scope_key", "base_ref"),
            ),
        ),
    ),
    _BaselineTable(
        "authority_epochs",
        (
            _column(
                "installation_id",
                Integer,
                generated_sequence="authority_epochs_installation_id_seq",
            ),
            _column("generation", Integer),
            _column("changed_at", DateTime, timezone=True),
        ),
        frozenset({"installation_id"}),
    ),
)


def _engine(database_url: str) -> Engine:
    connect_args: dict[str, object]
    if database_url.startswith("postgresql"):
        connect_args = {
            "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
            "options": f"-c statement_timeout={MIGRATION_STATEMENT_TIMEOUT_MILLISECONDS}",
        }
    elif database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    else:
        connect_args = {}
    return create_engine(
        database_url,
        connect_args=connect_args,
        poolclass=NullPool,
        pool_pre_ping=True,
    )


def _config(connection: Connection) -> Config:
    config = Config()
    config.set_main_option(
        "script_location",
        str(Path(__file__).with_name("alembic")),
    )
    config.attributes["connection"] = connection
    return config


def expected_revision() -> str:
    """Return the single migration head bundled with this installation."""
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).with_name("alembic")))
    head = ScriptDirectory.from_config(config).get_current_head()
    if head is None or head != DATABASE_MIGRATION_HEAD:
        raise RuntimeError(
            f"packaged migration head {head!r} does not match application head "
            f"{DATABASE_MIGRATION_HEAD!r}"
        )
    return head


def current_revision(database_url: str) -> str | None:
    """Return the database's current Alembic revision without changing it."""
    engine = _engine(database_url)
    try:
        with engine.connect() as connection:
            return MigrationContext.configure(connection).get_current_revision()
    finally:
        engine.dispose()


@contextmanager
def _migration_guard(connection: Connection, timeout_seconds: float) -> Iterator[None]:
    if not 0 < timeout_seconds <= 300:
        raise ValueError("migration lock timeout must be greater than 0 and at most 300 seconds")

    acquired = False
    if connection.dialect.name == "postgresql":
        deadline = time.monotonic() + timeout_seconds
        while True:
            acquired = bool(
                connection.scalar(
                    text("SELECT pg_try_advisory_lock(:key)"),
                    {"key": MIGRATION_LOCK_KEY},
                )
            )
            connection.commit()
            if acquired:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"timed out after {timeout_seconds:g}s waiting for the database migration lock"
                )
            time.sleep(min(0.1, remaining))
    else:
        acquired = _LOCAL_MIGRATION_LOCK.acquire(timeout=timeout_seconds)
        if not acquired:
            raise TimeoutError(
                f"timed out after {timeout_seconds:g}s waiting for the local migration lock"
            )

    try:
        yield
    finally:
        if connection.dialect.name == "postgresql" and acquired:
            try:
                connection.rollback()
                connection.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": MIGRATION_LOCK_KEY},
                )
                connection.commit()
            except Exception:
                # Closing the NullPool connection below is the authoritative
                # lock release if the explicit unlock cannot be confirmed.
                connection.invalidate()
        elif acquired:
            _LOCAL_MIGRATION_LOCK.release()


def _baseline_tables() -> frozenset[str]:
    return frozenset(table.name for table in _PRE_ALEMBIC_0_1_BASELINE)


def _has_unexpected_index_options(index: Mapping[str, object]) -> bool:
    """Return whether an inspected index has non-baseline behavior."""
    if index.get("include_columns") or index.get("column_sorting") or index.get("expressions"):
        return True
    dialect_options = index.get("dialect_options")
    if not isinstance(dialect_options, Mapping):
        return dialect_options is not None
    for name, value in dialect_options.items():
        if name == "postgresql_include" and (value is None or value == [] or value == ()):
            continue
        return True
    return False


def _adopt_pre_alembic_schema(connection: Connection, config: Config) -> None:
    if __version__ != PRE_ALEMBIC_ADOPTION_RELEASE:
        raise RuntimeError(
            "pre-Alembic adoption is available only from the 0.1.0 artifact; "
            "use that artifact to adopt the immutable baseline before upgrading"
        )
    inspector = inspect(connection)
    dialect_name = connection.dialect.name
    if dialect_name not in {"postgresql", "sqlite"}:
        raise RuntimeError(
            f"pre-Alembic adoption does not support database dialect {dialect_name!r}"
        )
    actual_tables = set(inspector.get_table_names())
    baseline_tables = _baseline_tables()
    if actual_tables != baseline_tables:
        missing = sorted(baseline_tables - actual_tables)
        unexpected = sorted(actual_tables - baseline_tables)
        raise RuntimeError(
            "refusing to adopt a non-baseline pre-Alembic schema; "
            f"missing tables: {missing!r}; unexpected tables: {unexpected!r}"
        )
    for table in _PRE_ALEMBIC_0_1_BASELINE:
        expected_columns = {column.name for column in table.columns}
        inspected_columns = inspector.get_columns(table.name)
        actual_columns = {column["name"] for column in inspected_columns}
        if actual_columns != expected_columns:
            raise RuntimeError(
                f"refusing to adopt pre-Alembic table {table.name!r}: expected columns "
                f"{sorted(expected_columns)!r}, found {sorted(actual_columns)!r}"
            )
        actual_by_name = {column["name"]: column for column in inspected_columns}
        for expected_column in table.columns:
            actual_column = actual_by_name[expected_column.name]
            actual_type = actual_column["type"]
            actual_length = getattr(actual_type, "length", None)
            actual_timezone = getattr(actual_type, "timezone", None)
            if (
                not isinstance(actual_type, expected_column.type_affinity)
                or expected_column.length != actual_length
                or bool(actual_column["nullable"]) != expected_column.nullable
                or (
                    dialect_name == "postgresql"
                    and expected_column.timezone is not None
                    and actual_timezone != expected_column.timezone
                )
            ):
                raise RuntimeError(
                    f"refusing to adopt pre-Alembic column "
                    f"{table.name}.{expected_column.name}: type, length, timezone, or "
                    "nullability differs"
                )
            actual_default = actual_column.get("default")
            actual_identity = actual_column.get("identity")
            actual_computed = actual_column.get("computed")
            actual_autoincrement = bool(actual_column.get("autoincrement"))
            generation_matches = (
                actual_default is None
                and actual_identity is None
                and actual_computed is None
                and not actual_autoincrement
            )
            if dialect_name == "postgresql" and expected_column.generated_sequence is not None:
                default_schema = inspector.default_schema_name
                expected_serial = (
                    f"{default_schema}.{expected_column.generated_sequence}"
                    if default_schema
                    else expected_column.generated_sequence
                )
                actual_serial = connection.scalar(
                    text("SELECT pg_get_serial_sequence(:table_name, :column_name)"),
                    {"table_name": table.name, "column_name": expected_column.name},
                )
                allowed_defaults = {
                    f"nextval('{expected_column.generated_sequence}'::regclass)",
                    f"nextval('{expected_serial}'::regclass)",
                }
                generation_matches = (
                    actual_serial == expected_serial
                    and actual_default in allowed_defaults
                    and actual_identity is None
                    and actual_computed is None
                    and actual_autoincrement
                )
            elif dialect_name == "sqlite" and expected_column.generated_sequence is not None:
                # SQLite represents integer-primary-key generation without a
                # reflected server default or identity object.
                generation_matches = (
                    actual_default is None and actual_identity is None and actual_computed is None
                )
            if not generation_matches:
                raise RuntimeError(
                    f"refusing to adopt pre-Alembic column "
                    f"{table.name}.{expected_column.name}: default, owned sequence, identity, "
                    "computed value, or autoincrement behavior differs"
                )
        actual_primary_key = set(inspector.get_pk_constraint(table.name)["constrained_columns"])
        if actual_primary_key != table.primary_key:
            raise RuntimeError(
                f"refusing to adopt pre-Alembic table {table.name!r}: expected primary key "
                f"{sorted(table.primary_key)!r}, found {sorted(actual_primary_key)!r}"
            )
        expected_indexes = {index.name: (index.columns, False) for index in table.indexes}
        actual_indexes: dict[str, tuple[tuple[str, ...], bool]] = {}
        for index in inspector.get_indexes(table.name):
            if index["name"] is None or index.get("duplicates_constraint") is not None:
                continue
            if _has_unexpected_index_options(index):
                raise RuntimeError(
                    f"refusing to adopt pre-Alembic index {index['name']!r} on "
                    f"table {table.name!r}: included columns, expressions, ordering, "
                    "predicates, or dialect options differ"
                )
            actual_indexes[str(index["name"])] = (
                tuple(str(column) for column in index["column_names"]),
                bool(index["unique"]),
            )
        if actual_indexes != expected_indexes:
            raise RuntimeError(
                f"refusing to adopt pre-Alembic table {table.name!r}: expected indexes "
                f"{expected_indexes!r}, found {actual_indexes!r}"
            )
        expected_uniques = {
            constraint.name: constraint.columns for constraint in table.unique_constraints
        }
        actual_uniques = {
            str(constraint["name"]): tuple(str(column) for column in constraint["column_names"])
            for constraint in inspector.get_unique_constraints(table.name)
            if constraint["name"] is not None
        }
        if actual_uniques != expected_uniques:
            raise RuntimeError(
                f"refusing to adopt pre-Alembic table {table.name!r}: expected unique "
                f"constraints {expected_uniques!r}, found {actual_uniques!r}"
            )
        foreign_keys = inspector.get_foreign_keys(table.name)
        check_constraints = inspector.get_check_constraints(table.name)
        if foreign_keys or check_constraints:
            raise RuntimeError(
                f"refusing to adopt pre-Alembic table {table.name!r}: baseline has no "
                "foreign-key or check constraints"
            )
    marker_rows = tuple(
        tuple(row)
        for row in connection.execute(
            text("SELECT singleton_id, version FROM schema_metadata ORDER BY singleton_id")
        )
    )
    expected_marker_rows = ((1, PRE_ALEMBIC_SCHEMA_MARKER),)
    if marker_rows != expected_marker_rows:
        raise RuntimeError(
            f"refusing to adopt pre-Alembic schema marker {marker_rows!r}; "
            f"expected {expected_marker_rows!r}"
        )
    connection.commit()
    command.stamp(config, BASELINE_REVISION)
    connection.commit()


def _apply_upgrade(config: Config, revision: str) -> None:
    """Apply migrations; isolated so interruption recovery is testable."""
    command.upgrade(config, revision)


def upgrade_database(
    database_url: str,
    *,
    lock_timeout_seconds: float = 60.0,
    adopt_pre_alembic_schema: bool = False,
    revision: str = "head",
) -> None:
    """Upgrade one database under a bounded cross-replica lock.

    ``revision`` exists to exercise upgrade boundaries in tests. Operator-facing
    commands always target ``head``.
    """
    expected_revision()
    engine = _engine(database_url)
    try:
        with engine.connect() as connection, _migration_guard(connection, lock_timeout_seconds):
            config = _config(connection)
            migration_context = MigrationContext.configure(connection)
            current = migration_context.get_current_revision()
            unversioned_tables = set(inspect(connection).get_table_names())
            if current is None and unversioned_tables:
                if not adopt_pre_alembic_schema:
                    raise RuntimeError(
                        "database contains an unversioned schema; back it up, then rerun with "
                        "--adopt-pre-alembic-schema only for the exact documented 0.1 "
                        "pre-Alembic baseline"
                    )
                _adopt_pre_alembic_schema(connection, config)
            # Inspector and revision queries autobegin a transaction. End that
            # read transaction so Alembic owns and commits the migration one.
            connection.commit()
            _apply_upgrade(config, revision)
            connection.commit()
    finally:
        engine.dispose()
