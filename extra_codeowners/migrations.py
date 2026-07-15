"""Explicit, lock-serialized Alembic database migration orchestration."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine, UniqueConstraint, create_engine, inspect, select, text
from sqlalchemy.pool import NullPool

from extra_codeowners.database import (
    DATABASE_CONNECT_TIMEOUT_SECONDS,
    DATABASE_MIGRATION_HEAD,
    SCHEMA_VERSION,
    Base,
    SchemaMetadata,
)

# Signed BLAKE2b-64 of ``extra-codeowners\0database-migrations``. Keep this
# stable across every release so different migrator versions serialize.
MIGRATION_LOCK_KEY = 4_177_414_672_904_750_600
MIGRATION_STATEMENT_TIMEOUT_MILLISECONDS = 60_000
BASELINE_REVISION = "0001_initial_schema"
_LOCAL_MIGRATION_LOCK = threading.Lock()


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


def _application_tables() -> set[str]:
    return {table.name for table in Base.metadata.sorted_tables}


def _adopt_pre_alembic_schema(connection: Connection, config: Config) -> bool:
    inspector = inspect(connection)
    actual_tables = set(inspector.get_table_names())
    known_tables = actual_tables & _application_tables()
    if not known_tables:
        return False
    if known_tables != _application_tables():
        missing = sorted(_application_tables() - known_tables)
        raise RuntimeError(
            "refusing to adopt a partial pre-Alembic schema; missing tables: " + ", ".join(missing)
        )
    for table in Base.metadata.sorted_tables:
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
            expected_affinity = expected_column.type._type_affinity
            expected_length = getattr(expected_column.type, "length", None)
            actual_length = getattr(actual_type, "length", None)
            if (
                expected_affinity is None
                or not isinstance(actual_type, expected_affinity)
                or expected_length != actual_length
                or bool(actual_column["nullable"]) != bool(expected_column.nullable)
            ):
                raise RuntimeError(
                    f"refusing to adopt pre-Alembic column "
                    f"{table.name}.{expected_column.name}: type, length, or nullability differs"
                )
        expected_primary_key = {column.name for column in table.primary_key.columns}
        actual_primary_key = set(inspector.get_pk_constraint(table.name)["constrained_columns"])
        if actual_primary_key != expected_primary_key:
            raise RuntimeError(
                f"refusing to adopt pre-Alembic table {table.name!r}: expected primary key "
                f"{sorted(expected_primary_key)!r}, found {sorted(actual_primary_key)!r}"
            )
        expected_indexes = {str(index.name) for index in table.indexes if index.name is not None}
        actual_indexes = {
            str(index["name"])
            for index in inspector.get_indexes(table.name)
            if index["name"] is not None
        }
        if not expected_indexes <= actual_indexes:
            raise RuntimeError(
                f"refusing to adopt pre-Alembic table {table.name!r}: missing indexes "
                f"{sorted(expected_indexes - actual_indexes)!r}"
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
        if not expected_uniques <= actual_uniques:
            raise RuntimeError(
                f"refusing to adopt pre-Alembic table {table.name!r}: missing unique constraints "
                f"{sorted(expected_uniques - actual_uniques)!r}"
            )
    version = connection.scalar(
        select(SchemaMetadata.version).where(SchemaMetadata.singleton_id == 1)
    )
    if version != SCHEMA_VERSION:
        raise RuntimeError(
            f"refusing to adopt pre-Alembic schema marker {version!r}; expected {SCHEMA_VERSION}"
        )
    connection.commit()
    command.stamp(config, BASELINE_REVISION)
    connection.commit()
    return True


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
            known_tables = set(inspect(connection).get_table_names()) & _application_tables()
            if current is None and known_tables:
                if not adopt_pre_alembic_schema:
                    raise RuntimeError(
                        "database contains a pre-Alembic Extra CODEOWNERS schema; back it up, "
                        "then rerun with --adopt-pre-alembic-schema after reviewing the "
                        "pre-release adoption procedure"
                    )
                _adopt_pre_alembic_schema(connection, config)
            # Inspector and revision queries autobegin a transaction. End that
            # read transaction so Alembic owns and commits the migration one.
            connection.commit()
            _apply_upgrade(config, revision)
            connection.commit()
    finally:
        engine.dispose()
