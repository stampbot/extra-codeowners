from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from extra_codeowners.database import (
    DATABASE_MIGRATION_HEAD,
    Base,
    InstallationApiBudget,
    QueueStore,
    utcnow,
)
from extra_codeowners.migrations import current_revision, upgrade_database


@pytest.fixture(params=["sqlite", "postgresql"])
def migration_url(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[str]:
    if request.param == "postgresql":
        request.node.add_marker(pytest.mark.integration)
        url = os.environ.get("TEST_POSTGRES_URL", "")
        if not url:
            pytest.skip("TEST_POSTGRES_URL is not configured")
        database = make_url(url).database
        assert database is not None and database.endswith("_test")
    else:
        url = f"sqlite:///{tmp_path / 'conditional-migration.db'}"
    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    engine.dispose()
    yield url


def test_upgrade_0008_budget_rows_backfills_revision_and_preserves_state(
    migration_url: str,
) -> None:
    upgrade_database(migration_url, revision="0008_recovery_api_budget")
    now = utcnow().replace(microsecond=0)
    reset_at = now + timedelta(hours=1)
    engine = create_engine(migration_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO installation_api_budgets
                    (installation_id, request_limit, remaining, reset_at,
                     probe_after, repository_cursor)
                VALUES (:installation_id, :request_limit, :remaining, :reset_at,
                        :probe_after, :repository_cursor)
                """
            ),
            {
                "installation_id": 17,
                "request_limit": 100,
                "remaining": 41,
                "reset_at": reset_at,
                "probe_after": now,
                "repository_cursor": "acme/project",
            },
        )
    engine.dispose()

    assert current_revision(migration_url) == "0008_recovery_api_budget"
    old_store = QueueStore(migration_url)
    with pytest.raises(RuntimeError, match="required revision"):
        old_store.initialize()
    old_store.close()

    upgrade_database(migration_url)
    assert current_revision(migration_url) == DATABASE_MIGRATION_HEAD
    engine = create_engine(migration_url)
    with engine.connect() as connection:
        metadata_version = connection.scalar(
            text("SELECT version FROM schema_metadata WHERE singleton_id = 1")
        )
    columns = {
        column["name"]: column for column in inspect(engine).get_columns("installation_api_budgets")
    }
    engine.dispose()

    store = QueueStore(migration_url)
    with store.session() as session:
        values = session.get(InstallationApiBudget, 17)
        assert values is not None
        assert values.request_limit == 100
        assert values.remaining == 41
        assert values.reset_at == reset_at
        assert values.probe_after == now
        assert values.repository_cursor == "acme/project"
        assert values.accounting_revision == 0
    store.close()

    assert metadata_version == 8
    assert columns["accounting_revision"]["nullable"] is False

    store = QueueStore(migration_url)
    store.initialize()
    store.close()
