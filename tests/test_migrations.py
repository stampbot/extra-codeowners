from __future__ import annotations

from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

import extra_codeowners.database as database
import extra_codeowners.migrations as migrations
from extra_codeowners.database import DATABASE_MIGRATION_HEAD, QueueStore
from extra_codeowners.migrations import (
    BASELINE_REVISION,
    current_revision,
    expected_revision,
    upgrade_database,
)


def database_url(tmp_path: Path, name: str = "migrations.db") -> str:
    return f"sqlite:///{tmp_path / name}"


def test_fresh_database_upgrades_to_packaged_head(tmp_path: Path) -> None:
    url = database_url(tmp_path)

    upgrade_database(url)

    assert expected_revision() == DATABASE_MIGRATION_HEAD
    assert current_revision(url) == DATABASE_MIGRATION_HEAD
    store = QueueStore(url)
    store.initialize()
    assert store.database_available() is True


def test_current_head_schema_drift_blocks_migration_success(tmp_path: Path) -> None:
    url = database_url(tmp_path, "drift-at-head.db")
    upgrade_database(url)
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_evaluation_jobs_claim"))
    engine.dispose()

    with pytest.raises(RuntimeError, match="incompatible indexes"):
        upgrade_database(url)


def test_runtime_startup_rejects_and_does_not_create_an_empty_schema(tmp_path: Path) -> None:
    url = database_url(tmp_path)
    store = QueueStore(url)

    with pytest.raises(RuntimeError, match="database has not been migrated"):
        store.initialize()

    assert set(inspect(store.engine).get_table_names()) == set()


def test_baseline_upgrade_reactivates_legacy_terminal_work(tmp_path: Path) -> None:
    url = database_url(tmp_path)
    upgrade_database(url, revision=BASELINE_REVISION)
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO evaluation_jobs (
                    installation_id, repository_full_name, pull_number, reason,
                    generation, authority_generation, state, attempts,
                    requested_at, available_at
                ) VALUES (
                    1, 'example/project', 7, 'pre-release', 1, 0, 'dead', 9,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                )
                """
            )
        )
    engine.dispose()

    upgrade_database(url)

    store = QueueStore(url)
    store.initialize()
    assert store.pending_count() == 1
    assert store.dead_count() == 0


def test_exact_head_requires_database_restore_across_rollback_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = database_url(tmp_path)
    upgrade_database(url, revision=BASELINE_REVISION)

    current_store = QueueStore(url)
    with pytest.raises(RuntimeError, match="required revision '0003_shared_head_epochs'"):
        current_store.initialize()
    current_store.close()

    upgrade_database(url)
    upgraded_store = QueueStore(url)
    upgraded_store.initialize()
    upgraded_store.close()

    monkeypatch.setattr(database, "DATABASE_MIGRATION_HEAD", BASELINE_REVISION)
    monkeypatch.setattr(database, "SCHEMA_VERSION", 1)
    previous_store = QueueStore(url)
    with pytest.raises(RuntimeError, match="required revision '0001_initial_schema'"):
        previous_store.initialize()
    previous_store.close()


def test_retry_schema_upgrades_existing_jobs_to_fail_closed_shared_head_fences(
    tmp_path: Path,
) -> None:
    url = database_url(tmp_path)
    upgrade_database(url, revision="0002_retry_dead_jobs")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO evaluation_jobs (
                    installation_id, repository_full_name, pull_number, reason,
                    head_sha_hint, generation, authority_generation, state,
                    attempts, requested_at, available_at
                ) VALUES (
                    17, 'example/project', 42, 'before-shared-head-fence',
                    NULL, 1, 0, 'pending', 0,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                ), (
                    17, 'example/project', 43, 'before-shared-head-fence',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    1, 0, 'pending', 0,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                )
                """
            )
        )
    engine.dispose()

    upgrade_database(url)

    migrated = create_engine(url)
    inspector = inspect(migrated)
    shared_generation = next(
        column
        for column in inspector.get_columns("evaluation_jobs")
        if column["name"] == "shared_head_generation"
    )
    with migrated.connect() as connection:
        marker = connection.scalar(
            text("SELECT version FROM schema_metadata WHERE singleton_id = 1")
        )
        queued_generations = {
            int(row.pull_number): int(row.shared_head_generation)
            for row in connection.execute(
                text(
                    "SELECT pull_number, shared_head_generation "
                    "FROM evaluation_jobs ORDER BY pull_number"
                )
            )
        }
        migrated_epoch = connection.execute(
            text(
                "SELECT generation, invalidated_generation "
                "FROM shared_head_epochs WHERE head_sha = :head_sha"
            ),
            {"head_sha": "b" * 40},
        ).one()
    assert marker == 2
    assert queued_generations == {42: 0, 43: 1}
    assert tuple(migrated_epoch) == (1, 0)
    assert shared_generation["nullable"] is False
    assert inspector.has_table("shared_head_epochs")
    epoch_columns = {
        column["name"]: column for column in inspector.get_columns("shared_head_epochs")
    }
    assert {
        "generation",
        "invalidated_generation",
        "changed_at",
        "available_at",
        "attempts",
        "lease_owner",
        "lease_until",
        "last_error",
    } <= epoch_columns.keys()
    assert epoch_columns["invalidated_generation"]["nullable"] is False
    assert epoch_columns["available_at"]["nullable"] is False
    assert epoch_columns["attempts"]["nullable"] is False
    assert {
        constraint["name"] for constraint in inspector.get_check_constraints("shared_head_epochs")
    } == {
        "ck_shared_head_epochs_attempts_nonnegative",
        "ck_shared_head_epochs_generation_positive",
        "ck_shared_head_epochs_invalidation_bounds",
    }
    assert {index["name"] for index in inspector.get_indexes("shared_head_epochs")} >= {
        "ix_shared_head_epochs_changed_at",
        "ix_shared_head_epochs_claim",
    }
    webhook_columns = {column["name"] for column in inspector.get_columns("webhook_deliveries")}
    assert {
        "installation_id",
        "repository_full_name",
        "pull_number",
        "head_sha",
        "shared_head_generation",
    } <= webhook_columns
    with migrated.connect() as connection:
        claim_index_sql = connection.scalar(
            text(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'index' AND name = 'ix_shared_head_epochs_claim'"
            )
        )
    assert "WHERE invalidated_generation < generation" in str(claim_index_sql)
    migrated.dispose()

    store = QueueStore(url)
    store.initialize()
    claimed = store.claim("migration-test-worker", 60)
    assert claimed is not None
    assert claimed.shared_head_generation == 0
    bound = store.bind_claim_to_head(claimed, "a" * 40)
    assert bound is not None
    assert bound.shared_head_generation == 1
    assert store.shared_head_generation_is_current(bound, "a" * 40) is True
    assert store.shared_head_generation_is_publishable(bound, "a" * 40) is False
    assert store.shared_head_invalidation_generation(17, "example/project", "a" * 40) == 0


def test_legacy_delivery_redelivery_uses_current_head_fast_path(
    tmp_path: Path,
) -> None:
    url = database_url(tmp_path)
    upgrade_database(url, revision="0002_retry_dead_jobs")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO webhook_deliveries (
                    delivery_id, event, received_at, invalidation_required
                ) VALUES (
                    'legacy-delivery', 'pull_request', CURRENT_TIMESTAMP, TRUE
                )
                """
            )
        )
    engine.dispose()
    upgrade_database(url)
    store = QueueStore(url)
    store.initialize()

    acceptance = store.accept_delivery(
        "legacy-delivery",
        "pull_request",
        database.JobRequest(
            17,
            "example/project",
            42,
            "pull_request.opened",
            "a" * 40,
        ),
    )

    assert acceptance.accepted is False
    assert acceptance.shared_head_generation is None
    assert store.delivery_needs_invalidation("legacy-delivery") is True


def test_failed_migration_releases_guard_and_can_be_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = database_url(tmp_path)
    real_upgrade = migrations._apply_upgrade
    calls = 0

    def fail_once(config: Config, revision: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated interrupted migration")
        real_upgrade(config, revision)

    monkeypatch.setattr(migrations, "_apply_upgrade", fail_once)

    with pytest.raises(RuntimeError, match="simulated interrupted migration"):
        upgrade_database(url, lock_timeout_seconds=0.2)
    upgrade_database(url, lock_timeout_seconds=0.2)

    assert current_revision(url) == DATABASE_MIGRATION_HEAD


def test_pre_alembic_schema_requires_explicit_strict_adoption(tmp_path: Path) -> None:
    url = database_url(tmp_path)
    upgrade_database(url, revision=BASELINE_REVISION)
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
    engine.dispose()

    with pytest.raises(RuntimeError, match="--adopt-pre-alembic-schema"):
        upgrade_database(url)

    upgrade_database(url, adopt_pre_alembic_schema=True)
    assert current_revision(url) == DATABASE_MIGRATION_HEAD


def test_immutable_adoption_contract_matches_revision_0001(tmp_path: Path) -> None:
    url = database_url(tmp_path)
    upgrade_database(url, revision=BASELINE_REVISION)
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
    engine.dispose()

    upgrade_database(url, adopt_pre_alembic_schema=True)

    assert current_revision(url) == DATABASE_MIGRATION_HEAD


def test_partial_pre_alembic_schema_is_never_adopted(tmp_path: Path) -> None:
    url = database_url(tmp_path)
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE schema_metadata (singleton_id INTEGER, version INTEGER)")
        )
        connection.execute(text("INSERT INTO schema_metadata VALUES (1, 1)"))
    engine.dispose()

    with pytest.raises(RuntimeError, match="non-baseline pre-Alembic schema"):
        upgrade_database(url, adopt_pre_alembic_schema=True)


def test_modified_pre_alembic_contract_is_never_adopted(tmp_path: Path) -> None:
    url = database_url(tmp_path)
    upgrade_database(url, revision=BASELINE_REVISION)
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
        connection.execute(text("CREATE INDEX unexpected_index ON service_leases (owner)"))
    engine.dispose()

    with pytest.raises(RuntimeError, match="expected indexes"):
        upgrade_database(url, adopt_pre_alembic_schema=True)


def test_future_artifact_cannot_reinterpret_pre_alembic_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = database_url(tmp_path)
    upgrade_database(url, revision=BASELINE_REVISION)
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
    engine.dispose()
    monkeypatch.setattr(migrations, "__version__", "0.2.0")

    with pytest.raises(RuntimeError, match=r"only from the 0\.1\.0 artifact"):
        upgrade_database(url, adopt_pre_alembic_schema=True)


def test_packaged_head_has_versioned_upgrade_notes() -> None:
    notes = Path("docs/reference/upgrade-notes.md").read_text(encoding="utf-8")

    assert f"`{DATABASE_MIGRATION_HEAD}`" in notes
