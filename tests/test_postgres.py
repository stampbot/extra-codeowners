from __future__ import annotations

import os
import threading
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from functools import partial
from time import monotonic
from typing import cast

import pytest
from alembic.config import Config
from sqlalchemy import Connection, create_engine, delete, inspect, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

import extra_codeowners.migrations as migrations
from extra_codeowners.database import (
    DATABASE_MIGRATION_HEAD,
    Base,
    ClaimedJob,
    EvaluationJob,
    JobRequest,
    QueueStore,
    SharedHeadEpoch,
    utcnow,
)
from extra_codeowners.migrations import (
    BASELINE_REVISION,
    MIGRATION_LOCK_KEY,
    current_revision,
    upgrade_database,
)

pytestmark = pytest.mark.integration


def postgres_url() -> str:
    value = os.environ.get("TEST_POSTGRES_URL")
    if value is None:
        pytest.skip("TEST_POSTGRES_URL is not configured")
    database = make_url(value).database
    if database is None or not database.endswith("_test"):
        pytest.fail("TEST_POSTGRES_URL must target a database whose name ends in '_test'")
    return value


@pytest.fixture
def postgres_store() -> Generator[QueueStore]:
    url = postgres_url()
    store = QueueStore(url)
    Base.metadata.drop_all(store.engine)
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    upgrade_database(url)
    store.initialize()
    try:
        yield store
    finally:
        Base.metadata.drop_all(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        store.close()


def request(pull_number: int = 42) -> JobRequest:
    return JobRequest(
        installation_id=17,
        repository_full_name="example/project",
        pull_number=pull_number,
        reason="integration-test",
        head_sha_hint="a" * 40,
    )


def test_concurrent_delivery_generations_are_not_lost(postgres_store: QueueStore) -> None:
    workers = 12
    barrier = threading.Barrier(workers)

    def accept(index: int) -> bool:
        barrier.wait()
        return postgres_store.accept_delivery(
            f"delivery-{index}",
            "pull_request",
            request(),
        ).accepted

    with ThreadPoolExecutor(max_workers=workers) as executor:
        accepted = list(executor.map(accept, range(workers)))

    with postgres_store.session() as session:
        generation = session.scalar(select(EvaluationJob.generation))
        shared_generation = session.scalar(select(EvaluationJob.shared_head_generation))
        epoch = session.scalar(select(SharedHeadEpoch.generation))

    assert accepted == [True] * workers
    assert generation == workers
    assert shared_generation == workers
    assert epoch == workers
    assert postgres_store.pending_count() == 2


def test_concurrent_same_delivery_advances_shared_head_once(
    postgres_store: QueueStore,
) -> None:
    workers = 12
    barrier = threading.Barrier(workers)

    def accept(_: int) -> bool:
        barrier.wait()
        return postgres_store.accept_delivery(
            "same-delivery",
            "pull_request",
            request(),
        ).accepted

    with ThreadPoolExecutor(max_workers=workers) as executor:
        accepted = list(executor.map(accept, range(workers)))

    with postgres_store.session() as session:
        evaluation = session.scalar(select(EvaluationJob))
        epoch = session.scalar(select(SharedHeadEpoch))

    assert accepted.count(True) == 1
    assert accepted.count(False) == workers - 1
    assert evaluation is not None
    assert evaluation.generation == 1
    assert evaluation.shared_head_generation == 1
    assert epoch is not None
    assert epoch.generation == 1
    assert epoch.invalidated_generation == 0
    assert postgres_store.pending_count() == 2


def test_new_generation_fences_prior_postgres_invalidation_lease(
    postgres_store: QueueStore,
) -> None:
    first_acceptance = postgres_store.accept_delivery(
        "first-generation",
        "pull_request",
        request(),
    )
    assert first_acceptance.shared_head_generation == 1
    first = postgres_store.claim_shared_head_invalidation("old-worker", 60)
    assert first is not None

    second_acceptance = postgres_store.accept_delivery(
        "second-generation",
        "pull_request",
        request(),
    )

    assert second_acceptance.shared_head_generation == 2
    assert postgres_store.complete_shared_head_invalidation(first) is False
    second = postgres_store.claim_shared_head_invalidation("new-worker", 60)
    assert second is not None
    assert second.generation == 2
    assert postgres_store.complete_shared_head_invalidation(second) is True


def test_reclaimed_postgres_invalidation_lease_rejects_old_owner(
    postgres_store: QueueStore,
) -> None:
    assert postgres_store.accept_delivery("lease-reclaim", "pull_request", request())
    first = postgres_store.claim_shared_head_invalidation("old-worker", 60)
    assert first is not None
    with postgres_store.engine.begin() as connection:
        connection.execute(
            update(SharedHeadEpoch).values(
                lease_until=utcnow() - timedelta(seconds=1),
            )
        )

    replacement = postgres_store.claim_shared_head_invalidation("new-worker", 60)

    assert replacement is not None
    assert replacement.generation == first.generation
    assert postgres_store.complete_shared_head_invalidation(first) is False
    assert postgres_store.complete_shared_head_invalidation(replacement) is True


def test_postgres_shared_head_fanout_preserves_concurrent_new_head(
    postgres_store: QueueStore,
) -> None:
    accepted = postgres_store.accept_delivery(
        "fanout-source",
        "pull_request",
        request(pull_number=41),
    )
    assert accepted.shared_head_generation == 1
    old_head = "a" * 40

    for round_number in range(12):
        pull_number = 100 + round_number
        new_head = f"{round_number + 2:040x}"
        barrier = threading.Barrier(2)

        def fan_out(
            sync: threading.Barrier = barrier,
            number: int = pull_number,
        ) -> bool:
            sync.wait()
            return postgres_store.enqueue_for_shared_head_generation(
                JobRequest(
                    17,
                    "example/project",
                    number,
                    "shared_head_invalidation",
                    old_head,
                ),
                1,
            )

        def accept_new_head(
            sync: threading.Barrier = barrier,
            delivery_number: int = round_number,
            number: int = pull_number,
            head: str = new_head,
        ) -> bool:
            sync.wait()
            return postgres_store.accept_delivery(
                f"new-head-{delivery_number}",
                "pull_request",
                JobRequest(
                    17,
                    "example/project",
                    number,
                    "pull_request.synchronize",
                    head,
                ),
            ).accepted

        with ThreadPoolExecutor(max_workers=2) as executor:
            fanout_future = executor.submit(fan_out)
            delivery_future = executor.submit(accept_new_head)
            assert fanout_future.result(timeout=5) is True
            assert delivery_future.result(timeout=5) is True

        with postgres_store.session() as session:
            evaluation = session.scalar(
                select(EvaluationJob).where(EvaluationJob.pull_number == pull_number)
            )
        assert evaluation is not None
        assert evaluation.head_sha_hint == new_head
        assert evaluation.shared_head_generation == 1


def test_postgres_prune_cannot_orphan_hintless_binding(
    postgres_store: QueueStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head_sha = "d" * 40
    assert postgres_store.accept_delivery(
        "prune-bind-seed",
        "pull_request",
        JobRequest(17, "example/project", 70, "seed", head_sha),
    )
    seed_invalidation = postgres_store.claim_shared_head_invalidation("seed-worker", 60)
    assert seed_invalidation is not None
    assert postgres_store.complete_shared_head_invalidation(seed_invalidation)
    with postgres_store.engine.begin() as connection:
        connection.execute(delete(EvaluationJob).where(EvaluationJob.pull_number == 70))
        connection.execute(
            update(SharedHeadEpoch)
            .where(SharedHeadEpoch.head_sha == head_sha)
            .values(changed_at=utcnow() - timedelta(days=90))
        )

    postgres_store.enqueue(JobRequest(17, "example/project", 71, "hintless-reconciliation"))
    claimed = postgres_store.claim("binding-worker", 60)
    assert claimed is not None
    advanced = threading.Event()
    allow_binding = threading.Event()
    original_advance = postgres_store._advance_shared_head_epoch_in_session

    def pause_after_epoch_lock(session: object, bind_request: JobRequest) -> int:
        generation = original_advance(session, bind_request)  # type: ignore[arg-type]
        advanced.set()
        assert allow_binding.wait(timeout=5)
        return generation

    monkeypatch.setattr(
        postgres_store,
        "_advance_shared_head_epoch_in_session",
        pause_after_epoch_lock,
    )
    boundary = utcnow() - timedelta(days=30)
    with ThreadPoolExecutor(max_workers=2) as executor:
        bound_future = executor.submit(postgres_store.bind_claim_to_head, claimed, head_sha)
        assert advanced.wait(timeout=5)
        prune_future = executor.submit(postgres_store.prune_shared_head_epochs, boundary)
        assert prune_future.done() is False
        allow_binding.set()
        bound = bound_future.result(timeout=5)
        pruned = prune_future.result(timeout=5)

    assert bound is not None
    assert pruned == 0
    with postgres_store.session() as session:
        epoch = session.scalar(select(SharedHeadEpoch).where(SharedHeadEpoch.head_sha == head_sha))
        evaluation = session.scalar(select(EvaluationJob).where(EvaluationJob.pull_number == 71))
    assert epoch is not None
    assert evaluation is not None
    assert epoch.generation == bound.shared_head_generation
    assert epoch.invalidated_generation < epoch.generation
    assert evaluation.shared_head_generation == epoch.generation


def test_postgres_prune_cannot_orphan_known_head_enqueue(
    postgres_store: QueueStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head_sha = "e" * 40
    assert postgres_store.accept_delivery(
        "prune-enqueue-seed",
        "pull_request",
        JobRequest(17, "example/project", 72, "seed", head_sha),
    )
    seed_invalidation = postgres_store.claim_shared_head_invalidation("seed-worker", 60)
    assert seed_invalidation is not None
    assert postgres_store.complete_shared_head_invalidation(seed_invalidation)
    with postgres_store.engine.begin() as connection:
        connection.execute(delete(EvaluationJob).where(EvaluationJob.pull_number == 72))
        connection.execute(
            update(SharedHeadEpoch)
            .where(SharedHeadEpoch.head_sha == head_sha)
            .values(changed_at=utcnow() - timedelta(days=90))
        )

    advanced = threading.Event()
    allow_enqueue = threading.Event()
    original_advance = postgres_store._advance_shared_head_epoch_in_session

    def pause_after_epoch_lock(session: object, enqueue_request: JobRequest) -> int:
        generation = original_advance(session, enqueue_request)  # type: ignore[arg-type]
        advanced.set()
        assert allow_enqueue.wait(timeout=5)
        return generation

    monkeypatch.setattr(
        postgres_store,
        "_advance_shared_head_epoch_in_session",
        pause_after_epoch_lock,
    )
    boundary = utcnow() - timedelta(days=30)
    enqueue_request = JobRequest(
        17,
        "example/project",
        73,
        "authority-fanout",
        head_sha,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        enqueue_future = executor.submit(postgres_store.enqueue, enqueue_request)
        assert advanced.wait(timeout=5)
        prune_future = executor.submit(postgres_store.prune_shared_head_epochs, boundary)
        deadline = monotonic() + 5
        prune_waiting = False
        while monotonic() < deadline:
            with postgres_store.engine.connect() as observer:
                prune_waiting = bool(
                    observer.scalar(
                        text(
                            """
                            SELECT count(*)
                            FROM pg_stat_activity
                            WHERE datname = current_database()
                              AND pid <> pg_backend_pid()
                              AND state = 'active'
                              AND wait_event_type = 'Lock'
                              AND lower(query) LIKE
                                  '%delete from shared_head_epochs%'
                            """
                        )
                    )
                )
            if prune_waiting:
                break
            threading.Event().wait(0.01)
        assert prune_waiting, "prune DELETE did not reach the epoch row lock"
        assert prune_future.done() is False
        allow_enqueue.set()
        enqueue_future.result(timeout=5)
        pruned = prune_future.result(timeout=5)

    assert pruned == 0
    with postgres_store.session() as session:
        epoch = session.scalar(select(SharedHeadEpoch).where(SharedHeadEpoch.head_sha == head_sha))
        evaluation = session.scalar(select(EvaluationJob).where(EvaluationJob.pull_number == 73))
    assert epoch is not None
    assert evaluation is not None
    assert epoch.generation == 2
    assert epoch.invalidated_generation == 1
    assert evaluation.shared_head_generation == epoch.generation
    assert postgres_store.pending_shared_head_invalidation_count() == 1
    claimed_view = cast(ClaimedJob, evaluation)
    assert postgres_store.shared_head_generation_is_current(claimed_view, head_sha) is True
    assert postgres_store.shared_head_generation_is_publishable(claimed_view, head_sha) is False


def test_concurrent_delivery_and_reconciliation_compose_without_phantom_epoch(
    postgres_store: QueueStore,
) -> None:
    workers = 16

    def race(
        index: int,
        *,
        barrier: threading.Barrier,
        delivery_id: str,
        reconciliation: JobRequest,
    ) -> tuple[str, bool]:
        barrier.wait()
        if index % 2 == 0:
            return (
                "delivery",
                postgres_store.accept_delivery(
                    delivery_id,
                    "pull_request",
                    reconciliation,
                ).accepted,
            )
        return (
            "reconciliation",
            postgres_store.enqueue_if_absent(reconciliation),
        )

    for round_number in range(10):
        barrier = threading.Barrier(workers)
        head_sha = f"{round_number + 1:040x}"
        reconciliation = JobRequest(
            installation_id=17,
            repository_full_name="example/project",
            pull_number=100 + round_number,
            reason="integration-test",
            head_sha_hint=head_sha,
        )
        race_round = partial(
            race,
            barrier=barrier,
            delivery_id=f"composed-delivery-{round_number}",
            reconciliation=reconciliation,
        )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(race_round, range(workers)))

        accepted = [result for kind, result in outcomes if kind == "delivery"]
        reconciled = [result for kind, result in outcomes if kind == "reconciliation"]
        with postgres_store.session() as session:
            evaluation = session.scalar(
                select(EvaluationJob).where(EvaluationJob.pull_number == 100 + round_number)
            )
            epoch = session.scalar(
                select(SharedHeadEpoch).where(SharedHeadEpoch.head_sha == head_sha)
            )

        assert accepted.count(True) == 1
        assert reconciled.count(True) <= 1
        expected_generation = 1 + reconciled.count(True)
        assert evaluation is not None
        assert evaluation.generation == expected_generation
        assert evaluation.shared_head_generation == expected_generation
        assert epoch is not None
        assert epoch.generation == expected_generation


def test_existing_job_reconciliation_rolls_back_tentative_postgres_epoch(
    postgres_store: QueueStore,
) -> None:
    reconciliation = request()
    postgres_store.enqueue(reconciliation)

    assert postgres_store.shared_head_generation(17, "example/project", "a" * 40) == 1
    assert postgres_store.enqueue_if_absent(reconciliation) is False
    assert postgres_store.shared_head_generation(17, "example/project", "a" * 40) == 1


def test_internal_head_trigger_stales_prior_postgres_shared_head_claim(
    postgres_store: QueueStore,
) -> None:
    head = "a" * 40
    assert postgres_store.accept_delivery(
        "other-pull",
        "pull_request",
        JobRequest(17, "example/project", 41, "pull_request.opened", head),
    )
    prior = postgres_store.claim("worker", 60)
    assert prior is not None

    postgres_store.enqueue_shared_head_trigger(
        JobRequest(17, "example/project", 42, "head_changed_before_evaluation", head)
    )

    assert postgres_store.shared_head_generation(17, "example/project", head) == 2
    assert postgres_store.shared_head_generation_is_current(prior, head) is False


def test_claim_and_service_lease_election_are_atomic(postgres_store: QueueStore) -> None:
    workers = 8
    for pull_number in range(1, workers + 1):
        postgres_store.enqueue(request(pull_number))

    barrier = threading.Barrier(workers)

    def claim(index: int) -> ClaimedJob | None:
        barrier.wait()
        return postgres_store.claim(f"worker-{index}", 60)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        claims = list(executor.map(claim, range(workers)))

    assert all(claimed is not None for claimed in claims)
    assert len({claimed.id for claimed in claims if claimed is not None}) == workers

    lease_barrier = threading.Barrier(workers)

    def elect(index: int) -> bool:
        lease_barrier.wait()
        return postgres_store.acquire_service_lease(
            "integration-reconciler", f"candidate-{index}", 60
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        elected = list(executor.map(elect, range(workers)))

    assert elected.count(True) == 1
    winner = f"candidate-{elected.index(True)}"
    assert postgres_store.release_service_lease("integration-reconciler", "outsider") is False
    assert (
        postgres_store.acquire_service_lease("integration-reconciler", "replacement", 60) is False
    )
    assert postgres_store.release_service_lease("integration-reconciler", winner) is True
    assert postgres_store.acquire_service_lease("integration-reconciler", "replacement", 60) is True
    assert postgres_store.release_service_lease("integration-reconciler", winner) is False


def test_postgres_advisory_guard_orders_writers_and_survives_connection_loss(
    postgres_store: QueueStore,
) -> None:
    first = postgres_store.acquire_check_write_guard("example/project", 42, 2)
    assert first is not None

    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            postgres_store.acquire_check_write_guard,
            "example/project",
            42,
            2,
        )
        assert waiting.done() is False
        postgres_store.release_check_write_guard(first)
        second = waiting.result(timeout=3)

    assert second is not None
    postgres_store.release_check_write_guard(second)

    lost = postgres_store.acquire_check_write_guard("example/project", 42, 2)
    assert lost is not None and lost.connection is not None
    lost.connection.invalidate()
    lost.connection.close()

    recovered = postgres_store.acquire_check_write_guard("example/project", 42, 2)
    assert recovered is not None
    postgres_store.release_check_write_guard(recovered)


def test_postgres_authority_guards_are_shared_and_do_not_hold_idle_transactions(
    postgres_store: QueueStore,
) -> None:
    first = postgres_store.acquire_authority_guard(17, shared=True, timeout_seconds=2)
    second = postgres_store.acquire_authority_guard(17, shared=True, timeout_seconds=2)
    assert first is not None and first.connection is not None
    assert second is not None

    driver_connection = first.connection.connection.driver_connection
    assert driver_connection is not None
    backend_pid = driver_connection.info.backend_pid
    with postgres_store.engine.connect() as observer:
        state = observer.scalar(
            text("SELECT state FROM pg_stat_activity WHERE pid = :pid"),
            {"pid": backend_pid},
        )
    assert state == "idle"

    try:
        with pytest.raises(DBAPIError):
            postgres_store.acquire_authority_guard(17, shared=False, timeout_seconds=0.05)
    finally:
        postgres_store.release_check_write_guard(second)
        postgres_store.release_check_write_guard(first)

    exclusive = postgres_store.acquire_authority_guard(17, shared=False, timeout_seconds=2)
    assert exclusive is not None
    postgres_store.release_check_write_guard(exclusive)


def test_concurrent_migrations_create_one_valid_schema() -> None:
    url = postgres_url()
    cleanup = QueueStore(url)
    Base.metadata.drop_all(cleanup.engine)
    with cleanup.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    cleanup.close()
    stores = [QueueStore(url), QueueStore(url)]
    barrier = threading.Barrier(len(stores))

    def migrate(store: QueueStore) -> None:
        barrier.wait()
        upgrade_database(url, lock_timeout_seconds=5)
        store.initialize()

    try:
        with ThreadPoolExecutor(max_workers=len(stores)) as executor:
            list(executor.map(migrate, stores))
        assert all(store.database_available() for store in stores)
        assert current_revision(url) == DATABASE_MIGRATION_HEAD
    finally:
        Base.metadata.drop_all(stores[0].engine)
        with stores[0].engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        for store in stores:
            store.close()


def test_postgres_baseline_upgrade_reactivates_representative_dead_jobs() -> None:
    url = postgres_url()
    cleanup = QueueStore(url)
    Base.metadata.drop_all(cleanup.engine)
    with cleanup.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    cleanup.close()
    engine = create_engine(url)
    try:
        upgrade_database(url, revision="0001_initial_schema")
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO evaluation_jobs (
                        installation_id, repository_full_name, pull_number, reason,
                        generation, authority_generation, state, attempts,
                        requested_at, available_at, lease_owner, lease_until, last_error
                    ) VALUES (
                        17, 'example/project', 42, 'postgres-upgrade', 1, 0,
                        'dead', 9, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                        'old-worker', CURRENT_TIMESTAMP, 'old error'
                    )
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO authority_jobs (
                        installation_id, scope_key, base_ref, reason, generation,
                        state, attempts, requested_at, available_at, lease_owner,
                        lease_until, last_error
                    ) VALUES (
                        17, 'example/project', 'main', 'postgres-upgrade', 1,
                        'dead', 8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                        'old-worker', CURRENT_TIMESTAMP, 'old error'
                    )
                    """
                )
            )

        upgrade_database(url)

        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT 'authority', state, attempts, lease_owner, lease_until, last_error
                    FROM authority_jobs
                    UNION ALL
                    SELECT 'evaluation', state, attempts, lease_owner, lease_until, last_error
                    FROM evaluation_jobs
                    ORDER BY 1
                    """
                )
            ).all()
        assert [tuple(row) for row in rows] == [
            ("authority", "pending", 0, None, None, None),
            ("evaluation", "pending", 0, None, None, None),
        ]
    finally:
        Base.metadata.drop_all(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        engine.dispose()


def test_postgres_0002_existing_row_is_fenced_after_0003_upgrade() -> None:
    url = postgres_url()
    store = QueueStore(url)
    Base.metadata.drop_all(store.engine)
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    try:
        upgrade_database(url, revision="0002_retry_dead_jobs")
        with store.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO evaluation_jobs (
                        installation_id, repository_full_name, pull_number, reason,
                        head_sha_hint, generation, authority_generation, state, attempts,
                        requested_at, available_at
                    ) VALUES (
                        17, 'example/project', 41, 'before-shared-head-fence',
                        :head_sha, 1, 0, 'pending', 0,
                        TIMESTAMPTZ '2000-01-01 00:00:00+00',
                        TIMESTAMPTZ '2000-01-01 00:00:00+00'
                    )
                    """
                ),
                {"head_sha": "a" * 40},
            )

        upgrade_database(url)
        store.initialize()
        assert current_revision(url) == DATABASE_MIGRATION_HEAD
        with store.session() as session:
            backfilled = session.scalar(
                select(EvaluationJob).where(EvaluationJob.pull_number == 41)
            )
            backfilled_epoch = session.scalar(select(SharedHeadEpoch))
        assert backfilled is not None
        assert backfilled.shared_head_generation == 1
        assert backfilled_epoch is not None
        assert backfilled_epoch.generation == 1
        assert backfilled_epoch.invalidated_generation == 0
        assert store.accept_delivery(
            "post-upgrade-other-pull",
            "pull_request",
            request(pull_number=42),
        )
        assert store.shared_head_generation(17, "example/project", "a" * 40) == 2
        assert store.shared_head_invalidation_generation(17, "example/project", "a" * 40) == 0

        migrated = store.claim("migration-test-worker", 60)
        assert migrated is not None
        assert migrated.pull_number == 41
        assert migrated.shared_head_generation == 1
        assert store.shared_head_generation_is_current(migrated, "a" * 40) is False
    finally:
        Base.metadata.drop_all(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        store.close()


def test_interrupted_postgres_migration_rolls_back_and_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = postgres_url()
    cleanup = QueueStore(url)
    Base.metadata.drop_all(cleanup.engine)
    with cleanup.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    cleanup.close()
    real_upgrade = migrations._apply_upgrade

    def interrupt(config: Config, revision: str) -> None:
        del revision
        connection = cast(Connection, config.attributes["connection"])
        connection.execute(text("CREATE TABLE interrupted_migration (id INTEGER)"))
        raise RuntimeError("simulated process interruption")

    monkeypatch.setattr(migrations, "_apply_upgrade", interrupt)
    with pytest.raises(RuntimeError, match="simulated process interruption"):
        upgrade_database(url, lock_timeout_seconds=1)

    observer = create_engine(url)
    assert inspect(observer).has_table("interrupted_migration") is False
    observer.dispose()

    monkeypatch.setattr(migrations, "_apply_upgrade", real_upgrade)
    upgrade_database(url, lock_timeout_seconds=1)
    assert current_revision(url) == DATABASE_MIGRATION_HEAD

    final = QueueStore(url)
    Base.metadata.drop_all(final.engine)
    with final.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    final.close()


def test_postgres_migration_lock_timeout_is_bounded() -> None:
    url = postgres_url()
    engine = create_engine(url)
    with engine.connect() as holder:
        assert holder.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
        holder.commit()
        started = monotonic()
        with pytest.raises(TimeoutError, match="database migration lock"):
            upgrade_database(url, lock_timeout_seconds=0.1)
        assert monotonic() - started < 1
        holder.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": MIGRATION_LOCK_KEY})
        holder.commit()
    engine.dispose()


def test_postgres_pre_alembic_schema_adoption_is_strict_and_usable() -> None:
    url = postgres_url()
    store = QueueStore(url)
    Base.metadata.drop_all(store.engine)
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    upgrade_database(url, revision=BASELINE_REVISION)
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))

    upgrade_database(url, adopt_pre_alembic_schema=True)

    store.initialize()
    assert store.database_available() is True
    Base.metadata.drop_all(store.engine)
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    store.close()


def test_postgres_revision_0001_matches_immutable_adoption_contract() -> None:
    url = postgres_url()
    store = QueueStore(url)
    Base.metadata.drop_all(store.engine)
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    try:
        upgrade_database(url, revision=BASELINE_REVISION)
        with store.engine.connect() as connection:
            sequences = tuple(
                connection.execute(
                    text(
                        "SELECT sequence_name FROM information_schema.sequences "
                        "WHERE sequence_schema = current_schema() ORDER BY sequence_name"
                    )
                ).scalars()
            )
        assert sequences == (
            "authority_epochs_installation_id_seq",
            "authority_jobs_id_seq",
            "evaluation_audits_id_seq",
            "evaluation_jobs_id_seq",
        )
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE alembic_version"))

        upgrade_database(url, adopt_pre_alembic_schema=True)

        store.initialize()
        assert current_revision(url) == DATABASE_MIGRATION_HEAD
    finally:
        Base.metadata.drop_all(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        store.close()


@pytest.mark.parametrize(
    ("alter_statement", "error_match"),
    [
        (
            "ALTER TABLE evaluation_jobs ALTER COLUMN id DROP DEFAULT",
            "owned sequence",
        ),
        (
            "ALTER TABLE evaluation_jobs ALTER COLUMN requested_at "
            "TYPE TIMESTAMP WITHOUT TIME ZONE",
            "timezone",
        ),
    ],
    ids=("missing-serial-default", "timestamp-without-timezone"),
)
def test_postgres_runtime_schema_validation_rejects_behavior_changes(
    alter_statement: str, error_match: str
) -> None:
    url = postgres_url()
    store = QueueStore(url)
    Base.metadata.drop_all(store.engine)
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    try:
        upgrade_database(url)
        with store.engine.begin() as connection:
            connection.execute(text(alter_statement))

        with pytest.raises(RuntimeError, match=error_match):
            store.initialize()
    finally:
        Base.metadata.drop_all(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        store.close()


@pytest.mark.parametrize(
    ("alter_statements", "error_match"),
    [
        (
            ("ALTER TABLE evaluation_jobs ALTER COLUMN id DROP DEFAULT",),
            "default, owned sequence",
        ),
        (
            (
                "ALTER TABLE evaluation_jobs ALTER COLUMN requested_at "
                "TYPE TIMESTAMP WITHOUT TIME ZONE",
            ),
            "timezone",
        ),
        (
            (
                "DROP INDEX ix_evaluation_jobs_claim",
                "CREATE INDEX ix_evaluation_jobs_claim ON evaluation_jobs "
                "(state, available_at, lease_until) WHERE state = 'pending'",
            ),
            "predicates",
        ),
    ],
    ids=("missing-serial-default", "timestamp-without-timezone", "partial-index"),
)
def test_postgres_pre_alembic_adoption_rejects_behavior_changes(
    alter_statements: tuple[str, ...], error_match: str
) -> None:
    url = postgres_url()
    store = QueueStore(url)
    Base.metadata.drop_all(store.engine)
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    upgrade_database(url, revision=BASELINE_REVISION)
    try:
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE alembic_version"))
            for statement in alter_statements:
                connection.execute(text(statement))

        with pytest.raises(RuntimeError, match=error_match):
            upgrade_database(url, adopt_pre_alembic_schema=True)
    finally:
        Base.metadata.drop_all(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        store.close()
