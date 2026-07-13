from __future__ import annotations

import os
import threading
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from extra_codeowners.database import Base, ClaimedJob, EvaluationJob, JobRequest, QueueStore

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
    store = QueueStore(postgres_url())
    Base.metadata.drop_all(store.engine)
    store.initialize()
    try:
        yield store
    finally:
        Base.metadata.drop_all(store.engine)
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
        return postgres_store.accept_delivery(f"delivery-{index}", "pull_request", request())

    with ThreadPoolExecutor(max_workers=workers) as executor:
        accepted = list(executor.map(accept, range(workers)))

    with postgres_store.session() as session:
        generation = session.scalar(select(EvaluationJob.generation))

    assert accepted == [True] * workers
    assert generation == workers
    assert postgres_store.pending_count() == 1


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


def test_concurrent_first_start_creates_one_valid_schema() -> None:
    url = postgres_url()
    cleanup = QueueStore(url)
    Base.metadata.drop_all(cleanup.engine)
    cleanup.close()
    stores = [QueueStore(url), QueueStore(url)]
    barrier = threading.Barrier(len(stores))

    def initialize(store: QueueStore) -> None:
        barrier.wait()
        store.initialize()

    try:
        with ThreadPoolExecutor(max_workers=len(stores)) as executor:
            list(executor.map(initialize, stores))
        assert all(store.database_available() for store in stores)
    finally:
        Base.metadata.drop_all(stores[0].engine)
        for store in stores:
            store.close()
