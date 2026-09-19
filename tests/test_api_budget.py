from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy import text, update
from sqlalchemy.engine import make_url

from extra_codeowners.api_budget import (
    REQUEST_LANE,
    CoreQuota,
    ProviderQuotaExhaustedError,
    RecoveryApiBudget,
    RecoveryBudgetDeferredError,
    request_lane,
)
from extra_codeowners.database import Base, InstallationApiBudget, QueueStore, ServiceLease, utcnow
from extra_codeowners.github import GitHubClient, GitHubRateLimitError
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.tracing import Tracing


@pytest.fixture(params=["sqlite", "postgresql"])
def budget_store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[QueueStore]:
    url = f"sqlite:///{tmp_path / 'budget.db'}"
    if request.param == "postgresql":
        request.node.add_marker(pytest.mark.integration)
        url = os.environ.get("TEST_POSTGRES_URL", "")
        if not url:
            pytest.skip("TEST_POSTGRES_URL is not configured")
        database = make_url(url).database
        assert database is not None and database.endswith("_test")
    store = QueueStore(url)
    if request.param == "postgresql":
        Base.metadata.drop_all(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    upgrade_database(url)
    store.initialize()
    try:
        yield store
    finally:
        store.close()


def quota(remaining: int = 100, limit: int = 100) -> CoreQuota:
    return CoreQuota(limit, remaining, (utcnow() + timedelta(hours=1)).replace(microsecond=0))


def headers(remaining: int = 99) -> dict[str, str]:
    value = quota(remaining)
    return {
        "x-ratelimit-resource": "core",
        "x-ratelimit-limit": str(value.limit),
        "x-ratelimit-remaining": str(value.remaining),
        "x-ratelimit-reset": str(int(value.reset_at.timestamp())),
    }


@pytest.mark.parametrize(
    "key,value",
    [
        ("x-ratelimit-resource", "graphql"),
        ("x-ratelimit-resource", ""),
        ("x-ratelimit-limit", "0"),
        ("x-ratelimit-limit", "NaN"),
        ("x-ratelimit-limit", "9" * 100),
        ("x-ratelimit-remaining", "101"),
        ("x-ratelimit-remaining", "-1"),
        ("x-ratelimit-remaining", " 2"),
        ("x-ratelimit-reset", "0"),
        ("x-ratelimit-reset", "999999999999"),
    ],
)
def test_invalid_quota_is_not_a_refill(key: str, value: str) -> None:
    candidate = headers()
    candidate[key] = value
    assert CoreQuota.from_headers(candidate) is None


def test_valid_core_headers() -> None:
    observed = CoreQuota.from_headers(headers(42))
    assert observed is not None
    assert (observed.limit, observed.remaining) == (100, 42)


def test_missing_headers_are_not_quota() -> None:
    assert CoreQuota.from_headers({}) is None


def test_conditional_receipt_refunds_once(budget_store: QueueStore) -> None:
    budget = RecoveryApiBudget(budget_store)
    observed = quota()
    budget.observe(17, observed)
    receipt = budget.admit(17, recovery=True)
    assert receipt is not None
    budget.observe(17, observed, not_modified_receipt=receipt)
    budget.observe(17, observed, not_modified_receipt=receipt)
    with budget_store.session() as session:
        row = session.get(InstallationApiBudget, 17)
        assert row is not None and row.remaining == 100


def test_peer_debit_prevents_conditional_refund(budget_store: QueueStore) -> None:
    budget = RecoveryApiBudget(budget_store)
    peer = RecoveryApiBudget(budget_store)
    observed = quota()
    budget.observe(17, observed)
    receipt = budget.admit(17, recovery=True)
    peer.admit(17, recovery=False)
    budget.observe(17, observed, not_modified_receipt=receipt)
    with budget_store.session() as session:
        row = session.get(InstallationApiBudget, 17)
        assert row is not None and row.remaining == 98


def test_explicit_zero_fences_receipt_even_when_balance_already_zero(
    budget_store: QueueStore,
) -> None:
    budget = RecoveryApiBudget(budget_store)
    observed = quota(1)
    budget.observe(17, observed)
    receipt = budget.admit(17, recovery=False)
    budget.observe(17, CoreQuota(observed.limit, 0, observed.reset_at))
    budget.observe(17, observed, not_modified_receipt=receipt)
    with budget_store.session() as session:
        row = session.get(InstallationApiBudget, 17)
        assert row is not None and row.remaining == 0


def test_two_peers_cannot_refund_same_receipt_twice(budget_store: QueueStore) -> None:
    budget = RecoveryApiBudget(budget_store)
    observed = quota(90)
    budget.observe(17, observed)
    receipt = budget.admit(17, recovery=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(budget.observe, 17, observed, not_modified_receipt=receipt)
            for _ in range(2)
        ]
        for future in futures:
            future.result()
    with budget_store.session() as session:
        row = session.get(InstallationApiBudget, 17)
        assert row is not None and row.remaining == 90


def test_two_replicas_share_atomic_reserve(budget_store: QueueStore) -> None:
    peer = QueueStore(budget_store.engine.url.render_as_string(hide_password=False))
    first, second = RecoveryApiBudget(budget_store), RecoveryApiBudget(peer)
    first.observe(17, quota(21))

    def attempt(index: int) -> bool:
        try:
            (first if index % 2 else second).admit(17, recovery=True)
            return True
        except RecoveryBudgetDeferredError:
            return False

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            assert sum(pool.map(attempt, range(16))) == 1
        first.admit(17, recovery=False)
        second.admit(18, recovery=True)
        assert not budget_store.provider_is_backpressured(17)
        with budget_store.session() as session:
            row = session.get(InstallationApiBudget, 17)
            assert row is not None and row.remaining == 19
    finally:
        peer.close()


def test_unknown_budget_allows_one_probe_across_replicas(budget_store: QueueStore) -> None:
    budgets = [RecoveryApiBudget(budget_store), RecoveryApiBudget(budget_store)]

    def attempt(index: int) -> bool:
        try:
            budgets[index % 2].admit(17, recovery=True)
            return True
        except RecoveryBudgetDeferredError as error:
            assert 1 <= error.retry_after_seconds <= 60
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(16))) == 1
    budgets[0].admit(17, recovery=False)
    with budget_store.session() as session:
        session.execute(
            update(InstallationApiBudget).values(probe_after=utcnow() - timedelta(seconds=1))
        )
    budgets[1].admit(17, recovery=True)


def test_late_observations_cannot_refund_spending(budget_store: QueueStore) -> None:
    budget = RecoveryApiBudget(budget_store)
    observed = quota(23)
    budget.observe(17, observed)
    budget.admit(17, recovery=True)
    budget.observe(17, observed)
    budget.observe(17, CoreQuota(100, 100, observed.reset_at - timedelta(seconds=1)))
    budget.observe(17, CoreQuota(100, 100, observed.reset_at + timedelta(seconds=1)))
    budget.admit(17, recovery=True)
    budget.admit(17, recovery=True)
    with pytest.raises(RecoveryBudgetDeferredError):
        budget.admit(17, recovery=True)
    budget.observe(17, CoreQuota(100, 10, observed.reset_at + timedelta(seconds=1)))
    with budget_store.session() as session:
        row = session.get(InstallationApiBudget, 17)
        assert row is not None and row.remaining == 10


def test_reset_requires_observed_quota_not_an_assumed_refill(budget_store: QueueStore) -> None:
    budget = RecoveryApiBudget(budget_store)
    budget.observe(17, quota(0))
    with pytest.raises(ProviderQuotaExhaustedError):
        budget.admit(17, recovery=False)
    with budget_store.session() as session:
        session.execute(
            update(InstallationApiBudget).values(reset_at=utcnow() - timedelta(seconds=1))
        )
    budget.admit(17, recovery=True)
    with pytest.raises(RecoveryBudgetDeferredError):
        budget.admit(17, recovery=True)
    budget.observe(17, quota(50))
    budget.admit(17, recovery=True)


def test_shifted_nonzero_observations_do_not_postpone_recovery_forever(
    budget_store: QueueStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    start = utcnow().replace(microsecond=0)
    now = start
    monkeypatch.setattr("extra_codeowners.api_budget.utcnow", lambda: now)
    peer = QueueStore(budget_store.engine.url.render_as_string(hide_password=False))
    first, second = RecoveryApiBudget(budget_store), RecoveryApiBudget(peer)
    original_reset = start + timedelta(seconds=60)
    try:
        first.observe(17, CoreQuota(100, 20, original_reset))
        for index, elapsed in enumerate((5, 15, 45), start=1):
            now = start + timedelta(seconds=elapsed)
            second.observe(17, CoreQuota(100, 99, now + timedelta(hours=1)))
            first.admit(17, recovery=False)
            with budget_store.session() as session:
                row = session.get(InstallationApiBudget, 17)
                assert row is not None and row.remaining == 20 - index
                assert row.reset_at.replace(tzinfo=start.tzinfo) == original_reset
            with pytest.raises(RecoveryBudgetDeferredError) as deferred:
                second.admit(17, recovery=True)
            assert deferred.value.retry_after_seconds == 61 - elapsed

        now = original_reset + timedelta(seconds=1)

        def probe(index: int) -> bool:
            try:
                (first if index % 2 else second).admit(17, recovery=True)
                return True
            except RecoveryBudgetDeferredError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            assert sum(pool.map(probe, range(16))) == 1
        with budget_store.session() as session:
            row = session.get(InstallationApiBudget, 17)
            assert row is not None and row.remaining == 17
        second.observe(17, CoreQuota(100, 80, now + timedelta(hours=1)))
        first.admit(17, recovery=True)
        with budget_store.session() as session:
            row = session.get(InstallationApiBudget, 17)
            assert row is not None and row.remaining == 79
    finally:
        peer.close()


@pytest.mark.parametrize("recovery", [False, True])
def test_shifted_zero_observation_preserves_provider_exhaustion_deadline(
    budget_store: QueueStore, monkeypatch: pytest.MonkeyPatch, recovery: bool
) -> None:
    start = utcnow().replace(microsecond=0)
    now = start
    monkeypatch.setattr("extra_codeowners.api_budget.utcnow", lambda: now)
    budget = RecoveryApiBudget(budget_store)
    budget.observe(17, CoreQuota(100, 20, start + timedelta(seconds=60)))
    provider_reset = start + timedelta(seconds=180)
    budget.observe(17, CoreQuota(100, 0, provider_reset))

    now = start + timedelta(seconds=61)
    with pytest.raises(ProviderQuotaExhaustedError) as exhausted:
        budget.admit(17, recovery=recovery)
    assert exhausted.value.retry_after_seconds == 120
    with budget_store.session() as session:
        row = session.get(InstallationApiBudget, 17)
        assert row is not None and row.remaining == 0
        assert row.reset_at.replace(tzinfo=start.tzinfo) == provider_reset


def test_repository_cursor_requires_live_owner(budget_store: QueueStore) -> None:
    budget = RecoveryApiBudget(budget_store)
    assert budget.repository_cursor(17) == ""
    assert budget_store.acquire_service_lease("open-pr-reconciler", "one", 60)
    budget.advance_repository(17, "Example/One", "one")
    budget.advance_repository(17, "example/two", "other")
    assert budget.repository_cursor(17) == "example/one"
    with budget_store.session() as session:
        session.execute(update(ServiceLease).values(lease_until=utcnow() - timedelta(seconds=1)))
    budget.advance_repository(17, "example/three", "one")
    assert budget.repository_cursor(17) == "example/one"


@pytest.mark.asyncio
async def test_request_lane_is_task_local_and_restored() -> None:
    async def observe() -> str:
        return REQUEST_LANE.get()

    with request_lane("recovery"):
        child = asyncio.create_task(observe())
        with request_lane("authority"):
            assert await observe() == "authority"
        assert await child == "recovery"
    assert REQUEST_LANE.get() == "interactive"
    with pytest.raises(ValueError), request_lane("repository-name"):
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("rejected_remaining", [0, 1, 60])
async def test_client_counts_retry_and_reserves_next_request(
    budget_store: QueueStore,
    private_key: str,
    streaming: bool,
    rejected_remaining: int,
) -> None:
    budget = RecoveryApiBudget(budget_store)
    budget.observe(17, quota(22))
    attempts = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "token",
                    "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
                },
            )
        attempts += 1
        if attempts == 1:
            rejected_headers = {
                **headers(),
                "x-ratelimit-limit": "60",
                "x-ratelimit-remaining": str(rejected_remaining),
            }
            return httpx.Response(401, json={}, headers=rejected_headers)
        return httpx.Response(200, json={}, headers=headers(21))

    client = GitHubClient(
        1, private_key, recovery_budget=budget, transport=httpx.MockTransport(handle)
    )
    try:
        with request_lane("recovery"):
            if streaming:
                async with client._authenticated_streaming_response("GET", "/repos/o/r", 17):
                    pass
            else:
                await client._api_response("GET", "/repos/o/r", installation_id=17)
            with pytest.raises(RecoveryBudgetDeferredError):
                await client._api_response("GET", "/repos/o/r", installation_id=17)
        assert attempts == 2
        await client._api_response("GET", "/repos/o/r", installation_id=17)
        assert attempts == 3
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_client_stops_all_lanes_at_known_zero(
    budget_store: QueueStore, private_key: str
) -> None:
    budget = RecoveryApiBudget(budget_store)
    budget.observe(17, quota(0))
    client = GitHubClient(
        1,
        private_key,
        recovery_budget=budget,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                201,
                json={
                    "token": "token",
                    "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
                },
            )
        ),
    )
    try:
        with pytest.raises(GitHubRateLimitError, match="quota is exhausted"):
            await client._api_response("GET", "/repos/o/r", installation_id=17)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_each_pagination_page_uses_the_shared_budget(
    budget_store: QueueStore,
    private_key: str,
) -> None:
    pages: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "token",
                    "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
                },
            )
        pages.append(str(request.url))
        return httpx.Response(
            200,
            json=[{"number": 1}],
            headers={
                **headers(20),
                "link": f'<{request.url.copy_set_param("page", "2")}>; rel="next"',
            },
        )

    client = GitHubClient(
        1,
        private_key,
        recovery_budget=RecoveryApiBudget(budget_store),
        transport=httpx.MockTransport(handle),
    )
    try:
        with request_lane("recovery"), pytest.raises(RecoveryBudgetDeferredError):
            await client.list_open_pulls(17, "example/project")
        assert len(pages) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_quota_traces_explain_lane_and_reset_without_repository_metadata(
    private_key: str,
    streaming: bool,
) -> None:
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=1,
        processor=SimpleSpanProcessor(exporter),
    )
    observed = headers(31)

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "secret-test-token",
                    "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
                },
            )
        return httpx.Response(200, json={}, headers=observed)

    client = GitHubClient(1, private_key, tracing=tracing, transport=httpx.MockTransport(handle))
    try:
        with request_lane("recovery"):
            if streaming:
                async with client._authenticated_streaming_response(
                    "GET", "/repos/private/repo", 17
                ):
                    pass
            else:
                await client._api_response("GET", "/repos/private/repo", installation_id=17)
    finally:
        await client.close()
        tracing.shutdown()
    spans = [
        span
        for span in exporter.get_finished_spans()
        if span.attributes and span.attributes.get("github.authentication") == "installation"
    ]
    assert len(spans) == 1
    attributes = dict(spans[0].attributes or {})
    assert attributes["queue.work_class"] == "recovery"
    assert attributes["github.quota.remaining"] == 31
    assert attributes["github.quota.limit"] == 100
    assert attributes["github.quota.reset_at"] == int(observed["x-ratelimit-reset"])
    assert "private/repo" not in str(attributes)
    assert "secret-test-token" not in str(attributes)


@pytest.mark.asyncio
async def test_stream_closes_if_quota_recording_fails(
    budget_store: QueueStore,
    private_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    budget = RecoveryApiBudget(budget_store)
    responses: list[httpx.Response] = []

    class Body(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"{}"

        async def aclose(self) -> None:
            self.closed = True

    body = Body()

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "token",
                    "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
                },
            )
        response = httpx.Response(200, stream=body, headers=headers())
        responses.append(response)
        return response

    def failed_observation(*args: object) -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(budget, "observe", failed_observation)
    client = GitHubClient(
        1, private_key, recovery_budget=budget, transport=httpx.MockTransport(handle)
    )
    try:
        with pytest.raises(RuntimeError, match="database unavailable"):
            async with client._authenticated_streaming_response("GET", "/repos/o/r", 17):
                pytest.fail("unaccounted response escaped")
        assert len(responses) == 1 and responses[0].is_closed
        assert body.closed
    finally:
        await client.close()
