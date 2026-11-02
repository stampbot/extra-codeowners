"""Transient discovery retries stay bounded, authenticated and observable."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import Mock, call

import httpx
import pytest

from extra_codeowners.api_budget import (
    RecoveryApiBudget,
    RecoveryBudgetDeferredError,
    request_lane,
)
from extra_codeowners.github import (
    GitHubAPIError,
    GitHubClient,
    GitHubError,
    GitHubOperationStoppedError,
    GitHubRateLimitError,
)
from extra_codeowners.metrics import GITHUB_API_PHASE_SECONDS, GITHUB_PHYSICAL_REQUESTS


def client_for(
    private_key: str,
    statuses: list[int],
    headers: dict[str, str] | None = None,
    *,
    requested: asyncio.Event | None = None,
) -> tuple[GitHubClient, list[httpx.Request]]:
    replies = iter(statuses)
    requests: list[httpx.Request] = []
    tokens = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal tokens
        if request.url.path.endswith("/access_tokens"):
            tokens += 1
            return httpx.Response(
                201,
                json={
                    "token": f"fictional-token-{tokens}",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        requests.append(request)
        if requested is not None:
            requested.set()
        status = next(replies)
        payload: Any = [] if status == 200 else {"message": "unavailable"}
        return httpx.Response(status, json=payload, headers=headers or {})

    return GitHubClient(7, private_key, transport=httpx.MockTransport(respond)), requests


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [500, 502, 503, 504])
async def test_discovery_retries_one_transient_response(private_key: str, status: int) -> None:
    # Verifies XCO-014: a retry fetches current evidence from authenticated GitHub.
    client, requests = client_for(private_key, [status, 200])
    physical = GITHUB_PHYSICAL_REQUESTS.labels("pull.list", "installation", "interactive")
    before = physical._value.get()
    wait = GITHUB_API_PHASE_SECONDS.labels("pull.list", "installation", "interactive", "retry_wait")
    wait_before = wait._sum.get()
    try:
        assert await client.list_open_pulls(17, "example/project") == []
        assert len(requests) == 2
        assert all(r.headers["authorization"] == "Bearer fictional-token-1" for r in requests)
        assert physical._value.get() - before == 2
        assert wait._sum.get() > wait_before
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_persistent_failure_stops_after_one_transient_retry(private_key: str) -> None:
    # Verifies XCO-001: exhaustion remains an error, never cached approval evidence.
    client, requests = client_for(private_key, [500, 502, 200])
    try:
        with pytest.raises(GitHubAPIError, match="returned 502"):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == 2
        assert client._discovery_cache.entry_count == 0
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("statuses", [[500, 401, 200], [401, 500, 200]])
async def test_one_token_refresh_and_one_transient_retry_share_the_bound(
    private_key: str, statuses: list[int]
) -> None:
    client, requests = client_for(private_key, statuses)
    try:
        assert await client.list_open_pulls(17, "example/project") == []
        assert len(requests) == 3
        assert requests[-1].headers["authorization"] == "Bearer fictional-token-2"
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("statuses", [[401, 401], [500, 401, 401]])
async def test_repeated_authentication_failure_does_not_gain_token_retries(
    private_key: str, statuses: list[int]
) -> None:
    client, requests = client_for(private_key, statuses)
    try:
        with pytest.raises(GitHubAPIError, match="returned 401"):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == len(statuses)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 403, 404, 422, 429, 501])
async def test_other_failures_are_not_retried_inline(private_key: str, status: int) -> None:
    client, requests = client_for(private_key, [status, 200])
    try:
        with pytest.raises(GitHubAPIError):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_retry_after_response_is_not_retried_inline(private_key: str) -> None:
    client, requests = client_for(private_key, [503, 200], {"Retry-After": "120"})
    try:
        with pytest.raises(GitHubAPIError, match="returned 503"):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_rate_limit_metadata_keeps_provider_backpressure(private_key: str) -> None:
    client, requests = client_for(private_key, [429, 200], {"Retry-After": "120"})
    try:
        with pytest.raises(GitHubRateLimitError) as result:
            await client.list_open_pulls(17, "example/project")
        assert result.value.retry_after_seconds == 120
        assert len(requests) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "DELETE"])
async def test_ordinary_requests_do_not_gain_transient_retries(
    private_key: str, method: str
) -> None:
    client, requests = client_for(private_key, [503, 200])
    try:
        result = await client._api_response(method, "/repos/example/project", installation_id=17)
        assert result.status_code == 503
        assert len(requests) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_retry_uses_original_deadline(private_key: str) -> None:
    client, requests = client_for(private_key, [500, 200])
    try:
        await client._installation_token(17)
        client._request_deadline_seconds = 0.25
        with pytest.raises(GitHubError, match="wall-clock deadline"):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stop_interrupts_retry_wait_without_sending_again(private_key: str) -> None:
    requested = asyncio.Event()
    client, requests = client_for(private_key, [500, 200], requested=requested)
    stop = asyncio.Event()
    task = asyncio.create_task(client.list_open_pulls(17, "example/project", stop=stop))
    try:
        async with asyncio.timeout(1):
            await requested.wait()
        stop.set()
        with pytest.raises(GitHubOperationStoppedError):
            await task
        assert len(requests) == 1
        assert client._discovery_cache.entry_count == 0
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await client.close()


@pytest.mark.asyncio
async def test_retry_drops_cached_validator_and_rejects_an_unmatched_304(private_key: str) -> None:
    # Verifies XCO-001 and XCO-014: an error cannot bless an old cached body.
    client, requests = client_for(private_key, [200, 500, 304], {"ETag": '"one"'})
    try:
        assert await client.list_open_pulls(17, "example/project") == []
        with pytest.raises(GitHubError, match="without a matching discovery response"):
            await client.list_open_pulls(17, "example/project")
        assert requests[1].headers["if-none-match"] == '"one"'
        assert "if-none-match" not in requests[2].headers
        assert client._discovery_cache.entry_count == 0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_retry_does_not_hold_the_request_permit(private_key: str) -> None:
    requested = asyncio.Event()
    client, requests = client_for(private_key, [500, 200, 200], requested=requested)
    client._request_semaphore = asyncio.Semaphore(1)
    task = asyncio.create_task(client.list_open_pulls(17, "example/project"))
    try:
        async with asyncio.timeout(0.5):
            await requested.wait()
            result = await client._api_response("GET", "/repos/example/other", installation_id=17)
            assert result.status_code == 200
        assert await task == []
        assert [r.url.path for r in requests] == [
            "/repos/example/project/pulls",
            "/repos/example/other",
            "/repos/example/project/pulls",
        ]
        assert not client._request_semaphore.locked()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await client.close()


@pytest.mark.asyncio
async def test_task_cancellation_during_retry_wait_does_not_send_again(private_key: str) -> None:
    requested = asyncio.Event()
    client, requests = client_for(private_key, [500, 200], requested=requested)
    task = asyncio.create_task(client.list_open_pulls(17, "example/project"))
    try:
        async with asyncio.timeout(1):
            await requested.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(requests) == 1
        assert client._discovery_cache.entry_count == 0
        assert not client._request_semaphore.locked()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("deferred", [False, True])
async def test_each_retry_needs_shared_quota_admission(private_key: str, deferred: bool) -> None:
    reset = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    client, requests = client_for(
        private_key,
        [500, 200],
        {
            "x-ratelimit-resource": "core",
            "x-ratelimit-limit": "100",
            "x-ratelimit-remaining": "90",
            "x-ratelimit-reset": str(reset),
        },
    )
    budget = Mock(spec=RecoveryApiBudget)
    budget.admit.side_effect = [None, RecoveryBudgetDeferredError(5) if deferred else None]
    client._recovery_budget = budget
    try:
        with request_lane("recovery"):
            if deferred:
                with pytest.raises(RecoveryBudgetDeferredError):
                    await client.list_open_pulls(17, "example/project")
            else:
                assert await client.list_open_pulls(17, "example/project") == []
        assert budget.admit.call_args_list == [call(17, recovery=True), call(17, recovery=True)]
        assert len(requests) == (1 if deferred else 2)
        assert budget.observe.call_count == len(requests)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE"])
async def test_discovery_marker_cannot_enable_write_retries(private_key: str, method: str) -> None:
    # Verifies XCO-008: a discovery marker never permits retrying an uncertain write.
    client, requests = client_for(private_key, [503, 200])
    try:
        result = await client._api_response(
            method, "/repos/example/project", installation_id=17, discovery_cache_status="absent"
        )
        assert result.status_code == 503
        assert len(requests) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("app_authenticated,unauthenticated", [(True, False), (False, True)])
async def test_discovery_marker_cannot_enable_other_authentication_retries(
    private_key: str, app_authenticated: bool, unauthenticated: bool
) -> None:
    client, requests = client_for(private_key, [503, 200])
    try:
        result = await client._api_response(
            "GET",
            "/app/installations",
            installation_id=17,
            app_authenticated=app_authenticated,
            unauthenticated=unauthenticated,
            discovery_cache_status="absent",
        )
        assert result.status_code == 503
        assert len(requests) == 1
    finally:
        await client.close()
