"""Transient discovery retries stay bounded, authenticated and observable."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
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
from extra_codeowners.discovery_cache import CacheLookupStatus
from extra_codeowners.github import (
    GitHubAPIError,
    GitHubClient,
    GitHubError,
    GitHubOperationStoppedError,
    GitHubRateLimitError,
)
from extra_codeowners.metrics import GITHUB_API_PHASE_SECONDS, GITHUB_PHYSICAL_REQUESTS

type Reply = int | type[httpx.RequestError]


def client_for(
    private_key: str,
    statuses: Sequence[Reply],
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
        if not isinstance(status, int):
            raise status("fictional private transport detail", request=request)
        payload: Any = [] if status == 200 else {"message": "unavailable"}
        return httpx.Response(status, json=payload, headers=headers or {})

    return GitHubClient(7, private_key, transport=httpx.MockTransport(respond)), requests


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [500, 502, 503, 504, httpx.RemoteProtocolError])
async def test_discovery_retries_one_transient_response(private_key: str, status: Reply) -> None:
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
@pytest.mark.parametrize(
    "statuses",
    [
        [500, 401, 200],
        [401, 500, 200],
        [httpx.RemoteProtocolError, 401, 200],
        [401, httpx.RemoteProtocolError, 200],
    ],
)
async def test_one_token_refresh_and_one_transient_retry_share_the_bound(
    private_key: str, statuses: list[Reply]
) -> None:
    client, requests = client_for(private_key, statuses)
    try:
        assert await client.list_open_pulls(17, "example/project") == []
        assert len(requests) == 3
        assert requests[-1].headers["authorization"] == "Bearer fictional-token-2"
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "statuses", [[401, 401], [500, 401, 401], [httpx.RemoteProtocolError, 401, 401]]
)
async def test_repeated_authentication_failure_does_not_gain_token_retries(
    private_key: str, statuses: list[Reply]
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
@pytest.mark.parametrize("transient", [500, httpx.RemoteProtocolError])
async def test_retry_uses_original_deadline(private_key: str, transient: Reply) -> None:
    client, requests = client_for(private_key, [transient, 200])
    try:
        await client._installation_token(17)
        client._request_deadline_seconds = 0.25
        with pytest.raises(GitHubError, match="wall-clock deadline"):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("transient", [500, httpx.RemoteProtocolError])
async def test_stop_interrupts_retry_wait_without_sending_again(
    private_key: str, transient: Reply
) -> None:
    requested = asyncio.Event()
    client, requests = client_for(private_key, [transient, 200], requested=requested)
    stop = asyncio.Event()
    task = asyncio.create_task(client.list_open_pulls(17, "example/project", stop=stop))
    try:
        async with asyncio.timeout(1):
            await requested.wait()
        stop.set()
        with pytest.raises(GitHubOperationStoppedError):
            await asyncio.gather(task)
        assert len(requests) == 1
        assert client._discovery_cache.entry_count == 0
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("transient", [500, httpx.RemoteProtocolError])
async def test_retry_drops_cached_validator_and_rejects_an_unmatched_304(
    private_key: str, transient: Reply
) -> None:
    # Verifies XCO-001 and XCO-014: an error cannot bless an old cached body.
    client, requests = client_for(private_key, [200, transient, 304], {"ETag": '"one"'})
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
@pytest.mark.parametrize("transient", [500, httpx.RemoteProtocolError])
async def test_retry_does_not_hold_the_request_permit(private_key: str, transient: Reply) -> None:
    requested = asyncio.Event()
    client, requests = client_for(private_key, [transient, 200, 200], requested=requested)
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
@pytest.mark.parametrize("transient", [500, httpx.RemoteProtocolError])
async def test_task_cancellation_during_retry_wait_does_not_send_again(
    private_key: str, transient: Reply
) -> None:
    requested = asyncio.Event()
    client, requests = client_for(private_key, [transient, 200], requested=requested)
    task = asyncio.create_task(client.list_open_pulls(17, "example/project"))
    try:
        async with asyncio.timeout(1):
            await requested.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.gather(task)
        assert len(requests) == 1
        assert client._discovery_cache.entry_count == 0
        assert not client._request_semaphore.locked()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("deferred", [False, True])
@pytest.mark.parametrize("transient", [500, httpx.RemoteProtocolError])
async def test_each_retry_needs_shared_quota_admission(
    private_key: str, deferred: bool, transient: Reply
) -> None:
    reset = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    client, requests = client_for(
        private_key,
        [transient, 200],
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
        # A disconnect has no quota headers and cannot justify a refund.
        assert budget.observe.call_count == len(requests) - int(
            transient is httpx.RemoteProtocolError
        )
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "statuses",
    [
        [httpx.RemoteProtocolError, httpx.RemoteProtocolError, 200],
        [httpx.RemoteProtocolError, 500, 200],
        [500, httpx.RemoteProtocolError, 200],
        [401, httpx.RemoteProtocolError, 503, 200],
        [httpx.RemoteProtocolError, 401, httpx.RemoteProtocolError, 200],
    ],
)
async def test_disconnect_and_server_errors_share_one_retry(
    private_key: str, statuses: list[Reply]
) -> None:
    # Verifies XCO-001: exhausting the retry budget cannot supply stale evidence.
    client, requests = client_for(private_key, statuses)
    try:
        with pytest.raises((GitHubAPIError, httpx.RemoteProtocolError)):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == len(statuses) - 1
        assert client._discovery_cache.entry_count == 0
        assert not client._request_semaphore.locked()
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,marker",
    [
        ("GET", None),
        ("POST", None),
        ("PATCH", None),
        ("DELETE", None),
        ("POST", "absent"),
        ("PATCH", "absent"),
        ("DELETE", "absent"),
    ],
)
async def test_disconnect_does_not_enable_ordinary_or_write_retries(
    private_key: str, method: str, marker: CacheLookupStatus | None
) -> None:
    # Verifies XCO-008: a lost write response is not a replay-safe discovery read.
    client, requests = client_for(private_key, [httpx.RemoteProtocolError, 200])
    try:
        with pytest.raises(httpx.RemoteProtocolError):
            await client._api_response(
                method,
                "/repos/example/project",
                installation_id=17,
                discovery_cache_status=marker,
            )
        assert len(requests) == 1
        assert not client._request_semaphore.locked()
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("app_authenticated,unauthenticated", [(True, False), (False, True)])
async def test_disconnect_does_not_retry_other_authentication_modes(
    private_key: str, app_authenticated: bool, unauthenticated: bool
) -> None:
    client, requests = client_for(private_key, [httpx.RemoteProtocolError, 200])
    try:
        with pytest.raises(httpx.RemoteProtocolError):
            await client._api_response(
                "GET",
                "/app/installations",
                installation_id=17,
                app_authenticated=app_authenticated,
                unauthenticated=unauthenticated,
                discovery_cache_status="absent",
            )
        assert len(requests) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError,
        httpx.ReadError,
        httpx.ReadTimeout,
        httpx.WriteError,
        httpx.PoolTimeout,
        httpx.LocalProtocolError,
    ],
)
async def test_other_transport_failures_do_not_gain_inline_retries(
    private_key: str, error: type[httpx.RequestError]
) -> None:
    client, requests = client_for(private_key, [error, 200])
    try:
        with pytest.raises(error):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == 1
        assert client._discovery_cache.entry_count == 0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stream_disconnect_does_not_gain_an_inline_retry(private_key: str) -> None:
    client, requests = client_for(private_key, [httpx.RemoteProtocolError, 200])
    try:
        with pytest.raises(httpx.RemoteProtocolError):
            await client.get_file_text(17, "example/project", "policy.toml", ref="b" * 40)
        assert len(requests) == 1
        assert not client._request_semaphore.locked()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_token_request_disconnect_is_not_retried_as_discovery(private_key: str) -> None:
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise httpx.RemoteProtocolError("fictional transport detail", request=request)

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(httpx.RemoteProtocolError):
            await client.list_open_pulls(17, "example/project")
        assert len(requests) == 1
        assert requests[0].url.path.endswith("/access_tokens")
        assert client._discovery_cache.entry_count == 0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_persistent_disconnect_discards_an_existing_cached_body(private_key: str) -> None:
    # Verifies XCO-001 and XCO-014: failed validation cannot preserve old evidence.
    client, requests = client_for(
        private_key,
        [200, httpx.RemoteProtocolError, httpx.RemoteProtocolError],
        {"ETag": '"one"'},
    )
    try:
        assert await client.list_open_pulls(17, "example/project") == []
        assert client._discovery_cache.entry_count == 1
        with pytest.raises(httpx.RemoteProtocolError):
            await client.list_open_pulls(17, "example/project")
        assert client._discovery_cache.entry_count == 0
        assert len(requests) == 3
        assert requests[1].headers["if-none-match"] == '"one"'
        assert "if-none-match" not in requests[2].headers
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stream_body_disconnect_is_closed_without_retry(private_key: str) -> None:
    class BrokenBody(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"partial body"
            raise httpx.RemoteProtocolError("fictional body disconnect")

        async def aclose(self) -> None:
            self.closed = True

    body = BrokenBody()
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "fictional-token",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        requests.append(request)
        return httpx.Response(200, stream=body)

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(httpx.RemoteProtocolError):
            await client.get_file_text(17, "example/project", "policy.toml", ref="b" * 40)
        assert len(requests) == 1
        assert body.closed
        assert not client._request_semaphore.locked()
    finally:
        await client.close()
