from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from extra_codeowners.api_budget import CoreQuota, RecoveryApiBudget
from extra_codeowners.database import InstallationApiBudget, QueueStore, utcnow
from extra_codeowners.github import (
    GitHubAPIError,
    GitHubClient,
    GitHubError,
    GitHubOperationStoppedError,
)
from extra_codeowners.metrics import GITHUB_PHYSICAL_REQUESTS
from extra_codeowners.migrations import upgrade_database


def token_response() -> dict[str, str]:
    return {
        "token": "installation-token",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }


def quota_headers(remaining: int, reset: int) -> dict[str, str]:
    return {
        "x-ratelimit-resource": "core",
        "x-ratelimit-limit": "100",
        "x-ratelimit-remaining": str(remaining),
        "x-ratelimit-reset": str(reset),
    }


def response(
    status: int, payload: Any = None, *, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers or {})


def client_for(handler: Any, private_key: str) -> GitHubClient:
    return GitHubClient(1, private_key, transport=httpx.MockTransport(handler))


async def close(client: GitHubClient) -> None:
    await client.close()


@pytest.mark.asyncio
async def test_open_pulls_200_then_304_replays_unchanged_body(private_key: str) -> None:
    calls: list[httpx.Request] = []
    body = [{"number": 1, "title": "one"}]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        if len([item for item in calls if item.url.path.endswith("/pulls")]) == 1:
            return response(200, body, headers={"ETag": '"pulls-v1"'})
        return response(304, headers={"ETag": '"pulls-v1"'})

    client = client_for(handler, private_key)
    try:
        assert await client.list_open_pulls(17, "example/project") == body
        assert await client.list_open_pulls(17, "example/project") == body
    finally:
        await close(client)
    pulls = [request for request in calls if request.url.path.endswith("/pulls")]
    assert len(pulls) == 2
    assert pulls[1].headers["if-none-match"] == '"pulls-v1"'


@pytest.mark.asyncio
async def test_open_pulls_changed_200_replaces_cached_result(private_key: str) -> None:
    bodies = [[{"number": 1}], [{"number": 2}, {"number": 3}]]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        index = len([r for r in requests if r.url.path.endswith("/pulls")]) - 1
        return response(200, bodies[index], headers={"ETag": f'"v{index}"'})

    client = client_for(handler, private_key)
    try:
        assert await client.list_open_pulls(17, "example/project") == bodies[0]
        assert await client.list_open_pulls(17, "example/project") == bodies[1]
    finally:
        await close(client)
    assert requests[-1].headers["if-none-match"] == '"v0"'


@pytest.mark.asyncio
async def test_discovery_cache_isolated_by_installation_repository_and_page(
    private_key: str,
) -> None:
    seen: list[tuple[int, str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        seen.append(
            (
                int(request.headers["authorization"].endswith("token")),
                request.url.path,
                request.headers.get("if-none-match"),
            )
        )
        return response(200, [{"id": len(seen)}], headers={"ETag": f'"{len(seen)}"'})

    client = client_for(handler, private_key)
    try:
        await client.list_open_pulls(17, "example/one")
        await client.list_open_pulls(18, "example/one")
        await client.list_open_pulls(17, "example/two")
        await client.list_open_pulls(17, "example/one")
    finally:
        await close(client)
    assert [item[2] for item in seen] == [None, None, None, '"1"']


@pytest.mark.asyncio
async def test_repositories_all_pages_304_preserves_cached_links(private_key: str) -> None:
    page_calls: list[tuple[int, str | None]] = []
    next_link = '<https://api.github.com/installation/repositories?per_page=100&page=2>; rel="next"'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        page = int(request.url.params["page"])
        etag = f'"page-{page}"'
        page_calls.append((page, request.headers.get("if-none-match")))
        if len(page_calls) <= 2:
            headers = {"ETag": etag}
            if page == 1:
                headers["Link"] = next_link
            return response(
                200, {"total_count": 2, "repositories": [{"id": page}]}, headers=headers
            )
        return response(304, headers={"ETag": etag})

    client = client_for(handler, private_key)
    try:
        first = await client.list_installation_repositories(17)
        second = await client.list_installation_repositories(17)
    finally:
        await close(client)
    assert first == second == [{"id": 1}, {"id": 2}]
    assert page_calls == [(1, None), (2, None), (1, '"page-1"'), (2, '"page-2"')]


@pytest.mark.asyncio
async def test_repositories_changed_pagination_total_is_revalidated(private_key: str) -> None:
    calls: list[tuple[int, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        page = int(request.url.params["page"])
        calls.append((page, request.headers.get("if-none-match")))
        if len(calls) == 1:
            return response(
                200, {"total_count": 1, "repositories": [{"id": 1}]}, headers={"ETag": '"one"'}
            )
        if len(calls) == 2:
            return response(
                200,
                {"total_count": 2, "repositories": [{"id": 1}]},
                headers={
                    "ETag": '"two"',
                    "Link": (
                        "<https://api.github.com/installation/repositories?per_page=100&page=2>; "
                        'rel="next"'
                    ),
                },
            )
        return response(
            200, {"total_count": 2, "repositories": [{"id": 2}]}, headers={"ETag": '"three"'}
        )

    client = client_for(handler, private_key)
    try:
        assert await client.list_installation_repositories(17) == [{"id": 1}]
        assert await client.list_installation_repositories(17) == [{"id": 1}, {"id": 2}]
    finally:
        await close(client)
    assert calls == [(1, None), (1, '"one"'), (2, None)]


@pytest.mark.asyncio
async def test_304_without_cache_fails(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        return response(304)

    client = client_for(handler, private_key)
    try:
        with pytest.raises(GitHubError, match="without a matching"):
            await client.list_open_pulls(17, "example/project")
    finally:
        await close(client)


@pytest.mark.asyncio
async def test_401_retry_removes_conditional_header_and_refreshes_token(private_key: str) -> None:
    calls: list[tuple[str, str | None]] = []
    token_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls
        if request.url.path.endswith("/access_tokens"):
            token_calls += 1
            return response(200, {**token_response(), "token": f"token-{token_calls}"})
        calls.append((request.headers["authorization"], request.headers.get("if-none-match")))
        if len(calls) == 1:
            return response(200, [{"number": 1}], headers={"ETag": '"old"'})
        if len(calls) == 2:
            return response(401, {"message": "expired"})
        return response(200, [{"number": 2}], headers={"ETag": '"new"'})

    client = client_for(handler, private_key)
    try:
        await client.list_open_pulls(17, "example/project")
        assert await client.list_open_pulls(17, "example/project") == [{"number": 2}]
    finally:
        await close(client)
    assert token_calls == 2
    assert calls == [
        ("Bearer token-1", None),
        ("Bearer token-1", '"old"'),
        ("Bearer token-2", None),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 404])
async def test_error_never_falls_back_to_stale_cache(private_key: str, status: int) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        calls += 1
        return (
            response(200, [{"number": 1}], headers={"ETag": '"old"'})
            if calls == 1
            else response(status, {"message": "no"})
        )

    client = client_for(handler, private_key)
    try:
        await client.list_open_pulls(17, "example/project")
        with pytest.raises(GitHubAPIError) as caught:
            await client.list_open_pulls(17, "example/project")
        assert caught.value.status_code == status
    finally:
        await close(client)
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers", [{}, {"ETag": '"x"', "Cache-Control": "no-store"}, {"ETag": '"x"', "Vary": "*"}]
)
async def test_unvalidated_responses_are_not_cached(
    private_key: str, headers: dict[str, str]
) -> None:
    pulls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal pulls
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        pulls += 1
        return response(200, [{"number": pulls}], headers=headers)

    client = client_for(handler, private_key)
    try:
        await client.list_open_pulls(17, "example/project")
        await client.list_open_pulls(17, "example/project")
    finally:
        await close(client)
    assert pulls == 2


@pytest.mark.asyncio
async def test_oversized_response_is_not_cached(private_key: str) -> None:
    pulls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal pulls
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        pulls += 1
        return response(200, [{"number": pulls}], headers={"ETag": '"x"'})

    client = client_for(handler, private_key)
    client._discovery_cache.max_entry_bytes = 1  # bounded test-only cache configuration
    try:
        await client.list_open_pulls(17, "example/project")
        await client.list_open_pulls(17, "example/project")
    finally:
        await close(client)
    assert pulls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [({}, None), ([{"number": 1}], "malformed")])
async def test_malformed_body_or_link_is_not_retained(
    private_key: str, bad: tuple[Any, str | None]
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        calls += 1
        if calls == 1:
            headers = {"ETag": '"bad"'}
            if bad[1]:
                headers["Link"] = "<broken; rel=next"
            return response(200, bad[0], headers=headers)
        return response(200, [{"number": 2}], headers={"ETag": '"good"'})

    client = client_for(handler, private_key)
    try:
        with pytest.raises(GitHubError):
            await client.list_open_pulls(17, "example/project")
        assert await client.list_open_pulls(17, "example/project") == [{"number": 2}]
    finally:
        await close(client)
    assert calls == 2


@pytest.mark.asyncio
async def test_cancellation_discards_stale_cache(private_key: str) -> None:
    calls = 0
    stop = asyncio.Event()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        calls += 1
        return response(200, [{"number": calls}], headers={"ETag": '"old"'})

    client = client_for(handler, private_key)
    try:
        await client.list_open_pulls(17, "example/project")
        stop.set()
        with pytest.raises(GitHubOperationStoppedError):
            await client.list_open_pulls(17, "example/project", stop=stop)
        stop.clear()
        assert await client.list_open_pulls(17, "example/project") == [{"number": 2}]
    finally:
        await close(client)
    assert calls == 2


@pytest.mark.asyncio
async def test_mutating_returned_json_does_not_change_cached_bytes(private_key: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return response(200, token_response())
        calls += 1
        return (
            response(200, [{"number": 1, "nested": {"ok": True}}], headers={"ETag": '"same"'})
            if calls == 1
            else response(304)
        )

    client = client_for(handler, private_key)
    try:
        first = await client.list_open_pulls(17, "example/project")
        first[0]["number"] = 99
        first[0]["nested"]["ok"] = False
        assert await client.list_open_pulls(17, "example/project") == [
            {"number": 1, "nested": {"ok": True}}
        ]
    finally:
        await close(client)


def test_304_refunds_own_budget_but_counts_physical_request(
    tmp_path: Path, private_key: str
) -> None:
    store = QueueStore(f"sqlite:///{tmp_path / 'budget.db'}")
    upgrade_database(str(store.engine.url))
    store.initialize()
    try:
        budget = RecoveryApiBudget(store)
        reset = (utcnow() + timedelta(hours=1)).replace(microsecond=0)
        budget.observe(17, CoreQuota(100, 91, reset))
        physical_before = GITHUB_PHYSICAL_REQUESTS.labels(
            "get.other", "installation", "interactive"
        )._value.get()

        responses = iter(
            [
                response(200, token_response()),
                response(
                    200,
                    [{"number": 1}],
                    headers={**quota_headers(90, int(reset.timestamp())), "ETag": '"same"'},
                ),
                response(
                    304, headers={**quota_headers(90, int(reset.timestamp())), "ETag": '"same"'}
                ),
            ]
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return next(responses)

        client = GitHubClient(
            1, private_key, transport=httpx.MockTransport(handler), recovery_budget=budget
        )

        async def run() -> None:
            try:
                assert await client.list_open_pulls(17, "example/project") == [{"number": 1}]
                with store.session() as session:
                    row = session.get(InstallationApiBudget, 17)
                    assert row is not None and row.remaining == 90
                assert await client.list_open_pulls(17, "example/project") == [{"number": 1}]
            finally:
                await client.close()

        asyncio.run(run())
        with store.session() as session:
            row = session.get(InstallationApiBudget, 17)
            assert row is not None and row.remaining == 90
        physical_after = GITHUB_PHYSICAL_REQUESTS.labels(
            "get.other", "installation", "interactive"
        )._value.get()
        assert physical_after - physical_before == 2
    finally:
        store.close()
