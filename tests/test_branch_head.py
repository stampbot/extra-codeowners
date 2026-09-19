"""Validate current branch references independently of PR metadata."""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from extra_codeowners.github import (
    GitHubAPIError,
    GitHubClient,
    GitHubError,
    GitHubOperationStoppedError,
)


def token() -> httpx.Response:
    return httpx.Response(
        201,
        json={"token": "test", "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
    )


def reference(branch: str, sha: str) -> dict[str, Any]:
    return {"ref": f"refs/heads/{branch}", "object": {"type": "commit", "sha": sha}}


@pytest.mark.asyncio
async def test_branch_head_revalidates_each_read_and_observes_new_commit(private_key: str) -> None:
    calls: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return token()
        calls.append(request)
        assert request.url.path == "/repos/example/project/git/ref/heads/release/one"
        if len(calls) == 1:
            assert "if-none-match" not in request.headers
            return httpx.Response(
                200, json=reference("release/one", "a" * 40), headers={"etag": '"one"'}
            )
        assert request.headers["if-none-match"] == '"one"'
        if len(calls) == 2:
            return httpx.Response(304)
        return httpx.Response(
            200, json=reference("release/one", "b" * 40), headers={"etag": '"two"'}
        )

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        assert await client.get_branch_head(17, "example/project", "release/one") == "a" * 40
        assert await client.get_branch_head(17, "example/project", "release/one") == "a" * 40
        assert await client.get_branch_head(17, "example/project", "release/one") == "b" * 40
        assert len(calls) == 3
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"ref": "refs/heads/other", "object": {"type": "commit", "sha": "a" * 40}},
        {"ref": "refs/heads/main", "object": {"type": "tag", "sha": "a" * 40}},
        {"ref": "refs/heads/main", "object": {"type": "commit", "sha": True}},
        {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "A" * 40}},
        {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "a" * 39}},
    ],
)
async def test_branch_head_rejects_malformed_or_mismatched_reference(
    private_key: str, payload: Any
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return (
            token()
            if request.url.path.endswith("/access_tokens")
            else httpx.Response(200, json=payload)
        )

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(GitHubError):
            await client.get_branch_head(17, "example/project", "main")
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "branch", ["", "../main", "main/..", "a//b", "/main", "main\n", "\ud800", "x" * 1025]
)
async def test_branch_head_rejects_unsafe_path_before_http(private_key: str, branch: str) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid branch must not make an HTTP request")

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(GitHubError):
            await client.get_branch_head(17, "example/project", branch)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_missing_branch_discards_conditional_state(private_key: str) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return token()
        calls += 1
        if calls == 2:
            assert request.headers["if-none-match"] == '"one"'
            return httpx.Response(404, json={"message": "Not found"})
        assert "if-none-match" not in request.headers
        return httpx.Response(200, json=reference("main", "a" * 40), headers={"etag": '"one"'})

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        assert await client.get_branch_head(17, "example/project", "main") == "a" * 40
        with pytest.raises(GitHubAPIError):
            await client.get_branch_head(17, "example/project", "main")
        assert await client.get_branch_head(17, "example/project", "main") == "a" * 40
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content,headers",
    [
        (b'{"ref":"refs/heads/main","ref":"refs/heads/main"}', {}),
        (b'{"ref":"refs/heads/main","object":NaN}', {}),
        (b"\xff", {}),
        (b" " * (64 * 1024 + 1), {}),
        (b"{}", {"link": '<https://api.github.com/next>; rel="next"'}),
    ],
)
async def test_invalid_branch_response_is_not_cached(
    private_key: str, content: bytes, headers: dict[str, str]
) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return token()
        calls += 1
        assert "if-none-match" not in request.headers
        if calls == 1:
            return httpx.Response(200, content=content, headers={"etag": '"bad"', **headers})
        return httpx.Response(200, json=reference("main", "a" * 40))

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(GitHubError):
            await client.get_branch_head(17, "example/project", "main")
        assert await client.get_branch_head(17, "example/project", "main") == "a" * 40
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_branch_cache_does_not_cross_installations(private_key: str) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return token()
        calls += 1
        assert "if-none-match" not in request.headers
        return httpx.Response(
            200,
            json=reference("main", ("a" if calls == 1 else "b") * 40),
            headers={"etag": '"branch"'},
        )

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        assert await client.get_branch_head(17, "example/project", "main") == "a" * 40
        assert await client.get_branch_head(18, "example/project", "main") == "b" * 40
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stopped_branch_lookup_never_uses_cached_authority(private_key: str) -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return token()
        calls += 1
        assert calls == 1
        return httpx.Response(200, json=reference("main", "a" * 40), headers={"etag": '"one"'})

    client = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        assert await client.get_branch_head(17, "example/project", "main") == "a" * 40
        stop = asyncio.Event()
        stop.set()
        with pytest.raises(GitHubOperationStoppedError):
            await client.get_branch_head(17, "example/project", "main", stop=stop)
    finally:
        await client.close()
