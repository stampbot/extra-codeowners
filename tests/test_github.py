import asyncio
import gzip
import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from typing import cast

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

from extra_codeowners.dco import (
    MAX_PULL_COMMITS,
    GitHubActor,
    PullRequestSnapshot,
    RepositoryIdentity,
)
from extra_codeowners.github import (
    MAX_JSON_RESPONSE_DEPTH,
    GitHubAPIError,
    GitHubClient,
    GitHubError,
    GitHubRateLimitError,
    PullRequestTooLargeError,
)


def token_response() -> dict[str, str]:
    return {
        "token": "installation-token",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }


def unexpected_request(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"unexpected request: {request.method} {request.url}")


class TrackingStream(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.chunks_read = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.chunks_read += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def commit_sha(number: int) -> str:
    return f"{number:040x}"


def dco_pull_snapshot(
    *,
    count: int = 1,
    base_sha: str = commit_sha(10_000),
    head_sha: str = commit_sha(1),
    head_repository: RepositoryIdentity | None = None,
) -> PullRequestSnapshot:
    repository = RepositoryIdentity(id=100, full_name="example/project")
    return PullRequestSnapshot(
        number=7,
        state="open",
        repository=repository,
        base_repository=repository,
        base_ref="main",
        base_sha=base_sha,
        head_repository=head_repository or repository,
        head_ref="feature/dco",
        head_sha=head_sha,
        author=GitHubActor(login="contributor", id=200, type="User"),
        commit_count=count,
    )


def graphql_pull_page(
    pull: PullRequestSnapshot,
    shas: list[str],
    *,
    total_count: object | None = None,
    has_next_page: object = False,
    end_cursor: object = "final-cursor",
) -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "databaseId": pull.repository.id,
                "nameWithOwner": pull.repository.full_name,
                "pullRequest": {
                    "number": pull.number,
                    "state": pull.state.upper(),
                    "baseRefName": pull.base_ref,
                    "baseRefOid": pull.base_sha,
                    "baseRepository": {
                        "databaseId": pull.base_repository.id,
                        "nameWithOwner": pull.base_repository.full_name,
                    },
                    "headRefName": pull.head_ref,
                    "headRefOid": pull.head_sha,
                    "headRepository": {
                        "databaseId": pull.head_repository.id,
                        "nameWithOwner": pull.head_repository.full_name,
                    },
                    "commits": {
                        "totalCount": (pull.commit_count if total_count is None else total_count),
                        "nodes": [{"id": f"PRC_{sha}", "commit": {"oid": sha}} for sha in shas],
                        "pageInfo": {
                            "hasNextPage": has_next_page,
                            "endCursor": end_cursor,
                        },
                    },
                },
            }
        }
    }


def graphql_commit_detail(
    pull: PullRequestSnapshot,
    sha: str,
    *,
    message: str = "test: change\n\nSigned-off-by: Contributor <contributor@example.com>",
    parents: list[str] | None = None,
) -> dict[str, object]:
    node_id = f"PRC_{sha}"
    parent_shas = parents if parents is not None else [pull.base_sha]
    return {
        "data": {
            "node": {
                "__typename": "PullRequestCommit",
                "id": node_id,
                "pullRequest": {
                    "number": pull.number,
                    "state": pull.state.upper(),
                    "baseRefName": pull.base_ref,
                    "baseRefOid": pull.base_sha,
                    "baseRepository": {
                        "databaseId": pull.base_repository.id,
                        "nameWithOwner": pull.base_repository.full_name,
                    },
                    "headRefName": pull.head_ref,
                    "headRefOid": pull.head_sha,
                    "headRepository": {
                        "databaseId": pull.head_repository.id,
                        "nameWithOwner": pull.head_repository.full_name,
                    },
                    "repository": {
                        "databaseId": pull.repository.id,
                        "nameWithOwner": pull.repository.full_name,
                    },
                },
                "commit": {
                    "oid": sha,
                    "parents": {
                        "totalCount": len(parent_shas),
                        "nodes": [{"oid": parent} for parent in parent_shas],
                        "pageInfo": {"hasNextPage": False, "endCursor": "parent-cursor"},
                    },
                    "message": message,
                    "author": {
                        "name": "Contributor",
                        "email": "contributor@example.com",
                        "user": {"login": "contributor", "databaseId": 200},
                    },
                    "committer": {
                        "name": "Contributor",
                        "email": "contributor@example.com",
                        "user": {"login": "contributor", "databaseId": 200},
                    },
                    "signature": None,
                },
            }
        }
    }


@pytest.mark.asyncio
async def test_reads_raw_content_at_exact_ref(private_key: str) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        assert request.headers["accept"] == "application/vnd.github.raw+json"
        return httpx.Response(200, content=b"enabled = true\n")

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    content = await client.get_file_text(
        2, "example/project", ".github/extra-codeowners.toml", ref="base-sha"
    )
    await client.close()

    assert content == "enabled = true\n"
    assert requests[-1].url.params["ref"] == "base-sha"


@pytest.mark.asyncio
async def test_raw_content_enforces_caller_limit(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, content=b"12345")

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    with pytest.raises(GitHubError, match="4-byte file limit"):
        await client.get_file_text(2, "example/project", "policy", max_bytes=4)
    await client.close()


@pytest.mark.asyncio
async def test_raw_content_rejects_declared_oversize_before_streaming(
    private_key: str,
) -> None:
    stream = TrackingStream(b"12345")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, headers={"Content-Length": "5"}, stream=stream)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="4-byte file limit"):
        await client.get_file_text(2, "example/project", "policy", max_bytes=4)
    await client.close()

    assert stream.chunks_read == 0
    assert stream.closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [{}, {"Transfer-Encoding": "chunked"}],
    ids=["no-content-length", "chunked"],
)
async def test_raw_content_caps_undeclared_streams(
    private_key: str,
    headers: dict[str, str],
) -> None:
    stream = TrackingStream(b"12", b"345")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, headers=headers, stream=stream)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="4-byte file limit"):
        await client.get_file_text(2, "example/project", "policy", max_bytes=4)
    await client.close()

    assert stream.chunks_read == 2
    assert stream.closed is True


@pytest.mark.asyncio
async def test_raw_content_tolerates_malformed_length_and_enforces_stream_limit(
    private_key: str,
) -> None:
    stream = TrackingStream(b"1234", b"5")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            headers={"Content-Length": "not-a-number"},
            stream=stream,
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="4-byte file limit"):
        await client.get_file_text(2, "example/project", "policy", max_bytes=4)
    await client.close()

    assert stream.chunks_read == 2
    assert stream.closed is True


@pytest.mark.asyncio
async def test_raw_content_accepts_malformed_length_with_bounded_body(
    private_key: str,
) -> None:
    stream = TrackingStream(b"1234")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            headers={"Content-Length": "not-a-number"},
            stream=stream,
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    assert await client.get_file_text(2, "example/project", "policy", max_bytes=4) == "1234"
    await client.close()

    assert stream.chunks_read == 1
    assert stream.closed is True


@pytest.mark.asyncio
async def test_raw_content_refreshes_rejected_installation_token(private_key: str) -> None:
    token_calls = 0
    content_calls = 0
    rejected = TrackingStream(b'{"message":"Bad credentials"}')

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls, content_calls
        if request.url.path.endswith("/access_tokens"):
            token_calls += 1
            return httpx.Response(
                201,
                json={
                    "token": f"installation-token-{token_calls}",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        content_calls += 1
        if request.headers["authorization"] == "Bearer installation-token-1":
            return httpx.Response(401, stream=rejected)
        return httpx.Response(200, stream=TrackingStream(b"enabled = true\n"))

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    assert await client.get_file_text(2, "example/project", "policy") == "enabled = true\n"
    await client.close()

    assert token_calls == 2
    assert content_calls == 2
    assert rejected.closed is True


@pytest.mark.asyncio
async def test_raw_content_reads_only_bounded_error_prefix(private_key: str) -> None:
    stream = TrackingStream(b"deny", b"unread error detail")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(500, stream=stream)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAPIError, match="returned 500: deny"):
        await client.get_file_text(2, "example/project", "policy", max_bytes=4)
    await client.close()

    assert stream.chunks_read == 1
    assert stream.closed is True


@pytest.mark.asyncio
async def test_raw_content_does_not_decode_bounded_error_prefix_twice(private_key: str) -> None:
    compressed = gzip.compress(b'{"message":"compressed denial"}')

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            500,
            headers={"Content-Encoding": "gzip"},
            stream=TrackingStream(compressed),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAPIError, match="compressed denial"):
        await client.get_file_text(2, "example/project", "policy")
    await client.close()


@pytest.mark.asyncio
async def test_content_path_url_delimiters_are_percent_encoded(private_key: str) -> None:
    observed_path = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal observed_path
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        observed_path = request.url.raw_path.decode()
        return httpx.Response(200, content=b"enabled = true\n")

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    await client.get_file_text(2, "example/project", ".github/a #100%.toml")
    await client.close()

    assert observed_path.endswith("/.github/a%20%23100%25.toml")


@pytest.mark.asyncio
async def test_pull_files_fail_closed_at_github_cap(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        page = int(request.url.params["page"])
        if page > 30:
            return httpx.Response(200, json=[])
        start = (page - 1) * 100
        return httpx.Response(
            200,
            json=[
                {"filename": f"files/{index}", "status": "modified"}
                for index in range(start, start + 100)
            ],
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    with pytest.raises(PullRequestTooLargeError, match="3,000-file"):
        await client.get_pull_files(2, "example/project", 3)
    await client.close()


@pytest.mark.asyncio
async def test_check_run_is_created_for_current_app(private_key: str) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.method == "GET":
            return httpx.Response(200, json={"total_count": 0, "check_runs": []})
        return httpx.Response(201, json={"id": 99})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    check_id = await client.upsert_check_run(
        2,
        "example/project",
        "a" * 40,
        "Extra CODEOWNERS / approval",
        conclusion="success",
        title="Satisfied",
        summary="All owner sets are satisfied.",
    )
    await client.close()

    assert check_id == 99
    create = requests[-1]
    assert create.method == "POST"
    assert json.loads(create.content)["conclusion"] == "success"


@pytest.mark.asyncio
async def test_completed_check_can_be_moved_back_to_in_progress(private_key: str) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.method == "GET":
            return httpx.Response(
                200,
                json={"check_runs": [{"id": 77, "name": "check", "app": {"id": 1}}]},
            )
        return httpx.Response(200, json={"id": 77})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    await client.upsert_check_run(
        2,
        "example/project",
        "a" * 40,
        "check",
        status="in_progress",
        title="Evaluating",
        summary="Approval blocked",
    )
    await client.close()

    payload = json.loads(requests[-1].content)
    assert payload["status"] == "in_progress"
    assert "conclusion" not in payload
    assert "completed_at" not in payload


def test_invalid_private_key_is_rejected_at_startup() -> None:
    with pytest.raises(ValueError, match="valid unencrypted PEM"):
        GitHubClient(1, "not-a-private-key")


def test_api_error_truncates_json_message() -> None:
    """A structured API error must not bypass the diagnostic-size limit."""

    response = httpx.Response(500, json={"message": "x" * 1001})

    assert GitHubClient._response_message(response) == "x" * 1000


@pytest.mark.parametrize("retry_after", ["INF", "-INF", "NAN"])
def test_non_finite_retry_after_uses_bounded_default(retry_after: str) -> None:
    response = httpx.Response(429, headers={"Retry-After": retry_after})

    assert GitHubClient._retry_delay(response, "rate limit") == 60


@pytest.mark.asyncio
async def test_installation_token_is_downscoped_without_status_write(private_key: str) -> None:
    token_request: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            token_request.update(json.loads(request.content))
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json={"state": "open"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    await client.get_pull(2, "example/project", 3)
    await client.close()

    assert token_request["permissions"] == {
        "checks": "write",
        "contents": "read",
        "members": "read",
        "pull_requests": "read",
    }


@pytest.mark.asyncio
async def test_codeowners_validation_404_fails_closed(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(404, json={"message": "Not Found"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAPIError, match="404"):
        await client.get_codeowners_errors(2, "example/project", "base")
    await client.close()


@pytest.mark.asyncio
async def test_read_helpers_share_installation_token_and_validate_shapes(private_key: str) -> None:
    token_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls
        path = request.url.path
        if path.endswith("/access_tokens"):
            token_calls += 1
            return httpx.Response(201, json=token_response())
        if path == "/repos/example/project/pulls/3/reviews":
            return httpx.Response(200, json=[{"id": 1}])
        if path == "/repos/example/project/codeowners/errors":
            return httpx.Response(200, json={"errors": [{"line": 2, "message": "Invalid owner"}]})
        if path.endswith("/memberships/octocat"):
            return httpx.Response(200, json={"state": "active"})
        if path.endswith("/collaborators/octocat/permission"):
            return httpx.Response(200, json={"permission": "write"})
        if path == "/orgs/example/teams/platform":
            return httpx.Response(200, json={"privacy": "closed"})
        if path == "/orgs/example/teams/platform/repos/example/project":
            return httpx.Response(200, json={"permissions": {"push": True}})
        if path == "/apps/stampbot":
            return httpx.Response(200, json={"id": 99, "slug": "stampbot"})
        if path.endswith("/contents/missing"):
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(500, json={"message": "unexpected route"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    assert await client.get_reviews(2, "example/project", 3) == [{"id": 1}]
    assert await client.get_codeowners_errors(2, "example/project", "base") == [
        {"line": 2, "message": "Invalid owner"}
    ]
    assert await client.team_member(2, "example", "platform", "octocat") is True
    assert await client.user_can_own_repository(2, "example/project", "octocat") is True
    assert await client.team_can_own_repository(2, "example", "platform", "example/project") is True
    assert await client.get_app(2, "stampbot") == {"id": 99, "slug": "stampbot"}
    assert await client.get_file_text(2, "example/project", "missing") is None
    await client.close()

    assert token_calls == 1


@pytest.mark.asyncio
async def test_api_errors_expose_status_without_leaking_headers(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(403, json={"message": "rate limit exceeded"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    with pytest.raises(GitHubAPIError, match="403: rate limit exceeded") as caught:
        await client.get_pull(2, "example/project", 3)
    await client.close()

    assert caught.value.status_code == 403


@pytest.mark.asyncio
async def test_rejected_cached_installation_token_is_refreshed_once(private_key: str) -> None:
    token_calls = 0
    api_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls, api_calls
        if request.url.path.endswith("/access_tokens"):
            token_calls += 1
            return httpx.Response(
                201,
                json={
                    "token": f"installation-token-{token_calls}",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        api_calls += 1
        if request.headers["authorization"] == "Bearer installation-token-1":
            return httpx.Response(401, json={"message": "Bad credentials"})
        return httpx.Response(200, json={"state": "open"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    assert await client.get_pull(2, "example/project", 3) == {"state": "open"}
    await client.close()

    assert token_calls == 2
    assert api_calls == 2


@pytest.mark.asyncio
async def test_rate_limit_response_carries_provider_retry_delay(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            429,
            headers={"Retry-After": "37"},
            json={"message": "secondary rate limit"},
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    with pytest.raises(GitHubRateLimitError) as caught:
        await client.get_pull(2, "example/project", 3)
    await client.close()

    assert caught.value.retry_after_seconds == 37


@pytest.mark.asyncio
async def test_existing_check_run_is_updated(private_key: str) -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.method == "GET":
            return httpx.Response(
                200,
                json={"check_runs": [{"id": 77, "name": "check", "app": {"id": 1}}]},
            )
        return httpx.Response(200, json={"id": 77})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    head_sha = "c" * 40

    check_id = await client.upsert_check_run(
        2,
        "example/project",
        head_sha,
        "check",
        conclusion="failure",
        title="Approval required",
        summary="Missing approval",
        external_id=f"project@{head_sha}",
    )
    await client.close()

    assert check_id == 77
    assert methods[-1] == "PATCH"


@pytest.mark.asyncio
async def test_reconciliation_list_endpoints_paginate(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if path == "/app/installations":
            page = int(request.url.params["page"])
            return httpx.Response(
                200, json=[{"id": index} for index in range(100)] if page == 1 else []
            )
        if path == "/installation/repositories":
            return httpx.Response(200, json={"repositories": [{"full_name": "example/project"}]})
        if path == "/repos/example/project/pulls":
            return httpx.Response(200, json=[{"number": 3}])
        return httpx.Response(404)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))

    assert len(await client.list_installations()) == 100
    assert await client.list_installation_repositories(2) == [{"full_name": "example/project"}]
    assert await client.list_open_pulls(2, "example/project") == [{"number": 3}]
    await client.close()


def test_non_rsa_private_key_is_rejected_at_startup() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    with pytest.raises(ValueError, match="must be an RSA private key"):
        GitHubClient(1, private_key.decode())


@pytest.mark.asyncio
async def test_concurrent_requests_share_one_installation_token_exchange(
    private_key: str,
) -> None:
    token_request_started = asyncio.Event()
    allow_token_response = asyncio.Event()
    token_calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls
        if request.url.path.endswith("/access_tokens"):
            token_calls += 1
            token_request_started.set()
            await allow_token_response.wait()
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json={"state": "open"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    first = asyncio.create_task(client.get_pull(2, "example/project", 3))
    await token_request_started.wait()
    second = asyncio.create_task(client.get_pull(2, "example/project", 4))
    allow_token_response.set()

    assert await first == {"state": "open"}
    assert await second == {"state": "open"}
    await client.close()
    assert token_calls == 1


@pytest.mark.asyncio
async def test_installation_token_response_shape_fails_closed(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/access_tokens")
        return httpx.Response(201, json={"expires_at": "2027-01-01T00:00:00Z"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="omitted token or expiry"):
        await client.get_pull(2, "example/project", 3)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authentication",
    [{}, {"installation_id": 2, "app_authenticated": True}],
)
async def test_request_requires_exactly_one_authentication_mode(
    private_key: str,
    authentication: dict[str, object],
) -> None:
    client = GitHubClient(1, private_key, transport=httpx.MockTransport(unexpected_request))
    with pytest.raises(ValueError, match="exactly one authentication mode"):
        await client._request("GET", "/test", **authentication)  # type: ignore[arg-type]
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 204])
async def test_empty_success_responses_are_objects(private_key: str, status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(status)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    assert await client.get_pull(2, "example/project", 3) == {}
    await client.close()


@pytest.mark.asyncio
async def test_object_endpoint_rejects_array_response(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json=[])

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="expected object response"):
        await client.get_pull(2, "example/project", 3)
    await client.close()


@pytest.mark.asyncio
async def test_optional_membership_404_fails_closed(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(404, json={"message": "Not Found"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    assert await client.team_member(2, "example", "platform", "octocat") is False
    await client.close()


def test_retry_delay_accepts_http_date_and_falls_back_safely() -> None:
    future = (datetime.now(UTC) + timedelta(seconds=30)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    dated = httpx.Response(403, headers={"Retry-After": future})
    invalid = httpx.Response(
        403,
        headers={
            "Retry-After": "not-a-delay",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "also-not-a-timestamp",
        },
    )
    reset = httpx.Response(
        403,
        headers={
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(datetime.now(UTC).timestamp() + 10),
        },
    )

    dated_delay = GitHubClient._retry_delay(dated, "secondary limit")
    assert dated_delay is not None and 1 <= dated_delay <= 30
    assert GitHubClient._retry_delay(invalid, "secondary limit") == 60
    reset_delay = GitHubClient._retry_delay(reset, "secondary limit")
    assert reset_delay is not None and 1 <= reset_delay <= 10
    assert GitHubClient._retry_delay(httpx.Response(403), "forbidden") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"not": "a list"}, "expected list response"),
        ([{"id": 1}, "malformed"], "expected object items"),
    ],
)
async def test_list_endpoint_rejects_malformed_shapes(
    private_key: str,
    payload: object,
    message: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match=message):
        await client.get_reviews(2, "example/project", 3)
    await client.close()


@pytest.mark.asyncio
async def test_list_endpoint_propagates_api_error(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(502, content=b"upstream unavailable")

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAPIError, match="upstream unavailable"):
        await client.get_reviews(2, "example/project", 3)
    await client.close()


@pytest.mark.asyncio
async def test_list_endpoint_enforces_explicit_limit(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json=[{"id": 1}, {"id": 2}])

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(PullRequestTooLargeError, match="supported 1-item limit"):
        await client._get_list("/test", 2, max_items=1)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({}, "omitted its errors list"),
        ({"errors": ["malformed"]}, "contained a malformed error"),
    ],
)
async def test_codeowners_validation_rejects_malformed_shapes(
    private_key: str,
    payload: dict[str, object],
    message: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match=message):
        await client.get_codeowners_errors(2, "example/project", "base")
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(500, content=b"upstream unavailable"), "returned 500"),
        (httpx.Response(200, content=b"\xff"), "not valid UTF-8"),
    ],
)
async def test_raw_content_fails_closed_on_api_and_encoding_errors(
    private_key: str,
    response: httpx.Response,
    message: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return response

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match=message):
        await client.get_file_text(2, "example/project", "policy")
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("team", "repository"),
    [
        ({"privacy": "secret"}, {"permissions": {"push": True}}),
        ({"privacy": "closed"}, {"permissions": ["push"]}),
    ],
)
async def test_team_ownership_requires_visible_team_and_permission_object(
    private_key: str,
    team: dict[str, object],
    repository: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.url.path == "/orgs/example/teams/platform":
            return httpx.Response(200, json=team)
        return httpx.Response(200, json=repository)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    assert (
        await client.team_can_own_repository(2, "example", "platform", "example/project") is False
    )
    await client.close()


@pytest.mark.asyncio
async def test_has_check_run_rejects_malformed_list(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json={"check_runs": {"id": 99}})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="omitted its list"):
        await client.has_check_run(2, "example/project", "a" * 40, "check")
    await client.close()


@pytest.mark.asyncio
async def test_has_check_run_ignores_foreign_and_malformed_runs(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            json={
                "check_runs": [
                    "malformed",
                    {"id": 1, "name": "another", "app": {"id": 1}},
                    {"id": 2, "name": "check", "app": {"id": 9}},
                    {"id": "bad", "name": "check", "app": {"id": 1}},
                ]
            },
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    assert await client.has_check_run(2, "example/project", "a" * 40, "check") is False
    await client.close()


@pytest.mark.asyncio
async def test_existing_check_id_and_reset_never_post_a_new_check(private_key: str) -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        methods.append(request.method)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "check_runs": [
                        {"id": 99, "name": "check", "app": {"id": 1}},
                    ]
                },
            )
        assert request.method == "PATCH"
        assert request.url.path.endswith("/check-runs/99")
        payload = json.loads(request.content)
        assert payload["status"] == "in_progress"
        assert "conclusion" not in payload
        return httpx.Response(200, json={"id": 99})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    check_run_id = await client.existing_check_run_id(
        2,
        "example/project",
        "a" * 40,
        "check",
    )
    assert check_run_id == 99
    await client.reset_check_run(
        2,
        "example/project",
        check_run_id,
        "check",
        title="reset",
        summary="pending",
    )
    assert methods == ["GET", "PATCH"]
    await client.close()


@pytest.mark.asyncio
async def test_reset_check_rejects_changed_response_id(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json={"id": 100})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="changed the requested check ID"):
        await client.reset_check_run(
            2,
            "example/project",
            99,
            "check",
            title="reset",
            summary="pending",
        )
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "conclusion", "message"),
    [
        ("waiting", None, "unsupported check-run status"),
        ("completed", None, "require a conclusion"),
        ("queued", "success", "cannot have a conclusion"),
    ],
)
async def test_check_run_state_combinations_are_validated_before_api_calls(
    private_key: str,
    status: str,
    conclusion: str | None,
    message: str,
) -> None:
    client = GitHubClient(1, private_key, transport=httpx.MockTransport(unexpected_request))
    with pytest.raises(ValueError, match=message):
        await client.upsert_check_run(
            2,
            "example/project",
            "a" * 40,
            "check",
            status=status,
            conclusion=conclusion,
            title="title",
            summary="summary",
        )
    await client.close()


@pytest.mark.asyncio
async def test_check_run_response_requires_integer_id(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.method == "GET":
            return httpx.Response(200, json={"check_runs": []})
        return httpx.Response(201, json={"id": "not-an-integer"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="omitted its integer ID"):
        await client.upsert_check_run(
            2,
            "example/project",
            "a" * 40,
            "check",
            conclusion="success",
            title="title",
            summary="summary",
        )
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(502, content=b"unavailable"), "returned 502"),
        (httpx.Response(200, json={"installations": []}), "expected list response"),
    ],
)
async def test_installation_listing_fails_closed(
    private_key: str,
    response: httpx.Response,
    message: str,
) -> None:
    client = GitHubClient(
        1,
        private_key,
        transport=httpx.MockTransport(lambda _: response),
    )
    with pytest.raises(GitHubError, match=message):
        await client.list_installations()
    await client.close()


@pytest.mark.asyncio
async def test_installation_repository_listing_paginates_and_filters_shapes(
    private_key: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        page = int(request.url.params["page"])
        if page == 1:
            return httpx.Response(
                200,
                json={
                    "repositories": [
                        *({"full_name": f"example/repository-{index}"} for index in range(99)),
                        "malformed",
                    ]
                },
            )
        return httpx.Response(200, json={"repositories": [{"full_name": "example/final"}]})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    repositories = await client.list_installation_repositories(2)
    await client.close()

    assert len(repositories) == 100
    assert repositories[-1] == {"full_name": "example/final"}


@pytest.mark.asyncio
async def test_installation_repository_listing_requires_list(private_key: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json={})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="omitted repositories"):
        await client.list_installation_repositories(2)
    await client.close()


@pytest.mark.asyncio
async def test_commit_pull_listing_uses_commit_endpoint(private_key: str) -> None:
    observed_path = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal observed_path
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        observed_path = request.url.path
        return httpx.Response(200, json=[{"number": 3}])

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    assert await client.list_commit_pulls(2, "example/project", "a" * 40) == [{"number": 3}]
    await client.close()
    assert observed_path == f"/repos/example/project/commits/{'a' * 40}/pulls"


@pytest.mark.asyncio
@pytest.mark.parametrize("expected_count", (1, 100, 101, 200, MAX_PULL_COMMITS))
async def test_compare_pull_commits_uses_selected_graphql_pages_bound_to_the_snapshot(
    private_key: str,
    expected_count: int,
) -> None:
    pull = dco_pull_snapshot(count=expected_count, head_sha=commit_sha(expected_count))
    ordered_shas = [commit_sha(index) for index in range(1, expected_count + 1)]
    cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        assert request.method == "POST"
        assert request.url.path == "/graphql"
        body = json.loads(request.content)
        query = body["query"]
        assert "DcoPullCommits" in query
        assert all(field not in query for field in ("files", "patch", "additions", "deletions"))
        variables = body["variables"]
        assert {key: value for key, value in variables.items() if key != "cursor"} == {
            "owner": "example",
            "name": "project",
            "number": pull.number,
        }
        cursor = variables.get("cursor")
        cursors.append(cursor)
        page = 0 if cursor is None else int(cursor.removeprefix("cursor-"))
        offset = page * 100
        page_shas = ordered_shas[offset : offset + 100]
        has_next_page = offset + len(page_shas) < expected_count
        return httpx.Response(
            200,
            json=graphql_pull_page(
                pull,
                page_shas,
                has_next_page=has_next_page,
                end_cursor=f"cursor-{page + 1}",
            ),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    comparison = await client.compare_pull_commits(2, pull)
    await client.close()

    assert comparison.repository == pull.repository
    assert comparison.pull_number == pull.number
    assert comparison.base_sha == comparison.base_commit_sha == pull.base_sha
    assert comparison.head_sha == pull.head_sha
    assert comparison.total_commits == comparison.ahead_by == expected_count
    assert [item.sha for item in comparison.commits] == ordered_shas
    assert [item.node_id for item in comparison.commits] == [f"PRC_{sha}" for sha in ordered_shas]
    assert len(cursors) == (expected_count + 99) // 100


@pytest.mark.asyncio
async def test_compare_pull_commits_supports_a_fork_without_interpolating_refs(
    private_key: str,
) -> None:
    pull = dco_pull_snapshot(
        head_repository=RepositoryIdentity(id=101, full_name="fork-owner/project")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        body = json.loads(request.content)
        assert pull.head_sha not in body["query"]
        assert pull.head_ref not in body["query"]
        return httpx.Response(200, json=graphql_pull_page(pull, [pull.head_sha]))

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    comparison = await client.compare_pull_commits(2, pull)
    await client.close()

    assert comparison.commits[0].sha == pull.head_sha


@pytest.mark.parametrize("count", (0, -1, True, MAX_PULL_COMMITS + 1))
def test_pull_snapshot_rejects_unrepresentable_commit_counts(count: int) -> None:
    with pytest.raises(ValidationError):
        dco_pull_snapshot(count=count)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("total_count", "error"),
    (
        (True, GitHubError),
        (0, GitHubError),
        (2, GitHubError),
        (MAX_PULL_COMMITS + 1, PullRequestTooLargeError),
    ),
)
async def test_compare_pull_commits_rejects_invalid_or_changed_counts(
    private_key: str,
    total_count: object,
    error: type[Exception],
) -> None:
    pull = dco_pull_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            json=graphql_pull_page(pull, [pull.head_sha], total_count=total_count),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(error):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload["data"].__setitem__("repository", None),
        lambda payload: payload["data"]["repository"].__setitem__("pullRequest", None),
        lambda payload: payload["data"]["repository"]["pullRequest"].__setitem__(
            "baseRefOid", commit_sha(999)
        ),
        lambda payload: payload["data"]["repository"]["pullRequest"].__setitem__(
            "headRefName", "changed"
        ),
        lambda payload: payload["data"]["repository"]["pullRequest"]["commits"].__setitem__(
            "nodes", [None]
        ),
        lambda payload: payload["data"]["repository"]["pullRequest"]["commits"].__setitem__(
            "nodes", [{"id": "node", "commit": {"oid": "A" * 40}}]
        ),
        lambda payload: payload["data"]["repository"]["pullRequest"]["commits"].__setitem__(
            "pageInfo", None
        ),
    ),
    ids=(
        "null-repository",
        "null-pull",
        "changed-base",
        "changed-head-ref",
        "null-node",
        "invalid-oid",
        "null-page-info",
    ),
)
async def test_compare_pull_commits_rejects_malformed_or_changed_pages(
    private_key: str,
    mutation: Callable[[dict[str, object]], object],
) -> None:
    pull = dco_pull_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        payload = graphql_pull_page(pull, [pull.head_sha])
        mutation(payload)
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
async def test_graphql_primary_rate_limit_preserves_reset_delay(private_key: str) -> None:
    reset = int(datetime.now(UTC).timestamp()) + 300

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset),
            },
            json={"data": None, "errors": [{"message": "provider detail"}]},
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubRateLimitError) as caught:
        await client.compare_pull_commits(2, dco_pull_snapshot())
    await client.close()

    assert caught.value.status_code == 200
    assert caught.value.method == "POST"
    assert caught.value.path == "/graphql"
    assert 290 <= caught.value.retry_after_seconds <= 300
    assert "provider detail" not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "error", "expected_delay"),
    (
        (
            {"Retry-After": "37"},
            {"message": "You have exceeded a secondary rate limit."},
            37,
        ),
        ({}, {"type": "RATE_LIMITED", "message": "provider detail"}, 60),
        ({}, {"extensions": {"code": "RATE_LIMITED"}}, 60),
        ({}, {"message": "secondary rate limit"}, 60),
    ),
    ids=("retry-after", "type", "extension-code", "message"),
)
async def test_graphql_secondary_rate_limit_uses_bounded_delay(
    private_key: str,
    headers: dict[str, str],
    error: dict[str, object],
    expected_delay: int,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            headers=headers,
            json={"data": None, "errors": [error]},
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubRateLimitError) as caught:
        await client.compare_pull_commits(2, dco_pull_snapshot())
    await client.close()

    assert caught.value.retry_after_seconds == expected_delay


@pytest.mark.asyncio
@pytest.mark.parametrize("identity_field", ("pull", "repository"))
async def test_compare_pull_commits_revalidates_identity_on_later_pages(
    private_key: str,
    identity_field: str,
) -> None:
    pull = dco_pull_snapshot(count=101, head_sha=commit_sha(101))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        cursor = json.loads(request.content)["variables"]["cursor"]
        if cursor is None:
            return httpx.Response(
                200,
                json=graphql_pull_page(
                    pull,
                    [commit_sha(index) for index in range(1, 101)],
                    has_next_page=True,
                    end_cursor="next",
                ),
            )
        payload = graphql_pull_page(pull, [pull.head_sha])
        data = cast(dict[str, object], payload["data"])
        repository = cast(dict[str, object], data["repository"])
        pull_request = cast(dict[str, object], repository["pullRequest"])
        if identity_field == "repository":
            repository["databaseId"] = 999
        else:
            pull_request["baseRefOid"] = commit_sha(999)
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="identity changed"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("has_next_page", "end_cursor"),
    ((False, "ignored"), (True, None), (True, "")),
    ids=("premature-final-page", "null-cursor", "empty-cursor"),
)
async def test_compare_pull_commits_rejects_inconsistent_pagination(
    private_key: str,
    has_next_page: bool,
    end_cursor: object,
) -> None:
    pull = dco_pull_snapshot(count=101, head_sha=commit_sha(101))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            json=graphql_pull_page(
                pull,
                [commit_sha(index) for index in range(1, 101)],
                has_next_page=has_next_page,
                end_cursor=end_cursor,
            ),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
async def test_compare_pull_commits_rejects_oversized_cursor(private_key: str) -> None:
    pull = dco_pull_snapshot(count=101, head_sha=commit_sha(101))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            json=graphql_pull_page(
                pull,
                [commit_sha(index) for index in range(1, 101)],
                has_next_page=True,
                end_cursor="x" * 4097,
            ),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="cursor is invalid"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
async def test_compare_pull_commits_rejects_repeated_cursor(private_key: str) -> None:
    pull = dco_pull_snapshot(count=201, head_sha=commit_sha(201))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        cursor = json.loads(request.content)["variables"]["cursor"]
        start = 1 if cursor is None else 101
        return httpx.Response(
            200,
            json=graphql_pull_page(
                pull,
                [commit_sha(index) for index in range(start, start + 100)],
                has_next_page=True,
                end_cursor="repeated",
            ),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="cursor is invalid"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("shas", "message"),
    (
        ([commit_sha(1), commit_sha(1)], "repeated a commit"),
        ([commit_sha(1), commit_sha(999)], "did not end"),
    ),
)
async def test_compare_pull_commits_rejects_duplicate_or_wrong_head_lists(
    private_key: str,
    shas: list[str],
    message: str,
) -> None:
    pull = dco_pull_snapshot(count=2, head_sha=commit_sha(2))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json=graphql_pull_page(pull, shas))

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match=message):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
async def test_compare_pull_commits_rejects_duplicate_node_id(private_key: str) -> None:
    pull = dco_pull_snapshot(count=2, head_sha=commit_sha(2))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        payload = graphql_pull_page(pull, [commit_sha(1), pull.head_sha])
        data = cast(dict[str, object], payload["data"])
        repository = cast(dict[str, object], data["repository"])
        pull_request = cast(dict[str, object], repository["pullRequest"])
        commits = cast(dict[str, object], pull_request["commits"])
        nodes = cast(list[dict[str, object]], commits["nodes"])
        nodes[1]["id"] = nodes[0]["id"]
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="repeated a commit"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    (
        httpx.Response(200, json={"errors": [{"message": "private"}], "data": {}}),
        httpx.Response(200, json={"errors": {"message": "rate limit"}, "data": {}}),
        httpx.Response(200, json={"errors": [None], "data": {}}),
        httpx.Response(200, json={"data": None}),
        httpx.Response(200, json=[]),
    ),
)
async def test_compare_pull_commits_rejects_graphql_errors_and_null_data(
    private_key: str,
    response: httpx.Response,
) -> None:
    pull = dco_pull_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return response

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError) as caught:
        await client.compare_pull_commits(2, pull)
    await client.close()

    assert type(caught.value) is GitHubError


@pytest.mark.asyncio
async def test_compare_pull_commits_propagates_api_failure(private_key: str) -> None:
    pull = dco_pull_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(502, json={"message": "unavailable"})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAPIError, match="returned 502"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
async def test_commit_evidence_is_pr_anchored_and_omits_raw_blobs(
    private_key: str,
) -> None:
    pull = dco_pull_snapshot(count=2, head_sha=commit_sha(2))
    shas = [commit_sha(1), commit_sha(2)]
    detail_queries: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        body = json.loads(request.content)
        if "DcoPullCommits" in body["query"]:
            return httpx.Response(200, json=graphql_pull_page(pull, shas))
        detail_queries.append(body["query"])
        node_id = body["variables"]["id"]
        sha = node_id.removeprefix("PRC_")
        parent = pull.base_sha if sha == shas[0] else shas[0]
        return httpx.Response(
            200,
            json=graphql_commit_detail(pull, sha, parents=[parent]),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    comparison, evidence = await client.get_pull_commit_evidence(2, pull)
    await client.close()

    assert [item.sha for item in comparison.commits] == shas
    assert [item.sha for item in evidence] == shas
    assert all(item.author_signoff_present for item in evidence)
    assert all("message" not in item.model_fields_set for item in evidence)
    assert all(
        "payload" not in query and "files" not in query and "patch" not in query
        for query in detail_queries
    )


@pytest.mark.asyncio
async def test_commit_evidence_enforces_the_aggregate_message_budget(
    private_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("extra_codeowners.github.MAX_DCO_AGGREGATE_MESSAGE_BYTES", 10)
    pull = dco_pull_snapshot(count=2, head_sha=commit_sha(2))
    shas = [commit_sha(1), commit_sha(2)]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        body = json.loads(request.content)
        if "DcoPullCommits" in body["query"]:
            return httpx.Response(200, json=graphql_pull_page(pull, shas))
        sha = body["variables"]["id"].removeprefix("PRC_")
        return httpx.Response(200, json=graphql_commit_detail(pull, sha, message="123456"))

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="aggregate DCO evidence limit"):
        await client.get_pull_commit_evidence(2, pull)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload["data"].__setitem__("node", None),
        lambda payload: payload["data"]["node"].__setitem__("__typename", "Commit"),
        lambda payload: payload["data"]["node"].__setitem__("id", "wrong"),
        lambda payload: payload["data"]["node"]["pullRequest"].__setitem__(
            "headRefOid", commit_sha(999)
        ),
        lambda payload: payload["data"]["node"]["pullRequest"].pop("repository"),
        lambda payload: payload["data"]["node"]["pullRequest"].__setitem__("repository", None),
        lambda payload: payload["data"]["node"]["pullRequest"]["repository"].__setitem__(
            "databaseId", 999
        ),
        lambda payload: payload["data"]["node"]["pullRequest"]["repository"].__setitem__(
            "nameWithOwner", "example/other"
        ),
        lambda payload: payload["data"]["node"]["commit"].__setitem__("oid", commit_sha(999)),
    ),
    ids=(
        "null-node",
        "wrong-type",
        "wrong-node",
        "changed-pull",
        "missing-repository",
        "null-repository",
        "changed-repository-id",
        "changed-repository-name",
        "wrong-commit",
    ),
)
async def test_commit_evidence_rejects_wrong_node_or_pull_identity(
    private_key: str,
    mutation: Callable[[dict[str, object]], object],
) -> None:
    pull = dco_pull_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        body = json.loads(request.content)
        if "DcoPullCommits" in body["query"]:
            return httpx.Response(200, json=graphql_pull_page(pull, [pull.head_sha]))
        payload = graphql_commit_detail(pull, pull.head_sha)
        mutation(payload)
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError):
        await client.get_pull_commit_evidence(2, pull)
    await client.close()


@pytest.mark.asyncio
async def test_commit_evidence_cancels_a_sibling_detail_request_on_failure(
    private_key: str,
) -> None:
    pull = dco_pull_snapshot(count=2, head_sha=commit_sha(2))
    shas = [commit_sha(1), pull.head_sha]
    sibling_started = asyncio.Event()
    sibling_cancelled = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        body = json.loads(request.content)
        if "DcoPullCommits" in body["query"]:
            return httpx.Response(200, json=graphql_pull_page(pull, shas))
        sha = body["variables"]["id"].removeprefix("PRC_")
        if sha == shas[0]:
            await sibling_started.wait()
            return httpx.Response(502, json={"message": "unavailable"})
        sibling_started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            sibling_cancelled.set()
            raise
        raise AssertionError("unreachable")

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubAPIError, match="returned 502"):
        await asyncio.wait_for(client.get_pull_commit_evidence(2, pull), timeout=1)
    await client.close()

    assert sibling_cancelled.is_set()


@pytest.mark.asyncio
async def test_dco_json_fetch_rejects_declared_oversize_before_streaming(
    private_key: str,
) -> None:
    stream = TrackingStream(b"{}")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, headers={"Content-Length": "5"}, stream=stream)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="4-byte response limit"):
        await client._get_bounded_json("/evidence", 2, max_bytes=4)
    await client.close()

    assert stream.chunks_read == 0
    assert stream.closed is True


@pytest.mark.asyncio
async def test_dco_json_fetch_caps_undeclared_decoded_stream(
    private_key: str,
) -> None:
    stream = TrackingStream(b'{"a"', b":1}")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, stream=stream)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="4-byte response limit"):
        await client._get_bounded_json("/evidence", 2, max_bytes=4)
    await client.close()

    assert stream.chunks_read == 2
    assert stream.closed is True


@pytest.mark.asyncio
async def test_dco_json_fetch_rejects_malformed_or_non_utf8_json(private_key: str) -> None:
    responses = iter((b"not-json", b'"\xff"'))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, content=next(responses))

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    for _ in range(2):
        with pytest.raises(GitHubError, match="expected JSON response"):
            await client._get_bounded_json("/evidence", 2, max_bytes=100)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    (
        b"\xef\xbb\xbf{}",
        "{}".encode("utf-16"),
        "{}".encode("utf-16-le"),
        "{}".encode("utf-16-be"),
        "{}".encode("utf-32"),
        "{}".encode("utf-32-le"),
        "{}".encode("utf-32-be"),
    ),
    ids=(
        "utf-8-bom",
        "utf-16-bom",
        "utf-16-le",
        "utf-16-be",
        "utf-32-bom",
        "utf-32-le",
        "utf-32-be",
    ),
)
async def test_dco_json_fetch_accepts_only_bomless_utf8(private_key: str, body: bytes) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, content=body)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="expected JSON response"):
        await client._get_bounded_json("/evidence", 2, max_bytes=100)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    (
        b'{"sha":"one","sha":"two"}',
        b'{"outer":{"sha":"one","sha":"two"}}',
        b"1" * 5000,
        b"[" * (MAX_JSON_RESPONSE_DEPTH + 1) + b"0" + b"]" * (MAX_JSON_RESPONSE_DEPTH + 1),
        b"[" * 10_000 + b"0" + b"]" * 10_000,
        b"NaN",
        b"Infinity",
        b"-Infinity",
    ),
    ids=(
        "duplicate-root-key",
        "duplicate-nested-key",
        "integer-limit",
        "nesting-boundary",
        "nesting-pathological",
        "nan",
        "positive-infinity",
        "negative-infinity",
    ),
)
async def test_dco_json_fetch_normalizes_ambiguous_or_pathological_json(
    private_key: str,
    body: bytes,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, content=body)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="expected JSON response"):
        await client._get_bounded_json("/evidence", 2, max_bytes=25_000)
    await client.close()


@pytest.mark.asyncio
async def test_dco_json_fetch_accepts_explicit_nesting_boundary_and_string_delimiters(
    private_key: str,
) -> None:
    leaf = 'literal [{]} " \\ tail'
    encoded_leaf = json.dumps(leaf).encode()
    body = b'{"nested":' * MAX_JSON_RESPONSE_DEPTH + encoded_leaf + b"}" * MAX_JSON_RESPONSE_DEPTH

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, content=body)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    parsed = await client._get_bounded_json("/evidence", 2, max_bytes=1000)
    await client.close()

    for _ in range(MAX_JSON_RESPONSE_DEPTH):
        assert isinstance(parsed, dict)
        assert list(parsed) == ["nested"]
        parsed = parsed["nested"]
    assert parsed == leaf
