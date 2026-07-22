import asyncio
import gzip
import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta

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


def compare_payload(
    pull: PullRequestSnapshot,
    shas: list[str],
    *,
    base_commit_sha: str | None = None,
    total_commits: object | None = None,
    ahead_by: object | None = None,
) -> dict[str, object]:
    return {
        "base_commit": {"sha": base_commit_sha or pull.base_sha},
        "total_commits": pull.commit_count if total_commits is None else total_commits,
        "ahead_by": pull.commit_count if ahead_by is None else ahead_by,
        "commits": [{"sha": sha} for sha in shas],
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
@pytest.mark.parametrize("expected_count", (1, 101, MAX_PULL_COMMITS))
async def test_compare_pull_commits_uses_exact_snapshot_and_bounded_pagination(
    private_key: str,
    expected_count: int,
) -> None:
    pull = dco_pull_snapshot(count=expected_count, head_sha=commit_sha(expected_count))
    ordered_shas = [commit_sha(index) for index in range(1, expected_count + 1)]
    pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        assert request.url.path == (
            f"/repos/example/project/compare/{pull.base_sha}...{pull.head_sha}"
        )
        assert request.url.params["per_page"] == "100"
        page = int(request.url.params["page"])
        pages.append(page)
        offset = (page - 1) * 100
        return httpx.Response(
            200,
            json=compare_payload(pull, ordered_shas[offset : offset + 100]),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    comparison = await client.compare_pull_commits(2, pull)
    await client.close()

    assert comparison.repository == pull.repository
    assert comparison.pull_number == pull.number
    assert comparison.base_sha == pull.base_sha
    assert comparison.head_sha == pull.head_sha
    assert comparison.base_commit_sha == pull.base_sha
    assert comparison.total_commits == expected_count
    assert comparison.ahead_by == expected_count
    assert [item.sha for item in comparison.commits] == ordered_shas
    assert pages == list(range(1, (expected_count - 1) // 100 + 2))


@pytest.mark.asyncio
async def test_compare_pull_commits_uses_qualified_owners_for_a_fork_head(
    private_key: str,
) -> None:
    fork = RepositoryIdentity(id=101, full_name="fork-owner/project")
    pull = dco_pull_snapshot(head_repository=fork)
    observed_path = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal observed_path
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        observed_path = request.url.path
        return httpx.Response(200, json=compare_payload(pull, [pull.head_sha]))

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    comparison = await client.compare_pull_commits(2, pull)
    await client.close()

    assert comparison.head_sha == pull.head_sha
    assert observed_path == (
        f"/repos/example/project/compare/example:{pull.base_sha}...fork-owner:{pull.head_sha}"
    )


@pytest.mark.asyncio
async def test_compare_pull_commits_rejects_an_ambiguous_same_owner_fork(
    private_key: str,
) -> None:
    pull = dco_pull_snapshot(
        head_repository=RepositoryIdentity(id=101, full_name="example/renamed-fork")
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="base and head owners are identical"):
        await client.compare_pull_commits(2, pull)
    await client.close()

    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("expected_count", "page_lengths"),
    (
        (101, (100, 0)),
        (1, (0,)),
        (1, (2,)),
    ),
    ids=("truncated-second-page", "missing-first-page", "unexpected-extra-item"),
)
async def test_compare_pull_commits_rejects_incomplete_or_oversized_pages(
    private_key: str,
    expected_count: int,
    page_lengths: tuple[int, ...],
) -> None:
    pull = dco_pull_snapshot(count=expected_count, head_sha=commit_sha(expected_count))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        page = int(request.url.params["page"])
        length = page_lengths[page - 1] if page <= len(page_lengths) else 0
        offset = (page - 1) * 100
        shas = [commit_sha(index) for index in range(offset + 1, offset + length + 1)]
        return httpx.Response(200, json=compare_payload(pull, shas))

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="page length does not match"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
async def test_compare_pull_commits_rejects_api_metadata_beyond_the_hard_limit(
    private_key: str,
) -> None:
    pull = dco_pull_snapshot(count=MAX_PULL_COMMITS, head_sha=commit_sha(MAX_PULL_COMMITS))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            json=compare_payload(
                pull,
                [commit_sha(index) for index in range(1, 101)],
                total_commits=MAX_PULL_COMMITS + 1,
                ahead_by=MAX_PULL_COMMITS + 1,
            ),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(PullRequestTooLargeError, match="250-commit limit"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.parametrize("count", (0, -1, True, MAX_PULL_COMMITS + 1))
def test_pull_snapshot_rejects_unrepresentable_compare_counts(count: int) -> None:
    with pytest.raises(ValidationError):
        dco_pull_snapshot(count=count)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda payload: [], "expected object response"),
        (lambda payload: payload.pop("base_commit"), "base_commit object"),
        (lambda payload: payload.__setitem__("base_commit", []), "base_commit object"),
        (
            lambda payload: payload.__setitem__("base_commit", {"sha": "A" * 40}),
            "invalid base commit SHA",
        ),
        (lambda payload: payload.__setitem__("total_commits", True), "invalid total_commits"),
        (lambda payload: payload.__setitem__("total_commits", 0), "invalid total_commits"),
        (lambda payload: payload.__setitem__("ahead_by", True), "invalid ahead_by"),
        (lambda payload: payload.__setitem__("ahead_by", 0), "invalid ahead_by"),
        (lambda payload: payload.__setitem__("commits", {}), "commits array"),
        (lambda payload: payload.__setitem__("commits", ["bad"]), "non-object commit"),
        (
            lambda payload: payload.__setitem__("commits", [{"sha": "A" * 40}]),
            "invalid commit",
        ),
    ),
    ids=(
        "non-object",
        "missing-base-commit",
        "non-object-base-commit",
        "invalid-base-sha",
        "boolean-total",
        "zero-total",
        "boolean-ahead",
        "zero-ahead",
        "non-array-commits",
        "non-object-commit",
        "invalid-commit-sha",
    ),
)
async def test_compare_pull_commits_rejects_malformed_page_shapes(
    private_key: str,
    mutation: Callable[[dict[str, object]], object | None],
    message: str,
) -> None:
    pull = dco_pull_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        payload = compare_payload(pull, [pull.head_sha])
        changed = mutation(payload)
        if changed is not None:
            return httpx.Response(200, json=changed)
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match=message):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ("base_commit", "total_commits", "ahead_by"))
async def test_compare_pull_commits_rejects_metadata_changes_between_pages(
    private_key: str,
    field: str,
) -> None:
    pull = dco_pull_snapshot(count=101, head_sha=commit_sha(101))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        page = int(request.url.params["page"])
        offset = (page - 1) * 100
        payload = compare_payload(
            pull,
            [
                commit_sha(index)
                for index in range(offset + 1, min(offset + 101, pull.commit_count + 1))
            ],
        )
        if page == 2:
            payload[field] = (
                {"sha": commit_sha(999)} if field == "base_commit" else pull.commit_count - 1
            )
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="metadata changed between pages"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ("total_commits", "ahead_by"))
async def test_compare_pull_commits_rejects_counts_that_disagree_with_snapshot(
    private_key: str,
    field: str,
) -> None:
    pull = dco_pull_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        payload = compare_payload(pull, [pull.head_sha])
        payload[field] = 2
        return httpx.Response(200, json=payload)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="count does not match the snapshot"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
async def test_compare_pull_commits_rejects_a_different_valid_base_sha(
    private_key: str,
) -> None:
    pull = dco_pull_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200,
            json=compare_payload(
                pull,
                [pull.head_sha],
                base_commit_sha=commit_sha(999),
            ),
        )

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="base commit does not match the snapshot"):
        await client.compare_pull_commits(2, pull)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("shas", "message"),
    (
        ([commit_sha(1), commit_sha(1)], "repeated a commit SHA"),
        ([commit_sha(1), commit_sha(999)], "did not end at the snapshot head"),
    ),
    ids=("duplicate", "wrong-head"),
)
async def test_compare_pull_commits_rejects_non_unique_or_wrong_head_histories(
    private_key: str,
    shas: list[str],
    message: str,
) -> None:
    pull = dco_pull_snapshot(count=2, head_sha=commit_sha(2))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json=compare_payload(pull, shas))

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match=message):
        await client.compare_pull_commits(2, pull)
    await client.close()


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
async def test_individual_commit_fetch_is_bound_to_the_exact_sha(private_key: str) -> None:
    expected_sha = "a" * 40
    observed_path = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal observed_path
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        observed_path = request.url.path
        return httpx.Response(200, json={"sha": expected_sha})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    assert await client.get_commit(2, "example/project", expected_sha) == {"sha": expected_sha}
    await client.close()

    assert observed_path == f"/repos/example/project/commits/{expected_sha}"


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_sha", ("a" * 39, "A" * 40, "g" * 40, True))
async def test_individual_commit_fetch_rejects_malformed_sha_without_api_calls(
    private_key: str,
    invalid_sha: object,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500)

    client = GitHubClient(
        1,
        private_key,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ValueError, match="40 lowercase hexadecimal"):
        await client.get_commit(2, "example/project", invalid_sha)  # type: ignore[arg-type]
    await client.close()

    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "repository",
    (
        "owner//repo",
        "owner/repo?query",
        "owner/repo#fragment",
        "owner/repo%2fother",
        "ownér/repo",
        "\ud800/repo",
        r"owner\repo",
        "owner/.",
    ),
)
async def test_dco_commit_endpoint_rejects_unsafe_repository_paths_without_api_calls(
    private_key: str,
    repository: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="GitHub-safe ASCII"):
        await client.get_commit(2, repository, "a" * 40)
    await client.close()

    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "error"),
    (
        (httpx.Response(503, json={"message": "unavailable"}), GitHubAPIError),
        (httpx.Response(200, json=[]), GitHubError),
    ),
)
async def test_individual_commit_fetch_fails_closed_on_api_or_shape_errors(
    private_key: str,
    response: httpx.Response,
    error: type[Exception],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return response

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    with pytest.raises(error):
        await client.get_commit(2, "example/project", "a" * 40)
    await client.close()


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
