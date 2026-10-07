from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from test_authority_enrollment import authority_fixture, pull_summary
from test_github import pull_listing_record, token_response, unexpected_request

from extra_codeowners.api_budget import RecoveryBudgetDeferredError
from extra_codeowners.database import AuthorityJob, utcnow
from extra_codeowners.github import AuthorityPullPage, GitHubClient, GitHubError


def github_client(
    private_key: str, handler: Callable[[httpx.Request], httpx.Response]
) -> GitHubClient:
    return GitHubClient(1, private_key, transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_stable_listing_keeps_created_order_with_tied_and_inverted_numbers(
    private_key: str,
) -> None:
    requested_queries: list[dict[str, str]] = []

    def record(number: int, state: str, created_at: str) -> dict[str, Any]:
        result = pull_listing_record(number, state)
        result["created_at"] = created_at
        return result

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.url.path != "/repos/example/project/pulls":
            return unexpected_request(request)
        page = request.url.params["page"]
        requested_queries.append(dict(request.url.params))
        if page == "1":
            payload = [
                record(55, "open", "2026-10-01T00:00:00Z"),
                record(54, "open", "2026-10-01T00:00:00Z"),
                record(100, "closed", "2026-10-01T00:00:01Z"),
            ]
            next_page = request.url.copy_set_param("page", "2")
            return httpx.Response(
                200,
                json=payload,
                headers={"Link": f'<{next_page}>; rel="next"'},
            )
        if page == "2":
            payload = [record(6, "closed", "2026-10-01T00:00:02Z")]
            next_page = request.url.copy_set_param("page", "3")
            return httpx.Response(
                200,
                json=payload,
                headers={"Link": f'<{next_page}>; rel="next"'},
            )
        if page == "3":
            return httpx.Response(200, json=[record(5, "open", "2026-10-01T00:00:03Z")])
        return unexpected_request(request)

    client = github_client(private_key, handler)
    try:
        pulls = await client.list_open_pulls(2, "example/project", stable=True)
    finally:
        await client.close()

    assert requested_queries == [
        {
            "state": "all",
            "sort": "created",
            "direction": "asc",
            "per_page": "100",
            "page": page,
        }
        for page in ("1", "2", "3")
    ]
    assert [pull["number"] for pull in pulls] == [55, 54, 5]


@pytest.mark.asyncio
@pytest.mark.parametrize("number", [5, 100])
async def test_authority_page_does_not_filter_number_below_prior_page_cursor(
    private_key: str, number: int
) -> None:
    requested_queries: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.url.path != "/repos/example/project/pulls":
            return unexpected_request(request)
        requested_queries.append(dict(request.url.params))
        assert request.url.params["page"] == "2"
        return httpx.Response(200, json=[pull_listing_record(number)])

    client = github_client(private_key, handler)
    try:
        page = await client.list_authority_pull_page(2, "example/project", page=2, after_number=100)
    finally:
        await client.close()

    assert [pull["number"] for pull in page.pulls] == [number]
    assert page.last_number == number
    assert requested_queries == [
        {
            "state": "all",
            "sort": "created",
            "direction": "asc",
            "per_page": "100",
            "page": "2",
        }
    ]


@pytest.mark.asyncio
async def test_stable_listing_allows_same_pull_to_reappear_on_a_later_page(
    private_key: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.url.path != "/repos/example/project/pulls":
            return unexpected_request(request)
        if request.url.params["page"] == "1":
            next_page = request.url.copy_set_param("page", "2")
            return httpx.Response(
                200,
                json=[pull_listing_record(55, updated_at="2026-10-01T00:00:00Z")],
                headers={"Link": f'<{next_page}>; rel="next"'},
            )
        return httpx.Response(
            200,
            json=[pull_listing_record(55, updated_at="2026-10-02T00:00:00Z")],
        )

    client = github_client(private_key, handler)
    try:
        pulls = await client.list_open_pulls(2, "example/project", stable=True)
    finally:
        await client.close()

    assert [pull["number"] for pull in pulls] == [55, 55]


@pytest.mark.asyncio
async def test_authority_page_rejects_nonadjacent_duplicate_including_closed_pull(
    private_key: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.url.path != "/repos/example/project/pulls":
            return unexpected_request(request)
        return httpx.Response(
            200,
            json=[
                pull_listing_record(55, "open"),
                pull_listing_record(54, "closed"),
                pull_listing_record(55, "closed"),
            ],
        )

    client = github_client(private_key, handler)
    try:
        with pytest.raises(GitHubError, match="duplicate pull request numbers"):
            await client.list_authority_pull_page(2, "example/project")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_authority_page_rejects_malformed_closed_pull(
    private_key: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.url.path != "/repos/example/project/pulls":
            return unexpected_request(request)
        return httpx.Response(200, json=[pull_listing_record(5, "closed", updated_at=None)])

    client = github_client(private_key, handler)
    try:
        with pytest.raises(GitHubError, match="invalid updated_at"):
            await client.list_authority_pull_page(2, "example/project")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_authority_resume_processes_lower_numbers_after_closed_page_and_partial_deferral(
    tmp_path: Path,
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    page_calls: list[tuple[int, int]] = []

    async def list_page(
        _installation: int,
        _repository: str,
        *,
        page: int = 1,
        after_number: int = 0,
    ) -> AuthorityPullPage:
        page_calls.append((page, after_number))
        if page == 1:
            # A page containing only closed history still carries a diagnostic
            # number, but that number must not discard lower-number later rows.
            return AuthorityPullPage([], next_page=2, last_number=100)
        assert page == 2 and after_number == 100
        return AuthorityPullPage(
            [pull_summary(5, "2026-10-01T00:00:00Z"), pull_summary(6, "2026-10-01T00:00:00Z")],
            next_page=0,
            last_number=6,
        )

    github.list_authority_pull_page = AsyncMock(side_effect=list_page)
    original_get_pull = github.get_pull
    visited: list[int] = []
    defer_six = True

    async def current_pull(installation: int, repository: str, number: int) -> dict[str, Any]:
        nonlocal defer_six
        visited.append(number)
        if number == 6 and defer_six:
            raise RecoveryBudgetDeferredError(600)
        return await original_get_pull(installation, repository, number)  # type: ignore[no-any-return]

    github.get_pull = AsyncMock(side_effect=current_pull)
    first = store.claim_authority("worker", 60)
    assert first is not None
    assert await worker._process_authority(first) == "budget_deferred"

    expected_fingerprint = hashlib.sha256(
        json.dumps([5, "a" * 40, "main", "2026-10-01T00:00:00Z"], separators=(",", ":")).encode()
    ).hexdigest()
    with store.session() as session:
        row = session.get(AuthorityJob, first.id)
        assert row is not None
        assert row.listing_next_page == 2 and row.listing_last_number == 100
        assert row.handled_pull_fingerprints == {"5": expected_fingerprint}
        assert row.pull_cursor_number == 5
        row.available_at = utcnow() - timedelta(seconds=1)

    defer_six = False
    worker.owner = "second-replica"
    second = store.claim_authority("second-replica", 60)
    assert second is not None
    worker = type(worker)(worker.settings, store, worker.evaluator, "second-replica")
    assert await worker._process_authority(second) == "completed"

    assert page_calls == [(1, 0), (2, 100), (2, 100)]
    assert visited.count(5) == 1
    assert visited.count(6) == 2
