"""Quota-header diagnostics preserve parsing, accounting and privacy boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import httpx
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from extra_codeowners import api_budget
from extra_codeowners.api_budget import CoreQuota, RecoveryApiBudget
from extra_codeowners.github import GitHubClient
from extra_codeowners.tracing import Tracing

NOW = datetime(2026, 1, 2, tzinfo=UTC)
SECRET = "fictional-private-header-value"


def headers(issue: str | None = None) -> dict[str, str]:
    result = {
        "x-ratelimit-resource": "core",
        "x-ratelimit-limit": "100",
        "x-ratelimit-remaining": "42",
        "x-ratelimit-reset": str(int(NOW.timestamp()) + 3600),
    }
    if issue == "missing_resource":
        del result["x-ratelimit-resource"]
    elif issue == "other_resource":
        result["x-ratelimit-resource"] = SECRET
    elif issue == "missing_numbers":
        del result["x-ratelimit-remaining"]
    elif issue == "malformed_numbers":
        result["x-ratelimit-remaining"] = SECRET
    elif issue == "invalid_balance":
        result["x-ratelimit-remaining"] = "101"
    elif issue == "stale_reset":
        result["x-ratelimit-reset"] = str(int(NOW.timestamp()))
    elif issue == "reset_too_far":
        result["x-ratelimit-reset"] = str(int(NOW.timestamp()) + 86401)
    return result


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_budget, "utcnow", lambda: NOW)


ISSUES = [
    "missing_resource",
    "other_resource",
    "missing_numbers",
    "malformed_numbers",
    "invalid_balance",
    "stale_reset",
    "reset_too_far",
]


@pytest.mark.parametrize("issue", ISSUES)
def test_rejection_diagnostic_preserves_legacy_result_and_input(issue: str) -> None:
    candidate = headers(issue)
    before = dict(candidate)
    observed, reason = CoreQuota.inspect_headers(candidate)
    assert observed is None and reason == issue
    assert CoreQuota.from_headers(candidate) is None
    assert candidate == before
    assert SECRET not in reason


@pytest.mark.parametrize("seconds", [1, 3600, 86400])
def test_valid_quota_and_reset_boundaries_are_unchanged(seconds: int) -> None:
    candidate = headers()
    candidate["x-ratelimit-reset"] = str(int(NOW.timestamp()) + seconds)
    observed, issue = CoreQuota.inspect_headers(candidate)
    assert issue is None
    assert observed == CoreQuota(100, 42, NOW + timedelta(seconds=seconds))
    assert CoreQuota.from_headers(candidate) == observed


@pytest.mark.asyncio
@pytest.mark.parametrize("issue", [*ISSUES, "rejected_token", None])
async def test_observation_exports_only_fixed_reason_and_never_accounts_rejected_headers(
    private_key: str, issue: str | None
) -> None:
    # Verifies XCO-011: response-header values never become diagnostic metadata.
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=1,
        processor=SimpleSpanProcessor(exporter),
    )
    budget = Mock(spec=RecoveryApiBudget)
    client = GitHubClient(7, private_key, recovery_budget=budget, tracing=tracing)
    try:
        with tracing.span("fixture.quota") as span:
            await client._observe_quota(
                17,
                httpx.Response(401 if issue == "rejected_token" else 200, headers=headers(issue)),
                span,
            )
    finally:
        await client.close()
        tracing.shutdown()
    [finished] = exporter.get_finished_spans()
    attributes = dict(finished.attributes or {})
    assert attributes["github.quota.core_headers_valid"] is (issue is None)
    assert attributes["github.quota.observation"] == (issue or "accepted")
    assert "github.quota.ignored_reason" not in attributes
    if issue is None:
        budget.observe.assert_called_once_with(17, CoreQuota(100, 42, NOW + timedelta(hours=1)))
    else:
        assert "github.quota.remaining" not in attributes
        assert "github.quota.reset_at" not in attributes
        budget.observe.assert_not_called()
    if issue == "rejected_token":
        assert attributes["github.quota.ignored_rejected_token"] is True
    assert SECRET not in repr(attributes)


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("issue", ["missing_resource", "malformed_numbers", "stale_reset"])
async def test_finished_http_spans_report_reason_without_extra_requests(
    private_key: str, streaming: bool, issue: str
) -> None:
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=1,
        processor=SimpleSpanProcessor(exporter),
    )
    calls: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": SECRET,
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        return httpx.Response(200, json={"id": 42}, headers=headers(issue))

    client = GitHubClient(7, private_key, tracing=tracing, transport=httpx.MockTransport(handle))
    try:
        if streaming:
            async with client._authenticated_streaming_response(
                "GET", "/repos/example/private", 17
            ) as response:
                assert response.status_code == 200
                await response.aread()
        else:
            response = await client._api_response(
                "GET", "/repos/example/private", installation_id=17
            )
            assert response.status_code == 200
    finally:
        await client.close()
        tracing.shutdown()
    spans = [
        s
        for s in exporter.get_finished_spans()
        if s.attributes and s.attributes.get("github.authentication") == "installation"
    ]
    assert len(spans) == 1
    attributes = dict(spans[0].attributes or {})
    assert attributes["github.quota.observation"] == issue
    assert attributes["github.quota.core_headers_valid"] is False
    assert len(calls) == 2  # One token request and one installation request, no new probe/retry.
    assert "example/private" not in repr(attributes) and SECRET not in repr(attributes)


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_token_refresh_keeps_latest_quota_observation_coherent(
    private_key: str, streaming: bool
) -> None:
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=1,
        processor=SimpleSpanProcessor(exporter),
    )
    token_requests = 0
    resource_requests = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal token_requests, resource_requests
        if request.url.path.endswith("/access_tokens"):
            token_requests += 1
            return httpx.Response(
                201,
                json={
                    "token": f"{SECRET}-{token_requests}",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        resource_requests += 1
        return httpx.Response(
            401 if resource_requests == 1 else 200, json={"id": 42}, headers=headers()
        )

    client = GitHubClient(7, private_key, tracing=tracing, transport=httpx.MockTransport(handle))
    try:
        if streaming:
            async with client._authenticated_streaming_response(
                "GET", "/repos/example/private", 17
            ) as response:
                assert response.status_code == 200
                await response.aread()
        else:
            response = await client._api_response(
                "GET", "/repos/example/private", installation_id=17
            )
            assert response.status_code == 200
    finally:
        await client.close()
        tracing.shutdown()
    [finished] = [
        s
        for s in exporter.get_finished_spans()
        if s.attributes and s.attributes.get("github.authentication") == "installation"
    ]
    attributes = dict(finished.attributes or {})
    assert "github.quota.ignored_reason" not in attributes
    assert attributes["github.quota.observation"] == "accepted"
    assert attributes["github.quota.core_headers_valid"] is True
    assert attributes["github.quota.remaining"] == 42
    assert attributes["github.quota.ignored_rejected_token"] is True  # Historical flag.
    assert token_requests == resource_requests == 2
    assert SECRET not in repr(attributes)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first_issue", "last_issue"), [("stale_reset", None), (None, "missing_resource")]
)
async def test_discovery_retry_records_final_observation_and_last_accepted_balance(
    private_key: str, first_issue: str | None, last_issue: str | None
) -> None:
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=1,
        processor=SimpleSpanProcessor(exporter),
    )
    resource_requests = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal resource_requests
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": SECRET,
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        resource_requests += 1
        return httpx.Response(
            503 if resource_requests == 1 else 200,
            json={},
            headers=headers(first_issue if resource_requests == 1 else last_issue),
        )

    client = GitHubClient(7, private_key, tracing=tracing, transport=httpx.MockTransport(handle))
    try:
        response = await client._api_response(
            "GET", "/repos/example/private", installation_id=17, discovery_cache_status="absent"
        )
        assert response.status_code == 200
    finally:
        await client.close()
        tracing.shutdown()
    [finished] = [
        s
        for s in exporter.get_finished_spans()
        if s.attributes and s.attributes.get("github.authentication") == "installation"
    ]
    attributes = dict(finished.attributes or {})
    assert "github.quota.ignored_reason" not in attributes
    assert attributes["github.quota.observation"] == (last_issue or "accepted")
    assert attributes["github.quota.core_headers_valid"] is (last_issue is None)
    assert attributes["github.quota.remaining"] == 42  # Most recent accepted observation.
    assert resource_requests == 2
    assert SECRET not in repr(attributes)
