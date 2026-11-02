"""Request diagnostics must not change deadlines, permits, or metadata boundaries."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import httpx
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Span

from extra_codeowners.github import GitHubClient
from extra_codeowners.metrics import GITHUB_API_PHASE_SECONDS
from extra_codeowners.request_timing import RequestTiming
from extra_codeowners.tracing import Tracing


def raise_request_failure() -> None:
    """Exercise exception cleanup without hiding the assertions from static analysis."""
    raise RuntimeError("not exported")


def test_phase_totals_include_retries_and_failed_phases(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = iter((0.0, 2.0, 3.0, 7.0))
    monkeypatch.setattr("extra_codeowners.request_timing.time.perf_counter", lambda: next(clock))
    span = Mock(spec=Span)
    timing = RequestTiming(span, "pull.get", "installation", "recovery")
    metric = GITHUB_API_PHASE_SECONDS.labels("pull.get", "installation", "recovery", "http")
    before = metric._sum.get()
    with timing.phase("http"):
        pass
    with pytest.raises(RuntimeError, match="not exported"), timing.phase("http"):
        raise_request_failure()
    assert timing.seconds == {"http": 6.0}
    assert metric._sum.get() - before == 6.0
    assert span.set_attribute.call_args_list[-1].args == ("github.phase.http.seconds", 6.0)


@pytest.mark.asyncio
async def test_cancelled_wait_does_not_release_another_requests_permit() -> None:
    semaphore = asyncio.Semaphore(1)
    timing = RequestTiming(Mock(spec=Span), "pull.get", "installation", "recovery")
    waiting = asyncio.Event()

    async def waiter() -> None:
        waiting.set()
        async with timing.slot(semaphore):
            pytest.fail("cancelled waiter acquired a permit")

    async with semaphore:
        task = asyncio.create_task(waiter())
        await waiting.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.gather(task)
        assert semaphore.locked()
    assert not semaphore.locked()
    assert timing.seconds["semaphore_wait"] >= 0


@pytest.mark.asyncio
async def test_slot_releases_permit_when_body_fails() -> None:
    semaphore = asyncio.Semaphore(1)
    timing = RequestTiming(Mock(spec=Span), "pull.get", "installation", "recovery")
    with pytest.raises(RuntimeError), timing.phase("http"):
        async with timing.slot(semaphore):
            assert semaphore.locked()
            raise_request_failure()
    assert not semaphore.locked()


def traced_client(
    private_key: str, handler: object
) -> tuple[GitHubClient, Tracing, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=1,
        processor=SimpleSpanProcessor(exporter),
    )
    client = GitHubClient(
        1,
        private_key,
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
        tracing=tracing,
    )
    return client, tracing, exporter


def token_response() -> httpx.Response:
    return httpx.Response(
        201,
        json={
            "token": "secret-test-token",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )


@pytest.mark.asyncio
async def test_request_phases_and_cache_state_use_existing_private_safe_spans(
    private_key: str,
) -> None:
    # Verifies XCO-011: attributes and metric labels omit repository, ETag, and token.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return token_response()
        if "if-none-match" in request.headers:
            return httpx.Response(304)
        return httpx.Response(200, json=[], headers={"ETag": '"secret-validator"'})

    client, tracing, exporter = traced_client(private_key, handler)
    try:
        assert await client.list_open_pulls(17, "private/project") == []
        assert await client.list_open_pulls(17, "private/project") == []
    finally:
        await client.close()
        tracing.shutdown()

    spans = exporter.get_finished_spans()
    pulls = [
        dict(s.attributes or {})
        for s in spans
        if (s.attributes or {}).get("github.operation") == "pull.list"
    ]
    assert len(spans) == 3  # Two list operations and one token request; no phase spans.
    assert [attrs["github.discovery.lookup"] for attrs in pulls] == ["absent", "hit"]
    assert [attrs["github.request.conditional"] for attrs in pulls] == [False, True]
    for attrs in pulls:
        for phase in (
            "authentication",
            "semaphore_wait",
            "quota_admission",
            "http",
            "quota_accounting",
        ):
            seconds = attrs[f"github.phase.{phase}.seconds"]
            assert isinstance(seconds, float) and seconds >= 0
    rendered = repr([(s.attributes, s.events) for s in spans])
    for value in ("private/project", "secret-validator", "secret-test-token"):
        assert value not in rendered
        assert value not in repr(list(GITHUB_API_PHASE_SECONDS.collect()))


@pytest.mark.asyncio
async def test_auth_retry_records_final_unconditional_attempt(private_key: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/access_tokens"):
            return token_response()
        calls += 1
        if calls == 1:
            return httpx.Response(200, json=[], headers={"ETag": '"one"'})
        if calls == 2:
            assert request.headers["if-none-match"] == '"one"'
            return httpx.Response(401)
        assert "if-none-match" not in request.headers
        return httpx.Response(200, json=[], headers={"ETag": '"two"'})

    client, tracing, exporter = traced_client(private_key, handler)
    try:
        await client.list_open_pulls(17, "example/project")
        await client.list_open_pulls(17, "example/project")
    finally:
        await client.close()
        tracing.shutdown()
    pulls = [
        dict(s.attributes or {})
        for s in exporter.get_finished_spans()
        if (s.attributes or {}).get("github.operation") == "pull.list"
    ]
    assert pulls[-1]["github.retry_count"] == 1
    assert pulls[-1]["github.request.conditional"] is False
    assert pulls[-1]["github.discovery.lookup"] == "hit"


@pytest.mark.asyncio
async def test_stream_body_is_timed_and_response_closed(private_key: str) -> None:
    responses: list[httpx.Response] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return token_response()
        response = httpx.Response(200, text="content")
        responses.append(response)
        return response

    client, tracing, exporter = traced_client(private_key, handler)
    try:
        assert (
            await client.get_file_text(17, "example/project", "policy.toml", ref="b" * 40)
            == "content"
        )
    finally:
        await client.close()
        tracing.shutdown()
    [stream] = [s for s in exporter.get_finished_spans() if s.name == "github.stream_request"]
    for phase in ("body", "http"):
        seconds = (stream.attributes or {})[f"github.phase.{phase}.seconds"]
        assert isinstance(seconds, float) and seconds >= 0
    assert all(response.is_closed for response in responses)
