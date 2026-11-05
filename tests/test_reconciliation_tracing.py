"""Bound complete scan diagnostics without changing request or queue behavior."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.id_generator import RandomIdGenerator

from extra_codeowners.reconciliation_tracing import CURRENT_SCAN, REQUEST_DEPTH
from extra_codeowners.request_timing import RequestTiming
from extra_codeowners.tracing import TraceAttribute, Tracing


def raise_test_failure(error: BaseException) -> None:
    """Exercise exception cleanup without obscuring assertions from static checks."""
    raise error


def traced(
    sample_ratio: float = 1, *, private: bool = False
) -> tuple[Tracing, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    return (
        Tracing(
            enabled=True,
            endpoint="http://tempo.example.test/v1/traces",
            sample_ratio=sample_ratio,
            include_private_metadata=private,
            processor=SimpleSpanProcessor(exporter),
        ),
        exporter,
    )


def assert_independent_details(spans: tuple[ReadableSpan, ...]) -> None:
    [root] = [span for span in spans if span.name == "reconciliation.run"]
    assert root.parent is None
    assert root.context is not None
    details = [span for span in spans if span.name != "reconciliation.run"]
    assert len({span.context.trace_id for span in spans if span.context}) == len(spans)
    for span in details:
        assert span.parent is None
        assert len(span.links) == 1
        assert span.links[0].context == root.context
        assert span.attributes is not None
        assert span.attributes["reconciliation.scan_trace_id"] == f"{root.context.trace_id:032x}"


def test_request_roots_share_local_scan_sampling_and_preserve_nested_phase_attribution() -> None:
    tracing, exporter = traced()
    with tracing.reconciliation_span():
        with tracing.span("github.request", reconciliation_request=True) as request:
            timing = RequestTiming(request, "pull_requests", "installation", "recovery")
            with (
                timing.phase("authentication"),
                tracing.span("github.request", reconciliation_request=True) as token,
            ):
                nested = RequestTiming(token, "installation_token", "app", "recovery")
                with nested.phase("http"):
                    pass
            with timing.phase("http"):
                pass
        with (
            tracing.span("github.stream_request", reconciliation_request=True) as stream,
            RequestTiming(stream, "files", "installation", "recovery").phase("body"),
        ):
            pass
    tracing.shutdown()
    spans = exporter.get_finished_spans()
    assert_independent_details(spans)
    [root] = [span for span in spans if span.name == "reconciliation.run"]
    assert root.attributes is not None
    assert root.attributes["reconciliation.detail_traces"] == 3
    assert root.attributes["reconciliation.outer_requests"] == 2
    assert (
        root.attributes["reconciliation.phase.authentication.seconds"]
        == timing.seconds["authentication"]
    )
    assert root.attributes["reconciliation.phase.http.seconds"] == timing.seconds["http"]
    body_seconds = root.attributes["reconciliation.phase.body.seconds"]
    assert isinstance(body_seconds, float) and body_seconds > 0


@pytest.mark.parametrize("ratio", [0, 0.1, 1])
def test_sampled_scans_keep_all_details_and_unsampled_scans_keep_none(
    ratio: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    identities: Iterator[int] = iter(
        identity
        for scan in range(50)
        for identity in (
            (scan + 1 if scan % 2 == 0 else (1 << 128) - scan - 1),
            *range(10_000 + scan * 5, 10_005 + scan * 5),
        )
    )

    def next_identity(generator: RandomIdGenerator) -> int:
        return next(identities)

    monkeypatch.setattr(RandomIdGenerator, "generate_trace_id", next_identity)
    tracing, exporter = traced(ratio)
    sampled = 0
    for _ in range(50):
        with tracing.reconciliation_span() as root:
            sampled += int(root.is_recording())
            for _ in range(5):
                with tracing.span("github.request", reconciliation_request=True) as request:
                    assert request.is_recording() == root.is_recording()
    tracing.shutdown()
    assert len(exporter.get_finished_spans()) == sampled * 6
    if ratio == 0:
        assert sampled == 0
    if ratio == 1:
        assert sampled == 50
    if ratio == 0.1:
        assert sampled == 25  # Both decisions exercised without random test coverage.


def test_request_traces_outside_a_scan_keep_existing_parent_relationships() -> None:
    tracing, exporter = traced()
    with (
        tracing.span("worker.evaluation"),
        tracing.span("github.request", reconciliation_request=True),
    ):
        pass
    tracing.shutdown()
    request, worker = exporter.get_finished_spans()
    assert request.parent == worker.context
    assert request.links == ()
    assert "reconciliation.scan_trace_id" not in (request.attributes or {})


@pytest.mark.asyncio
async def test_concurrent_scans_keep_ownership_and_phase_totals_isolated() -> None:
    tracing, exporter = traced()

    async def scan(count: int) -> None:
        with tracing.reconciliation_span() as root:
            root.set_attribute("test.count", count)
            for _ in range(count):
                with (
                    tracing.span("github.request", reconciliation_request=True) as request,
                    RequestTiming(request, "pull_requests", "installation", "recovery").phase(
                        "http"
                    ),
                ):
                    await asyncio.sleep(0)

    await asyncio.gather(scan(2), scan(7))
    tracing.shutdown()
    roots = [span for span in exporter.get_finished_spans() if span.name == "reconciliation.run"]
    assert len(roots) == 2
    for root in roots:
        assert root.attributes is not None
        assert root.attributes["test.count"] == root.attributes["reconciliation.outer_requests"]
        details = [
            span
            for span in exporter.get_finished_spans()
            if span.links and span.links[0].context == root.context
        ]
        assert len(details) == root.attributes["test.count"]
    assert CURRENT_SCAN.get() is None
    assert REQUEST_DEPTH.get() == 0


@pytest.mark.parametrize("error", [RuntimeError("failure"), asyncio.CancelledError()])
def test_failures_reset_scope_and_finish_summary(error: BaseException) -> None:
    tracing, exporter = traced()
    with (
        pytest.raises(type(error)),
        tracing.reconciliation_span(),
        tracing.span("github.request", reconciliation_request=True),
    ):
        raise_test_failure(error)
    assert CURRENT_SCAN.get() is None
    assert REQUEST_DEPTH.get() == 0
    with tracing.span("github.request", reconciliation_request=True):
        pass
    tracing.shutdown()
    request, summary, unrelated = exporter.get_finished_spans()
    assert summary.attributes is not None
    assert summary.attributes["reconciliation.detail_traces"] == 1
    assert summary.attributes["reconciliation.outcome"] == (
        "cancelled" if isinstance(error, asyncio.CancelledError) else "failure"
    )
    assert request.links[0].context == summary.context
    assert unrelated.links == ()


def test_private_metadata_and_exception_text_are_bounded_and_clipping_is_counted() -> None:
    # Verifies XCO-011: opting into private details does not remove trace bounds.
    tracing, exporter = traced(private=True)
    with (
        tracing.reconciliation_span(),
        pytest.raises(RuntimeError),
        tracing.span(
            "github.request",
            reconciliation_request=True,
            private_attributes={"github.path": "\U0001f331" * 100_000},
        ),
    ):
        raise_test_failure(RuntimeError("\U0001f331" * 100_000))
    tracing.shutdown()
    request, root = exporter.get_finished_spans()
    assert request.attributes is not None
    assert len(str(request.attributes["github.path"])) == 2048
    assert request.attributes["tracing.truncated_fields"] == 3
    for event in request.events:
        assert event.attributes is not None
        assert all(len(str(value)) <= 2048 for value in event.attributes.values())
    assert encode_spans((request,)).ByteSize() < 64 * 1024
    assert encode_spans((root,)).ByteSize() < 4096


def test_private_fields_and_exception_text_still_absent_by_default() -> None:
    tracing, exporter = traced()
    with (
        tracing.reconciliation_span(),
        pytest.raises(RuntimeError),
        tracing.span(
            "github.request",
            reconciliation_request=True,
            private_attributes={"github.path": "/repos/private/secret"},
        ),
    ):
        raise_test_failure(RuntimeError("private payload"))
    tracing.shutdown()
    request, _ = exporter.get_finished_spans()
    assert request.attributes is not None
    assert "github.path" not in request.attributes
    assert request.events == ()


@pytest.mark.parametrize("linked", [False, True])
def test_ten_thousand_requests_compare_growing_and_bounded_layouts(linked: bool) -> None:
    tracing, exporter = traced()
    attributes: dict[str, TraceAttribute] = {
        "github.operation": "installation.repositories",
        "github.authentication": "installation",
        "queue.work_class": "recovery",
        "http.request.method": "GET",
        "http.response.status_code": 200,
        "github.retry_count": 0,
        "github.discovery.cache": "pages",
        "github.discovery.lookup": "hit",
        "github.request.conditional": True,
        **{
            f"github.phase.{phase}.seconds": 0.01
            for phase in (
                "authentication",
                "semaphore_wait",
                "quota_admission",
                "http",
                "quota_accounting",
                "body",
                "retry_wait",
            )
        },
    }
    manager = (
        tracing.reconciliation_span() if linked else tracing.span("reconciliation.run", root=True)
    )
    with manager as root:
        for _ in range(10_000):
            with tracing.span(
                "github.request", attributes=attributes, reconciliation_request=linked
            ):
                pass
        root.set_attribute("reconciliation.outcome", "success")
    tracing.shutdown()
    spans = exporter.get_finished_spans()
    assert len(spans) == 10_001  # No deliberate detail omission.
    if not linked:
        assert len({span.context.trace_id for span in spans if span.context}) == 1
        assert encode_spans(spans).ByteSize() > 5_000_000
        return
    assert_independent_details(spans)
    sizes = [encode_spans((span,)).ByteSize() for span in spans]
    assert max(sizes) < 4096
    assert encode_spans(spans).ByteSize() > 5_000_000
    assert spans[-1].attributes is not None
    assert spans[-1].attributes["reconciliation.detail_traces"] == 10_000
    assert spans[-1].attributes["reconciliation.outcome"] == "success"


def test_disabled_scan_tracing_does_not_create_scope() -> None:
    tracing = Tracing(enabled=False)
    with (
        tracing.reconciliation_span(),
        tracing.span("github.request", reconciliation_request=True) as request,
    ):
        assert not request.get_span_context().is_valid
        assert CURRENT_SCAN.get() is None
    tracing.shutdown()
