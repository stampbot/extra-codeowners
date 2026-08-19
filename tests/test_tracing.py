"""Tests for opt-in trace export and metadata boundaries."""

from __future__ import annotations

import pytest
import structlog
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from extra_codeowners.tracing import Tracing


def raise_private_failure() -> None:
    """Raise from a helper so the test exercises normal error handling."""
    raise RuntimeError("private failure")


def test_disabled_tracing_is_a_noop() -> None:
    tracing = Tracing(enabled=False)

    with tracing.span("test.operation", attributes={"safe": "value"}) as span:
        assert span.get_span_context().is_valid is False

    tracing.shutdown()


def test_trace_export_omits_private_metadata_and_exception_text_by_default() -> None:
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=1,
        processor=SimpleSpanProcessor(exporter),
    )

    with (
        pytest.raises(RuntimeError, match="private failure"),
        tracing.span(
            "test.operation",
            attributes={"safe": "value"},
            private_attributes={"repository": "private/project"},
        ),
    ):
        raise_private_failure()

    tracing.shutdown()
    [span] = exporter.get_finished_spans()
    assert span.attributes == {"safe": "value"}
    assert span.status.status_code is StatusCode.ERROR
    assert span.status.description == "RuntimeError"
    assert span.events == ()


def test_private_metadata_mode_exports_detailed_attributes_and_exception() -> None:
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=1,
        include_private_metadata=True,
        processor=SimpleSpanProcessor(exporter),
    )

    with (
        pytest.raises(RuntimeError, match="private failure"),
        tracing.span(
            "test.operation",
            attributes={"safe": "value"},
            private_attributes={"repository": "private/project"},
        ),
    ):
        raise_private_failure()

    tracing.shutdown()
    [span] = exporter.get_finished_spans()
    assert span.attributes == {"safe": "value", "repository": "private/project"}
    assert span.events[0].name == "exception"


def test_unsampled_spans_do_not_bind_trace_ids_to_structured_logs() -> None:
    exporter = InMemorySpanExporter()
    tracing = Tracing(
        enabled=True,
        endpoint="http://tempo.example.test/v1/traces",
        sample_ratio=0,
        processor=SimpleSpanProcessor(exporter),
    )
    structlog.contextvars.clear_contextvars()

    with tracing.span("test.operation"):
        context = structlog.contextvars.get_contextvars()
        assert "trace_id" not in context
        assert "span_id" not in context

    tracing.shutdown()
    assert exporter.get_finished_spans() == ()


@pytest.mark.parametrize("sample_ratio", [-0.1, 1.1])
def test_enabled_tracing_rejects_invalid_sample_ratios(sample_ratio: float) -> None:
    with pytest.raises(ValueError, match="sample ratio"):
        Tracing(
            enabled=True,
            endpoint="http://tempo.example.test/v1/traces",
            sample_ratio=sample_ratio,
        )


def test_enabled_tracing_requires_an_endpoint() -> None:
    with pytest.raises(ValueError, match="requires an OTLP endpoint"):
        Tracing(enabled=True)
