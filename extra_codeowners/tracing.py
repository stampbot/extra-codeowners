"""Opt-in, privacy-aware OpenTelemetry tracing for operations diagnosis.

Tracing stays process-local. A retained direct delivery can carry a trusted
local producer identity, so a later worker attempt can link back across
replicas without making either trace a remote parent. Structured logs still
carry durable identifiers. The default attributes are fixed-cardinality and
safe for a shared tracing backend.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING

import structlog
from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from opentelemetry.trace import Link, Span, SpanContext, Status, StatusCode, TraceFlags, Tracer

from extra_codeowners import __version__
from extra_codeowners.metrics import TRACE_EXPORTS
from extra_codeowners.trace_context import TrustedTraceContext

if TYPE_CHECKING:
    from extra_codeowners.settings import Settings

type TraceAttribute = str | bool | int | float
log = structlog.get_logger()


class _CountingSpanExporter(SpanExporter):
    """Record exporter health without exposing trace content as metrics."""

    def __init__(self, delegate: SpanExporter) -> None:
        self._delegate = delegate

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            result = self._delegate.export(spans)
        except Exception:
            TRACE_EXPORTS.labels("failure").inc()
            return SpanExportResult.FAILURE
        TRACE_EXPORTS.labels("success" if result is SpanExportResult.SUCCESS else "failure").inc()
        return result

    def shutdown(self) -> None:
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return self._delegate.force_flush(timeout_millis)


class Tracing:
    """Create sampled spans without changing OpenTelemetry's process-global provider."""

    def __init__(
        self,
        *,
        enabled: bool,
        endpoint: str | None = None,
        sample_ratio: float = 0.1,
        include_private_metadata: bool = False,
        environment: str = "development",
        processor: SpanProcessor | None = None,
    ) -> None:
        self.enabled = enabled
        self.include_private_metadata = include_private_metadata
        self._provider: TracerProvider | None = None
        if not enabled:
            self._tracer: Tracer = trace.NoOpTracerProvider().get_tracer(__name__)
            return
        if endpoint is None:
            raise ValueError("tracing requires an OTLP endpoint")
        if not 0 <= sample_ratio <= 1:
            raise ValueError("tracing sample ratio must be between 0 and 1")

        self._provider = TracerProvider(
            resource=Resource.create(
                {
                    "service.name": "extra-codeowners",
                    "service.version": __version__,
                    "deployment.environment.name": environment,
                }
            ),
            sampler=ParentBased(TraceIdRatioBased(sample_ratio)),
        )
        self._provider.add_span_processor(
            processor
            or BatchSpanProcessor(_CountingSpanExporter(OTLPSpanExporter(endpoint=endpoint)))
        )
        self._tracer = self._provider.get_tracer("extra_codeowners")
        log.info(
            "tracing_enabled",
            sample_ratio=sample_ratio,
            include_private_metadata=include_private_metadata,
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> Tracing:
        """Build a trace provider from validated non-secret runtime settings."""
        endpoint = (
            str(settings.tracing_otlp_endpoint)
            if settings.tracing_otlp_endpoint is not None
            else None
        )
        return cls(
            enabled=settings.tracing_enabled,
            endpoint=endpoint,
            sample_ratio=settings.tracing_sample_ratio,
            include_private_metadata=settings.tracing_include_private_metadata,
            environment=settings.environment,
        )

    @contextmanager
    def span(
        self,
        name: str,
        *,
        attributes: Mapping[str, TraceAttribute] | None = None,
        private_attributes: Mapping[str, TraceAttribute] | None = None,
        links: Sequence[TrustedTraceContext] = (),
        root: bool = False,
    ) -> Iterator[Span]:
        """Record a span and bind IDs into logs only when it is sampled.

        GitHub does not authenticate external trace context on webhook
        deliveries. Webhook ingress therefore requests a root span rather than
        accepting an attacker-selected trace identifier into trusted logs.
        Durable worker attempts use a link to a separately persisted local
        producer span; a link preserves causality without becoming a parent.
        """
        span_attributes = dict(attributes or {})
        if self.include_private_metadata and private_attributes is not None:
            span_attributes.update(private_attributes)
        otel_links = tuple(
            Link(
                SpanContext(
                    trace_id=int(link.trace_id, 16),
                    span_id=int(link.span_id, 16),
                    is_remote=True,
                    trace_flags=TraceFlags(link.trace_flags),
                )
            )
            for link in links
        )
        with self._tracer.start_as_current_span(
            name,
            context=otel_context.Context() if root else None,
            attributes=span_attributes,
            links=otel_links or None,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            context = span.get_span_context()
            sampled = bool(context.trace_flags & TraceFlags.SAMPLED)
            if span.is_recording() and context.is_valid and sampled:
                with (
                    structlog.contextvars.bound_contextvars(
                        trace_id=f"{context.trace_id:032x}",
                        span_id=f"{context.span_id:016x}",
                    ),
                    self._error_status(span),
                ):
                    yield span
            else:
                with self._error_status(span):
                    yield span

    @staticmethod
    def capture_trusted_context(span: Span) -> TrustedTraceContext | None:
        """Capture a sampled span identity created by this local tracer only."""

        context = span.get_span_context()
        if not (
            span.is_recording()
            and context.is_valid
            and bool(context.trace_flags & TraceFlags.SAMPLED)
        ):
            return None
        return TrustedTraceContext(
            trace_id=f"{context.trace_id:032x}",
            span_id=f"{context.span_id:016x}",
            trace_flags=int(context.trace_flags),
        )

    @staticmethod
    def mark_error(span: Span, description: str) -> None:
        """Mark a known failure without exporting an API body or exception text."""
        span.set_status(Status(StatusCode.ERROR, description[:128]))

    @contextmanager
    def _error_status(self, span: Span) -> Iterator[Span]:
        """Mark exceptions while keeping default traces free of exception text."""
        try:
            yield span
        except Exception as error:
            self.mark_error(span, type(error).__name__)
            if self.include_private_metadata:
                span.record_exception(error)
            raise

    def shutdown(self) -> None:
        """Flush and close the local exporter during service shutdown."""
        if self._provider is not None:
            self._provider.shutdown()
