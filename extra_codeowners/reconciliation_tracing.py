"""Constant-size scan summaries and locally sampled, linked request roots."""

from __future__ import annotations

from collections.abc import Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Literal

from opentelemetry.context import Context, create_key, get_value, set_value
from opentelemetry.sdk.trace.sampling import Decision, Sampler, SamplingResult
from opentelemetry.trace import Link, Span, SpanContext, SpanKind, TraceState
from opentelemetry.util.types import Attributes

type RequestPhase = Literal[
    "authentication",
    "semaphore_wait",
    "quota_admission",
    "http",
    "quota_accounting",
    "body",
    "retry_wait",
]

# A local OTel context value, never a header or serialized delivery field.
_SCAN_SAMPLED = create_key("extra-codeowners-reconciliation-sampled")
MAX_FIELD_CHARACTERS = 2048


class LinkedScanSampler(Sampler):
    """Follow the scan's local sampling decision for its independent roots."""

    def __init__(self, ordinary_root: Sampler) -> None:
        self._ordinary_root = ordinary_root

    def should_sample(
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        sampled = get_value(_SCAN_SAMPLED, parent_context)
        if isinstance(sampled, bool):
            return SamplingResult(
                Decision.RECORD_AND_SAMPLE if sampled else Decision.DROP,
                attributes,
                trace_state,
            )
        return self._ordinary_root.should_sample(
            parent_context, trace_id, name, kind, attributes, links, trace_state
        )

    def get_description(self) -> str:
        return f"LinkedScanSampler({self._ordinary_root.get_description()})"


@dataclass
class ScanTrace:
    """One scan's fixed counters; never retains requests or repository names."""

    owner: object
    context: SpanContext
    detail_traces: int = 0
    outer_requests: int = 0
    seconds: dict[RequestPhase, float] = field(default_factory=dict)

    def request_context(self) -> Context:
        return set_value(_SCAN_SAMPLED, self.context.trace_flags.sampled, Context())

    def finish(self, span: Span) -> None:
        span.set_attribute("reconciliation.detail_traces", self.detail_traces)
        span.set_attribute("reconciliation.outer_requests", self.outer_requests)
        for phase, seconds in self.seconds.items():
            span.set_attribute(f"reconciliation.phase.{phase}.seconds", seconds)


CURRENT_SCAN: ContextVar[ScanTrace | None] = ContextVar("reconciliation_trace", default=None)
REQUEST_DEPTH: ContextVar[int] = ContextVar("reconciliation_request_depth", default=0)


def observe_scan_phase(phase: RequestPhase, elapsed: float) -> None:
    """Aggregate outer requests only: token work is already authentication time."""
    scan = CURRENT_SCAN.get()
    if scan is not None and REQUEST_DEPTH.get() == 1:
        scan.seconds[phase] = scan.seconds.get(phase, 0.0) + elapsed


@dataclass
class BoundedFields:
    """Bound exported text and make clipping visible on the affected span."""

    truncated: int = 0

    def value(self, value: str | bool | int | float) -> str | bool | int | float:
        if isinstance(value, str) and len(value) > MAX_FIELD_CHARACTERS:
            self.truncated += 1
            return value[:MAX_FIELD_CHARACTERS]
        return value

    def finish(self, span: Span) -> None:
        span.set_attribute("tracing.truncated_fields", self.truncated)
