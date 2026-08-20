"""Validated locally generated trace context for durable webhook work."""

from __future__ import annotations

import re
from dataclasses import dataclass

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")


@dataclass(frozen=True, slots=True)
class TrustedTraceContext:
    """One sampled local producer span retained with an accepted delivery.

    This deliberately models only identifiers created by this service after it
    verifies a GitHub webhook. It does not parse or accept HTTP trace headers.
    """

    trace_id: str
    span_id: str
    trace_flags: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.trace_id, str)
            or _TRACE_ID.fullmatch(self.trace_id) is None
            or int(self.trace_id, 16) == 0
        ):
            raise ValueError("trace_id must be a nonzero 32-character lowercase hexadecimal value")
        if (
            not isinstance(self.span_id, str)
            or _SPAN_ID.fullmatch(self.span_id) is None
            or int(self.span_id, 16) == 0
        ):
            raise ValueError("span_id must be a nonzero 16-character lowercase hexadecimal value")
        if (
            isinstance(self.trace_flags, bool)
            or not isinstance(self.trace_flags, int)
            or not 0 <= self.trace_flags <= 0xFF
        ):
            raise ValueError("trace_flags must be an unsigned W3C trace-flags byte")

    @classmethod
    def from_values(
        cls,
        trace_id: str | None,
        span_id: str | None,
        trace_flags: int | None,
    ) -> TrustedTraceContext | None:
        """Return a context only when an optional durable record is valid.

        Trace linkage is diagnostic. A manually corrupted or pre-migration
        delivery row must not prevent a policy evaluation from running.
        """

        if trace_id is None and span_id is None and trace_flags is None:
            return None
        try:
            return cls(trace_id=trace_id, span_id=span_id, trace_flags=trace_flags)  # type: ignore[arg-type]
        except ValueError:
            return None
