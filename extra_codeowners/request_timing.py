"""Fixed-phase timing for GitHub operations, without request metadata."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Literal

from opentelemetry.trace import Span

from extra_codeowners.metrics import GITHUB_API_PHASE_SECONDS

type RequestPhase = Literal[
    "authentication",
    "semaphore_wait",
    "quota_admission",
    "http",
    "quota_accounting",
    "body",
    "retry_wait",
]


class RequestTiming:
    """Accumulate phases across retries on the existing logical request span."""

    def __init__(self, span: Span, operation: str, authentication: str, work_class: str) -> None:
        self.span = span
        self.labels = (operation, authentication, work_class)
        self.seconds: dict[RequestPhase, float] = {}

    @contextmanager
    def phase(self, phase: RequestPhase) -> Iterator[None]:
        """Include failed and cancelled phases without recording exception contents."""
        started = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - started
            self.seconds[phase] = self.seconds.get(phase, 0.0) + elapsed
            self.span.set_attribute(f"github.phase.{phase}.seconds", self.seconds[phase])
            GITHUB_API_PHASE_SECONDS.labels(*self.labels, phase).observe(elapsed)

    @asynccontextmanager
    async def slot(self, semaphore: asyncio.Semaphore) -> AsyncIterator[None]:
        """Measure only permit acquisition, retaining the permit until exit."""
        with self.phase("semaphore_wait"):
            await semaphore.acquire()
        try:
            yield
        finally:
            semaphore.release()
