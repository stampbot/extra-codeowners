"""Advisory polling cadence; durable leases and API budgets stay authoritative."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Iterable


class ReconciliationCadence:
    """Keep healthy installations out of another installation's early retry.

    This process-local state never authorizes a check or replaces durable work.
    A cold or replacement leader starts fresh, including its cycle accounting.
    Deadlines use monotonic time and are discarded when election is lost.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._due: dict[int, float] = {}
        self._pending: set[int] | None = None

    def reset(self) -> None:
        """Forget advisory state, without touching durable work or quota."""
        self._due.clear()
        self._pending = None

    def begin(self, active_installations: Iterable[int]) -> frozenset[int]:
        """Use a fully validated current scope to select due installations."""
        active = set(active_installations)
        known = self._due.keys()
        new = active.difference(known)
        self._due = {key: value for key, value in self._due.items() if key in active}
        now = self._clock()
        due = frozenset(key for key in active if self._due.get(key, now) <= now)
        if self._pending is None:
            if due or not active:
                self._pending = active.copy()
        else:
            self._pending.intersection_update(active)
            self._pending.update(new)
        return due

    def record(self, installation_id: int, delay: int, *, complete: bool) -> None:
        """Set a post-attempt deadline and update only this leader's cycle."""
        if type(delay) is not int or not 1 <= delay <= 86_401:
            raise ValueError("reconciliation delay must be an integer from 1 through 86401")
        if self._pending is None:
            raise RuntimeError("reconciliation cycle has not started")
        self._due[installation_id] = self._clock() + delay
        if complete:
            self._pending.discard(installation_id)
        else:
            self._pending.add(installation_id)

    def finish(self) -> bool:
        """Report one cycle completion, never an idle/subset-only success."""
        if self._pending == set():
            self._pending = None
            return True
        return False

    def delay(self, discovery_interval: int) -> int:
        """Wake at the earliest due time, with bounded App-scope polling."""
        now = self._clock()
        remaining = min((due - now for due in self._due.values()), default=discovery_interval)
        return max(1, min(discovery_interval, math.ceil(remaining)))
