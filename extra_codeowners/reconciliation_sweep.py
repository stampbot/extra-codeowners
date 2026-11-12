"""Advisory active-sweep progress, never cached authorization or membership."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field


@dataclass
class _Progress:
    started_at: float
    completed: set[tuple[int, str]] = field(default_factory=set)
    recent: set[tuple[int, str]] = field(default_factory=set)
    remaining: set[tuple[int, str]] = field(default_factory=set)


class ReconciliationSweeps:
    """Avoid replaying a completed prefix during a short continuation.

    Every attempt still supplies authenticated, complete repository membership.
    Identity includes the immutable repository ID and current route. Lost state,
    missing IDs, expired progress and replacement leaders cause extra reads,
    never permission to skip fresh authorization evidence in the evaluator.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._progress: dict[int, _Progress] = {}

    def reset(self) -> None:
        self._progress.clear()

    def retain(self, active_installations: Iterable[int]) -> None:
        active = set(active_installations)
        self._progress = {key: value for key, value in self._progress.items() if key in active}

    def begin(
        self,
        installation_id: int,
        identities: dict[str, int],
        *,
        lifetime_seconds: int,
    ) -> frozenset[str]:
        """Return completed routes still present in this bounded active sweep."""
        now = self._clock()
        progress = self._progress.get(installation_id)
        if progress is None:
            progress = self._progress[installation_id] = _Progress(now)
        elif now - progress.started_at >= lifetime_seconds:
            # Expire permission to omit a read, not evidence that this cycle
            # already visited the repository. Slow cycles must still finish.
            progress.recent.clear()
        current = {(repository_id, route.lower()) for route, repository_id in identities.items()}
        progress.completed.intersection_update(current)
        progress.recent.intersection_update(current)
        progress.remaining = current - progress.completed
        return frozenset(route for _, route in progress.recent)

    def complete_repository(self, installation_id: int, route: str, repository_id: int) -> None:
        progress = self._progress[installation_id]
        identity = (repository_id, route.lower())
        progress.completed.add(identity)
        progress.recent.add(identity)
        progress.remaining.discard(identity)

    def covered(self, installation_id: int) -> bool:
        """Cycle coverage survives read-skip expiry, but not scope/election changes."""
        return not self._progress[installation_id].remaining

    def finish(self, installation_id: int) -> None:
        """The next due scan must revisit every repository, even if unchanged."""
        self._progress.pop(installation_id, None)
