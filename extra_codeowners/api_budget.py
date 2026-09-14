"""Installation-wide REST core budget for background recovery requests."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from extra_codeowners.database import InstallationApiBudget, QueueStore, ServiceLease, utcnow

REQUEST_LANE: ContextVar[str] = ContextVar("github_request_lane", default="interactive")


@contextmanager
def request_lane(lane: str) -> Iterator[None]:
    """Carry the worker lane into paginated requests and child tasks."""
    if lane not in {"interactive", "recovery", "authority"}:
        raise ValueError("unknown GitHub request lane")
    token = REQUEST_LANE.set(lane)
    try:
        yield
    finally:
        REQUEST_LANE.reset(token)


class RecoveryBudgetDeferredError(Exception):
    """Recovery must wait; this is not a provider limit on interactive work."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__("recovery is preserving the installation's REST core quota")


class ProviderQuotaExhaustedError(RecoveryBudgetDeferredError):
    """GitHub reported zero remaining requests in the current core window."""


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


@dataclass(frozen=True)
class CoreQuota:
    limit: int
    remaining: int
    reset_at: datetime

    @classmethod
    def from_headers(cls, headers: Mapping[str, str]) -> CoreQuota | None:
        """Ignore other resources and incomplete, stale, or malformed headers."""
        if headers.get("x-ratelimit-resource") != "core":
            return None
        values = [
            headers.get(f"x-ratelimit-{name}", "") for name in ("limit", "remaining", "reset")
        ]
        if not all(re.fullmatch(r"[0-9]{1,12}", value) for value in values):
            return None
        limit, remaining, reset = map(int, values)
        now = utcnow()
        if not (0 <= remaining <= limit <= 1_000_000_000 and limit > 0):
            return None
        if not now.timestamp() < reset <= now.timestamp() + 86_400:
            return None
        return cls(limit, remaining, datetime.fromtimestamp(reset, UTC))


class RecoveryApiBudget:
    """Reserve part of a shared installation quota for direct events.

    Every transaction writes before reading. The insert takes SQLite's writer
    lock, including on conflict; PostgreSQL additionally locks the row. Do not
    replace this with an unlocked read followed by a Python decrement.
    """

    def __init__(self, store: QueueStore, reserve_percent: int = 20) -> None:
        if type(reserve_percent) is not int or not 1 <= reserve_percent <= 90:
            raise ValueError("recovery reserve must be from 1 through 90 percent")
        self.store = store
        self.reserve_percent = reserve_percent

    def _locked_row(self, session: Session, installation_id: int) -> InstallationApiBudget:
        if installation_id <= 0:
            raise ValueError("installation_id must be positive")
        insert = (
            postgresql_insert if self.store.engine.dialect.name == "postgresql" else sqlite_insert
        )
        now = utcnow()
        session.execute(
            insert(InstallationApiBudget)
            .values(
                installation_id=installation_id,
                request_limit=0,
                remaining=0,
                reset_at=now,
                probe_after=now,
                repository_cursor="",
            )
            .on_conflict_do_nothing(index_elements=["installation_id"])
        )
        row = session.get(InstallationApiBudget, installation_id, with_for_update=True)
        assert row is not None
        return row

    def admit(self, installation_id: int, *, recovery: bool) -> None:
        """Charge before each physical request, including retries and pages."""
        delay = 0
        exhausted = False
        with self.store.session() as session:
            row = self._locked_row(session, installation_id)
            now = utcnow()
            if _utc(row.reset_at) > now and row.request_limit > 0:
                reserve = math.ceil(row.request_limit * self.reserve_percent / 100)
                if row.remaining == 0 or (recovery and row.remaining <= reserve):
                    delay = math.ceil((_utc(row.reset_at) - now).total_seconds()) + 1
                    exhausted = row.remaining == 0
                else:
                    row.remaining = max(0, row.remaining - 1)
            elif recovery:
                if _utc(row.probe_after) > now:
                    delay = math.ceil((_utc(row.probe_after) - now).total_seconds())
                else:
                    # A new/reset budget gets one probe, not a guessed refill.
                    # Missing headers or a lost response permit at most one
                    # further recovery request per minute across all replicas.
                    row.probe_after = now + timedelta(seconds=60)
        if delay:
            if exhausted:
                raise ProviderQuotaExhaustedError(delay)
            raise RecoveryBudgetDeferredError(delay)

    def observe(self, installation_id: int, quota: CoreQuota) -> None:
        with self.store.session() as session:
            row = self._locked_row(session, installation_id)
            previous_reset = _utc(row.reset_at)
            if quota.reset_at < previous_reset:
                return
            if row.request_limit == 0 or previous_reset <= utcnow():
                row.request_limit = quota.limit
                row.remaining = quota.remaining
                row.reset_at = quota.reset_at
            else:
                # A late response must not refund requests spent by peers.
                # A shifted future reset is not proof the window reset early.
                row.remaining = min(row.remaining, quota.remaining)
                row.request_limit = max(row.request_limit, quota.limit)
                row.reset_at = quota.reset_at

    def repository_cursor(self, installation_id: int) -> str:
        with self.store.session() as session:
            return self._locked_row(session, installation_id).repository_cursor

    def advance_repository(self, installation_id: int, full_name: str, owner: str) -> None:
        """Persist only completed repositories while the caller owns discovery."""
        with self.store.session() as session:
            row = self._locked_row(session, installation_id)
            lease = session.scalar(
                select(ServiceLease)
                .where(
                    ServiceLease.name == "open-pr-reconciler",
                    ServiceLease.owner == owner,
                    ServiceLease.lease_until > utcnow(),
                )
                .with_for_update()
            )
            if lease is not None:
                row.repository_cursor = full_name.lower()
