"""Lease durable merge candidate work without contacting GitHub."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.sql.elements import ColumnElement

from extra_codeowners.database import MergeGroupWork, QueueStore, utcnow
from extra_codeowners.merge_queue import MergeCandidateIdentity, MergeGroupTrigger


@dataclass(frozen=True, slots=True)
class ClaimedMergeGroup:
    """One attempt at a candidate generation, not authority to publish."""

    trigger: MergeGroupTrigger
    generation: int
    attempts: int
    lease_owner: str


def _key(trigger: MergeGroupTrigger) -> tuple[ColumnElement[bool], ...]:
    return (
        MergeGroupWork.installation_id == trigger.installation_id,
        MergeGroupWork.repository_id == trigger.repository_id,
        MergeGroupWork.head_sha == trigger.head_sha,
    )


def _pending() -> ColumnElement[bool]:
    return MergeGroupWork.completed_generation < MergeGroupWork.generation


def _unleased(now: datetime) -> ColumnElement[bool]:
    return or_(MergeGroupWork.lease_until.is_(None), MergeGroupWork.lease_until <= now)


def _owns(job: ClaimedMergeGroup, now: datetime) -> tuple[ColumnElement[bool], ...]:
    return (
        *_key(job.trigger),
        _pending(),
        MergeGroupWork.generation == job.generation,
        MergeGroupWork.attempts == job.attempts,
        MergeGroupWork.lease_owner == job.lease_owner,
        MergeGroupWork.lease_until > now,
    )


class MergeGroupQueue:
    """Claim work stored by the same transaction as its authenticated delivery.

    Completing a row retains its entry binding. Destruction is terminal for
    that candidate commit, so late events cannot turn revocation into evaluation.
    """

    def __init__(self, store: QueueStore) -> None:
        self.store = store

    def claim(self, owner: str, lease_seconds: int) -> ClaimedMergeGroup | None:
        """Claim available work across replicas, putting cancellations first."""
        if not 0 < len(owner) <= 128 or lease_seconds <= 0:
            raise ValueError("merge group claim needs an owner and a positive lease")
        for _ in range(3):
            now = utcnow()
            with self.store.session() as session:
                ready = (
                    _pending(),
                    MergeGroupWork.available_at <= now,
                    _unleased(now),
                    self.store._provider_available_condition(MergeGroupWork.installation_id, now),
                )
                row = session.scalar(
                    select(MergeGroupWork)
                    .where(*ready)
                    .order_by(
                        MergeGroupWork.destroyed.desc(),
                        MergeGroupWork.available_at,
                        MergeGroupWork.requested_at,
                        MergeGroupWork.installation_id,
                        MergeGroupWork.repository_id,
                        MergeGroupWork.head_sha,
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if row is None:
                    return None
                trigger = MergeGroupTrigger(
                    action="destroyed" if row.destroyed else "checks_requested",
                    installation_id=row.installation_id,
                    repository_id=row.repository_id,
                    repository=row.repository_full_name,
                    base_ref=row.base_ref,
                    base_sha=row.base_sha,
                    head_ref=row.head_ref,
                    head_sha=row.head_sha,
                )
                result = session.execute(
                    update(MergeGroupWork)
                    .where(*_key(trigger), *ready, MergeGroupWork.generation == row.generation)
                    .values(
                        attempts=MergeGroupWork.attempts + 1,
                        lease_owner=owner,
                        lease_until=now + timedelta(seconds=lease_seconds),
                    )
                    .execution_options(synchronize_session=False)
                )
                if getattr(result, "rowcount", 0) == 1:
                    return ClaimedMergeGroup(trigger, row.generation, row.attempts + 1, owner)
        return None

    def is_current(self, job: ClaimedMergeGroup) -> bool:
        """Check whether this attempt still owns an unexpired lease."""
        with self.store.session() as session:
            return (
                session.scalar(select(MergeGroupWork.generation).where(*_owns(job, utcnow())))
                is not None
            )

    def bind(self, job: ClaimedMergeGroup, identity: MergeCandidateIdentity) -> bool:
        """Bind the associated PR once; later attempts must see the same entry and head."""
        if identity.trigger != job.trigger or identity.trigger.action != "checks_requested":
            return False
        with self.store.session() as session:
            result = session.execute(
                update(MergeGroupWork)
                .where(
                    *_owns(job, utcnow()),
                    MergeGroupWork.destroyed.is_(False),
                    or_(
                        MergeGroupWork.entry_id.is_(None),
                        (
                            (MergeGroupWork.entry_id == identity.entry_id)
                            & (MergeGroupWork.pull_id == identity.pull_id)
                            & (MergeGroupWork.pull_number == identity.pull_number)
                            & (MergeGroupWork.pull_head_sha == identity.pull_head_sha)
                        ),
                    ),
                )
                .values(
                    entry_id=identity.entry_id,
                    pull_id=identity.pull_id,
                    pull_number=identity.pull_number,
                    pull_head_sha=identity.pull_head_sha,
                )
            )
            return getattr(result, "rowcount", 0) == 1

    def renew(self, job: ClaimedMergeGroup, lease_seconds: int) -> bool:
        """Extend a live attempt's lease without reviving an expired one."""
        if lease_seconds <= 0:
            raise ValueError("merge group lease must be positive")
        now = utcnow()
        return self._update(job, now, lease_until=now + timedelta(seconds=lease_seconds))

    def retry(self, job: ClaimedMergeGroup, delay_seconds: int) -> bool:
        """Release this attempt until its retry time without clearing newer work."""
        if delay_seconds <= 0:
            raise ValueError("merge group retry delay must be positive")
        now = utcnow()
        return self._update(
            job,
            now,
            available_at=now + timedelta(seconds=delay_seconds),
            lease_owner=None,
            lease_until=None,
        )

    def complete(self, job: ClaimedMergeGroup) -> bool:
        """Finish this attempt without deleting its identity or cancellation."""
        return self._update(
            job,
            utcnow(),
            completed_generation=job.generation,
            lease_owner=None,
            lease_until=None,
        )

    def _update(self, job: ClaimedMergeGroup, now: datetime, **values: object) -> bool:
        with self.store.session() as session:
            result = session.execute(
                update(MergeGroupWork).where(*_owns(job, now)).values(**values)
            )
            return getattr(result, "rowcount", 0) == 1
