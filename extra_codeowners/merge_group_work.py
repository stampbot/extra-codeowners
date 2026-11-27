"""Lease durable merge candidate work without contacting GitHub."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.sql.elements import ColumnElement

from extra_codeowners.database import (
    AuthorityEpoch,
    AuthorityJob,
    MergeGroupWork,
    QueueStore,
    SharedHeadEpoch,
    utcnow,
)
from extra_codeowners.merge_queue import MergeCandidateIdentity, MergeGroupTrigger


@dataclass(frozen=True, slots=True)
class PublishedMergeCandidate:
    """Identity of a confirmed pass that can be rechecked but not recreated."""

    check_id: int
    pull_id: str
    pull_number: int


@dataclass(frozen=True, slots=True)
class ClaimedMergeGroup:
    """One attempt at a candidate generation, not authority to publish."""

    trigger: MergeGroupTrigger
    generation: int
    attempts: int
    lease_owner: str
    published: PublishedMergeCandidate | None = None
    pull_identity: tuple[str, int] | None = None
    withdrawal: bool = False


@dataclass(frozen=True, slots=True)
class MergeGroupEvidenceEpoch:
    """Durable generations observed before reading mutable approval evidence."""

    installation: int
    pull_head: int


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
    claim = (
        *_key(job.trigger),
        MergeGroupWork.generation == job.generation,
        MergeGroupWork.attempts == job.attempts,
        MergeGroupWork.lease_owner == job.lease_owner,
        MergeGroupWork.lease_until > now,
        MergeGroupWork.retired_at.is_(None),
    )
    if job.published is None:
        return (*claim, _pending())
    return (
        *claim,
        MergeGroupWork.completed_generation == job.generation,
        MergeGroupWork.destroyed.is_(False),
        MergeGroupWork.recheck_check_id == job.published.check_id,
    )


class MergeGroupQueue:
    """Claim work stored by the same transaction as its authenticated delivery.

    Completing a row retains its entry binding. Destruction is terminal for
    that candidate commit, so late events cannot turn revocation into evaluation.
    """

    def __init__(self, store: QueueStore) -> None:
        self.store = store

    def claim(
        self,
        owner: str,
        lease_seconds: int,
        *,
        repository_scope: tuple[str, int] | None = None,
        recheck: bool = False,
    ) -> ClaimedMergeGroup | None:
        """Claim an event first, or independently claim a due published result."""
        if not 0 < len(owner) <= 128 or lease_seconds <= 0:
            raise ValueError("merge group claim needs an owner and a positive lease")
        for _ in range(3):
            now = utcnow()
            with self.store.session() as session:
                ready: tuple[ColumnElement[bool], ...] = (
                    MergeGroupWork.available_at <= now,
                    MergeGroupWork.retired_at.is_(None),
                    _unleased(now),
                    self.store._provider_available_condition(MergeGroupWork.installation_id, now),
                )
                if recheck:
                    ready += (
                        MergeGroupWork.completed_generation == MergeGroupWork.generation,
                        MergeGroupWork.destroyed.is_(False),
                        MergeGroupWork.recheck_check_id > 0,
                        MergeGroupWork.pull_id.is_not(None),
                        MergeGroupWork.pull_number > 0,
                    )
                else:
                    ready += (_pending(),)
                if repository_scope is not None:
                    repository, repository_id = repository_scope
                    ready += (
                        MergeGroupWork.repository_full_name == repository,
                        MergeGroupWork.repository_id == repository_id,
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
                pull_identity = (
                    (row.pull_id, row.pull_number)
                    if row.pull_id is not None and row.pull_number is not None
                    else None
                )
                published = None
                if recheck:
                    if row.recheck_check_id is None or pull_identity is None:
                        raise RuntimeError("published candidate lost its check or PR identity")
                    published = PublishedMergeCandidate(row.recheck_check_id, *pull_identity)
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
                    return ClaimedMergeGroup(
                        trigger,
                        row.generation,
                        row.attempts + 1,
                        owner,
                        published,
                        pull_identity,
                        withdrawal=not recheck
                        and (row.destroyed or row.recheck_check_id is not None),
                    )
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

    def evidence_epoch(
        self, job: ClaimedMergeGroup, identity: MergeCandidateIdentity
    ) -> MergeGroupEvidenceEpoch | None:
        """Return current evidence generations only after authority and reset work finish."""
        trigger = job.trigger
        if trigger != identity.trigger or trigger.action != "checks_requested":
            return None
        with self.store.session() as session:
            claimed = session.scalar(
                select(MergeGroupWork.generation).where(
                    *_owns(job, utcnow()),
                    MergeGroupWork.entry_id == identity.entry_id,
                    MergeGroupWork.pull_head_sha == identity.pull_head_sha,
                )
            )
            authority_pending = session.scalar(
                select(AuthorityJob.id)
                .where(
                    AuthorityJob.installation_id == trigger.installation_id,
                    AuthorityJob.scope_key.in_(("*", trigger.repository)),
                    AuthorityJob.base_ref.in_(("", trigger.base_branch)),
                )
                .limit(1)
            )
            if claimed is None or authority_pending is not None:
                return None
            installation = session.scalar(
                select(AuthorityEpoch.generation).where(
                    AuthorityEpoch.installation_id == trigger.installation_id
                )
            )
            head = session.execute(
                select(SharedHeadEpoch.generation, SharedHeadEpoch.invalidated_generation).where(
                    SharedHeadEpoch.installation_id == trigger.installation_id,
                    SharedHeadEpoch.repository_full_name == trigger.repository,
                    SharedHeadEpoch.head_sha == identity.pull_head_sha,
                )
            ).one_or_none()
            if head is not None and head.generation != head.invalidated_generation:
                return None
            return MergeGroupEvidenceEpoch(installation or 0, head.generation if head else 0)

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

    def complete(
        self,
        job: ClaimedMergeGroup,
        *,
        check_id: int | None = None,
        recheck_seconds: int | None = None,
        retire: bool = False,
    ) -> bool:
        """Finish an attempt, scheduling only a confirmed pass for another read."""
        now = utcnow()
        finished_generation = job.generation
        schedule: dict[str, object] = {"recheck_check_id": None, "recheck_due_at": None}
        if check_id is not None or recheck_seconds is not None:
            if (
                retire
                or type(check_id) is not int
                or check_id <= 0
                or type(recheck_seconds) is not int
                or recheck_seconds <= 0
                or (job.published is not None and check_id != job.published.check_id)
                or job.trigger.action != "checks_requested"
            ):
                raise ValueError("a candidate recheck needs its confirmed check and delay")
            due = now + timedelta(seconds=recheck_seconds)
            schedule = {
                "recheck_check_id": check_id,
                "recheck_due_at": due,
                "available_at": due,
                "attempts": 0,
            }
            if job.published is not None:
                # Advance both counters together. Reusing attempt 1 with the
                # same owner must not let a finished timer borrow a later lease.
                finished_generation += 1
                schedule["generation"] = finished_generation
        if retire:
            schedule["retired_at"] = now
        return self._update(
            job,
            now,
            completed_generation=finished_generation,
            lease_owner=None,
            lease_until=None,
            **schedule,
        )

    def _update(self, job: ClaimedMergeGroup, now: datetime, **values: object) -> bool:
        with self.store.session() as session:
            result = session.execute(
                update(MergeGroupWork).where(*_owns(job, now)).values(**values)
            )
            return getattr(result, "rowcount", 0) == 1
