"""Candidate delivery, retry, and cancellation share durable state."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from sqlalchemy import select

import extra_codeowners.merge_group_work as candidate_work
from extra_codeowners.database import (
    AuthorityRequest,
    JobRequest,
    QueueStore,
    WebhookDelivery,
    utcnow,
)
from extra_codeowners.merge_queue import MergeCandidateIdentity, MergeGroupTrigger
from extra_codeowners.migrations import upgrade_database

TRIGGER = MergeGroupTrigger(
    action="checks_requested",
    installation_id=23,
    repository_id=9876543210,
    repository="example/queue-lab",
    base_ref="refs/heads/main",
    base_sha="a" * 40,
    head_ref="refs/heads/gh-readonly-queue/main/pr-7-fictional",
    head_sha="b" * 40,
)
IDENTITY = MergeCandidateIdentity(
    TRIGGER, "R_sample", "MQ_sample", "MQE_sample", "PR_7", 7, "c" * 40
)


@pytest.fixture
def replica_pair(tmp_path: Path) -> Iterator[tuple[QueueStore, QueueStore]]:
    url = f"sqlite:///{tmp_path / 'merge-groups.db'}"
    upgrade_database(url)
    first, second = QueueStore(url), QueueStore(url)
    try:
        first.initialize()
        second.initialize()
        yield first, second
    finally:
        first.close()
        second.close()


def test_delivery_and_candidate_survive_an_ingress_restart(
    replica_pair: tuple[QueueStore, QueueStore],
) -> None:
    # Verifies XCO-013: the next store sees both reduced delivery and work.
    ingress, worker = replica_pair
    assert ingress.accept_delivery("one", "merge_group", TRIGGER)
    ingress.close()
    claim = candidate_work.MergeGroupQueue(worker).claim("first-worker", 60)
    assert claim is not None
    assert claim.trigger == TRIGGER
    assert claim.generation == 1
    with worker.session() as session:
        delivery = session.get(WebhookDelivery, "one")
        assert delivery is not None
        assert delivery.merge_group_digest is not None and len(delivery.merge_group_digest) == 64
    assert not worker.accept_delivery("one", "merge_group", TRIGGER)
    assert candidate_work.MergeGroupQueue(worker).is_current(claim)


def test_conflicting_candidate_delivery_is_not_committed(
    replica_pair: tuple[QueueStore, QueueStore],
) -> None:
    ingress, worker = replica_pair
    assert ingress.accept_delivery("one", "merge_group", TRIGGER)
    conflicting = replace(TRIGGER, base_sha="d" * 40)
    with pytest.raises(RuntimeError, match="different merge group evidence"):
        ingress.accept_delivery("one", "merge_group", conflicting)
    with pytest.raises(RuntimeError, match="disagrees with the recorded candidate"):
        ingress.accept_delivery("invalid", "merge_group", conflicting)
    with worker.session() as session:
        assert session.scalars(select(WebhookDelivery.delivery_id)).all() == ["one"]
    claim = candidate_work.MergeGroupQueue(worker).claim("current", 60)
    assert claim is not None and claim.trigger == TRIGGER and claim.generation == 1


@pytest.mark.parametrize("destroyed_first", [False, True])
def test_cancelled_candidate_cannot_be_revived_by_delayed_delivery(
    replica_pair: tuple[QueueStore, QueueStore], destroyed_first: bool
) -> None:
    # Verifies XCO-001. Duplicates and reordering cannot authorize a cancelled candidate.
    ingress, worker = replica_pair
    queue = candidate_work.MergeGroupQueue(worker)
    cancelled = replace(TRIGGER, action="destroyed")
    original = None
    if not destroyed_first:
        assert ingress.accept_delivery("queued", "merge_group", TRIGGER)
        original = queue.claim("starting", 60)
        assert original is not None and queue.bind(original, IDENTITY)
    assert ingress.accept_delivery("cancelled", "merge_group", cancelled)
    if original is not None:
        assert not queue.is_current(original)
        assert not queue.complete(original)
        assert not queue.renew(original, 60)
    assert ingress.accept_delivery("delayed", "merge_group", TRIGGER)
    revocation = queue.claim("revoker", 60)
    assert revocation is not None and revocation.trigger == cancelled
    assert revocation.generation == (1 if destroyed_first else 2)
    assert queue.complete(revocation)
    assert ingress.accept_delivery("another-delivery", "merge_group", TRIGGER)
    assert queue.claim("no-resurrection", 60) is None


def test_lease_takeover_with_same_owner_cannot_reuse_expired_attempt(
    replica_pair: tuple[QueueStore, QueueStore], monkeypatch: pytest.MonkeyPatch
) -> None:
    ingress, worker = replica_pair
    assert ingress.accept_delivery("one", "merge_group", TRIGGER)
    now = utcnow() + timedelta(seconds=1)
    clock = Mock(return_value=now)
    monkeypatch.setattr(candidate_work, "utcnow", clock)
    first, second = candidate_work.MergeGroupQueue(ingress), candidate_work.MergeGroupQueue(worker)
    old = first.claim("same-slot", 5)
    assert old is not None
    clock.return_value = now + timedelta(seconds=5)
    assert not first.renew(old, 5)
    new = second.claim("same-slot", 5)
    assert new is not None and new.generation == old.generation and new.attempts == old.attempts + 1
    assert not first.bind(old, IDENTITY)
    assert not first.retry(old, 1)
    assert not first.complete(old)
    assert second.is_current(new)
    assert second.complete(new)


def test_retry_waits_without_starving_a_cancellation(
    replica_pair: tuple[QueueStore, QueueStore], monkeypatch: pytest.MonkeyPatch
) -> None:
    ingress, worker = replica_pair
    assert ingress.accept_delivery("queued", "merge_group", TRIGGER)
    now = utcnow() + timedelta(seconds=1)
    clock = Mock(return_value=now)
    monkeypatch.setattr(candidate_work, "utcnow", clock)
    queue = candidate_work.MergeGroupQueue(worker)
    first = queue.claim("one", 60)
    assert first is not None and queue.retry(first, 30)
    assert queue.claim("two", 60) is None
    cancelled = replace(TRIGGER, action="destroyed", head_sha="d" * 40)
    assert ingress.accept_delivery("different-candidate", "merge_group", cancelled)
    assert queue.claim("revoker", 60) is not None
    clock.return_value = now + timedelta(seconds=30)
    retried = queue.claim("two", 60)
    assert retried is not None and retried.trigger == TRIGGER and retried.attempts == 2


def test_review_delivery_requeues_bound_candidate_with_no_cross_repository_effect(
    replica_pair: tuple[QueueStore, QueueStore],
) -> None:
    ingress, worker = replica_pair
    assert ingress.accept_delivery("queued", "merge_group", TRIGGER)
    queue = candidate_work.MergeGroupQueue(worker)
    first = queue.claim("initial", 60)
    assert first is not None and queue.bind(first, IDENTITY)
    assert not queue.bind(first, replace(IDENTITY, entry_id="MQE_wrong"))
    reason = "pull_request_review.dismissed"
    wrong_repo = JobRequest(23, "example/other", 7, reason, IDENTITY.pull_head_sha)
    tracked_repo = replace(wrong_repo, repository_full_name=TRIGGER.repository)
    assert ingress.accept_delivery(
        "unrelated", "pull_request_review", wrong_repo, invalidate_merge_groups=True
    )
    assert queue.is_current(first)
    assert ingress.accept_delivery(
        "withdrawn", "pull_request_review", tracked_repo, invalidate_merge_groups=True
    )
    assert not queue.is_current(first)
    assert not queue.complete(first)
    second = queue.claim("retry", 60)
    assert second is not None and second.generation == first.generation + 1
    assert queue.bind(second, IDENTITY)
    assert not ingress.accept_delivery(
        "withdrawn", "pull_request_review", tracked_repo, invalidate_merge_groups=True
    )
    assert queue.is_current(second)
    assert queue.complete(second)
    assert ingress.accept_delivery(
        "changed-again", "pull_request_review", tracked_repo, invalidate_merge_groups=True
    )
    third = queue.claim("new", 60)
    assert third is not None and third.generation == second.generation + 1


@pytest.mark.parametrize(
    ("branch", "reason", "still_current"),
    [
        ("docs", "push.repository_base", True),
        ("main", "push.repository_base", False),
        (None, "repository.edited", False),
    ],
)
def test_candidate_invalidation_follows_authority_scope(
    replica_pair: tuple[QueueStore, QueueStore],
    branch: str | None,
    reason: str,
    still_current: bool,
) -> None:
    # Verifies XCO-017: only relevant authority changes should interrupt a candidate.
    ingress, worker = replica_pair
    assert ingress.accept_delivery("queued", "merge_group", TRIGGER)
    queue = candidate_work.MergeGroupQueue(worker)
    job = queue.claim("replica", 60)
    assert job is not None
    assert ingress.accept_delivery(
        "authority",
        "push" if branch is not None else "repository",
        AuthorityRequest(TRIGGER.installation_id, TRIGGER.repository, branch, reason),
        invalidate_merge_groups=True,
    )
    assert queue.is_current(job) is still_current
