"""The candidate worker can never project a head check onto a queue commit."""

from __future__ import annotations

import asyncio
import hmac
import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from extra_codeowners.app import create_app
from extra_codeowners.database import AuthorityRequest, JobRequest, QueueStore
from extra_codeowners.github import (
    GitHubAPIError,
    GitHubClient,
    GitHubError,
    MergeCandidateReplacedError,
)
from extra_codeowners.merge_group_work import ClaimedMergeGroup
from extra_codeowners.merge_group_worker import MergeGroupWorker
from extra_codeowners.merge_queue import (
    MERGE_CANDIDATE_CHECK_NAME,
    MergeCandidateAssessment,
    MergeCandidateIdentity,
    MergeGroupTrigger,
)
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.models import EvaluationConclusion, EvaluationResult
from extra_codeowners.service import EvaluationService, Worker
from extra_codeowners.settings import Settings

TRIGGER = MergeGroupTrigger(
    "checks_requested",
    18,
    33,
    "example/queue-lab",
    "refs/heads/main",
    "a" * 40,
    "refs/heads/gh-readonly-queue/main/pr-7-fictional",
    "b" * 40,
)
IDENTITY = MergeCandidateIdentity(
    TRIGGER, "R_sample", "MQ_sample", "MQE_sample", "PR_sample", 7, "c" * 40
)


@pytest.fixture
def stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock]]:
    url = f"sqlite:///{tmp_path / 'candidate-worker.db'}"
    upgrade_database(url)
    store = QueueStore(url)
    store.initialize()
    client = Mock(spec=GitHubClient)
    client.installation_includes_repository = AsyncMock(return_value=True)
    client.get_repository = AsyncMock(return_value={"id": 33, "full_name": "Example/Queue-Lab"})
    client.get_merge_candidate = AsyncMock(return_value=IDENTITY)
    client.existing_merge_group_check = AsyncMock(return_value=None)
    client.write_merge_group_check = AsyncMock(return_value=88)
    service = EvaluationService(Settings(), client, store)
    assess = AsyncMock(
        return_value=MergeCandidateAssessment(
            IDENTITY, EvaluationResult(conclusion=EvaluationConclusion.SUCCESS, summary="approved")
        )
    )
    monkeypatch.setattr(service, "assess_merge_candidate", assess)
    worker = MergeGroupWorker(service, "queue-replica", (TRIGGER.repository, TRIGGER.repository_id))
    try:
        yield worker, store, client, assess
    finally:
        store.close()


def queued(
    worker: MergeGroupWorker, store: QueueStore, *, destroyed: bool = False
) -> ClaimedMergeGroup:
    trigger = replace(TRIGGER, action="destroyed") if destroyed else TRIGGER
    assert store.accept_delivery("candidate-delivery", "merge_group", trigger)
    job = worker.queue.claim("queue-replica", 60, repository_scope=worker.repository)
    assert job is not None
    return job


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
async def test_new_candidate_publishes_only_the_evaluated_group(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    approved: bool,
) -> None:
    # Verifies XCO-007. The PR head can supply review evidence, not the write target.
    worker, store, client, assess = stack
    decision = EvaluationConclusion.SUCCESS if approved else EvaluationConclusion.FAILURE
    assess.return_value = MergeCandidateAssessment(
        IDENTITY, EvaluationResult(conclusion=decision, summary="candidate decision")
    )
    await worker.process(queued(worker, store))
    assess.assert_awaited_once_with(IDENTITY, authority_generation=0)
    assert client.get_merge_candidate.await_count == 2
    client.write_merge_group_check.assert_awaited_once_with(
        TRIGGER, MERGE_CANDIDATE_CHECK_NAME, approved=approved, summary="candidate decision"
    )
    assert worker.settings.check_name != MERGE_CANDIDATE_CHECK_NAME
    assert worker.queue.claim("restart", 60) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("check_lookup_available", [True, False])
async def test_replaced_unpublished_candidate_retires_without_writing(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    check_lookup_available: bool,
) -> None:
    worker, store, client, assess = stack
    client.get_merge_candidate.side_effect = MergeCandidateReplacedError("candidate was replaced")
    if not check_lookup_available:
        client.existing_merge_group_check.side_effect = GitHubAPIError(
            422, "GET", "/checks", "old test commit no longer available"
        )
    await worker.process(queued(worker, store))
    assess.assert_not_awaited()
    client.write_merge_group_check.assert_not_awaited()
    assert store.accept_delivery("delayed", "merge_group", TRIGGER)
    assert worker.queue.claim("restart", 60) is None


@pytest.mark.asyncio
async def test_missing_check_lookup_is_not_by_itself_retirement_evidence(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
) -> None:
    worker, store, client, _ = stack
    client.existing_merge_group_check.side_effect = GitHubAPIError(
        422, "GET", "/checks", "old test commit no longer available"
    )
    job = queued(worker, store)
    with pytest.raises(GitHubAPIError, match="no longer available"):
        await worker.process(job)
    assert worker.queue.is_current(job)
    client.write_merge_group_check.assert_not_awaited()


@pytest.mark.asyncio
async def test_due_candidate_recheck_gets_a_turn_between_ready_events(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Verifies XCO-007: newer work must not stop the worker rechecking a confirmed pass.
    worker, store, _, _ = stack
    approved = queued(worker, store)
    assert worker.queue.bind(approved, IDENTITY)
    assert worker.queue.complete(approved, check_id=88, recheck_seconds=1)
    clock = Mock(return_value=datetime.now(UTC) + timedelta(seconds=2))
    monkeypatch.setattr("extra_codeowners.merge_group_work.utcnow", clock)
    cancelled = replace(TRIGGER, action="destroyed", head_sha="d" * 40)
    waiting = replace(TRIGGER, head_sha="e" * 40)
    assert store.accept_delivery("other-destroyed", "merge_group", cancelled)
    assert store.accept_delivery("other-waiting", "merge_group", waiting)

    stop = asyncio.Event()
    processed = []

    async def record(job: ClaimedMergeGroup) -> None:
        processed.append(job.trigger)
        if len(processed) == 3:
            stop.set()

    monkeypatch.setattr(worker, "_run_attempt", record)
    await asyncio.wait_for(worker.run(stop), timeout=3)

    assert processed == [cancelled, TRIGGER, waiting]


@pytest.mark.asyncio
async def test_signed_review_dismissal_revokes_a_confirmed_candidate_pass(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Verifies XCO-007 and XCO-013: acknowledge the revocation durably,
    # then block the same candidate, not just the PR head.
    worker, store, github, assess = stack
    first = queued(worker, store)
    await worker.process(first)
    assert worker.queue.claim("observer", 60) is None
    github.existing_merge_group_check.return_value = 88

    async def idle(_worker: Worker, stop: asyncio.Event) -> None:
        await stop.wait()

    monkeypatch.setattr(Worker, "run", idle)
    # PR-head invalidation is separate. The candidate still has to revoke
    # its own result even before the ordinary PR worker reaches that head.
    monkeypatch.setattr(EvaluationService, "invalidate_for_trigger", AsyncMock(return_value=False))
    secret = "fictional-candidate-webhook"
    app = create_app(
        Settings(
            _env_file=None,
            environment="test",
            github_app_id=1,
            github_private_key="unused-with-injected-client",
            github_webhook_secret=secret,
            worker_enabled=True,
            reconcile_enabled=False,
            experimental_merge_queue_repository=TRIGGER.repository,
            experimental_merge_queue_repository_id=TRIGGER.repository_id,
        ),
        github=github,
        store=store,
    )
    body = json.dumps(
        {
            "action": "dismissed",
            "installation": {"id": TRIGGER.installation_id},
            "repository": {"id": TRIGGER.repository_id, "full_name": TRIGGER.repository},
            "pull_request": {
                "number": IDENTITY.pull_number,
                "state": "open",
                "head": {"sha": IDENTITY.pull_head_sha},
            },
            "review": {"state": "dismissed"},
        }
    ).encode()
    signature = hmac.digest(secret.encode(), body, "sha256").hex()
    with TestClient(app) as client:
        response = client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request_review",
                "X-GitHub-Delivery": "fictional-review-dismissal",
                "X-Hub-Signature-256": f"sha256={signature}",
            },
        )
        assert response.status_code == 202
        assert response.json() == {"accepted": True, "queued": True}
        revocation = worker.queue.claim("queue-replica-2", 60, repository_scope=worker.repository)
        assert revocation is not None and revocation.generation == first.generation + 1
        await worker.process(revocation)

    initial, withdrawn = github.write_merge_group_check.await_args_list
    assert initial.kwargs["approved"] is True
    assert withdrawn.args == (TRIGGER, MERGE_CANDIDATE_CHECK_NAME)
    assert withdrawn.kwargs["check_id"] == 88 and withdrawn.kwargs["approved"] is False
    assess.assert_awaited_once()
    assert worker.queue.claim("observer", 60) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["none", "review", "unknown", "merged", "different-check", "retry"]
)
async def test_timer_rechecks_published_candidate_without_a_webhook(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    # Verifies XCO-001 and XCO-007. The timer can withdraw the same check,
    # but never projects a result to a different candidate or rewrites a pass.
    worker, store, github, assess = stack
    now = datetime.now(UTC) + timedelta(seconds=1)
    clock = Mock(return_value=now)
    monkeypatch.setattr("extra_codeowners.merge_group_work.utcnow", clock)
    first = queued(worker, store)
    await worker.process(first)
    assert worker.queue.claim("observer", 60, recheck=True) is None
    clock.return_value = now + timedelta(seconds=31)
    due = worker.queue.claim("replica-2", 60, recheck=True)
    assert due is not None and due.published is not None and due.published.check_id == 88
    assert worker.queue.claim("replica-3", 60, recheck=True) is None
    if change == "retry":
        clock.return_value = now + timedelta(seconds=92)
        recovered = worker.queue.claim("replica-3", 60, recheck=True)
        assert recovered is not None and recovered.attempts == 2
        assert not worker.queue.is_current(due)
        due = recovered
    github.existing_merge_group_check.return_value = 89 if change == "different-check" else 88
    github.merge_group_check_is_passing = AsyncMock(return_value=True)
    github.get_pull = AsyncMock(
        return_value={
            "number": IDENTITY.pull_number,
            "node_id": IDENTITY.pull_id,
            "state": "closed" if change == "merged" else "open",
            "merged": change == "merged",
            "base": {"repo": {"id": TRIGGER.repository_id, "full_name": TRIGGER.repository}},
        }
    )
    if change == "review":
        assess.return_value = MergeCandidateAssessment(
            IDENTITY,
            EvaluationResult(conclusion=EvaluationConclusion.FAILURE, summary="review removed"),
        )
    if change in {"unknown", "merged"}:
        github.get_merge_candidate.side_effect = GitHubError("candidate evidence unavailable")
    if change == "different-check":
        with pytest.raises(GitHubError, match="not the recorded pass"):
            await worker.process(due)
        assert worker.queue.is_current(due)
    else:
        await worker.process(due)
    calls = github.write_merge_group_check.await_args_list
    assert calls[0].kwargs["approved"] is True
    if change in {"review", "unknown", "retry"}:
        assert len(calls) == 2 and calls[1].args == (TRIGGER, MERGE_CANDIDATE_CHECK_NAME)
        assert calls[1].kwargs["approved"] is False and calls[1].kwargs["check_id"] == 88
    else:
        assert len(calls) == 1
    if change in {"none", "review"}:
        assert assess.await_args is not None and assess.await_args.kwargs["rechecking"] is True
    if change == "none":
        assert github.get_merge_candidate.await_count == 4
    if change == "retry":
        assess.assert_awaited_once()
    clock.return_value += timedelta(seconds=31)
    future = worker.queue.claim("replica-2", 60, recheck=True)
    assert (future is not None) == (change == "none")
    if future is not None:
        assert future.lease_owner == due.lease_owner and future.attempts == due.attempts == 1
        assert future.generation == due.generation + 1
        assert not worker.queue.is_current(due)


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger_kind", ["pull_request", "destroyed"])
@pytest.mark.parametrize("closed", [False, True])
async def test_candidate_event_preserves_only_authoritatively_closed_history(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    trigger_kind: str,
    closed: bool,
) -> None:
    # Verifies XCO-007: retirement must use the candidate's bound pull request.
    worker, store, client, _ = stack
    await worker.process(queued(worker, store))
    client.existing_merge_group_check.return_value = 88
    client.get_pull.return_value = {
        "number": IDENTITY.pull_number,
        "node_id": IDENTITY.pull_id,
        "state": "closed" if closed else "open",
        "merged": closed,
        "base": {"repo": {"id": TRIGGER.repository_id, "full_name": TRIGGER.repository}},
    }
    if trigger_kind == "destroyed":
        assert store.accept_delivery(
            "queue-finished", "merge_group", replace(TRIGGER, action="destroyed")
        )
    else:
        assert store.accept_delivery(
            "pull-changed",
            "pull_request",
            JobRequest(
                TRIGGER.installation_id,
                TRIGGER.repository,
                IDENTITY.pull_number,
                "review",
                head_sha_hint=IDENTITY.pull_head_sha,
            ),
            invalidate_merge_groups=True,
        )
    job = worker.queue.claim("queue-replica", 60, repository_scope=worker.repository)
    assert job is not None and job.published is None
    await worker.process(job)
    assert client.write_merge_group_check.await_count == (1 if closed else 2)
    if not closed:
        assert client.write_merge_group_check.await_args.kwargs["approved"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(("destroyed", "known_check"), [(True, None), (True, 88), (False, 88)])
async def test_only_reset_existing_checks_after_invalidation_or_cancellation(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    destroyed: bool,
    known_check: int | None,
) -> None:
    worker, store, client, assess = stack
    client.existing_merge_group_check.return_value = known_check
    job = queued(worker, store, destroyed=destroyed)
    await worker.process(job)
    assess.assert_not_called()
    client.get_merge_candidate.assert_not_called()
    if known_check is None:
        client.write_merge_group_check.assert_not_called()
    else:
        assert client.write_merge_group_check.await_count == 1
        call = client.write_merge_group_check.await_args
        assert call.args[0] == job.trigger
        assert call.kwargs["check_id"] == known_check
        assert call.kwargs["approved"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["authority", "replaced", "lost-access", "different-repo"])
async def test_missing_current_authorization_never_writes(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    scenario: str,
) -> None:
    # Verifies XCO-001 and XCO-009.
    worker, store, client, _ = stack
    job = queued(worker, store)
    if scenario == "authority":
        store.enqueue_authority(
            AuthorityRequest(18, TRIGGER.repository, "main", "push.repository_base")
        )
    elif scenario == "replaced":
        client.get_merge_candidate.side_effect = [IDENTITY, replace(IDENTITY, entry_id="MQE_later")]
    elif scenario == "lost-access":
        client.installation_includes_repository.return_value = False
    else:
        client.get_repository.return_value = {"id": 34, "full_name": TRIGGER.repository}
    with pytest.raises(GitHubError):
        await worker.process(job)
    client.write_merge_group_check.assert_not_called()
    assert worker.queue.is_current(job)


@pytest.mark.asyncio
@pytest.mark.parametrize("race", ["response-lost", "dismissal"])
async def test_uncertain_success_is_reset_and_not_completed(
    stack: tuple[MergeGroupWorker, QueueStore, Mock, AsyncMock],
    race: str,
) -> None:
    # Verifies XCO-008 with an actual durable delivery racing the write.
    worker, store, client, _ = stack
    job = queued(worker, store)
    client.existing_merge_group_check.side_effect = [None, None, 88]

    async def write(*args: Any, **kwargs: Any) -> None:
        if kwargs["approved"]:
            if race == "response-lost":
                raise GitHubError("lost response after write")
            review = JobRequest(
                18, TRIGGER.repository, 7, "review.dismissed", IDENTITY.pull_head_sha
            )
            assert await asyncio.to_thread(
                store.accept_delivery,
                "dismissed",
                "pull_request_review",
                review,
                invalidate_merge_groups=True,
            )

    client.write_merge_group_check.side_effect = write
    with pytest.raises(GitHubError):
        await worker.process(job)
    calls = client.write_merge_group_check.await_args_list
    assert [call.kwargs["approved"] for call in calls] == [True, False]
    assert calls[1].kwargs["check_id"] == 88
    if race == "dismissal":
        retry = worker.queue.claim("new-generation", 60)
        assert retry is not None and retry.generation == job.generation + 1
    else:
        assert worker.queue.is_current(job)
