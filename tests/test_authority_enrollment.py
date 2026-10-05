from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from test_service import BASE, HEAD, FakeGitHub, migrated_store, settings

from extra_codeowners.api_budget import (
    REQUEST_LANE,
    CoreQuota,
    RecoveryApiBudget,
    RecoveryBudgetDeferredError,
)
from extra_codeowners.database import (
    AuthorityJob,
    AuthorityRequest,
    ClaimedAuthorityJob,
    EvaluationJob,
    JobRequest,
    QueueStore,
    utcnow,
)
from extra_codeowners.github import AuthorityPullPage, GitHubError, GitHubRateLimitError
from extra_codeowners.service import EvaluationService, Worker


def authority_fixture(tmp_path: Path) -> tuple[QueueStore, Any, EvaluationService, Worker]:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-enrollment.db'}")
    github = FakeGitHub(changed_path="uv.lock")
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"number": 3, "head": {"sha": HEAD}, "base": {"ref": "main"}}]
    )
    github.get_pull = AsyncMock(wraps=github.get_pull)  # type: ignore[method-assign]
    github.has_check_run = AsyncMock(wraps=github.has_check_run)  # type: ignore[method-assign]
    github.has_reconciliation_check = AsyncMock(  # type: ignore[method-assign]
        wraps=github.has_reconciliation_check
    )
    github.get_branch_head = AsyncMock(return_value="c" * 40)  # type: ignore[method-assign]
    github.get_file_text = AsyncMock(return_value=None)  # type: ignore[method-assign]
    runtime = settings()
    evaluator = EvaluationService(runtime, github, store)  # type: ignore[arg-type]
    worker = Worker(runtime, store, evaluator, "worker")
    store.enqueue_authority(
        AuthorityRequest(2, "example/project", None, "push.organization_policy")
    )
    return store, github, evaluator, worker


def pull_summary(number: int, updated_at: str, *, sha: str = HEAD) -> dict[str, Any]:
    return {
        "number": number,
        "head": {"sha": sha},
        "base": {"ref": "main"},
        "updated_at": updated_at,
    }


async def run_deferred_authority_attempt(store: QueueStore, worker: Worker) -> ClaimedAuthorityJob:
    claimed = store.claim_authority(worker.owner, 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "budget_deferred"
    with store.session() as session:
        row = session.get(AuthorityJob, claimed.id)
        assert row is not None
        row.available_at = utcnow() - timedelta(seconds=1)
    return claimed


@pytest.mark.asyncio
@pytest.mark.parametrize("direct", [False, True])
async def test_unenrolled_authority_does_not_queue_duplicate_work(
    tmp_path: Path, direct: bool
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    if direct:
        store.accept_delivery(
            "direct", "pull_request", JobRequest(2, "example/project", 3, "direct", HEAD)
        )
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    assert await worker._process_authority(claimed) == "completed"

    # Read enrollment once at the current branch, not the PR's stale base SHA.
    github.get_pull.assert_awaited_once_with(2, "example/project", 3)
    github.has_reconciliation_check.assert_awaited_once()
    github.has_check_run.assert_not_awaited()
    github.get_branch_head.assert_awaited_once_with(2, "example/project", "main")
    github.get_file_text.assert_awaited_once_with(
        2, "example/project", settings().policy_path, ref="c" * 40
    )
    assert github.checks == []
    assert store.claim_authority("observer", 60) is None
    evaluation = store.claim("observer", 60)
    if direct:
        assert evaluation is not None
        assert evaluation.reason == "direct"
        assert evaluation.work_class == "interactive"
        assert evaluation.last_delivery_id == "direct"
        assert store.pending_shared_head_invalidation_count() == 1
    else:
        assert evaluation is None
        assert store.pending_count() == 0
        assert store.pending_shared_head_invalidation_count() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize("policy", [None, "", "enabled = false", "malformed = ["])
async def test_authority_preserves_managed_and_present_policy_work(
    tmp_path: Path, managed: bool, policy: str | None
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.get_file_text.return_value = policy
    if managed:
        github.checks.append({"status": "completed", "conclusion": "success"})
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    assert await worker._process_authority(claimed) == "completed"

    evaluation = store.claim("observer", 60)
    if managed or policy is not None:
        assert evaluation is not None and evaluation.work_class == "recovery"
        assert github.checks[-1]["status"] == "in_progress"
        assert store.pending_shared_head_invalidation_count() == 1
    else:
        assert evaluation is None
        assert not github.checks


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["closed", "head", "repository", "unknown_state"])
async def test_changed_pull_does_not_take_unenrolled_shortcut(tmp_path: Path, change: str) -> None:
    _, github, evaluator, _ = authority_fixture(tmp_path)
    pull = await github.get_pull(2, "example/project", 3)
    if change == "closed":
        pull["state"] = "closed"
    elif change == "head":
        pull["head"]["sha"] = "d" * 40
    elif change == "repository":
        pull["base"]["repo"]["full_name"] = "example/renamed"
    else:
        pull["state"] = "unknown"
    github.get_pull.return_value = pull

    assert await evaluator.authority_followup_required(
        JobRequest(2, "example/project", 3, "push.organization_policy", HEAD)
    )
    github.has_reconciliation_check.assert_not_awaited()
    github.get_file_text.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["head", "base", "base_ref", "repository", "sha"])
async def test_malformed_metadata_cannot_prove_absence(tmp_path: Path, field: str) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    pull = await github.get_pull(2, "example/project", 3)
    if field in {"head", "base"}:
        pull[field] = None
    elif field == "base_ref":
        pull["base"]["ref"] = None
    elif field == "repository":
        pull["base"]["repo"] = None
    else:
        pull["head"]["sha"] = "not-a-sha"
    github.get_pull.return_value = pull
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    assert await worker._process_authority(claimed) == "completed"
    evaluation = store.claim("observer", 60)
    assert evaluation is not None and evaluation.work_class == "interactive"
    github.get_file_text.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation", ["get_pull", "has_reconciliation_check", "get_branch_head", "get_file_text"]
)
@pytest.mark.parametrize("limited", [False, True])
async def test_enrollment_lookup_errors_keep_durable_retry(
    tmp_path: Path, operation: str, limited: bool
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    getattr(github, operation).side_effect = (
        GitHubRateLimitError(429, "GET", "/test", "limited", 61)
        if limited
        else GitHubError("lookup unavailable")
    )
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    assert await worker._process_authority(claimed) == ("rate_limited" if limited else "completed")
    if limited:
        assert store.provider_is_backpressured(2)
        assert store.pending_count() >= 2
    else:
        evaluation = store.claim("observer", 60)
        assert evaluation is not None and evaluation.work_class == "interactive"
    assert not github.checks


@pytest.mark.asyncio
async def test_interrupted_enrollment_keeps_repository_authority_fence(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.get_file_text.side_effect = asyncio.CancelledError()
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    with pytest.raises(asyncio.CancelledError):
        await worker._execute_authority(claimed)

    assert store.pending_count() == 1
    assert store.pending_shared_head_invalidation_count() == 0
    assert not github.checks


@pytest.mark.asyncio
async def test_policy_added_after_absence_is_observed_on_next_authority_job(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    first = store.claim_authority("worker", 60)
    assert first is not None
    assert await worker._process_authority(first) == "completed"
    assert store.pending_count() == 0

    github.get_branch_head.return_value = BASE
    github.get_file_text.return_value = "schema_version = 1\nenabled = true\n"
    store.enqueue_authority(AuthorityRequest(2, "example/project", "main", "push.repository_base"))
    second = store.claim_authority("worker", 60)
    assert second is not None
    assert await worker._process_authority(second) == "completed"
    assert github.checks[-1]["status"] == "in_progress"
    evaluation = store.claim("observer", 60)
    assert evaluation is not None and evaluation.head_sha_hint == HEAD


@pytest.mark.asyncio
async def test_large_unenrolled_fanout_does_not_create_a_second_queue(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.list_open_pulls.return_value = [
        {"number": number, "head": {"sha": HEAD}, "base": {"ref": "main"}}
        for number in range(1, 1001)
    ]
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    assert await worker._process_authority(claimed) == "completed"

    assert github.get_pull.await_count == 1000
    assert github.has_reconciliation_check.await_count == 1000
    github.has_check_run.assert_not_awaited()
    assert github.get_branch_head.await_count == 1
    assert github.get_file_text.await_count == 1
    assert store.pending_count() == 0
    assert not github.checks


@pytest.mark.asyncio
async def test_revocation_new_head_is_not_overwritten_after_enrollment_lookup(
    tmp_path: Path,
) -> None:
    store, github, evaluator, worker = authority_fixture(tmp_path)
    github.get_file_text.return_value = "schema_version = 1\nenabled = true\n"
    original = evaluator.authority_followup_required
    new_head = "d" * 40

    async def advance_after_lookup(
        job: JobRequest, *, policy_present: Callable[[str], Awaitable[bool]] | None = None
    ) -> bool:
        required = await original(job, policy_present=policy_present)
        pull = await github.get_pull(2, "example/project", 3)
        pull["head"]["sha"] = new_head
        github.get_pull.return_value = pull
        return required

    evaluator.authority_followup_required = advance_after_lookup  # type: ignore[method-assign]
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    assert await worker._process_authority(claimed) == "completed"

    evaluation = store.claim("observer", 60)
    assert evaluation is not None and evaluation.head_sha_hint == new_head
    assert evaluation.work_class == "interactive"
    assert store.shared_head_generation(2, "example/project", HEAD) == 1
    assert store.shared_head_generation(2, "example/project", new_head) == 1


@pytest.mark.asyncio
async def test_authority_policy_reads_are_shared_only_for_the_same_target_branch(
    tmp_path: Path,
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.list_open_pulls.return_value = [
        {"number": number, "head": {"sha": HEAD}, "base": {"ref": "main"}} for number in range(1, 6)
    ]
    original = github.get_pull

    async def different_branch(installation: int, repository: str, number: int) -> dict[str, Any]:
        pull: dict[str, Any] = await original(installation, repository, number)
        pull["base"]["ref"] = "main" if number % 2 else "release"
        return pull

    github.get_pull = AsyncMock(side_effect=different_branch)
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "completed"
    assert github.get_branch_head.await_count == 2
    assert github.get_file_text.await_count == 2
    assert store.pending_count() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_lookup", ["branch", "policy"])
async def test_authority_caches_failed_policy_observation_per_attempt(
    tmp_path: Path, failed_lookup: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("extra_codeowners.service.log.exception", lambda *_args, **_kwargs: None)
    store, github, _, worker = authority_fixture(tmp_path)
    github.list_open_pulls.return_value = [
        {"number": number, "head": {"sha": f"{number:040x}"}, "base": {"ref": "main"}}
        for number in range(1, 101)
    ]
    original = github.get_pull

    async def distinct_pull(installation: int, repository: str, number: int) -> dict[str, Any]:
        pull: dict[str, Any] = await original(installation, repository, number)
        pull["head"]["sha"] = f"{number:040x}"
        return pull

    github.get_pull = AsyncMock(side_effect=distinct_pull)
    cached_error = GitHubError(f"{failed_lookup} unavailable")
    if failed_lookup == "branch":
        github.get_branch_head.side_effect = [cached_error, "c" * 40]
    else:
        github.get_file_text.side_effect = [cached_error, None]

    first = store.claim_authority("worker", 60)
    assert first is not None
    assert await worker._process_authority(first) == "completed"
    assert github.get_branch_head.await_count == 1
    assert github.get_file_text.await_count == (0 if failed_lookup == "branch" else 1)

    store.enqueue_authority(AuthorityRequest(2, "example/project", "main", "push.repository_base"))
    second = store.claim_authority("worker", 60)
    assert second is not None
    assert await worker._process_authority(second) == "completed"

    # A failed observation is shared among same-branch pulls only within its
    # attempt; a later attempt makes a fresh branch/policy read.
    assert github.get_branch_head.await_count == 2
    assert github.get_file_text.await_count == (1 if failed_lookup == "branch" else 2)
    traceback_depth = 0
    traceback = cached_error.__traceback__
    while traceback is not None:
        traceback_depth += 1
        traceback = traceback.tb_next
    assert traceback_depth < 30


@pytest.mark.asyncio
async def test_failed_revocation_promotion_without_delivery_uses_authority_reserve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("extra_codeowners.service.log.exception", lambda *_args, **_kwargs: None)
    store, github, _, worker = authority_fixture(tmp_path)
    github.checks.append({"status": "completed", "conclusion": "success"})
    github.has_reconciliation_check.return_value = True
    github.has_check_run.return_value = True
    github.upsert_check_run = AsyncMock(side_effect=GitHubError("reset unavailable"))

    first = store.claim_authority("worker", 60)
    assert first is not None
    assert await worker._process_authority(first) == "completed"
    assert github.upsert_check_run.await_count == 1
    with store.session() as session:
        promoted = session.scalar(select(EvaluationJob).where(EvaluationJob.pull_number == 3))
        assert promoted is not None
        assert promoted.work_class == "interactive"
        assert promoted.last_delivery_id is None

    # This quota allows authority work but not background recovery work. The
    # failed-revocation row must therefore make the next authority attempt
    # reserve-eligible even though no webhook delivery produced it.
    budget = RecoveryApiBudget(store)
    budget.observe(2, CoreQuota(100, 20, datetime.now(UTC) + timedelta(minutes=10)))
    lanes: list[str] = []

    async def list_with_budget(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        lanes.append(REQUEST_LANE.get())
        budget.admit(2, recovery=REQUEST_LANE.get() == "recovery")
        return [{"number": 3, "head": {"sha": HEAD}, "base": {"ref": "main"}}]

    github.list_open_pulls.side_effect = list_with_budget
    store.enqueue_authority(AuthorityRequest(2, "example/project", "main", "push.repository_base"))
    resumed = store.claim_authority("worker", 60)
    assert resumed is not None
    assert await worker._process_authority(resumed) == "completed"
    assert lanes == ["authority"]
    assert not store.provider_is_backpressured(2)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["list_open_pulls", "get_pull", "get_branch_head"])
async def test_local_discovery_pause_keeps_fence_without_promoting_or_provider_backoff(
    tmp_path: Path, operation: str
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    getattr(github, operation).side_effect = RecoveryBudgetDeferredError(600)
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "budget_deferred"
    assert not store.provider_is_backpressured(2)
    assert store.pending_count() == 1
    assert store.pending_shared_head_invalidation_count() == 0
    assert store.claim_authority("observer", 60) is None
    with store.session() as session:
        row = session.get(AuthorityJob, claimed.id)
        assert row is not None and row.attempts == 0 and row.lease_owner is None


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["example/project", None])
async def test_direct_delivery_wakes_deferred_discovery_and_uses_reserved_quota(
    tmp_path: Path, scope: str | None
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    budget = RecoveryApiBudget(store)
    budget.observe(2, CoreQuota(100, 20, datetime.now(UTC) + timedelta(minutes=10)))

    async def list_with_budget(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        budget.admit(2, recovery=REQUEST_LANE.get() == "recovery")
        return [{"number": 3, "head": {"sha": HEAD}, "base": {"ref": "main"}}]

    github.list_open_pulls.side_effect = list_with_budget
    if scope is None:
        # Replace the fixture's repository job with installation-wide discovery.
        first = store.claim_authority("worker", 60)
        assert first is not None and store.complete_authority(first, "worker")
        store.enqueue_authority(AuthorityRequest(2, None, None, "push.organization_policy"))

        async def repositories_with_budget(*_args: Any) -> list[dict[str, Any]]:
            budget.admit(2, recovery=REQUEST_LANE.get() == "recovery")
            return [{"full_name": "example/project", "archived": False}]

        github.list_installation_repositories = AsyncMock(side_effect=repositories_with_budget)

    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "budget_deferred"
    assert store.claim_authority("observer", 60) is None

    store.accept_delivery(
        "direct", "pull_request_review", JobRequest(2, "example/project", 3, "review", HEAD)
    )
    # Replay cannot keep waking a job or increment its generation.
    assert not store.accept_delivery(
        "direct", "pull_request_review", JobRequest(2, "example/project", 3, "review", HEAD)
    )
    resumed = store.claim_authority("worker", 60)
    assert resumed is not None
    assert resumed.generation == claimed.generation
    assert await worker._process_authority(resumed) == "completed"
    if scope is None:
        repository_job = store.claim_authority("worker", 60)
        assert repository_job is not None
        assert await worker._process_authority(repository_job) == "completed"
    assert store.claim_authority("observer", 60) is None
    assert not store.provider_is_backpressured(2)
    assert store.pending_count() >= 1  # Original direct work is retained.


@pytest.mark.asyncio
async def test_direct_delivery_during_discovery_deferral_is_not_lost(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)

    async def arrival_during_request(*_args: Any, **_kwargs: Any) -> None:
        store.accept_delivery(
            "during", "pull_request_review", JobRequest(2, "example/project", 3, "review", HEAD)
        )
        raise RecoveryBudgetDeferredError(600)

    github.list_open_pulls.side_effect = arrival_during_request
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "budget_deferred"
    resumed = store.claim_authority("another-replica", 60)
    assert resumed is not None and resumed.generation == claimed.generation
    assert store.authority_has_direct_waiter(resumed)


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["example/project", None])
@pytest.mark.parametrize("arrival_during_claim", [False, True])
async def test_exhausted_provider_quota_retains_reset_delay_with_direct_waiter(
    tmp_path: Path, scope: str | None, arrival_during_claim: bool
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    budget = RecoveryApiBudget(store)
    reset_at = utcnow() + timedelta(minutes=10)
    budget.observe(2, CoreQuota(100, 0, reset_at))
    if scope is None:
        previous = store.claim_authority("worker", 60)
        assert previous is not None and store.complete_authority(previous, "worker")
        store.enqueue_authority(AuthorityRequest(2, None, None, "push.organization_policy"))

    def accept_direct() -> None:
        assert store.accept_delivery(
            "quota-exhausted-direct",
            "pull_request_review",
            JobRequest(2, "example/project", 3, "review", HEAD),
        )

    if not arrival_during_claim:
        accept_direct()

    async def exhausted_request(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        if arrival_during_claim:
            accept_direct()
        budget.admit(2, recovery=REQUEST_LANE.get() == "recovery")
        raise AssertionError("an exhausted provider budget must prevent the physical request")

    github.list_open_pulls.side_effect = exhausted_request
    if scope is None:
        github.list_installation_repositories = AsyncMock(side_effect=exhausted_request)
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "budget_deferred"
    assert store.authority_has_direct_waiter(claimed)
    with store.session() as session:
        row = session.get(AuthorityJob, claimed.id)
        assert row is not None and row.lease_owner is None and row.attempts == 0
        deadline = row.available_at.replace(tzinfo=UTC)
        assert deadline >= reset_at
    for _ in range(3):
        assert store.claim_authority("other-replica", 60) is None

    # The exhausted installation cannot monopolize another replica's claims.
    store.enqueue_authority(AuthorityRequest(3, "other/project", None, "label.edited"))
    unrelated = store.claim_authority("other-replica", 60)
    assert unrelated is not None and unrelated.installation_id == 3
    with store.session() as session:
        pending = session.scalars(select(EvaluationJob)).all()
        assert len(pending) == 1
        assert pending[0].last_delivery_id == "quota-exhausted-direct"
        assert pending[0].state == "pending"


@pytest.mark.asyncio
async def test_identified_revocation_uses_reserved_quota(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.checks.append({"status": "completed", "conclusion": "success"})
    lanes: list[str] = []
    original = worker.evaluator.invalidate_for_trigger

    async def capture_lane(
        job: JobRequest, shared_head_generation: int | None = None, **kwargs: Any
    ) -> bool:
        lanes.append(REQUEST_LANE.get())
        return await original(job, shared_head_generation, **kwargs)

    worker.evaluator.invalidate_for_trigger = capture_lane  # type: ignore[method-assign]
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "completed"
    assert lanes == ["authority"]
    assert github.checks[-1]["status"] == "in_progress"


@pytest.mark.asyncio
async def test_new_enrollment_reuses_policy_during_revocation(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.get_file_text.return_value = "enabled = true"
    github.list_open_pulls.return_value = [
        {"number": number, "head": {"sha": f"{number:040x}"}, "base": {"ref": "main"}}
        for number in range(1, 21)
    ]

    async def current_pull(installation: int, repository: str, number: int) -> dict[str, Any]:
        return {
            "state": "open",
            "head": {"sha": f"{number:040x}"},
            "base": {"ref": "main", "repo": {"full_name": repository}},
        }

    github.get_pull.side_effect = current_pull
    github.has_reconciliation_check.return_value = False
    github.has_check_run.return_value = False
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "completed"
    assert github.get_pull.await_count == 40  # Fresh evidence before each reset.
    assert github.get_branch_head.await_count == 1
    assert github.get_file_text.await_count == 1
    assert len(github.checks) == 20


@pytest.mark.asyncio
async def test_authority_resumes_handled_prefix_on_another_replica(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.list_open_pulls.return_value = [
        {"number": number, "head": {"sha": f"{number:040x}"}, "base": {"ref": "main"}}
        for number in range(205, 0, -1)
    ]
    original = github.get_pull
    paused = True
    visited: list[int] = []

    async def limited_pull(installation: int, repository: str, number: int) -> dict[str, Any]:
        visited.append(number)
        if paused and number >= 126:
            raise RecoveryBudgetDeferredError(600)
        pull: dict[str, Any] = await original(installation, repository, number)
        pull["head"]["sha"] = f"{number:040x}"
        return pull

    github.get_pull = AsyncMock(side_effect=limited_pull)
    worker.owner = "first-replica"
    first = store.claim_authority("first-replica", 60)
    assert first is not None
    assert await worker._process_authority(first) == "budget_deferred"
    with store.session() as session:
        row = session.get(AuthorityJob, first.id)
        assert row is not None and row.pull_cursor_number == 125
        assert row.listing_next_page == 2 and row.listing_last_number == 100
        assert set(row.handled_pull_fingerprints) == {str(number) for number in range(101, 126)}
        assert all(len(value) == 64 for value in row.handled_pull_fingerprints.values())
        expected_handled = dict(row.handled_pull_fingerprints)
        row.available_at = utcnow() - timedelta(seconds=1)
    assert store.pending_count() == 1
    paused = False
    visited.clear()
    second = store.claim_authority("second-replica", 60)
    assert second is not None and second.pull_cursor_number == 125
    assert second.listing_next_page == 2 and second.listing_last_number == 100
    assert dict(second.handled_pull_fingerprints) == expected_handled
    worker = Worker(worker.settings, store, worker.evaluator, "second-replica")
    assert await worker._process_authority(second) == "completed"
    assert min(visited) == 126 and max(visited) == 205
    assert store.pending_count() == 0


@pytest.mark.asyncio
async def test_authority_does_not_checkpoint_past_an_earlier_deferred_pull(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.list_open_pulls.return_value = [
        {"number": number, "head": {"sha": HEAD}, "base": {"ref": "main"}} for number in range(1, 5)
    ]
    original = github.get_pull

    async def out_of_order(installation: int, repository: str, number: int) -> dict[str, Any]:
        if number == 2:
            await asyncio.sleep(0.01)
            raise RecoveryBudgetDeferredError(600)
        return await original(installation, repository, number)  # type: ignore[no-any-return]

    github.get_pull = AsyncMock(side_effect=out_of_order)
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "budget_deferred"
    with store.session() as session:
        row = session.get(AuthorityJob, claimed.id)
        assert row is not None and row.pull_cursor_number == 1
        assert set(row.handled_pull_fingerprints) == {"1"}


@pytest.mark.asyncio
async def test_authority_visits_low_number_reopened_between_quota_attempts(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    old = "2026-09-01T12:00:00Z"
    reopened = "2026-09-03T12:00:00Z"
    listings = iter(
        [
            [pull_summary(1, old), pull_summary(2, old)],
            [pull_summary(2, old)],  # Pull 1 is closed during this observation.
            [pull_summary(1, reopened), pull_summary(2, old)],  # It reopens with new evidence.
        ]
    )
    stable_calls: list[bool] = []

    async def list_stable(
        _installation: int, _repository: str, *, stable: bool = False
    ) -> list[dict[str, Any]]:
        stable_calls.append(stable)
        return next(listings)

    github.list_open_pulls = AsyncMock(side_effect=list_stable)
    original = github.get_pull
    visited: list[int] = []

    async def defer_pull_two(installation: int, repository: str, number: int) -> dict[str, Any]:
        visited.append(number)
        if number == 2:
            raise RecoveryBudgetDeferredError(600)
        return await original(installation, repository, number)  # type: ignore[no-any-return]

    github.get_pull = AsyncMock(side_effect=defer_pull_two)

    await run_deferred_authority_attempt(store, worker)
    await run_deferred_authority_attempt(store, worker)
    await run_deferred_authority_attempt(store, worker)

    assert stable_calls == [True, True, True]
    assert visited.count(1) == 2
    assert visited.count(2) == 3


@pytest.mark.asyncio
async def test_authority_revisits_handled_pull_when_updated_at_changes(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    listings = iter(
        [
            [pull_summary(5, "2026-09-01T12:00:00Z"), pull_summary(6, "2026-09-01T12:00:00Z")],
            [pull_summary(5, "2026-09-02T12:00:00Z"), pull_summary(6, "2026-09-01T12:00:00Z")],
        ]
    )

    async def list_stable(
        _installation: int, _repository: str, *, stable: bool = False
    ) -> list[dict[str, Any]]:
        assert stable
        return next(listings)

    github.list_open_pulls = AsyncMock(side_effect=list_stable)
    original = github.get_pull
    visited: list[int] = []

    async def defer_pull_six(installation: int, repository: str, number: int) -> dict[str, Any]:
        visited.append(number)
        if number == 6:
            raise RecoveryBudgetDeferredError(600)
        return await original(installation, repository, number)  # type: ignore[no-any-return]

    github.get_pull = AsyncMock(side_effect=defer_pull_six)

    await run_deferred_authority_attempt(store, worker)
    await run_deferred_authority_attempt(store, worker)

    assert visited.count(5) == 2
    assert visited.count(6) == 2


@pytest.mark.asyncio
async def test_authority_resume_keeps_closed_page_progress_across_reserve_deferral(
    tmp_path: Path,
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    page_calls: list[tuple[int, int]] = []

    async def list_page(
        _installation: int,
        _repository: str,
        *,
        page: int = 1,
        after_number: int = 0,
    ) -> AuthorityPullPage:
        page_calls.append((page, after_number))
        if page == 1:
            # This full page contains only closed PRs, so it yields no pulls but
            # still advances the durable listing cursor.
            return AuthorityPullPage([], next_page=2, last_number=100)
        assert page == 2 and after_number == 100
        return AuthorityPullPage(
            [pull_summary(101, "2026-09-01T12:00:00Z"), pull_summary(102, "2026-09-01T12:00:00Z")],
            next_page=0,
            last_number=200,
        )

    github.list_authority_pull_page = AsyncMock(side_effect=list_page)
    original = github.get_pull
    pause_second = True
    visited: list[int] = []

    async def pause_second_pull(installation: int, repository: str, number: int) -> dict[str, Any]:
        nonlocal pause_second
        visited.append(number)
        if number == 102 and pause_second:
            raise RecoveryBudgetDeferredError(600)
        return await original(installation, repository, number)  # type: ignore[no-any-return]

    github.get_pull = AsyncMock(side_effect=pause_second_pull)
    first = await run_deferred_authority_attempt(store, worker)
    assert page_calls == [(1, 0), (2, 100)]
    with store.session() as session:
        row = session.get(AuthorityJob, first.id)
        assert row is not None
        assert row.listing_next_page == 2
        assert row.listing_last_number == 100
        assert set(row.handled_pull_fingerprints) == {"101"}

    pause_second = False
    worker.owner = "second-replica"
    second = store.claim_authority("second-replica", 60)
    assert second is not None
    assert second.listing_next_page == 2 and second.listing_last_number == 100
    worker = Worker(worker.settings, store, worker.evaluator, "second-replica")
    assert await worker._process_authority(second) == "completed"
    assert page_calls == [(1, 0), (2, 100), (2, 100)]
    assert visited.count(101) == 1
    assert visited.count(102) == 2


@pytest.mark.asyncio
async def test_authority_resume_keeps_closed_page_progress_when_next_listing_defers(
    tmp_path: Path,
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    page_calls: list[tuple[int, int]] = []
    defer_listing = True

    async def list_page(
        _installation: int,
        _repository: str,
        *,
        page: int = 1,
        after_number: int = 0,
    ) -> AuthorityPullPage:
        nonlocal defer_listing
        page_calls.append((page, after_number))
        if page == 1:
            return AuthorityPullPage([], next_page=2, last_number=100)
        assert page == 2 and after_number == 100
        if defer_listing:
            defer_listing = False
            raise RecoveryBudgetDeferredError(600)
        return AuthorityPullPage(
            [pull_summary(101, "2026-09-01T12:00:00Z")],
            next_page=0,
            last_number=101,
        )

    github.list_authority_pull_page = AsyncMock(side_effect=list_page)

    first = await run_deferred_authority_attempt(store, worker)
    assert page_calls == [(1, 0), (2, 100)]
    with store.session() as session:
        row = session.get(AuthorityJob, first.id)
        assert row is not None
        assert row.listing_next_page == 2
        assert row.listing_last_number == 100
        assert row.handled_pull_fingerprints == {}

    worker.owner = "second-replica"
    second = store.claim_authority("second-replica", 60)
    assert second is not None
    assert second.listing_next_page == 2 and second.listing_last_number == 100
    worker = Worker(worker.settings, store, worker.evaluator, "second-replica")
    assert await worker._process_authority(second) == "completed"
    assert page_calls == [(1, 0), (2, 100), (2, 100)]


@pytest.mark.asyncio
async def test_narrow_followup_revisits_pull_already_handled_by_broad_scan(
    tmp_path: Path,
) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    summary = pull_summary(3, "2026-09-01T12:00:00Z")
    fingerprint = hashlib.sha256(
        json.dumps([3, HEAD, "main", summary["updated_at"]], separators=(",", ":")).encode()
    ).hexdigest()
    broad = store.claim_authority("worker", 60)
    assert broad is not None
    assert store.advance_authority_cursor(
        broad,
        3,
        {"3": fingerprint},
        listing_next_page=2,
        listing_last_number=100,
    )
    store.enqueue_authority(AuthorityRequest(2, "example/project", "main", "push.repository_base"))
    assert store.complete_authority(broad, "worker")
    narrow = store.claim_authority("narrow-worker", 60)
    assert narrow is not None and narrow.base_ref == "main"
    github.list_authority_pull_page = AsyncMock(
        return_value=AuthorityPullPage([summary], next_page=0, last_number=3)
    )
    worker = Worker(worker.settings, store, worker.evaluator, "narrow-worker")

    assert await worker._process_authority(narrow) == "completed"

    github.get_pull.assert_awaited_once_with(2, "example/project", 3)


def test_authority_cursor_is_monotonic_and_retains_later_full_pass(tmp_path: Path) -> None:
    store, _, _, _ = authority_fixture(tmp_path)
    first = store.claim_authority("first-replica", 60)
    assert first is not None
    handled = {"10": "a" * 64, "20": "b" * 64}
    assert store.advance_authority_cursor(
        first, 20, handled, listing_next_page=3, listing_last_number=200
    )
    assert store.advance_authority_cursor(
        first, 10, handled, listing_next_page=3, listing_last_number=200
    )
    with store.session() as session:
        row = session.get(AuthorityJob, first.id)
        assert row is not None and row.pull_cursor_number == 20
        assert row.handled_pull_fingerprints == handled
        assert row.listing_next_page == 3 and row.listing_last_number == 200
    store.enqueue_authority(
        AuthorityRequest(2, "example/project", None, "push.organization_policy")
    )
    assert store.advance_authority_cursor(first, 30)
    assert store.claim_authority("second-replica", 60) is None
    assert store.complete_authority(first, "first-replica")
    second = store.claim_authority("second-replica", 60)
    assert second is not None and second.generation > first.generation
    assert second.pull_cursor_number == 0
    assert second.handled_pull_fingerprints == ()
    assert second.listing_next_page == 1 and second.listing_last_number == 0


def test_expired_claim_cannot_advance_but_takeover_retains_progress(tmp_path: Path) -> None:
    store, _, _, _ = authority_fixture(tmp_path)
    first = store.claim_authority("first-replica", 60)
    assert first is not None
    handled = {"20": "c" * 64}
    assert store.advance_authority_cursor(
        first, 20, handled, listing_next_page=2, listing_last_number=100
    )
    with store.session() as session:
        row = session.get(AuthorityJob, first.id)
        assert row is not None
        row.lease_until = utcnow() - timedelta(seconds=1)
    assert not store.advance_authority_cursor(first, 30)
    second = store.claim_authority("second-replica", 60)
    assert second is not None and second.generation > first.generation
    assert second.pull_cursor_number == 20
    assert dict(second.handled_pull_fingerprints) == handled
    assert second.listing_next_page == 2 and second.listing_last_number == 100
    assert not store.advance_authority_cursor(first, 30)
    extended = {**handled, "40": "d" * 64}
    assert store.advance_authority_cursor(
        second, 40, extended, listing_next_page=3, listing_last_number=200
    )
    with store.session() as session:
        row = session.get(AuthorityJob, second.id)
        assert row is not None and row.handled_pull_fingerprints == extended
        assert row.listing_next_page == 3 and row.listing_last_number == 200
