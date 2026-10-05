from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from test_service import BASE, HEAD, FakeGitHub, migrated_store, settings

from extra_codeowners.api_budget import (
    REQUEST_LANE,
    CoreQuota,
    RecoveryApiBudget,
    RecoveryBudgetDeferredError,
)
from extra_codeowners.database import AuthorityJob, AuthorityRequest, JobRequest, QueueStore
from extra_codeowners.github import GitHubError, GitHubRateLimitError
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

    async def list_with_budget(*_args: Any) -> list[dict[str, Any]]:
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
            return [{"full_name": "example/project"}]

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

    async def arrival_during_request(*_args: Any) -> None:
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
async def test_identified_revocation_uses_reserved_quota(tmp_path: Path) -> None:
    store, github, _, worker = authority_fixture(tmp_path)
    github.checks.append({"status": "completed", "conclusion": "success"})
    lanes: list[str] = []
    original = worker.evaluator.invalidate_for_trigger

    async def capture_lane(job: JobRequest, shared_head_generation: int | None = None) -> bool:
        lanes.append(REQUEST_LANE.get())
        return await original(job, shared_head_generation)

    worker.evaluator.invalidate_for_trigger = capture_lane  # type: ignore[method-assign]
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert await worker._process_authority(claimed) == "completed"
    assert lanes == ["authority"]
    assert github.checks[-1]["status"] == "in_progress"
