from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import ANY, AsyncMock, MagicMock

import pytest

import extra_codeowners.service as service_module
from extra_codeowners.codeowners import parse_codeowners
from extra_codeowners.database import (
    AuthorityJob,
    AuthorityRequest,
    ClaimedJob,
    EvaluationJob,
    JobRequest,
    QueueStore,
    utcnow,
)
from extra_codeowners.github import GitHubError, GitHubOperationStoppedError, GitHubRateLimitError
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.models import OrganizationPolicy
from extra_codeowners.settings import Settings

AuthorityChangePendingError = service_module.AuthorityChangePendingError
EvaluationService = service_module.EvaluationService
Reconciler = service_module.Reconciler
ReconciliationOutcome = service_module.ReconciliationOutcome
Worker = service_module.Worker

HEAD = "a" * 40
BASE = "b" * 40


class FakeGitHub:
    def __init__(self, *, changed_path: str, reviewer_type: str = "Bot") -> None:
        self.changed_path = changed_path
        self.reviewer_type = reviewer_type
        self.checks: list[dict[str, Any]] = []

    async def get_pull(self, installation_id: int, repository: str, number: int) -> dict[str, Any]:
        return {
            "number": number,
            "state": "open",
            "html_url": f"https://github.com/{repository}/pull/{number}",
            "head": {"sha": HEAD},
            "base": {
                "sha": BASE,
                "ref": "main",
                "repo": {"full_name": "example/project"},
            },
            "changed_files": 1,
            "labels": [{"name": "autoapprove"}],
        }

    async def get_file_text(
        self,
        installation_id: int,
        repository: str,
        path: str,
        *,
        ref: str | None = None,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        if repository == "example/.github" and path.endswith("extra-codeowners.toml"):
            return """
schema_version = 1
[apps.stampbot]
slug = "stampbot"
app_id = 2909932
bot_user_id = 262871904
"""
        if path.endswith("extra-codeowners.toml"):
            return """
schema_version = 1
enabled = true
[[delegations]]
app = "stampbot"
paths = ["**/*.lock", ".github/workflows/**"]
for_owners = ["@example/platform"]
required_labels = ["autoapprove"]
"""
        if path == ".github/CODEOWNERS":
            return "* @example/platform\n"
        return None

    async def get_pull_files(
        self, installation_id: int, repository: str, number: int
    ) -> list[dict[str, Any]]:
        return [{"filename": self.changed_path, "status": "modified"}]

    async def get_reviews(
        self, installation_id: int, repository: str, number: int
    ) -> list[dict[str, Any]]:
        if self.reviewer_type == "Bot":
            user = {"id": 262871904, "login": "stampbot[bot]", "type": "Bot"}
        else:
            user = {"id": 100, "login": "human-reviewer", "type": "User"}
        return [
            {
                "id": 5,
                "state": "APPROVED",
                "user": user,
                "commit_id": HEAD,
                "submitted_at": datetime.now(UTC).isoformat(),
            }
        ]

    async def get_codeowners_errors(
        self, installation_id: int, repository: str, ref: str
    ) -> list[dict[str, Any]]:
        return []

    async def team_member(
        self,
        installation_id: int,
        organization: str,
        team_slug: str,
        username: str,
    ) -> bool:
        return self.reviewer_type == "User" and team_slug == "platform"

    async def user_can_own_repository(
        self,
        installation_id: int,
        repository: str,
        username: str,
    ) -> bool:
        return self.reviewer_type == "User"

    async def team_can_own_repository(
        self,
        installation_id: int,
        organization: str,
        team_slug: str,
        repository: str,
    ) -> bool:
        return team_slug == "platform"

    async def get_app(self, installation_id: int, slug: str) -> dict[str, Any]:
        return {"id": 2909932, "slug": slug}

    async def upsert_check_run(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
        **values: Any,
    ) -> int:
        self.checks.append(
            {"repository": repository, "head_sha": head_sha, "name": check_name, **values}
        )
        return 99

    async def has_check_run(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
    ) -> bool:
        return bool(self.checks)

    async def existing_check_run_id(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
    ) -> int | None:
        return 99 if self.checks else None

    async def reset_check_run(
        self,
        installation_id: int,
        repository: str,
        check_run_id: int,
        check_name: str,
        **values: Any,
    ) -> None:
        head_sha = next(
            (
                str(check["head_sha"])
                for check in reversed(self.checks)
                if isinstance(check.get("head_sha"), str)
            ),
            HEAD,
        )
        self.checks.append(
            {
                "repository": repository,
                "head_sha": head_sha,
                "name": check_name,
                "status": "in_progress",
                **values,
            }
        )

    async def list_commit_pulls(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
    ) -> list[dict[str, Any]]:
        return [
            {
                "number": 3,
                "state": "open",
                "head": {"sha": head_sha},
            }
        ]


def settings() -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        worker_enabled=False,
        reconcile_enabled=False,
    )


def migrated_store(database_url: str) -> QueueStore:
    upgrade_database(database_url)
    store = QueueStore(database_url)
    store.initialize()
    return store


def job(store: QueueStore) -> ClaimedJob:
    store.enqueue(
        JobRequest(
            installation_id=2,
            repository_full_name="example/project",
            pull_number=3,
            reason="test",
            head_sha_hint=HEAD,
        )
    )
    invalidations = 0
    while invalidation := store.claim_shared_head_invalidation("test-head-worker", 60):
        assert store.complete_shared_head_invalidation(invalidation)
        invalidations += 1
    assert invalidations >= 1
    claimed = store.claim("test-worker", 60)
    assert claimed is not None
    return claimed


def record_guard_releases(store: QueueStore, events: list[str]) -> None:
    """Record publication-guard release order without changing lock behavior."""
    original_release = store.release_check_write_guard

    def release(guard: Any) -> None:
        events.append("guard_released")
        original_release(guard)

    store.release_check_write_guard = release  # type: ignore[method-assign]


@pytest.mark.asyncio
async def test_allowed_application_approval_satisfies_owned_lockfile(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]

    await service.evaluate_job(job(store))

    assert github.checks[-1]["conclusion"] == "success"


@pytest.mark.asyncio
async def test_stale_repository_alias_is_discarded_before_policy_or_check_access(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    original = github.get_pull

    async def pull_from_renamed_repository(*args: Any, **kwargs: Any) -> dict[str, Any]:
        pull = await original(*args, **kwargs)
        pull["base"]["repo"]["full_name"] = "example/renamed-project"
        return pull

    github.get_pull = pull_from_renamed_repository  # type: ignore[method-assign]
    github.has_check_run = AsyncMock(  # type: ignore[method-assign]
        side_effect=AssertionError("stale repository alias reached Check Runs")
    )
    github.get_file_text = AsyncMock(  # type: ignore[method-assign]
        side_effect=AssertionError("stale repository alias reached policy content")
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'stale-alias.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks == []
    github.has_check_run.assert_not_awaited()
    github.get_file_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_trailing_comment_does_not_replace_another_actors_approval(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    approved = await github.get_reviews(2, "example/project", 3)
    github.get_reviews = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            *approved,
            {"id": 6, "state": "COMMENTED", "user": None},
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'comment.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "success"


@pytest.mark.asyncio
async def test_shared_head_commit_fails_closed_across_pull_requests(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_commit_pulls = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            {"number": 3, "state": "open", "head": {"sha": HEAD}},
            {"number": 4, "state": "open", "head": {"sha": HEAD}},
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'shared-head.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "failure"
    assert "shared" in github.checks[-1]["text"]


@pytest.mark.parametrize(
    "stale_summary",
    [
        {"number": 4, "state": "closed", "head": {"sha": HEAD}},
        {"number": 4, "state": "open", "head": {"sha": "c" * 40}},
    ],
    ids=("stale-closed", "stale-other-head"),
)
@pytest.mark.asyncio
async def test_shared_head_uniqueness_fetches_current_state_for_stale_summaries(
    tmp_path: Path,
    stale_summary: dict[str, Any],
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_commit_pulls = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            {"number": 3, "state": "open", "head": {"sha": HEAD}},
            stale_summary,
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'stale-shared-head-summary.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "failure"
    assert "shared" in github.checks[-1]["text"]


@pytest.mark.parametrize(
    "stale_summary",
    [
        {"number": 4, "state": "closed", "head": {"sha": HEAD}},
        {"number": 4, "state": "open", "head": {"sha": "c" * 40}},
    ],
    ids=("stale-closed", "stale-other-head"),
)
@pytest.mark.asyncio
async def test_durable_invalidation_fans_out_current_pull_despite_stale_summary(
    tmp_path: Path,
    stale_summary: dict[str, Any],
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.checks.append({"status": "completed", "conclusion": "success", "head_sha": HEAD})
    github.list_commit_pulls = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            {"number": 3, "state": "open", "head": {"sha": HEAD}},
            stale_summary,
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'stale-invalidation-summary.db'}")
    acceptance = store.accept_delivery(
        "stale-associated-summary",
        "pull_request",
        JobRequest(2, "example/project", 3, "pull_request.opened", HEAD),
    )
    assert acceptance.accepted is True
    invalidation = store.claim_shared_head_invalidation("head-worker", 60)
    assert invalidation is not None

    await EvaluationService(settings(), github, store).invalidate_shared_head(  # type: ignore[arg-type]
        invalidation,
        asyncio.Event(),
    )

    first = store.claim("evaluation-1", 60)
    second = store.claim("evaluation-2", 60)
    assert first is not None and second is not None
    assert {first.pull_number, second.pull_number} == {3, 4}
    assert {first.shared_head_generation, second.shared_head_generation} == {
        invalidation.generation
    }


@pytest.mark.asyncio
async def test_cross_pull_trigger_fences_stale_shared_head_success(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'cross-pull-fence.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    final_read_entered = asyncio.Event()
    allow_final_read = asyncio.Event()
    original_get_pull = github.get_pull
    first_pull_reads = 0

    async def pause_first_pull_final_read(
        installation_id: int,
        repository: str,
        number: int,
    ) -> dict[str, Any]:
        nonlocal first_pull_reads
        if number == 3:
            first_pull_reads += 1
            if first_pull_reads == 2:
                final_read_entered.set()
                await allow_final_read.wait()
        return await original_get_pull(installation_id, repository, number)

    github.get_pull = pause_first_pull_final_read  # type: ignore[method-assign]
    stale_evaluation = asyncio.create_task(service.evaluate_job(claimed))
    await final_read_entered.wait()

    second_pull_trigger = JobRequest(
        installation_id=2,
        repository_full_name="example/project",
        pull_number=4,
        reason="pull_request_review.submitted",
        head_sha_hint=HEAD,
    )
    assert store.accept_delivery(
        "second-pull-review",
        "pull_request_review",
        second_pull_trigger,
    )
    assert await service.invalidate_for_trigger(second_pull_trigger) is True

    allow_final_read.set()
    await asyncio.wait_for(stale_evaluation, timeout=1)

    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "in_progress",
    ]
    assert all(check.get("conclusion") is None for check in github.checks)
    assert store.shared_head_generation(2, "example/project", HEAD) == 2


@pytest.mark.asyncio
async def test_cross_pull_trigger_during_completion_restores_blocking_check(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'cross-pull-postflight.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    original_upsert = github.upsert_check_run
    accepted = False

    async def accept_other_pull_during_completion(*args: Any, **kwargs: Any) -> int:
        nonlocal accepted
        result = await original_upsert(*args, **kwargs)
        if kwargs.get("status") == "completed" and not accepted:
            accepted = True
            assert store.accept_delivery(
                "other-pull-during-completion",
                "pull_request",
                JobRequest(
                    installation_id=2,
                    repository_full_name="example/project",
                    pull_number=4,
                    reason="pull_request.labeled",
                    head_sha_hint=HEAD,
                ),
            )
        return result

    github.upsert_check_run = accept_other_pull_during_completion  # type: ignore[method-assign]

    await service.evaluate_job(claimed)

    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "completed",
        "in_progress",
    ]
    assert github.checks[-1].get("conclusion") is None


@pytest.mark.asyncio
async def test_evaluation_lease_loss_during_associated_pull_reads_blocks_completion(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'lease-loss-associated-reads.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    original_get_pull = github.get_pull
    pull_reads = 0
    replacement: ClaimedJob | None = None

    async def replace_expired_claim(
        installation_id: int,
        repository: str,
        number: int,
    ) -> dict[str, Any]:
        nonlocal pull_reads, replacement
        pull_reads += 1
        pull = await original_get_pull(installation_id, repository, number)
        if pull_reads == 3:
            assert store.renew_claim(claimed, -1)
            replacement = store.claim("replacement-worker", 60)
            assert replacement is not None
        return pull

    github.get_pull = replace_expired_claim  # type: ignore[method-assign]

    await service.evaluate_job(claimed)

    assert replacement is not None
    assert replacement.generation == claimed.generation + 1
    assert [check["status"] for check in github.checks] == ["in_progress"]
    assert store.is_current_claim(claimed) is False


@pytest.mark.asyncio
async def test_evaluation_lease_loss_during_completion_restores_blocking_check(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'lease-loss-postflight.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    original_upsert = github.upsert_check_run
    replacement: ClaimedJob | None = None

    async def replace_claim_after_completion(*args: Any, **kwargs: Any) -> int:
        nonlocal replacement
        result = await original_upsert(*args, **kwargs)
        if kwargs.get("status") == "completed":
            assert store.renew_claim(claimed, -1)
            replacement = store.claim("replacement-worker", 60)
            assert replacement is not None
        return result

    github.upsert_check_run = replace_claim_after_completion  # type: ignore[method-assign]

    await service.evaluate_job(claimed)

    assert replacement is not None
    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "completed",
        "in_progress",
    ]
    assert github.checks[-1].get("conclusion") is None


@pytest.mark.asyncio
async def test_applied_completed_write_error_resets_before_guard_release_and_propagates(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'completed-write-error.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    original_upsert = github.upsert_check_run
    publication_error = GitHubError("response lost after completed check was applied")
    events: list[str] = []
    record_guard_releases(store, events)

    async def apply_then_raise(*args: Any, **kwargs: Any) -> int:
        result = await original_upsert(*args, **kwargs)
        if kwargs.get("status") == "completed":
            events.append("completed_applied")
            raise publication_error
        if "completed_applied" in events:
            events.append("blocking_reset_applied")
        return result

    github.upsert_check_run = apply_then_raise  # type: ignore[method-assign]

    with pytest.raises(GitHubError) as caught:
        await service.evaluate_job(claimed)

    assert caught.value is publication_error
    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "completed",
        "in_progress",
    ]
    assert github.checks[-1].get("conclusion") is None
    assert events[-4:] == [
        "completed_applied",
        "blocking_reset_applied",
        "guard_released",
        "guard_released",
    ]


@pytest.mark.asyncio
async def test_cancellation_after_completed_write_applies_resets_before_guard_release(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'completed-write-cancel.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    original_upsert = github.upsert_check_run
    completed_applied = asyncio.Event()
    never_return = asyncio.Event()
    events: list[str] = []
    record_guard_releases(store, events)

    async def apply_then_wait(*args: Any, **kwargs: Any) -> int:
        result = await original_upsert(*args, **kwargs)
        if kwargs.get("status") == "completed":
            events.append("completed_applied")
            completed_applied.set()
            await never_return.wait()
        elif "completed_applied" in events:
            events.append("blocking_reset_applied")
        return result

    github.upsert_check_run = apply_then_wait  # type: ignore[method-assign]
    evaluation = asyncio.create_task(service.evaluate_job(claimed))

    await asyncio.wait_for(completed_applied.wait(), timeout=1)
    evaluation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(evaluation, timeout=1)

    assert evaluation.cancelled()
    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "completed",
        "in_progress",
    ]
    assert github.checks[-1].get("conclusion") is None
    assert events[-4:] == [
        "completed_applied",
        "blocking_reset_applied",
        "guard_released",
        "guard_released",
    ]


@pytest.mark.asyncio
async def test_postflight_database_error_restores_blocking_check_before_propagating(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'postflight-database-error.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    original_upsert = github.upsert_check_run
    original_generation_check = store.shared_head_generation_is_publishable
    completed = threading.Event()

    async def observe_completion(*args: Any, **kwargs: Any) -> int:
        result = await original_upsert(*args, **kwargs)
        if kwargs.get("status") == "completed":
            completed.set()
        return result

    def fail_postflight(job_to_check: ClaimedJob, head_sha: str) -> bool:
        if completed.is_set():
            raise RuntimeError("postflight database unavailable")
        return original_generation_check(job_to_check, head_sha)

    github.upsert_check_run = observe_completion  # type: ignore[method-assign]
    store.shared_head_generation_is_publishable = fail_postflight  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="postflight database unavailable"):
        await service.evaluate_job(claimed)

    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "completed",
        "in_progress",
    ]
    assert github.checks[-1].get("conclusion") is None


@pytest.mark.asyncio
async def test_cancellation_during_postflight_waits_for_shielded_blocking_reset(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'postflight-cancellation.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    original_upsert = github.upsert_check_run
    original_generation_check = store.shared_head_generation_is_publishable
    completed = threading.Event()
    postflight_entered = threading.Event()
    release_postflight = threading.Event()
    reset_started = asyncio.Event()
    release_reset = asyncio.Event()
    events: list[str] = []
    record_guard_releases(store, events)

    async def pause_reset(*args: Any, **kwargs: Any) -> int:
        if kwargs.get("status") == "in_progress" and completed.is_set():
            reset_started.set()
            await release_reset.wait()
        result = await original_upsert(*args, **kwargs)
        if kwargs.get("status") == "completed":
            completed.set()
            events.append("completed_applied")
        elif completed.is_set():
            events.append("blocking_reset_applied")
        return result

    def block_postflight(job_to_check: ClaimedJob, head_sha: str) -> bool:
        if completed.is_set():
            postflight_entered.set()
            assert release_postflight.wait(timeout=2)
        return original_generation_check(job_to_check, head_sha)

    github.upsert_check_run = pause_reset  # type: ignore[method-assign]
    store.shared_head_generation_is_publishable = block_postflight  # type: ignore[assignment]
    evaluation = asyncio.create_task(service.evaluate_job(claimed))

    assert await asyncio.to_thread(postflight_entered.wait, 1)
    evaluation.cancel()
    await asyncio.wait_for(reset_started.wait(), timeout=1)
    evaluation.cancel()
    await asyncio.sleep(0)
    assert evaluation.done() is False

    release_reset.set()
    release_postflight.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(evaluation, timeout=1)

    assert evaluation.cancelled()
    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "completed",
        "in_progress",
    ]
    assert github.checks[-1].get("conclusion") is None
    assert events[-4:] == [
        "completed_applied",
        "blocking_reset_applied",
        "guard_released",
        "guard_released",
    ]


@pytest.mark.asyncio
async def test_postflight_reset_failure_preserves_database_error_for_retry(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'postflight-reset-failure.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    claimed = job(store)
    original_upsert = github.upsert_check_run
    original_generation_check = store.shared_head_generation_is_publishable
    completed = threading.Event()

    async def fail_reset(*args: Any, **kwargs: Any) -> int:
        if kwargs.get("status") == "in_progress" and completed.is_set():
            raise GitHubError("blocking reset unavailable")
        result = await original_upsert(*args, **kwargs)
        if kwargs.get("status") == "completed":
            completed.set()
        return result

    def fail_postflight(job_to_check: ClaimedJob, head_sha: str) -> bool:
        if completed.is_set():
            raise RuntimeError("postflight database unavailable")
        return original_generation_check(job_to_check, head_sha)

    github.upsert_check_run = fail_reset  # type: ignore[method-assign]
    store.shared_head_generation_is_publishable = fail_postflight  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="postflight database unavailable"):
        await service.evaluate_job(claimed)

    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "completed",
    ]


@pytest.mark.asyncio
async def test_direct_human_owner_without_write_access_is_not_accepted(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock", reviewer_type="User")
    original = github.get_file_text

    async def direct_owner(*args: Any, **kwargs: Any) -> str | None:
        path = str(args[2])
        if path == ".github/CODEOWNERS":
            return "* @human-reviewer\n"
        return await original(*args, **kwargs)

    github.get_file_text = direct_owner  # type: ignore[method-assign]
    github.user_can_own_repository = AsyncMock(return_value=False)  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'direct-permission.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "failure"


@pytest.mark.asyncio
async def test_team_member_without_team_repository_write_is_not_accepted(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock", reviewer_type="User")
    github.user_can_own_repository = AsyncMock(return_value=False)  # type: ignore[method-assign]
    github.team_can_own_repository = AsyncMock(return_value=False)  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'team-permission.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "failure"
    assert "1 of 1 distinct CODEOWNER requirements are unsatisfied" in github.checks[-1]["summary"]


@pytest.mark.asyncio
async def test_application_cannot_approve_builtin_workflow_path(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path=".github/workflows/release.yml")
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]

    await service.evaluate_job(job(store))

    assert github.checks[-1]["conclusion"] == "failure"
    assert "unsatisfied" in github.checks[-1]["summary"]


@pytest.mark.asyncio
async def test_human_team_member_can_approve_non_delegable_path(tmp_path: Path) -> None:
    github = FakeGitHub(
        changed_path=".github/workflows/release.yml",
        reviewer_type="User",
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]

    await service.evaluate_job(job(store))

    assert github.checks[-1]["conclusion"] == "success"


@pytest.mark.asyncio
async def test_runtime_escape_hatch_is_disclosed_in_check(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path=".github/workflows/release.yml")
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")
    insecure_settings = settings().model_copy(update={"allow_insecure_changes": True})
    service = EvaluationService(insecure_settings, github, store)  # type: ignore[arg-type]

    await service.evaluate_job(job(store))

    assert github.checks[-1]["conclusion"] == "success"
    assert "ALLOW_INSECURE_CHANGES" in github.checks[-1]["summary"]


@pytest.mark.asyncio
async def test_disabled_repository_publishes_failing_check(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    original = github.get_file_text

    async def disabled_policy(*args: Any, **kwargs: Any) -> str | None:
        path = args[2]
        repository = args[1]
        if repository == "example/project" and path.endswith("extra-codeowners.toml"):
            return "schema_version = 1\nenabled = false\n"
        return await original(*args, **kwargs)

    github.get_file_text = disabled_policy  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "failure"


@pytest.mark.asyncio
async def test_missing_codeowners_fails_closed(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    original = github.get_file_text

    async def without_codeowners(*args: Any, **kwargs: Any) -> str | None:
        if str(args[2]).endswith("CODEOWNERS"):
            return None
        return await original(*args, **kwargs)

    github.get_file_text = without_codeowners  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "failure"
    assert "no CODEOWNERS" in github.checks[-1]["text"]


@pytest.mark.asyncio
async def test_github_codeowners_errors_fail_closed(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.get_codeowners_errors = AsyncMock(  # type: ignore[method-assign]
        return_value=[{"line": 2, "message": "Invalid owner"}]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "failure"
    assert "Invalid owner" in github.checks[-1]["text"]


@pytest.mark.asyncio
async def test_missing_label_evidence_fails_closed(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    original = github.get_pull

    async def pull_without_labels(*args: Any, **kwargs: Any) -> dict[str, Any]:
        pull = await original(*args, **kwargs)
        pull.pop("labels")
        return pull

    github.get_pull = pull_without_labels  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")

    with pytest.raises(GitHubError, match="labels list"):
        await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert [check["status"] for check in github.checks] == ["in_progress"]


@pytest.mark.asyncio
async def test_existing_success_is_revoked_before_policy_fetch_failure(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.checks.append({"status": "completed", "conclusion": "success"})
    original = github.get_file_text

    async def broken_policy(
        installation_id: int,
        repository: str,
        path: str,
        **kwargs: Any,
    ) -> str | None:
        if repository == "example/project" and path.endswith("extra-codeowners.toml"):
            raise GitHubError("policy content is unavailable")
        return await original(installation_id, repository, path, **kwargs)

    github.get_file_text = broken_policy  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'policy-fetch.db'}")

    with pytest.raises(GitHubError, match="policy content is unavailable"):
        await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["status"] == "in_progress"


@pytest.mark.asyncio
async def test_app_metadata_mismatch_does_not_authorize_bot(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.get_app = AsyncMock(return_value={"id": 999, "slug": "stampbot"})  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert github.checks[-1]["conclusion"] == "failure"


@pytest.mark.asyncio
async def test_stale_head_hint_requeues_live_head_and_stales_shared_claim(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    original = github.get_pull

    async def current_pull(*args: Any, **kwargs: Any) -> dict[str, Any]:
        pull = await original(*args, **kwargs)
        pull["head"] = {"sha": "c" * 40}
        return pull

    github.get_pull = current_pull  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'stale-head.db'}")
    assert store.accept_delivery(
        "other-current-head",
        "pull_request",
        JobRequest(2, "example/project", 4, "pull_request.opened", "c" * 40),
    )
    prior_current_head_claim = store.claim("other-worker", 60)
    assert prior_current_head_claim is not None
    store.complete(prior_current_head_claim, prior_current_head_claim.lease_owner)
    claimed = job(store)

    await EvaluationService(settings(), github, store).evaluate_job(claimed)  # type: ignore[arg-type]

    assert github.checks == []
    assert store.pending_count() == 2
    assert store.shared_head_generation(2, "example/project", "c" * 40) == 2
    assert store.shared_head_generation_is_current(prior_current_head_claim, "c" * 40) is False


@pytest.mark.asyncio
async def test_revision_change_during_evaluation_is_requeued_without_stale_check(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    calls = 0
    original = github.get_pull

    async def changing_pull(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        pull = await original(*args, **kwargs)
        if calls > 1:
            pull["head"] = {"sha": "c" * 40}
        return pull

    github.get_pull = changing_pull  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")
    assert store.accept_delivery(
        "other-current-head",
        "pull_request",
        JobRequest(2, "example/project", 4, "pull_request.opened", "c" * 40),
    )
    prior_current_head_claim = store.claim("other-worker", 60)
    assert prior_current_head_claim is not None
    store.complete(prior_current_head_claim, prior_current_head_claim.lease_owner)
    claimed = job(store)

    await EvaluationService(settings(), github, store).evaluate_job(claimed)  # type: ignore[arg-type]

    assert [check["status"] for check in github.checks] == ["in_progress"]
    assert store.pending_count() == 2
    assert store.shared_head_generation(2, "example/project", "c" * 40) == 2
    assert store.shared_head_generation_is_current(prior_current_head_claim, "c" * 40) is False


@pytest.mark.asyncio
async def test_label_change_during_evaluation_is_requeued_without_stale_check(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    calls = 0
    original = github.get_pull

    async def changing_pull(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        pull = await original(*args, **kwargs)
        if calls > 1:
            pull["labels"] = []
        return pull

    github.get_pull = changing_pull  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")
    assert store.accept_delivery(
        "other-same-head",
        "pull_request",
        JobRequest(2, "example/project", 4, "pull_request.opened", HEAD),
    )
    prior_same_head_claim = store.claim("other-worker", 60)
    assert prior_same_head_claim is not None
    store.complete(prior_same_head_claim, prior_same_head_claim.lease_owner)
    initial_invalidation = store.claim_shared_head_invalidation("head-worker", 60)
    assert initial_invalidation is not None
    assert store.complete_shared_head_invalidation(initial_invalidation)
    claimed = job(store)

    await EvaluationService(settings(), github, store).evaluate_job(claimed)  # type: ignore[arg-type]

    assert [check["status"] for check in github.checks] == ["in_progress"]
    assert store.pending_count() == 2
    assert store.shared_head_generation(2, "example/project", HEAD) == 3
    assert store.shared_head_generation_is_current(prior_same_head_claim, HEAD) is False
    assert store.shared_head_generation_is_current(claimed, HEAD) is False


@pytest.mark.asyncio
async def test_new_generation_during_collection_prevents_stale_completion(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")
    original = github.upsert_check_run
    triggered = False

    async def trigger_after_pending(*args: Any, **kwargs: Any) -> int:
        nonlocal triggered
        result = await original(*args, **kwargs)
        if kwargs.get("status") == "in_progress" and not triggered:
            triggered = True
            store.enqueue(
                JobRequest(
                    installation_id=2,
                    repository_full_name="example/project",
                    pull_number=3,
                    reason="pull_request_review.dismissed",
                )
            )
        return result

    github.upsert_check_run = trigger_after_pending  # type: ignore[method-assign]

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert [check["status"] for check in github.checks] == ["in_progress"]
    assert store.pending_count() == 1


@pytest.mark.asyncio
async def test_new_generation_during_publish_restores_blocking_check(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'audit.db'}")
    original = github.upsert_check_run

    async def trigger_during_completion(*args: Any, **kwargs: Any) -> int:
        result = await original(*args, **kwargs)
        if kwargs.get("status") == "completed":
            store.enqueue(
                JobRequest(
                    installation_id=2,
                    repository_full_name="example/project",
                    pull_number=3,
                    reason="pull_request.unlabeled",
                )
            )
        return result

    github.upsert_check_run = trigger_during_completion  # type: ignore[method-assign]

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert [check["status"] for check in github.checks] == [
        "in_progress",
        "completed",
        "in_progress",
    ]
    assert store.pending_count() == 1


@pytest.mark.asyncio
async def test_revocation_is_ordered_after_inflight_stale_completion(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'ordered-check.db'}")
    claimed = job(store)
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]
    completion_entered = asyncio.Event()
    allow_completion = asyncio.Event()
    original = github.upsert_check_run

    async def block_completion(*args: Any, **kwargs: Any) -> int:
        if kwargs.get("status") == "completed":
            completion_entered.set()
            await allow_completion.wait()
        return await original(*args, **kwargs)

    github.upsert_check_run = block_completion  # type: ignore[method-assign]
    evaluation = asyncio.create_task(service.evaluate_job(claimed))
    await completion_entered.wait()

    trigger = JobRequest(
        installation_id=2,
        repository_full_name="example/project",
        pull_number=3,
        reason="pull_request_review.submitted",
        head_sha_hint=HEAD,
    )
    store.enqueue(trigger)
    revocation = asyncio.create_task(service.invalidate_for_trigger(trigger))
    await asyncio.sleep(0.05)
    assert revocation.done() is False

    allow_completion.set()
    await asyncio.wait_for(evaluation, timeout=1)
    assert await revocation is True
    # The known-head enqueue already created a durable invalidation generation
    # before the fast reset waited for the in-flight check write.
    store.complete(claimed, claimed.lease_owner)

    statuses = [check["status"] for check in github.checks]
    assert statuses[:2] == ["in_progress", "completed"]
    assert statuses[-1] == "in_progress"
    assert set(statuses[2:]) == {"in_progress"}
    assert store.pending_count() == 2


@pytest.mark.asyncio
async def test_malformed_opinionated_review_fails_closed() -> None:
    github = FakeGitHub(changed_path="uv.lock")
    service = EvaluationService(settings(), github, QueueStore("sqlite:///:memory:"))  # type: ignore[arg-type]

    with pytest.raises(GitHubError, match="omitted actor"):
        await service._reviews(
            2,
            "example/project",
            [{"id": 1, "state": "APPROVED", "user": {"id": 4}}],
            OrganizationPolicy(),
            parse_codeowners("* @example/platform"),
            HEAD,
        )


@pytest.mark.asyncio
async def test_worker_completes_a_durable_job(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'worker.db'}")
    store.enqueue(
        JobRequest(
            installation_id=2,
            repository_full_name="example/project",
            pull_number=3,
            reason="test",
        )
    )
    stop = __import__("asyncio").Event()

    class Evaluator:
        async def evaluate_job(self, claimed: ClaimedJob) -> None:
            assert claimed.pull_number == 3
            stop.set()

    worker = Worker(settings(), store, Evaluator(), "worker")  # type: ignore[arg-type]

    await worker.run(stop)

    assert store.pending_count() == 0


@pytest.mark.asyncio
async def test_worker_defers_rate_limit_without_spending_backoff_attempt(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'worker-rate.db'}")
    store.enqueue(
        JobRequest(
            installation_id=2,
            repository_full_name="example/project",
            pull_number=3,
            reason="test",
        )
    )
    stop = asyncio.Event()

    class Evaluator:
        async def evaluate_job(self, claimed: ClaimedJob) -> None:
            stop.set()
            raise GitHubRateLimitError(429, "GET", "/pulls/3", "rate limited", 60)

    worker = Worker(settings(), store, Evaluator(), "worker")  # type: ignore[arg-type]

    await worker.run(stop)

    assert store.pending_count() == 1
    assert store.dead_count() == 0


@pytest.mark.asyncio
async def test_authority_work_preempts_evaluations_and_fans_out_open_pulls(
    tmp_path: Path,
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-worker.db'}")
    store.enqueue(
        JobRequest(
            installation_id=2,
            repository_full_name="example/project",
            pull_number=3,
            reason="pull_request.opened",
        )
    )
    store.accept_delivery(
        "authority-1",
        "push",
        AuthorityRequest(
            installation_id=2,
            repository_full_name="example/project",
            base_ref="main",
            reason="push.repository_base",
        ),
    )
    stop = asyncio.Event()
    calls: list[str] = []

    class AuthorityGitHub:
        async def list_open_pulls(
            self, installation_id: int, repository: str
        ) -> list[dict[str, Any]]:
            calls.append("authority")
            return [
                {
                    "number": 4,
                    "head": {"sha": "c" * 40},
                    "base": {"ref": "main"},
                }
            ]

    class Evaluator:
        github = AuthorityGitHub()

        async def evaluate_job(self, claimed: ClaimedJob) -> None:
            calls.append("evaluation")

        async def invalidate_for_trigger(self, request: JobRequest) -> bool:
            calls.append(f"revoke-{request.pull_number}")
            stop.set()
            return False

    worker = Worker(settings(), store, Evaluator(), "worker")  # type: ignore[arg-type]

    await worker.run(stop)

    assert calls == ["authority", "revoke-4"]
    assert store.claim_authority("observer", 60) is None
    first = store.claim("observer", 60)
    second = store.claim("observer", 60)
    assert first is not None and second is not None
    assert {first.pull_number, second.pull_number} == {3, 4}
    fanout = first if first.pull_number == 4 else second
    assert fanout.head_sha_hint == "c" * 40
    assert fanout.shared_head_generation == 1
    assert store.shared_head_generation(2, "example/project", "c" * 40) == 1
    assert store.pending_shared_head_invalidation_count() == 1
    assert store.shared_head_generation_is_current(fanout, "c" * 40) is True
    assert store.shared_head_generation_is_publishable(fanout, "c" * 40) is False


@pytest.mark.asyncio
async def test_accepted_authority_change_fences_inflight_success(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-fence.db'}")
    original_get_pull = github.get_pull
    calls = 0

    async def accept_authority_before_final_read(
        installation_id: int, repository: str, number: int
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        pull = await original_get_pull(installation_id, repository, number)
        if calls == 2:
            store.accept_delivery(
                "membership-1",
                "membership",
                AuthorityRequest(
                    installation_id=installation_id,
                    repository_full_name=None,
                    base_ref=None,
                    reason="membership.removed",
                ),
            )
        return pull

    github.get_pull = accept_authority_before_final_read  # type: ignore[method-assign]

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert [check["status"] for check in github.checks] == ["in_progress"]
    assert store.pending_count() == 2


@pytest.mark.asyncio
async def test_authority_ingress_is_serialized_against_check_publication(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-publish.db'}")
    original_upsert = github.upsert_check_run
    acceptance: asyncio.Task[Any] | None = None

    async def accept_during_completion(
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
        **values: Any,
    ) -> int:
        nonlocal acceptance
        result = await original_upsert(
            installation_id,
            repository,
            head_sha,
            check_name,
            **values,
        )
        if values.get("status") == "completed" and acceptance is None:
            acceptance = asyncio.create_task(
                asyncio.to_thread(
                    store.accept_delivery,
                    "label-1",
                    "label",
                    AuthorityRequest(
                        installation_id=installation_id,
                        repository_full_name=repository,
                        base_ref=None,
                        reason="label.edited",
                    ),
                )
            )
            await asyncio.sleep(0.05)
            assert not acceptance.done()
        return result

    github.upsert_check_run = accept_during_completion  # type: ignore[method-assign]

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert acceptance is not None
    assert (await acceptance).accepted is True
    assert [check["status"] for check in github.checks] == ["in_progress", "completed"]
    assert github.checks[-1].get("conclusion") == "success"
    assert store.pending_count() == 2


@pytest.mark.asyncio
async def test_installation_authority_splits_into_normalized_repository_jobs(
    tmp_path: Path,
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-installation.db'}")
    store.accept_delivery(
        "organization-1",
        "organization",
        AuthorityRequest(2, None, None, "organization.member_removed"),
    )
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    class AuthorityGitHub:
        async def list_installation_repositories(
            self, installation_id: int
        ) -> list[dict[str, Any]]:
            return [
                {"full_name": "Example/Project", "archived": False},
                {"full_name": "example/archived", "archived": True},
                {"full_name": "example/.github", "archived": False},
                {"full_name": 7, "archived": False},
            ]

    class Evaluator:
        github = AuthorityGitHub()

    worker = Worker(settings(), store, Evaluator(), "worker")  # type: ignore[arg-type]

    await worker._process_authority(claimed)

    repository_job = store.claim_authority("observer", 60)
    assert repository_job is not None
    assert repository_job.repository_full_name == "example/project"
    assert repository_job.reason == "organization.member_removed"
    assert store.claim_authority("observer", 60) is None


@pytest.mark.asyncio
async def test_authority_rate_limit_defers_after_bounded_batch_and_keeps_fanout(
    tmp_path: Path,
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-rate.db'}")
    store.accept_delivery(
        "push-1",
        "push",
        AuthorityRequest(2, "example/project", "main", "push.repository_base"),
    )
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    class AuthorityGitHub:
        async def list_open_pulls(
            self, installation_id: int, repository: str
        ) -> list[dict[str, Any]]:
            return [
                {"number": 4, "head": {"sha": "c" * 40}, "base": {"ref": "main"}},
                {"number": 5, "head": {"sha": "d" * 40}, "base": {"ref": "main"}},
                {"number": 6, "head": {"sha": "e" * 40}, "base": {"ref": "release"}},
            ]

    class Evaluator:
        github = AuthorityGitHub()

        async def invalidate_for_trigger(self, request: JobRequest) -> bool:
            if request.pull_number == 4:
                return True
            raise GitHubRateLimitError(429, "PATCH", "/check-runs/1", "limited", 61)

    worker = Worker(settings(), store, Evaluator(), "worker")  # type: ignore[arg-type]

    await worker._process_authority(claimed)

    assert store.pending_count() == 5
    assert store.shared_head_generation(2, "example/project", "c" * 40) == 1
    assert store.shared_head_generation(2, "example/project", "d" * 40) == 1
    assert store.dead_count() == 0
    assert store.claim("observer", 60) is None
    assert store.claim_authority("observer", 60) is None


@pytest.mark.asyncio
async def test_authority_fast_revocation_failure_keeps_durable_evaluation(
    tmp_path: Path,
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-revoke.db'}")
    store.accept_delivery(
        "label-1",
        "label",
        AuthorityRequest(2, "example/project", None, "label.edited"),
    )
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    class AuthorityGitHub:
        async def list_open_pulls(
            self, installation_id: int, repository: str
        ) -> list[dict[str, Any]]:
            return [{"number": 4, "head": {"sha": "c" * 40}, "base": {"ref": "main"}}]

    class Evaluator:
        github = AuthorityGitHub()

        async def invalidate_for_trigger(self, request: JobRequest) -> bool:
            raise GitHubError("temporary Check Runs failure")

    worker = Worker(settings(), store, Evaluator(), "worker")  # type: ignore[arg-type]

    await worker._process_authority(claimed)

    evaluation = store.claim("observer", 60)
    assert evaluation is not None
    assert evaluation.pull_number == 4
    assert store.dead_count() == 0


@pytest.mark.asyncio
async def test_malformed_authority_fanout_remains_pending_fail_closed(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-malformed.db'}")
    store.accept_delivery(
        "member-1",
        "member",
        AuthorityRequest(2, "example/project", None, "member.removed"),
    )
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None

    class AuthorityGitHub:
        async def list_open_pulls(
            self, installation_id: int, repository: str
        ) -> list[dict[str, Any]]:
            return [{"number": True, "head": {"sha": "c" * 40}, "base": {"ref": "main"}}]

    class Evaluator:
        github = AuthorityGitHub()

    runtime = settings().model_copy(update={"worker_retry_max_seconds": 5})
    worker = Worker(runtime, store, Evaluator(), "worker")  # type: ignore[arg-type]

    await worker._process_authority(claimed)

    assert store.pending_count() == 1
    assert store.dead_count() == 0


@pytest.mark.asyncio
async def test_evaluation_failure_automatically_retries_until_prior_success_is_revoked(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.checks.append({"status": "completed", "conclusion": "success"})
    original_get_pull = github.get_pull
    failures_remaining = 1

    async def flaky_get_pull(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal failures_remaining
        if failures_remaining:
            failures_remaining -= 1
            raise GitHubError("temporary pull request failure")
        return await original_get_pull(*args, **kwargs)

    github.get_pull = flaky_get_pull  # type: ignore[method-assign]
    store = migrated_store(f"sqlite:///{tmp_path / 'automatic-evaluation-retry.db'}")
    claimed = job(store)
    runtime = settings().model_copy(update={"worker_retry_max_seconds": 5})
    worker = Worker(
        runtime,
        store,
        EvaluationService(runtime, github, store),  # type: ignore[arg-type]
        claimed.lease_owner,
    )

    await worker._process(claimed)

    assert store.pending_count() == 1
    assert store.dead_count() == 0
    assert [check["status"] for check in github.checks] == ["completed"]
    with store.session() as session:
        row = session.get(EvaluationJob, claimed.id)
        assert row is not None
        row.available_at = utcnow()

    retry = store.claim(claimed.lease_owner, 60)
    assert retry is not None
    await worker._process(retry)

    assert "in_progress" in [check["status"] for check in github.checks[1:]]
    assert store.dead_count() == 0


@pytest.mark.asyncio
async def test_authority_failure_automatically_retries_until_prior_success_is_revoked(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.checks.append({"status": "completed", "conclusion": "success"})
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            GitHubError("temporary repository listing failure"),
            [{"full_name": "example/project", "archived": False}],
        ]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {
                "number": 3,
                "head": {"sha": HEAD},
                "base": {"ref": "main"},
            }
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'automatic-authority-retry.db'}")
    store.accept_delivery(
        "membership-removal",
        "membership",
        AuthorityRequest(2, None, None, "membership.removed"),
    )
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    runtime = settings().model_copy(update={"worker_retry_max_seconds": 5})
    worker = Worker(
        runtime,
        store,
        EvaluationService(runtime, github, store),  # type: ignore[arg-type]
        "worker",
    )

    await worker._process_authority(claimed)

    assert store.pending_count() == 1
    assert store.dead_count() == 0
    with store.session() as session:
        row = session.get(AuthorityJob, claimed.id)
        assert row is not None
        row.available_at = utcnow()

    broad_retry = store.claim_authority("worker", 60)
    assert broad_retry is not None
    await worker._process_authority(broad_retry)
    repository_retry = store.claim_authority("worker", 60)
    assert repository_retry is not None
    await worker._process_authority(repository_retry)

    assert "in_progress" in [check["status"] for check in github.checks[1:]]
    assert store.dead_count() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        AuthorityChangePendingError("authority pending"),
        GitHubError("evidence unavailable"),
    ],
)
async def test_worker_keeps_deferred_or_failed_evaluation_pending(
    tmp_path: Path, error: Exception
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'evaluation-retry.db'}")
    store.enqueue(JobRequest(2, "example/project", 3, "test"))
    claimed = store.claim("worker", 60)
    assert claimed is not None

    class Evaluator:
        async def evaluate_job(self, job: ClaimedJob) -> None:
            raise error

    runtime = settings().model_copy(update={"worker_retry_max_seconds": 5})
    worker = Worker(runtime, store, Evaluator(), "worker")  # type: ignore[arg-type]

    await worker._process(claimed)

    assert store.dead_count() == 0
    assert store.pending_count() == 1


@pytest.mark.asyncio
async def test_reconciler_enqueues_open_pull_requests(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"id": 2, "suspended_at": None}]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"full_name": "example/project", "archived": False}]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"number": 3, "head": {"sha": HEAD}}]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    queued = await reconciler.reconcile_once()

    assert queued == ReconciliationOutcome(queued=1)
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    assert store.shared_head_generation(2, "example/project", HEAD) == 1

    assert await reconciler.reconcile_once() == ReconciliationOutcome(queued=0)
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    assert store.shared_head_generation(2, "example/project", HEAD) == 1


@pytest.mark.asyncio
async def test_unelected_reconciler_does_not_report_an_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-election.db'}")
    assert store.acquire_service_lease("open-pr-reconciler", "elected", 300)
    github = FakeGitHub(changed_path="uv.lock")
    reconciler = Reconciler(settings(), github, store, "unelected")  # type: ignore[arg-type]
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration()

    attempts.labels.assert_not_called()
    last_success.set_to_current_time.assert_not_called()


@pytest.mark.asyncio
async def test_shutdown_before_election_does_not_report_an_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = asyncio.Event()
    stop.set()
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-stopped-before-election.db'}")
    acquire = MagicMock(wraps=store.acquire_service_lease)
    monkeypatch.setattr(store, "acquire_service_lease", acquire)
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock()  # type: ignore[attr-defined]
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration(stop)

    acquire.assert_not_called()
    github.list_installations.assert_not_awaited()  # type: ignore[attr-defined]
    attempts.labels.assert_not_called()
    last_success.set_to_current_time.assert_not_called()


@pytest.mark.asyncio
async def test_shutdown_winning_during_election_does_not_report_an_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = asyncio.Event()
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-stopped-during-election.db'}")
    event_loop = asyncio.get_running_loop()
    original_acquire = store.acquire_service_lease

    def acquire_then_stop(name: str, owner: str, lease_seconds: int) -> bool:
        stop_visible = threading.Event()

        def mark_stopped() -> None:
            stop.set()
            stop_visible.set()

        event_loop.call_soon_threadsafe(mark_stopped)
        assert stop_visible.wait(timeout=1)
        return original_acquire(name, owner, lease_seconds)

    acquire = MagicMock(side_effect=acquire_then_stop)
    monkeypatch.setattr(store, "acquire_service_lease", acquire)
    release = MagicMock(wraps=store.release_service_lease)
    monkeypatch.setattr(store, "release_service_lease", release)
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock()  # type: ignore[attr-defined]
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration(stop)

    acquire.assert_called_once()
    release.assert_called_once_with("open-pr-reconciler", "reconciler")
    assert original_acquire("open-pr-reconciler", "replacement", 300) is True
    github.list_installations.assert_not_awaited()  # type: ignore[attr-defined]
    attempts.labels.assert_not_called()
    last_success.set_to_current_time.assert_not_called()


@pytest.mark.asyncio
async def test_shutdown_lease_release_error_reports_election_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = asyncio.Event()
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-release-failure.db'}")
    event_loop = asyncio.get_running_loop()
    original_acquire = store.acquire_service_lease

    def acquire_then_stop(name: str, owner: str, lease_seconds: int) -> bool:
        stop_visible = threading.Event()

        def mark_stopped() -> None:
            stop.set()
            stop_visible.set()

        event_loop.call_soon_threadsafe(mark_stopped)
        assert stop_visible.wait(timeout=1)
        return original_acquire(name, owner, lease_seconds)

    monkeypatch.setattr(store, "acquire_service_lease", acquire_then_stop)
    monkeypatch.setattr(
        store,
        "release_service_lease",
        MagicMock(side_effect=RuntimeError("database unavailable")),
    )
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock()  # type: ignore[attr-defined]
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration(stop)

    attempts.labels.assert_called_once_with("failure")
    attempts.labels.return_value.inc.assert_called_once_with()
    last_success.set_to_current_time.assert_not_called()
    github.list_installations.assert_not_awaited()  # type: ignore[attr-defined]
    assert original_acquire("open-pr-reconciler", "replacement", 300) is False


@pytest.mark.asyncio
async def test_combined_reconciliation_event_wakes_for_either_source() -> None:
    first = asyncio.Event()
    second = asyncio.Event()

    async with service_module._combine_events(first, second) as combined:
        waiter = asyncio.create_task(combined.wait())
        second.set()
        await asyncio.wait_for(waiter, timeout=1)

        assert combined.is_set()


@pytest.mark.asyncio
async def test_lost_reconciliation_lease_reports_partial_without_success_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"id": 2, "suspended_at": None}]
    )
    lost = asyncio.Event()

    async def list_repositories_after_lease_loss(
        installation_id: int,
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        del installation_id, stop
        lost.set()
        return [{"full_name": "example/project", "archived": False}]

    github.list_installation_repositories = (  # type: ignore[attr-defined]
        list_repositories_after_lease_loss
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-lost-lease.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    outcome = await reconciler._reconcile_owned(lost)
    assert outcome == ReconciliationOutcome(queued=0, lease_lost=True)
    monkeypatch.setattr(
        reconciler,
        "reconcile_once",
        AsyncMock(return_value=outcome),
    )
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration()

    attempts.labels.assert_called_once_with("partial")
    attempts.labels.return_value.inc.assert_called_once_with()
    last_success.set_to_current_time.assert_not_called()


@pytest.mark.asyncio
async def test_stopped_reconciliation_reports_partial_without_success_timestamp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-stopped-metric.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    monkeypatch.setattr(
        reconciler,
        "reconcile_once",
        AsyncMock(return_value=ReconciliationOutcome(queued=1, stopped=True)),
    )
    attempts = MagicMock()
    last_success = MagicMock()
    logger = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)
    monkeypatch.setattr(service_module, "log", logger)

    await reconciler.run_iteration(asyncio.Event())

    attempts.labels.assert_called_once_with("partial")
    attempts.labels.return_value.inc.assert_called_once_with()
    last_success.set_to_current_time.assert_not_called()
    assert logger.warning.call_args.kwargs["stopped"] is True
    assert logger.warning.call_args.kwargs["lease_lost"] is False


@pytest.mark.asyncio
async def test_lease_loss_observed_after_scan_is_folded_into_iteration_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"id": 2, "suspended_at": None}]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"full_name": "example/project", "archived": False}]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"number": 3, "head": {"sha": HEAD}}]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-late-lease-loss.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    async def lose_lease_after_scan(
        done: asyncio.Event,
        lost: asyncio.Event,
        lease_seconds: int,
    ) -> None:
        del lease_seconds
        await done.wait()
        lost.set()

    monkeypatch.setattr(reconciler, "_renew_lease", lose_lease_after_scan)
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration()

    attempts.labels.assert_called_once_with("partial")
    attempts.labels.return_value.inc.assert_called_once_with()
    last_success.set_to_current_time.assert_not_called()
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1


@pytest.mark.asyncio
async def test_reconciliation_prunes_before_discovery_and_stops_after_lease_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lost = asyncio.Event()
    order: list[str] = []
    github = FakeGitHub(changed_path="uv.lock")

    async def list_installations_after_lease_loss(
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        del stop
        order.append("discover_installations")
        lost.set()
        return [{"id": 2, "suspended_at": None}]

    github.list_installations = list_installations_after_lease_loss  # type: ignore[attr-defined]
    github.list_installation_repositories = AsyncMock()  # type: ignore[attr-defined]
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-prune-order.db'}")
    original_delivery_prune = store.prune_deliveries
    original_shared_head_prune = store.prune_shared_head_epochs

    def record_delivery_prune(boundary: datetime) -> int:
        order.append("prune_deliveries")
        return original_delivery_prune(boundary)

    def record_shared_head_prune(boundary: datetime) -> int:
        order.append("prune_shared_head_epochs")
        return original_shared_head_prune(boundary)

    monkeypatch.setattr(store, "prune_deliveries", record_delivery_prune)
    monkeypatch.setattr(store, "prune_shared_head_epochs", record_shared_head_prune)
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    outcome = await reconciler._reconcile_owned(lost)

    assert outcome == ReconciliationOutcome(queued=0, lease_lost=True)
    assert order == [
        "prune_deliveries",
        "prune_shared_head_epochs",
        "discover_installations",
    ]
    github.list_installation_repositories.assert_not_awaited()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_reconciliation_stops_between_delivery_and_shared_head_pruning_after_lease_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lost = asyncio.Event()
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock()  # type: ignore[attr-defined]
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-prune-lease-loss.db'}")
    original_delivery_prune = store.prune_deliveries
    shared_head_prune = MagicMock(wraps=store.prune_shared_head_epochs)

    def prune_deliveries_then_lose_lease(boundary: datetime) -> int:
        result = original_delivery_prune(boundary)
        lost.set()
        return result

    monkeypatch.setattr(store, "prune_deliveries", prune_deliveries_then_lose_lease)
    monkeypatch.setattr(store, "prune_shared_head_epochs", shared_head_prune)
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    outcome = await reconciler._reconcile_owned(lost)

    assert outcome == ReconciliationOutcome(queued=0, lease_lost=True)
    shared_head_prune.assert_not_called()
    github.list_installations.assert_not_awaited()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_reconciliation_stop_after_installation_scan_prevents_repository_calls(
    tmp_path: Path,
) -> None:
    shutdown = asyncio.Event()
    github = FakeGitHub(changed_path="uv.lock")

    async def list_installations_then_stop(
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        assert stop is not None
        shutdown.set()
        return [{"id": 2, "suspended_at": None}]

    github.list_installations = list_installations_then_stop  # type: ignore[attr-defined]
    github.list_installation_repositories = AsyncMock()  # type: ignore[attr-defined]
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-stop-installations.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    outcome = await reconciler._reconcile_owned(asyncio.Event(), shutdown)

    assert outcome == ReconciliationOutcome(queued=0, stopped=True)
    github.list_installation_repositories.assert_not_awaited()  # type: ignore[attr-defined]
    assert store.pending_count() == 0


@pytest.mark.asyncio
async def test_reconciliation_stopped_error_is_never_reported_as_complete(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        side_effect=GitHubOperationStoppedError("custom client stopped")
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-stopped-error.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    outcome = await reconciler._reconcile_owned(asyncio.Event(), asyncio.Event())

    assert outcome == ReconciliationOutcome(queued=0, stopped=True)
    assert outcome.complete is False


@pytest.mark.asyncio
async def test_reconciler_task_exits_within_grace_after_stop_during_repository_scan(
    tmp_path: Path,
) -> None:
    shutdown = asyncio.Event()
    stop_signalled = asyncio.Event()
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"id": 2, "suspended_at": None}]
    )

    async def list_repositories_then_stop(
        installation_id: int,
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        del installation_id
        assert stop is not None
        shutdown.set()
        stop_signalled.set()
        return [{"full_name": "example/project", "archived": False}]

    github.list_installation_repositories = (  # type: ignore[attr-defined]
        list_repositories_then_stop
    )
    github.list_open_pulls = AsyncMock()  # type: ignore[attr-defined]
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-stop-repositories.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    task = asyncio.create_task(reconciler.run(shutdown))
    try:
        # Startup includes a synchronous lease operation in a worker thread.
        # Measure the shutdown grace period only after the scan signals stop.
        await asyncio.wait_for(stop_signalled.wait(), timeout=10)
        await asyncio.wait_for(task, timeout=1)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    github.list_open_pulls.assert_not_awaited()  # type: ignore[attr-defined]
    assert store.pending_count() == 0


@pytest.mark.asyncio
async def test_reconciliation_does_not_enqueue_pulls_returned_after_lease_loss(
    tmp_path: Path,
) -> None:
    lost = asyncio.Event()
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"id": 2, "suspended_at": None}]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"full_name": "example/project", "archived": False}]
    )

    async def list_pulls_after_lease_loss(
        installation_id: int,
        repository: str,
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        del installation_id, repository, stop
        lost.set()
        return [
            {"number": 1, "head": {"sha": HEAD}},
            {"number": 2, "head": {"sha": BASE}},
        ]

    github.list_open_pulls = list_pulls_after_lease_loss  # type: ignore[attr-defined]
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-pulls-after-loss.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    outcome = await reconciler._reconcile_owned(lost)

    assert outcome == ReconciliationOutcome(queued=0, lease_lost=True)
    assert store.pending_count() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "listing",
    ["list_installations", "list_installation_repositories", "list_open_pulls"],
)
async def test_lease_loss_stops_paginated_reconciliation_listing(
    tmp_path: Path,
    listing: str,
) -> None:
    lost = asyncio.Event()
    pages: list[int] = []
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"id": 2, "suspended_at": None}]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"full_name": "example/project", "archived": False}]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"number": 3, "head": {"sha": HEAD}}]
    )

    async def lose_lease_after_first_page(
        *args: Any,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        del args
        assert stop is not None
        pages.append(1)
        lost.set()
        assert stop.is_set()
        if not stop.is_set():  # pragma: no cover - documents the forbidden request
            pages.append(2)
        raise GitHubOperationStoppedError("stopped before page 2")

    setattr(github, listing, lose_lease_after_first_page)
    store = migrated_store(f"sqlite:///{tmp_path / f'reconcile-{listing}-pagination.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    outcome = await reconciler._reconcile_owned(lost)

    assert outcome == ReconciliationOutcome(queued=0, lease_lost=True)
    assert pages == [1]
    assert store.pending_count() == 0


@pytest.mark.asyncio
async def test_reconciliation_stops_pull_loop_when_lease_loss_becomes_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lost = asyncio.Event()
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"id": 2, "suspended_at": None}]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"full_name": "example/project", "archived": False}]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"number": 1, "head": {"sha": HEAD}},
            {"number": 2, "head": {"sha": BASE}},
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-pull-loop-loss.db'}")
    original_enqueue = store.enqueue_if_absent

    class EnqueueResult:
        def __init__(self, added: bool) -> None:
            self.added = added

        def __int__(self) -> int:
            lost.set()
            return int(self.added)

    enqueue = MagicMock(side_effect=lambda request: EnqueueResult(original_enqueue(request)))
    monkeypatch.setattr(store, "enqueue_if_absent", enqueue)
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    outcome = await reconciler._reconcile_owned(lost)

    assert outcome == ReconciliationOutcome(queued=1, lease_lost=True)
    assert enqueue.call_count == 1
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    claimed = store.claim("test-worker", 60)
    assert claimed is not None
    assert claimed.pull_number == 1


@pytest.mark.asyncio
async def test_reconciliation_exception_reports_failure_without_success_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-failure.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    monkeypatch.setattr(
        store,
        "acquire_service_lease",
        MagicMock(side_effect=RuntimeError("database unavailable")),
    )
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration()

    attempts.labels.assert_called_once_with("failure")
    attempts.labels.return_value.inc.assert_called_once_with()
    last_success.set_to_current_time.assert_not_called()


@pytest.mark.asyncio
async def test_partial_reconciliation_queues_healthy_installations_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"id": 2, "suspended_at": None},
            {"id": 3, "suspended_at": None},
        ]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            GitHubError("installation temporarily unavailable"),
            [{"full_name": "example/healthy", "archived": False}],
            [{"full_name": "example/recovered", "archived": False}],
            [{"full_name": "example/healthy", "archived": False}],
        ]
    )

    async def open_pulls(
        installation_id: int,
        repository: str,
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        del installation_id, stop
        number = 2 if repository == "example/recovered" else 3
        return [{"number": number, "head": {"sha": HEAD}}]

    github.list_open_pulls = open_pulls  # type: ignore[attr-defined]
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-partial.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration()

    attempts.labels.assert_called_once_with("partial")
    attempts.labels.return_value.inc.assert_called_once_with()
    last_success.set_to_current_time.assert_not_called()
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    first = store.claim("test-worker", 60)
    assert first is not None
    assert first.repository_full_name == "example/healthy"
    store.complete(first, first.lease_owner)

    attempts.reset_mock()
    last_success.reset_mock()
    await reconciler.run_iteration()

    attempts.labels.assert_called_once_with("success")
    attempts.labels.return_value.inc.assert_called_once_with()
    last_success.set_to_current_time.assert_called_once_with()
    assert store.pending_count() == 4
    assert store.pending_shared_head_invalidation_count() == 2
    repositories: set[str] = set()
    for _ in range(2):
        claimed = store.claim("test-worker", 60)
        assert claimed is not None
        repositories.add(claimed.repository_full_name)
        store.complete(claimed, claimed.lease_owner)
    assert repositories == {"example/healthy", "example/recovered"}


@pytest.mark.parametrize(
    ("validator", "payload", "reason"),
    [
        (
            service_module._reconciliation_installations,
            [
                {"id": 2, "suspended_at": None},
                {"id": 2, "suspended_at": None},
            ],
            "duplicate_installation_id",
        ),
        (
            service_module._reconciliation_repositories,
            [
                {"full_name": "example/project", "archived": False},
                {"full_name": "example/project", "archived": False},
            ],
            "duplicate_repository_full_name",
        ),
        (
            service_module._reconciliation_pulls,
            [
                {"number": 3, "head": {"sha": HEAD}},
                {"number": 3, "head": {"sha": BASE}},
            ],
            "duplicate_pull_number",
        ),
    ],
)
def test_reconciliation_rejects_duplicate_identities_in_collected_pages(
    validator: Any,
    payload: object,
    reason: str,
) -> None:
    with pytest.raises(ValueError, match=f"^{reason}$"):
        validator(payload)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("malformed", "secret", "is_batch"),
    [
        ("not-a-list", "not-a-list", True),
        ("not-an-object", "not-an-object", False),
        ({"id": True, "suspended_at": None}, "True", False),
        (
            {"id": "secret-installation-value", "suspended_at": None},
            "secret-installation-value",
            False,
        ),
        ({"id": None, "suspended_at": None}, "None", False),
        ({"id": 0, "suspended_at": None}, "0", False),
        ({"id": -1, "suspended_at": None}, "-1", False),
        ({"id": 2}, "{'id': 2}", False),
        ({"id": 2, "suspended_at": True}, "True", False),
        ({"id": 2, "suspended_at": "secret-timestamp"}, "secret-timestamp", False),
        (
            {"id": 2, "suspended_at": "2026-07-22T00:00:00"},
            "2026-07-22T00:00:00",
            False,
        ),
    ],
)
async def test_malformed_installation_batch_or_record_is_global_failure_without_salvage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed: object,
    secret: str,
    is_batch: bool,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=(
            malformed
            if is_batch
            else [
                {"id": 1, "suspended_at": None},
                malformed,
                {"id": 3, "suspended_at": None},
            ]
        )
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"full_name": "example/should-not-run", "archived": False}]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"number": 3, "head": {"sha": HEAD}}]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-invalid-payload.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    logger = MagicMock()
    monkeypatch.setattr(service_module, "log", logger)
    attempts = MagicMock()
    last_success = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", last_success)

    await reconciler.run_iteration()

    attempts.labels.assert_called_once_with("failure")
    attempts.labels.return_value.inc.assert_called_once_with()
    last_success.set_to_current_time.assert_not_called()
    github.list_installation_repositories.assert_not_awaited()  # type: ignore[attr-defined]
    github.list_open_pulls.assert_not_awaited()  # type: ignore[attr-defined]
    assert store.pending_count() == 0
    logger.exception.assert_called_once_with("reconciliation_failed")
    assert secret not in repr(logger.method_calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "malformed_repositories",
    [
        "not-a-list",
        ["secret-repository-record"],
        [{"full_name": None, "archived": False}],
        [{"full_name": "missing-slash", "archived": False}],
        [{"full_name": "secret\nowner/repository", "archived": False}],
        [{"full_name": "example/project"}],
        [{"full_name": "example/project", "archived": None}],
        [{"full_name": "example/project", "archived": 0}],
        [{"full_name": "example/project", "archived": 1}],
        [{"full_name": "example/project", "archived": "false"}],
    ],
)
async def test_malformed_repository_batch_is_partial_and_later_installations_continue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed_repositories: object,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"id": 2, "suspended_at": None},
            {"id": 3, "suspended_at": None},
        ]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            malformed_repositories,
            [{"full_name": "example/healthy", "archived": False}],
        ]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"number": 3, "head": {"sha": HEAD}}]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-invalid-repository.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    logger = MagicMock()
    monkeypatch.setattr(service_module, "log", logger)

    outcome = await reconciler.reconcile_once()

    assert outcome == ReconciliationOutcome(queued=1, failed_installations=1)
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    github.list_open_pulls.assert_awaited_once_with(  # type: ignore[attr-defined]
        3, "example/healthy", stop=ANY
    )
    assert logger.warning.call_count == 1
    warning = logger.warning.call_args
    assert warning.args == ("installation_reconciliation_payload_invalid",)
    assert warning.kwargs["installation_id"] == 2
    assert warning.kwargs["reason"].startswith("invalid_repository_")
    assert repr(malformed_repositories) not in repr(logger.warning.call_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("malformed_pulls", "reason"),
    [
        ("not-a-list", "invalid_pull_batch"),
        (["not-an-object"], "invalid_pull_record"),
    ],
)
async def test_malformed_pull_batch_is_partial_and_later_installations_continue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed_pulls: object,
    reason: str,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"id": 2, "suspended_at": None},
            {"id": 3, "suspended_at": None},
        ]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            [{"full_name": "example/malformed", "archived": False}],
            [{"full_name": "example/healthy", "archived": False}],
        ]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            malformed_pulls,
            [{"number": 3, "head": {"sha": HEAD}}],
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-invalid-pull-batch.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    logger = MagicMock()
    monkeypatch.setattr(service_module, "log", logger)

    outcome = await reconciler.reconcile_once()

    assert outcome == ReconciliationOutcome(queued=1, failed_installations=1)
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    logger.warning.assert_called_once_with(
        "installation_reconciliation_payload_invalid",
        installation_id=2,
        reason=reason,
    )
    assert repr(malformed_pulls) not in repr(logger.warning.call_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize("number", [True, "3", None, 0, -1])
async def test_malformed_pull_number_is_partial_and_later_installations_continue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    number: object,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"id": 2, "suspended_at": None},
            {"id": 3, "suspended_at": None},
        ]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            [{"full_name": "example/malformed", "archived": False}],
            [{"full_name": "example/healthy", "archived": False}],
        ]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            [{"number": number, "head": {"sha": HEAD}}],
            [{"number": 3, "head": {"sha": HEAD}}],
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-invalid-pull-number.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    logger = MagicMock()
    monkeypatch.setattr(service_module, "log", logger)

    outcome = await reconciler.reconcile_once()

    assert outcome == ReconciliationOutcome(queued=1, failed_installations=1)
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    logger.warning.assert_called_once_with(
        "installation_reconciliation_payload_invalid",
        installation_id=2,
        reason="invalid_pull_number",
    )
    assert repr(number) not in repr(logger.warning.call_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "head",
    [
        None,
        "not-an-object",
        {},
        {"sha": None},
        {"sha": "a" * 39},
        {"sha": "A" * 40},
    ],
)
async def test_malformed_pull_head_is_partial_and_later_installations_continue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    head: object,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"id": 2, "suspended_at": None},
            {"id": 3, "suspended_at": None},
        ]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            [{"full_name": "example/malformed", "archived": False}],
            [{"full_name": "example/healthy", "archived": False}],
        ]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        side_effect=[
            [{"number": 2, "head": head}],
            [{"number": 3, "head": {"sha": HEAD}}],
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-invalid-pull-head.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    logger = MagicMock()
    monkeypatch.setattr(service_module, "log", logger)

    outcome = await reconciler.reconcile_once()

    assert outcome == ReconciliationOutcome(queued=1, failed_installations=1)
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    logger.warning.assert_called_once_with(
        "installation_reconciliation_payload_invalid",
        installation_id=2,
        reason="invalid_pull_head",
    )
    assert repr(head) not in repr(logger.warning.call_args_list)


@pytest.mark.asyncio
async def test_reconciliation_intentionally_skips_suspended_installations_and_archives(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"id": 1, "suspended_at": "2026-07-22T00:00:00Z"},
            {"id": 2, "suspended_at": None},
        ]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"full_name": "example/archived", "archived": True},
            {"full_name": "example/healthy", "archived": False},
        ]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"number": 3, "head": {"sha": HEAD}}]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'reconcile-intentional-skips.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]

    outcome = await reconciler.reconcile_once()

    assert outcome == ReconciliationOutcome(queued=1)
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    github.list_installation_repositories.assert_awaited_once_with(  # type: ignore[attr-defined]
        2, stop=ANY
    )
    github.list_open_pulls.assert_awaited_once_with(  # type: ignore[attr-defined]
        2, "example/healthy", stop=ANY
    )


@pytest.mark.asyncio
async def test_reconciler_recovers_missed_shared_head_open_and_fails_closed(
    tmp_path: Path,
) -> None:
    github = FakeGitHub(changed_path="uv.lock")
    github.checks.append({"status": "completed", "conclusion": "success"})
    github.list_installations = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"id": 2, "suspended_at": None}]
    )
    github.list_installation_repositories = AsyncMock(  # type: ignore[attr-defined]
        return_value=[{"full_name": "example/project", "archived": False}]
    )
    github.list_open_pulls = AsyncMock(  # type: ignore[attr-defined]
        return_value=[
            {"number": 3, "head": {"sha": HEAD}},
            {"number": 4, "head": {"sha": HEAD}},
        ]
    )
    github.list_commit_pulls = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            {"number": 3, "state": "open", "head": {"sha": HEAD}},
            {"number": 4, "state": "open", "head": {"sha": HEAD}},
        ]
    )
    store = migrated_store(f"sqlite:///{tmp_path / 'missed-shared-head.db'}")
    reconciler = Reconciler(settings(), github, store, "reconciler")  # type: ignore[arg-type]
    service = EvaluationService(settings(), github, store)  # type: ignore[arg-type]

    assert await reconciler.reconcile_once() == ReconciliationOutcome(queued=2)
    assert store.pending_count() == 3
    assert store.pending_shared_head_invalidation_count() == 1
    invalidation = store.claim_shared_head_invalidation("head-worker", 60)
    assert invalidation is not None
    await service.invalidate_shared_head(invalidation, asyncio.Event())
    assert store.complete_shared_head_invalidation(invalidation)
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 0
    for _ in range(2):
        claimed = store.claim("worker", 60)
        assert claimed is not None
        await service.evaluate_job(claimed)
        store.complete(claimed, claimed.lease_owner)

    published = [check for check in github.checks[1:] if check.get("status") == "completed"]
    assert published
    assert all(check.get("conclusion") == "failure" for check in published)
    assert all("shared" in str(check.get("text")) for check in published)
    assert store.shared_head_generation(2, "example/project", HEAD) == 2
    assert store.pending_count() == 0


@pytest.mark.asyncio
async def test_evaluator_skips_organization_config_repository(tmp_path: Path) -> None:
    github = FakeGitHub(changed_path="README.md")
    store = migrated_store(f"sqlite:///{tmp_path / 'org-config.db'}")
    store.enqueue(
        JobRequest(
            installation_id=2,
            repository_full_name="example/.github",
            pull_number=3,
            reason="test",
        )
    )
    claimed = store.claim("worker", 60)
    assert claimed is not None

    await EvaluationService(settings(), github, store).evaluate_job(claimed)  # type: ignore[arg-type]

    assert github.checks == []
