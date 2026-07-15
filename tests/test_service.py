from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

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
from extra_codeowners.github import GitHubError, GitHubRateLimitError
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.models import OrganizationPolicy
from extra_codeowners.service import (
    AuthorityChangePendingError,
    EvaluationService,
    Reconciler,
    Worker,
)
from extra_codeowners.settings import Settings

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
    claimed = store.claim("test-worker", 60)
    assert claimed is not None
    return claimed


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

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert [check["status"] for check in github.checks] == ["in_progress"]
    assert store.pending_count() == 1


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

    await EvaluationService(settings(), github, store).evaluate_job(job(store))  # type: ignore[arg-type]

    assert [check["status"] for check in github.checks] == ["in_progress"]
    assert store.pending_count() == 1


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
    # The webhook path adds one post-PATCH generation to fence any worker
    # that completed immediately before revocation.
    store.enqueue(trigger)
    store.complete(claimed, claimed.lease_owner)

    statuses = [check["status"] for check in github.checks]
    assert statuses[:2] == ["in_progress", "completed"]
    assert statuses[-1] == "in_progress"
    assert set(statuses[2:]) == {"in_progress"}
    assert store.pending_count() == 1


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
    acceptance: asyncio.Task[bool] | None = None

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
    assert await acceptance is True
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

    assert store.pending_count() == 3
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

    assert queued == 1
    assert store.pending_count() == 1

    assert await reconciler.reconcile_once() == 0


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

    assert await reconciler.reconcile_once() == 2
    for _ in range(2):
        claimed = store.claim("worker", 60)
        assert claimed is not None
        await service.evaluate_job(claimed)
        store.complete(claimed, claimed.lease_owner)

    published = [check for check in github.checks[1:] if check.get("status") == "completed"]
    assert len(published) == 2
    assert all(check.get("conclusion") == "failure" for check in published)
    assert all("shared" in str(check.get("text")) for check in published)
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
