"""Review evidence must name a distinct, verified GitHub PR test-merge commit."""

from typing import Any
from unittest.mock import AsyncMock

import pytest

from extra_codeowners.github import GitHubClient, GitHubError
from extra_codeowners.merge_queue import MERGE_CANDIDATE_CHECK_NAME
from extra_codeowners.merge_queue_paths import MergeTreeEvidenceError
from extra_codeowners.queue_admission import QueueAdmissionTarget, bind_admission_target

REPO = "example/project"
TARGET = QueueAdmissionTarget(42, 33, "main", "a" * 40, "b" * 40, "c" * 40)


def _pull() -> dict[str, Any]:
    return {
        "number": TARGET.pull_number,
        "state": "open",
        "draft": False,
        "merged": False,
        "mergeable": True,
        "merge_commit_sha": TARGET.test_merge_sha,
        "base": {
            "ref": TARGET.base_ref,
            "sha": TARGET.base_sha,
            "repo": {"id": TARGET.repository_id, "full_name": REPO},
        },
        "head": {"sha": TARGET.pull_head_sha},
    }


def _bind(
    pull: dict[str, Any], merge_ref_sha: str = TARGET.test_merge_sha
) -> QueueAdmissionTarget | None:
    return bind_admission_target(
        pull,
        repository=REPO,
        repository_id=TARGET.repository_id,
        pull_number=TARGET.pull_number,
        base_ref=TARGET.base_ref,
        base_sha=TARGET.base_sha,
        pull_head_sha=TARGET.pull_head_sha,
        merge_ref_sha=merge_ref_sha,
    )


def test_admission_target_is_not_the_reviewed_head() -> None:
    assert _bind(_pull()) == TARGET
    assert _bind(_pull() | {"merge_commit_sha": None}) == TARGET
    with pytest.raises(MergeTreeEvidenceError, match="distinct"):
        _bind(_pull() | {"merge_commit_sha": None}, TARGET.pull_head_sha)
    with pytest.raises(MergeTreeEvidenceError, match="does not match"):
        _bind(_pull() | {"merge_commit_sha": TARGET.pull_head_sha})


def test_admission_continues_to_parent_proof_with_a_stale_reported_base() -> None:
    pull = _pull()
    pull["base"]["sha"] = "f" * 40
    assert _bind(pull) == TARGET


@pytest.mark.parametrize("change", [{"draft": True}, {"mergeable": False}])
def test_ineligible_pr_has_no_admission_target(change: dict[str, Any]) -> None:
    assert _bind(_pull() | change) is None


@pytest.mark.parametrize("change", [{"mergeable": None}, {"number": 7}, {"state": "closed"}])
def test_admission_refuses_incomplete_or_mismatched_pr_evidence(change: dict[str, Any]) -> None:
    with pytest.raises(MergeTreeEvidenceError):
        _bind(_pull() | change)


def _rules(app_id: int) -> list[dict[str, Any]]:
    return [
        {
            "type": "merge_queue",
            "parameters": {
                "grouping_strategy": "ALLGREEN",
                "merge_method": "SQUASH",
                "max_entries_to_build": 1,
                "min_entries_to_merge": 1,
                "max_entries_to_merge": 1,
            },
        },
        {
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [
                    {"integration_id": app_id, "context": MERGE_CANDIDATE_CHECK_NAME}
                ],
            },
        },
    ]


@pytest.mark.asyncio
async def test_admission_proof_checks_exact_app_rule_and_ordered_commit_parents(
    private_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = GitHubClient(7, private_key)
    rules = AsyncMock(return_value=_rules(7))
    commit = AsyncMock(
        return_value={
            "sha": TARGET.test_merge_sha,
            "parents": [{"sha": TARGET.base_sha}, {"sha": TARGET.pull_head_sha}],
        }
    )
    monkeypatch.setattr(client, "_read_queue_branch_rules", rules)
    monkeypatch.setattr(client, "_get_bounded_json", commit)
    try:
        assert await client.prove_queue_admission(3, REPO, TARGET)
        commit.return_value["parents"][0]["sha"] = "f" * 40
        with pytest.raises(GitHubError, match="expected parents"):
            await client.prove_queue_admission(3, REPO, TARGET)
        commit.return_value["parents"][0]["sha"] = TARGET.base_sha
        commit.return_value["parents"].reverse()
        with pytest.raises(GitHubError, match="expected parents"):
            await client.prove_queue_admission(3, REPO, TARGET)
        commit.reset_mock()
        rules.return_value = _rules(8)
        with pytest.raises(GitHubError, match="not pinned"):
            await client.prove_queue_admission(3, REPO, TARGET)
        commit.assert_not_awaited()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_admission_writer_will_not_replace_another_role(
    private_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = GitHubClient(7, private_key)
    read = AsyncMock(
        return_value={
            "total_count": 1,
            "check_runs": [
                {
                    "id": 305,
                    "app": {"id": 7},
                    "name": MERGE_CANDIDATE_CHECK_NAME,
                    "head_sha": TARGET.test_merge_sha,
                    "external_id": "another-role",
                }
            ],
        }
    )
    monkeypatch.setattr(client, "_request", read)
    try:
        with pytest.raises(GitHubError, match="does not identify"):
            await client.write_queue_admission_check(3, REPO, TARGET, approved=True, summary="OK")
        assert read.await_count == 1
        assert read.await_args is not None
        assert read.await_args.args == (
            "GET",
            f"/repos/{REPO}/commits/{TARGET.test_merge_sha}/check-runs",
        )
    finally:
        await client.close()
