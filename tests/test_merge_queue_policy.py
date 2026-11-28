"""Candidate assessments use the reviewed PR head and current target policy."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import replace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from extra_codeowners.database import QueueStore
from extra_codeowners.github import GitHubClient, GitHubError
from extra_codeowners.merge_queue import (
    MergeCandidateIdentity,
    MergeGroupTrigger,
    MergeQueueEvidenceError,
)
from extra_codeowners.merge_queue_paths import CandidateChangedPaths
from extra_codeowners.models import EvaluationConclusion
from extra_codeowners.service import EvaluationService
from extra_codeowners.settings import Settings

BASE = "a" * 40
CANDIDATE = "b" * 40
PULL_HEAD = "c" * 40
EARLIER = "d" * 40
REPO = "fictional-org/queue-lab"
NEW_PATH = "owned/new.txt"
OLD_PATH = "history/old.txt"
IDENTITY = MergeCandidateIdentity(
    MergeGroupTrigger(
        "checks_requested",
        10,
        20,
        REPO,
        "refs/heads/main",
        BASE,
        "refs/heads/gh-readonly-queue/main/pr-3-example",
        CANDIDATE,
    ),
    "R_sample",
    "MQ_sample",
    "MQE_sample",
    "PR_sample",
    3,
    PULL_HEAD,
)


def pull() -> dict[str, Any]:
    return {
        "number": 3,
        "node_id": IDENTITY.pull_id,
        "state": "open",
        "draft": False,
        "merged": False,
        "labels": [],
        "changed_files": 1,
        "user": {"id": 21, "login": "contributor", "type": "User"},
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"id": 20, "node_id": "R_sample", "full_name": REPO},
        },
        "head": {"sha": PULL_HEAD},
    }


def review(login: str, review_id: int, commit: str, *, state: str = "APPROVED") -> dict[str, Any]:
    return {
        "id": review_id,
        "commit_id": commit,
        "state": state,
        "submitted_at": f"2025-01-01T00:00:0{review_id}Z",
        "user": {"id": 33 if login == "first-owner" else 34, "login": login, "type": "User"},
    }


@pytest.fixture
def assessment_stack() -> tuple[EvaluationService, Mock, Mock]:
    settings = Settings()
    github = Mock(spec=GitHubClient)
    store = Mock(spec=QueueStore)
    github.get_merge_candidate = AsyncMock(return_value=IDENTITY)
    github.get_pull = AsyncMock(return_value=pull())
    github.get_candidate_changed_paths = AsyncMock(
        return_value=CandidateChangedPaths(BASE, CANDIDATE, frozenset({NEW_PATH, OLD_PATH}))
    )
    github.get_pull_files = AsyncMock(
        return_value=[{"status": "renamed", "filename": NEW_PATH, "previous_filename": OLD_PATH}]
    )
    github.get_reviews = AsyncMock(
        return_value=[review("first-owner", 1, PULL_HEAD), review("second-owner", 2, PULL_HEAD)]
    )
    github.get_codeowners_errors = AsyncMock(return_value=[])
    github.user_can_own_repository = AsyncMock(return_value=True)
    github.installation_includes_repository = AsyncMock(return_value=True)

    async def file_text(
        installation_id: int,
        repository: str,
        path: str,
        *,
        ref: str | None = None,
        max_bytes: int | None = None,
    ) -> str | None:
        assert installation_id == 10
        if repository == "fictional-org/.github":
            return None
        assert repository == REPO
        # Verifies XCO-014: both repo policy and CODEOWNERS come from the
        # candidate's verified target, not from its head or the PR head.
        assert ref == BASE
        if path == ".github/CODEOWNERS":
            assert max_bytes is not None
        return {
            settings.policy_path: "schema_version = 1\nenabled = true",
            ".github/CODEOWNERS": "/owned/ @first-owner\n/history/ @second-owner\n",
        }.get(path)

    github.get_regular_file_text = AsyncMock(side_effect=file_text)
    return EvaluationService(settings, github, store), github, store


@pytest.mark.asyncio
async def test_candidate_uses_existing_policy_and_does_not_publish(
    assessment_stack: tuple[EvaluationService, Mock, Mock],
) -> None:
    service, github, store = assessment_stack
    assessment = await service.assess_merge_candidate(IDENTITY, authority_generation=8)
    assert assessment.identity == IDENTITY
    assert assessment.result.conclusion is EvaluationConclusion.SUCCESS
    github.get_candidate_changed_paths.assert_awaited_once_with(
        10, REPO, target_ref=IDENTITY.trigger.base_ref, target_sha=BASE, candidate_sha=CANDIDATE
    )
    github.get_codeowners_errors.assert_awaited_once_with(10, REPO, BASE)
    github.get_merge_candidate.assert_awaited_once_with(IDENTITY.trigger)
    assert github.get_pull.await_count == 2
    github.upsert_check_run.assert_not_called()
    assert store.mock_calls == []


@pytest.mark.asyncio
async def test_later_queue_entry_uses_live_candidate_base_not_recorded_pr_base(
    assessment_stack: tuple[EvaluationService, Mock, Mock],
) -> None:
    service, github, _ = assessment_stack
    queued_pull = pull()
    queued_pull["base"]["sha"] = EARLIER
    github.get_pull.return_value = queued_pull
    assessment = await service.assess_merge_candidate(IDENTITY, authority_generation=8)
    assert assessment.result.conclusion is EvaluationConclusion.SUCCESS
    github.get_candidate_changed_paths.assert_awaited_once_with(
        10, REPO, target_ref=IDENTITY.trigger.base_ref, target_sha=BASE, candidate_sha=CANDIDATE
    )
    github.get_codeowners_errors.assert_awaited_once_with(10, REPO, BASE)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_commit", [EARLIER, CANDIDATE])
async def test_candidate_refuses_a_review_for_any_other_commit(
    assessment_stack: tuple[EvaluationService, Mock, Mock], bad_commit: str
) -> None:
    # Verifies XCO-002 and XCO-006: the old name's owner must also approve the PR head.
    service, github, _ = assessment_stack
    github.get_reviews.return_value = [
        review("first-owner", 1, PULL_HEAD),
        review("second-owner", 2, bad_commit),
    ]
    result = await service.assess_merge_candidate(IDENTITY, authority_generation=8)
    assert result.result.conclusion is EvaluationConclusion.FAILURE


@pytest.mark.asyncio
async def test_candidate_fails_on_a_dismissed_approval(
    assessment_stack: tuple[EvaluationService, Mock, Mock],
) -> None:
    service, github, _ = assessment_stack
    github.get_reviews.return_value.append(review("second-owner", 3, PULL_HEAD, state="DISMISSED"))
    result = await service.assess_merge_candidate(IDENTITY, authority_generation=8)
    assert result.result.conclusion is EvaluationConclusion.FAILURE


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_paths", [frozenset({"extra.txt", NEW_PATH}), frozenset({OLD_PATH})])
async def test_unreviewed_relative_paths_deny_candidate(
    assessment_stack: tuple[EvaluationService, Mock, Mock], bad_paths: frozenset[str]
) -> None:
    # Verifies XCO-001. In the second case, an "unchanged" record doesn't
    # substantiate a candidate change, even though it names the right file.
    service, github, _ = assessment_stack
    github.get_candidate_changed_paths.return_value = CandidateChangedPaths(
        BASE, CANDIDATE, bad_paths
    )
    if bad_paths == {OLD_PATH}:
        github.get_pull_files.return_value = [{"status": "unchanged", "filename": OLD_PATH}]
    result = await service.assess_merge_candidate(IDENTITY, authority_generation=8)
    assert result.result.conclusion is EvaluationConclusion.FAILURE
    assert result.result.errors[0].code == "candidate_paths_not_covered"


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", ["entry", "labels", "head", "route", "base_branch"])
async def test_mid_assessment_changes_discard_result(
    assessment_stack: tuple[EvaluationService, Mock, Mock], changes: str
) -> None:
    # Verifies XCO-001. The comparison covers the identity, not only the ref name.
    service, github, _ = assessment_stack
    first = pull()
    second = deepcopy(first)
    if changes == "entry":
        github.get_merge_candidate.return_value = replace(IDENTITY, entry_id="MQE_other")
    elif changes == "labels":
        second["labels"] = [{"name": "explicit-approval"}]
    elif changes == "head":
        second["head"]["sha"] = EARLIER
    elif changes == "route":
        second["base"]["repo"]["id"] = 99
    else:
        second["base"]["ref"] = "other-branch"
    github.get_pull.side_effect = [first, second]
    with pytest.raises(
        (GitHubError, MergeQueueEvidenceError), match=r"changed|current queue entry"
    ):
        await service.assess_merge_candidate(IDENTITY, authority_generation=8)


@pytest.mark.asyncio
async def test_candidate_path_response_is_bound_to_both_commits(
    assessment_stack: tuple[EvaluationService, Mock, Mock],
) -> None:
    # Verifies XCO-007. Coverage from a different commit can't authorize this candidate.
    service, github, _ = assessment_stack
    github.get_candidate_changed_paths.return_value = CandidateChangedPaths(
        BASE, EARLIER, frozenset({NEW_PATH, OLD_PATH})
    )
    with pytest.raises(GitHubError, match="different merge candidate"):
        await service.assess_merge_candidate(IDENTITY, authority_generation=8)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "conclusion"),
    [("allow-app", EvaluationConclusion.SUCCESS), (None, EvaluationConclusion.FAILURE)],
)
async def test_current_app_review_still_needs_the_delegation_label(
    assessment_stack: tuple[EvaluationService, Mock, Mock],
    label: str | None,
    conclusion: EvaluationConclusion,
) -> None:
    # Verifies XCO-003 and XCO-004. Enrollment comes from org policy; its
    # approval and the destination path's repo delegation are both necessary.
    service, github, _ = assessment_stack
    original: Callable[..., Awaitable[str | None]] = github.get_regular_file_text.side_effect

    async def file_text(
        installation_id: int,
        repository: str,
        path: str,
        *,
        ref: str | None = None,
        max_bytes: int | None = None,
    ) -> str | None:
        if path == service.settings.policy_path:
            if repository == "fictional-org/.github":
                return """
schema_version = 1
[apps.routine]
slug = "routine"
app_id = 101
bot_user_id = 102
"""
            assert repository == REPO and ref == BASE
            return """
schema_version = 1
enabled = true
[[delegations]]
app = "routine"
paths = ["owned/**"]
for_owners = ["@first-owner"]
required_labels = ["allow-app"]
"""
        return await original(installation_id, repository, path, ref=ref, max_bytes=max_bytes)

    bot = {"id": 102, "login": "routine[bot]", "type": "Bot"}
    github.get_regular_file_text.side_effect = file_text
    github.get_user = AsyncMock(return_value=bot)
    github.get_reviews.return_value = [
        {**review("first-owner", 1, PULL_HEAD), "user": bot},
        review("second-owner", 2, PULL_HEAD),
    ]
    github.get_pull.return_value["labels"] = [] if label is None else [{"name": label}]
    result = await service.assess_merge_candidate(IDENTITY, authority_generation=8)
    assert result.result.conclusion is conclusion


@pytest.mark.asyncio
async def test_disabled_policy_denies_candidate_even_if_path_evidence_is_unavailable(
    assessment_stack: tuple[EvaluationService, Mock, Mock],
) -> None:
    service, github, _ = assessment_stack
    github.get_regular_file_text.side_effect = None
    github.get_regular_file_text.return_value = None
    result = await service.assess_merge_candidate(IDENTITY, authority_generation=8)
    assert result.result.conclusion is EvaluationConclusion.FAILURE
    assert result.result.errors[0].code == "repository_policy_disabled"
    github.get_candidate_changed_paths.assert_not_called()
