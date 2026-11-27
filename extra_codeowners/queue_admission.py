"""Identify the PR test merge used for admission, never the final candidate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from extra_codeowners.merge_queue_paths import MergeTreeEvidenceError, require_object_id


@dataclass(frozen=True, slots=True)
class QueueAdmissionTarget:
    """A two-parent test merge for the evaluated branch and PR head."""

    pull_number: int
    repository_id: int
    base_ref: str
    base_sha: str
    pull_head_sha: str
    test_merge_sha: str

    @property
    def external_id(self) -> str:
        return (
            f"extra-codeowners:queue-admission:{self.repository_id}:{self.pull_number}"
            f":{self.base_sha}:{self.pull_head_sha}"
        )


def bind_admission_target(
    pull: dict[str, Any],
    *,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_ref: str,
    base_sha: str,
    pull_head_sha: str,
    merge_ref_sha: str | None,
) -> QueueAdmissionTarget | None:
    """Bind a fresh, mergeable PR snapshot to the policy evidence already read."""
    if pull.get("draft") is True or pull.get("mergeable") is False:
        return None
    base, head = pull.get("base"), pull.get("head")
    repo = base.get("repo") if isinstance(base, dict) else None
    route = repo.get("full_name") if isinstance(repo, dict) else None
    if (
        pull.get("state") != "open"
        or pull.get("merged") is not False
        or pull.get("draft") is not False
        or type(pull.get("number")) is not int
        or pull["number"] != pull_number
        or not isinstance(base, dict)
        or base.get("ref") != base_ref
        or base.get("sha") != base_sha
        or not isinstance(head, dict)
        or head.get("sha") != pull_head_sha
        or not isinstance(repo, dict)
        or type(repo.get("id")) is not int
        or repo["id"] != repository_id
        or not isinstance(route, str)
        or route.lower() != repository.lower()
    ):
        raise MergeTreeEvidenceError("PR test merge does not match the evaluated PR and branch")
    if pull.get("mergeable") is not True:
        raise MergeTreeEvidenceError("GitHub has not finished computing the PR test merge")
    merge_sha = require_object_id(merge_ref_sha)
    # The installation may not see merge_commit_sha. When GitHub supplies
    # both forms, they must agree with the named Git ref.
    reported_merge_sha = pull.get("merge_commit_sha")
    if reported_merge_sha is not None and reported_merge_sha != merge_sha:
        raise MergeTreeEvidenceError("PR merge SHA does not match its test-merge Git ref")
    if merge_sha in {base_sha, pull_head_sha} or base_sha == pull_head_sha:
        raise MergeTreeEvidenceError("PR test merge must be distinct from both parents")
    return QueueAdmissionTarget(
        pull_number, repository_id, base_ref, base_sha, pull_head_sha, merge_sha
    )
