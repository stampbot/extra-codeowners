"""The experiment checks candidate identity and ownership coverage."""

from __future__ import annotations

from typing import Any

import pytest

from tools.merge_queue_candidate import (
    CandidateEvidenceError,
    ChangedPaths,
    identify_candidate,
    verify_candidate_paths,
)

BASE, REVIEWED, CANDIDATE = (digit * 40 for digit in "abc")
BASE_REF = "refs/heads/main"
# The ref text looks like a different PR; its encoded number is not evidence.
QUEUE_REF = "refs/heads/gh-readonly-queue/main/pr-999-fixture"


@pytest.fixture
def evidence() -> dict[str, Any]:
    pull = {"id": "fixture-pull", "number": 17, "state": "OPEN", "headRefOid": REVIEWED}
    entry = {
        "id": "fixture-entry",
        "state": "AWAITING_CHECKS",
        "position": 1,
        "baseCommit": {"oid": BASE},
        "headCommit": {"oid": CANDIDATE},
        "pullRequest": pull.copy(),
    }
    return {
        "installation_id": 2,
        "repository": {"id": 3, "node_id": "fixture-repository"},
        "delivery": {
            "action": "checks_requested",
            "installation": {"id": 2},
            "repository": {"id": 3},
            "merge_group": {
                "base_ref": BASE_REF,
                "base_sha": BASE,
                "head_ref": QUEUE_REF,
                "head_sha": CANDIDATE,
            },
        },
        "graph": {
            "id": "fixture-repository",
            "ref": {"prefix": "refs/heads/", "name": "main", "target": {"oid": BASE}},
            "pullRequest": {**pull, "baseRefName": "main", "baseRefOid": BASE},
            "mergeQueue": {
                "entries": {"totalCount": 1, "nodes": [entry], "pageInfo": {"hasNextPage": False}}
            },
        },
        "candidate_ref": {"ref": QUEUE_REF, "object": {"sha": CANDIDATE, "type": "commit"}},
    }


def test_binds_the_queued_pr_without_using_the_ref_name(evidence: dict[str, Any]) -> None:
    binding = identify_candidate(**evidence)
    assert binding.pull_number == 17
    assert binding.reviewed_head == REVIEWED
    assert binding.candidate_sha == CANDIDATE
    assert binding.candidate_ref == QUEUE_REF
    assert binding.entry_id == "fixture-entry"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("installation_id", True),
        ("delivery.action", "destroyed"),
        ("delivery.installation.id", 5),
        ("delivery.repository.id", 5),
        ("delivery.merge_group.base_ref", "refs/heads/different"),
        ("delivery.merge_group.head_sha", "e" * 40),
        ("delivery.merge_group.head_sha", "not-a-commit"),
        ("graph.id", "other-repository"),
        ("graph.ref.target.oid", "e" * 40),
        ("graph.ref.name", "another-branch"),
        ("graph.pullRequest.state", "CLOSED"),
        ("graph.pullRequest.baseRefOid", "e" * 40),
        ("graph.pullRequest.headRefOid", "e" * 40),
        ("graph.mergeQueue.entries.totalCount", 2),
        ("graph.mergeQueue.entries.totalCount", True),
        ("graph.mergeQueue.entries.pageInfo.hasNextPage", True),
        ("graph.mergeQueue.entries.pageInfo.hasNextPage", None),
        ("graph.mergeQueue.entries.nodes", []),
        ("graph.mergeQueue.entries.nodes.0.id", None),
        ("graph.mergeQueue.entries.nodes.0.state", "QUEUED"),
        ("graph.mergeQueue.entries.nodes.0.baseCommit", None),
        ("graph.mergeQueue.entries.nodes.0.headCommit", None),
        ("graph.mergeQueue.entries.nodes.0.pullRequest.id", "a-different-pr"),
        ("candidate_ref.object.sha", "e" * 40),
        ("candidate_ref.object.type", "blob"),
    ],
)
def test_rejects_stale_incomplete_or_contradictory_evidence(
    evidence: dict[str, Any], path: str, value: object
) -> None:
    # Partial XCO-001/XCO-007 evidence: no publishing path is exercised here.
    *parents, leaf = path.split(".")
    target: Any = evidence
    for part in parents:
        target = target[int(part) if part.isdigit() else part]
    target[leaf] = value
    with pytest.raises(CandidateEvidenceError):
        identify_candidate(**evidence)


def test_candidate_can_touch_a_subset_of_the_evaluated_paths(evidence: dict[str, Any]) -> None:
    binding = identify_candidate(**evidence)
    verify_candidate_paths(
        binding,
        reviewed=ChangedPaths(BASE, REVIEWED, frozenset({"one.txt", "two.txt"})),
        candidate=ChangedPaths(BASE, CANDIDATE, frozenset({"one.txt"})),
    )


@pytest.mark.parametrize(
    ("target", "head", "paths"),
    [
        ("d" * 40, CANDIDATE, {"old.txt", "new.txt"}),
        (BASE, REVIEWED, {"old.txt", "new.txt"}),
        (BASE, CANDIDATE, {"old.txt", "new.txt", ".github/CODEOWNERS"}),
    ],
)
def test_candidate_paths_must_be_covered_and_bound(
    evidence: dict[str, Any], target: str, head: str, paths: set[str]
) -> None:
    # Verifies XCO-001 for path coverage and commit binding.
    with pytest.raises(CandidateEvidenceError):
        verify_candidate_paths(
            identify_candidate(**evidence),
            reviewed=ChangedPaths(BASE, REVIEWED, frozenset({"old.txt", "new.txt"})),
            candidate=ChangedPaths(target, head, frozenset(paths)),
        )


def test_candidate_rename_source_needs_coverage(evidence: dict[str, Any]) -> None:
    # Verifies XCO-006 when the candidate also removes the old pathname.
    with pytest.raises(CandidateEvidenceError, match="not covered"):
        verify_candidate_paths(
            identify_candidate(**evidence),
            reviewed=ChangedPaths(BASE, REVIEWED, frozenset({"new.txt"})),
            candidate=ChangedPaths(BASE, CANDIDATE, frozenset({"old.txt", "new.txt"})),
        )
