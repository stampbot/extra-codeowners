"""The experiment proves identity and tree equivalence, not authorization."""

from __future__ import annotations

from typing import Any

import pytest

from tools.merge_queue_candidate import CandidateEvidenceError, bind_candidate

BASE, REVIEWED, CANDIDATE, TREE = (digit * 40 for digit in "abcd")
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
        "candidate_commit": {"sha": CANDIDATE, "tree": {"sha": TREE}, "parents": [{"sha": BASE}]},
        "reviewed_commit": {"sha": REVIEWED, "tree": {"sha": TREE}, "parents": [{"sha": BASE}]},
    }


def test_binds_the_queued_pr_without_using_the_ref_name(evidence: dict[str, Any]) -> None:
    binding = bind_candidate(**evidence)
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
        ("candidate_commit.tree.sha", "e" * 40),
        ("candidate_commit.parents", [{"sha": BASE}, {"sha": REVIEWED}]),
        ("reviewed_commit.parents", []),
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
        bind_candidate(**evidence)
