"""Read-only evidence checks for a single-entry merge-queue experiment.

The caller authenticates the App and obtains all snapshots from GitHub.
This tool neither evaluates policy nor publishes a Check Run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_OID = re.compile(r"[0-9a-f]{40}\Z")


class CandidateEvidenceError(ValueError):
    """The snapshots don't prove the identity and contents of one candidate."""


@dataclass(frozen=True, slots=True)
class CandidateIdentity:
    installation_id: int
    repository_id: int
    entry_id: str
    pull_id: str
    pull_number: int
    base_ref: str
    base_sha: str
    reviewed_head: str
    candidate_ref: str
    candidate_sha: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateEvidenceError(message)


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateEvidenceError("required candidate evidence object is missing")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise CandidateEvidenceError("required candidate evidence text is missing")
    return value


def _positive_id(value: object) -> int:
    if type(value) is not int or value < 1:
        raise CandidateEvidenceError("required candidate evidence ID is invalid")
    return value


def _oid(value: object) -> str:
    if not isinstance(value, str) or _OID.fullmatch(value) is None:
        raise CandidateEvidenceError("required candidate evidence commit or tree is invalid")
    return value


def _one_entry(queue: dict[str, Any]) -> dict[str, Any]:
    entries = _object(queue.get("entries"))
    nodes = entries.get("nodes")
    if (
        _positive_id(entries.get("totalCount")) != 1
        or _object(entries.get("pageInfo")).get("hasNextPage") is not False
        or not isinstance(nodes, list)
        or len(nodes) != 1
    ):
        raise CandidateEvidenceError("queue does not establish exactly one entry")
    return _object(nodes[0])


def _tree_at_base(commit: dict[str, Any], sha: str, base: str) -> str:
    parents = commit.get("parents")
    _require(
        commit.get("sha") == sha
        and isinstance(parents, list)
        and len(parents) == 1
        and _object(parents[0]).get("sha") == base,
        "commit is not the expected single child of the base",
    )
    return _oid(_object(commit.get("tree")).get("sha"))


def bind_candidate(
    *,
    delivery: dict[str, Any],
    installation_id: int,
    repository: dict[str, Any],
    graph: dict[str, Any],
    candidate_ref: dict[str, Any],
    candidate_commit: dict[str, Any],
    reviewed_commit: dict[str, Any],
) -> CandidateIdentity:
    """Bind separately fetched GitHub snapshots; never infer a PR from its ref name."""
    install_id, repo_id = _positive_id(installation_id), _positive_id(repository.get("id"))
    _require(
        delivery.get("action") == "checks_requested"
        and _positive_id(_object(delivery.get("installation")).get("id")) == install_id
        and _positive_id(_object(delivery.get("repository")).get("id")) == repo_id
        and graph.get("id") == _text(repository.get("node_id")),
        "delivery and queue aren't for the authenticated installation and repository",
    )
    group = _object(delivery.get("merge_group"))
    base_sha, sha = _oid(group.get("base_sha")), _oid(group.get("head_sha"))
    base_ref, ref_name = _text(group.get("base_ref")), _text(group.get("head_ref"))
    _require(
        base_ref.startswith("refs/heads/")
        and ref_name.startswith("refs/heads/gh-readonly-queue/")
        and base_ref != ref_name,
        "unexpected base or queue ref",
    )
    base = _object(graph.get("ref"))
    _require(
        base.get("prefix") == "refs/heads/"
        and base.get("name") == base_ref.removeprefix("refs/heads/")
        and _object(base.get("target")).get("oid") == base_sha,
        "base no longer matches the target tip",
    )
    entry = _one_entry(_object(graph.get("mergeQueue")))
    _require(
        entry.get("state") == "AWAITING_CHECKS"
        and _positive_id(entry.get("position")) == 1
        and _object(entry.get("baseCommit")).get("oid") == base_sha
        and _object(entry.get("headCommit")).get("oid") == sha,
        "queue entry does not match the pending candidate",
    )
    pull, linked = _object(graph.get("pullRequest")), _object(entry.get("pullRequest"))
    head = _oid(pull.get("headRefOid"))
    pull_id, pull_number = _text(pull.get("id")), _positive_id(pull.get("number"))
    _require(
        linked.get("id") == pull_id
        and _positive_id(linked.get("number")) == pull_number
        and linked.get("state") == pull.get("state") == "OPEN"
        and linked.get("headRefOid") == head
        and pull.get("baseRefName") == base_ref.removeprefix("refs/heads/")
        and pull.get("baseRefOid") == base_sha
        and sha != head,
        "queue entry does not identify the open PR and its current head",
    )
    target = _object(candidate_ref.get("object"))
    _require(
        candidate_ref.get("ref") == ref_name
        and target.get("type") == "commit"
        and target.get("sha") == sha,
        "queue ref no longer points to the expected candidate",
    )
    _require(
        _tree_at_base(candidate_commit, sha, base_sha)
        == _tree_at_base(reviewed_commit, head, base_sha),
        "candidate tree differs from the PR head",
    )
    return CandidateIdentity(
        install_id,
        repo_id,
        _text(entry.get("id")),
        pull_id,
        pull_number,
        base_ref,
        base_sha,
        head,
        ref_name,
        sha,
    )
