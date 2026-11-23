"""Identify a GitHub merge candidate without treating its webhook as approval."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from extra_codeowners.merge_queue_paths import MergeTreeEvidenceError, require_object_id
from extra_codeowners.models import ChangedFile, ChangedFileStatus, EvaluationResult

MergeGroupAction = Literal["checks_requested", "destroyed"]

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_HEADS = "refs/heads/"
_QUEUE = "gh-readonly-queue/"
_INVALID_REF = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]|\.\.|@\{")

MAX_MERGE_QUEUE_ENTRIES = 100
MAX_MERGE_QUEUE_BRANCH_RULES = 100

QUEUE_CANDIDATE_QUERY = """\
query QueueCandidate(
  $owner: String!, $repo: String!, $branch: String!, $base: String!, $head: String!,
  $entryLimit: Int!
) {
  repository(owner: $owner, name: $repo) {
    id
    databaseId
    nameWithOwner
    base: ref(qualifiedName: $base) { name prefix target { __typename oid } }
    head: ref(qualifiedName: $head) { name prefix target { __typename oid } }
    mergeQueue(branch: $branch) {
      id
      entries(first: $entryLimit) {
        totalCount
        pageInfo { hasNextPage }
        nodes {
          id
          state
          position
          baseCommit { oid }
          headCommit { oid }
          pullRequest {
            id
            number
            state
            isDraft
            baseRefName
            baseRefOid
            headRefOid
            repository { id }
          }
        }
      }
    }
  }
}
"""


class MergeQueueEvidenceError(ValueError):
    """The delivery or the current queue does not identify one candidate."""


def _record(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MergeQueueEvidenceError("GitHub omitted required merge queue evidence")
    return value


def _positive_id(value: object) -> int:
    if type(value) is not int or not 0 < value <= 2**63 - 1:
        raise MergeQueueEvidenceError("invalid merge queue numeric identity")
    return value


def _node_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= 256
        or not all(33 <= ord(char) <= 126 for char in value)
    ):
        raise MergeQueueEvidenceError("invalid merge queue node identity")
    return value


def _commit_id(value: object) -> str:
    try:
        return require_object_id(value)
    except MergeTreeEvidenceError as error:
        raise MergeQueueEvidenceError("invalid merge candidate commit") from error


def _repository_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 512
        or not _REPOSITORY.fullmatch(value)
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise MergeQueueEvidenceError("invalid merge queue repository name")
    return value


def _branch_ref(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or not value.startswith(_HEADS)
        or _INVALID_REF.search(value)
        or value.endswith(".")
        or any(
            not part or part.startswith(".") or part.endswith(".lock") for part in value.split("/")
        )
    ):
        raise MergeQueueEvidenceError("invalid merge queue branch ref")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise MergeQueueEvidenceError("invalid merge queue branch encoding") from error
    return value


@dataclass(frozen=True, slots=True)
class MergeGroupTrigger:
    """Identity from a verified delivery. It schedules work, not a decision."""

    action: MergeGroupAction
    installation_id: int
    repository_id: int
    repository: str
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str

    def __post_init__(self) -> None:
        _positive_id(self.installation_id)
        _positive_id(self.repository_id)
        _repository_name(self.repository)
        if self.action not in {"checks_requested", "destroyed"}:
            raise MergeQueueEvidenceError("unsupported merge group action")
        base, head = _branch_ref(self.base_ref), _branch_ref(self.head_ref)
        if base.startswith(_HEADS + _QUEUE) or not head.startswith(_HEADS + _QUEUE):
            raise MergeQueueEvidenceError("unexpected target or candidate branch")
        if _commit_id(self.base_sha) == _commit_id(self.head_sha):
            raise MergeQueueEvidenceError("merge candidate matches its target commit")

    @property
    def base_branch(self) -> str:
        return self.base_ref.removeprefix(_HEADS)

    @property
    def check_external_id(self) -> str:
        """Distinguish a managed candidate check from an ordinary PR-head check."""
        return f"merge-group:{self.repository_id}:{self.head_sha}"

    @classmethod
    def from_payload(cls, action: MergeGroupAction, payload: dict[str, Any]) -> MergeGroupTrigger:
        repo = _record(payload.get("repository"))
        installation = _record(payload.get("installation"))
        group = _record(payload.get("merge_group"))
        return cls(
            action=action,
            installation_id=_positive_id(installation.get("id")),
            repository_id=_positive_id(repo.get("id")),
            repository=_repository_name(repo.get("full_name")).lower(),
            base_ref=_branch_ref(group.get("base_ref")),
            base_sha=_commit_id(group.get("base_sha")),
            head_ref=_branch_ref(group.get("head_ref")),
            head_sha=_commit_id(group.get("head_sha")),
        )


@dataclass(frozen=True, slots=True)
class MergeCandidateIdentity:
    """The current queue entry and PR head associated with a candidate commit."""

    trigger: MergeGroupTrigger
    repository_node_id: str
    queue_id: str
    entry_id: str
    pull_id: str
    pull_number: int
    pull_head_sha: str


@dataclass(frozen=True, slots=True)
class MergeCandidateAssessment:
    """Read-only result, tied to a candidate and the PR head whose reviews it used."""

    identity: MergeCandidateIdentity
    result: EvaluationResult


def _require_ref(value: object, ref: str, sha: str) -> None:
    branch = _record(value)
    target = _record(branch.get("target"))
    if (
        branch.get("prefix") != _HEADS
        or branch.get("name") != ref.removeprefix(_HEADS)
        or target.get("__typename") != "Commit"
        or target.get("oid") != sha
    ):
        raise MergeQueueEvidenceError("merge queue ref changed or no longer points to a commit")


def require_serial_queue_rule(rules: object) -> None:
    """Require the effective queue rule tested in the one-build fixture."""
    if not isinstance(rules, list) or not 0 < len(rules) < MAX_MERGE_QUEUE_BRANCH_RULES:
        raise MergeQueueEvidenceError("GitHub did not return a complete branch rule list")
    merge_rules: list[dict[str, Any]] = []
    for value in rules:
        rule = _record(value)
        kind = rule.get("type")
        if not isinstance(kind, str) or not kind:
            raise MergeQueueEvidenceError("GitHub omitted an effective branch rule type")
        if kind == "merge_queue":
            merge_rules.append(_record(rule.get("parameters")))
    if len(merge_rules) != 1:
        raise MergeQueueEvidenceError(
            "GitHub did not return exactly one effective merge queue rule"
        )
    parameters = merge_rules[0]
    counts = ("max_entries_to_build", "min_entries_to_merge", "max_entries_to_merge")
    if (
        parameters.get("grouping_strategy") != "ALLGREEN"
        or parameters.get("merge_method") != "SQUASH"
        or any(type(parameters.get(field)) is not int or parameters[field] != 1 for field in counts)
    ):
        raise MergeQueueEvidenceError(
            "effective merge queue rule does not match the serial fixture"
        )


def _require_waiting_entries(nodes: list[object], identity: MergeCandidateIdentity) -> None:
    """Distinguish unbuilt PRs from a second candidate or conflicting entry."""
    entry_ids = {identity.entry_id}
    pull_ids = {identity.pull_id}
    pull_numbers = {identity.pull_number}
    for position, value in enumerate(nodes, start=2):
        entry = _record(value)
        entry_id = _node_id(entry.get("id"))
        pull = _record(entry.get("pullRequest"))
        pull_id = _node_id(pull.get("id"))
        pull_number = _positive_id(pull.get("number"))
        if (
            _positive_id(entry.get("position")) != position
            or entry.get("state") != "QUEUED"
            or "baseCommit" not in entry
            or entry["baseCommit"] is not None
            or "headCommit" not in entry
            or entry["headCommit"] is not None
            or entry_id in entry_ids
            or pull_id in pull_ids
            or pull_number in pull_numbers
            or _record(pull.get("repository")).get("id") != identity.repository_node_id
            or pull.get("baseRefName") != identity.trigger.base_branch
            or pull.get("state") != "OPEN"
            or pull.get("isDraft") is not False
        ):
            raise MergeQueueEvidenceError("another merge queue entry is not an unbuilt waiting PR")
        entry_ids.add(entry_id)
        pull_ids.add(pull_id)
        pull_numbers.add(pull_number)


def bind_candidate(
    trigger: MergeGroupTrigger,
    graph: object,
    *,
    effective_rules: object,
    rechecking: bool = False,
) -> MergeCandidateIdentity:
    """Bind the only built candidate to its target and PR in a serial queue."""
    if trigger.action != "checks_requested":
        raise MergeQueueEvidenceError("destroyed candidates are not eligible for evaluation")
    require_serial_queue_rule(effective_rules)
    repo = _record(graph)
    route = repo.get("nameWithOwner")
    if (
        _positive_id(repo.get("databaseId")) != trigger.repository_id
        or not isinstance(route, str)
        or route.lower() != trigger.repository.lower()
    ):
        raise MergeQueueEvidenceError("merge queue repository changed")
    repo_id = _node_id(repo.get("id"))
    _require_ref(repo.get("base"), trigger.base_ref, trigger.base_sha)
    _require_ref(repo.get("head"), trigger.head_ref, trigger.head_sha)

    queue = _record(repo.get("mergeQueue"))
    entries = _record(queue.get("entries"))
    nodes = entries.get("nodes")
    count = entries.get("totalCount")
    if (
        type(count) is not int
        or not 0 < count <= MAX_MERGE_QUEUE_ENTRIES
        or _record(entries.get("pageInfo")).get("hasNextPage") is not False
        or not isinstance(nodes, list)
        or len(nodes) != count
    ):
        raise MergeQueueEvidenceError("GitHub did not return a complete merge queue entry list")
    entry = _record(nodes[0])
    eligible_states = (
        ("AWAITING_CHECKS", "MERGEABLE", "LOCKED") if rechecking else ("AWAITING_CHECKS",)
    )
    if (
        entry.get("state") not in eligible_states
        or _positive_id(entry.get("position")) != 1
        or _record(entry.get("baseCommit")).get("oid") != trigger.base_sha
        or _record(entry.get("headCommit")).get("oid") != trigger.head_sha
    ):
        raise MergeQueueEvidenceError("queue entry is not awaiting checks on this candidate")

    pull = _record(entry.get("pullRequest"))
    head = _commit_id(pull.get("headRefOid"))
    if (
        _record(pull.get("repository")).get("id") != repo_id
        or pull.get("state") != "OPEN"
        or pull.get("isDraft") is not False
        or pull.get("baseRefName") != trigger.base_branch
        or pull.get("baseRefOid") != trigger.base_sha
        or head == trigger.head_sha
    ):
        raise MergeQueueEvidenceError("queue entry does not identify the open PR and its revisions")
    identity = MergeCandidateIdentity(
        trigger=trigger,
        repository_node_id=repo_id,
        queue_id=_node_id(queue.get("id")),
        entry_id=_node_id(entry.get("id")),
        pull_id=_node_id(pull.get("id")),
        pull_number=_positive_id(pull.get("number")),
        pull_head_sha=head,
    )
    _require_waiting_entries(nodes[1:], identity)
    return identity


def candidate_pull_is_closed(
    trigger: MergeGroupTrigger, pull_id: str, pull_number: int, value: object
) -> bool:
    """Retire a timer only after a fresh read identifies its closed PR."""
    pull = _record(value)
    repo = _record(_record(pull.get("base")).get("repo"))
    if (
        _positive_id(pull.get("number")) != pull_number
        or pull.get("node_id") != pull_id
        or _positive_id(repo.get("id")) != trigger.repository_id
        or _repository_name(repo.get("full_name")).lower() != trigger.repository
        or pull.get("state") not in ("open", "closed")
        or type(pull.get("merged")) is not bool
    ):
        raise MergeQueueEvidenceError("could not confirm current candidate PR lifecycle")
    return bool(pull["state"] == "closed")


def require_candidate_pull(identity: MergeCandidateIdentity, value: object) -> None:
    """Check that the REST policy input still describes the GraphQL queue entry."""
    pull = _record(value)
    base, head = _record(pull.get("base")), _record(pull.get("head"))
    repo = _record(base.get("repo"))
    trigger = identity.trigger
    if (
        _positive_id(pull.get("number")) != identity.pull_number
        or pull.get("node_id") != identity.pull_id
        or pull.get("state") != "open"
        or pull.get("draft") is not False
        or pull.get("merged") is not False
        or _positive_id(repo.get("id")) != trigger.repository_id
        or repo.get("node_id") != identity.repository_node_id
        or _repository_name(repo.get("full_name")).lower() != trigger.repository
        or base.get("ref") != trigger.base_branch
        or base.get("sha") != trigger.base_sha
        or head.get("sha") != identity.pull_head_sha
    ):
        raise MergeQueueEvidenceError("pull evidence does not match the current queue entry")


def require_reviewed_paths(
    candidate_paths: frozenset[str], changed_files: tuple[ChangedFile, ...]
) -> None:
    """Require policy coverage for each path changed relative to the candidate base."""
    reviewed: set[str] = set()
    filenames: set[str] = set()
    for change in changed_files:
        if change.path in filenames:
            raise MergeQueueEvidenceError("pull file evidence repeated a filename")
        filenames.add(change.path)
        if change.status is not ChangedFileStatus.UNCHANGED:
            reviewed.add(change.path)
            if change.previous_path is not None:
                reviewed.add(change.previous_path)
    if not candidate_paths <= reviewed:
        raise MergeQueueEvidenceError("merge candidate changes paths not covered by the PR")
