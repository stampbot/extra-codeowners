"""Read-only changed-path evidence for one GitHub merge candidate."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from extra_codeowners.models import normalize_repository_path

MAX_TREE_ENTRIES: Final = 100_000
_EMPTY_TREE: Final = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")
_MODE_TYPES: Final = {
    "040000": "tree",
    "100644": "blob",
    "100755": "blob",
    "120000": "blob",
    "160000": "commit",
}

CANDIDATE_ANCESTRY_QUERY = """\
query CandidateAncestry($owner: String!, $repo: String!, $baseRef: String!, $candidate: String!) {
  repository(owner: $owner, name: $repo) {
    nameWithOwner
    ref(qualifiedName: $baseRef) {
      compare(headRef: $candidate) {
        status
        aheadBy
        behindBy
        baseTarget { __typename oid }
        headTarget { __typename oid }
      }
    }
  }
}
"""


class MergeTreeEvidenceError(ValueError):
    """GitHub did not provide complete evidence for the requested object."""


@dataclass(frozen=True, slots=True)
class CandidateChangedPaths:
    """The paths changed by applying the candidate to its target commit."""

    target_sha: str
    candidate_sha: str
    paths: frozenset[str]


def require_object_id(value: object) -> str:
    """Require a SHA-1 object ID rather than a Git ref or abbreviated SHA."""
    if not isinstance(value, str) or _OBJECT_ID.fullmatch(value) is None:
        raise MergeTreeEvidenceError("invalid merge candidate Git object ID")
    return value


def commit_tree_id(commit: object, expected_commit: str) -> str:
    """Bind the tree root to the GitHub commit that was requested."""
    if not isinstance(commit, dict) or commit.get("sha") != expected_commit:
        raise MergeTreeEvidenceError("GitHub returned a different commit")
    tree = commit.get("tree")
    if not isinstance(tree, dict):
        raise MergeTreeEvidenceError("GitHub commit omitted its tree")
    return require_object_id(tree.get("sha"))


def require_commit_parents(
    commit: object, expected_commit: str, expected_parents: tuple[str, ...]
) -> None:
    """Bind a GitHub Git commit to its expected, ordered parent list."""
    if not isinstance(commit, dict) or commit.get("sha") != expected_commit:
        raise MergeTreeEvidenceError("GitHub returned a different commit")
    parents = commit.get("parents")
    if (
        not isinstance(parents, list)
        or len(parents) != len(expected_parents)
        or any(
            not isinstance(parent, dict) or parent.get("sha") != expected
            for parent, expected in zip(parents, expected_parents, strict=True)
        )
    ):
        raise MergeTreeEvidenceError("GitHub commit does not have the expected parents")


def first_candidate_parent(commit: dict[str, object]) -> str:
    """Read the first parent of a candidate whose commit identity was checked."""
    parents = commit.get("parents")
    if not isinstance(parents, list) or not parents or not isinstance(parents[0], dict):
        raise MergeTreeEvidenceError("GitHub candidate commit omitted its first parent")
    return require_object_id(parents[0].get("sha"))


def require_candidate_ancestry(
    evidence: object, repository: str, target_sha: str, candidate_sha: str
) -> None:
    """Require GitHub to prove the target is an ancestor of this candidate."""
    if not isinstance(evidence, dict):
        raise MergeTreeEvidenceError("GitHub omitted the candidate comparison repository")
    name = evidence.get("nameWithOwner")
    ref = evidence.get("ref")
    comparison = ref.get("compare") if isinstance(ref, dict) else None
    if not isinstance(name, str) or name.lower() != repository.lower():
        raise MergeTreeEvidenceError("GitHub compared commits from a different repository")
    if not isinstance(comparison, dict):
        raise MergeTreeEvidenceError("GitHub omitted the candidate ancestry comparison")
    for field, sha in (("baseTarget", target_sha), ("headTarget", candidate_sha)):
        commit = comparison.get(field)
        if (
            not isinstance(commit, dict)
            or commit.get("__typename") != "Commit"
            or commit.get("oid") != sha
        ):
            raise MergeTreeEvidenceError("GitHub compared different candidate revisions")
    ahead, behind = comparison.get("aheadBy"), comparison.get("behindBy")
    if (
        comparison.get("status") != "AHEAD"
        or type(ahead) is not int
        or ahead <= 0
        or type(behind) is not int
        or behind != 0
    ):
        raise MergeTreeEvidenceError("GitHub did not prove the candidate descends from its target")


def _read_tree_entries(evidence: object, tree_id: str) -> dict[str, tuple[str, str]]:
    if (
        not isinstance(evidence, dict)
        or evidence.get("sha") != tree_id
        or evidence.get("truncated") is not False
    ):
        raise MergeTreeEvidenceError("GitHub returned a different or incomplete tree")
    rows = evidence.get("tree")
    if not isinstance(rows, list) or len(rows) > MAX_TREE_ENTRIES:
        raise MergeTreeEvidenceError("GitHub tree has an invalid entry list")

    entries: dict[str, tuple[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise MergeTreeEvidenceError("GitHub tree entry must be an object")
        path, mode = row.get("path"), row.get("mode")
        if (
            not isinstance(path, str)
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path in entries
        ):
            raise MergeTreeEvidenceError("GitHub tree has an invalid or duplicate path")
        if not isinstance(mode, str) or mode not in _MODE_TYPES:
            raise MergeTreeEvidenceError("GitHub tree has an unsupported file mode")
        if row.get("type") != _MODE_TYPES[mode]:
            raise MergeTreeEvidenceError("GitHub tree entry type disagrees with its file mode")
        entries[path] = (mode, require_object_id(row.get("sha")))
    return entries


def immediate_tree_entry(evidence: object, tree_id: str, name: str) -> tuple[str, str] | None:
    """Look up a single child in a complete, non-recursive Git tree."""
    entries = _read_tree_entries(evidence, tree_id)
    if any("/" in path for path in entries):
        raise MergeTreeEvidenceError("GitHub returned a recursive tree for a direct lookup")
    return entries.get(name)


def _tree_entries(evidence: object, tree_id: str) -> dict[str, tuple[str, str]]:
    entries = _read_tree_entries(evidence, tree_id)
    # Check the hierarchy even when GitHub explicitly says it didn't truncate.
    # An absent parent can hide a change from the path comparison.
    directories = {path for path, (mode, _) in entries.items() if mode == "040000"}
    parents = {path.rpartition("/")[0] for path in entries if "/" in path}
    if not parents <= directories:
        raise MergeTreeEvidenceError("GitHub tree entry is missing its parent directory")
    if any(entries[path][1] != _EMPTY_TREE for path in directories - parents):
        raise MergeTreeEvidenceError("GitHub tree omitted a non-empty directory's entries")
    # Leaf entries capture file changes; a directory ID also changes when any
    # descendant changes. Keep empty directories so a directory-only change
    # can't silently disappear from the result.
    return {path: entry for path, entry in entries.items() if path not in parents}


def changed_paths(
    target_tree: object,
    candidate_tree: object,
    *,
    target_tree_id: str,
    candidate_tree_id: str,
) -> frozenset[str]:
    """Compare complete GitHub trees without relying on rename detection."""
    before = _tree_entries(target_tree, target_tree_id)
    after = _tree_entries(candidate_tree, candidate_tree_id)
    paths = {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}
    try:
        return frozenset(normalize_repository_path(path) for path in paths)
    except ValueError as error:
        raise MergeTreeEvidenceError(
            "changed tree path cannot be evaluated as a repository path"
        ) from error
