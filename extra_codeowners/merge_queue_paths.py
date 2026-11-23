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


def _tree_entries(evidence: object, tree_id: str) -> dict[str, tuple[str, str]]:
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
