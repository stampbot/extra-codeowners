from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from extra_codeowners import merge_queue_paths as trees
from extra_codeowners.github import GitHubClient, GitHubError

BASE = "a" * 40
CANDIDATE = "b" * 40
OLD = "c" * 40
NEW = "d" * 40
TARGET_COMMIT = "e" * 40
CANDIDATE_COMMIT = "f" * 40
TARGET_REF = "refs/heads/main"
REPOSITORY = "example/project"
COMMITS_ROUTE = f"/repos/{REPOSITORY}/git/commits"
TREES_ROUTE = f"/repos/{REPOSITORY}/git/trees"


def entry(path: str, oid: str, mode: str = "100644", kind: str = "blob") -> dict[str, str]:
    return {"path": path, "mode": mode, "type": kind, "sha": oid}


def tree(oid: str, *rows: dict[str, str]) -> dict[str, Any]:
    return {"sha": oid, "tree": list(rows), "truncated": False}


def diff(before: object, after: object) -> frozenset[str]:
    return trees.changed_paths(before, after, target_tree_id=BASE, candidate_tree_id=CANDIDATE)


def test_paths_compare_against_target_not_an_older_pr_base() -> None:
    # Verifies XCO-006: a moved file counts under both names.
    before = tree(
        BASE,
        entry("service", OLD, "040000", "tree"),
        entry("service/owner-only.py", OLD),
        entry("service/common.py", NEW),
        entry("branch-only.txt", OLD),
        entry("bin/command", OLD),
        entry("bin", NEW, "040000", "tree"),
        entry("module", OLD, "160000", "commit"),
    )
    after = tree(
        CANDIDATE,
        entry("service", NEW, "040000", "tree"),
        entry("service/moved.py", OLD),
        entry("service/common.py", NEW),
        entry("branch-only.txt", OLD),
        entry("bin/command", OLD, "100755"),
        entry("bin", OLD, "040000", "tree"),
        entry("module", NEW, "160000", "commit"),
    )
    assert diff(before, after) == {
        "service/owner-only.py",
        "service/moved.py",
        "bin/command",
        "module",
    }


def test_tree_changes_include_type_changes_and_empty_tree_entries() -> None:
    before = tree(BASE, entry("link", OLD, "120000"))
    after = tree(
        CANDIDATE,
        entry("link", OLD),
        entry("empty", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "040000", "tree"),
    )
    assert diff(before, after) == {"link", "empty"}


@pytest.mark.parametrize(
    "bad",
    [
        {"sha": CANDIDATE, "truncated": True, "tree": []},
        {"sha": CANDIDATE, "truncated": 0, "tree": []},
        {"sha": CANDIDATE, "tree": []},
        tree(BASE),
        tree(CANDIDATE, entry("file", "main")),
        tree(CANDIDATE, entry("file", OLD), entry("file", NEW)),
        tree(CANDIDATE, entry("path/../file", OLD)),
        tree(CANDIDATE, entry("path/file", OLD)),
        tree(CANDIDATE, entry("path", OLD, "040000", "tree")),
        tree(CANDIDATE, entry("path", OLD), entry("path/file", OLD)),
        tree(CANDIDATE, entry("file", OLD, "160000", "blob")),
        tree(CANDIDATE, entry("file", OLD, "777777")),
        tree(CANDIDATE, entry("file ", OLD)),
        tree(CANDIDATE, entry("file\x00", OLD)),
    ],
)
def test_rejects_incomplete_or_contradictory_evidence(bad: object) -> None:
    # Verifies XCO-001.
    with pytest.raises(trees.MergeTreeEvidenceError):
        diff(tree(BASE), bad)


def test_tree_entry_limit_counts_directories_and_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trees, "MAX_TREE_ENTRIES", 1)
    with pytest.raises(trees.MergeTreeEvidenceError, match="entry list"):
        diff(tree(BASE), tree(CANDIDATE, entry("file", OLD), entry("other", OLD)))


@pytest.mark.asyncio
@pytest.mark.parametrize("matching_roots", [False, True])
@pytest.mark.parametrize("topology", ["direct", "merge", "rebase"])
async def test_candidate_evidence_reads_both_exact_commits(
    private_key: str, matching_roots: bool, topology: str
) -> None:
    requests: list[str] = []
    # Verifies XCO-001: a comparison cannot silently stop at 300 changed files.
    paths = {f"file-{n}.txt" for n in range(301)}
    parents = {
        "direct": [TARGET_COMMIT],
        "merge": [TARGET_COMMIT, OLD],
        "rebase": [OLD],
    }[topology]
    responses = {
        f"{COMMITS_ROUTE}/{TARGET_COMMIT}": {"sha": TARGET_COMMIT, "tree": {"sha": BASE}},
        f"{COMMITS_ROUTE}/{CANDIDATE_COMMIT}": {
            "sha": CANDIDATE_COMMIT,
            "tree": {"sha": BASE if matching_roots else CANDIDATE},
            "parents": [{"sha": sha} for sha in parents],
        },
        f"{TREES_ROUTE}/{BASE}": tree(BASE),
        f"{TREES_ROUTE}/{CANDIDATE}": tree(CANDIDATE, *(entry(path, NEW) for path in paths)),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/app/installations/7/access_tokens":
            return httpx.Response(
                201,
                json={
                    "token": "fictional-installation-token",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        if path == "/graphql":
            assert request.method == "POST"
            assert json.loads(request.content)["variables"] == {
                "owner": "example",
                "repo": "project",
                "baseRef": TARGET_REF,
                "candidate": CANDIDATE_COMMIT,
            }
            requests.append(path)
            return httpx.Response(200, json={"data": {"repository": ancestry()}})
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer fictional-installation-token"
        assert str(request.url.params) == ("recursive=1" if path.startswith(TREES_ROUTE) else "")
        requests.append(path)
        return httpx.Response(200, json=responses[path])

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    try:
        result = await client.get_candidate_changed_paths(
            7,
            REPOSITORY,
            target_ref=TARGET_REF,
            target_sha=TARGET_COMMIT,
            candidate_sha=CANDIDATE_COMMIT,
        )
    finally:
        await client.close()
    assert result == trees.CandidateChangedPaths(
        TARGET_COMMIT, CANDIDATE_COMMIT, frozenset() if matching_roots else frozenset(paths)
    )
    expected = [f"{COMMITS_ROUTE}/{CANDIDATE_COMMIT}"]
    if topology == "rebase":
        expected.append("/graphql")
    expected.append(f"{COMMITS_ROUTE}/{TARGET_COMMIT}")
    if not matching_roots:
        expected.extend([f"{TREES_ROUTE}/{BASE}", f"{TREES_ROUTE}/{CANDIDATE}"])
    assert requests == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("repo, target", [(REPOSITORY, "main"), ("example/..", TARGET_COMMIT)])
async def test_rejects_unbound_or_invalid_ref_before_requests(
    private_key: str, repo: str, target: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"unexpected request {request.method} {request.url.path}")

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(GitHubError, match="invalid merge candidate"):
            await client.get_candidate_changed_paths(
                7, repo, target_ref=TARGET_REF, target_sha=target, candidate_sha=CANDIDATE_COMMIT
            )
    finally:
        await client.close()


def test_commit_response_must_match_identity() -> None:
    for wrong in (
        None,
        {"sha": CANDIDATE_COMMIT, "tree": {"sha": BASE}},
        {"sha": TARGET_COMMIT},
        {"sha": TARGET_COMMIT, "tree": {"sha": "main"}},
    ):
        with pytest.raises(trees.MergeTreeEvidenceError):
            trees.commit_tree_id(wrong, TARGET_COMMIT)


def ancestry() -> dict[str, Any]:
    return {
        "nameWithOwner": REPOSITORY,
        "ref": {
            "compare": {
                "status": "AHEAD",
                "aheadBy": 2,
                "behindBy": 0,
                "baseTarget": {"__typename": "Commit", "oid": TARGET_COMMIT},
                "headTarget": {"__typename": "Commit", "oid": CANDIDATE_COMMIT},
            }
        },
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "DIVERGED"),
        ("aheadBy", True),
        ("aheadBy", 0),
        ("behindBy", 1),
        ("behindBy", False),
        ("baseTarget", {"__typename": "Commit", "oid": OLD}),
        ("headTarget", {"__typename": "Commit", "oid": NEW}),
        ("headTarget", {"__typename": "Tag", "oid": CANDIDATE_COMMIT}),
        ("baseTarget", None),
    ],
)
def test_rejects_incomplete_or_contradictory_candidate_ancestry(field: str, value: object) -> None:
    # Verifies XCO-001 and XCO-007: the proof must name the two evaluated commits.
    evidence = ancestry()
    evidence["ref"]["compare"][field] = value
    with pytest.raises(trees.MergeTreeEvidenceError):
        trees.require_candidate_ancestry(evidence, REPOSITORY, TARGET_COMMIT, CANDIDATE_COMMIT)


@pytest.mark.parametrize("parents", [None, [], [{}], [{"sha": "main"}]])
def test_requires_candidate_parent_before_collecting_ancestry(parents: object) -> None:
    with pytest.raises(trees.MergeTreeEvidenceError):
        trees.first_candidate_parent({"parents": parents})
