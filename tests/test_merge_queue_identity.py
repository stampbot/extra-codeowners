from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from extra_codeowners.github import GitHubClient, GitHubError
from extra_codeowners.merge_queue import (
    MAX_MERGE_QUEUE_ENTRIES,
    MergeGroupTrigger,
    MergeQueueEvidenceError,
    bind_candidate,
)
from extra_codeowners.webhooks import WebhookError, merge_group_trigger, verify_webhook

TARGET = MergeGroupTrigger(
    action="checks_requested",
    installation_id=7,
    repository_id=41,
    repository="example/project",
    base_ref="refs/heads/release/main",
    base_sha="a" * 40,
    head_ref="refs/heads/gh-readonly-queue/release/main/pr-99-generated-name",
    head_sha="b" * 40,
)


def _event(action: str = "checks_requested", **fields: str) -> bytes:
    return json.dumps(
        {
            "action": action,
            "installation": {"id": TARGET.installation_id},
            "repository": {"id": TARGET.repository_id, "full_name": TARGET.repository},
            "merge_group": {
                "base_ref": TARGET.base_ref,
                "base_sha": TARGET.base_sha,
                "head_ref": TARGET.head_ref,
                "head_sha": TARGET.head_sha,
            }
            | fields,
        }
    ).encode()


def _trigger(payload: bytes, event: str = "merge_group") -> MergeGroupTrigger | None:
    secret = "fictional-webhook-secret"
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    webhook = verify_webhook(
        payload,
        signature=f"sha256={digest}",
        event=event,
        delivery_id="example-delivery",
        secret=secret,
    )
    return merge_group_trigger(webhook)


def _graph() -> dict[str, Any]:
    def ref(name: str, sha: str) -> dict[str, Any]:
        return {
            "name": name.removeprefix("refs/heads/"),
            "prefix": "refs/heads/",
            "target": {"__typename": "Commit", "oid": sha},
        }

    return {
        "id": "repository-node",
        "databaseId": TARGET.repository_id,
        "nameWithOwner": "Example/Project",
        "base": ref(TARGET.base_ref, TARGET.base_sha),
        "head": ref(TARGET.head_ref, TARGET.head_sha),
        "mergeQueue": {
            "id": "queue-node",
            "entries": {
                "totalCount": 1,
                "pageInfo": {"hasNextPage": False},
                "nodes": [
                    {
                        "id": "entry-node",
                        "position": 1,
                        "state": "AWAITING_CHECKS",
                        "baseCommit": {"oid": TARGET.base_sha},
                        "headCommit": {"oid": TARGET.head_sha},
                        "pullRequest": {
                            "id": "pr-node",
                            "number": 17,
                            "state": "OPEN",
                            "isDraft": False,
                            "baseRefOid": TARGET.base_sha,
                            "baseRefName": TARGET.base_branch,
                            "headRefOid": "c" * 40,
                            "repository": {"id": "repository-node"},
                        },
                    }
                ],
            },
        },
    }


def _rules() -> list[dict[str, Any]]:
    return [
        {"type": "required_status_checks"},
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
    ]


def _waiting(position: int) -> dict[str, Any]:
    return {
        "id": f"waiting-entry-{position}",
        "position": position,
        "state": "QUEUED",
        "baseCommit": None,
        "headCommit": None,
        "pullRequest": {
            "id": f"waiting-pr-{position}",
            "number": 100 + position,
            "repository": {"id": "repository-node"},
            "baseRefName": TARGET.base_branch,
            "state": "OPEN",
            "isDraft": False,
        },
    }


def _crowded_graph(count: int) -> dict[str, Any]:
    result = _graph()
    entries = result["mergeQueue"]["entries"]
    entries["totalCount"] = count
    entries["nodes"].extend(_waiting(position) for position in range(2, count + 1))
    return result


def test_verified_delivery_only_identifies_the_candidate() -> None:
    # Verifies XCO-014: a verified delivery supplies only a trigger.
    assert _trigger(_event()) == TARGET
    assert _trigger(_event("destroyed")) == replace(TARGET, action="destroyed")
    assert _trigger(_event("future_action")) is None
    assert _trigger(_event(), event="pull_request") is None
    identified = bind_candidate(TARGET, _graph(), effective_rules=_rules())
    assert identified.pull_number == 17  # The ref's unrelated pr-99 is not a PR identity.
    assert identified.pull_head_sha == "c" * 40
    assert identified.entry_id == "entry-node"
    assert identified.queue_id == "queue-node"


@pytest.mark.parametrize(
    "fields",
    [
        {"base_ref": "main"},
        {"base_ref": "refs/heads/release/../main"},
        {"head_ref": "refs/heads/ordinary"},
        {"head_ref": "refs/heads/gh-readonly-queue/invalid@{ref"},
        {"head_sha": "b" * 39},
        {"head_sha": TARGET.base_sha},
    ],
)
def test_rejects_malformed_signed_candidate(fields: dict[str, str]) -> None:
    with pytest.raises(WebhookError):
        _trigger(_event(**fields))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("databaseId",), 42),
        (("nameWithOwner",), "elsewhere/project"),
        (("base", "target", "oid"), "d" * 40),
        (("head", "target", "oid"), "d" * 40),
        (("head", "target", "__typename"), "Tag"),
        (("head", "prefix"), "refs/tags/"),
        (("mergeQueue",), None),
        (("mergeQueue", "entries", "totalCount"), 2),
        (("mergeQueue", "entries", "totalCount"), True),
        (("mergeQueue", "entries", "nodes"), []),
        (("mergeQueue", "entries", "pageInfo", "hasNextPage"), True),
        (("mergeQueue", "entries", "nodes", 0, "state"), "QUEUED"),
        (("mergeQueue", "entries", "nodes", 0, "baseCommit"), None),
        (("mergeQueue", "entries", "nodes", 0, "headCommit", "oid"), "d" * 40),
        (("mergeQueue", "entries", "nodes", 0, "pullRequest", "state"), "CLOSED"),
        (("mergeQueue", "entries", "nodes", 0, "pullRequest", "isDraft"), True),
        (("mergeQueue", "entries", "nodes", 0, "pullRequest", "baseRefOid"), "d" * 40),
        (("mergeQueue", "entries", "nodes", 0, "pullRequest", "headRefOid"), TARGET.head_sha),
        (("mergeQueue", "entries", "nodes", 0, "pullRequest", "repository", "id"), "other-node"),
    ],
)
def test_refuses_missing_stale_or_ambiguous_queue_evidence(
    path: tuple[str | int, ...], value: object
) -> None:
    # Verifies XCO-001: no candidate identity can be formed from an incomplete read.
    graph = _graph()
    parent: Any = graph
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = value
    with pytest.raises(MergeQueueEvidenceError):
        bind_candidate(TARGET, graph, effective_rules=_rules())


@pytest.mark.parametrize("count", [2, 3, MAX_MERGE_QUEUE_ENTRIES])
def test_waiting_entries_do_not_change_the_only_built_candidate(count: int) -> None:
    # Verifies XCO-007. Waiting entries don't get to borrow the front candidate.
    binding = bind_candidate(TARGET, _crowded_graph(count), effective_rules=_rules())
    assert binding == bind_candidate(TARGET, _graph(), effective_rules=_rules())


@pytest.mark.parametrize("state", ["MERGEABLE", "LOCKED"])
def test_green_lifecycle_states_are_only_eligible_for_an_existing_result(state: str) -> None:
    graph = _graph()
    graph["mergeQueue"]["entries"]["nodes"][0]["state"] = state
    with pytest.raises(MergeQueueEvidenceError):
        bind_candidate(TARGET, graph, effective_rules=_rules())
    assert (
        bind_candidate(TARGET, graph, effective_rules=_rules(), rechecking=True).pull_number == 17
    )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("state",), "AWAITING_CHECKS"),
        (("headCommit",), {"oid": "d" * 40}),
        (("baseCommit",), {"oid": TARGET.base_sha}),
        (("id",), "entry-node"),
        (("position",), 1),
        (("position",), 3),
        (("pullRequest",), None),
        (("pullRequest", "id"), "pr-node"),
        (("pullRequest", "number"), 17),
        (("pullRequest", "baseRefName"), "another-base"),
        (("pullRequest", "repository", "id"), "another-repo"),
        (("pullRequest", "state"), "CLOSED"),
        (("pullRequest", "isDraft"), True),
    ],
)
def test_waiting_entry_cannot_hide_conflicting_evidence(
    path: tuple[str, ...], value: object
) -> None:
    # Verifies XCO-001. An entry must be positively identified as still unbuilt.
    graph = _crowded_graph(2)
    row = graph["mergeQueue"]["entries"]["nodes"][1]
    for part in path[:-1]:
        row = row[part]
    row[path[-1]] = value
    with pytest.raises(MergeQueueEvidenceError):
        bind_candidate(TARGET, graph, effective_rules=_rules())


@pytest.mark.parametrize("missing", ["baseCommit", "headCommit"])
def test_waiting_commits_must_be_explicitly_null(missing: str) -> None:
    graph = _crowded_graph(2)
    del graph["mergeQueue"]["entries"]["nodes"][1][missing]
    with pytest.raises(MergeQueueEvidenceError, match="waiting PR"):
        bind_candidate(TARGET, graph, effective_rules=_rules())


def test_queue_over_the_limit_does_not_supply_complete_evidence() -> None:
    with pytest.raises(MergeQueueEvidenceError, match="complete merge queue entry list"):
        bind_candidate(
            TARGET, _crowded_graph(MAX_MERGE_QUEUE_ENTRIES + 1), effective_rules=_rules()
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("grouping_strategy", "HEADGREEN"),
        ("merge_method", "REBASE"),
        ("max_entries_to_build", 2),
        ("max_entries_to_build", True),
        ("max_entries_to_merge", "1"),
        ("min_entries_to_merge", 2),
        ("max_entries_to_merge", None),
    ],
)
def test_queue_requires_the_effective_serial_rule(field: str, value: object) -> None:
    rules = _rules()
    rules[1]["parameters"][field] = value
    # Verifies XCO-014: the signed trigger doesn't prove the active rules.
    with pytest.raises(MergeQueueEvidenceError, match="serial fixture"):
        bind_candidate(TARGET, _crowded_graph(2), effective_rules=rules)


@pytest.mark.parametrize(
    "rules",
    [None, [], [{"type": "required_status_checks"}], _rules() + _rules(), _rules() * 50, [{}]],
)
def test_missing_duplicate_or_excessive_branch_rules_do_not_authorize_candidate(
    rules: object,
) -> None:
    with pytest.raises(MergeQueueEvidenceError):
        bind_candidate(TARGET, _graph(), effective_rules=rules)


@pytest.mark.asyncio
@pytest.mark.parametrize("paginated", [False, True])
async def test_merge_queue_refresh_cannot_evict_or_reuse_the_write_token(
    private_key: str, paginated: bool
) -> None:
    queue_reads = 0
    token_requests: list[dict[str, str]] = []
    pull_tokens: list[str] = []
    queue_permission = {"contents": "read", "pull_requests": "read", "merge_queues": "read"}

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal queue_reads
        path = request.url.path
        if path == "/repos/example/project/installation":
            return httpx.Response(200, json={"id": TARGET.installation_id})
        if path == "/app/installations/7/access_tokens":
            permissions = json.loads(request.content)["permissions"]
            token_requests.append(permissions)
            token = (
                f"fictional-queue-{queue_reads}"
                if permissions == queue_permission
                else "fictional-write"
            )
            return httpx.Response(
                201,
                json={
                    "token": token,
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        if path == "/graphql":
            assert request.headers["authorization"] == f"Bearer fictional-queue-{queue_reads}"
            assert json.loads(request.content)["variables"] == {
                "owner": "example",
                "repo": "project",
                "branch": TARGET.base_branch,
                "base": TARGET.base_ref,
                "head": TARGET.head_ref,
                "entryLimit": MAX_MERGE_QUEUE_ENTRIES,
            }
            queue_reads += 1
            if queue_reads == 1:
                return httpx.Response(401, json={"message": "expired"})
            return httpx.Response(200, json={"data": {"repository": _crowded_graph(2)}})
        if path == "/repos/example/project/rules/branches/release/main":
            assert request.method == "GET"
            assert b"/branches/release%2Fmain?" in request.url.raw_path
            assert request.url.params["per_page"] == "100"
            assert request.headers["authorization"] == "Bearer fictional-queue-0"
            assert queue_reads == 0
            return httpx.Response(
                200,
                json=_rules(),
                headers={"link": '<https://api.github.com/?page=2>; rel="next"'}
                if paginated
                else {},
            )
        assert path == "/repos/example/project/pulls/17"
        pull_tokens.append(request.headers["authorization"])
        return httpx.Response(200, json={})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handle))
    try:
        await client.get_pull(7, TARGET.repository, 17)
        if paginated:
            with pytest.raises(GitHubError, match="complete response"):
                await client.get_merge_candidate(TARGET)
        else:
            actual = await client.get_merge_candidate(TARGET)
            assert actual == bind_candidate(TARGET, _graph(), effective_rules=_rules())
        await client.get_pull(7, TARGET.repository, 17)
    finally:
        await client.close()
    assert token_requests == [
        {"checks": "write", "contents": "read", "members": "read", "pull_requests": "read"},
        queue_permission,
    ] + ([] if paginated else [queue_permission])
    assert queue_reads == (0 if paginated else 2)
    assert pull_tokens == ["Bearer fictional-write", "Bearer fictional-write"]


@pytest.mark.asyncio
async def test_scope_loss_and_destroyed_event_never_read_the_queue(private_key: str) -> None:
    paths: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        assert request.url.path == "/repos/example/project/installation"
        return httpx.Response(200, json={"id": TARGET.installation_id + 1})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(GitHubError, match="destroyed"):
            await client.get_merge_candidate(replace(TARGET, action="destroyed"))
        # Verifies XCO-014: current installation access must agree with the trigger.
        with pytest.raises(GitHubError, match="outside the installation"):
            await client.get_merge_candidate(TARGET)
    finally:
        await client.close()
    assert paths == ["/repos/example/project/installation"]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_field", [None, "app", "head_sha", "external_id", "conclusion"])
async def test_candidate_write_requires_exact_check_receipt(
    private_key: str, bad_field: str | None
) -> None:
    # Verifies XCO-007. A REST success code alone is not check publication evidence.
    check_name = "Fixture check"

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/app/installations/{TARGET.installation_id}/access_tokens":
            return httpx.Response(
                201,
                json={
                    "token": "synthetic-writer",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        assert request.url.path == f"/repos/{TARGET.repository}/check-runs"
        assert request.method == "POST"
        sent = json.loads(request.content)
        assert sent["head_sha"] == TARGET.head_sha
        assert sent["external_id"] == TARGET.check_external_id
        result = {**sent, "id": 100, "app": {"id": 1}}
        if bad_field is not None:
            result[bad_field] = None
        return httpx.Response(201, json=result)

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handle))
    try:
        if bad_field is None:
            await client.write_merge_group_check(TARGET, check_name, approved=True, summary="test")
        else:
            with pytest.raises(GitHubError):
                await client.write_merge_group_check(
                    TARGET, check_name, approved=True, summary="test"
                )
        destroyed = replace(TARGET, action="destroyed")
        with pytest.raises(ValueError, match="only reset"):
            await client.write_merge_group_check(
                destroyed, check_name, approved=False, summary="test"
            )
    finally:
        await client.close()
