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


def test_verified_delivery_only_identifies_the_candidate() -> None:
    # Verifies XCO-014: a verified delivery supplies only a trigger.
    assert _trigger(_event()) == TARGET
    assert _trigger(_event("destroyed")) == replace(TARGET, action="destroyed")
    assert _trigger(_event("future_action")) is None
    assert _trigger(_event(), event="pull_request") is None
    identified = bind_candidate(TARGET, _graph())
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
        bind_candidate(TARGET, graph)


@pytest.mark.asyncio
async def test_merge_queue_refresh_cannot_evict_or_reuse_the_write_token(private_key: str) -> None:
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
            }
            queue_reads += 1
            if queue_reads == 1:
                return httpx.Response(401, json={"message": "expired"})
            return httpx.Response(200, json={"data": {"repository": _graph()}})
        assert path == "/repos/example/project/pulls/17"
        pull_tokens.append(request.headers["authorization"])
        return httpx.Response(200, json={})

    client = GitHubClient(1, private_key, transport=httpx.MockTransport(handle))
    try:
        await client.get_pull(7, TARGET.repository, 17)
        actual = await client.get_merge_candidate(TARGET)
        await client.get_pull(7, TARGET.repository, 17)
    finally:
        await client.close()
    assert actual == bind_candidate(TARGET, _graph())
    assert token_requests == [
        {"checks": "write", "contents": "read", "members": "read", "pull_requests": "read"},
        queue_permission,
        queue_permission,
    ]
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
