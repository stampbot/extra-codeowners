"""A signed repository access grant is not a global membership change."""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

from extra_codeowners.database import AuthorityRequest, JobRequest, QueueStore, WebhookDelivery
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.webhooks import VerifiedWebhook, evaluation_job, verify_webhook


def signed(body: dict[str, Any], event: str) -> VerifiedWebhook:
    raw = json.dumps(body).encode()
    signature = "sha256=" + hmac.new(b"fixture-secret", raw, hashlib.sha256).hexdigest()
    return verify_webhook(
        raw, signature=signature, delivery_id="delivery-id", event=event, secret="fixture-secret"
    )


def payload() -> dict[str, Any]:
    return {
        "action": "added_to_repository",
        "installation": {"id": 17},
        "organization": {"id": 99, "login": "Example"},
        "team": {"id": 82},
        "repository": {
            "id": 101,
            "name": "Project",
            "full_name": "Example/Project",
            "owner": {"id": 99, "login": "EXAMPLE", "type": "Organization"},
        },
    }


def test_repository_grant_with_minimal_installation_context_is_scoped() -> None:
    result = evaluation_job(signed(payload(), event="team"))
    assert result == AuthorityRequest(17, "example/project", None, "team.added_to_repository")


def test_matching_optional_installation_account_is_scoped() -> None:
    body = payload()
    body["installation"]["account"] = {"id": 99, "login": "example", "type": "Organization"}
    assert evaluation_job(signed(body, event="team")) == AuthorityRequest(
        17, "example/project", None, "team.added_to_repository"
    )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("repository",), None),
        (("repository",), []),
        (("organization",), None),
        (("team",), None),
        (("organization", "id"), True),
        (("organization", "id"), 0),
        (("organization", "id"), "99"),
        (("organization", "login"), None),
        (("organization", "login"), "bad/owner"),
        (("repository", "id"), True),
        (("repository", "id"), 0),
        (("repository", "id"), "101"),
        (("repository", "name"), None),
        (("repository", "name"), ".."),
        (("repository", "name"), "wrong"),
        (("repository", "full_name"), None),
        (("repository", "full_name"), "other/project"),
        (("repository", "full_name"), "example/project/extra"),
        (("repository", "owner"), None),
        (("repository", "owner", "id"), True),
        (("repository", "owner", "id"), 100),
        (("repository", "owner", "login"), None),
        (("repository", "owner", "login"), "other"),
        (("repository", "owner", "type"), "User"),
        (("team", "id"), True),
        (("team", "id"), 0),
        (("team", "id"), None),
        (("installation", "account"), None),
        (("installation", "account"), {"id": 100, "login": "example"}),
        (("installation", "account"), {"id": 99, "login": "other"}),
        (("installation", "account"), {"id": True, "login": "example"}),
        (("installation", "account"), {"id": 99, "login": "example", "type": "User"}),
    ],
)
def test_ambiguous_context_retains_global_work(path: tuple[str, ...], value: Any) -> None:
    body = payload()
    target = body
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert evaluation_job(signed(body, event="team")) == AuthorityRequest(
        17, None, None, "team.added_to_repository"
    )


@pytest.mark.parametrize(
    ("name", "policy_repository", "expected"),
    [
        (".GiThUb", ".github", None),
        ("Policies", "POLICIES", None),
        (".github", "Policies", "example/.github"),
    ],
)
def test_configured_shared_policy_repository_is_never_narrowed(
    name: str, policy_repository: str, expected: str | None
) -> None:
    body = payload()
    body["repository"].update(name=name, full_name=f"Example/{name}")
    assert evaluation_job(
        signed(body, event="team"), org_config_repository=policy_repository
    ) == AuthorityRequest(17, expected, None, "team.added_to_repository")


@pytest.mark.parametrize(
    "action", ["edited", "deleted", "created", "removed_from_repository", "unknown"]
)
def test_other_team_actions_remain_global_even_with_a_repository(action: str) -> None:
    body = payload()
    body["action"] = action
    assert evaluation_job(signed(body, event="team")) == AuthorityRequest(
        17, None, None, f"team.{action}"
    )


@pytest.mark.parametrize("event", ["membership", "organization"])
def test_membership_and_organization_events_remain_global(event: str) -> None:
    body = payload()
    body["action"] = "removed"
    assert evaluation_job(signed(body, event=event)) == AuthorityRequest(
        17, None, None, f"{event}.removed"
    )


# Verifies XCO-009: scope controls pending authority work, never approval itself.
@pytest.mark.parametrize("ambiguous", [False, True])
def test_accepted_grant_keeps_relevant_publication_fences(tmp_path: Path, ambiguous: bool) -> None:
    url = f"sqlite:///{tmp_path / 'team-grant.db'}"
    upgrade_database(url)
    store = QueueStore(url)
    store.initialize()
    try:
        store.enqueue(JobRequest(17, "example/project", 1, "pull_request.opened", "a" * 40))
        affected = store.claim("affected", 60)
        store.enqueue(JobRequest(17, "example/other", 2, "pull_request.opened", "b" * 40))
        other = store.claim("other", 60)
        assert affected is not None and other is not None
        body = payload()
        if ambiguous:
            body["repository"]["owner"]["id"] = 100
        webhook = signed(body, event="team")
        request = evaluation_job(webhook)
        assert isinstance(request, AuthorityRequest)
        assert store.accept_delivery(webhook.delivery_id, webhook.event, request).accepted
        assert not store.accept_delivery(webhook.delivery_id, webhook.event, request).accepted
        with store.session() as session:
            delivery = session.get(WebhookDelivery, webhook.delivery_id)
            assert delivery is not None and delivery.installation_id == 17
            assert delivery.repository_full_name == (None if ambiguous else "example/project")
            assert delivery.pull_number is None and delivery.head_sha is None
            assert not delivery.invalidation_required
        assert store.has_blocking_authority(affected, "main")
        assert store.has_blocking_authority(other, "main") is ambiguous
    finally:
        store.close()
