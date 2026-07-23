import hashlib
import hmac
import json

import pytest

from extra_codeowners.database import AuthorityRequest, JobRequest
from extra_codeowners.webhooks import (
    MAX_WEBHOOK_BYTES,
    VerifiedWebhook,
    WebhookError,
    evaluation_job,
    verify_webhook,
)


def signed(payload: dict[str, object], event: str = "pull_request") -> VerifiedWebhook:
    body = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    return verify_webhook(
        body,
        signature=signature,
        delivery_id="delivery-id",
        event=event,
        secret="secret",
    )


def pull_payload(action: str = "opened") -> dict[str, object]:
    return {
        "action": action,
        "installation": {"id": 10},
        "repository": {"full_name": "example/project"},
        "number": 7,
        "pull_request": {"number": 7, "head": {"sha": "a" * 40}},
    }


def test_valid_pull_request_trigger_becomes_job() -> None:
    job = evaluation_job(signed(pull_payload()))

    assert isinstance(job, JobRequest)
    assert job.repository_full_name == "example/project"
    assert job.pull_number == 7
    assert job.reason == "pull_request.opened"


def test_irrelevant_action_is_accepted_without_job() -> None:
    assert evaluation_job(signed(pull_payload("closed"))) is None


def test_review_dismissal_triggers_re_evaluation() -> None:
    webhook = signed(pull_payload("dismissed"), event="pull_request_review")

    job = evaluation_job(webhook)

    assert job is not None
    assert job.reason == "pull_request_review.dismissed"


@pytest.mark.parametrize(
    "head",
    [
        None,
        {},
        {"sha": ""},
        {"sha": "a" * 39},
        {"sha": "a" * 41},
        {"sha": "a" * 63},
        {"sha": "a" * 65},
        {"sha": "A" * 40},
        {"sha": "a" * 39 + " "},
        {"sha": "a" * 39 + "/"},
        {"sha": "é" * 40},
    ],
)
def test_direct_pull_trigger_requires_authoritative_canonical_head(
    head: object,
) -> None:
    payload = pull_payload()
    pull = payload["pull_request"]
    assert isinstance(pull, dict)
    pull["head"] = head

    with pytest.raises(WebhookError, match="head"):
        evaluation_job(signed(payload))


def test_invalid_signature_is_rejected_before_json_is_trusted() -> None:
    with pytest.raises(WebhookError, match="signature mismatch"):
        verify_webhook(
            b'{"action":"opened"}',
            signature="sha256=" + "0" * 64,
            delivery_id="delivery-id",
            event="pull_request",
            secret="secret",
        )


def test_missing_delivery_header_is_rejected() -> None:
    body = b"{}"
    signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    with pytest.raises(WebhookError, match="X-GitHub-Delivery"):
        verify_webhook(
            body,
            signature=signature,
            delivery_id=None,
            event="ping",
            secret="secret",
        )


@pytest.mark.parametrize(
    ("body", "signature", "delivery", "event", "message"),
    [
        (b"{}", None, "delivery", "ping", "Signature"),
        (b"{}", "sha256=bad", None, "ping", "Delivery"),
        (b"{}", "sha256=bad", "delivery", None, "Event"),
        (b"[]", "valid", "delivery", "ping", "root must be an object"),
        (b"not-json", "valid", "delivery", "ping", "not valid JSON"),
    ],
)
def test_malformed_envelopes_are_rejected(
    body: bytes,
    signature: str | None,
    delivery: str | None,
    event: str | None,
    message: str,
) -> None:
    if signature == "valid":
        signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    with pytest.raises(WebhookError, match=message):
        verify_webhook(
            body,
            signature=signature,
            delivery_id=delivery,
            event=event,
            secret="secret",
        )


def test_oversized_payload_is_rejected_before_signature_work() -> None:
    with pytest.raises(WebhookError, match="10 MiB"):
        verify_webhook(
            b"x" * (MAX_WEBHOOK_BYTES + 1),
            signature="sha256=unused",
            delivery_id="delivery",
            event="ping",
            secret="secret",
        )


def test_check_run_rerequest_maps_single_pull() -> None:
    webhook = signed(
        {
            "action": "rerequested",
            "installation": {"id": 10},
            "repository": {"full_name": "example/project"},
            "check_run": {
                "head_sha": "a" * 40,
                "pull_requests": [{"number": 7}],
            },
        },
        event="check_run",
    )

    job = evaluation_job(webhook)

    assert job is not None
    assert job.reason == "check_run.rerequested"


def test_check_run_rerequest_requires_authoritative_head() -> None:
    webhook = signed(
        {
            "action": "rerequested",
            "installation": {"id": 10},
            "repository": {"full_name": "example/project"},
            "check_run": {
                "pull_requests": [{"number": 7}],
            },
        },
        event="check_run",
    )

    with pytest.raises(WebhookError, match=r"check_run\.head_sha"):
        evaluation_job(webhook)


def test_installation_event_becomes_installation_authority_job() -> None:
    webhook = signed({"action": "created", "installation": {"id": 10}}, event="installation")

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None
    assert job.base_ref is None


def test_removing_organization_policy_repository_fans_out_installation() -> None:
    webhook = signed(
        {
            "action": "removed",
            "installation": {"id": 10},
            "repositories_removed": [{"full_name": "Example/.GitHub"}],
        },
        event="installation_repositories",
    )

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None
    assert job.reason == "installation_repositories.removed"


@pytest.mark.parametrize("repositories_removed", [None, [], "malformed", [{}]])
def test_malformed_repository_removal_fans_out_conservatively(
    repositories_removed: object,
) -> None:
    webhook = signed(
        {
            "action": "removed",
            "installation": {"id": 10},
            "repositories_removed": repositories_removed,
        },
        event="installation_repositories",
    )

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None


def test_removing_only_an_ordinary_target_repository_is_acknowledged_without_work() -> None:
    webhook = signed(
        {
            "action": "removed",
            "installation": {"id": 10},
            "repositories_removed": [{"full_name": "example/project"}],
        },
        event="installation_repositories",
    )

    assert evaluation_job(webhook) is None


def test_every_repository_branch_push_fans_out_to_matching_base_ref() -> None:
    webhook = signed(
        {
            "ref": "refs/heads/main",
            "installation": {"id": 10},
            "repository": {
                "full_name": "example/project",
                "default_branch": "main",
            },
            "commits": [{"added": [], "modified": ["README.md"], "removed": []}],
            "distinct_size": 1,
        },
        event="push",
    )

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name == "example/project"
    assert job.base_ref == "main"
    assert job.reason == "push.repository_base"


def test_org_policy_push_fans_out_installation_and_ignores_unrelated_complete_push() -> None:
    payload = {
        "ref": "refs/heads/main",
        "forced": False,
        "installation": {"id": 10},
        "repository": {"full_name": "example/.github", "default_branch": "main"},
        "commits": [
            {
                "added": [],
                "modified": [".github/extra-codeowners.toml"],
                "removed": [],
            }
        ],
        "distinct_size": 1,
    }

    job = evaluation_job(signed(payload, event="push"))
    payload["commits"] = [{"added": [], "modified": ["profile/README.md"], "removed": []}]

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None
    assert evaluation_job(signed(payload, event="push")) is None


def test_malformed_org_push_evidence_fans_out_conservatively() -> None:
    webhook = signed(
        {
            "ref": "refs/heads/main",
            "installation": {"id": 10},
            "repository": {"full_name": "example/.github", "default_branch": "main"},
            "commits": "truncated",
            "distinct_size": None,
        },
        event="push",
    )

    assert isinstance(evaluation_job(webhook), AuthorityRequest)


def test_forced_org_policy_branch_reset_fans_out_even_without_changed_paths() -> None:
    webhook = signed(
        {
            "ref": "refs/heads/main",
            "forced": True,
            "installation": {"id": 10},
            "repository": {"full_name": "example/.github", "default_branch": "main"},
            "commits": [],
            "distinct_size": 0,
        },
        event="push",
    )

    assert isinstance(evaluation_job(webhook), AuthorityRequest)


def test_org_policy_repository_matching_is_case_insensitive() -> None:
    webhook = signed(
        {
            "ref": "refs/heads/main",
            "forced": False,
            "installation": {"id": 10},
            "repository": {"full_name": "Example/Policies", "default_branch": "main"},
            "commits": [
                {
                    "added": [],
                    "modified": [".github/extra-codeowners.toml"],
                    "removed": [],
                }
            ],
            "distinct_size": 1,
        },
        event="push",
    )

    job = evaluation_job(webhook, org_config_repository="Policies")

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None


def test_label_definition_change_fans_out_repository() -> None:
    webhook = signed(
        {
            "action": "edited",
            "installation": {"id": 10},
            "repository": {"full_name": "example/project"},
            "label": {"name": "automation-approved"},
        },
        event="label",
    )

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name == "example/project"
    assert job.base_ref is None


def test_organization_membership_change_fans_out_installation() -> None:
    webhook = signed(
        {
            "action": "member_removed",
            "installation": {"id": 10},
            "organization": {"login": "example"},
        },
        event="organization",
    )

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None


def test_org_config_default_branch_change_fans_out_installation() -> None:
    webhook = signed(
        {
            "action": "edited",
            "installation": {"id": 10},
            "repository": {"full_name": "example/.github"},
            "changes": {"default_branch": {"from": "main"}},
        },
        event="repository",
    )

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None
    assert job.reason == "repository.edited"


def test_unrelated_repository_edit_is_ignored() -> None:
    webhook = signed(
        {
            "action": "edited",
            "installation": {"id": 10},
            "repository": {"full_name": "example/project"},
            "changes": {"description": {"from": "old"}},
        },
        event="repository",
    )

    assert evaluation_job(webhook) is None


@pytest.mark.parametrize("action", ["renamed", "transferred", "unarchived"])
def test_repository_identity_or_archive_change_fans_out_installation(action: str) -> None:
    webhook = signed(
        {
            "action": action,
            "installation": {"id": 10},
            "repository": {"full_name": "example/project"},
            "changes": {"repository": {"name": {"from": "old-project"}}},
        },
        event="repository",
    )

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None


def test_installation_target_rename_fans_out_installation() -> None:
    webhook = signed(
        {
            "action": "renamed",
            "installation": {"id": 10},
            "account": {"login": "renamed-example"},
        },
        event="installation_target",
    )

    job = evaluation_job(webhook)

    assert isinstance(job, AuthorityRequest)
    assert job.repository_full_name is None


def test_webhook_repository_name_is_normalized_for_queue_identity() -> None:
    payload = pull_payload()
    payload["repository"] = {"full_name": "Example/Project"}

    job = evaluation_job(signed(payload))

    assert job is not None
    assert job.repository_full_name == "example/project"
