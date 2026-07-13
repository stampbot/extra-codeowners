"""GitHub webhook authentication and trigger extraction."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Final

from extra_codeowners.database import AuthorityRequest, JobRequest

MAX_WEBHOOK_BYTES: Final = 10 * 1024 * 1024
PULL_REQUEST_ACTIONS: Final = frozenset(
    {
        "opened",
        "reopened",
        "synchronize",
        "ready_for_review",
        "converted_to_draft",
        "edited",
        "labeled",
        "unlabeled",
        "review_requested",
        "review_request_removed",
    }
)
REVIEW_ACTIONS: Final = frozenset({"submitted", "edited", "dismissed"})
CODEOWNERS_PATHS: Final = frozenset({".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"})


class WebhookError(ValueError):
    """A webhook cannot be safely authenticated or interpreted."""


@dataclass(frozen=True, slots=True)
class VerifiedWebhook:
    """Authenticated delivery metadata and parsed payload."""

    delivery_id: str
    event: str
    action: str
    payload: dict[str, Any]


def verify_webhook(
    body: bytes,
    *,
    signature: str | None,
    delivery_id: str | None,
    event: str | None,
    secret: str,
) -> VerifiedWebhook:
    """Authenticate a GitHub webhook before parsing user-controlled JSON."""
    if len(body) > MAX_WEBHOOK_BYTES:
        msg = "webhook payload exceeds the 10 MiB limit"
        raise WebhookError(msg)
    if not signature or not signature.startswith("sha256="):
        msg = "missing or malformed X-Hub-Signature-256"
        raise WebhookError(msg)
    if not delivery_id or len(delivery_id) > 128:
        msg = "missing or malformed X-GitHub-Delivery"
        raise WebhookError(msg)
    if not event or len(event) > 128:
        msg = "missing or malformed X-GitHub-Event"
        raise WebhookError(msg)
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        msg = "webhook signature mismatch"
        raise WebhookError(msg)
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        msg = "webhook body is not valid JSON"
        raise WebhookError(msg) from error
    if not isinstance(parsed, dict):
        msg = "webhook JSON root must be an object"
        raise WebhookError(msg)
    action = parsed.get("action", "")
    if not isinstance(action, str):
        msg = "webhook action must be a string"
        raise WebhookError(msg)
    return VerifiedWebhook(delivery_id, event, action, parsed)


def _positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        msg = f"webhook {field} must be a positive integer"
        raise WebhookError(msg)
    return value


def _repository_name(payload: dict[str, Any]) -> str:
    repository = payload.get("repository")
    if not isinstance(repository, dict) or not isinstance(repository.get("full_name"), str):
        msg = "webhook omitted repository.full_name"
        raise WebhookError(msg)
    full_name = str(repository["full_name"])
    if full_name.count("/") != 1 or any(part == "" for part in full_name.split("/")):
        raise WebhookError("webhook repository.full_name must be owner/repository")
    return full_name.lower()


def _installation_id(payload: dict[str, Any]) -> int:
    installation = payload.get("installation")
    if not isinstance(installation, dict):
        msg = "webhook omitted installation"
        raise WebhookError(msg)
    return _positive_int(installation.get("id"), "installation.id")


def _pull_request_job(webhook: VerifiedWebhook) -> JobRequest:
    pull = webhook.payload.get("pull_request")
    if not isinstance(pull, dict):
        msg = "webhook omitted pull_request"
        raise WebhookError(msg)
    number = _positive_int(pull.get("number") or webhook.payload.get("number"), "pull number")
    head = pull.get("head")
    head_sha = head.get("sha") if isinstance(head, dict) else None
    return JobRequest(
        installation_id=_installation_id(webhook.payload),
        repository_full_name=_repository_name(webhook.payload),
        pull_number=number,
        reason=f"{webhook.event}.{webhook.action or 'received'}",
        head_sha_hint=head_sha if isinstance(head_sha, str) else None,
    )


def _push_authority_job(
    webhook: VerifiedWebhook,
    *,
    policy_path: str,
    org_config_repository: str,
) -> AuthorityRequest | None:
    payload = webhook.payload
    if payload.get("deleted") is True:
        return None
    ref = payload.get("ref")
    if not isinstance(ref, str) or not ref.startswith("refs/heads/"):
        return None
    branch = ref.removeprefix("refs/heads/")
    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise WebhookError("webhook omitted repository")
    full_name = _repository_name(payload)
    repository_name = full_name.split("/", 1)[-1]

    if repository_name != org_config_repository.lower():
        # Every base-branch push can change a pull request's merge base and
        # therefore its changed files and applicable CODEOWNERS rules. The
        # fan-out later narrows this event to PRs whose base ref is ``branch``.
        return AuthorityRequest(
            installation_id=_installation_id(payload),
            repository_full_name=full_name,
            base_ref=branch,
            reason="push.repository_base",
        )

    default_branch = repository.get("default_branch")
    if not isinstance(default_branch, str) or branch != default_branch:
        return None

    # GitHub bounds the commits included in a push payload. Only the shared
    # organization-policy repository can safely use path filtering, and any
    # missing, malformed, or truncated evidence must conservatively fan out.
    commits = payload.get("commits")
    changed: set[str] = set()
    malformed = not isinstance(commits, list)
    if isinstance(commits, list):
        for commit in commits:
            if not isinstance(commit, dict):
                malformed = True
                continue
            for field in ("added", "modified", "removed"):
                paths = commit.get(field)
                if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
                    malformed = True
                    continue
                changed.update(paths)
    distinct_size = payload.get("distinct_size")
    if (
        isinstance(distinct_size, int)
        and not isinstance(distinct_size, bool)
        and distinct_size >= 0
    ):
        valid_distinct_size = True
        reported_commit_count = distinct_size
    else:
        valid_distinct_size = False
        reported_commit_count = 0
    forced = payload.get("forced")
    truncated = (
        malformed
        or not valid_distinct_size
        or not isinstance(commits, list)
        or reported_commit_count > len(commits)
        or forced is not False
    )
    if not truncated and policy_path not in changed:
        return None
    return AuthorityRequest(
        installation_id=_installation_id(payload),
        repository_full_name=None,
        base_ref=None,
        reason="push.organization_policy",
    )


def evaluation_job(
    webhook: VerifiedWebhook,
    *,
    policy_path: str = ".github/extra-codeowners.toml",
    org_config_repository: str = ".github",
) -> JobRequest | AuthorityRequest | None:
    """Map a verified delivery to evaluation or authority fan-out work."""
    if webhook.event == "pull_request":
        return _pull_request_job(webhook) if webhook.action in PULL_REQUEST_ACTIONS else None
    if webhook.event == "pull_request_review":
        return _pull_request_job(webhook) if webhook.action in REVIEW_ACTIONS else None
    if webhook.event == "check_run" and webhook.action == "rerequested":
        check_run = webhook.payload.get("check_run")
        if not isinstance(check_run, dict):
            raise WebhookError("webhook omitted check_run")
        pulls = check_run.get("pull_requests")
        if not isinstance(pulls, list) or len(pulls) != 1 or not isinstance(pulls[0], dict):
            return None
        number = _positive_int(pulls[0].get("number"), "check_run pull number")
        head_sha = check_run.get("head_sha")
        return JobRequest(
            installation_id=_installation_id(webhook.payload),
            repository_full_name=_repository_name(webhook.payload),
            pull_number=number,
            reason="check_run.rerequested",
            head_sha_hint=head_sha if isinstance(head_sha, str) else None,
        )
    if webhook.event == "push":
        return _push_authority_job(
            webhook,
            policy_path=policy_path,
            org_config_repository=org_config_repository,
        )
    if webhook.event == "repository":
        repository = webhook.payload.get("repository")
        if not isinstance(repository, dict):
            raise WebhookError("webhook omitted repository")
        full_name = _repository_name(webhook.payload)
        repository_name = full_name.split("/", 1)[-1]
        changes = webhook.payload.get("changes")
        previous_name: str | None = None
        default_branch_changed = False
        if isinstance(changes, dict):
            repository_change = changes.get("repository")
            if isinstance(repository_change, dict):
                name_change = repository_change.get("name")
                if isinstance(name_change, dict) and isinstance(name_change.get("from"), str):
                    previous_name = str(name_change["from"])
            default_branch_changed = "default_branch" in changes
        org_repository_affected = repository_name == org_config_repository.lower() or (
            previous_name is not None and previous_name.lower() == org_config_repository.lower()
        )
        if org_repository_affected and (
            webhook.action in {"deleted", "renamed", "transferred"}
            or (webhook.action == "edited" and default_branch_changed)
        ):
            return AuthorityRequest(
                installation_id=_installation_id(webhook.payload),
                repository_full_name=None,
                base_ref=None,
                reason=f"repository.{webhook.action}",
            )
        if webhook.action in {"renamed", "transferred", "unarchived"}:
            # Mutable repository names are API routes, not durable identities.
            # Fence the whole installation so an old-name in-flight evaluation
            # cannot race work discovered under the new route. Unarchive also
            # revisits checks that were intentionally skipped while archived.
            return AuthorityRequest(
                installation_id=_installation_id(webhook.payload),
                repository_full_name=None,
                base_ref=None,
                reason=f"repository.{webhook.action}",
            )
        return None
    if webhook.event in {"label", "member", "team_add"}:
        return AuthorityRequest(
            installation_id=_installation_id(webhook.payload),
            repository_full_name=_repository_name(webhook.payload),
            base_ref=None,
            reason=f"{webhook.event}.{webhook.action or 'received'}",
        )
    if webhook.event in {"membership", "organization", "team"}:
        return AuthorityRequest(
            installation_id=_installation_id(webhook.payload),
            repository_full_name=None,
            base_ref=None,
            reason=f"{webhook.event}.{webhook.action or 'received'}",
        )
    if webhook.event == "installation" and webhook.action in {
        "created",
        "unsuspend",
        "new_permissions_accepted",
    }:
        return AuthorityRequest(
            installation_id=_installation_id(webhook.payload),
            repository_full_name=None,
            base_ref=None,
            reason=f"installation.{webhook.action}",
        )
    if webhook.event == "installation_repositories":
        if webhook.action == "added":
            return AuthorityRequest(
                installation_id=_installation_id(webhook.payload),
                repository_full_name=None,
                base_ref=None,
                reason="installation_repositories.added",
            )
        if webhook.action == "removed":
            removed = webhook.payload.get("repositories_removed")
            malformed = not isinstance(removed, list) or not removed
            organization_policy_removed = False
            if isinstance(removed, list):
                for repository in removed:
                    if not isinstance(repository, dict):
                        malformed = True
                        continue
                    removed_full_name = repository.get("full_name")
                    if (
                        not isinstance(removed_full_name, str)
                        or removed_full_name.count("/") != 1
                        or any(part == "" for part in removed_full_name.split("/"))
                    ):
                        malformed = True
                        continue
                    repository_name = removed_full_name.rsplit("/", 1)[-1]
                    organization_policy_removed |= (
                        repository_name.lower() == org_config_repository.lower()
                    )
            if malformed or organization_policy_removed:
                # Losing the shared policy source can invalidate application
                # enrollment across every still-accessible target repository.
                # Malformed evidence is treated as that security-sensitive case.
                return AuthorityRequest(
                    installation_id=_installation_id(webhook.payload),
                    repository_full_name=None,
                    base_ref=None,
                    reason="installation_repositories.removed",
                )
            # The App has already lost the capability needed to revoke a check
            # in an ordinary removed target repository. Operators must follow
            # the documented access-removal sequence for that case.
            return None
    if webhook.event == "installation_target" and webhook.action == "renamed":
        return AuthorityRequest(
            installation_id=_installation_id(webhook.payload),
            repository_full_name=None,
            base_ref=None,
            reason="installation_target.renamed",
        )
    return None
