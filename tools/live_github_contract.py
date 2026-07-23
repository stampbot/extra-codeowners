"""Exercise GitHub's commit-scoped Check Run contract in a disposable repository.

This tool deliberately uses live GitHub resources. It never runs as part of ordinary CI.
Credentials are accepted only through environment variables so they do not appear in the
process list. The generated report contains assertions and payload key sets, not tokens,
signatures, raw webhook payloads, or private keys.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, cast
from urllib.parse import parse_qsl, quote, urlsplit

import httpx
import jwt

API_VERSION: Final = "2026-03-10"
API_URL: Final = "https://api.github.com"
CONFIRMATION_PREFIX: Final = "delete-disposable-repository-in:"
REPORT_SCHEMA_VERSION: Final = 2
DELIVERY_LINK_HEADER_LIMIT: Final = 8192
DELIVERY_CURSOR_LIMIT: Final = 1024
DELIVERY_LINK_RELATIONS: Final = frozenset({"first", "last", "next", "prev"})
DELIVERY_PAGE_SIZE_MAXIMUM: Final = 100
WEBHOOK_DELIVERY_LIST_LIMIT: Final = 300
WEBHOOK_DELIVERY_PAGE_LIMIT: Final = 3
WEBHOOK_DELIVERY_PAGE_SIZE: Final = 100
WEBHOOK_CAPTURE_SECONDS: Final = 30
REPOSITORY_RECOVERY_ATTEMPTS: Final = 6
REPOSITORY_RECOVERY_INTERVAL_SECONDS: Final = 5
REPOSITORY_CLEANUP_STATES: Final = frozenset(
    {
        "not_attempted",
        "response_confirmed_cleaned",
        "response_unknown_cleaned",
    }
)

CORE_OBSERVATIONS: Final = (
    "organization_ruleset_expected_source",
    "repository_ruleset_expected_source",
    "completed_success_to_in_progress_blocks_merge",
    "shared_head_inherits_success_before_invalidation",
    "shared_head_invalidation_blocks_both_pull_requests",
    "retarget_inherits_commit_scoped_success_before_invalidation",
    "pull_request_opened_delivery_observed",
    "pull_request_retarget_delivery_observed",
)
APP_REVIEW_OBSERVATIONS: Final = (
    "numeric_approval_rule_blocks_before_app_review",
    "app_review_attributed_to_bot",
    "app_review_counts_as_numeric_approval",
)
DIAGNOSTIC_OBSERVATIONS: Final = (
    "in_progress_merge_state_blocked",
    "in_progress_merge_attempt_blocked",
    "installation_repository_added_delivery_observed",
)
WEBHOOK_OBSERVATIONS: Final = (
    "installation_repository_added_delivery_observed",
    "pull_request_opened_delivery_observed",
    "pull_request_retarget_delivery_observed",
)
MANUAL_EVIDENCE_REQUIRED: Final = (
    "deployed_webhook_delay_and_redelivery",
    "deployed_webhook_loss_and_reconciliation",
    "installation_lifecycle_delivery_contracts",
    "repository_rename_transfer_and_deletion",
    "installation_suspension_and_deletion",
    "repository_selection_access_removal",
    "authority_loss_merge_handback",
)

JsonObject = dict[str, Any]


class ContractError(RuntimeError):
    """The live fixture could not establish or verify a GitHub contract."""


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ContractError(f"{name} is required")
    return value


def _positive_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ContractError(f"{name} must be a positive integer") from error
    if parsed <= 0:
        raise ContractError(f"{name} must be a positive integer")
    return parsed


def _boolean_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ContractError(f"{name} must be true or false")


@dataclass(frozen=True, slots=True)
class AppCredentials:
    """A disposable fixture's App identity."""

    app_id: int
    installation_id: int
    private_key_file: Path

    @classmethod
    def from_environment(cls, prefix: str, *, optional: bool = False) -> AppCredentials | None:
        names = {
            "app_id": f"{prefix}_APP_ID",
            "installation_id": f"{prefix}_INSTALLATION_ID",
            "private_key_file": f"{prefix}_PRIVATE_KEY_FILE",
        }
        values = {field: os.getenv(name, "").strip() for field, name in names.items()}
        configured = [bool(value) for value in values.values()]
        if optional and not any(configured):
            return None
        if not all(configured):
            missing = [names[field] for field, value in values.items() if not value]
            raise ContractError(f"configure all {prefix} credentials; missing {', '.join(missing)}")
        private_key_file = Path(values["private_key_file"])
        if not private_key_file.is_file():
            raise ContractError(f"{names['private_key_file']} must name a readable file")
        return cls(
            app_id=_positive_int(values["app_id"], names["app_id"]),
            installation_id=_positive_int(values["installation_id"], names["installation_id"]),
            private_key_file=private_key_file,
        )


@dataclass(frozen=True, slots=True)
class Config:
    """Validated live-contract configuration."""

    organization: str
    operator_token: str
    repository_selection_token: str | None
    source_revision: str
    checker: AppCredentials
    approver: AppCredentials | None
    report_file: Path
    check_name: str
    observation_seconds: int
    keep_repository: bool

    @classmethod
    def from_environment(cls) -> Config:
        organization = _required_env("EXTRA_CODEOWNERS_LIVE_ORGANIZATION")
        if "/" in organization or organization in {".", ".."}:
            raise ContractError("EXTRA_CODEOWNERS_LIVE_ORGANIZATION must be one account name")
        confirmation = _required_env("EXTRA_CODEOWNERS_LIVE_CONFIRM")
        expected = f"{CONFIRMATION_PREFIX}{organization}"
        if confirmation != expected:
            raise ContractError(
                "EXTRA_CODEOWNERS_LIVE_CONFIRM must equal "
                f"{expected!r}; the fixture creates and deletes organization resources"
            )
        checker = AppCredentials.from_environment("EXTRA_CODEOWNERS_LIVE_CHECKER")
        assert checker is not None
        observation_seconds = _positive_int(
            os.getenv("EXTRA_CODEOWNERS_LIVE_OBSERVATION_SECONDS", "5"),
            "EXTRA_CODEOWNERS_LIVE_OBSERVATION_SECONDS",
        )
        if observation_seconds > 30:
            raise ContractError("EXTRA_CODEOWNERS_LIVE_OBSERVATION_SECONDS cannot exceed 30")
        check_name = os.getenv(
            "EXTRA_CODEOWNERS_LIVE_CHECK_NAME", "Extra CODEOWNERS / live contract"
        ).strip()
        if not check_name or len(check_name) > 100:
            raise ContractError("EXTRA_CODEOWNERS_LIVE_CHECK_NAME must contain 1-100 characters")
        source_revision = _required_env("EXTRA_CODEOWNERS_LIVE_SOURCE_REVISION").lower()
        if re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
            raise ContractError("EXTRA_CODEOWNERS_LIVE_SOURCE_REVISION must be a full commit SHA")
        operator_token = _required_env("EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN")
        repository_selection_token = os.getenv(
            "EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN", ""
        ).strip()
        if repository_selection_token == operator_token:
            raise ContractError(
                "EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN must be a separate "
                "short-lived classic PAT, not the operator token"
            )
        return cls(
            organization=organization,
            operator_token=operator_token,
            repository_selection_token=repository_selection_token or None,
            source_revision=source_revision,
            checker=checker,
            approver=AppCredentials.from_environment(
                "EXTRA_CODEOWNERS_LIVE_APPROVER", optional=True
            ),
            report_file=Path(
                os.getenv(
                    "EXTRA_CODEOWNERS_LIVE_REPORT_FILE",
                    "live-github-contract-report.json",
                )
            ),
            check_name=check_name,
            observation_seconds=observation_seconds,
            keep_repository=_boolean_env("EXTRA_CODEOWNERS_LIVE_KEEP_REPOSITORY"),
        )


class RestClient:
    """Small bounded GitHub REST client that never logs credentials."""

    def __init__(self, token: str) -> None:
        self._http = httpx.Client(
            base_url=API_URL,
            timeout=httpx.Timeout(30),
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "extra-codeowners-live-contract",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )

    def close(self) -> None:
        self._http.close()

    def _request_response(
        self,
        method: str,
        path: str,
        *,
        body: JsonObject | None = None,
        params: dict[str, str | int] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> httpx.Response:
        response = self._http.request(method, path, json=body, params=params)
        if response.status_code not in expected:
            message = ""
            try:
                parsed = response.json()
                if isinstance(parsed, dict) and isinstance(parsed.get("message"), str):
                    message = f": {parsed['message'][:300]}"
            except ValueError:
                # A non-JSON error body adds no safe detail beyond the status and API path.
                pass
            raise ContractError(
                f"GitHub API {method} {path} returned {response.status_code}{message}"
            )
        return response

    @staticmethod
    def _response_body(response: httpx.Response) -> Any:
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: JsonObject | None = None,
        params: dict[str, str | int] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        response = self._request_response(
            method,
            path,
            body=body,
            params=params,
            expected=expected,
        )
        return self._response_body(response)

    def request_with_link(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str | int] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> tuple[Any, str | None]:
        """Return a response body and only its pagination Link header."""
        response = self._request_response(
            method,
            path,
            params=params,
            expected=expected,
        )
        return self._response_body(response), response.headers.get("link")

    def status(
        self,
        method: str,
        path: str,
        *,
        body: JsonObject | None = None,
    ) -> int:
        return self._http.request(method, path, json=body).status_code


def _malformed_delivery_link() -> ContractError:
    return ContractError("GitHub delivery Link header is malformed or ambiguous")


def _next_delivery_link_target(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        not value
        or len(value) > DELIVERY_LINK_HEADER_LIMIT
        or any(character in value for character in "\r\n\0")
    ):
        raise _malformed_delivery_link()

    links: dict[str, str] = {}
    position = 0
    while position < len(value):
        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != "<":
            raise _malformed_delivery_link()
        target_end = value.find(">", position + 1)
        if target_end < 0:
            raise _malformed_delivery_link()
        target = value[position + 1 : target_end]
        if not target or any(character.isspace() or ord(character) < 0x21 for character in target):
            raise _malformed_delivery_link()
        position = target_end + 1

        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != ";":
            raise _malformed_delivery_link()
        position += 1
        while position < len(value) and value[position] in " \t":
            position += 1
        if value[position : position + 3].lower() != "rel":
            raise _malformed_delivery_link()
        position += 3
        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != "=":
            raise _malformed_delivery_link()
        position += 1
        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != '"':
            raise _malformed_delivery_link()
        relation_end = value.find('"', position + 1)
        if relation_end < 0:
            raise _malformed_delivery_link()
        relation = value[position + 1 : relation_end].lower()
        if relation not in DELIVERY_LINK_RELATIONS or relation in links:
            raise _malformed_delivery_link()
        links[relation] = target
        position = relation_end + 1

        while position < len(value) and value[position] in " \t":
            position += 1
        if position == len(value):
            break
        if value[position] != ",":
            raise _malformed_delivery_link()
        position += 1
        if position == len(value):
            raise _malformed_delivery_link()

    return links.get("next")


def _next_delivery_cursor(link_header: str | None) -> str | None:
    target = _next_delivery_link_target(link_header)
    if target is None:
        return None
    try:
        parsed = urlsplit(target)
        port = parsed.port
        query = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=3,
        )
    except ValueError as error:
        raise _malformed_delivery_link() from error
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.hostname.lower() != "api.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path != "/app/hook/deliveries"
        or parsed.fragment
        or not query
    ):
        raise _malformed_delivery_link()

    values: dict[str, str] = {}
    for name, item in query:
        if name not in {"cursor", "per_page"} or name in values:
            raise _malformed_delivery_link()
        values[name] = item
    cursor = values.get("cursor")
    if (
        cursor is None
        or not cursor
        or len(cursor) > DELIVERY_CURSOR_LIMIT
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in cursor)
    ):
        raise _malformed_delivery_link()
    per_page = values.get("per_page")
    if per_page is not None and (
        not per_page.isdecimal() or not 1 <= int(per_page) <= DELIVERY_PAGE_SIZE_MAXIMUM
    ):
        raise _malformed_delivery_link()
    return cursor


def delivery_summaries_bounded(
    client: RestClient,
    *,
    list_limit: int,
    page_limit: int,
    page_size: int,
) -> tuple[list[JsonObject], bool, int]:
    """List delivery summaries through validated cursors within explicit bounds."""
    if (
        list_limit <= 0
        or page_limit <= 0
        or page_size <= 0
        or page_size > DELIVERY_PAGE_SIZE_MAXIMUM
    ):
        raise ValueError(
            "delivery pagination bounds must be positive and page_size cannot exceed 100"
        )

    summaries: list[JsonObject] = []
    seen_cursors: set[str] = set()
    cursor: str | None = None
    pages_read = 0

    while pages_read < page_limit and len(summaries) < list_limit:
        requested_page_size = min(page_size, list_limit - len(summaries))
        params: dict[str, str | int] = {"per_page": requested_page_size}
        if cursor is not None:
            params["cursor"] = cursor
        response, link_header = client.request_with_link(
            "GET",
            "/app/hook/deliveries",
            params=params,
        )
        pages_read += 1
        if not isinstance(response, list) or any(not isinstance(item, dict) for item in response):
            raise ContractError("GitHub delivery listing is not a list of objects")
        if len(response) > requested_page_size:
            raise ContractError("GitHub delivery listing exceeded the requested page size")
        summaries.extend(response)

        next_cursor = _next_delivery_cursor(link_header)
        if next_cursor is None:
            return summaries, True, pages_read
        if next_cursor in seen_cursors:
            raise ContractError("GitHub delivery pagination repeated a cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    return summaries, False, pages_read


class AppAuth:
    """GitHub App JWT and installation-token issuer for the fixture."""

    def __init__(self, credentials: AppCredentials) -> None:
        self.credentials = credentials
        self._private_key = credentials.private_key_file.read_text()

    def jwt_client(self) -> RestClient:
        now = datetime.now(UTC)
        token = jwt.encode(
            {
                "iat": int((now - timedelta(seconds=60)).timestamp()),
                "exp": int((now + timedelta(minutes=9)).timestamp()),
                "iss": str(self.credentials.app_id),
            },
            self._private_key,
            algorithm="RS256",
        )
        return RestClient(str(token))

    def installation_client(self, permissions: dict[str, str]) -> RestClient:
        client = self.jwt_client()
        try:
            result = client.request(
                "POST",
                f"/app/installations/{self.credentials.installation_id}/access_tokens",
                body={"permissions": permissions},
                expected=(201,),
            )
        finally:
            client.close()
        if not isinstance(result, dict) or not isinstance(result.get("token"), str):
            raise ContractError("GitHub installation-token response omitted its token")
        return RestClient(str(result["token"]))

    def repository_selection(self) -> str:
        """Return whether this installation covers all or selected repositories."""
        client = self.jwt_client()
        try:
            result = client.request("GET", f"/app/installations/{self.credentials.installation_id}")
        finally:
            client.close()
        if not isinstance(result, dict) or result.get("repository_selection") not in {
            "all",
            "selected",
        }:
            raise ContractError("GitHub installation response omitted repository_selection")
        return str(result["repository_selection"])


def required_check_has_expected_source(ruleset: JsonObject, *, context: str, app_id: int) -> bool:
    """Return whether a ruleset requires exactly this context from this App."""
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters")
        checks = parameters.get("required_status_checks") if isinstance(parameters, dict) else None
        if not isinstance(checks, list):
            continue
        if any(
            isinstance(check, dict)
            and check.get("context") == context
            and check.get("integration_id") == app_id
            for check in checks
        ):
            return True
    return False


def _positive_delivery_integer(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractError(f"GitHub delivery {description} is not a positive integer")
    return cast(int, value)


def _delivery_pair(delivery: JsonObject, description: str) -> tuple[str, str]:
    event = delivery.get("event")
    action = delivery.get("action")
    if not isinstance(event, str) or not event or not isinstance(action, str) or not action:
        raise ContractError(f"GitHub delivery {description} omitted event or action")
    return event, action


def _delivery_status(delivery: JsonObject, description: str) -> tuple[bool, int]:
    redelivery = delivery.get("redelivery")
    status_code = delivery.get("status_code")
    if not isinstance(redelivery, bool):
        raise ContractError(f"GitHub delivery {description} omitted Boolean redelivery metadata")
    # GitHub's REST schema requires an integer but does not publish minimum or maximum bounds.
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        raise ContractError(f"GitHub delivery {description} omitted integer status metadata")
    return redelivery, status_code


def sanitize_delivery(delivery: JsonObject) -> JsonObject:
    """Reduce a raw App delivery to metadata and payload field names."""
    redelivery, status_code = _delivery_status(delivery, "detail")
    request = delivery.get("request")
    payload = request.get("payload") if isinstance(request, dict) else None
    shape: JsonObject = {}
    if isinstance(payload, dict):
        shape["root_keys"] = sorted(str(key) for key in payload)
        for name in (
            "account",
            "changes",
            "enterprise",
            "installation",
            "organization",
            "pull_request",
            "repositories",
            "repositories_added",
            "repositories_removed",
            "repository",
            "requester",
            "sender",
        ):
            value = payload.get(name)
            if isinstance(value, dict):
                shape[f"{name}_keys"] = sorted(str(key) for key in value)
            elif isinstance(value, list):
                object_keys = {str(key) for item in value if isinstance(item, dict) for key in item}
                shape[f"{name}_item_keys"] = sorted(object_keys)
    return {
        "action": delivery.get("action") if isinstance(delivery.get("action"), str) else None,
        "event": delivery.get("event") if isinstance(delivery.get("event"), str) else None,
        "payload_shape": shape,
        "redelivery": redelivery,
        "status_code": status_code,
    }


def installation_add_targets_repository(
    delivery: JsonObject,
    *,
    repository_id: int,
    installation_id: int,
) -> bool:
    """Validate an installation add payload and test its added-repository list."""
    expected_repository = _positive_delivery_integer(repository_id, "fixture repository ID")
    expected_installation = _positive_delivery_integer(
        installation_id,
        "fixture installation ID",
    )
    request = delivery.get("request")
    payload = request.get("payload") if isinstance(request, dict) else None
    if not isinstance(payload, dict):
        raise ContractError("GitHub installation add delivery omitted its payload")
    if payload.get("action") != "added":
        raise ContractError("GitHub installation add delivery payload has an unexpected action")
    installation = payload.get("installation")
    if not isinstance(installation, dict):
        raise ContractError("GitHub installation add delivery omitted its installation")
    payload_installation = _positive_delivery_integer(
        installation.get("id"),
        "payload installation ID",
    )
    if payload_installation != expected_installation:
        raise ContractError("GitHub installation add delivery targets another installation")

    repository_ids: dict[str, set[int]] = {}
    for field in ("repositories_added", "repositories_removed"):
        repositories = payload.get(field)
        if not isinstance(repositories, list):
            raise ContractError(f"GitHub installation add delivery omitted {field}")
        ids: set[int] = set()
        for item in repositories:
            if not isinstance(item, dict):
                raise ContractError(
                    f"GitHub installation add delivery {field} is not a list of objects"
                )
            item_id = _positive_delivery_integer(
                item.get("id"),
                f"{field} repository ID",
            )
            if item_id in ids:
                raise ContractError(
                    f"GitHub installation add delivery repeated a repository in {field}"
                )
            ids.add(item_id)
        repository_ids[field] = ids
    if repository_ids["repositories_added"] & repository_ids["repositories_removed"]:
        raise ContractError(
            "GitHub installation add delivery puts one repository in both change lists"
        )
    return expected_repository in repository_ids["repositories_added"]


def _validate_webhook_detail(
    summary: JsonObject,
    detail: JsonObject,
    *,
    expected_pair: tuple[str, str],
    installation_id: int,
    repository_id: int,
) -> None:
    summary_id = _positive_delivery_integer(summary.get("id"), "summary ID")
    detail_id = _positive_delivery_integer(detail.get("id"), "detail ID")
    summary_installation = _positive_delivery_integer(
        summary.get("installation_id"),
        "summary installation ID",
    )
    detail_installation = _positive_delivery_integer(
        detail.get("installation_id"),
        "detail installation ID",
    )
    if (
        detail_id != summary_id
        or summary_installation != installation_id
        or detail_installation != installation_id
        or _delivery_pair(summary, "summary") != expected_pair
        or _delivery_pair(detail, "detail") != expected_pair
        or _delivery_status(summary, "summary") != _delivery_status(detail, "detail")
    ):
        raise ContractError("GitHub delivery detail does not match its summary")

    if expected_pair[0] == "pull_request":
        summary_repository = _positive_delivery_integer(
            summary.get("repository_id"),
            "summary repository ID",
        )
        detail_repository = _positive_delivery_integer(
            detail.get("repository_id"),
            "detail repository ID",
        )
        if summary_repository != repository_id or detail_repository != repository_id:
            raise ContractError("GitHub delivery detail does not match its fixture repository")


def _status_check_rule(context: str, app_id: int) -> JsonObject:
    return {
        "type": "required_status_checks",
        "parameters": {
            "do_not_enforce_on_create": True,
            "required_status_checks": [{"context": context, "integration_id": app_id}],
            "strict_required_status_checks_policy": False,
        },
    }


def _review_rule() -> JsonObject:
    return {
        "type": "pull_request",
        "parameters": {
            "allowed_merge_methods": ["merge", "squash", "rebase"],
            "dismiss_stale_reviews_on_push": True,
            "require_code_owner_review": False,
            "require_last_push_approval": False,
            "required_approving_review_count": 1,
            "required_review_thread_resolution": False,
        },
    }


def contract_interpretation(assertions: JsonObject) -> JsonObject:
    """Interpret observed booleans without treating an unsafe result as a fixture error."""
    protective_assertions = (
        "organization_ruleset_expected_source",
        "repository_ruleset_expected_source",
        "completed_success_to_in_progress_blocks_merge",
        "shared_head_invalidation_blocks_both_pull_requests",
    )
    inheritance_assertions = (
        "shared_head_inherits_success_before_invalidation",
        "retarget_inherits_commit_scoped_success_before_invalidation",
    )
    github_contract_fail_closed = all(
        assertions.get(name) is True for name in protective_assertions
    ) and all(assertions.get(name) is False for name in inheritance_assertions)
    return {
        "github_contract_fail_closed": github_contract_fail_closed,
        "production_warning_required": True,
        "production_warning_reason": (
            "GitHub contract is not fail closed"
            if not github_contract_fail_closed
            else "fixture does not cover deployed webhook delivery and reconciliation"
        ),
        "scope": "GitHub rules and Check Run behavior only; deployment delivery is separate",
    }


def _observation_state(assertions: JsonObject, name: str) -> str:
    if name not in assertions:
        return "missing"
    value = assertions[name]
    if value is None:
        return "not_run"
    if value is True:
        return "observed_true"
    if value is False:
        return "observed_false"
    return "invalid"


def evidence_completeness(report: JsonObject, *, approver_configured: bool) -> JsonObject:
    """Describe which evidence this report contains without interpreting false as absent."""
    assertions_value = report.get("assertions")
    assertions = assertions_value if isinstance(assertions_value, dict) else {}
    names = (*CORE_OBSERVATIONS, *APP_REVIEW_OBSERVATIONS, *DIAGNOSTIC_OBSERVATIONS)
    observations = {name: _observation_state(assertions, name) for name in names}
    webhook_capture = report.get("webhook_capture")
    webhook_capture_valid = False
    incomplete_observations: list[str] = []
    if isinstance(webhook_capture, dict):
        incomplete_value = webhook_capture.get("incomplete_observations")
        incomplete_candidates = (
            [name for name in incomplete_value if isinstance(name, str)]
            if isinstance(incomplete_value, list)
            else []
        )
        webhook_capture_valid = (
            isinstance(incomplete_value, list)
            and len(incomplete_candidates) == len(incomplete_value)
            and all(name in WEBHOOK_OBSERVATIONS for name in incomplete_candidates)
            and all(name not in assertions for name in incomplete_candidates)
            and len(set(incomplete_value)) == len(incomplete_value)
            and type(webhook_capture.get("delivery_list_limit")) is int
            and webhook_capture["delivery_list_limit"] == WEBHOOK_DELIVERY_LIST_LIMIT
            and type(webhook_capture.get("delivery_page_limit")) is int
            and webhook_capture["delivery_page_limit"] == WEBHOOK_DELIVERY_PAGE_LIMIT
            and type(webhook_capture.get("delivery_page_size")) is int
            and webhook_capture["delivery_page_size"] == WEBHOOK_DELIVERY_PAGE_SIZE
            and type(webhook_capture.get("delivery_window_complete")) is bool
            and type(webhook_capture.get("last_poll_pages_read")) is int
            and 1 <= webhook_capture["last_poll_pages_read"] <= WEBHOOK_DELIVERY_PAGE_LIMIT
            and type(webhook_capture.get("pages_read_total")) is int
            and type(webhook_capture.get("poll_count")) is int
            and 1
            <= webhook_capture["poll_count"]
            <= webhook_capture["pages_read_total"]
            <= webhook_capture["poll_count"] * WEBHOOK_DELIVERY_PAGE_LIMIT
            and webhook_capture["last_poll_pages_read"] <= webhook_capture["pages_read_total"]
            and (not incomplete_candidates or webhook_capture["delivery_window_complete"] is False)
        )
        if webhook_capture_valid:
            incomplete_observations = sorted(incomplete_candidates)
            for name in incomplete_observations:
                observations[name] = "incomplete"

    fixture = report.get("fixture")
    selection = fixture.get("checker_repository_selection") if isinstance(fixture, dict) else None
    configured_required = list(CORE_OBSERVATIONS)
    if approver_configured:
        configured_required.extend(APP_REVIEW_OBSERVATIONS)
    if selection == "selected":
        configured_required.append("installation_repository_added_delivery_observed")

    def observed(name: str) -> bool:
        return observations[name] in {"observed_true", "observed_false"}

    configured_observations_complete = all(observed(name) for name in configured_required)
    full_automated_complete = webhook_capture_valid and all(
        observed(name) for name in (*CORE_OBSERVATIONS, *APP_REVIEW_OBSERVATIONS)
    )
    report_result = report.get("result")
    cleanup_succeeded = report.get("cleanup_succeeded")
    selection_valid = selection in {"all", "selected"}
    return {
        "configured_run_complete": (
            report_result == "observed"
            and cleanup_succeeded is True
            and selection_valid
            and webhook_capture_valid
            and configured_observations_complete
        ),
        "configured_observations_complete": configured_observations_complete,
        "full_automated_observations_complete": full_automated_complete,
        "webhook_capture_metadata_valid": webhook_capture_valid,
        "configured_required": configured_required,
        "full_automated_required": [
            *CORE_OBSERVATIONS,
            *APP_REVIEW_OBSERVATIONS,
        ],
        "observations": observations,
        "observed_false": sorted(
            name for name, state in observations.items() if state == "observed_false"
        ),
        "not_run": sorted(name for name, state in observations.items() if state == "not_run"),
        "missing": sorted(name for name, state in observations.items() if state == "missing"),
        "invalid": sorted(name for name, state in observations.items() if state == "invalid"),
        "incomplete": incomplete_observations,
        "manual_evidence_required": list(MANUAL_EVIDENCE_REQUIRED),
        "scope": (
            "automated GitHub fixture only; lifecycle, deployed delivery, and "
            "authority-loss evidence remain separate"
        ),
    }


def merge_attempt_was_blocked(status_code: int) -> bool:
    """Interpret a merge response, retaining an accepted merge as unsafe evidence."""
    if status_code == 200:
        return False
    if status_code in {405, 409}:
        return True
    raise ContractError(
        "merge probe returned an indeterminate HTTP status; "
        f"GitHub returned {status_code} instead of 200, 405, or 409"
    )


def _object(value: Any, description: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ContractError(f"GitHub response omitted {description}")
    return value


def _integer(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"GitHub response omitted {description}")
    return cast(int, value)


def _string(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"GitHub response omitted {description}")
    return value


class Fixture:
    """Own and clean up every resource in one contract run."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.operator = RestClient(config.operator_token)
        self.repository_selection = (
            RestClient(config.repository_selection_token)
            if config.repository_selection_token is not None
            else None
        )
        self.checker_auth = AppAuth(config.checker)
        self.checker: RestClient | None = None
        self.approver_auth = AppAuth(config.approver) if config.approver is not None else None
        self.approver: RestClient | None = None
        suffix = secrets.token_hex(16)
        self.repository_name = f"extra-codeowners-contract-{suffix}"
        self.repository = f"{config.organization}/{self.repository_name}"
        self.repository_created = False
        self.repository_creation_attempted = False
        self.repository_creation_outcome_unknown = False
        self.repository_creation_state = "not_attempted"
        self.repository_id: int | None = None
        self.default_branch = ""
        self.organization_ruleset_name = f"Extra CODEOWNERS contract {self.repository_name}"
        self.organization_ruleset_id: int | None = None
        self.organization_ruleset_creation_attempted = False
        self.report: JsonObject = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "api_version": API_VERSION,
            "source_revision": config.source_revision,
            "started_at": datetime.now(UTC).isoformat(),
            "fixture": {
                "approver_repository_selection": None,
                "checker_repository_selection": None,
                "private_repository": True,
                "repository_creation_state": self.repository_creation_state,
                "repository_kept": config.keep_repository,
            },
            "assertions": {},
            "webhook_contracts": [],
        }

    @property
    def repo_path(self) -> str:
        return f"/repos/{quote(self.repository, safe='/')}"

    def _set_repository_creation_state(self, state: str) -> None:
        self.repository_creation_state = state
        report = getattr(self, "report", None)
        fixture_report = report.get("fixture") if isinstance(report, dict) else None
        if isinstance(fixture_report, dict):
            fixture_report["repository_creation_state"] = state

    def _create_repository(self) -> JsonObject:
        sys.stdout.write(
            "Prepared disposable repository recovery coordinates:\n"
            f"  owner: {self.config.organization}\n"
            f"  name: {self.repository_name}\n"
            f"  URL: https://github.com/{self.repository}\n"
        )
        # The POST can succeed even when its response is lost. Make the recovery
        # coordinates durable in redirected logs before any request can create
        # the repository.
        sys.stdout.flush()
        preflight_status = self.operator.status("GET", self.repo_path)
        if preflight_status != 404:
            raise ContractError(
                "disposable repository preflight did not return 404; creation was not attempted"
            )

        self.repository_creation_attempted = True
        self.repository_creation_outcome_unknown = True
        self._set_repository_creation_state("attempted_response_unknown")
        created_response = self.operator.request(
            "POST",
            f"/orgs/{quote(self.config.organization)}/repos",
            body={
                "name": self.repository_name,
                "private": True,
                "auto_init": True,
                "delete_branch_on_merge": False,
                "description": "Disposable Extra CODEOWNERS live contract fixture",
            },
            expected=(201,),
        )
        # A returned response proves that GitHub accepted the request even if its body is malformed.
        self.repository_created = True
        self.repository_creation_outcome_unknown = False
        self._set_repository_creation_state("response_confirmed")
        return _object(created_response, "created repository")

    def _ensure_app_access(
        self,
        auth: AppAuth,
        permissions: dict[str, str],
        *,
        repository_selection: str,
    ) -> RestClient:
        client = auth.installation_client(permissions)
        status = client.status("GET", self.repo_path)
        if status == 200:
            return client
        client.close()
        if status != 404 or self.repository_id is None:
            raise ContractError(f"App repository probe returned unexpected status {status}")

        if repository_selection == "all":
            for _ in range(20):
                client = auth.installation_client(permissions)
                status = client.status("GET", self.repo_path)
                if status == 200:
                    return client
                client.close()
                if status != 404:
                    raise ContractError(
                        f"all-repositories App probe returned unexpected status {status}"
                    )
                time.sleep(1)
            raise ContractError(
                "all-repositories GitHub App installation did not gain access to the "
                "new fixture repository"
            )

        if repository_selection != "selected":
            raise ContractError("GitHub App installation returned an unknown repository selection")
        if self.repository_selection is None:
            raise ContractError(
                "selected-repositories installation does not cover the new fixture repository; "
                "prefer an all-repositories installation in the disposable organization or set "
                "EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN to a separate short-lived "
                "classic PAT with repo scope"
            )
        self.repository_selection.request(
            "PUT",
            (
                f"/user/installations/{auth.credentials.installation_id}/repositories/"
                f"{self.repository_id}"
            ),
            expected=(204,),
        )
        for _ in range(20):
            client = auth.installation_client(permissions)
            status = client.status("GET", self.repo_path)
            if status == 200:
                return client
            client.close()
            if status != 404:
                raise ContractError(f"selected-repositories App probe returned status {status}")
            time.sleep(1)
        raise ContractError("GitHub App installation did not gain access to the fixture repository")

    def _create_branch(self, branch: str, sha: str) -> None:
        self.operator.request(
            "POST",
            f"{self.repo_path}/git/refs",
            body={"ref": f"refs/heads/{branch}", "sha": sha},
            expected=(201,),
        )

    def _commit_file(self, branch: str, path: str, content: str) -> str:
        result = _object(
            self.operator.request(
                "PUT",
                f"{self.repo_path}/contents/{quote(path, safe='/')}",
                body={
                    "branch": branch,
                    "content": base64.b64encode(content.encode()).decode(),
                    "message": f"contract: add {path}",
                },
                expected=(201,),
            ),
            "content-creation result",
        )
        return _string(_object(result.get("commit"), "created commit").get("sha"), "commit SHA")

    def _create_pull(self, *, head: str, base: str, title: str) -> int:
        result = _object(
            self.operator.request(
                "POST",
                f"{self.repo_path}/pulls",
                body={
                    "base": base,
                    "head": head,
                    "title": title,
                    "body": "Disposable contract probe.",
                },
                expected=(201,),
            ),
            "created pull request",
        )
        return _integer(result.get("number"), "pull request number")

    def _attempt_in_progress_merge(self, pull_number: int) -> tuple[bool, int]:
        """Attempt the blocked merge and recover the remaining probes if GitHub accepts it."""
        merge_status = self.operator.status(
            "PUT", f"{self.repo_path}/pulls/{pull_number}/merge", body={"merge_method": "squash"}
        )
        blocked = merge_attempt_was_blocked(merge_status)
        if blocked:
            return True, pull_number
        replacement = self._create_pull(
            head="shared-head",
            base="replacement",
            title="Replacement contract PR after unsafe merge",
        )
        return False, replacement

    def _create_check(self, sha: str) -> int:
        assert self.checker is not None
        result = _object(
            self.checker.request(
                "POST",
                f"{self.repo_path}/check-runs",
                body={
                    "name": self.config.check_name,
                    "head_sha": sha,
                    "status": "completed",
                    "conclusion": "success",
                    "external_id": "disposable-live-contract",
                    "output": {
                        "title": "Live contract probe",
                        "summary": "Disposable success used to test GitHub repository rules.",
                    },
                },
                expected=(201,),
            ),
            "created check run",
        )
        return _integer(result.get("id"), "check run ID")

    def _update_check(self, check_id: int, status: str) -> None:
        assert self.checker is not None
        body: JsonObject = {
            "name": self.config.check_name,
            "status": status,
            "output": {
                "title": "Live contract probe",
                "summary": f"Disposable check is {status}.",
            },
        }
        if status == "completed":
            body["conclusion"] = "success"
        self.checker.request(
            "PATCH",
            f"{self.repo_path}/check-runs/{check_id}",
            body=body,
        )

    def _wait_for_merge_outcome(self, pull_number: int, *, preferred: bool | None = None) -> bool:
        """Return true for clean and false for blocked; reject indeterminate states."""
        deadline = time.monotonic() + 90
        observed: list[str] = []
        last_terminal: bool | None = None
        while time.monotonic() < deadline:
            pull = _object(
                self.operator.request("GET", f"{self.repo_path}/pulls/{pull_number}"),
                "pull request",
            )
            value = pull.get("mergeable_state")
            if isinstance(value, str):
                observed.append(value)
                if value == "clean":
                    last_terminal = True
                elif value == "blocked":
                    last_terminal = False
                if last_terminal is not None and (preferred is None or last_terminal is preferred):
                    return last_terminal
            time.sleep(1)
        if last_terminal is not None:
            return last_terminal
        raise ContractError(
            "pull request did not reach a terminal 'clean' or 'blocked' merge state; "
            f"observed {sorted(set(observed))}"
        )

    def _create_rulesets(self) -> None:
        assert self.repository_id is not None
        rule = _status_check_rule(self.config.check_name, self.config.checker.app_id)
        sys.stdout.write(f"Organization ruleset recovery name: {self.organization_ruleset_name}\n")
        self.organization_ruleset_creation_attempted = True
        org_ruleset = _object(
            self.operator.request(
                "POST",
                f"/orgs/{quote(self.config.organization)}/rulesets",
                body={
                    "name": self.organization_ruleset_name,
                    "target": "branch",
                    "enforcement": "active",
                    "bypass_actors": [],
                    "conditions": {
                        "ref_name": {
                            "include": [f"refs/heads/{self.default_branch}"],
                            "exclude": [],
                        },
                        "repository_id": {"repository_ids": [self.repository_id]},
                    },
                    "rules": [rule],
                },
                expected=(201,),
            ),
            "organization ruleset",
        )
        self.organization_ruleset_id = _integer(org_ruleset.get("id"), "organization ruleset ID")
        sys.stdout.write(
            "Created disposable organization ruleset "
            f"{self.organization_ruleset_name!r} (ID {self.organization_ruleset_id})\n"
        )
        repository_ruleset = _object(
            self.operator.request(
                "POST",
                f"{self.repo_path}/rulesets",
                body={
                    "name": "Extra CODEOWNERS live contract",
                    "target": "branch",
                    "enforcement": "active",
                    "bypass_actors": [],
                    "conditions": {
                        "ref_name": {
                            "include": [
                                "refs/heads/alternate",
                                "refs/heads/replacement",
                                "refs/heads/retarget",
                            ],
                            "exclude": [],
                        }
                    },
                    "rules": [rule],
                },
                expected=(201,),
            ),
            "repository ruleset",
        )
        assertions = _object(self.report["assertions"], "report assertions")
        assertions["organization_ruleset_expected_source"] = required_check_has_expected_source(
            org_ruleset,
            context=self.config.check_name,
            app_id=self.config.checker.app_id,
        )
        assertions["repository_ruleset_expected_source"] = required_check_has_expected_source(
            repository_ruleset,
            context=self.config.check_name,
            app_id=self.config.checker.app_id,
        )

    def _exercise_app_review(self, base_sha: str) -> None:
        assertions = _object(self.report["assertions"], "report assertions")
        if self.approver is None:
            assertions["app_review_counts_as_numeric_approval"] = None
            assertions["app_review_attributed_to_bot"] = None
            assertions["numeric_approval_rule_blocks_before_app_review"] = None
            self.report["app_review_note"] = "not run: approver App credentials were not supplied"
            return
        self._create_branch("review-base", base_sha)
        self._create_branch("review-head", base_sha)
        review_sha = self._commit_file("review-head", "review-probe.txt", "review contract\n")
        self.operator.request(
            "POST",
            f"{self.repo_path}/rulesets",
            body={
                "name": "Extra CODEOWNERS App review contract",
                "target": "branch",
                "enforcement": "active",
                "bypass_actors": [],
                "conditions": {"ref_name": {"include": ["refs/heads/review-base"], "exclude": []}},
                "rules": [
                    _status_check_rule(self.config.check_name, self.config.checker.app_id),
                    _review_rule(),
                ],
            },
            expected=(201,),
        )
        pull = self._create_pull(
            head="review-head", base="review-base", title="App numeric approval contract"
        )
        self._create_check(review_sha)
        blocked_before_review = not self._wait_for_merge_outcome(pull, preferred=False)
        assertions["numeric_approval_rule_blocks_before_app_review"] = blocked_before_review
        review = _object(
            self.approver.request(
                "POST",
                f"{self.repo_path}/pulls/{pull}/reviews",
                body={"body": "Disposable App approval contract.", "event": "APPROVE"},
                expected=(200,),
            ),
            "App-authored review",
        )
        actor = _object(review.get("user"), "review actor")
        assertions["app_review_attributed_to_bot"] = actor.get("type") == "Bot"
        clean_after_review = self._wait_for_merge_outcome(pull, preferred=True)
        assertions["app_review_counts_as_numeric_approval"] = (
            blocked_before_review
            and assertions["app_review_attributed_to_bot"] is True
            and clean_after_review
        )

    def _capture_webhook_contracts(self) -> None:
        client = self.checker_auth.jwt_client()
        try:
            deadline = time.monotonic() + WEBHOOK_CAPTURE_SECONDS
            fixture_report = _object(self.report["fixture"], "fixture report")
            selected_installation = fixture_report["checker_repository_selection"] == "selected"
            wanted = {
                ("installation_repositories", "added"),
                ("pull_request", "edited"),
                ("pull_request", "opened"),
            }
            required = {
                ("pull_request", "edited"),
                ("pull_request", "opened"),
            }
            if selected_installation:
                required.add(("installation_repositories", "added"))
            contracts: dict[tuple[str, str], JsonObject] = {}
            inspected_ids: set[int] = set()
            poll_count = 0
            pages_read_total = 0
            last_poll_pages_read = 0
            window_complete = False
            while time.monotonic() < deadline:
                deliveries, window_complete, last_poll_pages_read = delivery_summaries_bounded(
                    client,
                    list_limit=WEBHOOK_DELIVERY_LIST_LIMIT,
                    page_limit=WEBHOOK_DELIVERY_PAGE_LIMIT,
                    page_size=WEBHOOK_DELIVERY_PAGE_SIZE,
                )
                poll_count += 1
                pages_read_total += last_poll_pages_read
                for summary in deliveries:
                    event = summary.get("event")
                    if event not in {"installation_repositories", "pull_request"}:
                        continue
                    pair = _delivery_pair(summary, "summary")
                    if pair not in wanted or pair in contracts:
                        continue
                    summary_installation = _positive_delivery_integer(
                        summary.get("installation_id"),
                        "summary installation ID",
                    )
                    if summary_installation != self.config.checker.installation_id:
                        continue
                    if pair[0] == "pull_request":
                        summary_repository = _positive_delivery_integer(
                            summary.get("repository_id"),
                            "summary repository ID",
                        )
                        if summary_repository != self.repository_id:
                            continue
                    delivery_id = _positive_delivery_integer(summary.get("id"), "summary ID")
                    if delivery_id in inspected_ids:
                        continue
                    inspected_ids.add(delivery_id)
                    detail = client.request("GET", f"/app/hook/deliveries/{delivery_id}")
                    if not isinstance(detail, dict):
                        raise ContractError("GitHub delivery detail is not an object")
                    assert self.repository_id is not None
                    _validate_webhook_detail(
                        summary,
                        detail,
                        expected_pair=pair,
                        installation_id=self.config.checker.installation_id,
                        repository_id=self.repository_id,
                    )
                    if pair == ("installation_repositories", "added") and not (
                        installation_add_targets_repository(
                            detail,
                            repository_id=self.repository_id,
                            installation_id=self.config.checker.installation_id,
                        )
                    ):
                        continue
                    contracts[pair] = sanitize_delivery(detail)
                if required <= contracts.keys():
                    break
                time.sleep(1)
            seen = set(contracts)
            self.report["webhook_contracts"] = [contracts[pair] for pair in sorted(contracts)]
            assertions = _object(self.report["assertions"], "report assertions")
            observation_pairs = {
                "pull_request_opened_delivery_observed": ("pull_request", "opened"),
                "pull_request_retarget_delivery_observed": ("pull_request", "edited"),
            }
            if selected_installation:
                observation_pairs["installation_repository_added_delivery_observed"] = (
                    "installation_repositories",
                    "added",
                )
            else:
                assertions["installation_repository_added_delivery_observed"] = None

            incomplete_observations: list[str] = []
            for observation, pair in observation_pairs.items():
                if pair in seen:
                    assertions[observation] = True
                elif window_complete:
                    assertions[observation] = False
                else:
                    assertions.pop(observation, None)
                    incomplete_observations.append(observation)

            self.report["webhook_capture"] = {
                "delivery_list_limit": WEBHOOK_DELIVERY_LIST_LIMIT,
                "delivery_page_limit": WEBHOOK_DELIVERY_PAGE_LIMIT,
                "delivery_page_size": WEBHOOK_DELIVERY_PAGE_SIZE,
                "delivery_window_complete": window_complete,
                "incomplete_observations": sorted(incomplete_observations),
                "last_poll_pages_read": last_poll_pages_read,
                "pages_read_total": pages_read_total,
                "poll_count": poll_count,
            }
            opened_observed = assertions.get("pull_request_opened_delivery_observed") is True
            retarget_observed = assertions.get("pull_request_retarget_delivery_observed") is True
            if not opened_observed or not retarget_observed:
                raise ContractError(
                    "the checker App did not expose both pull_request.opened and "
                    "pull_request.edited deliveries within the bounded capture window"
                )
        finally:
            client.close()

    def run(self) -> JsonObject:
        fixture_report = _object(self.report["fixture"], "fixture report")
        checker_repository_selection = self.checker_auth.repository_selection()
        approver_repository_selection = (
            self.approver_auth.repository_selection() if self.approver_auth is not None else None
        )
        fixture_report["checker_repository_selection"] = checker_repository_selection
        fixture_report["approver_repository_selection"] = approver_repository_selection
        created = self._create_repository()
        self.repository_id = _integer(created.get("id"), "repository ID")
        sys.stdout.write(f"Created disposable repository https://github.com/{self.repository}\n")
        self.default_branch = _string(created.get("default_branch"), "default branch")
        base_sha = ""
        for _ in range(30):
            try:
                ref = _object(
                    self.operator.request(
                        "GET", f"{self.repo_path}/git/ref/heads/{quote(self.default_branch)}"
                    ),
                    "default branch ref",
                )
                base_sha = _string(_object(ref.get("object"), "ref object").get("sha"), "base SHA")
                break
            except ContractError:
                time.sleep(1)
        if not base_sha:
            raise ContractError("GitHub did not initialize the fixture default branch")

        self.checker = self._ensure_app_access(
            self.checker_auth,
            {"checks": "write", "contents": "read"},
            repository_selection=checker_repository_selection,
        )
        if self.approver_auth is not None:
            assert approver_repository_selection is not None
            self.approver = self._ensure_app_access(
                self.approver_auth,
                {"contents": "read", "pull_requests": "write"},
                repository_selection=approver_repository_selection,
            )

        for branch in ("alternate", "replacement", "retarget", "shared-head"):
            self._create_branch(branch, base_sha)
        head_sha = self._commit_file("shared-head", "contract-probe.txt", "shared head\n")
        check_id = self._create_check(head_sha)
        self._create_rulesets()

        first = self._create_pull(
            head="shared-head", base=self.default_branch, title="First contract PR"
        )
        if not self._wait_for_merge_outcome(first, preferred=True):
            raise ContractError(
                "indeterminate transition: the completed successful check did not satisfy "
                "the fixture's required-check precondition"
            )
        self._update_check(check_id, "in_progress")
        transition_blocked = not self._wait_for_merge_outcome(first, preferred=False)
        merge_attempt_blocked = False
        if transition_blocked:
            merge_attempt_blocked, first = self._attempt_in_progress_merge(first)
        assertions = _object(self.report["assertions"], "report assertions")
        assertions["in_progress_merge_state_blocked"] = transition_blocked
        assertions["in_progress_merge_attempt_blocked"] = (
            merge_attempt_blocked if transition_blocked else None
        )
        assertions["completed_success_to_in_progress_blocks_merge"] = (
            transition_blocked and merge_attempt_blocked
        )
        self._update_check(check_id, "completed")
        if not self._wait_for_merge_outcome(first, preferred=True):
            raise ContractError(
                "indeterminate shared-head probe: the restored successful check did not satisfy "
                "the first pull request"
            )
        second = self._create_pull(
            head="shared-head", base="alternate", title="Shared-head contract PR"
        )
        self._wait_for_merge_outcome(second)
        time.sleep(self.config.observation_seconds)
        assertions["shared_head_inherits_success_before_invalidation"] = (
            self._wait_for_merge_outcome(second)
        )

        self._update_check(check_id, "in_progress")
        first_blocked = not self._wait_for_merge_outcome(first, preferred=False)
        second_blocked = not self._wait_for_merge_outcome(second, preferred=False)
        assertions["shared_head_invalidation_blocks_both_pull_requests"] = (
            first_blocked and second_blocked
        )

        self._update_check(check_id, "completed")
        if not self._wait_for_merge_outcome(second, preferred=True):
            raise ContractError(
                "indeterminate retarget probe: the restored successful check did not satisfy "
                "the shared-head pull request"
            )
        self.operator.request(
            "PATCH",
            f"{self.repo_path}/pulls/{second}",
            body={"base": "retarget"},
        )
        self._wait_for_merge_outcome(second)
        time.sleep(self.config.observation_seconds)
        assertions["retarget_inherits_commit_scoped_success_before_invalidation"] = (
            self._wait_for_merge_outcome(second)
        )

        self._exercise_app_review(base_sha)
        self._capture_webhook_contracts()
        self.report["interpretation"] = contract_interpretation(assertions)
        self.report["finished_at"] = datetime.now(UTC).isoformat()
        return self.report

    def close(self) -> list[str]:
        errors: list[str] = []

        def record_failure(operation: str, error: Exception) -> None:
            errors.append(f"{operation} failed ({type(error).__name__})")

        if self.config.keep_repository:
            if getattr(self, "repository_creation_outcome_unknown", False):
                self._set_repository_creation_state("response_unknown_retained")
            elif getattr(self, "repository_created", False):
                self._set_repository_creation_state("response_confirmed_retained")
            sys.stdout.write(
                "Cleanup disabled; retaining any created fixture repository "
                f"https://github.com/{self.repository} and organization ruleset "
                f"{self.organization_ruleset_name!r}\n"
            )
        else:
            ruleset_id = self.organization_ruleset_id
            ruleset_attempted = getattr(
                self,
                "organization_ruleset_creation_attempted",
                ruleset_id is not None,
            )
            if ruleset_id is None and ruleset_attempted:
                try:
                    rulesets = self.operator.request(
                        "GET",
                        f"/orgs/{quote(self.config.organization)}/rulesets",
                        params={"per_page": 100},
                    )
                    if not isinstance(rulesets, list):
                        raise ContractError("GitHub organization ruleset listing is not a list")
                    matching_ids = [
                        _integer(item.get("id"), "organization ruleset ID")
                        for item in rulesets
                        if isinstance(item, dict)
                        and item.get("name") == self.organization_ruleset_name
                        and isinstance(item.get("id"), int)
                        and not isinstance(item.get("id"), bool)
                    ]
                    if len(matching_ids) != 1:
                        raise ContractError(
                            "GitHub organization ruleset recovery did not find exactly one rule"
                        )
                    ruleset_id = matching_ids[0]
                except Exception as error:
                    record_failure("organization ruleset discovery", error)
            if ruleset_id is not None:
                try:
                    self.operator.request(
                        "DELETE",
                        (f"/orgs/{quote(self.config.organization)}/rulesets/{ruleset_id}"),
                        expected=(204,),
                    )
                except Exception as error:
                    record_failure("organization ruleset cleanup", error)
            creation_outcome_unknown = getattr(
                self,
                "repository_creation_outcome_unknown",
                False,
            )
            if creation_outcome_unknown:
                try:
                    for attempt in range(REPOSITORY_RECOVERY_ATTEMPTS):
                        recovery_status = self.operator.status("GET", self.repo_path)
                        if recovery_status == 200:
                            self.operator.request("DELETE", self.repo_path, expected=(204,))
                            self.repository_creation_outcome_unknown = False
                            self.repository_created = False
                            self._set_repository_creation_state("response_unknown_cleaned")
                            break
                        if recovery_status != 404:
                            raise ContractError(
                                "repository recovery probe returned an unexpected status"
                            )
                        if attempt + 1 < REPOSITORY_RECOVERY_ATTEMPTS:
                            time.sleep(REPOSITORY_RECOVERY_INTERVAL_SECONDS)
                    else:
                        # A transport failure leaves the POST outcome unknowable.
                        # Repeated 404s reduce the chance of delayed visibility but
                        # cannot prove that GitHub never accepted the create.
                        raise ContractError(
                            "repository remained absent during bounded recovery; "
                            "manual verification is required"
                        )
                except Exception as error:
                    self._set_repository_creation_state("manual_cleanup_required")
                    sys.stderr.write(
                        "Manual repository verification required: "
                        f"https://github.com/{self.repository}\n"
                    )
                    record_failure("repository recovery", error)
            elif getattr(self, "repository_created", False):
                try:
                    self.operator.request("DELETE", self.repo_path, expected=(204,))
                    self.repository_created = False
                    self._set_repository_creation_state("response_confirmed_cleaned")
                except Exception as error:
                    self._set_repository_creation_state("manual_cleanup_required")
                    record_failure("repository cleanup", error)
        clients = (
            ("checker client close", getattr(self, "checker", None)),
            ("approver client close", getattr(self, "approver", None)),
            ("repository-selection client close", getattr(self, "repository_selection", None)),
            ("operator client close", self.operator),
        )
        for operation, client in clients:
            if client is None:
                continue
            try:
                client.close()
            except Exception as error:
                record_failure(operation, error)
        return errors


def main() -> int:
    """Run the fixture and write one sanitized JSON report."""
    try:
        config = Config.from_environment()
    except ContractError as error:
        sys.stderr.write(f"configuration error: {error}\n")
        return 2
    try:
        fixture = Fixture(config)
    except (OSError, ValueError) as error:
        sys.stderr.write(f"credential error: {error}\n")
        return 2
    report: JsonObject
    exit_code = 0
    try:
        report = fixture.run()
    except KeyboardInterrupt:
        report = fixture.report
        report["finished_at"] = datetime.now(UTC).isoformat()
        report["result"] = "interrupted"
        sys.stderr.write("live contract interrupted; cleaning up fixture resources\n")
        exit_code = 130
    except Exception as error:
        report = fixture.report
        report["finished_at"] = datetime.now(UTC).isoformat()
        report["result"] = "failed"
        report["failure_type"] = type(error).__name__
        sys.stderr.write(f"live contract failed: {error}\n")
        exit_code = 1
    else:
        report["result"] = "observed"
    try:
        cleanup_errors = fixture.close()
    except Exception as error:
        cleanup_errors = [f"fixture cleanup failed ({type(error).__name__})"]
    fixture_report = report.get("fixture")
    repository_creation_state = (
        fixture_report.get("repository_creation_state")
        if isinstance(fixture_report, dict)
        else None
    )
    if (
        not config.keep_repository
        and repository_creation_state not in REPOSITORY_CLEANUP_STATES
        and not cleanup_errors
    ):
        cleanup_errors.append("repository cleanup accounting failed (ContractError)")
    report["cleanup_succeeded"] = (
        not cleanup_errors
        and not config.keep_repository
        and repository_creation_state in REPOSITORY_CLEANUP_STATES
    )
    if cleanup_errors:
        report["cleanup_failure_count"] = len(cleanup_errors)
        for cleanup_error in cleanup_errors:
            sys.stderr.write(f"{cleanup_error}\n")
        exit_code = 1
    completeness = evidence_completeness(
        report,
        approver_configured=config.approver is not None,
    )
    report["evidence_completeness"] = completeness
    if exit_code == 0 and completeness.get("configured_run_complete") is not True:
        exit_code = 1
    config.report_file.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    sys.stdout.write(f"Wrote sanitized report to {config.report_file}\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
