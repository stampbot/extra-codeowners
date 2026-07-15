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
from urllib.parse import quote

import httpx
import jwt

API_VERSION: Final = "2026-03-10"
API_URL: Final = "https://api.github.com"
CONFIRMATION_PREFIX: Final = "delete-disposable-repository-in:"
REPORT_SCHEMA_VERSION: Final = 1

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
        return cls(
            organization=organization,
            operator_token=_required_env("EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN"),
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

    def request(
        self,
        method: str,
        path: str,
        *,
        body: JsonObject | None = None,
        params: dict[str, str | int] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        response = self._http.request(method, path, json=body, params=params)
        if response.status_code not in expected:
            message = ""
            try:
                parsed = response.json()
                if isinstance(parsed, dict) and isinstance(parsed.get("message"), str):
                    message = f": {parsed['message'][:300]}"
            except ValueError:
                pass
            raise ContractError(
                f"GitHub API {method} {path} returned {response.status_code}{message}"
            )
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def status(
        self,
        method: str,
        path: str,
        *,
        body: JsonObject | None = None,
    ) -> int:
        return self._http.request(method, path, json=body).status_code


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


def sanitize_delivery(delivery: JsonObject) -> JsonObject:
    """Reduce a raw App delivery to metadata and payload field names."""
    request = delivery.get("request")
    payload = request.get("payload") if isinstance(request, dict) else None
    shape: JsonObject = {}
    if isinstance(payload, dict):
        shape["root_keys"] = sorted(str(key) for key in payload)
        for name in (
            "installation",
            "organization",
            "pull_request",
            "repositories_added",
            "repositories_removed",
            "repository",
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
        "redelivery": delivery.get("redelivery") is True,
        "status_code": (
            delivery.get("status_code") if isinstance(delivery.get("status_code"), int) else None
        ),
    }


def delivery_targets_repository(delivery: JsonObject, repository_id: int) -> bool:
    """Return whether a delivery payload identifies the disposable repository."""
    request = delivery.get("request")
    payload = request.get("payload") if isinstance(request, dict) else None
    if not isinstance(payload, dict):
        return False
    repository = payload.get("repository")
    if isinstance(repository, dict) and repository.get("id") == repository_id:
        return True
    for field in ("repositories_added", "repositories_removed"):
        repositories = payload.get(field)
        if isinstance(repositories, list) and any(
            isinstance(item, dict) and item.get("id") == repository_id for item in repositories
        ):
            return True
    return False


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
        self.checker_auth = AppAuth(config.checker)
        self.checker: RestClient | None = None
        self.approver_auth = AppAuth(config.approver) if config.approver is not None else None
        self.approver: RestClient | None = None
        suffix = secrets.token_hex(4)
        self.repository_name = f"extra-codeowners-contract-{suffix}"
        self.repository = f"{config.organization}/{self.repository_name}"
        self.repository_created = False
        self.repository_id: int | None = None
        self.default_branch = ""
        self.organization_ruleset_name = f"Extra CODEOWNERS contract {self.repository_name}"
        self.organization_ruleset_id: int | None = None
        self.report: JsonObject = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "api_version": API_VERSION,
            "source_revision": config.source_revision,
            "started_at": datetime.now(UTC).isoformat(),
            "fixture": {
                "approver_repository_selection": None,
                "checker_repository_selection": None,
                "private_repository": True,
                "repository_kept": config.keep_repository,
            },
            "assertions": {},
            "webhook_contracts": [],
        }

    @property
    def repo_path(self) -> str:
        return f"/repos/{quote(self.repository, safe='/')}"

    def _ensure_app_access(self, auth: AppAuth, permissions: dict[str, str]) -> RestClient:
        client = auth.installation_client(permissions)
        status = client.status("GET", self.repo_path)
        if status == 200:
            return client
        client.close()
        if status != 404 or self.repository_id is None:
            raise ContractError(f"App repository probe returned unexpected status {status}")
        self.operator.request(
            "PUT",
            (
                f"/user/installations/{auth.credentials.installation_id}/repositories/"
                f"{self.repository_id}"
            ),
            expected=(204,),
        )
        for _ in range(20):
            client = auth.installation_client(permissions)
            if client.status("GET", self.repo_path) == 200:
                return client
            client.close()
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

    def _wait_for_merge_state(self, pull_number: int, expected: str) -> str:
        deadline = time.monotonic() + 90
        observed: list[str] = []
        while time.monotonic() < deadline:
            pull = _object(
                self.operator.request("GET", f"{self.repo_path}/pulls/{pull_number}"),
                "pull request",
            )
            value = pull.get("mergeable_state")
            if isinstance(value, str):
                observed.append(value)
                if value == expected:
                    return value
            time.sleep(1)
        raise ContractError(
            f"pull request did not become {expected!r}; observed {sorted(set(observed))}"
        )

    def _create_rulesets(self) -> None:
        assert self.repository_id is not None
        rule = _status_check_rule(self.config.check_name, self.config.checker.app_id)
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
        if not all(assertions.values()):
            raise ContractError("GitHub did not preserve the expected App source in both rulesets")

    def _exercise_app_review(self, base_sha: str) -> None:
        assertions = _object(self.report["assertions"], "report assertions")
        if self.approver is None:
            assertions["app_review_counts_as_numeric_approval"] = None
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
        self._wait_for_merge_state(pull, "blocked")
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
        if actor.get("type") != "Bot":
            raise ContractError("GitHub did not attribute the approving App review to a Bot actor")
        self._wait_for_merge_state(pull, "clean")
        assertions["app_review_counts_as_numeric_approval"] = True

    def _capture_webhook_contracts(self) -> None:
        client = self.checker_auth.jwt_client()
        try:
            deadline = time.monotonic() + 30
            matching: list[JsonObject] = []
            while time.monotonic() < deadline:
                deliveries = client.request("GET", "/app/hook/deliveries", params={"per_page": 100})
                if isinstance(deliveries, list):
                    summaries = [item for item in deliveries if isinstance(item, dict)]
                    matching = [
                        item
                        for item in summaries
                        if item.get("installation_id") == self.config.checker.installation_id
                        and (
                            item.get("repository_id") == self.repository_id
                            or item.get("event") == "installation_repositories"
                        )
                    ]
                actions = {(item.get("event"), item.get("action")) for item in matching}
                if ("pull_request", "opened") in actions and ("pull_request", "edited") in actions:
                    break
                time.sleep(1)
            selected: list[JsonObject] = []
            wanted = {
                ("installation_repositories", "added"),
                ("pull_request", "edited"),
                ("pull_request", "opened"),
            }
            seen: set[tuple[Any, Any]] = set()
            for summary in matching:
                key = (summary.get("event"), summary.get("action"))
                delivery_id = summary.get("id")
                if key not in wanted or key in seen or not isinstance(delivery_id, int):
                    continue
                detail = client.request("GET", f"/app/hook/deliveries/{delivery_id}")
                if isinstance(detail, dict) and (
                    key != ("installation_repositories", "added")
                    or (
                        self.repository_id is not None
                        and delivery_targets_repository(detail, self.repository_id)
                    )
                ):
                    selected.append(sanitize_delivery(detail))
                    seen.add(key)
            self.report["webhook_contracts"] = selected
            assertions = _object(self.report["assertions"], "report assertions")
            opened_observed = ("pull_request", "opened") in seen
            retarget_observed = ("pull_request", "edited") in seen
            assertions["pull_request_opened_delivery_observed"] = opened_observed
            assertions["pull_request_retarget_delivery_observed"] = retarget_observed
            assertions["installation_repository_added_delivery_observed"] = (
                "installation_repositories",
                "added",
            ) in seen
            if not opened_observed or not retarget_observed:
                raise ContractError(
                    "the checker App did not expose both pull_request.opened and "
                    "pull_request.edited deliveries within 30 seconds"
                )
        finally:
            client.close()

    def run(self) -> JsonObject:
        fixture_report = _object(self.report["fixture"], "fixture report")
        fixture_report["checker_repository_selection"] = self.checker_auth.repository_selection()
        fixture_report["approver_repository_selection"] = (
            self.approver_auth.repository_selection() if self.approver_auth is not None else None
        )
        created_response = self.operator.request(
            "POST",
            f"/orgs/{quote(self.config.organization)}/repos",
            body={
                "name": self.repository_name,
                "private": True,
                "auto_init": True,
                "delete_branch_on_merge": True,
                "description": "Disposable Extra CODEOWNERS live contract fixture",
            },
            expected=(201,),
        )
        self.repository_created = True
        created = _object(created_response, "created repository")
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
            self.checker_auth, {"checks": "write", "contents": "read"}
        )
        if self.approver_auth is not None:
            self.approver = self._ensure_app_access(
                self.approver_auth, {"contents": "read", "pull_requests": "write"}
            )

        for branch in ("alternate", "retarget", "shared-head"):
            self._create_branch(branch, base_sha)
        head_sha = self._commit_file("shared-head", "contract-probe.txt", "shared head\n")
        self._create_rulesets()

        first = self._create_pull(
            head="shared-head", base=self.default_branch, title="First contract PR"
        )
        check_id = self._create_check(head_sha)
        self._wait_for_merge_state(first, "clean")
        self._update_check(check_id, "in_progress")
        self._wait_for_merge_state(first, "blocked")
        merge_status = self.operator.status(
            "PUT", f"{self.repo_path}/pulls/{first}/merge", body={"merge_method": "squash"}
        )
        if merge_status not in {405, 409}:
            raise ContractError(
                "an in-progress required check did not block the disposable merge; "
                f"GitHub returned {merge_status}"
            )
        assertions = _object(self.report["assertions"], "report assertions")
        assertions["completed_success_to_in_progress_blocks_merge"] = True

        self._update_check(check_id, "completed")
        self._wait_for_merge_state(first, "clean")
        second = self._create_pull(
            head="shared-head", base="alternate", title="Shared-head contract PR"
        )
        self._wait_for_merge_state(second, "clean")
        time.sleep(self.config.observation_seconds)
        self._wait_for_merge_state(second, "clean")
        assertions["shared_head_inherits_success_before_invalidation"] = True

        self._update_check(check_id, "in_progress")
        self._wait_for_merge_state(first, "blocked")
        self._wait_for_merge_state(second, "blocked")
        assertions["shared_head_invalidation_blocks_both_pull_requests"] = True

        self._update_check(check_id, "completed")
        self._wait_for_merge_state(second, "clean")
        self.operator.request(
            "PATCH",
            f"{self.repo_path}/pulls/{second}",
            body={"base": "retarget"},
        )
        self._wait_for_merge_state(second, "clean")
        time.sleep(self.config.observation_seconds)
        self._wait_for_merge_state(second, "clean")
        assertions["retarget_inherits_commit_scoped_success_before_invalidation"] = True

        self._exercise_app_review(base_sha)
        self._capture_webhook_contracts()
        self.report["finished_at"] = datetime.now(UTC).isoformat()
        return self.report

    def close(self) -> list[str]:
        errors: list[str] = []
        if self.config.keep_repository:
            sys.stdout.write(f"Keeping fixture repository https://github.com/{self.repository}\n")
        else:
            ruleset_id = self.organization_ruleset_id
            if ruleset_id is None and self.repository_created:
                try:
                    rulesets = self.operator.request(
                        "GET",
                        f"/orgs/{quote(self.config.organization)}/rulesets",
                        params={"per_page": 100},
                    )
                    if isinstance(rulesets, list):
                        matching_ids = [
                            _integer(item.get("id"), "organization ruleset ID")
                            for item in rulesets
                            if isinstance(item, dict)
                            and item.get("name") == self.organization_ruleset_name
                            and isinstance(item.get("id"), int)
                            and not isinstance(item.get("id"), bool)
                        ]
                        if len(matching_ids) == 1:
                            ruleset_id = matching_ids[0]
                except ContractError as error:
                    errors.append(f"organization ruleset discovery failed: {error}")
            if ruleset_id is not None:
                try:
                    self.operator.request(
                        "DELETE",
                        (f"/orgs/{quote(self.config.organization)}/rulesets/{ruleset_id}"),
                        expected=(204,),
                    )
                except ContractError as error:
                    errors.append(f"organization ruleset cleanup failed: {error}")
            if self.repository_created:
                try:
                    self.operator.request("DELETE", self.repo_path, expected=(204,))
                except ContractError as error:
                    errors.append(f"repository cleanup failed: {error}")
        if self.checker is not None:
            self.checker.close()
        if self.approver is not None:
            self.approver.close()
        self.operator.close()
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
    cleanup_errors = fixture.close()
    report["cleanup_succeeded"] = not cleanup_errors and not config.keep_repository
    if cleanup_errors:
        report["cleanup_failure_count"] = len(cleanup_errors)
        for cleanup_error in cleanup_errors:
            sys.stderr.write(f"{cleanup_error}\n")
        exit_code = 1
    config.report_file.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    sys.stdout.write(f"Wrote sanitized report to {config.report_file}\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
