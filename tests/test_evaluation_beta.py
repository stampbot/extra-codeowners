"""Tests for the disposable evaluation-beta preflight."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError
from sqlalchemy.pool import NullPool

from extra_codeowners import __version__
from extra_codeowners.database import DATABASE_MIGRATION_HEAD
from tools import evaluation_beta as beta
from tools.live_github_contract import API_URL


def config_values(tmp_path: Path) -> dict[str, object]:
    """Return one complete non-secret preflight configuration."""

    return {
        "schema_version": 1,
        "source_revision": "a" * 40,
        "source_signer_fingerprint": "B" * 40,
        "source_checkout": tmp_path,
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "uv_version": "0.11.28",
        "extra_codeowners_version": __version__,
        "postgres_server_version_num": 170006,
        "organization_id": 10,
        "target_repository": "example/beta-target",
        "target_repository_id": 11,
        "organization_policy_repository": "example/.github",
        "organization_policy_repository_id": 12,
        "target_default_branch": "main",
        "target_default_branch_sha": "c" * 40,
        "organization_policy_default_branch": "main",
        "organization_policy_default_branch_sha": "d" * 40,
        "checker_app_id": 101,
        "checker_app_slug": "extra-codeowners-beta",
        "checker_installation_id": 1001,
        "approver_app_id": 202,
        "approver_app_slug": "approver-beta",
        "approver_installation_id": 2002,
        "approver_bot_user_id": 303,
        "service_url": "https://beta.example.test",
        "checker_webhook_url": "https://beta.example.test/webhooks/github",
        "policy_path": ".github/extra-codeowners.toml",
        "delegation_test_path": "docs/beta-probe.md",
        "delegation_test_labels": ["bot-approved"],
    }


def config(tmp_path: Path, **updates: object) -> beta.BetaConfig:
    values = config_values(tmp_path)
    values.update(updates)
    return beta.BetaConfig.model_validate(values)


ORGANIZATION_POLICY = b"""\
schema_version = 1

[apps.approver]
slug = "approver-beta"
app_id = 202
bot_user_id = 303
"""

REPOSITORY_POLICY = b"""\
schema_version = 1
enabled = true

[[delegations]]
app = "approver"
paths = ["docs/beta-probe.md"]
for_owners = ["@example/maintainers"]
required_labels = ["bot-approved"]
"""


class FakeGitHub:
    """Complete in-memory GitHub evidence for one passing preflight."""

    def __init__(self) -> None:
        self.installations: list[tuple[str, dict[str, int], int, str | None]] = []
        self.closed = False
        self.private_repository: str | None = None
        self.classic: beta.JsonObject | None = None
        self.branch_head_calls: dict[str, int] = {}
        self.repository_calls: dict[str, int] = {}
        self.move_repository_on_final: str | None = None
        self.replace_repository_on_final: str | None = None
        self.labels = {"bot-approved"}
        self.bot_login = "approver-beta[bot]"
        self.repository_archived: object = False
        self.repository_disabled: object = False
        self.rules: list[beta.JsonObject] = [
            {
                "type": "pull_request",
                "parameters": {
                    "require_code_owner_review": True,
                    "required_approving_review_count": 1,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{"context": "unrelated / test", "integration_id": 9}]
                },
            },
        ]
        self.errors: list[beta.JsonObject] = []
        self.files = {
            (
                "example/beta-target",
                ".github/CODEOWNERS",
                "c" * 40,
            ): b"* @example/maintainers\n",
            (
                "example/beta-target",
                ".github/extra-codeowners.toml",
                "c" * 40,
            ): REPOSITORY_POLICY,
            (
                "example/.github",
                ".github/extra-codeowners.toml",
                "d" * 40,
            ): ORGANIZATION_POLICY,
            (
                "example/beta-target",
                "docs/beta-probe.md",
                "c" * 40,
            ): b"# Disposable test path\n",
        }

    def verify_installation(
        self,
        identity: beta.AppIdentity,
        expected_repositories: Mapping[str, int],
        *,
        organization_id: int,
        checker_webhook_url: str | None,
    ) -> beta.Evidence:
        self.installations.append(
            (
                identity.role,
                dict(expected_repositories),
                organization_id,
                checker_webhook_url,
            )
        )
        return {
            "app_id": identity.app_id,
            "app_slug": identity.slug,
            "installation_id": identity.installation_id,
            "repository_selection": "selected",
            "repository_count": len(expected_repositories),
            "repository_ids": dict(expected_repositories),
            "token_permissions": "metadata:read",
        }

    def repository(self, full_name: str) -> beta.JsonObject:
        self.repository_calls[full_name] = self.repository_calls.get(full_name, 0) + 1
        observed_name = full_name
        if full_name == self.replace_repository_on_final and self.repository_calls[full_name] > 1:
            observed_name = "example/replacement"
        return {
            "id": 11 if full_name.endswith("beta-target") else 12,
            "full_name": observed_name,
            "private": full_name == self.private_repository,
            "visibility": "private" if full_name == self.private_repository else "public",
            "archived": self.repository_archived,
            "disabled": self.repository_disabled,
            "default_branch": "main",
            "owner": {"id": 10, "login": "example", "type": "Organization"},
        }

    def branch_head(self, full_name: str, branch: str) -> str:
        assert branch == "main"
        self.branch_head_calls[full_name] = self.branch_head_calls.get(full_name, 0) + 1
        if full_name == self.move_repository_on_final and self.branch_head_calls[full_name] > 1:
            return "e" * 40
        return "c" * 40 if full_name.endswith("beta-target") else "d" * 40

    def branch_rules(self, full_name: str, branch: str) -> list[beta.JsonObject]:
        assert full_name == "example/beta-target"
        assert branch == "main"
        return self.rules

    def classic_branch_protection(
        self,
        full_name: str,
        branch: str,
    ) -> beta.JsonObject | None:
        assert full_name == "example/beta-target"
        assert branch == "main"
        return self.classic

    def codeowners_errors(self, full_name: str, ref: str) -> list[beta.JsonObject]:
        assert full_name == "example/beta-target"
        assert ref == "c" * 40
        return self.errors

    def repository_file(self, full_name: str, path: str, ref: str) -> bytes:
        return self.files[(full_name, path, ref)]

    def bot_user(self, user_id: int) -> beta.JsonObject:
        assert user_id == 303
        return {
            "id": 303,
            "login": self.bot_login,
            "type": "Bot",
            "site_admin": False,
        }

    def repository_label(self, full_name: str, label: str) -> beta.JsonObject:
        assert full_name == "example/beta-target"
        if label not in self.labels:
            raise beta.PreflightError(f"label {label} not found")
        return {"name": label}

    def close(self) -> None:
        self.closed = True


class FakeService:
    """Passing deployment responses."""

    def __init__(self, version: str = __version__) -> None:
        self.version = version
        self.worker_enabled = True
        self.metric = 0
        self.closed = False
        self.runtime_identity: beta.JsonObject = {
            "schema_version": 1,
            "environment": "production",
            "github_api_url": f"{API_URL}/",
            "github_app_id": 101,
            "database_backend": "postgresql",
            "check_name": "Extra CODEOWNERS / approval",
            "policy_path": ".github/extra-codeowners.toml",
            "organization_policy_repository_name": ".github",
            "application_version": version,
            "build_revision": None,
        }

    def json(self, path: str) -> beta.JsonObject:
        if path == "/":
            return {"version": self.version}
        if path == "/api/runtime-identity":
            return dict(self.runtime_identity)
        if path == "/health/live":
            return {
                "status": "alive",
                "worker_enabled": self.worker_enabled,
                "reconciler_enabled": True,
                "worker": True,
                "reconciler": True,
            }
        if path == "/health/ready":
            return {
                "status": "ready",
                "github_credentials": True,
                "database": True,
                "worker_enabled": self.worker_enabled,
                "reconciler_enabled": True,
                "worker": True,
                "reconciler": True,
            }
        raise AssertionError(path)

    def metrics(self) -> str:
        return (
            "# HELP extra_codeowners_insecure_changes_enabled unsafe mode\n"
            "# TYPE extra_codeowners_insecure_changes_enabled gauge\n"
            f"extra_codeowners_insecure_changes_enabled {self.metric}\n"
        )

    def close(self) -> None:
        self.closed = True


class FakeSystem:
    """Passing source, tool, and PostgreSQL evidence."""

    def __init__(self) -> None:
        self.source_error: beta.PreflightError | None = None
        self.database_error: beta.PreflightError | None = None

    def source(self, loaded: beta.BetaConfig) -> beta.Evidence:
        if self.source_error is not None:
            raise self.source_error
        return {
            "scope": "local-checkout-self-consistency",
            "independent_source_attestation": False,
            "revision": loaded.source_revision,
            "signature": "valid-and-exact-fingerprint-match",
            "signer_fingerprint": loaded.source_signer_fingerprint,
            "checkout_clean_observations": 2,
        }

    def tools(self, loaded: beta.BetaConfig) -> beta.Evidence:
        return {
            "python": loaded.python_version,
            "uv": loaded.uv_version,
            "extra_codeowners": loaded.extra_codeowners_version,
            "package_loaded_from_checkout": True,
        }

    def database(self, loaded: beta.BetaConfig) -> beta.Evidence:
        if self.database_error is not None:
            raise self.database_error
        return {
            "backend": "postgresql",
            "server_version_num": loaded.postgres_server_version_num,
            "database_revision": DATABASE_MIGRATION_HEAD,
            "schema_contract": "required-release-contract",
            "transaction_mode": "read-only",
            "search_path": "public",
            "statement_timeout_ms": 5000,
            "lock_timeout_ms": 5000,
            "idle_in_transaction_session_timeout_ms": 5000,
        }


@pytest.fixture
def app_key_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checker = tmp_path / "checker.pem"
    approver = tmp_path / "approver.pem"
    checker.write_text("checker")
    approver.write_text("approver")
    checker.chmod(0o600)
    approver.chmod(0o600)
    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE",
        str(checker),
    )
    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_BETA_APPROVER_PRIVATE_KEY_FILE",
        str(approver),
    )


def result(report: beta.JsonObject, check_id: str) -> beta.JsonObject:
    return next(check for check in report["checks"] if check["id"] == check_id)


def test_complete_preflight_passes_with_exact_disposable_scope(
    tmp_path: Path,
    app_key_files: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    github = FakeGitHub()
    service = FakeService()
    system = FakeSystem()
    monkeypatch.setenv("GH_TOKEN", "must-not-appear")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-appear-either")
    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_BETA_DATABASE_URL",
        "postgresql://operator:database-secret@example.invalid/beta",
    )

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=service,
        system=system,
    )

    assert report["preflight_passed"] is True
    assert report["result"] == "passed"
    assert isinstance(report["run_nonce"], str)
    assert len(report["run_nonce"]) == 32
    assert len(report["checks"]) == 11
    assert {check["outcome"] for check in report["checks"]} == {"passed"}
    assert github.installations == [
        (
            "checker",
            {"example/beta-target": 11, "example/.github": 12},
            10,
            "https://beta.example.test/webhooks/github",
        ),
        ("approver", {"example/beta-target": 11}, 10, None),
    ]
    assert github.branch_head_calls == {
        "example/beta-target": 2,
        "example/.github": 2,
    }
    assert github.repository_calls == {
        "example/beta-target": 2,
        "example/.github": 2,
    }
    assert report["scope"]["deployment_kind"] == "source"
    serialized = json.dumps(report)
    assert "must-not-appear" not in serialized
    assert "database-secret" not in serialized


def test_independent_failure_is_recorded_without_skipping_other_checks(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    system = FakeSystem()
    system.source_error = beta.PreflightError("revision mismatch")

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=FakeGitHub(),
        service=FakeService(),
        system=system,
    )

    assert report["preflight_passed"] is False
    assert result(report, "source") == {
        "id": "source",
        "outcome": "failed",
        "failure": "revision mismatch",
    }
    assert result(report, "tool_versions")["outcome"] == "passed"
    assert result(report, "postgresql")["outcome"] == "passed"


def test_private_policy_repository_fails_public_repository_check(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    github = FakeGitHub()
    github.private_repository = "example/.github"

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "public_repositories")["outcome"] == "failed"
    assert "not public" in result(report, "public_repositories")["failure"]


@pytest.mark.parametrize(
    ("archived", "disabled"),
    [(True, False), (False, True), (None, False), (False, None)],
)
def test_unavailable_repository_fails_public_repository_check(
    tmp_path: Path,
    app_key_files: None,
    archived: object,
    disabled: object,
) -> None:
    github = FakeGitHub()
    github.repository_archived = archived
    github.repository_disabled = disabled

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "public_repositories")["outcome"] == "failed"
    assert "archived, disabled" in result(report, "public_repositories")["failure"]


@pytest.mark.parametrize(
    ("rules", "failure"),
    [
        ([], "native code-owner review is not active"),
        (
            [
                {
                    "type": "pull_request",
                    "parameters": {
                        "require_code_owner_review": True,
                        "required_approving_review_count": 1,
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [{"context": "Extra CODEOWNERS / approval"}]
                    },
                },
            ],
            "already a required check",
        ),
        (
            [
                {
                    "type": "pull_request",
                    "parameters": {
                        "require_code_owner_review": True,
                        "required_approving_review_count": 1,
                    },
                },
                {"type": "merge_queue"},
            ],
            "merge queue",
        ),
        (
            [
                {
                    "type": "pull_request",
                    "parameters": {
                        "require_code_owner_review": True,
                        "required_approving_review_count": 0,
                    },
                }
            ],
            "at least one approving",
        ),
    ],
)
def test_branch_safety_fails_closed(
    tmp_path: Path,
    app_key_files: None,
    rules: list[beta.JsonObject],
    failure: str,
) -> None:
    github = FakeGitHub()
    github.rules = rules

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "branch_safety")["outcome"] == "failed"
    assert failure in result(report, "branch_safety")["failure"]


def test_classic_protection_can_supply_codeowner_and_review_requirements(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    github = FakeGitHub()
    github.rules = []
    github.classic = {
        "required_pull_request_reviews": {
            "require_code_owner_reviews": True,
            "required_approving_review_count": 1,
        },
        "required_status_checks": None,
    }

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    branch_safety = result(report, "branch_safety")
    assert branch_safety["outcome"] == "passed"
    assert branch_safety["evidence"]["protection_sources"] == ["classic"]
    assert branch_safety["evidence"]["minimum_approving_review_count"] == 1


@pytest.mark.parametrize("github_errors", [True, False])
def test_codeowners_rejects_github_or_local_syntax_failure(
    tmp_path: Path,
    app_key_files: None,
    github_errors: bool,
) -> None:
    github = FakeGitHub()
    if github_errors:
        github.errors = [{"line": 1, "message": "bad"}]
    else:
        github.files[("example/beta-target", ".github/CODEOWNERS", "c" * 40)] = b"[bad] @owner\n"

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "codeowners")["outcome"] == "failed"


def test_policy_must_enroll_and_delegate_to_configured_approver(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    github = FakeGitHub()
    github.files[
        (
            "example/beta-target",
            ".github/extra-codeowners.toml",
            "c" * 40,
        )
    ] = REPOSITORY_POLICY.replace(b"enabled = true", b"enabled = false")

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "policy")["outcome"] == "failed"
    assert "not enabled" in result(report, "policy")["failure"]


@pytest.mark.parametrize(
    ("organization_policy", "repository_policy", "message"),
    [
        (
            ORGANIZATION_POLICY
            + b'\n[apps.extra]\nslug = "extra"\napp_id = 404\nbot_user_id = 405\n',
            REPOSITORY_POLICY,
            "exactly one App",
        ),
        (
            ORGANIZATION_POLICY,
            REPOSITORY_POLICY
            + b'\n[[delegations]]\napp = "approver"\n'
            + b'paths = ["docs/other.md"]\n'
            + b'for_owners = ["@example/maintainers"]\n',
            "exactly one delegation",
        ),
        (
            ORGANIZATION_POLICY,
            REPOSITORY_POLICY.replace(
                b'paths = ["docs/beta-probe.md"]',
                b'paths = ["docs/**"]',
            ),
            "must exactly match",
        ),
        (
            ORGANIZATION_POLICY,
            REPOSITORY_POLICY.replace(
                b'for_owners = ["@example/maintainers"]',
                b'for_owners = ["*"]',
            ),
            "must exactly match",
        ),
    ],
)
def test_policy_scope_is_exactly_the_disposable_fixture(
    tmp_path: Path,
    app_key_files: None,
    organization_policy: bytes,
    repository_policy: bytes,
    message: str,
) -> None:
    github = FakeGitHub()
    github.files[
        (
            "example/.github",
            ".github/extra-codeowners.toml",
            "d" * 40,
        )
    ] = organization_policy
    github.files[
        (
            "example/beta-target",
            ".github/extra-codeowners.toml",
            "c" * 40,
        )
    ] = repository_policy

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "policy")["outcome"] == "failed"
    assert message in result(report, "policy")["failure"]


def test_policy_requires_the_configured_label_to_change_eligibility(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    github = FakeGitHub()
    github.files[
        (
            "example/beta-target",
            ".github/extra-codeowners.toml",
            "c" * 40,
        )
    ] = REPOSITORY_POLICY.replace(b'required_labels = ["bot-approved"]\n', b"")

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "policy")["outcome"] == "failed"
    assert "must exactly match" in result(report, "policy")["failure"]


def test_policy_proves_every_configured_label_is_jointly_required(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    github = FakeGitHub()
    github.labels.add("security-reviewed")
    github.files[
        (
            "example/beta-target",
            ".github/extra-codeowners.toml",
            "c" * 40,
        )
    ] = REPOSITORY_POLICY.replace(
        b'required_labels = ["bot-approved"]',
        b'required_labels = ["bot-approved", "security-reviewed"]',
    )

    report = beta.evaluate_preflight(
        config(
            tmp_path,
            delegation_test_labels=["bot-approved", "security-reviewed"],
        ),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert report["preflight_passed"] is True
    policy_evidence = result(report, "policy")["evidence"]
    assert policy_evidence["configured_labels_affect_evaluator_eligibility"] is True
    assert policy_evidence["labels_are_independent_approver_authority"] is False


def test_approver_bot_user_identity_is_bound_to_app_slug(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    github = FakeGitHub()
    github.bot_login = "different-app[bot]"

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "app_installations")["outcome"] == "failed"
    assert "bot user identity" in result(report, "app_installations")["failure"]


def test_final_ref_reread_detects_branch_movement(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    github = FakeGitHub()
    github.move_repository_on_final = "example/beta-target"

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "public_repositories")["outcome"] == "passed"
    assert result(report, "final_branch_refs")["outcome"] == "failed"
    assert "changed during the preflight" in result(report, "final_branch_refs")["failure"]


def test_final_ref_reread_detects_repository_replacement(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    github = FakeGitHub()
    github.replace_repository_on_final = "example/beta-target"

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=github,
        service=FakeService(),
        system=FakeSystem(),
    )

    assert result(report, "public_repositories")["outcome"] == "passed"
    assert result(report, "final_branch_refs")["outcome"] == "failed"
    assert "changed during the preflight" in result(report, "final_branch_refs")["failure"]


def test_service_requires_explicitly_enabled_worker_and_reconciler(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    service = FakeService()
    service.worker_enabled = False

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=FakeGitHub(),
        service=service,
        system=FakeSystem(),
    )

    assert result(report, "service_health")["outcome"] == "failed"
    assert "worker and reconciler" in result(report, "service_health")["failure"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("environment", "test"),
        ("github_api_url", "https://github.example.test/api/v3"),
        ("github_app_id", 202),
        ("database_backend", "sqlite"),
        ("check_name", "Other check"),
        ("policy_path", ".github/other.toml"),
        ("organization_policy_repository_name", "policies"),
        ("application_version", "99.0.0"),
        ("build_revision", "f" * 40),
    ],
)
def test_service_runtime_identity_must_match_the_pinned_checker(
    tmp_path: Path,
    app_key_files: None,
    field: str,
    value: object,
) -> None:
    service = FakeService()
    service.runtime_identity[field] = value

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=FakeGitHub(),
        service=service,
        system=FakeSystem(),
    )

    service_health = result(report, "service_health")
    assert service_health["outcome"] == "failed"
    assert "runtime identity" in service_health["failure"]


def test_database_failure_is_sanitized_and_insecure_metric_must_be_zero(
    tmp_path: Path,
    app_key_files: None,
) -> None:
    service = FakeService()
    service.metric = 1
    system = FakeSystem()
    system.database_error = beta.PreflightError("read-only database probe failed")

    report = beta.evaluate_preflight(
        config(tmp_path),
        github=FakeGitHub(),
        service=service,
        system=system,
    )

    assert result(report, "postgresql")["outcome"] == "failed"
    assert result(report, "insecure_changes_metric")["outcome"] == "failed"


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"schema_version": True}, "schema_version"),
        ({"source_revision": "main"}, "source_revision"),
        ({"service_url": "http://beta.example.test"}, "service_url"),
        ({"service_url": "https://user:secret@beta.example.test"}, "service_url"),
        (
            {"checker_webhook_url": "https://other.example.test/webhooks/github"},
            "inspected service_url",
        ),
        ({"target_repository": "other/.github"}, "share one owner"),
        ({"organization_policy_repository": "example/policy"}, ".github"),
        ({"approver_app_id": 101}, "App IDs"),
        ({"approver_installation_id": 1001}, "installation IDs"),
        ({"codeowners_path": "config/CODEOWNERS"}, "codeowners_path"),
    ],
)
def test_config_rejects_ambiguous_or_unsafe_boundaries(
    tmp_path: Path,
    update: dict[str, object],
    message: str,
) -> None:
    values = config_values(tmp_path)
    values.update(update)

    with pytest.raises(ValidationError, match=message):
        beta.BetaConfig.model_validate(values)


@pytest.mark.parametrize(
    ("fingerprint", "normalized"),
    [
        ("a" * 40, "A" * 40),
        ("b" * 64, "B" * 64),
        ("SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/abcde", None),
    ],
)
def test_config_accepts_only_exact_source_fingerprint_forms(
    tmp_path: Path,
    fingerprint: str,
    normalized: str | None,
) -> None:
    updates: dict[str, object] = {"source_signer_fingerprint": fingerprint}
    if fingerprint.startswith("SHA256:"):
        updates["source_ssh_allowed_signers_file"] = tmp_path / "allowed_signers"
    loaded = config(tmp_path, **updates)

    assert loaded.source_signer_fingerprint == (normalized or fingerprint)


@pytest.mark.parametrize(
    "fingerprint",
    [
        "A" * 39,
        "A" * 41,
        "A" * 63,
        "A" * 65,
        "sha256:" + "A" * 43,
        "SHA256:" + "A" * 42,
        "SHA256:" + "A" * 44,
        "prefix-" + "A" * 40,
    ],
)
def test_config_rejects_partial_or_noncanonical_source_fingerprints(
    tmp_path: Path,
    fingerprint: str,
) -> None:
    with pytest.raises(ValidationError, match="source_signer_fingerprint"):
        config(tmp_path, source_signer_fingerprint=fingerprint)


def test_config_requires_explicit_ssh_trust_file_only_for_ssh_signatures(
    tmp_path: Path,
) -> None:
    ssh_fingerprint = "SHA256:" + "A" * 43

    with pytest.raises(ValidationError, match="source_ssh_allowed_signers_file"):
        config(tmp_path, source_signer_fingerprint=ssh_fingerprint)
    with pytest.raises(ValidationError, match="source_ssh_allowed_signers_file"):
        config(
            tmp_path,
            source_ssh_allowed_signers_file=tmp_path / "allowed_signers",
        )

    loaded = config(
        tmp_path,
        source_signer_fingerprint=ssh_fingerprint,
        source_ssh_allowed_signers_file=tmp_path / "allowed_signers",
    )
    assert loaded.source_ssh_allowed_signers_file == tmp_path / "allowed_signers"


def test_config_file_resolves_ssh_trust_file_relative_to_configuration(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / "operator"
    config_dir.mkdir()
    values = config_values(tmp_path)
    values["source_checkout"] = "checkout"
    values["source_signer_fingerprint"] = "SHA256:" + "A" * 43
    values["source_ssh_allowed_signers_file"] = "trust/allowed_signers"
    path = config_dir / "beta.toml"
    path.write_text("\n".join(f"{name} = {json.dumps(value)}" for name, value in values.items()))
    path.chmod(0o600)

    loaded = beta.BetaConfig.from_file(path)

    assert (
        loaded.source_ssh_allowed_signers_file
        == (config_dir / "trust" / "allowed_signers").absolute()
    )


def test_config_file_is_bounded_and_resolves_checkout_relative_to_it(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / "operator"
    config_dir.mkdir()
    checkout = config_dir / "checkout"
    checkout.mkdir()
    values = config_values(tmp_path)
    values["source_checkout"] = "checkout"
    lines = [
        f"{name} = {json.dumps(value)}"
        for name, value in values.items()
        if name != "source_checkout"
    ]
    lines.append('source_checkout = "checkout"')
    path = config_dir / "beta.toml"
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)

    loaded = beta.BetaConfig.from_file(path)

    assert loaded.source_checkout == checkout.resolve()


@pytest.mark.parametrize("kind", ["mode", "hardlink", "owner", "symlink", "fifo"])
def test_config_file_rejects_unsafe_local_trust_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    values = config_values(tmp_path)
    values["source_checkout"] = "."
    content = "\n".join(f"{name} = {json.dumps(value)}" for name, value in values.items())
    path = tmp_path / "beta.toml"
    path.write_text(content)
    path.chmod(0o600)
    if kind == "mode":
        path.chmod(0o640)
    elif kind == "hardlink":
        (tmp_path / "second-link.toml").hardlink_to(path)
    elif kind == "owner":
        monkeypatch.setattr(os, "geteuid", lambda: path.stat().st_uid + 1)
    elif kind == "symlink":
        target = path
        path = tmp_path / "linked.toml"
        path.symlink_to(target)
    elif kind == "fifo":
        path.unlink()
        os.mkfifo(path, mode=0o600)

    with pytest.raises(beta.ConfigurationError, match="could not be parsed"):
        beta.BetaConfig.from_file(path)


def test_exclusive_report_is_published_with_mode_0600(tmp_path: Path) -> None:
    report = tmp_path / "report.json"

    beta.write_report_exclusive(report, {"result": "passed"})

    assert json.loads(report.read_text()) == {"result": "passed"}
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [report]


def test_exclusive_report_refuses_to_replace_an_existing_file(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("operator evidence")

    with pytest.raises(beta.PreflightError, match="refusing to overwrite"):
        beta.write_report_exclusive(report, {"result": "passed"})

    assert report.read_text() == "operator evidence"
    assert list(tmp_path.iterdir()) == [report]


def test_exclusive_report_refuses_a_symlink_target(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    protected.write_text("do not replace")
    report = tmp_path / "report.json"
    report.symlink_to(protected)

    with pytest.raises(beta.PreflightError, match="refusing to overwrite"):
        beta.write_report_exclusive(report, {"result": "passed"})

    assert report.is_symlink()
    assert protected.read_text() == "do not replace"


def test_exclusive_report_rejects_symlink_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(beta.PreflightError, match="could not publish exclusive report"):
        beta.write_report_exclusive(linked_parent / "report.json", {"result": "passed"})

    assert list(real_parent.iterdir()) == []


def test_exclusive_report_rejects_shared_writable_parent(tmp_path: Path) -> None:
    shared_parent = tmp_path / "shared"
    shared_parent.mkdir(mode=0o777)
    shared_parent.chmod(0o777)

    with pytest.raises(beta.PreflightError, match="not group/world-writable"):
        beta.write_report_exclusive(shared_parent / "report.json", {"result": "passed"})

    assert list(shared_parent.iterdir()) == []


def test_exclusive_report_rejects_unbounded_output(tmp_path: Path) -> None:
    with pytest.raises(beta.PreflightError, match="size limit"):
        beta.write_report_exclusive(
            tmp_path / "report.json",
            {"value": "x" * beta.MAX_REPORT_BYTES},
        )


def test_exclusive_report_removes_a_failed_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "report.json"
    real_fsync = os.fsync
    calls = 0

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated directory sync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)

    with pytest.raises(beta.PreflightError, match="could not publish exclusive report"):
        beta.write_report_exclusive(report, {"result": "passed"})

    assert not report.exists()
    assert list(tmp_path.iterdir()) == []


def test_report_destination_cannot_overlap_any_local_input(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    config_file = tmp_path / "preflight.toml"
    checker_key = tmp_path / "checker.pem"
    approver_key = tmp_path / "approver.pem"
    allowed_signers = tmp_path / "allowed_signers"

    for protected in (config_file, checker_key, approver_key, allowed_signers):
        with pytest.raises(beta.PreflightError, match="collides with a preflight input"):
            beta.validate_report_destination(
                protected,
                config_path=config_file,
                key_paths=(checker_key, approver_key, allowed_signers),
                source_checkout=checkout,
            )

    with pytest.raises(beta.PreflightError, match="outside the source checkout"):
        beta.validate_report_destination(
            checkout / "tracked.py",
            config_path=config_file,
            key_paths=(checker_key, approver_key),
            source_checkout=checkout,
        )


def test_main_does_not_replace_config_when_report_path_collides(tmp_path: Path) -> None:
    config_file = tmp_path / "preflight.toml"
    original = "schema_version = 2\n"
    config_file.write_text(original)

    exit_code = beta.main(["preflight", "--config", str(config_file), "--report", str(config_file)])

    assert exit_code == 2
    assert config_file.read_text() == original


def test_main_does_not_replace_ssh_allowed_signers_when_report_collides(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / "operator"
    config_dir.mkdir()
    allowed_signers = config_dir / "allowed_signers"
    original = "evaluation-beta ssh-ed25519 AAAA\n"
    allowed_signers.write_text(original)
    values = config_values(tmp_path)
    values["source_checkout"] = "checkout"
    values["source_signer_fingerprint"] = "SHA256:" + "A" * 43
    values["source_ssh_allowed_signers_file"] = "allowed_signers"
    config_file = config_dir / "preflight.toml"
    config_file.write_text(
        "\n".join(f"{name} = {json.dumps(value)}" for name, value in values.items())
    )

    exit_code = beta.main(
        [
            "preflight",
            "--config",
            str(config_file),
            "--report",
            str(allowed_signers),
        ]
    )

    assert exit_code == 2
    assert allowed_signers.read_text() == original


def test_main_writes_sanitized_mode_0600_configuration_failure(
    tmp_path: Path,
) -> None:
    config_file = tmp_path / "bad.toml"
    report_file = tmp_path / "report.json"
    config_file.write_text("schema_version = 2\n")

    exit_code = beta.main(["preflight", "--config", str(config_file), "--report", str(report_file)])

    assert exit_code == 2
    report = json.loads(report_file.read_text())
    assert report["result"] == "configuration_error"
    assert report["preflight_passed"] is False
    assert stat.S_IMODE(report_file.stat().st_mode) == 0o600


def test_configuration_failure_never_copies_an_accidental_secret_to_report(
    tmp_path: Path,
) -> None:
    values = config_values(tmp_path)
    values["service_url"] = "https://operator:accidental-secret@beta.example.test"
    values["source_checkout"] = str(tmp_path)
    config_file = tmp_path / "secret-in-invalid-url.toml"
    config_file.write_text(
        "\n".join(f"{name} = {json.dumps(value)}" for name, value in values.items()) + "\n"
    )
    report_file = tmp_path / "report.json"

    exit_code = beta.main(["preflight", "--config", str(config_file), "--report", str(report_file)])

    assert exit_code == 2
    assert "accidental-secret" not in report_file.read_text()


def make_standalone_source_checkout(tmp_path: Path) -> None:
    """Create the repository metadata shape required by the local probe."""

    git_directory = tmp_path / ".git"
    (git_directory / "objects" / "info").mkdir(parents=True)
    (tmp_path / "tracked.py").write_text("value = 1\n")
    (tmp_path / "tracked.py").chmod(0o644)
    tmp_path.chmod(0o700)
    git_directory.chmod(0o700)
    (git_directory / "objects").chmod(0o700)
    (git_directory / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
    (git_directory / "HEAD").write_text("ref: refs/heads/main\n")
    (git_directory / "config").chmod(0o600)
    (git_directory / "HEAD").chmod(0o600)


def source_git_responder(
    loaded: beta.BetaConfig,
    checkout: Path,
    calls: list[tuple[str, ...]],
    *,
    signature_fingerprint: str | None = None,
    final_head: str | None = None,
    replacements: str = "",
    dirty: str = "",
    index_entries: str | None = None,
    index_flags: str = "H tracked.py\0",
    tree_entries: str | None = None,
) -> Callable[..., str]:
    """Return a deterministic fixed-Git responder for a standalone checkout."""

    head_reads = 0
    object_format = "sha1" if len(loaded.source_revision) == 40 else "sha256"
    tracked_content = (checkout / "tracked.py").read_bytes()
    tracked_digest = hashlib.new(object_format)
    tracked_digest.update(f"blob {len(tracked_content)}\0".encode())
    tracked_digest.update(tracked_content)
    tracked_object_id = tracked_digest.hexdigest()

    def fake_run(
        arguments: Sequence[str],
        *,
        checkout_fd: int,
        output_limit: int = beta.GIT_OUTPUT_BYTES,
        extra_fds: Sequence[int] = (),
    ) -> str:
        nonlocal head_reads
        assert os.path.samefile(f"/proc/self/fd/{checkout_fd}", checkout)
        assert output_limit in {beta.GIT_OUTPUT_BYTES, beta.GIT_INDEX_OUTPUT_BYTES}
        assert all(descriptor >= 0 for descriptor in extra_fds)
        call = tuple(arguments)
        calls.append(call)
        if call == ("rev-parse", "--show-toplevel"):
            return str(checkout)
        if call == ("rev-parse", "--path-format=absolute", "--absolute-git-dir"):
            return str(checkout / ".git")
        if call == ("rev-parse", "--path-format=absolute", "--git-common-dir"):
            return str(checkout / ".git")
        if call == ("rev-parse", "--path-format=absolute", "--git-path", "objects"):
            return str(checkout / ".git" / "objects")
        if call == ("rev-parse", "--is-shallow-repository"):
            return "false"
        if call == ("rev-parse", "--show-object-format"):
            return object_format
        if call[:2] == ("cat-file", "-t"):
            return "commit"
        if call == ("rev-parse", "--symbolic-full-name", "HEAD"):
            return "refs/heads/main"
        if call == ("rev-parse", "--verify", "HEAD"):
            head_reads += 1
            if final_head is not None and head_reads > 1:
                return final_head
            return loaded.source_revision
        if call[:2] == ("rev-parse", "--verify"):
            return loaded.source_revision
        if call[0] == "for-each-ref":
            return replacements
        if "show" in call:
            return f"G\0{signature_fingerprint or loaded.source_signer_fingerprint}"
        if call[0] == "status":
            return dirty
        if call[:2] == ("ls-files", "--others"):
            return dirty
        if call[:2] == ("ls-files", "--stage"):
            return index_entries or f"100644 {tracked_object_id} 0\ttracked.py\0"
        if call[:3] == ("ls-files", "-v", "-f"):
            return index_flags
        if call[:4] == ("ls-tree", "-r", "--full-tree", "-z"):
            return tree_entries or f"100644 blob {tracked_object_id}\ttracked.py\0"
        return ""

    return fake_run


def test_local_source_probe_requires_exact_signature_and_clean_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = config(tmp_path)
    calls: list[tuple[str, ...]] = []
    make_standalone_source_checkout(tmp_path)
    monkeypatch.setattr(
        beta.LocalSystemProbe,
        "_run_git",
        staticmethod(source_git_responder(loaded, tmp_path, calls)),
    )

    evidence = beta.LocalSystemProbe().source(loaded)

    assert evidence["scope"] == "local-checkout-self-consistency"
    assert evidence["independent_source_attestation"] is False
    assert evidence["signature"] == "valid-and-exact-fingerprint-match"
    assert evidence["tracked_file_count"] == 1
    assert evidence["tracked_content"] == "hashed-twice-against-signed-tree"
    assert evidence["untracked_and_ignored_content"] == "absent-at-both-observations"
    assert any("verify-commit" in call for call in calls)
    assert sum(call[0] == "status" for call in calls) == 2
    assert calls.count(("ls-files", "--others", "-z", "--")) == 2
    assert all("--exclude-standard" not in call for call in calls)
    assert ("for-each-ref", "--format=%(refname)", "refs/replace") in calls
    assert ("fsck", "--strict", "--no-dangling", "--no-reflogs", loaded.source_revision) in calls


@pytest.mark.parametrize(
    ("index_entries", "index_flags", "message"),
    [
        (None, "h tracked.py\0", "index flags"),
        (None, "S tracked.py\0", "index flags"),
        ("120000 " + "a" * 40 + " 0\tlinked.py\0", "H linked.py\0", "tracked-file mode"),
        ("160000 " + "a" * 40 + " 0\tsubmodule\0", "H submodule\0", "tracked-file mode"),
        ("100644 " + "a" * 40 + " 1\tconflict.py\0", "H conflict.py\0", "tracked-file mode"),
    ],
)
def test_local_source_probe_rejects_hidden_or_external_tracked_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    index_entries: str | None,
    index_flags: str,
    message: str,
) -> None:
    loaded = config(tmp_path)
    calls: list[tuple[str, ...]] = []
    make_standalone_source_checkout(tmp_path)
    monkeypatch.setattr(
        beta.LocalSystemProbe,
        "_run_git",
        staticmethod(
            source_git_responder(
                loaded,
                tmp_path,
                calls,
                index_entries=index_entries,
                index_flags=index_flags,
            )
        ),
    )

    with pytest.raises(beta.PreflightError, match=message):
        beta.LocalSystemProbe().source(loaded)


def test_local_source_probe_rejects_content_hidden_from_git_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = config(tmp_path)
    calls: list[tuple[str, ...]] = []
    make_standalone_source_checkout(tmp_path)
    responder = source_git_responder(loaded, tmp_path, calls)
    (tmp_path / "tracked.py").write_text("tampered = True\n")
    monkeypatch.setattr(
        beta.LocalSystemProbe,
        "_run_git",
        staticmethod(responder),
    )

    with pytest.raises(beta.PreflightError, match="does not match the signed source tree"):
        beta.LocalSystemProbe().source(loaded)


def test_local_source_probe_rejects_index_not_bound_to_signed_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = config(tmp_path)
    calls: list[tuple[str, ...]] = []
    make_standalone_source_checkout(tmp_path)
    monkeypatch.setattr(
        beta.LocalSystemProbe,
        "_run_git",
        staticmethod(
            source_git_responder(
                loaded,
                tmp_path,
                calls,
                tree_entries=f"100644 blob {'b' * 40}\ttracked.py\0",
            )
        ),
    )

    with pytest.raises(beta.PreflightError, match="index does not exactly match"):
        beta.LocalSystemProbe().source(loaded)


def test_local_source_probe_verifies_ssh_commit_with_only_explicit_trust_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    private_key = tmp_path / "signing-key"
    public_key = tmp_path / "signing-key.pub"
    allowed_signers = tmp_path / "allowed_signers"
    command_environment = {
        "HOME": str(tmp_path),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }

    def run(command: Sequence[str], *, cwd: Path | None = None) -> str:
        completed = subprocess.run(  # noqa: S603 - fixed binaries and test-owned paths.
            command,
            cwd=cwd,
            env=command_environment,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    run(
        [
            "/usr/bin/ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(private_key),
        ]
    )
    run([beta.GIT_BINARY, "init", "-q", "-b", "main", str(checkout)])
    checkout.chmod(0o700)
    (checkout / ".git").chmod(0o700)
    (checkout / ".git" / "objects").chmod(0o700)
    (checkout / ".gitignore").write_text("httpx.py\n")
    (checkout / ".gitignore").chmod(0o644)
    (checkout / "tracked.py").write_text("value = 1\n")
    (checkout / "tracked.py").chmod(0o644)
    run([beta.GIT_BINARY, "add", ".gitignore", "tracked.py"], cwd=checkout)
    run(
        [
            beta.GIT_BINARY,
            "-c",
            "user.name=Evaluation Beta",
            "-c",
            "user.email=beta@example.test",
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={private_key}",
            "-c",
            "commit.gpgsign=true",
            "commit",
            "-q",
            "-m",
            "signed source fixture",
        ],
        cwd=checkout,
    )
    revision = run([beta.GIT_BINARY, "rev-parse", "HEAD"], cwd=checkout)
    (checkout / ".git" / "config").chmod(0o600)
    (checkout / ".git" / "HEAD").chmod(0o600)
    fingerprint = run(["/usr/bin/ssh-keygen", "-E", "sha256", "-lf", str(public_key)]).split()[1]
    allowed_signers.write_text(f"evaluation-beta {public_key.read_text()}")
    allowed_signers.chmod(0o600)
    hostile_global = tmp_path / "hostile.gitconfig"
    hostile_global.write_text('[gpg "ssh"]\n\tallowedSignersFile = /does/not/exist\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(hostile_global))
    loaded = config(
        checkout,
        source_revision=revision,
        source_signer_fingerprint=fingerprint,
        source_ssh_allowed_signers_file=allowed_signers,
    )

    evidence = beta.LocalSystemProbe().source(loaded)

    assert evidence["signature_format"] == "ssh"
    assert evidence["signer_fingerprint"] == fingerprint
    assert evidence["independent_source_attestation"] is False

    ignored_module = checkout / "httpx.py"
    ignored_module.write_text("raise RuntimeError('tracked ignore shadow executed')\n")
    with pytest.raises(beta.PreflightError, match="untracked, or ignored"):
        beta.LocalSystemProbe().source(loaded)
    ignored_module.unlink()

    (checkout / ".git" / "info" / "exclude").write_text("jwt.py\n")
    locally_ignored_module = checkout / "jwt.py"
    locally_ignored_module.write_text("raise RuntimeError('local exclude shadow executed')\n")
    with pytest.raises(beta.PreflightError, match="untracked, or ignored"):
        beta.LocalSystemProbe().source(loaded)
    locally_ignored_module.unlink()

    run([beta.GIT_BINARY, "update-index", "--assume-unchanged", "tracked.py"], cwd=checkout)
    (checkout / "tracked.py").write_text("value = 'hidden modification'\n")

    with pytest.raises(beta.PreflightError, match="index flags"):
        beta.LocalSystemProbe().source(loaded)


@pytest.mark.parametrize(
    ("variant", "message"),
    [
        ("fingerprint", "exact fingerprint"),
        ("replace", "replacement refs"),
        ("dirty", "modifications"),
        ("moved", "moved during"),
    ],
)
def test_local_source_probe_rejects_adversarial_checkout_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
    message: str,
) -> None:
    loaded = config(tmp_path)
    make_standalone_source_checkout(tmp_path)
    calls: list[tuple[str, ...]] = []
    responder = source_git_responder(
        loaded,
        tmp_path,
        calls,
        signature_fingerprint=(
            f"{loaded.source_signer_fingerprint}A" if variant == "fingerprint" else None
        ),
        replacements="refs/replace/unsafe" if variant == "replace" else "",
        dirty="?? ignored-payload.py\0" if variant == "dirty" else "",
        final_head="f" * 40 if variant == "moved" else None,
    )
    monkeypatch.setattr(beta.LocalSystemProbe, "_run_git", staticmethod(responder))

    with pytest.raises(beta.PreflightError, match=message):
        beta.LocalSystemProbe().source(loaded)


def test_local_source_probe_rejects_object_alternates_before_running_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = config(tmp_path)
    make_standalone_source_checkout(tmp_path)
    (tmp_path / ".git" / "objects" / "info" / "alternates").write_text("/untrusted/objects\n")
    monkeypatch.setattr(
        beta.LocalSystemProbe,
        "_run_git",
        staticmethod(lambda *args, **kwargs: pytest.fail("Git must not run")),
    )

    with pytest.raises(beta.PreflightError, match="alternate object store"):
        beta.LocalSystemProbe().source(loaded)


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("missing", "not safely readable"),
        ("empty", "must contain"),
        ("mode", "non-group/world-writable"),
        ("hardlink", "single-link"),
        ("symlink", "not safely readable"),
        ("oversized", "must contain"),
    ],
)
def test_source_ssh_allowed_signers_file_rejects_unsafe_local_state(
    tmp_path: Path,
    kind: str,
    message: str,
) -> None:
    trust_file = tmp_path / "allowed_signers"
    if kind != "missing":
        trust_file.write_text("evaluation-beta ssh-ed25519 AAAA\n")
        trust_file.chmod(0o600)
    if kind == "empty":
        trust_file.write_bytes(b"")
    elif kind == "mode":
        trust_file.chmod(0o622)
    elif kind == "hardlink":
        (tmp_path / "second-link").hardlink_to(trust_file)
    elif kind == "symlink":
        target = trust_file
        trust_file = tmp_path / "allowed_signers-link"
        trust_file.symlink_to(target)
    elif kind == "oversized":
        trust_file.write_bytes(b"x" * (beta.MAX_ALLOWED_SIGNERS_BYTES + 1))

    with pytest.raises(beta.PreflightError, match=message):
        beta.LocalSystemProbe._open_allowed_signers_file(trust_file)


def test_source_probe_rejects_allowed_signers_file_changed_during_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = "SHA256:" + "A" * 43
    allowed_signers = tmp_path / "allowed_signers"
    allowed_signers.write_text("evaluation-beta ssh-ed25519 AAAA\n")
    allowed_signers.chmod(0o600)
    loaded = config(
        tmp_path,
        source_signer_fingerprint=fingerprint,
        source_ssh_allowed_signers_file=allowed_signers,
    )
    make_standalone_source_checkout(tmp_path)
    calls: list[tuple[str, ...]] = []
    stable_responder = source_git_responder(loaded, tmp_path, calls)

    def racing_responder(
        arguments: Sequence[str],
        *,
        checkout_fd: int,
        output_limit: int = beta.GIT_OUTPUT_BYTES,
        extra_fds: Sequence[int] = (),
    ) -> str:
        response = stable_responder(
            arguments,
            checkout_fd=checkout_fd,
            output_limit=output_limit,
            extra_fds=extra_fds,
        )
        if "show" in arguments:
            allowed_signers.write_text("evaluation-beta ssh-ed25519 CHANGED\n")
        return response

    monkeypatch.setattr(
        beta.LocalSystemProbe,
        "_run_git",
        staticmethod(racing_responder),
    )

    with pytest.raises(beta.PreflightError, match="allowed-signers file changed"):
        beta.LocalSystemProbe().source(loaded)


def test_fixed_git_environment_drops_ambient_configuration_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(tmp_path / "untrusted"))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "wrong-repository"))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "agent"))
    monkeypatch.setenv("GH_TOKEN", "secret")

    environment = beta.LocalSystemProbe._git_environment()

    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert "GIT_CONFIG_COUNT" not in environment
    assert "GIT_DIR" not in environment
    assert "SSH_AUTH_SOCK" not in environment
    assert "GH_TOKEN" not in environment


def test_fixed_git_runner_enforces_aggregate_output_bound(tmp_path: Path) -> None:
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(beta.PreflightError, match="output limit"):
            beta.LocalSystemProbe._run_git(
                ["--version"],
                checkout_fd=descriptor,
                output_limit=1,
            )
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("mode", "mode 0600"),
        ("hardlink", "exactly one hard link"),
        ("owner", "owned by the current user"),
        ("symlink", "safely readable"),
    ],
)
def test_app_private_key_rejects_unsafe_local_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    message: str,
) -> None:
    key_file = tmp_path / "checker.pem"
    key_file.write_text("private key")
    key_file.chmod(0o600)
    if kind == "mode":
        key_file.chmod(0o640)
    elif kind == "hardlink":
        (tmp_path / "second-link.pem").hardlink_to(key_file)
    elif kind == "owner":
        monkeypatch.setattr(os, "geteuid", lambda: key_file.stat().st_uid + 1)
    elif kind == "symlink":
        target = key_file
        key_file = tmp_path / "linked.pem"
        key_file.symlink_to(target)
    monkeypatch.setenv("EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE", str(key_file))

    with pytest.raises(beta.PreflightError, match=message):
        beta.AppIdentity.from_environment(
            "checker",
            app_id=101,
            slug="checker",
            installation_id=1001,
        )


def test_app_private_key_bytes_are_retained_after_single_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_file = tmp_path / "checker.pem"
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_file.write_bytes(key_bytes)
    key_file.chmod(0o600)
    monkeypatch.setenv("EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE", str(key_file))
    identity = beta.AppIdentity.from_environment(
        "checker",
        app_id=101,
        slug="checker",
        installation_id=1001,
    )

    key_file.unlink()

    assert identity.private_key == key_bytes
    assert beta.GitHubRestProbe._app_jwt(identity)


def test_app_private_key_rejects_metadata_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_file = tmp_path / "checker.pem"
    key_file.write_bytes(b"x" * 1024)
    key_file.chmod(0o600)
    monkeypatch.setenv("EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE", str(key_file))
    real_read = os.read
    changed = False

    def changing_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        content = real_read(descriptor, size)
        if not changed:
            changed = True
            key_file.chmod(0o640)
        return content

    monkeypatch.setattr(os, "read", changing_read)

    with pytest.raises(beta.PreflightError, match="changed while it was being read"):
        beta.AppIdentity.from_environment(
            "checker",
            app_id=101,
            slug="checker",
            installation_id=1001,
        )


def test_operator_credential_uses_dedicated_fine_grained_pat_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = tmp_path / "operator-token"
    token_file.write_text("github_pat_disposable_beta_operator_123456\n")
    token_file.chmod(0o400)
    monkeypatch.setenv("EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    credential = beta.OperatorCredential.from_environment()

    assert credential.path == token_file
    assert credential.token == "github_pat_disposable_beta_operator_123456"
    assert credential.token not in repr(credential)


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("mode", "mode 0400 or 0600"),
        ("hardlink", "exactly one hard link"),
        ("symlink", "safely readable"),
        ("legacy", "fine-grained GitHub PAT"),
        ("ambient", "must not reuse the ambient GH_TOKEN"),
    ],
)
def test_operator_credential_rejects_unsafe_or_ambient_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    message: str,
) -> None:
    token = "github_pat_disposable_beta_operator_123456"
    token_file = tmp_path / "operator-token"
    token_file.write_text(token)
    token_file.chmod(0o600)
    if kind == "mode":
        token_file.chmod(0o640)
    elif kind == "hardlink":
        (tmp_path / "second-token-link").hardlink_to(token_file)
    elif kind == "symlink":
        target = token_file
        token_file = tmp_path / "linked-token"
        token_file.symlink_to(target)
    elif kind == "legacy":
        token_file.write_text("ghp_legacy_personal_access_token")
    elif kind == "ambient":
        monkeypatch.setenv("GH_TOKEN", token)
    monkeypatch.setenv("EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE", str(token_file))

    with pytest.raises(beta.PreflightError, match=message):
        beta.OperatorCredential.from_environment()


class FakeRows:
    def __init__(self, value: str) -> None:
        self.value = value

    def scalar_one(self) -> str:
        return self.value


class FakeConnection(AbstractContextManager["FakeConnection"]):
    def execute(self, statement: object) -> FakeRows:
        rendered = str(statement)
        values = {
            "SHOW default_transaction_read_only": "on",
            "SHOW transaction_read_only": "on",
            "SHOW statement_timeout": "5s",
            "SHOW lock_timeout": "5s",
            "SHOW idle_in_transaction_session_timeout": "5s",
            "SHOW search_path": "public",
            "SHOW server_version_num": "170006",
        }
        assert rendered in values
        return FakeRows(values[rendered])

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


class FakeEngine:
    def __init__(self) -> None:
        self.disposed = False

    def connect(self) -> FakeConnection:
        return FakeConnection()

    def dispose(self) -> None:
        self.disposed = True


def test_database_probe_is_postgres_read_only_and_at_exact_migration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = FakeEngine()
    captured: dict[str, Any] = {}
    schema_engines: list[object] = []

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        captured["url"] = url
        captured.update(kwargs)
        return engine

    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_BETA_DATABASE_URL",
        ("postgresql+psycopg://operator:secret@db.example.test/beta?sslmode=verify-full"),
    )
    monkeypatch.setattr(beta, "create_engine", fake_create_engine)
    monkeypatch.setattr(
        beta,
        "validate_database_schema",
        lambda supplied: schema_engines.append(supplied),
    )

    evidence = beta.LocalSystemProbe().database(config(tmp_path))

    assert evidence == {
        "backend": "postgresql",
        "server_version_num": 170006,
        "database_revision": DATABASE_MIGRATION_HEAD,
        "schema_contract": "required-release-contract",
        "transaction_mode": "read-only",
        "search_path": "public",
        "statement_timeout_ms": 5000,
        "lock_timeout_ms": 5000,
        "idle_in_transaction_session_timeout_ms": 5000,
    }
    assert "default_transaction_read_only=on" in captured["connect_args"]["options"]
    assert "search_path=public" in captured["connect_args"]["options"]
    assert captured["connect_args"]["host"] == "db.example.test"
    assert captured["connect_args"]["hostaddr"] == ""
    assert captured["connect_args"]["port"] == 5432
    assert captured["connect_args"]["dbname"] == "beta"
    assert captured["connect_args"]["user"] == "operator"
    assert captured["connect_args"]["password"] == "secret"
    assert captured["connect_args"]["sslmode"] == "verify-full"
    assert captured["poolclass"] is NullPool
    assert captured["pool_pre_ping"] is False
    assert captured["hide_parameters"] is True
    assert schema_engines == [engine]
    assert engine.disposed is True


def test_database_probe_rejects_ambient_libpq_connection_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_BETA_DATABASE_URL",
        "postgresql+psycopg://operator:secret@db.example.test/beta?sslmode=verify-full",
    )
    monkeypatch.setenv("PGHOSTADDR", "203.0.113.1")
    monkeypatch.setattr(
        beta,
        "create_engine",
        lambda *args, **kwargs: pytest.fail("ambient transport must not open an engine"),
    )

    with pytest.raises(beta.PreflightError, match="database URL is invalid"):
        beta.LocalSystemProbe().database(config(tmp_path))


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://operator:secret@db.example.test/beta",
        (
            "postgresql+psycopg://operator:secret@db.example.test/beta"
            "?sslmode=verify-full&options=-csearch_path%3Dunsafe"
        ),
        "postgresql+psycopg://operator:secret@/beta",
        "postgresql+psycopg://operator@127.0.0.1/beta",
        "postgresql://operator:secret@127.0.0.1/beta",
    ],
)
def test_database_probe_rejects_unsafe_or_ambient_connection_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    database_url: str,
) -> None:
    monkeypatch.setenv("EXTRA_CODEOWNERS_BETA_DATABASE_URL", database_url)
    monkeypatch.setattr(
        beta,
        "create_engine",
        lambda *args, **kwargs: pytest.fail("unsafe transport must not open an engine"),
    )

    with pytest.raises(beta.PreflightError, match="database"):
        beta.LocalSystemProbe().database(config(tmp_path))


def test_database_probe_disposes_engine_when_required_release_contract_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = FakeEngine()
    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_BETA_DATABASE_URL",
        ("postgresql+psycopg://operator:do-not-report@db.example.test/beta?sslmode=verify-full"),
    )
    monkeypatch.setattr(beta, "create_engine", lambda *args, **kwargs: engine)

    def reject_schema(supplied: object) -> None:
        assert supplied is engine
        raise RuntimeError("missing secret_named_table")

    monkeypatch.setattr(beta, "validate_database_schema", reject_schema)

    with pytest.raises(beta.PreflightError, match="RuntimeError") as failure:
        beta.LocalSystemProbe().database(config(tmp_path))

    assert "do-not-report" not in str(failure.value)
    assert "secret_named_table" not in str(failure.value)
    assert engine.disposed is True


def test_repository_file_accepts_github_base64_line_wrapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = beta.GitHubRestProbe()
    encoded = "aGVs\nbG8=\n"

    monkeypatch.setattr(
        probe,
        "_json",
        lambda *args, **kwargs: {
            "type": "file",
            "encoding": "base64",
            "size": 5,
            "content": encoded,
        },
    )
    try:
        assert probe.repository_file("example/repo", "CODEOWNERS", "main") == b"hello"
    finally:
        probe.close()


def test_github_http_client_ignores_ambient_proxy_and_certificate_settings() -> None:
    probe = beta.GitHubRestProbe()
    try:
        assert probe._http._client.trust_env is False
    finally:
        probe.close()


@respx.mock
def test_github_checker_probe_verifies_contract_and_mints_metadata_token(
    tmp_path: Path,
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_file = tmp_path / "checker.pem"
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_file.chmod(0o600)
    key_bytes = key_file.read_bytes()
    app_route = respx.get(f"{API_URL}/app").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": 101,
                "slug": "checker",
                "owner": {
                    "id": 10,
                    "login": "example",
                    "type": "Organization",
                },
                "permissions": beta.CHECKER_PERMISSIONS,
                "events": sorted(beta.CHECKER_EVENTS),
                "installations_count": 1,
            },
        )
    )
    app_installations_route = respx.get(
        f"{API_URL}/app/installations",
        params={"per_page": "100", "page": "1"},
    ).mock(
        return_value=httpx.Response(
            200,
            json=[{"id": 1001}],
        )
    )
    installation_requests_route = respx.get(
        f"{API_URL}/app/installation-requests",
        params={"per_page": "100", "page": "1"},
    ).mock(return_value=httpx.Response(200, json=[]))
    hook_route = respx.get(f"{API_URL}/app/hook/config").mock(
        return_value=httpx.Response(
            200,
            json={
                "url": "https://hooks.example.test/webhooks/github",
                "content_type": "json",
                "insecure_ssl": "0",
                "secret": "********",
            },
        )
    )
    installation_route = respx.get(f"{API_URL}/app/installations/1001").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": 1001,
                "app_id": 101,
                "app_slug": "checker",
                "repository_selection": "selected",
                "target_type": "Organization",
                "target_id": 10,
                "suspended_at": None,
                "account": {
                    "id": 10,
                    "login": "example",
                    "type": "Organization",
                },
                "permissions": beta.CHECKER_PERMISSIONS,
                "events": sorted(beta.CHECKER_EVENTS),
            },
        )
    )
    token_route = respx.post(f"{API_URL}/app/installations/1001/access_tokens").mock(
        return_value=httpx.Response(
            201,
            json={"token": "ghs_test", "permissions": {"metadata": "read"}},
        )
    )
    inventory_route = respx.get(
        f"{API_URL}/installation/repositories",
        params={"per_page": "100", "page": "1"},
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": 2,
                "repositories": [
                    {"id": 11, "full_name": "example/beta-target"},
                    {"id": 12, "full_name": "example/.github"},
                ],
            },
        )
    )
    probe = beta.GitHubRestProbe()
    try:
        evidence = probe.verify_installation(
            beta.AppIdentity("checker", 101, "checker", 1001, key_file, key_bytes),
            {"example/beta-target": 11, "example/.github": 12},
            organization_id=10,
            checker_webhook_url="https://hooks.example.test/webhooks/github",
        )
    finally:
        probe.close()

    assert evidence["token_permissions"] == "metadata:read"
    assert json.loads(token_route.calls[0].request.content) == {
        "permissions": {"metadata": "read"},
    }
    assert token_route.calls[0].request.headers["authorization"].startswith("Bearer ")
    assert inventory_route.calls[0].request.headers["authorization"] == "Bearer ghs_test"
    assert app_route.called
    assert app_installations_route.called
    assert installation_requests_route.called
    assert hook_route.called
    assert installation_route.called


@pytest.mark.parametrize(
    ("installation_count", "installations", "requests", "message"),
    [
        (2, [{"id": 2002}], [], "exactly one installation"),
        (1, [{"id": 9999}], [], "installation inventory"),
        (1, [{"id": 2002}], [{"id": 99}], "pending installation requests"),
    ],
)
def test_github_app_must_be_isolated_to_the_disposable_beta(
    monkeypatch: pytest.MonkeyPatch,
    installation_count: int,
    installations: list[beta.JsonObject],
    requests: list[beta.JsonObject],
    message: str,
) -> None:
    probe = beta.GitHubRestProbe()
    identity = beta.AppIdentity(
        "approver",
        202,
        "approver",
        2002,
        Path("/unused"),
        b"unused",
    )
    responses: dict[str, object] = {
        "/app": {
            "id": 202,
            "slug": "approver",
            "owner": {
                "id": 10,
                "login": "example",
                "type": "Organization",
            },
            "permissions": beta.APPROVER_PERMISSIONS,
            "events": sorted(beta.APPROVER_EVENTS),
            "installations_count": installation_count,
        },
        "/app/installations?per_page=100&page=1": installations,
        "/app/installation-requests?per_page=100&page=1": requests,
    }
    monkeypatch.setattr(probe, "_app_jwt", lambda supplied: "app-jwt")
    monkeypatch.setattr(
        probe,
        "_json",
        lambda method, path, **kwargs: responses[path],
    )
    try:
        with pytest.raises(beta.PreflightError, match=message):
            probe.verify_installation(
                identity,
                {"example/beta-target": 11},
                organization_id=10,
                checker_webhook_url=None,
            )
    finally:
        probe.close()


def test_app_contract_rejects_checker_permission_drift() -> None:
    permissions = dict(beta.CHECKER_PERMISSIONS)
    permissions["issues"] = "write"
    identity = beta.AppIdentity(
        "checker",
        101,
        "checker",
        1001,
        Path("/unused"),
        b"unused",
    )

    with pytest.raises(beta.PreflightError, match="exact contract"):
        beta.GitHubRestProbe._verify_app_contract(
            identity,
            permissions=permissions,
            events=beta.CHECKER_EVENTS,
        )


@pytest.mark.parametrize(
    ("permissions", "events"),
    [
        ({**beta.APPROVER_PERMISSIONS, "checks": "write"}, beta.APPROVER_EVENTS),
        ({**beta.APPROVER_PERMISSIONS, "contents": "write"}, beta.APPROVER_EVENTS),
        (beta.APPROVER_PERMISSIONS, frozenset({"pull_request"})),
    ],
)
def test_app_contract_rejects_approver_authority_or_event_drift(
    permissions: Mapping[str, str],
    events: frozenset[str],
) -> None:
    identity = beta.AppIdentity(
        "approver",
        202,
        "approver",
        2002,
        Path("/unused"),
        b"unused",
    )

    with pytest.raises(beta.PreflightError, match="exact contract"):
        beta.GitHubRestProbe._verify_app_contract(
            identity,
            permissions=permissions,
            events=events,
        )


def test_approver_app_contract_is_exact_and_has_no_webhook_events() -> None:
    identity = beta.AppIdentity(
        "approver",
        202,
        "approver",
        2002,
        Path("/unused"),
        b"unused",
    )

    beta.GitHubRestProbe._verify_app_contract(
        identity,
        permissions=beta.APPROVER_PERMISSIONS,
        events=beta.APPROVER_EVENTS,
    )


@respx.mock
def test_classic_protection_404_is_absent_only_after_admin_capability_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "github_pat_disposable_beta_operator_123456"
    token_file = tmp_path / "operator-token"
    token_file.write_text(token)
    token_file.chmod(0o600)
    monkeypatch.setenv("EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    capability_route = respx.get(f"{API_URL}/repos/example/repo/actions/permissions").mock(
        return_value=httpx.Response(200, json={"enabled": True})
    )
    protection_route = respx.get(f"{API_URL}/repos/example/repo/branches/main/protection").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    probe = beta.GitHubRestProbe()
    try:
        protection = probe.classic_branch_protection("example/repo", "main")
    finally:
        probe.close()

    assert protection is None
    assert capability_route.calls[0].request.headers["authorization"] == f"Bearer {token}"
    assert protection_route.calls[0].request.headers["authorization"] == f"Bearer {token}"


@respx.mock
def test_classic_protection_does_not_treat_missing_admin_access_as_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = tmp_path / "operator-token"
    token_file.write_text("github_pat_disposable_beta_operator_123456")
    token_file.chmod(0o600)
    monkeypatch.setenv("EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    respx.get(f"{API_URL}/repos/example/repo/actions/permissions").mock(
        return_value=httpx.Response(403, json={"message": "Resource not accessible"})
    )
    protection_route = respx.get(f"{API_URL}/repos/example/repo/branches/main/protection").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    probe = beta.GitHubRestProbe()
    try:
        with pytest.raises(beta.PreflightError, match="returned HTTP 403"):
            probe.classic_branch_protection("example/repo", "main")
    finally:
        probe.close()

    assert protection_route.called is False


def test_branch_rule_reader_fails_when_pagination_bound_is_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = beta.GitHubRestProbe()
    monkeypatch.setattr(
        probe,
        "_json",
        lambda *args, **kwargs: [{"type": "deletion"} for _ in range(100)],
    )
    try:
        with pytest.raises(beta.PreflightError, match="first-page limit"):
            probe.branch_rules("example/repo", "main")
    finally:
        probe.close()
