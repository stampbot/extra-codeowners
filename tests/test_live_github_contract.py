from __future__ import annotations

from pathlib import Path

import pytest

from tools.live_github_contract import (
    Config,
    ContractError,
    delivery_targets_repository,
    required_check_has_expected_source,
    sanitize_delivery,
)


def test_expected_source_requires_context_and_integration() -> None:
    ruleset = {
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [
                        {"context": "Extra CODEOWNERS / approval", "integration_id": 123}
                    ]
                },
            }
        ]
    }

    assert required_check_has_expected_source(
        ruleset, context="Extra CODEOWNERS / approval", app_id=123
    )
    assert not required_check_has_expected_source(
        ruleset, context="Extra CODEOWNERS / approval", app_id=456
    )
    assert not required_check_has_expected_source(ruleset, context="lookalike", app_id=123)


@pytest.mark.parametrize("rules", [None, {}, [], [{"type": "required_status_checks"}]])
def test_expected_source_rejects_malformed_rules(rules: object) -> None:
    assert not required_check_has_expected_source(
        {"rules": rules}, context="Extra CODEOWNERS / approval", app_id=123
    )


def test_delivery_sanitizer_retains_only_shape_and_status() -> None:
    sanitized = sanitize_delivery(
        {
            "id": 987,
            "guid": "secret-ish-delivery-id",
            "event": "installation_repositories",
            "action": "added",
            "status_code": 202,
            "redelivery": False,
            "request": {
                "headers": {"X-Hub-Signature-256": "sha256=do-not-copy"},
                "payload": {
                    "installation": {"id": 1, "access_tokens_url": "private"},
                    "repositories_added": [{"id": 2, "full_name": "private/repository"}],
                    "sender": {"login": "private-user"},
                },
            },
            "response": {"payload": "private response"},
        }
    )

    assert sanitized == {
        "action": "added",
        "event": "installation_repositories",
        "payload_shape": {
            "installation_keys": ["access_tokens_url", "id"],
            "repositories_added_item_keys": ["full_name", "id"],
            "root_keys": ["installation", "repositories_added", "sender"],
            "sender_keys": ["login"],
        },
        "redelivery": False,
        "status_code": 202,
    }
    serialized = repr(sanitized)
    assert "do-not-copy" not in serialized
    assert "private/repository" not in serialized
    assert "private-user" not in serialized


def test_delivery_repository_match_handles_installation_repository_lists() -> None:
    delivery = {
        "request": {
            "payload": {
                "repositories_added": [
                    {"id": 123, "full_name": "example/one"},
                    {"id": 456, "full_name": "example/two"},
                ]
            }
        }
    }

    assert delivery_targets_repository(delivery, 456)
    assert not delivery_targets_repository(delivery, 789)


def test_config_requires_explicit_organization_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_ORGANIZATION", "fixture-org")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_CONFIRM", "wrong")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN", "unused")

    with pytest.raises(ContractError, match="LIVE_CONFIRM"):
        Config.from_environment()


def test_config_records_a_full_source_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key_file = tmp_path / "checker.pem"
    key_file.write_text("fixture key parsed only by the live client")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_ORGANIZATION", "fixture-org")
    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_LIVE_CONFIRM", "delete-disposable-repository-in:fixture-org"
    )
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN", "unused")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_SOURCE_REVISION", "a" * 40)
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_CHECKER_APP_ID", "123")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_CHECKER_INSTALLATION_ID", "456")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_CHECKER_PRIVATE_KEY_FILE", str(key_file))

    assert Config.from_environment().source_revision == "a" * 40

    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_SOURCE_REVISION", "main")
    with pytest.raises(ContractError, match="full commit SHA"):
        Config.from_environment()
