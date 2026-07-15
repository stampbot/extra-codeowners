from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from tools.live_github_contract import (
    AppAuth,
    AppCredentials,
    Config,
    ContractError,
    Fixture,
    RestClient,
    contract_interpretation,
    delivery_targets_repository,
    merge_attempt_was_blocked,
    required_check_has_expected_source,
    sanitize_delivery,
)


class StubClient:
    def __init__(self, statuses: list[int], responses: list[Any] | None = None) -> None:
        self.statuses = statuses
        self.responses = responses or []
        self.closed = False
        self.requests: list[tuple[str, str]] = []

    def status(self, method: str, path: str, *, body: dict[str, Any] | None = None) -> int:
        del method, path, body
        return self.statuses.pop(0)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, str | int] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        del body, params, expected
        self.requests.append((method, path))
        return self.responses.pop(0) if self.responses else None

    def close(self) -> None:
        self.closed = True


class StubAuth:
    def __init__(self, clients: list[StubClient]) -> None:
        self.credentials = AppCredentials(
            app_id=123,
            installation_id=456,
            private_key_file=Path("unused.pem"),
        )
        self.clients = clients

    def installation_client(self, permissions: dict[str, str]) -> RestClient:
        del permissions
        return cast(RestClient, self.clients.pop(0))


def fixture_without_network(selection_client: StubClient | None = None) -> Fixture:
    fixture = object.__new__(Fixture)
    fixture.repository = "fixture-org/fixture-repository"
    fixture.repository_id = 789
    fixture.repository_selection = cast(RestClient | None, selection_client)
    return fixture


def fixture_for_merge_probe(merge_status: int) -> tuple[Fixture, list[tuple[str, str, str]]]:
    fixture = fixture_without_network()
    fixture.operator = cast(RestClient, StubClient([merge_status]))
    replacements: list[tuple[str, str, str]] = []

    def create_pull(*, head: str, base: str, title: str) -> int:
        replacements.append((head, base, title))
        return 2

    fixture._create_pull = create_pull  # type: ignore[method-assign]
    return fixture, replacements


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


def test_contract_interpretation_requires_protection_without_inheritance() -> None:
    assertions = {
        "organization_ruleset_expected_source": True,
        "repository_ruleset_expected_source": True,
        "completed_success_to_in_progress_blocks_merge": True,
        "shared_head_invalidation_blocks_both_pull_requests": True,
        "shared_head_inherits_success_before_invalidation": False,
        "retarget_inherits_commit_scoped_success_before_invalidation": False,
    }

    assert contract_interpretation(assertions) == {
        "github_contract_fail_closed": True,
        "production_warning_required": True,
        "production_warning_reason": (
            "fixture does not cover deployed webhook delivery and reconciliation"
        ),
        "scope": "GitHub rules and Check Run behavior only; deployment delivery is separate",
    }

    assertions["shared_head_inherits_success_before_invalidation"] = True
    interpretation = contract_interpretation(assertions)
    assert interpretation["github_contract_fail_closed"] is False
    assert interpretation["production_warning_required"] is True
    assert interpretation["production_warning_reason"] == "GitHub contract is not fail closed"


@pytest.mark.parametrize(("status_code", "blocked"), [(200, False), (405, True), (409, True)])
def test_merge_attempt_records_safe_and_unsafe_terminal_results(
    status_code: int, blocked: bool
) -> None:
    assert merge_attempt_was_blocked(status_code) is blocked


def test_merge_attempt_rejects_indeterminate_response() -> None:
    with pytest.raises(ContractError, match="indeterminate HTTP status"):
        merge_attempt_was_blocked(403)


def test_accepted_merge_uses_replacement_pull_and_remains_observed() -> None:
    fixture, replacements = fixture_for_merge_probe(200)

    blocked, pull_number = fixture._attempt_in_progress_merge(1)

    assert blocked is False
    assert pull_number == 2
    assert replacements == [
        ("shared-head", "replacement", "Replacement contract PR after unsafe merge")
    ]


def test_blocked_merge_keeps_original_pull() -> None:
    fixture, replacements = fixture_for_merge_probe(405)

    blocked, pull_number = fixture._attempt_in_progress_merge(1)

    assert blocked is True
    assert pull_number == 1
    assert replacements == []


@pytest.mark.parametrize(("state", "outcome"), [("clean", True), ("blocked", False)])
def test_merge_outcome_records_both_terminal_states(state: str, outcome: bool) -> None:
    fixture = fixture_without_network()
    operator = StubClient([], [{"mergeable_state": state}])
    fixture.operator = cast(RestClient, operator)

    assert fixture._wait_for_merge_outcome(1) is outcome


def test_merge_outcome_returns_opposite_terminal_state_after_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = fixture_without_network()
    operator = StubClient([], [{"mergeable_state": "clean"}])
    fixture.operator = cast(RestClient, operator)
    monotonic_values = iter((0.0, 1.0, 91.0))
    monkeypatch.setattr("tools.live_github_contract.time.monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    assert fixture._wait_for_merge_outcome(1, preferred=False) is True


def test_selected_installation_requires_separate_classic_pat() -> None:
    fixture = fixture_without_network()
    auth = StubAuth([StubClient([404])])

    with pytest.raises(ContractError, match="separate short-lived classic PAT"):
        fixture._ensure_app_access(
            cast(AppAuth, auth),
            {"checks": "write"},
            repository_selection="selected",
        )


def test_selected_installation_uses_repository_selection_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection_client = StubClient([])
    fixture = fixture_without_network(selection_client)
    first = StubClient([404])
    second = StubClient([200])
    auth = StubAuth([first, second])
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    result = fixture._ensure_app_access(
        cast(AppAuth, auth),
        {"checks": "write"},
        repository_selection="selected",
    )

    assert result is cast(RestClient, second)
    assert selection_client.requests == [("PUT", "/user/installations/456/repositories/789")]


def test_all_repositories_installation_waits_without_selection_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = fixture_without_network()
    first = StubClient([404])
    second = StubClient([200])
    auth = StubAuth([first, second])
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    result = fixture._ensure_app_access(
        cast(AppAuth, auth),
        {"checks": "write"},
        repository_selection="all",
    )

    assert result is cast(RestClient, second)


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


def test_config_requires_repository_selection_pat_to_be_separate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key_file = tmp_path / "checker.pem"
    key_file.write_text("fixture key parsed only by the live client")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_ORGANIZATION", "fixture-org")
    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_LIVE_CONFIRM", "delete-disposable-repository-in:fixture-org"
    )
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_OPERATOR_TOKEN", "operator-token")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_REPOSITORY_SELECTION_TOKEN", "operator-token")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_SOURCE_REVISION", "a" * 40)
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_CHECKER_APP_ID", "123")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_CHECKER_INSTALLATION_ID", "456")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIVE_CHECKER_PRIVATE_KEY_FILE", str(key_file))

    with pytest.raises(ContractError, match="must be a separate"):
        Config.from_environment()
