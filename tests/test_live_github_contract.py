from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
import respx

import tools.live_github_contract as contract_module
from tools.live_github_contract import (
    AppAuth,
    AppCredentials,
    Config,
    ContractError,
    Fixture,
    RestClient,
    contract_interpretation,
    evidence_completeness,
    installation_add_targets_repository,
    merge_attempt_was_blocked,
    required_check_has_expected_source,
    sanitize_delivery,
)


class StubClient:
    def __init__(
        self,
        statuses: list[int],
        responses: list[Any] | None = None,
        *,
        close_error: Exception | None = None,
    ) -> None:
        self.statuses = statuses
        self.responses = responses or []
        self.close_error = close_error
        self.closed = False
        self.requests: list[tuple[str, str]] = []
        self.transcript: list[dict[str, Any]] = []

    def status(self, method: str, path: str, *, body: dict[str, Any] | None = None) -> int:
        self.transcript.append(
            {
                "method": method,
                "path": path,
                "body": body,
                "params": None,
                "expected": None,
            }
        )
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
        self.requests.append((method, path))
        self.transcript.append(
            {
                "method": method,
                "path": path,
                "body": body,
                "params": params,
                "expected": expected,
            }
        )
        response = self.responses.pop(0) if self.responses else None
        if isinstance(response, Exception):
            raise response
        return response

    def request_with_link(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str | int] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> tuple[Any, str | None]:
        self.requests.append((method, path))
        self.transcript.append(
            {
                "method": method,
                "path": path,
                "body": None,
                "params": params,
                "expected": expected,
            }
        )
        response = self.responses.pop(0) if self.responses else None
        if isinstance(response, Exception):
            raise response
        if isinstance(response, tuple):
            return cast(tuple[Any, str | None], response)
        return response, None

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class StubAuth:
    def __init__(
        self,
        clients: list[StubClient],
        *,
        jwt_clients: list[StubClient] | None = None,
    ) -> None:
        self.credentials = AppCredentials(
            app_id=123,
            installation_id=456,
            private_key_file=Path("unused.pem"),
        )
        self.clients = clients
        self.jwt_clients = jwt_clients or []

    def installation_client(self, permissions: dict[str, str]) -> RestClient:
        del permissions
        return cast(RestClient, self.clients.pop(0))

    def jwt_client(self) -> RestClient:
        return cast(RestClient, self.jwt_clients.pop(0))

    def repository_selection(self) -> str:
        return "all"


def config(*, approver: AppCredentials | None = None, keep_repository: bool = False) -> Config:
    return Config(
        organization="fixture-org",
        operator_token="operator-token",
        repository_selection_token=None,
        source_revision="a" * 40,
        checker=AppCredentials(123, 456, Path("unused.pem")),
        approver=approver,
        report_file=Path("unused-report.json"),
        check_name="Extra CODEOWNERS / live contract",
        observation_seconds=1,
        keep_repository=keep_repository,
    )


def complete_webhook_capture(*, incomplete: object = None) -> dict[str, Any]:
    return {
        "delivery_list_limit": contract_module.WEBHOOK_DELIVERY_LIST_LIMIT,
        "delivery_page_limit": contract_module.WEBHOOK_DELIVERY_PAGE_LIMIT,
        "delivery_page_size": contract_module.WEBHOOK_DELIVERY_PAGE_SIZE,
        "delivery_window_complete": not bool(incomplete),
        "incomplete_observations": [] if incomplete is None else incomplete,
        "last_poll_pages_read": 1,
        "pages_read_total": 1,
        "poll_count": 1,
    }


def fixture_without_network(selection_client: StubClient | None = None) -> Fixture:
    fixture = object.__new__(Fixture)
    fixture.config = config()
    fixture.repository_name = "fixture-repository"
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


@respx.mock
def test_rest_client_returns_body_with_only_the_link_header() -> None:
    link = '<https://api.github.com/app/hook/deliveries?cursor=private-cursor>; rel="next"'
    route = respx.get("https://api.github.com/app/hook/deliveries").mock(
        return_value=httpx.Response(
            200,
            json=[],
            headers={
                "Link": link,
                "X-Private-Provider-Header": "private-value",
            },
        )
    )
    client = RestClient("private-token")
    try:
        body, returned_link = client.request_with_link(
            "GET",
            "/app/hook/deliveries",
        )
    finally:
        client.close()

    assert body == []
    assert returned_link == link
    assert route.called


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


def test_evidence_completeness_distinguishes_false_null_and_missing() -> None:
    assertions = {
        **dict.fromkeys(contract_module.CORE_OBSERVATIONS, False),
        "numeric_approval_rule_blocks_before_app_review": None,
        "app_review_attributed_to_bot": None,
        "app_review_counts_as_numeric_approval": None,
        "in_progress_merge_state_blocked": False,
        "in_progress_merge_attempt_blocked": "false",
        "installation_repository_added_delivery_observed": None,
    }
    del assertions["pull_request_retarget_delivery_observed"]
    report = {
        "result": "observed",
        "cleanup_succeeded": True,
        "fixture": {"checker_repository_selection": "all"},
        "assertions": assertions,
        "webhook_capture": complete_webhook_capture(),
    }

    completeness = evidence_completeness(report, approver_configured=False)

    assert completeness["configured_run_complete"] is False
    assert completeness["observations"]["organization_ruleset_expected_source"] == "observed_false"
    assert completeness["observations"]["app_review_attributed_to_bot"] == "not_run"
    assert completeness["observations"]["pull_request_retarget_delivery_observed"] == "missing"
    assert completeness["observations"]["in_progress_merge_attempt_blocked"] == "invalid"
    assert "organization_ruleset_expected_source" in completeness["observed_false"]
    assert "app_review_attributed_to_bot" in completeness["not_run"]
    assert "pull_request_retarget_delivery_observed" in completeness["missing"]
    assert "in_progress_merge_attempt_blocked" in completeness["invalid"]


def test_evidence_completeness_accepts_false_but_requires_configured_approver() -> None:
    assertions = {
        **dict.fromkeys(contract_module.CORE_OBSERVATIONS, False),
        **dict.fromkeys(contract_module.APP_REVIEW_OBSERVATIONS),
        **dict.fromkeys(contract_module.DIAGNOSTIC_OBSERVATIONS),
    }
    report = {
        "result": "observed",
        "cleanup_succeeded": True,
        "fixture": {"checker_repository_selection": "all"},
        "assertions": assertions,
        "webhook_capture": complete_webhook_capture(),
    }

    assert evidence_completeness(report, approver_configured=False)["configured_run_complete"]
    configured = evidence_completeness(report, approver_configured=True)
    assert configured["configured_run_complete"] is False
    assert configured["full_automated_observations_complete"] is False

    selected = {
        **report,
        "fixture": {"checker_repository_selection": "selected"},
    }
    assert (
        evidence_completeness(selected, approver_configured=False)["configured_run_complete"]
        is False
    )


@pytest.mark.parametrize(
    "incomplete",
    [
        ["unknown_observation"],
        [
            "pull_request_opened_delivery_observed",
            "pull_request_opened_delivery_observed",
        ],
        ["pull_request_opened_delivery_observed"],
        "pull_request_opened_delivery_observed",
    ],
)
def test_evidence_completeness_rejects_malformed_or_contradictory_capture_metadata(
    incomplete: object,
) -> None:
    report = {
        "result": "observed",
        "cleanup_succeeded": True,
        "fixture": {"checker_repository_selection": "all"},
        "assertions": {
            **dict.fromkeys(contract_module.CORE_OBSERVATIONS, False),
            **dict.fromkeys(contract_module.APP_REVIEW_OBSERVATIONS),
            **dict.fromkeys(contract_module.DIAGNOSTIC_OBSERVATIONS),
        },
        "webhook_capture": complete_webhook_capture(incomplete=incomplete),
    }

    completeness = evidence_completeness(report, approver_configured=False)

    assert completeness["webhook_capture_metadata_valid"] is False
    assert completeness["configured_run_complete"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("delivery_list_limit", 100),
        ("delivery_window_complete", 1),
        ("last_poll_pages_read", 0),
        ("pages_read_total", True),
        ("poll_count", 2),
    ],
)
def test_evidence_completeness_rejects_inconsistent_capture_bounds(
    field: str,
    value: object,
) -> None:
    capture = complete_webhook_capture()
    capture[field] = value
    report = {
        "result": "observed",
        "cleanup_succeeded": True,
        "fixture": {"checker_repository_selection": "all"},
        "assertions": {
            **dict.fromkeys(contract_module.CORE_OBSERVATIONS, False),
            **dict.fromkeys(contract_module.APP_REVIEW_OBSERVATIONS),
            **dict.fromkeys(contract_module.DIAGNOSTIC_OBSERVATIONS),
        },
        "webhook_capture": capture,
    }

    completeness = evidence_completeness(report, approver_configured=False)

    assert completeness["webhook_capture_metadata_valid"] is False
    assert completeness["configured_run_complete"] is False


def test_evidence_completeness_requires_webhook_capture_metadata() -> None:
    report = {
        "result": "observed",
        "cleanup_succeeded": True,
        "fixture": {"checker_repository_selection": "all"},
        "assertions": {
            **dict.fromkeys(contract_module.CORE_OBSERVATIONS, False),
            **dict.fromkeys(contract_module.APP_REVIEW_OBSERVATIONS),
            **dict.fromkeys(contract_module.DIAGNOSTIC_OBSERVATIONS),
        },
    }

    completeness = evidence_completeness(report, approver_configured=False)

    assert completeness["webhook_capture_metadata_valid"] is False
    assert completeness["configured_run_complete"] is False


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


def test_ruleset_transcript_binds_both_scopes_to_the_checker_app(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_rule = contract_module._status_check_rule(
        "Extra CODEOWNERS / live contract",
        123,
    )
    operator = StubClient(
        [],
        [
            {"id": 91, "rules": [expected_rule]},
            {"id": 92, "rules": [expected_rule]},
        ],
    )
    fixture = fixture_without_network()
    fixture.operator = cast(RestClient, operator)
    fixture.default_branch = "main"
    fixture.organization_ruleset_name = "fixture organization rule"
    fixture.organization_ruleset_id = cast(int | None, None)
    fixture.report = cast(dict[str, Any], {"assertions": {}})

    fixture._create_rulesets()

    assert fixture.organization_ruleset_id == 91
    output = capsys.readouterr().out
    assert "Organization ruleset recovery name: fixture organization rule" in output
    assert "Created disposable organization ruleset 'fixture organization rule' (ID 91)" in output
    assert fixture.report["assertions"] == {
        "organization_ruleset_expected_source": True,
        "repository_ruleset_expected_source": True,
    }
    assert [request["path"] for request in operator.transcript] == [
        "/orgs/fixture-org/rulesets",
        "/repos/fixture-org/fixture-repository/rulesets",
    ]
    for request in operator.transcript:
        required = request["body"]["rules"][0]["parameters"]["required_status_checks"]
        assert required == [
            {
                "context": "Extra CODEOWNERS / live contract",
                "integration_id": 123,
            }
        ]


def test_optional_app_review_transcript_records_a_numeric_approval() -> None:
    approver = StubClient([], [{"user": {"type": "Bot"}}])
    fixture = fixture_without_network()
    fixture.approver = cast(RestClient, approver)
    fixture.operator = cast(RestClient, StubClient([], [None]))
    fixture.report = {"assertions": {}}
    branches: list[tuple[str, str]] = []
    fixture._create_branch = lambda branch, sha: branches.append((branch, sha))  # type: ignore[method-assign]
    fixture._commit_file = lambda branch, path, content: "b" * 40  # type: ignore[method-assign]
    fixture._create_pull = lambda **kwargs: 17  # type: ignore[method-assign]
    fixture._create_check = lambda sha: 88  # type: ignore[method-assign]
    outcomes = iter((False, True))

    def merge_outcome(pull_number: int, *, preferred: bool | None = None) -> bool:
        del pull_number, preferred
        return next(outcomes)

    fixture._wait_for_merge_outcome = merge_outcome  # type: ignore[method-assign]

    fixture._exercise_app_review("a" * 40)

    assert branches == [("review-base", "a" * 40), ("review-head", "a" * 40)]
    assert fixture.report["assertions"] == {
        "numeric_approval_rule_blocks_before_app_review": True,
        "app_review_attributed_to_bot": True,
        "app_review_counts_as_numeric_approval": True,
    }
    assert approver.transcript == [
        {
            "method": "POST",
            "path": "/repos/fixture-org/fixture-repository/pulls/17/reviews",
            "body": {
                "body": "Disposable App approval contract.",
                "event": "APPROVE",
            },
            "params": None,
            "expected": (200,),
        }
    ]


def test_missing_optional_approver_is_explicitly_not_run() -> None:
    fixture = fixture_without_network()
    fixture.approver = None
    fixture.report = {"assertions": {}}

    fixture._exercise_app_review("a" * 40)

    assert fixture.report["assertions"] == {
        "app_review_counts_as_numeric_approval": None,
        "app_review_attributed_to_bot": None,
        "numeric_approval_rule_blocks_before_app_review": None,
    }


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


@pytest.mark.parametrize(
    ("field", "value", "remove", "message"),
    [
        ("redelivery", None, False, "Boolean redelivery"),
        ("redelivery", "false", False, "Boolean redelivery"),
        ("redelivery", None, True, "Boolean redelivery"),
        ("status_code", True, False, "integer status"),
        ("status_code", "202", False, "integer status"),
        ("status_code", None, True, "integer status"),
    ],
)
def test_delivery_sanitizer_rejects_missing_or_invalid_status_metadata(
    field: str,
    value: object,
    remove: bool,
    message: str,
) -> None:
    delivery: dict[str, Any] = {
        "event": "installation_repositories",
        "action": "added",
        "status_code": 202,
        "redelivery": False,
        "request": {"payload": {}},
    }
    if remove:
        del delivery[field]
    else:
        delivery[field] = value

    with pytest.raises(ContractError, match=message):
        sanitize_delivery(delivery)


def test_installation_add_requires_the_fixture_in_repositories_added() -> None:
    delivery = {
        "request": {
            "payload": {
                "action": "added",
                "installation": {"id": 456},
                "repositories_added": [
                    {"id": 123, "full_name": "example/one"},
                    {"id": 456, "full_name": "example/two"},
                ],
                "repositories_removed": [],
            }
        }
    }

    assert installation_add_targets_repository(
        delivery,
        repository_id=456,
        installation_id=456,
    )
    assert not installation_add_targets_repository(
        delivery,
        repository_id=789,
        installation_id=456,
    )


def test_installation_add_rejects_boolean_ids() -> None:
    delivery = {
        "request": {
            "payload": {
                "action": "added",
                "installation": {"id": 456},
                "repositories_added": [{"id": True}],
                "repositories_removed": [],
            }
        }
    }

    with pytest.raises(ContractError, match="positive integer"):
        installation_add_targets_repository(
            delivery,
            repository_id=1,
            installation_id=456,
        )


def test_installation_add_ignores_repository_field_and_removed_only_target() -> None:
    payload = {
        "action": "added",
        "installation": {"id": 456},
        "repository": {"id": 789},
        "repositories_added": [{"id": 999}],
        "repositories_removed": [{"id": 789}],
    }

    assert not installation_add_targets_repository(
        {"request": {"payload": payload}},
        repository_id=789,
        installation_id=456,
    )


def test_installation_add_rejects_missing_change_lists() -> None:
    delivery = {
        "request": {
            "payload": {
                "action": "added",
                "installation": {"id": 456},
                "repository": {"id": 789},
            }
        }
    }

    with pytest.raises(ContractError, match="repositories_added"):
        installation_add_targets_repository(
            delivery,
            repository_id=789,
            installation_id=456,
        )


def test_installation_add_rejects_contradictory_change_lists() -> None:
    delivery = {
        "request": {
            "payload": {
                "action": "added",
                "installation": {"id": 456},
                "repositories_added": [{"id": 789}],
                "repositories_removed": [{"id": 789}],
            }
        }
    }

    with pytest.raises(ContractError, match="both change lists"):
        installation_add_targets_repository(
            delivery,
            repository_id=789,
            installation_id=456,
        )


@pytest.mark.parametrize(
    ("action", "installation_id"),
    [("removed", 456), ("added", 999), ("added", True)],
)
def test_installation_add_rejects_wrong_action_or_installation(
    action: str,
    installation_id: object,
) -> None:
    delivery = {
        "request": {
            "payload": {
                "action": action,
                "installation": {"id": installation_id},
                "repositories_added": [{"id": 789}],
                "repositories_removed": [],
            }
        }
    }

    with pytest.raises(ContractError, match=r"action|installation"):
        installation_add_targets_repository(
            delivery,
            repository_id=789,
            installation_id=456,
        )


def delivery_detail(
    delivery_id: int,
    *,
    event: str,
    action: str,
    repository_id: int = 789,
) -> dict[str, Any]:
    return {
        "id": delivery_id,
        "installation_id": 456,
        "repository_id": repository_id,
        "event": event,
        "action": action,
        "status_code": 202,
        "redelivery": False,
        "request": {
            "headers": {"X-Hub-Signature-256": "sha256=secret"},
            "payload": {
                "installation": {"id": 456},
                "repository": {"id": repository_id, "full_name": "private/name"},
                "sender": {"login": "private-user"},
            },
        },
    }


def delivery_summary(
    delivery_id: int,
    *,
    event: str,
    action: str,
    installation_id: int = 456,
    repository_id: int | None = 789,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": delivery_id,
        "installation_id": installation_id,
        "event": event,
        "action": action,
        "status_code": 202,
        "redelivery": False,
    }
    if repository_id is not None:
        result["repository_id"] = repository_id
    return result


def webhook_fixture(client: StubClient, *, selection: str) -> Fixture:
    fixture = fixture_without_network()
    fixture.checker_auth = cast(AppAuth, StubAuth([], jwt_clients=[client]))
    fixture.report = {
        "fixture": {"checker_repository_selection": selection},
        "assertions": {},
        "webhook_contracts": [],
    }
    return fixture


def test_webhook_capture_transcript_records_only_sanitized_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summaries = [
        delivery_summary(1, event="pull_request", action="opened"),
        delivery_summary(2, event="pull_request", action="edited"),
        delivery_summary(
            3,
            event="installation_repositories",
            action="added",
            repository_id=None,
        ),
    ]
    added = delivery_detail(3, event="installation_repositories", action="added")
    added["request"]["payload"] = {
        "action": "added",
        "installation": {"id": 456},
        "repositories_added": [{"id": 789, "full_name": "private/name"}],
        "repositories_removed": [],
        "sender": {"login": "private-user"},
    }
    client = StubClient(
        [],
        [
            summaries,
            delivery_detail(1, event="pull_request", action="opened"),
            delivery_detail(2, event="pull_request", action="edited"),
            added,
        ],
    )
    fixture = webhook_fixture(client, selection="selected")
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    fixture._capture_webhook_contracts()

    assert fixture.report["assertions"] == {
        "pull_request_opened_delivery_observed": True,
        "pull_request_retarget_delivery_observed": True,
        "installation_repository_added_delivery_observed": True,
    }
    assert len(fixture.report["webhook_contracts"]) == 3
    serialized = repr(fixture.report)
    assert "sha256=secret" not in serialized
    assert "private/name" not in serialized
    assert "private-user" not in serialized
    assert client.closed


def test_all_repository_webhook_capture_marks_selection_probe_not_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summaries = [
        delivery_summary(1, event="pull_request", action="opened"),
        delivery_summary(2, event="pull_request", action="edited"),
    ]
    client = StubClient(
        [],
        [
            summaries,
            delivery_detail(1, event="pull_request", action="opened"),
            delivery_detail(2, event="pull_request", action="edited"),
        ],
    )
    fixture = webhook_fixture(client, selection="all")
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    fixture._capture_webhook_contracts()

    assert fixture.report["assertions"]["installation_repository_added_delivery_observed"] is None


def test_selected_webhook_capture_waits_for_a_delayed_targeted_add(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pull_summaries = [
        delivery_summary(1, event="pull_request", action="opened"),
        delivery_summary(2, event="pull_request", action="edited"),
    ]
    add_summary = delivery_summary(
        3,
        event="installation_repositories",
        action="added",
        repository_id=None,
    )
    added = delivery_detail(3, event="installation_repositories", action="added")
    added["request"]["payload"] = {
        "action": "added",
        "installation": {"id": 456},
        "repositories_added": [{"id": 789, "full_name": "private/name"}],
        "repositories_removed": [],
    }
    client = StubClient(
        [],
        [
            pull_summaries,
            delivery_detail(1, event="pull_request", action="opened"),
            delivery_detail(2, event="pull_request", action="edited"),
            [*pull_summaries, add_summary],
            added,
        ],
    )
    fixture = webhook_fixture(client, selection="selected")
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    fixture._capture_webhook_contracts()

    listings = [
        request for request in client.transcript if request["path"] == "/app/hook/deliveries"
    ]
    assert len(listings) == 2
    assert fixture.report["assertions"]["installation_repository_added_delivery_observed"] is True


def test_selected_webhook_capture_waits_for_the_bound_before_recording_no_add(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summaries = [
        delivery_summary(1, event="pull_request", action="opened"),
        delivery_summary(2, event="pull_request", action="edited"),
    ]
    client = StubClient(
        [],
        [
            summaries,
            delivery_detail(1, event="pull_request", action="opened"),
            delivery_detail(2, event="pull_request", action="edited"),
        ],
    )
    fixture = webhook_fixture(client, selection="selected")
    monotonic_values = iter((0.0, 0.0, 31.0))
    monkeypatch.setattr(
        "tools.live_github_contract.time.monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    fixture._capture_webhook_contracts()

    assert fixture.report["assertions"] == {
        "pull_request_opened_delivery_observed": True,
        "pull_request_retarget_delivery_observed": True,
        "installation_repository_added_delivery_observed": False,
    }


def test_unrelated_add_does_not_complete_selected_webhook_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summaries = [
        delivery_summary(1, event="pull_request", action="opened"),
        delivery_summary(2, event="pull_request", action="edited"),
        delivery_summary(
            3,
            event="installation_repositories",
            action="added",
            repository_id=None,
        ),
    ]
    unrelated = delivery_detail(
        3,
        event="installation_repositories",
        action="added",
        repository_id=999,
    )
    unrelated["request"]["payload"] = {
        "action": "added",
        "installation": {"id": 456},
        "repositories_added": [{"id": 999, "full_name": "private/other"}],
        "repositories_removed": [],
    }
    client = StubClient(
        [],
        [
            summaries,
            delivery_detail(1, event="pull_request", action="opened"),
            delivery_detail(2, event="pull_request", action="edited"),
            unrelated,
        ],
    )
    fixture = webhook_fixture(client, selection="selected")
    monotonic_values = iter((0.0, 0.0, 31.0))
    monkeypatch.setattr(
        "tools.live_github_contract.time.monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    fixture._capture_webhook_contracts()

    assert fixture.report["assertions"]["installation_repository_added_delivery_observed"] is False
    assert len(fixture.report["webhook_contracts"]) == 2


def test_webhook_capture_follows_validated_pagination_in_a_busy_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_page = [
        delivery_summary(
            delivery_id,
            event="push",
            action="completed",
            installation_id=999,
            repository_id=None,
        )
        for delivery_id in range(1, 101)
    ]
    next_link = (
        "<https://api.github.com/app/hook/deliveries"
        '?per_page=100&cursor=private-cursor>; rel="next"'
    )
    second_page = [
        delivery_summary(101, event="pull_request", action="opened"),
        delivery_summary(102, event="pull_request", action="edited"),
    ]
    client = StubClient(
        [],
        [
            (first_page, next_link),
            second_page,
            delivery_detail(101, event="pull_request", action="opened"),
            delivery_detail(102, event="pull_request", action="edited"),
        ],
    )
    fixture = webhook_fixture(client, selection="all")
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    fixture._capture_webhook_contracts()

    capture = fixture.report["webhook_capture"]
    assert capture["delivery_window_complete"] is True
    assert capture["last_poll_pages_read"] == 2
    assert capture["pages_read_total"] == 2
    assert capture["incomplete_observations"] == []
    assert fixture.report["assertions"]["pull_request_opened_delivery_observed"] is True
    assert fixture.report["assertions"]["pull_request_retarget_delivery_observed"] is True
    assert "private-cursor" not in repr(fixture.report)
    assert "api.github.com" not in repr(fixture.report)


def test_truncated_webhook_window_marks_unseen_selected_add_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summaries = [
        delivery_summary(1, event="pull_request", action="opened"),
        delivery_summary(2, event="pull_request", action="edited"),
    ]
    next_link = (
        "<https://api.github.com/app/hook/deliveries"
        '?per_page=100&cursor=private-cursor>; rel="next"'
    )
    client = StubClient(
        [],
        [
            (summaries, next_link),
            delivery_detail(1, event="pull_request", action="opened"),
            delivery_detail(2, event="pull_request", action="edited"),
        ],
    )
    fixture = webhook_fixture(client, selection="selected")
    monotonic_values = iter((0.0, 0.0, 31.0))
    monkeypatch.setattr(contract_module, "WEBHOOK_DELIVERY_PAGE_LIMIT", 1)
    monkeypatch.setattr(
        "tools.live_github_contract.time.monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    fixture._capture_webhook_contracts()

    assertion_name = "installation_repository_added_delivery_observed"
    assert assertion_name not in fixture.report["assertions"]
    assert fixture.report["webhook_capture"]["delivery_window_complete"] is False
    assert fixture.report["webhook_capture"]["incomplete_observations"] == [assertion_name]
    completeness = evidence_completeness(fixture.report, approver_configured=False)
    assert completeness["observations"][assertion_name] == "incomplete"
    assert completeness["incomplete"] == [assertion_name]
    assert completeness["configured_observations_complete"] is False
    assert "private-cursor" not in repr(fixture.report)


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("summary", "id", True),
        ("summary", "installation_id", True),
        ("summary", "repository_id", True),
        ("detail", "id", True),
        ("detail", "id", 2),
        ("detail", "installation_id", 999),
        ("detail", "repository_id", 999),
        ("detail", "event", "push"),
        ("detail", "action", "edited"),
        ("detail", "redelivery", True),
        ("detail", "status_code", 500),
    ],
)
def test_webhook_capture_rejects_summary_detail_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    field: str,
    value: object,
) -> None:
    listed = delivery_summary(1, event="pull_request", action="opened")
    fetched = delivery_detail(1, event="pull_request", action="opened")
    if target == "summary":
        listed[field] = value
    else:
        fetched[field] = value
    client = StubClient([], [[listed], fetched])
    fixture = webhook_fixture(client, selection="all")
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    with pytest.raises(ContractError, match="GitHub delivery"):
        fixture._capture_webhook_contracts()

    assert client.closed


def test_fixture_run_follows_the_complete_check_transition_transcript(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = object.__new__(Fixture)
    fixture.config = config()
    fixture.operator = cast(
        RestClient,
        StubClient(
            [404],
            [
                {"id": 789, "default_branch": "main"},
                {"object": {"sha": "a" * 40}},
                None,
            ],
        ),
    )
    fixture.repository_selection = None
    fixture.checker_auth = cast(AppAuth, StubAuth([]))
    fixture.checker = None
    fixture.approver_auth = None
    fixture.approver = None
    fixture.repository_name = "fixture-repository"
    fixture.repository = "fixture-org/fixture-repository"
    fixture.repository_created = False
    fixture.repository_id = None
    fixture.default_branch = ""
    fixture.organization_ruleset_name = "fixture organization rule"
    fixture.organization_ruleset_id = None
    fixture.report = {
        "schema_version": contract_module.REPORT_SCHEMA_VERSION,
        "api_version": contract_module.API_VERSION,
        "source_revision": "a" * 40,
        "started_at": "2026-07-23T00:00:00+00:00",
        "fixture": {
            "approver_repository_selection": None,
            "checker_repository_selection": None,
            "private_repository": True,
            "repository_kept": False,
        },
        "assertions": {},
        "webhook_contracts": [],
    }
    fixture._ensure_app_access = lambda *args, **kwargs: cast(  # type: ignore[method-assign]
        RestClient, StubClient([])
    )
    branches: list[tuple[str, str]] = []
    fixture._create_branch = lambda branch, sha: branches.append((branch, sha))  # type: ignore[method-assign]
    fixture._commit_file = lambda branch, path, content: "b" * 40  # type: ignore[method-assign]
    fixture._create_check = lambda sha: 77  # type: ignore[method-assign]

    def rulesets() -> None:
        fixture.report["assertions"].update(
            {
                "organization_ruleset_expected_source": True,
                "repository_ruleset_expected_source": True,
            }
        )

    fixture._create_rulesets = rulesets  # type: ignore[method-assign]
    pulls = iter((1, 2))
    fixture._create_pull = lambda **kwargs: next(pulls)  # type: ignore[method-assign]
    outcomes = iter((True, False, True, True, True, False, False, True, True, True))

    def merge_outcome(pull_number: int, *, preferred: bool | None = None) -> bool:
        del pull_number, preferred
        return next(outcomes)

    fixture._wait_for_merge_outcome = merge_outcome  # type: ignore[method-assign]

    def merge_attempt(pull_number: int) -> tuple[bool, int]:
        return True, pull_number

    fixture._attempt_in_progress_merge = merge_attempt  # type: ignore[method-assign]
    check_updates: list[str] = []
    fixture._update_check = lambda check_id, status: check_updates.append(status)  # type: ignore[method-assign]

    def app_review(base_sha: str) -> None:
        fixture.report["assertions"].update(
            {
                "numeric_approval_rule_blocks_before_app_review": None,
                "app_review_attributed_to_bot": None,
                "app_review_counts_as_numeric_approval": None,
            }
        )

    fixture._exercise_app_review = app_review  # type: ignore[method-assign]

    def webhooks() -> None:
        fixture.report["assertions"].update(
            {
                "pull_request_opened_delivery_observed": True,
                "pull_request_retarget_delivery_observed": True,
                "installation_repository_added_delivery_observed": None,
            }
        )

    fixture._capture_webhook_contracts = webhooks  # type: ignore[method-assign]
    monkeypatch.setattr("tools.live_github_contract.time.sleep", lambda _: None)

    report = fixture.run()

    assert branches == [
        ("alternate", "a" * 40),
        ("replacement", "a" * 40),
        ("retarget", "a" * 40),
        ("shared-head", "a" * 40),
    ]
    assert check_updates == ["in_progress", "completed", "in_progress", "completed"]
    assert report["assertions"]["completed_success_to_in_progress_blocks_merge"] is True
    assert report["assertions"]["shared_head_invalidation_blocks_both_pull_requests"] is True
    assert report["assertions"]["shared_head_inherits_success_before_invalidation"] is True
    assert report["interpretation"]["github_contract_fail_closed"] is False


def repository_creation_fixture(operator: StubClient) -> Fixture:
    fixture = fixture_without_network()
    fixture.operator = cast(RestClient, operator)
    fixture.repository_created = False
    fixture.repository_creation_attempted = False
    fixture.repository_creation_outcome_unknown = False
    fixture.repository_creation_state = "not_attempted"
    fixture.organization_ruleset_name = "fixture organization rule"
    fixture.organization_ruleset_id = None
    fixture.organization_ruleset_creation_attempted = False
    fixture.checker = None
    fixture.approver = None
    fixture.report = {
        "fixture": {"repository_creation_state": "not_attempted"},
        "assertions": {},
    }
    return fixture


def test_fixture_uses_a_128_bit_repository_suffix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "checker.pem"
    private_key.write_text("not parsed while the fixture is initialized")
    runtime = replace(
        config(),
        checker=AppCredentials(123, 456, private_key),
    )
    requested_bytes: list[int] = []

    def token_hex(byte_count: int) -> str:
        requested_bytes.append(byte_count)
        return "a" * (byte_count * 2)

    monkeypatch.setattr("tools.live_github_contract.secrets.token_hex", token_hex)

    fixture = Fixture(runtime)
    try:
        assert requested_bytes == [16]
        assert fixture.repository_name == f"extra-codeowners-contract-{'a' * 32}"
        assert fixture.report["fixture"]["repository_creation_state"] == "not_attempted"
    finally:
        assert fixture.close() == []


@pytest.mark.parametrize(
    "create_error",
    [
        json.JSONDecodeError("private JSON detail", "private document", 0),
        httpx.ReadTimeout("private transport detail"),
    ],
    ids=["invalid-json", "transport-loss"],
)
def test_repository_creation_recovers_an_unknown_accepted_request(
    create_error: Exception,
    capsys: pytest.CaptureFixture[str],
) -> None:
    operator = StubClient([404, 200], [create_error, None])
    fixture = repository_creation_fixture(operator)

    with pytest.raises(type(create_error)):
        fixture._create_repository()

    output = capsys.readouterr().out
    assert output.index("owner: fixture-org") < output.index("name: fixture-repository")
    assert "URL: https://github.com/fixture-org/fixture-repository" in output
    assert fixture.repository_creation_attempted is True
    assert fixture.repository_creation_outcome_unknown is True
    assert fixture.report["fixture"]["repository_creation_state"] == ("attempted_response_unknown")

    assert fixture.close() == []
    assert fixture.report["fixture"]["repository_creation_state"] == "response_unknown_cleaned"
    assert [request["method"] for request in operator.transcript] == [
        "GET",
        "POST",
        "GET",
        "DELETE",
    ]
    assert "private" not in repr(fixture.report)


def test_repository_creation_resolves_an_unknown_request_that_created_nothing() -> None:
    operator = StubClient(
        [404, 404],
        [httpx.ReadTimeout("private transport detail")],
    )
    fixture = repository_creation_fixture(operator)

    with pytest.raises(httpx.ReadTimeout):
        fixture._create_repository()

    assert fixture.close() == []
    assert fixture.report["fixture"]["repository_creation_state"] == (
        "response_unknown_resolved_absent"
    )
    assert [request["method"] for request in operator.transcript] == ["GET", "POST", "GET"]


def test_repository_creation_cleans_up_after_a_malformed_success_body() -> None:
    operator = StubClient([404], [None, None])
    fixture = repository_creation_fixture(operator)

    with pytest.raises(ContractError, match="created repository"):
        fixture._create_repository()

    assert fixture.repository_created is True
    assert fixture.repository_creation_outcome_unknown is False
    assert fixture.close() == []
    assert fixture.report["fixture"]["repository_creation_state"] == "response_confirmed_cleaned"
    assert [request["method"] for request in operator.transcript] == [
        "GET",
        "POST",
        "DELETE",
    ]


def test_repository_creation_recovery_failure_requires_manual_cleanup() -> None:
    operator = StubClient(
        [404, 503],
        [httpx.ReadTimeout("private transport detail")],
    )
    fixture = repository_creation_fixture(operator)

    with pytest.raises(httpx.ReadTimeout):
        fixture._create_repository()

    assert fixture.close() == ["repository recovery failed (ContractError)"]
    assert fixture.report["fixture"]["repository_creation_state"] == "manual_cleanup_required"
    assert "private" not in repr(fixture.report)


def test_cleanup_transcript_discovers_the_ruleset_and_closes_clients() -> None:
    operator = StubClient(
        [],
        [
            [{"id": 91, "name": "fixture organization rule"}],
            None,
            None,
        ],
    )
    fixture = fixture_without_network()
    fixture.operator = cast(RestClient, operator)
    fixture.repository_created = True
    fixture.organization_ruleset_name = "fixture organization rule"
    fixture.organization_ruleset_id = None
    fixture.organization_ruleset_creation_attempted = True
    checker = StubClient([])
    approver = StubClient([])
    repository_selection = StubClient([])
    fixture.checker = cast(RestClient, checker)
    fixture.approver = cast(RestClient, approver)
    fixture.repository_selection = cast(RestClient, repository_selection)

    assert fixture.close() == []

    assert [request["path"] for request in operator.transcript] == [
        "/orgs/fixture-org/rulesets",
        "/orgs/fixture-org/rulesets/91",
        "/repos/fixture-org/fixture-repository",
    ]
    assert checker.closed
    assert approver.closed
    assert repository_selection.closed
    assert operator.closed


def test_cleanup_records_each_failure_and_still_closes_clients() -> None:
    operator = StubClient(
        [],
        [
            ContractError("ruleset delete failed"),
            ContractError("repository delete failed"),
        ],
    )
    fixture = fixture_without_network()
    fixture.operator = cast(RestClient, operator)
    fixture.repository_created = True
    fixture.organization_ruleset_id = 91
    checker = StubClient([])
    fixture.checker = cast(RestClient, checker)
    fixture.approver = None

    assert fixture.close() == [
        "organization ruleset cleanup failed (ContractError)",
        "repository cleanup failed (ContractError)",
    ]
    assert [request["path"] for request in operator.transcript] == [
        "/orgs/fixture-org/rulesets/91",
        "/repos/fixture-org/fixture-repository",
    ]
    assert checker.closed
    assert operator.closed


def test_cleanup_continues_after_transport_failure_without_retaining_provider_detail() -> None:
    operator = StubClient(
        [],
        [
            httpx.ReadTimeout("private transport detail"),
            None,
        ],
    )
    fixture = fixture_without_network()
    fixture.operator = cast(RestClient, operator)
    fixture.repository_created = True
    fixture.organization_ruleset_id = 91
    checker = StubClient([])
    fixture.checker = cast(RestClient, checker)
    fixture.approver = None

    errors = fixture.close()

    assert errors == ["organization ruleset cleanup failed (ReadTimeout)"]
    assert "private transport detail" not in repr(errors)
    assert [request["path"] for request in operator.transcript] == [
        "/orgs/fixture-org/rulesets/91",
        "/repos/fixture-org/fixture-repository",
    ]
    assert checker.closed
    assert operator.closed


def test_cleanup_continues_after_ruleset_discovery_json_failure() -> None:
    operator = StubClient(
        [],
        [
            json.JSONDecodeError("private provider detail", "private document", 0),
            None,
        ],
    )
    fixture = fixture_without_network()
    fixture.operator = cast(RestClient, operator)
    fixture.repository_created = True
    fixture.organization_ruleset_name = "fixture organization rule"
    fixture.organization_ruleset_id = None
    fixture.organization_ruleset_creation_attempted = True
    fixture.checker = None
    fixture.approver = None

    errors = fixture.close()

    assert errors == ["organization ruleset discovery failed (JSONDecodeError)"]
    assert "private" not in repr(errors)
    assert [request["path"] for request in operator.transcript] == [
        "/orgs/fixture-org/rulesets",
        "/repos/fixture-org/fixture-repository",
    ]
    assert operator.closed


def test_cleanup_attempts_every_client_close_after_close_failure() -> None:
    fixture = fixture_without_network()
    fixture.repository_created = False
    fixture.organization_ruleset_id = None
    fixture.organization_ruleset_creation_attempted = False
    checker = StubClient(
        [],
        close_error=httpx.ReadTimeout("private checker close detail"),
    )
    approver = StubClient([])
    repository_selection = StubClient([])
    operator = StubClient(
        [],
        close_error=json.JSONDecodeError(
            "private operator close detail",
            "private document",
            0,
        ),
    )
    fixture.checker = cast(RestClient, checker)
    fixture.approver = cast(RestClient, approver)
    fixture.repository_selection = cast(RestClient, repository_selection)
    fixture.operator = cast(RestClient, operator)

    errors = fixture.close()

    assert errors == [
        "checker client close failed (ReadTimeout)",
        "operator client close failed (JSONDecodeError)",
    ]
    assert "private" not in repr(errors)
    assert checker.closed
    assert approver.closed
    assert repository_selection.closed
    assert operator.closed


def test_keep_mode_names_both_retained_resources_and_closes_clients(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = fixture_without_network()
    fixture.config = config(keep_repository=True)
    fixture.organization_ruleset_name = "fixture organization rule"
    fixture.organization_ruleset_id = 91
    fixture.repository_created = True
    operator = StubClient([])
    checker = StubClient([])
    fixture.operator = cast(RestClient, operator)
    fixture.checker = cast(RestClient, checker)
    fixture.approver = None

    assert fixture.close() == []

    output = capsys.readouterr().out
    assert "retaining any created fixture repository" in output
    assert "https://github.com/fixture-org/fixture-repository" in output
    assert "organization ruleset 'fixture organization rule'" in output
    assert operator.transcript == []
    assert checker.closed
    assert operator.closed


def test_main_writes_machine_readable_completeness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_file = tmp_path / "report.json"
    runtime = replace(config(), report_file=report_file)
    assertions = {
        **dict.fromkeys(contract_module.CORE_OBSERVATIONS, False),
        **dict.fromkeys(contract_module.APP_REVIEW_OBSERVATIONS),
        **dict.fromkeys(contract_module.DIAGNOSTIC_OBSERVATIONS),
    }

    class MainFixture:
        def __init__(self, supplied: Config) -> None:
            assert supplied is runtime
            self.report = {
                "fixture": {
                    "checker_repository_selection": "all",
                    "repository_creation_state": "not_attempted",
                },
                "assertions": assertions,
                "webhook_capture": complete_webhook_capture(),
            }

        def run(self) -> dict[str, Any]:
            return self.report

        def close(self) -> list[str]:
            return []

    monkeypatch.setattr(Config, "from_environment", classmethod(lambda cls: runtime))
    monkeypatch.setattr(contract_module, "Fixture", MainFixture)

    assert contract_module.main() == 0

    report = json.loads(report_file.read_text())
    assert report["result"] == "observed"
    assert report["cleanup_succeeded"] is True
    assert report["evidence_completeness"]["configured_run_complete"] is True
    assert report["evidence_completeness"]["full_automated_observations_complete"] is False


def test_main_marks_failed_observation_and_cleanup_as_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_file = tmp_path / "failed-report.json"
    runtime = replace(config(), report_file=report_file)

    class FailedFixture:
        def __init__(self, supplied: Config) -> None:
            assert supplied is runtime
            self.report = {
                "fixture": {"checker_repository_selection": "all"},
                "assertions": {"organization_ruleset_expected_source": True},
            }

        def run(self) -> dict[str, Any]:
            raise ContractError("private provider detail")

        def close(self) -> list[str]:
            return ["private cleanup detail"]

    monkeypatch.setattr(Config, "from_environment", classmethod(lambda cls: runtime))
    monkeypatch.setattr(contract_module, "Fixture", FailedFixture)

    assert contract_module.main() == 1

    report = json.loads(report_file.read_text())
    assert report["result"] == "failed"
    assert report["failure_type"] == "ContractError"
    assert report["cleanup_succeeded"] is False
    assert report["cleanup_failure_count"] == 1
    assert report["evidence_completeness"]["configured_run_complete"] is False
    assert "repository_ruleset_expected_source" in report["evidence_completeness"]["missing"]
    assert "private provider detail" not in json.dumps(report)
    assert "private cleanup detail" not in json.dumps(report)


def test_main_writes_sanitized_report_when_cleanup_raises_transport_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_file = tmp_path / "cleanup-exception-report.json"
    runtime = replace(config(), report_file=report_file)

    class CleanupExceptionFixture:
        def __init__(self, supplied: Config) -> None:
            assert supplied is runtime
            self.report = {
                "fixture": {"checker_repository_selection": "all"},
                "assertions": {
                    **dict.fromkeys(contract_module.CORE_OBSERVATIONS, True),
                    **dict.fromkeys(contract_module.APP_REVIEW_OBSERVATIONS),
                    **dict.fromkeys(contract_module.DIAGNOSTIC_OBSERVATIONS),
                },
            }

        def run(self) -> dict[str, Any]:
            return self.report

        def close(self) -> list[str]:
            raise httpx.ReadTimeout("private transport detail")

    monkeypatch.setattr(Config, "from_environment", classmethod(lambda cls: runtime))
    monkeypatch.setattr(contract_module, "Fixture", CleanupExceptionFixture)

    assert contract_module.main() == 1

    report = json.loads(report_file.read_text())
    assert report["result"] == "observed"
    assert report["cleanup_succeeded"] is False
    assert report["cleanup_failure_count"] == 1
    assert report["evidence_completeness"]["configured_run_complete"] is False
    assert "private transport detail" not in json.dumps(report)


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
