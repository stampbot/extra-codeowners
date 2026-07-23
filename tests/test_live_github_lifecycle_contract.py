from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import tools.capture_github_lifecycle_contract as lifecycle_module
from tools.capture_github_lifecycle_contract import (
    CaptureConfig,
    capture_lifecycle_contracts,
)
from tools.live_github_contract import AppCredentials, ContractError, RestClient


class CaptureClient:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = responses
        self.closed = False
        self.transcript: list[dict[str, Any]] = []

    def _next_response(self) -> Any:
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, str | int] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        self.transcript.append(
            {
                "method": method,
                "path": path,
                "body": body,
                "params": params,
                "expected": expected,
            }
        )
        return self._next_response()

    def request_with_link(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str | int] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> tuple[Any, str | None]:
        self.transcript.append(
            {
                "method": method,
                "path": path,
                "body": None,
                "params": params,
                "expected": expected,
            }
        )
        response = self._next_response()
        if (
            isinstance(response, tuple)
            and len(response) == 2
            and (response[1] is None or isinstance(response[1], str))
        ):
            return response
        return response, None

    def close(self) -> None:
        self.closed = True


def capture_config(
    tmp_path: Path,
    *,
    expected: tuple[str, ...] = (
        "installation.unsuspend",
        "installation_repositories.removed",
    ),
) -> CaptureConfig:
    return CaptureConfig(
        credentials=AppCredentials(123, 456, Path("unused.pem")),
        source_revision="a" * 40,
        since_text="2026-07-23T12:00:00Z",
        since=datetime(2026, 7, 23, 12, tzinfo=UTC),
        expected=expected,
        report_file=tmp_path / "lifecycle.json",
    )


def summary(
    delivery_id: int,
    *,
    event: str,
    action: str | None,
    delivered_at: str = "2026-07-23T12:05:00Z",
    installation_id: int = 456,
) -> dict[str, Any]:
    return {
        "id": delivery_id,
        "installation_id": installation_id,
        "delivered_at": delivered_at,
        "event": event,
        "action": action,
        "status_code": 202,
        "redelivery": False,
    }


def detail(
    delivery_id: int,
    *,
    event: str,
    action: str,
    delivered_at: str = "2026-07-23T12:05:00Z",
) -> dict[str, Any]:
    return {
        **summary(
            delivery_id,
            event=event,
            action=action,
            delivered_at=delivered_at,
        ),
        "url": f"https://private.example/deliveries/{delivery_id}",
        "request": {
            "headers": {
                "Authorization": "Bearer private-token",
                "X-Hub-Signature-256": "sha256=private-signature",
            },
            "payload": {
                "action": action,
                "installation": {"id": 456, "account": {"login": "private-org"}},
                "organization": {"login": "private-org"},
                "repository": {"id": 789, "full_name": "private-org/private-repo"},
                "sender": {"login": "private-user"},
            },
        },
        "response": {"payload": "private response"},
    }


def test_capture_records_unique_sanitized_contracts_and_missing_events(tmp_path: Path) -> None:
    summaries = [
        summary(1, event="installation", action="unsuspend"),
        summary(2, event="installation", action="unsuspend"),
        summary(3, event="installation", action="created", installation_id=999),
        summary(
            4,
            event="installation_repositories",
            action="removed",
            delivered_at="2026-07-23T11:59:59Z",
        ),
    ]
    client = CaptureClient(
        [
            summaries,
            detail(1, event="installation", action="unsuspend"),
            detail(2, event="installation", action="unsuspend"),
        ]
    )

    report = capture_lifecycle_contracts(
        capture_config(tmp_path),
        client=cast(RestClient, client),
    )

    assert report["result"] == "observed"
    assert report["delivery_window_complete"] is True
    assert report["delivery_details_complete"] is True
    assert report["capture_complete"] is False
    assert report["observations"]["installation.unsuspend"] == {
        "state": "observed",
        "delivery_count": 2,
        "contracts": [
            {
                "action": "unsuspend",
                "event": "installation",
                "payload_shape": {
                    "installation_keys": ["account", "id"],
                    "organization_keys": ["login"],
                    "repository_keys": ["full_name", "id"],
                    "root_keys": [
                        "action",
                        "installation",
                        "organization",
                        "repository",
                        "sender",
                    ],
                    "sender_keys": ["login"],
                },
                "redelivery": False,
                "status_code": 202,
            }
        ],
    }
    assert report["observations"]["installation_repositories.removed"] == {
        "state": "not_observed",
        "delivery_count": 0,
        "contracts": [],
    }
    serialized = json.dumps(report)
    assert "private-token" not in serialized
    assert "private-signature" not in serialized
    assert "private-org" not in serialized
    assert "private-user" not in serialized
    assert "private.example" not in serialized
    assert not client.closed


def test_full_page_without_next_link_is_a_complete_window(tmp_path: Path) -> None:
    summaries = [
        summary(1, event="installation", action="unsuspend"),
        *[
            summary(
                delivery_id,
                event="installation",
                action="created",
                installation_id=999,
            )
            for delivery_id in range(2, lifecycle_module.DELIVERY_LIST_LIMIT + 1)
        ],
    ]
    client = CaptureClient(
        [
            summaries,
            detail(1, event="installation", action="unsuspend"),
        ]
    )

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("installation.unsuspend",)),
        client=cast(RestClient, client),
    )

    assert report["result"] == "observed"
    assert report["delivery_window_complete"] is True
    assert report["delivery_pages_read"] == 1
    assert report["capture_complete"] is True
    assert report["observations"]["installation.unsuspend"]["state"] == "observed"


def test_short_page_with_next_link_follows_its_validated_cursor(
    tmp_path: Path,
) -> None:
    next_link = (
        '<https://api.github.com/app/hook/deliveries?per_page=100&cursor=cursor-2>; rel="next"'
    )
    client = CaptureClient(
        [
            (
                [summary(1, event="push", action=None, installation_id=999)],
                next_link,
            ),
            [summary(2, event="installation", action="unsuspend")],
            detail(2, event="installation", action="unsuspend"),
        ]
    )

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("installation.unsuspend",)),
        client=cast(RestClient, client),
    )

    assert report["delivery_window_complete"] is True
    assert report["delivery_pages_read"] == 2
    assert report["capture_complete"] is True
    assert [entry["params"] for entry in client.transcript[:2]] == [
        {"per_page": lifecycle_module.DELIVERY_PAGE_SIZE},
        {
            "per_page": lifecycle_module.DELIVERY_LIST_LIMIT - 1,
            "cursor": "cursor-2",
        },
    ]
    serialized = json.dumps(report)
    assert "cursor-2" not in serialized
    assert "api.github.com" not in serialized


def test_next_link_at_the_summary_bound_marks_the_window_incomplete(
    tmp_path: Path,
) -> None:
    summaries = [
        summary(
            delivery_id,
            event="installation",
            action="created",
            installation_id=999,
        )
        for delivery_id in range(1, lifecycle_module.DELIVERY_LIST_LIMIT + 1)
    ]
    link = (
        "<https://api.github.com/app/hook/deliveries"
        '?per_page=100&cursor=more-private-data>; rel="next"'
    )
    client = CaptureClient([(summaries, link)])

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("installation.unsuspend",)),
        client=cast(RestClient, client),
    )

    assert report["delivery_window_complete"] is False
    assert report["capture_complete"] is False
    assert report["result"] == "incomplete"
    assert report["observations"]["installation.unsuspend"]["state"] == "incomplete"
    assert len(client.transcript) == 1
    assert "more-private-data" not in json.dumps(report)


@pytest.mark.parametrize(
    "link",
    [
        "not-a-link",
        (
            "<https://api.github.com/app/hook/deliveries?cursor=one>; "
            'rel="next", <https://api.github.com/app/hook/deliveries?cursor=two>; '
            'rel="next"'
        ),
        '<https://private.example/app/hook/deliveries?cursor=secret>; rel="next"',
        ('<https://api.github.com/app/hook/deliveries?cursor=one&cursor=two>; rel="next"'),
        '<https://api.github.com/app/hook/deliveries?cursor=>; rel="next"',
    ],
)
def test_malformed_or_ambiguous_link_fails_without_following_it(
    tmp_path: Path,
    link: str,
) -> None:
    client = CaptureClient(
        [
            (
                [summary(1, event="installation", action="created", installation_id=999)],
                link,
            )
        ]
    )

    with pytest.raises(ContractError, match="Link header is malformed or ambiguous") as caught:
        capture_lifecycle_contracts(
            capture_config(tmp_path, expected=("installation.unsuspend",)),
            client=cast(RestClient, client),
        )

    assert len(client.transcript) == 1
    assert "private.example" not in str(caught.value)
    assert "secret" not in str(caught.value)


def test_page_limit_marks_a_cursor_chain_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(lifecycle_module, "DELIVERY_PAGE_LIMIT", 2)
    first_link = '<https://api.github.com/app/hook/deliveries?cursor=cursor-2>; rel="next"'
    second_link = '<https://api.github.com/app/hook/deliveries?cursor=cursor-3>; rel="next"'
    client = CaptureClient(
        [
            ([], first_link),
            ([], second_link),
        ]
    )

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("installation.unsuspend",)),
        client=cast(RestClient, client),
    )

    assert report["delivery_pages_read"] == 2
    assert report["delivery_window_complete"] is False
    assert report["observations"]["installation.unsuspend"]["state"] == "incomplete"
    assert report["capture_complete"] is False


def test_unrelated_same_installation_event_with_null_action_is_skipped(
    tmp_path: Path,
) -> None:
    unrelated = summary(1, event="push", action=None)
    unrelated["delivered_at"] = None
    client = CaptureClient(
        [
            [
                unrelated,
                summary(2, event="installation", action="unsuspend"),
            ],
            detail(2, event="installation", action="unsuspend"),
        ]
    )

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("installation.unsuspend",)),
        client=cast(RestClient, client),
    )

    assert report["capture_complete"] is True
    assert report["observations"]["installation.unsuspend"]["delivery_count"] == 1


def test_unrequested_action_in_expected_event_family_is_skipped_before_timestamp_validation(
    tmp_path: Path,
) -> None:
    unrelated = summary(1, event="installation", action="created")
    unrelated["delivered_at"] = None
    client = CaptureClient(
        [
            [
                unrelated,
                summary(2, event="installation", action="unsuspend"),
            ],
            detail(2, event="installation", action="unsuspend"),
        ]
    )

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("installation.unsuspend",)),
        client=cast(RestClient, client),
    )

    assert report["capture_complete"] is True
    assert report["observations"]["installation.unsuspend"]["delivery_count"] == 1


def test_expected_event_with_null_action_is_rejected(tmp_path: Path) -> None:
    client = CaptureClient(
        [
            [
                summary(1, event="installation", action=None),
            ]
        ]
    )

    with pytest.raises(ContractError, match="omitted event or action"):
        capture_lifecycle_contracts(
            capture_config(tmp_path, expected=("installation.unsuspend",)),
            client=cast(RestClient, client),
        )


def test_capture_marks_an_event_incomplete_when_its_details_are_truncated(
    tmp_path: Path,
) -> None:
    count = lifecycle_module.DETAIL_LIMIT + 1
    summaries = [
        summary(delivery_id, event="installation", action="unsuspend")
        for delivery_id in range(1, count + 1)
    ]
    details = [
        detail(delivery_id, event="installation", action="unsuspend")
        for delivery_id in range(1, lifecycle_module.DETAIL_LIMIT + 1)
    ]
    client = CaptureClient([summaries, *details])

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("installation.unsuspend",)),
        client=cast(RestClient, client),
    )

    assert report["result"] == "incomplete"
    assert report["delivery_window_complete"] is True
    assert report["delivery_details_complete"] is False
    assert report["capture_complete"] is False
    assert report["observations"]["installation.unsuspend"]["state"] == "incomplete"
    assert report["observations"]["installation.unsuspend"]["delivery_count"] == count


def test_capture_rejects_detail_that_differs_from_its_summary(tmp_path: Path) -> None:
    client = CaptureClient(
        [
            [summary(1, event="installation", action="unsuspend")],
            detail(1, event="installation", action="deleted"),
        ]
    )

    with pytest.raises(ContractError, match="does not match"):
        capture_lifecycle_contracts(
            capture_config(tmp_path, expected=("installation.unsuspend",)),
            client=cast(RestClient, client),
        )


@pytest.mark.parametrize(
    ("field", "summary_value", "detail_value"),
    [
        ("status_code", 202, 500),
        ("redelivery", False, True),
        ("guid", "private-summary-guid", "private-detail-guid"),
        ("duration", 0.1, 0.2),
        ("status", "OK", "Failed"),
        ("repository_id", 789, 790),
        ("repository_id", 1, True),
        ("throttled_at", None, "2026-07-23T12:06:00Z"),
    ],
)
def test_capture_rejects_summary_detail_metadata_mismatch(
    tmp_path: Path,
    field: str,
    summary_value: object,
    detail_value: object,
) -> None:
    listed = summary(1, event="installation", action="unsuspend")
    listed[field] = summary_value
    fetched = detail(1, event="installation", action="unsuspend")
    fetched[field] = detail_value
    client = CaptureClient([[listed], fetched])

    with pytest.raises(ContractError, match="metadata does not match") as caught:
        capture_lifecycle_contracts(
            capture_config(tmp_path, expected=("installation.unsuspend",)),
            client=cast(RestClient, client),
        )

    assert "private-summary-guid" not in str(caught.value)
    assert "private-detail-guid" not in str(caught.value)


def test_repository_lifecycle_delivery_requires_matching_positive_repository_ids(
    tmp_path: Path,
) -> None:
    listed = summary(1, event="repository", action="renamed")
    listed["repository_id"] = 789
    fetched = detail(1, event="repository", action="renamed")
    fetched["repository_id"] = 789
    client = CaptureClient([[listed], fetched])

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("repository.renamed",)),
        client=cast(RestClient, client),
    )

    assert report["capture_complete"] is True
    assert report["observations"]["repository.renamed"]["state"] == "observed"


@pytest.mark.parametrize("repository_id", [True, False, 0, -1, "789", None])
def test_repository_lifecycle_delivery_rejects_non_positive_repository_ids(
    tmp_path: Path,
    repository_id: object,
) -> None:
    listed = summary(1, event="repository", action="renamed")
    listed["repository_id"] = repository_id
    fetched = detail(1, event="repository", action="renamed")
    fetched["repository_id"] = repository_id
    client = CaptureClient([[listed], fetched])

    with pytest.raises(ContractError, match="repository metadata"):
        capture_lifecycle_contracts(
            capture_config(tmp_path, expected=("repository.renamed",)),
            client=cast(RestClient, client),
        )


def test_repository_lifecycle_delivery_rejects_missing_repository_ids(
    tmp_path: Path,
) -> None:
    client = CaptureClient(
        [
            [summary(1, event="repository", action="renamed")],
            detail(1, event="repository", action="renamed"),
        ]
    )

    with pytest.raises(ContractError, match="repository metadata"):
        capture_lifecycle_contracts(
            capture_config(tmp_path, expected=("repository.renamed",)),
            client=cast(RestClient, client),
        )


def test_non_repository_lifecycle_delivery_accepts_nullable_repository_ids(
    tmp_path: Path,
) -> None:
    listed = summary(1, event="installation", action="unsuspend")
    listed["repository_id"] = None
    fetched = detail(1, event="installation", action="unsuspend")
    fetched["repository_id"] = None
    client = CaptureClient([[listed], fetched])

    report = capture_lifecycle_contracts(
        capture_config(tmp_path, expected=("installation.unsuspend",)),
        client=cast(RestClient, client),
    )

    assert report["capture_complete"] is True


def test_capture_rejects_summary_metadata_missing_from_detail(tmp_path: Path) -> None:
    listed = summary(1, event="installation", action="unsuspend")
    listed["guid"] = "private-summary-guid"
    client = CaptureClient(
        [
            [listed],
            detail(1, event="installation", action="unsuspend"),
        ]
    )

    with pytest.raises(ContractError, match="metadata does not match") as caught:
        capture_lifecycle_contracts(
            capture_config(tmp_path, expected=("installation.unsuspend",)),
            client=cast(RestClient, client),
        )

    assert "private-summary-guid" not in str(caught.value)


@pytest.mark.parametrize(
    ("target", "field", "value", "remove", "message"),
    [
        ("summary", "id", True, False, "positive integer ID"),
        ("summary", "installation_id", True, False, "installation ID"),
        ("summary", "redelivery", None, True, "Boolean redelivery"),
        ("summary", "redelivery", "false", False, "Boolean redelivery"),
        ("summary", "status_code", True, False, "integer status"),
        ("summary", "status_code", None, True, "integer status"),
        ("detail", "id", True, False, "positive integer ID"),
        ("detail", "installation_id", True, False, "installation ID"),
        ("detail", "redelivery", None, True, "Boolean redelivery"),
        ("detail", "redelivery", "false", False, "Boolean redelivery"),
        ("detail", "status_code", True, False, "integer status"),
        ("detail", "status_code", None, True, "integer status"),
    ],
)
def test_capture_rejects_missing_or_invalid_identity_and_status_metadata(
    tmp_path: Path,
    target: str,
    field: str,
    value: object,
    remove: bool,
    message: str,
) -> None:
    listed = summary(1, event="installation", action="unsuspend")
    fetched = detail(1, event="installation", action="unsuspend")
    delivery = listed if target == "summary" else fetched
    if remove:
        del delivery[field]
    else:
        delivery[field] = value
    client = CaptureClient([[listed], fetched])

    with pytest.raises(ContractError, match=message):
        capture_lifecycle_contracts(
            capture_config(tmp_path, expected=("installation.unsuspend",)),
            client=cast(RestClient, client),
        )


def test_lifecycle_config_requires_a_bounded_supported_delivery_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "app.pem"
    key_file.write_text("not parsed while configuration is loaded")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIFECYCLE_APP_ID", "123")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIFECYCLE_INSTALLATION_ID", "456")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIFECYCLE_PRIVATE_KEY_FILE", str(key_file))
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIFECYCLE_SOURCE_REVISION", "a" * 40)
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIFECYCLE_SINCE", "2026-07-23T12:00:00Z")
    monkeypatch.setenv(
        "EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED",
        "installation.unsuspend,repository.renamed",
    )

    loaded = CaptureConfig.from_environment()

    assert loaded.expected == ("installation.unsuspend", "repository.renamed")
    monkeypatch.setenv("EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED", "pull_request.opened")
    with pytest.raises(ContractError, match="unsupported"):
        CaptureConfig.from_environment()


def test_lifecycle_main_writes_failure_metadata_without_provider_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = capture_config(tmp_path, expected=("installation.unsuspend",))
    monkeypatch.setattr(CaptureConfig, "from_environment", classmethod(lambda cls: config))
    monkeypatch.setattr(
        lifecycle_module,
        "capture_lifecycle_contracts",
        lambda supplied: (_ for _ in ()).throw(ContractError("private provider value")),
    )

    assert lifecycle_module.main([]) == 1

    report = json.loads(config.report_file.read_text())
    assert set(report) == {
        "api_version",
        "captured_at",
        "expected",
        "failure_type",
        "result",
        "schema_version",
        "since",
        "source_revision",
    }
    assert report["result"] == "failed"
    assert report["failure_type"] == "ContractError"
    assert "private provider value" not in json.dumps(report)


@pytest.mark.parametrize(
    ("capture_complete", "expected_exit"),
    [(True, 0), (False, 1)],
)
def test_lifecycle_main_requires_every_expected_delivery_for_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    *,
    capture_complete: bool,
    expected_exit: int,
) -> None:
    config = capture_config(tmp_path, expected=("installation.unsuspend",))
    report = {
        "schema_version": lifecycle_module.CAPTURE_SCHEMA_VERSION,
        "result": "observed",
        "capture_complete": capture_complete,
        "observations": {
            "installation.unsuspend": {
                "state": "observed" if capture_complete else "not_observed",
                "delivery_count": 1 if capture_complete else 0,
                "contracts": [{}] if capture_complete else [],
            }
        },
    }
    monkeypatch.setattr(CaptureConfig, "from_environment", classmethod(lambda cls: config))
    monkeypatch.setattr(
        lifecycle_module,
        "capture_lifecycle_contracts",
        lambda supplied: report,
    )

    assert lifecycle_module.main([]) == expected_exit
    assert json.loads(config.report_file.read_text()) == report
    stderr = capsys.readouterr().err
    assert ("evidence is incomplete" in stderr) is (not capture_complete)


def test_lifecycle_help_states_the_fail_closed_shell_contract(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert lifecycle_module.main(["--help"]) == 0

    output = capsys.readouterr()
    assert "capture_complete=true" in output.out
    assert "every expected delivery was observed" in output.out
    assert output.err == ""


def test_lifecycle_cli_rejects_unexpected_arguments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert lifecycle_module.main(["private-value"]) == 2

    output = capsys.readouterr()
    assert "unexpected command arguments" in output.err
    assert "private-value" not in output.err
