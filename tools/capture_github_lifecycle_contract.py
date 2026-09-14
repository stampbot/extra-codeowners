"""Capture sanitized GitHub App lifecycle delivery contracts from a bounded window."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from tools.live_github_contract import (
    API_VERSION,
    AppAuth,
    AppCredentials,
    ContractError,
    JsonObject,
    RestClient,
    delivery_summaries_bounded,
    sanitize_delivery,
)

CAPTURE_SCHEMA_VERSION: Final = 1
DELIVERY_LIST_LIMIT: Final = 100
DELIVERY_PAGE_LIMIT: Final = 8
DELIVERY_PAGE_SIZE: Final = 100
DETAIL_LIMIT: Final = 24
REVISION: Final = re.compile(r"^[0-9a-f]{40}$")
UTC_TIMESTAMP: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SUMMARY_DETAIL_FIELDS: Final = (
    "guid",
    "redelivery",
    "duration",
    "status",
    "status_code",
    "throttled_at",
)
SUPPORTED_DELIVERIES: Final = frozenset(
    {
        "installation.created",
        "installation.deleted",
        "installation.new_permissions_accepted",
        "installation.suspend",
        "installation.unsuspend",
        "installation_repositories.added",
        "installation_repositories.removed",
        "installation_target.renamed",
        "repository.archived",
        "repository.deleted",
        "repository.renamed",
        "repository.transferred",
        "repository.unarchived",
    }
)
USAGE: Final = """\
usage: python -m tools.capture_github_lifecycle_contract

Capture a bounded, sanitized GitHub App lifecycle-delivery report.

Required environment:
  EXTRA_CODEOWNERS_LIFECYCLE_APP_ID
  EXTRA_CODEOWNERS_LIFECYCLE_INSTALLATION_ID
  EXTRA_CODEOWNERS_LIFECYCLE_PRIVATE_KEY_FILE
  EXTRA_CODEOWNERS_LIFECYCLE_SOURCE_REVISION
  EXTRA_CODEOWNERS_LIFECYCLE_SINCE
  EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED

Optional environment:
  EXTRA_CODEOWNERS_LIFECYCLE_REPORT_FILE

Exit status:
  0  The bounded capture is complete and every expected delivery was observed.
  1  Evidence is absent, incomplete, or capture failed.
  2  Configuration or command arguments are invalid.

The JSON report is authoritative. Require capture_complete=true; result=observed
alone does not mean that an expected delivery appeared.
"""


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ContractError(f"{name} is required")
    return value


def _timestamp(value: str, name: str) -> datetime:
    if UTC_TIMESTAMP.fullmatch(value) is None:
        raise ContractError(f"{name} must use UTC format YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise ContractError(f"{name} must be a valid UTC timestamp") from error


def _expected_deliveries(value: str) -> tuple[str, ...]:
    requested = tuple(item.strip() for item in value.split(",") if item.strip())
    if not requested:
        raise ContractError("EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED must name at least one delivery")
    if len(requested) > len(SUPPORTED_DELIVERIES):
        raise ContractError("EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED contains too many deliveries")
    if len(set(requested)) != len(requested):
        raise ContractError("EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED repeats a delivery")
    unsupported = sorted(set(requested) - SUPPORTED_DELIVERIES)
    if unsupported:
        raise ContractError(
            "EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED contains unsupported deliveries: "
            + ", ".join(unsupported)
        )
    return tuple(sorted(requested))


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    """Validated configuration for one lifecycle-delivery capture."""

    credentials: AppCredentials
    source_revision: str
    since_text: str
    since: datetime
    expected: tuple[str, ...]
    report_file: Path

    @classmethod
    def from_environment(cls) -> CaptureConfig:
        credentials = AppCredentials.from_environment("EXTRA_CODEOWNERS_LIFECYCLE")
        assert credentials is not None
        source_revision = _required_env("EXTRA_CODEOWNERS_LIFECYCLE_SOURCE_REVISION").lower()
        if REVISION.fullmatch(source_revision) is None:
            raise ContractError(
                "EXTRA_CODEOWNERS_LIFECYCLE_SOURCE_REVISION must be a full commit SHA"
            )
        since_text = _required_env("EXTRA_CODEOWNERS_LIFECYCLE_SINCE")
        return cls(
            credentials=credentials,
            source_revision=source_revision,
            since_text=since_text,
            since=_timestamp(since_text, "EXTRA_CODEOWNERS_LIFECYCLE_SINCE"),
            expected=_expected_deliveries(_required_env("EXTRA_CODEOWNERS_LIFECYCLE_EXPECTED")),
            report_file=Path(
                os.getenv(
                    "EXTRA_CODEOWNERS_LIFECYCLE_REPORT_FILE",
                    "live-github-lifecycle-report.json",
                )
            ),
        )


def _summary_time(summary: JsonObject) -> datetime:
    value = summary.get("delivered_at")
    if (
        not isinstance(value, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is None
    ):
        raise ContractError("GitHub delivery summary omitted delivered_at")
    try:
        return datetime.fromisoformat(value)
    except ValueError as error:
        raise ContractError("GitHub delivery delivered_at must be a valid UTC timestamp") from error


def _summary_key(summary: JsonObject) -> str:
    event = summary.get("event")
    action = summary.get("action")
    if not isinstance(event, str) or not event or not isinstance(action, str) or not action:
        raise ContractError("GitHub delivery summary omitted event or action")
    return f"{event}.{action}"


def _matching_summary_key(
    summary: JsonObject,
    *,
    expected: frozenset[str],
    expected_events: frozenset[str],
) -> str | None:
    event = summary.get("event")
    if not isinstance(event, str) or not event or event not in expected_events:
        return None
    key = _summary_key(summary)
    return key if key in expected else None


def _positive_delivery_id(summary: JsonObject) -> int:
    value = summary.get("id")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractError("GitHub delivery summary omitted its positive integer ID")
    return value


def _positive_detail_id(detail: JsonObject) -> int:
    value = detail.get("id")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractError("GitHub delivery detail omitted its positive integer ID")
    return value


def _metadata_installation_id(delivery: JsonObject, description: str) -> int | None:
    if "installation_id" not in delivery:
        raise ContractError(f"GitHub delivery {description} omitted its installation ID")
    value = delivery.get("installation_id")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractError(
            f"GitHub delivery {description} omitted its positive integer installation ID"
        )
    return int(value)


def _validate_status_metadata(delivery: JsonObject, description: str) -> tuple[bool, int]:
    redelivery = delivery.get("redelivery")
    status_code = delivery.get("status_code")
    if not isinstance(redelivery, bool):
        raise ContractError(f"GitHub delivery {description} omitted Boolean redelivery metadata")
    # GitHub's REST schema requires an integer but does not publish minimum or maximum bounds.
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        raise ContractError(f"GitHub delivery {description} omitted integer status metadata")
    return redelivery, status_code


def _canonical_contract(value: JsonObject) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _delivery_summaries(client: RestClient) -> tuple[list[JsonObject], bool, int]:
    return delivery_summaries_bounded(
        client,
        list_limit=DELIVERY_LIST_LIMIT,
        page_limit=DELIVERY_PAGE_LIMIT,
        page_size=DELIVERY_PAGE_SIZE,
    )


def _valid_repository_id(value: object, *, nullable: bool) -> bool:
    return (nullable and value is None) or (type(value) is int and value > 0)


def _validate_repository_metadata(
    summary: JsonObject,
    detail: JsonObject,
    *,
    repository_event: bool,
) -> None:
    summary_has_repository = "repository_id" in summary
    detail_has_repository = "repository_id" in detail
    if summary_has_repository != detail_has_repository or (
        repository_event and not summary_has_repository
    ):
        raise ContractError("GitHub delivery detail repository metadata does not match its summary")
    if not summary_has_repository:
        return

    summary_repository = summary["repository_id"]
    detail_repository = detail["repository_id"]
    nullable = not repository_event
    if (
        not _valid_repository_id(summary_repository, nullable=nullable)
        or not _valid_repository_id(detail_repository, nullable=nullable)
        or type(detail_repository) is not type(summary_repository)
        or detail_repository != summary_repository
    ):
        raise ContractError("GitHub delivery detail repository metadata does not match its summary")


def _validate_detail(
    summary: JsonObject,
    detail: JsonObject,
    *,
    delivery_id: int,
    delivered_at: datetime,
    key: str,
) -> int:
    summary_status = _validate_status_metadata(summary, "summary")
    detail_status = _validate_status_metadata(detail, "detail")
    if (
        _positive_detail_id(detail) != delivery_id
        or _metadata_installation_id(detail, "detail")
        != _metadata_installation_id(summary, "summary")
        or _summary_key(detail) != key
        or _summary_time(detail) != delivered_at
    ):
        raise ContractError("GitHub delivery detail does not match its summary")
    if summary_status != detail_status:
        raise ContractError("GitHub delivery detail metadata does not match its summary")
    _validate_repository_metadata(
        summary,
        detail,
        repository_event=key.startswith("repository."),
    )
    if any(
        field not in detail
        or type(detail[field]) is not type(summary[field])
        or detail[field] != summary[field]
        for field in SUMMARY_DETAIL_FIELDS
        if field in summary
    ):
        raise ContractError("GitHub delivery detail metadata does not match its summary")
    request = detail.get("request")
    payload = request.get("payload") if isinstance(request, dict) else None
    installation = payload.get("installation") if isinstance(payload, dict) else None
    payload_installation = installation.get("id") if isinstance(installation, dict) else None
    if (
        type(payload_installation) is not int
        or payload_installation <= 0
        or not isinstance(payload, dict)
        or payload.get("action") != key.split(".", 1)[1]
    ):
        raise ContractError("GitHub delivery payload omitted valid installation or action evidence")
    metadata_installation = _metadata_installation_id(detail, "detail")
    if metadata_installation is not None and payload_installation != metadata_installation:
        raise ContractError("GitHub delivery payload installation disagrees with its metadata")
    if key.startswith("repository."):
        repository = payload.get("repository")
        if (
            not isinstance(repository, dict)
            or type(repository.get("id")) is not int
            or repository["id"] != detail["repository_id"]
        ):
            raise ContractError("GitHub delivery payload repository disagrees with its metadata")
    return payload_installation


def capture_lifecycle_contracts(
    config: CaptureConfig,
    *,
    client: RestClient | None = None,
) -> JsonObject:
    """Fetch and sanitize the requested delivery contracts without retaining payload values."""
    owns_client = client is None
    active_client = client or AppAuth(config.credentials).jwt_client()
    try:
        summaries, window_complete, pages_read = _delivery_summaries(active_client)
        expected = frozenset(config.expected)
        expected_events = frozenset(name.split(".", 1)[0] for name in expected)
        requested: list[tuple[JsonObject, datetime, str, int]] = []
        delivery_ids: set[int] = set()
        for summary in summaries:
            key = _matching_summary_key(
                summary,
                expected=expected,
                expected_events=expected_events,
            )
            if key is None:
                continue
            metadata_installation = _metadata_installation_id(summary, "summary")
            if metadata_installation not in {None, config.credentials.installation_id}:
                continue
            _validate_status_metadata(summary, "summary")
            delivered_at = _summary_time(summary)
            if delivered_at < config.since:
                continue
            delivery_id = _positive_delivery_id(summary)
            if delivery_id in delivery_ids:
                raise ContractError("GitHub delivery listing repeated an expected delivery")
            delivery_ids.add(delivery_id)
            requested.append((summary, delivered_at, key, delivery_id))
        requested.sort(key=lambda item: item[1], reverse=True)
        details_complete = len(requested) <= DETAIL_LIMIT
        selected = requested[:DETAIL_LIMIT]

        contracts: dict[str, dict[str, JsonObject]] = {name: {} for name in config.expected}
        counts = dict.fromkeys(config.expected, 0)
        captured_counts = dict.fromkeys(config.expected, 0)
        for summary, _, key, _ in requested:
            if _metadata_installation_id(summary, "summary") is not None:
                counts[key] += 1
        for summary, delivered_at, key, delivery_id in selected:
            detail = active_client.request("GET", f"/app/hook/deliveries/{delivery_id}")
            if not isinstance(detail, dict):
                raise ContractError("GitHub delivery detail is not an object")
            payload_installation = _validate_detail(
                summary,
                detail,
                delivery_id=delivery_id,
                delivered_at=delivered_at,
                key=key,
            )
            if payload_installation != config.credentials.installation_id:
                continue
            if _metadata_installation_id(summary, "summary") is None:
                counts[key] += 1
            sanitized = sanitize_delivery(detail)
            captured_counts[key] += 1
            contracts[key][_canonical_contract(sanitized)] = sanitized

        observations: JsonObject = {}
        for name in config.expected:
            unique = sorted(contracts[name].values(), key=_canonical_contract)
            if not window_complete or not details_complete or captured_counts[name] < counts[name]:
                state = "incomplete"
            elif unique:
                state = "observed"
            else:
                state = "not_observed"
            observations[name] = {
                "state": state,
                "delivery_count": counts[name],
                "contracts": unique,
            }
        all_observed = all(
            isinstance(value, dict) and value.get("state") == "observed"
            for value in observations.values()
        )
        return {
            "schema_version": CAPTURE_SCHEMA_VERSION,
            "api_version": API_VERSION,
            "source_revision": config.source_revision,
            "since": config.since_text,
            "captured_at": datetime.now(UTC).isoformat(),
            "scope": "configured disposable GitHub App installation",
            "expected": list(config.expected),
            "delivery_list_limit": DELIVERY_LIST_LIMIT,
            "delivery_page_limit": DELIVERY_PAGE_LIMIT,
            "delivery_page_size": DELIVERY_PAGE_SIZE,
            "delivery_pages_read": pages_read,
            "delivery_detail_limit": DETAIL_LIMIT,
            "delivery_window_complete": window_complete,
            "delivery_details_complete": details_complete,
            "capture_complete": window_complete and details_complete and all_observed,
            "observations": observations,
            "result": "observed" if window_complete and details_complete else "incomplete",
        }
    finally:
        if owns_client:
            active_client.close()


def main(argv: Sequence[str] | None = None) -> int:
    """Capture one bounded set of sanitized lifecycle delivery contracts."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments in (["-h"], ["--help"]):
        sys.stdout.write(USAGE)
        return 0
    if arguments:
        sys.stderr.write(f"unexpected command arguments; this command accepts none\n{USAGE}")
        return 2

    try:
        config = CaptureConfig.from_environment()
    except ContractError as error:
        sys.stderr.write(f"configuration error: {error}\n")
        return 2

    try:
        report = capture_lifecycle_contracts(config)
    except Exception as error:
        report = {
            "schema_version": CAPTURE_SCHEMA_VERSION,
            "api_version": API_VERSION,
            "source_revision": config.source_revision,
            "since": config.since_text,
            "captured_at": datetime.now(UTC).isoformat(),
            "expected": list(config.expected),
            "result": "failed",
            "failure_type": type(error).__name__,
        }
        sys.stderr.write(
            "lifecycle delivery capture failed; the sanitized report records "
            f"failure_type={type(error).__name__}\n"
        )
        exit_code = 1
    else:
        exit_code = 0 if report.get("capture_complete") is True else 1
        if exit_code:
            sys.stderr.write(
                "lifecycle delivery evidence is incomplete; inspect capture_complete "
                "and observations in the sanitized report\n"
            )
    config.report_file.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    sys.stdout.write(f"Wrote sanitized lifecycle report to {config.report_file}\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
