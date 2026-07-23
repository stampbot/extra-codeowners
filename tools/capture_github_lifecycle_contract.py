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
from urllib.parse import parse_qsl, urlsplit

from tools.live_github_contract import (
    API_VERSION,
    AppAuth,
    AppCredentials,
    ContractError,
    JsonObject,
    RestClient,
    sanitize_delivery,
)

CAPTURE_SCHEMA_VERSION: Final = 1
DELIVERY_LIST_LIMIT: Final = 100
DELIVERY_PAGE_LIMIT: Final = 8
DELIVERY_PAGE_SIZE: Final = 100
DETAIL_LIMIT: Final = 24
LINK_HEADER_LIMIT: Final = 8192
CURSOR_LIMIT: Final = 1024
REVISION: Final = re.compile(r"^[0-9a-f]{40}$")
UTC_TIMESTAMP: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
LINK_RELATIONS: Final = frozenset({"first", "last", "next", "prev"})
SUMMARY_DETAIL_FIELDS: Final = (
    "guid",
    "redelivery",
    "duration",
    "status",
    "status_code",
    "repository_id",
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


def _malformed_link() -> ContractError:
    return ContractError("GitHub delivery Link header is malformed or ambiguous")


def _next_link_target(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        not value
        or len(value) > LINK_HEADER_LIMIT
        or any(character in value for character in "\r\n\0")
    ):
        raise _malformed_link()

    links: dict[str, str] = {}
    position = 0
    while position < len(value):
        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != "<":
            raise _malformed_link()
        target_end = value.find(">", position + 1)
        if target_end < 0:
            raise _malformed_link()
        target = value[position + 1 : target_end]
        if not target or any(character.isspace() or ord(character) < 0x21 for character in target):
            raise _malformed_link()
        position = target_end + 1

        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != ";":
            raise _malformed_link()
        position += 1
        while position < len(value) and value[position] in " \t":
            position += 1
        if value[position : position + 3].lower() != "rel":
            raise _malformed_link()
        position += 3
        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != "=":
            raise _malformed_link()
        position += 1
        while position < len(value) and value[position] in " \t":
            position += 1
        if position >= len(value) or value[position] != '"':
            raise _malformed_link()
        relation_end = value.find('"', position + 1)
        if relation_end < 0:
            raise _malformed_link()
        relation = value[position + 1 : relation_end].lower()
        if relation not in LINK_RELATIONS or relation in links:
            raise _malformed_link()
        links[relation] = target
        position = relation_end + 1

        while position < len(value) and value[position] in " \t":
            position += 1
        if position == len(value):
            break
        if value[position] != ",":
            raise _malformed_link()
        position += 1
        if position == len(value):
            raise _malformed_link()

    return links.get("next")


def _next_cursor(link_header: str | None) -> str | None:
    target = _next_link_target(link_header)
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
        raise _malformed_link() from error
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
        raise _malformed_link()

    values: dict[str, str] = {}
    for name, item in query:
        if name not in {"cursor", "per_page"} or name in values:
            raise _malformed_link()
        values[name] = item
    cursor = values.get("cursor")
    if (
        cursor is None
        or not cursor
        or len(cursor) > CURSOR_LIMIT
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in cursor)
    ):
        raise _malformed_link()
    per_page = values.get("per_page")
    if per_page is not None and (
        not per_page.isdecimal() or not 1 <= int(per_page) <= DELIVERY_PAGE_SIZE
    ):
        raise _malformed_link()
    return cursor


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
    if not isinstance(value, str):
        raise ContractError("GitHub delivery summary omitted delivered_at")
    return _timestamp(value, "GitHub delivery delivered_at")


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


def _positive_installation_id(delivery: JsonObject, description: str) -> int:
    value = delivery.get("installation_id")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractError(
            f"GitHub delivery {description} omitted its positive integer installation ID"
        )
    return value


def _validate_status_metadata(delivery: JsonObject, description: str) -> tuple[bool, int]:
    redelivery = delivery.get("redelivery")
    status_code = delivery.get("status_code")
    if not isinstance(redelivery, bool):
        raise ContractError(f"GitHub delivery {description} omitted Boolean redelivery metadata")
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        raise ContractError(f"GitHub delivery {description} omitted integer status metadata")
    return redelivery, status_code


def _canonical_contract(value: JsonObject) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _delivery_summaries(client: RestClient) -> tuple[list[JsonObject], bool, int]:
    summaries: list[JsonObject] = []
    seen_cursors: set[str] = set()
    cursor: str | None = None
    pages_read = 0

    while pages_read < DELIVERY_PAGE_LIMIT and len(summaries) < DELIVERY_LIST_LIMIT:
        page_size = min(DELIVERY_PAGE_SIZE, DELIVERY_LIST_LIMIT - len(summaries))
        params: dict[str, str | int] = {"per_page": page_size}
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
        if len(response) > page_size:
            raise ContractError("GitHub delivery listing exceeded the requested page size")
        summaries.extend(response)

        next_cursor = _next_cursor(link_header)
        if next_cursor is None:
            return summaries, True, pages_read
        if next_cursor in seen_cursors:
            raise ContractError("GitHub delivery pagination repeated a cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    return summaries, False, pages_read


def _validate_detail(
    summary: JsonObject,
    detail: JsonObject,
    *,
    delivery_id: int,
    delivered_at: datetime,
    key: str,
    installation_id: int,
) -> None:
    summary_status = _validate_status_metadata(summary, "summary")
    detail_status = _validate_status_metadata(detail, "detail")
    if (
        _positive_detail_id(detail) != delivery_id
        or _positive_installation_id(detail, "detail") != installation_id
        or _summary_key(detail) != key
        or _summary_time(detail) != delivered_at
    ):
        raise ContractError("GitHub delivery detail does not match its summary")
    if summary_status != detail_status:
        raise ContractError("GitHub delivery detail metadata does not match its summary")
    if any(
        field not in detail
        or type(detail[field]) is not type(summary[field])
        or detail[field] != summary[field]
        for field in SUMMARY_DETAIL_FIELDS
        if field in summary
    ):
        raise ContractError("GitHub delivery detail metadata does not match its summary")


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
            if _positive_installation_id(summary, "summary") != config.credentials.installation_id:
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
        for _, _, key, _ in requested:
            counts[key] += 1
        for summary, delivered_at, key, delivery_id in selected:
            detail = active_client.request("GET", f"/app/hook/deliveries/{delivery_id}")
            if not isinstance(detail, dict):
                raise ContractError("GitHub delivery detail is not an object")
            _validate_detail(
                summary,
                detail,
                delivery_id=delivery_id,
                delivered_at=delivered_at,
                key=key,
                installation_id=config.credentials.installation_id,
            )
            sanitized = sanitize_delivery(detail)
            captured_counts[key] += 1
            contracts[key][_canonical_contract(sanitized)] = sanitized

        observations: JsonObject = {}
        for name in config.expected:
            unique = sorted(contracts[name].values(), key=_canonical_contract)
            if not window_complete or captured_counts[name] < counts[name]:
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
