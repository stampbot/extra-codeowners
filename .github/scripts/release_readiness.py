#!/usr/bin/env python3
"""Fail closed unless the configured GitHub release milestone has no open issues."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

API_ROOT = "https://api.github.com"
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]*$")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ReadinessError(RuntimeError):
    """The release milestone cannot be proven ready."""


def strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadinessError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise ReadinessError(f"non-finite JSON number is not allowed: {value}")


def strict_json_loads(value: str | bytes, source: str) -> object:
    try:
        parsed: object = json.loads(
            value,
            object_pairs_hook=strict_json_object,
            parse_constant=reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReadinessError(f"cannot parse JSON from {source}: {exc}") from exc
    return parsed


def validate_milestone(
    milestone: object, required_number: int, required_title: str
) -> dict[str, Any]:
    """Return the exact ready milestone or fail closed."""

    if not isinstance(milestone, dict):
        raise ReadinessError("GitHub milestone response is not an object")
    number = milestone.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ReadinessError("release milestone has an invalid number")
    if number != required_number:
        raise ReadinessError(
            f"GitHub returned milestone #{number}, expected milestone #{required_number}"
        )
    if milestone.get("title") != required_title:
        raise ReadinessError(
            f"milestone #{number} is named {milestone.get('title')!r}, expected {required_title!r}"
        )
    open_issues = milestone.get("open_issues")
    if not isinstance(open_issues, int) or isinstance(open_issues, bool) or open_issues < 0:
        raise ReadinessError("release milestone has an invalid open_issues count")
    closed_issues = milestone.get("closed_issues")
    if not isinstance(closed_issues, int) or isinstance(closed_issues, bool) or closed_issues < 0:
        raise ReadinessError("release milestone has an invalid closed_issues count")
    return milestone


def require_ready(milestone: Mapping[str, Any]) -> None:
    """Fail unless a structurally validated milestone is open and empty."""

    number = milestone["number"]
    title = milestone["title"]
    if milestone.get("state") != "open":
        raise ReadinessError(f"release milestone #{number} ({title!r}) is not open")
    open_issues = milestone["open_issues"]
    if open_issues != 0:
        raise ReadinessError(
            f"release milestone #{number} ({title!r}) still has {open_issues} open issue(s)"
        )


def configured_milestone(path: Path) -> tuple[int, str]:
    try:
        policy = strict_json_loads(path.read_text(), str(path))
    except OSError as exc:
        raise ReadinessError(f"cannot read release policy {path}: {exc}") from exc
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ReadinessError("unsupported release-readiness policy schema")
    number = policy.get("milestone_number")
    title = policy.get("milestone")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ReadinessError("release-readiness policy has no valid milestone_number")
    if not isinstance(title, str) or not title.strip():
        raise ReadinessError("release-readiness policy has no milestone")
    return number, title


def github_milestone(repository: str, number: int, token: str) -> dict[str, Any]:
    if not REPOSITORY.fullmatch(repository):
        raise ReadinessError("repository must have the form owner/name")
    if not token:
        raise ReadinessError("GITHUB_TOKEN is required")
    encoded = urllib.parse.quote(repository, safe="/")
    url = f"{API_ROOT}/repos/{encoded}/milestones/{number}"
    request = urllib.request.Request(  # noqa: S310 - fixed HTTPS API root
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "extra-codeowners-release-readiness/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            if response.status != 200:
                raise ReadinessError(f"GitHub milestone query returned HTTP {response.status}")
            value = strict_json_loads(
                response.read(MAX_RESPONSE_BYTES), "GitHub milestone response"
            )
            if response.read(1):
                raise ReadinessError("GitHub milestone response exceeds the size limit")
    except (OSError, urllib.error.URLError) as exc:
        raise ReadinessError(f"cannot query GitHub milestones: {exc}") from exc
    if not isinstance(value, dict):
        raise ReadinessError("GitHub milestone response is not an object")
    return value


def write_summary(
    path: Path,
    milestone: Mapping[str, Any],
    *,
    repository: str,
    commit: str,
    run_id: str,
) -> None:
    """Append a durable, linked release-readiness report to the workflow summary."""

    if not COMMIT.fullmatch(commit):
        raise ReadinessError("commit must be a 40-character lowercase Git object ID")
    if not RUN_ID.fullmatch(run_id):
        raise ReadinessError("workflow run ID must be a positive integer")
    number = milestone["number"]
    title = milestone["title"]
    root = f"https://github.com/{repository}"
    report = (
        "## Release readiness\n\n"
        f"- Repository: [`{repository}`]({root})\n"
        f"- Commit: [`{commit}`]({root}/commit/{commit})\n"
        f"- Workflow run: [`{run_id}`]({root}/actions/runs/{run_id})\n"
        f"- Milestone: [#{number} — {title}]({root}/milestone/{number})\n"
        f"- Open issues: **{milestone['open_issues']}**\n"
        f"- Closed issues: **{milestone['closed_issues']}**\n\n"
    )
    try:
        with path.open("a", encoding="utf-8") as summary:
            summary.write(report)
    except OSError as exc:
        raise ReadinessError(f"cannot write workflow summary {path}: {exc}") from exc


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", required=True)
    result.add_argument("--policy", default=".release-readiness.json")
    result.add_argument("--commit", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--summary", required=True)
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        number, title = configured_milestone(Path(args.policy))
        milestone = validate_milestone(
            github_milestone(args.repository, number, os.environ.get("GITHUB_TOKEN", "")),
            number,
            title,
        )
        write_summary(
            Path(args.summary),
            milestone,
            repository=args.repository,
            commit=args.commit,
            run_id=args.run_id,
        )
        require_ready(milestone)
    except ReadinessError as exc:
        sys.stderr.write(f"release readiness error: {exc}\n")
        return 1
    sys.stdout.write(
        f"Release milestone #{milestone['number']} ({milestone['title']}) has no open issues.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
