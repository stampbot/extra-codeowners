#!/usr/bin/env python3
"""Authenticate one completed tagged release workflow without publication authority."""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import hashlib
import re
import sys
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol, cast

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import acquire_github_release_assets as acquisition  # noqa: E402
import verify_github_release as github_release  # noqa: E402
from release_controller import (  # noqa: E402
    MAX_ID,
    ControllerError,
    ReleasePlan,
    canonical_json,
    load_manifest,
)

SCHEMA_VERSION = 1
RECORD_KIND = "extra-codeowners/authenticated-release-workflow"
MAX_WORKFLOW_BYTES = 1024 * 1024
MAX_BASE64_BYTES = ((MAX_WORKFLOW_BYTES + 2) // 3) * 4 + 32 * 1024

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class WorkflowVerificationError(RuntimeError):
    """The tagged release workflow identity could not be authenticated."""


class WorkflowClient(Protocol):
    """Read-only GitHub operations used by the workflow verifier."""

    def check_version(self) -> str:
        raise NotImplementedError

    def api(self, endpoint: str) -> object:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class WorkflowRun:
    """Stable security-relevant fields from one completed workflow run."""

    workflow_id: int
    run_attempt: int
    url: str


@dataclasses.dataclass(frozen=True)
class WorkflowFile:
    """Exact workflow bytes read from the tagged source commit."""

    blob_sha1: str
    sha256: str
    size: int


def _mapping(value: object, source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise WorkflowVerificationError(f"{source} is not a JSON object")
    return cast(Mapping[str, Any], value)


def _positive_id(value: object, source: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ID:
        raise WorkflowVerificationError(f"{source} is outside its integer bounds")
    return value


def _bounded_string(
    value: object,
    source: str,
    *,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str) or not value:
        raise WorkflowVerificationError(f"{source} is not a bounded nonempty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise WorkflowVerificationError(f"{source} is not valid Unicode") from None
    if len(encoded) > maximum or (pattern is not None and pattern.fullmatch(value) is None):
        raise WorkflowVerificationError(f"{source} is not a bounded nonempty string")
    return value


def _repository_identity(
    value: object,
    plan: ReleasePlan,
    authenticated: acquisition.AuthenticatedRelease,
    source: str,
) -> None:
    repository = _mapping(value, source)
    owner = _mapping(repository.get("owner"), f"{source} owner")
    if (
        _positive_id(repository.get("id"), f"{source} ID") != plan.repository_id
        or repository.get("full_name") != plan.repository
        or _positive_id(owner.get("id"), f"{source} owner ID") != authenticated.owner_id
    ):
        raise WorkflowVerificationError(f"{source} does not match the authenticated repository")


def _run_endpoint(plan: ReleasePlan) -> str:
    repository = urllib.parse.quote(plan.repository, safe="/")
    return f"repos/{repository}/actions/runs/{plan.run_id}"


def _workflow_content_endpoint(plan: ReleasePlan) -> str:
    repository = urllib.parse.quote(plan.repository, safe="/")
    path = urllib.parse.quote(plan.workflow_path, safe="/")
    revision = urllib.parse.quote(plan.workflow_sha, safe="")
    return f"repos/{repository}/contents/{path}?ref={revision}"


def _validate_run(
    value: object,
    plan: ReleasePlan,
    authenticated: acquisition.AuthenticatedRelease,
) -> WorkflowRun:
    run = _mapping(value, "GitHub release workflow run")
    run_id = _positive_id(run.get("id"), "GitHub release workflow run ID")
    workflow_id = _positive_id(
        run.get("workflow_id"),
        "GitHub release workflow definition ID",
    )
    run_attempt = _positive_id(
        run.get("run_attempt"),
        "GitHub release workflow run attempt",
    )
    expected_url = f"https://github.com/{plan.repository}/actions/runs/{plan.run_id}"
    if (
        run_id != plan.run_id
        or run.get("event") != "push"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("head_branch") != plan.tag
        or run.get("head_sha") != plan.target_commit
        or run.get("path") != plan.workflow_path
        or run.get("html_url") != expected_url
    ):
        raise WorkflowVerificationError("GitHub release workflow run does not match the manifest")
    _repository_identity(
        run.get("repository"),
        plan,
        authenticated,
        "GitHub release workflow repository",
    )
    _repository_identity(
        run.get("head_repository"),
        plan,
        authenticated,
        "GitHub release workflow head repository",
    )
    return WorkflowRun(
        workflow_id=workflow_id,
        run_attempt=run_attempt,
        url=expected_url,
    )


def _decode_workflow_content(value: object) -> bytes:
    encoded = _bounded_string(
        value,
        "GitHub release workflow file content",
        maximum=MAX_BASE64_BYTES,
    )
    if "\r" in encoded:
        raise WorkflowVerificationError(
            "GitHub release workflow file content is not canonical base64"
        )
    if encoded.endswith("\n"):
        encoded = encoded[:-1]
    lines = encoded.split("\n")
    if not lines or any(not line or len(line) > 76 for line in lines):
        raise WorkflowVerificationError(
            "GitHub release workflow file content is not canonical base64"
        )
    compact = "".join(lines)
    try:
        raw = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error):
        raise WorkflowVerificationError(
            "GitHub release workflow file content is not canonical base64"
        ) from None
    if not 1 <= len(raw) <= MAX_WORKFLOW_BYTES:
        raise WorkflowVerificationError("GitHub release workflow file is outside its byte bound")
    if base64.b64encode(raw).decode("ascii") != compact:
        raise WorkflowVerificationError(
            "GitHub release workflow file content is not canonical base64"
        )
    return raw


def _validate_workflow_file(value: object, plan: ReleasePlan) -> WorkflowFile:
    record = _mapping(value, "GitHub release workflow file")
    blob_sha1 = _bounded_string(
        record.get("sha"),
        "GitHub release workflow blob SHA-1",
        maximum=40,
        pattern=HEX40,
    )
    size = _positive_id(record.get("size"), "GitHub release workflow file size")
    if size > MAX_WORKFLOW_BYTES:
        raise WorkflowVerificationError("GitHub release workflow file is outside its byte bound")
    if (
        record.get("type") != "file"
        or record.get("name") != Path(plan.workflow_path).name
        or record.get("path") != plan.workflow_path
        or record.get("encoding") != "base64"
    ):
        raise WorkflowVerificationError("GitHub release workflow file does not match the manifest")
    raw = _decode_workflow_content(record.get("content"))
    if len(raw) != size:
        raise WorkflowVerificationError("GitHub release workflow file has the wrong size")
    expected_blob_sha1 = hashlib.sha1(  # noqa: S324 - Git object identity is SHA-1
        f"blob {len(raw)}\0".encode("ascii") + raw
    ).hexdigest()
    if blob_sha1 != expected_blob_sha1:
        raise WorkflowVerificationError(
            "GitHub release workflow file has the wrong Git blob identity"
        )
    return WorkflowFile(
        blob_sha1=blob_sha1,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=size,
    )


def verify_release_workflow(
    plan: ReleasePlan,
    authenticated: acquisition.AuthenticatedRelease,
    *,
    expected_manifest_sha256: str,
    client: WorkflowClient,
) -> Mapping[str, object]:
    """Authenticate one successful tagged workflow run and its exact workflow bytes."""

    if HEX64.fullmatch(expected_manifest_sha256) is None:
        raise WorkflowVerificationError("trusted manifest SHA-256 is invalid")
    if plan.manifest_sha256 != expected_manifest_sha256:
        raise WorkflowVerificationError("release manifest does not match the trusted SHA-256")
    if plan.workflow_sha != plan.target_commit:
        raise WorkflowVerificationError(
            "release workflow SHA does not match the tagged target commit"
        )

    gh_version = client.check_version()
    run = _validate_run(client.api(_run_endpoint(plan)), plan, authenticated)
    workflow_file = _validate_workflow_file(
        client.api(_workflow_content_endpoint(plan)),
        plan,
    )

    final_run = _validate_run(client.api(_run_endpoint(plan)), plan, authenticated)
    if final_run != run:
        raise WorkflowVerificationError("GitHub release workflow run changed during verification")
    final_workflow_file = _validate_workflow_file(
        client.api(_workflow_content_endpoint(plan)),
        plan,
    )
    if final_workflow_file != workflow_file:
        raise WorkflowVerificationError("GitHub release workflow file changed during verification")

    return {
        "authenticated_release": {"sha256": authenticated.record_sha256},
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {
            "minimum_version": github_release.MINIMUM_GH_VERSION_TEXT,
            "version": gh_version,
        },
        "kind": RECORD_KIND,
        "publication_allowed": False,
        "repository": {
            "id": plan.repository_id,
            "name": plan.repository,
            "owner_id": authenticated.owner_id,
        },
        "schema_version": SCHEMA_VERSION,
        "tag": {
            "name": plan.tag,
            "target_commit": plan.target_commit,
        },
        "workflow": {
            "event": "push",
            "file": {
                "git_blob_sha1": workflow_file.blob_sha1,
                "sha256": workflow_file.sha256,
                "size": workflow_file.size,
            },
            "id": run.workflow_id,
            "path": plan.workflow_path,
            "ref": f"refs/tags/{plan.tag}",
            "run_attempt": run.run_attempt,
            "run_id": plan.run_id,
            "sha": plan.workflow_sha,
            "url": run.url,
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Authenticate the completed tagged workflow named by one reviewed "
            "release-controller manifest."
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--authenticated-release-record", type=Path, required=True)
    parser.add_argument("--authenticated-release-record-sha256", required=True)
    parser.add_argument("--gh", default="gh")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=github_release.DEFAULT_TIMEOUT_SECONDS,
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        try:
            plan = load_manifest(arguments.manifest)
        except ControllerError as exc:
            raise WorkflowVerificationError("release-controller manifest is invalid") from exc
        try:
            authenticated = acquisition.load_authenticated_release(
                arguments.authenticated_release_record,
                expected_sha256=arguments.authenticated_release_record_sha256,
                plan=plan,
            )
        except acquisition.AcquisitionError as exc:
            raise WorkflowVerificationError("authenticated-release record is invalid") from exc
        client = github_release.GitHubCLI(
            executable=arguments.gh,
            timeout=arguments.timeout_seconds,
        )
        result = verify_release_workflow(
            plan,
            authenticated,
            expected_manifest_sha256=arguments.manifest_sha256,
            client=client,
        )
        sys.stdout.buffer.write(canonical_json(result))
    except WorkflowVerificationError as exc:
        sys.stderr.write(f"Release workflow verification failed: {exc}\n")
        return 1
    except github_release.VerificationError as exc:
        sys.stderr.write(f"Release workflow verification failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
