#!/usr/bin/env python3
"""Capture and verify a read-only immutable-release settings preflight."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import http.client
import json
import os
import re
import stat
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NoReturn, Protocol

SCHEMA_VERSION = 1
API_VERSION = "2026-03-10"
RECORD_MEDIA_TYPE = "application/vnd.stampbot.immutable-release-preflight.v1+json"
API_HOST = "api.github.com"
USER_AGENT = "extra-codeowners-immutable-release-preflight/1"

DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 120.0
MAX_RESPONSE_BYTES = 256 * 1024
MAX_RECORD_BYTES = 64 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_ITEMS = 4096
MAX_TOKEN_BYTES = 4096
MAX_REQUEST_ID_BYTES = 128
MAX_ID = 2**63 - 1
READ_CHUNK_BYTES = 64 * 1024

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
JSON_INTEGER = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
SAFE_REF_SUFFIX = re.compile(r"^refs/(?:heads|tags|pull)/[A-Za-z0-9_.\-/]+$")
REQUEST_ID = re.compile(r"^[A-Za-z0-9:._-]+$")


class PreflightError(RuntimeError):
    """The immutable-release setting or its evidence could not be proven."""


class _ResponseValidationError(ValueError):
    """A successful GitHub response violated the bounded response contract."""


@dataclasses.dataclass(frozen=True)
class RepositoryIdentity:
    """One exact GitHub repository identity."""

    id: int
    name: str


@dataclasses.dataclass(frozen=True)
class ImmutableReleasePolicy:
    """The immutable-release setting reported by GitHub."""

    enabled: bool
    enforced_by_owner: bool


@dataclasses.dataclass(frozen=True)
class ExpectedIdentity:
    """Trusted workflow values that a preflight record must match."""

    repository_id: int
    repository: str
    workflow_path: str
    workflow_ref: str
    workflow_sha: str
    run_id: int
    run_attempt: int


@dataclasses.dataclass(frozen=True)
class PreflightRecord:
    """A verified immutable-release setting bound to one workflow run."""

    repository_id: int
    repository: str
    workflow_path: str
    workflow_ref: str
    workflow_sha: str
    run_id: int
    run_attempt: int
    api_version: str
    enabled: bool
    enforced_by_owner: bool
    sha256: str


class PreflightAPI(Protocol):
    """Read-only GitHub surface used while capturing a preflight record."""

    def repository_identity(self) -> RepositoryIdentity:
        raise NotImplementedError

    def immutable_release_policy(self) -> ImmutableReleasePolicy:
        raise NotImplementedError


def _reject_json_constant(_value: str) -> NoReturn:
    raise _ResponseValidationError("JSON contains a non-finite number")


def _reject_json_float(_value: str) -> NoReturn:
    raise _ResponseValidationError("JSON contains a floating-point number")


def _bounded_json_integer(value: str) -> int:
    if JSON_INTEGER.fullmatch(value) is None or len(value) > len(str(MAX_ID)) + 1:
        raise _ResponseValidationError("JSON integer is outside its bounds")
    parsed = int(value)
    if not -MAX_ID <= parsed <= MAX_ID:
        raise _ResponseValidationError("JSON integer is outside its bounds")
    return parsed


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _ResponseValidationError(f"JSON repeats key {key!r}")
        result[key] = value
    return result


def _json_shape(value: object, *, depth: int = 1) -> int:
    if depth > MAX_JSON_DEPTH:
        raise _ResponseValidationError("JSON exceeds its depth limit")
    if isinstance(value, dict):
        count = 1 + len(value)
        for key, child in value.items():
            if not isinstance(key, str):
                raise _ResponseValidationError("JSON has a non-string object key")
            count += _json_shape(child, depth=depth + 1)
        return count
    if isinstance(value, list):
        return 1 + len(value) + sum(_json_shape(child, depth=depth + 1) for child in value)
    if value is None or isinstance(value, (str, int, bool)):
        return 1
    raise _ResponseValidationError("JSON contains an unsupported value")


def _strict_json(raw: bytes, source: str) -> object:
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_bounded_json_integer,
        )
        items = _json_shape(value)
    except (
        RecursionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _ResponseValidationError,
    ) as exc:
        raise PreflightError(f"{source} is not bounded JSON") from exc
    if items > MAX_JSON_ITEMS:
        raise PreflightError(f"{source} exceeds its JSON item limit")
    return value


def canonical_json(value: object) -> bytes:
    """Return the one accepted canonical JSON encoding."""

    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PreflightError("preflight record cannot be represented as canonical JSON") from exc
    return encoded + b"\n"


def _positive_integer(value: object, source: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ID:
        raise PreflightError(f"{source} is outside its integer bounds")
    return value


def _repository_name(value: object, source: str) -> str:
    if not isinstance(value, str) or len(value) > 256 or REPOSITORY.fullmatch(value) is None:
        raise PreflightError(f"{source} is invalid")
    components = value.split("/")
    if len(components) != 2 or any(
        component in {".", ".."} or len(component) > 100 for component in components
    ):
        raise PreflightError(f"{source} is invalid")
    return value


def _workflow_path(value: object, source: str) -> str:
    if not isinstance(value, str) or len(value) > 512 or WORKFLOW_PATH.fullmatch(value) is None:
        raise PreflightError(f"{source} is invalid")
    return value


def _workflow_ref(value: object, repository: str, workflow_path: str) -> str:
    if not isinstance(value, str) or len(value) > 768:
        raise PreflightError("workflow ref is invalid")
    prefix = f"{repository}/{workflow_path}@"
    if not value.startswith(prefix):
        raise PreflightError("workflow ref does not match the trusted repository and path")
    suffix = value.removeprefix(prefix)
    if SAFE_REF_SUFFIX.fullmatch(suffix) is None:
        raise PreflightError("workflow ref is invalid")
    ref_parts = suffix.split("/")[2:]
    if not ref_parts or any(part in {"", ".", ".."} for part in ref_parts):
        raise PreflightError("workflow ref is invalid")
    return value


def validate_expected_identity(expected: ExpectedIdentity) -> None:
    """Validate every independently trusted workflow value."""

    _positive_integer(expected.repository_id, "repository ID")
    repository = _repository_name(expected.repository, "repository name")
    workflow_path = _workflow_path(expected.workflow_path, "workflow path")
    _workflow_ref(expected.workflow_ref, repository, workflow_path)
    if not isinstance(expected.workflow_sha, str) or HEX40.fullmatch(expected.workflow_sha) is None:
        raise PreflightError("workflow SHA is invalid")
    _positive_integer(expected.run_id, "workflow run ID")
    _positive_integer(expected.run_attempt, "workflow run attempt")


def _policy_requirement(value: object) -> bool:
    if not isinstance(value, bool):
        raise PreflightError("owner-enforcement requirement must be a boolean")
    return value


def _record_value(
    expected: ExpectedIdentity, policy: ImmutableReleasePolicy
) -> Mapping[str, object]:
    return {
        "api": {"version": API_VERSION},
        "immutable_releases": {
            "enabled": policy.enabled,
            "enforced_by_owner": policy.enforced_by_owner,
        },
        "media_type": RECORD_MEDIA_TYPE,
        "repository": {
            "id": expected.repository_id,
            "name": expected.repository,
        },
        "run": {
            "attempt": expected.run_attempt,
            "id": expected.run_id,
        },
        "schema_version": SCHEMA_VERSION,
        "workflow": {
            "path": expected.workflow_path,
            "ref": expected.workflow_ref,
            "sha": expected.workflow_sha,
        },
    }


def _require_policy(policy: ImmutableReleasePolicy, require_owner_enforcement: bool) -> None:
    required = _policy_requirement(require_owner_enforcement)
    if (
        not isinstance(policy, ImmutableReleasePolicy)
        or not isinstance(policy.enabled, bool)
        or not isinstance(policy.enforced_by_owner, bool)
    ):
        raise PreflightError("immutable-release policy is ambiguous")
    if not policy.enabled:
        raise PreflightError("immutable releases are not enabled")
    if required and not policy.enforced_by_owner:
        raise PreflightError("immutable releases are not enforced by the repository owner")


def _same_repository(actual: RepositoryIdentity, expected: ExpectedIdentity) -> None:
    if not isinstance(actual, RepositoryIdentity):
        raise PreflightError("GitHub repository identity is ambiguous")
    repository_id = _positive_integer(actual.id, "GitHub repository ID")
    repository_name = _repository_name(actual.name, "GitHub repository name")
    if repository_id != expected.repository_id or repository_name != expected.repository:
        raise PreflightError("GitHub repository identity does not match trusted workflow context")


def _write_exclusive(path: Path, raw: bytes) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise PreflightError("preflight capture requires O_NOFOLLOW support")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | nofollow
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise PreflightError("cannot create the preflight record exclusively") from exc
    try:
        os.fchmod(descriptor, 0o600)
        position = 0
        while position < len(raw):
            written = os.write(descriptor, raw[position:])
            if written <= 0:
                raise PreflightError("cannot write the complete preflight record")
            position += written
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(raw)
        ):
            raise PreflightError("preflight record output has unsafe file metadata")
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise PreflightError("cannot write or inspect the preflight record safely") from exc
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    try:
        os.close(descriptor)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise PreflightError("cannot close the preflight record") from exc


def capture_record(
    api: PreflightAPI,
    output: Path,
    *,
    expected: ExpectedIdentity,
    require_owner_enforcement: bool,
) -> str:
    """Capture one positive setting result and return the raw record SHA-256."""

    validate_expected_identity(expected)
    required = _policy_requirement(require_owner_enforcement)
    _same_repository(api.repository_identity(), expected)
    policy = api.immutable_release_policy()
    _require_policy(policy, required)
    _same_repository(api.repository_identity(), expected)
    raw = canonical_json(_record_value(expected, policy))
    if not 1 <= len(raw) <= MAX_RECORD_BYTES:
        raise PreflightError("preflight record exceeds its byte limit")
    _write_exclusive(output, raw)
    return hashlib.sha256(raw).hexdigest()


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise PreflightError(f"{source} must contain exactly {sorted(fields)}")
    return value


def _validate_record_value(value: object, digest: str) -> PreflightRecord:
    record = _exact_mapping(
        value,
        {
            "api",
            "immutable_releases",
            "media_type",
            "repository",
            "run",
            "schema_version",
            "workflow",
        },
        "preflight record",
    )
    schema_version = _positive_integer(record["schema_version"], "preflight schema version")
    if schema_version != SCHEMA_VERSION:
        raise PreflightError("preflight record has an unsupported schema version")
    if record["media_type"] != RECORD_MEDIA_TYPE:
        raise PreflightError("preflight record has an unsupported media type")

    api = _exact_mapping(record["api"], {"version"}, "preflight API identity")
    if api["version"] != API_VERSION:
        raise PreflightError("preflight record has an unsupported GitHub API version")

    repository = _exact_mapping(
        record["repository"], {"id", "name"}, "preflight repository identity"
    )
    repository_id = _positive_integer(repository["id"], "preflight repository ID")
    repository_name = _repository_name(repository["name"], "preflight repository name")

    workflow = _exact_mapping(
        record["workflow"], {"path", "ref", "sha"}, "preflight workflow identity"
    )
    workflow_path = _workflow_path(workflow["path"], "preflight workflow path")
    workflow_ref = _workflow_ref(workflow["ref"], repository_name, workflow_path)
    workflow_sha = workflow["sha"]
    if not isinstance(workflow_sha, str) or HEX40.fullmatch(workflow_sha) is None:
        raise PreflightError("preflight workflow SHA is invalid")

    run = _exact_mapping(record["run"], {"attempt", "id"}, "preflight run identity")
    run_id = _positive_integer(run["id"], "preflight workflow run ID")
    run_attempt = _positive_integer(run["attempt"], "preflight workflow run attempt")

    policy = _exact_mapping(
        record["immutable_releases"],
        {"enabled", "enforced_by_owner"},
        "preflight immutable-release policy",
    )
    enabled = policy["enabled"]
    enforced_by_owner = policy["enforced_by_owner"]
    if not isinstance(enabled, bool) or not isinstance(enforced_by_owner, bool):
        raise PreflightError("preflight immutable-release policy is ambiguous")

    return PreflightRecord(
        repository_id=repository_id,
        repository=repository_name,
        workflow_path=workflow_path,
        workflow_ref=workflow_ref,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        api_version=API_VERSION,
        enabled=enabled,
        enforced_by_owner=enforced_by_owner,
        sha256=digest,
    )


def _file_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_record(path: Path) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise PreflightError("preflight verification requires O_NOFOLLOW support")
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | nofollow
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PreflightError("cannot open the preflight record safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_RECORD_BYTES
        ):
            raise PreflightError("preflight record has unsafe file metadata")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise PreflightError("preflight record was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PreflightError("preflight record has trailing bytes")
        after = os.fstat(descriptor)
        if _file_signature(after) != _file_signature(before):
            raise PreflightError("preflight record changed while it was read")
        try:
            path_metadata = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise PreflightError("preflight record path changed while it was read") from exc
        if _file_signature(path_metadata) != _file_signature(before):
            raise PreflightError("preflight record path changed while it was read")
        raw = b"".join(chunks)
    except OSError as exc:
        with contextlib.suppress(BaseException):
            os.close(descriptor)
        raise PreflightError("cannot read the preflight record safely") from exc
    except BaseException:
        with contextlib.suppress(BaseException):
            os.close(descriptor)
        raise
    try:
        os.close(descriptor)
    except OSError as exc:
        raise PreflightError("cannot close the preflight record safely") from exc
    return raw


def _require_expected_record(record: PreflightRecord, expected: ExpectedIdentity) -> None:
    observed = (
        record.repository_id,
        record.repository,
        record.workflow_path,
        record.workflow_ref,
        record.workflow_sha,
        record.run_id,
        record.run_attempt,
    )
    trusted = (
        expected.repository_id,
        expected.repository,
        expected.workflow_path,
        expected.workflow_ref,
        expected.workflow_sha,
        expected.run_id,
        expected.run_attempt,
    )
    if observed != trusted:
        raise PreflightError("preflight record does not match trusted workflow context")


def verify_record(
    path: Path,
    *,
    expected: ExpectedIdentity,
    capture_sha256: str,
    record_artifact_sha256: str,
    require_owner_enforcement: bool,
) -> PreflightRecord:
    """Verify a raw preflight artifact against independent workflow evidence."""

    validate_expected_identity(expected)
    required = _policy_requirement(require_owner_enforcement)
    if not isinstance(capture_sha256, str) or HEX64.fullmatch(capture_sha256) is None:
        raise PreflightError("captured preflight SHA-256 is invalid")
    if (
        not isinstance(record_artifact_sha256, str)
        or HEX64.fullmatch(record_artifact_sha256) is None
    ):
        raise PreflightError("preflight artifact SHA-256 is invalid")
    if capture_sha256 != record_artifact_sha256:
        raise PreflightError(
            "captured preflight SHA-256 does not match the provider artifact SHA-256"
        )
    raw = _read_record(path)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != capture_sha256:
        raise PreflightError("captured preflight SHA-256 does not match the downloaded bytes")
    if digest != record_artifact_sha256:
        raise PreflightError("preflight artifact SHA-256 does not match the downloaded bytes")
    value = _strict_json(raw, "preflight record")
    if canonical_json(value) != raw:
        raise PreflightError("preflight record is not canonically encoded")
    record = _validate_record_value(value, digest)
    _require_expected_record(record, expected)
    _require_policy(
        ImmutableReleasePolicy(record.enabled, record.enforced_by_owner),
        required,
    )
    return record


def _valid_timeout(value: object) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise PreflightError("GitHub request timeout is invalid")
    try:
        parsed = float(value)
    except (OverflowError, TypeError, ValueError):
        raise PreflightError("GitHub request timeout is invalid") from None
    if not 0 < parsed <= MAX_TIMEOUT_SECONDS:
        raise PreflightError("GitHub request timeout is invalid")
    return parsed


def _validate_token(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise PreflightError("GitHub token is invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise PreflightError("GitHub token is invalid") from None
    if (
        len(encoded) > MAX_TOKEN_BYTES
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
        or any(character.isspace() for character in value)
    ):
        raise PreflightError("GitHub token is invalid")
    return value


def _request_id(response: http.client.HTTPResponse) -> str:
    value = response.getheader("X-GitHub-Request-Id")
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("ascii", errors="ignore")) > MAX_REQUEST_ID_BYTES
        or REQUEST_ID.fullmatch(value) is None
    ):
        return "unavailable"
    return value


def _response_json(response: http.client.HTTPResponse) -> object:
    encoding = response.getheader("Content-Encoding")
    if encoding is not None and encoding.strip().lower() != "identity":
        raise _ResponseValidationError("response has an unsupported content encoding")
    content_type = response.getheader("Content-Type")
    if not isinstance(content_type, str) or content_type.partition(";")[0].strip().lower() != (
        "application/json"
    ):
        raise _ResponseValidationError("response has an unsupported media type")
    length_header = response.getheader("Content-Length")
    declared_length: int | None = None
    if length_header is not None:
        if DECIMAL.fullmatch(length_header) is None or len(length_header) > len(
            str(MAX_RESPONSE_BYTES)
        ):
            raise _ResponseValidationError("response has an invalid content length")
        declared_length = int(length_header)
        if declared_length > MAX_RESPONSE_BYTES:
            raise _ResponseValidationError("response exceeds its byte limit")
    try:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException):
        raise _ResponseValidationError("response body could not be read") from None
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
        raise _ResponseValidationError("response exceeds its byte limit")
    if declared_length is not None and len(raw) != declared_length:
        raise _ResponseValidationError("response body is truncated or extended")
    try:
        value = _strict_json(raw, "GitHub response")
    except PreflightError:
        raise _ResponseValidationError("response is not bounded JSON") from None
    return value


class GitHubImmutableReleasePreflightAPI:
    """Read the two GitHub endpoints required by the preflight contract."""

    __slots__ = ("_repository", "_timeout", "_token")

    def __init__(
        self,
        *,
        token: str,
        repository: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._token = _validate_token(token)
        self._repository = _repository_name(repository, "GitHub repository name")
        self._timeout = _valid_timeout(timeout)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(repository={self._repository!r}, timeout={self._timeout!r})"

    @property
    def _repository_path(self) -> str:
        return urllib.parse.quote(self._repository, safe="/")

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "identity",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }

    def _get_object(self, path: str) -> Mapping[str, Any]:
        try:
            connection = http.client.HTTPSConnection(API_HOST, timeout=self._timeout)
        except (OSError, http.client.HTTPException):
            raise PreflightError(f"GitHub GET {path} failed before request start") from None
        response: http.client.HTTPResponse | None = None
        try:
            connection.request("GET", path, headers=self._headers())
            response = connection.getresponse()
        except (OSError, http.client.HTTPException):
            with contextlib.suppress(OSError, http.client.HTTPException):
                connection.close()
            raise PreflightError(f"GitHub GET {path} failed during transport") from None
        except BaseException:
            with contextlib.suppress(BaseException):
                connection.close()
            raise
        try:
            request_id = _request_id(response)
            if response.status != http.client.OK:
                if response.status == http.client.NOT_FOUND:
                    raise PreflightError(
                        f"GitHub GET {path} returned 404; "
                        "immutable releases are not proven enabled "
                        f"(request {request_id})"
                    )
                raise PreflightError(
                    f"GitHub GET {path} returned {response.status} (request {request_id})"
                )
            try:
                value = _response_json(response)
            except _ResponseValidationError:
                raise PreflightError(
                    f"GitHub GET {path} returned an invalid success response (request {request_id})"
                ) from None
            if not isinstance(value, dict):
                raise PreflightError(
                    f"GitHub GET {path} did not return an object (request {request_id})"
                )
            return value
        finally:
            with contextlib.suppress(OSError, http.client.HTTPException):
                response.close()
            with contextlib.suppress(OSError, http.client.HTTPException):
                connection.close()

    def repository_identity(self) -> RepositoryIdentity:
        value = self._get_object(f"/repos/{self._repository_path}")
        if value.get("full_name") != self._repository:
            raise PreflightError("GitHub repository full name does not match trusted routing")
        return RepositoryIdentity(
            _positive_integer(value.get("id"), "GitHub repository ID"),
            self._repository,
        )

    def immutable_release_policy(self) -> ImmutableReleasePolicy:
        value = self._get_object(f"/repos/{self._repository_path}/immutable-releases")
        if set(value) != {"enabled", "enforced_by_owner"}:
            raise PreflightError("GitHub immutable-release response has unexpected fields")
        enabled = value["enabled"]
        enforced_by_owner = value["enforced_by_owner"]
        if not isinstance(enabled, bool) or not isinstance(enforced_by_owner, bool):
            raise PreflightError("GitHub immutable-release response is ambiguous")
        policy = ImmutableReleasePolicy(enabled, enforced_by_owner)
        _require_policy(policy, False)
        return policy
