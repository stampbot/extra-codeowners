#!/usr/bin/env python3
"""Authenticate one exact immutable GitHub release and its asset inventory."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn, Protocol, cast

# Python's isolated mode removes the script directory from sys.path. Add only
# this reviewed directory so the verifier can reuse the controller's manifest
# parser without making the caller's working directory importable.
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from release_controller import (  # noqa: E402
    MAX_ASSET_BYTES,
    MAX_ID,
    REPOSITORY,
    Asset,
    ControllerError,
    ReleasePlan,
    canonical_json,
    load_manifest,
)

SCHEMA_VERSION = 1
RECORD_KIND = "extra-codeowners/authenticated-github-release"
API_VERSION = "2026-03-10"
MINIMUM_GH_VERSION = (2, 93, 0)
MINIMUM_GH_VERSION_TEXT = ".".join(str(part) for part in MINIMUM_GH_VERSION)

DEFAULT_TIMEOUT_SECONDS = 120.0
MAX_TIMEOUT_SECONDS = 300.0
MAX_VERSION_OUTPUT_BYTES = 4096
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_COMMAND_ERROR_BYTES = 64 * 1024
MAX_ATTESTATION_PAYLOAD_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 200_000
READ_CHUNK_BYTES = 64 * 1024
TERMINATION_GRACE_SECONDS = 5.0
MAX_TOKEN_BYTES = 4096

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DECIMAL_ID = re.compile(r"^[1-9][0-9]{0,18}$")
GH_VERSION = re.compile(
    r"^gh version ([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9}) "
    r"\([0-9]{4}-[0-9]{2}-[0-9]{2}\)$"
)
RELEASE_PREDICATE_TYPE = "https://in-toto.io/attestation/release/v0.2"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
VERIFICATION_RESULT_MEDIA_TYPE = "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class VerificationError(RuntimeError):
    """The authenticated GitHub release contract could not be proven."""


@dataclasses.dataclass(frozen=True)
class RepositoryIdentity:
    """Immutable repository and owner identities observed from GitHub."""

    repository_id: int
    owner_id: int


@dataclasses.dataclass(frozen=True)
class ReleaseIdentity:
    """The exact immutable release accepted from the GitHub API."""

    release_id: int
    url: str


@dataclasses.dataclass(frozen=True)
class TagIdentity:
    """The release tag reference and the commit it resolves to."""

    attestation_subject_sha1: str
    target_commit: str


class GitHubClient(Protocol):
    """Read-only GitHub operations used by the verifier."""

    def check_version(self) -> str:
        raise NotImplementedError

    def api(self, endpoint: str) -> object:
        raise NotImplementedError

    def verify_release(self, repository: str, tag: str) -> object:
        raise NotImplementedError


def _reject_json_constant(value: str) -> NoReturn:
    raise VerificationError(f"JSON contains a non-finite number: {value}")


def _reject_json_float(value: str) -> NoReturn:
    raise VerificationError(f"JSON contains a floating-point number: {value}")


def _bounded_json_integer(value: str) -> int:
    if len(value) > 19:
        raise VerificationError("JSON integer exceeds its lexical bound")
    parsed = int(value)
    if parsed < -MAX_ID or parsed > MAX_ID:
        raise VerificationError("JSON integer exceeds its numeric bound")
    return parsed


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"JSON repeats object key {key!r}")
        result[key] = value
    return result


def _json_shape(value: object, *, depth: int = 1) -> int:
    if depth > MAX_JSON_DEPTH:
        raise VerificationError("JSON exceeds its depth bound")
    if isinstance(value, dict):
        items = 1 + len(value)
        for key, child in value.items():
            if not isinstance(key, str):
                raise VerificationError("JSON object has a non-string key")
            items += _json_shape(child, depth=depth + 1)
        return items
    if isinstance(value, list):
        items = 1
        for child in value:
            items += _json_shape(child, depth=depth + 1)
        return items
    if value is None or isinstance(value, (str, int, bool)):
        return 1
    raise VerificationError("JSON contains an unsupported value")


def strict_json(raw: bytes, source: str, *, maximum: int = MAX_COMMAND_OUTPUT_BYTES) -> object:
    """Parse one bounded UTF-8 JSON document with duplicate-key rejection."""

    if not 1 <= len(raw) <= maximum:
        raise VerificationError(f"{source} is outside its byte bound")
    try:
        value: object = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_bounded_json_integer,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise VerificationError(f"{source} is not strict bounded JSON") from exc
    if _json_shape(value) > MAX_JSON_ITEMS:
        raise VerificationError(f"{source} exceeds its item bound")
    return value


def _mapping(value: object, source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{source} is not a JSON object")
    return cast(Mapping[str, Any], value)


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    record = _mapping(value, source)
    if set(record) != fields:
        raise VerificationError(f"{source} must contain exactly {sorted(fields)}")
    return record


def _positive_id(value: object, source: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ID:
        raise VerificationError(f"{source} is outside its integer bounds")
    return value


def _decimal_id(value: object, source: str) -> int:
    if not isinstance(value, str) or DECIMAL_ID.fullmatch(value) is None or int(value) > MAX_ID:
        raise VerificationError(f"{source} is not a canonical positive ID")
    return int(value)


def _bounded_string(value: object, source: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{source} is not a bounded nonempty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise VerificationError(f"{source} is not valid Unicode") from None
    if len(encoded) > maximum:
        raise VerificationError(f"{source} is not a bounded nonempty string")
    return value


def _validated_token(value: str) -> str:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise VerificationError("GitHub token environment is invalid") from None
    if (
        not encoded
        or len(encoded) > MAX_TOKEN_BYTES
        or value != value.strip()
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
    ):
        raise VerificationError("GitHub token environment is invalid")
    return value


def _command_environment(
    source: Mapping[str, str],
    *,
    authenticated: bool,
) -> dict[str, str]:
    environment = {
        "GH_HOST": "github.com",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_PAGER": "cat",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PAGER": "cat",
        "TERM": "dumb",
    }
    for key in (
        "GH_CONFIG_DIR",
        "HOME",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
    ):
        if value := source.get(key):
            environment[key] = value
    if authenticated:
        gh_token = source.get("GH_TOKEN")
        github_token = source.get("GITHUB_TOKEN")
        if gh_token and github_token and gh_token != github_token:
            raise VerificationError("GH_TOKEN and GITHUB_TOKEN disagree")
        if token := gh_token or github_token:
            environment["GH_TOKEN"] = _validated_token(token)
    return environment


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _run_bounded(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout: float,
    maximum_stdout: int,
) -> bytes:
    """Run one fixed argv without a shell and retain only bounded output."""

    try:
        process = subprocess.Popen(  # noqa: S603 - argv and executable are validated by caller
            tuple(command),
            close_fds=True,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise VerificationError("cannot start the GitHub CLI") from exc
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise VerificationError("cannot capture GitHub CLI output")

    output = bytearray()
    errors = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise VerificationError("GitHub CLI command timed out")
            for key, _events in selector.select(min(remaining, 0.5)):
                chunk = os.read(key.fd, READ_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                retained = output if key.data == "stdout" else errors
                maximum = maximum_stdout if key.data == "stdout" else MAX_COMMAND_ERROR_BYTES
                if len(retained) + len(chunk) > maximum:
                    _stop_process(process)
                    stream = "output" if key.data == "stdout" else "diagnostics"
                    raise VerificationError(f"GitHub CLI {stream} exceeds its byte bound")
                retained.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_process(process)
            raise VerificationError("GitHub CLI command timed out")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _stop_process(process)
            raise VerificationError("GitHub CLI command timed out") from None
    except OSError as exc:
        _stop_process(process)
        raise VerificationError("cannot read GitHub CLI output") from exc
    except BaseException:
        if process.poll() is None:
            _stop_process(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if return_code != 0:
        raise VerificationError(f"GitHub CLI command failed with exit status {return_code}")
    return bytes(output)


def _run_download(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout: float,
    destination: int,
    maximum_bytes: int,
) -> tuple[int, str]:
    """Stream one fixed-argv command into a retained descriptor."""

    if not 1 <= maximum_bytes <= MAX_ASSET_BYTES:
        raise VerificationError("GitHub release asset byte bound is invalid")
    try:
        metadata = os.fstat(destination)
    except OSError as exc:
        raise VerificationError("cannot inspect the release asset destination") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size != 0:
        raise VerificationError("release asset destination is not one empty regular file")

    try:
        process = subprocess.Popen(  # noqa: S603 - argv and executable are validated by caller
            tuple(command),
            close_fds=True,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise VerificationError("cannot start the GitHub CLI") from exc
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise VerificationError("cannot capture GitHub CLI output")

    digest = hashlib.sha256()
    received = 0
    errors = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise VerificationError("GitHub CLI command timed out")
            for key, _events in selector.select(min(remaining, 0.5)):
                chunk = os.read(key.fd, READ_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    if len(errors) + len(chunk) > MAX_COMMAND_ERROR_BYTES:
                        _stop_process(process)
                        raise VerificationError("GitHub CLI diagnostics exceeds its byte bound")
                    errors.extend(chunk)
                    continue
                if len(chunk) > maximum_bytes - received:
                    _stop_process(process)
                    raise VerificationError("GitHub release asset exceeds its byte bound")
                view = memoryview(chunk)
                while view:
                    written = os.write(destination, view)
                    if written <= 0:
                        raise OSError("short write")
                    view = view[written:]
                digest.update(chunk)
                received += len(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_process(process)
            raise VerificationError("GitHub CLI command timed out")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _stop_process(process)
            raise VerificationError("GitHub CLI command timed out") from None
    except OSError as exc:
        _stop_process(process)
        raise VerificationError("cannot retain GitHub release asset bytes") from exc
    except BaseException:
        if process.poll() is None:
            _stop_process(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if return_code != 0:
        raise VerificationError(f"GitHub CLI command failed with exit status {return_code}")
    return received, digest.hexdigest()


class GitHubCLI:
    """Bounded, token-minimizing access to the pinned GitHub CLI."""

    __slots__ = ("_environment", "_executable", "_timeout")

    def __init__(
        self,
        *,
        executable: str = "gh",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < float(timeout) <= MAX_TIMEOUT_SECONDS
        ):
            raise VerificationError("GitHub CLI timeout is outside its bounds")
        resolved = shutil.which(executable)
        if resolved is None:
            raise VerificationError("cannot find the GitHub CLI executable")
        try:
            metadata = os.stat(resolved)
        except OSError as exc:
            raise VerificationError("cannot inspect the GitHub CLI executable") from exc
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            raise VerificationError("GitHub CLI executable is not an executable regular file")
        self._executable = resolved
        self._timeout = float(timeout)
        self._environment = dict(os.environ if environment is None else environment)

    def _run(
        self,
        arguments: Sequence[str],
        *,
        authenticated: bool,
        maximum_stdout: int = MAX_COMMAND_OUTPUT_BYTES,
    ) -> bytes:
        return _run_bounded(
            (self._executable, *arguments),
            environment=_command_environment(self._environment, authenticated=authenticated),
            timeout=self._timeout,
            maximum_stdout=maximum_stdout,
        )

    def check_version(self) -> str:
        raw = self._run(
            ("version",),
            authenticated=False,
            maximum_stdout=MAX_VERSION_OUTPUT_BYTES,
        )
        try:
            first_line = raw.decode("ascii").splitlines()[0]
        except (IndexError, UnicodeDecodeError) as exc:
            raise VerificationError("GitHub CLI returned an invalid version") from exc
        match = GH_VERSION.fullmatch(first_line)
        if match is None:
            raise VerificationError("GitHub CLI returned an invalid version")
        version = tuple(int(part) for part in match.groups())
        if version < MINIMUM_GH_VERSION:
            raise VerificationError(f"GitHub CLI {MINIMUM_GH_VERSION_TEXT} or newer is required")
        return ".".join(match.groups())

    def api(self, endpoint: str) -> object:
        raw = self._run(
            (
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                f"X-GitHub-Api-Version: {API_VERSION}",
                endpoint,
            ),
            authenticated=True,
        )
        return strict_json(raw, "GitHub API response")

    def verify_release(self, repository: str, tag: str) -> object:
        raw = self._run(
            (
                "release",
                "verify",
                tag,
                "--repo",
                repository,
                "--format",
                "json",
            ),
            authenticated=True,
        )
        return strict_json(raw, "GitHub release-verification response")

    def download_asset(
        self,
        repository: str,
        asset_id: int,
        destination: int,
        maximum_bytes: int,
    ) -> tuple[int, str]:
        """Download one immutable release asset by database ID."""

        if REPOSITORY.fullmatch(repository) is None:
            raise VerificationError("GitHub release repository is invalid")
        _positive_id(asset_id, "GitHub release asset ID")
        endpoint = f"repos/{urllib.parse.quote(repository, safe='/')}/releases/assets/{asset_id}"
        return _run_download(
            (
                self._executable,
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "-H",
                "Accept: application/octet-stream",
                "-H",
                f"X-GitHub-Api-Version: {API_VERSION}",
                endpoint,
            ),
            environment=_command_environment(self._environment, authenticated=True),
            timeout=self._timeout,
            destination=destination,
            maximum_bytes=maximum_bytes,
        )


def _repository_endpoint(repository: str) -> str:
    return f"repos/{urllib.parse.quote(repository, safe='/')}"


def _release_purl(plan: ReleasePlan) -> str:
    return f"pkg:github/{plan.repository}@{plan.tag}"


def _validate_repository(value: object, plan: ReleasePlan) -> RepositoryIdentity:
    record = _mapping(value, "GitHub repository response")
    repository_id = _positive_id(record.get("id"), "GitHub repository ID")
    if repository_id != plan.repository_id or record.get("full_name") != plan.repository:
        raise VerificationError("GitHub repository identity does not match the manifest")
    owner = _mapping(record.get("owner"), "GitHub repository owner")
    owner_id = _positive_id(owner.get("id"), "GitHub repository owner ID")
    if owner.get("login") != plan.repository.partition("/")[0]:
        raise VerificationError("GitHub repository owner does not match the manifest")
    return RepositoryIdentity(repository_id, owner_id)


def _resolve_tag(client: GitHubClient, plan: ReleasePlan) -> TagIdentity:
    repository = urllib.parse.quote(plan.repository, safe="/")
    tag = urllib.parse.quote(plan.tag, safe="")
    reference = _mapping(
        client.api(f"repos/{repository}/git/ref/tags/{tag}"),
        "GitHub tag reference",
    )
    if reference.get("ref") != f"refs/tags/{plan.tag}":
        raise VerificationError("GitHub returned a different tag reference")
    target = _mapping(reference.get("object"), "GitHub tag reference object")
    target_sha = target.get("sha")
    if not isinstance(target_sha, str) or HEX40.fullmatch(target_sha) is None:
        raise VerificationError("GitHub tag reference has an invalid object ID")
    if target.get("type") == "commit":
        return TagIdentity(target_sha, target_sha)
    if target.get("type") != "tag":
        raise VerificationError("GitHub tag reference has an unsupported object type")
    annotated = _mapping(
        client.api(f"repos/{repository}/git/tags/{target_sha}"),
        "GitHub annotated tag",
    )
    if annotated.get("sha") != target_sha or annotated.get("tag") != plan.tag:
        raise VerificationError("GitHub returned a different annotated tag")
    commit = _mapping(annotated.get("object"), "GitHub annotated tag object")
    commit_sha = commit.get("sha")
    if (
        commit.get("type") != "commit"
        or not isinstance(commit_sha, str)
        or HEX40.fullmatch(commit_sha) is None
    ):
        raise VerificationError("GitHub annotated tag does not point directly to a commit")
    return TagIdentity(target_sha, commit_sha)


def _validate_release(
    value: object,
    plan: ReleasePlan,
    *,
    expected_id: int | None = None,
) -> ReleaseIdentity:
    record = _mapping(value, "GitHub release response")
    release_id = _positive_id(record.get("id"), "GitHub release ID")
    if expected_id is not None and release_id != expected_id:
        raise VerificationError("GitHub returned a different release ID")
    expected_url = f"https://github.com/{plan.repository}/releases/tag/{plan.tag}"
    expected_api_url = f"https://api.github.com/repos/{plan.repository}/releases/{release_id}"
    expected_assets_url = f"{expected_api_url}/assets"
    expected = {
        "assets_url": expected_assets_url,
        "body": plan.marker,
        "draft": False,
        "html_url": expected_url,
        "immutable": True,
        "name": plan.tag,
        "prerelease": False,
        "tag_name": plan.tag,
        "target_commitish": plan.target_commit,
        "url": expected_api_url,
    }
    if any(record.get(key) != expected_value for key, expected_value in expected.items()):
        raise VerificationError("GitHub release does not match the immutable manifest identity")
    return ReleaseIdentity(release_id, expected_url)


def _asset_value(value: object, expected: Asset, plan: ReleasePlan) -> int:
    record = _mapping(value, f"GitHub release asset {expected.name}")
    asset_id = _positive_id(record.get("id"), f"GitHub release asset {expected.name} ID")
    expected_api_url = f"https://api.github.com/repos/{plan.repository}/releases/assets/{asset_id}"
    encoded_name = urllib.parse.quote(expected.name, safe="")
    expected_download_url = (
        f"https://github.com/{plan.repository}/releases/download/{plan.tag}/{encoded_name}"
    )
    expected_values = {
        "browser_download_url": expected_download_url,
        "content_type": "application/octet-stream",
        "digest": f"sha256:{expected.sha256}",
        "label": None,
        "name": expected.name,
        "size": expected.size,
        "state": "uploaded",
        "url": expected_api_url,
    }
    if any(record.get(key) != expected_value for key, expected_value in expected_values.items()):
        raise VerificationError(f"GitHub release asset {expected.name} does not match the manifest")
    return asset_id


def _validate_assets(value: object, plan: ReleasePlan) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, list):
        raise VerificationError("GitHub release-assets response is not an array")
    if len(value) != len(plan.assets):
        raise VerificationError("GitHub release has the wrong asset count")
    expected = {asset.name: asset for asset in plan.assets}
    observed: dict[str, int] = {}
    ids: set[int] = set()
    for raw in value:
        record = _mapping(raw, "GitHub release asset")
        name = record.get("name")
        if not isinstance(name, str) or name not in expected or name in observed:
            raise VerificationError("GitHub release has an unexpected or duplicate asset")
        asset_id = _asset_value(record, expected[name], plan)
        if asset_id in ids:
            raise VerificationError("GitHub release repeats an asset ID")
        observed[name] = asset_id
        ids.add(asset_id)
    if set(observed) != set(expected):
        raise VerificationError("GitHub release is missing an expected asset")
    return tuple(sorted(observed.items()))


def _decode_attestation_payload(value: object) -> bytes:
    payload = _bounded_string(value, "release attestation payload", maximum=2_000_000)
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError("release attestation payload is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != payload:
        raise VerificationError("release attestation payload is not canonical base64")
    if not 1 <= len(decoded) <= MAX_ATTESTATION_PAYLOAD_BYTES:
        raise VerificationError("release attestation payload is outside its byte bound")
    return decoded


def _validate_subjects(
    value: object,
    plan: ReleasePlan,
    *,
    tag_subject_sha1: str,
) -> None:
    if not isinstance(value, list) or len(value) != len(plan.assets) + 1:
        raise VerificationError("release attestation has the wrong subject count")
    release = _exact_mapping(value[0], {"digest", "uri"}, "release attestation tag subject")
    if release["uri"] != _release_purl(plan):
        raise VerificationError("release attestation has the wrong tag subject")
    release_digest = _exact_mapping(release["digest"], {"sha1"}, "release attestation tag digest")
    if release_digest["sha1"] != tag_subject_sha1:
        raise VerificationError("release attestation has the wrong tag reference")

    expected = {asset.name: asset.sha256 for asset in plan.assets}
    observed: dict[str, str] = {}
    for index, raw in enumerate(value[1:]):
        subject = _exact_mapping(
            raw,
            {"digest", "name"},
            f"release attestation asset subject {index}",
        )
        name = subject["name"]
        if not isinstance(name, str) or name not in expected or name in observed:
            raise VerificationError("release attestation has an unexpected or duplicate asset")
        digest = _exact_mapping(
            subject["digest"],
            {"sha256"},
            f"release attestation asset {name} digest",
        )
        sha256 = digest["sha256"]
        if not isinstance(sha256, str) or sha256 != expected[name]:
            raise VerificationError(f"release attestation asset {name} has the wrong digest")
        observed[name] = sha256
    if observed != expected:
        raise VerificationError("release attestation is missing an expected asset")


def _validate_release_attestation(
    value: object,
    plan: ReleasePlan,
    *,
    owner_id: int,
    release_id: int,
    tag_subject_sha1: str,
) -> str:
    result = _exact_mapping(
        value,
        {"attestation", "verificationResult"},
        "GitHub release-verification response",
    )
    verification_result = _exact_mapping(
        result["verificationResult"],
        {
            "mediaType",
            "signature",
            "statement",
            "verifiedIdentity",
            "verifiedTimestamps",
        },
        "GitHub release verification result",
    )
    attestation = _exact_mapping(
        result["attestation"],
        {"bundle", "bundle_url", "initiator"},
        "GitHub release attestation",
    )
    # GitHub CLI 2.96.0 filters the API response to initiator=github, fetches
    # the selected bundle, and returns a new in-memory Attestation containing
    # only that bundle. These two API routing fields therefore serialize empty.
    if attestation["initiator"] != "" or attestation["bundle_url"] != "":
        raise VerificationError("release attestation has unexpected retained API metadata")
    bundle = _exact_mapping(
        attestation["bundle"],
        {"dsseEnvelope", "mediaType", "verificationMaterial"},
        "GitHub release attestation bundle",
    )
    if bundle["mediaType"] != SIGSTORE_BUNDLE_MEDIA_TYPE:
        raise VerificationError("release attestation has an unsupported Sigstore bundle type")
    _mapping(bundle["verificationMaterial"], "release attestation verification material")
    envelope = _exact_mapping(
        bundle["dsseEnvelope"],
        {"payload", "payloadType", "signatures"},
        "release attestation DSSE envelope",
    )
    if envelope["payloadType"] != DSSE_PAYLOAD_TYPE:
        raise VerificationError("release attestation has the wrong DSSE payload type")
    signatures = envelope["signatures"]
    if (
        not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], dict)
    ):
        raise VerificationError("release attestation has the wrong signature count")
    payload = _decode_attestation_payload(envelope["payload"])
    statement = _exact_mapping(
        strict_json(
            payload,
            "release attestation statement",
            maximum=MAX_ATTESTATION_PAYLOAD_BYTES,
        ),
        {"_type", "predicate", "predicateType", "subject"},
        "release attestation statement",
    )
    if statement["_type"] != STATEMENT_TYPE:
        raise VerificationError("release attestation has the wrong statement type")
    if statement["predicateType"] != RELEASE_PREDICATE_TYPE:
        raise VerificationError("release attestation has the wrong predicate type")
    if (
        verification_result["mediaType"] != VERIFICATION_RESULT_MEDIA_TYPE
        or verification_result["statement"] != statement
        or not _mapping(
            verification_result["signature"],
            "GitHub release verified signature",
        )
        or not _mapping(
            verification_result["verifiedIdentity"],
            "GitHub release verified identity",
        )
        or not isinstance(verification_result["verifiedTimestamps"], list)
        or not verification_result["verifiedTimestamps"]
        or any(
            not isinstance(timestamp, dict)
            for timestamp in verification_result["verifiedTimestamps"]
        )
    ):
        raise VerificationError("GitHub release verification result does not match its bundle")
    predicate = _exact_mapping(
        statement["predicate"],
        {
            "databaseId",
            "ownerId",
            "packageId",
            "purl",
            "repository",
            "repositoryId",
            "tag",
        },
        "release attestation predicate",
    )
    expected_predicate: Mapping[str, object] = {
        "databaseId": release_id,
        "ownerId": owner_id,
        "packageId": plan.repository_id,
        "repositoryId": plan.repository_id,
    }
    for field, expected in expected_predicate.items():
        if _decimal_id(predicate[field], f"release attestation {field}") != expected:
            raise VerificationError(f"release attestation {field} does not match GitHub")
    if (
        predicate["purl"] != _release_purl(plan)
        or predicate["repository"] != plan.repository
        or predicate["tag"] != plan.tag
    ):
        raise VerificationError("release attestation predicate does not match the manifest")
    _validate_subjects(
        statement["subject"],
        plan,
        tag_subject_sha1=tag_subject_sha1,
    )
    return hashlib.sha256(payload).hexdigest()


def _release_endpoint(plan: ReleasePlan) -> str:
    repository = urllib.parse.quote(plan.repository, safe="/")
    tag = urllib.parse.quote(plan.tag, safe="")
    return f"repos/{repository}/releases/tags/{tag}"


def _release_id_endpoint(plan: ReleasePlan, release_id: int) -> str:
    repository = urllib.parse.quote(plan.repository, safe="/")
    return f"repos/{repository}/releases/{release_id}"


def _assets_endpoint(plan: ReleasePlan, release_id: int) -> str:
    return f"{_release_id_endpoint(plan, release_id)}/assets?per_page=100&page=1"


def verify_github_release(
    plan: ReleasePlan,
    *,
    expected_manifest_sha256: str,
    client: GitHubClient,
) -> Mapping[str, object]:
    """Authenticate one live immutable release against a reviewed manifest."""

    if HEX64.fullmatch(expected_manifest_sha256) is None:
        raise VerificationError("expected manifest SHA-256 is invalid")
    if plan.manifest_sha256 != expected_manifest_sha256:
        raise VerificationError("release manifest does not match the trusted SHA-256")

    gh_version = client.check_version()
    repository = _validate_repository(client.api(_repository_endpoint(plan.repository)), plan)
    tag = _resolve_tag(client, plan)
    if tag.target_commit != plan.target_commit:
        raise VerificationError("GitHub release tag does not resolve to the manifest commit")
    release = _validate_release(client.api(_release_endpoint(plan)), plan)
    assets = _validate_assets(client.api(_assets_endpoint(plan, release.release_id)), plan)
    payload_sha256 = _validate_release_attestation(
        client.verify_release(plan.repository, plan.tag),
        plan,
        owner_id=repository.owner_id,
        release_id=release.release_id,
        tag_subject_sha1=tag.attestation_subject_sha1,
    )

    final_repository = _validate_repository(client.api(_repository_endpoint(plan.repository)), plan)
    if final_repository != repository:
        raise VerificationError("GitHub repository identity changed during verification")
    final_tag = _resolve_tag(client, plan)
    if final_tag.target_commit != plan.target_commit or final_tag != tag:
        raise VerificationError("GitHub release tag changed during verification")
    final_release = _validate_release(
        client.api(_release_id_endpoint(plan, release.release_id)),
        plan,
        expected_id=release.release_id,
    )
    if final_release != release:
        raise VerificationError("GitHub release identity changed during verification")
    final_assets = _validate_assets(client.api(_assets_endpoint(plan, release.release_id)), plan)
    if final_assets != assets:
        raise VerificationError("GitHub release assets changed during verification")

    return {
        "assets": [
            {"name": asset.name, "sha256": asset.sha256, "size": asset.size}
            for asset in plan.assets
        ],
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {
            "minimum_version": MINIMUM_GH_VERSION_TEXT,
            "version": gh_version,
        },
        "kind": RECORD_KIND,
        "release": {
            "attestation_payload_sha256": payload_sha256,
            "attestation_predicate_type": RELEASE_PREDICATE_TYPE,
            "id": release.release_id,
            "immutable": True,
            "url": release.url,
        },
        "repository": {
            "id": repository.repository_id,
            "name": plan.repository,
            "owner_id": repository.owner_id,
        },
        "schema_version": SCHEMA_VERSION,
        "tag": {
            "attestation_subject_sha1": tag.attestation_subject_sha1,
            "name": plan.tag,
            "target_commit": plan.target_commit,
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Authenticate an immutable GitHub release against one reviewed "
            "release-controller manifest."
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--gh", default="gh")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        try:
            plan = load_manifest(arguments.manifest)
        except ControllerError as exc:
            raise VerificationError("release-controller manifest is invalid") from exc
        client = GitHubCLI(
            executable=arguments.gh,
            timeout=arguments.timeout_seconds,
        )
        result = verify_github_release(
            plan,
            expected_manifest_sha256=arguments.manifest_sha256,
            client=client,
        )
        sys.stdout.buffer.write(canonical_json(result))
    except VerificationError as exc:
        sys.stderr.write(f"GitHub release verification failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
