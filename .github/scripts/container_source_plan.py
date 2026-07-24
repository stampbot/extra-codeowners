#!/usr/bin/env python3
"""Build the network-facing direct source request plan.

This program reads trusted policy and lock metadata. It does not fetch or open
source archives. A later fetch-only process consumes the plan, while archive
parsing stays behind the offline parser boundary.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import lzma
import os
import re
import secrets
import stat
import sys
import tarfile
import tomllib
import urllib.parse
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Literal, cast

SCHEMA_VERSION = 1
MEDIA_TYPE = "application/vnd.stampbot.container-source-plan.v1+json"
KIND = "direct"
ALPINE_DISTFILES_KIND = "alpine-distfiles"
SUPPORTED_EVIDENCE_SCHEMA_VERSION = 7

PLATFORMS = ("linux/amd64", "linux/arm64")
APPLICATION_NAME = "extra-codeowners"

MAX_POLICY_BYTES = 8 * 1024 * 1024
MAX_UV_LOCK_BYTES = 4 * 1024 * 1024
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_NATIVE_SOURCE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_OBJECT_BYTES = 1024 * 1024 * 1024
MAX_LICENSE_BYTES = 2 * 1024 * 1024
MAX_REQUESTS = 512
MAX_CONSUMERS_PER_REQUEST = 512
MAX_TOTAL_CONSUMER_REFERENCES = 2_048
MAX_TOKEN_BYTES = 512
MAX_CONTAINER_DEPTH = 64
MAX_CONTAINER_ITEMS = 1_000_000
MAX_RECIPE_ARCHIVE_MEMBERS = 250_000
MAX_RECIPE_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_RECIPE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TAR_EXTENSION_BYTES = 1024 * 1024
MAX_TAR_EXTENSIONS_TOTAL_BYTES = 8 * 1024 * 1024
MAX_APKBUILD_BYTES = 1024 * 1024
MAX_DISTFILE_FILENAME_BYTES = 255
MAX_ARCHIVE_PATH_BYTES = 4096
READ_CHUNK_BYTES = 1024 * 1024

SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA512 = re.compile(r"^[0-9a-f]{128}$")
PACKAGE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,198}[a-z0-9])?$")
ALPINE_ORIGIN = re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,199}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
LICENSE_ID = re.compile(r"^[A-Za-z0-9.+-]+$")
HOST = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
PLAN_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@#+-]*$")
WHEEL_PART = re.compile(r"^[A-Za-z0-9_.]+$")
WHEEL_PYTHON_TAG = re.compile(r"^cp[0-9]+$")
WHEEL_BUILD = re.compile(r"^[0-9][A-Za-z0-9_]*$")
ALPINE_RELEASE = re.compile(r"^v[0-9]+\.[0-9]+$")
SHA512_LINE = re.compile(r"^([0-9a-f]{128})  (\S.*)$")
SHELL_VARIABLE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}")
STATIC_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]{0,127})=(.*)$")
STATIC_ASSIGNMENT_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,255}")
STATIC_SOURCE_METADATA_VARIABLES = frozenset({"pkgver"})
SOURCE_ASSIGNMENT = re.compile(r"^[ \t]*(?:export[ \t]+)?source(?:[+?])?=", re.MULTILINE)
WHEEL_PLATFORM = {
    "linux/amd64": re.compile(r"^musllinux_[0-9]+_[0-9]+_x86_64$"),
    "linux/arm64": re.compile(r"^musllinux_[0-9]+_[0-9]+_aarch64$"),
}


class PlanError(ValueError):
    """The reviewed metadata cannot produce one unambiguous direct plan."""


@dataclass(frozen=True)
class Artifact:
    """One digest-pinned artifact binding from policy or the lock file."""

    url: str
    digest: str
    size: int | None


@dataclass(frozen=True)
class LockPackage:
    """The source and wheel records needed from one selected lock package."""

    sdist: Artifact | None
    wheels: tuple[Artifact, ...]


@dataclass(frozen=True)
class WheelNeed:
    """One platform-specific native wheel selected by reviewed policy."""

    platform: str
    owner: str
    package: tuple[str, str]
    artifact: Artifact
    consumer: str


@dataclass(frozen=True)
class RecipeNeed:
    """One exact parent-store recipe object selected for offline parsing."""

    request_id: str
    origin: str
    recipe_key: str
    artifact: Artifact
    consumers: frozenset[str]
    distfiles_release: str
    allow_dynamic_sources: bool
    allowed_links: tuple[Mapping[str, str], ...]
    reviewed_distfiles: tuple[ReviewedDistfile, ...] | None


@dataclass(frozen=True)
class ParsedDistfile:
    """One checksummed non-local file derived from an APKBUILD."""

    filename: str
    digest: str


@dataclass(frozen=True)
class ReviewedDistfile:
    """One policy-listed native-component distfile binding."""

    filename: str
    artifact: Artifact


class _BoundedTarInfo(tarfile.TarInfo):
    """Reject attacker-sized PAX and GNU extension payloads before allocation."""

    def _bound_extension(self, archive: tarfile.TarFile) -> None:
        if self.size < 0 or self.size > MAX_TAR_EXTENSION_BYTES:
            raise PlanError("recipe archive extension header exceeds its size limit")
        attribute = "_extra_codeowners_source_plan_extension_bytes"
        total = int(getattr(archive, attribute, 0)) + self.size
        if total > MAX_TAR_EXTENSIONS_TOTAL_BYTES:
            raise PlanError("recipe archive extension headers exceed their aggregate limit")
        setattr(archive, attribute, total)

    def _proc_pax(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        self._bound_extension(archive)
        try:
            result: tarfile.TarInfo | None = super()._proc_pax(archive)  # type: ignore[misc]
        except tarfile.HeaderError as exc:
            raise PlanError("recipe archive has a malformed PAX header") from exc
        if result is not None and result.size < 0:
            raise PlanError("recipe archive has a negative PAX member size")
        return result

    def _proc_gnulong(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        self._bound_extension(archive)
        try:
            result: tarfile.TarInfo | None = super()._proc_gnulong(archive)  # type: ignore[misc]
        except tarfile.HeaderError as exc:
            raise PlanError("recipe archive has a malformed GNU long-name header") from exc
        if result is not None and result.size < 0:
            raise PlanError("recipe archive has a negative GNU member size")
        return result


@dataclass(frozen=True)
class _FileIdentity:
    """Security-relevant identity retained across one local-file read."""

    device: int
    inode: int
    mode: int
    links: int
    uid: int
    gid: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass
class _Request:
    """Mutable consumer aggregation for one otherwise immutable request."""

    request_id: str
    url: str
    allowed_hosts: tuple[str, ...]
    algorithm: str
    digest: str
    expected_size: int | None
    max_bytes: int
    consumers: set[str] = field(default_factory=set)

    def binding(self) -> tuple[object, ...]:
        return (
            self.url,
            self.allowed_hosts,
            self.algorithm,
            self.digest,
            self.expected_size,
            self.max_bytes,
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.request_id,
            "url": self.url,
            "allowed_hosts": list(self.allowed_hosts),
            "algorithm": self.algorithm,
            "digest": self.digest,
            "expected_size": self.expected_size,
            "max_bytes": self.max_bytes,
            "consumers": sorted(self.consumers),
        }


class _PlanBuilder:
    """Collect requests while rejecting ambiguous identity and URL bindings."""

    def __init__(self) -> None:
        self._requests: dict[str, _Request] = {}
        self._request_spellings: dict[str, str] = {}
        self._url_bindings: dict[str, tuple[str, str, int | None]] = {}
        self._digest_sizes: dict[tuple[str, str], int] = {}
        self._known_total_size = 0
        self._consumer_spellings: dict[str, str] = {}
        self._consumer_references = 0

    def add(
        self,
        request_id: str,
        artifact: Artifact,
        *,
        max_bytes: int,
        consumers: Sequence[str] | set[str],
        algorithm: str = "sha256",
        allow_alpine_distfiles: bool = False,
    ) -> None:
        checked_id = _checked_token(request_id, "request id")
        checked_consumers = {
            _checked_token(consumer, f"consumer for {checked_id}") for consumer in consumers
        }
        folded_id = checked_id.casefold()
        previous_id_spelling = self._request_spellings.get(folded_id)
        if previous_id_spelling is not None and previous_id_spelling != checked_id:
            raise PlanError(
                f"request IDs differ only by case: {previous_id_spelling} / {checked_id}"
            )
        folded_consumers: dict[str, str] = {}
        for consumer in checked_consumers:
            folded = consumer.casefold()
            previous_spelling = folded_consumers.get(folded)
            if previous_spelling is not None and previous_spelling != consumer:
                raise PlanError(f"consumers differ only by case: {previous_spelling} / {consumer}")
            previous_spelling = self._consumer_spellings.get(folded)
            if previous_spelling is not None and previous_spelling != consumer:
                raise PlanError(f"consumers differ only by case: {previous_spelling} / {consumer}")
            folded_consumers[folded] = consumer
        if not checked_consumers:
            raise PlanError(f"request has no consumers: {checked_id}")
        if len(checked_consumers) > MAX_CONSUMERS_PER_REQUEST:
            raise PlanError(f"request has too many consumers: {checked_id}")

        allowed_hosts = _allowed_hosts(
            artifact.url,
            allow_alpine_distfiles=allow_alpine_distfiles,
        )
        digest = _checked_digest(algorithm, artifact.digest, f"digest for {checked_id}")
        expected_size = _checked_optional_size(artifact.size, f"expected size for {checked_id}")
        if isinstance(max_bytes, bool) or not 0 < max_bytes <= MAX_NATIVE_SOURCE_BYTES:
            raise PlanError(f"request has an invalid byte limit: {checked_id}")
        if expected_size is not None and expected_size > max_bytes:
            raise PlanError(f"request exceeds its byte limit: {checked_id}")

        request = _Request(
            request_id=checked_id,
            url=artifact.url,
            allowed_hosts=allowed_hosts,
            algorithm=algorithm,
            digest=digest,
            expected_size=expected_size,
            max_bytes=max_bytes,
            consumers=checked_consumers,
        )
        previous = self._requests.get(checked_id)
        if previous is not None:
            if previous.binding() != request.binding():
                raise PlanError(f"conflicting request binding: {checked_id}")
            added_consumers = checked_consumers - previous.consumers
            if len(previous.consumers) + len(added_consumers) > MAX_CONSUMERS_PER_REQUEST:
                raise PlanError(f"request has too many consumers: {checked_id}")
            if self._consumer_references + len(added_consumers) > MAX_TOTAL_CONSUMER_REFERENCES:
                raise PlanError("direct plan has too many consumer references")
            previous.consumers.update(added_consumers)
            self._consumer_references += len(added_consumers)
            self._consumer_spellings.update(folded_consumers)
            return

        url_binding = (algorithm, digest, expected_size)
        previous_url = self._url_bindings.get(artifact.url)
        if previous_url is not None and (
            previous_url[:2] != url_binding[:2]
            or (
                previous_url[2] is not None
                and expected_size is not None
                and previous_url[2] != expected_size
            )
        ):
            raise PlanError(
                f"URL has conflicting artifact bindings at {_safe_url_origin(artifact.url)}"
            )

        digest_identity = (algorithm, digest)
        added_known_size = 0
        if expected_size is not None:
            previous_size = self._digest_sizes.get(digest_identity)
            if previous_size is not None and previous_size != expected_size:
                raise PlanError(f"{algorithm} digest has conflicting expected sizes: {digest}")
            if previous_size is None:
                added_known_size = expected_size
                if self._known_total_size + added_known_size > MAX_TOTAL_OBJECT_BYTES:
                    raise PlanError("direct plan known objects exceed their aggregate byte limit")

        if len(self._requests) >= MAX_REQUESTS:
            raise PlanError("direct plan has too many requests")
        if self._consumer_references + len(checked_consumers) > MAX_TOTAL_CONSUMER_REFERENCES:
            raise PlanError("direct plan has too many consumer references")
        if previous_url is None or previous_url[2] is None:
            self._url_bindings[artifact.url] = url_binding
        if added_known_size:
            self._digest_sizes[digest_identity] = added_known_size
            self._known_total_size += added_known_size
        self._requests[checked_id] = request
        self._request_spellings[folded_id] = checked_id
        self._consumer_spellings.update(folded_consumers)
        self._consumer_references += len(checked_consumers)

    def requests(self) -> list[dict[str, Any]]:
        return [self._requests[key].as_json() for key in sorted(self._requests)]


def canonical_json(value: object) -> bytes:
    """Encode the one accepted ASCII JSON representation, including one LF."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise PlanError(f"cannot encode canonical JSON: {exc}") from exc
    return encoded.encode("ascii") + b"\n"


def _write_plan_output(path: Path, content: bytes) -> None:
    """Publish one plan atomically without following or replacing filesystem entries."""

    if not content or len(content) > MAX_PLAN_BYTES:
        raise PlanError("generated source plan is outside its byte bound")
    absolute = Path(os.path.abspath(path))
    if absolute.name in {"", ".", ".."}:
        raise PlanError("plan output must name a regular file")
    try:
        resolved_parent = absolute.parent.resolve(strict=True)
        parent_metadata = absolute.parent.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise PlanError("plan output parent is unavailable") from exc
    if resolved_parent != absolute.parent or not stat.S_ISDIR(parent_metadata.st_mode):
        raise PlanError("plan output parent must be one canonical directory")

    required_flags = (
        getattr(os, "O_CLOEXEC", None),
        getattr(os, "O_DIRECTORY", None),
        getattr(os, "O_NOFOLLOW", None),
    )
    if any(flag is None for flag in required_flags):
        raise PlanError("secure descriptor flags are unavailable on this platform")
    cloexec, directory, nofollow = cast(tuple[int, int, int], required_flags)
    parent = -1
    temporary = ""
    descriptor = -1
    try:
        parent = os.open(absolute.parent, os.O_RDONLY | directory | nofollow | cloexec)
        opened_parent = os.fstat(parent)
        if (
            opened_parent.st_dev != parent_metadata.st_dev
            or opened_parent.st_ino != parent_metadata.st_ino
            or not stat.S_ISDIR(opened_parent.st_mode)
        ):
            raise PlanError("plan output parent changed before it was opened")
        try:
            os.stat(absolute.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise PlanError("cannot inspect the plan output destination") from exc
        else:
            raise PlanError("plan output destination already exists")

        for _attempt in range(128):
            candidate = f".{absolute.name}.tmp-{secrets.token_hex(16)}"
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
                    0o600,
                    dir_fd=parent,
                )
            except FileExistsError:
                continue
            temporary = candidate
            break
        if descriptor < 0:
            raise PlanError("cannot allocate a temporary plan output")

        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise PlanError("cannot write the generated source plan")
            written += count
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_size != len(content)
        ):
            raise PlanError("temporary plan output has an unsafe filesystem identity")
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary,
                absolute.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise PlanError("plan output destination already exists") from exc
        except OSError as exc:
            raise PlanError("cannot publish the generated source plan atomically") from exc
        os.unlink(temporary, dir_fd=parent)
        temporary = ""
        os.fsync(parent)
    except OSError as exc:
        raise PlanError("cannot publish the generated source plan") from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if temporary and parent >= 0:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=parent)
        if parent >= 0:
            with contextlib.suppress(OSError):
                os.close(parent)


def _source_store_contract() -> ModuleType:
    path = Path(__file__).with_name("verified_source_store.py")
    spec = importlib.util.spec_from_file_location("_verified_source_store_contract", path)
    if spec is None or spec.loader is None:
        raise PlanError(f"cannot load source-store contract: {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError, SyntaxError) as exc:
        raise PlanError(f"cannot load source-store contract {path}: {exc}") from exc
    return module


def _self_validate_plan(plan: dict[str, Any], encoded: bytes) -> None:
    contract = _source_store_contract()
    if getattr(contract, "MAX_TOTAL_OBJECT_BYTES", None) != MAX_TOTAL_OBJECT_BYTES:
        raise PlanError("source planner aggregate byte limit differs from its store contract")
    try:
        parsed = contract.strict_json_bytes(
            encoded,
            "generated source plan",
            maximum=MAX_PLAN_BYTES,
        )
        validated = contract.validate_source_plan(parsed)
    except Exception as exc:
        error_type = getattr(contract, "SourceStoreError", ())
        if error_type and isinstance(exc, error_type):
            raise PlanError(f"generated direct plan violates its contract: {exc}") from exc
        raise
    if validated != plan:
        raise PlanError("generated source plan changes during contract validation")


def _utf8_length(value: str, description: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise PlanError(f"invalid {description}") from exc


def _checked_token(value: object, description: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _utf8_length(value, description) > MAX_TOKEN_BYTES
        or PLAN_TOKEN.fullmatch(value) is None
    ):
        raise PlanError(f"invalid {description}")
    return value


def _checked_digest(algorithm: str, value: object, description: str) -> str:
    patterns = {"sha256": SHA256, "sha512": SHA512}
    pattern = patterns.get(algorithm)
    if pattern is None:
        raise PlanError(f"unsupported digest algorithm: {algorithm}")
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PlanError(f"invalid {description}")
    return value


def _checked_optional_size(value: object, description: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PlanError(f"invalid {description}")
    return value


def _checked_string(value: object, description: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _utf8_length(value, description) > MAX_TOKEN_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PlanError(f"invalid {description}")
    return value


def _mapping(value: object, description: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise PlanError(f"{description} is not an object")
    return value


def _sequence(value: object, description: str, *, limit: int = MAX_REQUESTS) -> list[Any]:
    if not isinstance(value, list) or len(value) > limit:
        raise PlanError(f"{description} is not a bounded array")
    return value


def _required_string(record: Mapping[str, Any], key: str, description: str) -> str:
    return _checked_string(record.get(key), f"{description} {key}")


def _normalize_python_name(value: object, description: str) -> str:
    raw = _checked_string(value, description)
    normalized = re.sub(r"[-_.]+", "-", raw).lower()
    if PACKAGE_NAME.fullmatch(normalized) is None:
        raise PlanError(f"invalid {description}")
    return normalized


def _safe_url_origin(url: object) -> str:
    """Return nonsecret origin context for a URL validation error."""

    if not isinstance(url, str) or not url.isascii():
        return "unknown origin"
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        return "unknown origin"
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or hostname.endswith(".")
        or len(hostname) > 253
        or HOST.fullmatch(hostname.lower()) is None
    ):
        return "unknown origin"
    authority = hostname.lower()
    default_port = 80 if parsed.scheme == "http" else 443
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    return f"{parsed.scheme}://{authority}/"


def _url_error(reason: str, url: object) -> PlanError:
    """Build a URL error without copying credentials, paths, or queries."""

    return PlanError(f"source URL {reason} ({_safe_url_origin(url)})")


def _validate_url(url: object) -> tuple[str, urllib.parse.SplitResult]:
    if (
        not isinstance(url, str)
        or not url
        or not url.isascii()
        or "\\" in url
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url)
    ):
        raise _url_error("contains unsafe characters", url)
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise _url_error("is invalid", url) from None
    if parsed.scheme != "https":
        raise _url_error("is not HTTPS", url)
    if parsed.username is not None or parsed.password is not None:
        raise _url_error("contains credentials", url)
    if port not in {None, 443}:
        raise _url_error("uses a non-443 port", url)
    if parsed.fragment:
        raise _url_error("contains a fragment", url)
    host = parsed.hostname
    if (
        host is None
        or host != host.lower()
        or host.endswith(".")
        or len(host) > 253
        or HOST.fullmatch(host) is None
    ):
        raise _url_error("has an invalid host", url)
    canonical_authority = host if port is None else f"{host}:443"
    if parsed.netloc != canonical_authority or not parsed.path.startswith("/"):
        raise _url_error("has a non-canonical authority or path", url)
    return host, parsed


def _allowed_hosts(
    url: str,
    *,
    allow_alpine_distfiles: bool = False,
) -> tuple[str, ...]:
    host, parsed = _validate_url(url)
    if host == "distfiles.alpinelinux.org" and not allow_alpine_distfiles:
        raise PlanError("direct plans must not fetch Alpine distfiles")
    if allow_alpine_distfiles and host != "distfiles.alpinelinux.org":
        raise PlanError("Alpine distfile plans must use the fixed distfiles origin")
    allowed = {host}
    if host == "github.com":
        path_segments = parsed.path.split("/")
        if len(path_segments) >= 4 and path_segments[3] == "archive":
            allowed.add("codeload.github.com")
        if len(path_segments) >= 5 and path_segments[3:5] == ["releases", "download"]:
            allowed.add("release-assets.githubusercontent.com")
    return tuple(sorted(allowed))


def _file_identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _checked_regular_identity(
    metadata: os.stat_result,
    description: str,
    path: Path,
    *,
    max_bytes: int,
) -> _FileIdentity:
    identity = _file_identity(metadata)
    if not stat.S_ISREG(identity.mode):
        raise PlanError(f"{description} is not a regular file: {path}")
    if identity.links != 1:
        raise PlanError(f"{description} must have exactly one link: {path}")
    if identity.size > max_bytes:
        raise PlanError(f"{description} exceeds its size limit: {path}")
    return identity


def _read_regular_file(path: Path, description: str, *, max_bytes: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or nonblock is None or cloexec is None:
        raise PlanError("secure descriptor flags are unavailable on this platform")
    descriptor = -1
    try:
        before = _checked_regular_identity(
            path.lstat(),
            description,
            path,
            max_bytes=max_bytes,
        )
        descriptor = os.open(path, os.O_RDONLY | nofollow | nonblock | cloexec)
        opened = _checked_regular_identity(
            os.fstat(descriptor),
            description,
            path,
            max_bytes=max_bytes,
        )
        if before != opened:
            raise PlanError(f"{description} changed before it was opened: {path}")

        chunks: list[bytes] = []
        received = 0
        while received <= max_bytes:
            chunk = os.read(
                descriptor,
                min(READ_CHUNK_BYTES, max_bytes + 1 - received),
            )
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
        if received > max_bytes:
            raise PlanError(f"{description} exceeds its size limit: {path}")

        after = _checked_regular_identity(
            os.fstat(descriptor),
            description,
            path,
            max_bytes=max_bytes,
        )
        path_after = _checked_regular_identity(
            path.lstat(),
            description,
            path,
            max_bytes=max_bytes,
        )
        if opened != after or after != path_after:
            raise PlanError(f"{description} changed while it was read: {path}")
        content = b"".join(chunks)
        if len(content) != opened.size:
            raise PlanError(f"{description} changed while it was read: {path}")
    except PlanError:
        raise
    except OSError as exc:
        raise PlanError(f"cannot read {description} {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return content


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanError("JSON object repeats key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise PlanError(f"JSON contains a non-finite number: {value}")


def _validate_container_shape(value: object, description: str) -> None:
    """Reject pathologically deep or broad parsed metadata containers."""

    count = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_CONTAINER_ITEMS:
            raise PlanError(f"{description} has too many values")
        if depth > MAX_CONTAINER_DEPTH:
            raise PlanError(f"{description} exceeds its nesting limit")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise PlanError(f"{description} contains a non-string object key")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _load_policy(path: Path) -> tuple[Mapping[str, Any], bytes]:
    content = _read_regular_file(path, "container policy", max_bytes=MAX_POLICY_BYTES)
    try:
        decoded = content.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except PlanError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PlanError(f"cannot parse container policy {path}: {exc}") from exc
    _validate_container_shape(value, "container policy")
    return _mapping(value, "container policy"), content


def _load_lock(path: Path) -> tuple[Mapping[str, Any], bytes]:
    content = _read_regular_file(path, "uv lock", max_bytes=MAX_UV_LOCK_BYTES)
    try:
        value = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise PlanError(f"cannot parse uv lock {path}: {exc}") from exc
    _validate_container_shape(value, "uv lock")
    return _mapping(value, "uv lock"), content


def _sha256_artifact(
    value: object,
    description: str,
    *,
    size_required: bool,
) -> Artifact:
    record = _mapping(value, description)
    url = _required_string(record, "url", description)
    _validate_url(url)
    digest = _checked_digest("sha256", record.get("sha256"), f"{description} SHA-256")
    size = _checked_optional_size(record.get("size"), f"{description} size")
    if size_required and size is None:
        raise PlanError(f"{description} has no expected size")
    return Artifact(url=url, digest=digest, size=size)


def _lock_artifact(value: object, description: str) -> Artifact:
    record = _mapping(value, description)
    allowed_keys = ({"url", "hash", "size"}, {"url", "hash", "size", "upload-time"})
    if set(record) not in allowed_keys:
        raise PlanError(f"{description} has an invalid record")
    url = _required_string(record, "url", description)
    _validate_url(url)
    raw_hash = record.get("hash")
    if not isinstance(raw_hash, str) or not raw_hash.startswith("sha256:"):
        raise PlanError(f"{description} has no SHA-256")
    digest = _checked_digest("sha256", raw_hash.removeprefix("sha256:"), f"{description} SHA-256")
    size = _checked_optional_size(record.get("size"), f"{description} size")
    if size is None:
        raise PlanError(f"{description} has no expected size")
    upload_time = record.get("upload-time")
    if upload_time is not None:
        _checked_string(upload_time, f"{description} upload time")
    return Artifact(url=url, digest=digest, size=size)


def _collect_platform_needs(
    policy: Mapping[str, Any],
) -> tuple[
    dict[tuple[str, str], set[str]],
    dict[tuple[str, str], set[str]],
    dict[str, set[tuple[str, str]]],
]:
    raw_platforms = _mapping(policy.get("platforms"), "policy platforms")
    if set(raw_platforms) != set(PLATFORMS):
        raise PlanError("policy must contain exactly the two supported platforms")

    python: dict[tuple[str, str], set[str]] = {}
    alpine: dict[tuple[str, str], set[str]] = {}
    python_by_platform: dict[str, set[tuple[str, str]]] = {
        platform: set() for platform in PLATFORMS
    }
    for platform in PLATFORMS:
        components = _sequence(
            raw_platforms.get(platform),
            f"components for {platform}",
            limit=MAX_CONSUMERS_PER_REQUEST,
        )
        seen: set[tuple[str, str, str]] = set()
        for index, raw_component in enumerate(components):
            component = _mapping(raw_component, f"component {index} for {platform}")
            ecosystem = _required_string(component, "ecosystem", "component")
            name = _required_string(component, "name", "component")
            version = _required_string(component, "version", "component")
            normalized = (
                _normalize_python_name(name, "Python component name")
                if ecosystem == "python"
                else name
            )
            identity = (ecosystem, normalized, version)
            if identity in seen:
                raise PlanError(f"platform repeats component identity: {platform}/{identity!r}")
            seen.add(identity)
            if ecosystem == "python":
                if normalized == APPLICATION_NAME:
                    continue
                key = (normalized, version)
                python_by_platform[platform].add(key)
                python.setdefault(key, set()).add(
                    f"platform:{platform}:python:{normalized}@{version}"
                )
            elif ecosystem == "alpine":
                origin = _required_string(component, "origin", "Alpine component")
                commit = _required_string(component, "aports_commit", "Alpine component")
                if ALPINE_ORIGIN.fullmatch(origin) is None or COMMIT.fullmatch(commit) is None:
                    raise PlanError(f"Alpine component has an invalid recipe identity: {name}")
                key = (origin, commit)
                alpine.setdefault(key, set()).add(f"platform:{platform}:alpine:{name}@{version}")
    return python, alpine, python_by_platform


def _parse_owner(value: object, description: str) -> tuple[str, str]:
    owner = _checked_string(value, description)
    if not owner.startswith("python:") or "@" not in owner:
        raise PlanError(f"invalid {description}")
    raw_name, version = owner.removeprefix("python:").rsplit("@", maxsplit=1)
    name = _normalize_python_name(raw_name, f"{description} name")
    _checked_string(version, f"{description} version")
    if owner != f"python:{name}@{version}":
        raise PlanError(f"non-canonical {description}")
    return name, version


def _wheel_filename_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.]+", "_", value)


def _validate_wheel_binding(need: WheelNeed) -> None:
    """Bind a reviewed wheel filename to its owner, version, tags, and platform."""

    _host, parsed = _validate_url(need.artifact.url)
    if parsed.query or "%" in parsed.path:
        raise PlanError(
            f"native wheel URL is not a canonical filename URL: {need.platform}/{need.owner}"
        )
    filename = parsed.path.rsplit("/", maxsplit=1)[-1]
    if not filename.endswith(".whl") or not filename.isascii():
        raise PlanError(f"native wheel URL does not name a wheel: {need.platform}/{need.owner}")
    fields = filename.removesuffix(".whl").split("-")
    if len(fields) == 5:
        distribution, version, python_tag, abi_tag, platform_tag = fields
        build_tag: str | None = None
    elif len(fields) == 6:
        distribution, version, build_tag, python_tag, abi_tag, platform_tag = fields
    else:
        raise PlanError(
            f"native wheel filename has an invalid field count: {need.platform}/{need.owner}"
        )

    expected_distribution = re.sub(r"[-_.]+", "_", need.package[0])
    expected_version = _wheel_filename_component(need.package[1])
    if (
        WHEEL_PART.fullmatch(distribution) is None
        or distribution != expected_distribution
        or WHEEL_PART.fullmatch(version) is None
        or version != expected_version
    ):
        raise PlanError(
            f"native wheel filename differs from its owner: {need.platform}/{need.owner}"
        )
    if build_tag is not None and WHEEL_BUILD.fullmatch(build_tag) is None:
        raise PlanError(
            f"native wheel filename has an invalid build tag: {need.platform}/{need.owner}"
        )
    if WHEEL_PYTHON_TAG.fullmatch(python_tag) is None or (
        abi_tag != "abi3" and abi_tag != python_tag
    ):
        raise PlanError(
            f"native wheel filename has invalid compatibility tags: {need.platform}/{need.owner}"
        )
    platform_pattern = WHEEL_PLATFORM.get(need.platform)
    if platform_pattern is None or platform_pattern.fullmatch(platform_tag) is None:
        raise PlanError(
            f"native wheel filename targets the wrong platform: {need.platform}/{need.owner}"
        )


def _collect_native_coverage(
    policy: Mapping[str, Any],
    *,
    python_needs_by_platform: Mapping[str, set[tuple[str, str]]],
    native_source_ids: set[str],
) -> tuple[
    list[WheelNeed],
    dict[tuple[str, str], Artifact],
    dict[tuple[str, str], set[str]],
    dict[str, set[str]],
]:
    raw_coverage = _mapping(policy.get("native_component_coverage"), "native coverage")
    if set(raw_coverage) != set(PLATFORMS):
        raise PlanError("native coverage must contain exactly the two supported platforms")

    wheel_needs: list[WheelNeed] = []
    owner_sources: dict[tuple[str, str], Artifact] = {}
    owner_consumers: dict[tuple[str, str], set[str]] = {}
    source_consumers: dict[str, set[str]] = {}
    for platform in PLATFORMS:
        owners = _sequence(
            raw_coverage.get(platform), f"native coverage for {platform}", limit=MAX_REQUESTS
        )
        seen_owners: set[str] = set()
        for index, raw_owner in enumerate(owners):
            owner_record = _mapping(raw_owner, f"native owner {index} for {platform}")
            owner = _required_string(owner_record, "owner", "native owner")
            if owner in seen_owners:
                raise PlanError(f"native coverage repeats owner: {platform}/{owner}")
            seen_owners.add(owner)
            package = _parse_owner(owner, "native owner")
            if package not in python_needs_by_platform[platform]:
                raise PlanError(
                    f"native owner is absent from platform components: {platform}/{owner}"
                )
            consumer = f"platform:{platform}:native-owner:{owner}"

            owner_source = _sha256_artifact(
                owner_record.get("owner_source"),
                f"owner source for {platform}/{owner}",
                size_required=True,
            )
            previous_source = owner_sources.get(package)
            if previous_source is not None and previous_source != owner_source:
                raise PlanError(f"native owner has conflicting source bindings: {owner}")
            owner_sources[package] = owner_source
            owner_consumers.setdefault(package, set()).add(consumer)

            wheel = _sha256_artifact(
                owner_record.get("wheel"),
                f"wheel for {platform}/{owner}",
                size_required=True,
            )
            wheel_needs.append(
                WheelNeed(
                    platform=platform,
                    owner=owner,
                    package=package,
                    artifact=wheel,
                    consumer=consumer,
                )
            )

            reviews = _sequence(
                owner_record.get("component_reviews"),
                f"component reviews for {platform}/{owner}",
                limit=MAX_REQUESTS,
            )
            seen_reviews: set[tuple[str, tuple[str, ...]]] = set()
            for review_index, raw_review in enumerate(reviews):
                review = _mapping(
                    raw_review,
                    f"component review {review_index} for {platform}/{owner}",
                )
                source_id = _required_string(review, "source", "component review")
                if source_id not in native_source_ids:
                    raise PlanError(f"native review names an unknown source: {source_id}")
                observations = _sequence(
                    review.get("observations"),
                    f"observations for {platform}/{owner}/{source_id}",
                    limit=MAX_CONSUMERS_PER_REQUEST,
                )
                observation_ids = tuple(
                    _checked_string(
                        observation,
                        f"observation for {platform}/{owner}/{source_id}",
                    )
                    if isinstance(observation, str)
                    else canonical_json(observation).decode("ascii")
                    for observation in observations
                )
                review_identity = (source_id, observation_ids)
                if review_identity in seen_reviews:
                    raise PlanError(
                        f"native coverage repeats a component review: {platform}/{owner}"
                    )
                seen_reviews.add(review_identity)
                source_consumers.setdefault(source_id, set()).add(consumer)

    if set(source_consumers) != native_source_ids:
        missing = sorted(native_source_ids - set(source_consumers))
        stale = sorted(set(source_consumers) - native_source_ids)
        raise PlanError(
            "native source consumers do not exactly cover policy sources; "
            f"missing={missing!r}, stale={stale!r}"
        )
    return wheel_needs, owner_sources, owner_consumers, source_consumers


def _load_selected_lock_packages(
    lock: Mapping[str, Any],
    *,
    relevant: set[tuple[str, str]],
    wheel_packages: set[tuple[str, str]],
) -> dict[tuple[str, str], LockPackage]:
    lock_version = lock.get("version")
    if isinstance(lock_version, bool) or lock_version != 1:
        raise PlanError("uv lock has an unsupported schema version")
    packages = _sequence(lock.get("package"), "uv lock packages", limit=MAX_REQUESTS)
    selected: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for index, raw_package in enumerate(packages):
        package = _mapping(raw_package, f"uv lock package {index}")
        name_value = package.get("name")
        version_value = package.get("version")
        if not isinstance(name_value, str) or not isinstance(version_value, str):
            raise PlanError(f"uv lock package {index} has an invalid identity")
        name = _normalize_python_name(name_value, "uv lock package name")
        version = _checked_string(version_value, "uv lock package version")
        key = (name, version)
        if key in relevant:
            selected.setdefault(key, []).append(package)

    result: dict[tuple[str, str], LockPackage] = {}
    for key in sorted(relevant):
        matches = selected.get(key, [])
        if len(matches) > 1:
            raise PlanError(f"uv lock repeats selected package: {key[0]} {key[1]}")
        if not matches:
            result[key] = LockPackage(sdist=None, wheels=())
            continue
        package = matches[0]
        raw_sdist = package.get("sdist")
        sdist = (
            None
            if raw_sdist is None
            else _lock_artifact(raw_sdist, f"locked sdist for {key[0]} {key[1]}")
        )
        wheels: tuple[Artifact, ...] = ()
        if key in wheel_packages:
            raw_wheels = _sequence(
                package.get("wheels"),
                f"locked wheels for {key[0]} {key[1]}",
                limit=MAX_REQUESTS,
            )
            if not raw_wheels:
                raise PlanError(f"selected native package has no wheels: {key[0]} {key[1]}")
            wheels = tuple(
                _lock_artifact(
                    raw_wheel,
                    f"locked wheel {index} for {key[0]} {key[1]}",
                )
                for index, raw_wheel in enumerate(raw_wheels)
            )
        result[key] = LockPackage(sdist=sdist, wheels=wheels)
    return result


def _fallback_sources(policy: Mapping[str, Any]) -> dict[tuple[str, str], Artifact]:
    raw_sources = _sequence(policy.get("python_sources"), "Python source fallbacks")
    result: dict[tuple[str, str], Artifact] = {}
    for index, raw_source in enumerate(raw_sources):
        source = _mapping(raw_source, f"Python source fallback {index}")
        name = _normalize_python_name(source.get("name"), "Python source fallback name")
        version = _required_string(source, "version", "Python source fallback")
        key = (name, version)
        if key in result:
            raise PlanError(f"policy repeats Python source fallback: {name} {version}")
        result[key] = _sha256_artifact(
            source, f"Python source fallback for {name} {version}", size_required=True
        )
    return result


def _add_base_requests(
    builder: _PlanBuilder,
    policy: Mapping[str, Any],
) -> None:
    base_consumers = {f"platform:{platform}:base" for platform in PLATFORMS}
    recipe = _mapping(policy.get("docker_python_recipe"), "Docker Python recipe")
    recipe_artifact = _sha256_artifact(recipe, "Docker Python recipe", size_required=False)
    builder.add(
        "docker-python:recipe",
        recipe_artifact,
        max_bytes=MAX_DOWNLOAD_BYTES,
        consumers=base_consumers,
    )
    license_artifact = Artifact(
        url=_required_string(recipe, "license_url", "Docker Python recipe"),
        digest=_checked_digest(
            "sha256", recipe.get("license_sha256"), "Docker Python recipe license SHA-256"
        ),
        size=_checked_optional_size(
            recipe.get("license_size"), "Docker Python recipe license size"
        ),
    )
    builder.add(
        "docker-python:license",
        license_artifact,
        max_bytes=MAX_LICENSE_BYTES,
        consumers=base_consumers,
    )

    cpython = _sha256_artifact(policy.get("cpython_source"), "CPython source", size_required=True)
    builder.add(
        "cpython:source",
        cpython,
        max_bytes=MAX_DOWNLOAD_BYTES,
        consumers=base_consumers,
    )


def _add_python_sources(
    builder: _PlanBuilder,
    policy: Mapping[str, Any],
    *,
    python_needs: Mapping[tuple[str, str], set[str]],
    owner_sources: Mapping[tuple[str, str], Artifact],
    owner_consumers: Mapping[tuple[str, str], set[str]],
    lock_packages: Mapping[tuple[str, str], LockPackage],
) -> dict[tuple[str, str], Artifact]:
    fallbacks = _fallback_sources(policy)
    expected_fallbacks = {
        key for key in python_needs if lock_packages.get(key, LockPackage(None, ())).sdist is None
    }
    if set(fallbacks) != expected_fallbacks:
        missing = sorted(expected_fallbacks - set(fallbacks))
        stale = sorted(set(fallbacks) - expected_fallbacks)
        raise PlanError(
            "Python source fallbacks do not exactly cover lock omissions; "
            f"missing={missing!r}, stale={stale!r}"
        )

    selected: dict[tuple[str, str], Artifact] = {}
    for key in sorted(python_needs):
        locked = lock_packages.get(key)
        artifact = locked.sdist if locked is not None else None
        if artifact is None:
            artifact = fallbacks.get(key)
        if artifact is None:
            raise PlanError(f"Python component has no source archive: {key[0]} {key[1]}")
        reviewed_owner_source = owner_sources.get(key)
        if reviewed_owner_source is not None and reviewed_owner_source != artifact:
            raise PlanError(
                f"native owner source differs from selected Python source: {key[0]} {key[1]}"
            )
        consumers = set(python_needs[key])
        consumers.update(owner_consumers.get(key, set()))
        builder.add(
            f"python-sdist:{key[0]}@{key[1]}",
            artifact,
            max_bytes=MAX_DOWNLOAD_BYTES,
            consumers=consumers,
        )
        selected[key] = artifact
    return selected


def _add_native_wheels(
    builder: _PlanBuilder,
    wheel_needs: Sequence[WheelNeed],
    lock_packages: Mapping[tuple[str, str], LockPackage],
) -> None:
    for need in sorted(wheel_needs, key=lambda item: (item.platform, item.owner)):
        _validate_wheel_binding(need)
        locked = lock_packages.get(need.package)
        if locked is None:
            raise PlanError(f"native wheel owner is absent from uv lock: {need.owner}")
        matches = [wheel for wheel in locked.wheels if wheel == need.artifact]
        if len(matches) != 1:
            raise PlanError(
                f"reviewed native wheel does not select one exact lock entry: "
                f"{need.platform}/{need.owner}"
            )
        builder.add(
            f"python-wheel:{need.platform}:{need.package[0]}@{need.package[1]}",
            need.artifact,
            max_bytes=MAX_DOWNLOAD_BYTES,
            consumers={need.consumer},
        )


def _add_alpine_recipes(
    builder: _PlanBuilder,
    policy: Mapping[str, Any],
    *,
    alpine_needs: Mapping[tuple[str, str], set[str]],
) -> None:
    archives = _mapping(policy.get("alpine_recipe_archives"), "Alpine recipe archives")
    expected_keys = {f"{origin}@{commit}" for origin, commit in alpine_needs}
    if set(archives) != expected_keys:
        missing = sorted(expected_keys - set(archives))
        stale = sorted(set(archives) - expected_keys)
        raise PlanError(
            "Alpine recipe policy does not exactly cover platform components; "
            f"missing={missing!r}, stale={stale!r}"
        )
    for origin, commit in sorted(alpine_needs):
        digest = _checked_digest(
            "sha256",
            archives[f"{origin}@{commit}"],
            f"Alpine recipe SHA-256 for {origin}@{commit}",
        )
        url = (
            "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
            f"{commit}/aports-{commit}.tar.gz?path=main/{origin}"
        )
        builder.add(
            f"alpine-recipe:{origin}@{commit}",
            Artifact(url=url, digest=digest, size=None),
            max_bytes=MAX_DOWNLOAD_BYTES,
            consumers=alpine_needs[(origin, commit)],
        )


def _add_license_texts(builder: _PlanBuilder, policy: Mapping[str, Any]) -> None:
    entries = _sequence(policy.get("license_texts"), "standard license texts")
    seen: set[str] = set()
    for index, raw_entry in enumerate(entries):
        entry = _mapping(raw_entry, f"standard license text {index}")
        identifier = _required_string(entry, "id", "standard license text")
        if LICENSE_ID.fullmatch(identifier) is None:
            raise PlanError(f"invalid standard license identifier: {identifier}")
        if identifier in seen:
            raise PlanError(f"policy repeats standard license text: {identifier}")
        seen.add(identifier)
        artifact = _sha256_artifact(
            entry, f"standard license text {identifier}", size_required=False
        )
        builder.add(
            f"license-text:{identifier}",
            artifact,
            max_bytes=MAX_LICENSE_BYTES,
            consumers={f"policy:license:{identifier}"},
        )


def _add_native_sources(
    builder: _PlanBuilder,
    policy: Mapping[str, Any],
    *,
    selected_python_sources: Mapping[tuple[str, str], Artifact],
    source_consumers: Mapping[str, set[str]],
) -> None:
    sources = _mapping(policy.get("native_component_sources"), "native component sources")
    for source_id in sorted(sources):
        source = _mapping(sources[source_id], f"native source {source_id}")
        kind = _required_string(source, "kind", f"native source {source_id}")
        consumers = source_consumers.get(source_id)
        if not consumers:
            raise PlanError(f"native source has no reviewed consumer: {source_id}")
        request_prefix = f"native-source:{source_id}"
        if kind == "alpine-aports":
            recipe = _sha256_artifact(
                source.get("recipe"),
                f"native Alpine recipe {source_id}",
                size_required=True,
            )
            builder.add(
                f"{request_prefix}:recipe",
                recipe,
                max_bytes=MAX_DOWNLOAD_BYTES,
                consumers=consumers,
            )
            # Distfiles are deliberately deferred. The offline recipe parser
            # derives that plan and cross-checks the policy-listed records.
        elif kind == "crates-io":
            crate = _sha256_artifact(
                source.get("crate"), f"native crate {source_id}", size_required=True
            )
            builder.add(
                f"{request_prefix}:crate",
                crate,
                max_bytes=MAX_NATIVE_SOURCE_BYTES,
                consumers=consumers,
            )
        elif kind == "owner-sdist-subpath":
            owner = _parse_owner(source.get("owner"), f"owner for native source {source_id}")
            canonical_owner = f"python:{owner[0]}@{owner[1]}"
            if any(
                not consumer.endswith(f":native-owner:{canonical_owner}") for consumer in consumers
            ):
                raise PlanError(
                    f"owner-sdist source owner differs from reviewed consumers: {source_id}"
                )
            artifact = selected_python_sources.get(owner)
            if artifact is None:
                raise PlanError(
                    f"owner-sdist native source has no Python-sdist request: {source_id}"
                )
            builder.add(
                f"python-sdist:{owner[0]}@{owner[1]}",
                artifact,
                max_bytes=MAX_DOWNLOAD_BYTES,
                consumers=consumers,
            )
        elif kind == "checksummed-upstream-release":
            checksum = _sha256_artifact(
                source.get("checksum_document"),
                f"native checksum document {source_id}",
                size_required=True,
            )
            archive = _sha256_artifact(
                source.get("archive"),
                f"native upstream archive {source_id}",
                size_required=True,
            )
            builder.add(
                f"{request_prefix}:checksum-document",
                checksum,
                max_bytes=MAX_DOWNLOAD_BYTES,
                consumers=consumers,
            )
            builder.add(
                f"{request_prefix}:archive",
                archive,
                max_bytes=MAX_NATIVE_SOURCE_BYTES,
                consumers=consumers,
            )
        else:
            raise PlanError(f"unsupported native source kind: {kind}")


def _checked_archive_path(value: str, description: str) -> PurePosixPath:
    """Reject traversal, aliases, controls, and oversized archive member names."""

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PlanError(f"unsafe {description}: {value!r}") from exc
    comparable = value[:-1] if value.endswith("/") else value
    path = PurePosixPath(comparable)
    if (
        not comparable
        or len(encoded) > MAX_ARCHIVE_PATH_BYTES
        or "\\" in value
        or any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in value)
        or comparable in {".", ".."}
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != comparable
    ):
        raise PlanError(f"unsafe {description}: {value!r}")
    return path


def _checked_distfile_filename(value: object, description: str) -> str:
    filename = _checked_string(value, description)
    try:
        encoded = filename.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PlanError(f"invalid {description}") from exc
    path = PurePosixPath(filename)
    if (
        not 1 <= len(encoded) <= MAX_DISTFILE_FILENAME_BYTES
        or filename in {".", ".."}
        or path.name != filename
        or "/" in filename
        or "\\" in filename
        or any(character in filename for character in ("?", "#"))
    ):
        raise PlanError(f"invalid {description}")
    return filename


def _read_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    description: str,
    *,
    maximum: int,
) -> bytes:
    if not member.isfile() or member.size < 0 or member.size > maximum:
        raise PlanError(f"{description} exceeds its size limit")
    stream = archive.extractfile(member)
    if stream is None:
        raise PlanError(f"cannot read {description}")
    content = stream.read(maximum + 1)
    if len(content) != member.size or len(content) > maximum:
        raise PlanError(f"{description} is truncated or exceeds its size limit")
    return content


def _hash_tar_member_sha512(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    description: str,
) -> str:
    if not member.isfile() or member.size < 0 or member.size > MAX_RECIPE_MEMBER_BYTES:
        raise PlanError(f"{description} exceeds its size limit")
    stream = archive.extractfile(member)
    if stream is None:
        raise PlanError(f"cannot read {description}")
    digest = hashlib.sha512()
    remaining = member.size
    while remaining:
        chunk = stream.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise PlanError(f"{description} is truncated")
        digest.update(chunk)
        remaining -= len(chunk)
    if stream.read(1):
        raise PlanError(f"{description} exceeds its declared size")
    return digest.hexdigest()


def _validate_allowed_recipe_links(
    value: object,
    description: str,
) -> tuple[Mapping[str, str], ...]:
    entries = _sequence(value, description, limit=MAX_REQUESTS)
    result: list[Mapping[str, str]] = []
    seen: set[str] = set()
    for index, raw_entry in enumerate(entries):
        entry = _mapping(raw_entry, f"{description} entry {index}")
        if set(entry) != {"path", "target", "type"}:
            raise PlanError(f"{description} entry has invalid fields")
        path_value = _required_string(entry, "path", description)
        target_value = _required_string(entry, "target", description)
        link_type = _required_string(entry, "type", description)
        path = str(_checked_archive_path(path_value, f"{description} path"))
        target = str(_checked_archive_path(target_value, f"{description} target"))
        if path != path_value or target != target_value or link_type not in {"symlink", "hardlink"}:
            raise PlanError(f"{description} entry is noncanonical")
        if path in seen:
            raise PlanError(f"{description} repeats a path: {path}")
        seen.add(path)
        result.append({"path": path, "target": target, "type": link_type})
    return tuple(result)


def _alpine_recipe_exception(
    policy: Mapping[str, Any],
    recipe_key: str,
) -> tuple[bool, tuple[Mapping[str, str], ...]]:
    raw_exceptions = _mapping(
        policy.get("alpine_recipe_exceptions"),
        "Alpine recipe exceptions",
    )
    raw_exception = raw_exceptions.get(recipe_key)
    if raw_exception is None:
        return False, ()
    exception = _mapping(raw_exception, f"Alpine recipe exception for {recipe_key}")
    if not exception or set(exception) - {
        "allow_dynamic_sources",
        "allowed_links",
        "rationale",
    }:
        raise PlanError(f"invalid Alpine recipe exception for {recipe_key}")
    rationale = _required_string(
        exception,
        "rationale",
        f"Alpine recipe exception for {recipe_key}",
    )
    if not rationale.strip():
        raise PlanError(f"Alpine recipe exception has no rationale for {recipe_key}")
    dynamic = exception.get("allow_dynamic_sources", False)
    if not isinstance(dynamic, bool):
        raise PlanError(f"invalid dynamic-source exception for {recipe_key}")
    links = _validate_allowed_recipe_links(
        exception.get("allowed_links", []),
        f"allowed recipe links for {recipe_key}",
    )
    return dynamic, links


def _source_filename_pattern(source: str, origin: str) -> re.Pattern[str]:
    if (
        not source
        or "\\" in source
        or any(character in source for character in ('"', "'", "`", ";", "&", "|", "<", ">"))
        or "$(" in source
    ):
        raise PlanError(f"unsupported APKBUILD source token for {origin}: {source!r}")
    fragments: list[str] = []
    position = 0
    for match in SHELL_VARIABLE.finditer(source):
        fragments.append(re.escape(source[position : match.start()]))
        fragments.append(r"[^/]+")
        position = match.end()
    fragments.append(re.escape(source[position:]))
    if "$" in SHELL_VARIABLE.sub("", source):
        raise PlanError(f"unsupported APKBUILD variable form for {origin}: {source!r}")
    return re.compile("".join(fragments))


def _static_source_assignments(text: str) -> dict[str, tuple[str | None, ...]]:
    """Collect narrowly supported scalar assignments used by source aliases."""

    lines = text.splitlines()
    source_lines = [
        index
        for index, line in enumerate(lines)
        if re.match(r"^source(?:[+?])?=", line) is not None
    ]
    adjacent: set[int] = set()
    metadata: set[int] = set()
    if len(source_lines) == 1:
        for index, line in enumerate(lines[: source_lines[0]]):
            if not line or line.startswith("#"):
                continue
            if STATIC_ASSIGNMENT.fullmatch(line) is None:
                break
            metadata.add(index)

        index = source_lines[0] - 1
        while index >= 0:
            line = lines[index]
            if not line or line.startswith("#"):
                index -= 1
                continue
            if STATIC_ASSIGNMENT.fullmatch(line) is None:
                break
            adjacent.add(index)
            index -= 1

    collected: dict[str, list[str | None]] = {}
    for index, line in enumerate(lines):
        match = STATIC_ASSIGNMENT.fullmatch(line)
        if match is None:
            continue
        name, raw_value = match.groups()
        value = (
            raw_value
            if (
                index in adjacent
                or (name in STATIC_SOURCE_METADATA_VARIABLES and index in metadata)
            )
            and STATIC_ASSIGNMENT_VALUE.fullmatch(raw_value) is not None
            else None
        )
        collected.setdefault(name, []).append(value)
    return {name: tuple(values) for name, values in collected.items()}


def _variable_name(reference: str) -> str:
    return reference[2:-1] if reference.startswith("${") else reference[1:]


def _substitute_known_variables(value: str, replacements: Mapping[str, str]) -> str:
    fragments: list[str] = []
    position = 0
    for match in SHELL_VARIABLE.finditer(value):
        fragments.append(value[position : match.start()])
        reference = match.group(0)
        fragments.append(replacements.get(_variable_name(reference), reference))
        position = match.end()
    fragments.append(value[position:])
    return "".join(fragments)


def _resolve_source_alias(
    alias: str,
    origin: str,
    assignments: Mapping[str, tuple[str | None, ...]],
) -> tuple[str, dict[str, str]]:
    """Resolve only exact scalar variables required by one source alias."""

    if "$" in SHELL_VARIABLE.sub("", alias):
        raise PlanError(f"unsupported APKBUILD variable form in source alias for {origin}")
    names = {_variable_name(match.group(0)) for match in SHELL_VARIABLE.finditer(alias)}
    replacements: dict[str, str] = {}
    for name in sorted(names):
        if not name.startswith("_") and name not in STATIC_SOURCE_METADATA_VARIABLES:
            raise PlanError(f"unsupported static APKBUILD variable {name} for {origin}")
        values = assignments.get(name)
        if values is None:
            raise PlanError(f"unresolved static APKBUILD variable {name} for {origin}")
        if len(values) != 1:
            raise PlanError(f"ambiguous static APKBUILD variable {name} for {origin}")
        value = values[0]
        if value is None:
            raise PlanError(f"nonliteral static APKBUILD variable {name} for {origin}")
        replacements[name] = value
    return _substitute_known_variables(alias, replacements), replacements


def _parse_literal_source_token(
    token: str,
    filename: str,
    origin: str,
    regular_hashes: Mapping[str, str],
    static_assignments: Mapping[str, tuple[str | None, ...]],
) -> bool:
    """Return true for a verified local source and false for an upstream source."""

    parts = token.split("::")
    if len(parts) > 2:
        raise PlanError(f"unsupported APKBUILD source alias for {origin}: {token!r}")
    location = parts[-1]
    alias = parts[0] if len(parts) == 2 else None
    if alias is not None:
        alias, replacements = _resolve_source_alias(
            alias,
            origin,
            static_assignments,
        )
        location = _substitute_known_variables(location, replacements)
        checked_alias = _checked_distfile_filename(alias, f"APKBUILD source alias for {origin}")
        if checked_alias != filename:
            raise PlanError(
                f"APKBUILD checksum filename {filename!r} does not match "
                f"source {token!r} for {origin}"
            )

    if "://" in location:
        _validate_url(location)
        parsed = urllib.parse.urlsplit(location)
        selected = alias if alias is not None else parsed.path.rsplit("/", maxsplit=1)[-1]
        if not selected or _source_filename_pattern(selected, origin).fullmatch(filename) is None:
            raise PlanError(
                f"APKBUILD checksum filename {filename!r} does not match "
                f"source {token!r} for {origin}"
            )
        return False

    if alias is not None or SHELL_VARIABLE.search(location):
        raise PlanError(f"unsupported local APKBUILD source for {origin}: {token!r}")
    local = _checked_distfile_filename(location, f"local APKBUILD source for {origin}")
    if local != filename or local not in regular_hashes:
        raise PlanError(f"local APKBUILD source is not retained exactly: {origin}/{filename}")
    return True


def _literal_assignment(
    text: str,
    field: str,
    origin: str,
) -> tuple[str | None, int]:
    assignment = re.compile(
        rf'^{re.escape(field)}="(.*?)"[ \t]*$',
        re.MULTILINE | re.DOTALL,
    )
    matches = list(assignment.finditer(text))
    marker = re.compile(
        rf"^[ \t]*(?:export[ \t]+)?{re.escape(field)}(?:[+?])?=",
        re.MULTILINE,
    )
    marker_count = len(marker.findall(text))
    if len(matches) > 1:
        raise PlanError(f"APKBUILD repeats literal {field} blocks for {origin}")
    return (matches[0].group(1) if matches else None), marker_count


def _looks_like_uncompressed_tar(archive_bytes: bytes) -> bool:
    """Recognize one uncompressed tar header without format auto-detection."""

    block_size = 512
    if len(archive_bytes) < block_size:
        return False
    block = archive_bytes[:block_size]
    if block == bytes(block_size):
        return True
    raw_checksum = block[148:156].strip(b"\x00 ")
    if not raw_checksum or any(byte < ord("0") or byte > ord("7") for byte in raw_checksum):
        return False
    expected = int(raw_checksum, 8)
    unsigned = sum(block[:148]) + (8 * ord(" ")) + sum(block[156:])
    signed = (
        sum(byte if byte < 128 else byte - 256 for byte in block[:148])
        + (8 * ord(" "))
        + sum(byte if byte < 128 else byte - 256 for byte in block[156:])
    )
    return expected in {unsigned, signed}


def _recipe_archive_mode(
    archive_bytes: bytes,
    origin: str,
) -> Literal["r:", "r:gz", "r:bz2", "r:xz"]:
    """Select only the compression formats supported on every Python target."""

    prefix = archive_bytes[:6]
    if prefix.startswith(b"\x28\xb5\x2f\xfd") or (
        len(prefix) >= 4 and 0x50 <= prefix[0] <= 0x5F and prefix[1:4] == b"\x2a\x4d\x18"
    ):
        raise PlanError(f"recipe archive uses unsupported zstd compression: {origin}")
    if prefix.startswith(b"\x1f\x8b\x08"):
        return "r:gz"
    if prefix.startswith(b"BZh"):
        return "r:bz2"
    if prefix.startswith(b"\xfd7zXZ\x00"):
        return "r:xz"
    if _looks_like_uncompressed_tar(archive_bytes):
        return "r:"
    raise PlanError(f"recipe archive has unknown compression: {origin}")


def _parse_recipe_distfiles(
    archive_bytes: bytes,
    need: RecipeNeed,
) -> tuple[ParsedDistfile, ...]:
    """Parse one bounded recipe archive without evaluating APKBUILD shell."""

    expected_links = {
        (entry["path"], entry["target"], entry["type"]) for entry in need.allowed_links
    }
    observed_links: set[tuple[str, str, str]] = set()
    regular_paths: set[str] = set()
    regular_hashes: dict[str, str] = {}
    basename_spellings: dict[str, str] = {}
    seen_paths: set[str] = set()
    seen_casefold_paths: dict[str, str] = {}
    apkbuild: bytes | None = None
    total_bytes = 0
    member_count = 0

    archive_mode = _recipe_archive_mode(archive_bytes, need.origin)
    try:
        with tarfile.open(
            fileobj=io.BytesIO(archive_bytes),
            mode=archive_mode,
            tarinfo=_BoundedTarInfo,
        ) as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_RECIPE_ARCHIVE_MEMBERS:
                    raise PlanError(f"recipe archive has too many entries: {need.origin}")
                path = _checked_archive_path(member.name, "recipe archive path")
                path_string = str(path)
                if path_string in seen_paths:
                    raise PlanError(
                        f"recipe archive repeats an entry path: {need.origin}/{path_string}"
                    )
                folded_path = path_string.casefold()
                previous_path = seen_casefold_paths.get(folded_path)
                if previous_path is not None and previous_path != path_string:
                    raise PlanError(
                        f"recipe archive has case-colliding paths: {previous_path} / {path_string}"
                    )
                seen_paths.add(path_string)
                seen_casefold_paths[folded_path] = path_string

                if member.issym() or member.islnk():
                    if member.size != 0:
                        raise PlanError(f"recipe archive link has a payload: {need.origin}")
                    raw_target = member.linkname
                    _checked_archive_path(raw_target, "recipe archive link target")
                    if member.issym():
                        target = _checked_archive_path(
                            str(path.parent / raw_target),
                            "resolved recipe archive symlink target",
                        )
                    else:
                        target = _checked_archive_path(
                            raw_target,
                            "resolved recipe archive hardlink target",
                        )
                    observed_links.add(
                        (
                            path_string,
                            str(target),
                            "symlink" if member.issym() else "hardlink",
                        )
                    )
                    continue
                if member.isdir():
                    if member.size != 0:
                        raise PlanError(f"recipe archive directory has a payload: {need.origin}")
                    continue
                if not member.isfile():
                    raise PlanError(f"recipe archive has an unsupported entry: {need.origin}")

                total_bytes += member.size
                if (
                    member.size < 0
                    or member.size > MAX_RECIPE_MEMBER_BYTES
                    or total_bytes > MAX_RECIPE_EXPANDED_BYTES
                ):
                    raise PlanError(
                        f"recipe archive exceeds its expanded size limit: {need.origin}"
                    )
                regular_paths.add(path_string)
                basename = path.name
                folded_basename = basename.casefold()
                previous_basename = basename_spellings.get(folded_basename)
                if previous_basename is not None:
                    raise PlanError(
                        f"recipe archive repeats a regular-file basename: "
                        f"{previous_basename} / {basename}"
                    )
                basename_spellings[folded_basename] = basename
                expected_suffix = ("main", need.origin, "APKBUILD")
                if path.parts[-3:] == expected_suffix:
                    if apkbuild is not None or basename != "APKBUILD":
                        raise PlanError(f"recipe archive has an ambiguous APKBUILD: {need.origin}")
                    apkbuild = _read_tar_member(
                        archive,
                        member,
                        f"APKBUILD for {need.origin}",
                        maximum=MAX_APKBUILD_BYTES,
                    )
                    regular_hashes[basename] = hashlib.sha512(apkbuild).hexdigest()
                else:
                    regular_hashes[basename] = _hash_tar_member_sha512(
                        archive,
                        member,
                        f"recipe member {path_string}",
                    )
    except PlanError:
        raise
    except (EOFError, OSError, lzma.LZMAError, tarfile.TarError, zlib.error):
        raise PlanError(f"invalid recipe archive for {need.origin}") from None

    if apkbuild is None:
        raise PlanError(f"recipe archive has no exact APKBUILD path: {need.origin}")
    if observed_links != expected_links:
        unexpected = sorted(observed_links - expected_links)
        missing = sorted(expected_links - observed_links)
        raise PlanError(
            f"recipe archive links differ from reviewed policy for {need.origin}; "
            f"unexpected={unexpected!r}, missing={missing!r}"
        )
    unresolved = sorted(
        (path, target) for path, target, _link_type in observed_links if target not in regular_paths
    )
    if unresolved:
        raise PlanError(
            f"recipe archive links do not resolve directly to regular files for "
            f"{need.origin}: {unresolved!r}"
        )

    try:
        text = apkbuild.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PlanError(f"APKBUILD is not UTF-8: {need.origin}") from exc
    static_assignments = _static_source_assignments(text)
    source_block, source_markers = _literal_assignment(text, "source", need.origin)
    checksum_block, checksum_markers = _literal_assignment(text, "sha512sums", need.origin)
    if source_markers == 0 and checksum_markers == 0:
        return ()
    if checksum_block is None or checksum_markers != 1:
        raise PlanError(f"APKBUILD must have one literal sha512sums block: {need.origin}")
    if not checksum_block.startswith("\n") or not checksum_block.endswith("\n"):
        raise PlanError(
            f"APKBUILD sha512sums block must use canonical multiline form: {need.origin}"
        )
    checksum_block = checksum_block[1:-1]
    if not need.allow_dynamic_sources and (source_block is None or source_markers != 1):
        raise PlanError(f"APKBUILD must have one literal source block: {need.origin}")
    if need.allow_dynamic_sources:
        # The exception authorizes a constructed source list; the checksum block
        # remains the complete authority, and retained regular bytes distinguish
        # local files from upstream distfiles.
        source_block = None

    checksums: dict[str, str] = {}
    checksum_spellings: dict[str, str] = {}
    for line in checksum_block.splitlines():
        parsed = SHA512_LINE.fullmatch(line.strip())
        if parsed is None:
            raise PlanError(f"unsupported APKBUILD checksum line for {need.origin}: {line!r}")
        digest, raw_filename = parsed.groups()
        filename = _checked_distfile_filename(
            raw_filename,
            f"APKBUILD checksum filename for {need.origin}",
        )
        folded = filename.casefold()
        previous = checksum_spellings.get(folded)
        if previous is not None:
            raise PlanError(
                f"APKBUILD repeats or case-collides source filenames: {previous} / {filename}"
            )
        checksum_spellings[folded] = filename
        checksums[filename] = digest
    if not checksums:
        raise PlanError(f"APKBUILD source list has no checksummed files: {need.origin}")

    local_sources: set[str] = set()
    if source_block is not None:
        source_tokens = source_block.split()
        if len(source_tokens) != len(checksums):
            raise PlanError(
                f"APKBUILD source and checksum counts differ for {need.origin}: "
                f"{len(source_tokens)} source(s), {len(checksums)} checksum(s)"
            )
        for token, filename in zip(source_tokens, checksums, strict=True):
            if _parse_literal_source_token(
                token,
                filename,
                need.origin,
                regular_hashes,
                static_assignments,
            ):
                local_sources.add(filename)
    else:
        local_sources = set(checksums) & set(regular_hashes)

    link_basenames = {PurePosixPath(path).name for path, _target, _type in observed_links}
    conflicts = sorted(link_basenames & ({"APKBUILD"} | set(checksums)))
    if conflicts:
        raise PlanError(
            f"reviewed recipe links conflict with authoritative source files for "
            f"{need.origin}: {', '.join(conflicts)}"
        )
    for filename in sorted(local_sources):
        actual = regular_hashes[filename]
        expected = checksums[filename]
        if actual != expected:
            raise PlanError(
                f"local recipe source checksum mismatch for {need.origin}/{filename}: "
                f"expected {expected}, got {actual}"
            )
    return tuple(
        ParsedDistfile(filename=filename, digest=digest)
        for filename, digest in checksums.items()
        if filename not in local_sources
    )


def _reviewed_native_distfiles(
    source: Mapping[str, Any],
    source_id: str,
    release: str,
) -> tuple[ReviewedDistfile, ...]:
    entries = _sequence(
        source.get("distfiles"),
        f"reviewed distfiles for {source_id}",
        limit=MAX_REQUESTS,
    )
    result: list[ReviewedDistfile] = []
    seen: set[str] = set()
    for index, raw_entry in enumerate(entries):
        entry = _mapping(raw_entry, f"reviewed distfile {index} for {source_id}")
        if set(entry) != {"filename", "sha512", "size", "url"}:
            raise PlanError(f"reviewed distfile has invalid fields: {source_id}/{index}")
        filename = _checked_distfile_filename(
            entry.get("filename"),
            f"reviewed distfile filename for {source_id}",
        )
        if filename.casefold() in seen:
            raise PlanError(f"reviewed distfiles repeat a filename: {source_id}/{filename}")
        seen.add(filename.casefold())
        url = _required_string(entry, "url", f"reviewed distfile for {source_id}")
        expected_url = (
            f"https://distfiles.alpinelinux.org/distfiles/{release}/"
            f"{urllib.parse.quote(filename, safe='')}"
        )
        if url != expected_url:
            raise PlanError(f"reviewed distfile does not use its fixed origin: {source_id}")
        digest = _checked_digest(
            "sha512",
            entry.get("sha512"),
            f"reviewed distfile SHA-512 for {source_id}/{filename}",
        )
        size = _checked_optional_size(
            entry.get("size"),
            f"reviewed distfile size for {source_id}/{filename}",
        )
        if size is None:
            raise PlanError(f"reviewed distfile has no expected size: {source_id}/{filename}")
        result.append(
            ReviewedDistfile(
                filename=filename,
                artifact=Artifact(url=url, digest=digest, size=size),
            )
        )
    return tuple(result)


def _expected_recipe_needs(
    policy: Mapping[str, Any],
) -> dict[str, RecipeNeed]:
    python_needs, alpine_needs, python_by_platform = _collect_platform_needs(policy)
    del python_needs
    native_sources = _mapping(policy.get("native_component_sources"), "native component sources")
    _wheels, _owners, _owner_consumers, source_consumers = _collect_native_coverage(
        policy,
        python_needs_by_platform=python_by_platform,
        native_source_ids=set(native_sources),
    )
    release = _required_string(policy, "alpine_distfiles_release", "container policy")
    if ALPINE_RELEASE.fullmatch(release) is None:
        raise PlanError("container policy has an invalid Alpine distfiles release")
    archives = _mapping(policy.get("alpine_recipe_archives"), "Alpine recipe archives")
    expected_archive_keys = {f"{origin}@{commit}" for origin, commit in alpine_needs}
    if set(archives) != expected_archive_keys:
        missing = sorted(expected_archive_keys - set(archives))
        stale = sorted(set(archives) - expected_archive_keys)
        raise PlanError(
            "Alpine recipe policy does not exactly cover platform components; "
            f"missing={missing!r}, stale={stale!r}"
        )
    exceptions = _mapping(policy.get("alpine_recipe_exceptions"), "Alpine recipe exceptions")
    if not set(exceptions) <= expected_archive_keys:
        raise PlanError("Alpine recipe exceptions name an unselected recipe")

    result: dict[str, RecipeNeed] = {}
    for origin, commit in sorted(alpine_needs):
        recipe_key = f"{origin}@{commit}"
        digest = _checked_digest(
            "sha256",
            archives[recipe_key],
            f"Alpine recipe SHA-256 for {recipe_key}",
        )
        artifact = Artifact(
            url=(
                "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
                f"{commit}/aports-{commit}.tar.gz?path=main/{origin}"
            ),
            digest=digest,
            size=None,
        )
        dynamic, links = _alpine_recipe_exception(policy, recipe_key)
        request_id = f"alpine-recipe:{recipe_key}"
        result[request_id] = RecipeNeed(
            request_id=request_id,
            origin=origin,
            recipe_key=recipe_key,
            artifact=artifact,
            consumers=frozenset(alpine_needs[(origin, commit)]),
            distfiles_release=release,
            allow_dynamic_sources=dynamic,
            allowed_links=links,
            reviewed_distfiles=None,
        )

    for source_id in sorted(native_sources):
        source = _mapping(native_sources[source_id], f"native source {source_id}")
        if _required_string(source, "kind", f"native source {source_id}") != "alpine-aports":
            continue
        origin = _required_string(source, "origin", f"native source {source_id}")
        commit = _required_string(source, "aports_commit", f"native source {source_id}")
        if ALPINE_ORIGIN.fullmatch(origin) is None or COMMIT.fullmatch(commit) is None:
            raise PlanError(f"native Alpine source has an invalid recipe identity: {source_id}")
        native_release = _required_string(
            source,
            "distfiles_release",
            f"native source {source_id}",
        )
        if ALPINE_RELEASE.fullmatch(native_release) is None:
            raise PlanError(f"native source has an invalid distfiles release: {source_id}")
        artifact = _sha256_artifact(
            source.get("recipe"),
            f"native Alpine recipe {source_id}",
            size_required=True,
        )
        links = _validate_allowed_recipe_links(
            source.get("allowed_recipe_links"),
            f"allowed recipe links for native source {source_id}",
        )
        request_id = f"native-source:{source_id}:recipe"
        result[request_id] = RecipeNeed(
            request_id=request_id,
            origin=origin,
            recipe_key=f"{origin}@{commit}",
            artifact=artifact,
            consumers=frozenset(source_consumers[source_id]),
            distfiles_release=native_release,
            allow_dynamic_sources=False,
            allowed_links=links,
            reviewed_distfiles=_reviewed_native_distfiles(
                source,
                source_id,
                native_release,
            ),
        )
    return result


def _assert_parent_recipe_request(
    request: Mapping[str, Any],
    need: RecipeNeed,
) -> None:
    expected = {
        "id": need.request_id,
        "url": need.artifact.url,
        "allowed_hosts": list(_allowed_hosts(need.artifact.url)),
        "algorithm": "sha256",
        "digest": need.artifact.digest,
        "expected_size": need.artifact.size,
        "max_bytes": MAX_DOWNLOAD_BYTES,
        "consumers": sorted(need.consumers),
    }
    if dict(request) != expected:
        raise PlanError(
            f"parent direct plan has a swapped or stale recipe request: {need.request_id}"
        )


def _contract_failure(contract: ModuleType, exc: Exception, description: str) -> PlanError | None:
    error_type = getattr(contract, "SourceStoreError", ())
    if error_type and isinstance(exc, error_type):
        return PlanError(f"{description}: {exc}")
    return None


def _distfile_request_id(release: str, filename: str) -> str:
    filename_digest = hashlib.sha256(filename.encode("ascii")).hexdigest()
    return f"alpine-distfile:{release}:{filename_digest}"


def build_alpine_distfile_plan(
    policy_path: Path,
    direct_store_root: Path,
    *,
    expected_parent_plan_sha256: str,
    expected_parent_plan_size: int,
) -> dict[str, Any]:
    """Derive a bounded fixed-origin distfile plan from one verified direct store."""

    policy, policy_bytes = _load_policy(policy_path)
    policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
    contract = _source_store_contract()
    try:
        with contract.VerifiedSourceStoreReader(
            direct_store_root,
            expected_plan_sha256=expected_parent_plan_sha256,
            expected_plan_size=expected_parent_plan_size,
        ) as reader:
            parent_plan = cast(Mapping[str, Any], reader.plan)
            verification = cast(Mapping[str, Any], reader.verification)
            if parent_plan.get("kind") != KIND:
                raise PlanError("parent source plan is not a direct plan")
            if (
                parent_plan.get("evidence_schema_version") != SUPPORTED_EVIDENCE_SCHEMA_VERSION
                or parent_plan.get("policy_sha256") != policy_sha256
            ):
                raise PlanError("parent direct plan does not bind the exact reviewed policy")

            needs = _expected_recipe_needs(policy)
            parent_requests = {
                cast(str, request["id"]): request
                for request in cast(Sequence[Mapping[str, Any]], parent_plan["requests"])
            }
            selected_parent_ids = {
                request_id
                for request_id in parent_requests
                if request_id.startswith("alpine-recipe:")
                or (request_id.startswith("native-source:") and request_id.endswith(":recipe"))
            }
            if selected_parent_ids != set(needs):
                missing = sorted(set(needs) - selected_parent_ids)
                stale = sorted(selected_parent_ids - set(needs))
                raise PlanError(
                    "parent direct plan recipe requests do not exactly cover reviewed policy; "
                    f"missing={missing!r}, stale={stale!r}"
                )
            for request_id, need in needs.items():
                _assert_parent_recipe_request(parent_requests[request_id], need)

            builder = _PlanBuilder()
            recipe_records: list[dict[str, Any]] = []
            for request_id in sorted(needs):
                need = needs[request_id]
                archive_bytes = cast(bytes, reader.read_request(request_id).content)
                recipe_sha256 = hashlib.sha256(archive_bytes).hexdigest()
                parsed_distfiles = _parse_recipe_distfiles(archive_bytes, need)

                reviewed = (
                    None
                    if need.reviewed_distfiles is None
                    else {item.filename: item.artifact for item in need.reviewed_distfiles}
                )
                if reviewed is not None:
                    parsed_bindings = {item.filename: item.digest for item in parsed_distfiles}
                    reviewed_bindings = {
                        filename: artifact.digest for filename, artifact in reviewed.items()
                    }
                    if parsed_bindings != reviewed_bindings:
                        raise PlanError(
                            f"native recipe distfiles differ from reviewed policy: "
                            f"{need.request_id}"
                        )

                for distfile in parsed_distfiles:
                    if reviewed is None:
                        artifact = Artifact(
                            url=(
                                "https://distfiles.alpinelinux.org/distfiles/"
                                f"{need.distfiles_release}/"
                                f"{urllib.parse.quote(distfile.filename, safe='')}"
                            ),
                            digest=distfile.digest,
                            size=None,
                        )
                    else:
                        artifact = reviewed[distfile.filename]
                    builder.add(
                        _distfile_request_id(need.distfiles_release, distfile.filename),
                        artifact,
                        max_bytes=MAX_NATIVE_SOURCE_BYTES,
                        consumers=set(need.consumers),
                        algorithm="sha512",
                        allow_alpine_distfiles=True,
                    )
                recipe_records.append(
                    {
                        "request_id": request_id,
                        "object_sha256": recipe_sha256,
                        "size": len(archive_bytes),
                    }
                )

            parent_plan_descriptor = dict(cast(Mapping[str, Any], verification["plan"]))
            parent_manifest_descriptor = dict(cast(Mapping[str, Any], verification["manifest"]))
            plan: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "media_type": MEDIA_TYPE,
                "kind": ALPINE_DISTFILES_KIND,
                "evidence_schema_version": SUPPORTED_EVIDENCE_SCHEMA_VERSION,
                "source_revision": parent_plan["source_revision"],
                "policy_sha256": policy_sha256,
                "uv_lock_sha256": parent_plan["uv_lock_sha256"],
                "parent_plan": parent_plan_descriptor,
                "parent_manifest": parent_manifest_descriptor,
                "recipes": recipe_records,
                "requests": builder.requests(),
            }
            encoded = canonical_json(plan)
            if len(encoded) > MAX_PLAN_BYTES:
                raise PlanError("Alpine distfile plan exceeds its encoded size limit")
            _self_validate_plan(plan, encoded)
        return plan
    except PlanError:
        raise
    except Exception as exc:
        translated = _contract_failure(
            contract,
            exc,
            "parent source store does not verify or changed during recipe parsing",
        )
        if translated is not None:
            raise translated from exc
        raise


def build_direct_plan(
    policy_path: Path,
    uv_lock_path: Path,
    *,
    source_revision: str,
) -> dict[str, Any]:
    """Build one direct plan without fetching or parsing source archives."""

    if SHA1.fullmatch(source_revision) is None:
        raise PlanError("source revision must be a lowercase 40-character Git object id")
    policy, policy_bytes = _load_policy(policy_path)
    lock, lock_bytes = _load_lock(uv_lock_path)

    evidence_schema = policy.get("schema_version")
    if isinstance(evidence_schema, bool) or evidence_schema != SUPPORTED_EVIDENCE_SCHEMA_VERSION:
        raise PlanError(
            f"container policy must use evidence schema {SUPPORTED_EVIDENCE_SCHEMA_VERSION}"
        )

    native_sources = _mapping(policy.get("native_component_sources"), "native component sources")
    python_needs, alpine_needs, python_needs_by_platform = _collect_platform_needs(policy)
    wheel_needs, owner_sources, owner_consumers, source_consumers = _collect_native_coverage(
        policy,
        python_needs_by_platform=python_needs_by_platform,
        native_source_ids=set(native_sources),
    )
    wheel_packages = {need.package for need in wheel_needs}
    lock_packages = _load_selected_lock_packages(
        lock,
        relevant=set(python_needs),
        wheel_packages=wheel_packages,
    )

    builder = _PlanBuilder()
    _add_base_requests(builder, policy)
    selected_python_sources = _add_python_sources(
        builder,
        policy,
        python_needs=python_needs,
        owner_sources=owner_sources,
        owner_consumers=owner_consumers,
        lock_packages=lock_packages,
    )
    _add_native_wheels(builder, wheel_needs, lock_packages)
    _add_alpine_recipes(builder, policy, alpine_needs=alpine_needs)
    _add_license_texts(builder, policy)
    _add_native_sources(
        builder,
        policy,
        selected_python_sources=selected_python_sources,
        source_consumers=source_consumers,
    )

    plan = {
        "schema_version": SCHEMA_VERSION,
        "media_type": MEDIA_TYPE,
        "kind": KIND,
        "evidence_schema_version": evidence_schema,
        "source_revision": source_revision,
        # These are transport bindings to exact checkout bytes. The evidence
        # manifest's canonical policy hash remains a separate downstream field.
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "uv_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "requests": builder.requests(),
    }
    encoded = canonical_json(plan)
    if len(encoded) > MAX_PLAN_BYTES:
        raise PlanError("direct plan exceeds its encoded size limit")
    _self_validate_plan(plan, encoded)
    return plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build deterministic container source request plans."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    direct = commands.add_parser(
        "direct-plan",
        help="emit the direct request plan from reviewed policy and uv.lock",
    )
    direct.add_argument(
        "--policy",
        type=Path,
        default=Path(".compliance/container-policy.json"),
    )
    direct.add_argument("--uv-lock", type=Path, default=Path("uv.lock"))
    direct.add_argument("--source-revision", required=True)
    direct.add_argument("--output", type=Path)
    distfiles = commands.add_parser(
        "alpine-distfile-plan",
        help="emit a fixed-origin Alpine distfile plan from a verified direct store",
    )
    distfiles.add_argument(
        "--policy",
        type=Path,
        default=Path(".compliance/container-policy.json"),
    )
    distfiles.add_argument("--direct-store", type=Path, required=True)
    distfiles.add_argument("--expected-parent-plan-sha256", required=True)
    distfiles.add_argument("--expected-parent-plan-size", required=True, type=int)
    distfiles.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "direct-plan":
            plan = build_direct_plan(
                args.policy,
                args.uv_lock,
                source_revision=args.source_revision,
            )
        elif args.command == "alpine-distfile-plan":
            plan = build_alpine_distfile_plan(
                args.policy,
                args.direct_store,
                expected_parent_plan_sha256=args.expected_parent_plan_sha256,
                expected_parent_plan_size=args.expected_parent_plan_size,
            )
        else:
            raise PlanError(f"unsupported command: {args.command}")
    except PlanError as exc:
        sys.stderr.write(f"Container source plan error: {exc}\n")
        return 1
    encoded = canonical_json(plan)
    if args.output is None:
        sys.stdout.buffer.write(encoded)
    else:
        try:
            _write_plan_output(cast(Path, args.output), encoded)
        except PlanError as exc:
            sys.stderr.write(f"Container source plan error: {exc}\n")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
