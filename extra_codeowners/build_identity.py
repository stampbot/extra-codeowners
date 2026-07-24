"""Load immutable source identity baked into the official container image."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BUILD_IDENTITY_PATH = Path("/app/build-identity.json")
MAX_BUILD_IDENTITY_BYTES = 16 * 1024
_BUILD_IDENTITY_KEYS = frozenset(
    {
        "schema_version",
        "source_revision",
        "selection_record_sha256",
        "wheel_filename",
        "wheel_sha256",
        "sdist_filename",
        "sdist_sha256",
    }
)
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")


class BuildIdentityError(RuntimeError):
    """The baked build identity is present but cannot be trusted."""


@dataclass(frozen=True, slots=True)
class BuildIdentity:
    """Source and distribution facts emitted by verified wheel selection."""

    source_revision: str
    selection_record_sha256: str
    wheel_filename: str
    wheel_sha256: str
    sdist_filename: str
    sdist_sha256: str


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value!r}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError(f"duplicate JSON member {name!r}")
        value[name] = item
    return value


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def parse_build_identity(content: bytes) -> BuildIdentity:
    """Parse the canonical, bounded result of ``verify-selection``."""
    try:
        value = json.loads(
            content,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise BuildIdentityError("build identity is not valid canonical JSON") from error
    if not isinstance(value, dict) or set(value) != _BUILD_IDENTITY_KEYS:
        raise BuildIdentityError("build identity has an unexpected schema")
    if _canonical_json(value) != content:
        raise BuildIdentityError("build identity is not canonical JSON")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise BuildIdentityError("build identity has an unsupported schema version")

    source_revision = value["source_revision"]
    selection_record_sha256 = value["selection_record_sha256"]
    wheel_filename = value["wheel_filename"]
    wheel_sha256 = value["wheel_sha256"]
    sdist_filename = value["sdist_filename"]
    sdist_sha256 = value["sdist_sha256"]
    if not isinstance(source_revision, str) or _REVISION.fullmatch(source_revision) is None:
        raise BuildIdentityError("build identity has an invalid source revision")
    digests = (selection_record_sha256, wheel_sha256, sdist_sha256)
    if any(not isinstance(digest, str) or _SHA256.fullmatch(digest) is None for digest in digests):
        raise BuildIdentityError("build identity has an invalid artifact digest")
    filenames = (wheel_filename, sdist_filename)
    if any(
        not isinstance(filename, str) or _ARTIFACT_FILENAME.fullmatch(filename) is None
        for filename in filenames
    ):
        raise BuildIdentityError("build identity has an invalid artifact filename")
    if not wheel_filename.endswith(".whl") or not sdist_filename.endswith(".tar.gz"):
        raise BuildIdentityError("build identity has an unexpected artifact type")
    return BuildIdentity(
        source_revision=source_revision,
        selection_record_sha256=selection_record_sha256,
        wheel_filename=wheel_filename,
        wheel_sha256=wheel_sha256,
        sdist_filename=sdist_filename,
        sdist_sha256=sdist_sha256,
    )


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def load_build_identity(
    path: Path = BUILD_IDENTITY_PATH,
    *,
    expected_owner_uid: int = 0,
) -> BuildIdentity | None:
    """Load a non-writable regular identity file, or return ``None`` when absent."""
    required_flags = ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required_flags):
        raise BuildIdentityError("build identity requires secure descriptor flags")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise BuildIdentityError("build identity could not be opened safely") from error

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BuildIdentityError("build identity is not a regular file")
        if before.st_uid != expected_owner_uid:
            raise BuildIdentityError("build identity has an unexpected owner")
        if stat.S_IMODE(before.st_mode) != 0o444:
            raise BuildIdentityError("build identity must have mode 0444")
        if before.st_nlink != 1:
            raise BuildIdentityError("build identity must have exactly one hard link")
        if not 1 <= before.st_size <= MAX_BUILD_IDENTITY_BYTES:
            raise BuildIdentityError("build identity exceeds its size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            content = source.read(MAX_BUILD_IDENTITY_BYTES + 1)
        after = os.fstat(descriptor)
        if _stable_identity(before) != _stable_identity(after) or len(content) != before.st_size:
            raise BuildIdentityError("build identity changed while it was read")
        return parse_build_identity(content)
    except OSError as error:
        raise BuildIdentityError("build identity could not be read safely") from error
    finally:
        os.close(descriptor)
