#!/usr/bin/env python3
"""Verify or materialize an opaque five-file Python-distribution spine."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import dataclasses
import errno
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn, cast

SCHEMA_VERSION = 1
RECORD_MEDIA_TYPE = "application/vnd.stampbot.python-distribution-spine.v1+json"
SPINE_MEDIA_TYPE = "application/vnd.stampbot.python-distribution-spine.v1+octet-stream"

MAX_RECORD_BYTES = 128 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_ITEMS = 1024
MAX_RECORD_FILE_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 64 * 1024 * 1024
MAX_SPINE_BYTES = 2 * MAX_ARCHIVE_FILE_BYTES + 3 * MAX_RECORD_FILE_BYTES
MAX_ID = 2**63 - 1
READ_CHUNK_BYTES = 1024 * 1024
RENAME_NOREPLACE = 1
ROOT_UID = 0
LINUX_OVERFLOW_UID = 65534
MAX_UID_MAP_BYTES = 4096
MAX_LINUX_UID = 2**32 - 1

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DECIMAL_ID = re.compile(r"^[1-9][0-9]{0,18}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
SAFE_REF_SUFFIX = re.compile(r"^refs/(?:heads|tags|pull)/[A-Za-z0-9_.\-/]+$")
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
WHEEL_FILENAME = re.compile(r"^(?P<identity>[A-Za-z0-9_]+-[A-Za-z0-9.!+_-]+)-py3-none-any\.whl$")
SDIST_FILENAME = re.compile(r"^(?P<identity>[A-Za-z0-9_]+-[A-Za-z0-9.!+_-]+)\.tar\.gz$")

KIND_ORDER = (
    "build-record-amd64",
    "build-record-arm64",
    "selection-record",
    "sdist",
    "wheel",
)
FIXED_KIND_FILENAMES = {
    "build-record-amd64": "python-build-record-amd64.json",
    "build-record-arm64": "python-build-record-arm64.json",
    "selection-record": "python-selection-record.json",
}
RECORD_FIELDS = {"filename", "kind", "offset", "sha256", "size"}


class SpineError(RuntimeError):
    """The Python-distribution spine contract was violated."""


@dataclasses.dataclass(frozen=True)
class ExpectedIdentity:
    """Trusted workflow values that an untrusted record must match exactly."""

    repository_id: str
    repository_name: str
    run_id: str
    run_attempt: str
    source_revision: str
    workflow_path: str
    workflow_ref: str
    workflow_sha: str
    selected_artifact_id: str
    selected_artifact_sha256: str
    wheel_sha256: str
    selection_record_sha256: str


@dataclasses.dataclass(frozen=True)
class FileIdentity:
    """Stable metadata for one already-open regular file."""

    device: int
    inode: int
    mode: int
    links: int
    uid: int
    gid: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclasses.dataclass(frozen=True)
class DirectoryIdentity:
    """Stable ownership and mode for one open materialization directory."""

    device: int
    inode: int
    mode: int
    uid: int


@dataclasses.dataclass(frozen=True)
class DirectoryHop:
    """One retained descriptor and name in an absolute directory chain."""

    descriptor: int
    identity: DirectoryIdentity
    name: str | None


@dataclasses.dataclass(frozen=True)
class DirectoryChain:
    """Retained absolute ancestry plus its numeric root authority."""

    hops: tuple[DirectoryHop, ...]
    root_uid: int


@dataclasses.dataclass(frozen=True)
class FileRange:
    """One immutable file range captured from a validated record."""

    filename: str
    offset: int
    size: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class VerifiedSpine:
    """A verified spine whose descriptor remains open for a bounded consumer."""

    descriptor: int
    files: tuple[FileRange, ...]

    def file_chunks(self, filename: str) -> tuple[bytes, ...]:
        """Return one verified file as bounded immutable chunks."""

        matches = [item for item in self.files if item.filename == filename]
        if len(matches) != 1:
            raise SpineError("requested file is not uniquely present in the verified record")
        item = matches[0]
        remaining = item.size
        position = item.offset
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        while remaining:
            try:
                chunk = os.pread(self.descriptor, min(READ_CHUNK_BYTES, remaining), position)
            except OSError as exc:
                raise SpineError("cannot stage a verified Python distribution file") from exc
            if not chunk:
                raise SpineError("verified Python distribution changed while a range was read")
            digest.update(chunk)
            chunks.append(chunk)
            remaining -= len(chunk)
            position += len(chunk)
        if digest.hexdigest() != item.sha256:
            raise SpineError("verified Python distribution changed before a file was exposed")
        return tuple(chunks)


def canonical_json(value: object) -> bytes:
    """Return the one accepted JSON encoding, including its final line feed."""

    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SpineError("record cannot be encoded as canonical JSON") from exc
    return encoded + b"\n"


def _reject_constant(value: str) -> NoReturn:
    raise SpineError(f"record contains a non-finite number: {value}")


def _reject_float(value: str) -> NoReturn:
    raise SpineError(f"record contains a floating-point number: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SpineError(f"record repeats JSON key: {key!r}")
        result[key] = value
    return result


def strict_json_bytes(raw: bytes, source: str, *, canonical: bool) -> Any:
    """Parse bounded JSON while rejecting duplicate keys and ambiguous numbers."""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpineError(f"{source} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except SpineError:
        raise
    except (ValueError, RecursionError) as exc:
        raise SpineError(f"{source} is not valid bounded JSON") from exc

    count = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_JSON_ITEMS:
            raise SpineError(f"{source} has too many JSON values")
        if depth > MAX_JSON_DEPTH:
            raise SpineError(f"{source} exceeds the JSON depth limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            raise SpineError(f"{source} contains a floating-point number")
    if canonical and canonical_json(value) != raw:
        raise SpineError(f"{source} is not in canonical JSON form")
    return value


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SpineError(f"{source} must contain exactly {sorted(fields)}")
    return value


def _integer(value: object, source: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise SpineError(f"{source} is outside its integer bounds")
    return value


def _scalar(value: object, source: str, pattern: re.Pattern[str], *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
        or pattern.fullmatch(value) is None
    ):
        raise SpineError(f"{source} is invalid")
    return value


def _workflow_ref(value: object, source: str, repository: str, workflow_path: str) -> str:
    if not isinstance(value, str) or len(value) > 768 or not value.isascii():
        raise SpineError(f"{source} is invalid")
    prefix = f"{repository}/{workflow_path}@"
    if not value.startswith(prefix):
        raise SpineError(f"{source} is not bound to its repository and workflow path")
    suffix = value.removeprefix(prefix)
    segments = suffix.split("/")
    if SAFE_REF_SUFFIX.fullmatch(suffix) is None or any(
        segment in {"", ".", ".."} for segment in segments
    ):
        raise SpineError(f"{source} is invalid")
    return value


def _decimal_id(value: object, source: str) -> str:
    result = _scalar(value, source, DECIMAL_ID, maximum=19)
    if int(result) > MAX_ID:
        raise SpineError(f"{source} exceeds the ID limit")
    return result


def expected_spine_filename(
    source_revision: str, selected_artifact_id: str, run_attempt: str
) -> str:
    return (
        f"extra-codeowners-python-{source_revision}-artifact-{selected_artifact_id}"
        f"-attempt-{run_attempt}.bin"
    )


def expected_record_filename(
    source_revision: str, selected_artifact_id: str, run_attempt: str
) -> str:
    return (
        f"extra-codeowners-python-{source_revision}-artifact-{selected_artifact_id}"
        f"-attempt-{run_attempt}.spine.json"
    )


def validate_expected_identity(expected: ExpectedIdentity) -> None:
    """Validate trusted inputs before comparing them with untrusted data."""

    _decimal_id(expected.repository_id, "expected repository ID")
    _scalar(expected.repository_name, "expected repository name", REPOSITORY)
    _decimal_id(expected.run_id, "expected run ID")
    _decimal_id(expected.run_attempt, "expected run attempt")
    _scalar(expected.source_revision, "expected source revision", HEX40, maximum=40)
    _scalar(expected.workflow_path, "expected workflow path", WORKFLOW_PATH)
    _workflow_ref(
        expected.workflow_ref,
        "expected workflow ref",
        expected.repository_name,
        expected.workflow_path,
    )
    _scalar(expected.workflow_sha, "expected workflow SHA", HEX40, maximum=40)
    _decimal_id(expected.selected_artifact_id, "expected selected artifact ID")
    for value, source in (
        (expected.selected_artifact_sha256, "expected selected artifact SHA-256"),
        (expected.wheel_sha256, "expected wheel SHA-256"),
        (expected.selection_record_sha256, "expected selection-record SHA-256"),
    ):
        _scalar(value, source, HEX64, maximum=64)


def _validated_filename(kind: str, value: object) -> tuple[str, str | None]:
    filename = _scalar(value, f"{kind} filename", SAFE_FILENAME, maximum=255)
    fixed = FIXED_KIND_FILENAMES.get(kind)
    if fixed is not None:
        if filename != fixed:
            raise SpineError(f"{kind} has the wrong filename")
        return filename, None
    pattern = SDIST_FILENAME if kind == "sdist" else WHEEL_FILENAME
    match = pattern.fullmatch(filename)
    if match is None:
        raise SpineError(f"{kind} has an unsupported filename")
    return filename, match.group("identity")


def validate_record(value: object, expected: ExpectedIdentity) -> Mapping[str, Any]:
    """Validate one parsed record and bind it to trusted workflow identity."""

    validate_expected_identity(expected)
    record = _exact_mapping(
        value,
        {
            "files",
            "media_type",
            "repository",
            "run",
            "schema_version",
            "selected_artifact",
            "selection",
            "source",
            "spine",
            "workflow",
        },
        "Python-distribution spine record",
    )
    if record["schema_version"] != SCHEMA_VERSION or isinstance(record["schema_version"], bool):
        raise SpineError("Python-distribution spine record has an unsupported schema version")
    if record["media_type"] != RECORD_MEDIA_TYPE:
        raise SpineError("Python-distribution spine record has an unsupported media type")

    repository = _exact_mapping(record["repository"], {"id", "name"}, "repository")
    if _decimal_id(repository["id"], "repository ID") != expected.repository_id:
        raise SpineError("repository ID does not match the trusted workflow value")
    if _scalar(repository["name"], "repository name", REPOSITORY) != expected.repository_name:
        raise SpineError("repository name does not match the trusted workflow value")

    run = _exact_mapping(record["run"], {"attempt", "id"}, "run")
    if _decimal_id(run["id"], "run ID") != expected.run_id:
        raise SpineError("run ID does not match the trusted workflow value")
    if _decimal_id(run["attempt"], "run attempt") != expected.run_attempt:
        raise SpineError("run attempt does not match the trusted workflow value")

    source = _exact_mapping(record["source"], {"revision"}, "source")
    if (
        _scalar(source["revision"], "source revision", HEX40, maximum=40)
        != expected.source_revision
    ):
        raise SpineError("source revision does not match the trusted workflow value")

    workflow = _exact_mapping(record["workflow"], {"path", "ref", "sha"}, "workflow")
    if _scalar(workflow["path"], "workflow path", WORKFLOW_PATH) != expected.workflow_path:
        raise SpineError("workflow path does not match the trusted workflow value")
    if (
        _workflow_ref(
            workflow["ref"],
            "workflow ref",
            expected.repository_name,
            expected.workflow_path,
        )
        != expected.workflow_ref
    ):
        raise SpineError("workflow ref does not match the trusted workflow value")
    if _scalar(workflow["sha"], "workflow SHA", HEX40, maximum=40) != expected.workflow_sha:
        raise SpineError("workflow SHA does not match the trusted workflow value")

    selected = _exact_mapping(record["selected_artifact"], {"id", "sha256"}, "selected artifact")
    if _decimal_id(selected["id"], "selected artifact ID") != expected.selected_artifact_id:
        raise SpineError("selected artifact ID does not match the trusted workflow value")
    if (
        _scalar(selected["sha256"], "selected artifact SHA-256", HEX64, maximum=64)
        != expected.selected_artifact_sha256
    ):
        raise SpineError("selected artifact SHA-256 does not match the trusted workflow value")

    selection = _exact_mapping(record["selection"], {"record_sha256", "wheel_sha256"}, "selection")
    if (
        _scalar(selection["wheel_sha256"], "wheel SHA-256", HEX64, maximum=64)
        != expected.wheel_sha256
    ):
        raise SpineError("wheel SHA-256 does not match the trusted workflow value")
    if (
        _scalar(selection["record_sha256"], "selection-record SHA-256", HEX64, maximum=64)
        != expected.selection_record_sha256
    ):
        raise SpineError("selection-record SHA-256 does not match the trusted workflow value")

    spine = _exact_mapping(record["spine"], {"filename", "media_type", "sha256", "size"}, "spine")
    filename = _scalar(spine["filename"], "spine filename", SAFE_FILENAME, maximum=255)
    if filename != expected_spine_filename(
        expected.source_revision,
        expected.selected_artifact_id,
        expected.run_attempt,
    ):
        raise SpineError(
            "spine filename is not bound to the selected artifact and producer attempt"
        )
    if spine["media_type"] != SPINE_MEDIA_TYPE:
        raise SpineError("spine has an unsupported media type")
    _scalar(spine["sha256"], "spine SHA-256", HEX64, maximum=64)
    spine_size = _integer(spine["size"], "spine size", minimum=1, maximum=MAX_SPINE_BYTES)

    raw_files = record["files"]
    if not isinstance(raw_files, list) or len(raw_files) != len(KIND_ORDER):
        raise SpineError("record must contain exactly five distribution files")
    files: list[dict[str, object]] = []
    expected_offset = 0
    digests: set[str] = set()
    archive_identities: dict[str, str] = {}
    for position, (raw_file, expected_kind) in enumerate(zip(raw_files, KIND_ORDER, strict=True)):
        item = _exact_mapping(raw_file, RECORD_FIELDS, f"file {position}")
        if item["kind"] != expected_kind:
            raise SpineError("distribution files are missing, unsupported, or out of order")
        item_filename, archive_identity = _validated_filename(expected_kind, item["filename"])
        if archive_identity is not None:
            archive_identities[expected_kind] = archive_identity
        offset = _integer(
            item["offset"], f"{expected_kind} offset", minimum=0, maximum=MAX_SPINE_BYTES
        )
        if offset != expected_offset:
            raise SpineError("file ranges contain a prefix, gap, overlap, or alias")
        maximum = (
            MAX_ARCHIVE_FILE_BYTES if expected_kind in {"sdist", "wheel"} else MAX_RECORD_FILE_BYTES
        )
        size = _integer(item["size"], f"{expected_kind} size", minimum=1, maximum=maximum)
        if size > MAX_SPINE_BYTES - expected_offset:
            raise SpineError("file ranges exceed the spine size limit")
        expected_offset += size
        digest = _scalar(item["sha256"], f"{expected_kind} SHA-256", HEX64, maximum=64)
        if digest in digests:
            raise SpineError("distribution file digest is repeated")
        digests.add(digest)
        files.append(
            {
                "filename": item_filename,
                "kind": expected_kind,
                "offset": offset,
                "sha256": digest,
                "size": size,
            }
        )
    if expected_offset != spine_size:
        raise SpineError("file ranges do not cover the exact spine size")
    if archive_identities.get("sdist") != archive_identities.get("wheel"):
        raise SpineError("wheel and source distribution filenames identify different projects")
    files_by_kind = {str(item["kind"]): item for item in files}
    if files_by_kind["wheel"]["sha256"] != expected.wheel_sha256:
        raise SpineError("wheel file range does not match the selected wheel")
    if files_by_kind["selection-record"]["sha256"] != expected.selection_record_sha256:
        raise SpineError("selection-record range does not match the selected record")

    return {**record, "files": files}


def _file_identity(metadata: os.stat_result, source: str, *, maximum: int) -> FileIdentity:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SpineError(f"{source} must be one single-link regular file")
    if not 1 <= metadata.st_size <= maximum:
        raise SpineError(f"{source} is outside its file-size limit")
    return FileIdentity(
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


def _open_regular(path: Path, source: str, *, maximum: int) -> tuple[int, FileIdentity]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise SpineError("Python-distribution spine verification requires O_NOFOLLOW support")
    try:
        descriptor = os.open(path, flags | nofollow)
    except OSError as exc:
        raise SpineError(f"cannot open {source} safely") from exc
    try:
        identity = _file_identity(os.fstat(descriptor), source, maximum=maximum)
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (identity.device, identity.inode):
            raise SpineError(f"{source} path changed while it was opened")
    except OSError as exc:
        os.close(descriptor)
        raise SpineError(f"{source} path changed while it was opened") from exc
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, identity


def _require_unchanged(descriptor: int, path: Path, before: FileIdentity, source: str) -> None:
    after = _file_identity(os.fstat(descriptor), source, maximum=before.size)
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise SpineError(f"{source} path changed while it was read") from exc
    if after != before or (current.st_dev, current.st_ino) != (before.device, before.inode):
        raise SpineError(f"{source} changed while it was read")


def _directory_open_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise SpineError("Python-distribution materialization requires directory no-follow support")
    return flags | nofollow | directory


def _directory_identity(metadata: os.stat_result, source: str) -> DirectoryIdentity:
    if not stat.S_ISDIR(metadata.st_mode):
        raise SpineError(f"{source} is not a directory")
    return DirectoryIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
    )


def _linux_uid_map() -> tuple[tuple[int, int, int], ...]:
    """Read the current Linux user-namespace map through a bounded descriptor."""

    if sys.platform != "linux":
        raise SpineError("Linux user-namespace identity is unavailable")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise SpineError("Linux user-namespace identity requires no-follow support")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    descriptor = -1
    try:
        descriptor = os.open("/proc/self/uid_map", flags)
        chunks: list[bytes] = []
        remaining = MAX_UID_MAP_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise SpineError("cannot establish the Linux user-namespace UID map") from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    raw = b"".join(chunks)
    if not raw or len(raw) > MAX_UID_MAP_BYTES:
        raise SpineError("Linux user-namespace UID map is empty or oversized")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SpineError("Linux user-namespace UID map is not ASCII") from exc
    mappings: list[tuple[int, int, int]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(not field.isdecimal() for field in fields):
            raise SpineError("Linux user-namespace UID map is malformed")
        try:
            inside, outside, length = (int(field) for field in fields)
        except ValueError as exc:
            raise SpineError("Linux user-namespace UID map is outside numeric bounds") from exc
        if (
            not length
            or inside > MAX_LINUX_UID
            or outside > MAX_LINUX_UID
            or length > MAX_LINUX_UID + 1
            or inside + length - 1 > MAX_LINUX_UID
            or outside + length - 1 > MAX_LINUX_UID
        ):
            raise SpineError("Linux user-namespace UID map is outside numeric bounds")
        mappings.append((inside, outside, length))
    if not mappings:
        raise SpineError("Linux user-namespace UID map has no mappings")
    return tuple(mappings)


def _uid_is_mapped(uid: int, mappings: Sequence[tuple[int, int, int]]) -> bool:
    return any(inside <= uid < inside + length for inside, _outside, length in mappings)


def _root_authority_uid(identity: DirectoryIdentity) -> int:
    """Return UID 0, or the narrowly proven overflow UID for an unmapped root."""

    effective_uid = os.geteuid()
    if effective_uid == LINUX_OVERFLOW_UID:
        raise SpineError("materialization cannot run as the Linux overflow UID")
    if identity.uid == ROOT_UID:
        return ROOT_UID
    if identity.uid != LINUX_OVERFLOW_UID or stat.S_IMODE(identity.mode) & 0o022:
        raise SpineError("materialization root has an untrusted owner")
    mappings = _linux_uid_map()
    if (
        _uid_is_mapped(ROOT_UID, mappings)
        or _uid_is_mapped(LINUX_OVERFLOW_UID, mappings)
        or not _uid_is_mapped(effective_uid, mappings)
    ):
        raise SpineError("materialization root overflow owner is not an unmapped-root namespace")
    return LINUX_OVERFLOW_UID


def _require_trusted_transition(
    parent: DirectoryIdentity,
    child: DirectoryIdentity,
    root_uid: int,
) -> None:
    """Enforce the Linux owner, write-bit, and sticky-directory trust rule."""

    trusted_uids = {ROOT_UID, root_uid, os.geteuid()}
    if parent.uid not in trusted_uids or child.uid not in trusted_uids:
        raise SpineError("materialization ancestry has an untrusted owner")
    if stat.S_IMODE(parent.mode) & 0o022 and not (
        parent.uid in {ROOT_UID, root_uid}
        and parent.mode & stat.S_ISVTX
        and child.uid in trusted_uids
    ):
        raise SpineError("materialization ancestry has an unsafe writable directory")


def _require_private_parent(identity: DirectoryIdentity) -> None:
    if identity.uid != os.geteuid() or stat.S_IMODE(identity.mode) & 0o077:
        raise SpineError("materialization parent must be an owner-controlled private directory")


def _current_directory_identity(
    hop: DirectoryHop,
    parent: DirectoryHop | None,
) -> DirectoryIdentity:
    """Recheck one held descriptor against its absolute path-chain entry."""

    try:
        descriptor_identity = _directory_identity(
            os.fstat(hop.descriptor),
            "materialization ancestry descriptor",
        )
        if parent is None:
            path_metadata = os.stat("/", follow_symlinks=False)
        else:
            if hop.name is None:
                raise SpineError("materialization ancestry is internally inconsistent")
            path_metadata = os.stat(
                hop.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        path_identity = _directory_identity(path_metadata, "materialization ancestry entry")
    except OSError as exc:
        raise SpineError("materialization ancestry changed during verification") from exc
    if (
        descriptor_identity != hop.identity
        or path_identity.device != hop.identity.device
        or path_identity.inode != hop.identity.inode
        or path_identity.mode != hop.identity.mode
        or path_identity.uid != hop.identity.uid
    ):
        raise SpineError("materialization ancestry changed during verification")
    return descriptor_identity


def _require_directory_chain_current(chain: DirectoryChain) -> None:
    """Recheck every retained ancestry descriptor and trust transition."""

    if not chain.hops:
        raise SpineError("materialization ancestry is empty")
    identities: list[DirectoryIdentity] = []
    for position, hop in enumerate(chain.hops):
        parent = chain.hops[position - 1] if position else None
        identities.append(_current_directory_identity(hop, parent))
    if _root_authority_uid(identities[0]) != chain.root_uid:
        raise SpineError("materialization root authority changed during verification")
    for position in range(1, len(identities)):
        _require_trusted_transition(
            identities[position - 1],
            identities[position],
            chain.root_uid,
        )
    _require_private_parent(identities[-1])


def _open_trusted_directory_chain(path: Path) -> DirectoryChain:
    """Walk and retain every component of an absolute materialization parent."""

    if not path.is_absolute() or path.anchor != "/" or ".." in path.parts:
        raise SpineError("materialization parent must be an absolute path without traversal")
    flags = _directory_open_flags()
    chain: list[DirectoryHop] = []
    try:
        root_descriptor = os.open("/", flags)
        try:
            root_identity = _directory_identity(
                os.fstat(root_descriptor),
                "materialization root",
            )
            root_path_identity = _directory_identity(
                os.stat("/", follow_symlinks=False),
                "materialization root path",
            )
            if root_identity != root_path_identity:
                raise SpineError("materialization root changed while it was opened")
            root_uid = _root_authority_uid(root_identity)
        except BaseException:
            os.close(root_descriptor)
            raise
        chain.append(DirectoryHop(root_descriptor, root_identity, None))

        for component in path.parts[1:]:
            parent = chain[-1]
            try:
                descriptor = os.open(component, flags, dir_fd=parent.descriptor)
            except OSError as exc:
                raise SpineError("cannot open materialization ancestry without symlinks") from exc
            try:
                identity = _directory_identity(
                    os.fstat(descriptor),
                    "materialization ancestry descriptor",
                )
                current = _directory_identity(
                    os.stat(
                        component,
                        dir_fd=parent.descriptor,
                        follow_symlinks=False,
                    ),
                    "materialization ancestry entry",
                )
                if identity != current:
                    raise SpineError("materialization ancestry changed while it was opened")
                _require_trusted_transition(parent.identity, identity, root_uid)
            except BaseException:
                os.close(descriptor)
                raise
            chain.append(DirectoryHop(descriptor, identity, component))
        _require_private_parent(chain[-1].identity)
        result = DirectoryChain(tuple(chain), root_uid)
        _require_directory_chain_current(result)
        return result
    except BaseException:
        for hop in reversed(chain):
            with contextlib.suppress(OSError):
                os.close(hop.descriptor)
        raise


def _close_directory_chain(chain: DirectoryChain) -> None:
    for hop in reversed(chain.hops):
        with contextlib.suppress(OSError):
            os.close(hop.descriptor)


def _rename_noreplace(
    source_descriptor: int,
    source_name: str,
    destination_descriptor: int,
    destination_name: str,
) -> None:
    """Publish with Linux renameat2 and reject every existing destination."""

    if sys.platform != "linux":
        raise SpineError("atomic no-replace materialization requires Linux")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise SpineError("Linux renameat2 is unavailable; refusing to publish") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_descriptor,
        os.fsencode(source_name),
        destination_descriptor,
        os.fsencode(destination_name),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise SpineError("materialization destination appeared before publication")
    if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise SpineError("Linux renameat2 no-replace publication is unavailable")
    raise SpineError(f"Linux renameat2 no-replace publication failed with errno {error}")


def _require_published_directory(
    parent_descriptor: int,
    name: str,
    expected: DirectoryIdentity,
) -> None:
    """Require the destination entry to resolve to the staged directory."""

    try:
        current = _directory_identity(
            os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False),
            "materialized output",
        )
    except OSError as exc:
        raise SpineError("materialized output disappeared after publication") from exc
    if current != expected:
        raise SpineError("materialized output changed during publication")


def _require_absent(descriptor: int, name: str) -> None:
    """Require a directory entry to be absent without following a symlink."""

    try:
        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SpineError("cannot inspect the materialization destination safely") from exc
    raise SpineError("materialization destination already exists")


def _create_staging_directory(parent_descriptor: int) -> tuple[int, str]:
    """Create and open an unpredictable owner-private staging directory."""

    for _ in range(16):
        name = f".python-distribution-materialize-{os.getpid()}-{os.urandom(8).hex()}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        except OSError as exc:
            raise SpineError("cannot create a private materialization staging directory") from exc
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            os.fchmod(descriptor, 0o700)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise SpineError("materialization staging directory is not private")
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            with contextlib.suppress(OSError):
                os.rmdir(name, dir_fd=parent_descriptor)
            raise
        return descriptor, name
    raise SpineError("cannot allocate a unique materialization staging directory")


def _write_materialized_file(
    directory_descriptor: int,
    item: FileRange,
    chunks: tuple[bytes, ...],
    created: list[str],
) -> None:
    """Create one staged file exclusively and write its authenticated chunks."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    created.append(item.filename)
    try:
        descriptor = os.open(item.filename, flags, 0o600, dir_fd=directory_descriptor)
    except OSError as exc:
        raise SpineError(f"cannot create materialized file safely: {item.filename}") from exc
    try:
        os.fchmod(descriptor, 0o600)
        digest = hashlib.sha256()
        size = 0
        for chunk in chunks:
            digest.update(chunk)
            size += len(chunk)
            remaining = memoryview(chunk)
            while remaining:
                try:
                    written = os.write(descriptor, remaining)
                except OSError as exc:
                    raise SpineError(f"cannot write materialized file: {item.filename}") from exc
                if written <= 0:
                    raise SpineError(f"cannot write materialized file: {item.filename}")
                remaining = remaining[written:]
        os.fsync(descriptor)
        metadata = _file_identity(
            os.fstat(descriptor),
            f"materialized file {item.filename}",
            maximum=item.size,
        )
        if (
            metadata.size != item.size
            or stat.S_IMODE(metadata.mode) != 0o600
            or size != item.size
            or digest.hexdigest() != item.sha256
        ):
            raise SpineError(
                f"materialized file does not match its verified range: {item.filename}"
            )
    finally:
        os.close(descriptor)


def _cleanup_staging_directory(
    parent_descriptor: int,
    staging_descriptor: int,
    staging_name: str,
    created: Sequence[str],
) -> None:
    """Best-effort removal of private output after a failed materialization."""

    for filename in reversed(created):
        with contextlib.suppress(OSError):
            os.unlink(filename, dir_fd=staging_descriptor)
    with contextlib.suppress(OSError, SpineError):
        expected = _directory_identity(
            os.fstat(staging_descriptor),
            "failed materialization",
        )
        current = _directory_identity(
            os.stat(
                staging_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            ),
            "failed materialization entry",
        )
        if current == expected:
            os.rmdir(staging_name, dir_fd=parent_descriptor)


def load_record(path: Path, expected: ExpectedIdentity) -> tuple[Mapping[str, Any], str]:
    """Read and validate a canonical record from one stable file descriptor."""

    descriptor, identity = _open_regular(
        path, "Python-distribution spine record", maximum=MAX_RECORD_BYTES
    )
    try:
        chunks: list[bytes] = []
        remaining = identity.size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise SpineError("Python-distribution spine record is truncated")
            chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        _require_unchanged(descriptor, path, identity, "Python-distribution spine record")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    value = strict_json_bytes(raw, "Python-distribution spine record", canonical=True)
    return validate_record(value, expected), digest.hexdigest()


@contextlib.contextmanager
def open_verified_spine(
    path: Path,
    record: Mapping[str, Any],
    *,
    artifact_sha256: str,
) -> Iterator[VerifiedSpine]:
    """Verify every file range and retain the same descriptor for a consumer."""

    expected_artifact = _scalar(
        artifact_sha256, "spine artifact provider SHA-256", HEX64, maximum=64
    )
    spine = _exact_mapping(record["spine"], {"filename", "media_type", "sha256", "size"}, "spine")
    expected_hash = cast(str, spine["sha256"])
    if expected_artifact != expected_hash:
        raise SpineError("spine artifact provider digest does not match the record")
    files = tuple(
        FileRange(
            filename=str(item["filename"]),
            offset=int(item["offset"]),
            size=int(item["size"]),
            sha256=str(item["sha256"]),
        )
        for item in record["files"]
    )
    descriptor, identity = _open_regular(path, "Python-distribution spine", maximum=MAX_SPINE_BYTES)
    try:
        if path.name != spine["filename"] or identity.size != spine["size"]:
            raise SpineError("spine path or size does not match the record")
        whole = hashlib.sha256()
        for item in files:
            item_hash = hashlib.sha256()
            remaining = item.size
            while remaining:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise SpineError("Python-distribution spine is truncated within a file range")
                whole.update(chunk)
                item_hash.update(chunk)
                remaining -= len(chunk)
            if item_hash.hexdigest() != item.sha256:
                raise SpineError(f"Python-distribution file digest mismatch: {item.filename}")
        if os.read(descriptor, 1):
            raise SpineError("Python-distribution spine has trailing bytes")
        if whole.hexdigest() != expected_hash:
            raise SpineError("Python-distribution spine SHA-256 does not match the record")
        _require_unchanged(descriptor, path, identity, "Python-distribution spine")
        yield VerifiedSpine(descriptor=descriptor, files=files)
        _require_unchanged(descriptor, path, identity, "Python-distribution spine")
    finally:
        os.close(descriptor)


def validate_selection_projection(
    verified: VerifiedSpine,
    record: Mapping[str, Any],
    expected: ExpectedIdentity,
) -> Mapping[str, Any]:
    """Bind every opaque file range through the trusted small selection record."""

    raw = b"".join(verified.file_chunks(FIXED_KIND_FILENAMES["selection-record"]))
    value = strict_json_bytes(raw, "embedded Python selection record", canonical=True)
    selection = _exact_mapping(
        value,
        {"artifacts", "proofs", "schema_version", "selected_architecture", "source_revision"},
        "embedded Python selection record",
    )
    if selection["schema_version"] != 1 or isinstance(selection["schema_version"], bool):
        raise SpineError("embedded Python selection record has an unsupported schema version")
    if selection["selected_architecture"] != "amd64":
        raise SpineError("embedded Python selection record has the wrong selected architecture")
    if (
        _scalar(
            selection["source_revision"],
            "embedded selection source revision",
            HEX40,
            maximum=40,
        )
        != expected.source_revision
    ):
        raise SpineError("embedded Python selection record has the wrong source revision")

    files = {str(item["kind"]): item for item in cast(Sequence[Mapping[str, Any]], record["files"])}
    proofs = _exact_mapping(selection["proofs"], {"amd64", "arm64"}, "selection proofs")
    for architecture, machine, kind in (
        ("amd64", "x86_64", "build-record-amd64"),
        ("arm64", "aarch64", "build-record-arm64"),
    ):
        proof = _exact_mapping(
            proofs[architecture],
            {"python_machine", "record_filename", "record_sha256"},
            f"{architecture} selection proof",
        )
        file_record = files[kind]
        if proof["python_machine"] != machine:
            raise SpineError(f"{architecture} selection proof has the wrong machine")
        if proof["record_filename"] != file_record["filename"]:
            raise SpineError(f"{architecture} selection proof has the wrong filename")
        if (
            _scalar(
                proof["record_sha256"],
                f"{architecture} selection proof SHA-256",
                HEX64,
                maximum=64,
            )
            != file_record["sha256"]
        ):
            raise SpineError(f"{architecture} selection proof has the wrong digest")
    if proofs["amd64"]["record_sha256"] == proofs["arm64"]["record_sha256"]:
        raise SpineError("selection proof record digests must differ")

    artifacts = _exact_mapping(selection["artifacts"], {"sdist", "wheel"}, "selection artifacts")
    for artifact_name, kind in (("sdist", "sdist"), ("wheel", "wheel")):
        artifact = _exact_mapping(
            artifacts[artifact_name],
            {"filename", "sha256", "size"},
            f"selected {artifact_name}",
        )
        file_record = files[kind]
        if artifact["filename"] != file_record["filename"]:
            raise SpineError(f"selected {artifact_name} has the wrong filename")
        if (
            _scalar(
                artifact["sha256"],
                f"selected {artifact_name} SHA-256",
                HEX64,
                maximum=64,
            )
            != file_record["sha256"]
        ):
            raise SpineError(f"selected {artifact_name} has the wrong digest")
        if (
            _integer(
                artifact["size"],
                f"selected {artifact_name} size",
                minimum=1,
                maximum=MAX_ARCHIVE_FILE_BYTES,
            )
            != file_record["size"]
        ):
            raise SpineError(f"selected {artifact_name} has the wrong size")
    return selection


def _load_bound_record(
    record_path: Path,
    expected: ExpectedIdentity,
    *,
    record_artifact_sha256: str,
) -> Mapping[str, Any]:
    """Load a canonical record bound to its trusted provider digest."""

    expected_record_hash = _scalar(
        record_artifact_sha256, "record artifact provider SHA-256", HEX64, maximum=64
    )
    if record_path.name != expected_record_filename(
        expected.source_revision,
        expected.selected_artifact_id,
        expected.run_attempt,
    ):
        raise SpineError(
            "record filename is not bound to the selected artifact and producer attempt"
        )
    record, actual_record_hash = load_record(record_path, expected)
    if actual_record_hash != expected_record_hash:
        raise SpineError("record artifact provider digest does not match its bytes")
    return record


def verify(
    record_path: Path,
    spine_path: Path,
    expected: ExpectedIdentity,
    *,
    record_artifact_sha256: str,
    spine_artifact_sha256: str,
) -> Mapping[str, Any]:
    """Verify both raw artifacts and return the validated small record."""

    record = _load_bound_record(
        record_path,
        expected,
        record_artifact_sha256=record_artifact_sha256,
    )
    with open_verified_spine(spine_path, record, artifact_sha256=spine_artifact_sha256) as verified:
        validate_selection_projection(verified, record, expected)
    return record


def materialize(
    record_path: Path,
    spine_path: Path,
    output_directory: Path,
    expected: ExpectedIdentity,
    *,
    record_artifact_sha256: str,
    spine_artifact_sha256: str,
) -> tuple[FileRange, ...]:
    """Verify and atomically expose the five recorded files in a new directory."""

    if (
        not output_directory.is_absolute()
        or output_directory.name in {"", ".", ".."}
        or ".." in output_directory.parts
    ):
        raise SpineError("materialization destination must be a safe absolute child path")
    directory_chain = _open_trusted_directory_chain(output_directory.parent)
    parent_descriptor = directory_chain.hops[-1].descriptor
    staging_descriptor = -1
    staging_name = ""
    cleanup_name = ""
    created: list[str] = []
    published = False
    try:
        _require_absent(parent_descriptor, output_directory.name)
        record = _load_bound_record(
            record_path,
            expected,
            record_artifact_sha256=record_artifact_sha256,
        )
        with open_verified_spine(
            spine_path,
            record,
            artifact_sha256=spine_artifact_sha256,
        ) as verified:
            validate_selection_projection(verified, record, expected)
            staging_descriptor, staging_name = _create_staging_directory(parent_descriptor)
            cleanup_name = staging_name
            for item in verified.files:
                chunks = verified.file_chunks(item.filename)
                _write_materialized_file(staging_descriptor, item, chunks, created)
            os.fsync(staging_descriptor)

        staging_identity = _directory_identity(
            os.fstat(staging_descriptor),
            "materialization staging directory",
        )
        _require_directory_chain_current(directory_chain)
        _require_absent(parent_descriptor, output_directory.name)
        _rename_noreplace(
            parent_descriptor,
            staging_name,
            parent_descriptor,
            output_directory.name,
        )
        cleanup_name = output_directory.name
        _require_directory_chain_current(directory_chain)
        _require_published_directory(
            parent_descriptor,
            output_directory.name,
            staging_identity,
        )
        published = True
        return verified.files
    except OSError as exc:
        raise SpineError("materialization failed during a bounded file operation") from exc
    finally:
        if staging_descriptor >= 0:
            if not published:
                _cleanup_staging_directory(
                    parent_descriptor,
                    staging_descriptor,
                    cleanup_name,
                    created,
                )
            os.close(staging_descriptor)
        _close_directory_chain(directory_chain)


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--repository-name", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--selected-artifact-id", required=True)
    parser.add_argument("--selected-artifact-sha256", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--selection-record-sha256", required=True)


def expected_from_args(args: argparse.Namespace) -> ExpectedIdentity:
    return ExpectedIdentity(
        repository_id=args.repository_id,
        repository_name=args.repository_name,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        source_revision=args.source_revision,
        workflow_path=args.workflow_path,
        workflow_ref=args.workflow_ref,
        workflow_sha=args.workflow_sha,
        selected_artifact_id=args.selected_artifact_id,
        selected_artifact_sha256=args.selected_artifact_sha256,
        wheel_sha256=args.wheel_sha256,
        selection_record_sha256=args.selection_record_sha256,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    verify_command = commands.add_parser(
        "verify", help="verify two raw Python-distribution artifacts"
    )
    materialize_command = commands.add_parser(
        "materialize", help="verify and atomically expose all five distribution files"
    )
    for command in (verify_command, materialize_command):
        command.add_argument("--record", required=True)
        command.add_argument("--spine", required=True)
        command.add_argument("--record-artifact-sha256", required=True)
        command.add_argument("--spine-artifact-sha256", required=True)
        add_identity_arguments(command)
    materialize_command.add_argument("--output", required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        expected = expected_from_args(args)
        if args.command == "materialize":
            materialize(
                Path(args.record),
                Path(args.spine),
                Path(args.output),
                expected,
                record_artifact_sha256=args.record_artifact_sha256,
                spine_artifact_sha256=args.spine_artifact_sha256,
            )
        else:
            verify(
                Path(args.record),
                Path(args.spine),
                expected,
                record_artifact_sha256=args.record_artifact_sha256,
                spine_artifact_sha256=args.spine_artifact_sha256,
            )
    except SpineError as exc:
        sys.stderr.write(f"Python-distribution spine error: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
