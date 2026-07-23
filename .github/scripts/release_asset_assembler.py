#!/usr/bin/env python3
"""Assemble one exact, explicitly non-publishable release candidate inventory."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import dataclasses
import errno
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import build_python_artifacts
import python_distribution_spine

SCHEMA_VERSION = 1
RECORD_MEDIA_TYPE = "application/vnd.stampbot.release-asset-candidate.v1+json"
RECORD_NAME = "release-asset-candidate.json"
ASSET_DIRECTORY_NAME = "assets"
ASSET_POLICY = "current-dormant-release-inputs-v1"
ASSET_SCOPE = "current-dormant-release-inputs"
BLOCKING_ISSUES = (1, 18, 25, 28, 30, 32)
EXPECTED_ASSET_COUNT = 15
RELEASE_WORKFLOW_PATH = ".github/workflows/release.yml"
MAX_RECORD_BYTES = 256 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 16 * 1024 * 1024 * 1024
PYTHON_RECORD_NAMES = frozenset(
    {
        "python-build-record-amd64.json",
        "python-build-record-arm64.json",
        "python-selection-record.json",
    }
)
RENAME_NOREPLACE = 1
READ_CHUNK_BYTES = 1024 * 1024
SEMANTIC_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
SEMANTIC_TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9_-])?$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AssemblyError(RuntimeError):
    """The bounded release candidate inventory could not be proven."""


@dataclasses.dataclass(frozen=True)
class ReleaseIdentity:
    """Trusted release-workflow values bound into the candidate record."""

    tag: str
    version: str
    workflow_path: str
    workflow_sha: str


@dataclasses.dataclass(frozen=True)
class FileIdentity:
    """Stable metadata for one retained input descriptor."""

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
class RetainedFile:
    """One exact input file retained by descriptor through assembly."""

    name: str
    descriptor: int
    identity: FileIdentity


@dataclasses.dataclass(frozen=True)
class CandidateAsset:
    """One exact file in the current dormant candidate-input scope."""

    name: str
    relative_path: str
    size: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class CandidateRecord:
    """A validated record that is structurally forbidden from publication."""

    assets: tuple[CandidateAsset, ...]
    repository_id: int
    repository: str
    run_id: int
    tag: str
    version: str
    target_commit: str
    workflow_path: str
    workflow_sha: str
    record_sha256: str


@dataclasses.dataclass(frozen=True)
class AssemblyResult:
    """The atomically exposed local candidate directory and validated record."""

    directory: Path
    record: CandidateRecord


def _file_identity(metadata: os.stat_result, source: str) -> FileIdentity:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AssemblyError(f"{source} must be one single-link regular file")
    if not 1 <= metadata.st_size <= MAX_ASSET_BYTES:
        raise AssemblyError(f"{source} is outside its size limit")
    if metadata.st_uid != os.geteuid():
        raise AssemblyError(f"{source} is not owned by the assembler user")
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


def _directory_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _absolute_child(path: Path, source: str) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."} or ".." in path.parts:
        raise AssemblyError(f"{source} must be a safe absolute child path")
    return Path(os.path.abspath(path))


def _require_private_parent(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AssemblyError("cannot inspect the assembly output parent") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AssemblyError("assembly output parent must be an assembler-owned mode-0700 directory")


def _require_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AssemblyError("cannot inspect the assembly output path") from exc
    raise AssemblyError("assembly output path already exists")


def _open_directory(path: Path, source: str) -> tuple[int, tuple[int, ...]]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise AssemblyError("release assembly requires O_NOFOLLOW and O_DIRECTORY support")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AssemblyError(f"cannot open {source} safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise AssemblyError(f"{source} must be an assembler-owned directory")
        return descriptor, _directory_signature(metadata)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise


def _open_file_at(directory: int, name: str, source: str) -> RetainedFile:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError as exc:
        raise AssemblyError(f"cannot open {source} safely") from exc
    try:
        identity = _file_identity(os.fstat(descriptor), source)
        return RetainedFile(name=name, descriptor=descriptor, identity=identity)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise


@contextlib.contextmanager
def _open_exact_directory(
    path: Path,
    expected_names: frozenset[str],
    source: str,
) -> Iterator[Mapping[str, RetainedFile]]:
    """Retain every file from one exact flat input directory."""

    descriptor, identity = _open_directory(path, source)
    opened: dict[str, RetainedFile] = {}
    try:
        try:
            names = os.listdir(descriptor)
        except OSError as exc:
            raise AssemblyError(f"cannot list {source}") from exc
        if len(names) != len(set(names)):
            raise AssemblyError(f"{source} repeats a filename")
        if set(names) != set(expected_names):
            missing = sorted(set(expected_names).difference(names))
            unexpected = sorted(set(names).difference(expected_names))
            raise AssemblyError(
                f"{source} has the wrong exact file set; "
                f"missing={missing!r}, unexpected={unexpected!r}"
            )
        if len({name.casefold() for name in names}) != len(names):
            raise AssemblyError(f"{source} contains case-colliding filenames")
        for name in sorted(names):
            opened[name] = _open_file_at(descriptor, name, f"{source} file {name}")
        if _directory_signature(os.fstat(descriptor)) != identity:
            raise AssemblyError(f"{source} changed while it was retained")
        yield opened
        if _directory_signature(os.fstat(descriptor)) != identity:
            raise AssemblyError(f"{source} changed during assembly")
    except OSError as exc:
        raise AssemblyError(f"cannot retain {source}") from exc
    finally:
        close_error: OSError | None = None
        for retained in reversed(tuple(opened.values())):
            try:
                os.close(retained.descriptor)
            except OSError as exc:
                close_error = close_error or exc
        try:
            os.close(descriptor)
        except OSError as exc:
            close_error = close_error or exc
        if close_error is not None:
            raise AssemblyError(f"cannot close {source} safely") from close_error


def _descriptor_digest(retained: RetainedFile, source: str) -> str:
    digest = hashlib.sha256()
    position = 0
    remaining = retained.identity.size
    try:
        while remaining:
            chunk = os.pread(
                retained.descriptor,
                min(READ_CHUNK_BYTES, remaining),
                position,
            )
            if not chunk:
                raise AssemblyError(f"{source} was truncated while hashing")
            digest.update(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        if os.pread(retained.descriptor, 1, position):
            raise AssemblyError(f"{source} has trailing bytes")
        if _file_identity(os.fstat(retained.descriptor), source) != retained.identity:
            raise AssemblyError(f"{source} changed while it was hashed")
    except OSError as exc:
        raise AssemblyError(f"cannot hash {source}") from exc
    return digest.hexdigest()


def _write_all(descriptor: int, content: bytes, source: str) -> None:
    remaining = memoryview(content)
    while remaining:
        try:
            written = os.write(descriptor, remaining)
        except OSError as exc:
            raise AssemblyError(f"cannot write {source}") from exc
        if written <= 0:
            raise AssemblyError(f"cannot write {source}")
        remaining = remaining[written:]


def _copy_retained(
    retained: RetainedFile,
    destination_directory: int,
) -> CandidateAsset:
    """Copy one retained input without reopening its path."""

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        destination = os.open(
            retained.name,
            flags,
            0o600,
            dir_fd=destination_directory,
        )
    except OSError as exc:
        raise AssemblyError(f"cannot create release asset {retained.name}") from exc
    digest = hashlib.sha256()
    position = 0
    remaining = retained.identity.size
    try:
        os.fchmod(destination, 0o600)
        while remaining:
            try:
                chunk = os.pread(
                    retained.descriptor,
                    min(READ_CHUNK_BYTES, remaining),
                    position,
                )
            except OSError as exc:
                raise AssemblyError(f"cannot read release asset {retained.name}") from exc
            if not chunk:
                raise AssemblyError(f"release asset {retained.name} was truncated")
            digest.update(chunk)
            _write_all(destination, chunk, f"release asset {retained.name}")
            position += len(chunk)
            remaining -= len(chunk)
        if os.pread(retained.descriptor, 1, position):
            raise AssemblyError(f"release asset {retained.name} has trailing bytes")
        os.fsync(destination)
        destination_identity = _file_identity(
            os.fstat(destination),
            f"assembled release asset {retained.name}",
        )
        if (
            destination_identity.size != retained.identity.size
            or stat.S_IMODE(destination_identity.mode) != 0o600
            or _file_identity(
                os.fstat(retained.descriptor),
                f"release asset {retained.name}",
            )
            != retained.identity
        ):
            raise AssemblyError(f"release asset {retained.name} changed while copied")
    except OSError as exc:
        raise AssemblyError(f"cannot finish release asset {retained.name}") from exc
    finally:
        try:
            os.close(destination)
        except OSError as exc:
            raise AssemblyError(f"cannot close assembled release asset {retained.name}") from exc
    return CandidateAsset(
        name=retained.name,
        relative_path=retained.name,
        size=retained.identity.size,
        sha256=digest.hexdigest(),
    )


def _expected_names(
    version: str,
) -> tuple[
    frozenset[str],
    frozenset[str],
    frozenset[str],
    str,
    str,
]:
    if SEMANTIC_VERSION.fullmatch(version) is None:
        raise AssemblyError("release version must be an exact MAJOR.MINOR.PATCH value")
    wheel = f"extra_codeowners-{version}-py3-none-any.whl"
    sdist = f"extra_codeowners-{version}.tar.gz"
    python_signed = frozenset(
        {
            wheel,
            f"{wheel}.sigstore.json",
            sdist,
            f"{sdist}.sigstore.json",
        }
    )
    image_security = frozenset(
        {
            "image-sbom-linux-amd64.spdx.json",
            "image-sbom-linux-amd64.spdx.json.sigstore.json",
            "image-sbom-linux-arm64.spdx.json",
            "image-sbom-linux-arm64.spdx.json.sigstore.json",
            f"extra-codeowners-{version}.openvex.json",
            f"extra-codeowners-{version}.openvex.json.sigstore.json",
        }
    )
    chart = f"extra-codeowners-{version}.tgz"
    chart_files = frozenset({chart, f"{chart}.sigstore.json"})
    return python_signed, image_security, chart_files, wheel, sdist


def _validate_release_identity(
    python_identity: python_distribution_spine.ExpectedIdentity,
    release_identity: ReleaseIdentity,
) -> tuple[int, int]:
    if release_identity.tag != f"v{release_identity.version}":
        raise AssemblyError("release tag and version disagree")
    if release_identity.workflow_sha != python_identity.source_revision:
        raise AssemblyError("release workflow SHA and source revision disagree")
    if release_identity.workflow_path != RELEASE_WORKFLOW_PATH:
        raise AssemblyError("release workflow path is not the reviewed tagged workflow")
    if python_identity.workflow_sha != python_identity.source_revision:
        raise AssemblyError("Python proof workflow SHA and source revision disagree")
    try:
        repository_id = int(python_identity.repository_id)
        run_id = int(python_identity.run_id)
    except ValueError as exc:
        raise AssemblyError("Python proof repository or run ID is not decimal") from exc
    if str(repository_id) != python_identity.repository_id:
        raise AssemblyError("Python proof repository ID is not canonical decimal")
    if str(run_id) != python_identity.run_id:
        raise AssemblyError("Python proof run ID is not canonical decimal")
    return repository_id, run_id


def _record_value(
    assets: Sequence[CandidateAsset],
    python_identity: python_distribution_spine.ExpectedIdentity,
    release_identity: ReleaseIdentity,
    repository_id: int,
    run_id: int,
) -> dict[str, object]:
    return {
        "assets": [
            {
                "name": asset.name,
                "path": asset.relative_path,
                "sha256": asset.sha256,
                "size": asset.size,
            }
            for asset in assets
        ],
        "candidate": {
            "asset_count": EXPECTED_ASSET_COUNT,
            "asset_policy": ASSET_POLICY,
            "asset_scope": ASSET_SCOPE,
            "blocking_issues": list(BLOCKING_ISSUES),
            "controller_manifest": False,
            "final_asset_policy_frozen": False,
            "non_python_payload_semantics_verified": False,
            "publication_allowed": False,
            "source_completeness": False,
        },
        "identity": {
            "repository": python_identity.repository_name,
            "repository_id": repository_id,
            "run_id": run_id,
            "tag": release_identity.tag,
            "target_commit": python_identity.source_revision,
            "version": release_identity.version,
            "workflow_path": release_identity.workflow_path,
            "workflow_sha": release_identity.workflow_sha,
        },
        "media_type": RECORD_MEDIA_TYPE,
        "schema_version": SCHEMA_VERSION,
    }


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AssemblyError(f"{source} must contain exactly {sorted(fields)}")
    return value


def _exact_integer(value: object, source: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise AssemblyError(f"{source} is outside its integer bounds")
    return value


def _exact_integer_list(
    value: object,
    source: str,
    *,
    minimum: int,
    maximum: int,
) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise AssemblyError(f"{source} must be a JSON array")
    return tuple(
        _exact_integer(
            item,
            f"{source} item {position}",
            minimum=minimum,
            maximum=maximum,
        )
        for position, item in enumerate(value)
    )


def _exact_string(
    value: object,
    source: str,
    pattern: re.Pattern[str],
    *,
    maximum: int,
) -> str:
    if not isinstance(value, str) or len(value) > maximum or pattern.fullmatch(value) is None:
        raise AssemblyError(f"{source} has an invalid value")
    return value


def _expected_asset_set(version: str) -> frozenset[str]:
    python_signed, image_security, chart, _, _ = _expected_names(version)
    return frozenset(
        {
            *PYTHON_RECORD_NAMES,
            *python_signed,
            *image_security,
            *chart,
        }
    )


def validate_candidate_record(value: object, record_sha256: str) -> CandidateRecord:
    """Validate the publication-blocked record without accepting a controller plan."""

    root = _exact_mapping(
        value,
        {"assets", "candidate", "identity", "media_type", "schema_version"},
        "release candidate record",
    )
    if (
        _exact_integer(
            root["schema_version"],
            "release candidate schema version",
            minimum=SCHEMA_VERSION,
            maximum=SCHEMA_VERSION,
        )
        != SCHEMA_VERSION
        or root["media_type"] != RECORD_MEDIA_TYPE
    ):
        raise AssemblyError("release candidate record has the wrong schema identity")
    candidate = _exact_mapping(
        root["candidate"],
        {
            "asset_count",
            "asset_policy",
            "asset_scope",
            "blocking_issues",
            "controller_manifest",
            "final_asset_policy_frozen",
            "non_python_payload_semantics_verified",
            "publication_allowed",
            "source_completeness",
        },
        "release candidate state",
    )
    blocking_issues = _exact_integer_list(
        candidate["blocking_issues"],
        "release candidate blocking issues",
        minimum=1,
        maximum=2**63 - 1,
    )
    asset_count = _exact_integer(
        candidate["asset_count"],
        "release candidate asset count",
        minimum=EXPECTED_ASSET_COUNT,
        maximum=EXPECTED_ASSET_COUNT,
    )
    if (
        asset_count != EXPECTED_ASSET_COUNT
        or candidate["asset_policy"] != ASSET_POLICY
        or candidate["asset_scope"] != ASSET_SCOPE
        or blocking_issues != BLOCKING_ISSUES
        or candidate["controller_manifest"] is not False
        or candidate["final_asset_policy_frozen"] is not False
        or candidate["non_python_payload_semantics_verified"] is not False
        or candidate["publication_allowed"] is not False
        or candidate["source_completeness"] is not False
    ):
        raise AssemblyError("release candidate state is not publication-blocked")

    identity = _exact_mapping(
        root["identity"],
        {
            "repository",
            "repository_id",
            "run_id",
            "tag",
            "target_commit",
            "version",
            "workflow_path",
            "workflow_sha",
        },
        "release candidate identity",
    )
    repository_id = _exact_integer(
        identity["repository_id"],
        "release candidate repository ID",
        minimum=1,
        maximum=2**63 - 1,
    )
    repository = _exact_string(
        identity["repository"],
        "release candidate repository",
        REPOSITORY,
        maximum=256,
    )
    run_id = _exact_integer(
        identity["run_id"],
        "release candidate run ID",
        minimum=1,
        maximum=2**63 - 1,
    )
    version = _exact_string(
        identity["version"],
        "release candidate version",
        SEMANTIC_VERSION,
        maximum=64,
    )
    tag = _exact_string(
        identity["tag"],
        "release candidate tag",
        SEMANTIC_TAG,
        maximum=64,
    )
    if tag != f"v{version}":
        raise AssemblyError("release candidate tag and version disagree")
    target_commit = _exact_string(
        identity["target_commit"],
        "release candidate target commit",
        HEX40,
        maximum=40,
    )
    workflow_path = identity["workflow_path"]
    if workflow_path != RELEASE_WORKFLOW_PATH:
        raise AssemblyError("release candidate has an unreviewed workflow path")
    workflow_sha = _exact_string(
        identity["workflow_sha"],
        "release candidate workflow SHA",
        HEX40,
        maximum=40,
    )
    if workflow_sha != target_commit:
        raise AssemblyError("release candidate workflow SHA and target commit disagree")

    raw_assets = root["assets"]
    if not isinstance(raw_assets, list) or len(raw_assets) != EXPECTED_ASSET_COUNT:
        raise AssemblyError("release candidate record has the wrong asset count")
    expected_assets = _expected_asset_set(version)
    assets: list[CandidateAsset] = []
    total = 0
    for position, raw_asset in enumerate(raw_assets):
        item = _exact_mapping(
            raw_asset,
            {"name", "path", "sha256", "size"},
            f"release candidate asset {position}",
        )
        name = _exact_string(
            item["name"],
            "release candidate asset name",
            SAFE_NAME,
            maximum=255,
        )
        if item["path"] != name:
            raise AssemblyError(f"release candidate asset {name} has a non-flat path")
        size = _exact_integer(
            item["size"],
            f"release candidate asset {name} size",
            minimum=1,
            maximum=MAX_ASSET_BYTES,
        )
        digest = _exact_string(
            item["sha256"],
            f"release candidate asset {name} SHA-256",
            HEX64,
            maximum=64,
        )
        if size > MAX_TOTAL_ASSET_BYTES - total:
            raise AssemblyError("release candidate assets exceed the total size limit")
        total += size
        assets.append(CandidateAsset(name, name, size, digest))
    names = [asset.name for asset in assets]
    if names != sorted(names) or len(names) != len(set(names)):
        raise AssemblyError("release candidate assets are not unique and sorted")
    if set(names) != set(expected_assets):
        raise AssemblyError("release candidate record has the wrong exact asset set")
    if len({name.casefold() for name in names}) != len(names):
        raise AssemblyError("release candidate assets contain case-colliding names")
    digest = _exact_string(
        record_sha256,
        "release candidate record SHA-256",
        HEX64,
        maximum=64,
    )
    if hashlib.sha256(python_distribution_spine.canonical_json(value)).hexdigest() != digest:
        raise AssemblyError("release candidate record differs from its supplied SHA-256")
    return CandidateRecord(
        assets=tuple(assets),
        repository_id=repository_id,
        repository=repository,
        run_id=run_id,
        tag=tag,
        version=version,
        target_commit=target_commit,
        workflow_path=workflow_path,
        workflow_sha=workflow_sha,
        record_sha256=digest,
    )


def load_candidate_record(path: Path) -> CandidateRecord:
    """Read one bounded canonical candidate record from a retained descriptor."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AssemblyError("cannot open the release candidate record safely") from exc
    try:
        before = _file_identity(os.fstat(descriptor), "release candidate record")
        if before.size > MAX_RECORD_BYTES:
            raise AssemblyError("release candidate record exceeds its size limit")
        chunks: list[bytes] = []
        remaining = before.size
        while remaining:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise AssemblyError("release candidate record was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise AssemblyError("release candidate record has trailing bytes")
        if _file_identity(os.fstat(descriptor), "release candidate record") != before:
            raise AssemblyError("release candidate record changed while it was read")
    except OSError as exc:
        raise AssemblyError("cannot read the release candidate record safely") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            raise AssemblyError("cannot close the release candidate record safely") from exc
    raw = b"".join(chunks)
    try:
        value = python_distribution_spine.strict_json_bytes(
            raw,
            "release candidate record",
            canonical=True,
        )
    except python_distribution_spine.SpineError as exc:
        raise AssemblyError(
            f"release candidate record is not strict canonical JSON: {exc}"
        ) from exc
    return validate_candidate_record(value, hashlib.sha256(raw).hexdigest())


def _write_record(path: Path, content: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AssemblyError("cannot create the release candidate record safely") from exc
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, content, "release candidate record")
        os.fsync(descriptor)
        identity = _file_identity(os.fstat(descriptor), "assembled release candidate record")
        if identity.size != len(content) or stat.S_IMODE(identity.mode) != 0o600:
            raise AssemblyError("assembled release candidate record has the wrong identity")
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            raise AssemblyError("cannot close the release candidate record safely") from exc


def _rename_noreplace(source: Path, destination: Path) -> None:
    if sys.platform != "linux":
        raise AssemblyError("atomic no-replace assembly requires Linux")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise AssemblyError(
            "Linux renameat2 is unavailable; refusing to expose the candidate"
        ) from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise AssemblyError("assembly output path appeared before publication")
    if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise AssemblyError("atomic no-replace assembly is unavailable")
    raise AssemblyError(f"atomic no-replace assembly failed with errno {error}")


def _remove_owned_tree(path: Path) -> None:
    with contextlib.suppress(OSError):
        shutil.rmtree(path)


def _fsync_directory(path: Path, source: str) -> None:
    descriptor, _ = _open_directory(path, source)
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise AssemblyError(f"cannot sync {source}") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            raise AssemblyError(f"cannot close {source}") from exc


def _require_complete_output(path: Path, expected_assets: frozenset[str]) -> None:
    entries = {entry.name for entry in path.iterdir()}
    if entries != {ASSET_DIRECTORY_NAME, RECORD_NAME}:
        raise AssemblyError("assembled candidate directory has an unexpected entry")
    assets = path / ASSET_DIRECTORY_NAME
    if {entry.name for entry in assets.iterdir()} != set(expected_assets):
        raise AssemblyError("assembled asset directory is not the complete exact set")


def _verify_candidate_assets(path: Path, record: CandidateRecord) -> None:
    expected = frozenset(asset.name for asset in record.assets)
    with _open_exact_directory(path, expected, "assembled candidate assets") as retained:
        for asset in record.assets:
            source = retained[asset.name]
            if (
                source.identity.size != asset.size
                or _descriptor_digest(source, f"assembled candidate asset {asset.name}")
                != asset.sha256
            ):
                raise AssemblyError(
                    f"assembled candidate asset {asset.name} differs from its record"
                )


def assemble(
    *,
    record_path: Path,
    spine_path: Path,
    output_directory: Path,
    python_signed_directory: Path,
    image_security_directory: Path,
    chart_directory: Path,
    python_identity: python_distribution_spine.ExpectedIdentity,
    record_artifact_sha256: str,
    spine_artifact_sha256: str,
    release_identity: ReleaseIdentity,
) -> AssemblyResult:
    """Materialize the raw Python spine and inventory current candidate inputs."""

    output = _absolute_child(output_directory, "assembly output")
    _require_private_parent(output.parent)
    _require_absent(output)
    repository_id, run_id = _validate_release_identity(
        python_identity,
        release_identity,
    )
    (
        expected_python_signed,
        expected_image_security,
        expected_chart,
        wheel_name,
        sdist_name,
    ) = _expected_names(release_identity.version)
    expected_materialized = frozenset({*PYTHON_RECORD_NAMES, wheel_name, sdist_name})
    expected_assets = _expected_asset_set(release_identity.version)
    if len(expected_assets) != EXPECTED_ASSET_COUNT:
        raise AssemblyError("internal candidate asset policy has the wrong expected name count")

    staging = Path(
        tempfile.mkdtemp(
            prefix=f".release-asset-assembly-{os.getpid()}-",
            dir=output.parent,
        )
    )
    staging.chmod(0o700)
    published = False
    try:
        materialized = staging / "python-materialized"
        python_distribution_spine.materialize(
            record_path,
            spine_path,
            materialized,
            python_identity,
            record_artifact_sha256=record_artifact_sha256,
            spine_artifact_sha256=spine_artifact_sha256,
        )
        verification = build_python_artifacts.verify_selection(
            materialized,
            source_revision=python_identity.source_revision,
            wheel_sha256=python_identity.wheel_sha256,
            selection_record_sha256=python_identity.selection_record_sha256,
        )
        if (
            verification.get("wheel_filename") != wheel_name
            or verification.get("sdist_filename") != sdist_name
            or verification.get("wheel_sha256") != python_identity.wheel_sha256
            or verification.get("selection_record_sha256")
            != python_identity.selection_record_sha256
        ):
            raise AssemblyError("revalidated Python selection has the wrong release identity")

        assets_directory = staging / ASSET_DIRECTORY_NAME
        assets_directory.mkdir(mode=0o700)
        assets_descriptor, _ = _open_directory(
            assets_directory,
            "assembly asset destination",
        )
        try:
            with contextlib.ExitStack() as stack:
                materialized_files = stack.enter_context(
                    _open_exact_directory(
                        materialized,
                        expected_materialized,
                        "materialized Python distribution",
                    )
                )
                signed_files = stack.enter_context(
                    _open_exact_directory(
                        python_signed_directory,
                        expected_python_signed,
                        "signed Python artifacts",
                    )
                )
                image_files = stack.enter_context(
                    _open_exact_directory(
                        image_security_directory,
                        expected_image_security,
                        "image security metadata",
                    )
                )
                chart_files = stack.enter_context(
                    _open_exact_directory(
                        chart_directory,
                        expected_chart,
                        "signed Helm chart",
                    )
                )

                for archive_name in (wheel_name, sdist_name):
                    materialized_archive = materialized_files[archive_name]
                    signed_archive = signed_files[archive_name]
                    if (
                        materialized_archive.identity.size != signed_archive.identity.size
                        or _descriptor_digest(
                            materialized_archive,
                            f"materialized Python archive {archive_name}",
                        )
                        != _descriptor_digest(
                            signed_archive,
                            f"signed Python archive {archive_name}",
                        )
                    ):
                        raise AssemblyError(
                            f"signed Python archive {archive_name} differs from the raw spine"
                        )

                candidates: dict[str, RetainedFile] = {
                    name: materialized_files[name] for name in expected_materialized
                }
                for name in expected_python_signed.difference({wheel_name, sdist_name}):
                    candidates[name] = signed_files[name]
                candidates.update(image_files)
                candidates.update(chart_files)
                if set(candidates) != set(expected_assets):
                    raise AssemblyError("candidate release asset set is incomplete or duplicated")
                if len({name.casefold() for name in candidates}) != len(candidates):
                    raise AssemblyError("candidate release assets contain case-colliding names")
                candidate_size = sum(file.identity.size for file in candidates.values())
                if candidate_size > MAX_TOTAL_ASSET_BYTES:
                    raise AssemblyError("candidate release assets exceed the total size limit")

                assets = tuple(
                    _copy_retained(candidates[name], assets_descriptor)
                    for name in sorted(candidates)
                )
            populated_identity = _directory_signature(os.fstat(assets_descriptor))
            os.fsync(assets_descriptor)
            if _directory_signature(os.fstat(assets_descriptor)) != populated_identity:
                raise AssemblyError("assembly asset destination changed while it was synced")
        finally:
            try:
                os.close(assets_descriptor)
            except OSError as exc:
                raise AssemblyError("cannot close the assembly asset destination") from exc

        shutil.rmtree(materialized)
        record_value = _record_value(
            assets,
            python_identity,
            release_identity,
            repository_id,
            run_id,
        )
        record_bytes = python_distribution_spine.canonical_json(record_value)
        candidate_record_path = staging / RECORD_NAME
        _write_record(candidate_record_path, record_bytes)
        candidate_record = load_candidate_record(candidate_record_path)
        if len(candidate_record.assets) != EXPECTED_ASSET_COUNT or {
            asset.name for asset in candidate_record.assets
        } != set(expected_assets):
            raise AssemblyError("candidate record does not retain the complete scoped asset set")
        _verify_candidate_assets(assets_directory, candidate_record)
        _require_complete_output(staging, expected_assets)
        _fsync_directory(staging, "assembled candidate directory")
        _require_absent(output)
        _rename_noreplace(staging, output)
        published = True
        _fsync_directory(output.parent, "assembly output parent")
        _require_complete_output(output, expected_assets)
        return AssemblyResult(directory=output, record=candidate_record)
    except (
        build_python_artifacts.BuildError,
        python_distribution_spine.SpineError,
        OSError,
    ) as exc:
        raise AssemblyError(f"release asset assembly failed closed: {exc}") from exc
    finally:
        if not published:
            _remove_owned_tree(staging)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--record", required=True)
    result.add_argument("--spine", required=True)
    result.add_argument("--output", required=True)
    result.add_argument("--python-signed-directory", required=True)
    result.add_argument("--image-security-directory", required=True)
    result.add_argument("--chart-directory", required=True)
    result.add_argument("--record-artifact-sha256", required=True)
    result.add_argument("--spine-artifact-sha256", required=True)
    python_distribution_spine.add_identity_arguments(result)
    result.add_argument("--tag", required=True)
    result.add_argument("--version", required=True)
    result.add_argument("--release-workflow-path", required=True)
    result.add_argument("--release-workflow-sha", required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        python_identity = python_distribution_spine.expected_from_args(args)
        result = assemble(
            record_path=Path(args.record),
            spine_path=Path(args.spine),
            output_directory=Path(args.output),
            python_signed_directory=Path(args.python_signed_directory),
            image_security_directory=Path(args.image_security_directory),
            chart_directory=Path(args.chart_directory),
            python_identity=python_identity,
            record_artifact_sha256=args.record_artifact_sha256,
            spine_artifact_sha256=args.spine_artifact_sha256,
            release_identity=ReleaseIdentity(
                tag=args.tag,
                version=args.version,
                workflow_path=args.release_workflow_path,
                workflow_sha=args.release_workflow_sha,
            ),
        )
    except AssemblyError as exc:
        sys.stderr.write(f"Release asset assembly error: {exc}\n")
        return 1
    sys.stdout.write(f"candidate-record-sha256={result.record.record_sha256}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
