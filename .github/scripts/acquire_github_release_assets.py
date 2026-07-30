#!/usr/bin/env python3
"""Acquire exact authenticated GitHub release assets without parsing them."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import dataclasses
import errno
import hashlib
import os
import re
import secrets
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, cast

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_github_release as github_release  # noqa: E402
from release_controller import (  # noqa: E402
    MAX_ASSETS,
    MAX_ID,
    MAX_MANIFEST_BYTES,
    SAFE_SEGMENT,
    Asset,
    ControllerError,
    ReleasePlan,
    canonical_json,
    load_manifest,
)

SCHEMA_VERSION = 1
RECORD_KIND = "extra-codeowners/acquired-github-release-assets"
MAX_AUTHENTICATED_RECORD_BYTES = MAX_MANIFEST_BYTES
MAX_INVENTORY_ENTRIES = MAX_ASSETS
MAX_CLEANUP_ENTRIES = MAX_INVENTORY_ENTRIES + 32
MAX_CLEANUP_DEPTH = 8
RENAME_NOREPLACE = 1
SEMANTIC_VERSION = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AcquisitionError(RuntimeError):
    """Authenticated release assets could not be acquired safely."""


class AcquisitionClient(Protocol):
    """Read-only GitHub operations needed by the acquisition boundary."""

    def check_version(self) -> str:
        raise NotImplementedError

    def api(self, endpoint: str) -> object:
        raise NotImplementedError

    def download_asset(
        self,
        repository: str,
        asset_id: int,
        destination: int,
        maximum_bytes: int,
    ) -> tuple[int, str]:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class AuthenticatedRelease:
    """The exact hash-bound release proof accepted as acquisition input."""

    record_sha256: str
    owner_id: int
    release_id: int
    release_url: str
    attestation_payload_sha256: str
    attestation_subject_sha1: str


@dataclasses.dataclass(frozen=True)
class RemoteSnapshot:
    """One complete live GitHub identity and asset-ID observation."""

    repository: github_release.RepositoryIdentity
    tag: github_release.TagIdentity
    release: github_release.ReleaseIdentity
    assets: tuple[tuple[str, int], ...]


@dataclasses.dataclass(frozen=True)
class RetainedAsset:
    """One downloaded file retained through atomic directory promotion."""

    asset: Asset
    descriptor: int
    identity: tuple[int, ...]


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_uid,
        left.st_gid,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_uid,
        right.st_gid,
    )


def _read_canonical_record(path: Path, expected_sha256: str) -> tuple[Mapping[str, Any], str]:
    if HEX64.fullmatch(expected_sha256) is None:
        raise AcquisitionError("trusted authenticated-release record SHA-256 is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise AcquisitionError("authenticated release acquisition requires O_NOFOLLOW")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AcquisitionError("cannot open authenticated release record safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AcquisitionError(
                "authenticated release record must be one single-link regular file"
            )
        if not 1 <= before.st_size <= MAX_AUTHENTICATED_RECORD_BYTES:
            raise AcquisitionError("authenticated release record is outside its byte bound")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(github_release.READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise AcquisitionError("authenticated release record was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise AcquisitionError("authenticated release record has trailing bytes")
        after = os.fstat(descriptor)
        if _file_identity(after) != _file_identity(before):
            raise AcquisitionError("authenticated release record changed while reading")
    except OSError as exc:
        raise AcquisitionError("cannot read authenticated release record safely") from exc
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)

    raw = b"".join(chunks)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise AcquisitionError("authenticated release record does not match the trusted SHA-256")
    try:
        value: object = github_release.strict_json(
            raw,
            "authenticated release record",
            maximum=MAX_AUTHENTICATED_RECORD_BYTES,
        )
    except github_release.VerificationError as exc:
        raise AcquisitionError("authenticated release record is not strict bounded JSON") from exc
    if canonical_json(value) != raw:
        raise AcquisitionError("authenticated release record is not canonical JSON")
    if not isinstance(value, dict):
        raise AcquisitionError("authenticated release record is not a JSON object")
    return cast(Mapping[str, Any], value), expected_sha256


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AcquisitionError(f"{source} must contain exactly {sorted(fields)}")
    return cast(Mapping[str, Any], value)


def _positive_id(value: object, source: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ID:
        raise AcquisitionError(f"{source} is outside its integer bounds")
    return value


def _lower_digest(value: object, source: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AcquisitionError(f"{source} is invalid")
    return value


def _validated_version(value: object, source: str) -> str:
    if not isinstance(value, str):
        raise AcquisitionError(f"{source} is invalid")
    match = SEMANTIC_VERSION.fullmatch(value)
    if match is None:
        raise AcquisitionError(f"{source} is invalid")
    if tuple(int(part) for part in match.groups()) < github_release.MINIMUM_GH_VERSION:
        raise AcquisitionError(f"{source} predates the minimum supported GitHub CLI")
    return value


def load_authenticated_release(
    path: Path,
    *,
    expected_sha256: str,
    plan: ReleasePlan,
) -> AuthenticatedRelease:
    """Load and bind one canonical authenticated-release record."""

    value, record_sha256 = _read_canonical_record(path, expected_sha256)
    record = _exact_mapping(
        value,
        {
            "assets",
            "controller_manifest",
            "github_cli",
            "kind",
            "release",
            "repository",
            "schema_version",
            "tag",
        },
        "authenticated release record",
    )
    if (
        not isinstance(record["schema_version"], int)
        or isinstance(record["schema_version"], bool)
        or record["schema_version"] != github_release.SCHEMA_VERSION
    ):
        raise AcquisitionError("authenticated release record has an unsupported schema")
    if record["kind"] != github_release.RECORD_KIND:
        raise AcquisitionError("authenticated release record has an unsupported kind")

    controller_manifest = _exact_mapping(
        record["controller_manifest"],
        {"sha256"},
        "authenticated release controller manifest",
    )
    if controller_manifest["sha256"] != plan.manifest_sha256:
        raise AcquisitionError("authenticated release record names a different controller manifest")

    cli = _exact_mapping(
        record["github_cli"],
        {"minimum_version", "version"},
        "authenticated release GitHub CLI",
    )
    if cli["minimum_version"] != github_release.MINIMUM_GH_VERSION_TEXT:
        raise AcquisitionError("authenticated release record has a different CLI minimum")
    _validated_version(cli["version"], "authenticated release GitHub CLI version")

    repository = _exact_mapping(
        record["repository"],
        {"id", "name", "owner_id"},
        "authenticated release repository",
    )
    if (
        _positive_id(repository["id"], "authenticated release repository ID") != plan.repository_id
        or repository["name"] != plan.repository
    ):
        raise AcquisitionError("authenticated release record names a different repository")
    owner_id = _positive_id(repository["owner_id"], "authenticated release owner ID")

    tag = _exact_mapping(
        record["tag"],
        {"attestation_subject_sha1", "name", "target_commit"},
        "authenticated release tag",
    )
    if tag["name"] != plan.tag or tag["target_commit"] != plan.target_commit:
        raise AcquisitionError("authenticated release record names a different tag")
    attestation_subject_sha1 = _lower_digest(
        tag["attestation_subject_sha1"],
        "authenticated release attestation subject SHA-1",
        HEX40,
    )

    release = _exact_mapping(
        record["release"],
        {
            "attestation_payload_sha256",
            "attestation_predicate_type",
            "id",
            "immutable",
            "url",
        },
        "authenticated release",
    )
    release_id = _positive_id(release["id"], "authenticated release ID")
    release_url = f"https://github.com/{plan.repository}/releases/tag/{plan.tag}"
    if (
        release["url"] != release_url
        or release["immutable"] is not True
        or release["attestation_predicate_type"] != github_release.RELEASE_PREDICATE_TYPE
    ):
        raise AcquisitionError("authenticated release record has a different release identity")
    attestation_payload_sha256 = _lower_digest(
        release["attestation_payload_sha256"],
        "authenticated release attestation payload SHA-256",
        HEX64,
    )

    raw_assets = record["assets"]
    if not isinstance(raw_assets, list) or len(raw_assets) != len(plan.assets):
        raise AcquisitionError("authenticated release record has a different asset inventory")
    for index, (raw_asset, asset) in enumerate(zip(raw_assets, plan.assets, strict=True)):
        item = _exact_mapping(
            raw_asset,
            {"name", "sha256", "size"},
            f"authenticated release asset {index}",
        )
        if (
            not isinstance(item["name"], str)
            or item["name"] != asset.name
            or not isinstance(item["sha256"], str)
            or item["sha256"] != asset.sha256
            or not isinstance(item["size"], int)
            or isinstance(item["size"], bool)
            or item["size"] != asset.size
        ):
            raise AcquisitionError("authenticated release record has a different asset inventory")

    return AuthenticatedRelease(
        record_sha256=record_sha256,
        owner_id=owner_id,
        release_id=release_id,
        release_url=release_url,
        attestation_payload_sha256=attestation_payload_sha256,
        attestation_subject_sha1=attestation_subject_sha1,
    )


def _remote_snapshot(
    client: AcquisitionClient,
    plan: ReleasePlan,
    authenticated: AuthenticatedRelease,
) -> RemoteSnapshot:
    repository = github_release._validate_repository(
        client.api(github_release._repository_endpoint(plan.repository)),
        plan,
    )
    if repository.owner_id != authenticated.owner_id:
        raise AcquisitionError("GitHub repository owner differs from the authenticated release")
    tag = github_release._resolve_tag(
        cast(github_release.GitHubClient, client),
        plan,
    )
    if (
        tag.target_commit != plan.target_commit
        or tag.attestation_subject_sha1 != authenticated.attestation_subject_sha1
    ):
        raise AcquisitionError("GitHub tag differs from the authenticated release")
    release = github_release._validate_release(
        client.api(github_release._release_id_endpoint(plan, authenticated.release_id)),
        plan,
        expected_id=authenticated.release_id,
    )
    if release.url != authenticated.release_url:
        raise AcquisitionError("GitHub release differs from the authenticated release")
    assets = github_release._validate_assets(
        client.api(github_release._assets_endpoint(plan, authenticated.release_id)),
        plan,
    )
    return RemoteSnapshot(repository, tag, release, assets)


def _open_directory_at(parent: int, name: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise AcquisitionError("release asset acquisition requires directory no-follow support")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory,
            dir_fd=parent,
        )
    except OSError as exc:
        raise AcquisitionError("cannot open acquisition directory safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise AcquisitionError("acquisition path is not a directory")
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    return descriptor


def _open_output_parent(path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise AcquisitionError("release asset acquisition requires directory no-follow support")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory,
        )
    except OSError as exc:
        raise AcquisitionError("cannot open output parent safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise AcquisitionError("output parent is not a directory")
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    return descriptor


def _require_absent(parent: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AcquisitionError("cannot inspect requested output directory") from exc
    raise AcquisitionError("requested output directory already exists")


def _create_staging(parent: int) -> tuple[str, int]:
    for _attempt in range(32):
        name = f".github-release-assets-{os.getpid()}-{secrets.token_hex(8)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            continue
        except OSError as exc:
            raise AcquisitionError("cannot create private acquisition directory") from exc
        descriptor = -1
        try:
            descriptor = _open_directory_at(parent, name)
            os.fchmod(descriptor, 0o700)
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise AcquisitionError("private acquisition directory has the wrong mode")
            return name, descriptor
        except BaseException:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            with contextlib.suppress(OSError):
                os.rmdir(name, dir_fd=parent)
            raise
    raise AcquisitionError("cannot allocate a unique acquisition directory")


def _create_asset(root: int, asset: Asset) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | nofollow
    )
    try:
        descriptor = os.open(
            asset.name,
            flags,
            0o600,
            dir_fd=root,
        )
    except OSError as exc:
        raise AcquisitionError(f"cannot create destination for release asset {asset.name}") from exc
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_size != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise AcquisitionError(
                f"destination for release asset {asset.name} is not one private empty file"
            )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise
    return descriptor


def _verify_descriptor(
    descriptor: int,
    asset: Asset,
    *,
    expected_identity: tuple[int, ...] | None = None,
) -> tuple[int, ...]:
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_size != asset.size
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise AcquisitionError(f"release asset {asset.name} has an unsafe local identity")
        digest = hashlib.sha256()
        position = 0
        remaining = asset.size
        while remaining:
            chunk = os.pread(
                descriptor,
                min(github_release.READ_CHUNK_BYTES, remaining),
                position,
            )
            if not chunk:
                raise AcquisitionError(f"release asset {asset.name} was truncated")
            digest.update(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        if os.pread(descriptor, 1, position):
            raise AcquisitionError(f"release asset {asset.name} has trailing bytes")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AcquisitionError(f"cannot verify release asset {asset.name}") from exc
    identity = _file_identity(before)
    if _file_identity(after) != identity:
        raise AcquisitionError(f"release asset {asset.name} changed while hashing")
    if expected_identity is not None and identity != expected_identity:
        raise AcquisitionError(f"release asset {asset.name} changed after download")
    if digest.hexdigest() != asset.sha256:
        raise AcquisitionError(f"release asset {asset.name} has the wrong SHA-256")
    return identity


def _inventory(directory: int) -> set[str]:
    files: set[str] = set()
    try:
        os.lseek(directory, 0, os.SEEK_SET)
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(files) >= MAX_INVENTORY_ENTRIES:
                    raise AcquisitionError("acquired asset directory exceeds its entry bound")
                if SAFE_SEGMENT.fullmatch(entry.name) is None:
                    raise AcquisitionError("acquired asset directory contains an unsafe name")
                metadata = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    raise AcquisitionError("acquired asset directory contains a non-regular entry")
                files.add(entry.name)
    except OSError as exc:
        raise AcquisitionError("cannot inventory acquired release assets safely") from exc
    return files


def _open_existing_asset(root: int, asset: Asset) -> int:
    try:
        descriptor = os.open(
            asset.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root,
        )
    except OSError as exc:
        raise AcquisitionError(f"cannot reopen release asset {asset.name}") from exc
    return descriptor


def _require_tree_matches(
    root: int,
    plan: ReleasePlan,
    retained: Sequence[RetainedAsset],
) -> None:
    files = _inventory(root)
    if files != {asset.name for asset in plan.assets}:
        raise AcquisitionError("acquired asset directory has an unexpected inventory")
    by_name = {item.asset.name: item for item in retained}
    for asset in plan.assets:
        current = _open_existing_asset(root, asset)
        try:
            identity = _verify_descriptor(current, asset)
        finally:
            with contextlib.suppress(OSError):
                os.close(current)
        if identity != by_name[asset.name].identity:
            raise AcquisitionError(f"release asset path {asset.name} was replaced")


def _require_retained_directory(parent: int, name: str, directory: int) -> None:
    try:
        retained = os.fstat(directory)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        raise AcquisitionError("private acquisition directory changed") from exc
    if not stat.S_ISDIR(current.st_mode) or not _same_file(retained, current):
        raise AcquisitionError("private acquisition directory changed")


def _require_output_parent_unchanged(path: Path, directory: int) -> None:
    try:
        retained = os.fstat(directory)
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise AcquisitionError("output parent changed") from exc
    if not stat.S_ISDIR(current.st_mode) or not _same_file(retained, current):
        raise AcquisitionError("output parent changed")


def _rename_noreplace(parent: int, source: str, destination: str) -> None:
    if sys.platform != "linux":
        raise AcquisitionError("atomic acquisition output requires Linux")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError):
        raise AcquisitionError("atomic no-replace rename is unavailable") from None
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent,
        os.fsencode(source),
        parent,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise AcquisitionError("requested output directory appeared during acquisition")
    if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise AcquisitionError("atomic no-replace rename is unavailable")
    raise AcquisitionError("cannot atomically retain acquired release assets")


def _remove_directory_contents(
    directory: int,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> None:
    if budget is None:
        budget = [MAX_CLEANUP_ENTRIES]
    if depth > MAX_CLEANUP_DEPTH or budget[0] <= 0:
        return
    try:
        os.lseek(directory, 0, os.SEEK_SET)
        with os.scandir(directory) as entries:
            for entry in entries:
                if budget[0] <= 0:
                    return
                budget[0] -= 1
                name = entry.name
                try:
                    metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    with contextlib.suppress(OSError):
                        os.unlink(name, dir_fd=directory)
                    continue
                child = -1
                try:
                    child = _open_directory_at(directory, name)
                    retained = os.fstat(child)
                    if not _same_file(metadata, retained):
                        continue
                    _remove_directory_contents(
                        child,
                        depth=depth + 1,
                        budget=budget,
                    )
                    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if _same_file(retained, current):
                        os.rmdir(name, dir_fd=directory)
                except (AcquisitionError, OSError):
                    continue
                finally:
                    if child >= 0:
                        with contextlib.suppress(OSError):
                            os.close(child)
    except (OSError, TypeError):
        return


def _remove_staging(parent: int, name: str, directory: int) -> None:
    try:
        retained = os.fstat(directory)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        return
    if not stat.S_ISDIR(current.st_mode) or not _same_file(retained, current):
        return
    _remove_directory_contents(directory)
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISDIR(current.st_mode) and _same_file(retained, current):
            os.rmdir(name, dir_fd=parent)
    except OSError:
        return


def acquire_release_assets(
    plan: ReleasePlan,
    authenticated: AuthenticatedRelease,
    output_root: Path,
    *,
    client: AcquisitionClient,
) -> Mapping[str, object]:
    """Download, byte-bind, and atomically retain one exact release asset set."""

    if output_root.name in {"", ".", ".."} or SAFE_SEGMENT.fullmatch(output_root.name) is None:
        raise AcquisitionError("output directory name is unsafe")
    output_parent_path = output_root.parent
    parent = _open_output_parent(output_parent_path)
    staging_name = ""
    staging = -1
    retained: list[RetainedAsset] = []
    promoted = False
    try:
        _require_absent(parent, output_root.name)
        try:
            gh_version = _validated_version(
                client.check_version(),
                "acquisition GitHub CLI version",
            )
            initial = _remote_snapshot(client, plan, authenticated)
        except github_release.VerificationError as exc:
            raise AcquisitionError("live GitHub release identity is invalid") from exc
        staging_name, staging = _create_staging(parent)
        asset_ids = dict(initial.assets)
        for asset in plan.assets:
            descriptor = _create_asset(staging, asset)
            try:
                received, digest = client.download_asset(
                    plan.repository,
                    asset_ids[asset.name],
                    descriptor,
                    asset.size,
                )
                if received != asset.size:
                    raise AcquisitionError(f"release asset {asset.name} has the wrong size")
                if digest != asset.sha256:
                    raise AcquisitionError(f"release asset {asset.name} has the wrong SHA-256")
                os.fsync(descriptor)
                identity = _verify_descriptor(descriptor, asset)
            except github_release.VerificationError as exc:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                raise AcquisitionError(f"cannot download release asset {asset.name}") from exc
            except BaseException:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                raise
            retained.append(RetainedAsset(asset, descriptor, identity))

        try:
            final = _remote_snapshot(client, plan, authenticated)
        except github_release.VerificationError as exc:
            raise AcquisitionError("final GitHub release identity is invalid") from exc
        if final != initial:
            raise AcquisitionError("GitHub release changed during asset acquisition")
        for item in retained:
            _verify_descriptor(
                item.descriptor,
                item.asset,
                expected_identity=item.identity,
            )
        _require_tree_matches(staging, plan, retained)
        os.fsync(staging)
        _require_retained_directory(parent, staging_name, staging)
        _require_output_parent_unchanged(output_parent_path, parent)
        _require_absent(parent, output_root.name)
        _rename_noreplace(parent, staging_name, output_root.name)
        promoted = True
        staging_name = ""
        try:
            os.fsync(parent)
        except OSError:
            sys.stderr.write(
                "GitHub release asset acquisition warning: "
                "output parent could not be synchronized\n"
            )

        return {
            "assets": [
                {
                    "github_asset_id": asset_ids[asset.name],
                    "name": asset.name,
                    "path": asset.name,
                    "sha256": asset.sha256,
                    "size": asset.size,
                }
                for asset in plan.assets
            ],
            "authenticated_release": {
                "attestation_payload_sha256": (authenticated.attestation_payload_sha256),
                "sha256": authenticated.record_sha256,
            },
            "controller_manifest": {"sha256": plan.manifest_sha256},
            "github_cli": {
                "minimum_version": github_release.MINIMUM_GH_VERSION_TEXT,
                "version": gh_version,
            },
            "kind": RECORD_KIND,
            "publication_allowed": False,
            "release": {
                "id": authenticated.release_id,
                "immutable": True,
                "url": authenticated.release_url,
            },
            "repository": {
                "id": plan.repository_id,
                "name": plan.repository,
                "owner_id": authenticated.owner_id,
            },
            "schema_version": SCHEMA_VERSION,
            "tag": {
                "attestation_subject_sha1": authenticated.attestation_subject_sha1,
                "name": plan.tag,
                "target_commit": plan.target_commit,
            },
        }
    except OSError as exc:
        raise AcquisitionError("local release asset acquisition failed") from exc
    finally:
        for item in reversed(retained):
            with contextlib.suppress(OSError):
                os.close(item.descriptor)
        if staging_name and not promoted and staging >= 0:
            _remove_staging(parent, staging_name, staging)
        if staging >= 0:
            with contextlib.suppress(OSError):
                os.close(staging)
        with contextlib.suppress(OSError):
            os.close(parent)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Acquire exact authenticated GitHub release assets into one private "
            "directory without parsing their contents."
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--authenticated-release-record", type=Path, required=True)
    parser.add_argument("--authenticated-release-record-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
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
            raise AcquisitionError("release-controller manifest is invalid") from exc
        if plan.manifest_sha256 != arguments.manifest_sha256:
            raise AcquisitionError("release manifest does not match the trusted SHA-256")
        authenticated = load_authenticated_release(
            arguments.authenticated_release_record,
            expected_sha256=arguments.authenticated_release_record_sha256,
            plan=plan,
        )
        client = github_release.GitHubCLI(
            executable=arguments.gh,
            timeout=arguments.timeout_seconds,
        )
        result = acquire_release_assets(
            plan,
            authenticated,
            arguments.output_dir,
            client=client,
        )
        sys.stdout.buffer.write(canonical_json(result))
    except (AcquisitionError, github_release.VerificationError) as exc:
        sys.stderr.write(f"GitHub release asset acquisition failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
