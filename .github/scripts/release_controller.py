#!/usr/bin/env python3
"""Safely reconcile one exact immutable GitHub release from a reviewed asset plan."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import re
import stat
import urllib.parse
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Protocol, cast

SCHEMA_VERSION = 1
MARKER_VERSION = 1
PAGE_SIZE = 100
MAX_PAGES = 10
MAX_MANIFEST_BYTES = 256 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_ITEMS = 4096
MAX_ASSETS = 64
MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 16 * 1024 * 1024 * 1024
MAX_PATH_SEGMENTS = 8
READ_CHUNK_BYTES = 1024 * 1024
MAX_RECONCILE_POLLS = 3
MAX_ID = 2**63 - 1

REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SEMANTIC_TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


class ControllerError(RuntimeError):
    """The immutable-release contract could not be proven."""


class AmbiguousMutationError(ControllerError):
    """A GitHub mutation may have succeeded despite a lost response."""


@dataclasses.dataclass(frozen=True)
class Asset:
    """One exact local file and its intended remote release-asset name."""

    name: str
    relative_path: str
    size: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class ExpectedIdentity:
    """Trusted workflow and manifest values that a release plan must match."""

    repository_id: int
    repository: str
    tag: str
    target_commit: str
    workflow_path: str
    workflow_sha: str
    run_id: int
    manifest_sha256: str


@dataclasses.dataclass(frozen=True)
class ReleasePlan:
    """The complete trusted identity and asset set for one release."""

    repository_id: int
    repository: str
    tag: str
    target_commit: str
    workflow_path: str
    workflow_sha: str
    run_id: int
    assets: tuple[Asset, ...]
    manifest_sha256: str

    @property
    def marker(self) -> str:
        return (
            "<!-- extra-codeowners-release-controller:"
            f"v{MARKER_VERSION} manifest-sha256:{self.manifest_sha256} -->"
        )


@dataclasses.dataclass(frozen=True)
class VerifiedAsset:
    """One verified asset retained by descriptor until publication finishes."""

    asset: Asset
    descriptor: int
    identity: tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class ReleaseResult:
    """The exact immutable release accepted by the controller."""

    release_id: int
    tag: str
    immutable: bool
    resumed: bool


class ReleaseAPI(Protocol):
    """Narrow GitHub REST surface required by the state machine.

    upload_asset must stream from VerifiedAsset.descriptor without reopening a
    filesystem path. The descriptor remains owned by the controller.
    """

    def repository_id(self) -> int:
        raise NotImplementedError

    def resolve_tag(self, tag: str) -> str:
        raise NotImplementedError

    def list_releases(self, page: int, per_page: int) -> Sequence[Mapping[str, Any]]:
        raise NotImplementedError

    def create_draft(self, plan: ReleasePlan) -> Mapping[str, Any]:
        raise NotImplementedError

    def get_release(self, release_id: int) -> Mapping[str, Any]:
        raise NotImplementedError

    def list_assets(self, release_id: int, page: int, per_page: int) -> Sequence[Mapping[str, Any]]:
        raise NotImplementedError

    def upload_asset(
        self, release_id: int, upload_url: str, asset: VerifiedAsset
    ) -> Mapping[str, Any]:
        raise NotImplementedError

    def publish_release(self, release_id: int) -> Mapping[str, Any]:
        raise NotImplementedError


def _reject_constant(value: str) -> NoReturn:
    raise ControllerError(f"manifest contains a non-finite number: {value}")


def _reject_float(value: str) -> NoReturn:
    raise ControllerError(f"manifest contains a floating-point number: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ControllerError(f"manifest repeats JSON key {key!r}")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    try:
        result = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ControllerError("manifest cannot be represented as canonical JSON") from exc
    return result + b"\n"


def _json_shape(value: object, *, depth: int = 1) -> tuple[int, int]:
    if depth > MAX_JSON_DEPTH:
        raise ControllerError("manifest exceeds the JSON depth limit")
    if isinstance(value, dict):
        objects = 1
        items = len(value)
        for key, child in value.items():
            if not isinstance(key, str):
                raise ControllerError("manifest has a non-string object key")
            child_objects, child_items = _json_shape(child, depth=depth + 1)
            objects += child_objects
            items += child_items
        return objects, items
    if isinstance(value, list):
        objects = 1
        items = len(value)
        for child in value:
            child_objects, child_items = _json_shape(child, depth=depth + 1)
            objects += child_objects
            items += child_items
        return objects, items
    if value is None or isinstance(value, (str, int, float, bool)):
        return 0, 1
    raise ControllerError("manifest contains an unsupported JSON value")


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ControllerError(f"{source} must contain exactly {sorted(fields)}")
    return value


def _bounded_integer(value: object, source: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise ControllerError(f"{source} is outside its integer bounds")
    return value


def _bounded_string(value: object, source: str, pattern: re.Pattern[str], *, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum or pattern.fullmatch(value) is None:
        raise ControllerError(f"{source} has an invalid value")
    return value


def _safe_relative_path(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\\" in value:
        raise ControllerError(f"asset {name} has an unsafe local path")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or candidate.name != name or candidate.as_posix() != value:
        raise ControllerError(f"asset {name} has an unsafe local path")
    parts = candidate.parts
    if (
        not parts
        or len(parts) > MAX_PATH_SEGMENTS
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ControllerError(f"asset {name} has an unsafe local path")
    if any(SAFE_SEGMENT.fullmatch(part) is None for part in parts):
        raise ControllerError(f"asset {name} has an unsafe local path")
    return candidate.as_posix()


def validate_manifest(value: object, manifest_sha256: str) -> ReleasePlan:
    record = _exact_mapping(
        value,
        {
            "assets",
            "repository",
            "repository_id",
            "run_id",
            "schema_version",
            "tag",
            "target_commit",
            "workflow_path",
            "workflow_sha",
        },
        "release manifest",
    )
    schema_version = _bounded_integer(
        record["schema_version"],
        "release manifest schema version",
        minimum=0,
        maximum=MAX_ID,
    )
    if schema_version != SCHEMA_VERSION:
        raise ControllerError("release manifest has an unsupported schema version")
    repository_id = _bounded_integer(
        record["repository_id"], "repository ID", minimum=1, maximum=MAX_ID
    )
    repository = _bounded_string(record["repository"], "repository", REPOSITORY, maximum=256)
    tag = _bounded_string(record["tag"], "release tag", SEMANTIC_TAG, maximum=64)
    target_commit = _bounded_string(record["target_commit"], "target commit", HEX40, maximum=40)
    workflow_path = _bounded_string(
        record["workflow_path"], "workflow path", WORKFLOW_PATH, maximum=255
    )
    workflow_sha = _bounded_string(record["workflow_sha"], "workflow SHA", HEX40, maximum=40)
    run_id = _bounded_integer(record["run_id"], "run ID", minimum=1, maximum=MAX_ID)
    raw_assets = record["assets"]
    if not isinstance(raw_assets, list) or not 1 <= len(raw_assets) <= MAX_ASSETS:
        raise ControllerError("release manifest has an invalid asset count")
    assets: list[Asset] = []
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    total = 0
    for index, raw_asset in enumerate(raw_assets):
        item = _exact_mapping(
            raw_asset,
            {"name", "path", "sha256", "size"},
            f"release asset {index}",
        )
        name = _bounded_string(item["name"], "release asset name", SAFE_NAME, maximum=255)
        relative_path = _safe_relative_path(item["path"], name)
        size = _bounded_integer(
            item["size"], f"release asset {name} size", minimum=1, maximum=MAX_ASSET_BYTES
        )
        sha256 = _bounded_string(item["sha256"], f"release asset {name} SHA-256", HEX64, maximum=64)
        if name in seen_names or relative_path in seen_paths:
            raise ControllerError("release manifest repeats an asset name or path")
        if size > MAX_TOTAL_ASSET_BYTES - total:
            raise ControllerError("release manifest exceeds the total asset-size limit")
        seen_names.add(name)
        seen_paths.add(relative_path)
        total += size
        assets.append(Asset(name, relative_path, size, sha256))
    if [item.name for item in assets] != sorted(item.name for item in assets):
        raise ControllerError("release manifest assets are not sorted by name")
    checked_manifest_sha256 = _bounded_string(
        manifest_sha256, "release manifest SHA-256", HEX64, maximum=64
    )
    return ReleasePlan(
        repository_id=repository_id,
        repository=repository,
        tag=tag,
        target_commit=target_commit,
        workflow_path=workflow_path,
        workflow_sha=workflow_sha,
        run_id=run_id,
        assets=tuple(assets),
        manifest_sha256=checked_manifest_sha256,
    )


def _manifest_value(plan: ReleasePlan) -> Mapping[str, object]:
    return {
        "assets": [
            {
                "name": asset.name,
                "path": asset.relative_path,
                "sha256": asset.sha256,
                "size": asset.size,
            }
            for asset in plan.assets
        ],
        "repository": plan.repository,
        "repository_id": plan.repository_id,
        "run_id": plan.run_id,
        "schema_version": SCHEMA_VERSION,
        "tag": plan.tag,
        "target_commit": plan.target_commit,
        "workflow_path": plan.workflow_path,
        "workflow_sha": plan.workflow_sha,
    }


def _require_expected_identity(plan: ReleasePlan, expected: ExpectedIdentity) -> None:
    """Bind an untrusted release plan to separate trusted workflow values."""

    reconstructed = _manifest_value(plan)
    reconstructed_sha256 = hashlib.sha256(canonical_json(reconstructed)).hexdigest()
    validated = validate_manifest(reconstructed, reconstructed_sha256)
    if validated != plan or reconstructed_sha256 != plan.manifest_sha256:
        raise ControllerError("release plan does not match its canonical manifest digest")

    _bounded_integer(
        expected.repository_id,
        "expected repository ID",
        minimum=1,
        maximum=MAX_ID,
    )
    _bounded_string(
        expected.repository,
        "expected repository",
        REPOSITORY,
        maximum=256,
    )
    _bounded_string(expected.tag, "expected release tag", SEMANTIC_TAG, maximum=64)
    _bounded_string(
        expected.target_commit,
        "expected target commit",
        HEX40,
        maximum=40,
    )
    _bounded_string(
        expected.workflow_path,
        "expected workflow path",
        WORKFLOW_PATH,
        maximum=255,
    )
    _bounded_string(
        expected.workflow_sha,
        "expected workflow SHA",
        HEX40,
        maximum=40,
    )
    _bounded_integer(expected.run_id, "expected run ID", minimum=1, maximum=MAX_ID)
    _bounded_string(
        expected.manifest_sha256,
        "expected release manifest SHA-256",
        HEX64,
        maximum=64,
    )

    comparisons = (
        (plan.repository_id, expected.repository_id, "repository ID"),
        (plan.repository, expected.repository, "repository name"),
        (plan.tag, expected.tag, "release tag"),
        (plan.target_commit, expected.target_commit, "target commit"),
        (plan.workflow_path, expected.workflow_path, "workflow path"),
        (plan.workflow_sha, expected.workflow_sha, "workflow SHA"),
        (plan.run_id, expected.run_id, "run ID"),
        (plan.manifest_sha256, expected.manifest_sha256, "manifest SHA-256"),
    )
    for actual, trusted, source in comparisons:
        if actual != trusted:
            raise ControllerError(f"release plan {source} does not match trusted identity")


def load_manifest(path: Path) -> ReleasePlan:
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow:
            raise ControllerError("release controller requires O_NOFOLLOW support")
        descriptor = os.open(path, flags | nofollow)
    except OSError as exc:
        raise ControllerError("cannot open release manifest safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ControllerError("release manifest must be one single-link regular file")
        if not 1 <= before.st_size <= MAX_MANIFEST_BYTES:
            raise ControllerError("release manifest is outside its size limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise ControllerError("release manifest was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ControllerError("release manifest has trailing bytes")
        after = os.fstat(descriptor)
        if _file_signature(after) != _file_signature(before):
            raise ControllerError("release manifest changed while reading")
    except OSError as exc:
        raise ControllerError("cannot read release manifest safely") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            raise ControllerError("cannot close the release manifest safely") from exc
    raw = b"".join(chunks)
    try:
        value: object = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise ControllerError("release manifest is not strict JSON") from exc
    _, items = _json_shape(value)
    if items > MAX_JSON_ITEMS:
        raise ControllerError("release manifest exceeds the JSON item limit")
    if canonical_json(value) != raw:
        raise ControllerError("release manifest is not canonical JSON")
    return validate_manifest(value, hashlib.sha256(raw).hexdigest())


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


def _open_asset_at(
    parent_descriptor: int,
    parts: tuple[str, ...],
    directory_flags: int,
    file_flags: int,
) -> int:
    """Open one no-follow relative path and close every intermediate directory."""

    if len(parts) == 1:
        return os.open(parts[0], file_flags, dir_fd=parent_descriptor)
    directory_descriptor = os.open(parts[0], directory_flags, dir_fd=parent_descriptor)
    asset_descriptor = -1
    try:
        asset_descriptor = _open_asset_at(
            directory_descriptor,
            parts[1:],
            directory_flags,
            file_flags,
        )
        os.close(directory_descriptor)
    except BaseException:
        if asset_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(asset_descriptor)
        with contextlib.suppress(OSError):
            os.close(directory_descriptor)
        raise
    return asset_descriptor


def _open_asset_descriptor(root_descriptor: int, asset: Asset) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow
    parts = PurePosixPath(asset.relative_path).parts
    try:
        return _open_asset_at(root_descriptor, parts, directory_flags, file_flags)
    except OSError as exc:
        raise ControllerError(f"cannot open release asset {asset.name} safely") from exc


def _verify_retained_asset(descriptor: int, asset: Asset) -> tuple[int, ...]:
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ControllerError(f"release asset {asset.name} is not one regular file")
        if before.st_size != asset.size:
            raise ControllerError(f"release asset {asset.name} has the wrong size")
        digest = hashlib.sha256()
        remaining = asset.size
        position = 0
        while remaining:
            chunk = os.pread(descriptor, min(READ_CHUNK_BYTES, remaining), position)
            if not chunk:
                raise ControllerError(f"release asset {asset.name} was truncated")
            digest.update(chunk)
            remaining -= len(chunk)
            position += len(chunk)
        if os.pread(descriptor, 1, position):
            raise ControllerError(f"release asset {asset.name} has trailing bytes")
        after = os.fstat(descriptor)
        if _file_signature(after) != _file_signature(before):
            raise ControllerError(f"release asset {asset.name} changed while reading")
        if digest.hexdigest() != asset.sha256:
            raise ControllerError(f"release asset {asset.name} has the wrong SHA-256")
    except OSError as exc:
        raise ControllerError(f"cannot read release asset {asset.name} safely") from exc
    return _file_signature(before)


def require_retained_asset_unchanged(verified: VerifiedAsset) -> None:
    """Rehash the same retained descriptor and require stable file identity."""

    identity = _verify_retained_asset(verified.descriptor, verified.asset)
    if identity != verified.identity:
        raise ControllerError(f"release asset {verified.asset.name} changed after verification")


@contextlib.contextmanager
def open_verified_assets(root: Path, plan: ReleasePlan) -> Iterator[tuple[VerifiedAsset, ...]]:
    """Open, verify, retain, and deterministically close every planned asset."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise ControllerError("release controller requires O_NOFOLLOW and O_DIRECTORY support")
    try:
        root_descriptor = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory,
        )
    except OSError as exc:
        raise ControllerError("cannot open the release-asset root safely") from exc
    opened: list[VerifiedAsset] = []
    try:
        root_metadata = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise ControllerError("release-asset root is not a directory")
        for asset in plan.assets:
            descriptor = _open_asset_descriptor(root_descriptor, asset)
            try:
                identity = _verify_retained_asset(descriptor, asset)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                raise
            opened.append(VerifiedAsset(asset, descriptor, identity))
        yield tuple(opened)
    except OSError as exc:
        raise ControllerError("cannot retain the verified release assets safely") from exc
    finally:
        close_error: OSError | None = None
        for verified in reversed(opened):
            try:
                os.close(verified.descriptor)
            except OSError as exc:
                close_error = close_error or exc
        try:
            os.close(root_descriptor)
        except OSError as exc:
            close_error = close_error or exc
        if close_error is not None:
            raise ControllerError(
                "cannot close retained release-asset descriptors"
            ) from close_error


def _positive_id(value: object, source: str) -> int:
    return _bounded_integer(value, source, minimum=1, maximum=MAX_ID)


def _release_identity(release: Mapping[str, Any], plan: ReleasePlan) -> tuple[int, bool, bool]:
    release_id = _positive_id(release.get("id"), "GitHub release ID")
    if release.get("tag_name") != plan.tag:
        raise ControllerError("GitHub release has the wrong tag")
    if release.get("target_commitish") != plan.target_commit:
        raise ControllerError("GitHub release has the wrong target commit")
    if release.get("name") != plan.tag:
        raise ControllerError("GitHub release has the wrong name")
    if release.get("body") != plan.marker:
        raise ControllerError("GitHub release is not owned by this exact controller plan")
    draft = release.get("draft")
    immutable = release.get("immutable")
    prerelease = release.get("prerelease")
    if (
        not isinstance(draft, bool)
        or not isinstance(immutable, bool)
        or not isinstance(prerelease, bool)
    ):
        raise ControllerError("GitHub release has invalid draft, immutable, or prerelease state")
    if prerelease:
        raise ControllerError("GitHub release is unexpectedly marked as a prerelease")
    if draft and immutable:
        raise ControllerError("GitHub release is both draft and immutable")
    return release_id, draft, immutable


def _all_pages(
    fetch: Callable[[int, int], Sequence[Mapping[str, Any]]], source: str
) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        raw_values: object = fetch(page, PAGE_SIZE)
        if not isinstance(raw_values, Sequence) or isinstance(raw_values, (str, bytes)):
            raise ControllerError(f"{source} page is not a sequence")
        values = cast(Sequence[object], raw_values)
        if len(values) > PAGE_SIZE:
            raise ControllerError(f"{source} page exceeds its item limit")
        for value in values:
            if not isinstance(value, Mapping):
                raise ControllerError(f"{source} contains a non-object item")
            result.append(value)
        if len(values) < PAGE_SIZE:
            return result
    raise ControllerError(f"{source} exceeds the pagination limit")


def _find_release(api: ReleaseAPI, plan: ReleasePlan) -> Mapping[str, Any] | None:
    releases = _all_pages(api.list_releases, "GitHub releases")
    matching_tag = [release for release in releases if release.get("tag_name") == plan.tag]
    if not matching_tag:
        return None
    if len(matching_tag) != 1:
        raise ControllerError("GitHub has multiple releases for the release tag")
    _release_identity(matching_tag[0], plan)
    return matching_tag[0]


def _validate_upload_url(value: object, plan: ReleasePlan, release_id: int) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ControllerError("GitHub release has an invalid upload URL")
    if "{" in value:
        base, template = value.split("{", 1)
        if "{" + template != "{?name,label}":
            raise ControllerError("GitHub release has an unsupported upload URL template")
    else:
        base = value
    parsed = urllib.parse.urlsplit(base)
    expected_path = f"/repos/{plan.repository}/releases/{release_id}/assets"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "uploads.github.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != expected_path
    ):
        raise ControllerError("GitHub release has an untrusted upload URL")
    return value


def _remote_asset(value: Mapping[str, Any], expected: Asset | None = None) -> tuple[int, str]:
    asset_id = _positive_id(value.get("id"), "GitHub release asset ID")
    name = _bounded_string(value.get("name"), "GitHub release asset name", SAFE_NAME, maximum=255)
    if value.get("state") != "uploaded":
        raise ControllerError(f"GitHub release asset {name} is not uploaded")
    size = _bounded_integer(
        value.get("size"), f"GitHub release asset {name} size", minimum=1, maximum=MAX_ASSET_BYTES
    )
    digest = value.get("digest")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or HEX64.fullmatch(digest.removeprefix("sha256:")) is None
    ):
        raise ControllerError(f"GitHub release asset {name} has no server SHA-256")
    if expected is not None and (size != expected.size or digest != f"sha256:{expected.sha256}"):
        raise ControllerError(f"GitHub release asset {name} does not match local bytes")
    return asset_id, name


def _remote_assets(api: ReleaseAPI, release_id: int, plan: ReleasePlan) -> dict[str, int]:
    values = _all_pages(
        lambda page, per_page: api.list_assets(release_id, page, per_page),
        "GitHub release assets",
    )
    expected = {asset.name: asset for asset in plan.assets}
    observed: dict[str, int] = {}
    for value in values:
        raw_name = value.get("name")
        if not isinstance(raw_name, str) or raw_name not in expected:
            raise ControllerError("GitHub release contains an unexpected asset")
        asset_id, name = _remote_asset(value, expected[raw_name])
        if name in observed:
            raise ControllerError("GitHub release repeats an asset name")
        observed[name] = asset_id
    return observed


def _require_complete_remote_assets(api: ReleaseAPI, release_id: int, plan: ReleasePlan) -> None:
    observed = _remote_assets(api, release_id, plan)
    expected = {asset.name for asset in plan.assets}
    if set(observed) != expected:
        raise ControllerError("GitHub release is missing one or more expected assets")


def _get_exact_release(api: ReleaseAPI, release_id: int, plan: ReleasePlan) -> Mapping[str, Any]:
    release = api.get_release(release_id)
    _release_identity(release, plan)
    return release


def _require_tag_target(api: ReleaseAPI, plan: ReleasePlan) -> None:
    if api.resolve_tag(plan.tag) != plan.target_commit:
        raise ControllerError("GitHub release tag does not resolve to the planned commit")


def _reconcile_verified_release(
    api: ReleaseAPI, plan: ReleasePlan, verified_assets: tuple[VerifiedAsset, ...]
) -> ReleaseResult:
    release = _find_release(api, plan)
    resumed = release is not None
    if release is None:
        try:
            release = api.create_draft(plan)
            _, created_draft, created_immutable = _release_identity(release, plan)
            if not created_draft or created_immutable:
                raise ControllerError("GitHub did not create the requested draft release")
        except AmbiguousMutationError:
            release = _find_release(api, plan)
            if release is None:
                raise ControllerError("cannot reconcile an ambiguous draft creation") from None
            resumed = True
    release_id, draft, immutable = _release_identity(release, plan)
    if not draft:
        if not immutable:
            raise ControllerError("matching GitHub release is public but mutable")
        _require_complete_remote_assets(api, release_id, plan)
        _require_tag_target(api, plan)
        return ReleaseResult(release_id, plan.tag, True, resumed=True)

    upload_url = _validate_upload_url(release.get("upload_url"), plan, release_id)
    observed = _remote_assets(api, release_id, plan)
    for verified in verified_assets:
        if verified.asset.name in observed:
            continue
        try:
            response = api.upload_asset(release_id, upload_url, verified)
            _remote_asset(response, verified.asset)
        except AmbiguousMutationError:
            reconciled = _remote_assets(api, release_id, plan)
            if verified.asset.name not in reconciled:
                raise ControllerError(
                    f"cannot reconcile ambiguous upload of {verified.asset.name}"
                ) from None
        require_retained_asset_unchanged(verified)
    for verified in verified_assets:
        require_retained_asset_unchanged(verified)

    final_release = _get_exact_release(api, release_id, plan)
    _, final_draft, final_immutable = _release_identity(final_release, plan)
    if not final_draft or final_immutable:
        raise ControllerError("GitHub release changed before final draft publication")
    _require_complete_remote_assets(api, release_id, plan)
    _require_tag_target(api, plan)
    try:
        published = api.publish_release(release_id)
        _release_identity(published, plan)
    except AmbiguousMutationError:
        # The bounded readback loop below reconciles whether publication succeeded.
        pass
    for _ in range(MAX_RECONCILE_POLLS):
        current = _get_exact_release(api, release_id, plan)
        _, current_draft, current_immutable = _release_identity(current, plan)
        if not current_draft:
            if not current_immutable:
                raise ControllerError("published GitHub release is not immutable")
            _require_complete_remote_assets(api, release_id, plan)
            _require_tag_target(api, plan)
            return ReleaseResult(release_id, plan.tag, True, resumed=resumed)
    raise ControllerError("GitHub release did not become immutable after publication")


def reconcile_release(
    api: ReleaseAPI,
    plan: ReleasePlan,
    asset_root: Path,
    *,
    expected: ExpectedIdentity,
) -> ReleaseResult:
    """Create or resume one exact draft and accept only its immutable publication."""

    _require_expected_identity(plan, expected)
    if api.repository_id() != plan.repository_id:
        raise ControllerError("GitHub repository ID does not match the release plan")
    _require_tag_target(api, plan)
    with open_verified_assets(asset_root, plan) as verified_assets:
        return _reconcile_verified_release(api, plan, verified_assets)
