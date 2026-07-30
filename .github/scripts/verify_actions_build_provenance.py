#!/usr/bin/env python3
"""Verify one acquired release asset's exact GitHub Actions provenance."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import hashlib
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol, cast

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import acquire_github_release_assets as acquisition  # noqa: E402
import verify_github_release as github_release  # noqa: E402
import verify_release_workflow as workflow_verifier  # noqa: E402
from release_controller import (  # noqa: E402
    MAX_ASSETS,
    MAX_ID,
    MAX_MANIFEST_BYTES,
    SAFE_NAME,
    Asset,
    ControllerError,
    ReleasePlan,
    canonical_json,
    load_manifest,
)

SCHEMA_VERSION = 1
RECORD_KIND = "extra-codeowners/authenticated-actions-build-provenance"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
ATTESTATION_LIMIT = 30
MAX_RECORD_BYTES = MAX_MANIFEST_BYTES
MAX_ATTESTATION_PAYLOAD_BYTES = 1024 * 1024
MAX_STRING_BYTES = 4096

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SEMANTIC_VERSION = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")


class ProvenanceVerificationError(RuntimeError):
    """The selected asset's Actions build provenance could not be proven."""


class ProvenanceClient(Protocol):
    """Read-only GitHub operations needed by the provenance boundary."""

    def check_version(self) -> str:
        raise NotImplementedError

    def verify_attestation(
        self,
        artifact: Path,
        *,
        repository: str,
        certificate_identity: str,
        signer_digest: str,
        source_digest: str,
        source_ref: str,
        predicate_type: str,
        limit: int,
    ) -> object:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class AuthenticatedWorkflow:
    """The exact prior workflow proof accepted by this boundary."""

    record_sha256: str
    authenticated_release_sha256: str
    owner_id: int
    workflow_id: int
    run_attempt: int
    url: str
    file_sha256: str


@dataclasses.dataclass(frozen=True)
class AcquiredAssets:
    """The exact prior acquisition proof accepted by this boundary."""

    record_sha256: str
    authenticated_release_sha256: str
    owner_id: int
    assets: tuple[tuple[Asset, int], ...]


@dataclasses.dataclass(frozen=True)
class RetainedAsset:
    """One selected file retained across external verification."""

    descriptor: int
    identity: tuple[int, ...]
    root_descriptor: int
    root_identity: tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class VerifiedAttestation:
    """Stable fields from one fully checked SLSA statement."""

    run_invocation: str
    payload_sha256: str
    subject_count: int
    timestamp_count: int


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProvenanceVerificationError(f"{source} must contain exactly {sorted(fields)}")
    return cast(Mapping[str, Any], value)


def _positive_id(value: object, source: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ID:
        raise ProvenanceVerificationError(f"{source} is outside its integer bounds")
    return value


def _decimal_id(value: object, source: str) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
        or len(value) > 19
    ):
        raise ProvenanceVerificationError(f"{source} is not a canonical positive ID")
    return _positive_id(int(value), source)


def _digest(value: object, source: str, pattern: re.Pattern[str] = HEX64) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProvenanceVerificationError(f"{source} is invalid")
    return value


def _bounded_string(value: object, source: str, *, maximum: int = MAX_STRING_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise ProvenanceVerificationError(f"{source} is not a bounded nonempty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ProvenanceVerificationError(f"{source} is not valid Unicode") from None
    if len(encoded) > maximum:
        raise ProvenanceVerificationError(f"{source} is not a bounded nonempty string")
    return value


def _validated_version(value: object, source: str) -> str:
    version = _bounded_string(value, source, maximum=64)
    match = SEMANTIC_VERSION.fullmatch(version)
    if match is None:
        raise ProvenanceVerificationError(f"{source} is invalid")
    if tuple(int(part) for part in match.groups()) < github_release.MINIMUM_GH_VERSION:
        raise ProvenanceVerificationError(f"{source} predates the minimum supported GitHub CLI")
    return version


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


def _read_canonical_record(
    path: Path,
    *,
    expected_sha256: str,
    source: str,
) -> tuple[Mapping[str, Any], str]:
    _digest(expected_sha256, f"trusted {source} SHA-256")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ProvenanceVerificationError("record verification requires O_NOFOLLOW")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow,
        )
    except OSError as exc:
        raise ProvenanceVerificationError(f"cannot open {source} safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ProvenanceVerificationError(f"{source} must be one single-link regular file")
        if not 1 <= before.st_size <= MAX_RECORD_BYTES:
            raise ProvenanceVerificationError(f"{source} is outside its byte bound")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(github_release.READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise ProvenanceVerificationError(f"{source} was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ProvenanceVerificationError(f"{source} has trailing bytes")
        after = os.fstat(descriptor)
        if _file_identity(after) != _file_identity(before):
            raise ProvenanceVerificationError(f"{source} changed while reading")
    except OSError as exc:
        raise ProvenanceVerificationError(f"cannot read {source} safely") from exc
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)
    raw = b"".join(chunks)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ProvenanceVerificationError(f"{source} does not match the trusted SHA-256")
    try:
        value = github_release.strict_json(raw, source, maximum=MAX_RECORD_BYTES)
    except github_release.VerificationError as exc:
        raise ProvenanceVerificationError(f"{source} is not strict bounded JSON") from exc
    if canonical_json(value) != raw or not isinstance(value, dict):
        raise ProvenanceVerificationError(f"{source} is not one canonical JSON object")
    return cast(Mapping[str, Any], value), expected_sha256


def _require_record_header(
    record: Mapping[str, Any],
    *,
    schema_version: int,
    kind: str,
    source: str,
) -> None:
    if (
        not isinstance(record["schema_version"], int)
        or isinstance(record["schema_version"], bool)
        or record["schema_version"] != schema_version
    ):
        raise ProvenanceVerificationError(f"{source} has an unsupported schema")
    if record["kind"] != kind:
        raise ProvenanceVerificationError(f"{source} has an unsupported kind")
    if record["publication_allowed"] is not False:
        raise ProvenanceVerificationError(f"{source} grants publication authority")


def _require_manifest(
    value: object,
    plan: ReleasePlan,
    source: str,
) -> None:
    manifest = _exact_mapping(value, {"sha256"}, source)
    if manifest["sha256"] != plan.manifest_sha256:
        raise ProvenanceVerificationError(f"{source} names a different controller manifest")


def _require_cli(value: object, source: str) -> None:
    cli = _exact_mapping(value, {"minimum_version", "version"}, source)
    if cli["minimum_version"] != github_release.MINIMUM_GH_VERSION_TEXT:
        raise ProvenanceVerificationError(f"{source} has a different minimum version")
    _validated_version(cli["version"], f"{source} version")


def _require_repository(value: object, plan: ReleasePlan, source: str) -> int:
    repository = _exact_mapping(value, {"id", "name", "owner_id"}, source)
    if (
        _positive_id(repository["id"], f"{source} ID") != plan.repository_id
        or repository["name"] != plan.repository
    ):
        raise ProvenanceVerificationError(f"{source} names a different repository")
    return _positive_id(repository["owner_id"], f"{source} owner ID")


def _require_tag(value: object, plan: ReleasePlan, source: str) -> None:
    tag = _exact_mapping(value, {"name", "target_commit"}, source)
    if tag["name"] != plan.tag or tag["target_commit"] != plan.target_commit:
        raise ProvenanceVerificationError(f"{source} names a different tag")


def load_authenticated_workflow(
    path: Path,
    *,
    expected_sha256: str,
    plan: ReleasePlan,
) -> AuthenticatedWorkflow:
    """Load and bind one canonical authenticated-workflow record."""

    value, record_sha256 = _read_canonical_record(
        path,
        expected_sha256=expected_sha256,
        source="authenticated workflow record",
    )
    record = _exact_mapping(
        value,
        {
            "authenticated_release",
            "controller_manifest",
            "github_cli",
            "kind",
            "publication_allowed",
            "repository",
            "schema_version",
            "tag",
            "workflow",
        },
        "authenticated workflow record",
    )
    _require_record_header(
        record,
        schema_version=workflow_verifier.SCHEMA_VERSION,
        kind=workflow_verifier.RECORD_KIND,
        source="authenticated workflow record",
    )
    _require_manifest(
        record["controller_manifest"],
        plan,
        "authenticated workflow controller manifest",
    )
    authenticated_release = _exact_mapping(
        record["authenticated_release"],
        {"sha256"},
        "authenticated workflow release",
    )
    authenticated_release_sha256 = _digest(
        authenticated_release["sha256"],
        "authenticated workflow release SHA-256",
    )
    _require_cli(record["github_cli"], "authenticated workflow GitHub CLI")
    owner_id = _require_repository(
        record["repository"],
        plan,
        "authenticated workflow repository",
    )
    _require_tag(record["tag"], plan, "authenticated workflow tag")

    workflow = _exact_mapping(
        record["workflow"],
        {
            "event",
            "file",
            "id",
            "path",
            "ref",
            "run_attempt",
            "run_id",
            "sha",
            "url",
        },
        "authenticated workflow",
    )
    expected_ref = f"refs/tags/{plan.tag}"
    expected_url = f"https://github.com/{plan.repository}/actions/runs/{plan.run_id}"
    if (
        workflow["event"] != "push"
        or workflow["path"] != plan.workflow_path
        or workflow["ref"] != expected_ref
        or _positive_id(workflow["run_id"], "authenticated workflow run ID") != plan.run_id
        or workflow["sha"] != plan.workflow_sha
        or workflow["url"] != expected_url
    ):
        raise ProvenanceVerificationError(
            "authenticated workflow identity differs from the manifest"
        )
    workflow_id = _positive_id(workflow["id"], "authenticated workflow definition ID")
    run_attempt = _positive_id(workflow["run_attempt"], "authenticated workflow run attempt")
    file_record = _exact_mapping(
        workflow["file"],
        {"git_blob_sha1", "sha256", "size"},
        "authenticated workflow file",
    )
    _digest(file_record["git_blob_sha1"], "authenticated workflow Git blob SHA-1", HEX40)
    file_sha256 = _digest(
        file_record["sha256"],
        "authenticated workflow file SHA-256",
    )
    file_size = _positive_id(file_record["size"], "authenticated workflow file size")
    if file_size > workflow_verifier.MAX_WORKFLOW_BYTES:
        raise ProvenanceVerificationError("authenticated workflow file is outside its byte bound")
    return AuthenticatedWorkflow(
        record_sha256=record_sha256,
        authenticated_release_sha256=authenticated_release_sha256,
        owner_id=owner_id,
        workflow_id=workflow_id,
        run_attempt=run_attempt,
        url=expected_url,
        file_sha256=file_sha256,
    )


def load_acquired_assets(
    path: Path,
    *,
    expected_sha256: str,
    plan: ReleasePlan,
) -> AcquiredAssets:
    """Load and bind one canonical release-asset acquisition record."""

    value, record_sha256 = _read_canonical_record(
        path,
        expected_sha256=expected_sha256,
        source="acquired assets record",
    )
    record = _exact_mapping(
        value,
        {
            "assets",
            "authenticated_release",
            "controller_manifest",
            "github_cli",
            "kind",
            "publication_allowed",
            "release",
            "repository",
            "schema_version",
            "tag",
        },
        "acquired assets record",
    )
    _require_record_header(
        record,
        schema_version=acquisition.SCHEMA_VERSION,
        kind=acquisition.RECORD_KIND,
        source="acquired assets record",
    )
    _require_manifest(
        record["controller_manifest"],
        plan,
        "acquired assets controller manifest",
    )
    authenticated_release = _exact_mapping(
        record["authenticated_release"],
        {"attestation_payload_sha256", "sha256"},
        "acquired assets authenticated release",
    )
    _digest(
        authenticated_release["attestation_payload_sha256"],
        "acquired assets release-attestation payload SHA-256",
    )
    authenticated_release_sha256 = _digest(
        authenticated_release["sha256"],
        "acquired assets authenticated-release SHA-256",
    )
    _require_cli(record["github_cli"], "acquired assets GitHub CLI")
    owner_id = _require_repository(record["repository"], plan, "acquired assets repository")
    tag = _exact_mapping(
        record["tag"],
        {"attestation_subject_sha1", "name", "target_commit"},
        "acquired assets tag",
    )
    if tag["name"] != plan.tag or tag["target_commit"] != plan.target_commit:
        raise ProvenanceVerificationError("acquired assets tag differs from the manifest")
    _digest(tag["attestation_subject_sha1"], "acquired assets tag-object SHA-1", HEX40)
    release = _exact_mapping(
        record["release"],
        {"id", "immutable", "url"},
        "acquired assets release",
    )
    expected_release_url = f"https://github.com/{plan.repository}/releases/tag/{plan.tag}"
    _positive_id(release["id"], "acquired assets release ID")
    if release["immutable"] is not True or release["url"] != expected_release_url:
        raise ProvenanceVerificationError("acquired assets release identity is invalid")

    raw_assets = record["assets"]
    if not isinstance(raw_assets, list) or len(raw_assets) != len(plan.assets):
        raise ProvenanceVerificationError("acquired assets record has a different asset count")
    bound_assets: list[tuple[Asset, int]] = []
    ids: set[int] = set()
    for index, (raw, asset) in enumerate(zip(raw_assets, plan.assets, strict=True)):
        item = _exact_mapping(
            raw,
            {"github_asset_id", "name", "path", "sha256", "size"},
            f"acquired asset {index}",
        )
        asset_id = _positive_id(item["github_asset_id"], f"acquired asset {index} GitHub ID")
        if asset_id in ids:
            raise ProvenanceVerificationError("acquired assets record repeats a GitHub asset ID")
        if (
            item["name"] != asset.name
            or item["path"] != asset.name
            or item["sha256"] != asset.sha256
            or not isinstance(item["size"], int)
            or isinstance(item["size"], bool)
            or item["size"] != asset.size
        ):
            raise ProvenanceVerificationError(
                "acquired assets record has a different asset inventory"
            )
        ids.add(asset_id)
        bound_assets.append((asset, asset_id))
    return AcquiredAssets(
        record_sha256=record_sha256,
        authenticated_release_sha256=authenticated_release_sha256,
        owner_id=owner_id,
        assets=tuple(bound_assets),
    )


def _hash_descriptor(descriptor: int, asset: Asset) -> tuple[int, ...]:
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != asset.size
        ):
            raise ProvenanceVerificationError(
                f"acquired asset {asset.name} has an unsafe local identity"
            )
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
                raise ProvenanceVerificationError(f"acquired asset {asset.name} was truncated")
            digest.update(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        if os.pread(descriptor, 1, position):
            raise ProvenanceVerificationError(f"acquired asset {asset.name} has trailing bytes")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ProvenanceVerificationError(f"cannot inspect acquired asset {asset.name}") from exc
    identity = _file_identity(before)
    if _file_identity(after) != identity:
        raise ProvenanceVerificationError(f"acquired asset {asset.name} changed while hashing")
    if digest.hexdigest() != asset.sha256:
        raise ProvenanceVerificationError(f"acquired asset {asset.name} has the wrong SHA-256")
    return identity


def _same_path(path: Path, descriptor: int, expected: tuple[int, ...], source: str) -> None:
    try:
        current = os.stat(path, follow_symlinks=False)
        retained = os.fstat(descriptor)
    except OSError as exc:
        raise ProvenanceVerificationError(f"{source} changed") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or not stat.S_ISDIR(retained.st_mode)
        or current.st_dev != retained.st_dev
        or current.st_ino != retained.st_ino
        or _file_identity(retained) != expected
    ):
        raise ProvenanceVerificationError(f"{source} changed")


def _open_retained_asset(root_path: Path, plan: ReleasePlan, asset: Asset) -> RetainedAsset:
    if not root_path.is_absolute():
        raise ProvenanceVerificationError("acquired asset root must be absolute")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise ProvenanceVerificationError(
            "acquired asset verification requires directory no-follow support"
        )
    try:
        root = os.open(
            root_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory,
        )
    except OSError as exc:
        raise ProvenanceVerificationError("cannot open acquired asset root safely") from exc
    descriptor = -1
    try:
        root_metadata = os.fstat(root)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise ProvenanceVerificationError(
                "acquired asset root is not one owned mode-0700 directory"
            )
        root_identity = _file_identity(root_metadata)
        observed: set[str] = set()
        expected = {item.name: item for item in plan.assets}
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if len(observed) >= MAX_ASSETS:
                        raise ProvenanceVerificationError(
                            "acquired asset root exceeds its entry bound"
                        )
                    if entry.name in observed or entry.name not in expected:
                        raise ProvenanceVerificationError(
                            "acquired asset root has an unexpected entry"
                        )
                    metadata = os.stat(entry.name, dir_fd=root, follow_symlinks=False)
                    expected_asset = expected[entry.name]
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or metadata.st_uid != os.geteuid()
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or metadata.st_size != expected_asset.size
                    ):
                        raise ProvenanceVerificationError(
                            f"acquired asset {entry.name} has an unsafe local identity"
                        )
                    observed.add(entry.name)
        except OSError as exc:
            raise ProvenanceVerificationError("cannot inventory acquired asset root") from exc
        if observed != set(expected):
            raise ProvenanceVerificationError(
                "acquired asset root does not contain the complete manifest inventory"
            )
        descriptor = os.open(
            asset.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow,
            dir_fd=root,
        )
        identity = _hash_descriptor(descriptor, asset)
        _same_path(root_path, root, root_identity, "acquired asset root")
        return RetainedAsset(descriptor, identity, root, root_identity)
    except BaseException:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.close(root)
        raise


def _require_retained_asset(
    retained: RetainedAsset,
    root_path: Path,
    asset: Asset,
) -> None:
    if _hash_descriptor(retained.descriptor, asset) != retained.identity:
        raise ProvenanceVerificationError(f"acquired asset {asset.name} changed")
    _same_path(root_path, retained.root_descriptor, retained.root_identity, "acquired asset root")
    try:
        reopened = os.open(
            asset.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=retained.root_descriptor,
        )
    except OSError as exc:
        raise ProvenanceVerificationError(f"acquired asset path {asset.name} changed") from exc
    try:
        if _hash_descriptor(reopened, asset) != retained.identity:
            raise ProvenanceVerificationError(f"acquired asset path {asset.name} changed")
    finally:
        with contextlib.suppress(OSError):
            os.close(reopened)


def _decode_payload(value: object) -> bytes:
    payload = _bounded_string(value, "Actions provenance payload", maximum=2_000_000)
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProvenanceVerificationError(
            "Actions provenance payload is not canonical base64"
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != payload:
        raise ProvenanceVerificationError("Actions provenance payload is not canonical base64")
    if not 1 <= len(decoded) <= MAX_ATTESTATION_PAYLOAD_BYTES:
        raise ProvenanceVerificationError("Actions provenance payload is outside its byte bound")
    return decoded


def _validated_timestamps(value: object) -> int:
    if not isinstance(value, list) or not value:
        raise ProvenanceVerificationError("Actions provenance has no verified timestamp")
    for index, raw in enumerate(value):
        timestamp = _exact_mapping(
            raw,
            {"timestamp", "type", "uri"},
            f"Actions provenance timestamp {index}",
        )
        if timestamp["type"] != "Tlog" or not _bounded_string(
            timestamp["uri"],
            f"Actions provenance timestamp {index} URI",
            maximum=1024,
        ).startswith("https://"):
            raise ProvenanceVerificationError("Actions provenance has an invalid timestamp")
        _bounded_string(
            timestamp["timestamp"],
            f"Actions provenance timestamp {index} value",
            maximum=128,
        )
    return len(value)


def _validate_subjects(value: object, asset: Asset) -> int:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ASSETS:
        raise ProvenanceVerificationError("Actions provenance has an invalid subject count")
    observed: set[str] = set()
    matches = 0
    for index, raw in enumerate(value):
        subject = _exact_mapping(
            raw,
            {"digest", "name"},
            f"Actions provenance subject {index}",
        )
        name = _bounded_string(
            subject["name"],
            f"Actions provenance subject {index} name",
            maximum=255,
        )
        if SAFE_NAME.fullmatch(name) is None or name in observed:
            raise ProvenanceVerificationError(
                "Actions provenance has an unsafe or duplicate subject"
            )
        digest = _exact_mapping(
            subject["digest"],
            {"sha256"},
            f"Actions provenance subject {index} digest",
        )
        sha256 = _digest(
            digest["sha256"],
            f"Actions provenance subject {index} SHA-256",
        )
        if name == asset.name and sha256 == asset.sha256:
            matches += 1
        observed.add(name)
    if matches != 1:
        raise ProvenanceVerificationError(
            "Actions provenance does not contain the selected asset exactly once"
        )
    return len(value)


def _validate_attestation(
    value: object,
    plan: ReleasePlan,
    workflow: AuthenticatedWorkflow,
    asset: Asset,
) -> VerifiedAttestation:
    result = _exact_mapping(
        value,
        {"attestation", "verificationResult"},
        "GitHub attestation-verification result",
    )
    attestation = _exact_mapping(
        result["attestation"],
        {"bundle", "bundle_url", "initiator"},
        "GitHub Actions attestation",
    )
    if attestation["bundle_url"] != "" or attestation["initiator"] != "":
        raise ProvenanceVerificationError(
            "GitHub Actions attestation retained unexpected API metadata"
        )
    bundle = _exact_mapping(
        attestation["bundle"],
        {"dsseEnvelope", "mediaType", "verificationMaterial"},
        "GitHub Actions attestation bundle",
    )
    if bundle["mediaType"] != github_release.SIGSTORE_BUNDLE_MEDIA_TYPE:
        raise ProvenanceVerificationError("Actions provenance has an unsupported bundle type")
    _exact_mapping(
        bundle["verificationMaterial"],
        {"certificate", "timestampVerificationData", "tlogEntries"},
        "Actions provenance verification material",
    )
    envelope = _exact_mapping(
        bundle["dsseEnvelope"],
        {"payload", "payloadType", "signatures"},
        "Actions provenance DSSE envelope",
    )
    if envelope["payloadType"] != github_release.DSSE_PAYLOAD_TYPE:
        raise ProvenanceVerificationError("Actions provenance has the wrong payload type")
    signatures = envelope["signatures"]
    if (
        not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], dict)
    ):
        raise ProvenanceVerificationError("Actions provenance has the wrong signature count")
    payload = _decode_payload(envelope["payload"])
    try:
        raw_statement = github_release.strict_json(
            payload,
            "Actions provenance statement",
            maximum=MAX_ATTESTATION_PAYLOAD_BYTES,
        )
    except github_release.VerificationError as exc:
        raise ProvenanceVerificationError(
            "Actions provenance statement is not strict bounded JSON"
        ) from exc
    statement = _exact_mapping(
        raw_statement,
        {"_type", "predicate", "predicateType", "subject"},
        "Actions provenance statement",
    )
    if (
        statement["_type"] != github_release.STATEMENT_TYPE
        or statement["predicateType"] != PREDICATE_TYPE
    ):
        raise ProvenanceVerificationError("Actions provenance statement has the wrong type")
    subject_count = _validate_subjects(statement["subject"], asset)

    verification = _exact_mapping(
        result["verificationResult"],
        {
            "mediaType",
            "signature",
            "statement",
            "verifiedIdentity",
            "verifiedTimestamps",
        },
        "GitHub Actions verification result",
    )
    if (
        verification["mediaType"] != github_release.VERIFICATION_RESULT_MEDIA_TYPE
        or verification["statement"] != statement
    ):
        raise ProvenanceVerificationError(
            "GitHub Actions verification result does not match its bundle"
        )
    timestamp_count = _validated_timestamps(verification["verifiedTimestamps"])

    expected_ref = f"refs/tags/{plan.tag}"
    repository_url = f"https://github.com/{plan.repository}"
    owner = plan.repository.partition("/")[0]
    signer_identity = f"{repository_url}/{plan.workflow_path}@{expected_ref}"
    verified_identity = _exact_mapping(
        verification["verifiedIdentity"],
        {"issuer", "runnerEnvironment", "subjectAlternativeName"},
        "Actions provenance verified identity",
    )
    alternative_name = _exact_mapping(
        verified_identity["subjectAlternativeName"],
        {"subjectAlternativeName"},
        "Actions provenance verified alternative name",
    )
    issuer = _exact_mapping(
        verified_identity["issuer"],
        {"issuer", "regexp"},
        "Actions provenance verified issuer",
    )
    if (
        alternative_name["subjectAlternativeName"] != signer_identity
        or issuer["issuer"] != ""
        or issuer["regexp"] != ".*"
        or verified_identity["runnerEnvironment"] != "github-hosted"
    ):
        raise ProvenanceVerificationError("Actions provenance verified identity is invalid")

    signature = _exact_mapping(
        verification["signature"],
        {"certificate"},
        "Actions provenance verified signature",
    )
    certificate = _exact_mapping(
        signature["certificate"],
        {
            "buildConfigDigest",
            "buildConfigURI",
            "buildSignerDigest",
            "buildSignerURI",
            "buildTrigger",
            "certificateIssuer",
            "githubWorkflowName",
            "githubWorkflowRef",
            "githubWorkflowRepository",
            "githubWorkflowSHA",
            "githubWorkflowTrigger",
            "issuer",
            "runInvocationURI",
            "runnerEnvironment",
            "sourceRepositoryDigest",
            "sourceRepositoryIdentifier",
            "sourceRepositoryOwnerIdentifier",
            "sourceRepositoryOwnerURI",
            "sourceRepositoryRef",
            "sourceRepositoryURI",
            "sourceRepositoryVisibilityAtSigning",
            "subjectAlternativeName",
        },
        "Actions provenance signing certificate",
    )
    expected_certificate = {
        "buildConfigDigest": plan.target_commit,
        "buildConfigURI": signer_identity,
        "buildSignerDigest": plan.target_commit,
        "buildSignerURI": signer_identity,
        "buildTrigger": "push",
        "githubWorkflowRef": expected_ref,
        "githubWorkflowRepository": plan.repository,
        "githubWorkflowSHA": plan.target_commit,
        "githubWorkflowTrigger": "push",
        "issuer": OIDC_ISSUER,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryDigest": plan.target_commit,
        "sourceRepositoryIdentifier": str(plan.repository_id),
        "sourceRepositoryOwnerIdentifier": str(workflow.owner_id),
        "sourceRepositoryOwnerURI": f"https://github.com/{owner}",
        "sourceRepositoryRef": expected_ref,
        "sourceRepositoryURI": repository_url,
        "subjectAlternativeName": signer_identity,
    }
    if any(certificate[key] != expected for key, expected in expected_certificate.items()):
        raise ProvenanceVerificationError(
            "Actions provenance signing certificate differs from the release identity"
        )
    _bounded_string(
        certificate["certificateIssuer"],
        "Actions provenance certificate issuer",
        maximum=1024,
    )
    _bounded_string(
        certificate["githubWorkflowName"],
        "Actions provenance workflow name",
        maximum=1024,
    )
    if certificate["sourceRepositoryVisibilityAtSigning"] not in {
        "internal",
        "private",
        "public",
    }:
        raise ProvenanceVerificationError("Actions provenance repository visibility is invalid")
    certificate_run = _bounded_string(
        certificate["runInvocationURI"],
        "Actions provenance run invocation URI",
        maximum=1024,
    )

    predicate = _exact_mapping(
        statement["predicate"],
        {"buildDefinition", "runDetails"},
        "Actions provenance predicate",
    )
    build_definition = _exact_mapping(
        predicate["buildDefinition"],
        {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        },
        "Actions provenance build definition",
    )
    if build_definition["buildType"] != BUILD_TYPE:
        raise ProvenanceVerificationError("Actions provenance has the wrong build type")
    external = _exact_mapping(
        build_definition["externalParameters"],
        {"workflow"},
        "Actions provenance external parameters",
    )
    external_workflow = _exact_mapping(
        external["workflow"],
        {"path", "ref", "repository"},
        "Actions provenance external workflow",
    )
    if external_workflow != {
        "path": plan.workflow_path,
        "ref": expected_ref,
        "repository": repository_url,
    }:
        raise ProvenanceVerificationError("Actions provenance names a different workflow")
    internal = _exact_mapping(
        build_definition["internalParameters"],
        {"github"},
        "Actions provenance internal parameters",
    )
    github = _exact_mapping(
        internal["github"],
        {"event_name", "repository_id", "repository_owner_id", "runner_environment"},
        "Actions provenance GitHub parameters",
    )
    if (
        github["event_name"] != "push"
        or _decimal_id(github["repository_id"], "Actions provenance repository ID")
        != plan.repository_id
        or _decimal_id(github["repository_owner_id"], "Actions provenance owner ID")
        != workflow.owner_id
        or github["runner_environment"] != "github-hosted"
    ):
        raise ProvenanceVerificationError("Actions provenance has different GitHub parameters")
    dependencies = build_definition["resolvedDependencies"]
    if not isinstance(dependencies, list) or len(dependencies) != 1:
        raise ProvenanceVerificationError(
            "Actions provenance has an unexpected resolved dependency set"
        )
    dependency = _exact_mapping(
        dependencies[0],
        {"digest", "uri"},
        "Actions provenance resolved dependency",
    )
    dependency_digest = _exact_mapping(
        dependency["digest"],
        {"gitCommit"},
        "Actions provenance resolved dependency digest",
    )
    if (
        dependency["uri"] != f"git+{repository_url}@{expected_ref}"
        or dependency_digest["gitCommit"] != plan.target_commit
    ):
        raise ProvenanceVerificationError("Actions provenance has a different resolved dependency")
    run_details = _exact_mapping(
        predicate["runDetails"],
        {"builder", "metadata"},
        "Actions provenance run details",
    )
    builder = _exact_mapping(
        run_details["builder"],
        {"id"},
        "Actions provenance builder",
    )
    metadata = _exact_mapping(
        run_details["metadata"],
        {"invocationId"},
        "Actions provenance run metadata",
    )
    predicate_run = _bounded_string(
        metadata["invocationId"],
        "Actions provenance predicate invocation ID",
        maximum=1024,
    )
    if builder["id"] != signer_identity or predicate_run != certificate_run:
        raise ProvenanceVerificationError(
            "Actions provenance run details differ from the signing certificate"
        )
    invocation_prefix = f"{workflow.url}/attempts/"
    if not certificate_run.startswith(invocation_prefix):
        raise ProvenanceVerificationError("Actions provenance names a different workflow run")
    _decimal_id(
        certificate_run.removeprefix(invocation_prefix),
        "Actions provenance run attempt",
    )
    return VerifiedAttestation(
        run_invocation=certificate_run,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        subject_count=subject_count,
        timestamp_count=timestamp_count,
    )


def _select_attestation(
    value: object,
    plan: ReleasePlan,
    workflow: AuthenticatedWorkflow,
    asset: Asset,
) -> VerifiedAttestation:
    if not isinstance(value, list) or not 1 <= len(value) <= ATTESTATION_LIMIT:
        raise ProvenanceVerificationError(
            "GitHub attestation verification returned an invalid result count"
        )
    expected_run = f"{workflow.url}/attempts/{workflow.run_attempt}"
    matches = [
        attestation
        for raw in value
        if (attestation := _validate_attestation(raw, plan, workflow, asset)).run_invocation
        == expected_run
    ]
    if len(matches) != 1:
        raise ProvenanceVerificationError(
            "Actions provenance does not identify the authenticated run attempt exactly once"
        )
    return matches[0]


def verify_actions_build_provenance(
    plan: ReleasePlan,
    workflow: AuthenticatedWorkflow,
    acquired: AcquiredAssets,
    *,
    expected_manifest_sha256: str,
    asset_root: Path,
    asset_name: str,
    client: ProvenanceClient,
) -> Mapping[str, object]:
    """Verify one acquired asset against exact Actions SLSA provenance."""

    _digest(expected_manifest_sha256, "trusted manifest SHA-256")
    if plan.manifest_sha256 != expected_manifest_sha256:
        raise ProvenanceVerificationError("release manifest does not match the trusted SHA-256")
    if plan.workflow_sha != plan.target_commit:
        raise ProvenanceVerificationError(
            "release workflow SHA does not match the tagged target commit"
        )
    if workflow.authenticated_release_sha256 != acquired.authenticated_release_sha256:
        raise ProvenanceVerificationError(
            "workflow and acquisition records name different authenticated releases"
        )
    if workflow.owner_id != acquired.owner_id:
        raise ProvenanceVerificationError(
            "workflow and acquisition records name different repository owners"
        )
    selected = [
        (asset, asset_id) for asset, asset_id in acquired.assets if asset.name == asset_name
    ]
    if len(selected) != 1:
        raise ProvenanceVerificationError(
            "selected asset is not named exactly once by the acquisition record"
        )
    asset, asset_id = selected[0]
    retained = _open_retained_asset(asset_root, plan, asset)
    try:
        version = client.check_version()
        expected_ref = f"refs/tags/{plan.tag}"
        signer_identity = (
            f"https://github.com/{plan.repository}/{plan.workflow_path}@{expected_ref}"
        )
        response = client.verify_attestation(
            asset_root / asset.name,
            repository=plan.repository,
            certificate_identity=signer_identity,
            signer_digest=plan.target_commit,
            source_digest=plan.target_commit,
            source_ref=expected_ref,
            predicate_type=PREDICATE_TYPE,
            limit=ATTESTATION_LIMIT,
        )
        attestation = _select_attestation(response, plan, workflow, asset)
        _require_retained_asset(retained, asset_root, asset)
    finally:
        with contextlib.suppress(OSError):
            os.close(retained.descriptor)
        with contextlib.suppress(OSError):
            os.close(retained.root_descriptor)
    return {
        "acquired_assets": {"sha256": acquired.record_sha256},
        "asset": {
            "github_asset_id": asset_id,
            "name": asset.name,
            "path": asset.name,
            "sha256": asset.sha256,
            "size": asset.size,
        },
        "attestation": {
            "bundle_media_type": github_release.SIGSTORE_BUNDLE_MEDIA_TYPE,
            "predicate_type": PREDICATE_TYPE,
            "statement_payload_sha256": attestation.payload_sha256,
            "subject_count": attestation.subject_count,
            "verification_media_type": github_release.VERIFICATION_RESULT_MEDIA_TYPE,
            "verified_timestamp_count": attestation.timestamp_count,
        },
        "authenticated_release": {"sha256": acquired.authenticated_release_sha256},
        "authenticated_workflow": {"sha256": workflow.record_sha256},
        "controller_manifest": {"sha256": plan.manifest_sha256},
        "github_cli": {
            "minimum_version": github_release.MINIMUM_GH_VERSION_TEXT,
            "version": version,
        },
        "kind": RECORD_KIND,
        "publication_allowed": False,
        "repository": {
            "id": plan.repository_id,
            "name": plan.repository,
            "owner_id": workflow.owner_id,
        },
        "schema_version": SCHEMA_VERSION,
        "tag": {"name": plan.tag, "target_commit": plan.target_commit},
        "workflow": {
            "file_sha256": workflow.file_sha256,
            "id": workflow.workflow_id,
            "path": plan.workflow_path,
            "ref": f"refs/tags/{plan.tag}",
            "run_attempt": workflow.run_attempt,
            "run_id": plan.run_id,
            "sha": plan.workflow_sha,
            "signer_identity": (
                f"https://github.com/{plan.repository}/{plan.workflow_path}@refs/tags/{plan.tag}"
            ),
            "url": workflow.url,
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=("Verify one acquired release asset's GitHub-hosted Actions build provenance.")
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--authenticated-workflow-record", type=Path, required=True)
    parser.add_argument("--authenticated-workflow-record-sha256", required=True)
    parser.add_argument("--acquisition-record", type=Path, required=True)
    parser.add_argument("--acquisition-record-sha256", required=True)
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--asset-name", required=True)
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
            raise ProvenanceVerificationError("release-controller manifest is invalid") from exc
        workflow = load_authenticated_workflow(
            arguments.authenticated_workflow_record,
            expected_sha256=arguments.authenticated_workflow_record_sha256,
            plan=plan,
        )
        acquired = load_acquired_assets(
            arguments.acquisition_record,
            expected_sha256=arguments.acquisition_record_sha256,
            plan=plan,
        )
        client = github_release.GitHubCLI(
            executable=arguments.gh,
            timeout=arguments.timeout_seconds,
        )
        result = verify_actions_build_provenance(
            plan,
            workflow,
            acquired,
            expected_manifest_sha256=arguments.manifest_sha256,
            asset_root=arguments.asset_root,
            asset_name=arguments.asset_name,
            client=client,
        )
        sys.stdout.buffer.write(canonical_json(result))
    except (ProvenanceVerificationError, github_release.VerificationError) as exc:
        sys.stderr.write(f"Actions build-provenance verification failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
