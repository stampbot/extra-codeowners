#!/usr/bin/env python3
"""Select the exact release platforms from an authenticated OCI root index."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import os
import re
import stat
import sys
import urllib.parse
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, cast

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import acquire_oci_index as index_acquisition  # noqa: E402
import verify_actions_build_provenance as actions_provenance  # noqa: E402
import verify_blob_signature as blob_signature  # noqa: E402
from release_controller import (  # noqa: E402
    HEX40,
    HEX64,
    MAX_ID,
    REPOSITORY,
    SEMANTIC_TAG,
    WORKFLOW_PATH,
    canonical_json,
)

SCHEMA_VERSION = 1
RECORD_KIND = "extra-codeowners/selected-oci-platforms"
INPUT_RECORD_KIND = index_acquisition.RECORD_KIND
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
DOCKER_REFERENCE_TYPE = "vnd.docker.reference.type"
DOCKER_REFERENCE_DIGEST = "vnd.docker.reference.digest"
ATTESTATION_MANIFEST = "attestation-manifest"
INDEX_NAME = index_acquisition.INDEX_NAME
SIGNATURE_NAME = index_acquisition.SIGNATURE_NAME
EXPECTED_DESCRIPTOR_COUNT = 4
MAX_CHILD_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_COSIGN_VERSION_BYTES = 64
MAX_RECORD_STRING_BYTES = 4096
SUPPORTED_PLATFORMS = (("linux", "amd64"), ("linux", "arm64"))

DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
COSIGN_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class OCIPlatformError(RuntimeError):
    """The authenticated OCI index did not satisfy the release platform policy."""


@dataclasses.dataclass(frozen=True)
class FileIdentity:
    """The expected identity of one retained acquisition file."""

    name: str
    sha256: str
    size: int


@dataclasses.dataclass(frozen=True)
class AuthenticatedIndex:
    """The relevant, internally consistent facts from the trusted input record."""

    record_sha256: str
    controller_manifest_sha256: str
    authenticated_workflow_sha256: str
    repository: str
    repository_id: int
    owner_id: int
    tag: str
    target_commit: str
    workflow_id: int
    workflow_path: str
    workflow_ref: str
    workflow_run_id: int
    workflow_run_attempt: int
    workflow_sha: str
    workflow_signer_identity: str
    workflow_url: str
    workflow_file_sha256: str
    image_repository: str
    image_reference: str
    image_digest: str
    index: FileIdentity
    signature: FileIdentity
    descriptor_count: int


@dataclasses.dataclass(frozen=True)
class Descriptor:
    """One exact descriptor selected from the authenticated root index."""

    position: int
    digest: str
    media_type: str
    size: int

    def record(self) -> Mapping[str, object]:
        """Return the stable record representation of this descriptor."""

        return {
            "digest": self.digest,
            "media_type": self.media_type,
            "position": self.position,
            "size": self.size,
        }


@dataclasses.dataclass(frozen=True)
class RetainedDirectory:
    """Open descriptors that keep the acquisition directory stable during parsing."""

    root: int
    root_identity: tuple[int, ...]
    files: Mapping[str, int]
    file_identities: Mapping[str, tuple[int, ...]]


def _exact_mapping(
    value: object,
    fields: set[str],
    source: str,
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OCIPlatformError(f"{source} must contain exactly {sorted(fields)}")
    return cast(Mapping[str, Any], value)


def _bounded_string(
    value: object,
    source: str,
    *,
    maximum: int = MAX_RECORD_STRING_BYTES,
) -> str:
    if not isinstance(value, str) or not value:
        raise OCIPlatformError(f"{source} must be a bounded nonempty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise OCIPlatformError(f"{source} is not valid Unicode") from None
    if len(encoded) > maximum:
        raise OCIPlatformError(f"{source} must be a bounded nonempty string")
    return value


def _positive_integer(value: object, source: str, *, maximum: int = MAX_ID) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise OCIPlatformError(f"{source} is outside its integer bound")
    return value


def _bounded_integer(
    value: object,
    source: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_ID,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise OCIPlatformError(f"{source} is outside its integer bound")
    return value


def _lower_digest(
    value: object,
    source: str,
    *,
    prefixed: bool = False,
) -> str:
    pattern = DIGEST if prefixed else HEX64
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise OCIPlatformError(f"{source} is not a lowercase SHA-256")
    return value


def _checked_string(
    value: object,
    source: str,
    pattern: re.Pattern[str],
    *,
    maximum: int,
) -> str:
    checked = _bounded_string(value, source, maximum=maximum)
    if pattern.fullmatch(checked) is None:
        raise OCIPlatformError(f"{source} is invalid")
    return checked


def _load_record(
    path: Path,
    expected_sha256: str,
) -> tuple[Mapping[str, Any], str]:
    try:
        return actions_provenance._read_canonical_record(
            path,
            expected_sha256=expected_sha256,
            source="authenticated OCI index record",
        )
    except actions_provenance.ProvenanceVerificationError as exc:
        raise OCIPlatformError("authenticated OCI index record is invalid") from exc


def _validate_cosign(value: object) -> None:
    record = _exact_mapping(
        value,
        {"maximum_major_version", "minimum_version", "version"},
        "authenticated OCI index Cosign record",
    )
    if record["maximum_major_version"] != blob_signature.MAX_COSIGN_MAJOR_VERSION:
        raise OCIPlatformError("authenticated OCI index has the wrong Cosign major bound")
    if record["minimum_version"] != blob_signature.MINIMUM_COSIGN_VERSION_TEXT:
        raise OCIPlatformError("authenticated OCI index has the wrong Cosign minimum")
    version = _checked_string(
        record["version"],
        "authenticated OCI index Cosign version",
        COSIGN_VERSION,
        maximum=MAX_COSIGN_VERSION_BYTES,
    )
    match = COSIGN_VERSION.fullmatch(version)
    if match is None:
        raise OCIPlatformError("authenticated OCI index Cosign version is invalid")
    parsed = tuple(int(part) for part in match.groups())
    if (
        parsed < blob_signature.MINIMUM_COSIGN_VERSION
        or parsed[0] > blob_signature.MAX_COSIGN_MAJOR_VERSION
    ):
        raise OCIPlatformError("authenticated OCI index Cosign version is unsupported")


def _validate_registry(
    value: object,
    *,
    repository: str,
    digest: str,
) -> None:
    record = _exact_mapping(
        value,
        {"host", "manifest_url", "redirects", "token_url"},
        "authenticated OCI index registry record",
    )
    if record["host"] != index_acquisition.GHCR_HOST or record["redirects"] != []:
        raise OCIPlatformError("authenticated OCI index has an unsupported registry path")
    expected_manifest = (
        f"https://{index_acquisition.GHCR_HOST}/v2/{repository}/manifests/"
        f"{urllib.parse.quote(digest, safe=':')}"
    )
    expected_token = "https://ghcr.io/token?" + urllib.parse.urlencode(
        {
            "service": index_acquisition.GHCR_HOST,
            "scope": f"repository:{repository}:pull",
        }
    )
    if record["manifest_url"] != expected_manifest or record["token_url"] != expected_token:
        raise OCIPlatformError("authenticated OCI index registry URLs disagree")


def _validate_signature(value: object) -> FileIdentity:
    record = _exact_mapping(
        value,
        {
            "certificate_sha256",
            "envelope_sha256",
            "integrated_time",
            "log_id",
            "log_index",
            "media_type",
            "path",
            "payload_sha256",
            "sha256",
            "signature_sha256",
            "size",
            "timestamp_count",
            "transparency_log_entry_count",
            "tree_size",
        },
        "authenticated OCI signature bundle",
    )
    for field in (
        "certificate_sha256",
        "envelope_sha256",
        "payload_sha256",
        "sha256",
        "signature_sha256",
    ):
        _lower_digest(record[field], f"authenticated OCI signature {field}")
    transparency_log_entry_count = _positive_integer(
        record["transparency_log_entry_count"],
        "authenticated OCI signature transparency-log entry count",
    )
    if (
        record["media_type"] != blob_signature.SIGSTORE_BUNDLE_MEDIA_TYPE
        or record["path"] != SIGNATURE_NAME
        or transparency_log_entry_count != 1
    ):
        raise OCIPlatformError("authenticated OCI signature identity is unsupported")
    _positive_integer(
        record["integrated_time"],
        "authenticated OCI signature integrated time",
    )
    _bounded_integer(
        record["log_index"],
        "authenticated OCI signature log index",
    )
    _positive_integer(
        record["tree_size"],
        "authenticated OCI signature proof tree size",
    )
    _bounded_integer(
        record["timestamp_count"],
        "authenticated OCI signature timestamp count",
        maximum=blob_signature.MAX_TIMESTAMP_COUNT,
    )
    _bounded_string(
        record["log_id"],
        "authenticated OCI signature log ID",
        maximum=1024,
    )
    size = _positive_integer(
        record["size"],
        "authenticated OCI signature bundle size",
        maximum=blob_signature.MAX_BUNDLE_BYTES,
    )
    return FileIdentity(
        name=SIGNATURE_NAME,
        sha256=cast(str, record["sha256"]),
        size=size,
    )


def load_authenticated_index(
    path: Path,
    *,
    expected_sha256: str,
) -> AuthenticatedIndex:
    """Load one canonical, independently hash-bound OCI acquisition record."""

    value, record_sha256 = _load_record(path, expected_sha256)
    record = _exact_mapping(
        value,
        {
            "authenticated_workflow",
            "controller_manifest",
            "cosign",
            "image",
            "kind",
            "publication_allowed",
            "registry",
            "repository",
            "schema_version",
            "signature_bundle",
            "tag",
            "workflow",
        },
        "authenticated OCI index record",
    )
    if (
        record["schema_version"] != index_acquisition.SCHEMA_VERSION
        or isinstance(record["schema_version"], bool)
        or record["kind"] != INPUT_RECORD_KIND
        or record["publication_allowed"] is not False
    ):
        raise OCIPlatformError("authenticated OCI index has an unsupported record header")

    controller_manifest = _exact_mapping(
        record["controller_manifest"],
        {"sha256"},
        "authenticated OCI index controller manifest",
    )
    controller_manifest_sha256 = _lower_digest(
        controller_manifest["sha256"],
        "authenticated OCI index controller manifest SHA-256",
    )
    authenticated_workflow = _exact_mapping(
        record["authenticated_workflow"],
        {"sha256"},
        "authenticated OCI index workflow input",
    )
    authenticated_workflow_sha256 = _lower_digest(
        authenticated_workflow["sha256"],
        "authenticated OCI index workflow input SHA-256",
    )
    _validate_cosign(record["cosign"])

    repository_record = _exact_mapping(
        record["repository"],
        {"id", "name", "owner_id"},
        "authenticated OCI index repository",
    )
    repository = _checked_string(
        repository_record["name"],
        "authenticated OCI index repository name",
        REPOSITORY,
        maximum=256,
    )
    if repository != repository.lower():
        raise OCIPlatformError("authenticated OCI index repository must be lowercase")
    repository_id = _positive_integer(
        repository_record["id"],
        "authenticated OCI index repository ID",
    )
    owner_id = _positive_integer(
        repository_record["owner_id"],
        "authenticated OCI index owner ID",
    )

    tag_record = _exact_mapping(
        record["tag"],
        {"name", "target_commit"},
        "authenticated OCI index tag",
    )
    tag = _checked_string(
        tag_record["name"],
        "authenticated OCI index tag name",
        SEMANTIC_TAG,
        maximum=64,
    )
    target_commit = _checked_string(
        tag_record["target_commit"],
        "authenticated OCI index target commit",
        HEX40,
        maximum=40,
    )

    workflow = _exact_mapping(
        record["workflow"],
        {
            "file_sha256",
            "id",
            "path",
            "ref",
            "run_attempt",
            "run_id",
            "sha",
            "signer_identity",
            "url",
        },
        "authenticated OCI index workflow",
    )
    workflow_id = _positive_integer(
        workflow["id"],
        "authenticated OCI index workflow ID",
    )
    workflow_path = _checked_string(
        workflow["path"],
        "authenticated OCI index workflow path",
        WORKFLOW_PATH,
        maximum=255,
    )
    workflow_ref = f"refs/tags/{tag}"
    workflow_run_id = _positive_integer(
        workflow["run_id"],
        "authenticated OCI index workflow run ID",
    )
    workflow_run_attempt = _positive_integer(
        workflow["run_attempt"],
        "authenticated OCI index workflow run attempt",
    )
    workflow_sha = _checked_string(
        workflow["sha"],
        "authenticated OCI index workflow SHA",
        HEX40,
        maximum=40,
    )
    workflow_file_sha256 = _lower_digest(
        workflow["file_sha256"],
        "authenticated OCI index workflow file SHA-256",
    )
    workflow_signer_identity = f"https://github.com/{repository}/{workflow_path}@{workflow_ref}"
    workflow_url = f"https://github.com/{repository}/actions/runs/{workflow_run_id}"
    if (
        workflow["ref"] != workflow_ref
        or workflow_sha != target_commit
        or workflow["signer_identity"] != workflow_signer_identity
        or workflow["url"] != workflow_url
    ):
        raise OCIPlatformError("authenticated OCI index workflow identity disagrees")

    image = _exact_mapping(
        record["image"],
        {"digest", "index", "reference", "repository"},
        "authenticated OCI index image",
    )
    image_digest = _lower_digest(
        image["digest"],
        "authenticated OCI index image digest",
        prefixed=True,
    )
    image_repository = f"{index_acquisition.GHCR_HOST}/{repository}"
    image_reference = f"{image_repository}@{image_digest}"
    if image["repository"] != image_repository or image["reference"] != image_reference:
        raise OCIPlatformError("authenticated OCI index image identity disagrees")

    index = _exact_mapping(
        image["index"],
        {"descriptor_count", "media_type", "path", "sha256", "size"},
        "authenticated OCI index file",
    )
    descriptor_count = _positive_integer(
        index["descriptor_count"],
        "authenticated OCI index descriptor count",
        maximum=index_acquisition.MAX_INDEX_DESCRIPTORS,
    )
    index_sha256 = _lower_digest(
        index["sha256"],
        "authenticated OCI index file SHA-256",
    )
    if (
        index["media_type"] != index_acquisition.OCI_INDEX_MEDIA_TYPE
        or index["path"] != INDEX_NAME
        or image_digest != f"sha256:{index_sha256}"
    ):
        raise OCIPlatformError("authenticated OCI index file identity disagrees")
    index_size = _positive_integer(
        index["size"],
        "authenticated OCI index file size",
        maximum=index_acquisition.MAX_INDEX_BYTES,
    )
    index_identity = FileIdentity(
        name=INDEX_NAME,
        sha256=index_sha256,
        size=index_size,
    )
    signature_identity = _validate_signature(record["signature_bundle"])
    _validate_registry(
        record["registry"],
        repository=repository,
        digest=image_digest,
    )

    return AuthenticatedIndex(
        record_sha256=record_sha256,
        controller_manifest_sha256=controller_manifest_sha256,
        authenticated_workflow_sha256=authenticated_workflow_sha256,
        repository=repository,
        repository_id=repository_id,
        owner_id=owner_id,
        tag=tag,
        target_commit=target_commit,
        workflow_id=workflow_id,
        workflow_path=workflow_path,
        workflow_ref=workflow_ref,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        workflow_sha=workflow_sha,
        workflow_signer_identity=workflow_signer_identity,
        workflow_url=workflow_url,
        workflow_file_sha256=workflow_file_sha256,
        image_repository=image_repository,
        image_reference=image_reference,
        image_digest=image_digest,
        index=index_identity,
        signature=signature_identity,
        descriptor_count=descriptor_count,
    )


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


def _same_directory(
    path: Path,
    descriptor: int,
    expected: tuple[int, ...],
) -> None:
    try:
        current = os.stat(path, follow_symlinks=False)
        retained = os.fstat(descriptor)
    except OSError as exc:
        raise OCIPlatformError("authenticated OCI directory changed") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or not stat.S_ISDIR(retained.st_mode)
        or current.st_dev != retained.st_dev
        or current.st_ino != retained.st_ino
        or _file_identity(retained) != expected
    ):
        raise OCIPlatformError("authenticated OCI directory changed")


def _hash_descriptor(
    descriptor: int,
    expected: FileIdentity,
    *,
    return_bytes: bool,
) -> tuple[tuple[int, ...], bytes | None]:
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != expected.size
        ):
            raise OCIPlatformError(f"authenticated OCI file {expected.name} has an unsafe identity")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        position = 0
        remaining = expected.size
        while remaining:
            chunk = os.pread(
                descriptor,
                min(index_acquisition.READ_CHUNK_BYTES, remaining),
                position,
            )
            if not chunk:
                raise OCIPlatformError(f"authenticated OCI file {expected.name} was truncated")
            digest.update(chunk)
            if return_bytes:
                chunks.append(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        if os.pread(descriptor, 1, position):
            raise OCIPlatformError(f"authenticated OCI file {expected.name} has trailing bytes")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise OCIPlatformError(f"cannot inspect authenticated OCI file {expected.name}") from exc
    identity = _file_identity(before)
    if _file_identity(after) != identity:
        raise OCIPlatformError(f"authenticated OCI file {expected.name} changed while reading")
    if digest.hexdigest() != expected.sha256:
        raise OCIPlatformError(f"authenticated OCI file {expected.name} has the wrong SHA-256")
    return identity, b"".join(chunks) if return_bytes else None


def _inventory(
    root: int,
    expected: Mapping[str, FileIdentity],
) -> None:
    observed: set[str] = set()
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if len(observed) >= len(expected):
                    raise OCIPlatformError("authenticated OCI directory has an unexpected entry")
                if entry.name in observed or entry.name not in expected:
                    raise OCIPlatformError("authenticated OCI directory has an unexpected entry")
                metadata = os.stat(entry.name, dir_fd=root, follow_symlinks=False)
                wanted = expected[entry.name]
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size != wanted.size
                ):
                    raise OCIPlatformError(
                        f"authenticated OCI file {entry.name} has an unsafe identity"
                    )
                observed.add(entry.name)
    except OSError as exc:
        raise OCIPlatformError("cannot inventory authenticated OCI directory") from exc
    if observed != set(expected):
        raise OCIPlatformError("authenticated OCI directory is incomplete")


@contextlib.contextmanager
def _retained_directory(
    path: Path,
    authenticated: AuthenticatedIndex,
) -> Iterator[tuple[RetainedDirectory, bytes]]:
    """Open and close the exact retained files around one selection operation."""

    if not path.is_absolute():
        raise OCIPlatformError("authenticated OCI directory must be absolute")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise OCIPlatformError("platform selection requires directory no-follow support")
    try:
        root = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory,
        )
    except OSError as exc:
        raise OCIPlatformError("cannot open authenticated OCI directory safely") from exc

    expected = {
        authenticated.index.name: authenticated.index,
        authenticated.signature.name: authenticated.signature,
    }
    try:
        root_metadata = os.fstat(root)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise OCIPlatformError(
                "authenticated OCI directory is not one owned mode-0700 directory"
            )
        root_identity = _file_identity(root_metadata)
        _inventory(root, expected)
        try:
            with os.fdopen(
                os.open(
                    INDEX_NAME,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | nofollow,
                    dir_fd=root,
                ),
                "rb",
                closefd=True,
            ) as index_file:
                index_descriptor = index_file.fileno()
                index_identity, index_raw = _hash_descriptor(
                    index_descriptor,
                    authenticated.index,
                    return_bytes=True,
                )
                if index_raw is None:
                    raise OCIPlatformError("authenticated OCI directory has no index bytes")
                try:
                    with os.fdopen(
                        os.open(
                            SIGNATURE_NAME,
                            os.O_RDONLY
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NONBLOCK", 0)
                            | nofollow,
                            dir_fd=root,
                        ),
                        "rb",
                        closefd=True,
                    ) as signature_file:
                        signature_descriptor = signature_file.fileno()
                        signature_identity, _ = _hash_descriptor(
                            signature_descriptor,
                            authenticated.signature,
                            return_bytes=False,
                        )
                        _same_directory(path, root, root_identity)
                        yield (
                            RetainedDirectory(
                                root=root,
                                root_identity=root_identity,
                                files={
                                    INDEX_NAME: index_descriptor,
                                    SIGNATURE_NAME: signature_descriptor,
                                },
                                file_identities={
                                    INDEX_NAME: index_identity,
                                    SIGNATURE_NAME: signature_identity,
                                },
                            ),
                            index_raw,
                        )
                except OSError as exc:
                    raise OCIPlatformError(
                        f"cannot open authenticated OCI file {SIGNATURE_NAME} safely"
                    ) from exc
        except OSError as exc:
            raise OCIPlatformError(
                f"cannot open authenticated OCI file {INDEX_NAME} safely"
            ) from exc
    finally:
        with contextlib.suppress(OSError):
            os.close(root)


def _require_retained_directory(
    retained: RetainedDirectory,
    path: Path,
    authenticated: AuthenticatedIndex,
) -> None:
    expected = {
        authenticated.index.name: authenticated.index,
        authenticated.signature.name: authenticated.signature,
    }
    _inventory(retained.root, expected)
    for name, wanted in expected.items():
        identity, _ = _hash_descriptor(
            retained.files[name],
            wanted,
            return_bytes=False,
        )
        if identity != retained.file_identities[name]:
            raise OCIPlatformError(f"authenticated OCI file {name} changed")
        try:
            reopened = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=retained.root,
            )
        except OSError as exc:
            raise OCIPlatformError(f"authenticated OCI file {name} changed") from exc
        try:
            reopened_identity, _ = _hash_descriptor(
                reopened,
                wanted,
                return_bytes=False,
            )
            if reopened_identity != retained.file_identities[name]:
                raise OCIPlatformError(f"authenticated OCI file {name} changed")
        finally:
            with contextlib.suppress(OSError):
                os.close(reopened)
    _same_directory(path, retained.root, retained.root_identity)


def _descriptor(
    value: object,
    *,
    position: int,
    platform: tuple[str, str],
    target_digest: str | None,
) -> Descriptor:
    os_name, architecture = platform
    source = f"OCI index descriptor {position}"
    expected_fields = {"digest", "mediaType", "platform", "size"}
    if target_digest is not None:
        expected_fields.add("annotations")
    record = _exact_mapping(value, expected_fields, source)
    if record["mediaType"] != OCI_MANIFEST_MEDIA_TYPE:
        raise OCIPlatformError(f"{source} has an unsupported media type")
    digest = _lower_digest(record["digest"], f"{source} digest", prefixed=True)
    size = _positive_integer(
        record["size"],
        f"{source} size",
        maximum=MAX_CHILD_MANIFEST_BYTES,
    )
    platform_record = _exact_mapping(
        record["platform"],
        {"architecture", "os"},
        f"{source} platform",
    )
    if platform_record["os"] != os_name or platform_record["architecture"] != architecture:
        raise OCIPlatformError(f"{source} has the wrong platform")
    if target_digest is not None:
        annotations = _exact_mapping(
            record["annotations"],
            {DOCKER_REFERENCE_DIGEST, DOCKER_REFERENCE_TYPE},
            f"{source} annotations",
        )
        if (
            annotations[DOCKER_REFERENCE_TYPE] != ATTESTATION_MANIFEST
            or annotations[DOCKER_REFERENCE_DIGEST] != target_digest
        ):
            raise OCIPlatformError(f"{source} is not the matching BuildKit attestation manifest")
    return Descriptor(
        position=position,
        digest=digest,
        media_type=OCI_MANIFEST_MEDIA_TYPE,
        size=size,
    )


def _select_descriptors(
    raw: bytes,
    authenticated: AuthenticatedIndex,
) -> Mapping[str, tuple[Descriptor, Descriptor]]:
    try:
        value = blob_signature._strict_json(
            raw,
            "authenticated OCI root index",
            maximum=index_acquisition.MAX_INDEX_BYTES,
        )
    except blob_signature.BlobVerificationError as exc:
        raise OCIPlatformError("authenticated OCI root index is not strict JSON") from exc
    root = _exact_mapping(
        value,
        {"manifests", "mediaType", "schemaVersion"},
        "authenticated OCI root index",
    )
    manifests = root["manifests"]
    if (
        root["schemaVersion"] != 2
        or isinstance(root["schemaVersion"], bool)
        or root["mediaType"] != index_acquisition.OCI_INDEX_MEDIA_TYPE
        or not isinstance(manifests, list)
        or len(manifests) != EXPECTED_DESCRIPTOR_COUNT
        or authenticated.descriptor_count != EXPECTED_DESCRIPTOR_COUNT
    ):
        raise OCIPlatformError(
            "authenticated OCI root index does not have the required four descriptors"
        )

    selected: dict[str, tuple[Descriptor, Descriptor]] = {}
    image_descriptors: list[Descriptor] = []
    for position, platform in enumerate(SUPPORTED_PLATFORMS):
        descriptor = _descriptor(
            manifests[position],
            position=position,
            platform=platform,
            target_digest=None,
        )
        image_descriptors.append(descriptor)
    for offset, (platform, image_descriptor) in enumerate(
        zip(SUPPORTED_PLATFORMS, image_descriptors, strict=True),
        start=len(SUPPORTED_PLATFORMS),
    ):
        attestation = _descriptor(
            manifests[offset],
            position=offset,
            platform=("unknown", "unknown"),
            target_digest=image_descriptor.digest,
        )
        selected[f"{platform[0]}/{platform[1]}"] = (
            image_descriptor,
            attestation,
        )

    digests = [descriptor.digest for pair in selected.values() for descriptor in pair]
    if len(set(digests)) != EXPECTED_DESCRIPTOR_COUNT:
        raise OCIPlatformError("authenticated OCI root index repeats a descriptor digest")
    return selected


def select_oci_platforms(
    authenticated: AuthenticatedIndex,
    *,
    directory: Path,
) -> Mapping[str, object]:
    """Select two platform and two linked BuildKit descriptors without network access."""

    with _retained_directory(directory, authenticated) as (retained, raw):
        if hashlib.sha256(raw).hexdigest() != authenticated.index.sha256:
            raise OCIPlatformError("authenticated OCI root index bytes changed")
        selected = _select_descriptors(raw, authenticated)
        _require_retained_directory(retained, directory, authenticated)

    return {
        "authenticated_oci_index": {"sha256": authenticated.record_sha256},
        "controller_manifest": {
            "sha256": authenticated.controller_manifest_sha256,
        },
        "image": {
            "digest": authenticated.image_digest,
            "index": {
                "descriptor_count": authenticated.descriptor_count,
                "media_type": index_acquisition.OCI_INDEX_MEDIA_TYPE,
                "path": authenticated.index.name,
                "sha256": authenticated.index.sha256,
                "size": authenticated.index.size,
            },
            "platforms": {
                name: {
                    "attestation_manifest": attestation.record(),
                    "image_manifest": image.record(),
                }
                for name, (image, attestation) in selected.items()
            },
            "reference": authenticated.image_reference,
            "repository": authenticated.image_repository,
            "signature_bundle": {
                "path": authenticated.signature.name,
                "sha256": authenticated.signature.sha256,
                "size": authenticated.signature.size,
            },
        },
        "kind": RECORD_KIND,
        "publication_allowed": False,
        "repository": {
            "id": authenticated.repository_id,
            "name": authenticated.repository,
            "owner_id": authenticated.owner_id,
        },
        "schema_version": SCHEMA_VERSION,
        "tag": {
            "name": authenticated.tag,
            "target_commit": authenticated.target_commit,
        },
        "workflow": {
            "file_sha256": authenticated.workflow_file_sha256,
            "id": authenticated.workflow_id,
            "path": authenticated.workflow_path,
            "ref": authenticated.workflow_ref,
            "run_attempt": authenticated.workflow_run_attempt,
            "run_id": authenticated.workflow_run_id,
            "sha": authenticated.workflow_sha,
            "signer_identity": authenticated.workflow_signer_identity,
            "url": authenticated.workflow_url,
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Select the two release image manifests and their linked BuildKit "
            "attestation manifests from one authenticated OCI root index."
        )
    )
    parser.add_argument(
        "--authenticated-index-record",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--authenticated-index-record-sha256",
        required=True,
    )
    parser.add_argument(
        "--authenticated-index-directory",
        type=Path,
        required=True,
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        authenticated = load_authenticated_index(
            arguments.authenticated_index_record,
            expected_sha256=arguments.authenticated_index_record_sha256,
        )
        result = select_oci_platforms(
            authenticated,
            directory=arguments.authenticated_index_directory,
        )
        sys.stdout.buffer.write(canonical_json(result))
    except OCIPlatformError as exc:
        sys.stderr.write(f"OCI platform selection failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
