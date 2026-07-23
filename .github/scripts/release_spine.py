#!/usr/bin/env python3
"""Validate an opaque release-image spine without parsing OCI object bodies."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
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
RECORD_MEDIA_TYPE = "application/vnd.stampbot.oci-release-spine.v1+json"
SPINE_MEDIA_TYPE = "application/vnd.stampbot.oci-release-spine.v1+octet-stream"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"

MAX_RECORD_BYTES = 256 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_ITEMS = 4096
MAX_LAYERS_PER_PLATFORM = 64
MAX_OBJECTS = 160
MAX_SMALL_OBJECT_BYTES = 4 * 1024 * 1024
MAX_OBJECT_BYTES = 512 * 1024 * 1024
MAX_SPINE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ID = 2**63 - 1
READ_CHUNK_BYTES = 1024 * 1024

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
DECIMAL_ID = re.compile(r"^[1-9][0-9]{0,18}$")
VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REGISTRY = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
REGISTRY_REPOSITORY = re.compile(
    r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?)+$"
)
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
SAFE_REF_SUFFIX = re.compile(r"^refs/(?:heads|tags|pull)/[A-Za-z0-9_.\-/]+$")
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")

DESCRIPTOR_FIELDS = {"digest", "media_type", "size"}
OBJECT_FIELDS = {"digest", "kind", "media_type", "offset", "size"}
PLATFORM_FIELDS = {"architecture", "config", "layers", "manifest", "os"}
KIND_ORDER = {"layer": 0, "config": 1, "manifest": 2, "index": 3}
KIND_MEDIA_TYPE = {
    "layer": OCI_LAYER,
    "config": OCI_CONFIG,
    "manifest": OCI_MANIFEST,
    "index": OCI_INDEX,
}
PLATFORM_ORDER = (("amd64", "linux"), ("arm64", "linux"))


class SpineError(RuntimeError):
    """The release-spine contract was violated."""


@dataclasses.dataclass(frozen=True)
class ExpectedIdentity:
    """Trusted workflow values that an untrusted record must match exactly."""

    repository_id: str
    repository_name: str
    source_revision: str
    version: str
    workflow_path: str
    workflow_ref: str
    workflow_sha: str
    candidate_registry: str
    candidate_repository: str
    candidate_tag: str
    index_digest: str
    python_artifact_id: str
    python_artifact_sha256: str
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
class ObjectRange:
    """One immutable object range captured from a validated record."""

    digest: str
    offset: int
    size: int


@dataclasses.dataclass(frozen=True)
class VerifiedSpine:
    """A verified spine whose descriptor remains open for a future safe consumer."""

    descriptor: int
    objects: tuple[ObjectRange, ...]

    def object_chunks(self, digest: str) -> tuple[bytes, ...]:
        """Return one fully verified object as bounded immutable chunks."""

        matches = [item for item in self.objects if item.digest == digest]
        if len(matches) != 1:
            raise SpineError("requested object is not uniquely present in the verified record")
        item = matches[0]

        remaining = item.size
        position = item.offset
        object_hash = hashlib.sha256()
        chunks: list[bytes] = []
        while remaining:
            try:
                chunk = os.pread(self.descriptor, min(READ_CHUNK_BYTES, remaining), position)
            except OSError as exc:
                raise SpineError("cannot stage verified spine object safely") from exc
            if not chunk:
                raise SpineError("verified spine changed while a range was read")
            object_hash.update(chunk)
            chunks.append(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        if f"sha256:{object_hash.hexdigest()}" != item.digest:
            raise SpineError("verified spine changed before an object could be exposed")
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


def _descriptor(value: object, source: str, media_type: str) -> dict[str, object]:
    record = _exact_mapping(value, DESCRIPTOR_FIELDS, source)
    digest = _scalar(record["digest"], f"{source} digest", OCI_DIGEST, maximum=71)
    if record["media_type"] != media_type:
        raise SpineError(f"{source} has an unsupported media type")
    limit = MAX_OBJECT_BYTES if media_type == OCI_LAYER else MAX_SMALL_OBJECT_BYTES
    size = _integer(record["size"], f"{source} size", minimum=1, maximum=limit)
    return {"digest": digest, "media_type": media_type, "size": size}


def _projection(value: Mapping[str, Any]) -> dict[str, object]:
    return {
        "digest": value["digest"],
        "media_type": value["media_type"],
        "size": value["size"],
    }


def expected_spine_filename(source_revision: str) -> str:
    return f"extra-codeowners-image-{source_revision}.bin"


def expected_record_filename(source_revision: str) -> str:
    return f"extra-codeowners-image-{source_revision}.spine.json"


def validate_expected_identity(expected: ExpectedIdentity) -> None:
    """Validate trusted inputs before comparing them with untrusted data."""

    _decimal_id(expected.repository_id, "expected repository ID")
    _scalar(expected.repository_name, "expected repository name", REPOSITORY)
    _scalar(expected.source_revision, "expected source revision", HEX40, maximum=40)
    _scalar(expected.version, "expected version", VERSION, maximum=64)
    _scalar(expected.workflow_path, "expected workflow path", WORKFLOW_PATH)
    _workflow_ref(
        expected.workflow_ref,
        "expected workflow ref",
        expected.repository_name,
        expected.workflow_path,
    )
    _scalar(expected.workflow_sha, "expected workflow SHA", HEX40, maximum=40)
    _scalar(expected.candidate_registry, "expected candidate registry", REGISTRY, maximum=253)
    _scalar(
        expected.candidate_repository,
        "expected candidate repository",
        REGISTRY_REPOSITORY,
    )
    _scalar(expected.candidate_tag, "expected candidate tag", SAFE_FILENAME)
    if expected.candidate_tag != f"release-candidate-{expected.source_revision}":
        raise SpineError("expected candidate tag is not bound to the source revision")
    _scalar(expected.index_digest, "expected root OCI index digest", OCI_DIGEST, maximum=71)
    _decimal_id(expected.python_artifact_id, "expected Python artifact ID")
    for value, source in (
        (expected.python_artifact_sha256, "expected Python artifact SHA-256"),
        (expected.wheel_sha256, "expected application wheel SHA-256"),
        (expected.selection_record_sha256, "expected selection-record SHA-256"),
    ):
        _scalar(value, source, HEX64, maximum=64)


def validate_record(value: object, expected: ExpectedIdentity) -> Mapping[str, Any]:
    """Validate one parsed record and bind it to trusted workflow identity."""

    validate_expected_identity(expected)
    record = _exact_mapping(
        value,
        {
            "candidate",
            "index",
            "media_type",
            "objects",
            "platforms",
            "python_distribution",
            "repository",
            "schema_version",
            "source",
            "spine",
            "workflow",
        },
        "release-spine record",
    )
    if record["schema_version"] != SCHEMA_VERSION or isinstance(record["schema_version"], bool):
        raise SpineError("release-spine record has an unsupported schema version")
    if record["media_type"] != RECORD_MEDIA_TYPE:
        raise SpineError("release-spine record has an unsupported media type")

    repository = _exact_mapping(record["repository"], {"id", "name"}, "repository")
    if _decimal_id(repository["id"], "repository ID") != expected.repository_id:
        raise SpineError("repository ID does not match the trusted workflow value")
    if _scalar(repository["name"], "repository name", REPOSITORY) != expected.repository_name:
        raise SpineError("repository name does not match the trusted workflow value")

    source = _exact_mapping(record["source"], {"revision", "version"}, "source")
    if (
        _scalar(source["revision"], "source revision", HEX40, maximum=40)
        != expected.source_revision
    ):
        raise SpineError("source revision does not match the trusted workflow value")
    if _scalar(source["version"], "source version", VERSION, maximum=64) != expected.version:
        raise SpineError("source version does not match the trusted workflow value")

    workflow = _exact_mapping(record["workflow"], {"path", "ref", "sha"}, "workflow")
    if _scalar(workflow["path"], "workflow path", WORKFLOW_PATH) != expected.workflow_path:
        raise SpineError("workflow path does not match the trusted workflow value")
    workflow_ref = _workflow_ref(
        workflow["ref"], "workflow ref", expected.repository_name, expected.workflow_path
    )
    if workflow_ref != expected.workflow_ref:
        raise SpineError("workflow ref does not match the trusted workflow value")
    if _scalar(workflow["sha"], "workflow SHA", HEX40, maximum=40) != expected.workflow_sha:
        raise SpineError("workflow SHA does not match the trusted workflow value")

    candidate = _exact_mapping(record["candidate"], {"registry", "repository", "tag"}, "candidate")
    if _scalar(candidate["registry"], "candidate registry", REGISTRY, maximum=253) != (
        expected.candidate_registry
    ):
        raise SpineError("candidate registry does not match the trusted workflow value")
    if (
        _scalar(candidate["repository"], "candidate repository", REGISTRY_REPOSITORY)
        != expected.candidate_repository
    ):
        raise SpineError("candidate repository does not match the trusted workflow value")
    if _scalar(candidate["tag"], "candidate tag", SAFE_FILENAME) != expected.candidate_tag:
        raise SpineError("candidate tag does not match the trusted workflow value")

    python = _exact_mapping(
        record["python_distribution"],
        {"artifact_id", "artifact_sha256", "selection_record_sha256", "wheel_sha256"},
        "Python distribution",
    )
    if _decimal_id(python["artifact_id"], "Python artifact ID") != expected.python_artifact_id:
        raise SpineError("Python artifact ID does not match the trusted workflow value")
    for field, expected_value, source_name in (
        ("artifact_sha256", expected.python_artifact_sha256, "Python artifact SHA-256"),
        ("wheel_sha256", expected.wheel_sha256, "application wheel SHA-256"),
        (
            "selection_record_sha256",
            expected.selection_record_sha256,
            "selection-record SHA-256",
        ),
    ):
        if _scalar(python[field], source_name, HEX64, maximum=64) != expected_value:
            raise SpineError(f"{source_name} does not match the trusted workflow value")

    spine = _exact_mapping(record["spine"], {"filename", "media_type", "sha256", "size"}, "spine")
    filename = _scalar(spine["filename"], "spine filename", SAFE_FILENAME, maximum=255)
    if filename != expected_spine_filename(expected.source_revision):
        raise SpineError("spine filename is not bound to the source revision")
    if spine["media_type"] != SPINE_MEDIA_TYPE:
        raise SpineError("spine has an unsupported media type")
    _scalar(spine["sha256"], "spine SHA-256", HEX64, maximum=64)
    spine_size = _integer(spine["size"], "spine size", minimum=1, maximum=MAX_SPINE_BYTES)

    index = _descriptor(record["index"], "root index", OCI_INDEX)
    if index["digest"] != expected.index_digest:
        raise SpineError("root OCI index digest does not match the trusted BuildKit value")
    raw_platforms = record["platforms"]
    if not isinstance(raw_platforms, list) or len(raw_platforms) != len(PLATFORM_ORDER):
        raise SpineError("record must contain exactly the two supported platforms")
    platforms: list[dict[str, object]] = []
    referenced: list[tuple[str, dict[str, object]]] = [("index", index)]
    for position, (value_platform, expected_platform) in enumerate(
        zip(raw_platforms, PLATFORM_ORDER, strict=True)
    ):
        platform = _exact_mapping(value_platform, PLATFORM_FIELDS, f"platform {position}")
        architecture, operating_system = expected_platform
        if platform["architecture"] != architecture or platform["os"] != operating_system:
            raise SpineError("platforms are missing, unsupported, or out of order")
        manifest = _descriptor(platform["manifest"], f"{architecture} manifest", OCI_MANIFEST)
        config = _descriptor(platform["config"], f"{architecture} config", OCI_CONFIG)
        raw_layers = platform["layers"]
        if (
            not isinstance(raw_layers, list)
            or not raw_layers
            or len(raw_layers) > MAX_LAYERS_PER_PLATFORM
        ):
            raise SpineError(f"{architecture} has an invalid layer count")
        layers = [
            _descriptor(item, f"{architecture} layer {index_value}", OCI_LAYER)
            for index_value, item in enumerate(raw_layers)
        ]
        platforms.append(
            {
                "architecture": architecture,
                "os": operating_system,
                "manifest": manifest,
                "config": config,
                "layers": layers,
            }
        )
        referenced.extend((("manifest", manifest), ("config", config)))
        referenced.extend(("layer", layer) for layer in layers)

    raw_objects = record["objects"]
    if not isinstance(raw_objects, list) or not 1 <= len(raw_objects) <= MAX_OBJECTS:
        raise SpineError("record has an invalid object count")
    objects: list[dict[str, object]] = []
    digests: set[str] = set()
    expected_offset = 0
    for position, value_object in enumerate(raw_objects):
        item = _exact_mapping(value_object, OBJECT_FIELDS, f"object {position}")
        kind = item["kind"]
        if not isinstance(kind, str) or kind not in KIND_ORDER:
            raise SpineError(f"object {position} has an unsupported kind")
        descriptor = _descriptor(_projection(item), f"object {position}", KIND_MEDIA_TYPE[kind])
        offset = _integer(
            item["offset"], f"object {position} offset", minimum=0, maximum=MAX_SPINE_BYTES
        )
        if offset != expected_offset:
            raise SpineError("object ranges contain a prefix, gap, overlap, or alias")
        size = cast(int, descriptor["size"])
        expected_offset += size
        if expected_offset > MAX_SPINE_BYTES:
            raise SpineError("object ranges exceed the spine size limit")
        digest = str(descriptor["digest"])
        if digest in digests:
            raise SpineError("object digest is repeated or reused across kinds")
        digests.add(digest)
        objects.append({"kind": kind, "offset": offset, **descriptor})
    if expected_offset != spine_size:
        raise SpineError("object ranges do not cover the exact spine size")
    if objects != sorted(
        objects, key=lambda item: (KIND_ORDER[str(item["kind"])], str(item["digest"]))
    ):
        raise SpineError("objects are not in the canonical streaming order")

    object_by_digest = {str(item["digest"]): item for item in objects}
    referenced_digests: set[str] = set()
    kind_counts = dict.fromkeys(KIND_ORDER, 0)
    for kind, descriptor in referenced:
        digest = str(descriptor["digest"])
        actual = object_by_digest.get(digest)
        if actual is None or actual["kind"] != kind or _projection(actual) != descriptor:
            raise SpineError("an OCI descriptor does not match its spine object")
        referenced_digests.add(digest)
    for item in objects:
        kind_counts[str(item["kind"])] += 1
    if set(object_by_digest) != referenced_digests:
        raise SpineError("spine contains an unreferenced OCI object")
    if kind_counts["index"] != 1 or kind_counts["manifest"] != 2 or kind_counts["config"] != 2:
        raise SpineError("spine has an invalid index, manifest, or config count")

    return {
        **record,
        "index": index,
        "platforms": platforms,
        "objects": objects,
    }


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
        raise SpineError("release-spine verification requires O_NOFOLLOW support")
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


def load_record(path: Path, expected: ExpectedIdentity) -> tuple[Mapping[str, Any], str]:
    """Read and validate a canonical record from one stable file descriptor."""

    descriptor, identity = _open_regular(path, "release-spine record", maximum=MAX_RECORD_BYTES)
    try:
        chunks: list[bytes] = []
        remaining = identity.size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise SpineError("release-spine record is truncated")
            chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        _require_unchanged(descriptor, path, identity, "release-spine record")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    value = strict_json_bytes(raw, "release-spine record", canonical=True)
    return validate_record(value, expected), digest.hexdigest()


@contextlib.contextmanager
def open_verified_spine(
    path: Path,
    record: Mapping[str, Any],
    *,
    artifact_sha256: str,
) -> Iterator[VerifiedSpine]:
    """Verify every range once and retain the same descriptor for a future consumer."""

    expected_artifact = _scalar(
        artifact_sha256, "spine artifact provider SHA-256", HEX64, maximum=64
    )
    expected_hash = str(
        _exact_mapping(record["spine"], {"filename", "media_type", "sha256", "size"}, "spine")[
            "sha256"
        ]
    )
    if expected_artifact != expected_hash:
        raise SpineError("spine artifact provider digest does not match the record")
    objects = tuple(
        ObjectRange(
            digest=str(item["digest"]),
            offset=int(item["offset"]),
            size=int(item["size"]),
        )
        for item in record["objects"]
    )
    descriptor, identity = _open_regular(path, "release spine", maximum=MAX_SPINE_BYTES)
    try:
        if path.name != record["spine"]["filename"] or identity.size != record["spine"]["size"]:
            raise SpineError("release-spine path or size does not match the record")
        whole = hashlib.sha256()
        for item in objects:
            object_hash = hashlib.sha256()
            remaining = item.size
            while remaining:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise SpineError("release spine is truncated within an object range")
                whole.update(chunk)
                object_hash.update(chunk)
                remaining -= len(chunk)
            if f"sha256:{object_hash.hexdigest()}" != item.digest:
                raise SpineError(f"release-spine object digest mismatch: {item.digest}")
        if os.read(descriptor, 1):
            raise SpineError("release spine has trailing bytes")
        if whole.hexdigest() != expected_hash:
            raise SpineError("release-spine SHA-256 does not match the record")
        _require_unchanged(descriptor, path, identity, "release spine")
        yield VerifiedSpine(descriptor=descriptor, objects=objects)
        _require_unchanged(descriptor, path, identity, "release spine")
    finally:
        os.close(descriptor)


def verify(
    record_path: Path,
    spine_path: Path,
    expected: ExpectedIdentity,
    *,
    record_artifact_sha256: str,
    spine_artifact_sha256: str,
) -> Mapping[str, Any]:
    """Verify both raw artifacts and return the validated small record."""

    expected_record_hash = _scalar(
        record_artifact_sha256, "record artifact provider SHA-256", HEX64, maximum=64
    )
    if record_path.name != expected_record_filename(expected.source_revision):
        raise SpineError("record filename is not bound to the source revision")
    record, actual_record_hash = load_record(record_path, expected)
    if actual_record_hash != expected_record_hash:
        raise SpineError("record artifact provider digest does not match its bytes")
    with open_verified_spine(
        spine_path,
        record,
        artifact_sha256=spine_artifact_sha256,
    ):
        pass
    return record


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--repository-name", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--candidate-registry", required=True)
    parser.add_argument("--candidate-repository", required=True)
    parser.add_argument("--candidate-tag", required=True)
    parser.add_argument("--index-digest", required=True)
    parser.add_argument("--python-artifact-id", required=True)
    parser.add_argument("--python-artifact-sha256", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--selection-record-sha256", required=True)


def expected_from_args(args: argparse.Namespace) -> ExpectedIdentity:
    return ExpectedIdentity(
        repository_id=args.repository_id,
        repository_name=args.repository_name,
        source_revision=args.source_revision,
        version=args.version,
        workflow_path=args.workflow_path,
        workflow_ref=args.workflow_ref,
        workflow_sha=args.workflow_sha,
        candidate_registry=args.candidate_registry,
        candidate_repository=args.candidate_repository,
        candidate_tag=args.candidate_tag,
        index_digest=args.index_digest,
        python_artifact_id=args.python_artifact_id,
        python_artifact_sha256=args.python_artifact_sha256,
        wheel_sha256=args.wheel_sha256,
        selection_record_sha256=args.selection_record_sha256,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(required=True)
    verify_command = commands.add_parser("verify", help="verify two raw release-spine artifacts")
    verify_command.add_argument("--record", required=True)
    verify_command.add_argument("--spine", required=True)
    verify_command.add_argument("--record-artifact-sha256", required=True)
    verify_command.add_argument("--spine-artifact-sha256", required=True)
    add_identity_arguments(verify_command)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        verify(
            Path(args.record),
            Path(args.spine),
            expected_from_args(args),
            record_artifact_sha256=args.record_artifact_sha256,
            spine_artifact_sha256=args.spine_artifact_sha256,
        )
    except SpineError as exc:
        sys.stderr.write(f"release-spine error: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
