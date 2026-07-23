#!/usr/bin/env python3
"""Build a deterministic opaque spine from one pinned BuildKit OCI layout."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import os
import re
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import release_spine

OCI_LAYOUT_VERSION = "1.0.0"
OCI_LAYOUT_FIELDS = {"imageLayoutVersion"}
INDEX_FIELDS = {"manifests", "mediaType", "schemaVersion"}
WRAPPER_DESCRIPTOR_FIELDS = {"annotations", "digest", "mediaType", "size"}
PLATFORM_DESCRIPTOR_FIELDS = {"digest", "mediaType", "platform", "size"}
PLATFORM_FIELDS = {"architecture", "os"}
MANIFEST_FIELDS = {"config", "layers", "mediaType", "schemaVersion"}
MANIFEST_DESCRIPTOR_FIELDS = {"digest", "mediaType", "size"}
WRAPPER_ANNOTATION_FIELDS = {
    "io.containerd.image.name",
    "org.opencontainers.image.created",
    "org.opencontainers.image.ref.name",
}
CREATED = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$"
)
REVISION_LABEL = "org.opencontainers.image.revision"
VERSION_LABEL = "org.opencontainers.image.version"
WHEEL_LABEL = "org.stampbot.extra-codeowners.application-wheel.sha256"
SELECTION_LABEL = "org.stampbot.extra-codeowners.python-selection-record.sha256"
EXPECTED_PLATFORMS = (("amd64", "linux"), ("arm64", "linux"))


@dataclasses.dataclass(frozen=True)
class SourceObject:
    """One regular OCI object selected from the reviewed descriptor graph."""

    kind: str
    media_type: str
    digest: str
    size: int
    path: Path


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise release_spine.SpineError(f"{source} must contain exactly {sorted(fields)}")
    return value


def _integer(value: object, source: str, *, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise release_spine.SpineError(f"{source} is outside its integer bounds")
    return value


def _directory(path: Path, source: str) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise release_spine.SpineError(f"cannot inspect {source}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise release_spine.SpineError(f"{source} must be a real directory")


def _directory_names(path: Path, source: str, *, maximum: int) -> set[str]:
    _directory(path, source)
    try:
        names: set[str] = set()
        with os.scandir(path) as entries:
            for entry in entries:
                if len(names) >= maximum:
                    raise release_spine.SpineError(f"{source} has too many entries")
                names.add(entry.name)
        return names
    except OSError as exc:
        raise release_spine.SpineError(f"cannot enumerate {source}") from exc


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


@contextlib.contextmanager
def _open_regular(
    path: Path,
    source: str,
    *,
    maximum: int,
    exact_size: int | None = None,
) -> Iterator[tuple[int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise release_spine.SpineError("release-spine building requires O_NOFOLLOW support")
    try:
        descriptor = os.open(path, flags | nofollow)
    except OSError as exc:
        raise release_spine.SpineError(f"cannot open {source} safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= maximum
            or (exact_size is not None and before.st_size != exact_size)
        ):
            raise release_spine.SpineError(f"{source} is not one bounded single-link file")
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise release_spine.SpineError(f"{source} path changed while it was opened")
        yield descriptor, before.st_size
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if _file_signature(before) != _file_signature(after) or (
            current.st_dev,
            current.st_ino,
        ) != (before.st_dev, before.st_ino):
            raise release_spine.SpineError(f"{source} changed while it was read")
    except OSError as exc:
        raise release_spine.SpineError(f"{source} changed while it was read") from exc
    finally:
        os.close(descriptor)


def _read_regular(
    path: Path,
    source: str,
    *,
    maximum: int,
    exact_size: int | None = None,
) -> bytes:
    with _open_regular(path, source, maximum=maximum, exact_size=exact_size) as (descriptor, size):
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(release_spine.READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise release_spine.SpineError(f"{source} is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise release_spine.SpineError(f"{source} has trailing bytes")
        return b"".join(chunks)


def _json_file(path: Path, source: str) -> Any:
    return release_spine.strict_json_bytes(
        _read_regular(path, source, maximum=release_spine.MAX_SMALL_OBJECT_BYTES),
        source,
        canonical=False,
    )


def _descriptor(
    value: object,
    source: str,
    fields: set[str],
    media_type: str,
) -> dict[str, object]:
    descriptor = _exact_mapping(value, fields, source)
    digest = descriptor["digest"]
    if (
        not isinstance(digest, str)
        or release_spine.OCI_DIGEST.fullmatch(digest) is None
        or descriptor["mediaType"] != media_type
    ):
        raise release_spine.SpineError(f"{source} has an invalid digest or media type")
    limit = (
        release_spine.MAX_OBJECT_BYTES
        if media_type == release_spine.OCI_LAYER
        else release_spine.MAX_SMALL_OBJECT_BYTES
    )
    size = _integer(descriptor["size"], f"{source} size", maximum=limit)
    return {"digest": digest, "media_type": media_type, "size": size}


def _blob_path(layout: Path, digest: str) -> Path:
    return layout / "blobs" / "sha256" / digest.removeprefix("sha256:")


def _source_object(
    layout: Path,
    descriptor: Mapping[str, object],
    kind: str,
) -> SourceObject:
    digest = str(descriptor["digest"])
    size = cast(int, descriptor["size"])
    return SourceObject(
        kind=kind,
        media_type=str(descriptor["media_type"]),
        digest=digest,
        size=size,
        path=_blob_path(layout, digest),
    )


def _checked_json_object(
    layout: Path,
    descriptor: Mapping[str, object],
    kind: str,
    source: str,
) -> tuple[SourceObject, bytes]:
    selected = _source_object(layout, descriptor, kind)
    content = _read_regular(
        selected.path,
        source,
        maximum=release_spine.MAX_SMALL_OBJECT_BYTES,
        exact_size=selected.size,
    )
    if f"sha256:{hashlib.sha256(content).hexdigest()}" != selected.digest:
        raise release_spine.SpineError(f"{source} bytes do not match their descriptor")
    return selected, content


def _check_opaque_object(selected: SourceObject, source: str) -> None:
    digest = hashlib.sha256()
    with _open_regular(
        selected.path,
        source,
        maximum=release_spine.MAX_OBJECT_BYTES,
        exact_size=selected.size,
    ) as (file_descriptor, size):
        remaining = size
        while remaining:
            chunk = os.read(file_descriptor, min(release_spine.READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise release_spine.SpineError(f"{source} is truncated")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(file_descriptor, 1):
            raise release_spine.SpineError(f"{source} has trailing bytes")
    if f"sha256:{digest.hexdigest()}" != selected.digest:
        raise release_spine.SpineError(f"{source} bytes do not match their descriptor")


def _bounded_objects(objects: Mapping[str, SourceObject]) -> list[SourceObject]:
    if not 1 <= len(objects) <= release_spine.MAX_OBJECTS:
        raise release_spine.SpineError("OCI graph has too many unique objects")
    selected = sorted(
        objects.values(),
        key=lambda item: (release_spine.KIND_ORDER[item.kind], item.digest),
    )
    total = 0
    for item in selected:
        if item.size > release_spine.MAX_SPINE_BYTES - total:
            raise release_spine.SpineError("OCI graph exceeds the release-spine size limit")
        total += item.size
    return selected


def _parse_config(
    content: bytes,
    architecture: str,
    expected: release_spine.ExpectedIdentity,
) -> None:
    value = release_spine.strict_json_bytes(content, f"{architecture} config", canonical=False)
    if (
        not isinstance(value, dict)
        or value.get("architecture") != architecture
        or value.get("os") != "linux"
    ):
        raise release_spine.SpineError(f"{architecture} config has the wrong platform")
    runtime = value.get("config")
    if not isinstance(runtime, dict):
        raise release_spine.SpineError(f"{architecture} config has no runtime configuration")
    labels = runtime.get("Labels")
    if not isinstance(labels, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in labels.items()
    ):
        raise release_spine.SpineError(f"{architecture} config has invalid labels")
    required = {
        REVISION_LABEL: expected.source_revision,
        VERSION_LABEL: expected.version,
        WHEEL_LABEL: expected.wheel_sha256,
        SELECTION_LABEL: expected.selection_record_sha256,
    }
    for label, required_value in required.items():
        if labels.get(label) != required_value:
            raise release_spine.SpineError(f"{architecture} config label {label} changed")


def _wrapper_root(
    layout: Path,
    expected_index_digest: str,
    expected: release_spine.ExpectedIdentity,
) -> dict[str, object]:
    wrapper = _exact_mapping(
        _json_file(layout / "index.json", "OCI layout index"), INDEX_FIELDS, "OCI layout index"
    )
    if wrapper["schemaVersion"] != 2 or wrapper["mediaType"] != release_spine.OCI_INDEX:
        raise release_spine.SpineError("OCI layout index uses an unsupported schema or media type")
    manifests = wrapper["manifests"]
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise release_spine.SpineError("OCI layout index must contain one BuildKit root descriptor")
    raw_descriptor = _exact_mapping(
        manifests[0], WRAPPER_DESCRIPTOR_FIELDS, "BuildKit root descriptor"
    )
    descriptor = _descriptor(
        raw_descriptor,
        "BuildKit root descriptor",
        WRAPPER_DESCRIPTOR_FIELDS,
        release_spine.OCI_INDEX,
    )
    if descriptor["digest"] != expected_index_digest:
        raise release_spine.SpineError("BuildKit root descriptor does not match its trusted digest")
    annotations = _exact_mapping(
        raw_descriptor["annotations"], WRAPPER_ANNOTATION_FIELDS, "BuildKit root annotations"
    )
    candidate_name = (
        f"{expected.candidate_registry}/{expected.candidate_repository}:{expected.candidate_tag}"
    )
    if (
        annotations["io.containerd.image.name"] != candidate_name
        or annotations["org.opencontainers.image.ref.name"] != expected.candidate_tag
        or not isinstance(annotations["org.opencontainers.image.created"], str)
        or CREATED.fullmatch(annotations["org.opencontainers.image.created"]) is None
    ):
        raise release_spine.SpineError("BuildKit root annotations do not match the candidate")
    return descriptor


def inspect_layout(
    layout: Path,
    expected_index_digest: str,
    expected: release_spine.ExpectedIdentity,
) -> tuple[dict[str, object], list[dict[str, object]], list[SourceObject]]:
    """Validate one pinned BuildKit directory export without interpreting layers."""

    release_spine.validate_expected_identity(expected)
    if expected_index_digest != expected.index_digest:
        raise release_spine.SpineError("BuildKit index digest inputs disagree")
    if release_spine.OCI_DIGEST.fullmatch(expected_index_digest) is None:
        raise release_spine.SpineError("trusted BuildKit index digest is invalid")
    if _directory_names(layout, "OCI layout", maximum=4) != {
        "blobs",
        "index.json",
        "ingest",
        "oci-layout",
    }:
        raise release_spine.SpineError("OCI layout has missing or extra top-level entries")
    if _directory_names(layout / "ingest", "BuildKit ingest root", maximum=1):
        raise release_spine.SpineError("BuildKit ingest root is not empty")
    layout_record = _exact_mapping(
        _json_file(layout / "oci-layout", "OCI layout version"),
        OCI_LAYOUT_FIELDS,
        "OCI layout version",
    )
    if layout_record["imageLayoutVersion"] != OCI_LAYOUT_VERSION:
        raise release_spine.SpineError("OCI layout version is unsupported")
    if _directory_names(layout / "blobs", "OCI blob root", maximum=1) != {"sha256"}:
        raise release_spine.SpineError("OCI blob root has unexpected entries")
    raw_blob_names = _directory_names(
        layout / "blobs" / "sha256",
        "OCI SHA-256 blobs",
        maximum=release_spine.MAX_OBJECTS,
    )
    if not raw_blob_names or any(
        release_spine.HEX64.fullmatch(name) is None for name in raw_blob_names
    ):
        raise release_spine.SpineError("OCI blob store contains an invalid filename")

    root_descriptor = _wrapper_root(layout, expected_index_digest, expected)
    root_object, root_bytes = _checked_json_object(
        layout, root_descriptor, "index", "root OCI index"
    )
    root = _exact_mapping(
        release_spine.strict_json_bytes(root_bytes, "root OCI index", canonical=False),
        INDEX_FIELDS,
        "root OCI index",
    )
    if root["schemaVersion"] != 2 or root["mediaType"] != release_spine.OCI_INDEX:
        raise release_spine.SpineError("root OCI index uses an unsupported schema or media type")
    raw_platforms = root["manifests"]
    if not isinstance(raw_platforms, list) or len(raw_platforms) != len(EXPECTED_PLATFORMS):
        raise release_spine.SpineError("root OCI index must contain exactly two platforms")

    objects_by_digest: dict[str, SourceObject] = {root_object.digest: root_object}
    platform_records: list[dict[str, object]] = []
    for position, (raw_platform, expected_platform) in enumerate(
        zip(raw_platforms, EXPECTED_PLATFORMS, strict=True)
    ):
        architecture, operating_system = expected_platform
        raw_descriptor = _exact_mapping(
            raw_platform, PLATFORM_DESCRIPTOR_FIELDS, f"platform descriptor {position}"
        )
        descriptor = _descriptor(
            raw_descriptor,
            f"{architecture} manifest descriptor",
            PLATFORM_DESCRIPTOR_FIELDS,
            release_spine.OCI_MANIFEST,
        )
        platform = _exact_mapping(
            raw_descriptor["platform"], PLATFORM_FIELDS, f"{architecture} platform"
        )
        if platform != {"architecture": architecture, "os": operating_system}:
            raise release_spine.SpineError("root OCI platforms are missing or out of order")
        manifest_object, manifest_bytes = _checked_json_object(
            layout, descriptor, "manifest", f"{architecture} manifest"
        )
        manifest = _exact_mapping(
            release_spine.strict_json_bytes(
                manifest_bytes,
                f"{architecture} manifest",
                canonical=False,
            ),
            MANIFEST_FIELDS,
            f"{architecture} manifest",
        )
        if manifest["schemaVersion"] != 2 or manifest["mediaType"] != release_spine.OCI_MANIFEST:
            raise release_spine.SpineError(f"{architecture} manifest has an unsupported schema")
        config = _descriptor(
            manifest["config"],
            f"{architecture} config descriptor",
            MANIFEST_DESCRIPTOR_FIELDS,
            release_spine.OCI_CONFIG,
        )
        raw_layers = manifest["layers"]
        if (
            not isinstance(raw_layers, list)
            or not raw_layers
            or len(raw_layers) > release_spine.MAX_LAYERS_PER_PLATFORM
        ):
            raise release_spine.SpineError(f"{architecture} manifest has an invalid layer count")
        layers = [
            _descriptor(
                value,
                f"{architecture} layer descriptor {index}",
                MANIFEST_DESCRIPTOR_FIELDS,
                release_spine.OCI_LAYER,
            )
            for index, value in enumerate(raw_layers)
        ]
        config_object, config_bytes = _checked_json_object(
            layout, config, "config", f"{architecture} config"
        )
        _parse_config(config_bytes, architecture, expected)
        layer_objects = [_source_object(layout, layer, "layer") for layer in layers]
        for selected in (manifest_object, config_object, *layer_objects):
            previous = objects_by_digest.setdefault(selected.digest, selected)
            if previous != selected:
                raise release_spine.SpineError("OCI digest is reused with conflicting metadata")
        platform_records.append(
            {
                "architecture": architecture,
                "os": operating_system,
                "manifest": descriptor,
                "config": config,
                "layers": layers,
            }
        )

    expected_blob_names = {digest.removeprefix("sha256:") for digest in objects_by_digest}
    if raw_blob_names != expected_blob_names:
        raise release_spine.SpineError("OCI blob store has a missing or orphan object")
    selected_objects = _bounded_objects(objects_by_digest)
    for selected in selected_objects:
        if selected.kind == "layer":
            _check_opaque_object(selected, f"OCI layer {selected.digest}")
    return root_descriptor, platform_records, selected_objects


def _create_output(path: Path, source: str) -> int:
    try:
        parent = path.parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise release_spine.SpineError(f"cannot inspect {source} output directory") from exc
    if not stat.S_ISDIR(parent.st_mode):
        raise release_spine.SpineError(f"{source} output directory is not real")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise release_spine.SpineError("release-spine building requires O_NOFOLLOW support")
    try:
        return os.open(path, flags | nofollow, 0o600)
    except OSError as exc:
        raise release_spine.SpineError(f"cannot create {source} output safely") from exc


def _copy_object(output: int, selected: SourceObject, whole: Any) -> None:
    digest = hashlib.sha256()
    with _open_regular(
        selected.path,
        selected.digest,
        maximum=release_spine.MAX_OBJECT_BYTES,
        exact_size=selected.size,
    ) as (source, size):
        remaining = size
        while remaining:
            chunk = os.read(source, min(release_spine.READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise release_spine.SpineError(
                    f"OCI object changed before packing: {selected.digest}"
                )
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise release_spine.SpineError("release-spine output write was truncated")
                view = view[written:]
            digest.update(chunk)
            whole.update(chunk)
            remaining -= len(chunk)
        if os.read(source, 1):
            raise release_spine.SpineError(f"OCI object changed before packing: {selected.digest}")
    if f"sha256:{digest.hexdigest()}" != selected.digest:
        raise release_spine.SpineError(f"OCI object changed before packing: {selected.digest}")


def build(
    layout: Path,
    spine_output: Path,
    record_output: Path,
    expected_index_digest: str,
    expected: release_spine.ExpectedIdentity,
) -> Mapping[str, Any]:
    """Build and independently reverify one canonical spine and record pair."""

    if spine_output.name != release_spine.expected_spine_filename(
        expected.source_revision,
        expected.python_artifact_id,
        expected.run_id,
        expected.run_attempt,
    ):
        raise release_spine.SpineError(
            "spine output filename is not bound to the Python artifact and producer run"
        )
    if record_output.name != release_spine.expected_record_filename(
        expected.source_revision,
        expected.python_artifact_id,
        expected.run_id,
        expected.run_attempt,
    ):
        raise release_spine.SpineError(
            "record output filename is not bound to the Python artifact and producer run"
        )
    root, platforms, selected_objects = inspect_layout(layout, expected_index_digest, expected)
    output = _create_output(spine_output, "spine")
    whole = hashlib.sha256()
    object_records: list[dict[str, object]] = []
    offset = 0
    try:
        for selected in selected_objects:
            if selected.size > release_spine.MAX_SPINE_BYTES - offset:
                raise release_spine.SpineError("release spine exceeds the total size limit")
            _copy_object(output, selected, whole)
            object_records.append(
                {
                    "kind": selected.kind,
                    "media_type": selected.media_type,
                    "digest": selected.digest,
                    "offset": offset,
                    "size": selected.size,
                }
            )
            offset += selected.size
        os.fsync(output)
    finally:
        os.close(output)

    record: dict[str, object] = {
        "schema_version": release_spine.SCHEMA_VERSION,
        "media_type": release_spine.RECORD_MEDIA_TYPE,
        "repository": {"id": expected.repository_id, "name": expected.repository_name},
        "run": {"id": expected.run_id, "attempt": expected.run_attempt},
        "source": {"revision": expected.source_revision, "version": expected.version},
        "workflow": {
            "path": expected.workflow_path,
            "ref": expected.workflow_ref,
            "sha": expected.workflow_sha,
        },
        "candidate": {
            "registry": expected.candidate_registry,
            "repository": expected.candidate_repository,
            "tag": expected.candidate_tag,
        },
        "python_distribution": {
            "artifact_id": expected.python_artifact_id,
            "artifact_sha256": expected.python_artifact_sha256,
            "wheel_sha256": expected.wheel_sha256,
            "selection_record_sha256": expected.selection_record_sha256,
        },
        "spine": {
            "filename": spine_output.name,
            "media_type": release_spine.SPINE_MEDIA_TYPE,
            "size": offset,
            "sha256": whole.hexdigest(),
        },
        "index": root,
        "platforms": platforms,
        "objects": object_records,
    }
    validated = release_spine.validate_record(record, expected)
    record_bytes = release_spine.canonical_json(validated)
    if len(record_bytes) > release_spine.MAX_RECORD_BYTES:
        raise release_spine.SpineError("release-spine record exceeds its size limit")
    record_fd = _create_output(record_output, "record")
    try:
        view = memoryview(record_bytes)
        while view:
            written = os.write(record_fd, view)
            if written <= 0:
                raise release_spine.SpineError("release-spine record write was truncated")
            view = view[written:]
        os.fsync(record_fd)
    finally:
        os.close(record_fd)
    with release_spine.open_verified_spine(
        spine_output,
        validated,
        artifact_sha256=whole.hexdigest(),
    ):
        pass
    return validated


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--layout", required=True)
    result.add_argument("--spine-output", required=True)
    result.add_argument("--record-output", required=True)
    release_spine.add_identity_arguments(result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        build(
            Path(args.layout),
            Path(args.spine_output),
            Path(args.record_output),
            args.index_digest,
            release_spine.expected_from_args(args),
        )
    except release_spine.SpineError as exc:
        sys.stderr.write(f"release-spine builder error: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
