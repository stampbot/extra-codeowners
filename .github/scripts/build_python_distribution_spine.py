#!/usr/bin/env python3
"""Build a deterministic opaque spine from one verified five-file Python proof."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import os
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import build_python_artifacts
import python_distribution_spine


@dataclasses.dataclass(frozen=True)
class SourceFile:
    """One selected regular file with its already-reviewed identity."""

    filename: str
    kind: str
    sha256: str
    size: int
    path: Path


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
    exact_size: int,
) -> Iterator[int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise python_distribution_spine.SpineError(
            "Python-distribution spine building requires O_NOFOLLOW support"
        )
    try:
        descriptor = os.open(path, flags | nofollow)
    except OSError as exc:
        raise python_distribution_spine.SpineError(f"cannot open {source} safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= maximum
            or before.st_size != exact_size
        ):
            raise python_distribution_spine.SpineError(
                f"{source} is not one bounded single-link file"
            )
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise python_distribution_spine.SpineError(f"{source} path changed while it was opened")
        yield descriptor
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if _file_signature(before) != _file_signature(after) or (
            current.st_dev,
            current.st_ino,
        ) != (before.st_dev, before.st_ino):
            raise python_distribution_spine.SpineError(f"{source} changed while it was read")
    except OSError as exc:
        raise python_distribution_spine.SpineError(f"{source} changed while it was read") from exc
    finally:
        os.close(descriptor)


def _create_output(path: Path, source: str) -> int:
    try:
        parent = path.parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise python_distribution_spine.SpineError(
            f"cannot inspect {source} output directory"
        ) from exc
    if not stat.S_ISDIR(parent.st_mode):
        raise python_distribution_spine.SpineError(f"{source} output directory is not real")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise python_distribution_spine.SpineError(
            "Python-distribution spine building requires O_NOFOLLOW support"
        )
    try:
        return os.open(path, flags | nofollow, 0o600)
    except OSError as exc:
        raise python_distribution_spine.SpineError(f"cannot create {source} output safely") from exc


def _write_all(descriptor: int, content: bytes, source: str) -> None:
    view = memoryview(content)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as exc:
            raise python_distribution_spine.SpineError(f"cannot write {source} safely") from exc
        if written <= 0:
            raise python_distribution_spine.SpineError(f"{source} write was truncated")
        view = view[written:]


def _kind_for_filename(filename: str) -> str:
    for kind, expected in python_distribution_spine.FIXED_KIND_FILENAMES.items():
        if filename == expected:
            return kind
    if python_distribution_spine.WHEEL_FILENAME.fullmatch(filename) is not None:
        return "wheel"
    if python_distribution_spine.SDIST_FILENAME.fullmatch(filename) is not None:
        return "sdist"
    raise python_distribution_spine.SpineError(
        f"selected distribution has an unsupported filename: {filename}"
    )


def _selected_sources(directory: Path) -> list[SourceFile]:
    raw_records = build_python_artifacts.selected_file_records(directory)
    if len(raw_records) != len(python_distribution_spine.KIND_ORDER):
        raise python_distribution_spine.SpineError(
            "selected distribution does not contain exactly five file records"
        )
    sources: dict[str, SourceFile] = {}
    for position, raw in enumerate(raw_records):
        if not isinstance(raw, dict) or set(raw) != {"filename", "sha256", "size"}:
            raise python_distribution_spine.SpineError(
                f"selected file record {position} has an invalid shape"
            )
        filename = raw.get("filename")
        digest = raw.get("sha256")
        size = raw.get("size")
        if (
            not isinstance(filename, str)
            or python_distribution_spine.SAFE_FILENAME.fullmatch(filename) is None
            or not isinstance(digest, str)
            or python_distribution_spine.HEX64.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
        ):
            raise python_distribution_spine.SpineError(
                f"selected file record {position} has an invalid identity"
            )
        kind = _kind_for_filename(filename)
        maximum = (
            python_distribution_spine.MAX_ARCHIVE_FILE_BYTES
            if kind in {"sdist", "wheel"}
            else python_distribution_spine.MAX_RECORD_FILE_BYTES
        )
        if not 1 <= size <= maximum or kind in sources:
            raise python_distribution_spine.SpineError(
                "selected distribution has a repeated or oversized file kind"
            )
        sources[kind] = SourceFile(
            filename=filename,
            kind=kind,
            sha256=digest,
            size=size,
            path=directory / filename,
        )
    if set(sources) != set(python_distribution_spine.KIND_ORDER):
        raise python_distribution_spine.SpineError(
            "selected distribution is missing a required file kind"
        )
    return [sources[kind] for kind in python_distribution_spine.KIND_ORDER]


def _copy_source(output: int, selected: SourceFile, whole: Any) -> None:
    maximum = (
        python_distribution_spine.MAX_ARCHIVE_FILE_BYTES
        if selected.kind in {"sdist", "wheel"}
        else python_distribution_spine.MAX_RECORD_FILE_BYTES
    )
    digest = hashlib.sha256()
    with _open_regular(
        selected.path,
        selected.filename,
        maximum=maximum,
        exact_size=selected.size,
    ) as source:
        remaining = selected.size
        while remaining:
            try:
                chunk = os.read(
                    source,
                    min(python_distribution_spine.READ_CHUNK_BYTES, remaining),
                )
            except OSError as exc:
                raise python_distribution_spine.SpineError(
                    f"cannot read selected file safely: {selected.filename}"
                ) from exc
            if not chunk:
                raise python_distribution_spine.SpineError(
                    f"selected file is truncated: {selected.filename}"
                )
            _write_all(output, chunk, "Python-distribution spine")
            digest.update(chunk)
            whole.update(chunk)
            remaining -= len(chunk)
        if os.read(source, 1):
            raise python_distribution_spine.SpineError(
                f"selected file has trailing bytes: {selected.filename}"
            )
    if digest.hexdigest() != selected.sha256:
        raise python_distribution_spine.SpineError(
            f"selected file changed before packing: {selected.filename}"
        )


def build(
    directory: Path,
    spine_output: Path,
    record_output: Path,
    expected: python_distribution_spine.ExpectedIdentity,
) -> Mapping[str, Any]:
    """Build and independently reverify one canonical spine and record pair."""

    python_distribution_spine.validate_expected_identity(expected)
    if spine_output.name != python_distribution_spine.expected_spine_filename(
        expected.source_revision,
        expected.selected_artifact_id,
        expected.run_attempt,
    ):
        raise python_distribution_spine.SpineError(
            "spine output filename is not bound to the selected artifact and producer attempt"
        )
    if record_output.name != python_distribution_spine.expected_record_filename(
        expected.source_revision,
        expected.selected_artifact_id,
        expected.run_attempt,
    ):
        raise python_distribution_spine.SpineError(
            "record output filename is not bound to the selected artifact and producer attempt"
        )
    try:
        verified = build_python_artifacts.verify_selection(
            directory,
            source_revision=expected.source_revision,
            wheel_sha256=expected.wheel_sha256,
            selection_record_sha256=expected.selection_record_sha256,
        )
        selected_files = _selected_sources(directory)
    except build_python_artifacts.BuildError as exc:
        raise python_distribution_spine.SpineError(
            f"selected Python distribution is invalid: {exc}"
        ) from exc
    if (
        verified.get("wheel_sha256") != expected.wheel_sha256
        or verified.get("selection_record_sha256") != expected.selection_record_sha256
    ):
        raise python_distribution_spine.SpineError(
            "selected Python distribution returned conflicting identities"
        )
    output = _create_output(spine_output, "spine")
    whole = hashlib.sha256()
    file_records: list[dict[str, object]] = []
    offset = 0
    try:
        for selected in selected_files:
            if selected.size > python_distribution_spine.MAX_SPINE_BYTES - offset:
                raise python_distribution_spine.SpineError(
                    "Python-distribution spine exceeds its total size limit"
                )
            _copy_source(output, selected, whole)
            file_records.append(
                {
                    "filename": selected.filename,
                    "kind": selected.kind,
                    "offset": offset,
                    "sha256": selected.sha256,
                    "size": selected.size,
                }
            )
            offset += selected.size
        os.fsync(output)
    finally:
        os.close(output)

    record: dict[str, object] = {
        "schema_version": python_distribution_spine.SCHEMA_VERSION,
        "media_type": python_distribution_spine.RECORD_MEDIA_TYPE,
        "repository": {"id": expected.repository_id, "name": expected.repository_name},
        "run": {"id": expected.run_id, "attempt": expected.run_attempt},
        "source": {"revision": expected.source_revision},
        "workflow": {
            "path": expected.workflow_path,
            "ref": expected.workflow_ref,
            "sha": expected.workflow_sha,
        },
        "selected_artifact": {
            "id": expected.selected_artifact_id,
            "sha256": expected.selected_artifact_sha256,
        },
        "selection": {
            "wheel_sha256": expected.wheel_sha256,
            "record_sha256": expected.selection_record_sha256,
        },
        "spine": {
            "filename": spine_output.name,
            "media_type": python_distribution_spine.SPINE_MEDIA_TYPE,
            "size": offset,
            "sha256": whole.hexdigest(),
        },
        "files": file_records,
    }
    validated = python_distribution_spine.validate_record(record, expected)
    record_bytes = python_distribution_spine.canonical_json(validated)
    if len(record_bytes) > python_distribution_spine.MAX_RECORD_BYTES:
        raise python_distribution_spine.SpineError("spine record exceeds its size limit")
    record_descriptor = _create_output(record_output, "record")
    try:
        _write_all(record_descriptor, record_bytes, "Python-distribution spine record")
        os.fsync(record_descriptor)
    finally:
        os.close(record_descriptor)
    python_distribution_spine.verify(
        record_output,
        spine_output,
        expected,
        record_artifact_sha256=hashlib.sha256(record_bytes).hexdigest(),
        spine_artifact_sha256=whole.hexdigest(),
    )
    return validated


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--directory", required=True)
    result.add_argument("--spine-output", required=True)
    result.add_argument("--record-output", required=True)
    python_distribution_spine.add_identity_arguments(result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        build(
            Path(args.directory),
            Path(args.spine_output),
            Path(args.record_output),
            python_distribution_spine.expected_from_args(args),
        )
    except python_distribution_spine.SpineError as exc:
        sys.stderr.write(f"Python-distribution spine builder error: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
