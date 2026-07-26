#!/usr/bin/env python3
"""Export one local image without opening the resulting archive.

This program is the Docker-owning half of the image evidence boundary. It may
inspect Docker's bounded JSON response and stream ``docker image save`` bytes,
but it must not import or invoke an archive parser. The rootless offline parser
validates and opens the exported bytes in a later process.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = 1
RECORD_KIND = "extra-codeowners/container-image-export"
DOCKER_BINARY = "/usr/bin/docker"

MAX_DOCKER_JSON_BYTES = 1024 * 1024
MAX_DOCKER_ERROR_BYTES = 64 * 1024
MAX_IMAGE_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024 + 256 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024

SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_IMAGE_REFERENCE = re.compile(r"[\x21-\x7e]{1,512}")


class ImageExportError(RuntimeError):
    """The local image cannot be exported under the fixed handoff contract."""


def canonical_json(value: object) -> bytes:
    """Encode the one accepted export-record representation."""

    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ImageExportError("image export record cannot be encoded") from exc


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def strict_json_object(content: bytes, source: str) -> Mapping[str, Any]:
    """Parse one bounded object while rejecting duplicate keys and constants."""

    if not 1 <= len(content) <= MAX_DOCKER_JSON_BYTES:
        raise ImageExportError(f"{source} is empty or exceeds its byte limit")
    try:
        value = json.loads(
            content,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise ImageExportError(f"{source} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ImageExportError(f"{source} is not a JSON object")
    return value


def _safe_diagnostic(content: bytes) -> str:
    """Return a bounded single-line Docker diagnostic without control text."""

    text = content.decode("utf-8", errors="replace")
    cleaned = "".join(character if 0x20 <= ord(character) <= 0x7E else " " for character in text)
    return " ".join(cleaned.split())[:1024]


def _validate_image_reference(value: str) -> str:
    if (
        SAFE_IMAGE_REFERENCE.fullmatch(value) is None
        or value.startswith("-")
        or any(character in value for character in ('"', "'", "\\", "`", "$"))
    ):
        raise ImageExportError("image reference is not a bounded canonical token")
    return value


def _docker_command(
    arguments: Sequence[str],
    *,
    max_output_bytes: int,
) -> bytes:
    """Run one fixed Docker read operation with bounded output."""

    command = (DOCKER_BINARY, *arguments)
    process = subprocess.Popen(  # noqa: S603 - executable and verbs are fixed.
        command,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise ImageExportError("cannot capture Docker output")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = bytearray()
    error = bytearray()
    try:
        while selector.get_map():
            for key, _events in selector.select():
                chunk = os.read(key.fd, COPY_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    if len(output) + len(chunk) > max_output_bytes:
                        raise ImageExportError("Docker output exceeds its byte limit")
                    output.extend(chunk)
                elif len(error) < MAX_DOCKER_ERROR_BYTES:
                    error.extend(chunk[: MAX_DOCKER_ERROR_BYTES - len(error)])
        return_code = process.wait()
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
    if return_code:
        detail = _safe_diagnostic(bytes(error))
        raise ImageExportError(f"Docker read operation failed{f': {detail}' if detail else ''}")
    return bytes(output)


def _docker_inspect(image: str) -> Mapping[str, Any]:
    content = _docker_command(
        ("image", "inspect", image),
        max_output_bytes=MAX_DOCKER_JSON_BYTES,
    )
    try:
        value = json.loads(
            content,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise ImageExportError("Docker inspect response is not strict JSON") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ImageExportError("Docker inspect did not return exactly one image object")
    return value[0]


def _validate_local_image(
    info: Mapping[str, Any],
    *,
    platform: str,
    subject_digest: str,
    allow_config_digest_subject: bool,
) -> str:
    expected_architecture = platform.removeprefix("linux/")
    if info.get("Os") != "linux" or info.get("Architecture") != expected_architecture:
        raise ImageExportError("local image platform does not match the requested platform")
    config_digest = info.get("Id")
    if not isinstance(config_digest, str) or SHA256.fullmatch(config_digest) is None:
        raise ImageExportError("Docker returned an invalid image configuration digest")
    raw_repo_digests = info.get("RepoDigests")
    if raw_repo_digests is None:
        raw_repo_digests = []
    if not isinstance(raw_repo_digests, list) or not all(
        isinstance(item, str) for item in raw_repo_digests
    ):
        raise ImageExportError("Docker returned invalid repository digests")
    repository_digests: set[str] = set()
    for item in raw_repo_digests:
        _name, separator, digest = item.rpartition("@")
        if separator != "@" or SHA256.fullmatch(digest) is None:
            raise ImageExportError("Docker returned an invalid repository digest")
        repository_digests.add(digest)
    if subject_digest in repository_digests:
        return config_digest
    if allow_config_digest_subject and subject_digest == config_digest:
        return config_digest
    raise ImageExportError(
        "subject digest is not bound to the selected local image under the requested policy"
    )


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise ImageExportError("cannot write the image export record")
        written += count


def _stream_image_archive(config_digest: str, destination: Path) -> tuple[str, int]:
    """Stream exact Docker-save bytes to one create-once regular file."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or cloexec is None:
        raise ImageExportError("secure no-follow file creation is unavailable")
    descriptor = -1
    process: subprocess.Popen[bytes] | None = None
    created = False
    completed = False
    digest = hashlib.sha256()
    received = 0
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
            0o600,
        )
        created = True
        process = subprocess.Popen(  # noqa: S603 - executable, verb, and digest are fixed.
            (DOCKER_BINARY, "image", "save", config_digest),
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None or process.stderr is None:
            raise ImageExportError("cannot capture Docker image export")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        error = bytearray()
        try:
            while selector.get_map():
                for key, _events in selector.select():
                    chunk = os.read(key.fd, COPY_CHUNK_BYTES)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        received += len(chunk)
                        if received > MAX_IMAGE_ARCHIVE_BYTES:
                            raise ImageExportError("Docker image archive exceeds its byte limit")
                        digest.update(chunk)
                        _write_all(descriptor, chunk)
                    elif len(error) < MAX_DOCKER_ERROR_BYTES:
                        error.extend(chunk[: MAX_DOCKER_ERROR_BYTES - len(error)])
            return_code = process.wait()
        finally:
            selector.close()
        if return_code:
            detail = _safe_diagnostic(bytes(error))
            raise ImageExportError(f"Docker image export failed{f': {detail}' if detail else ''}")
        if received < 1:
            raise ImageExportError("Docker image export is empty")
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != received
        ):
            raise ImageExportError("Docker image export is not one exact regular file")
        completed = True
        return digest.hexdigest(), received
    except OSError as exc:
        raise ImageExportError("cannot create the Docker image export") from exc
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created and not completed:
            with contextlib.suppress(OSError):
                destination.unlink()


def _create_output_directory(path: Path) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ImageExportError("image export output must be one absolute new directory")
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImageExportError("image export output parent does not exist") from exc
    if path.parent != parent:
        raise ImageExportError("image export output parent must be canonical")
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise ImageExportError("image export output must not already exist") from exc


def _write_record(path: Path, record: Mapping[str, object]) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or cloexec is None:
        raise ImageExportError("secure no-follow file creation is unavailable")
    content = canonical_json(record)
    descriptor = -1
    created = False
    completed = False
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec,
            0o600,
        )
        created = True
        _write_all(descriptor, content)
        os.fsync(descriptor)
        completed = True
    except OSError as exc:
        raise ImageExportError("cannot create the image export record") from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created and not completed:
            with contextlib.suppress(OSError):
                path.unlink()


def export_local_image(
    *,
    image: str,
    platform: str,
    subject_digest: str,
    allow_config_digest_subject: bool,
    output: Path,
) -> Mapping[str, object]:
    """Create one exact archive and its immutable parser handoff record."""

    image = _validate_image_reference(image)
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise ImageExportError("image platform must be linux/amd64 or linux/arm64")
    if SHA256.fullmatch(subject_digest) is None:
        raise ImageExportError("subject digest must be one lowercase SHA-256 digest")
    _create_output_directory(output)
    archive = output / "image.tar"
    record_path = output / "image-export.json"
    completed = False
    try:
        info = _docker_inspect(image)
        config_digest = _validate_local_image(
            info,
            platform=platform,
            subject_digest=subject_digest,
            allow_config_digest_subject=allow_config_digest_subject,
        )
        archive_sha256, archive_size = _stream_image_archive(config_digest, archive)
        immutable_info = _docker_inspect(config_digest)
        if (
            immutable_info.get("Id") != config_digest
            or immutable_info.get("Os") != "linux"
            or immutable_info.get("Architecture") != platform.removeprefix("linux/")
        ):
            raise ImageExportError("local image identity changed during export")
        record: Mapping[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "kind": RECORD_KIND,
            "archive": {
                "filename": "image.tar",
                "sha256": archive_sha256,
                "size": archive_size,
            },
            "image": {
                "config_digest": config_digest,
                "platform": platform,
                "subject_digest": subject_digest,
            },
        }
        _write_record(record_path, record)
        archive.chmod(0o644)
        record_path.chmod(0o644)
        output.chmod(0o755)
        completed = True
        return record
    finally:
        if not completed:
            for candidate in (record_path, archive):
                with contextlib.suppress(OSError):
                    candidate.unlink()
            with contextlib.suppress(OSError):
                output.rmdir()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--image", required=True)
    result.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    result.add_argument("--subject-digest", required=True)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument(
        "--allow-config-digest-subject",
        action="store_true",
        help="allow a local-only config digest instead of a repository manifest digest",
    )
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        record = export_local_image(
            image=arguments.image,
            platform=arguments.platform,
            subject_digest=arguments.subject_digest,
            allow_config_digest_subject=arguments.allow_config_digest_subject,
            output=arguments.output,
        )
    except ImageExportError as exc:
        sys.stderr.write(f"container image export error: {exc}\n")
        return 1
    sys.stdout.buffer.write(canonical_json(record))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
