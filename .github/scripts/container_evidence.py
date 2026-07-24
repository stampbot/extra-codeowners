#!/usr/bin/env python3
"""Build deterministic, digest-bound container distribution evidence.

The collector treats image layers and retained source archives as hostile input.
It does not execute image content, APKBUILD recipes, setup.py files, or source
build scripts. Source bytes come only from independently bound, verified stores.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import configparser
import contextlib
import csv
import dataclasses
import datetime
import email.parser
import gzip
import hashlib
import io
import json
import os
import re
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.parse
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.tags import cpython_tags
from packaging.utils import (
    InvalidName,
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verified_source_store  # noqa: E402

SCHEMA_VERSION = 7
EVIDENCE_MEDIA_TYPE = f"application/vnd.stampbot.container-evidence.v{SCHEMA_VERSION}+tar+gzip"
APPLICATION_NAME = "extra-codeowners"
EXPECTED_RUNTIME_PYTHON = "3.14.6"
CPYTHON_RUNTIME_MINOR = EXPECTED_RUNTIME_PYTHON.rsplit(".", 1)[0]
CPYTHON_RUNTIME_NAME = "cpython"
CPYTHON_RUNTIME_PURL = f"pkg:generic/python@{EXPECTED_RUNTIME_PYTHON}"
CPYTHON_VERSION_HEADER = f"usr/local/include/python{CPYTHON_RUNTIME_MINOR}/patchlevel.h"
CPYTHON_INTERPRETER = f"usr/local/bin/python{CPYTHON_RUNTIME_MINOR}"
CPYTHON_INTERPRETER_LINK = f"usr/local/bin/python{EXPECTED_RUNTIME_PYTHON.split('.')[0]}"
CPYTHON_INTERPRETER_LINK_TARGET = f"python{CPYTHON_RUNTIME_MINOR}"
CPYTHON_SHARED_LIBRARY = f"usr/local/lib/libpython{CPYTHON_RUNTIME_MINOR}.so.1.0"
CPYTHON_REGULAR_IDENTITY_PATHS = {
    "version_header": CPYTHON_VERSION_HEADER,
    "interpreter": CPYTHON_INTERPRETER,
    "shared_library": CPYTHON_SHARED_LIBRARY,
}
CPYTHON_LINK_IDENTITY_PATHS = {"interpreter_link": CPYTHON_INTERPRETER_LINK}
CPYTHON_IDENTITY_PATHS = {
    **CPYTHON_REGULAR_IDENTITY_PATHS,
    **CPYTHON_LINK_IDENTITY_PATHS,
}
EXPECTED_UV_VERSION = "0.11.28"
APPLICATION_WHEEL_LABEL = "org.stampbot.extra-codeowners.application-wheel.sha256"
APPLICATION_SELECTION_LABEL = "org.stampbot.extra-codeowners.python-selection-record.sha256"
BASE_SOURCE_REQUEST_IDS = {
    "docker-python-recipe": "docker-python:recipe",
    "cpython": "cpython:source",
}
DOCKER_PYTHON_LICENSE_REQUEST_ID = "docker-python:license"
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_NATIVE_COMPONENT_SOURCE_BYTES = 128 * 1024 * 1024
MAX_ALPINE_DISTFILE_BYTES = MAX_NATIVE_COMPONENT_SOURCE_BYTES
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 250_000
MAX_ARCHIVE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_TAR_EXTENSION_BYTES = 1024 * 1024
MAX_TAR_EXTENSIONS_TOTAL_BYTES = 8 * 1024 * 1024
MAX_IMAGE_MEMBERS = 250_000
MAX_IMAGE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_DOCKER_SAVE_BYTES = MAX_IMAGE_TOTAL_BYTES + 256 * 1024 * 1024
MAX_PROCESS_ERROR_BYTES = 64 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_PATH_BYTES = 4096
MAX_TAR_ID = 2**31 - 1
MAX_LICENSE_BYTES = 2 * 1024 * 1024
MAX_COMPONENTS = 10_000
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_CPYTHON_PATCHLEVEL_BYTES = 64 * 1024
MAX_RECORD_ENTRIES = 100_000
MAX_HISTORICAL_RECORD_ENTRIES = MAX_RECORD_ENTRIES
MAX_CYCLONEDX_COMPONENTS = 10_000
MAX_CYCLONEDX_HASHES = 16
MAX_CYCLONEDX_LICENSES = 16
MAX_CYCLONEDX_OBSERVATION_FIELDS = 16
MAX_CYCLONEDX_OBSERVATION_VALUES = 16
MAX_COMPONENT_FIELD_LENGTH = 512
MAX_COMPONENT_KEY_LENGTH = 2 * MAX_COMPONENT_FIELD_LENGTH + 32
MAX_LICENSE_FIELD_LENGTH = 16 * 1024
MAX_REVIEW_RATIONALE_LENGTH = 4 * 1024
MAX_NATIVE_OWNERS = 10_000
MAX_SBOMS_PER_OWNER = 256
MAX_OBSERVATIONS_PER_OWNER = 10_000
MAX_COMPONENT_REVIEWS = 10_000
MAX_OBSERVATIONS_PER_REVIEW = 256
MAX_CANONICAL_RELATIONSHIPS = 1_024
MAX_KNOWN_OMISSIONS = 256
MAX_NATIVE_COMPONENT_SOURCES = 10_000
MAX_ALPINE_DISTFILES = 64
MAX_ALPINE_RECIPE_LINKS = 64
MAX_OWNER_SUBTREE_MEMBERS = 100_000
MAX_OWNER_SUBTREE_BYTES = 256 * 1024 * 1024
MAX_CARGO_LOCK_BYTES = 8 * 1024 * 1024
MAX_CARGO_LOCK_PACKAGES = 100_000
MAX_BUNDLE_SOURCE_READS = 10_000
MAX_BUNDLE_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_BUNDLE_FILES = 100_000
MAX_BUNDLE_RETAINED_BYTES = 1024 * 1024 * 1024
MAX_BUNDLE_OUTPUT_BYTES = 1024 * 1024 * 1024
MAX_APPLICATION_SOURCE_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_SELECTED_HELPER_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_REDIRECTS = 5
MAX_CI_ARTIFACT_CENTRAL_DIRECTORY_BYTES = 64 * 1024
MAX_CI_ARTIFACT_EXPANDED_BYTES = MAX_BUNDLE_OUTPUT_BYTES + 4 * MAX_JSON_BYTES
MAX_CI_ARTIFACT_ZIP_BYTES = MAX_CI_ARTIFACT_EXPANDED_BYTES + MAX_CI_ARTIFACT_CENTRAL_DIRECTORY_BYTES
MAX_CI_ARTIFACT_COMPRESSION_RATIO = 1_000
MAX_SOURCE_ZIP_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_SOURCE_ZIP_COMPRESSION_RATIO = 1_000
MAX_SOURCE_ZIP_ENTRIES = 10_000
MAX_SOURCE_LICENSE_FILES = 1_000
MAX_SOURCE_LICENSE_TOTAL_BYTES = 64 * 1024 * 1024
ZIP_EOCD = struct.Struct("<4s4H2LH")
ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
ZIP_DATA_DESCRIPTOR = struct.Struct("<4s3L")
ZIP_EXTRA_HEADER = struct.Struct("<HH")
ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")
CI_ARTIFACT_EXTERNAL_ATTR = (stat.S_IFREG | 0o644) << 16 | 0x20
LICENSE_NAME = re.compile(
    r"(^|/)(copying|copyright|licen[cs]es?|notice|authors?)([._-].*)?$", re.IGNORECASE
)
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA512_LINE = re.compile(r"^([0-9a-f]{128})  (\S.*)$")
SHELL_VARIABLE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^{}]+\}")
DIST_INFO = re.compile(r"(?:^|/)site-packages/([^/]+)\.dist-info/METADATA$")
DIST_INFO_SBOM = re.compile(r"(?:^|/)site-packages/[^/]+\.dist-info/sboms/.+$")
WHEEL_IDENTITY_FILE = re.compile(r"(?:^|/)site-packages/[^/]+\.dist-info/(?:RECORD|WHEEL)$")
BYTECODE_FILE = re.compile(r"\.(?:pyc|pyo)$", re.IGNORECASE)
INTERPRETER_BYTECODE_ROOTS = (
    "opt/venv/",
    f"usr/local/lib/python{CPYTHON_RUNTIME_MINOR}/",
)
WHEEL_TAG = re.compile(r"^[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+$")
ENTRY_POINT = re.compile(
    r"^(?P<module>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
    r":(?P<callable>[A-Za-z_]\w*)$"
)
SCRIPT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
NATIVE_LIBRARY = re.compile(r"(?:\.so(?:\.[0-9]+)*|\.dylib|\.dll)$", re.IGNORECASE)
CYCLONEDX_SERIAL_NUMBER = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
PACKAGE_URL = re.compile(
    r"^pkg:[a-z][a-z0-9.+-]*/[^\s/?#]+(?:/[^\s/?#]+)*(?:@[^\s/?#]+)?"
    r"(?:\?[^\s#]+)?(?:#[^\s]+)?$"
)
CARGO_CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CARGO_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
NORMALIZE_NAME = re.compile(r"[-_.]+")
APK_PACKAGE_NAME = re.compile(r"^(?:[a-z0-9]|\.[a-z0-9])[a-z0-9+_.-]{0,199}$")
APK_ORIGIN = re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,199}$")
APK_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:~-]{0,199}$")
APK_ARCHITECTURE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]{0,63}$")
ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
VENV_LINKS = {
    "opt/venv/bin/python": "/usr/local/bin/python3",
    "opt/venv/bin/python3": "python",
    "opt/venv/bin/python3.14": "python",
}
ELF_MAGIC = b"\x7fELF"
ELF64_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF_MACHINES = {
    "linux/amd64": (62, "x86_64"),
    "linux/arm64": (183, "aarch64"),
}
CYCLONEDX_SPEC_VERSIONS = {"1.4", "1.5", "1.6"}
CYCLONEDX_COMPONENT_TYPES = {
    "application",
    "container",
    "cryptographic-asset",
    "data",
    "device",
    "device-driver",
    "file",
    "firmware",
    "framework",
    "library",
    "machine-learning-model",
    "operating-system",
    "platform",
}


class EvidenceError(RuntimeError):
    """Fail-closed evidence collection error."""


class CaseSensitiveConfigParser(configparser.ConfigParser):
    """Preserve entry-point script names exactly as declared."""

    def optionxform(self, optionstr: str) -> str:
        return optionstr


@dataclass(frozen=True)
class PythonRecordInstallation:
    """One RECORD occurrence bound to the exact layer snapshot it described."""

    owner: str
    name: str
    version: str
    metadata: dict[str, Any]
    wheel: dict[str, Any]
    record: dict[str, Any]
    root_is_purelib: bool
    build: str
    tags: tuple[str, ...]
    entries: dict[str, tuple[str | None, int | None, dict[str, Any]]]


class BoundedTarInfo(tarfile.TarInfo):
    """Stop PAX/GNU extension payloads before tarfile allocates attacker-sized bodies."""

    def _bound_extension(self, archive: tarfile.TarFile) -> None:
        if self.size < 0 or self.size > MAX_TAR_EXTENSION_BYTES:
            raise EvidenceError("tar extension header exceeds the per-entry size limit")
        attribute = "_extra_codeowners_extension_bytes"
        total = int(getattr(archive, attribute, 0)) + self.size
        if total > MAX_TAR_EXTENSIONS_TOTAL_BYTES:
            raise EvidenceError("tar extension headers exceed the cumulative size limit")
        setattr(archive, attribute, total)

    def _proc_pax(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        self._bound_extension(archive)
        try:
            result: tarfile.TarInfo | None = super()._proc_pax(archive)  # type: ignore[misc]
        except tarfile.HeaderError as exc:
            raise EvidenceError("tar archive has a malformed PAX header") from exc
        if result is not None and result.size < 0:
            raise EvidenceError("tar archive has a negative PAX member size")
        return result

    def _proc_gnulong(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        self._bound_extension(archive)
        try:
            result: tarfile.TarInfo | None = super()._proc_gnulong(archive)  # type: ignore[misc]
        except tarfile.HeaderError as exc:
            raise EvidenceError("tar archive has a malformed GNU extension") from exc
        if result is not None and result.size < 0:
            raise EvidenceError("tar archive has a negative GNU member size")
        return result

    def _proc_sparse(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        del archive
        raise EvidenceError("GNU sparse tar entries are not supported")

    def _proc_gnusparse_00(
        self, next_member: tarfile.TarInfo, raw_headers: Mapping[str, str]
    ) -> None:
        del next_member, raw_headers
        raise EvidenceError("GNU sparse tar entries are not supported")

    def _proc_gnusparse_01(
        self, next_member: tarfile.TarInfo, pax_headers: Mapping[str, str]
    ) -> None:
        del next_member, pax_headers
        raise EvidenceError("GNU sparse tar entries are not supported")

    def _proc_gnusparse_10(
        self,
        next_member: tarfile.TarInfo,
        pax_headers: Mapping[str, str],
        archive: tarfile.TarFile,
    ) -> None:
        del next_member, pax_headers, archive
        raise EvidenceError("GNU sparse tar entries are not supported")


@dataclass(frozen=True)
class VerifiedSource:
    content: bytes
    urls: tuple[str, ...]


@dataclass(frozen=True)
class SourceZipCentralEntry:
    """One raw, preflighted source-ZIP central-directory record."""

    name: str
    raw_name: bytes
    create_system: int
    create_version: int
    extract_version: int
    flag_bits: int
    compress_type: int
    modified_time: int
    modified_date: int
    crc: int
    compress_size: int
    file_size: int
    internal_attr: int
    external_attr: int
    header_offset: int
    extra: bytes


@dataclass(frozen=True)
class ValidatedSourceZipEntry:
    """One source-ZIP entry with an exact, preflighted raw payload range."""

    metadata: SourceZipCentralEntry
    data_offset: int
    data_end: int


@dataclass
class BundleBudget:
    """Bound cumulative verified-source and retained evidence resources."""

    source_read_count: int = 0
    source_bytes: int = 0
    retained_file_count: int = 0
    retained_bytes: int = 0

    def record_source(self, content: bytes) -> None:
        self.source_read_count += 1
        self.source_bytes += len(content)
        if self.source_read_count > MAX_BUNDLE_SOURCE_READS:
            raise EvidenceError("evidence bundle exceeded the cumulative source-read limit")
        if self.source_bytes > MAX_BUNDLE_SOURCE_BYTES:
            raise EvidenceError("evidence bundle exceeded the cumulative source-size limit")

    def record_retained(self, content: bytes) -> None:
        self.retained_file_count += 1
        self.retained_bytes += len(content)
        if self.retained_file_count > MAX_BUNDLE_FILES:
            raise EvidenceError("evidence bundle exceeded the cumulative file-count limit")
        if self.retained_bytes > MAX_BUNDLE_RETAINED_BYTES:
            raise EvidenceError("evidence bundle exceeded the cumulative retained-size limit")


@dataclass
class BoundedBytesBuilder:
    """Build one generated archive member without exceeding its producer contract."""

    limit: int = MAX_ARCHIVE_MEMBER_BYTES
    content: bytearray = dataclasses.field(default_factory=bytearray)

    def append(self, value: str | bytes) -> None:
        encoded = value.encode("utf-8") if isinstance(value, str) else value
        if len(self.content) + len(encoded) > self.limit:
            raise EvidenceError("generated bundle member exceeds the size limit")
        self.content.extend(encoded)

    def finish(self) -> bytes:
        return bytes(self.content)


def canonical_json(value: object) -> bytes:
    """Return stable UTF-8 JSON with a final newline."""

    output = BoundedBytesBuilder(limit=MAX_JSON_BYTES)
    encoder = json.JSONEncoder(
        allow_nan=False,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    try:
        for chunk in encoder.iterencode(value):
            output.append(chunk)
        output.append("\n")
    except UnicodeEncodeError as exc:
        raise EvidenceError("JSON contains invalid Unicode") from exc
    return output.finish()


def compact_canonical_json(value: object, *, max_bytes: int) -> bytes:
    """Encode compact canonical JSON used by the isolated Python proof helper."""

    try:
        content = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise EvidenceError("selected Python helper JSON cannot be canonically encoded") from exc
    if len(content) > max_bytes:
        raise EvidenceError("selected Python helper JSON exceeds its output limit")
    return content


def strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise EvidenceError(f"non-finite JSON number is not allowed: {value}")


def reject_json_float(value: str) -> None:
    """Reject JSON floats; every evidence schema uses exact integers only."""

    raise EvidenceError(f"JSON floating-point number is not allowed: {value}")


def validate_json_unicode(value: object, source: str) -> None:
    """Reject lone surrogates that Python's JSON decoder otherwise preserves."""

    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EvidenceError(f"JSON from {source} contains invalid Unicode") from exc
    elif isinstance(value, list):
        for item in value:
            validate_json_unicode(item, source)
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_json_unicode(key, source)
            validate_json_unicode(item, source)


def strict_json_loads(value: str | bytes, source: str) -> object:
    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else value
    except UnicodeEncodeError as exc:
        raise EvidenceError(f"JSON from {source} contains invalid Unicode") from exc
    if len(encoded) > MAX_JSON_BYTES:
        raise EvidenceError(f"JSON from {source} exceeds the size limit")
    depth = 0
    in_string = False
    escaped = False
    for byte in encoded:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in (ord("{"), ord("[")):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise EvidenceError(f"JSON from {source} exceeds the nesting-depth limit")
        elif byte in (ord("}"), ord("]")):
            depth = max(0, depth - 1)
    try:
        parsed: object = json.loads(
            value,
            object_pairs_hook=strict_json_object,
            parse_constant=reject_json_constant,
            parse_float=reject_json_float,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EvidenceError(f"cannot parse JSON from {source}: {exc}") from exc
    validate_json_unicode(parsed, source)
    return parsed


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            total += len(chunk)
            if total > max_bytes:
                raise EvidenceError(f"local file exceeds the size limit: {path}")
            digest.update(chunk)
    return digest.hexdigest()


def read_local_bytes(path: Path, *, max_bytes: int) -> bytes:
    """Read one local file with a hard bound and a stable error."""

    try:
        with path.open("rb") as source:
            content = source.read(max_bytes + 1)
    except OSError as exc:
        raise EvidenceError(f"cannot read local file {path}: {exc}") from exc
    if len(content) > max_bytes:
        raise EvidenceError(f"local file exceeds the size limit: {path}")
    return content


def read_stable_local_bytes(path: Path, *, max_bytes: int, source: str) -> bytes:
    """Read one bounded file snapshot and fail if its name or bytes change."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow or not hasattr(os, "pread"):
        raise EvidenceError("stable local input requires no-follow descriptor support")
    absolute = path.absolute()
    descriptor = -1

    def identity(metadata: os.stat_result) -> tuple[int, ...]:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 <= metadata.st_size <= max_bytes
        ):
            raise EvidenceError(f"{source} must be one bounded, single-link regular file")
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

    try:
        before = identity(os.stat(absolute, follow_symlinks=False))
        descriptor = os.open(
            absolute,
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | nofollow,
        )
        opened = identity(os.fstat(descriptor))
        if opened != before:
            raise EvidenceError(f"{source} changed while it was opened")
        content = os.pread(descriptor, before[6] + 1, 0)
        after_open = identity(os.fstat(descriptor))
        after_path = identity(os.stat(absolute, follow_symlinks=False))
    except EvidenceError:
        raise
    except OSError as exc:
        raise EvidenceError(f"cannot read {source} safely") from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if len(content) != before[6] or len(content) > max_bytes:
        raise EvidenceError(f"{source} changed size while it was read")
    if opened != after_open or opened != after_path:
        raise EvidenceError(f"{source} changed while it was read")
    return content


def normalize_package_name(value: str) -> str:
    return NORMALIZE_NAME.sub("-", value).lower()


def checked_scalar(
    value: str,
    field: str,
    *,
    max_length: int = MAX_COMPONENT_FIELD_LENGTH,
    allow_empty: bool = False,
) -> str:
    """Return a bounded scalar that cannot forge paths, logs, or Markdown rows."""

    normalized = value.strip()
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceError(f"{field} is not valid UTF-8") from exc
    if (not normalized and not allow_empty) or len(encoded) > max_length:
        raise EvidenceError(f"{field} has an invalid length")
    if any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in normalized):
        raise EvidenceError(f"{field} contains control characters")
    return normalized


def markdown_cell(value: object) -> str:
    """Escape a previously validated scalar for a Markdown table cell."""

    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def is_native_payload_path(path: str) -> bool:
    if not path.startswith("opt/venv/"):
        return False
    parts = PurePosixPath(path).parts
    return any(part.endswith(".libs") for part in parts) or NATIVE_LIBRARY.search(path) is not None


def is_python_virtual_environment_path(path: str) -> bool:
    """Return whether a path is inside the reviewed runtime virtual environment."""

    return path.startswith("opt/venv/")


def checked_cyclonedx_scalar(
    value: object,
    field: str,
    *,
    max_length: int = MAX_COMPONENT_FIELD_LENGTH,
    allow_empty: bool = False,
) -> str:
    """Validate one exact CycloneDX scalar without normalizing hostile whitespace."""

    if not isinstance(value, str):
        raise EvidenceError(f"CycloneDX {field} is not a string")
    checked = checked_scalar(
        value, f"CycloneDX {field}", max_length=max_length, allow_empty=allow_empty
    )
    if checked != value:
        raise EvidenceError(f"CycloneDX {field} is not canonical")
    return checked


def validate_bounded_observation_json(
    value: object,
    source: str,
    *,
    component_children: bool = False,
) -> None:
    """Bound raw review-sensitive JSON retained from an upstream SBOM.

    The component walker owns a direct ``components`` child array. All other
    arrays keep the smaller observation limit, including arrays nested below
    extension fields that happen to use the same name.
    """

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EvidenceError(f"CycloneDX {source} is not valid UTF-8") from exc
        if (
            len(encoded) > MAX_LICENSE_FIELD_LENGTH
            or "\x00" in value
            or any(
                (ord(character) < 32 and character not in "\t\n\r")
                or 0x7F <= ord(character) <= 0x9F
                for character in value
            )
        ):
            raise EvidenceError(f"CycloneDX {source} is not a bounded text value")
        return
    if isinstance(value, list):
        if len(value) > MAX_CYCLONEDX_OBSERVATION_VALUES:
            raise EvidenceError(f"CycloneDX {source} has too many values")
        for index, item in enumerate(value):
            validate_bounded_observation_json(item, f"{source}[{index}]")
        return
    if isinstance(value, dict):
        if len(value) > MAX_CYCLONEDX_OBSERVATION_FIELDS:
            raise EvidenceError(f"CycloneDX {source} has too many fields")
        for key, item in value.items():
            checked_cyclonedx_scalar(key, f"{source} key")
            if component_children and key == "components":
                if not isinstance(item, list):
                    raise EvidenceError(f"CycloneDX {source} has invalid nested components")
                if len(item) > MAX_CYCLONEDX_COMPONENTS:
                    raise EvidenceError(f"CycloneDX {source} has too many nested components")
                continue
            validate_bounded_observation_json(item, f"{source}.{key}")
        return
    raise EvidenceError(f"CycloneDX {source} has an unsupported JSON value")


def cyclonedx_component_observation(value: object, source: str) -> tuple[dict[str, Any], str]:
    """Project one hostile component without discarding hashes or license observations."""

    if not isinstance(value, dict):
        raise EvidenceError(f"CycloneDX component is not an object: {source}")
    component_type = checked_cyclonedx_scalar(value.get("type"), f"component type in {source}")
    if component_type not in CYCLONEDX_COMPONENT_TYPES:
        raise EvidenceError(f"CycloneDX component has an unsupported type: {source}")
    name = checked_cyclonedx_scalar(value.get("name"), f"component name in {source}")
    version = checked_cyclonedx_scalar(
        value.get("version", ""), f"component version in {source}", allow_empty=True
    )
    purl = checked_cyclonedx_scalar(
        value.get("purl"),
        f"component purl in {source}",
        max_length=MAX_LICENSE_FIELD_LENGTH,
    )
    if PACKAGE_URL.fullmatch(purl) is None:
        raise EvidenceError(f"CycloneDX component has an invalid purl: {source}")
    if "bom-ref" in value and "bom_ref" in value:
        raise EvidenceError(f"CycloneDX component has conflicting bom-ref spellings: {source}")
    bom_ref_value = value.get("bom-ref", value.get("bom_ref", ""))
    bom_ref = checked_cyclonedx_scalar(
        bom_ref_value,
        f"component bom-ref in {source}",
        max_length=MAX_LICENSE_FIELD_LENGTH,
        allow_empty=True,
    )

    raw_hashes = value.get("hashes", [])
    if not isinstance(raw_hashes, list) or len(raw_hashes) > MAX_CYCLONEDX_HASHES:
        raise EvidenceError(f"CycloneDX component has invalid hashes: {source}")
    hashes: list[dict[str, str]] = []
    seen_hash_algorithms: set[str] = set()
    for index, raw_hash in enumerate(raw_hashes):
        record = require_exact_fields(
            raw_hash,
            {"alg", "content"},
            f"CycloneDX component hash {index} in {source}",
        )
        algorithm = checked_cyclonedx_scalar(record["alg"], f"component hash algorithm in {source}")
        content = checked_cyclonedx_scalar(
            record["content"],
            f"component hash content in {source}",
            max_length=MAX_LICENSE_FIELD_LENGTH,
        )
        if re.fullmatch(r"[0-9A-Fa-f]+", content) is None or len(content) % 2:
            raise EvidenceError(f"CycloneDX component has an invalid hash: {source}")
        algorithm_identity = algorithm.casefold()
        if algorithm_identity in seen_hash_algorithms:
            raise EvidenceError(f"CycloneDX component repeats a hash algorithm: {source}")
        seen_hash_algorithms.add(algorithm_identity)
        hashes.append({"alg": algorithm, "content": content})
    hashes.sort(key=lambda item: (item["alg"], item["content"]))

    raw_licenses = value.get("licenses", [])
    if not isinstance(raw_licenses, list) or len(raw_licenses) > MAX_CYCLONEDX_LICENSES:
        raise EvidenceError(f"CycloneDX component has invalid licenses: {source}")
    licenses: list[object] = []
    license_keys: set[bytes] = set()
    for index, raw_license in enumerate(raw_licenses):
        if not isinstance(raw_license, dict):
            raise EvidenceError(f"CycloneDX component license is not an object: {source}")
        validate_bounded_observation_json(raw_license, f"component license {index} in {source}")
        encoded = canonical_json(raw_license)
        if len(encoded) > MAX_LICENSE_FIELD_LENGTH:
            raise EvidenceError(f"CycloneDX component license is too large: {source}")
        if encoded in license_keys:
            raise EvidenceError(f"CycloneDX component repeats a license observation: {source}")
        license_keys.add(encoded)
        licenses.append(raw_license)
    licenses.sort(key=canonical_json)

    return {
        "type": component_type,
        "name": name,
        "version": version,
        "purl": purl,
        "bom_ref": bom_ref,
        "hashes": hashes,
        "licenses": licenses,
    }, bom_ref


def cyclonedx_occurrence_identity(component: Mapping[str, Any]) -> tuple[str, str]:
    """Return the document-local identity for one retained component occurrence."""

    bom_ref = str(component["bom_ref"])
    if bom_ref:
        return "bom-ref", bom_ref
    return "purl", str(component["purl"])


def validate_cyclonedx_occurrence_identities(
    components: Sequence[Mapping[str, Any]],
    source: str,
    *,
    metadata_purl: str | None = None,
) -> None:
    """Reject ambiguous occurrence identities without collapsing repeated packages."""

    seen_bom_refs: set[str] = set()
    purl_identities: dict[str, list[tuple[str, str]]] = {}
    for component in components:
        purl = str(component["purl"])
        kind, identity = cyclonedx_occurrence_identity(component)
        if metadata_purl is not None and purl == metadata_purl:
            raise EvidenceError(f"CycloneDX document repeats metadata component purl: {source}")
        if kind == "bom-ref":
            if identity in seen_bom_refs:
                raise EvidenceError(f"CycloneDX document repeats a non-echo bom-ref: {source}")
            seen_bom_refs.add(identity)
        identities = purl_identities.setdefault(purl, [])
        if identities and (kind != "bom-ref" or any(item[0] != "bom-ref" for item in identities)):
            raise EvidenceError(
                f"CycloneDX document has mixed or repeated fallback purl identity: {source}"
            )
        identities.append((kind, identity))


def cyclonedx_component_sort_key(component: Mapping[str, Any]) -> tuple[object, ...]:
    """Sort retained observations independently of hostile document order."""

    identity_kind, identity = cyclonedx_occurrence_identity(component)
    return (
        str(component["purl"]),
        identity_kind,
        identity,
        str(component["type"]),
        str(component["name"]),
        str(component["version"]),
        canonical_json(component["hashes"]),
        canonical_json(component["licenses"]),
    )


def validate_cyclonedx_observation_projection(
    metadata_component: object,
    components: object,
    source: str,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Validate a canonical document-scoped set of exact component observations."""

    expected_fields = {
        "type",
        "name",
        "version",
        "purl",
        "bom_ref",
        "hashes",
        "licenses",
    }
    if metadata_component is not None and (
        not isinstance(metadata_component, dict) or set(metadata_component) != expected_fields
    ):
        raise EvidenceError(f"CycloneDX metadata component projection is invalid: {source}")
    if not isinstance(components, list) or len(components) > MAX_CYCLONEDX_COMPONENTS:
        raise EvidenceError(f"CycloneDX component projection is invalid: {source}")

    projected: list[dict[str, Any]] = []
    if metadata_component is not None:
        projected.append(metadata_component)
    for component in components:
        if not isinstance(component, dict) or set(component) != expected_fields:
            raise EvidenceError(f"CycloneDX component projection is invalid: {source}")
        projected.append(component)

    validated: list[dict[str, Any]] = []
    for index, component in enumerate(projected):
        observation, _bom_ref = cyclonedx_component_observation(
            component, f"projected component {index} in {source}"
        )
        if observation != component:
            raise EvidenceError(f"CycloneDX component projection is not canonical: {source}")
        validated.append(observation)

    validated_components = validated[1:] if metadata_component is not None else validated
    validate_cyclonedx_occurrence_identities(
        validated_components,
        source,
        metadata_purl=(str(metadata_component["purl"]) if metadata_component is not None else None),
    )
    if (
        metadata_component is not None
        and metadata_component["bom_ref"]
        and any(
            component["bom_ref"] == metadata_component["bom_ref"]
            for component in validated_components
        )
    ):
        raise EvidenceError(f"CycloneDX document repeats a non-echo bom-ref: {source}")
    expected = sorted(components, key=cyclonedx_component_sort_key)
    if components != expected:
        raise EvidenceError(f"CycloneDX component projection is not canonical: {source}")
    return metadata_component, components


def parse_cyclonedx_sbom(content: bytes, path: str) -> dict[str, Any]:
    """Parse one bounded CycloneDX document into a review-sensitive observation."""

    document = strict_json_loads(content, f"embedded CycloneDX SBOM {path}")
    if not isinstance(document, dict):
        raise EvidenceError(f"embedded CycloneDX SBOM is not an object: {path}")
    if document.get("bomFormat") != "CycloneDX":
        raise EvidenceError(f"embedded SBOM is not CycloneDX: {path}")
    spec_version = checked_cyclonedx_scalar(document.get("specVersion"), f"specVersion in {path}")
    if spec_version not in CYCLONEDX_SPEC_VERSIONS:
        raise EvidenceError(f"embedded CycloneDX SBOM has an unsupported specVersion: {path}")
    document_version = document.get("version")
    if (
        not isinstance(document_version, int)
        or isinstance(document_version, bool)
        or not 1 <= document_version <= MAX_TAR_ID
    ):
        raise EvidenceError(f"embedded CycloneDX SBOM has an invalid version: {path}")
    serial_value = document.get("serialNumber", "")
    serial_number = checked_cyclonedx_scalar(
        serial_value,
        f"serialNumber in {path}",
        max_length=128,
        allow_empty=True,
    )
    if serial_number and CYCLONEDX_SERIAL_NUMBER.fullmatch(serial_number) is None:
        raise EvidenceError(f"embedded CycloneDX SBOM has an invalid serialNumber: {path}")

    metadata = document.get("metadata", {})
    if not isinstance(metadata, dict):
        raise EvidenceError(f"embedded CycloneDX SBOM has invalid metadata: {path}")
    raw_metadata_component = metadata.get("component")
    raw_components = document.get("components", [])
    if not isinstance(raw_components, list):
        raise EvidenceError(f"embedded CycloneDX SBOM has an invalid component list: {path}")

    flattened: list[tuple[dict[str, Any], str, bool, bool, Mapping[str, Any]]] = []
    component_count = 0

    def walk(
        raw: object,
        location: str,
        *,
        metadata_root: bool = False,
        top_level: bool = False,
    ) -> None:
        nonlocal component_count
        component_count += 1
        if component_count > MAX_CYCLONEDX_COMPONENTS:
            raise EvidenceError(f"embedded CycloneDX SBOM has too many components: {path}")
        projection, bom_ref = cyclonedx_component_observation(raw, location)
        assert isinstance(raw, dict)
        validate_bounded_observation_json(
            raw,
            f"raw component in {location}",
            component_children=True,
        )
        flattened.append((projection, bom_ref, metadata_root, top_level, raw))
        children = raw.get("components", [])
        if not isinstance(children, list):
            raise EvidenceError(f"CycloneDX component has invalid nested components: {location}")
        for index, child in enumerate(children):
            walk(child, f"{location}.components[{index}]")

    if raw_metadata_component is not None:
        walk(raw_metadata_component, f"{path}.metadata.component", metadata_root=True)
    for index, raw_component in enumerate(raw_components):
        walk(raw_component, f"{path}.components[{index}]", top_level=True)
    if not flattened:
        raise EvidenceError(f"embedded CycloneDX SBOM has no component identities: {path}")

    metadata_component: dict[str, Any] | None = None
    metadata_component_raw: Mapping[str, Any] | None = None
    metadata_root_echo: dict[str, Any] | None = None
    components: list[dict[str, Any]] = []
    for projection, bom_ref, metadata_root, top_level, raw_component in flattened:
        purl = str(projection["purl"])
        if metadata_component is not None and purl == metadata_component["purl"]:
            if (
                metadata_component_raw is None
                or metadata_root
                or not top_level
                or metadata_root_echo is not None
                or not bom_ref
                or projection != metadata_component
                or canonical_json(raw_component) != canonical_json(metadata_component_raw)
            ):
                raise EvidenceError(f"CycloneDX document repeats metadata component purl: {path}")
            metadata_root_echo = projection
            continue
        if metadata_root:
            if metadata_component is not None:
                raise EvidenceError(f"embedded CycloneDX SBOM repeats metadata component: {path}")
            metadata_component = projection
            metadata_component_raw = raw_component
        else:
            components.append(projection)

    components.sort(key=cyclonedx_component_sort_key)
    validate_cyclonedx_observation_projection(metadata_component, components, path)
    observation = {
        "metadata_component": metadata_component,
        "metadata_root_echo": metadata_root_echo,
        "upstream_invalid_duplicate_bom_ref": metadata_root_echo is not None,
        "components": components,
    }
    return {
        "bom_format": "CycloneDX",
        "spec_version": spec_version,
        **observation,
        "observation_sha256": sha256_bytes(canonical_json(observation)),
    }


def parse_elf_identity(content: bytes, platform: str, path: str) -> dict[str, Any]:
    """Validate one Linux ELF payload and return its reviewed architecture identity."""

    expected = ELF_MACHINES.get(platform)
    if expected is None:
        raise EvidenceError(f"unsupported ELF platform: {platform}")
    if not content.startswith(ELF_MAGIC):
        raise EvidenceError(f"native Python payload is not ELF: {path}")
    if len(content) < ELF64_HEADER.size:
        raise EvidenceError(f"native Python payload has a truncated ELF header: {path}")
    if content[4] != 2:
        raise EvidenceError(f"native Python payload is not ELF64: {path}")
    if content[5] != 1:
        raise EvidenceError(f"native Python payload is not little-endian ELF: {path}")
    if content[6] != 1:
        raise EvidenceError(f"native Python payload has an invalid ELF identity version: {path}")
    try:
        header = ELF64_HEADER.unpack_from(content)
    except struct.error as exc:
        raise EvidenceError(f"native Python payload has a malformed ELF header: {path}") from exc
    machine = header[2]
    elf_version = header[3]
    header_size = header[8]
    if elf_version != 1 or header_size != ELF64_HEADER.size:
        raise EvidenceError(f"native Python payload has a malformed ELF header: {path}")
    expected_machine, machine_name = expected
    if machine != expected_machine:
        raise EvidenceError(
            f"native Python payload ELF architecture does not match {platform}: {path}"
        )
    return {
        "bits": 64,
        "endianness": "little",
        "machine": machine_name,
        "machine_id": machine,
    }


def parse_cpython_patchlevel_header(content: bytes, path: str = CPYTHON_VERSION_HEADER) -> str:
    """Parse the immutable CPython version constants without executing image content."""

    if len(content) > MAX_CPYTHON_PATCHLEVEL_BYTES:
        raise EvidenceError(f"CPython patchlevel header exceeds its size limit: {path}")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"CPython patchlevel header is not UTF-8: {path}") from exc
    if "\r" in text or any(
        ord(character) < 32 and character not in {"\n", "\t"} for character in text
    ):
        raise EvidenceError(f"CPython patchlevel header contains invalid control bytes: {path}")
    if text.count("/*--start constants--*/") != 1 or text.count("/*--end constants--*/") != 1:
        raise EvidenceError(f"CPython patchlevel header has invalid constant markers: {path}")
    start = text.index("/*--start constants--*/")
    end = text.index("/*--end constants--*/")
    if start >= end:
        raise EvidenceError(f"CPython patchlevel header has invalid constant markers: {path}")

    conditionals = list(
        re.finditer(
            r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b([^\n]*)$",
            text,
            flags=re.MULTILINE,
        )
    )
    if conditionals and not (
        len(conditionals) == 2
        and conditionals[0].group(1) == "ifndef"
        and conditionals[0].group(2).strip() == "_Py_PATCHLEVEL_H"
        and conditionals[0].start() < start
        and conditionals[1].group(1) == "endif"
        and conditionals[1].start() > end
    ):
        raise EvidenceError(f"CPython patchlevel constants are conditional: {path}")

    expected_release_levels = {
        "PY_RELEASE_LEVEL_ALPHA": "0xA",
        "PY_RELEASE_LEVEL_BETA": "0xB",
        "PY_RELEASE_LEVEL_GAMMA": "0xC",
        "PY_RELEASE_LEVEL_FINAL": "0xF",
    }
    expected_version_constants = {
        "PY_MAJOR_VERSION": EXPECTED_RUNTIME_PYTHON.split(".")[0],
        "PY_MINOR_VERSION": EXPECTED_RUNTIME_PYTHON.split(".")[1],
        "PY_MICRO_VERSION": EXPECTED_RUNTIME_PYTHON.split(".")[2],
        "PY_RELEASE_LEVEL": "PY_RELEASE_LEVEL_FINAL",
        "PY_RELEASE_SERIAL": "0",
        "PY_VERSION": f'"{EXPECTED_RUNTIME_PYTHON}"',
    }
    expected = {**expected_release_levels, **expected_version_constants}
    expected_names = "|".join(re.escape(name) for name in expected)
    if re.search(
        rf"^[ \t]*#[ \t]*undef[ \t]+(?:{expected_names})\b",
        text,
        flags=re.MULTILINE,
    ):
        raise EvidenceError(f"CPython patchlevel header undefines a version constant: {path}")
    for name, expected_value in expected.items():
        matches = re.findall(
            rf"^[ \t]*#[ \t]*define[ \t]+{re.escape(name)}[ \t]+([^\n]+)$",
            text,
            flags=re.MULTILINE,
        )
        if len(matches) != 1:
            raise EvidenceError(
                f"CPython patchlevel header must define {name} exactly once: {path}"
            )
        value = re.sub(r"[ \t]*/\*.*\*/[ \t]*$", "", matches[0]).strip()
        if value != expected_value:
            raise EvidenceError(f"CPython patchlevel header has unexpected {name}: {path}")

    constants_block = text[start:end]
    block_names = re.findall(
        r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+",
        constants_block,
        flags=re.MULTILINE,
    )
    if block_names != list(expected_version_constants):
        raise EvidenceError(
            f"CPython patchlevel header has an unexpected version macro set: {path}"
        )
    return EXPECTED_RUNTIME_PYTHON


def runtime_payload_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    """Retain one exact regular-file occurrence without its redundant layer digest."""

    return {
        field: record[field]
        for field in ("effective", "layer", "path", "sha256", "size", "mode", "uid", "gid")
    }


def collect_cpython_runtime_component(
    occurrences: Sequence[Mapping[str, Any]],
    non_regular_occurrences: Sequence[Mapping[str, Any]],
    effective_types: Mapping[str, Mapping[str, Any]],
    identity_details: Mapping[tuple[int, str, str], bytes | Mapping[str, Any]],
    platform: str,
) -> dict[str, Any]:
    """Normalize the exact CPython runtime footprint from hostile image layers."""

    identities: dict[str, dict[str, Any]] = {}
    expected_modes = {
        "version_header": 0o644,
        "interpreter": 0o755,
        "shared_library": 0o755,
    }
    identity_layers: set[int] = set()
    for role, path in CPYTHON_REGULAR_IDENTITY_PATHS.items():
        matches = [record for record in occurrences if record.get("path") == path]
        if len(matches) != 1:
            raise EvidenceError(
                "image must contain exactly one CPython "
                f"{role.replace('_', ' ')} occurrence: {path}"
            )
        occurrence = matches[0]
        final_type = effective_types.get(path)
        if (
            occurrence.get("effective") is not True
            or final_type is None
            or final_type.get("kind") != "regular"
            or final_type.get("layer") != occurrence.get("layer")
            or occurrence.get("uid") != 0
            or occurrence.get("gid") != 0
            or occurrence.get("mode") != expected_modes[role]
        ):
            raise EvidenceError(f"CPython {role.replace('_', ' ')} has an invalid identity: {path}")
        layer = occurrence.get("layer")
        digest = occurrence.get("sha256")
        if not isinstance(layer, int) or isinstance(layer, bool) or not isinstance(digest, str):
            raise EvidenceError(
                f"CPython {role.replace('_', ' ')} has an invalid occurrence: {path}"
            )
        detail = identity_details.get((layer, path, digest))
        if detail is None:
            raise EvidenceError(f"cannot bind CPython identity content: {path}")
        projected = runtime_payload_projection(occurrence)
        if role == "version_header":
            if not isinstance(detail, bytes):
                raise EvidenceError(f"cannot bind CPython patchlevel header content: {path}")
            parse_cpython_patchlevel_header(detail, path)
        else:
            if not isinstance(detail, Mapping):
                raise EvidenceError(f"cannot bind CPython ELF identity: {path}")
            validate_retained_elf_identity(detail, platform, f"CPython {role}")
            projected["elf"] = dict(detail)
        identities[role] = projected
        identity_layers.add(layer)

    link_matches = [
        record
        for record in non_regular_occurrences
        if record.get("path") == CPYTHON_INTERPRETER_LINK
    ]
    if len(link_matches) != 1:
        raise EvidenceError(
            "image must contain exactly one CPython interpreter-link occurrence: "
            f"{CPYTHON_INTERPRETER_LINK}"
        )
    link = link_matches[0]
    link_layer = link.get("layer")
    final_link = effective_types.get(CPYTHON_INTERPRETER_LINK)
    if (
        not isinstance(link_layer, int)
        or isinstance(link_layer, bool)
        or link.get("kind") != "symlink"
        or link.get("target") != CPYTHON_INTERPRETER_LINK_TARGET
        or link.get("uid") != 0
        or link.get("gid") != 0
        or link.get("mode") != 0o777
        or final_link
        != {
            "kind": "symlink",
            "layer": link_layer,
            "target": CPYTHON_INTERPRETER_LINK_TARGET,
        }
    ):
        raise EvidenceError(
            f"CPython interpreter link has an invalid identity: {CPYTHON_INTERPRETER_LINK}"
        )
    identities["interpreter_link"] = {
        "effective": True,
        "kind": "symlink",
        "layer": link_layer,
        "path": CPYTHON_INTERPRETER_LINK,
        "target": CPYTHON_INTERPRETER_LINK_TARGET,
        "mode": 0o777,
        "uid": 0,
        "gid": 0,
    }
    identity_layers.add(link_layer)
    if len(identity_layers) != 1:
        raise EvidenceError("CPython runtime identity files do not share one base-layer footprint")
    return {
        "ecosystem": "runtime",
        "name": CPYTHON_RUNTIME_NAME,
        "version": EXPECTED_RUNTIME_PYTHON,
        "purl": CPYTHON_RUNTIME_PURL,
        "observed_license": "",
        "effective": True,
        "identity_files": identities,
    }


def checked_path(value: str) -> PurePosixPath:
    """Normalize an archive path and reject traversal or ambiguous names."""

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceError(f"unsafe archive path: {value!r}") from exc
    if (
        len(encoded) > MAX_PATH_BYTES
        or "\\" in value
        or any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value)
    ):
        raise EvidenceError(f"unsafe archive path: {value!r}")
    raw = value.removeprefix("./")
    comparable = raw[:-1] if raw.endswith("/") else raw
    path = PurePosixPath(comparable)
    if (
        not comparable
        or comparable in {".", ".."}
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != comparable
    ):
        raise EvidenceError(f"unsafe archive path: {value!r}")
    return path


def checked_canonical_path(value: str, field: str) -> PurePosixPath:
    """Validate one retained JSON path without accepting archive-name aliases."""

    path = checked_path(value)
    if str(path) != value:
        raise EvidenceError(f"{field} is not a canonical archive path")
    return path


def checked_link_target(value: str) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceError(f"unsafe archive link target: {value!r}") from exc
    if (
        not value
        or len(encoded) > MAX_PATH_BYTES
        or "\\" in value
        or any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value)
    ):
        raise EvidenceError(f"unsafe archive link target: {value!r}")
    target = PurePosixPath(value)
    if (
        target.is_absolute()
        or any(part in {"", ".", ".."} for part in target.parts)
        or target.as_posix() != value
    ):
        raise EvidenceError(f"unsafe archive link target: {value!r}")


def checked_image_link_target(value: str) -> None:
    """Validate, but never resolve, an OCI link target."""

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceError(f"invalid image link target: {value!r}") from exc
    if (
        not value
        or len(encoded) > MAX_PATH_BYTES
        or any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value)
    ):
        raise EvidenceError(f"invalid image link target: {value!r}")


def resolve_wheel_record_path(site_root: PurePosixPath, value: str) -> str:
    """Resolve one hostile wheel RECORD path without escaping /opt/venv."""

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceError(f"unsafe Python RECORD path: {value!r}") from exc
    if (
        not value
        or len(encoded) > MAX_PATH_BYTES
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value)
    ):
        raise EvidenceError(f"unsafe Python RECORD path: {value!r}")
    parts = value.split("/")
    if any(part in {"", "."} for part in parts):
        raise EvidenceError(f"unsafe Python RECORD path: {value!r}")
    resolved = list(site_root.parts)
    for part in parts:
        if part == "..":
            if len(resolved) <= 2:
                raise EvidenceError(f"Python RECORD path escapes /opt/venv: {value!r}")
            resolved.pop()
        else:
            resolved.append(part)
    if resolved[:2] != ["opt", "venv"]:
        raise EvidenceError(f"Python RECORD path escapes /opt/venv: {value!r}")
    return PurePosixPath(*resolved).as_posix()


def normalized_layer_header(member: tarfile.TarInfo) -> dict[str, int]:
    """Validate security-relevant OCI tar metadata and return its stable identity."""

    if member.size < 0:
        raise EvidenceError(f"image layer entry has a negative size: {member.name}")
    unexpected_pax = set(member.pax_headers) - {"path", "linkpath"}
    if unexpected_pax:
        fields = ", ".join(sorted(unexpected_pax))
        raise EvidenceError(f"image layer entry has unsupported PAX fields: {fields}")
    pax_path = member.pax_headers.get("path")
    if pax_path is not None and (
        not isinstance(pax_path, str)
        or str(checked_path(pax_path)) != str(checked_path(member.name))
    ):
        raise EvidenceError("image layer PAX path does not match the effective path")
    pax_link = member.pax_headers.get("linkpath")
    if pax_link is not None:
        if not isinstance(pax_link, str):
            raise EvidenceError("image layer PAX linkpath is invalid")
        checked_image_link_target(pax_link)
        if not (member.issym() or member.islnk()) or pax_link != member.linkname:
            raise EvidenceError("image layer PAX linkpath does not match the effective target")
    for field, value in (("mode", member.mode), ("uid", member.uid), ("gid", member.gid)):
        maximum = 0o7777 if field == "mode" else MAX_TAR_ID
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
            raise EvidenceError(f"image layer entry has an invalid {field}: {member.name}")
    if not member.isfile() and member.size != 0:
        raise EvidenceError(f"image layer non-regular entry has a payload: {member.name}")
    return {"mode": member.mode, "uid": member.uid, "gid": member.gid}


def parse_wheel_record(
    content: bytes, site_root: PurePosixPath, record_path: str
) -> dict[str, tuple[str | None, int | None]]:
    """Parse a bounded RECORD and return normalized image paths and identities."""

    if len(content) > MAX_RECORD_BYTES:
        raise EvidenceError("Python RECORD exceeds its size limit")
    try:
        text = content.decode("utf-8")
        rows = csv.reader(io.StringIO(text, newline=""), strict=True)
        result: dict[str, tuple[str | None, int | None]] = {}
        self_rows = 0
        for row_number, row in enumerate(rows, start=1):
            if row_number > MAX_RECORD_ENTRIES:
                raise EvidenceError("Python RECORD has too many entries")
            if len(row) != 3:
                raise EvidenceError(f"Python RECORD row {row_number} has {len(row)} fields")
            target = resolve_wheel_record_path(site_root, row[0])
            if target in result:
                raise EvidenceError(f"Python RECORD repeats path: {target}")
            hash_field, size_field = row[1:]
            if target == record_path:
                self_rows += 1
                if hash_field or size_field:
                    raise EvidenceError("Python RECORD self-entry must omit hash and size")
                result[target] = (None, None)
                continue
            if (
                not hash_field.startswith("sha256=")
                or re.fullmatch(r"(?:0|[1-9][0-9]*)", size_field) is None
            ):
                raise EvidenceError(
                    f"Python RECORD row {row_number} must have a SHA-256 hash and size"
                )
            if len(size_field) > 20:
                raise EvidenceError(f"Python RECORD row {row_number} has an invalid size")
            size = int(size_field)
            if size > MAX_ARCHIVE_MEMBER_BYTES:
                raise EvidenceError(f"Python RECORD row {row_number} has an invalid size")
            encoded = hash_field.removeprefix("sha256=")
            if re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is None:
                raise EvidenceError(f"Python RECORD row {row_number} has an invalid hash")
            try:
                digest_bytes = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
            except (binascii.Error, ValueError) as exc:
                raise EvidenceError(f"Python RECORD row {row_number} has an invalid hash") from exc
            if len(digest_bytes) != hashlib.sha256().digest_size:
                raise EvidenceError(f"Python RECORD row {row_number} has an invalid hash")
            result[target] = (digest_bytes.hex(), size)
    except UnicodeDecodeError as exc:
        raise EvidenceError("Python RECORD is not UTF-8") from exc
    except csv.Error as exc:
        raise EvidenceError(f"cannot parse Python RECORD: {exc}") from exc
    if not result or self_rows != 1:
        raise EvidenceError("Python RECORD must contain exactly one self-entry")
    return result


def parse_archive_wheel_record(
    content: bytes, record_path: str
) -> dict[str, tuple[str | None, int | None]]:
    """Parse a wheel's pre-install RECORD using archive-member paths."""

    if len(content) > MAX_RECORD_BYTES:
        raise EvidenceError("native wheel archive RECORD exceeds its size limit")
    try:
        text = content.decode("utf-8")
        rows = csv.reader(io.StringIO(text, newline=""), strict=True)
        result: dict[str, tuple[str | None, int | None]] = {}
        self_rows = 0
        for row_number, row in enumerate(rows, start=1):
            if row_number > MAX_RECORD_ENTRIES:
                raise EvidenceError("native wheel archive RECORD has too many entries")
            if len(row) != 3:
                raise EvidenceError(
                    f"native wheel archive RECORD row {row_number} has {len(row)} fields"
                )
            target = str(checked_canonical_path(row[0], "native wheel archive RECORD path"))
            if target in result:
                raise EvidenceError(f"native wheel archive RECORD repeats path: {target}")
            hash_field, size_field = row[1:]
            if target == record_path:
                self_rows += 1
                if hash_field or size_field:
                    raise EvidenceError("native wheel archive RECORD self-entry must be blank")
                result[target] = (None, None)
                continue
            if (
                not hash_field.startswith("sha256=")
                or re.fullmatch(r"(?:0|[1-9][0-9]*)", size_field) is None
                or len(size_field) > 20
            ):
                raise EvidenceError(
                    f"native wheel archive RECORD row {row_number} has an invalid identity"
                )
            size = int(size_field)
            if size > MAX_ARCHIVE_MEMBER_BYTES:
                raise EvidenceError(
                    f"native wheel archive RECORD row {row_number} has an invalid size"
                )
            encoded = hash_field.removeprefix("sha256=")
            if re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is None:
                raise EvidenceError(
                    f"native wheel archive RECORD row {row_number} has an invalid hash"
                )
            try:
                digest_bytes = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
            except (binascii.Error, ValueError) as exc:
                raise EvidenceError(
                    f"native wheel archive RECORD row {row_number} has an invalid hash"
                ) from exc
            if len(digest_bytes) != hashlib.sha256().digest_size:
                raise EvidenceError(
                    f"native wheel archive RECORD row {row_number} has an invalid hash"
                )
            result[target] = (digest_bytes.hex(), size)
    except UnicodeDecodeError as exc:
        raise EvidenceError("native wheel archive RECORD is not UTF-8") from exc
    except csv.Error as exc:
        raise EvidenceError(f"cannot parse native wheel archive RECORD: {exc}") from exc
    if not result or self_rows != 1:
        raise EvidenceError("native wheel archive RECORD must contain one self-entry")
    return result


def validate_wheel_metadata(content: bytes, path: str) -> dict[str, Any]:
    """Validate and normalize the security-relevant fields in one WHEEL file."""

    message = email.parser.BytesParser().parsebytes(content)
    if message.defects:
        raise EvidenceError(f"Python WHEEL has parser defects: {path}")
    allowed = {"Wheel-Version", "Generator", "Root-Is-Purelib", "Tag", "Build"}
    if any(field not in allowed for field in message):
        raise EvidenceError(f"Python WHEEL has an unsupported field: {path}")
    for field in ("Wheel-Version", "Generator", "Root-Is-Purelib", "Build"):
        if len(message.get_all(field, [])) > 1:
            raise EvidenceError(f"Python WHEEL repeats {field}: {path}")
    if checked_scalar(message.get("Wheel-Version", ""), f"Wheel-Version in {path}") != "1.0":
        raise EvidenceError(f"Python WHEEL uses an unsupported version: {path}")
    generator = message.get("Generator")
    if generator is not None:
        checked_scalar(generator, f"Generator in {path}")
    pure = checked_scalar(message.get("Root-Is-Purelib", ""), f"Root-Is-Purelib in {path}")
    if pure not in {"true", "false"}:
        raise EvidenceError(f"Python WHEEL has an invalid Root-Is-Purelib value: {path}")
    tags = message.get_all("Tag", [])
    if not 1 <= len(tags) <= 100:
        raise EvidenceError(f"Python WHEEL has an invalid tag count: {path}")
    checked_tags = [checked_scalar(tag, f"Tag in {path}") for tag in tags]
    if len(set(checked_tags)) != len(checked_tags):
        raise EvidenceError(f"Python WHEEL repeats Tag: {path}")
    for checked in checked_tags:
        if WHEEL_TAG.fullmatch(checked) is None:
            raise EvidenceError(f"Python WHEEL has an invalid tag: {path}")
    build = message.get("Build")
    if build is not None:
        build = checked_scalar(build, f"Build in {path}")
        if re.fullmatch(r"[0-9]+[A-Za-z0-9_.]*", build) is None:
            raise EvidenceError(f"Python WHEEL has an invalid Build value: {path}")
    return {
        "root_is_purelib": pure == "true",
        "build": build or "",
        "tags": sorted(checked_tags),
    }


def validate_pyvenv_config(content: bytes) -> None:
    """Require the one bounded interpreter configuration used by the runtime."""

    if len(content) > 4096:
        raise EvidenceError("pyvenv.cfg exceeds its size limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("pyvenv.cfg is not UTF-8") from exc
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(" = ")
        if not separator or key in fields:
            raise EvidenceError("pyvenv.cfg has an invalid or duplicate field")
        fields[key] = checked_scalar(value, f"pyvenv.cfg {key}")
    expected = {
        "home": "/usr/local/bin",
        "implementation": "CPython",
        "uv": EXPECTED_UV_VERSION,
        "version_info": EXPECTED_RUNTIME_PYTHON,
        "include-system-site-packages": "false",
        "prompt": "extra-codeowners",
    }
    if fields != expected:
        raise EvidenceError("pyvenv.cfg differs from the reviewed runtime configuration")


def is_venv_record_path(path: str) -> bool:
    """Return whether a canonical image path is a venv dist-info RECORD."""

    value = PurePosixPath(path)
    return (
        path.startswith("opt/venv/")
        and value.name == "RECORD"
        and value.parent.name.endswith(".dist-info")
        and value.parent.parent.name == "site-packages"
    )


def bound_identity_content(
    contents: Mapping[tuple[int, str, str], bytes],
    path: str,
    occurrence: Mapping[str, Any],
) -> bytes:
    """Read content previously bound to one exact regular-file occurrence."""

    layer = occurrence.get("layer")
    digest = occurrence.get("sha256")
    if (
        not isinstance(layer, int)
        or isinstance(layer, bool)
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise EvidenceError(f"cannot bind Python identity occurrence: {path}")
    content = contents.get((layer, path, digest))
    if content is None:
        raise EvidenceError(f"cannot bind Python identity content: {path}")
    return content


def parse_python_record_installation(
    record_path: str,
    effective: Mapping[str, dict[str, Any]],
    effective_types: Mapping[str, Mapping[str, Any]],
    identity_contents: Mapping[tuple[int, str, str], bytes],
    metadata_contents: Mapping[tuple[int, str, str], bytes],
) -> PythonRecordInstallation:
    """Bind an introduced RECORD to the complete post-layer filesystem snapshot."""

    if not is_venv_record_path(record_path):
        raise EvidenceError(
            f"Python RECORD is outside the reviewed virtual environment: {record_path}"
        )
    dist_info = PurePosixPath(record_path).parent
    site_root = dist_info.parent
    metadata_path = (dist_info / "METADATA").as_posix()
    wheel_path = (dist_info / "WHEEL").as_posix()
    identity_paths = {metadata_path, wheel_path, record_path}
    identity_records: dict[str, dict[str, Any]] = {}
    for path in sorted(identity_paths):
        occurrence = effective.get(path)
        kind = effective_types.get(path)
        if occurrence is None or kind is None or kind.get("kind") != "regular":
            raise EvidenceError(f"Python installation has no regular identity file: {path}")
        identity_records[path] = occurrence

    metadata_content = bound_identity_content(
        metadata_contents, metadata_path, identity_records[metadata_path]
    )
    package = parse_python_metadata(metadata_content, metadata_path)
    wheel_identity = validate_wheel_metadata(
        bound_identity_content(identity_contents, wheel_path, identity_records[wheel_path]),
        wheel_path,
    )
    parsed_entries = parse_wheel_record(
        bound_identity_content(identity_contents, record_path, identity_records[record_path]),
        site_root,
        record_path,
    )
    if not identity_paths.issubset(parsed_entries):
        raise EvidenceError(
            f"Python RECORD does not claim its own identity files: {package['name']}"
        )

    entries: dict[str, tuple[str | None, int | None, dict[str, Any]]] = {}
    for target, (expected_hash, expected_size) in sorted(parsed_entries.items()):
        actual = effective.get(target)
        kind = effective_types.get(target)
        if actual is None or kind is None or kind.get("kind") != "regular":
            raise EvidenceError(f"Python RECORD target is not a regular file: {target}")
        if expected_hash is not None and (
            actual.get("sha256") != expected_hash or actual.get("size") != expected_size
        ):
            raise EvidenceError(f"Python RECORD does not match layer snapshot file: {target}")
        entries[target] = (expected_hash, expected_size, actual)

    name = str(package["name"])
    version = str(package["version"])
    return PythonRecordInstallation(
        owner=f"python:{name}@{version}",
        name=name,
        version=version,
        metadata=identity_records[metadata_path],
        wheel=identity_records[wheel_path],
        record=identity_records[record_path],
        root_is_purelib=bool(wheel_identity["root_is_purelib"]),
        build=str(wheel_identity["build"]),
        tags=tuple(wheel_identity["tags"]),
        entries=entries,
    )


def validate_active_python_installations(
    effective: Mapping[str, Mapping[str, Any]],
    effective_types: Mapping[str, Mapping[str, Any]],
    active: Mapping[str, PythonRecordInstallation],
) -> dict[str, PythonRecordInstallation]:
    """Validate all active claims against one post-layer snapshot."""

    claimed: dict[str, PythonRecordInstallation] = {}
    owners: set[str] = set()
    for record_path, installation in sorted(active.items()):
        if effective.get(record_path) is not installation.record:
            raise EvidenceError(f"active Python RECORD is not effective: {record_path}")
        if installation.owner in owners:
            raise EvidenceError(
                f"layer snapshot contains duplicate Python owner: {installation.owner}"
            )
        owners.add(installation.owner)
        for target, (expected_hash, expected_size, occurrence) in installation.entries.items():
            actual = effective.get(target)
            kind = effective_types.get(target)
            if actual is None or kind is None or kind.get("kind") != "regular":
                raise EvidenceError(f"active Python RECORD target is not a regular file: {target}")
            if actual is not occurrence or (
                expected_hash is not None
                and (actual.get("sha256") != expected_hash or actual.get("size") != expected_size)
            ):
                raise EvidenceError(
                    "Python RECORD does not match installed file; managed file changed without "
                    f"a matching replacement RECORD: {target}"
                )
            previous = claimed.get(target)
            if previous is not None:
                raise EvidenceError(
                    "Python installations claim the same RECORD path: "
                    f"{target} ({previous.owner}, {installation.owner})"
                )
            claimed[target] = installation
    return claimed


def validate_effective_python_installations(
    effective: Mapping[str, Mapping[str, Any]],
    effective_types: Mapping[str, Mapping[str, Any]],
    components: Sequence[Mapping[str, Any]],
    identity_contents: Mapping[tuple[int, str, str], bytes],
    active: Mapping[str, PythonRecordInstallation],
) -> dict[str, str]:
    """Validate the final venv and derive the compatible effective ownership view."""

    # Minimal synthetic inventories used by parser unit tests predate wheel
    # installation. Real candidates must have identity files; policy comparison
    # rejects a candidate that removes all of them.
    if not identity_contents:
        return {}

    pyvenv_path = "opt/venv/pyvenv.cfg"
    pyvenv_record = effective.get(pyvenv_path)
    if pyvenv_record is None:
        raise EvidenceError("runtime virtual environment has no effective pyvenv.cfg")
    validate_pyvenv_config(bound_identity_content(identity_contents, pyvenv_path, pyvenv_record))

    active_claims = validate_active_python_installations(effective, effective_types, active)
    effective_python = [
        component
        for component in components
        if component.get("ecosystem") == "python" and component.get("effective") is True
    ]
    for component in effective_python:
        matches = [
            installation
            for installation in active.values()
            if installation.name == component.get("name")
            and installation.version == component.get("version")
            and installation.metadata.get("sha256") == component.get("metadata_sha256")
            and effective.get(str(installation.metadata.get("path"))) is installation.metadata
        ]
        if len(matches) != 1:
            raise EvidenceError(
                "effective Python distribution must have exactly one active RECORD: "
                f"{component.get('name')}"
            )
    effective_identities = {
        (component.get("name"), component.get("version"), component.get("metadata_sha256"))
        for component in effective_python
    }
    for installation in active.values():
        identity = (
            installation.name,
            installation.version,
            installation.metadata.get("sha256"),
        )
        if identity not in effective_identities:
            raise EvidenceError(
                f"active Python RECORD has no effective component: {installation.owner}"
            )

    for path, kind in effective_types.items():
        if not path.startswith("opt/venv/") or kind.get("kind") == "directory":
            continue
        if kind.get("kind") == "regular" and path not in active_claims and path != pyvenv_path:
            raise EvidenceError(f"virtual-environment file is not owned by a wheel RECORD: {path}")

    observed_links = {
        path: kind.get("target")
        for path, kind in effective_types.items()
        if path.startswith("opt/venv/")
        and kind.get("kind") != "directory"
        and kind.get("kind") != "regular"
    }
    if observed_links != VENV_LINKS:
        raise EvidenceError("runtime virtual environment has unexpected links or file types")
    return {path: installation.name for path, installation in active_claims.items()}


def run(
    command: Sequence[str],
    *,
    max_output_bytes: int,
    cwd: Path | None = None,
    pass_fds: Sequence[int] = (),
) -> bytes:
    """Run a fixed command with bounded stdout and stderr capture."""

    if max_output_bytes < 0:
        raise EvidenceError("command output limit must not be negative")
    inherited_descriptors = tuple(pass_fds)
    if (
        len(inherited_descriptors) > 16
        or len(set(inherited_descriptors)) != len(inherited_descriptors)
        or any(
            type(descriptor) is not int or descriptor < 0 for descriptor in inherited_descriptors
        )
    ):
        raise EvidenceError("inherited command descriptors are invalid")
    process = subprocess.Popen(  # noqa: S603 - every caller supplies a fixed executable
        command,
        close_fds=True,
        cwd=cwd,
        pass_fds=inherited_descriptors,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise EvidenceError("cannot capture command output")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = bytearray()
    error = bytearray()
    try:
        while selector.get_map():
            for key, _events in selector.select():
                chunk = os.read(key.fd, 1024 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    if len(output) + len(chunk) > max_output_bytes:
                        raise EvidenceError(
                            f"command output exceeds the size limit ({' '.join(command)})"
                        )
                    output.extend(chunk)
                elif len(error) < MAX_PROCESS_ERROR_BYTES:
                    remaining = MAX_PROCESS_ERROR_BYTES - len(error)
                    error.extend(chunk[:remaining])
        return_code = process.wait()
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
    if return_code:
        detail = bytes(error).decode(errors="replace").strip()
        raise EvidenceError(f"command failed ({' '.join(command)}): {detail}")
    return bytes(output)


def executable(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise EvidenceError(f"required executable is not available: {name}")
    return path


def save_docker_image_bounded(image_id: str, destination: Path) -> None:
    """Stream docker-save output with hard stdout and diagnostic limits."""

    process = subprocess.Popen(  # noqa: S603 - fixed executable and arguments
        [executable("docker"), "image", "save", image_id],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise EvidenceError("cannot capture docker image save output")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    saved_bytes = 0
    error = bytearray()
    try:
        with destination.open("wb") as output:
            while selector.get_map():
                for key, _events in selector.select():
                    chunk = os.read(key.fd, 1024 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        saved_bytes += len(chunk)
                        if saved_bytes > MAX_DOCKER_SAVE_BYTES:
                            raise EvidenceError("docker save archive exceeds the size limit")
                        output.write(chunk)
                    elif len(error) < MAX_PROCESS_ERROR_BYTES:
                        remaining = MAX_PROCESS_ERROR_BYTES - len(error)
                        error.extend(chunk[:remaining])
        return_code = process.wait()
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
    if return_code:
        detail = bytes(error).decode(errors="replace").strip()
        raise EvidenceError(f"docker image save failed: {detail}")


def load_json_bytes(content: bytes, source: str) -> dict[str, Any]:
    """Parse one already-retained JSON snapshot."""

    value = strict_json_loads(content, source)
    if not isinstance(value, dict):
        raise EvidenceError(f"expected a JSON object in {source}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    return load_json_bytes(
        read_stable_local_bytes(path, max_bytes=MAX_JSON_BYTES, source=f"JSON input {path}"),
        str(path),
    )


def require_schema(value: Mapping[str, Any], source: str) -> None:
    schema = value.get("schema_version")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != SCHEMA_VERSION:
        raise EvidenceError(f"unsupported {source} schema: {schema!r}")


def require_exact_fields(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError(f"{source} has an unexpected schema shape")
    return value


def validate_policy_schema(policy: Mapping[str, Any]) -> None:
    """Reject unknown, missing, or weakly typed policy fields at every level."""

    require_schema(policy, "policy")
    expected_top_level = {
        "schema_version",
        "base_image",
        "base_image_index_digest",
        "base_image_platforms",
        "platforms",
        "distribution_approval",
        "license_resolutions",
        "license_texts",
        "custom_license_evidence",
        "unexpanded_python_payloads",
        "filesystem_baselines",
        "docker_python_recipe",
        "cpython_source",
        "python_sources",
        "alpine_distfiles_release",
        "alpine_recipe_archives",
        "alpine_recipe_exceptions",
        "native_component_sources",
        "native_component_coverage",
    }
    require_exact_fields(policy, expected_top_level, "policy")

    base_image = policy.get("base_image")
    if isinstance(base_image, str):
        checked_scalar(base_image, "policy base image", max_length=MAX_PATH_BYTES)
    if (
        not isinstance(base_image, str)
        or not base_image
        or "@" in base_image
        or any(character.isspace() for character in base_image)
    ):
        raise EvidenceError("policy base image reference is invalid")
    base_digest = policy.get("base_image_index_digest")
    if not isinstance(base_digest, str) or SHA256.fullmatch(base_digest) is None:
        raise EvidenceError("policy base image index digest is invalid")
    base_platforms = require_exact_fields(
        policy.get("base_image_platforms"),
        {"linux/amd64", "linux/arm64"},
        "base-image platform policy",
    )
    for platform, record in base_platforms.items():
        reviewed = require_exact_fields(
            record, {"layer_diff_ids"}, f"base-image platform policy {platform}"
        )
        layers = reviewed["layer_diff_ids"]
        if (
            not isinstance(layers, list)
            or not layers
            or len(layers) > MAX_IMAGE_MEMBERS
            or not all(isinstance(item, str) and SHA256.fullmatch(item) for item in layers)
            or len(set(layers)) != len(layers)
        ):
            raise EvidenceError(f"base-image platform policy {platform} has invalid layers")

    platforms = require_exact_fields(
        policy.get("platforms"), {"linux/amd64", "linux/arm64"}, "component policy"
    )
    for platform, components in platforms.items():
        validated = validate_component_records(components, f"policy platform {platform}")
        validate_platform_component_invariants(validated, platform, f"policy platform {platform}")

    approval = require_exact_fields(
        policy.get("distribution_approval"),
        {"approved", "approved_by", "approved_on", "rationale"},
        "distribution approval",
    )
    if not isinstance(approval["approved"], bool):
        raise EvidenceError("distribution approval has an invalid approved state")
    for field in ("approved_by", "approved_on", "rationale"):
        value = approval[field]
        if not isinstance(value, str):
            raise EvidenceError(f"distribution approval has an invalid {field}")
        checked_scalar(
            value,
            f"distribution approval {field}",
            max_length=MAX_LICENSE_FIELD_LENGTH,
            allow_empty=field != "rationale",
        )

    resolutions = policy.get("license_resolutions")
    if not isinstance(resolutions, dict) or len(resolutions) > MAX_COMPONENTS:
        raise EvidenceError("policy has invalid license resolutions")
    for key, value in resolutions.items():
        if (
            checked_scalar(
                str(key),
                "license resolution identity",
                max_length=MAX_COMPONENT_KEY_LENGTH,
            )
            != key
        ):
            raise EvidenceError("policy has an invalid license resolution identity")
        resolution = require_exact_fields(
            value, {"expression", "rationale"}, f"license resolution {key}"
        )
        for field in ("expression", "rationale"):
            raw = resolution[field]
            if not isinstance(raw, str):
                raise EvidenceError(f"license resolution {key} has an invalid {field}")
            checked_scalar(
                raw,
                f"license resolution {key} {field}",
                max_length=MAX_LICENSE_FIELD_LENGTH,
            )

    license_texts = policy.get("license_texts")
    if not isinstance(license_texts, list) or len(license_texts) > MAX_COMPONENTS:
        raise EvidenceError("policy has invalid standard-license text records")
    for index, value in enumerate(license_texts):
        record = require_exact_fields(value, {"id", "sha256", "url"}, f"license text {index}")
        identifier = record["id"]
        digest = record["sha256"]
        url = record["url"]
        if (
            not isinstance(identifier, str)
            or checked_scalar(identifier, f"license text {index} identifier") != identifier
            or re.fullmatch(r"[A-Za-z0-9.+-]+", identifier) is None
        ):
            raise EvidenceError(f"license text {index} has an invalid identifier")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise EvidenceError(f"license text {index} has an invalid digest")
        if not isinstance(url, str):
            raise EvidenceError(f"license text {index} has an invalid URL")
        require_https_source_url(url)

    docker_recipe = require_exact_fields(
        policy.get("docker_python_recipe"),
        {"url", "sha256", "license_url", "license_sha256"},
        "policy docker_python_recipe",
    )
    for key, value in docker_recipe.items():
        if not isinstance(value, str):
            raise EvidenceError(f"policy docker_python_recipe has an invalid {key}")
        if key.endswith("url"):
            require_https_source_url(value)
        elif re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise EvidenceError(f"policy docker_python_recipe has an invalid {key}")

    cpython_source = require_exact_fields(
        policy.get("cpython_source"),
        {
            "url",
            "sha256",
            "size",
            "license_member",
            "license_sha256",
            "patchlevel_member",
            "patchlevel_sha256",
        },
        "policy cpython_source",
    )
    for key in (
        "url",
        "sha256",
        "license_member",
        "license_sha256",
        "patchlevel_member",
        "patchlevel_sha256",
    ):
        value = cpython_source[key]
        if not isinstance(value, str):
            raise EvidenceError(f"policy cpython_source has an invalid {key}")
        if key == "url":
            require_https_source_url(value)
        elif key in {"license_member", "patchlevel_member"}:
            checked_canonical_path(value, f"CPython source {key.removesuffix('_member')} member")
        elif re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise EvidenceError(f"policy cpython_source has an invalid {key}")
    cpython_size = cpython_source["size"]
    if (
        not isinstance(cpython_size, int)
        or isinstance(cpython_size, bool)
        or not 0 < cpython_size <= MAX_DOWNLOAD_BYTES
    ):
        raise EvidenceError("policy cpython_source has an invalid size")
    validate_cpython_policy_relationships(policy)

    python_sources = policy.get("python_sources")
    if not isinstance(python_sources, list) or len(python_sources) > MAX_COMPONENTS:
        raise EvidenceError("policy has invalid Python source records")
    for index, value in enumerate(python_sources):
        record = require_exact_fields(
            value, {"name", "version", "url", "sha256", "size"}, f"Python source {index}"
        )
        if not all(
            isinstance(record[field], str) for field in ("name", "version", "url", "sha256")
        ):
            raise EvidenceError(f"Python source {index} has invalid scalar fields")
        for field in ("name", "version"):
            if checked_scalar(record[field], f"Python source {index} {field}") != record[field]:
                raise EvidenceError(f"Python source {index} has a non-canonical {field}")
        require_https_source_url(record["url"])
        if re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None:
            raise EvidenceError(f"Python source {index} has an invalid digest")
        size = record["size"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_DOWNLOAD_BYTES
        ):
            raise EvidenceError(f"Python source {index} has an invalid size")

    alpine_release = policy.get("alpine_distfiles_release")
    if (
        not isinstance(alpine_release, str)
        or checked_scalar(alpine_release, "Alpine distfiles release") != alpine_release
        or re.fullmatch(r"v\d+\.\d+", alpine_release) is None
    ):
        raise EvidenceError("policy has an invalid Alpine distfiles release")
    recipes = policy.get("alpine_recipe_archives")
    if not isinstance(recipes, dict) or len(recipes) > MAX_COMPONENTS:
        raise EvidenceError("policy has invalid Alpine recipe archives")
    for key, digest in recipes.items():
        if checked_scalar(str(key), "Alpine recipe identity") != key:
            raise EvidenceError("policy has a non-canonical Alpine recipe identity")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise EvidenceError(f"policy has an invalid Alpine recipe digest for {key}")
    exceptions = policy.get("alpine_recipe_exceptions")
    if not isinstance(exceptions, dict) or not set(exceptions) <= set(recipes):
        raise EvidenceError("policy has invalid Alpine recipe exceptions")
    for key in exceptions:
        alpine_recipe_exception(policy, key)

    custom = policy.get("custom_license_evidence")
    if not isinstance(custom, dict) or len(custom) > MAX_COMPONENTS:
        raise EvidenceError("policy has invalid custom-license evidence")
    for identifier, value in custom.items():
        if (
            not isinstance(identifier, str)
            or checked_scalar(identifier, "custom-license identifier") != identifier
            or re.fullmatch(r"LicenseRef-[A-Za-z0-9][A-Za-z0-9.+-]*", identifier) is None
        ):
            raise EvidenceError("policy has an invalid custom-license identifier")
        requirement = require_exact_fields(
            value,
            {"components", "evidence", "rationale", "require_source_notice"},
            f"custom-license evidence {identifier}",
        )
        if requirement["require_source_notice"] is not True:
            raise EvidenceError(f"custom-license evidence {identifier} must require a notice")
        rationale = requirement["rationale"]
        if not isinstance(rationale, str) or not rationale.strip():
            raise EvidenceError(f"custom-license evidence {identifier} has no rationale")
        if (
            checked_scalar(
                rationale,
                f"custom-license evidence {identifier} rationale",
                max_length=MAX_LICENSE_FIELD_LENGTH,
            )
            != rationale
        ):
            raise EvidenceError(f"custom-license evidence {identifier} has invalid rationale")
        components = requirement["components"]
        if (
            not isinstance(components, list)
            or len(components) > MAX_COMPONENTS
            or not all(isinstance(component, str) for component in components)
            or len(components) != len(set(components))
        ):
            raise EvidenceError(f"custom-license evidence {identifier} has invalid components")
        for component in components:
            if (
                checked_scalar(
                    component,
                    "custom-license component identity",
                    max_length=MAX_COMPONENT_KEY_LENGTH,
                )
                != component
            ):
                raise EvidenceError(f"custom-license evidence {identifier} has invalid components")
        evidence_records = requirement["evidence"]
        if not isinstance(evidence_records, dict) or len(evidence_records) > MAX_COMPONENTS:
            raise EvidenceError(f"custom-license evidence {identifier} has invalid records")
        for component, evidence in evidence_records.items():
            if (
                checked_scalar(
                    str(component),
                    "custom-license evidence identity",
                    max_length=MAX_COMPONENT_KEY_LENGTH,
                )
                != component
            ):
                raise EvidenceError(
                    f"custom-license evidence {identifier} has an invalid component identity"
                )
            record = require_exact_fields(
                evidence, {"path", "sha256"}, f"custom-license evidence {identifier}/{component}"
            )
            if not isinstance(record["path"], str):
                raise EvidenceError(f"custom-license evidence {identifier} has an invalid path")
            checked_canonical_path(record["path"], f"custom-license evidence {identifier} path")
            if (
                not isinstance(record["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            ):
                raise EvidenceError(f"custom-license evidence {identifier} has an invalid digest")

    # These validators enforce the exact nested baseline record shapes.
    validate_unexpanded_payload_policy_schema(policy)
    validate_native_component_policy_schema(policy)
    if approval["approved"] is True and any(
        owner_record["review"]["state"] == "open"
        for platform_records in policy["native_component_coverage"].values()
        for owner_record in platform_records
    ):
        raise EvidenceError(
            "distribution approval cannot be true while native-component coverage is incomplete"
        )
    for platform in ("linux/amd64", "linux/arm64"):
        baseline = filesystem_baseline(policy, platform)
        validate_payload_records(
            baseline["apk_database_occurrences"], f"APK database policy for {platform}"
        )
        validate_directory_effect_policy(baseline["post_base_directory_effects"], platform)
        validate_removal_policy(baseline["post_base_removals"], platform)


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile():
        raise EvidenceError(f"expected regular file: {member.name}")
    if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
        raise EvidenceError(f"archive member exceeds size limit: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise EvidenceError(f"cannot read archive member: {member.name}")
    value = stream.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
    if len(value) > MAX_ARCHIVE_MEMBER_BYTES or len(value) != member.size:
        raise EvidenceError(f"archive member exceeds size limit: {member.name}")
    return value


def hash_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    algorithm: str = "sha256",
    max_bytes: int = MAX_IMAGE_TOTAL_BYTES,
) -> str:
    """Hash one bounded regular tar member without retaining it in memory."""

    if not member.isfile():
        raise EvidenceError(f"expected regular file: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise EvidenceError(f"cannot read archive member: {member.name}")
    if member.size < 0 or member.size > max_bytes:
        raise EvidenceError(f"archive member exceeds size limit: {member.name}")
    digest = hashlib.new(algorithm)
    remaining = member.size
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise EvidenceError(f"truncated archive member: {member.name}")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def image_inventory(
    image: str,
    platform: str,
    subject_digest: str,
    *,
    allow_config_digest_subject: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Inventory effective components and every regular file in every image layer."""

    if not SHA256.fullmatch(subject_digest):
        raise EvidenceError("subject digest must be sha256:<64 lowercase hex characters>")
    inspect = strict_json_loads(
        run(["docker", "image", "inspect", image], max_output_bytes=MAX_JSON_BYTES),
        "docker inspect",
    )
    if not isinstance(inspect, list) or len(inspect) != 1:
        raise EvidenceError("docker image inspect did not return exactly one image")
    info = inspect[0]
    if not isinstance(info, dict):
        raise EvidenceError("docker image inspect entry is not an object")
    expected_arch = platform.removeprefix("linux/")
    if info.get("Os") != "linux" or info.get("Architecture") != expected_arch:
        raise EvidenceError(
            f"image platform is {info.get('Os')}/{info.get('Architecture')}, expected {platform}"
        )
    image_id = verify_local_image_subject(
        info,
        subject_digest,
        allow_config_digest_subject=allow_config_digest_subject,
    )

    with tempfile.TemporaryDirectory(prefix="extra-codeowners-image-") as temporary:
        saved = Path(temporary) / "image.tar"
        save_docker_image_bounded(image_id, saved)
        inventory, files = _inventory_saved_image(
            saved,
            platform,
            subject_digest,
            expected_config_digest=image_id,
        )

    return inventory, files


def verify_local_image_subject(
    info: Mapping[str, Any],
    subject_digest: str,
    *,
    allow_config_digest_subject: bool,
) -> str:
    """Bind a claimed subject to a pulled manifest or an explicitly local config."""

    image_id = info.get("Id")
    if not isinstance(image_id, str) or not SHA256.fullmatch(image_id):
        raise EvidenceError("Docker returned an invalid image configuration digest")
    repo_digests = info.get("RepoDigests")
    if repo_digests is None:
        repo_digests = []
    if not isinstance(repo_digests, list) or not all(
        isinstance(item, str) for item in repo_digests
    ):
        raise EvidenceError("Docker returned invalid repository digests")
    manifest_digests: set[str] = set()
    for item in repo_digests:
        _, separator, digest = item.rpartition("@")
        if not separator or not SHA256.fullmatch(digest):
            raise EvidenceError(f"Docker returned an invalid repository digest: {item!r}")
        manifest_digests.add(digest)
    if subject_digest in manifest_digests:
        return image_id
    if allow_config_digest_subject and subject_digest == image_id:
        return image_id
    raise EvidenceError(
        "claimed subject digest is not a repository digest for the local image; "
        "configuration digests are allowed only for explicitly local CI evidence"
    )


def _inventory_saved_image(
    saved: Path,
    platform: str,
    subject_digest: str,
    *,
    expected_config_digest: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    effective: dict[str, dict[str, Any]] = {}
    occurrences: list[dict[str, Any]] = []
    directory_occurrences: list[dict[str, Any]] = []
    non_regular_occurrences: list[dict[str, Any]] = []
    whiteout_occurrences: list[dict[str, Any]] = []
    metadata_occurrences: list[dict[str, Any]] = []
    apk_database_contents: dict[tuple[int, str], bytes] = {}
    identity_contents: dict[tuple[int, str, str], bytes] = {}
    metadata_contents: dict[tuple[int, str, str], bytes] = {}
    wheel_installations: list[PythonRecordInstallation] = []
    active_python_installations: dict[str, PythonRecordInstallation] = {}
    historically_managed_paths: set[str] = set()
    historical_record_entry_count = 0
    payload_details: dict[tuple[int, str, str], dict[str, Any]] = {}
    runtime_identity_details: dict[tuple[int, str, str], bytes | Mapping[str, Any]] = {}
    effective_types: dict[str, dict[str, Any]] = {}
    layer_digests: list[str] = []
    saved_layers_total = 0
    image_regular_total = 0
    image_member_count = 0

    try:
        with tarfile.open(saved, mode="r|", tarinfo=BoundedTarInfo) as preflight:
            outer_names: set[str] = set()
            for outer_count, member in enumerate(preflight, start=1):
                if outer_count > MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError("docker save archive has too many entries")
                name = str(checked_path(member.name))
                if name in outer_names:
                    raise EvidenceError(f"docker save archive repeats path: {name}")
                outer_names.add(name)
    except EvidenceError:
        raise
    except tarfile.TarError as exc:
        raise EvidenceError(f"invalid docker save archive: {exc}") from exc

    with tarfile.open(saved, mode="r:", tarinfo=BoundedTarInfo) as outer:
        try:
            manifest_member = outer.getmember("manifest.json")
        except KeyError as exc:
            raise EvidenceError("docker save archive has no manifest.json") from exc
        manifest = strict_json_loads(read_member(outer, manifest_member), "docker manifest")
        if (
            not isinstance(manifest, list)
            or len(manifest) != 1
            or not isinstance(manifest[0], dict)
        ):
            raise EvidenceError("docker save archive must contain exactly one image")
        layers = manifest[0].get("Layers")
        if not isinstance(layers, list) or not layers:
            raise EvidenceError("docker save manifest has no layers")
        config_name = manifest[0].get("Config")
        if not isinstance(config_name, str):
            raise EvidenceError("docker save manifest has no image configuration")
        config_path = checked_path(config_name)
        if len(config_path.parts) != 3 or config_path.parts[:2] != ("blobs", "sha256"):
            raise EvidenceError(f"unexpected image configuration location: {config_name}")
        config_digest = f"sha256:{config_path.name}"
        if not SHA256.fullmatch(config_digest):
            raise EvidenceError(f"invalid image configuration digest: {config_digest}")
        try:
            config_member = outer.getmember(config_name)
        except KeyError as exc:
            raise EvidenceError("docker save archive has an invalid image configuration") from exc
        config_content = read_member(outer, config_member)
        if sha256_bytes(config_content) != config_path.name:
            raise EvidenceError("docker save image configuration digest does not match its bytes")
        if expected_config_digest is not None and config_digest != expected_config_digest:
            raise EvidenceError(
                "docker save image configuration does not match the inspected image"
            )
        config = strict_json_loads(config_content, "docker image configuration")
        if not isinstance(config, dict) or not isinstance(config.get("config"), dict):
            raise EvidenceError("docker save archive has an invalid image configuration")
        expected_architecture = platform.removeprefix("linux/")
        if config.get("os") != "linux" or config.get("architecture") != expected_architecture:
            raise EvidenceError(f"docker image configuration platform does not match {platform}")
        labels = config["config"].get("Labels", {})
        if not isinstance(labels, dict):
            raise EvidenceError("image labels are invalid")
        rootfs = config.get("rootfs")
        if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
            raise EvidenceError("docker image configuration has no layered root filesystem")
        diff_ids = rootfs.get("diff_ids")
        if not isinstance(diff_ids, list) or not all(
            isinstance(item, str) and SHA256.fullmatch(item) for item in diff_ids
        ):
            raise EvidenceError("docker image configuration has invalid rootfs diff IDs")

        seen_layers: set[str] = set()
        validated_layers: list[tuple[str, PurePosixPath, str]] = []
        for layer_name in layers:
            if not isinstance(layer_name, str):
                raise EvidenceError("invalid layer name")
            layer_path = checked_path(layer_name)
            if len(layer_path.parts) != 3 or layer_path.parts[:2] != ("blobs", "sha256"):
                raise EvidenceError(f"unexpected layer location: {layer_name}")
            layer_digest = f"sha256:{layer_path.name}"
            if not SHA256.fullmatch(layer_digest):
                raise EvidenceError(f"invalid layer digest: {layer_digest}")
            if layer_digest in seen_layers:
                raise EvidenceError(f"docker save manifest repeats layer: {layer_digest}")
            seen_layers.add(layer_digest)
            layer_digests.append(layer_digest)
            validated_layers.append((layer_name, layer_path, layer_digest))
        if diff_ids != layer_digests:
            raise EvidenceError(
                "docker save manifest layers do not match image configuration rootfs diff IDs"
            )

        def remove_effective(target: str) -> None:
            for candidate in list(effective_types):
                if candidate == target or candidate.startswith(f"{target}/"):
                    effective_types.pop(candidate, None)
                    effective.pop(candidate, None)

        def ensure_parent_directories(path: PurePosixPath, layer_index: int) -> None:
            parents = [parent for parent in path.parents if str(parent) != "."]
            for parent in reversed(parents):
                parent_text = str(parent)
                existing = effective_types.get(parent_text)
                if existing is not None and existing["kind"] != "directory":
                    raise EvidenceError(
                        "image layer entry has a non-directory ancestor: "
                        f"{path} through {parent_text}"
                    )
                if existing is None:
                    # Tar extraction creates absent parent directories. Track
                    # those implicit entries so a later child cannot traverse a
                    # regular file or link at the same path.
                    effective_types[parent_text] = {
                        "kind": "directory",
                        "layer": layer_index,
                    }

        for layer_index, (layer_name, layer_path, layer_digest) in enumerate(validated_layers):
            managed_before_layer = set(historically_managed_paths)
            try:
                member = outer.getmember(layer_name)
            except KeyError as exc:
                raise EvidenceError(f"missing image layer: {layer_name}") from exc
            if member.size > MAX_IMAGE_TOTAL_BYTES:
                raise EvidenceError(f"image layer exceeds size limit: {layer_digest}")
            saved_layers_total += member.size
            if saved_layers_total > MAX_IMAGE_TOTAL_BYTES:
                raise EvidenceError("saved image layers exceed the cumulative size limit")
            if hash_member(outer, member) != layer_path.name:
                raise EvidenceError(f"image layer digest does not match its bytes: {layer_digest}")
            whiteout_targets: list[str] = []
            opaque_directories: list[str] = []
            layer_directories: set[str] = set()
            scan_stream = outer.extractfile(member)
            if scan_stream is None:
                raise EvidenceError(f"cannot read image layer: {layer_name}")
            with tarfile.open(fileobj=scan_stream, mode="r|", tarinfo=BoundedTarInfo) as layer:
                layer_paths: set[str] = set()
                for entry in layer:
                    image_member_count += 1
                    if image_member_count > MAX_IMAGE_MEMBERS:
                        raise EvidenceError("image layers have too many cumulative entries")
                    path = checked_path(entry.name)
                    header = normalized_layer_header(entry)
                    path_text = str(path)
                    if path_text in layer_paths:
                        raise EvidenceError(
                            f"image layer repeats path {path_text!r}: {layer_digest}"
                        )
                    layer_paths.add(path_text)
                    basename = path.name
                    if (
                        not basename.startswith(".wh.")
                        and path_text.startswith("opt/venv/")
                        and BYTECODE_FILE.search(path_text)
                    ):
                        raise EvidenceError(
                            "image layer contains executable bytecode in virtual environment: "
                            f"{path_text}"
                        )
                    if entry.isdir():
                        layer_directories.add(path_text)
                    if basename.startswith(".wh."):
                        if not entry.isfile() or entry.size != 0:
                            raise EvidenceError(
                                f"whiteout must be an empty regular file: {path_text}"
                            )
                        if basename == ".wh.":
                            raise EvidenceError(f"whiteout has no target basename: {path_text}")
                    if basename == ".wh..wh..opq":
                        parent = str(path.parent)
                        opaque_directories.append(parent)
                        whiteout_occurrences.append(
                            {
                                "kind": "opaque",
                                "layer": layer_index,
                                "layer_digest": layer_digest,
                                "path": path_text,
                                "target": parent,
                                **header,
                            }
                        )
                        continue
                    if basename.startswith(".wh."):
                        whiteout_target_path = path.parent / basename.removeprefix(".wh.")
                        whiteout_target = str(whiteout_target_path)
                        whiteout_targets.append(whiteout_target)
                        whiteout_occurrences.append(
                            {
                                "kind": "whiteout",
                                "layer": layer_index,
                                "layer_digest": layer_digest,
                                "path": path_text,
                                "target": whiteout_target,
                                **header,
                            }
                        )
                        continue

            # OCI whiteouts always remove entries inherited from lower layers,
            # regardless of where the marker occurs in this layer's tar stream.
            # Apply every marker before any ordinary entry from this layer.
            lower_layer_paths = set(effective_types)

            def validate_marker_parent(parent: str, current_layer_directories: set[str]) -> None:
                if parent == ".":
                    return
                path = PurePosixPath(parent)
                for candidate in (path, *path.parents):
                    candidate_text = str(candidate)
                    if candidate_text == ".":
                        continue
                    existing = effective_types.get(candidate_text)
                    if (
                        existing is not None
                        and existing["kind"] != "directory"
                        and candidate_text not in current_layer_directories
                    ):
                        raise EvidenceError(
                            "OCI whiteout has a non-directory parent topology: "
                            f"{parent} through {candidate_text}"
                        )

            for parent in opaque_directories:
                validate_marker_parent(parent, layer_directories)
                prefix = "" if parent == "." else f"{parent}/"
                if not any(candidate.startswith(prefix) for candidate in lower_layer_paths):
                    raise EvidenceError(
                        f"OCI opaque whiteout does not remove any lower-layer entries: {parent}"
                    )
                for candidate in list(effective_types):
                    if candidate.startswith(prefix):
                        effective_types.pop(candidate, None)
                        effective.pop(candidate, None)
            for whiteout_target in whiteout_targets:
                validate_marker_parent(
                    str(PurePosixPath(whiteout_target).parent), layer_directories
                )
                if whiteout_target not in lower_layer_paths:
                    raise EvidenceError(
                        f"OCI whiteout target is absent from lower layers: {whiteout_target}"
                    )
                remove_effective(whiteout_target)

            layer_stream = outer.extractfile(member)
            if layer_stream is None:
                raise EvidenceError(f"cannot reread image layer: {layer_name}")
            current_layer_regular: dict[str, dict[str, Any]] = {}
            current_layer_ordinary_paths: set[str] = set()
            current_layer_record_paths: set[str] = set()
            with tarfile.open(fileobj=layer_stream, mode="r|", tarinfo=BoundedTarInfo) as layer:
                for entry in layer:
                    path = checked_path(entry.name)
                    header = normalized_layer_header(entry)
                    path_text = str(path)
                    basename = path.name
                    if basename.startswith(".wh."):
                        continue
                    current_layer_ordinary_paths.add(path_text)

                    ensure_parent_directories(path, layer_index)

                    existing_type = effective_types.get(path_text)
                    preserves_directory = entry.isdir() and (
                        existing_type is None or existing_type["kind"] == "directory"
                    )
                    if not preserves_directory:
                        remove_effective(path_text)

                    if not entry.isfile():
                        if (
                            path_text == "lib/apk/db/installed"
                            or DIST_INFO.search(path_text)
                            or WHEEL_IDENTITY_FILE.search(path_text)
                        ):
                            raise EvidenceError(
                                f"package metadata path is not a regular file: {path_text}"
                            )
                        kind = (
                            "directory"
                            if entry.isdir()
                            else "hardlink"
                            if entry.islnk()
                            else "symlink"
                            if entry.issym()
                            else "other"
                        )
                        if entry.islnk() or entry.issym():
                            checked_image_link_target(entry.linkname)
                        if kind == "directory":
                            directory_record: dict[str, Any] = {
                                "layer": layer_index,
                                "layer_digest": layer_digest,
                                "path": path_text,
                                **header,
                            }
                            directory_occurrences.append(directory_record)
                        else:
                            non_regular_occurrences.append(
                                {
                                    "kind": kind,
                                    "layer": layer_index,
                                    "layer_digest": layer_digest,
                                    "path": path_text,
                                    **header,
                                    **(
                                        {"target": entry.linkname}
                                        if entry.islnk() or entry.issym()
                                        else {}
                                    ),
                                }
                            )
                        effective_types[path_text] = {
                            "kind": kind,
                            "layer": layer_index,
                            **(
                                {"target": entry.linkname} if entry.islnk() or entry.issym() else {}
                            ),
                        }
                        continue
                    image_regular_total += entry.size
                    if image_regular_total > MAX_IMAGE_TOTAL_BYTES:
                        raise EvidenceError("image contents exceed the cumulative size limit")
                    content = read_member(layer, entry)
                    record: dict[str, Any] = {
                        "layer": layer_index,
                        "layer_digest": layer_digest,
                        "path": path_text,
                        "sha256": sha256_bytes(content),
                        "size": len(content),
                        **header,
                    }
                    occurrences.append(record)
                    current_layer_regular[path_text] = record
                    effective[path_text] = record
                    effective_types[path_text] = {
                        "kind": "regular",
                        "layer": layer_index,
                    }
                    if path_text == "lib/apk/db/installed":
                        apk_database_contents[(layer_index, record["sha256"])] = content
                    if DIST_INFO.search(path_text):
                        metadata_contents[(layer_index, path_text, record["sha256"])] = content
                        package = parse_python_metadata(content, path_text)
                        package["layer"] = layer_index
                        package["path"] = path_text
                        metadata_occurrences.append(package)
                        if len(metadata_occurrences) > MAX_COMPONENTS:
                            raise EvidenceError(
                                "image contains too many Python metadata occurrences"
                            )
                    if WHEEL_IDENTITY_FILE.search(path_text) or path_text == "opt/venv/pyvenv.cfg":
                        identity_contents[(layer_index, path_text, record["sha256"])] = content
                    payload_key = (layer_index, path_text, record["sha256"])
                    if path_text == CPYTHON_VERSION_HEADER:
                        runtime_identity_details[payload_key] = content
                    elif path_text in {CPYTHON_INTERPRETER, CPYTHON_SHARED_LIBRARY}:
                        runtime_identity_details[payload_key] = parse_elf_identity(
                            content, platform, path_text
                        )
                    if DIST_INFO_SBOM.search(path_text):
                        payload_details[payload_key] = {
                            "kind": "cyclonedx",
                            "identity": parse_cyclonedx_sbom(content, path_text),
                        }
                    native_path = is_native_payload_path(path_text)
                    native_magic = is_python_virtual_environment_path(
                        path_text
                    ) and content.startswith(ELF_MAGIC)
                    if native_path or native_magic:
                        if payload_key in payload_details:
                            raise EvidenceError(
                                "Python payload is ambiguously both an SBOM and native: "
                                f"{path_text}"
                            )
                        payload_details[payload_key] = {
                            "kind": "elf",
                            "identity": parse_elf_identity(content, platform, path_text),
                        }
                    if is_venv_record_path(path_text):
                        current_layer_record_paths.add(path_text)

            # Replay against the complete layer snapshot, not tar member order.
            # An overwritten or whiteouted RECORD is no longer active, but its
            # installation evidence remains in wheel_installations.
            for record_path, installation in list(active_python_installations.items()):
                if effective.get(record_path) is not installation.record:
                    active_python_installations.pop(record_path)

            for record_path in sorted(current_layer_record_paths):
                introduced = current_layer_regular[record_path]
                if effective.get(record_path) is not introduced:
                    raise EvidenceError(
                        f"introduced Python RECORD is not effective in its layer: {record_path}"
                    )
                installation = parse_python_record_installation(
                    record_path,
                    effective,
                    effective_types,
                    identity_contents,
                    metadata_contents,
                )
                historical_record_entry_count += len(installation.entries)
                if historical_record_entry_count > MAX_HISTORICAL_RECORD_ENTRIES:
                    raise EvidenceError("historical Python RECORD entries exceed their limit")
                wheel_installations.append(installation)
                active_python_installations[record_path] = installation

            active_claims = validate_active_python_installations(
                effective, effective_types, active_python_installations
            )
            for replacement_path in sorted(current_layer_ordinary_paths & managed_before_layer):
                current_regular = current_layer_regular.get(replacement_path)
                if (
                    current_regular is not None
                    and effective.get(replacement_path) is current_regular
                ):
                    replacement = active_claims.get(replacement_path)
                    if replacement is None or replacement.record.get("layer") != layer_index:
                        raise EvidenceError(
                            "managed Python file was replaced without a matching RECORD in "
                            f"the same layer: {replacement_path}"
                        )
                else:
                    current_type = effective_types.get(replacement_path)
                    if current_type is not None and current_type.get("layer") == layer_index:
                        raise EvidenceError(
                            "managed Python file was replaced by a non-regular entry: "
                            f"{replacement_path}"
                        )
            historically_managed_paths.update(active_claims)

    effective_bytecode = sorted(
        path
        for path, kind in effective_types.items()
        if kind.get("kind") != "directory"
        and BYTECODE_FILE.search(path)
        and any(path.startswith(root) for root in INTERPRETER_BYTECODE_ROOTS)
    )
    if effective_bytecode:
        raise EvidenceError(
            f"effective interpreter path contains executable bytecode: {effective_bytecode[0]}"
        )

    apk_record = effective.get("lib/apk/db/installed")
    if apk_record is None:
        raise EvidenceError("image has no effective Alpine installed-package database")
    latest_apk = apk_database_contents.get((apk_record["layer"], apk_record["sha256"]))
    if latest_apk is None:
        raise EvidenceError("cannot bind the effective Alpine package database content")
    effective_alpine = parse_apk_database(latest_apk)
    effective_alpine_keys = {(package["name"], package["version"]) for package in effective_alpine}
    alpine_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for _database_identity, database_content in sorted(apk_database_contents.items()):
        for package in parse_apk_database(database_content):
            key = (package["name"], package["version"])
            current = alpine_by_key.get(key)
            if current is not None and current != package:
                raise EvidenceError(
                    "image contains conflicting Alpine metadata for "
                    f"{package['name']} {package['version']}"
                )
            alpine_by_key.setdefault(key, package)
    alpine = [
        {**package, "effective": key in effective_alpine_keys}
        for key, package in sorted(alpine_by_key.items())
    ]
    expected_apk_arch = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}[platform]
    wrong_architectures = sorted(
        {
            package["architecture"]
            for package in alpine
            if package["architecture"] != expected_apk_arch
            and not (package["name"].startswith(".") and package["architecture"] == "noarch")
        }
    )
    if wrong_architectures:
        raise EvidenceError(
            f"Alpine package architecture does not match {platform}: "
            f"{', '.join(wrong_architectures)}"
        )

    python_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    python_occurrences: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for package in metadata_occurrences:
        key = (package["name"], package["version"])
        current = python_by_key.get(key)
        if current is not None and current["metadata_sha256"] != package["metadata_sha256"]:
            raise EvidenceError(
                "image contains conflicting Python metadata for "
                f"{package['name']} {package['version']}"
            )
        python_occurrences.setdefault(key, []).append(package)
        if current is None:
            python_by_key[key] = package
    for key, package in python_by_key.items():
        package["effective"] = any(
            (current := effective.get(occurrence["path"])) is not None
            and current["sha256"] == occurrence["metadata_sha256"]
            for occurrence in python_occurrences[key]
        )
        package.pop("path")
        package.pop("layer")

    components: list[dict[str, Any]] = []
    for package in alpine:
        if package["name"].startswith("."):
            continue
        components.append({"ecosystem": "alpine", **package})
    components.extend(
        {"ecosystem": "python", **package}
        for package in sorted(
            python_by_key.values(), key=lambda item: (item["name"], item["version"])
        )
    )
    if len(components) > MAX_COMPONENTS:
        raise EvidenceError("image contains too many package components")

    for record in occurrences:
        current = effective.get(record["path"])
        record["effective"] = current is record

    for record in directory_occurrences:
        current = effective_types.get(record["path"])
        record["effective"] = (
            current is not None
            and current.get("kind") == "directory"
            and current.get("layer") == record["layer"]
        )

    components.append(
        collect_cpython_runtime_component(
            occurrences,
            non_regular_occurrences,
            effective_types,
            runtime_identity_details,
            platform,
        )
    )
    if len(components) > MAX_COMPONENTS:
        raise EvidenceError("image contains too many package components")

    record_owners = validate_effective_python_installations(
        effective,
        effective_types,
        components,
        identity_contents,
        active_python_installations,
    )

    component_owner_keys = {
        component_key(component)
        for component in components
        if component.get("ecosystem") == "python"
    }
    owner_occurrences: dict[tuple[int, str, str], str] = {}
    for installation in wheel_installations:
        if installation.owner not in component_owner_keys:
            raise EvidenceError(f"cannot bind Python RECORD owner identity: {installation.owner}")
        for owner_path, (_digest, _size, owner_record) in installation.entries.items():
            owner_occurrence = (
                int(owner_record["layer"]),
                owner_path,
                str(owner_record["sha256"]),
            )
            previous_owner = owner_occurrences.get(owner_occurrence)
            if previous_owner is not None and previous_owner != installation.owner:
                raise EvidenceError(
                    f"Python RECORD occurrence has conflicting owners: {owner_path}"
                )
            owner_occurrences[owner_occurrence] = installation.owner

    def observed_payload(record: Mapping[str, Any]) -> dict[str, Any]:
        return {
            field: record[field]
            for field in ("effective", "layer", "path", "sha256", "size", "mode", "uid", "gid")
        }

    def structured_payload(record: Mapping[str, Any], kind: str) -> dict[str, Any]:
        key = (record["layer"], record["path"], record["sha256"])
        detail = payload_details.get(key)
        if detail is None or detail.get("kind") != kind:
            raise EvidenceError(f"cannot bind structured Python payload identity: {record['path']}")
        owner = owner_occurrences.get(key)
        if owner is None:
            raise EvidenceError(
                f"Python {kind} payload occurrence is not owned by a valid wheel RECORD: "
                f"{record['path']}"
            )
        field = "cyclonedx" if kind == "cyclonedx" else "elf"
        return {
            **observed_payload(record),
            "owner": owner,
            field: detail["identity"],
        }

    embedded_sboms = [
        structured_payload(record, "cyclonedx")
        for record in occurrences
        if DIST_INFO_SBOM.search(record["path"])
    ]
    native_payloads = [
        structured_payload(record, "elf")
        for record in occurrences
        if payload_details.get((record["layer"], record["path"], record["sha256"]), {}).get("kind")
        == "elf"
    ]
    wheel_identity_files = sorted(
        (
            observed_payload(record)
            for record in occurrences
            if WHEEL_IDENTITY_FILE.search(record["path"])
        ),
        key=lambda record: (record["layer"], record["path"]),
    )
    apk_database_occurrences = [
        observed_payload(record)
        for record in occurrences
        if record["path"] == "lib/apk/db/installed"
    ]
    python_record_ownership = [
        {
            "owner": record_owners[path],
            **observed_payload(effective[path]),
        }
        for path in sorted(record_owners)
    ]
    historical_installations = [
        {
            "owner": installation.owner,
            "metadata": observed_payload(installation.metadata),
            "wheel": observed_payload(installation.wheel),
            "record": observed_payload(installation.record),
            "root_is_purelib": installation.root_is_purelib,
            "build": installation.build,
            "tags": list(installation.tags),
            "entries": [
                {
                    "path": path,
                    "recorded_sha256": expected_hash,
                    "recorded_size": expected_size,
                    "occurrence": observed_payload(occurrence),
                }
                for path, (expected_hash, expected_size, occurrence) in sorted(
                    installation.entries.items()
                )
            ],
        }
        for installation in sorted(
            wheel_installations,
            key=lambda item: (int(item.record["layer"]), str(item.record["path"])),
        )
    ]

    layers_summary = []
    for layer_index, layer_digest in enumerate(layer_digests):
        layer_items = [item for item in occurrences if item["layer"] == layer_index]
        summary_directories = [
            item for item in directory_occurrences if item["layer"] == layer_index
        ]
        layer_non_regular = [
            item for item in non_regular_occurrences if item["layer"] == layer_index
        ]
        layer_whiteouts = [item for item in whiteout_occurrences if item["layer"] == layer_index]
        layers_summary.append(
            {
                "index": layer_index,
                "digest": layer_digest,
                "regular_file_count": len(layer_items),
                "directory_count": len(summary_directories),
                "non_regular_file_count": len(layer_non_regular),
                "whiteout_count": len(layer_whiteouts),
            }
        )
    inventory = {
        "schema_version": SCHEMA_VERSION,
        "platform": platform,
        "subject_digest": subject_digest,
        "image_config_digest": config_digest,
        "image_revision": labels.get("org.opencontainers.image.revision", ""),
        "image_version": labels.get("org.opencontainers.image.version", ""),
        "application_wheel_sha256": labels.get(APPLICATION_WHEEL_LABEL, ""),
        "application_selection_record_sha256": labels.get(APPLICATION_SELECTION_LABEL, ""),
        "apk_database_sha256": apk_record["sha256"],
        "apk_database_occurrences": apk_database_occurrences,
        "components": sorted(components, key=component_sort_key),
        "embedded_sboms": embedded_sboms,
        "native_payloads": native_payloads,
        "wheel_identity_files": wheel_identity_files,
        "wheel_installations": historical_installations,
        "python_record_ownership": python_record_ownership,
    }
    files = {
        "schema_version": SCHEMA_VERSION,
        "platform": platform,
        "subject_digest": subject_digest,
        "image_config_digest": config_digest,
        "layers": layers_summary,
        "regular_files": occurrences,
        "directories": directory_occurrences,
        "non_regular_files": non_regular_occurrences,
        "whiteouts": whiteout_occurrences,
    }
    return inventory, files


def parse_python_metadata(content: bytes, path: str) -> dict[str, Any]:
    message = email.parser.BytesParser().parsebytes(content)
    if message.defects:
        raise EvidenceError(f"Python metadata has parser defects: {path}")
    for field in ("Metadata-Version", "Name", "Version", "License-Expression", "License"):
        if len(message.get_all(field, [])) > 1:
            raise EvidenceError(f"Python metadata repeats {field}: {path}")
    metadata_version = checked_scalar(
        message.get("Metadata-Version", ""), f"Python metadata version in {path}"
    )
    if metadata_version not in {"1.0", "1.1", "1.2", "2.1", "2.2", "2.3", "2.4", "2.5"}:
        raise EvidenceError(f"Python metadata uses an unsupported Metadata-Version: {path}")
    raw_name = checked_scalar(message.get("Name", ""), f"Python package name in {path}")
    raw_version = checked_scalar(message.get("Version", ""), f"Python package version in {path}")
    try:
        name = str(canonicalize_name(raw_name, validate=True))
    except InvalidName as exc:
        raise EvidenceError(f"Python metadata has an invalid name: {path}") from exc
    try:
        version = str(Version(raw_version))
    except InvalidVersion as exc:
        raise EvidenceError(f"Python metadata has an invalid version: {path}") from exc
    if not name or not version:
        raise EvidenceError(f"Python metadata has no name/version: {path}")
    path_match = DIST_INFO.search(path)
    expected_directory = f"{name.replace('-', '_')}-{version.replace('-', '_')}"
    if path_match is None or path_match.group(1) != expected_directory:
        raise EvidenceError(
            "Python metadata name/version does not match its dist-info directory: "
            f"{path} (expected {expected_directory}.dist-info)"
        )
    license_value = checked_scalar(
        message.get("License-Expression", message.get("License", "")),
        f"Python package license in {path}",
        max_length=MAX_LICENSE_FIELD_LENGTH,
        allow_empty=True,
    )
    return {
        "name": normalize_package_name(name),
        "version": version,
        "observed_license": license_value,
        "metadata_sha256": sha256_bytes(content),
    }


def parse_apk_database(content: bytes) -> list[dict[str, Any]]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("Alpine package database is not UTF-8") from exc
    packages: list[dict[str, Any]] = []
    package_names: set[str] = set()
    authoritative = {"P", "V", "A", "L", "o", "c"}
    for paragraph in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if len(line) >= 2 and line[1] == ":":
                key = line[0]
                if key in authoritative and key in fields:
                    raise EvidenceError(f"Alpine package record repeats field {key}")
                fields.setdefault(key, line[2:])
        if not fields:
            continue
        missing = [key for key in ("P", "V", "A") if not fields.get(key)]
        if missing:
            raise EvidenceError(f"Alpine package record lacks {', '.join(missing)}")
        name = checked_scalar(fields["P"], "Alpine package name")
        version = checked_scalar(fields["V"], f"Alpine package version for {name}")
        architecture = checked_scalar(fields["A"], f"Alpine package architecture for {name}")
        origin = checked_scalar(
            fields.get("o", ""),
            f"Alpine package origin for {name}",
            allow_empty=name.startswith("."),
        )
        observed_license = checked_scalar(
            fields.get("L", ""),
            f"Alpine package license for {name}",
            max_length=MAX_LICENSE_FIELD_LENGTH,
            allow_empty=True,
        )
        if APK_PACKAGE_NAME.fullmatch(name) is None:
            raise EvidenceError(f"Alpine package has an invalid name: {name!r}")
        if APK_VERSION.fullmatch(version) is None:
            raise EvidenceError(f"Alpine package has an invalid version: {name} {version!r}")
        if APK_ARCHITECTURE.fullmatch(architecture) is None:
            raise EvidenceError(
                f"Alpine package has an invalid architecture: {name} {architecture!r}"
            )
        if origin and APK_ORIGIN.fullmatch(origin) is None:
            raise EvidenceError(f"Alpine package has an invalid origin: {name} {origin!r}")
        if name in package_names:
            raise EvidenceError(f"Alpine installed-package database repeats name: {name}")
        package_names.add(name)
        commit = checked_scalar(
            fields.get("c", ""),
            f"Alpine package source commit for {name}",
            max_length=40,
            allow_empty=True,
        )
        package: dict[str, Any] = {
            "name": name,
            "version": version,
            "architecture": architecture,
            "observed_license": observed_license,
            "origin": origin,
            "aports_commit": commit,
        }
        if not package["name"].startswith(".") and (
            not package["origin"] or not re.fullmatch(r"[0-9a-f]{40}", package["aports_commit"])
        ):
            raise EvidenceError(f"Alpine package lacks immutable source provenance: {fields['P']}")
        packages.append(package)
        if len(packages) > MAX_COMPONENTS:
            raise EvidenceError("Alpine installed-package database has too many records")
    return sorted(packages, key=lambda item: (item["name"], item["version"]))


def component_sort_key(component: Mapping[str, Any]) -> tuple[str, str, str]:
    return (str(component["ecosystem"]), str(component["name"]), str(component["version"]))


def component_key(component: Mapping[str, Any]) -> str:
    return f"{component['ecosystem']}:{component['name']}@{component['version']}"


def validate_cpython_runtime_component(
    component: Mapping[str, Any], source: str, *, platform: str | None = None
) -> None:
    """Validate the normalized CPython component and its exact identity occurrences."""

    if set(component) != {
        "ecosystem",
        "name",
        "version",
        "purl",
        "observed_license",
        "effective",
        "identity_files",
    }:
        raise EvidenceError(f"{source} has an invalid CPython runtime component record")
    if (
        component.get("ecosystem") != "runtime"
        or component.get("name") != CPYTHON_RUNTIME_NAME
        or component.get("version") != EXPECTED_RUNTIME_PYTHON
        or component.get("purl") != CPYTHON_RUNTIME_PURL
        or component.get("observed_license") != ""
        or component.get("effective") is not True
    ):
        raise EvidenceError(f"{source} has an invalid CPython runtime identity")
    identities = component.get("identity_files")
    if not isinstance(identities, dict) or set(identities) != set(CPYTHON_IDENTITY_PATHS):
        raise EvidenceError(f"{source} has invalid CPython runtime identity files")
    expected_modes = {
        "version_header": 0o644,
        "interpreter": 0o755,
        "shared_library": 0o755,
    }
    layers: set[int] = set()
    for role, expected_path in CPYTHON_IDENTITY_PATHS.items():
        record = identities.get(role)
        if role == "interpreter_link":
            if not isinstance(record, dict) or set(record) != {
                "effective",
                "kind",
                "layer",
                "path",
                "target",
                "mode",
                "uid",
                "gid",
            }:
                raise EvidenceError(f"{source} has an invalid CPython {role} record")
            layer = record.get("layer")
            path_value = record.get("path")
            target = record.get("target")
            if isinstance(target, str):
                checked_image_link_target(target)
            if (
                not isinstance(layer, int)
                or isinstance(layer, bool)
                or layer < 0
                or not isinstance(path_value, str)
                or str(checked_canonical_path(path_value, f"{source} CPython {role}"))
                != expected_path
                or record.get("effective") is not True
                or record.get("kind") != "symlink"
                or not isinstance(target, str)
                or target != CPYTHON_INTERPRETER_LINK_TARGET
                or record.get("uid") != 0
                or record.get("gid") != 0
                or record.get("mode") != 0o777
            ):
                raise EvidenceError(f"{source} has an invalid CPython {role} identity")
            layers.add(layer)
            continue
        expected_fields = (
            {
                "effective",
                "layer",
                "path",
                "sha256",
                "size",
                "mode",
                "uid",
                "gid",
                "elf",
            }
            if role != "version_header"
            else {
                "effective",
                "layer",
                "path",
                "sha256",
                "size",
                "mode",
                "uid",
                "gid",
            }
        )
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise EvidenceError(f"{source} has an invalid CPython {role} record")
        raw = {field: record[field] for field in record if field != "elf"}
        validated = validate_payload_records([raw], f"{source} CPython {role}")[0]
        if (
            validated["path"] != expected_path
            or validated["effective"] is not True
            or validated["uid"] != 0
            or validated["gid"] != 0
            or validated["mode"] != expected_modes[role]
        ):
            raise EvidenceError(f"{source} has an invalid CPython {role} identity")
        if role != "version_header":
            if platform is None:
                if not any(
                    record.get("elf")
                    == {
                        "bits": 64,
                        "endianness": "little",
                        "machine": machine_name,
                        "machine_id": machine_id,
                    }
                    for machine_id, machine_name in ELF_MACHINES.values()
                ):
                    raise EvidenceError(f"{source} has an invalid CPython {role} ELF identity")
            else:
                validate_retained_elf_identity(
                    record.get("elf"), platform, f"{source} CPython {role}"
                )
        layers.add(int(validated["layer"]))
    if len(layers) != 1:
        raise EvidenceError(f"{source} CPython runtime identity files span multiple layers")


def validate_component_records(value: object, source: str) -> list[dict[str, Any]]:
    """Validate component records before sorting or identity-key access."""

    if not isinstance(value, list) or len(value) > MAX_COMPONENTS:
        raise EvidenceError(f"{source} has an invalid component list")
    result: list[dict[str, Any]] = []
    identities: set[str] = set()
    for component in value:
        if not isinstance(component, dict):
            raise EvidenceError(f"{source} has an invalid component record")
        ecosystem = component.get("ecosystem")
        if ecosystem == "python":
            if set(component) != {
                "ecosystem",
                "name",
                "version",
                "observed_license",
                "effective",
                "metadata_sha256",
            }:
                raise EvidenceError(f"{source} has an invalid Python component record")
            name = component.get("name")
            version = component.get("version")
            digest = component.get("metadata_sha256")
            if not isinstance(name, str) or not isinstance(version, str):
                raise EvidenceError(f"{source} has invalid Python identity fields")
            checked_name = checked_scalar(name, f"{source} Python name")
            checked_version = checked_scalar(version, f"{source} Python version")
            if checked_name != name or checked_version != version:
                raise EvidenceError(f"{source} has non-canonical Python identity fields")
            try:
                canonical_name = str(canonicalize_name(checked_name, validate=True))
                canonical_version = str(Version(checked_version))
            except (InvalidName, InvalidVersion, ValueError) as exc:
                raise EvidenceError(f"{source} has invalid Python identity fields") from exc
            if name != canonical_name or version != canonical_version:
                raise EvidenceError(f"{source} has non-canonical Python identity fields")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise EvidenceError(f"{source} has an invalid Python metadata digest")
        elif ecosystem == "alpine":
            if set(component) != {
                "ecosystem",
                "name",
                "version",
                "architecture",
                "observed_license",
                "origin",
                "aports_commit",
                "effective",
            }:
                raise EvidenceError(f"{source} has an invalid Alpine component record")
            name = component.get("name")
            version = component.get("version")
            architecture = component.get("architecture")
            origin = component.get("origin")
            commit = component.get("aports_commit")
            if (
                not isinstance(name, str)
                or APK_PACKAGE_NAME.fullmatch(name) is None
                or name.startswith(".")
                or not isinstance(version, str)
                or APK_VERSION.fullmatch(version) is None
                or not isinstance(architecture, str)
                or APK_ARCHITECTURE.fullmatch(architecture) is None
                or not isinstance(origin, str)
                or APK_ORIGIN.fullmatch(origin) is None
                or not isinstance(commit, str)
                or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            ):
                raise EvidenceError(f"{source} has invalid Alpine identity fields")
        elif ecosystem == "runtime":
            validate_cpython_runtime_component(component, source)
        else:
            raise EvidenceError(f"{source} has an unsupported component ecosystem")
        observed_license = component.get("observed_license")
        if not isinstance(observed_license, str):
            raise EvidenceError(f"{source} has an invalid observed license")
        checked_scalar(
            observed_license,
            f"{source} observed license",
            max_length=MAX_LICENSE_FIELD_LENGTH,
            allow_empty=True,
        )
        if not isinstance(component.get("effective"), bool):
            raise EvidenceError(f"{source} has an invalid component state")
        identity = component_key(component)
        if identity in identities:
            raise EvidenceError(f"{source} repeats a component identity")
        identities.add(identity)
        result.append(component)
    return result


def validate_platform_component_invariants(
    components: Sequence[Mapping[str, Any]], platform: str, source: str
) -> None:
    """Enforce platform and ownership invariants shared by policy and inventories."""

    expected_apk_architecture = {
        "linux/amd64": "x86_64",
        "linux/arm64": "aarch64",
    }.get(platform)
    if expected_apk_architecture is None:
        raise EvidenceError(f"{source} has an unsupported platform")
    python_hashes: set[str] = set()
    effective_python_names: set[str] = set()
    runtime_count = 0
    for component in components:
        if component["ecosystem"] == "alpine":
            if component["architecture"] != expected_apk_architecture:
                raise EvidenceError(f"{source} has an Alpine architecture mismatch")
            continue
        if component["ecosystem"] == "runtime":
            runtime_count += 1
            validate_cpython_runtime_component(component, source, platform=platform)
            continue
        if component["ecosystem"] != "python":
            raise EvidenceError(f"{source} has an unsupported component ecosystem")
        metadata_hash = str(component["metadata_sha256"])
        if metadata_hash in python_hashes:
            raise EvidenceError(f"{source} reuses a Python metadata digest")
        python_hashes.add(metadata_hash)
        if component["effective"] is True:
            name = str(component["name"])
            if name in effective_python_names:
                raise EvidenceError(f"{source} has multiple effective versions of {name}")
            effective_python_names.add(name)
    if runtime_count != 1:
        raise EvidenceError(f"{source} must contain exactly one CPython runtime component")


def resolved_license(component: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    resolutions = policy.get("license_resolutions")
    if not isinstance(resolutions, dict):
        raise EvidenceError("policy has no reviewed license resolutions")
    resolution = resolutions.get(component_key(component))
    if not isinstance(resolution, dict):
        raise EvidenceError(f"policy has no license resolution for {component_key(component)}")
    expression = resolution.get("expression")
    rationale = resolution.get("rationale")
    if not isinstance(expression, str) or not expression.strip():
        raise EvidenceError(f"license resolution has no expression: {component_key(component)}")
    expression = checked_scalar(
        expression,
        f"license resolution for {component_key(component)}",
        max_length=MAX_LICENSE_FIELD_LENGTH,
    )
    if not isinstance(rationale, str) or not rationale.strip():
        raise EvidenceError(f"license resolution has no rationale: {component_key(component)}")
    return expression


def policy_components(policy: Mapping[str, Any], platform: str) -> list[dict[str, Any]]:
    platforms = policy.get("platforms")
    if not isinstance(platforms, dict) or not isinstance(platforms.get(platform), list):
        raise EvidenceError(f"policy has no reviewed component baseline for {platform}")
    records = validate_component_records(platforms[platform], f"policy platform {platform}")
    return sorted(records, key=component_sort_key)


def validated_custom_license_evidence(
    components: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]
) -> dict[str, set[str]]:
    required: dict[str, set[str]] = {}
    for component in components:
        key = component_key(component)
        for identifier in re.findall(
            r"LicenseRef-[A-Za-z0-9][A-Za-z0-9.+-]*",
            resolved_license(component, policy),
        ):
            required.setdefault(identifier, set()).add(key)
    configured = policy.get("custom_license_evidence")
    if not isinstance(configured, dict) or set(configured) != set(required):
        raise EvidenceError(
            "custom-license evidence does not exactly cover resolved LicenseRef identifiers"
        )
    for identifier, expected_components in required.items():
        requirement = configured.get(identifier)
        if not isinstance(requirement, dict):
            raise EvidenceError(f"invalid custom-license requirement: {identifier}")
        rationale = requirement.get("rationale")
        configured_components = requirement.get("components")
        configured_evidence = requirement.get("evidence")
        if requirement.get("require_source_notice") is not True:
            raise EvidenceError(f"custom-license requirement must require a notice: {identifier}")
        if not isinstance(rationale, str) or not rationale.strip():
            raise EvidenceError(f"custom-license requirement has no rationale: {identifier}")
        if not isinstance(configured_components, list) or not all(
            isinstance(item, str) for item in configured_components
        ):
            raise EvidenceError(f"custom-license components are invalid: {identifier}")
        if len(configured_components) != len(set(configured_components)):
            raise EvidenceError(f"custom-license components contain duplicates: {identifier}")
        if set(configured_components) != expected_components:
            raise EvidenceError(
                f"custom-license components do not exactly match {identifier} resolutions"
            )
        if (
            not isinstance(configured_evidence, dict)
            or set(configured_evidence) != expected_components
        ):
            raise EvidenceError(
                f"custom-license pinned evidence does not exactly match {identifier} resolutions"
            )
        for component_policy_key, evidence in configured_evidence.items():
            if not isinstance(evidence, dict):
                raise EvidenceError(
                    f"custom-license evidence is invalid: {identifier}/{component_policy_key}"
                )
            path = evidence.get("path")
            expected_hash = evidence.get("sha256")
            if not isinstance(path, str):
                raise EvidenceError(
                    f"custom-license evidence path is invalid: {identifier}/{component_policy_key}"
                )
            checked_canonical_path(
                path, f"custom-license evidence path for {identifier}/{component_policy_key}"
            )
            if not isinstance(expected_hash, str) or not re.fullmatch(
                r"[0-9a-f]{64}", expected_hash
            ):
                raise EvidenceError(
                    f"custom-license evidence hash is invalid: {identifier}/{component_policy_key}"
                )
    return required


def verify_pinned_custom_license_records(
    components: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    license_records: Sequence[Mapping[str, Any]],
) -> None:
    required = validated_custom_license_evidence(components, policy)
    custom_policy = policy["custom_license_evidence"]
    inventory_by_key = {component_key(item): item for item in components}
    for identifier, component_keys in required.items():
        for component_policy_key in component_keys:
            inventory_component = inventory_by_key[component_policy_key]
            if inventory_component["ecosystem"] == "alpine":
                evidence_component = f"alpine-{inventory_component['origin']}"
            elif inventory_component["ecosystem"] == "python":
                evidence_component = (
                    f"python-{inventory_component['name']}-{inventory_component['version']}"
                )
            elif inventory_component["ecosystem"] == "runtime":
                evidence_component = component_key(inventory_component)
            else:
                raise EvidenceError("custom-license component ecosystem is unsupported")
            pinned = custom_policy[identifier]["evidence"][component_policy_key]
            if not any(
                record.get("component") == evidence_component
                and record.get("path") == pinned["path"]
                and record.get("sha256") == pinned["sha256"]
                for record in license_records
            ):
                raise EvidenceError(
                    "pinned source-carried notice was not retained for "
                    f"{identifier} component {component_policy_key}"
                )


def validate_unexpanded_payload_policy_schema(
    policy: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Validate both platform baselines for known incomplete wheel surfaces."""

    categories = {"embedded_sboms", "native_payloads", "wheel_identity_files"}
    baselines = policy.get("unexpanded_python_payloads")
    if not isinstance(baselines, dict) or set(baselines) != {
        "linux/amd64",
        "linux/arm64",
    }:
        raise EvidenceError("policy must pin unexpanded Python payloads for both platforms")
    for platform, baseline in baselines.items():
        if not isinstance(baseline, dict) or set(baseline) != categories:
            raise EvidenceError(f"invalid unexpanded Python payload policy for {platform}")
        for category in sorted(categories):
            records = baseline[category]
            if not isinstance(records, list):
                raise EvidenceError(f"invalid {category} policy for {platform}")
            seen: set[tuple[int, str]] = set()
            for record in records:
                if not isinstance(record, dict) or set(record) != {
                    "effective",
                    "layer",
                    "path",
                    "sha256",
                    "size",
                    "mode",
                    "uid",
                    "gid",
                }:
                    raise EvidenceError(f"invalid {category} policy record for {platform}")
                layer = record.get("layer")
                path_value = record.get("path")
                digest = record.get("sha256")
                size = record.get("size")
                if not isinstance(layer, int) or isinstance(layer, bool) or layer < 0:
                    raise EvidenceError(f"invalid {category} layer policy for {platform}")
                if not isinstance(path_value, str):
                    raise EvidenceError(f"invalid {category} path policy for {platform}")
                path = str(
                    checked_canonical_path(path_value, f"{category} policy path for {platform}")
                )
                if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    raise EvidenceError(f"invalid {category} digest policy for {platform}")
                if (
                    not isinstance(size, int)
                    or isinstance(size, bool)
                    or not 0 <= size <= MAX_ARCHIVE_MEMBER_BYTES
                ):
                    raise EvidenceError(f"invalid {category} size policy for {platform}")
                if not isinstance(record.get("effective"), bool):
                    raise EvidenceError(f"invalid {category} state policy for {platform}")
                validate_header_identity(record, f"{category} policy for {platform}")
                occurrence = (layer, path)
                if occurrence in seen:
                    raise EvidenceError(f"duplicate {category} policy record for {platform}")
                seen.add(occurrence)
    return baselines


def verify_unexpanded_payload_policy(
    inventory: Mapping[str, Any], policy: Mapping[str, Any]
) -> None:
    """Bind every wheel surface's raw occurrence to a reviewed platform baseline."""

    categories = {"embedded_sboms", "native_payloads", "wheel_identity_files"}
    baselines = validate_unexpanded_payload_policy_schema(policy)

    platform = inventory.get("platform")
    if not isinstance(platform, str):
        raise EvidenceError("inventory platform is missing")
    if platform not in baselines:
        raise EvidenceError(f"policy has no unexpanded payload baseline for {platform}")
    observed: dict[str, object] = {}
    for category in categories:
        records = inventory.get(category)
        if category in {"embedded_sboms", "native_payloads"}:
            if not isinstance(records, list) or not all(
                isinstance(record, dict) and PAYLOAD_RECORD_FIELDS.issubset(record)
                for record in records
            ):
                raise EvidenceError(f"inventory has invalid structured {category}")
            observed[category] = [
                payload_record_projection(record) for record in records if isinstance(record, dict)
            ]
        else:
            observed[category] = records
    if canonical_json(observed) != canonical_json(baselines[platform]):
        raise EvidenceError(
            "unexpanded native, SBOM, or installed-wheel identity files differ from policy"
        )


def validate_payload_records(value: object, source: str) -> list[dict[str, Any]]:
    """Validate a reviewed list of exact regular-file occurrence identities."""

    if not isinstance(value, list) or len(value) > MAX_IMAGE_MEMBERS:
        raise EvidenceError(f"invalid {source} payload list")
    records: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for record in value:
        if not isinstance(record, dict) or set(record) != {
            "effective",
            "layer",
            "path",
            "sha256",
            "size",
            "mode",
            "uid",
            "gid",
        }:
            raise EvidenceError(f"invalid {source} payload record")
        layer = record.get("layer")
        path_value = record.get("path")
        digest = record.get("sha256")
        size = record.get("size")
        if not isinstance(layer, int) or isinstance(layer, bool) or layer < 0:
            raise EvidenceError(f"invalid {source} payload layer")
        if not isinstance(path_value, str):
            raise EvidenceError(f"invalid {source} payload path")
        path = str(checked_canonical_path(path_value, f"{source} payload path"))
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise EvidenceError(f"invalid {source} payload digest")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_ARCHIVE_MEMBER_BYTES
            or not isinstance(record.get("effective"), bool)
        ):
            raise EvidenceError(f"invalid {source} payload state")
        validate_header_identity(record, source)
        occurrence = (layer, path)
        if occurrence in seen:
            raise EvidenceError(f"duplicate {source} payload occurrence")
        seen.add(occurrence)
        records.append(record)
    return records


PAYLOAD_RECORD_FIELDS = {
    "effective",
    "layer",
    "path",
    "sha256",
    "size",
    "mode",
    "uid",
    "gid",
}


def payload_record_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the raw occurrence fields shared by every structured payload record."""

    return {field: record[field] for field in PAYLOAD_RECORD_FIELDS}


def validate_pinned_artifact(
    value: object,
    source: str,
    *,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> Mapping[str, Any]:
    """Validate one immutable URL, digest, and byte-size tuple."""

    record = require_exact_fields(value, {"url", "sha256", "size"}, source)
    url = record["url"]
    digest = record["sha256"]
    size = record["size"]
    if not isinstance(url, str):
        raise EvidenceError(f"{source} has an invalid URL")
    require_https_source_url(url)
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise EvidenceError(f"{source} has an invalid digest")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= max_bytes:
        raise EvidenceError(f"{source} has an invalid size")
    return record


def native_component_payload_role(path_value: object, platform: str, source: str) -> str:
    """Derive one platform-neutral native role from its exact installed path."""

    if platform not in ELF_MACHINES:
        raise EvidenceError(f"{source} has an unsupported payload platform")
    if not isinstance(path_value, str):
        raise EvidenceError(f"{source} has an invalid payload path")
    path = str(checked_canonical_path(path_value, f"{source} payload path"))
    site_packages_prefix = f"opt/venv/lib/python{CPYTHON_RUNTIME_MINOR}/site-packages/"
    if not path.startswith(site_packages_prefix):
        raise EvidenceError(f"{source} payload is outside the reviewed site-packages root")
    relative = path.removeprefix(site_packages_prefix)
    relative_path = checked_canonical_path(relative, f"{source} payload role projection")
    filename = relative_path.name

    cpython_suffix = re.search(
        r"\.cpython-(?P<abi>[0-9]+)-(?P<architecture>[A-Za-z0-9_]+)-linux-musl\.so$",
        filename,
    )
    if cpython_suffix is not None:
        expected_abi = CPYTHON_RUNTIME_MINOR.replace(".", "")
        expected_architecture = ELF_MACHINES[platform][1]
        if (
            cpython_suffix["abi"] != expected_abi
            or cpython_suffix["architecture"] != expected_architecture
        ):
            raise EvidenceError(f"{source} payload ABI suffix conflicts with {platform}")
        filename = f"{filename[: cpython_suffix.start()]}.cpython-{expected_abi}.so"
    elif relative_path.parts[0].endswith(".libs"):
        auditwheel_suffix = re.fullmatch(
            r"(?P<stem>.+)-(?P<hash>[^/]+)(?P<suffix>\.so(?:\.[0-9]+)*)",
            filename,
        )
        if auditwheel_suffix is not None and re.fullmatch(
            r"[0-9A-Fa-f]+", auditwheel_suffix["hash"]
        ):
            if re.fullmatch(r"[0-9a-f]{8}", auditwheel_suffix["hash"]) is None:
                raise EvidenceError(f"{source} payload has an invalid auditwheel hash")
            filename = f"{auditwheel_suffix['stem']}{auditwheel_suffix['suffix']}"

    role = str(relative_path.with_name(filename))
    return str(checked_canonical_path(role, f"{source} payload role projection"))


def validate_native_component_payloads(
    value: object, platform: str, source: str
) -> list[Mapping[str, Any]]:
    """Validate canonical logical-role/path/digest native payload references."""

    if not isinstance(value, list) or len(value) > MAX_IMAGE_MEMBERS:
        raise EvidenceError(f"{source} has an invalid payload list")
    records: list[Mapping[str, Any]] = []
    seen_paths: set[str] = set()
    seen_roles: set[str] = set()
    for index, value_record in enumerate(value):
        record = require_exact_fields(
            value_record,
            {"role", "path", "sha256", "size"},
            f"{source} payload {index}",
        )
        role_value = record["role"]
        path_value = record["path"]
        digest = record["sha256"]
        size = record["size"]
        if not isinstance(role_value, str):
            raise EvidenceError(f"{source} has an invalid payload role")
        role = str(checked_canonical_path(role_value, f"{source} payload role"))
        if role != role_value:
            raise EvidenceError(f"{source} has an invalid payload role")
        if not isinstance(path_value, str):
            raise EvidenceError(f"{source} has an invalid payload path")
        path = str(checked_canonical_path(path_value, f"{source} payload path"))
        expected_role = native_component_payload_role(path_value, platform, source)
        if role != expected_role:
            raise EvidenceError(f"{source} payload role does not match its path")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise EvidenceError(f"{source} has an invalid payload digest")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= MAX_ARCHIVE_MEMBER_BYTES
        ):
            raise EvidenceError(f"{source} has an invalid payload size")
        if path in seen_paths:
            raise EvidenceError(f"{source} repeats payload path {path}")
        if role in seen_roles:
            raise EvidenceError(f"{source} has an invalid payload role")
        seen_roles.add(role)
        seen_paths.add(path)
        records.append(record)
    if [record["role"] for record in records] != sorted(seen_roles):
        raise EvidenceError(f"{source} payloads are not canonical")
    return records


def validate_native_source_notices(value: object, source_id: str) -> list[Mapping[str, Any]]:
    """Validate a canonical, bounded notice inventory shared by every source kind."""

    if not isinstance(value, list) or not value or len(value) > MAX_SOURCE_LICENSE_FILES:
        raise EvidenceError(f"native-component source {source_id} has invalid notices")
    notices: list[Mapping[str, Any]] = []
    members: set[str] = set()
    total_size = 0
    for index, raw_notice in enumerate(value):
        notice = require_exact_fields(
            raw_notice,
            {"member", "sha256", "size"},
            f"native-component source {source_id} notice {index}",
        )
        member = notice["member"]
        digest = notice["sha256"]
        size = notice["size"]
        if (
            not isinstance(member, str)
            or str(checked_canonical_path(member, "native-component notice member")) != member
            or member in members
        ):
            raise EvidenceError(f"native-component source {source_id} has an invalid notice member")
        members.add(member)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise EvidenceError(f"native-component source {source_id} has an invalid notice digest")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_LICENSE_BYTES:
            raise EvidenceError(f"native-component source {source_id} has an invalid notice size")
        total_size += size
        if total_size > MAX_SOURCE_LICENSE_TOTAL_BYTES:
            raise EvidenceError(
                f"native-component source {source_id} notice bytes exceed the limit"
            )
        notices.append(notice)
    if [record["member"] for record in notices] != sorted(members):
        raise EvidenceError(f"native-component source {source_id} notices are not canonical")
    return notices


def validate_native_source_reviewed_license(value: object, source_id: str) -> str:
    """Validate one exact reviewed expression carried by a component source."""

    if (
        not isinstance(value, str)
        or checked_scalar(
            value,
            f"native-component source {source_id} reviewed license",
            max_length=MAX_LICENSE_FIELD_LENGTH,
        )
        != value
        or "LicenseRef-" in value
    ):
        raise EvidenceError(f"native-component source {source_id} has an invalid reviewed license")
    return value


def validate_native_source_manifest(
    value: object,
    source: str,
) -> Mapping[str, Any]:
    """Validate one digest-pinned Cargo manifest retained from a source archive."""

    record = require_exact_fields(value, {"member", "sha256", "size"}, source)
    member = record["member"]
    digest = record["sha256"]
    size = record["size"]
    if (
        not isinstance(member, str)
        or str(checked_canonical_path(member, f"{source} member")) != member
        or PurePosixPath(member).name != "Cargo.toml"
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 < size <= MAX_CARGO_LOCK_BYTES
    ):
        raise EvidenceError(f"{source} is invalid")
    return record


def validate_alpine_component_source(source_id: str, raw_record: object) -> Mapping[str, Any]:
    record = require_exact_fields(
        raw_record,
        {
            "kind",
            "origin",
            "version",
            "aports_commit",
            "distfiles_release",
            "recipe",
            "distfiles",
            "allowed_recipe_links",
            "observed_license",
            "notices",
        },
        f"native-component source {source_id}",
    )
    origin = record["origin"]
    version = record["version"]
    commit = record["aports_commit"]
    release = record["distfiles_release"]
    if (
        not isinstance(origin, str)
        or checked_scalar(origin, f"native-component source {source_id} origin") != origin
        or re.fullmatch(r"[a-z0-9][a-z0-9+._-]*", origin) is None
    ):
        raise EvidenceError(f"native-component source {source_id} has an invalid origin")
    if (
        not isinstance(version, str)
        or checked_scalar(version, f"native-component source {source_id} version") != version
    ):
        raise EvidenceError(f"native-component source {source_id} has an invalid version")
    if source_id != f"alpine:{origin}@{version}":
        raise EvidenceError(f"native-component source {source_id} has a conflicting identity")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise EvidenceError(f"native-component source {source_id} has an invalid commit")
    if not isinstance(release, str) or re.fullmatch(r"v\d+\.\d+", release) is None:
        raise EvidenceError(f"native-component source {source_id} has an invalid release")
    recipe = validate_pinned_artifact(
        record["recipe"], f"native-component source {source_id} recipe"
    )
    expected_recipe_url = (
        "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
        f"{commit}/aports-{commit}.tar.gz?path=main/{origin}"
    )
    if recipe["url"] != expected_recipe_url:
        raise EvidenceError(f"native-component source {source_id} recipe is not commit-pinned")

    distfiles = record["distfiles"]
    if not isinstance(distfiles, list) or not 1 <= len(distfiles) <= MAX_ALPINE_DISTFILES:
        raise EvidenceError(f"native-component source {source_id} has invalid distfiles")
    distfile_names: set[str] = set()
    for index, raw_distfile in enumerate(distfiles):
        distfile = require_exact_fields(
            raw_distfile,
            {"filename", "url", "sha512", "size"},
            f"native-component source {source_id} distfile {index}",
        )
        filename = distfile["filename"]
        url = distfile["url"]
        digest = distfile["sha512"]
        size = distfile["size"]
        if (
            not isinstance(filename, str)
            or str(checked_canonical_path(filename, "native-component distfile filename"))
            != filename
            or PurePosixPath(filename).name != filename
            or filename in distfile_names
        ):
            raise EvidenceError(
                f"native-component source {source_id} has an invalid distfile filename"
            )
        distfile_names.add(filename)
        expected_url = (
            f"https://distfiles.alpinelinux.org/distfiles/{release}/"
            f"{urllib.parse.quote(filename, safe='')}"
        )
        if not isinstance(url, str) or url != expected_url:
            raise EvidenceError(
                f"native-component source {source_id} has a noncanonical distfile URL"
            )
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{128}", digest) is None:
            raise EvidenceError(
                f"native-component source {source_id} has an invalid distfile digest"
            )
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= MAX_NATIVE_COMPONENT_SOURCE_BYTES
        ):
            raise EvidenceError(f"native-component source {source_id} has an invalid distfile size")
    if [record["filename"] for record in distfiles] != sorted(distfile_names):
        raise EvidenceError(f"native-component source {source_id} distfiles are not canonical")

    links = record["allowed_recipe_links"]
    if not isinstance(links, list) or len(links) > MAX_ALPINE_RECIPE_LINKS:
        raise EvidenceError(f"native-component source {source_id} has invalid recipe links")
    seen_links: set[str] = set()
    for index, raw_link in enumerate(links):
        link = require_exact_fields(
            raw_link,
            {"path", "type", "target"},
            f"native-component source {source_id} recipe link {index}",
        )
        path_value = link["path"]
        target_value = link["target"]
        if (
            link["type"] != "symlink"
            or not isinstance(path_value, str)
            or str(checked_canonical_path(path_value, "native-component recipe link path"))
            != path_value
            or path_value in seen_links
            or not isinstance(target_value, str)
            or str(checked_canonical_path(target_value, "native-component recipe link target"))
            != target_value
        ):
            raise EvidenceError(f"native-component source {source_id} has an invalid recipe link")
        path = PurePosixPath(path_value)
        target = PurePosixPath(target_value)
        if path == target or path.parent != target.parent:
            raise EvidenceError(
                f"native-component source {source_id} recipe link must target a sibling"
            )
        seen_links.add(path_value)
    if [record["path"] for record in links] != sorted(seen_links):
        raise EvidenceError(f"native-component source {source_id} recipe links are not canonical")

    observed_license = record["observed_license"]
    if not isinstance(observed_license, str) or not observed_license.strip():
        raise EvidenceError(f"native-component source {source_id} has no observed recipe license")
    checked_scalar(
        observed_license,
        f"native-component source {source_id} observed license",
        max_length=MAX_LICENSE_FIELD_LENGTH,
    )
    validate_native_source_notices(record["notices"], source_id)
    return record


def validate_crates_io_component_source(source_id: str, raw_record: object) -> Mapping[str, Any]:
    record = require_exact_fields(
        raw_record,
        {
            "kind",
            "name",
            "version",
            "crate",
            "manifest",
            "raw_license",
            "normalized_license",
            "notices",
        },
        f"native-component source {source_id}",
    )
    name = record["name"]
    version = record["version"]
    if (
        not isinstance(name, str)
        or checked_scalar(name, f"native-component source {source_id} name") != name
        or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", name) is None
        or not isinstance(version, str)
        or checked_scalar(version, f"native-component source {source_id} version") != version
        or source_id != f"crates-io:{name}@{version}"
    ):
        raise EvidenceError(f"native-component source {source_id} has a conflicting identity")
    crate = validate_pinned_artifact(
        record["crate"],
        f"native-component source {source_id} crate",
        max_bytes=MAX_NATIVE_COMPONENT_SOURCE_BYTES,
    )
    quoted_name = urllib.parse.quote(name, safe="-._~")
    quoted_version = urllib.parse.quote(version, safe="-._~+")
    expected_url = (
        f"https://static.crates.io/crates/{quoted_name}/{quoted_name}-{quoted_version}.crate"
    )
    if crate["url"] != expected_url:
        raise EvidenceError(f"native-component source {source_id} has a noncanonical crate URL")
    manifest = require_exact_fields(
        record["manifest"],
        {"member", "sha256", "size"},
        f"native-component source {source_id} manifest",
    )
    expected_member = f"{name}-{version}/Cargo.toml"
    if manifest["member"] != expected_member:
        raise EvidenceError(f"native-component source {source_id} has an invalid manifest member")
    if (
        not isinstance(manifest["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"]) is None
    ):
        raise EvidenceError(f"native-component source {source_id} has an invalid manifest digest")
    if (
        not isinstance(manifest["size"], int)
        or isinstance(manifest["size"], bool)
        or not 0 < manifest["size"] <= MAX_ARCHIVE_MEMBER_BYTES
    ):
        raise EvidenceError(f"native-component source {source_id} has an invalid manifest size")
    for field in ("raw_license", "normalized_license"):
        value = record[field]
        if (
            not isinstance(value, str)
            or checked_scalar(
                value,
                f"native-component source {source_id} {field}",
                max_length=MAX_LICENSE_FIELD_LENGTH,
            )
            != value
        ):
            raise EvidenceError(f"native-component source {source_id} has an invalid {field}")
    expected_normalized_license = (
        "MIT OR Apache-2.0" if record["raw_license"] == "MIT/Apache-2.0" else record["raw_license"]
    )
    if record["normalized_license"] != expected_normalized_license:
        raise EvidenceError(f"native-component source {source_id} license normalization differs")
    notices = validate_native_source_notices(record["notices"], source_id)
    if any(notice["member"] == expected_member for notice in notices):
        raise EvidenceError(f"native-component source {source_id} repeats its manifest as a notice")
    return record


def validate_owner_subpath_component_source(
    source_id: str, raw_record: object
) -> Mapping[str, Any]:
    record = require_exact_fields(
        raw_record,
        {
            "kind",
            "owner",
            "path",
            "tree_sha256",
            "member_count",
            "expanded_size",
            "reviewed_license",
            "workspace_manifest",
            "cargo_packages",
            "notices",
        },
        f"native-component source {source_id}",
    )
    owner = record["owner"]
    path_value = record["path"]
    if (
        not isinstance(owner, str)
        or not owner.startswith("python:")
        or "@" not in owner
        or not isinstance(path_value, str)
        or str(checked_canonical_path(path_value, "owner-sdist source path")) != path_value
        or source_id != f"owner-sdist:{owner}#{path_value}"
    ):
        raise EvidenceError(f"native-component source {source_id} has a conflicting identity")
    digest = record["tree_sha256"]
    count = record["member_count"]
    expanded = record["expanded_size"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise EvidenceError(f"native-component source {source_id} has an invalid tree digest")
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or not 0 < count <= MAX_OWNER_SUBTREE_MEMBERS
        or not isinstance(expanded, int)
        or isinstance(expanded, bool)
        or not 0 < expanded <= MAX_OWNER_SUBTREE_BYTES
    ):
        raise EvidenceError(f"native-component source {source_id} has invalid subtree bounds")
    validate_native_source_reviewed_license(record["reviewed_license"], source_id)
    workspace_manifest = validate_native_source_manifest(
        record["workspace_manifest"],
        f"native-component source {source_id} workspace manifest",
    )
    workspace_member = PurePosixPath(str(workspace_manifest["member"]))
    if len(workspace_member.parts) < 2:
        raise EvidenceError(
            f"native-component source {source_id} has an invalid workspace manifest member"
        )
    archive_root = PurePosixPath(workspace_member.parts[0])
    raw_packages = record["cargo_packages"]
    if (
        not isinstance(raw_packages, list)
        or not raw_packages
        or len(raw_packages) > MAX_OBSERVATIONS_PER_OWNER
    ):
        raise EvidenceError(f"native-component source {source_id} has invalid Cargo packages")
    package_paths: set[str] = set()
    package_names: set[str] = set()
    packages: list[Mapping[str, Any]] = []
    for index, raw_package in enumerate(raw_packages):
        package = require_exact_fields(
            raw_package,
            {"path", "name", "version", "manifest"},
            f"native-component source {source_id} Cargo package {index}",
        )
        package_path = package["path"]
        name = package["name"]
        version = package["version"]
        if (
            not isinstance(package_path, str)
            or (
                package_path != "."
                and str(
                    checked_canonical_path(
                        package_path,
                        f"native-component source {source_id} Cargo package path",
                    )
                )
                != package_path
            )
            or package_path in package_paths
            or not isinstance(name, str)
            or checked_scalar(
                name,
                f"native-component source {source_id} Cargo package name",
            )
            != name
            or CARGO_PACKAGE_NAME.fullmatch(name) is None
            or name in package_names
            or not isinstance(version, str)
            or checked_scalar(
                version,
                f"native-component source {source_id} Cargo package version",
            )
            != version
        ):
            raise EvidenceError(f"native-component source {source_id} has an invalid Cargo package")
        manifest = validate_native_source_manifest(
            package["manifest"],
            f"native-component source {source_id} Cargo package {package_path}",
        )
        relative_manifest = (
            PurePosixPath(path_value) / "Cargo.toml"
            if package_path == "."
            else PurePosixPath(path_value) / package_path / "Cargo.toml"
        )
        expected_member = archive_root / relative_manifest
        if manifest["member"] != str(expected_member) or (
            manifest["member"] == workspace_manifest["member"] and manifest != workspace_manifest
        ):
            raise EvidenceError(
                f"native-component source {source_id} Cargo package manifest differs"
            )
        package_paths.add(package_path)
        package_names.add(name)
        packages.append(package)
    if [str(package["path"]) for package in packages] != sorted(package_paths):
        raise EvidenceError(f"native-component source {source_id} Cargo packages are not canonical")
    validate_native_source_notices(record["notices"], source_id)
    return record


def validate_upstream_release_component_source(
    source_id: str, raw_record: object
) -> Mapping[str, Any]:
    record = require_exact_fields(
        raw_record,
        {
            "kind",
            "name",
            "version",
            "archive",
            "checksum_document",
            "checksum_filename",
            "reviewed_license",
            "notices",
        },
        f"native-component source {source_id}",
    )
    name = record["name"]
    version = record["version"]
    if (
        not isinstance(name, str)
        or checked_scalar(name, f"native-component source {source_id} name") != name
        or not isinstance(version, str)
        or checked_scalar(version, f"native-component source {source_id} version") != version
        or source_id != f"upstream-release:{name}@{version}"
    ):
        raise EvidenceError(f"native-component source {source_id} has a conflicting identity")
    archive = validate_pinned_artifact(
        record["archive"],
        f"native-component source {source_id} archive",
        max_bytes=MAX_NATIVE_COMPONENT_SOURCE_BYTES,
    )
    validate_pinned_artifact(
        record["checksum_document"],
        f"native-component source {source_id} checksum document",
        max_bytes=MAX_DOWNLOAD_BYTES,
    )
    filename = record["checksum_filename"]
    if (
        not isinstance(filename, str)
        or PurePosixPath(filename).name != filename
        or str(checked_canonical_path(filename, "upstream checksum filename")) != filename
        or safe_filename(str(archive["url"])) != filename
    ):
        raise EvidenceError(f"native-component source {source_id} has an invalid checksum filename")
    validate_native_source_reviewed_license(record["reviewed_license"], source_id)
    validate_native_source_notices(record["notices"], source_id)
    return record


def native_component_sources(policy: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    """Validate the schema-v7 tagged union of immutable component sources."""

    value = policy.get("native_component_sources")
    if not isinstance(value, dict) or len(value) > MAX_NATIVE_COMPONENT_SOURCES:
        raise EvidenceError("policy has invalid native-component sources")
    validators = {
        "alpine-aports": validate_alpine_component_source,
        "crates-io": validate_crates_io_component_source,
        "owner-sdist-subpath": validate_owner_subpath_component_source,
        "checksummed-upstream-release": validate_upstream_release_component_source,
    }
    sources: dict[str, Mapping[str, Any]] = {}
    for source_id, raw_record in value.items():
        if not isinstance(source_id, str):
            raise EvidenceError("native-component source has an invalid identity")
        checked_scalar(
            source_id,
            "native-component source identity",
            max_length=MAX_COMPONENT_KEY_LENGTH,
        )
        if not isinstance(raw_record, dict):
            raise EvidenceError(f"native-component source {source_id} is not an object")
        kind = raw_record.get("kind")
        validator = validators.get(kind) if isinstance(kind, str) else None
        if validator is None:
            raise EvidenceError(f"native-component source {source_id} has an unsupported kind")
        sources[source_id] = validator(source_id, raw_record)
    return sources


def cargo_package_identity(value: object, source: str) -> tuple[str, str, str, str]:
    """Validate one exact crates.io ``Cargo.lock`` package identity."""

    record = require_exact_fields(
        value,
        {"name", "version", "source", "checksum"},
        source,
    )
    name = record["name"]
    version = record["version"]
    registry = record["source"]
    checksum = record["checksum"]
    if (
        not isinstance(name, str)
        or checked_scalar(name, f"{source} name") != name
        or CARGO_PACKAGE_NAME.fullmatch(name) is None
        or not isinstance(version, str)
        or checked_scalar(version, f"{source} version") != version
        or registry != CARGO_CRATES_IO_SOURCE
        or not isinstance(checksum, str)
        or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
    ):
        raise EvidenceError(f"{source} has an invalid package identity")
    return name, version, registry, checksum


def validate_cargo_lock_context(
    value: object,
    *,
    owner: str,
    sources: Mapping[str, Mapping[str, Any]],
    crate_source_ids: set[str],
) -> Mapping[str, Any] | None:
    """Validate the exact lockfile context required by crates.io reviews."""

    if value is None:
        if crate_source_ids:
            raise EvidenceError(
                f"native-component coverage {owner} crate reviews require Cargo.lock context"
            )
        return None
    if not crate_source_ids:
        raise EvidenceError(
            f"native-component coverage {owner} has Cargo.lock context without crate reviews"
        )
    record = require_exact_fields(
        value,
        {"member", "sha256", "size", "source_ids", "non_sbom_packages"},
        f"native-component coverage {owner} Cargo.lock",
    )
    member = record["member"]
    digest = record["sha256"]
    size = record["size"]
    if (
        not isinstance(member, str)
        or str(
            checked_canonical_path(
                member,
                f"native-component coverage {owner} Cargo.lock member",
            )
        )
        != member
        or PurePosixPath(member).name != "Cargo.lock"
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 < size <= MAX_CARGO_LOCK_BYTES
    ):
        raise EvidenceError(f"native-component coverage {owner} has invalid Cargo.lock identity")

    raw_source_ids = record["source_ids"]
    if (
        not isinstance(raw_source_ids, list)
        or len(raw_source_ids) > MAX_CARGO_LOCK_PACKAGES
        or not all(isinstance(source_id, str) for source_id in raw_source_ids)
        or raw_source_ids != sorted(set(raw_source_ids))
        or set(raw_source_ids) != crate_source_ids
    ):
        raise EvidenceError(
            f"native-component coverage {owner} Cargo.lock source IDs differ from crate reviews"
        )
    for source_id in raw_source_ids:
        source_record = sources.get(source_id)
        if source_record is None or source_record["kind"] != "crates-io":
            raise EvidenceError(
                f"native-component coverage {owner} Cargo.lock has a non-crate source ID"
            )

    raw_non_sbom = record["non_sbom_packages"]
    if not isinstance(raw_non_sbom, list) or len(raw_non_sbom) > MAX_CARGO_LOCK_PACKAGES:
        raise EvidenceError(
            f"native-component coverage {owner} Cargo.lock has invalid non-SBOM packages"
        )
    non_sbom = [
        cargo_package_identity(
            package,
            f"native-component coverage {owner} Cargo.lock non-SBOM package {index}",
        )
        for index, package in enumerate(raw_non_sbom)
    ]
    if non_sbom != sorted(set(non_sbom)):
        raise EvidenceError(
            f"native-component coverage {owner} Cargo.lock non-SBOM packages are not canonical"
        )
    reviewed_identities = {
        (str(sources[source_id]["name"]), str(sources[source_id]["version"]))
        for source_id in raw_source_ids
    }
    if reviewed_identities & {(name, version) for name, version, _source, _checksum in non_sbom}:
        raise EvidenceError(
            f"native-component coverage {owner} Cargo.lock repeats a reviewed crate as non-SBOM"
        )
    return record


def cargo_purl_identity(value: object, source: str) -> tuple[str, str] | None:
    """Return one Cargo name/version identity, or ``None`` for another ecosystem."""

    if not isinstance(value, str) or not value.startswith("pkg:cargo/"):
        return None
    package = value.removeprefix("pkg:cargo/").split("?", maxsplit=1)[0].split("#", maxsplit=1)[0]
    if "/" in package or "@" not in package:
        raise EvidenceError(f"{source} has an invalid Cargo purl")
    raw_name, raw_version = package.rsplit("@", maxsplit=1)
    try:
        name = urllib.parse.unquote(raw_name, errors="strict")
        version = urllib.parse.unquote(raw_version, errors="strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{source} has an invalid Cargo purl") from exc
    if (
        CARGO_PACKAGE_NAME.fullmatch(name) is None
        or not version
        or checked_scalar(version, f"{source} Cargo version") != version
    ):
        raise EvidenceError(f"{source} has an invalid Cargo purl")
    return name, version


def cyclonedx_reviewed_license(value: object, source: str) -> str:
    """Return one exact supported CycloneDX license observation."""

    if not isinstance(value, list) or len(value) != 1:
        raise EvidenceError(f"{source} must have exactly one license observation")
    record = value[0]
    if not isinstance(record, dict):
        raise EvidenceError(f"{source} has an unsupported license observation")
    if set(record) == {"expression"}:
        expression = record["expression"]
    elif set(record) == {"license"}:
        license_record = record["license"]
        if not isinstance(license_record, dict) or set(license_record) != {"id"}:
            raise EvidenceError(f"{source} has an unsupported license observation")
        expression = license_record["id"]
    else:
        raise EvidenceError(f"{source} has an unsupported license observation")
    if (
        not isinstance(expression, str)
        or checked_scalar(
            expression,
            source,
            max_length=MAX_LICENSE_FIELD_LENGTH,
        )
        != expression
    ):
        raise EvidenceError(f"{source} has an invalid license observation")
    return expression


def verify_owner_cargo_lock(
    owner_context: Mapping[str, Any],
    sources: Mapping[str, Mapping[str, Any]],
    owner_archive: bytes,
    *,
    archive_name: str,
) -> bytes | None:
    """Verify exact lockfile membership and crate checksums in one retained owner sdist."""

    owner = str(owner_context["owner"])
    lock_context = owner_context["record"]["cargo_lock"]
    if lock_context is None:
        return None
    member = str(lock_context["member"])
    found = reviewed_files_from_source_archive(
        owner_archive,
        archive_name=archive_name,
        source_id=f"{owner} Cargo.lock",
        expected={
            member: {
                "sha256": lock_context["sha256"],
                "size": lock_context["size"],
            }
        },
        max_member_bytes=MAX_CARGO_LOCK_BYTES,
    )
    if set(found) != {member}:
        raise EvidenceError(f"retained owner sdist omits exact Cargo.lock member for {owner}")
    content = found[member]
    try:
        document = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError(f"retained owner Cargo.lock is invalid for {owner}") from exc
    if not isinstance(document, dict) or set(document) != {"version", "package"}:
        raise EvidenceError(f"retained owner Cargo.lock has an unexpected shape for {owner}")
    lock_version = document["version"]
    raw_packages = document["package"]
    if (
        not isinstance(lock_version, int)
        or isinstance(lock_version, bool)
        or lock_version not in {3, 4}
        or not isinstance(raw_packages, list)
        or not 1 <= len(raw_packages) <= MAX_CARGO_LOCK_PACKAGES
    ):
        raise EvidenceError(f"retained owner Cargo.lock has invalid bounds for {owner}")

    registry_packages: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    local_packages: set[tuple[str, str]] = set()
    for index, raw_package in enumerate(raw_packages):
        if not isinstance(raw_package, dict) or not {"name", "version"} <= set(raw_package):
            raise EvidenceError(f"retained owner Cargo.lock has an invalid package for {owner}")
        if set(raw_package) - {"name", "version", "source", "checksum", "dependencies"}:
            raise EvidenceError(
                f"retained owner Cargo.lock package has unexpected fields for {owner}"
            )
        dependencies = raw_package.get("dependencies", [])
        if (
            not isinstance(dependencies, list)
            or len(dependencies) > MAX_CARGO_LOCK_PACKAGES
            or not all(
                isinstance(dependency, str)
                and checked_scalar(
                    dependency,
                    f"retained owner Cargo.lock dependency {index}",
                )
                == dependency
                for dependency in dependencies
            )
        ):
            raise EvidenceError(
                f"retained owner Cargo.lock package has invalid dependencies for {owner}"
            )
        name = raw_package["name"]
        version = raw_package["version"]
        if (
            not isinstance(name, str)
            or checked_scalar(name, f"retained owner Cargo.lock package {index} name") != name
            or CARGO_PACKAGE_NAME.fullmatch(name) is None
            or not isinstance(version, str)
            or checked_scalar(version, f"retained owner Cargo.lock package {index} version")
            != version
        ):
            raise EvidenceError(f"retained owner Cargo.lock has an invalid package for {owner}")
        identity = (name, version)
        registry = raw_package.get("source")
        checksum = raw_package.get("checksum")
        if registry is None:
            if checksum is not None or identity in local_packages or identity in registry_packages:
                raise EvidenceError(
                    f"retained owner Cargo.lock repeats or corrupts a local package for {owner}"
                )
            local_packages.add(identity)
            continue
        if registry != CARGO_CRATES_IO_SOURCE:
            raise EvidenceError(f"retained owner Cargo.lock uses a foreign registry for {owner}")
        canonical = cargo_package_identity(
            {
                "name": name,
                "version": version,
                "source": registry,
                "checksum": checksum,
            },
            f"retained owner Cargo.lock package {index}",
        )
        if identity in registry_packages or identity in local_packages:
            raise EvidenceError(f"retained owner Cargo.lock repeats a package for {owner}")
        registry_packages[identity] = canonical

    expected_registry: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    for source_id in lock_context["source_ids"]:
        source_record = sources[source_id]
        identity = (str(source_record["name"]), str(source_record["version"]))
        expected_registry[identity] = (
            identity[0],
            identity[1],
            CARGO_CRATES_IO_SOURCE,
            str(source_record["crate"]["sha256"]),
        )
    for package in lock_context["non_sbom_packages"]:
        canonical = cargo_package_identity(package, f"{owner} Cargo.lock non-SBOM package")
        identity = (canonical[0], canonical[1])
        if identity in expected_registry:
            raise EvidenceError(f"{owner} Cargo.lock repeats a reviewed package")
        expected_registry[identity] = canonical
    if registry_packages != expected_registry:
        raise EvidenceError(
            f"retained owner Cargo.lock registry packages differ from reviewed context for {owner}"
        )

    expected_local: set[tuple[str, str]] = set()
    for reference in owner_context["owner_root_observations"]:
        observation = owner_context["observations"][reference]
        cargo_identity = cargo_purl_identity(
            observation["purl"],
            f"{owner} Cargo owner root",
        )
        if cargo_identity is not None:
            expected_local.add(cargo_identity)
    for review in owner_context["record"]["component_reviews"]:
        source_record = sources[str(review["source"])]
        if source_record["kind"] != "owner-sdist-subpath":
            continue
        for raw_reference in review["observations"]:
            reference = validate_observation_reference(
                raw_reference,
                f"{owner} local Cargo observation",
            )
            observation = owner_context["observations"][reference]
            cargo_identity = cargo_purl_identity(
                observation["purl"],
                f"{owner} local Cargo observation",
            )
            if cargo_identity is not None:
                expected_local.add(cargo_identity)
    if local_packages != expected_local:
        raise EvidenceError(
            "retained owner Cargo.lock local packages differ from reviewed "
            f"observations for {owner}"
        )
    return content


def verify_upstream_checksum_document(
    content: bytes,
    *,
    filename: str,
    expected_sha256: str,
) -> None:
    """Require one unambiguous GNU-style SHA-256 record for an exact filename."""

    if len(content) > MAX_DOWNLOAD_BYTES:
        raise EvidenceError("upstream checksum document exceeds the size limit")
    if (
        PurePosixPath(filename).name != filename
        or str(checked_canonical_path(filename, "upstream checksum filename")) != filename
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise EvidenceError("upstream checksum verification has an invalid expectation")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("upstream checksum document is not UTF-8") from exc
    records: list[tuple[str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line_number > MAX_RECORD_ENTRIES:
            raise EvidenceError("upstream checksum document has too many records")
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](\S(?:.*\S)?)", line)
        if match is None:
            raise EvidenceError(
                f"upstream checksum document has a malformed record at line {line_number}"
            )
        digest, raw_filename = match.groups()
        if (
            PurePosixPath(raw_filename).name != raw_filename
            or str(checked_canonical_path(raw_filename, "upstream checksum record filename"))
            != raw_filename
        ):
            raise EvidenceError(
                f"upstream checksum document has an unsafe filename at line {line_number}"
            )
        if raw_filename == filename:
            records.append((digest, raw_filename))
    if len(records) != 1:
        raise EvidenceError("upstream checksum document must contain exactly one matching filename")
    if records[0][0] != expected_sha256:
        raise EvidenceError("upstream checksum document digest differs from reviewed archive")


def verify_crates_io_archive(
    archive: bytes,
    *,
    source_id: str,
    source: Mapping[str, Any],
) -> dict[str, bytes]:
    """Validate one official ``.crate`` archive and return exact reviewed files."""

    name = str(source["name"])
    version = str(source["version"])
    expected_root = f"{name}-{version}"
    expected_files = {
        str(source["manifest"]["member"]): source["manifest"],
        **{str(record["member"]): record for record in source["notices"]},
    }
    expected_notice_members = {str(record["member"]) for record in source["notices"]}
    observed_notice_members: set[str] = set()
    found: dict[str, bytes] = {}
    seen_paths: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*", tarinfo=BoundedTarInfo) as crate:
            for count, member in enumerate(crate, start=1):
                if count > MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError(f"crate archive has too many entries: {source_id}")
                path = checked_path(member.name)
                path_string = str(path)
                if path.parts[0] != expected_root:
                    raise EvidenceError(f"crate archive has an unexpected root: {source_id}")
                if path_string in seen_paths:
                    raise EvidenceError(
                        f"crate archive repeats an entry path: {source_id}/{path_string}"
                    )
                seen_paths.add(path_string)
                if member.isdir():
                    if member.size != 0:
                        raise EvidenceError(f"crate archive directory has a payload: {source_id}")
                    continue
                if (
                    not member.isfile()
                    or member.issparse()
                    or member.size < 0
                    or member.size > MAX_ARCHIVE_MEMBER_BYTES
                ):
                    raise EvidenceError(
                        f"crate archive has an unsupported entry: {source_id}/{path_string}"
                    )
                if LICENSE_NAME.search(path_string) is not None:
                    observed_notice_members.add(path_string)
                total += member.size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise EvidenceError(f"crate archive exceeds the size limit: {source_id}")
                if path_string not in expected_files:
                    continue
                content = read_member(crate, member)
                expectation = expected_files[path_string]
                if (
                    len(content) != expectation["size"]
                    or sha256_bytes(content) != expectation["sha256"]
                ):
                    raise EvidenceError(f"crate reviewed file differs: {source_id}/{path_string}")
                found[path_string] = content
    except EvidenceError:
        raise
    except (tarfile.TarError, RuntimeError, OverflowError, ValueError) as exc:
        raise EvidenceError(f"invalid crate archive for {source_id}: {exc}") from exc
    if observed_notice_members != expected_notice_members:
        raise EvidenceError(f"crate archive notice inventory differs: {source_id}")
    if set(found) != set(expected_files):
        raise EvidenceError(f"crate archive omits reviewed files: {source_id}")
    manifest_path = str(source["manifest"]["member"])
    try:
        manifest = tomllib.loads(found[manifest_path].decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError(f"crate manifest is invalid: {source_id}") from exc
    package = manifest.get("package")
    if (
        not isinstance(package, dict)
        or package.get("name") != name
        or package.get("version") != version
        or package.get("license") != source["raw_license"]
    ):
        raise EvidenceError(f"crate manifest identity or license differs: {source_id}")
    return found


def verify_owner_sdist_subtree(
    archive: bytes,
    *,
    source_id: str,
    source: Mapping[str, Any],
    archive_name: str,
) -> list[dict[str, Any]]:
    """Verify a canonical file manifest for one path inside a hostile owner sdist."""

    configured_path = checked_canonical_path(
        str(source["path"]), f"owner-sdist subtree path for {source_id}"
    )
    records: list[dict[str, Any]] = []
    roots: set[str] = set()
    expanded_size = 0

    def retain(
        archive_path: PurePosixPath,
        *,
        entry_type: str,
        mode: int,
        size: int,
        content: bytes | None,
    ) -> None:
        nonlocal expanded_size
        roots.add(archive_path.parts[0])
        if len(archive_path.parts) < 2:
            return
        relative_to_root = PurePosixPath(*archive_path.parts[1:])
        try:
            relative = relative_to_root.relative_to(configured_path)
        except ValueError:
            return
        if not relative.parts:
            return
        if not 0 <= mode <= 0o777 or mode & 0o7000:
            raise EvidenceError(
                f"owner-sdist subtree has an unsafe mode: {source_id}/{archive_path}"
            )
        if entry_type == "file":
            assert content is not None
            expanded_size += size
            if expanded_size > MAX_OWNER_SUBTREE_BYTES:
                raise EvidenceError(f"owner-sdist subtree exceeds its size limit: {source_id}")
            digest: str | None = sha256_bytes(content)
        else:
            if size != 0 or content is not None:
                raise EvidenceError(
                    f"owner-sdist subtree directory has a payload: {source_id}/{archive_path}"
                )
            digest = None
        records.append(
            {
                "path": str(relative),
                "type": entry_type,
                "mode": mode,
                "size": size,
                "sha256": digest,
            }
        )

    try:
        zip_candidate = (
            archive_name.lower().endswith(".zip")
            or archive.startswith(ZIP_SIGNATURES)
            or has_source_zip_eocd(archive)
        )
        if zip_candidate:
            central_offset, central_size, entry_count = preflight_source_zip(archive)
            central_entries = read_source_zip_central_directory(
                archive,
                central_offset,
                central_size,
                entry_count,
            )
            entries = validate_source_zip_entries(
                archive,
                central_offset,
                central_entries,
            )
            for entry in entries:
                metadata = entry.metadata
                path = checked_path(metadata.name)
                mode = metadata.external_attr >> 16 & 0o777
                if metadata.name.endswith("/"):
                    retain(
                        path,
                        entry_type="directory",
                        mode=mode,
                        size=0,
                        content=None,
                    )
                else:
                    payload = read_source_zip_payload(
                        archive,
                        entry,
                        max_bytes=MAX_ARCHIVE_MEMBER_BYTES,
                        purpose="owner-sdist subtree member",
                    )
                    retain(
                        path,
                        entry_type="file",
                        mode=mode,
                        size=len(payload),
                        content=payload,
                    )
        else:
            seen_paths: set[str] = set()
            with tarfile.open(
                fileobj=io.BytesIO(archive), mode="r:*", tarinfo=BoundedTarInfo
            ) as sdist:
                total = 0
                for count, member in enumerate(sdist, start=1):
                    if count > MAX_ARCHIVE_MEMBERS:
                        raise EvidenceError(f"owner sdist has too many entries: {source_id}")
                    path = checked_path(member.name)
                    path_string = str(path)
                    roots.add(path.parts[0])
                    if path_string in seen_paths:
                        raise EvidenceError(
                            f"owner sdist repeats an entry path: {source_id}/{path_string}"
                        )
                    seen_paths.add(path_string)
                    if member.isdir():
                        if member.size != 0:
                            raise EvidenceError(f"owner sdist directory has a payload: {source_id}")
                        retain(
                            path,
                            entry_type="directory",
                            mode=member.mode,
                            size=0,
                            content=None,
                        )
                        continue
                    if (
                        not member.isfile()
                        or member.issparse()
                        or member.size < 0
                        or member.size > MAX_ARCHIVE_MEMBER_BYTES
                    ):
                        raise EvidenceError(
                            f"owner sdist has an unsupported entry: {source_id}/{path_string}"
                        )
                    total += member.size
                    if total > MAX_ARCHIVE_TOTAL_BYTES:
                        raise EvidenceError(f"owner sdist exceeds the size limit: {source_id}")
                    payload = read_member(sdist, member)
                    retain(
                        path,
                        entry_type="file",
                        mode=member.mode,
                        size=len(payload),
                        content=payload,
                    )
    except EvidenceError:
        raise
    except (tarfile.TarError, RuntimeError, OverflowError, ValueError) as exc:
        raise EvidenceError(f"invalid owner sdist for {source_id}: {exc}") from exc

    if len(roots) != 1:
        raise EvidenceError(f"owner sdist must have exactly one top-level root: {source_id}")
    records.sort(key=lambda item: (item["path"], item["type"]))
    if (
        not records
        or len(records) > MAX_OWNER_SUBTREE_MEMBERS
        or len(records) != source["member_count"]
        or expanded_size != source["expanded_size"]
        or sha256_bytes(canonical_json(records)) != source["tree_sha256"]
    ):
        raise EvidenceError(f"owner-sdist subtree differs from reviewed policy: {source_id}")
    return records


def verify_owner_sdist_cargo_packages(
    archive: bytes,
    *,
    source_id: str,
    source: Mapping[str, Any],
    archive_name: str,
    subtree: Sequence[Mapping[str, Any]],
    bindings: set[OwnerSdistObservationBinding],
) -> None:
    """Bind local Cargo observations to exact manifests and files in an owner sdist."""

    workspace_manifest = source["workspace_manifest"]
    packages = {str(package["path"]): package for package in source["cargo_packages"]}
    expected_manifests = {
        str(workspace_manifest["member"]): workspace_manifest,
        **{
            str(package["manifest"]["member"]): package["manifest"] for package in packages.values()
        },
    }
    found = reviewed_files_from_source_archive(
        archive,
        archive_name=archive_name,
        source_id=f"{source_id} Cargo manifests",
        expected=expected_manifests,
        max_member_bytes=MAX_CARGO_LOCK_BYTES,
    )
    if set(found) != set(expected_manifests):
        raise EvidenceError(f"owner-sdist omits reviewed Cargo manifests: {source_id}")

    def parse_manifest(member: str, purpose: str) -> Mapping[str, Any]:
        try:
            document = tomllib.loads(found[member].decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise EvidenceError(f"owner-sdist has an invalid {purpose}: {source_id}") from exc
        if not isinstance(document, dict):
            raise EvidenceError(f"owner-sdist has an invalid {purpose}: {source_id}")
        return document

    workspace_document = parse_manifest(
        str(workspace_manifest["member"]),
        "Cargo workspace manifest",
    )
    workspace = workspace_document.get("workspace")
    if not isinstance(workspace, dict):
        raise EvidenceError(f"owner-sdist has no exact Cargo workspace: {source_id}")
    workspace_package = workspace.get("package")
    raw_members = workspace.get("members")
    if (
        not isinstance(workspace_package, dict)
        or not isinstance(raw_members, list)
        or not raw_members
        or len(raw_members) > MAX_OBSERVATIONS_PER_OWNER
        or not all(isinstance(member, str) for member in raw_members)
    ):
        raise EvidenceError(f"owner-sdist has an invalid Cargo workspace: {source_id}")

    source_path = PurePosixPath(str(source["path"]))
    workspace_member = PurePosixPath(str(workspace_manifest["member"]))
    workspace_relative_root = PurePosixPath(*workspace_member.parts[1:-1])
    workspace_package_paths: list[str] = []
    for raw_member in raw_members:
        assert isinstance(raw_member, str)
        try:
            member_path = workspace_relative_root / checked_path(raw_member)
            relative = member_path.relative_to(source_path)
        except (EvidenceError, ValueError) as exc:
            raise EvidenceError(
                f"owner-sdist Cargo workspace member escapes the reviewed subtree: {source_id}"
            ) from exc
        workspace_package_paths.append("." if not relative.parts else str(relative))
    if len(workspace_package_paths) != len(set(workspace_package_paths)) or set(
        workspace_package_paths
    ) != set(packages):
        raise EvidenceError(f"owner-sdist Cargo workspace members differ: {source_id}")

    def resolved_package_field(
        package_document: Mapping[str, Any],
        package_path: str,
        field: str,
    ) -> str:
        value = package_document.get(field)
        if isinstance(value, dict) and value == {"workspace": True}:
            value = workspace_package.get(field)
        if (
            not isinstance(value, str)
            or checked_scalar(
                value,
                f"owner-sdist Cargo package {field}",
                max_length=MAX_LICENSE_FIELD_LENGTH,
            )
            != value
        ):
            raise EvidenceError(
                f"owner-sdist Cargo package has an invalid {field}: {source_id}/{package_path}"
            )
        return value

    subtree_records = {str(record["path"]): record for record in subtree}
    for package_path, package in packages.items():
        relative_manifest = "Cargo.toml" if package_path == "." else f"{package_path}/Cargo.toml"
        manifest_record = package["manifest"]
        subtree_record = subtree_records.get(relative_manifest)
        if (
            subtree_record is None
            or subtree_record["type"] != "file"
            or subtree_record["sha256"] != manifest_record["sha256"]
            or subtree_record["size"] != manifest_record["size"]
        ):
            raise EvidenceError(
                f"owner-sdist Cargo package manifest is outside the reviewed subtree: "
                f"{source_id}/{package_path}"
            )
        document = parse_manifest(
            str(manifest_record["member"]),
            f"Cargo package manifest for {package_path}",
        )
        package_document = document.get("package")
        if not isinstance(package_document, dict):
            raise EvidenceError(
                f"owner-sdist Cargo package has no exact identity: {source_id}/{package_path}"
            )

        if (
            package_document.get("name") != package["name"]
            or resolved_package_field(package_document, package_path, "version")
            != package["version"]
            or resolved_package_field(package_document, package_path, "license")
            != source["reviewed_license"]
        ):
            raise EvidenceError(
                f"owner-sdist Cargo package identity or license differs: {source_id}/{package_path}"
            )

    for package_path, fragment_member in bindings:
        if package_path not in packages:
            raise EvidenceError(f"owner-sdist Cargo observation has no package: {source_id}")
        if fragment_member is None:
            continue
        fragment_record = subtree_records.get(fragment_member)
        if fragment_record is None or fragment_record["type"] != "file":
            raise EvidenceError(
                f"owner-sdist Cargo observation source path is absent: "
                f"{source_id}/{fragment_member}"
            )


def parse_native_owner(value: object, source: str) -> tuple[str, str, str]:
    """Validate and split one canonical ``python:name@version`` owner identity."""

    if not isinstance(value, str) or not value.startswith("python:") or "@" not in value:
        raise EvidenceError(f"{source} has an invalid owner")
    raw_name, version = value.removeprefix("python:").rsplit("@", maxsplit=1)
    if (
        normalize_package_name(raw_name) != raw_name
        or not version
        or checked_scalar(version, f"{source} owner version") != version
    ):
        raise EvidenceError(f"{source} has an invalid owner")
    return value, raw_name, version


ObservationReferenceKey = tuple[str, str, str, str, str]
SemanticObservationProjection = tuple[
    list[dict[str, Any]],
    dict[ObservationReferenceKey, dict[str, str]],
]


def validate_observation_reference(value: object, source: str) -> ObservationReferenceKey:
    """Validate one digest-bound, document-local occurrence reference."""

    if not isinstance(value, dict):
        raise EvidenceError(f"{source} is not an object")
    identity_kind = value.get("identity_kind")
    expected_fields = {
        "sbom_path",
        "observation_sha256",
        "identity_kind",
        "purl",
    }
    if identity_kind == "bom-ref":
        expected_fields.add("bom_ref")
    elif identity_kind != "purl":
        raise EvidenceError(f"{source} has an invalid observation identity kind")
    record = require_exact_fields(value, expected_fields, source)
    path_value = record["sbom_path"]
    observation_sha256 = record["observation_sha256"]
    purl = record["purl"]
    if (
        not isinstance(path_value, str)
        or str(checked_canonical_path(path_value, f"{source} SBOM path")) != path_value
        or DIST_INFO_SBOM.search(path_value) is None
        or not isinstance(observation_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", observation_sha256) is None
        or not isinstance(purl, str)
        or checked_scalar(
            purl,
            f"{source} purl",
            max_length=MAX_LICENSE_FIELD_LENGTH,
        )
        != purl
        or PACKAGE_URL.fullmatch(purl) is None
    ):
        raise EvidenceError(f"{source} has an invalid observation reference")
    identity = purl
    if identity_kind == "bom-ref":
        bom_ref = record["bom_ref"]
        if (
            not isinstance(bom_ref, str)
            or checked_scalar(
                bom_ref,
                f"{source} bom-ref",
                max_length=MAX_LICENSE_FIELD_LENGTH,
            )
            != bom_ref
        ):
            raise EvidenceError(f"{source} has an invalid observation bom-ref")
        identity = bom_ref
    return path_value, observation_sha256, identity_kind, identity, purl


def retained_observation_reference(
    sbom_path: str,
    observation_sha256: str,
    component: Mapping[str, Any],
) -> dict[str, str]:
    """Build the exact policy reference for one retained component occurrence."""

    identity_kind, identity = cyclonedx_occurrence_identity(component)
    reference = {
        "sbom_path": sbom_path,
        "observation_sha256": observation_sha256,
        "identity_kind": identity_kind,
        "purl": str(component["purl"]),
    }
    if identity_kind == "bom-ref":
        reference["bom_ref"] = identity
    validate_observation_reference(reference, "retained observation")
    return reference


def validate_observation_references(
    value: object,
    source: str,
    *,
    allow_empty: bool = False,
) -> list[ObservationReferenceKey]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_OBSERVATIONS_PER_REVIEW
        or (not value and not allow_empty)
    ):
        raise EvidenceError(f"{source} has invalid observation references")
    references = [
        validate_observation_reference(record, f"{source} observation {index}")
        for index, record in enumerate(value)
    ]
    if len(references) != len(set(references)) or references != sorted(references):
        raise EvidenceError(f"{source} observation references are not canonical")
    return references


OwnerSdistObservationBinding = tuple[str, str | None]


def owner_sdist_observation_path(
    observation: Mapping[str, Any],
    *,
    owner: str,
    source_id: str,
    source_record: Mapping[str, Any],
) -> OwnerSdistObservationBinding:
    """Bind one local Cargo PURL and bom-ref to a reviewed owner-sdist path."""

    purl = str(observation["purl"])
    cargo_identity = cargo_purl_identity(
        purl,
        f"native-component coverage {owner} owner-sdist review {source_id}",
    )
    if cargo_identity is None:
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )
    cargo_name, cargo_version = cargo_identity
    expected_base = (
        f"pkg:cargo/{urllib.parse.quote(cargo_name, safe='-._~')}@"
        f"{urllib.parse.quote(cargo_version, safe='-._~+')}"
    )
    purl_without_fragment, separator, fragment = purl.partition("#")
    expected_download_prefix = f"{expected_base}?download_url=file://"
    if not purl_without_fragment.startswith(expected_download_prefix):
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )
    relative_value = purl_without_fragment.removeprefix(expected_download_prefix)
    if (
        not relative_value
        or "&" in relative_value
        or "?" in relative_value
        or (separator and not fragment)
    ):
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )
    fragment_path: PurePosixPath | None = None
    try:
        if relative_value == ".":
            relative_path: PurePosixPath | None = None
        else:
            relative_path = checked_canonical_path(
                urllib.parse.unquote(relative_value, errors="strict"),
                f"native-component coverage {owner} owner-sdist PURL path",
            )
        if fragment:
            fragment_path = checked_canonical_path(
                urllib.parse.unquote(fragment, errors="strict"),
                f"native-component coverage {owner} owner-sdist PURL fragment",
            )
    except UnicodeDecodeError as exc:
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        ) from exc

    package_path = "." if relative_path is None else str(relative_path)
    packages = {str(package["path"]): package for package in source_record["cargo_packages"]}
    package = packages.get(package_path)
    expected_relative_value = (
        "." if relative_path is None else urllib.parse.quote(str(relative_path), safe="/-._~")
    )
    expected_fragment = (
        "" if fragment_path is None else urllib.parse.quote(str(fragment_path), safe="/-._~")
    )
    if (
        package is None
        or cargo_name != package["name"]
        or cargo_version != package["version"]
        or relative_value != expected_relative_value
        or fragment != expected_fragment
    ):
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )

    bom_ref = str(observation["bom_ref"])
    try:
        encoded_bom_ref = bom_ref.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        ) from exc
    if (
        len(encoded_bom_ref) > MAX_LICENSE_FIELD_LENGTH
        or "\\" in bom_ref
        or any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in bom_ref)
    ):
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )
    try:
        parsed_bom_ref = urllib.parse.urlsplit(bom_ref)
    except ValueError as exc:
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        ) from exc
    if (
        parsed_bom_ref.scheme != "path+file"
        or parsed_bom_ref.netloc
        or not parsed_bom_ref.path.startswith("/")
        or not parsed_bom_ref.fragment
        or parsed_bom_ref.query
    ):
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )
    try:
        decoded_bom_ref_path = urllib.parse.unquote(parsed_bom_ref.path, errors="strict")
        encoded_bom_ref_path = decoded_bom_ref_path.encode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError) as exc:
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        ) from exc
    observed_path = PurePosixPath(decoded_bom_ref_path)
    if (
        len(encoded_bom_ref_path) > MAX_PATH_BYTES
        or "\\" in decoded_bom_ref_path
        or any(
            ord(character) < 32 or 0x7F <= ord(character) <= 0x9F
            for character in decoded_bom_ref_path
        )
        or any(part in {".", ".."} for part in observed_path.parts)
        or observed_path.as_posix() != decoded_bom_ref_path
    ):
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )
    reviewed_path = PurePosixPath(str(source_record["path"]))
    expected_suffix = reviewed_path if relative_path is None else reviewed_path / relative_path
    if len(observed_path.parts) < len(expected_suffix.parts) or (
        observed_path.parts[-len(expected_suffix.parts) :] != expected_suffix.parts
    ):
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )
    if (
        observation["type"] != "library"
        or normalize_package_name(str(observation["name"])) != normalize_package_name(cargo_name)
        or observation["version"] != cargo_version
        or observation["hashes"]
    ):
        raise EvidenceError(
            f"native-component coverage {owner} owner-sdist review differs from {source_id}"
        )
    fragment_member = (
        None
        if fragment_path is None
        else str(fragment_path if relative_path is None else relative_path / fragment_path)
    )
    return package_path, fragment_member


def validate_component_review_source_binding(
    *,
    owner: str,
    source_id: str,
    source_record: Mapping[str, Any],
    reviewed_license: str,
    references: Sequence[ObservationReferenceKey],
    observations: Mapping[ObservationReferenceKey, Mapping[str, Any]],
) -> set[OwnerSdistObservationBinding]:
    """Bind source kinds with machine-verifiable identity fields to each observation."""

    kind = source_record["kind"]
    if kind == "owner-sdist-subpath":
        if source_record["owner"] != owner or reviewed_license != source_record["reviewed_license"]:
            raise EvidenceError(
                f"native-component coverage {owner} owner-sdist review differs from {source_id}"
            )
        bindings: set[OwnerSdistObservationBinding] = set()
        for reference in references:
            observation = observations[reference]
            bindings.add(
                owner_sdist_observation_path(
                    observation,
                    owner=owner,
                    source_id=source_id,
                    source_record=source_record,
                )
            )
            if observation["licenses"]:
                observed_license = cyclonedx_reviewed_license(
                    observation["licenses"],
                    f"native-component coverage {owner} owner-sdist review {source_id}",
                )
                if observed_license != reviewed_license:
                    raise EvidenceError(
                        f"native-component coverage {owner} owner-sdist review "
                        f"differs from {source_id}"
                    )
        return bindings
    if kind == "checksummed-upstream-release":
        name = str(source_record["name"])
        version = str(source_record["version"])
        archive = source_record["archive"]
        expected_purl = (
            f"pkg:generic/{urllib.parse.quote(name, safe='-._~')}@"
            f"{urllib.parse.quote(version, safe='-._~+')}?download_url={archive['url']}"
        )
        expected_hashes = [
            {
                "alg": "SHA-256",
                "content": str(archive["sha256"]),
            }
        ]
        if reviewed_license != source_record["reviewed_license"]:
            raise EvidenceError(
                f"native-component coverage {owner} upstream review differs from {source_id}"
            )
        for reference in references:
            observation = observations[reference]
            if (
                observation["type"] != "library"
                or observation["name"] != name
                or observation["version"] != version
                or observation["purl"] != expected_purl
                or observation["bom_ref"] not in {"", expected_purl}
                or observation["hashes"] != expected_hashes
            ):
                raise EvidenceError(
                    f"native-component coverage {owner} upstream review differs from {source_id}"
                )
            if observation["licenses"]:
                observed_license = cyclonedx_reviewed_license(
                    observation["licenses"],
                    f"native-component coverage {owner} upstream review {source_id}",
                )
                if observed_license != reviewed_license:
                    raise EvidenceError(
                        f"native-component coverage {owner} upstream review "
                        f"differs from {source_id}"
                    )
        return set()
    if kind != "crates-io":
        return set()
    name = str(source_record["name"])
    version = str(source_record["version"])
    quoted_name = urllib.parse.quote(name, safe="-._~")
    quoted_version = urllib.parse.quote(version, safe="-._~+")
    expected_purl = f"pkg:cargo/{quoted_name}@{quoted_version}"
    expected_hash = {
        "alg": "SHA-256",
        "content": str(source_record["crate"]["sha256"]),
    }
    if reviewed_license != source_record["normalized_license"]:
        raise EvidenceError(
            f"native-component coverage {owner} crate review license differs from {source_id}"
        )
    for reference in references:
        observation = observations[reference]
        observed_license = cyclonedx_reviewed_license(
            observation["licenses"],
            f"native-component coverage {owner} crate review {source_id}",
        )
        if (
            observation["purl"] != expected_purl
            or expected_hash not in observation["hashes"]
            or observed_license != source_record["normalized_license"]
        ):
            raise EvidenceError(
                f"native-component coverage {owner} crate review differs from {source_id}"
            )
    return set()


def validate_bundle_source_reviewed_license_binding(
    source_id: str,
    source_record: Mapping[str, Any],
    reviewed_licenses: set[str] | None,
) -> None:
    """Reconnect source-level reviewed licenses to bundle source consumers."""

    if source_record["kind"] not in {
        "owner-sdist-subpath",
        "checksummed-upstream-release",
    }:
        return
    if reviewed_licenses != {str(source_record["reviewed_license"])}:
        raise EvidenceError(
            f"native-component bundle review license differs from source {source_id}"
        )


def validate_native_owner_review(
    raw_owner: object,
    *,
    platform: str,
    sources: Mapping[str, Mapping[str, Any]],
    used_sources: set[str],
) -> dict[str, Any]:
    """Validate one v7 owner record without resolving cross-owner relationships."""

    owner_record = require_exact_fields(
        raw_owner,
        {
            "owner",
            "wheel",
            "owner_source",
            "cargo_lock",
            "native_payloads",
            "sboms",
            "component_reviews",
            "payload_dispositions",
            "known_omissions",
            "canonical_relationships",
            "review",
        },
        f"native-component coverage {platform}",
    )
    owner, name, version = parse_native_owner(
        owner_record["owner"], f"native-component coverage {platform}"
    )
    wheel = validate_pinned_artifact(
        owner_record["wheel"], f"native-component coverage {owner} wheel"
    )
    filename = safe_filename(str(wheel["url"]))
    try:
        wheel_name, wheel_version, _build, tags = parse_wheel_filename(filename)
        expected_version = Version(version)
    except (InvalidVersion, InvalidWheelFilename) as exc:
        raise EvidenceError(f"native-component coverage {owner} has invalid wheel") from exc
    if (
        canonicalize_name(wheel_name) != name
        or wheel_version != expected_version
        or not tags
        or not all(wheel_tag_matches_native_platform(tag, platform) for tag in tags)
    ):
        raise EvidenceError(f"native-component coverage {owner} wheel conflicts with {platform}")
    validate_pinned_artifact(
        owner_record["owner_source"],
        f"native-component coverage {owner} owner source",
    )
    payloads = validate_native_component_payloads(
        owner_record["native_payloads"],
        platform,
        f"native-component coverage {owner}",
    )

    raw_sboms = owner_record["sboms"]
    if not isinstance(raw_sboms, list) or len(raw_sboms) > MAX_SBOMS_PER_OWNER:
        raise EvidenceError(f"native-component coverage {owner} has invalid SBOMs")
    sbom_paths: set[str] = set()
    observations: dict[ObservationReferenceKey, Mapping[str, Any]] = {}
    owner_root_observations: set[ObservationReferenceKey] = set()
    omission_root_observations: dict[ObservationReferenceKey, str] = {}
    sboms: list[Mapping[str, Any]] = []
    for sbom_index, raw_sbom in enumerate(raw_sboms):
        sbom = require_exact_fields(
            raw_sbom,
            {"path", "sha256", "observation", "metadata_root"},
            f"native-component coverage {owner} SBOM {sbom_index}",
        )
        path_value = sbom["path"]
        digest = sbom["sha256"]
        if (
            not isinstance(path_value, str)
            or str(checked_canonical_path(path_value, "native-component SBOM path")) != path_value
            or DIST_INFO_SBOM.search(path_value) is None
            or path_value in sbom_paths
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise EvidenceError(f"native-component coverage {owner} has an invalid SBOM identity")
        sbom_paths.add(path_value)
        observation = sbom["observation"]
        validate_retained_cyclonedx_identity(
            observation, f"native-component coverage {owner} SBOM {sbom_index}"
        )
        assert isinstance(observation, dict)
        metadata_component = observation["metadata_component"]
        root_disposition = sbom["metadata_root"]
        anomaly_review = (
            root_disposition.get("anomaly_review")
            if isinstance(root_disposition, dict)
            else object()
        )
        root_echo = observation["metadata_root_echo"]
        if root_echo is None:
            if anomaly_review is not None:
                raise EvidenceError(
                    f"native-component coverage {owner} has a stale metadata-root anomaly review"
                )
        else:
            anomaly = require_exact_fields(
                anomaly_review,
                {"kind", "reason"},
                f"native-component coverage {owner} metadata-root anomaly review",
            )
            reason = anomaly["reason"]
            if (
                anomaly["kind"] != "metadata-root-echo"
                or not isinstance(reason, str)
                or checked_scalar(
                    reason,
                    f"native-component coverage {owner} metadata-root anomaly reason",
                    max_length=MAX_REVIEW_RATIONALE_LENGTH,
                )
                != reason
            ):
                raise EvidenceError(
                    f"native-component coverage {owner} has an invalid metadata-root echo review"
                )
        if metadata_component is None:
            require_exact_fields(
                root_disposition,
                {"kind", "anomaly_review"},
                f"native-component coverage {owner} metadata root",
            )
            if root_disposition["kind"] != "missing":
                raise EvidenceError(
                    f"native-component coverage {owner} has a false metadata-root disposition"
                )
        else:
            assert isinstance(metadata_component, dict)
            root_reference = validate_observation_reference(
                retained_observation_reference(
                    path_value,
                    str(observation["observation_sha256"]),
                    metadata_component,
                ),
                f"native-component coverage {owner} metadata root",
            )
            root_kind = root_disposition.get("kind") if isinstance(root_disposition, dict) else None
            if root_kind == "owner":
                require_exact_fields(
                    root_disposition,
                    {"kind", "anomaly_review"},
                    f"native-component coverage {owner} metadata root",
                )
                if (
                    normalize_package_name(str(metadata_component["name"])) != name
                    or metadata_component["version"] != version
                ):
                    raise EvidenceError(
                        f"native-component coverage {owner} owner metadata root conflicts"
                    )
                owner_root_observations.add(root_reference)
            elif root_kind == "embedded-component":
                require_exact_fields(
                    root_disposition,
                    {"kind", "anomaly_review"},
                    f"native-component coverage {owner} metadata root",
                )
            elif root_kind == "known-omission":
                root = require_exact_fields(
                    root_disposition,
                    {"kind", "omission", "anomaly_review"},
                    f"native-component coverage {owner} metadata root",
                )
                omission = root["omission"]
                if not isinstance(omission, str):
                    raise EvidenceError(
                        f"native-component coverage {owner} has an invalid root omission"
                    )
                omission_root_observations[root_reference] = omission
            else:
                raise EvidenceError(
                    f"native-component coverage {owner} has an invalid metadata-root disposition"
                )
        document_observations = list(
            ([metadata_component] if metadata_component is not None else [])
            + list(observation["components"])
        )
        for component in document_observations:
            key = validate_observation_reference(
                retained_observation_reference(
                    path_value,
                    str(observation["observation_sha256"]),
                    component,
                ),
                f"native-component coverage {owner} retained observation",
            )
            if key in observations:
                raise EvidenceError(
                    f"native-component coverage {owner} repeats an SBOM observation"
                )
            observations[key] = component
        sboms.append(sbom)
    if [record["path"] for record in sboms] != sorted(sbom_paths):
        raise EvidenceError(f"native-component coverage {owner} SBOMs are not canonical")
    if len(observations) > MAX_OBSERVATIONS_PER_OWNER:
        raise EvidenceError(f"native-component coverage {owner} has too many observations")
    if not payloads and not sboms:
        raise EvidenceError(
            f"native-component coverage {owner} has no native payload or SBOM surface"
        )

    raw_reviews = owner_record["component_reviews"]
    if not isinstance(raw_reviews, list) or len(raw_reviews) > MAX_COMPONENT_REVIEWS:
        raise EvidenceError(f"native-component coverage {owner} has invalid component reviews")
    reviewed_observations: set[ObservationReferenceKey] = set()
    crate_source_ids: set[str] = set()
    owner_sdist_bindings: dict[str, set[OwnerSdistObservationBinding]] = {}
    review_order: list[tuple[ObservationReferenceKey, ...]] = []
    for review_index, raw_review in enumerate(raw_reviews):
        review = require_exact_fields(
            raw_review,
            {"observations", "source", "reviewed_license"},
            f"native-component coverage {owner} component review {review_index}",
        )
        references = validate_observation_references(
            review["observations"],
            f"native-component coverage {owner} component review {review_index}",
        )
        if not set(references) <= set(observations):
            raise EvidenceError(
                f"native-component coverage {owner} review references an unknown observation"
            )
        if reviewed_observations & set(references):
            raise EvidenceError(
                f"native-component coverage {owner} reviews an observation more than once"
            )
        reviewed_observations.update(references)
        source_id = review["source"]
        if not isinstance(source_id, str) or source_id not in sources:
            raise EvidenceError(f"native-component coverage {owner} review has an unknown source")
        used_sources.add(source_id)
        if sources[source_id]["kind"] == "crates-io":
            crate_source_ids.add(source_id)
        reviewed_license = review["reviewed_license"]
        if (
            not isinstance(reviewed_license, str)
            or checked_scalar(
                reviewed_license,
                f"native-component coverage {owner} reviewed license",
                max_length=MAX_LICENSE_FIELD_LENGTH,
            )
            != reviewed_license
            or "LicenseRef-" in reviewed_license
        ):
            raise EvidenceError(
                f"native-component coverage {owner} has an invalid reviewed license"
            )
        source_bindings = validate_component_review_source_binding(
            owner=owner,
            source_id=source_id,
            source_record=sources[source_id],
            reviewed_license=reviewed_license,
            references=references,
            observations=observations,
        )
        if source_bindings:
            owner_sdist_bindings.setdefault(source_id, set()).update(source_bindings)
        review_order.append(tuple(references))
    if review_order != sorted(review_order):
        raise EvidenceError(
            f"native-component coverage {owner} component reviews are not canonical"
        )
    for source_id, bindings in owner_sdist_bindings.items():
        expected_package_paths = {
            str(package["path"]) for package in sources[source_id]["cargo_packages"]
        }
        if {package_path for package_path, _fragment in bindings} != expected_package_paths:
            raise EvidenceError(
                f"native-component coverage {owner} owner-sdist packages differ from {source_id}"
            )
    cargo_lock = validate_cargo_lock_context(
        owner_record["cargo_lock"],
        owner=owner,
        sources=sources,
        crate_source_ids=crate_source_ids,
    )

    raw_omissions = owner_record["known_omissions"]
    if not isinstance(raw_omissions, list) or len(raw_omissions) > MAX_KNOWN_OMISSIONS:
        raise EvidenceError(f"native-component coverage {owner} has invalid known omissions")
    omission_ids: set[str] = set()
    omitted_observations: set[ObservationReferenceKey] = set()
    omitted_payload_roles: set[str] = set()
    omission_observations: dict[str, set[ObservationReferenceKey]] = {}
    omission_payload_roles: dict[str, set[str]] = {}
    missing_evidence_values = {
        "build-material-attestation",
        "component-inventory",
        "exact-source",
        "license-evidence",
        "notice-evidence",
        "payload-provenance",
        "sbom-observation",
        "source-payload-relationship",
    }
    for omission_index, raw_omission in enumerate(raw_omissions):
        omission = require_exact_fields(
            raw_omission,
            {
                "id",
                "component",
                "observations",
                "payload_roles",
                "missing_evidence",
                "reason",
            },
            f"native-component coverage {owner} omission {omission_index}",
        )
        omission_id = omission["id"]
        if (
            not isinstance(omission_id, str)
            or checked_scalar(omission_id, f"native-component coverage {owner} omission id")
            != omission_id
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", omission_id) is None
            or omission_id in omission_ids
        ):
            raise EvidenceError(f"native-component coverage {owner} has an invalid omission id")
        omission_ids.add(omission_id)
        component = require_exact_fields(
            omission["component"],
            {"type", "name", "version", "purl"},
            f"native-component coverage {owner} omission component",
        )
        for field in ("type", "name", "version", "purl"):
            raw_value = component[field]
            if (
                not isinstance(raw_value, str)
                or checked_scalar(
                    raw_value,
                    f"native-component coverage {owner} omission component {field}",
                    max_length=(
                        MAX_LICENSE_FIELD_LENGTH if field == "purl" else MAX_COMPONENT_FIELD_LENGTH
                    ),
                    allow_empty=field in {"version", "purl"},
                )
                != raw_value
            ):
                raise EvidenceError(
                    f"native-component coverage {owner} has an invalid omission component"
                )
        if component["purl"] and PACKAGE_URL.fullmatch(str(component["purl"])) is None:
            raise EvidenceError(
                f"native-component coverage {owner} has an invalid omission component purl"
            )
        references = validate_observation_references(
            omission["observations"],
            f"native-component coverage {owner} omission {omission_id}",
            allow_empty=True,
        )
        if not set(references) <= set(observations) or omitted_observations & set(references):
            raise EvidenceError(
                f"native-component coverage {owner} omission has invalid observations"
            )
        omitted_observations.update(references)
        omission_observations[omission_id] = set(references)
        roles = omission["payload_roles"]
        if (
            not isinstance(roles, list)
            or len(roles) > MAX_IMAGE_MEMBERS
            or not all(isinstance(role, str) for role in roles)
            or roles != sorted(set(roles))
            or not set(roles) <= {str(payload["role"]) for payload in payloads}
            or omitted_payload_roles & set(roles)
        ):
            raise EvidenceError(
                f"native-component coverage {owner} omission has invalid payload roles"
            )
        omitted_payload_roles.update(roles)
        omission_payload_roles[omission_id] = set(roles)
        missing_evidence = omission["missing_evidence"]
        if (
            not isinstance(missing_evidence, list)
            or not missing_evidence
            or missing_evidence != sorted(set(missing_evidence))
            or not set(missing_evidence) <= missing_evidence_values
        ):
            raise EvidenceError(
                f"native-component coverage {owner} omission has invalid missing evidence"
            )
        reason = omission["reason"]
        if (
            not isinstance(reason, str)
            or checked_scalar(
                reason,
                f"native-component coverage {owner} omission reason",
                max_length=MAX_REVIEW_RATIONALE_LENGTH,
            )
            != reason
        ):
            raise EvidenceError(f"native-component coverage {owner} omission has no exact reason")
    if [record["id"] for record in raw_omissions] != sorted(omission_ids):
        raise EvidenceError(f"native-component coverage {owner} omissions are not canonical")
    if set(omission_root_observations.values()) - omission_ids:
        raise EvidenceError(
            f"native-component coverage {owner} metadata root cites an unknown omission"
        )
    for reference, omission_id in omission_root_observations.items():
        if reference not in omission_observations[omission_id]:
            raise EvidenceError(
                f"native-component coverage {owner} metadata-root omission "
                "does not cite its observation"
            )

    raw_relationships = owner_record["canonical_relationships"]
    if (
        not isinstance(raw_relationships, list)
        or len(raw_relationships) > MAX_CANONICAL_RELATIONSHIPS
    ):
        raise EvidenceError(
            f"native-component coverage {owner} has invalid canonical relationships"
        )
    relationship_observations: set[ObservationReferenceKey] = set()
    relationship_order: list[ObservationReferenceKey] = []
    relationships: list[Mapping[str, Any]] = []
    for relationship_index, raw_relationship in enumerate(raw_relationships):
        relationship = require_exact_fields(
            raw_relationship,
            {
                "kind",
                "observation",
                "reference_owner",
                "reference_observation",
                "payload_role",
                "reference_payload_role",
            },
            f"native-component coverage {owner} relationship {relationship_index}",
        )
        if relationship["kind"] != "same-component-by-payload-equivalence":
            raise EvidenceError(
                f"native-component coverage {owner} has an unsupported relationship"
            )
        observation_reference = validate_observation_reference(
            relationship["observation"],
            f"native-component coverage {owner} relationship observation",
        )
        if (
            observation_reference not in observations
            or observation_reference in relationship_observations
        ):
            raise EvidenceError(
                f"native-component coverage {owner} relationship has an invalid observation"
            )
        relationship_observations.add(observation_reference)
        reference_owner, _reference_name, _reference_version = parse_native_owner(
            relationship["reference_owner"],
            f"native-component coverage {owner} relationship",
        )
        if reference_owner == owner:
            raise EvidenceError(
                f"native-component coverage {owner} relationship must reference another owner"
            )
        validate_observation_reference(
            relationship["reference_observation"],
            f"native-component coverage {owner} relationship reference",
        )
        payload_role = relationship["payload_role"]
        reference_payload_role = relationship["reference_payload_role"]
        for role_value in (payload_role, reference_payload_role):
            if not isinstance(role_value, str):
                raise EvidenceError(
                    f"native-component coverage {owner} relationship has an invalid payload role"
                )
            checked_canonical_path(
                role_value, f"native-component coverage {owner} relationship payload role"
            )
        if payload_role not in {payload["role"] for payload in payloads}:
            raise EvidenceError(
                f"native-component coverage {owner} relationship has an unknown payload role"
            )
        relationship_order.append(observation_reference)
        relationships.append(relationship)
    if relationship_order != sorted(relationship_order):
        raise EvidenceError(f"native-component coverage {owner} relationships are not canonical")

    raw_dispositions = owner_record["payload_dispositions"]
    if not isinstance(raw_dispositions, list) or len(raw_dispositions) > MAX_IMAGE_MEMBERS:
        raise EvidenceError(f"native-component coverage {owner} has invalid payload dispositions")
    payload_roles = {str(payload["role"]) for payload in payloads}
    disposition_roles: set[str] = set()
    payload_observations: dict[str, set[ObservationReferenceKey]] = {}
    for raw_disposition in raw_dispositions:
        if not isinstance(raw_disposition, dict):
            raise EvidenceError(
                f"native-component coverage {owner} has an invalid payload disposition"
            )
        role = raw_disposition.get("role")
        kind = raw_disposition.get("kind")
        if not isinstance(role, str) or role not in payload_roles or role in disposition_roles:
            raise EvidenceError(
                f"native-component coverage {owner} has an invalid payload disposition role"
            )
        disposition_roles.add(role)
        if kind == "owner":
            require_exact_fields(
                raw_disposition,
                {"role", "kind"},
                f"native-component coverage {owner} payload disposition",
            )
        elif kind == "sbom-components":
            disposition = require_exact_fields(
                raw_disposition,
                {"role", "kind", "observations"},
                f"native-component coverage {owner} payload disposition",
            )
            references = validate_observation_references(
                disposition["observations"],
                f"native-component coverage {owner} payload disposition",
            )
            if not set(references) <= set(observations):
                raise EvidenceError(
                    f"native-component coverage {owner} payload disposition has "
                    "unknown observations"
                )
            payload_observations[role] = set(references)
        elif kind == "known-omission":
            disposition = require_exact_fields(
                raw_disposition,
                {"role", "kind", "omission"},
                f"native-component coverage {owner} payload disposition",
            )
            omission_id = disposition["omission"]
            if not isinstance(omission_id, str) or omission_id not in omission_ids:
                raise EvidenceError(
                    f"native-component coverage {owner} payload disposition has unknown omission"
                )
            if role not in omission_payload_roles[omission_id]:
                raise EvidenceError(
                    f"native-component coverage {owner} named omission does not cite its payload"
                )
        else:
            raise EvidenceError(
                f"native-component coverage {owner} has an unsupported payload disposition"
            )
    if [record["role"] for record in raw_dispositions] != sorted(disposition_roles):
        raise EvidenceError(
            f"native-component coverage {owner} payload dispositions are not canonical"
        )
    if disposition_roles != payload_roles:
        raise EvidenceError(
            f"native-component coverage {owner} does not dispose every native payload"
        )

    disposed_observations = (
        owner_root_observations
        | reviewed_observations
        | omitted_observations
        | relationship_observations
    )
    if len(disposed_observations) != (
        len(owner_root_observations)
        + len(reviewed_observations)
        + len(omitted_observations)
        + len(relationship_observations)
    ):
        raise EvidenceError(
            f"native-component coverage {owner} gives one observation multiple dispositions"
        )
    if disposed_observations != set(observations):
        raise EvidenceError(
            f"native-component coverage {owner} does not dispose every SBOM observation"
        )

    review = require_exact_fields(
        owner_record["review"],
        {"state", "reason", "unresolved_items"},
        f"native-component coverage {owner} review",
    )
    state = review["state"]
    reason = review["reason"]
    unresolved = review["unresolved_items"]
    if state not in {"open", "closed"}:
        raise EvidenceError(f"native-component coverage {owner} has an invalid review state")
    if (
        not isinstance(reason, str)
        or checked_scalar(
            reason,
            f"native-component coverage {owner} review reason",
            max_length=MAX_REVIEW_RATIONALE_LENGTH,
            allow_empty=state == "closed",
        )
        != reason
        or not isinstance(unresolved, list)
        or len(unresolved) > MAX_COMPONENTS
        or not all(
            isinstance(item, str)
            and checked_scalar(
                item,
                f"native-component coverage {owner} unresolved item",
                max_length=MAX_REVIEW_RATIONALE_LENGTH,
            )
            == item
            for item in unresolved
        )
        or unresolved != sorted(set(unresolved))
    ):
        raise EvidenceError(f"native-component coverage {owner} has an invalid review")
    if state == "closed" and (reason or unresolved or raw_omissions):
        raise EvidenceError(
            f"native-component coverage {owner} cannot close with a reason, "
            "unresolved item, or omission"
        )
    if state == "open" and (not reason or not unresolved):
        raise EvidenceError(
            f"native-component coverage {owner} open review requires exact unresolved items"
        )
    if state == "open" and set(unresolved) != omission_ids:
        raise EvidenceError(
            f"native-component coverage {owner} unresolved items differ from known omissions"
        )

    return {
        "record": owner_record,
        "owner": owner,
        "state": state,
        "cargo_lock": cargo_lock,
        "observations": observations,
        "owner_root_observations": owner_root_observations,
        "reviewed_observations": reviewed_observations,
        "owner_sdist_bindings": owner_sdist_bindings,
        "relationship_observations": relationship_observations,
        "payloads": {str(payload["role"]): payload for payload in payloads},
        "payload_observations": payload_observations,
        "relationships": relationships,
    }


def validate_native_relationships(contexts: Mapping[str, Mapping[str, Any]], platform: str) -> None:
    """Resolve v7 relationships in a second pass against closed reference owners."""

    target_references: set[tuple[str, ObservationReferenceKey]] = set()
    relationship_sources = {
        (owner, reference)
        for owner, context in contexts.items()
        for reference in context["relationship_observations"]
    }
    for owner, context in contexts.items():
        for relationship in context["relationships"]:
            source_reference = validate_observation_reference(
                relationship["observation"], f"{platform} relationship source"
            )
            reference_owner = str(relationship["reference_owner"])
            reference_context = contexts.get(reference_owner)
            if reference_context is None or reference_context["state"] != "closed":
                raise EvidenceError(
                    f"native-component coverage {owner} relationship target is not closed"
                )
            reference = validate_observation_reference(
                relationship["reference_observation"], f"{platform} relationship target"
            )
            if reference not in reference_context["reviewed_observations"]:
                raise EvidenceError(
                    f"native-component coverage {owner} relationship target is not "
                    "directly reviewed"
                )
            payload_role = str(relationship["payload_role"])
            reference_payload_role = str(relationship["reference_payload_role"])
            if source_reference not in context["payload_observations"].get(payload_role, set()):
                raise EvidenceError(
                    f"native-component coverage {owner} relationship source payload "
                    "does not cite its observation"
                )
            if reference not in reference_context["payload_observations"].get(
                reference_payload_role, set()
            ):
                raise EvidenceError(
                    f"native-component coverage {owner} relationship target payload "
                    "does not cite its observation"
                )
            if (reference_owner, reference) in relationship_sources:
                raise EvidenceError(
                    f"native-component coverage {owner} relationships cannot form chains"
                )
            target_key = (reference_owner, reference)
            if target_key in target_references:
                raise EvidenceError(
                    f"native-component coverage {owner} reuses a relationship target"
                )
            target_references.add(target_key)
            observed = context["observations"][source_reference]
            reference_observed = reference_context["observations"][reference]
            if {field: observed[field] for field in ("type", "name", "version")} != {
                field: reference_observed[field] for field in ("type", "name", "version")
            }:
                raise EvidenceError(
                    f"native-component coverage {owner} relationship changes component identity"
                )
            payload = context["payloads"].get(payload_role)
            reference_payload = reference_context["payloads"].get(reference_payload_role)
            if (
                payload is None
                or reference_payload is None
                or {field: payload[field] for field in ("sha256", "size")}
                != {field: reference_payload[field] for field in ("sha256", "size")}
            ):
                raise EvidenceError(
                    f"native-component coverage {owner} relationship payloads are not "
                    "byte-identical"
                )


def native_owner_semantic_observation_projection(
    context: Mapping[str, Any], contexts: Mapping[str, Mapping[str, Any]]
) -> SemanticObservationProjection:
    """Canonicalize one owner's observations and exact-reference lookup."""

    record = context["record"]
    canonical_purls: dict[ObservationReferenceKey, str] = {}
    for relationship in context["relationships"]:
        source_reference = validate_observation_reference(
            relationship["observation"], "relationship semantic source"
        )
        reference_owner = str(relationship["reference_owner"])
        reference = validate_observation_reference(
            relationship["reference_observation"], "relationship semantic target"
        )
        canonical_purls[source_reference] = str(
            contexts[reference_owner]["observations"][reference]["purl"]
        )

    def canonical_observation(
        reference_key: ObservationReferenceKey,
        observation: Mapping[str, Any],
    ) -> dict[str, Any]:
        projected = dict(observation)
        original_purl = str(observation["purl"])
        canonical_purl = canonical_purls.get(reference_key, original_purl)
        projected["purl"] = canonical_purl
        if observation["bom_ref"] == original_purl:
            projected["bom_ref"] = canonical_purl
        return projected

    def semantic_reference(
        sbom_path: str,
        component: Mapping[str, Any],
    ) -> dict[str, str]:
        identity_kind, identity = cyclonedx_occurrence_identity(component)
        reference = {
            "sbom_path": sbom_path,
            "identity_kind": identity_kind,
            "purl": str(component["purl"]),
        }
        if identity_kind == "bom-ref":
            reference["bom_ref"] = identity
        return reference

    sboms = []
    semantic_references: dict[ObservationReferenceKey, dict[str, str]] = {}
    for sbom in record["sboms"]:
        observation = sbom["observation"]
        raw_observation_sha256 = str(observation["observation_sha256"])
        metadata_component = observation["metadata_component"]
        metadata_root_echo = observation["metadata_root_echo"]
        metadata_key: ObservationReferenceKey | None = None
        if metadata_component is not None:
            metadata_key = validate_observation_reference(
                retained_observation_reference(
                    str(sbom["path"]),
                    raw_observation_sha256,
                    metadata_component,
                ),
                "semantic metadata observation",
            )
            metadata_component = canonical_observation(metadata_key, metadata_component)
        if metadata_root_echo is not None:
            assert metadata_key is not None
            metadata_root_echo = canonical_observation(metadata_key, metadata_root_echo)
        if sbom["metadata_root"]["kind"] == "owner":
            _owner, owner_name, owner_version = parse_native_owner(
                record["owner"], "semantic owner root"
            )
            owner_root_identity = f"pkg:generic/python-owner/{owner_name}@{owner_version}"
            assert metadata_component is not None
            metadata_component["purl"] = owner_root_identity
            metadata_component["bom_ref"] = owner_root_identity
            if metadata_root_echo is not None:
                metadata_root_echo["purl"] = owner_root_identity
                metadata_root_echo["bom_ref"] = owner_root_identity
        elif metadata_component is not None and metadata_component["bom_ref"]:
            root_identity = {
                field: metadata_component[field]
                for field in ("type", "name", "version", "purl", "hashes", "licenses")
            }
            semantic_root_ref = "semantic-root:" + sha256_bytes(canonical_json(root_identity))
            metadata_component["bom_ref"] = semantic_root_ref
            if metadata_root_echo is not None:
                metadata_root_echo["bom_ref"] = semantic_root_ref
        raw_components = list(observation["components"])
        canonical_components: list[dict[str, Any]] = []
        component_pairs: list[tuple[ObservationReferenceKey, dict[str, Any]]] = []
        for component in raw_components:
            raw_key = validate_observation_reference(
                retained_observation_reference(
                    str(sbom["path"]),
                    raw_observation_sha256,
                    component,
                ),
                "semantic component observation",
            )
            canonical_component = canonical_observation(raw_key, component)
            canonical_components.append(canonical_component)
            component_pairs.append((raw_key, canonical_component))
        occurrence_groups: dict[bytes, list[tuple[ObservationReferenceKey, dict[str, Any]]]] = {}
        for raw_key, canonical_component in component_pairs:
            if not canonical_component["bom_ref"]:
                continue
            semantic_identity = canonical_json(
                {
                    field: canonical_component[field]
                    for field in (
                        "type",
                        "name",
                        "version",
                        "purl",
                        "hashes",
                        "licenses",
                    )
                }
            )
            occurrence_groups.setdefault(semantic_identity, []).append(
                (raw_key, canonical_component)
            )
        for semantic_identity, group in occurrence_groups.items():
            prefix = "semantic-occurrence:" + sha256_bytes(semantic_identity)
            for ordinal, (_raw_key, canonical_component) in enumerate(
                sorted(group, key=lambda item: item[0])
            ):
                canonical_component["bom_ref"] = f"{prefix}:{ordinal}"
        canonical_components.sort(key=cyclonedx_component_sort_key)
        semantic_body = {
            "metadata_component": metadata_component,
            "metadata_root_echo": metadata_root_echo,
            "upstream_invalid_duplicate_bom_ref": observation["upstream_invalid_duplicate_bom_ref"],
            "components": canonical_components,
        }
        semantic_digest = sha256_bytes(canonical_json(semantic_body))
        if metadata_key is not None:
            assert metadata_component is not None
            semantic_references[metadata_key] = semantic_reference(
                str(sbom["path"]),
                metadata_component,
            )
        for raw_key, canonical_component in component_pairs:
            semantic_references[raw_key] = semantic_reference(
                str(sbom["path"]),
                canonical_component,
            )
        sboms.append(
            {
                "path": sbom["path"],
                "metadata_root": sbom["metadata_root"],
                "observation": {
                    "bom_format": observation["bom_format"],
                    "spec_version": observation["spec_version"],
                    **semantic_body,
                    "observation_sha256": semantic_digest,
                },
            }
        )

    return sboms, semantic_references


def native_owner_semantic_projection(
    context: Mapping[str, Any],
    semantic_contexts: Mapping[str, SemanticObservationProjection],
) -> dict[str, Any]:
    """Remove platform bytes while retaining all cross-platform review semantics."""

    record = context["record"]
    semantic_context = semantic_contexts.get(str(context["owner"]))
    if semantic_context is None:
        raise EvidenceError("semantic owner context is unknown")
    sboms, semantic_references = semantic_context

    def canonical_reference(raw: object) -> dict[str, str]:
        key = validate_observation_reference(raw, "semantic observation reference")
        reference = semantic_references.get(key)
        if reference is None:
            raise EvidenceError("semantic observation reference is unknown")
        return reference

    def canonical_references(raw: Sequence[object]) -> list[dict[str, str]]:
        return sorted(
            (canonical_reference(reference) for reference in raw),
            key=canonical_json,
        )

    reviews = [
        {
            **review,
            "observations": canonical_references(review["observations"]),
        }
        for review in record["component_reviews"]
    ]
    reviews.sort(key=canonical_json)
    omissions = [
        {
            **omission,
            "observations": canonical_references(omission["observations"]),
        }
        for omission in record["known_omissions"]
    ]
    dispositions = []
    for disposition in record["payload_dispositions"]:
        if disposition["kind"] == "sbom-components":
            dispositions.append(
                {
                    **disposition,
                    "observations": canonical_references(disposition["observations"]),
                }
            )
        else:
            dispositions.append(disposition)
    relationships = []
    for relationship in record["canonical_relationships"]:
        reference_owner = str(relationship["reference_owner"])
        reference_context = semantic_contexts.get(reference_owner)
        if reference_context is None:
            raise EvidenceError("semantic relationship target owner is unknown")
        reference_key = validate_observation_reference(
            relationship["reference_observation"],
            "semantic relationship target",
        )
        reference_observation = reference_context[1].get(reference_key)
        if reference_observation is None:
            raise EvidenceError("semantic relationship target observation is unknown")
        relationships.append(
            {
                **relationship,
                "observation": canonical_reference(relationship["observation"]),
                "reference_observation": reference_observation,
            }
        )
    relationships.sort(key=canonical_json)
    return {
        "owner": record["owner"],
        "owner_source": record["owner_source"],
        "cargo_lock": record["cargo_lock"],
        "native_payload_roles": [payload["role"] for payload in record["native_payloads"]],
        "sboms": sboms,
        "component_reviews": reviews,
        "payload_dispositions": dispositions,
        "known_omissions": omissions,
        "canonical_relationships": relationships,
        "review": record["review"],
    }


def validate_native_component_policy_schema(policy: Mapping[str, Any]) -> None:
    """Validate the v7 observation, review-mapping, and closure policy."""

    sources = native_component_sources(policy)
    coverage = policy.get("native_component_coverage")
    if not isinstance(coverage, dict) or set(coverage) != {"linux/amd64", "linux/arm64"}:
        raise EvidenceError("policy must define native-component coverage for both platforms")
    used_sources: set[str] = set()
    platform_contexts: dict[str, dict[str, dict[str, Any]]] = {}
    for platform, raw_records in coverage.items():
        if not isinstance(raw_records, list) or len(raw_records) > MAX_NATIVE_OWNERS:
            raise EvidenceError(f"native-component coverage for {platform} is invalid")
        contexts: dict[str, dict[str, Any]] = {}
        for raw_owner in raw_records:
            context = validate_native_owner_review(
                raw_owner,
                platform=platform,
                sources=sources,
                used_sources=used_sources,
            )
            owner = context["owner"]
            if owner in contexts:
                raise EvidenceError(f"native-component coverage for {platform} repeats {owner}")
            contexts[owner] = context
        if [record["owner"] for record in raw_records] != sorted(contexts):
            raise EvidenceError(f"native-component coverage for {platform} is not canonical")
        validate_native_relationships(contexts, platform)
        platform_contexts[platform] = contexts
    amd64_contexts = platform_contexts["linux/amd64"]
    arm64_contexts = platform_contexts["linux/arm64"]
    if set(amd64_contexts) != set(arm64_contexts):
        raise EvidenceError("native-component coverage owners differ across platforms")
    amd64_semantic_contexts = {
        owner: native_owner_semantic_observation_projection(context, amd64_contexts)
        for owner, context in amd64_contexts.items()
    }
    arm64_semantic_contexts = {
        owner: native_owner_semantic_observation_projection(context, arm64_contexts)
        for owner, context in arm64_contexts.items()
    }
    for owner in sorted(amd64_contexts):
        amd64_semantics = native_owner_semantic_projection(
            amd64_contexts[owner], amd64_semantic_contexts
        )
        arm64_semantics = native_owner_semantic_projection(
            arm64_contexts[owner], arm64_semantic_contexts
        )
        if canonical_json(amd64_semantics) != canonical_json(arm64_semantics):
            raise EvidenceError(
                f"native-component coverage semantics differ across platforms for {owner}"
            )
    if used_sources != set(sources):
        raise EvidenceError("native-component sources are missing, extra, or unused")


def native_component_coverage_ledger(
    inventory: Mapping[str, Any], policy: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind every observed native owner to one explicit open or closed review."""

    validate_native_component_policy_schema(policy)
    platform = inventory.get("platform")
    coverage = policy.get("native_component_coverage")
    if platform not in {"linux/amd64", "linux/arm64"} or not isinstance(coverage, dict):
        raise EvidenceError("component inventory has an unsupported native-component platform")
    configured = coverage[platform]
    contexts = native_wheel_contexts(inventory)
    configured_owners = {
        str(record["owner"]): record
        for record in configured
        if isinstance(record, dict) and isinstance(record.get("owner"), str)
    }
    if set(configured_owners) != set(contexts):
        missing = sorted(set(contexts) - set(configured_owners))
        stale = sorted(set(configured_owners) - set(contexts))
        raise EvidenceError(
            "native-component coverage must exactly match observed owners; "
            f"missing={missing!r}, stale={stale!r}"
        )
    resolved: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    sbom_anomalies: list[dict[str, Any]] = []
    for owner_record in configured:
        owner = str(owner_record["owner"])
        context = contexts[owner]
        expected_payloads = {
            (str(record["path"]), str(record["sha256"]), int(record["size"]))
            for record in owner_record["native_payloads"]
        }
        expected_sboms: dict[tuple[str, str], Mapping[str, Any]] = {}
        for sbom in owner_record["sboms"]:
            key = (str(sbom["path"]), str(sbom["sha256"]))
            expected_sboms[key] = sbom
        observed_payloads = {
            (str(record["path"]), str(record["sha256"]), int(record["size"]))
            for record in context["native_payloads"]
        }
        if expected_payloads != observed_payloads:
            raise EvidenceError(
                f"native-component coverage does not exactly cover payloads for {owner}"
            )
        observed_sboms = {
            (str(record["path"]), str(record["sha256"])): record
            for record in context["embedded_sboms"]
        }
        if set(expected_sboms) != set(observed_sboms):
            raise EvidenceError(
                f"native-component coverage does not exactly cover SBOMs for {owner}"
            )
        for key, expected_sbom in expected_sboms.items():
            observed_sbom = observed_sboms[key]
            cyclonedx = observed_sbom.get("cyclonedx")
            if not isinstance(cyclonedx, dict):
                raise EvidenceError(f"native-component coverage SBOM is unparsed for {owner}")
            if canonical_json(expected_sbom["observation"]) != canonical_json(cyclonedx):
                raise EvidenceError(
                    f"native-component coverage differs from embedded SBOM observation for {owner}"
                )
            anomaly_review = expected_sbom["metadata_root"]["anomaly_review"]
            if anomaly_review is not None:
                sbom_anomalies.append(
                    {
                        "owner": owner,
                        "sbom_path": expected_sbom["path"],
                        "observation_sha256": expected_sbom["observation"]["observation_sha256"],
                        **anomaly_review,
                    }
                )
        review = owner_record["review"]
        if review["state"] == "closed":
            resolved.append(dict(owner_record))
        else:
            unresolved.append(dict(owner_record))
    return {
        "schema_version": SCHEMA_VERSION,
        "platform": platform,
        "complete": not unresolved,
        "resolved_owners": resolved,
        "unresolved_owners": unresolved,
        "observed_sbom_anomalies": sbom_anomalies,
        "remaining_owner_count": len(unresolved),
        "remaining_owner_names": [record["owner"] for record in unresolved],
    }


def verify_native_component_lock_bindings(
    inventory: Mapping[str, Any],
    policy: Mapping[str, Any],
    locked_wheels: Sequence[Mapping[str, Any]],
    lock_sources: Mapping[tuple[str, str], Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind every native owner to the selected wheel and reviewed source pins."""

    ledger = native_component_coverage_ledger(inventory, policy)
    selected: dict[str, Mapping[str, Any]] = {}
    for wheel in locked_wheels:
        owner = wheel.get("owner")
        if not isinstance(owner, str) or owner in selected:
            raise EvidenceError("locked native wheels repeat an owner")
        selected[owner] = wheel
    coverage = policy.get("native_component_coverage")
    platform = inventory.get("platform")
    if not isinstance(coverage, dict) or platform not in coverage:
        raise EvidenceError("native-component lock binding has no platform policy")
    for owner_record in coverage[platform]:
        owner = str(owner_record["owner"])
        selected_wheel = selected.get(owner)
        expected_wheel = owner_record["wheel"]
        if (
            selected_wheel is None
            or {field: selected_wheel.get(field) for field in ("url", "sha256", "size")}
            != expected_wheel
        ):
            raise EvidenceError(f"native-component coverage wheel differs from lock for {owner}")
        name, version = owner.removeprefix("python:").rsplit("@", maxsplit=1)
        expected_source = lock_sources.get((name, version))
        source_origin = "lock"
        if expected_source is None:
            fallback_source = source_policy_entry(policy, name, version)
            expected_source = {field: fallback_source[field] for field in ("url", "sha256", "size")}
            source_origin = "reviewed source fallback"
        if expected_source != owner_record["owner_source"]:
            raise EvidenceError(
                f"native-component coverage owner source differs from {source_origin} for {owner}"
            )
    return ledger


def validate_retained_cyclonedx_identity(value: object, source: str) -> None:
    """Validate a canonical CycloneDX observation retained beside its raw bytes."""

    if not isinstance(value, dict) or set(value) != {
        "bom_format",
        "spec_version",
        "metadata_component",
        "metadata_root_echo",
        "upstream_invalid_duplicate_bom_ref",
        "components",
        "observation_sha256",
    }:
        raise EvidenceError(f"{source} has an invalid CycloneDX observation")
    if value.get("bom_format") != "CycloneDX":
        raise EvidenceError(f"{source} has an invalid CycloneDX format")
    spec_version = value.get("spec_version")
    if spec_version not in CYCLONEDX_SPEC_VERSIONS:
        raise EvidenceError(f"{source} has an unsupported CycloneDX spec version")
    metadata_component, components = validate_cyclonedx_observation_projection(
        value.get("metadata_component"), value.get("components"), source
    )
    metadata_root_echo = value.get("metadata_root_echo")
    upstream_invalid = value.get("upstream_invalid_duplicate_bom_ref")
    if metadata_root_echo is None:
        if upstream_invalid is not False:
            raise EvidenceError(f"{source} has an invalid metadata-root echo state")
    elif (
        metadata_component is None
        or metadata_root_echo != metadata_component
        or upstream_invalid is not True
    ):
        raise EvidenceError(f"{source} has an invalid metadata-root echo")
    observation = {
        "metadata_component": metadata_component,
        "metadata_root_echo": metadata_root_echo,
        "upstream_invalid_duplicate_bom_ref": upstream_invalid,
        "components": components,
    }
    digest = value.get("observation_sha256")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or digest != sha256_bytes(canonical_json(observation))
    ):
        raise EvidenceError(f"{source} has an invalid CycloneDX observation digest")


def validate_retained_elf_identity(value: object, platform: str, source: str) -> None:
    """Validate a retained normalized ELF identity against its image platform."""

    expected = ELF_MACHINES.get(platform)
    if expected is None:
        raise EvidenceError(f"{source} has an unsupported ELF platform")
    expected_machine, expected_name = expected
    if not isinstance(value, dict) or value != {
        "bits": 64,
        "endianness": "little",
        "machine": expected_name,
        "machine_id": expected_machine,
    }:
        raise EvidenceError(f"{source} has an ELF architecture mismatch")


def validate_structured_python_payloads(
    value: object,
    source: str,
    *,
    identity_field: str,
    platform: str,
    component_owners: set[str],
) -> list[dict[str, Any]]:
    """Validate occurrence-bound SBOM or ELF evidence from installed wheels.

    CycloneDX identities are scoped to their source document. Wheel builders can
    report the same display identity under different PURL namespaces, so the
    occurrence's exact-byte digest, path, and RECORD owner remain the binding
    across documents. ``validate_retained_cyclonedx_identity`` still rejects
    contradictory identities inside each individual document.
    """

    if not isinstance(value, list) or len(value) > MAX_IMAGE_MEMBERS:
        raise EvidenceError(f"invalid {source} payload list")
    records: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    expected_fields = PAYLOAD_RECORD_FIELDS | {"owner", identity_field}
    for record in value:
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise EvidenceError(f"invalid {source} payload record")
        raw = payload_record_projection(record)
        validate_payload_records([raw], source)
        occurrence = (raw["layer"], raw["path"])
        if occurrence in seen:
            raise EvidenceError(f"duplicate {source} payload occurrence")
        seen.add(occurrence)
        owner = record.get("owner")
        if not isinstance(owner, str) or owner not in component_owners:
            raise EvidenceError(f"{source} payload has an invalid Python RECORD owner")
        if identity_field == "cyclonedx":
            validate_retained_cyclonedx_identity(record.get(identity_field), source)
        elif identity_field == "elf":
            validate_retained_elf_identity(record.get(identity_field), platform, source)
        else:
            raise EvidenceError(f"unsupported structured Python payload identity: {identity_field}")
        records.append(record)
    return records


def validate_header_identity(record: Mapping[str, Any], source: str) -> None:
    """Validate the normalized security metadata retained for a tar entry."""

    for field in ("mode", "uid", "gid"):
        value = record.get(field)
        maximum = 0o7777 if field == "mode" else MAX_TAR_ID
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
            raise EvidenceError(f"{source} has an invalid {field}")


def filesystem_baseline(policy: Mapping[str, Any], platform: object) -> Mapping[str, Any]:
    baselines = policy.get("filesystem_baselines")
    if not isinstance(baselines, dict) or set(baselines) != {
        "linux/amd64",
        "linux/arm64",
    }:
        raise EvidenceError("policy must pin filesystem baselines for both platforms")
    baseline = baselines.get(platform)
    if not isinstance(baseline, dict) or set(baseline) != {
        "apk_database_occurrences",
        "post_base_directory_effects",
        "post_base_removals",
    }:
        raise EvidenceError(f"invalid filesystem baseline for {platform!r}")
    return baseline


def verify_apk_database_baseline(inventory: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    """Bind every layered APK database, including ignored virtual records, byte-for-byte."""

    baseline = filesystem_baseline(policy, inventory.get("platform"))
    expected = validate_payload_records(baseline["apk_database_occurrences"], "APK database policy")
    observed = validate_payload_records(
        inventory.get("apk_database_occurrences"), "APK database inventory"
    )
    if canonical_json(observed) != canonical_json(expected):
        raise EvidenceError("layered APK databases differ from reviewed policy")


def validate_wheel_installations(
    value: object,
    components: Sequence[Mapping[str, Any]],
    occurrence_payloads: Mapping[tuple[int, str], Mapping[str, Any]] | None = None,
) -> tuple[
    dict[tuple[int, str, str], str],
    dict[tuple[int, str, str], str],
]:
    """Validate explicit historical RECORD replay evidence."""

    if not isinstance(value, list) or len(value) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("component inventory has invalid historical Python installations")
    python_components = {
        component_key(component): component
        for component in components
        if component.get("ecosystem") == "python"
    }
    seen_records: set[tuple[int, str]] = set()
    active_owners: set[str] = set()
    occurrence_owners: dict[tuple[int, str], str] = {}
    occurrence_records: dict[tuple[int, str], dict[str, Any]] = {}
    occurrence_bindings: dict[tuple[int, str, str], str] = {}
    effective_occurrence_bindings: dict[tuple[int, str, str], str] = {}
    total_entries = 0
    ordering: list[tuple[int, str]] = []
    for installation in value:
        if not isinstance(installation, dict) or set(installation) != {
            "owner",
            "metadata",
            "wheel",
            "record",
            "root_is_purelib",
            "build",
            "tags",
            "entries",
        }:
            raise EvidenceError("component inventory has invalid historical Python installation")
        owner = installation.get("owner")
        component = python_components.get(owner) if isinstance(owner, str) else None
        if component is None:
            raise EvidenceError("historical Python installation has an unknown owner")
        if not isinstance(installation.get("root_is_purelib"), bool):
            raise EvidenceError("historical Python installation has invalid purelib state")
        build = installation.get("build")
        if not isinstance(build, str) or (
            build and re.fullmatch(r"[0-9]+[A-Za-z0-9_.]*", build) is None
        ):
            raise EvidenceError("historical Python installation has an invalid build tag")
        tags = installation.get("tags")
        if (
            not isinstance(tags, list)
            or not 1 <= len(tags) <= 100
            or any(not isinstance(tag, str) or WHEEL_TAG.fullmatch(tag) is None for tag in tags)
            or tags != sorted(set(tags))
        ):
            raise EvidenceError("historical Python installation has invalid wheel tags")

        identities: dict[str, dict[str, Any]] = {}
        for field in ("metadata", "wheel", "record"):
            identity = installation.get(field)
            validated = validate_payload_records(
                [identity], f"historical Python installation {field}"
            )
            identities[field] = validated[0]
            key = (validated[0]["layer"], validated[0]["path"])
            if occurrence_payloads is not None and occurrence_payloads.get(key) != validated[0]:
                raise EvidenceError(
                    f"historical Python installation {field} does not match all-layer inventory"
                )

        record = identities["record"]
        record_key = (record["layer"], record["path"])
        if record_key in seen_records:
            raise EvidenceError("component inventory repeats a historical Python RECORD")
        seen_records.add(record_key)
        ordering.append(record_key)
        record_path = str(record["path"])
        if not is_venv_record_path(record_path):
            raise EvidenceError("historical Python installation has an invalid RECORD path")
        dist_info = PurePosixPath(record_path).parent
        metadata_path = (dist_info / "METADATA").as_posix()
        wheel_path = (dist_info / "WHEEL").as_posix()
        if (
            identities["metadata"]["path"] != metadata_path
            or identities["wheel"]["path"] != wheel_path
            or identities["metadata"]["sha256"] != component.get("metadata_sha256")
        ):
            raise EvidenceError("historical Python installation has conflicting identity files")
        if record["effective"] is True:
            if owner in active_owners:
                raise EvidenceError("component inventory repeats an active Python owner")
            active_owners.add(str(owner))
            if (
                component.get("effective") is not True
                or identities["metadata"]["effective"] is not True
                or identities["wheel"]["effective"] is not True
            ):
                raise EvidenceError("active Python RECORD has ineffective identity files")

        entries = installation.get("entries")
        if not isinstance(entries, list) or not entries:
            raise EvidenceError("historical Python installation has invalid RECORD entries")
        total_entries += len(entries)
        if total_entries > MAX_HISTORICAL_RECORD_ENTRIES:
            raise EvidenceError("historical Python RECORD entries exceed their limit")
        seen_paths: set[str] = set()
        observed_order: list[str] = []
        entry_occurrences: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "path",
                "recorded_sha256",
                "recorded_size",
                "occurrence",
            }:
                raise EvidenceError("historical Python installation has invalid RECORD entry")
            path_value = entry.get("path")
            if not isinstance(path_value, str) or not path_value.startswith("opt/venv/"):
                raise EvidenceError("historical Python RECORD entry has an invalid path")
            path = str(checked_canonical_path(path_value, "historical Python RECORD entry path"))
            if path in seen_paths:
                raise EvidenceError("historical Python RECORD repeats a normalized path")
            seen_paths.add(path)
            observed_order.append(path)
            occurrence = validate_payload_records(
                [entry.get("occurrence")], "historical Python RECORD entry occurrence"
            )[0]
            if occurrence["path"] != path:
                raise EvidenceError("historical Python RECORD entry path does not match occurrence")
            key = (occurrence["layer"], path)
            if occurrence_payloads is not None and occurrence_payloads.get(key) != occurrence:
                raise EvidenceError(
                    "historical Python RECORD entry does not match all-layer inventory"
                )
            previous_owner = occurrence_owners.get(key)
            if previous_owner is not None and previous_owner != owner:
                raise EvidenceError("historical Python RECORD occurrence has conflicting owners")
            previous_occurrence = occurrence_records.get(key)
            if previous_occurrence is not None and previous_occurrence != occurrence:
                raise EvidenceError("historical Python RECORD occurrence has conflicting identity")
            occurrence_owners[key] = str(owner)
            occurrence_records[key] = occurrence
            occurrence_identity = (occurrence["layer"], path, occurrence["sha256"])
            occurrence_bindings[occurrence_identity] = str(owner)
            if record["effective"] is True:
                effective_occurrence_bindings[occurrence_identity] = str(owner)
            recorded_hash = entry.get("recorded_sha256")
            recorded_size = entry.get("recorded_size")
            if path == record_path:
                if recorded_hash is not None or recorded_size is not None:
                    raise EvidenceError("historical Python RECORD self-entry has an identity")
            elif (
                not isinstance(recorded_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", recorded_hash) is None
                or not isinstance(recorded_size, int)
                or isinstance(recorded_size, bool)
                or not 0 <= recorded_size <= MAX_ARCHIVE_MEMBER_BYTES
                or occurrence["sha256"] != recorded_hash
                or occurrence["size"] != recorded_size
            ):
                raise EvidenceError("historical Python RECORD entry has conflicting identity")
            entry_occurrences[path] = occurrence
        if record["effective"] is True and any(
            occurrence["effective"] is not True for occurrence in entry_occurrences.values()
        ):
            raise EvidenceError("active Python RECORD has an ineffective owned occurrence")
        if observed_order != sorted(observed_order):
            raise EvidenceError("historical Python RECORD entries are not normalized")
        if not {metadata_path, wheel_path, record_path}.issubset(entry_occurrences):
            raise EvidenceError("historical Python RECORD omits its identity entries")
        for field, path in (
            ("metadata", metadata_path),
            ("wheel", wheel_path),
            ("record", record_path),
        ):
            if entry_occurrences[path] != identities[field]:
                raise EvidenceError(
                    f"historical Python RECORD {field} entry has a conflicting occurrence"
                )
    if ordering != sorted(ordering):
        raise EvidenceError("historical Python installations are not normalized")
    return occurrence_bindings, effective_occurrence_bindings


def validate_component_inventory(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Validate the standalone component inventory without trusting a companion file list."""

    require_schema(inventory, "component inventory")
    expected_fields = {
        "schema_version",
        "platform",
        "subject_digest",
        "image_config_digest",
        "image_revision",
        "image_version",
        "application_wheel_sha256",
        "application_selection_record_sha256",
        "apk_database_sha256",
        "apk_database_occurrences",
        "components",
        "embedded_sboms",
        "native_payloads",
        "wheel_identity_files",
        "wheel_installations",
        "python_record_ownership",
    }
    require_exact_fields(inventory, expected_fields, "component inventory")
    platform = inventory.get("platform")
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise EvidenceError("component inventory has an unsupported platform")
    for field in ("subject_digest", "image_config_digest"):
        value = inventory.get(field)
        if not isinstance(value, str) or SHA256.fullmatch(value) is None:
            raise EvidenceError(f"component inventory has an invalid {field}")
    revision = inventory.get("image_revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise EvidenceError("component inventory has an invalid image revision")
    version = inventory.get("image_version")
    if not isinstance(version, str):
        raise EvidenceError("component inventory has an invalid image version")
    checked_scalar(version, "component inventory image version")
    for field in (
        "application_wheel_sha256",
        "application_selection_record_sha256",
    ):
        value = inventory.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise EvidenceError(f"component inventory has an invalid {field}")
    apk_digest = inventory.get("apk_database_sha256")
    if not isinstance(apk_digest, str) or re.fullmatch(r"[0-9a-f]{64}", apk_digest) is None:
        raise EvidenceError("component inventory has an invalid APK database digest")
    components = validate_component_records(inventory.get("components"), "component inventory")
    validate_platform_component_invariants(components, str(platform), "component inventory")
    for category in ("apk_database_occurrences", "wheel_identity_files"):
        validate_payload_records(inventory.get(category), f"component inventory {category}")
    historical_occurrences, effective_historical_occurrences = validate_wheel_installations(
        inventory.get("wheel_installations"), components
    )
    python_owner_names = {
        component_key(component): str(component["name"])
        for component in components
        if component.get("ecosystem") == "python"
    }
    python_component_owners = {
        component_key(component)
        for component in components
        if component.get("ecosystem") == "python"
    }
    embedded_sboms = validate_structured_python_payloads(
        inventory.get("embedded_sboms"),
        "component inventory embedded_sboms",
        identity_field="cyclonedx",
        platform=str(platform),
        component_owners=python_component_owners,
    )
    if any(DIST_INFO_SBOM.search(record["path"]) is None for record in embedded_sboms):
        raise EvidenceError("component inventory has an SBOM outside wheel SBOM directories")
    native_payloads = validate_structured_python_payloads(
        inventory.get("native_payloads"),
        "component inventory native_payloads",
        identity_field="elf",
        platform=str(platform),
        component_owners=python_component_owners,
    )
    if any(not is_python_virtual_environment_path(record["path"]) for record in native_payloads):
        raise EvidenceError("component inventory has a native payload outside /opt/venv")
    ownership = inventory.get("python_record_ownership")
    if not isinstance(ownership, list) or len(ownership) > MAX_RECORD_ENTRIES:
        raise EvidenceError("component inventory has invalid Python RECORD ownership")
    owned_paths: set[str] = set()
    effective_python_names = {
        component["name"]
        for component in components
        if component.get("ecosystem") == "python" and component.get("effective") is True
    }
    for record in ownership:
        if not isinstance(record, dict) or set(record) != {
            "owner",
            "effective",
            "layer",
            "path",
            "sha256",
            "size",
            "mode",
            "uid",
            "gid",
        }:
            raise EvidenceError("component inventory has invalid Python RECORD ownership")
        owner = record.get("owner")
        path_value = record.get("path")
        if (
            not isinstance(owner, str)
            or owner not in effective_python_names
            or not isinstance(path_value, str)
            or not path_value.startswith("opt/venv/")
            or record.get("effective") is not True
        ):
            raise EvidenceError("component inventory has invalid Python RECORD ownership")
        path = str(
            checked_canonical_path(path_value, "component inventory Python RECORD ownership path")
        )
        if path in owned_paths:
            raise EvidenceError("component inventory repeats Python RECORD ownership")
        owned_paths.add(path)
        validate_payload_records(
            [{field: record[field] for field in record if field != "owner"}],
            "component inventory Python RECORD ownership",
        )
        occurrence = (record["layer"], path, record["sha256"])
        if python_owner_names.get(effective_historical_occurrences.get(occurrence, "")) != owner:
            raise EvidenceError(
                "Python RECORD ownership is not linked to its effective historical claim"
            )
    observed_ownership_occurrences = {
        (record["layer"], record["path"], record["sha256"])
        for record in ownership
        if isinstance(record, dict)
    }
    if observed_ownership_occurrences != set(effective_historical_occurrences):
        raise EvidenceError("Python RECORD ownership omits an effective historical claim")
    for payload in (*embedded_sboms, *native_payloads):
        occurrence = (payload["layer"], payload["path"], payload["sha256"])
        if historical_occurrences.get(occurrence) != payload["owner"]:
            raise EvidenceError(
                "structured Python payload is not linked to its RECORD ownership occurrence"
            )
    apk_occurrences = inventory["apk_database_occurrences"]
    apk_matches = [
        record
        for record in apk_occurrences
        if record["effective"] is True and record["sha256"] == apk_digest
    ]
    if len(apk_matches) != 1:
        raise EvidenceError(
            "component inventory APK digest does not identify one effective occurrence"
        )
    return components


def validate_standard_license_text_coverage(
    components: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]
) -> None:
    """Require the exact standard texts used by top-level and direct reviews."""

    reviewed_expressions = [resolved_license(component, policy) for component in components]
    raw_native_coverage = policy.get("native_component_coverage")
    if not isinstance(raw_native_coverage, dict):
        raise EvidenceError("policy has invalid native-component coverage")
    for platform_records in raw_native_coverage.values():
        if not isinstance(platform_records, list):
            raise EvidenceError("policy has invalid native-component coverage")
        for owner_record in platform_records:
            if not isinstance(owner_record, dict):
                raise EvidenceError("policy has invalid native-component coverage")
            component_reviews = owner_record.get("component_reviews")
            if not isinstance(component_reviews, list):
                raise EvidenceError("policy has invalid native-component reviews")
            for component_review in component_reviews:
                if not isinstance(component_review, dict) or not isinstance(
                    component_review.get("reviewed_license"), str
                ):
                    raise EvidenceError("policy has invalid native-component review license")
                reviewed_expressions.append(component_review["reviewed_license"])

    required_license_texts = {
        token
        for expression in reviewed_expressions
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression)
        if token not in {"AND", "OR", "WITH"} and not token.startswith("LicenseRef-")
    }
    license_texts = policy.get("license_texts")
    if not isinstance(license_texts, list):
        raise EvidenceError("policy has no reviewed license texts")
    configured_license_ids: set[str] = set()
    for entry in license_texts:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise EvidenceError("policy has an invalid license text record")
        identifier = entry["id"]
        if identifier in configured_license_ids:
            raise EvidenceError(f"policy repeats standard license text: {identifier}")
        configured_license_ids.add(identifier)
    if configured_license_ids != required_license_texts:
        raise EvidenceError(
            "standard license-text policy does not exactly cover reviewed identifiers"
        )


def verify_inventory(
    inventory: Mapping[str, Any], policy: Mapping[str, Any], *, require_approval: bool
) -> None:
    actual = validate_component_inventory(inventory)
    validate_policy_schema(policy)
    platform = inventory.get("platform")
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise EvidenceError("inventory platform is unsupported")
    expected = policy_components(policy, platform)
    if canonical_json(sorted(actual, key=component_sort_key)) != canonical_json(expected):
        raise EvidenceError(
            "component/license inventory differs from the reviewed policy; "
            "inspect the normalized diff and review every change"
        )
    verify_unexpanded_payload_policy(inventory, policy)
    native_coverage = native_component_coverage_ledger(inventory, policy)
    verify_apk_database_baseline(inventory, policy)
    actual_keys = {component_key(component) for component in actual}
    resolutions = policy.get("license_resolutions")
    if not isinstance(resolutions, dict) or set(resolutions) != actual_keys:
        raise EvidenceError(
            "reviewed license resolutions do not exactly cover the component inventory"
        )
    validate_standard_license_text_coverage(actual, policy)
    validated_custom_license_evidence(actual, policy)
    expected_base = policy.get("base_image_index_digest")
    if not isinstance(expected_base, str) or not SHA256.fullmatch(expected_base):
        raise EvidenceError("policy base image index digest is invalid")
    approval = policy.get("distribution_approval")
    if not isinstance(approval, dict):
        raise EvidenceError("policy has no distribution approval record")
    if approval.get("approved") is True and native_coverage["complete"] is not True:
        raise EvidenceError(
            "distribution approval cannot be true while native-component coverage is incomplete"
        )
    if require_approval:
        if approval.get("approved") is not True:
            raise EvidenceError(
                "recipient distribution mechanism has not received explicit maintainer approval"
            )
        for field in ("approved_by", "approved_on", "rationale"):
            if not isinstance(approval.get(field), str) or not approval[field].strip():
                raise EvidenceError(f"distribution approval is missing {field}")


def verify_image_revision(
    inventory: Mapping[str, Any], *, version: str, source_revision: str
) -> None:
    revision = inventory.get("image_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise EvidenceError("release image has no exact 40-character source revision label")
    if revision != source_revision:
        raise EvidenceError(
            f"image revision {revision} does not match source revision {source_revision}"
        )
    if inventory.get("image_version") != version:
        raise EvidenceError(
            f"image version {inventory.get('image_version')!r} does not match {version!r}"
        )


def verify_application_artifact_labels(
    inventory: Mapping[str, Any],
    *,
    source_revision: str,
    wheel_sha256: str,
    selection_record_sha256: str,
) -> None:
    """Bind stable image labels to one selected application proof."""

    if re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        raise EvidenceError("application source revision must be a lowercase Git SHA-1")
    for value, description in (
        (wheel_sha256, "application wheel digest"),
        (selection_record_sha256, "application selection-record digest"),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise EvidenceError(f"{description} must be a lowercase SHA-256 digest")
    expected = {
        "image_revision": source_revision,
        "application_wheel_sha256": wheel_sha256,
        "application_selection_record_sha256": selection_record_sha256,
    }
    for field, value in expected.items():
        if inventory.get(field) != value:
            raise EvidenceError(f"image {field} label does not match selected application proof")


def validate_selected_installation_contract(value: object) -> list[dict[str, Any]]:
    """Validate exact installed layouts emitted by the selected-wheel verifier."""

    contract = require_exact_fields(
        value,
        {
            "environment_root",
            "project",
            "version",
            "python_directory",
            "alternatives",
        },
        "selected installation contract",
    )
    if (
        contract["environment_root"] != "/opt/venv"
        or contract["project"] != APPLICATION_NAME
        or contract["python_directory"] != "python3.14"
        or not isinstance(contract["version"], str)
    ):
        raise EvidenceError("selected installation contract has the wrong identity")
    checked_scalar(contract["version"], "selected installation version")
    alternatives = contract["alternatives"]
    if not isinstance(alternatives, list) or len(alternatives) != 3:
        raise EvidenceError("selected installation contract has invalid alternatives")
    expected_interpreters = ("python", "python3", "python3.14")
    normalized: list[dict[str, Any]] = []
    for index, alternative in enumerate(alternatives):
        record = require_exact_fields(
            alternative,
            {"launcher_interpreter", "files"},
            "selected installation alternative",
        )
        if record["launcher_interpreter"] != expected_interpreters[index]:
            raise EvidenceError("selected installation alternatives have the wrong identity")
        files = record["files"]
        if not isinstance(files, list) or not 1 <= len(files) <= MAX_RECORD_ENTRIES:
            raise EvidenceError("selected installation alternative has an invalid file list")
        checked_files: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in files:
            selected = require_exact_fields(
                item,
                {"path", "sha256", "size", "mode"},
                "selected installed file",
            )
            path_value = selected["path"]
            digest = selected["sha256"]
            size = selected["size"]
            mode = selected["mode"]
            if not isinstance(path_value, str):
                raise EvidenceError("selected installed file has no path")
            path = str(checked_canonical_path(path_value, "selected installed application path"))
            if (
                path in seen
                or not path.startswith(("lib/python3.14/site-packages/", "bin/"))
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or not isinstance(size, int)
                or isinstance(size, bool)
                or not 0 <= size <= MAX_ARCHIVE_MEMBER_BYTES
                or mode not in {0o644, 0o755}
                or (path.startswith("bin/")) != (mode == 0o755)
            ):
                raise EvidenceError("selected installation alternative has an invalid file")
            seen.add(path)
            checked_files.append({"path": path, "sha256": digest, "size": size, "mode": mode})
        if checked_files != sorted(checked_files, key=lambda item: item["path"]):
            raise EvidenceError("selected installation files are not canonically ordered")
        normalized.append(
            {
                "launcher_interpreter": expected_interpreters[index],
                "files": checked_files,
            }
        )
    return normalized


def verify_selected_application_installation(
    inventory: Mapping[str, Any], installation: object
) -> str:
    """Match every distributed application installation to a verified wheel layout."""

    alternatives = validate_selected_installation_contract(installation)
    contract = installation
    if not isinstance(contract, dict):
        raise EvidenceError("selected installation contract is not an object")
    version = contract["version"]
    matching_components = [
        component
        for component in inventory.get("components", [])
        if component.get("ecosystem") == "python"
        and component.get("name") == APPLICATION_NAME
        and component.get("version") == version
        and component.get("effective") is True
    ]
    if len(matching_components) != 1:
        raise EvidenceError("selected wheel does not match one effective application component")

    historical = inventory.get("wheel_installations")
    if historical is not None:
        if not isinstance(historical, list):
            raise EvidenceError("component inventory has invalid historical Python installations")
        expected_owner = f"python:{APPLICATION_NAME}@{version}"
        application_installations: list[Mapping[str, Any]] = []
        for item in historical:
            if not isinstance(item, dict):
                raise EvidenceError(
                    "component inventory has invalid historical Python installation"
                )
            owner = item.get("owner")
            if isinstance(owner, str) and owner.startswith(f"python:{APPLICATION_NAME}@"):
                if owner != expected_owner:
                    raise EvidenceError(
                        "distributed application installation differs from the selected version"
                    )
                application_installations.append(item)
        if not application_installations:
            raise EvidenceError("component inventory has no selected application installation")
        active_interpreters: list[str] = []
        for item in application_installations:
            entries = item.get("entries")
            if not isinstance(entries, list):
                raise EvidenceError("application installation has invalid RECORD entries")
            occurrence_files: list[dict[str, Any]] = []
            for entry in entries:
                occurrence = entry.get("occurrence") if isinstance(entry, dict) else None
                if not isinstance(occurrence, dict):
                    raise EvidenceError("application installation has invalid RECORD occurrence")
                path_value = occurrence.get("path")
                if (
                    not isinstance(path_value, str)
                    or not path_value.startswith("opt/venv/")
                    or occurrence.get("uid") != 0
                    or occurrence.get("gid") != 0
                ):
                    raise EvidenceError(
                        "application RECORD occurrence has an invalid runtime identity"
                    )
                occurrence_files.append(
                    {
                        "path": path_value.removeprefix("opt/venv/"),
                        "sha256": occurrence.get("sha256"),
                        "size": occurrence.get("size"),
                        "mode": occurrence.get("mode"),
                    }
                )
            occurrence_files.sort(key=lambda candidate: str(candidate["path"]))
            interpreter = next(
                (
                    str(alternative["launcher_interpreter"])
                    for alternative in alternatives
                    if canonical_json(occurrence_files) == canonical_json(alternative["files"])
                ),
                None,
            )
            if interpreter is None:
                raise EvidenceError(
                    "distributed application installation differs from every selected-wheel layout"
                )
            record = item.get("record")
            if isinstance(record, dict) and record.get("effective") is True:
                active_interpreters.append(interpreter)
        if len(active_interpreters) != 1:
            raise EvidenceError(
                "selected wheel does not identify one effective application installation"
            )
        return active_interpreters[0]

    ownership = inventory.get("python_record_ownership")
    if not isinstance(ownership, list):
        raise EvidenceError("component inventory has no Python RECORD ownership")
    actual: list[dict[str, Any]] = []
    for item in ownership:
        if not isinstance(item, dict) or item.get("owner") != APPLICATION_NAME:
            continue
        path_value = item.get("path")
        if (
            not isinstance(path_value, str)
            or not path_value.startswith("opt/venv/")
            or item.get("effective") is not True
            or item.get("uid") != 0
            or item.get("gid") != 0
        ):
            raise EvidenceError("application RECORD ownership has an invalid runtime identity")
        actual.append(
            {
                "path": path_value.removeprefix("opt/venv/"),
                "sha256": item.get("sha256"),
                "size": item.get("size"),
                "mode": item.get("mode"),
            }
        )
    actual.sort(key=lambda item: str(item["path"]))
    for alternative in alternatives:
        if canonical_json(actual) == canonical_json(alternative["files"]):
            return str(alternative["launcher_interpreter"])
    raise EvidenceError(
        "effective application installation differs from every selected-wheel layout"
    )


def read_retained_regular_file(path: Path, *, max_bytes: int) -> bytes:
    """Read one retained proof file without following a link or blocking on a FIFO."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise EvidenceError("selected proof retention requires O_NOFOLLOW support")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 <= metadata.st_size <= max_bytes:
            raise EvidenceError(f"retained selected proof file is not bounded and regular: {path}")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            content = source.read(max_bytes + 1)
    except OSError as exc:
        raise EvidenceError(f"cannot read retained selected proof file {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > max_bytes:
        raise EvidenceError(f"retained selected proof file exceeds its limit: {path}")
    return content


def retain_selected_application_artifacts(
    *,
    directory: Path,
    output: Path,
    source_revision: str,
    wheel_sha256: str,
    selection_record_sha256: str,
    budget: BundleBudget,
    pass_fds: Sequence[int] = (),
) -> tuple[dict[str, Any], object]:
    """Use the Python verifier to retain and describe the exact five-file proof."""

    helper = SCRIPT_DIRECTORY / "build_python_artifacts.py"
    raw_result = run(
        [
            sys.executable,
            str(helper),
            "retain-selection",
            "--directory",
            str(directory),
            "--output",
            str(output),
            "--source-revision",
            source_revision,
            "--wheel-sha256",
            wheel_sha256,
            "--selection-record-sha256",
            selection_record_sha256,
        ],
        cwd=SCRIPT_DIRECTORY,
        max_output_bytes=MAX_SELECTED_HELPER_OUTPUT_BYTES,
        pass_fds=pass_fds,
    )
    parsed = strict_json_loads(raw_result, "selected Python retention helper")
    if (
        not isinstance(parsed, dict)
        or raw_result
        != compact_canonical_json(parsed, max_bytes=MAX_SELECTED_HELPER_OUTPUT_BYTES - 1) + b"\n"
    ):
        raise EvidenceError("selected Python retention helper returned noncanonical JSON")
    if type(parsed.get("schema_version")) is not int or parsed["schema_version"] != 1:
        raise EvidenceError("selected Python retention result has an unsupported schema")
    result = require_exact_fields(
        parsed,
        {
            "schema_version",
            "source_revision",
            "selection_record_sha256",
            "wheel_filename",
            "wheel_sha256",
            "sdist_filename",
            "sdist_sha256",
            "files",
            "installation",
        },
        "selected Python retention result",
    )
    if (
        result["source_revision"] != source_revision
        or result["wheel_sha256"] != wheel_sha256
        or result["selection_record_sha256"] != selection_record_sha256
    ):
        raise EvidenceError("selected Python retention result has the wrong identity")
    for field, suffix in (("wheel_filename", ".whl"), ("sdist_filename", ".tar.gz")):
        value = result[field]
        if (
            not isinstance(value, str)
            or len(checked_canonical_path(value, f"selected Python {field}").parts) != 1
            or not value.endswith(suffix)
        ):
            raise EvidenceError(f"selected Python retention result has an invalid {field}")
    sdist_sha256 = result["sdist_sha256"]
    if not isinstance(sdist_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sdist_sha256) is None:
        raise EvidenceError("selected Python retention result has an invalid sdist digest")
    files = result["files"]
    if not isinstance(files, list) or len(files) != 5:
        raise EvidenceError("selected Python retention result must describe exactly five files")
    expected_names: set[str] = set()
    manifest_files: list[dict[str, Any]] = []
    for item in files:
        record = require_exact_fields(
            item,
            {"filename", "sha256", "size"},
            "selected Python retained file",
        )
        filename = record["filename"]
        digest = record["sha256"]
        size = record["size"]
        if not isinstance(filename, str):
            raise EvidenceError("selected Python retained file has no filename")
        path = checked_canonical_path(filename, "selected Python retained filename")
        if (
            len(path.parts) != 1
            or filename in expected_names
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_ARCHIVE_MEMBER_BYTES
        ):
            raise EvidenceError("selected Python retention result has an invalid file")
        expected_names.add(filename)
        retained = output / filename
        content = read_retained_regular_file(retained, max_bytes=MAX_ARCHIVE_MEMBER_BYTES)
        if len(content) != size or sha256_bytes(content) != digest:
            raise EvidenceError("retained selected Python proof differs from its canonical hash")
        budget.record_retained(content)
        manifest_files.append(
            {
                "path": f"artifacts/application/{filename}",
                "sha256": digest,
                "size": size,
            }
        )
    try:
        actual_names = {entry.name for entry in os.scandir(output)}
    except OSError as exc:
        raise EvidenceError("cannot enumerate retained selected Python proof") from exc
    if actual_names != expected_names:
        raise EvidenceError("retained selected Python proof does not contain exactly five files")
    required_names = {
        str(result["wheel_filename"]),
        str(result["sdist_filename"]),
        "python-build-record-amd64.json",
        "python-build-record-arm64.json",
        "python-selection-record.json",
    }
    if expected_names != required_names:
        raise EvidenceError("selected Python proof does not have the exact five-file identity")
    file_digests = {Path(record["path"]).name: record["sha256"] for record in manifest_files}
    if (
        file_digests[result["wheel_filename"]] != wheel_sha256
        or file_digests[result["sdist_filename"]] != sdist_sha256
        or file_digests["python-selection-record.json"] != selection_record_sha256
    ):
        raise EvidenceError("selected Python proof artifact identities disagree")
    manifest_files.sort(key=lambda item: item["path"])
    binding = {
        "source_revision": source_revision,
        "wheel_sha256": wheel_sha256,
        "selection_record_sha256": selection_record_sha256,
        "files": manifest_files,
    }
    return binding, result["installation"]


def verify_base_layer_binding(files: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    """Require the final image to begin with the reviewed platform base layers."""

    platform = files.get("platform")
    platforms = policy.get("base_image_platforms")
    if not isinstance(platforms, dict) or set(platforms) != {
        "linux/amd64",
        "linux/arm64",
    }:
        raise EvidenceError("policy must pin both supported base-image platforms")
    reviewed = platforms.get(platform)
    if not isinstance(reviewed, dict) or set(reviewed) != {"layer_diff_ids"}:
        raise EvidenceError(f"invalid reviewed base-image platform policy: {platform!r}")
    expected_layers = reviewed["layer_diff_ids"]
    if (
        not isinstance(expected_layers, list)
        or not expected_layers
        or not all(isinstance(item, str) and SHA256.fullmatch(item) for item in expected_layers)
        or len(set(expected_layers)) != len(expected_layers)
    ):
        raise EvidenceError(f"invalid reviewed base-image layer list: {platform!r}")
    layers = files.get("layers")
    if not isinstance(layers, list) or not all(isinstance(item, dict) for item in layers):
        raise EvidenceError("all-layer inventory has no valid layer list")
    observed_layers = [item.get("digest") for item in layers]
    if observed_layers[: len(expected_layers)] != expected_layers:
        raise EvidenceError(
            f"final image layers do not begin with the reviewed {platform} base image"
        )


def validate_removal_policy(value: object, platform: object) -> list[dict[str, Any]]:
    """Validate semantic removals without retaining non-filesystem marker metadata."""

    if not isinstance(value, list) or len(value) > MAX_IMAGE_MEMBERS:
        raise EvidenceError(f"invalid post-base removal policy for {platform!r}")
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record in value:
        if not isinstance(record, dict) or set(record) != {"kind", "path", "target"}:
            raise EvidenceError(f"invalid post-base removal policy for {platform!r}")
        kind = record.get("kind")
        path_value = record.get("path")
        target_value = record.get("target")
        if (
            kind not in {"whiteout", "opaque"}
            or not isinstance(path_value, str)
            or not isinstance(target_value, str)
        ):
            raise EvidenceError(f"invalid post-base removal policy for {platform!r}")
        path = checked_canonical_path(path_value, f"post-base removal policy path for {platform!r}")
        if kind == "whiteout":
            target = checked_canonical_path(
                target_value, f"post-base removal policy target for {platform!r}"
            )
            valid = path.name == f".wh.{target.name}" and path.parent == target.parent
        else:
            valid = path.name == ".wh..wh..opq" and target_value == str(path.parent)
        if not valid:
            raise EvidenceError(f"invalid post-base removal policy for {platform!r}")
        identity = (kind, str(path))
        if identity in seen:
            raise EvidenceError(f"duplicate post-base removal policy for {platform!r}")
        seen.add(identity)
        records.append({"kind": kind, "path": str(path), "target": target_value})
    return sorted(records, key=lambda item: (item["path"], item["kind"], item["target"]))


def validate_directory_effect_policy(value: object, platform: object) -> list[dict[str, Any]]:
    """Validate effectful post-base directory metadata transitions."""

    if not isinstance(value, list) or len(value) > MAX_IMAGE_MEMBERS:
        raise EvidenceError(f"invalid post-base directory-effect policy for {platform!r}")
    records: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for record in value:
        if not isinstance(record, dict) or set(record) != {
            "layer",
            "path",
            "mode",
            "uid",
            "gid",
        }:
            raise EvidenceError(f"invalid post-base directory-effect policy for {platform!r}")
        layer = record.get("layer")
        path_value = record.get("path")
        if (
            not isinstance(layer, int)
            or isinstance(layer, bool)
            or layer < 0
            or not isinstance(path_value, str)
        ):
            raise EvidenceError(f"invalid post-base directory-effect policy for {platform!r}")
        path = str(
            checked_canonical_path(
                path_value, f"post-base directory-effect policy path for {platform!r}"
            )
        )
        validate_header_identity(record, f"post-base directory-effect policy for {platform!r}")
        if record.get("uid") != 0 or record.get("gid") != 0 or record.get("mode") != 0o755:
            raise EvidenceError("post-base directories must be root-owned with mode 0o0755")
        identity = (layer, path)
        if identity in seen:
            raise EvidenceError(f"duplicate post-base directory-effect policy for {platform!r}")
        seen.add(identity)
        records.append({field: record[field] for field in ("layer", "path", "mode", "uid", "gid")})
    return sorted(records, key=lambda item: (item["layer"], item["path"]))


def canonical_post_base_filesystem_changes(
    files: Mapping[str, Any], base_layer_count: int, platform: object
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Replay layer state and retain only effectful directory changes and removals."""

    layers = files.get("layers")
    if (
        not isinstance(layers, list)
        or not isinstance(base_layer_count, int)
        or isinstance(base_layer_count, bool)
        or not 0 <= base_layer_count <= len(layers)
    ):
        raise EvidenceError(f"invalid post-base filesystem state for {platform!r}")

    categories = {
        "directory": files.get("directories"),
        "regular": files.get("regular_files"),
        "non-regular": files.get("non_regular_files"),
        "removal": files.get("whiteouts"),
    }
    grouped: dict[str, list[list[Mapping[str, Any]]]] = {
        kind: [[] for _ in layers] for kind in categories
    }
    total_records = 0
    for kind, value in categories.items():
        if not isinstance(value, list) or len(value) > MAX_IMAGE_MEMBERS:
            raise EvidenceError(f"invalid post-base filesystem {kind} records for {platform!r}")
        total_records += len(value)
        if total_records > MAX_IMAGE_MEMBERS:
            raise EvidenceError(f"post-base filesystem records exceed the limit for {platform!r}")
        for record in value:
            if not isinstance(record, dict):
                raise EvidenceError(f"invalid post-base filesystem {kind} record for {platform!r}")
            layer = record.get("layer")
            if (
                not isinstance(layer, int)
                or isinstance(layer, bool)
                or not 0 <= layer < len(layers)
            ):
                raise EvidenceError(f"invalid post-base filesystem {kind} layer for {platform!r}")
            grouped[kind][layer].append(record)

    state: dict[str, dict[str, Any]] = {}
    directory_effects: list[dict[str, Any]] = []
    removals: list[dict[str, Any]] = []

    def remove_state(target: str) -> None:
        for candidate in list(state):
            if candidate == target or candidate.startswith(f"{target}/"):
                state.pop(candidate, None)

    def ensure_parents(path: PurePosixPath, *, allow_implicit: bool) -> None:
        for parent in reversed([item for item in path.parents if str(item) != "."]):
            parent_text = str(parent)
            existing = state.get(parent_text)
            if existing is not None and existing["kind"] != "directory":
                raise EvidenceError(
                    "filesystem entry traverses a non-directory ancestor during semantic replay: "
                    f"{path} through {parent_text}"
                )
            if existing is None:
                if not allow_implicit:
                    raise EvidenceError(
                        "post-base filesystem entry has an implicit parent directory: "
                        f"{path} through {parent_text}"
                    )
                # Extraction creates missing parents. Their metadata was not an
                # explicit layer header, so it cannot make a later explicit
                # directory assertion a semantic no-op.
                state[parent_text] = {"kind": "directory"}

    for layer_index in range(len(layers)):
        lower_layer_state = dict(state)
        layer_removals: list[dict[str, Any]] = []
        for marker in grouped["removal"][layer_index]:
            validate_header_identity(marker, "all-layer removal marker")
            try:
                semantic = {field: marker[field] for field in ("kind", "path", "target")}
            except KeyError as exc:
                raise EvidenceError("all-layer removal marker is incomplete") from exc
            validated = validate_removal_policy([semantic], platform)[0]
            target = validated["target"]
            if validated["kind"] == "whiteout":
                if target not in lower_layer_state:
                    raise EvidenceError(
                        f"OCI whiteout target is absent from lower layers: {target}"
                    )
            else:
                prefix = "" if target == "." else f"{target}/"
                if not any(candidate.startswith(prefix) for candidate in lower_layer_state):
                    raise EvidenceError(
                        f"OCI opaque whiteout does not remove any lower-layer entries: {target}"
                    )
            layer_removals.append(validated)

        for removal in layer_removals:
            target = removal["target"]
            if removal["kind"] == "opaque":
                prefix = "" if target == "." else f"{target}/"
                for candidate in list(state):
                    if candidate.startswith(prefix):
                        state.pop(candidate, None)
            else:
                remove_state(target)
            if layer_index >= base_layer_count:
                removals.append(removal)

        ordinary: list[tuple[str, Mapping[str, Any]]] = [
            (kind, record)
            for kind in ("directory", "regular", "non-regular")
            for record in grouped[kind][layer_index]
        ]
        seen_paths: set[str] = set()
        non_directory_paths: set[str] = set()
        normalized: list[tuple[str, PurePosixPath, Mapping[str, Any]]] = []
        for kind, record in ordinary:
            path_value = record.get("path")
            if not isinstance(path_value, str):
                raise EvidenceError("all-layer filesystem entry has no path")
            path = checked_canonical_path(path_value, "all-layer filesystem entry path")
            path_text = str(path)
            if path_text in seen_paths:
                raise EvidenceError(
                    f"all-layer inventory repeats a path across entry kinds: {path_text}"
                )
            seen_paths.add(path_text)
            if kind != "directory":
                non_directory_paths.add(path_text)
            normalized.append((kind, path, record))

        for _kind, path, _record in normalized:
            if any(str(parent) in non_directory_paths for parent in path.parents):
                raise EvidenceError(
                    f"one image layer contains a non-directory ancestor and descendant: {path}"
                )

        directories = sorted(
            (item for item in normalized if item[0] == "directory"),
            key=lambda item: (len(item[1].parts), str(item[1])),
        )
        for _kind, path, record in directories:
            validate_header_identity(record, "all-layer directory")
            path_text = str(path)
            ensure_parents(path, allow_implicit=layer_index < base_layer_count)
            metadata = {
                "mode": record["mode"],
                "uid": record["uid"],
                "gid": record["gid"],
            }
            if layer_index >= base_layer_count and (
                metadata["mode"] != 0o755 or metadata["uid"] != 0 or metadata["gid"] != 0
            ):
                raise EvidenceError("post-base directories must be root-owned with mode 0o0755")
            existing = state.get(path_text)
            is_noop = existing == {"kind": "directory", **metadata}
            if existing is not None and existing.get("kind") != "directory":
                remove_state(path_text)
            state[path_text] = {"kind": "directory", **metadata}
            if layer_index >= base_layer_count and not is_noop:
                directory_effects.append({"layer": layer_index, "path": path_text, **metadata})

        for kind, path, _record in sorted(
            (item for item in normalized if item[0] != "directory"),
            key=lambda item: str(item[1]),
        ):
            ensure_parents(path, allow_implicit=layer_index < base_layer_count)
            path_text = str(path)
            remove_state(path_text)
            state[path_text] = {"kind": kind}

    return (
        validate_directory_effect_policy(directory_effects, platform),
        validate_removal_policy(removals, platform),
    )


def post_base_layer_count(files: Mapping[str, Any], policy: Mapping[str, Any]) -> int:
    """Return the reviewed base boundary for one all-layer inventory."""

    platform = files.get("platform")
    platforms = policy.get("base_image_platforms")
    if not isinstance(platforms, dict) or not isinstance(platforms.get(platform), dict):
        raise EvidenceError(f"policy has no reviewed base for {platform!r}")
    base_layers = platforms[platform].get("layer_diff_ids")
    if (
        not isinstance(base_layers, list)
        or not base_layers
        or not all(isinstance(item, str) and SHA256.fullmatch(item) for item in base_layers)
    ):
        raise EvidenceError(f"policy has no valid reviewed base layers for {platform!r}")
    return len(base_layers)


def verify_post_base_filesystem_policy(files: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    """Compare semantic post-base directory changes and removals with policy."""

    platform = files.get("platform")
    base_layer_count = post_base_layer_count(files, policy)
    baseline = filesystem_baseline(policy, platform)
    observed_directory_effects, observed_removals = canonical_post_base_filesystem_changes(
        files, base_layer_count, platform
    )
    expected_directory_effects = validate_directory_effect_policy(
        baseline["post_base_directory_effects"], platform
    )
    if observed_directory_effects != expected_directory_effects:
        raise EvidenceError("post-base directory effects differ from reviewed policy")
    expected_removals = validate_removal_policy(baseline["post_base_removals"], platform)
    if observed_removals != expected_removals:
        raise EvidenceError("post-base removals differ from reviewed policy")


def verify_post_base_provenance(
    inventory: Mapping[str, Any],
    files: Mapping[str, Any],
    policy: Mapping[str, Any],
    repo: Path,
    *,
    source_revision: str = "HEAD",
) -> None:
    """Reject every unclassified file-system change above the reviewed base."""

    base_layer_count = post_base_layer_count(files, policy)

    def require_root_header(record: Mapping[str, Any], mode: int, subject: str) -> None:
        validate_header_identity(record, subject)
        if record.get("uid") != 0 or record.get("gid") != 0 or record.get("mode") != mode:
            raise EvidenceError(f"{subject} must be root-owned with mode {mode:#06o}")

    ownership = inventory.get("python_record_ownership")
    if not isinstance(ownership, list):
        raise EvidenceError("component inventory has no Python RECORD ownership")
    owned = {record["path"]: record for record in ownership if isinstance(record, dict)}
    license_content = run(
        ["git", "show", f"{source_revision}:LICENSE"],
        cwd=repo,
        max_output_bytes=MAX_LICENSE_BYTES,
    )
    expected_license = {
        "path": "usr/share/licenses/extra-codeowners/LICENSE",
        "sha256": sha256_bytes(license_content),
        "size": len(license_content),
    }
    license_occurrences = 0
    for record in files["regular_files"]:
        if record["layer"] < base_layer_count:
            continue
        path = record["path"]
        if path in owned:
            expected = owned[path]
            if record["effective"] is not True or any(
                record[field] != expected[field]
                for field in (
                    "effective",
                    "layer",
                    "path",
                    "sha256",
                    "size",
                    "mode",
                    "uid",
                    "gid",
                )
            ):
                raise EvidenceError(f"post-base Python file is not its RECORD-owned file: {path}")
            expected_mode = 0o755 if path.startswith("opt/venv/bin/") else 0o644
            require_root_header(record, expected_mode, f"post-base Python file {path}")
            continue
        if path == "opt/venv/pyvenv.cfg":
            if record["effective"] is not True:
                raise EvidenceError("post-base pyvenv.cfg is later hidden or replaced")
            require_root_header(record, 0o644, "post-base pyvenv.cfg")
            continue
        if path == expected_license["path"]:
            license_occurrences += 1
            if (
                record["effective"] is not True
                or record["sha256"] != expected_license["sha256"]
                or record["size"] != expected_license["size"]
            ):
                raise EvidenceError(
                    "post-base application LICENSE differs from the selected Git revision"
                )
            require_root_header(record, 0o644, "post-base application LICENSE")
            continue
        raise EvidenceError(f"unclassified post-base regular file: {path}")
    if license_occurrences != 1:
        raise EvidenceError("image must contain one Git-bound post-base application LICENSE")

    post_base_non_regular = [
        record for record in files["non_regular_files"] if record["layer"] >= base_layer_count
    ]
    observed_links = {
        record["path"]: record.get("target")
        for record in post_base_non_regular
        if record.get("kind") == "symlink"
    }
    if len(observed_links) != len(post_base_non_regular) or observed_links != VENV_LINKS:
        raise EvidenceError("image contains an unreviewed post-base non-regular file")
    for record in post_base_non_regular:
        require_root_header(record, 0o777, f"post-base link {record['path']}")

    verify_post_base_filesystem_policy(files, policy)


def validate_all_layer_inventory(files: Mapping[str, Any], inventory: Mapping[str, Any]) -> None:
    """Validate the complete collector output before retaining it as evidence."""

    require_schema(inventory, "component inventory")
    inventory_keys = {
        "schema_version",
        "platform",
        "subject_digest",
        "image_config_digest",
        "image_revision",
        "image_version",
        "application_wheel_sha256",
        "application_selection_record_sha256",
        "apk_database_sha256",
        "apk_database_occurrences",
        "components",
        "embedded_sboms",
        "native_payloads",
        "wheel_identity_files",
        "wheel_installations",
        "python_record_ownership",
    }
    if set(inventory) != inventory_keys:
        raise EvidenceError("component inventory has an unexpected schema shape")
    platform = inventory.get("platform")
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise EvidenceError("component inventory has an unsupported platform")
    for field in ("subject_digest", "image_config_digest"):
        digest = inventory.get(field)
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise EvidenceError(f"component inventory has an invalid {field}")
    revision = inventory.get("image_revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise EvidenceError("component inventory has an invalid image revision")
    image_version = inventory.get("image_version")
    if not isinstance(image_version, str):
        raise EvidenceError("component inventory has an invalid image version")
    checked_scalar(image_version, "component inventory image version")
    for field in (
        "application_wheel_sha256",
        "application_selection_record_sha256",
    ):
        value = inventory.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise EvidenceError(f"component inventory has an invalid {field}")
    components = validate_component_records(inventory.get("components"), "component inventory")
    validate_platform_component_invariants(components, str(platform), "component inventory")
    python_hashes = {
        str(component["metadata_sha256"]): component
        for component in components
        if component["ecosystem"] == "python"
    }

    require_schema(files, "all-layer inventory")
    required_keys = {
        "schema_version",
        "platform",
        "subject_digest",
        "image_config_digest",
        "layers",
        "regular_files",
        "directories",
        "non_regular_files",
        "whiteouts",
    }
    if set(files) != required_keys:
        raise EvidenceError("all-layer inventory has an unexpected schema shape")
    for field in ("platform", "subject_digest", "image_config_digest"):
        if files.get(field) != inventory.get(field):
            raise EvidenceError(f"component and all-layer inventories disagree about {field}")

    layers = files.get("layers")
    if not isinstance(layers, list) or not layers or len(layers) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("all-layer inventory has no layers")
    layer_digests: list[str] = []
    expected_counts: list[int] = []
    for expected_index, layer in enumerate(layers):
        if not isinstance(layer, dict) or set(layer) != {
            "digest",
            "index",
            "regular_file_count",
            "directory_count",
            "non_regular_file_count",
            "whiteout_count",
        }:
            raise EvidenceError("all-layer inventory has an invalid layer record")
        index = layer.get("index")
        counts = [
            layer.get("regular_file_count"),
            layer.get("directory_count"),
            layer.get("non_regular_file_count"),
            layer.get("whiteout_count"),
        ]
        digest = layer.get("digest")
        if not isinstance(index, int) or isinstance(index, bool) or index != expected_index:
            raise EvidenceError("all-layer inventory has a non-sequential layer index")
        if any(
            not isinstance(count, int) or isinstance(count, bool) or count < 0 for count in counts
        ):
            raise EvidenceError("all-layer inventory has an invalid per-layer entry count")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise EvidenceError("all-layer inventory has an invalid layer digest")
        if digest in layer_digests:
            raise EvidenceError("all-layer inventory repeats a layer digest")
        layer_digests.append(digest)
        expected_counts.append(layer["regular_file_count"])

    records = files.get("regular_files")
    if not isinstance(records, list) or len(records) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("all-layer inventory has an invalid regular-file list")
    observed_counts = [0] * len(layers)
    all_occurrences: set[tuple[int, str]] = set()
    seen_occurrences: set[tuple[int, str]] = set()
    effective_paths: set[str] = set()
    total_size = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "effective",
            "layer",
            "layer_digest",
            "path",
            "sha256",
            "size",
            "mode",
            "uid",
            "gid",
        }:
            raise EvidenceError("all-layer inventory has an invalid regular-file record")
        layer_index = record.get("layer")
        size = record.get("size")
        path_value = record.get("path")
        digest = record.get("sha256")
        effective_value = record.get("effective")
        if (
            not isinstance(layer_index, int)
            or isinstance(layer_index, bool)
            or not 0 <= layer_index < len(layers)
        ):
            raise EvidenceError("all-layer inventory file has an invalid layer index")
        if record.get("layer_digest") != layer_digests[layer_index]:
            raise EvidenceError("all-layer inventory file has the wrong layer digest")
        if not isinstance(path_value, str):
            raise EvidenceError("all-layer inventory file has no path")
        path = str(checked_canonical_path(path_value, "all-layer inventory regular-file path"))
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise EvidenceError("all-layer inventory file has an invalid SHA-256")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_ARCHIVE_MEMBER_BYTES
        ):
            raise EvidenceError("all-layer inventory file has an invalid size")
        if not isinstance(effective_value, bool):
            raise EvidenceError("all-layer inventory file has an invalid effective state")
        validate_header_identity(record, "all-layer inventory regular file")
        occurrence = (layer_index, path)
        if occurrence in seen_occurrences:
            raise EvidenceError("all-layer inventory repeats a path within one layer")
        seen_occurrences.add(occurrence)
        all_occurrences.add(occurrence)
        if effective_value:
            if path in effective_paths:
                raise EvidenceError("all-layer inventory repeats an effective path")
            effective_paths.add(path)
        observed_counts[layer_index] += 1
        total_size += size
        if total_size > MAX_IMAGE_TOTAL_BYTES:
            raise EvidenceError("all-layer inventory exceeds the cumulative size limit")
    if observed_counts != expected_counts:
        raise EvidenceError("all-layer inventory regular-file counts do not match its records")

    directories = files.get("directories")
    if not isinstance(directories, list) or len(directories) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("all-layer inventory has an invalid directory list")
    seen_directories: set[tuple[int, str]] = set()
    observed_directory_counts = [0] * len(layers)
    for record in directories:
        if not isinstance(record, dict) or set(record) != {
            "effective",
            "layer",
            "layer_digest",
            "path",
            "mode",
            "uid",
            "gid",
        }:
            raise EvidenceError("all-layer inventory has an invalid directory record")
        layer_index = record.get("layer")
        if (
            not isinstance(layer_index, int)
            or isinstance(layer_index, bool)
            or not 0 <= layer_index < len(layers)
            or record.get("layer_digest") != layer_digests[layer_index]
        ):
            raise EvidenceError("all-layer inventory directory has an invalid layer")
        path_value = record.get("path")
        if not isinstance(path_value, str):
            raise EvidenceError("all-layer inventory directory has no path")
        path = str(checked_canonical_path(path_value, "all-layer inventory directory path"))
        if not isinstance(record.get("effective"), bool):
            raise EvidenceError("all-layer inventory directory has an invalid effective state")
        validate_header_identity(record, "all-layer inventory directory")
        occurrence = (layer_index, path)
        if occurrence in seen_directories:
            raise EvidenceError("all-layer inventory repeats a directory within one layer")
        seen_directories.add(occurrence)
        if occurrence in all_occurrences:
            raise EvidenceError("all-layer inventory repeats one path across entry categories")
        all_occurrences.add(occurrence)
        observed_directory_counts[layer_index] += 1
    if observed_directory_counts != [layer["directory_count"] for layer in layers]:
        raise EvidenceError("all-layer inventory directory counts do not match its records")

    non_regular = files.get("non_regular_files")
    if not isinstance(non_regular, list) or len(non_regular) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("all-layer inventory has an invalid non-regular-file list")
    seen_non_regular: set[tuple[int, str]] = set()
    for record in non_regular:
        if not isinstance(record, dict):
            raise EvidenceError("all-layer inventory has an invalid non-regular-file record")
        kind = record.get("kind")
        expected_fields = (
            {"kind", "layer", "layer_digest", "path", "target", "mode", "uid", "gid"}
            if kind in {"symlink", "hardlink"}
            else {"kind", "layer", "layer_digest", "path", "mode", "uid", "gid"}
        )
        if set(record) != expected_fields or kind not in {
            "symlink",
            "hardlink",
            "other",
        }:
            raise EvidenceError("all-layer inventory has an invalid non-regular-file record")
        layer_index = record.get("layer")
        if (
            not isinstance(layer_index, int)
            or isinstance(layer_index, bool)
            or not 0 <= layer_index < len(layers)
            or record.get("layer_digest") != layer_digests[layer_index]
        ):
            raise EvidenceError("all-layer inventory non-regular file has an invalid layer")
        path_value = record.get("path")
        if not isinstance(path_value, str):
            raise EvidenceError("all-layer inventory non-regular file has no path")
        path = str(checked_canonical_path(path_value, "all-layer inventory non-regular-file path"))
        occurrence = (layer_index, path)
        if occurrence in seen_non_regular:
            raise EvidenceError("all-layer inventory repeats a non-regular path within one layer")
        seen_non_regular.add(occurrence)
        if occurrence in all_occurrences:
            raise EvidenceError("all-layer inventory repeats one path across entry categories")
        all_occurrences.add(occurrence)
        validate_header_identity(record, "all-layer inventory non-regular file")
        if kind in {"symlink", "hardlink"}:
            target = record.get("target")
            if not isinstance(target, str):
                raise EvidenceError("all-layer inventory link has no target")
            checked_image_link_target(target)

    whiteouts = files.get("whiteouts")
    if not isinstance(whiteouts, list) or len(whiteouts) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("all-layer inventory has an invalid whiteout list")
    seen_whiteouts: set[tuple[int, str]] = set()
    for record in whiteouts:
        if not isinstance(record, dict) or set(record) != {
            "kind",
            "layer",
            "layer_digest",
            "path",
            "target",
            "mode",
            "uid",
            "gid",
        }:
            raise EvidenceError("all-layer inventory has an invalid whiteout record")
        layer_index = record.get("layer")
        if (
            not isinstance(layer_index, int)
            or isinstance(layer_index, bool)
            or not 0 <= layer_index < len(layers)
            or record.get("layer_digest") != layer_digests[layer_index]
        ):
            raise EvidenceError("all-layer inventory whiteout has an invalid layer")
        path_value = record.get("path")
        target_value = record.get("target")
        if not isinstance(path_value, str) or not isinstance(target_value, str):
            raise EvidenceError("all-layer inventory whiteout has invalid paths")
        path_obj = checked_canonical_path(path_value, "all-layer inventory whiteout path")
        kind = record.get("kind")
        if kind == "opaque":
            if path_obj.name != ".wh..wh..opq" or target_value != str(path_obj.parent):
                raise EvidenceError("all-layer inventory has an invalid opaque whiteout")
        elif kind == "whiteout":
            target = checked_canonical_path(target_value, "all-layer inventory whiteout target")
            if path_obj.name != f".wh.{target.name}" or path_obj.parent != target.parent:
                raise EvidenceError("all-layer inventory has an invalid whiteout target")
        else:
            raise EvidenceError("all-layer inventory has an invalid whiteout kind")
        validate_header_identity(record, "all-layer inventory whiteout")
        occurrence = (layer_index, str(path_obj))
        if occurrence in seen_whiteouts:
            raise EvidenceError("all-layer inventory repeats a whiteout within one layer")
        seen_whiteouts.add(occurrence)
        if occurrence in all_occurrences:
            raise EvidenceError("all-layer inventory repeats one path across entry categories")
        all_occurrences.add(occurrence)
    if [
        sum(1 for record in non_regular if record["layer"] == layer_index)
        for layer_index in range(len(layers))
    ] != [layer["non_regular_file_count"] for layer in layers]:
        raise EvidenceError("all-layer inventory non-regular counts do not match its records")
    if [
        sum(1 for record in whiteouts if record["layer"] == layer_index)
        for layer_index in range(len(layers))
    ] != [layer["whiteout_count"] for layer in layers]:
        raise EvidenceError("all-layer inventory whiteout counts do not match its records")
    if len(records) + len(directories) + len(non_regular) + len(whiteouts) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("all-layer inventory exceeds the cumulative entry-count limit")

    def expected_payload(record: Mapping[str, Any]) -> dict[str, Any]:
        return {
            field: record[field]
            for field in ("effective", "layer", "path", "sha256", "size", "mode", "uid", "gid")
        }

    expected_embedded_sboms = [
        expected_payload(record) for record in records if DIST_INFO_SBOM.search(record["path"])
    ]
    required_native_payloads = [
        expected_payload(record) for record in records if is_native_payload_path(record["path"])
    ]
    expected_wheel_identity_files = sorted(
        (
            expected_payload(record)
            for record in records
            if WHEEL_IDENTITY_FILE.search(record["path"])
        ),
        key=lambda record: (record["layer"], record["path"]),
    )
    python_component_owners = {
        component_key(component)
        for component in components
        if component.get("ecosystem") == "python"
    }
    embedded_sboms = validate_structured_python_payloads(
        inventory.get("embedded_sboms"),
        "component inventory embedded_sboms",
        identity_field="cyclonedx",
        platform=str(platform),
        component_owners=python_component_owners,
    )
    observed_embedded_sboms = [payload_record_projection(record) for record in embedded_sboms]
    if observed_embedded_sboms != expected_embedded_sboms:
        raise EvidenceError("component inventory omits or alters embedded wheel SBOMs")
    native_payloads = validate_structured_python_payloads(
        inventory.get("native_payloads"),
        "component inventory native_payloads",
        identity_field="elf",
        platform=str(platform),
        component_owners=python_component_owners,
    )
    observed_native_payloads = [payload_record_projection(record) for record in native_payloads]
    all_record_occurrences = {
        (record["layer"], record["path"], record["sha256"]): expected_payload(record)
        for record in records
    }
    runtime_components = [
        component for component in components if component.get("ecosystem") == "runtime"
    ]
    if len(runtime_components) != 1:
        raise EvidenceError("component inventory must contain one CPython runtime component")
    runtime_identities = runtime_components[0].get("identity_files")
    if not isinstance(runtime_identities, dict):
        raise EvidenceError("component inventory has invalid CPython runtime identity files")

    def later_ancestor_hides_identity(identity: Mapping[str, Any], path: str) -> bool:
        layer = identity.get("layer")
        if not isinstance(layer, int) or isinstance(layer, bool):
            return True
        ancestors = {str(parent) for parent in PurePosixPath(path).parents}
        if any(
            record.get("layer", -1) >= layer and record.get("path") in ancestors
            for record in (*records, *non_regular)
        ):
            return True
        hidden_paths = {path, *ancestors}
        return any(
            record.get("layer", -1) > layer
            and record.get("target") in hidden_paths
            and record.get("kind") in {"whiteout", "opaque"}
            for record in whiteouts
        )

    for role, path in CPYTHON_REGULAR_IDENTITY_PATHS.items():
        identity = runtime_identities.get(role)
        if not isinstance(identity, dict):
            raise EvidenceError(f"component inventory has no CPython {role} identity")
        raw_identity = {field: identity[field] for field in identity if field != "elf"}
        path_occurrences = [record for record in records if record["path"] == path]
        if (
            len(path_occurrences) != 1
            or expected_payload(path_occurrences[0]) != raw_identity
            or any(record.get("path") == path for record in directories)
            or any(record.get("path") == path for record in non_regular)
            or any(
                record.get("path") == path or record.get("target") == path for record in whiteouts
            )
            or later_ancestor_hides_identity(identity, path)
        ):
            raise EvidenceError(
                f"CPython {role} is not one exact all-layer regular-file occurrence"
            )

    link_identity = runtime_identities.get("interpreter_link")
    if not isinstance(link_identity, dict):
        raise EvidenceError("component inventory has no CPython interpreter-link identity")
    expected_link = {
        "effective": True,
        "kind": "symlink",
        "layer": link_identity.get("layer"),
        "path": CPYTHON_INTERPRETER_LINK,
        "target": CPYTHON_INTERPRETER_LINK_TARGET,
        "mode": 0o777,
        "uid": 0,
        "gid": 0,
    }
    link_occurrences = [
        record for record in non_regular if record.get("path") == CPYTHON_INTERPRETER_LINK
    ]
    if (
        link_identity != expected_link
        or len(link_occurrences) != 1
        or {field: link_occurrences[0][field] for field in expected_link if field != "effective"}
        != {field: value for field, value in expected_link.items() if field != "effective"}
        or any(record.get("path") == CPYTHON_INTERPRETER_LINK for record in records)
        or any(record.get("path") == CPYTHON_INTERPRETER_LINK for record in directories)
        or any(
            record.get("path") == CPYTHON_INTERPRETER_LINK
            or record.get("target") == CPYTHON_INTERPRETER_LINK
            for record in whiteouts
        )
        or later_ancestor_hides_identity(link_identity, CPYTHON_INTERPRETER_LINK)
    ):
        raise EvidenceError("CPython interpreter link is not one exact effective symlink")
    observed_native_occurrences: set[tuple[int, str, str]] = set()
    for payload in observed_native_payloads:
        native_occurrence = (payload["layer"], payload["path"], payload["sha256"])
        if (
            native_occurrence in observed_native_occurrences
            or all_record_occurrences.get(native_occurrence) != payload
            or not is_python_virtual_environment_path(payload["path"])
        ):
            raise EvidenceError("component inventory alters a native Python payload occurrence")
        observed_native_occurrences.add(native_occurrence)
    if any(
        (payload["layer"], payload["path"], payload["sha256"]) not in observed_native_occurrences
        for payload in required_native_payloads
    ):
        raise EvidenceError("component inventory omits a path-classified native Python payload")
    if inventory.get("wheel_identity_files") != expected_wheel_identity_files:
        raise EvidenceError("component inventory omits or alters installed wheel identity files")
    occurrence_payloads = {
        (record["layer"], record["path"]): expected_payload(record) for record in records
    }
    historical_occurrences, effective_historical_occurrences = validate_wheel_installations(
        inventory.get("wheel_installations"), components, occurrence_payloads
    )
    installation_value = inventory.get("wheel_installations")
    if not isinstance(installation_value, list):
        raise EvidenceError("component inventory has invalid historical Python installations")
    observed_record_occurrences = {
        (installation["record"]["layer"], installation["record"]["path"])
        for installation in installation_value
    }
    expected_record_occurrences = {
        (record["layer"], record["path"])
        for record in expected_wheel_identity_files
        if is_venv_record_path(str(record["path"]))
    }
    if observed_record_occurrences != expected_record_occurrences:
        raise EvidenceError("component inventory omits a historical Python RECORD installation")
    ownership = inventory.get("python_record_ownership")
    if not isinstance(ownership, list) or len(ownership) > MAX_RECORD_ENTRIES:
        raise EvidenceError("component inventory has invalid Python RECORD ownership")
    effective_python_names = {
        component["name"]
        for component in components
        if component.get("ecosystem") == "python" and component.get("effective") is True
    }
    python_owner_names = {
        component_key(component): str(component["name"])
        for component in components
        if component.get("ecosystem") == "python"
    }
    effective_records = {
        record["path"]: record for record in records if record["effective"] is True
    }
    owned_paths: set[str] = set()
    for ownership_record in ownership:
        if not isinstance(ownership_record, dict) or set(ownership_record) != {
            "owner",
            "effective",
            "layer",
            "path",
            "sha256",
            "size",
            "mode",
            "uid",
            "gid",
        }:
            raise EvidenceError("component inventory has invalid Python RECORD ownership")
        owner = ownership_record.get("owner")
        path_value = ownership_record.get("path")
        if (
            not isinstance(owner, str)
            or owner not in effective_python_names
            or not isinstance(path_value, str)
            or not path_value.startswith("opt/venv/")
            or ownership_record.get("effective") is not True
        ):
            raise EvidenceError("component inventory has invalid Python RECORD ownership")
        path = str(
            checked_canonical_path(path_value, "component inventory Python RECORD ownership path")
        )
        if path in owned_paths:
            raise EvidenceError("component inventory repeats Python RECORD ownership")
        owned_paths.add(path)
        expected_record = effective_records.get(path)
        expected_payload_record = (
            expected_payload(expected_record) if expected_record is not None else None
        )
        observed_payload_record = {
            field: ownership_record[field]
            for field in (
                "effective",
                "layer",
                "path",
                "sha256",
                "size",
                "mode",
                "uid",
                "gid",
            )
        }
        if observed_payload_record != expected_payload_record:
            raise EvidenceError("Python RECORD ownership does not match all-layer inventory")
        ownership_occurrence = (
            ownership_record["layer"],
            path,
            ownership_record["sha256"],
        )
        if (
            python_owner_names.get(effective_historical_occurrences.get(ownership_occurrence, ""))
            != owner
        ):
            raise EvidenceError(
                "Python RECORD ownership is not linked to its effective historical claim"
            )
    observed_ownership_occurrences = {
        (record["layer"], record["path"], record["sha256"])
        for record in ownership
        if isinstance(record, dict)
    }
    if observed_ownership_occurrences != set(effective_historical_occurrences):
        raise EvidenceError("Python RECORD ownership omits an effective historical claim")
    for payload in (*embedded_sboms, *native_payloads):
        payload_occurrence = (payload["layer"], payload["path"], payload["sha256"])
        if historical_occurrences.get(payload_occurrence) != payload["owner"]:
            raise EvidenceError(
                "structured Python payload is not linked to its RECORD ownership occurrence"
            )

    apk_hash = inventory.get("apk_database_sha256")
    if not isinstance(apk_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", apk_hash):
        raise EvidenceError("component inventory has no effective APK database digest")
    apk_records = [
        record
        for record in records
        if record["path"] == "lib/apk/db/installed"
        and record["sha256"] == apk_hash
        and record["effective"] is True
    ]
    if len(apk_records) != 1:
        raise EvidenceError("all-layer inventory does not contain the effective APK database")
    expected_apk_occurrences = [
        expected_payload(record) for record in records if record["path"] == "lib/apk/db/installed"
    ]
    if inventory.get("apk_database_occurrences") != expected_apk_occurrences:
        raise EvidenceError("component inventory omits or alters an APK database occurrence")

    metadata_records = [record for record in records if DIST_INFO.search(record["path"])]
    if any(record["sha256"] not in python_hashes for record in metadata_records):
        raise EvidenceError("all-layer inventory has unbound Python metadata")
    for component in components:
        if component.get("ecosystem") != "python":
            continue
        expected_hash = component.get("metadata_sha256")
        expected_effective = component.get("effective")
        matches = [record for record in metadata_records if record["sha256"] == expected_hash]
        if not matches or not isinstance(expected_effective, bool):
            raise EvidenceError(
                "all-layer inventory is missing Python metadata for "
                f"{component.get('name')} {component.get('version')}"
            )
        has_effective = any(record["effective"] is True for record in matches)
        if has_effective != expected_effective:
            raise EvidenceError(
                "all-layer inventory has the wrong effective state for Python metadata "
                f"{component.get('name')} {component.get('version')}"
            )


def verify_dockerfile_base_bytes(
    dockerfile_content: bytes,
    source: str,
    policy: Mapping[str, Any],
) -> None:
    """Require builder and runtime stages to use the reviewed base index digest."""

    base_image = policy.get("base_image")
    base_digest = policy.get("base_image_index_digest")
    if (
        not isinstance(base_image, str)
        or not base_image
        or "@" in base_image
        or any(character.isspace() for character in base_image)
    ):
        raise EvidenceError("policy base image reference is invalid")
    if not isinstance(base_digest, str) or not SHA256.fullmatch(base_digest):
        raise EvidenceError("policy base image index digest is invalid")
    try:
        content = dockerfile_content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"cannot decode {source}") from exc
    stages: dict[str, str] = {}
    from_entries: list[tuple[str, str | None]] = []
    for line in content.splitlines():
        match = re.fullmatch(
            r"\s*FROM\s+(\S+)(?:\s+AS\s+([A-Za-z0-9_.-]+))?\s*",
            line,
            flags=re.IGNORECASE,
        )
        if match is not None:
            alias = match.group(2)
            from_entries.append((match.group(1), alias.lower() if alias is not None else None))
            if alias is not None:
                stages[alias.lower()] = match.group(1)
    expected = f"{base_image}@{base_digest}"
    for stage in ("builder", "runtime"):
        if stages.get(stage) != expected:
            raise EvidenceError(
                f"Dockerfile {stage} stage must use reviewed base {expected} exactly"
            )
    if not from_entries or from_entries[-1] != (expected, "runtime"):
        raise EvidenceError("Dockerfile final build stage must be the reviewed runtime base stage")


def verify_dockerfile_base(dockerfile: Path, policy: Mapping[str, Any]) -> None:
    verify_dockerfile_base_bytes(
        read_stable_local_bytes(
            dockerfile,
            max_bytes=1024 * 1024,
            source=f"Dockerfile {dockerfile}",
        ),
        str(dockerfile),
        policy,
    )


def require_https_source_url(url: str) -> None:
    try:
        checked = checked_scalar(url, "source URL", max_length=MAX_LICENSE_FIELD_LENGTH)
        if checked != url:
            raise EvidenceError(f"source URL must not contain surrounding whitespace: {url!r}")
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise EvidenceError(f"source URL is invalid: {url!r}") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or (port is not None and not 0 <= port <= 65535)
    ):
        raise EvidenceError(f"source URL must be credential-free HTTPS: {url}")


def validate_cpython_policy_relationships(policy: Mapping[str, Any]) -> None:
    """Bind the reviewed runtime, base tag, recipe URL, and source URL identities."""

    base_image = policy.get("base_image")
    if not isinstance(base_image, str):
        raise EvidenceError("policy has no CPython base image identity")
    tag = re.fullmatch(r"python:([0-9]+\.[0-9]+\.[0-9]+)-alpine([0-9]+\.[0-9]+)", base_image)
    if tag is None or tag.group(1) != EXPECTED_RUNTIME_PYTHON:
        raise EvidenceError("policy base image tag does not match the CPython runtime version")
    alpine_release = tag.group(2)

    recipe = policy.get("docker_python_recipe")
    if not isinstance(recipe, dict):
        raise EvidenceError("policy has no Docker Official Python recipe")
    recipe_url = recipe.get("url")
    license_url = recipe.get("license_url")
    if not isinstance(recipe_url, str) or not isinstance(license_url, str):
        raise EvidenceError("Docker Official Python recipe URLs are invalid")
    recipe_match = re.fullmatch(
        rf"https://raw\.githubusercontent\.com/docker-library/python/"
        rf"([0-9a-f]{{40}})/{re.escape(CPYTHON_RUNTIME_MINOR)}/"
        rf"alpine{re.escape(alpine_release)}/Dockerfile",
        recipe_url,
    )
    license_match = re.fullmatch(
        r"https://raw\.githubusercontent\.com/docker-library/python/([0-9a-f]{40})/LICENSE",
        license_url,
    )
    if (
        recipe_match is None
        or license_match is None
        or recipe_match.group(1) != license_match.group(1)
    ):
        raise EvidenceError(
            "Docker Official Python recipe and license must use one commit-pinned repository path"
        )

    cpython_source = policy.get("cpython_source")
    if not isinstance(cpython_source, dict):
        raise EvidenceError("policy has no CPython source")
    expected_url = (
        f"https://www.python.org/ftp/python/{EXPECTED_RUNTIME_PYTHON}/"
        f"Python-{EXPECTED_RUNTIME_PYTHON}.tar.xz"
    )
    expected_license_member = f"Python-{EXPECTED_RUNTIME_PYTHON}/LICENSE"
    expected_patchlevel_member = f"Python-{EXPECTED_RUNTIME_PYTHON}/Include/patchlevel.h"
    if cpython_source.get("url") != expected_url:
        raise EvidenceError("CPython source URL does not match the runtime version")
    if cpython_source.get("license_member") != expected_license_member:
        raise EvidenceError("CPython source license member does not match the runtime version")
    if cpython_source.get("patchlevel_member") != expected_patchlevel_member:
        raise EvidenceError("CPython source patchlevel member does not match the runtime version")
    patchlevel_sha256 = cpython_source.get("patchlevel_sha256")
    if not isinstance(patchlevel_sha256, str):
        raise EvidenceError("CPython source has no patchlevel digest")

    platforms = policy.get("platforms")
    base_platforms = policy.get("base_image_platforms")
    if not isinstance(platforms, dict) or not isinstance(base_platforms, dict):
        raise EvidenceError("policy has no cross-platform CPython runtime baseline")
    shared_identity: tuple[str, str, str] | None = None
    for platform in ("linux/amd64", "linux/arm64"):
        components = platforms.get(platform)
        if not isinstance(components, list):
            raise EvidenceError(f"policy has no CPython runtime baseline for {platform}")
        runtime_components = [
            component
            for component in components
            if isinstance(component, dict) and component.get("ecosystem") == "runtime"
        ]
        if len(runtime_components) != 1:
            raise EvidenceError(
                f"policy must contain exactly one CPython runtime component for {platform}"
            )
        runtime = runtime_components[0]
        identity = (str(runtime.get("name")), str(runtime.get("version")), str(runtime.get("purl")))
        if shared_identity is None:
            shared_identity = identity
        elif identity != shared_identity:
            raise EvidenceError("policy CPython runtime identity differs across platforms")
        reviewed_base = base_platforms.get(platform)
        identities = runtime.get("identity_files")
        if not isinstance(reviewed_base, dict) or not isinstance(identities, dict):
            raise EvidenceError(f"policy has an invalid CPython base boundary for {platform}")
        version_header = identities.get("version_header")
        if (
            not isinstance(version_header, dict)
            or version_header.get("sha256") != patchlevel_sha256
        ):
            raise EvidenceError(
                f"policy CPython version header does not match reviewed source for {platform}"
            )
        base_layers = reviewed_base.get("layer_diff_ids")
        if not isinstance(base_layers, list) or any(
            not isinstance(record, dict)
            or not isinstance(record.get("layer"), int)
            or isinstance(record.get("layer"), bool)
            or not 0 <= record["layer"] < len(base_layers)
            for record in identities.values()
        ):
            raise EvidenceError(
                f"policy CPython runtime identity is outside the reviewed base for {platform}"
            )


def verify_cpython_source_binding(docker_recipe: bytes, cpython_source: Mapping[str, Any]) -> None:
    """Bind the retained CPython archive to the pinned Official Image recipe."""

    try:
        recipe = docker_recipe.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("Docker Official Python recipe is not UTF-8") from exc
    version_matches = re.findall(
        r"^ENV PYTHON_VERSION ([0-9]+\.[0-9]+\.[0-9]+[a-z0-9.]*)$",
        recipe,
        flags=re.MULTILINE,
    )
    hash_matches = re.findall(r"^ENV PYTHON_SHA256 ([0-9a-f]{64})$", recipe, flags=re.MULTILINE)
    if len(version_matches) != 1 or len(hash_matches) != 1:
        raise EvidenceError(
            "Docker Official Python recipe must declare one literal "
            "PYTHON_VERSION and PYTHON_SHA256"
        )
    version = version_matches[0]
    expected_hash = hash_matches[0]
    if version != EXPECTED_RUNTIME_PYTHON:
        raise EvidenceError("Docker Official Python recipe version differs from the runtime")
    release_directory = re.split(r"[a-z]", version, maxsplit=1)[0]
    expected_url = f"https://www.python.org/ftp/python/{release_directory}/Python-{version}.tar.xz"
    if cpython_source.get("url") != expected_url:
        raise EvidenceError(
            "CPython source URL does not match the Docker Official Python recipe version"
        )
    if cpython_source.get("sha256") != expected_hash:
        raise EvidenceError(
            "CPython source SHA-256 does not match the Docker Official Python recipe"
        )


def verify_cpython_source_archive(content: bytes, cpython_source: Mapping[str, Any]) -> bytes:
    """Validate the exact source archive, LICENSE, and installed version header."""

    expected_size = cpython_source.get("size")
    expected_digest = cpython_source.get("sha256")
    license_member = cpython_source.get("license_member")
    expected_license_digest = cpython_source.get("license_sha256")
    patchlevel_member = cpython_source.get("patchlevel_member")
    expected_patchlevel_digest = cpython_source.get("patchlevel_sha256")
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or len(content) != expected_size
        or not isinstance(expected_digest, str)
        or sha256_bytes(content) != expected_digest
        or not isinstance(license_member, str)
        or not isinstance(expected_license_digest, str)
        or not isinstance(patchlevel_member, str)
        or not isinstance(expected_patchlevel_digest, str)
    ):
        raise EvidenceError("CPython source archive does not match its reviewed identity")
    checked_canonical_path(license_member, "CPython source license member")
    checked_canonical_path(patchlevel_member, "CPython source patchlevel member")
    if license_member == patchlevel_member:
        raise EvidenceError("CPython source members must be distinct")
    found_license: bytes | None = None
    found_patchlevel: bytes | None = None
    count = 0
    total = 0
    try:
        with tarfile.open(
            fileobj=io.BytesIO(content), mode="r|*", tarinfo=BoundedTarInfo
        ) as archive:
            for member in archive:
                count += 1
                if count > MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError("CPython source archive has too many entries")
                path = str(checked_path(member.name))
                if member.isfile():
                    if not 0 <= member.size <= MAX_ARCHIVE_MEMBER_BYTES:
                        raise EvidenceError("CPython source archive member exceeds its size limit")
                    total += member.size
                    if total > MAX_ARCHIVE_TOTAL_BYTES:
                        raise EvidenceError(
                            "CPython source archive exceeds its expanded-size limit"
                        )
                elif member.issym() or member.islnk():
                    if member.size != 0:
                        raise EvidenceError("CPython source archive link has a payload")
                    checked_link_target(member.linkname)
                elif member.isdir():
                    if member.size != 0:
                        raise EvidenceError("CPython source archive directory has a payload")
                else:
                    raise EvidenceError("CPython source archive has an unsupported entry type")
                if path not in {license_member, patchlevel_member}:
                    continue
                if not member.isfile():
                    raise EvidenceError("CPython reviewed source member is not a regular file")
                if path == license_member:
                    if found_license is not None or member.size > MAX_LICENSE_BYTES:
                        raise EvidenceError(
                            "CPython source LICENSE is not one bounded regular archive member"
                        )
                    found_license = read_member(archive, member)
                    continue
                if found_patchlevel is not None or member.size > MAX_CPYTHON_PATCHLEVEL_BYTES:
                    raise EvidenceError(
                        "CPython source patchlevel header is not one bounded regular archive member"
                    )
                found_patchlevel = read_member(archive, member)
    except EvidenceError:
        raise
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        raise EvidenceError(f"invalid CPython source archive: {exc}") from exc
    if found_license is None or sha256_bytes(found_license) != expected_license_digest:
        raise EvidenceError("CPython source LICENSE does not match reviewed policy")
    if found_patchlevel is None or sha256_bytes(found_patchlevel) != expected_patchlevel_digest:
        raise EvidenceError("CPython source patchlevel header does not match reviewed policy")
    parse_cpython_patchlevel_header(found_patchlevel, patchlevel_member)
    return found_license


def detached_license_source(entry: Mapping[str, Any], component: str) -> tuple[str, str] | None:
    """Return a separately retained license without conflating archive-member hashes."""

    license_url = entry.get("license_url")
    if license_url is None:
        return None
    license_hash = entry.get("license_sha256")
    if not isinstance(license_url, str) or not isinstance(license_hash, str):
        raise EvidenceError(f"invalid license source for {component}")
    return license_url, license_hash


def _open_verified_source_store(
    store_root: Path,
    *,
    expected_plan_sha256: str,
    expected_plan_size: int,
) -> verified_source_store.VerifiedSourceStoreReader:
    """Open one source store while keeping reader failures in the evidence API."""

    try:
        return verified_source_store.VerifiedSourceStoreReader(
            store_root,
            expected_plan_sha256=expected_plan_sha256,
            expected_plan_size=expected_plan_size,
        )
    except verified_source_store.SourceStoreError as exc:
        raise EvidenceError(f"verified source store cannot be opened: {exc}") from exc


def _read_verified_source(
    reader: verified_source_store.VerifiedSourceStoreReader,
    request_id: str,
    expected_url: str,
    expected_hash: str,
    algorithm: str = "sha256",
    *,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> VerifiedSource:
    """Read one exact planned object and recheck its consumer-side binding."""

    hash_lengths = {"sha256": 64, "sha512": 128}
    expected_length = hash_lengths.get(algorithm)
    if expected_length is None or not re.fullmatch(
        rf"[0-9a-f]{{{expected_length}}}", expected_hash
    ):
        raise EvidenceError(f"invalid expected {algorithm} digest for {request_id}")
    require_https_source_url(expected_url)
    try:
        source = reader.read_request(request_id)
    except verified_source_store.SourceStoreError as exc:
        raise EvidenceError(f"verified source request {request_id!r} failed: {exc}") from exc
    content = source.content
    urls = source.redirect_chain
    if not urls or urls[0] != expected_url:
        raise EvidenceError(f"verified source request {request_id!r} has the wrong initial URL")
    if len(urls) > MAX_REDIRECTS + 1:
        raise EvidenceError(f"verified source request {request_id!r} has too many redirects")
    for url in urls:
        require_https_source_url(url)
    if len(content) > max_bytes:
        raise EvidenceError(f"verified source request {request_id!r} exceeds its consumer limit")
    actual = hashlib.new(algorithm, content).hexdigest()
    if actual != expected_hash:
        raise EvidenceError(
            f"{algorithm} mismatch for {request_id}: expected {expected_hash}, got {actual}"
        )
    return VerifiedSource(content=content, urls=urls)


def _read_bounded_verified_source(
    reader: verified_source_store.VerifiedSourceStoreReader,
    request_id: str,
    expected_url: str,
    expected_hash: str,
    budget: BundleBudget,
    algorithm: str = "sha256",
    *,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> VerifiedSource:
    source = _read_verified_source(
        reader,
        request_id,
        expected_url,
        expected_hash,
        algorithm,
        max_bytes=max_bytes,
    )
    budget.record_source(source.content)
    return source


def _read_bounded_alpine_distfile(
    reader: verified_source_store.VerifiedSourceStoreReader,
    request_id: str,
    expected_url: str,
    expected_sha512: str,
    budget: BundleBudget,
) -> VerifiedSource:
    """Read one Alpine distfile using the planner's source-size contract."""

    return _read_bounded_verified_source(
        reader,
        request_id,
        expected_url,
        expected_sha512,
        budget,
        "sha512",
        max_bytes=MAX_ALPINE_DISTFILE_BYTES,
    )


def _alpine_distfile_request_id(release: str, filename: str) -> str:
    """Return the planner's collision-resistant request ID for one distfile."""

    try:
        encoded_filename = filename.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EvidenceError(f"Alpine distfile name is not ASCII: {filename!r}") from exc
    return f"alpine-distfile:{release}:{hashlib.sha256(encoded_filename).hexdigest()}"


def _python_wheel_request_id(platform: str, owner: object) -> str:
    _owner_kind, owner_name, owner_version = parse_native_owner(owner, "locked native wheel owner")
    return f"python-wheel:{platform}:{owner_name}@{owner_version}"


def _python_sdist_request_id(name: str, version: str) -> str:
    return f"python-sdist:{normalize_package_name(name)}@{version}"


def _native_source_request_ids(source_id: str, kind: str) -> dict[str, str]:
    """Return every direct-store artifact request for one native source kind."""

    artifacts_by_kind = {
        "alpine-aports": (("recipe", "recipe"),),
        "crates-io": (("crate", "crate"),),
        "owner-sdist-subpath": (),
        "checksummed-upstream-release": (
            ("checksum_document", "checksum-document"),
            ("archive", "archive"),
        ),
    }
    artifacts = artifacts_by_kind.get(kind)
    if artifacts is None:
        raise EvidenceError(f"unsupported native-component bundle source kind: {kind}")
    return {
        artifact: f"native-source:{source_id}:{request_suffix}"
        for artifact, request_suffix in artifacts
    }


def _alpine_recipe_request_id(origin: str, commit: str) -> str:
    return f"alpine-recipe:{origin}@{commit}"


def _license_text_request_id(identifier: str) -> str:
    return f"license-text:{identifier}"


def _reuse_owner_sdist_source(
    source: Mapping[str, Any],
    source_id: str,
    python_source_archives: Mapping[
        tuple[str, str],
        tuple[bytes, Sequence[str], str],
    ],
) -> tuple[bytes, Sequence[str], str]:
    """Return the already-read owner sdist; this source kind has no extra request."""

    _owner, owner_name, owner_version = parse_native_owner(
        source["owner"], f"native source {source_id}"
    )
    cached = python_source_archives.get((owner_name, owner_version))
    if cached is None:
        raise EvidenceError(f"owner-sdist source has no retained owner archive: {source_id}")
    return cached


def _validate_verified_source_stores(
    direct_reader: verified_source_store.VerifiedSourceStoreReader,
    alpine_reader: verified_source_store.VerifiedSourceStoreReader,
    *,
    policy_sha256: str,
    lock_sha256: str,
    source_revision: str,
) -> None:
    """Bind both stores to this checkout and to each other through public APIs."""

    try:
        direct_plan = direct_reader.plan
        alpine_plan = alpine_reader.plan
        direct_verification = direct_reader.verification
        direct_request_ids = direct_reader.request_ids
        alpine_request_ids = alpine_reader.request_ids
    except verified_source_store.SourceStoreError as exc:
        raise EvidenceError(f"verified source-store metadata changed: {exc}") from exc

    if direct_plan["kind"] != "direct":
        raise EvidenceError("direct source store has the wrong plan kind")
    if alpine_plan["kind"] != "alpine-distfiles":
        raise EvidenceError("Alpine source store has the wrong plan kind")
    if direct_plan["evidence_schema_version"] != SCHEMA_VERSION:
        raise EvidenceError("direct source plan targets the wrong evidence schema")
    if alpine_plan["evidence_schema_version"] != SCHEMA_VERSION:
        raise EvidenceError("Alpine source plan targets the wrong evidence schema")

    expected_bindings = (
        (direct_plan["source_revision"], alpine_plan["source_revision"], source_revision),
        (direct_plan["policy_sha256"], alpine_plan["policy_sha256"], policy_sha256),
        (direct_plan["uv_lock_sha256"], alpine_plan["uv_lock_sha256"], lock_sha256),
    )
    for direct_value, alpine_value, expected in expected_bindings:
        if direct_value != expected:
            raise EvidenceError("direct source plan has the wrong checkout binding")
        if alpine_value != expected:
            raise EvidenceError("Alpine source plan has the wrong checkout binding")

    if (
        alpine_plan.get("parent_plan") != direct_verification["plan"]
        or alpine_plan.get("parent_manifest") != direct_verification["manifest"]
    ):
        raise EvidenceError("Alpine source plan does not bind the direct source-store snapshot")

    planned_direct_ids = tuple(request["id"] for request in direct_plan["requests"])
    planned_alpine_ids = tuple(request["id"] for request in alpine_plan["requests"])
    if direct_request_ids != planned_direct_ids or alpine_request_ids != planned_alpine_ids:
        raise EvidenceError("verified source reader request IDs differ from their plans")

    expected_recipe_ids = {
        request_id
        for request_id in planned_direct_ids
        if request_id.startswith("alpine-recipe:")
        or (request_id.startswith("native-source:") and request_id.endswith(":recipe"))
    }
    recipe_records = alpine_plan.get("recipes")
    if (
        recipe_records is None
        or {recipe["request_id"] for recipe in recipe_records} != expected_recipe_ids
    ):
        raise EvidenceError("Alpine source plan does not exactly cover direct recipe requests")
    # Reader construction has already verified the store-wide request, object,
    # and byte ceilings. Recipe cross-binding reads are transient (never retained)
    # and remain governed by those aggregate limits; later bundle consumption is
    # charged separately to BundleBudget.
    for recipe in recipe_records:
        request_id = recipe["request_id"]
        direct_request = next(
            request for request in direct_plan["requests"] if request["id"] == request_id
        )
        source = _read_verified_source(
            direct_reader,
            request_id,
            direct_request["url"],
            direct_request["digest"],
            direct_request["algorithm"],
            max_bytes=direct_request["max_bytes"],
        )
        if (
            len(source.content) != recipe["size"]
            or hashlib.sha256(source.content).hexdigest() != recipe["object_sha256"]
        ):
            raise EvidenceError(f"Alpine source plan has a stale recipe binding: {request_id}")


def _close_verified_source_readers(
    *readers: verified_source_store.VerifiedSourceStoreReader,
) -> None:
    """Recheck every retained source snapshot before publishing the bundle."""

    failures: list[str] = []
    for reader in readers:
        try:
            reader.close()
        except verified_source_store.SourceStoreError as exc:
            failures.append(str(exc))
    if failures:
        raise EvidenceError(
            "verified source store changed before bundle publication: " + "; ".join(failures)
        )


@dataclass(frozen=True)
class _NodeIdentity:
    device: int
    inode: int
    mode: int
    links: int
    uid: int
    gid: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _RetainedInputPath:
    argument: Path
    resolved: Path
    identity: _NodeIdentity


@dataclass
class _ExclusiveOutputTarget:
    argument: Path
    parent_argument: Path
    parent_resolved: Path
    name: str
    parent_descriptor: int
    parent_identity: _NodeIdentity
    created: bool = False
    published_identity: _NodeIdentity | None = None


def _node_identity(metadata: os.stat_result, source: str) -> _NodeIdentity:
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
        raise EvidenceError(f"{source} must be a regular file or directory")
    return _NodeIdentity(
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


def _same_node_binding(first: _NodeIdentity, second: _NodeIdentity) -> bool:
    return (
        first.device,
        first.inode,
        first.mode,
        first.uid,
        first.gid,
    ) == (
        second.device,
        second.inode,
        second.mode,
        second.uid,
        second.gid,
    )


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _open_bound_directory(path: Path, source: str) -> tuple[int, _NodeIdentity]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise EvidenceError("bundle path isolation requires no-follow directory support")
    try:
        before = _node_identity(os.stat(path, follow_symlinks=False), source)
        if not stat.S_ISDIR(before.mode):
            raise EvidenceError(f"{source} must be a real directory")
        descriptor = os.open(
            path,
            os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0),
        )
        opened = _node_identity(os.fstat(descriptor), source)
        current = _node_identity(os.stat(path, follow_symlinks=False), source)
    except EvidenceError:
        raise
    except OSError as exc:
        raise EvidenceError(f"cannot open {source} safely") from exc
    if opened != before or current != before:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise EvidenceError(f"{source} changed while it was opened")
    return descriptor, opened


class BundlePathBoundary:
    """Hold filesystem identities while publishing without following links."""

    def __init__(
        self,
        *,
        work_root: Path,
        inputs: Sequence[Path],
        output: Path,
        predicate_output: Path,
    ) -> None:
        self._closed = True
        self._published = False
        self._work_argument = work_root.absolute()
        try:
            work_metadata = self._work_argument.lstat()
            self._work_resolved = self._work_argument.resolve(strict=True)
        except OSError as exc:
            raise EvidenceError("cannot inspect bundle work root safely") from exc
        if not stat.S_ISDIR(work_metadata.st_mode) or self._work_argument.is_symlink():
            raise EvidenceError("bundle work root must be an existing directory, not a link")
        self._work_descriptor, self._work_identity = _open_bound_directory(
            self._work_resolved,
            "bundle work root",
        )
        output_descriptors: list[int] = []
        try:
            if os.listdir(self._work_descriptor):
                raise EvidenceError("bundle work root must be an empty dedicated directory")

            retained_inputs: list[_RetainedInputPath] = []
            for raw_path in inputs:
                argument = raw_path.absolute()
                try:
                    resolved = argument.resolve(strict=True)
                    identity = _node_identity(
                        os.stat(resolved, follow_symlinks=False),
                        f"bundle input {argument}",
                    )
                except EvidenceError:
                    raise
                except OSError as exc:
                    raise EvidenceError(f"cannot inspect bundle input {argument}") from exc
                if _paths_overlap(self._work_resolved, resolved):
                    raise EvidenceError("bundle work root overlaps a retained input")
                retained_inputs.append(_RetainedInputPath(argument, resolved, identity))
            self._inputs = tuple(retained_inputs)

            output_arguments = (
                output.absolute(),
                output.with_suffix(output.suffix + ".sha256").absolute(),
                predicate_output.absolute(),
            )
            targets: list[_ExclusiveOutputTarget] = []
            physical_targets: list[Path] = []
            for argument in output_arguments:
                if not argument.name:
                    raise EvidenceError("bundle output has no filename")
                parent_argument = argument.parent
                try:
                    parent_resolved = parent_argument.resolve(strict=True)
                except OSError as exc:
                    raise EvidenceError("bundle output parent does not exist") from exc
                parent_descriptor, parent_identity = _open_bound_directory(
                    parent_resolved,
                    "bundle output parent",
                )
                output_descriptors.append(parent_descriptor)
                physical = parent_resolved / argument.name
                if _paths_overlap(self._work_resolved, physical):
                    raise EvidenceError("bundle output overlaps the dedicated work root")
                if any(_paths_overlap(physical, item.resolved) for item in self._inputs):
                    raise EvidenceError("bundle output overlaps a retained input")
                if physical in physical_targets:
                    raise EvidenceError("bundle output paths must be distinct")
                physical_targets.append(physical)
                targets.append(
                    _ExclusiveOutputTarget(
                        argument=argument,
                        parent_argument=parent_argument,
                        parent_resolved=parent_resolved,
                        name=argument.name,
                        parent_descriptor=parent_descriptor,
                        parent_identity=parent_identity,
                    )
                )
            self._targets = tuple(targets)

            # A previous invocation may have left output behind. Remove only
            # these three names, relative to retained directory descriptors,
            # before any evidence work begins.
            self._remove_outputs()
            self._require_boundaries_unchanged(require_outputs_absent=True)
        except BaseException:
            for descriptor in output_descriptors:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            with contextlib.suppress(OSError):
                os.close(self._work_descriptor)
            raise
        self._closed = False

    def __enter__(self) -> BundlePathBoundary:
        if self._closed:
            raise EvidenceError("bundle path boundary is closed")
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> None:
        del exception, traceback
        try:
            if exception_type is not None:
                self._remove_outputs()
        finally:
            self.close()

    @property
    def work_directory(self) -> Path:
        if self._closed:
            raise EvidenceError("bundle path boundary is closed")
        return Path(f"/proc/self/fd/{self._work_descriptor}")

    @property
    def work_descriptor(self) -> int:
        if self._closed:
            raise EvidenceError("bundle path boundary is closed")
        return self._work_descriptor

    def _remove_outputs(self) -> None:
        for target in getattr(self, "_targets", ()):
            try:
                os.unlink(target.name, dir_fd=target.parent_descriptor)
            except FileNotFoundError:
                # An absent output is already clean; reset its bookkeeping below.
                pass
            except IsADirectoryError as exc:
                raise EvidenceError("bundle output path is a directory") from exc
            except OSError as exc:
                raise EvidenceError("cannot clear bundle output safely") from exc
            target.created = False
            target.published_identity = None
        self._published = False

    def _require_boundaries_unchanged(self, *, require_outputs_absent: bool) -> None:
        try:
            if self._work_argument.resolve(strict=True) != self._work_resolved:
                raise EvidenceError("bundle work root changed physical location")
            if not _same_node_binding(
                _node_identity(os.fstat(self._work_descriptor), "bundle work root"),
                self._work_identity,
            ) or not _same_node_binding(
                _node_identity(
                    os.stat(self._work_resolved, follow_symlinks=False),
                    "bundle work root",
                ),
                self._work_identity,
            ):
                raise EvidenceError("bundle work root changed while retained")
            for item in self._inputs:
                if (
                    item.argument.resolve(strict=True) != item.resolved
                    or _node_identity(
                        os.stat(item.resolved, follow_symlinks=False),
                        f"bundle input {item.argument}",
                    )
                    != item.identity
                ):
                    raise EvidenceError("bundle input changed physical identity")
            for target in self._targets:
                if target.parent_argument.resolve(strict=True) != target.parent_resolved:
                    raise EvidenceError("bundle output parent changed physical location")
                if not _same_node_binding(
                    _node_identity(
                        os.fstat(target.parent_descriptor),
                        "bundle output parent",
                    ),
                    target.parent_identity,
                ) or not _same_node_binding(
                    _node_identity(
                        os.stat(target.parent_resolved, follow_symlinks=False),
                        "bundle output parent",
                    ),
                    target.parent_identity,
                ):
                    raise EvidenceError("bundle output parent changed while retained")
                if require_outputs_absent:
                    try:
                        os.stat(
                            target.name,
                            dir_fd=target.parent_descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        raise EvidenceError("bundle output appeared before publication")
                elif target.created:
                    current = _node_identity(
                        os.stat(
                            target.name,
                            dir_fd=target.parent_descriptor,
                            follow_symlinks=False,
                        ),
                        "published bundle output",
                    )
                    if current != target.published_identity:
                        raise EvidenceError("published bundle output changed during publication")
        except EvidenceError:
            raise
        except OSError as exc:
            raise EvidenceError("bundle path boundary changed while retained") from exc

    def _publish_one(self, source_path: Path, target: _ExclusiveOutputTarget) -> None:
        source_descriptor = -1
        output_descriptor = -1
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            source_descriptor = os.open(
                source_path,
                os.O_RDONLY | os.O_NONBLOCK | nofollow | getattr(os, "O_CLOEXEC", 0),
            )
            metadata = os.fstat(source_descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise EvidenceError("staged bundle output is not one regular file")
            output_descriptor = os.open(
                target.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=target.parent_descriptor,
            )
            remaining = metadata.st_size
            offset = 0
            while remaining:
                chunk = os.pread(source_descriptor, min(1024 * 1024, remaining), offset)
                if not chunk:
                    raise EvidenceError("staged bundle output was truncated")
                position = 0
                while position < len(chunk):
                    written = os.write(output_descriptor, chunk[position:])
                    if written <= 0:
                        raise EvidenceError("cannot make progress publishing bundle output")
                    position += written
                offset += len(chunk)
                remaining -= len(chunk)
            if os.pread(source_descriptor, 1, offset):
                raise EvidenceError("staged bundle output grew during publication")
            final_source_metadata = os.fstat(source_descriptor)
            if (
                _node_identity(final_source_metadata, "staged bundle output")
                != _node_identity(metadata, "staged bundle output")
                or final_source_metadata.st_size != metadata.st_size
                or final_source_metadata.st_mtime_ns != metadata.st_mtime_ns
                or final_source_metadata.st_ctime_ns != metadata.st_ctime_ns
            ):
                raise EvidenceError("staged bundle output changed during publication")
            os.fchmod(output_descriptor, 0o644)
            os.fsync(output_descriptor)
            published = _node_identity(
                os.fstat(output_descriptor),
                "published bundle output",
            )
            current = _node_identity(
                os.stat(
                    target.name,
                    dir_fd=target.parent_descriptor,
                    follow_symlinks=False,
                ),
                "published bundle output",
            )
            if current != published:
                raise EvidenceError("published bundle output was replaced during publication")
            target.created = True
            target.published_identity = published
        except EvidenceError:
            raise
        except OSError as exc:
            raise EvidenceError("cannot publish bundle output safely") from exc
        finally:
            if output_descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(output_descriptor)
            if source_descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(source_descriptor)

    def publish(
        self,
        *,
        bundle: Path,
        checksum: Path,
        predicate: Path,
    ) -> None:
        if self._closed or self._published:
            raise EvidenceError("bundle path boundary cannot publish")
        self._require_boundaries_unchanged(require_outputs_absent=True)
        try:
            for source_path, target in zip(
                (bundle, checksum, predicate),
                self._targets,
                strict=True,
            ):
                self._publish_one(source_path, target)
            self._require_boundaries_unchanged(require_outputs_absent=False)
        except BaseException:
            self._remove_outputs()
            raise
        self._published = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for target in self._targets:
            with contextlib.suppress(OSError):
                os.close(target.parent_descriptor)
        with contextlib.suppress(OSError):
            os.close(self._work_descriptor)

    def abort(self) -> None:
        """Remove every final output and close a boundary not yet entered."""

        if self._closed:
            return
        try:
            self._remove_outputs()
        finally:
            self.close()


def parse_lock_sources_bytes(
    content: bytes,
    source: str,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Parse Python source records from lock-file bytes that were read once."""

    try:
        lock = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError(f"cannot parse {source}: {exc}") from exc
    packages = lock.get("package")
    if not isinstance(packages, list) or len(packages) > MAX_COMPONENTS:
        raise EvidenceError("lock file has an invalid package list")
    sources: dict[tuple[str, str], dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise EvidenceError("lock file has an invalid package record")
        raw_name = package.get("name", "")
        version = package.get("version", "")
        sdist = package.get("sdist")
        if not isinstance(raw_name, str) or not isinstance(version, str):
            raise EvidenceError("lock file has invalid package identity fields")
        name = normalize_package_name(raw_name)
        if not name or not version or sdist is None:
            continue
        if not isinstance(sdist, dict) or set(sdist) not in (
            {"url", "hash", "size"},
            {"url", "hash", "size", "upload-time"},
        ):
            raise EvidenceError(f"locked sdist has an invalid record: {name} {version}")
        upload_time = sdist.get("upload-time")
        if upload_time is not None:
            if not isinstance(upload_time, str):
                raise EvidenceError(f"locked sdist has an invalid upload time: {name} {version}")
            checked_scalar(upload_time, f"locked sdist upload time for {name} {version}")
        hash_value = sdist.get("hash", "")
        if (
            not isinstance(hash_value, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", hash_value) is None
        ):
            raise EvidenceError(f"locked sdist has no SHA-256: {name} {version}")
        url = sdist.get("url")
        size = sdist.get("size")
        if not isinstance(url, str):
            raise EvidenceError(f"locked sdist has no URL: {name} {version}")
        require_https_source_url(url)
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_DOWNLOAD_BYTES
        ):
            raise EvidenceError(f"locked sdist has an invalid size: {name} {version}")
        key = (name, version)
        if key in sources:
            raise EvidenceError(f"lock file repeats Python source: {name} {version}")
        sources[key] = {
            "url": url,
            "sha256": hash_value.removeprefix("sha256:"),
            "size": size,
        }
    return sources


def parse_lock_sources(lock_path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    return parse_lock_sources_bytes(
        read_stable_local_bytes(
            lock_path,
            max_bytes=MAX_JSON_BYTES,
            source=f"lock file {lock_path}",
        ),
        str(lock_path),
    )


def native_wheel_contexts(inventory: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the exact installed-wheel owners exposing native or SBOM payloads."""

    payloads: dict[str, dict[str, list[Mapping[str, Any]]]] = {}
    for category in ("native_payloads", "embedded_sboms"):
        records = inventory.get(category)
        if not isinstance(records, list) or len(records) > MAX_IMAGE_MEMBERS:
            raise EvidenceError(f"component inventory has invalid {category}")
        for record in records:
            owner = record.get("owner") if isinstance(record, dict) else None
            if not isinstance(owner, str):
                raise EvidenceError(f"component inventory {category} has no wheel owner")
            payloads.setdefault(
                owner,
                {"native_payloads": [], "embedded_sboms": []},
            )[category].append(record)

    components: dict[str, Mapping[str, Any]] = {}
    for component in inventory.get("components", []):
        if not isinstance(component, dict) or component.get("ecosystem") != "python":
            continue
        owner = component_key(component)
        if owner in components:
            raise EvidenceError(f"component inventory repeats native-wheel owner: {owner}")
        components[owner] = component

    installations_by_owner: dict[str, list[Mapping[str, Any]]] = {}
    installations = inventory.get("wheel_installations")
    if not isinstance(installations, list) or len(installations) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("component inventory has invalid historical Python installations")
    for installation in installations:
        owner = installation.get("owner") if isinstance(installation, dict) else None
        if isinstance(owner, str) and owner in payloads:
            installations_by_owner.setdefault(owner, []).append(installation)

    contexts: dict[str, dict[str, Any]] = {}
    for owner in sorted(payloads):
        component = components.get(owner)
        if component is None:
            raise EvidenceError(f"native-wheel payload has no Python component: {owner}")
        matching_installations = installations_by_owner.get(owner, [])
        if len(matching_installations) != 1:
            raise EvidenceError(
                f"native-wheel owner must have exactly one historical installation: {owner}"
            )
        contexts[owner] = {
            "component": component,
            "installation": matching_installations[0],
            **payloads[owner],
        }
    return contexts


def wheel_tag_matches_native_platform(tag: Any, platform: str) -> bool:
    """Require the locked wheel to target the reviewed musl platform and architecture."""

    architecture = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}.get(platform)
    if architecture is None:
        raise EvidenceError(f"unsupported native-wheel platform: {platform}")
    wheel_platform = getattr(tag, "platform", None)
    if not isinstance(wheel_platform, str):
        return False
    match = re.fullmatch(rf"musllinux_([0-9]+)_([0-9]+)_{architecture}", wheel_platform)
    if match is None:
        return False
    required = (int(match.group(1)), int(match.group(2)))
    if required not in {(1, 1), (1, 2)}:
        return False
    compatible = set(
        cpython_tags(
            python_version=(3, 14),
            abis=["cp314"],
            platforms=[
                f"musllinux_1_2_{architecture}",
                f"musllinux_1_1_{architecture}",
            ],
        )
    )
    return tag in compatible


def raw_wheel_build_tag(filename: str, parsed_build: tuple[()] | tuple[int, str]) -> str:
    """Return the exact filename Build field without packaging normalization."""

    if not filename.endswith(".whl"):
        raise EvidenceError(f"locked wheel has an invalid filename: {filename}")
    fields = filename.removesuffix(".whl").split("-")
    if len(fields) not in {5, 6}:
        raise EvidenceError(f"locked wheel has an invalid filename: {filename}")
    build = fields[2] if len(fields) == 6 else ""
    if bool(parsed_build) != bool(build) or (
        build and re.fullmatch(r"[0-9]+[A-Za-z0-9_.]*", build) is None
    ):
        raise EvidenceError(f"locked wheel has an invalid Build field: {filename}")
    return build


def select_locked_native_wheels_bytes(
    content: bytes,
    source: str,
    inventory: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Select native wheels from lock-file bytes that were read once."""

    contexts = native_wheel_contexts(inventory)
    if not contexts:
        return []
    try:
        lock = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError(f"cannot parse {source}: {exc}") from exc
    packages = lock.get("package")
    if not isinstance(packages, list) or len(packages) > MAX_COMPONENTS:
        raise EvidenceError("lock file has an invalid package list")

    requested = {
        (str(context["component"]["name"]), str(context["component"]["version"])): owner
        for owner, context in contexts.items()
    }
    packages_by_key: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise EvidenceError("lock file has an invalid package record")
        raw_name = package.get("name")
        version = package.get("version")
        if not isinstance(raw_name, str) or not isinstance(version, str):
            raise EvidenceError("lock file has invalid package identity fields")
        name = normalize_package_name(raw_name)
        key = (name, version)
        if key in requested:
            packages_by_key.setdefault(key, []).append(package)

    platform = inventory.get("platform")
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise EvidenceError("component inventory has an unsupported native-wheel platform")
    selected: list[dict[str, Any]] = []
    for key, owner in sorted(requested.items(), key=lambda item: item[1]):
        matches = packages_by_key.get(key, [])
        if len(matches) != 1:
            raise EvidenceError(
                f"lock file must contain exactly one native-wheel package: {key[0]} {key[1]}"
            )
        package = matches[0]
        wheels = package.get("wheels")
        if not isinstance(wheels, list) or not wheels or len(wheels) > MAX_SOURCE_ZIP_ENTRIES:
            raise EvidenceError(f"locked package has an invalid wheel list: {key[0]} {key[1]}")
        installation = contexts[owner]["installation"]
        installed_tags = installation.get("tags")
        installed_build = installation.get("build")
        if (
            not isinstance(installed_tags, list)
            or not installed_tags
            or any(not isinstance(tag, str) for tag in installed_tags)
            or not isinstance(installed_build, str)
        ):
            raise EvidenceError(f"native-wheel installation has invalid tags or build: {owner}")

        candidates: list[dict[str, Any]] = []
        for wheel in wheels:
            if not isinstance(wheel, dict) or set(wheel) not in (
                {"url", "hash", "size"},
                {"url", "hash", "size", "upload-time"},
            ):
                raise EvidenceError(f"locked wheel has an invalid record: {key[0]} {key[1]}")
            upload_time = wheel.get("upload-time")
            if upload_time is not None:
                if not isinstance(upload_time, str):
                    raise EvidenceError(
                        f"locked wheel has an invalid upload time: {key[0]} {key[1]}"
                    )
                checked_scalar(upload_time, f"locked wheel upload time for {key[0]} {key[1]}")
            url = wheel.get("url")
            hash_value = wheel.get("hash")
            size = wheel.get("size")
            if not isinstance(url, str):
                raise EvidenceError(f"locked wheel has no URL: {key[0]} {key[1]}")
            require_https_source_url(url)
            if (
                not isinstance(hash_value, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", hash_value) is None
            ):
                raise EvidenceError(f"locked wheel has no SHA-256: {key[0]} {key[1]}")
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or not 0 < size <= MAX_DOWNLOAD_BYTES
            ):
                raise EvidenceError(f"locked wheel has an invalid size: {key[0]} {key[1]}")
            filename = safe_filename(url)
            try:
                parsed_name, parsed_version, build_tag, tags = parse_wheel_filename(filename)
                expected_version = Version(key[1])
            except (InvalidVersion, InvalidWheelFilename) as exc:
                raise EvidenceError(f"locked wheel has an invalid filename: {filename}") from exc
            if canonicalize_name(parsed_name) != key[0] or parsed_version != expected_version:
                raise EvidenceError(f"locked wheel filename has the wrong owner: {filename}")
            tag_strings = sorted(str(tag) for tag in tags)
            build = raw_wheel_build_tag(filename, build_tag)
            if (
                tag_strings == installed_tags
                and build == installed_build
                and all(wheel_tag_matches_native_platform(tag, str(platform)) for tag in tags)
            ):
                candidates.append(
                    {
                        "owner": owner,
                        "platform": platform,
                        "url": url,
                        "sha256": hash_value.removeprefix("sha256:"),
                        "size": size,
                        "filename": filename,
                        "build": build,
                        "tags": tag_strings,
                    }
                )
        if len(candidates) != 1:
            raise EvidenceError(
                f"lock file must select exactly one installed native wheel for {owner}; "
                f"found {len(candidates)}"
            )
        selected.append(candidates[0])
    if {record["owner"] for record in selected} != set(contexts):
        raise EvidenceError("locked native wheels do not exactly cover structured payload owners")
    return selected


def select_locked_native_wheels(
    lock_path: Path, inventory: Mapping[str, Any]
) -> list[dict[str, Any]]:
    return select_locked_native_wheels_bytes(
        read_stable_local_bytes(
            lock_path,
            max_bytes=MAX_JSON_BYTES,
            source=f"lock file {lock_path}",
        ),
        str(lock_path),
        inventory,
    )


def source_filename_pattern(source: str, origin: str) -> re.Pattern[str]:
    if any(character in source for character in ('"', "'", "`", ";")) or "$(" in source:
        raise EvidenceError(f"unsupported APKBUILD source token for {origin}: {source!r}")
    parts = source.split("::")
    if len(parts) > 2:
        raise EvidenceError(f"unsupported APKBUILD source alias for {origin}: {source!r}")
    selected = parts[0] if len(parts) == 2 else source.rsplit("/", maxsplit=1)[-1]
    if not selected or "/" in selected:
        raise EvidenceError(f"APKBUILD source has no safe basename for {origin}: {source!r}")
    fragments: list[str] = []
    position = 0
    for match in SHELL_VARIABLE.finditer(selected):
        fragments.append(re.escape(selected[position : match.start()]))
        fragments.append(r"[^/]+")
        position = match.end()
    fragments.append(re.escape(selected[position:]))
    if "$" in SHELL_VARIABLE.sub("", selected):
        raise EvidenceError(f"unsupported APKBUILD variable form for {origin}: {source!r}")
    return re.compile("".join(fragments))


def recipe_checksums(
    archive: bytes,
    origin: str,
    *,
    allow_dynamic_sources: bool = False,
    allowed_links: Sequence[Mapping[str, str]] = (),
) -> tuple[dict[str, str], set[str]]:
    expected_links: set[tuple[str, str, str]] = set()
    for entry in allowed_links:
        if set(entry) != {"path", "target", "type"}:
            raise EvidenceError(f"invalid allowed recipe link policy for {origin}")
        expected_path = str(checked_path(entry["path"]))
        target = str(checked_path(entry["target"]))
        link_type = entry["type"]
        if link_type not in {"symlink", "hardlink"}:
            raise EvidenceError(f"invalid allowed recipe link type for {origin}: {link_type}")
        record = (expected_path, target, link_type)
        if record in expected_links:
            raise EvidenceError(
                f"duplicate allowed recipe link policy for {origin}: {expected_path}"
            )
        expected_links.add(record)

    regular_hashes: dict[str, str] = {}
    regular_paths: set[str] = set()
    apkbuild: bytes | None = None
    observed_links: set[tuple[str, str, str]] = set()
    seen_paths: set[str] = set()
    try:
        with tarfile.open(
            fileobj=io.BytesIO(archive), mode="r:*", tarinfo=BoundedTarInfo
        ) as source:
            count = 0
            total = 0
            for member in source:
                count += 1
                if count > MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError(f"recipe archive has too many entries: {origin}")
                path = checked_path(member.name)
                path_string = str(path)
                if path_string in seen_paths:
                    raise EvidenceError(
                        f"recipe archive repeats an entry path: {origin}/{path_string}"
                    )
                seen_paths.add(path_string)
                if member.issym() or member.islnk():
                    if member.size != 0:
                        raise EvidenceError(f"recipe archive link has a payload: {origin}")
                    checked_link_target(member.linkname)
                    if member.issym():
                        target_path = checked_path(str(path.parent / member.linkname))
                    else:
                        target_path = checked_path(member.linkname)
                    observed_links.add(
                        (
                            path_string,
                            str(target_path),
                            "symlink" if member.issym() else "hardlink",
                        )
                    )
                    continue
                if member.isdir():
                    if member.size != 0:
                        raise EvidenceError(f"recipe archive directory has a payload: {origin}")
                    continue
                if not member.isfile():
                    raise EvidenceError(f"recipe archive has an unsupported entry: {origin}")
                regular_paths.add(path_string)
                total += member.size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise EvidenceError(f"recipe archive is too large: {origin}")
                if path.name in regular_hashes:
                    raise EvidenceError(
                        f"recipe archive repeats regular-file basename: {path.name}"
                    )
                if path.name == "APKBUILD":
                    if apkbuild is not None:
                        raise EvidenceError(
                            f"recipe archive contains multiple APKBUILD files: {origin}"
                        )
                    apkbuild = read_member(source, member)
                    regular_hashes[path.name] = hashlib.sha512(apkbuild).hexdigest()
                else:
                    regular_hashes[path.name] = hash_member(
                        source,
                        member,
                        algorithm="sha512",
                        max_bytes=MAX_DOWNLOAD_BYTES,
                    )
    except tarfile.TarError as exc:
        raise EvidenceError(f"invalid recipe archive for {origin}: {exc}") from exc
    if observed_links != expected_links:
        unexpected = sorted(observed_links - expected_links)
        missing = sorted(expected_links - observed_links)
        raise EvidenceError(
            f"recipe archive links are not allowed unless exactly pinned for {origin}; "
            f"unexpected={unexpected!r}, missing={missing!r}"
        )
    unresolved_links = sorted(
        (path, target) for path, target, _link_type in observed_links if target not in regular_paths
    )
    if unresolved_links:
        raise EvidenceError(
            f"recipe archive links must resolve directly to retained regular files for {origin}: "
            f"{unresolved_links!r}"
        )
    if apkbuild is None:
        raise EvidenceError(f"recipe archive has no APKBUILD: {origin}")
    try:
        text = apkbuild.decode()
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"APKBUILD is not UTF-8: {origin}") from exc
    matches = re.findall(r'^sha512sums="\n(.*?)\n"$', text, flags=re.MULTILINE | re.DOTALL)
    source_matches = re.findall(r'^source="(.*?)"$', text, flags=re.MULTILINE | re.DOTALL)
    has_source_assignment = re.search(r"^source=", text, flags=re.MULTILINE) is not None
    if not matches and not has_source_assignment:
        return {}, set()
    if len(source_matches) != 1 and not allow_dynamic_sources:
        raise EvidenceError(f"APKBUILD must have exactly one literal source block: {origin}")
    if len(matches) != 1:
        raise EvidenceError(f"APKBUILD must have exactly one literal sha512sums block: {origin}")
    checksums: dict[str, str] = {}
    for line in matches[0].splitlines():
        parsed = SHA512_LINE.fullmatch(line.strip())
        if parsed is None:
            raise EvidenceError(f"unsupported APKBUILD checksum line for {origin}: {line!r}")
        digest, filename = parsed.groups()
        checked_path(filename)
        if PurePosixPath(filename).name != filename:
            raise EvidenceError(f"APKBUILD checksum filename must be a basename: {filename}")
        if filename in checksums:
            raise EvidenceError(f"duplicate APKBUILD source filename: {filename}")
        checksums[filename] = digest
    if not checksums:
        raise EvidenceError(f"APKBUILD source list has no checksummed files: {origin}")
    if not allow_dynamic_sources:
        sources = source_matches[0].split()
        if len(sources) != len(checksums):
            raise EvidenceError(
                f"APKBUILD source and checksum counts differ for {origin}: "
                f"{len(sources)} source(s), {len(checksums)} checksum(s)"
            )
        for source_token, filename in zip(sources, checksums, strict=True):
            if source_filename_pattern(source_token, origin).fullmatch(filename) is None:
                raise EvidenceError(
                    f"APKBUILD checksum filename {filename!r} does not match "
                    f"source {source_token!r} for {origin}"
                )
    link_basenames = {PurePosixPath(path).name for path, _target, _type in observed_links}
    conflicts = sorted(link_basenames & ({"APKBUILD"} | set(checksums)))
    if conflicts:
        raise EvidenceError(
            f"allowed recipe links conflict with authoritative source files for {origin}: "
            f"{', '.join(conflicts)}"
        )
    local_sources: set[str] = set()
    for filename, expected in checksums.items():
        actual = regular_hashes.get(filename)
        if actual is None:
            continue
        if actual != expected:
            raise EvidenceError(
                f"local recipe source checksum mismatch for {origin}/{filename}: "
                f"expected {expected}, got {actual}"
            )
        local_sources.add(filename)
    return checksums, local_sources


def native_alpine_recipe_metadata(archive: bytes, origin: str) -> dict[str, str]:
    """Read exact literal identity and license fields from a validated aports recipe."""

    apkbuild: bytes | None = None
    try:
        with tarfile.open(
            fileobj=io.BytesIO(archive), mode="r:*", tarinfo=BoundedTarInfo
        ) as source:
            for member in source:
                path = checked_path(member.name)
                if path.parts[-3:] != ("main", origin, "APKBUILD"):
                    continue
                if apkbuild is not None or not member.isfile():
                    raise EvidenceError(
                        f"native-component recipe has an ambiguous APKBUILD: {origin}"
                    )
                apkbuild = read_member(source, member)
    except tarfile.TarError as exc:
        raise EvidenceError(f"invalid native-component recipe archive for {origin}: {exc}") from exc
    if apkbuild is None:
        raise EvidenceError(f"native-component recipe has no exact APKBUILD path: {origin}")
    try:
        text = apkbuild.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"native-component APKBUILD is not UTF-8: {origin}") from exc

    def one_literal(pattern: str, field: str) -> str:
        matches = re.findall(pattern, text, flags=re.MULTILINE)
        if len(matches) != 1:
            raise EvidenceError(
                f"native-component APKBUILD has no unique literal {field}: {origin}"
            )
        return checked_scalar(matches[0], f"native-component APKBUILD {field}")

    return {
        "origin": one_literal(r"^pkgname=([a-z0-9][a-z0-9+._-]*)$", "pkgname"),
        "pkgver": one_literal(r"^pkgver=([A-Za-z0-9.+_~-]+)$", "pkgver"),
        "pkgrel": one_literal(r"^pkgrel=([0-9]+)$", "pkgrel"),
        "observed_license": one_literal(r'^license="([^"\r\n]+)"$', "license"),
    }


def verify_native_component_recipe(
    source_id: str, source: Mapping[str, Any], archive: bytes
) -> None:
    """Bind one source policy to literal recipe metadata and every upstream distfile."""

    origin = str(source["origin"])
    checksums, local_sources = recipe_checksums(
        archive,
        origin,
        allowed_links=source["allowed_recipe_links"],
    )
    metadata = native_alpine_recipe_metadata(archive, origin)
    expected_version = f"{metadata['pkgver']}-r{metadata['pkgrel']}"
    if (
        metadata["origin"] != origin
        or expected_version != source["version"]
        or metadata["observed_license"] != source["observed_license"]
    ):
        raise EvidenceError(f"native-component recipe metadata differs for {source_id}")
    observed_upstream = {
        filename: digest for filename, digest in checksums.items() if filename not in local_sources
    }
    expected_upstream = {
        str(record["filename"]): str(record["sha512"]) for record in source["distfiles"]
    }
    if observed_upstream != expected_upstream:
        raise EvidenceError(
            f"native-component recipe distfiles differ from reviewed policy for {source_id}"
        )


def reviewed_files_from_source_archive(
    archive: bytes,
    *,
    archive_name: str,
    source_id: str,
    expected: Mapping[str, Mapping[str, Any]],
    max_member_bytes: int = MAX_LICENSE_BYTES,
    max_archive_bytes: int = MAX_DOWNLOAD_BYTES,
) -> dict[str, bytes]:
    """Validate a hostile archive and return the reviewed regular files it contains."""

    if not 0 < max_archive_bytes <= MAX_ALPINE_DISTFILE_BYTES:
        raise EvidenceError("reviewed source archive has an invalid input-size limit")
    if len(archive) > max_archive_bytes:
        raise EvidenceError(f"reviewed source archive exceeds its input-size limit: {source_id}")
    found: dict[str, bytes] = {}
    try:
        zip_candidate = (
            archive_name.lower().endswith(".zip")
            or archive.startswith(ZIP_SIGNATURES)
            or has_source_zip_eocd(archive)
        )
        if zip_candidate:
            central_offset, central_size, entry_count = preflight_source_zip(
                archive,
                max_archive_bytes=max_archive_bytes,
            )
            central_entries = read_source_zip_central_directory(
                archive,
                central_offset,
                central_size,
                entry_count,
            )
            entries = validate_source_zip_entries(
                archive,
                central_offset,
                central_entries,
            )
            for entry in entries:
                metadata = entry.metadata
                path = str(checked_path(metadata.name))
                if path not in expected:
                    continue
                if metadata.name.endswith("/"):
                    raise EvidenceError(f"reviewed source file is not regular: {source_id}/{path}")
                content = read_source_zip_payload(
                    archive,
                    entry,
                    max_bytes=max_member_bytes,
                    purpose="reviewed source file",
                )
                requirement = expected[path]
                if (
                    len(content) != requirement["size"]
                    or sha256_bytes(content) != requirement["sha256"]
                ):
                    raise EvidenceError(f"reviewed source file differs: {source_id}/{path}")
                found[path] = content
            return found

        seen_paths: set[str] = set()
        total = 0
        with tarfile.open(
            fileobj=io.BytesIO(archive), mode="r:*", tarinfo=BoundedTarInfo
        ) as tar_source:
            for count, member in enumerate(tar_source, start=1):
                if count > MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError(f"source archive has too many entries: {source_id}")
                path = str(checked_path(member.name))
                if path in seen_paths:
                    raise EvidenceError(f"source archive repeats an entry path: {source_id}/{path}")
                seen_paths.add(path)
                if member.isdir():
                    if member.size != 0:
                        raise EvidenceError(
                            f"source archive directory has a payload: {source_id}/{path}"
                        )
                    continue
                if member.issym() or member.islnk():
                    if member.size != 0:
                        raise EvidenceError(
                            f"source archive link has a payload: {source_id}/{path}"
                        )
                    checked_link_target(member.linkname)
                    if path in expected:
                        raise EvidenceError(
                            f"reviewed source file is not regular: {source_id}/{path}"
                        )
                    continue
                if (
                    not member.isfile()
                    or member.issparse()
                    or member.size < 0
                    or member.size > MAX_ARCHIVE_MEMBER_BYTES
                ):
                    raise EvidenceError(
                        f"source archive has an unsupported entry: {source_id}/{path}"
                    )
                total += member.size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise EvidenceError(f"source archive exceeds the size limit: {source_id}")
                if path not in expected:
                    continue
                if member.size > max_member_bytes:
                    raise EvidenceError(
                        f"reviewed source file exceeds its size limit: {source_id}/{path}"
                    )
                content = read_member(tar_source, member)
                requirement = expected[path]
                if (
                    len(content) != requirement["size"]
                    or sha256_bytes(content) != requirement["sha256"]
                ):
                    raise EvidenceError(f"reviewed source file differs: {source_id}/{path}")
                found[path] = content
        return found
    except EvidenceError:
        raise
    except (tarfile.TarError, RuntimeError, OverflowError, ValueError) as exc:
        raise EvidenceError(f"invalid source archive for {source_id}: {exc}") from exc


def retain_reviewed_native_notices(
    found: Mapping[str, bytes],
    *,
    component_directory: str,
    root: Path,
    budget: BundleBudget,
) -> list[str]:
    """Retain one copy of each reviewed native notice name and payload."""

    written: list[str] = []
    retained: set[tuple[str, str]] = set()
    for notice_member, content in sorted(found.items()):
        digest = sha256_bytes(content)
        basename = PurePosixPath(notice_member).name
        identity = (digest, basename)
        if identity in retained:
            continue
        retained.add(identity)
        relative = f"licenses/from-source/{component_directory}/{digest[:12]}-{basename}"
        write_file(root, relative, content, budget=budget)
        written.append(relative)
    return written


def retain_native_component_notices(
    archive: bytes,
    source_id: str,
    source: Mapping[str, Any],
    root: Path,
    *,
    budget: BundleBudget,
) -> list[str]:
    """Retain only exact reviewed notices while validating the whole hostile source tar."""

    expected = {str(record["member"]): record for record in source["notices"]}
    found: dict[str, bytes] = {}
    seen_paths: set[str] = set()
    total = 0
    try:
        with tarfile.open(
            fileobj=io.BytesIO(archive), mode="r:*", tarinfo=BoundedTarInfo
        ) as tar_source:
            for count, member in enumerate(tar_source, start=1):
                if count > MAX_ARCHIVE_MEMBERS:
                    raise EvidenceError(
                        f"native-component source has too many entries: {source_id}"
                    )
                path = str(checked_path(member.name))
                if path in seen_paths:
                    raise EvidenceError(
                        f"native-component source repeats an archive path: {source_id}/{path}"
                    )
                seen_paths.add(path)
                if member.isdir():
                    if member.size != 0:
                        raise EvidenceError(
                            f"native-component source directory has a payload: {source_id}"
                        )
                    continue
                if member.issym() or member.islnk():
                    if member.size != 0:
                        raise EvidenceError(
                            f"native-component source link has a payload: {source_id}"
                        )
                    checked_link_target(member.linkname)
                    if path in expected:
                        raise EvidenceError(
                            f"native-component notice is not a regular file: {source_id}/{path}"
                        )
                    continue
                if not member.isfile():
                    raise EvidenceError(
                        f"native-component source has an unsupported entry: {source_id}/{path}"
                    )
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise EvidenceError(
                        f"native-component source member exceeds the size limit: {source_id}/{path}"
                    )
                total += member.size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise EvidenceError(f"native-component source is too large: {source_id}")
                if path not in expected:
                    continue
                content = read_member(tar_source, member)
                requirement = expected[path]
                if (
                    len(content) != requirement["size"]
                    or sha256_bytes(content) != requirement["sha256"]
                ):
                    raise EvidenceError(
                        f"native-component notice differs from reviewed policy: {source_id}/{path}"
                    )
                found[path] = content
    except EvidenceError:
        raise
    except (tarfile.TarError, RuntimeError, OverflowError, ValueError) as exc:
        raise EvidenceError(
            f"invalid native-component source archive for {source_id}: {exc}"
        ) from exc
    if set(found) != set(expected):
        missing = ", ".join(sorted(set(expected) - set(found)))
        raise EvidenceError(
            f"native-component source omits reviewed notices: {source_id}: {missing}"
        )

    return retain_reviewed_native_notices(
        found,
        component_directory=f"native-{source['origin']}-{source['version']}",
        root=root,
        budget=budget,
    )


def source_policy_entry(policy: Mapping[str, Any], name: str, version: str) -> dict[str, Any]:
    entries = policy.get("python_sources", [])
    for entry in entries:
        if (
            isinstance(entry, dict)
            and normalize_package_name(str(entry.get("name", ""))) == name
            and entry.get("version") == version
        ):
            return entry
    raise EvidenceError(f"no reviewed source policy for Python component {name} {version}")


def validate_source_policy_coverage(
    inventory: Mapping[str, Any],
    policy: Mapping[str, Any],
    lock_sources: Mapping[tuple[str, str], Mapping[str, Any]],
) -> None:
    """Reject ambiguous or unused source and license policy records."""

    python_components = {
        (component["name"], component["version"])
        for component in inventory["components"]
        if component["ecosystem"] == "python" and component["name"] != APPLICATION_NAME
    }
    expected_python_fallbacks = python_components - set(lock_sources)
    configured_python = policy.get("python_sources")
    if not isinstance(configured_python, list):
        raise EvidenceError("policy has no Python source fallbacks")
    configured_python_keys: set[tuple[str, str]] = set()
    for entry in configured_python:
        if not isinstance(entry, dict):
            raise EvidenceError("policy has an invalid Python source fallback")
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise EvidenceError("policy has an invalid Python source identity")
        key = (normalize_package_name(name), version)
        if key in configured_python_keys:
            raise EvidenceError(f"policy repeats Python source fallback: {key[0]} {key[1]}")
        configured_python_keys.add(key)
    if configured_python_keys != expected_python_fallbacks:
        raise EvidenceError(
            "Python source fallback policy does not exactly cover components absent from uv.lock"
        )

    expected_recipes = {
        f"{component['origin']}@{component['aports_commit']}"
        for component in inventory["components"]
        if component["ecosystem"] == "alpine"
    }
    recipe_policy = policy.get("alpine_recipe_archives")
    if not isinstance(recipe_policy, dict) or set(recipe_policy) != expected_recipes:
        raise EvidenceError("Alpine recipe policy does not exactly cover installed package origins")
    recipe_exceptions = policy.get("alpine_recipe_exceptions")
    if not isinstance(recipe_exceptions, dict) or not set(recipe_exceptions) <= expected_recipes:
        raise EvidenceError("Alpine recipe exceptions contain an unused origin")

    validate_native_component_policy_schema(policy)
    validate_standard_license_text_coverage(inventory["components"], policy)


def alpine_recipe_exception(
    policy: Mapping[str, Any], key: str
) -> tuple[bool, tuple[Mapping[str, str], ...]]:
    exceptions = policy.get("alpine_recipe_exceptions", {})
    if not isinstance(exceptions, dict):
        raise EvidenceError("invalid Alpine recipe exception policy")
    raw = exceptions.get(key)
    if raw is None:
        return False, ()
    if not isinstance(raw, dict) or not raw:
        raise EvidenceError(f"invalid Alpine recipe exception for {key}")
    if set(raw) - {"allow_dynamic_sources", "allowed_links", "rationale"}:
        raise EvidenceError(f"unknown Alpine recipe exception field for {key}")
    rationale = raw.get("rationale")
    if not isinstance(rationale, str):
        raise EvidenceError(f"Alpine recipe exception has no rationale for {key}")
    checked_rationale = checked_scalar(
        rationale,
        f"Alpine recipe exception rationale for {key}",
        max_length=MAX_LICENSE_FIELD_LENGTH,
    )
    if checked_rationale != rationale:
        raise EvidenceError(f"Alpine recipe exception has a non-canonical rationale for {key}")
    dynamic = raw.get("allow_dynamic_sources", False)
    if not isinstance(dynamic, bool):
        raise EvidenceError(f"invalid dynamic-source exception for {key}")
    links = raw.get("allowed_links", [])
    if not isinstance(links, list) or len(links) > MAX_COMPONENTS:
        raise EvidenceError(f"invalid allowed recipe links for {key}")
    validated_links: list[Mapping[str, str]] = []
    seen_paths: set[str] = set()
    for link in links:
        if not isinstance(link, dict) or set(link) != {"path", "target", "type"}:
            raise EvidenceError(f"invalid allowed recipe link policy for {key}")
        path_value = link.get("path")
        target = link.get("target")
        link_type = link.get("type")
        if (
            not isinstance(path_value, str)
            or not isinstance(target, str)
            or not isinstance(link_type, str)
        ):
            raise EvidenceError(f"invalid allowed recipe link policy for {key}")
        path = str(checked_path(path_value))
        if path != path_value:
            raise EvidenceError(f"non-canonical allowed recipe link path for {key}")
        checked_link_target(target)
        target_path = str(checked_path(target))
        if (
            target_path != target
            or path == target_path
            or PurePosixPath(path).parent != PurePosixPath(target_path).parent
        ):
            raise EvidenceError(f"allowed recipe link must target one canonical sibling for {key}")
        if link_type not in {"symlink", "hardlink"}:
            raise EvidenceError(f"invalid allowed recipe link type for {key}: {link_type}")
        if path in seen_paths:
            raise EvidenceError(f"duplicate allowed recipe link policy for {key}: {path}")
        seen_paths.add(path)
        validated_links.append({"path": path, "target": target_path, "type": link_type})
    if not dynamic and not validated_links:
        raise EvidenceError(f"Alpine recipe exception grants nothing for {key}")
    return dynamic, tuple(validated_links)


def safe_filename(value: str) -> str:
    name = PurePosixPath(urllib.parse.urlparse(value).path).name
    checked_path(name)
    return name


def write_file(
    root: Path,
    relative: str,
    content: bytes,
    *,
    budget: BundleBudget | None = None,
    max_bytes: int | None = None,
) -> Path:
    limit = MAX_ARCHIVE_MEMBER_BYTES if max_bytes is None else max_bytes
    if len(content) > limit:
        raise EvidenceError(f"bundle member exceeds the size limit: {relative}")
    path = checked_path(relative)
    destination = root.joinpath(*path.parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise EvidenceError(f"duplicate bundle path: {relative}")
    if budget is not None:
        budget.record_retained(content)
    destination.write_bytes(content)
    return destination


def bundle_member_size_limit(relative: str) -> int:
    """Return the path-scoped retained and final-archive member limit."""

    parts = PurePosixPath(relative).parts
    if parts[:2] == ("sources", "native-components"):
        return MAX_NATIVE_COMPONENT_SOURCE_BYTES
    if len(parts) == 6 and parts[:2] == ("sources", "alpine") and parts[4] == "distfiles":
        return MAX_ALPINE_DISTFILE_BYTES
    return MAX_ARCHIVE_MEMBER_BYTES


def retain_alpine_distfile(
    root: Path,
    relative: str,
    content: bytes,
    *,
    budget: BundleBudget,
) -> Path:
    """Retain one Alpine distfile using the planner's source-size contract."""

    return write_file(
        root,
        relative,
        content,
        budget=budget,
        max_bytes=bundle_member_size_limit(relative),
    )


def preflight_source_zip(
    content: bytes,
    *,
    max_archive_bytes: int = MAX_DOWNLOAD_BYTES,
) -> tuple[int, int, int]:
    """Bound a source ZIP central directory before parsing its entry list."""

    size = len(content)
    if not ZIP_EOCD.size <= size <= max_archive_bytes:
        raise EvidenceError("source ZIP has an invalid size")
    tail_size = min(size, ZIP_EOCD.size + 65_535)
    tail = content[-tail_size:]
    candidates: list[tuple[int, tuple[Any, ...]]] = []
    position = 0
    while True:
        position = tail.find(b"PK\x05\x06", position)
        if position < 0:
            break
        if position + ZIP_EOCD.size <= len(tail):
            values = ZIP_EOCD.unpack_from(tail, position)
            absolute = size - tail_size + position
            if absolute + ZIP_EOCD.size + values[-1] == size:
                candidates.append((absolute, values))
        position += 1
    if len(candidates) != 1:
        raise EvidenceError("source ZIP has no unique end-of-central-directory record")
    eocd_offset, values = candidates[0]
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = values
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
    ):
        raise EvidenceError("source ZIP uses unsupported multi-disk metadata")
    if 0xFFFF in {disk_entries, total_entries} or 0xFFFFFFFF in {
        central_size,
        central_offset,
    }:
        raise EvidenceError("source ZIP64 metadata is not supported")
    if not 0 < total_entries <= MAX_SOURCE_ZIP_ENTRIES:
        raise EvidenceError("source ZIP has an invalid entry count")
    if comment_size != 0:
        raise EvidenceError("source ZIP comments are not supported")
    if (
        central_size > MAX_SOURCE_ZIP_CENTRAL_DIRECTORY_BYTES
        or central_offset <= 0
        or central_offset + central_size != eocd_offset
    ):
        raise EvidenceError("source ZIP has an invalid central-directory boundary")
    if eocd_offset >= 20 and content[eocd_offset - 20 : eocd_offset - 16] == b"PK\x06\x07":
        raise EvidenceError("source ZIP64 metadata is not supported")
    return int(central_offset), int(central_size), int(total_entries)


def has_source_zip_eocd(content: bytes) -> bool:
    """Recognize an EOF-bound EOCD even when a hostile ZIP has a prefix."""

    tail_start = max(0, len(content) - ZIP_EOCD.size - 65_535)
    position = content.find(b"PK\x05\x06", tail_start)
    while position >= 0:
        if position + ZIP_EOCD.size <= len(content):
            comment_size = int.from_bytes(content[position + 20 : position + 22], "little")
            if position + ZIP_EOCD.size + comment_size == len(content):
                return True
        position = content.find(b"PK\x05\x06", position + 1)
    return False


def validate_source_zip_extra(
    extra: bytes,
    subject: str,
    *,
    central: bool,
) -> dict[int, tuple[int, ...]]:
    """Parse the narrow Info-ZIP timestamp and Unix-owner extra-field dialect."""

    offset = 0
    records: dict[int, tuple[int, ...]] = {}
    while offset < len(extra):
        if len(extra) - offset < ZIP_EXTRA_HEADER.size:
            raise EvidenceError(f"source ZIP has malformed extra metadata: {subject}")
        identifier, size = ZIP_EXTRA_HEADER.unpack_from(extra, offset)
        offset += ZIP_EXTRA_HEADER.size
        end = offset + size
        if end > len(extra) or identifier in records:
            raise EvidenceError(f"source ZIP has malformed extra metadata: {subject}")
        if identifier not in {0x5455, 0x7875}:
            raise EvidenceError(f"source ZIP has unsupported extra metadata: {subject}")
        payload = extra[offset:end]
        if identifier == 0x5455:
            if not payload:
                raise EvidenceError(f"source ZIP has malformed timestamp metadata: {subject}")
            flags = payload[0]
            if not flags & 0x01 or flags & ~0x07:
                raise EvidenceError(f"source ZIP has unsupported timestamp metadata: {subject}")
            value_count = 1 if central else flags.bit_count()
            if len(payload) != 1 + 4 * value_count:
                raise EvidenceError(f"source ZIP has malformed timestamp metadata: {subject}")
            values = tuple(
                int.from_bytes(payload[index : index + 4], "little")
                for index in range(1, len(payload), 4)
            )
            records[identifier] = (flags, *values)
        else:
            if len(payload) < 3 or payload[0] != 1:
                raise EvidenceError(f"source ZIP has malformed Unix-owner metadata: {subject}")
            uid_size = payload[1]
            uid_end = 2 + uid_size
            if not 1 <= uid_size <= 4 or uid_end >= len(payload):
                raise EvidenceError(f"source ZIP has malformed Unix-owner metadata: {subject}")
            gid_size = payload[uid_end]
            gid_start = uid_end + 1
            if not 1 <= gid_size <= 4 or gid_start + gid_size != len(payload):
                raise EvidenceError(f"source ZIP has malformed Unix-owner metadata: {subject}")
            uid = int.from_bytes(payload[2:uid_end], "little")
            gid = int.from_bytes(payload[gid_start:], "little")
            if uid > MAX_TAR_ID or gid > MAX_TAR_ID:
                raise EvidenceError(f"source ZIP has unsupported Unix-owner metadata: {subject}")
            records[identifier] = (uid_size, uid, gid_size, gid)
        offset = end
    return records


def validate_source_zip_timestamp(modified_time: int, modified_date: int, name: str) -> None:
    """Reject impossible DOS timestamp bitfields instead of preserving aliases."""

    seconds = (modified_time & 0x1F) * 2
    minutes = modified_time >> 5 & 0x3F
    hours = modified_time >> 11 & 0x1F
    day = modified_date & 0x1F
    month = modified_date >> 5 & 0x0F
    year = 1980 + (modified_date >> 9 & 0x7F)
    try:
        if seconds > 59 or minutes > 59 or hours > 23:
            raise ValueError("invalid DOS time")
        datetime.date(year, month, day)
    except ValueError as exc:
        raise EvidenceError(f"source ZIP has an invalid DOS timestamp: {name}") from exc


def read_source_zip_central_directory(
    content: bytes,
    central_offset: int,
    central_size: int,
    expected_entries: int,
    *,
    allow_typeless_regular: bool = False,
    allow_stored_extract_version_20: bool = False,
) -> list[SourceZipCentralEntry]:
    """Parse bounded raw central records before constructing ZipInfo objects."""

    position = central_offset
    central_end = central_offset + central_size
    entries: list[SourceZipCentralEntry] = []
    raw_names: set[bytes] = set()
    names: set[str] = set()
    path_identities: set[str] = set()
    local_offsets: set[int] = set()
    expanded_total = 0
    for _index in range(expected_entries):
        if position + ZIP_CENTRAL_HEADER.size > central_end:
            raise EvidenceError("source ZIP has a truncated central-directory record")
        (
            signature,
            version_made,
            extract_version,
            flag_bits,
            compress_type,
            modified_time,
            modified_date,
            crc,
            compress_size,
            file_size,
            name_size,
            extra_size,
            comment_size,
            disk_start,
            internal_attr,
            external_attr,
            header_offset,
        ) = ZIP_CENTRAL_HEADER.unpack_from(content, position)
        if signature != b"PK\x01\x02":
            raise EvidenceError("source ZIP central-directory signature is invalid")
        name_start = position + ZIP_CENTRAL_HEADER.size
        name_end = name_start + name_size
        extra_end = name_end + extra_size
        record_end = extra_end + comment_size
        if record_end > central_end:
            raise EvidenceError("source ZIP central-directory entry is truncated")
        raw_name = content[name_start:name_end]
        extra = content[name_end:extra_end]
        if not raw_name or b"\0" in raw_name:
            raise EvidenceError("source ZIP has an empty or NUL-containing entry name")
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise EvidenceError("source ZIP has a non-ASCII entry name") from exc
        path = checked_path(name)
        is_directory = name.endswith("/")
        canonical_name = f"{path}/" if is_directory else str(path)
        path_identity = str(path)
        if (
            canonical_name != name
            or raw_name in raw_names
            or name in names
            or path_identity in path_identities
        ):
            raise EvidenceError("source ZIP has a duplicate or non-canonical entry name")
        raw_names.add(raw_name)
        names.add(name)
        path_identities.add(path_identity)
        validate_source_zip_extra(extra, name, central=True)
        validate_source_zip_timestamp(modified_time, modified_date, name)

        create_system = version_made >> 8
        create_version = version_made & 0xFF
        expected_extract_versions = (
            {10, 20}
            if allow_stored_extract_version_20 and compress_type == zipfile.ZIP_STORED
            else {10 if compress_type == zipfile.ZIP_STORED else 20}
        )
        if (
            create_system != 3
            or create_version not in {20, 30}
            or extract_version not in expected_extract_versions
            or flag_bits != 0
            or compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
            or disk_start != 0
            or internal_attr not in {0, 1}
            or comment_size != 0
        ):
            raise EvidenceError(f"source ZIP has unsupported entry metadata: {name}")
        if (
            file_size > MAX_ARCHIVE_MEMBER_BYTES
            or file_size > max(1, compress_size) * MAX_SOURCE_ZIP_COMPRESSION_RATIO
        ):
            raise EvidenceError(f"source ZIP entry exceeds its resource limits: {name}")
        if compress_type == zipfile.ZIP_STORED and compress_size != file_size:
            raise EvidenceError(f"source ZIP stored entry has inconsistent sizes: {name}")
        expanded_total += file_size
        if expanded_total > MAX_ARCHIVE_TOTAL_BYTES:
            raise EvidenceError("source ZIP exceeds the cumulative expansion limit")

        mode = external_attr >> 16
        expected_type = stat.S_IFDIR if is_directory else stat.S_IFREG
        expected_dos_attributes = 0x10 if is_directory else 0
        observed_type = stat.S_IFMT(mode)
        allowed_types = (
            {stat.S_IFREG, 0} if allow_typeless_regular and not is_directory else {expected_type}
        )
        if (
            observed_type not in allowed_types
            or external_attr & 0xFFFF != expected_dos_attributes
            or mode & ~(observed_type | 0o777)
        ):
            raise EvidenceError(f"source ZIP has an unsupported entry type: {name}")
        if is_directory and (
            file_size != 0 or compress_size != 0 or crc != 0 or compress_type != zipfile.ZIP_STORED
        ):
            raise EvidenceError(f"source ZIP directory has invalid payload metadata: {name}")
        if not 0 <= header_offset < central_offset or header_offset in local_offsets:
            raise EvidenceError(f"source ZIP has a duplicate or invalid local offset: {name}")
        local_offsets.add(header_offset)
        entries.append(
            SourceZipCentralEntry(
                name=name,
                raw_name=raw_name,
                create_system=create_system,
                create_version=create_version,
                extract_version=extract_version,
                flag_bits=flag_bits,
                compress_type=compress_type,
                modified_time=modified_time,
                modified_date=modified_date,
                crc=crc,
                compress_size=compress_size,
                file_size=file_size,
                internal_attr=internal_attr,
                external_attr=external_attr,
                header_offset=header_offset,
                extra=extra,
            )
        )
        position = record_end
    if position != central_end:
        raise EvidenceError("source ZIP central directory has an unexpected shape")
    return entries


def validate_source_zip_entries(
    content: bytes,
    central_offset: int,
    central_entries: Sequence[SourceZipCentralEntry],
) -> list[ValidatedSourceZipEntry]:
    """Validate source ZIP metadata and local ranges without expanding payloads."""

    local_extra_total = 0
    ranges: list[tuple[int, int, str]] = []
    entries: list[ValidatedSourceZipEntry] = []
    for central in central_entries:
        name = central.name
        header_end = central.header_offset + ZIP_LOCAL_HEADER.size
        if header_end > central_offset:
            raise EvidenceError(f"source ZIP has a truncated local header: {name}")
        (
            signature,
            _version,
            flags,
            compression,
            modified_time,
            modified_date,
            crc,
            compressed_size,
            file_size,
            name_size,
            extra_size,
        ) = ZIP_LOCAL_HEADER.unpack_from(content, central.header_offset)
        if (
            signature != b"PK\x03\x04"
            or _version != central.extract_version
            or flags != central.flag_bits
            or compression != central.compress_type
            or crc != central.crc
            or compressed_size != central.compress_size
            or file_size != central.file_size
        ):
            raise EvidenceError(f"source ZIP local header disagrees: {name}")
        if modified_time != central.modified_time or modified_date != central.modified_date:
            raise EvidenceError(f"source ZIP timestamp metadata disagrees: {name}")
        name_end = header_end + name_size
        extra_end = name_end + extra_size
        data_end = extra_end + central.compress_size
        if data_end > central_offset or content[header_end:name_end] != central.raw_name:
            raise EvidenceError(f"source ZIP local entry boundary disagrees: {name}")
        local_extra = content[name_end:extra_end]
        local_extra_total += len(local_extra)
        if local_extra_total > MAX_TAR_EXTENSIONS_TOTAL_BYTES:
            raise EvidenceError("source ZIP local extra metadata exceeds its size limit")
        central_extra = validate_source_zip_extra(central.extra, name, central=True)
        local_extra_records = validate_source_zip_extra(local_extra, name, central=False)
        if set(central_extra) != set(local_extra_records):
            raise EvidenceError(f"source ZIP local extra metadata disagrees: {name}")
        for identifier, central_record in central_extra.items():
            local_record = local_extra_records[identifier]
            if identifier == 0x5455:
                if central_record[0] != local_record[0] or central_record[1] != local_record[1]:
                    raise EvidenceError(f"source ZIP local timestamp metadata disagrees: {name}")
            elif central_record != local_record:
                raise EvidenceError(f"source ZIP local Unix-owner metadata disagrees: {name}")
        ranges.append((central.header_offset, data_end, name))
        entries.append(
            ValidatedSourceZipEntry(
                metadata=central,
                data_offset=extra_end,
                data_end=data_end,
            )
        )

    if [start for start, _end, _name in ranges] != sorted(start for start, _end, _name in ranges):
        raise EvidenceError("source ZIP central directory is not in local-record order")
    if not ranges or ranges[0][0] != 0 or ranges[-1][1] != central_offset:
        raise EvidenceError("source ZIP has a prefix, gap, or trailing local data")
    for index in range(1, len(ranges)):
        previous, current = ranges[index - 1], ranges[index]
        if current[0] != previous[1]:
            raise EvidenceError(f"source ZIP entries are not contiguous: {current[2]}")
    return entries


def read_source_zip_payload(
    content: bytes,
    entry: ValidatedSourceZipEntry,
    *,
    max_bytes: int = MAX_LICENSE_BYTES,
    purpose: str = "license payload",
) -> bytes:
    """Read one payload with an exact, allocation-bounded raw ZIP decoder."""

    metadata = entry.metadata
    if metadata.file_size > max_bytes:
        limit_subject = "license file" if purpose == "license payload" else purpose
        raise EvidenceError(f"{limit_subject} exceeds limit: {metadata.name}")
    payload = content[entry.data_offset : entry.data_end]
    if len(payload) != metadata.compress_size:
        raise EvidenceError(f"source ZIP payload boundary disagrees: {metadata.name}")
    if metadata.compress_type == zipfile.ZIP_STORED:
        if metadata.compress_size != metadata.file_size:
            raise EvidenceError(f"source ZIP stored payload size disagrees: {metadata.name}")
        result = payload
    elif metadata.compress_type == zipfile.ZIP_DEFLATED:
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            result = decoder.decompress(payload, metadata.file_size + 1)
        except zlib.error as exc:
            raise EvidenceError(
                f"source ZIP {purpose} cannot be decompressed: {metadata.name}"
            ) from exc
        if (
            len(result) != metadata.file_size
            or not decoder.eof
            or decoder.unused_data
            or decoder.unconsumed_tail
        ):
            raise EvidenceError(f"source ZIP {purpose} disagrees: {metadata.name}")
    else:  # The raw central-directory parser rejects this before ranges are trusted.
        raise EvidenceError(f"source ZIP compression method is unsupported: {metadata.name}")
    if zlib.crc32(result) & 0xFFFFFFFF != metadata.crc:
        raise EvidenceError(f"source ZIP {purpose} CRC disagrees: {metadata.name}")
    return result


def wheel_member_install_path(
    member_name: str,
    site_root: PurePosixPath,
    *,
    data_directory: str,
    component_name: str,
) -> str:
    """Map one regular wheel member to the reviewed venv layout.

    Only the observed PEP 427 header relocation is supported. Failing closed
    keeps provenance exact instead of guessing how an installer rewrote other
    scripts, headers, or data paths.
    """

    member = checked_path(member_name)
    if member.parts[0].endswith(".data"):
        if (
            member.parts[0] != data_directory
            or len(member.parts) < 3
            or member.parts[1] != "headers"
        ):
            raise EvidenceError(f"native wheel uses an unsupported .data relocation: {member_name}")
        header_root = PurePosixPath(f"opt/venv/include/site/python{CPYTHON_RUNTIME_MINOR}")
        return (header_root / component_name / PurePosixPath(*member.parts[2:])).as_posix()
    return (site_root / member).as_posix()


def console_script_installations(
    archive_members: Mapping[str, bytes], entry_points_path: str
) -> dict[str, dict[str, str]]:
    """Derive the reviewed console and GUI launcher set from entry_points.txt."""

    content = archive_members.get(entry_points_path)
    if content is None:
        return {}
    if len(content) > 64 * 1024:
        raise EvidenceError("native wheel entry_points.txt exceeds its size limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("native wheel entry_points.txt is not UTF-8") from exc
    parser = CaseSensitiveConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
    )
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise EvidenceError(f"cannot parse native wheel entry_points.txt: {exc}") from exc
    if parser.defaults():
        raise EvidenceError("native wheel entry_points.txt must not contain defaults")

    scripts: dict[str, dict[str, str]] = {}
    for section in ("console_scripts", "gui_scripts"):
        if not parser.has_section(section):
            continue
        for name, raw_value in parser.items(section, raw=True):
            if SCRIPT_NAME.fullmatch(name) is None:
                raise EvidenceError("native wheel has an unsafe launcher name")
            path = f"opt/venv/bin/{name}"
            if path in scripts:
                raise EvidenceError("native wheel repeats a launcher name")
            value = raw_value.strip()
            match = ENTRY_POINT.fullmatch(value)
            if match is None:
                raise EvidenceError("native wheel has an unsupported launcher entry point")
            scripts[path] = {
                "callable": match.group("callable"),
                "kind": section,
                "module": match.group("module"),
                "name": name,
                "source_path": entry_points_path,
            }
    return scripts


def expected_native_launcher(module: str, callable_name: str, *, interpreter_name: str) -> bytes:
    """Return the reviewed uv/distlib POSIX launcher for one native owner."""

    if interpreter_name not in {"python", "python3", f"python{CPYTHON_RUNTIME_MINOR}"}:
        raise EvidenceError("native-wheel launcher uses an unsupported interpreter alias")
    python = f"/opt/venv/bin/{interpreter_name}"
    return (
        f"#!{python}\n"
        "# -*- coding: utf-8 -*-\n"
        "import sys\n"
        f"from {module} import {callable_name}\n"
        'if __name__ == "__main__":\n'
        '    if sys.argv[0].endswith("-script.pyw"):\n'
        "        sys.argv[0] = sys.argv[0][:-11]\n"
        '    elif sys.argv[0].endswith(".exe"):\n'
        "        sys.argv[0] = sys.argv[0][:-4]\n"
        f"    sys.exit({callable_name}())\n"
    ).encode()


def verify_native_wheel_artifact(
    inventory: Mapping[str, Any],
    locked: Mapping[str, Any],
    content: bytes,
) -> tuple[dict[str, Any], list[tuple[dict[str, Any], bytes]]]:
    """Bind one hostile locked wheel to its exact historical installation."""

    expected_locked_fields = {
        "owner",
        "platform",
        "url",
        "sha256",
        "size",
        "filename",
        "build",
        "tags",
    }
    if set(locked) != expected_locked_fields:
        raise EvidenceError("selected native wheel has an invalid record")
    owner = locked.get("owner")
    platform = locked.get("platform")
    url = locked.get("url")
    filename = locked.get("filename")
    digest = locked.get("sha256")
    expected_size = locked.get("size")
    if (
        not isinstance(owner, str)
        or platform != inventory.get("platform")
        or not isinstance(url, str)
        or not isinstance(filename, str)
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size != len(content)
        or sha256_bytes(content) != digest
        or safe_filename(url) != filename
    ):
        raise EvidenceError(f"selected native wheel identity disagrees for {owner!r}")

    contexts = native_wheel_contexts(inventory)
    context = contexts.get(owner)
    if context is None:
        raise EvidenceError(f"selected native wheel has no structured payload owner: {owner}")
    installation = context["installation"]
    component = context["component"]
    metadata_occurrence = installation.get("metadata")
    wheel_occurrence = installation.get("wheel")
    record_occurrence = installation.get("record")
    if not all(
        isinstance(item, dict)
        for item in (metadata_occurrence, wheel_occurrence, record_occurrence)
    ):
        raise EvidenceError(f"native-wheel installation has invalid identities: {owner}")
    assert isinstance(metadata_occurrence, dict)
    assert isinstance(wheel_occurrence, dict)
    assert isinstance(record_occurrence, dict)
    metadata_path = metadata_occurrence.get("path")
    wheel_path = wheel_occurrence.get("path")
    record_path = record_occurrence.get("path")
    if not all(isinstance(path, str) for path in (metadata_path, wheel_path, record_path)):
        raise EvidenceError(f"native-wheel installation has invalid identity paths: {owner}")
    assert isinstance(metadata_path, str)
    assert isinstance(wheel_path, str)
    assert isinstance(record_path, str)
    site_root = PurePosixPath(record_path).parent.parent
    expected_site_root = PurePosixPath(f"opt/venv/lib/python{CPYTHON_RUNTIME_MINOR}/site-packages")
    if site_root != expected_site_root:
        raise EvidenceError(f"native-wheel installation has an unexpected site root: {owner}")
    component_name = component.get("name")
    if not isinstance(component_name, str):
        raise EvidenceError(f"native-wheel component has an invalid name: {owner}")
    dist_info_directory = PurePosixPath(record_path).parent.name
    if not dist_info_directory.endswith(".dist-info"):
        raise EvidenceError(f"native-wheel installation has an invalid dist-info path: {owner}")
    data_directory = f"{dist_info_directory.removesuffix('.dist-info')}.data"

    central_offset, central_size, entry_count = preflight_source_zip(content)
    central_entries = read_source_zip_central_directory(
        content,
        central_offset,
        central_size,
        entry_count,
        allow_typeless_regular=True,
        allow_stored_extract_version_20=True,
    )
    entries = validate_source_zip_entries(content, central_offset, central_entries)
    archive_payloads: dict[str, bytes] = {}
    installed_members: dict[str, tuple[str, bytes]] = {}
    for entry in entries:
        member_path = PurePosixPath(entry.metadata.name.removesuffix("/"))
        dist_info_parts = [part for part in member_path.parts if part.endswith(".dist-info")]
        if dist_info_parts and (
            dist_info_parts != [dist_info_directory] or member_path.parts[0] != dist_info_directory
        ):
            raise EvidenceError(
                f"native wheel contains a foreign dist-info path: {entry.metadata.name}"
            )
        if entry.metadata.name.endswith("/"):
            continue
        if BYTECODE_FILE.search(entry.metadata.name):
            raise EvidenceError(f"native wheel contains bytecode: {entry.metadata.name}")
        if member_path.parent.name == dist_info_directory and member_path.name in {
            "INSTALLER",
            "REQUESTED",
            "direct_url.json",
            "uv_cache.json",
        }:
            raise EvidenceError(
                f"native wheel contains installer-generated metadata: {entry.metadata.name}"
            )
        payload = read_source_zip_payload(
            content,
            entry,
            max_bytes=MAX_ARCHIVE_MEMBER_BYTES,
            purpose="native wheel member",
        )
        archive_payloads[entry.metadata.name] = payload
        installed_path = wheel_member_install_path(
            entry.metadata.name,
            site_root,
            data_directory=data_directory,
            component_name=component_name,
        )
        if installed_path in installed_members:
            raise EvidenceError(f"native wheel repeats an installed path: {installed_path}")
        installed_members[installed_path] = (entry.metadata.name, payload)

    identity_paths = {metadata_path, wheel_path, record_path}
    if not identity_paths <= set(installed_members):
        raise EvidenceError(f"native wheel omits METADATA, WHEEL, or RECORD for {owner}")
    archive_record_path = installed_members[record_path][0]
    record_content = installed_members[record_path][1]
    archive_record = parse_archive_wheel_record(record_content, archive_record_path)
    if set(archive_record) != set(archive_payloads):
        raise EvidenceError(f"native wheel RECORD does not exactly cover archive members: {owner}")
    for archive_path, payload in archive_payloads.items():
        recorded_digest, recorded_size = archive_record[archive_path]
        if archive_path == archive_record_path:
            if recorded_digest is not None or recorded_size is not None:
                raise EvidenceError(f"native wheel RECORD self-entry is not blank: {owner}")
        elif recorded_digest != sha256_bytes(payload) or recorded_size != len(payload):
            raise EvidenceError(f"native wheel RECORD disagrees with member: {archive_path}")

    installed_entries_value = installation.get("entries")
    if not isinstance(installed_entries_value, list):
        raise EvidenceError(f"native-wheel installation has invalid RECORD entries: {owner}")
    installed_entries: dict[str, Mapping[str, Any]] = {}
    for entry in installed_entries_value:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or path in installed_entries:
            raise EvidenceError(f"native-wheel installation repeats a RECORD path: {owner}")
        installed_entries[path] = entry
    entry_points_path = f"{dist_info_directory}/entry_points.txt"
    generated_scripts = console_script_installations(archive_payloads, entry_points_path)
    if set(installed_entries) != set(installed_members) | set(generated_scripts):
        raise EvidenceError(
            f"native wheel archive and installed RECORD have different member sets: {owner}"
        )
    for installed_path, (archive_path, payload) in installed_members.items():
        installed_entry = installed_entries[installed_path]
        occurrence = installed_entry.get("occurrence")
        if not isinstance(occurrence, dict):
            raise EvidenceError(
                f"native-wheel RECORD has no installed occurrence: {installed_path}"
            )
        if installed_path != record_path and (
            occurrence.get("sha256") != sha256_bytes(payload)
            or occurrence.get("size") != len(payload)
        ):
            raise EvidenceError(
                f"native wheel member differs from installed occurrence: {installed_path}"
            )
        if installed_path == record_path:
            if (
                installed_entry.get("recorded_sha256") is not None
                or installed_entry.get("recorded_size") is not None
            ):
                raise EvidenceError(
                    f"installed native-wheel RECORD self-entry is not blank: {owner}"
                )
        elif (
            installed_entry.get("recorded_sha256") != archive_record[archive_path][0]
            or installed_entry.get("recorded_size") != archive_record[archive_path][1]
        ):
            raise EvidenceError(
                f"native wheel member differs from installed RECORD: {installed_path}"
            )

    generated_records: list[dict[str, Any]] = []
    for path, script in sorted(generated_scripts.items()):
        installed_entry = installed_entries[path]
        occurrence = installed_entry.get("occurrence")
        if (
            not isinstance(occurrence, dict)
            or installed_entry.get("recorded_sha256") != occurrence.get("sha256")
            or installed_entry.get("recorded_size") != occurrence.get("size")
            or occurrence.get("mode") != 0o755
            or occurrence.get("uid") != 0
            or occurrence.get("gid") != 0
        ):
            raise EvidenceError(f"generated console script has an invalid RECORD entry: {path}")
        matching_interpreters = []
        for interpreter in ("python", "python3", f"python{CPYTHON_RUNTIME_MINOR}"):
            expected_launcher = expected_native_launcher(
                script["module"],
                script["callable"],
                interpreter_name=interpreter,
            )
            if occurrence.get("sha256") == sha256_bytes(expected_launcher) and occurrence.get(
                "size"
            ) == len(expected_launcher):
                matching_interpreters.append(interpreter)
        if len(matching_interpreters) != 1:
            raise EvidenceError(f"generated launcher differs from reviewed bytes: {path}")
        generated_records.append(
            {
                **script,
                "installed_occurrence": occurrence,
                "launcher_interpreter": matching_interpreters[0],
            }
        )

    for path, occurrence in (
        (metadata_path, metadata_occurrence),
        (wheel_path, wheel_occurrence),
        (record_path, record_occurrence),
    ):
        if installed_entries[path].get("occurrence") != occurrence:
            raise EvidenceError(f"native-wheel identity occurrence drifted: {path}")
    parsed_metadata = parse_python_metadata(installed_members[metadata_path][1], metadata_path)
    if parsed_metadata.get("name") != component.get("name") or parsed_metadata.get(
        "version"
    ) != component.get("version"):
        raise EvidenceError(f"native wheel METADATA has the wrong owner: {owner}")
    parsed_wheel = validate_wheel_metadata(installed_members[wheel_path][1], wheel_path)
    if parsed_wheel != {
        "root_is_purelib": installation.get("root_is_purelib"),
        "build": installation.get("build"),
        "tags": installation.get("tags"),
    } or parsed_wheel != {
        "root_is_purelib": installation.get("root_is_purelib"),
        "build": locked.get("build"),
        "tags": locked.get("tags"),
    }:
        raise EvidenceError(f"native wheel WHEEL identity disagrees with installation: {owner}")
    if context["native_payloads"] and parsed_wheel["root_is_purelib"] is not False:
        raise EvidenceError(f"native wheel with ELF payload claims Root-Is-Purelib: true: {owner}")

    observed_payload_paths = {
        "native_payloads": {
            path
            for path, (_archive_path, payload) in installed_members.items()
            if is_native_payload_path(path)
            or (is_python_virtual_environment_path(path) and payload.startswith(ELF_MAGIC))
        },
        "embedded_sboms": {
            path for path in installed_members if DIST_INFO_SBOM.search(path) is not None
        },
    }
    for category in ("native_payloads", "embedded_sboms"):
        expected_records = context[category]
        expected_paths = {str(record["path"]) for record in expected_records}
        if observed_payload_paths[category] != expected_paths:
            raise EvidenceError(
                f"native wheel {category} do not exactly match installed owner {owner}"
            )
        for record in expected_records:
            path = str(record["path"])
            payload = installed_members[path][1]
            occurrence = installed_entries[path].get("occurrence")
            if occurrence != payload_record_projection(record):
                raise EvidenceError(f"native wheel payload occurrence drifted: {path}")
            if sha256_bytes(payload) != record.get("sha256") or len(payload) != record.get("size"):
                raise EvidenceError(f"native wheel payload bytes drifted: {path}")

    raw_sboms: list[tuple[dict[str, Any], bytes]] = []
    expected_sboms = {str(record["path"]): record for record in context["embedded_sboms"]}
    for installed_path in sorted(observed_payload_paths["embedded_sboms"]):
        archive_path, payload = installed_members[installed_path]
        occurrence = payload_record_projection(expected_sboms[installed_path])
        raw_sboms.append(
            (
                {
                    "owner": owner,
                    "platform": platform,
                    "url": url,
                    "archive_path": archive_path,
                    "installed_occurrence": occurrence,
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                },
                payload,
            )
        )
    return (
        {
            "owner": owner,
            "platform": platform,
            "url": url,
            "filename": filename,
            "size": len(content),
            "sha256": digest,
            "build": locked.get("build"),
            "tags": locked.get("tags"),
            "generated_files": generated_records,
        },
        raw_sboms,
    )


def retain_native_wheel_artifact(
    root: Path,
    inventory: Mapping[str, Any],
    locked: Mapping[str, Any],
    content: bytes,
    *,
    budget: BundleBudget,
    urls: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Retain an exact native wheel and separately addressable raw SBOM bytes."""

    wheel_record, raw_sboms = verify_native_wheel_artifact(inventory, locked, content)
    url_chain = tuple(urls) if urls is not None else (str(wheel_record["url"]),)
    if not url_chain or len(url_chain) > MAX_REDIRECTS + 1 or url_chain[0] != wheel_record["url"]:
        raise EvidenceError("native wheel has an invalid download URL chain")
    for retained_url in url_chain:
        require_https_source_url(retained_url)
    wheel_record["urls"] = list(url_chain)
    owner = str(wheel_record["owner"])
    context = native_wheel_contexts(inventory)[owner]
    component = context["component"]
    directory = f"{component['name']}/{component['version']}"
    wheel_path = f"artifacts/native-wheels/{directory}/{wheel_record['filename']}"
    write_file(root, wheel_path, content, budget=budget)
    wheel_record["path"] = wheel_path
    retained_sboms: list[dict[str, Any]] = []
    for sbom_record, payload in raw_sboms:
        sbom_record["urls"] = list(url_chain)
        relative = (
            f"artifacts/native-wheels/{directory}/embedded-sboms/{sbom_record['archive_path']}"
        )
        write_file(root, relative, payload, budget=budget)
        sbom_record["path"] = relative
        retained_sboms.append(sbom_record)
    wheel_record["embedded_sboms"] = retained_sboms
    return wheel_record


def extract_license_files(
    archive: bytes,
    component: str,
    root: Path,
    *,
    archive_name: str | None = None,
    budget: BundleBudget | None = None,
    max_archive_bytes: int = MAX_DOWNLOAD_BYTES,
) -> list[str]:
    """Extract only bounded regular files with license/notice names."""

    if not 0 < max_archive_bytes <= MAX_ALPINE_DISTFILE_BYTES:
        raise EvidenceError("source archive has an invalid input-size limit")
    if len(archive) > max_archive_bytes:
        raise EvidenceError(f"source archive exceeds its input-size limit: {component}")
    try:
        expected_zip = archive_name is not None and urllib.parse.urlparse(
            archive_name
        ).path.lower().endswith(".zip")
    except ValueError as exc:
        raise EvidenceError("source archive name is invalid") from exc
    zip_candidate = (
        expected_zip or archive.startswith(ZIP_SIGNATURES) or has_source_zip_eocd(archive)
    )
    written: list[str] = []
    seen: set[str] = set()
    license_count = 0
    license_bytes = 0

    def record_license_candidate(source_path: str, size: int) -> None:
        nonlocal license_count, license_bytes
        if size > MAX_LICENSE_BYTES:
            raise EvidenceError(f"license file exceeds limit: {source_path}")
        license_count += 1
        license_bytes += size
        if license_count > MAX_SOURCE_LICENSE_FILES:
            raise EvidenceError(f"source archive has too many license files: {component}")
        if license_bytes > MAX_SOURCE_LICENSE_TOTAL_BYTES:
            raise EvidenceError(f"source archive license files exceed size limit: {component}")

    def retain(source_path: str, content: bytes) -> None:
        digest = sha256_bytes(content)
        if digest in seen:
            return
        seen.add(digest)
        basename = PurePosixPath(source_path).name
        relative = f"licenses/from-source/{component}/{digest[:12]}-{basename}"
        destination = root / relative
        if destination.exists():
            if read_local_bytes(destination, max_bytes=MAX_LICENSE_BYTES) != content:
                raise EvidenceError(f"conflicting license files at {relative}")
        else:
            write_file(root, relative, content, budget=budget)
        written.append(relative)

    try:
        if zip_candidate:
            central_offset, central_size, expected_entries = preflight_source_zip(
                archive,
                max_archive_bytes=max_archive_bytes,
            )
            central_entries = read_source_zip_central_directory(
                archive,
                central_offset,
                central_size,
                expected_entries,
            )
            entries = validate_source_zip_entries(
                archive,
                central_offset,
                central_entries,
            )
            for entry in entries:
                metadata = entry.metadata
                path = checked_path(metadata.name)
                if metadata.name.endswith("/") or not LICENSE_NAME.search(str(path)):
                    continue
                record_license_candidate(metadata.name, metadata.file_size)
                retain(str(path), read_source_zip_payload(archive, entry))
        else:
            with tarfile.open(
                fileobj=io.BytesIO(archive), mode="r:*", tarinfo=BoundedTarInfo
            ) as tar_source:
                count = 0
                total = 0
                for tar_member in tar_source:
                    count += 1
                    if count > MAX_ARCHIVE_MEMBERS:
                        raise EvidenceError(f"source archive has too many entries: {component}")
                    path = checked_path(tar_member.name)
                    if tar_member.isdir():
                        if tar_member.size != 0:
                            raise EvidenceError(
                                f"source archive directory has a payload: {component}"
                            )
                        continue
                    if tar_member.issym():
                        if tar_member.size != 0:
                            raise EvidenceError(
                                f"source archive symlink has a payload: {component}"
                            )
                        checked_link_target(tar_member.linkname)
                        if LICENSE_NAME.search(str(path)):
                            raise EvidenceError(
                                f"source archive license entry is not regular: {component}"
                            )
                        # Source archives are inspected in memory and never extracted. A
                        # bounded, traversal-free non-license symlink cannot influence
                        # which regular license bytes are retained.
                        continue
                    if not tar_member.isfile():
                        raise EvidenceError(f"source archive has an unsupported entry: {component}")
                    total += tar_member.size
                    if total > MAX_ARCHIVE_TOTAL_BYTES:
                        raise EvidenceError(f"source archive is too large: {component}")
                    if not LICENSE_NAME.search(str(path)):
                        continue
                    record_license_candidate(tar_member.name, tar_member.size)
                    retain(str(path), read_member(tar_source, tar_member))
    except EvidenceError:
        raise
    except (
        struct.error,
        tarfile.TarError,
        zipfile.BadZipFile,
        RuntimeError,
        NotImplementedError,
        OverflowError,
        ValueError,
        zlib.error,
    ) as exc:
        # Raw patches and text sources legitimately are not archives.
        if zip_candidate or archive.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")):
            raise EvidenceError(f"invalid source archive for {component}: {exc}") from exc
        return []

    return sorted(written)


def deterministic_source_archive(repo: Path, *, source_revision: str = "HEAD") -> bytes:
    """Archive exact blobs from one Git revision without applying export attributes."""

    entries = git_regular_tree_at_head(repo, source_revision=source_revision)
    paths = {path for _mode, path in entries}
    if "LICENSE" not in paths or not any(path.startswith("extra_codeowners/") for path in paths):
        raise EvidenceError("selected Git revision lacks the application source or LICENSE")
    result = io.BytesIO()
    aggregate = 0
    with tarfile.open(fileobj=result, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for mode, path in entries:
            content = run(
                ["git", "show", f"{source_revision}:{path}"],
                cwd=repo,
                max_output_bytes=MAX_ARCHIVE_MEMBER_BYTES,
            )
            aggregate += len(content)
            if aggregate > MAX_APPLICATION_SOURCE_ARCHIVE_BYTES:
                raise EvidenceError("application source archive exceeds the size limit")
            info = tarfile.TarInfo(path)
            info.size = len(content)
            info.mode = 0o755 if mode == "100755" else 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(content))
    content = result.getvalue()
    if len(content) > MAX_APPLICATION_SOURCE_ARCHIVE_BYTES:
        raise EvidenceError("application source archive exceeds the size limit")
    return content


def git_regular_tree_at_head(
    repo: Path,
    pathspec: str | None = None,
    *,
    source_revision: str = "HEAD",
) -> list[tuple[str, str]]:
    """Return regular-blob modes and paths from one Git revision."""

    command = ["git", "ls-tree", "-rz", source_revision]
    if pathspec is not None:
        command.extend(["--", pathspec])
    listing = run(command, cwd=repo, max_output_bytes=MAX_JSON_BYTES)
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_entry in listing.split(b"\0"):
        if not raw_entry:
            continue
        header, separator, raw_path = raw_entry.partition(b"\t")
        try:
            mode, object_type, object_id = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise EvidenceError("cannot parse the selected Git source listing") from exc
        if (
            not separator
            or object_type != "blob"
            or re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None
        ):
            raise EvidenceError("selected Git source listing has an invalid object record")
        normalized_path = str(checked_path(path))
        if mode not in {"100644", "100755"}:
            raise EvidenceError(f"application source is not a regular Git blob: {normalized_path}")
        if normalized_path in seen:
            raise EvidenceError(f"application source listing repeats path: {normalized_path}")
        seen.add(normalized_path)
        entries.append((mode, normalized_path))
        if len(entries) > MAX_BUNDLE_FILES:
            raise EvidenceError("application source listing has too many entries")
    return entries


def project_identity_at_head(repo: Path, *, source_revision: str = "HEAD") -> tuple[str, str]:
    """Read the application identity from one Git revision."""

    try:
        project_file = tomllib.loads(
            run(
                ["git", "show", f"{source_revision}:pyproject.toml"],
                cwd=repo,
                max_output_bytes=1024 * 1024,
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError("cannot parse pyproject.toml from the selected Git revision") from exc
    project = project_file.get("project")
    if not isinstance(project, dict):
        raise EvidenceError("pyproject.toml at the selected Git revision has no project table")
    raw_name = project.get("name")
    raw_version = project.get("version")
    if not isinstance(raw_name, str) or not isinstance(raw_version, str):
        raise EvidenceError(
            "pyproject.toml at the selected Git revision has no static name and version"
        )
    checked_name = checked_scalar(raw_name, "application project name")
    checked_version = checked_scalar(raw_version, "application project version")
    if checked_name != raw_name or checked_version != raw_version:
        raise EvidenceError(
            "pyproject.toml at the selected Git revision has non-canonical project identity"
        )
    try:
        name = str(canonicalize_name(checked_name, validate=True))
        version = str(Version(checked_version))
    except (InvalidName, InvalidVersion, ValueError) as exc:
        raise EvidenceError(
            "pyproject.toml at the selected Git revision has invalid project identity"
        ) from exc
    if name != APPLICATION_NAME:
        raise EvidenceError(
            f"application project name must remain {APPLICATION_NAME!r}, got {name!r}"
        )
    return name, version


def application_sources_at_head(
    repo: Path,
    *,
    source_revision: str = "HEAD",
) -> dict[str, bytes]:
    """Read the regular first-party package files from one Git revision."""

    sources: dict[str, bytes] = {}
    aggregate_size = 0
    for _mode, path in git_regular_tree_at_head(
        repo,
        "extra_codeowners",
        source_revision=source_revision,
    ):
        if not path.startswith("extra_codeowners/"):
            raise EvidenceError(f"application source escaped its package directory: {path}")
        content = run(
            ["git", "show", f"{source_revision}:{path}"],
            cwd=repo,
            max_output_bytes=MAX_ARCHIVE_MEMBER_BYTES,
        )
        aggregate_size += len(content)
        if aggregate_size > MAX_APPLICATION_SOURCE_ARCHIVE_BYTES:
            raise EvidenceError("application sources exceed the cumulative size limit")
        sources[path] = content
    if not sources:
        raise EvidenceError("selected Git revision has no tracked application package files")
    return sources


def validate_application_source_binding(
    inventory: Mapping[str, Any],
    files: Mapping[str, Any],
    repo: Path,
    *,
    source_revision: str = "HEAD",
) -> tuple[str, str]:
    """Bind one effective application installation to the selected Git revision."""

    expected_name, expected_version = project_identity_at_head(
        repo,
        source_revision=source_revision,
    )
    components = inventory["components"]
    application_components = [
        component
        for component in components
        if component["ecosystem"] == "python" and component["name"] == expected_name
    ]
    if len(application_components) != 1:
        raise EvidenceError(
            "image must contain exactly one application component across all layers"
        )
    application = application_components[0]
    if application["version"] != expected_version or application["effective"] is not True:
        raise EvidenceError(
            "effective application component does not match pyproject.toml at the selected "
            "Git revision"
        )
    metadata_hash = application["metadata_sha256"]
    metadata_records = [
        record
        for record in files["regular_files"]
        if DIST_INFO.search(record["path"]) and record["sha256"] == metadata_hash
    ]
    if len(metadata_records) != 1 or metadata_records[0]["effective"] is not True:
        raise EvidenceError(
            "image must contain exactly one effective application metadata occurrence"
        )
    metadata_path = PurePosixPath(metadata_records[0]["path"])
    site_root = metadata_path.parent.parent
    package_prefix = f"{site_root}/extra_codeowners/"
    installed_sources: dict[str, Mapping[str, Any]] = {}
    for record in files["regular_files"]:
        path = record["path"]
        if record["effective"] is not True or not path.startswith(package_prefix):
            continue
        relative = path.removeprefix(f"{site_root}/")
        if relative in installed_sources:
            raise EvidenceError(f"image repeats effective application source: {relative}")
        installed_sources[relative] = record
    expected_sources = application_sources_at_head(
        repo,
        source_revision=source_revision,
    )
    if set(installed_sources) != set(expected_sources):
        raise EvidenceError(
            "effective application package files do not match the selected Git revision"
        )
    for path, content in expected_sources.items():
        installed = installed_sources[path]
        if installed["sha256"] != sha256_bytes(content) or installed["size"] != len(content):
            raise EvidenceError(
                f"effective application source differs from the selected Git revision: {path}"
            )
    return expected_name, expected_version


def _build_bundle_with_boundary(
    *,
    path_boundary: BundlePathBoundary,
    inventory_path: Path,
    files_path: Path,
    policy_path: Path,
    lock_path: Path,
    direct_source_store_root: Path,
    direct_source_plan_sha256: str,
    direct_source_plan_size: int,
    alpine_source_store_root: Path,
    alpine_source_plan_sha256: str,
    alpine_source_plan_size: int,
    repo: Path,
    output: Path,
    predicate_output: Path,
    version: str,
    source_date_epoch: int,
    selected_python_directory: Path,
    application_source_revision: str,
    application_wheel_sha256: str,
    application_selection_record_sha256: str,
    require_approval: bool,
    require_image_revision: bool,
) -> None:
    inventory = load_json(inventory_path)
    files = load_json(files_path)
    policy_bytes = read_stable_local_bytes(
        policy_path,
        max_bytes=MAX_JSON_BYTES,
        source=f"container policy {policy_path}",
    )
    policy = load_json_bytes(policy_bytes, str(policy_path))
    lock_bytes = read_stable_local_bytes(
        lock_path,
        max_bytes=MAX_JSON_BYTES,
        source=f"lock file {lock_path}",
    )
    validate_all_layer_inventory(files, inventory)
    verify_inventory(inventory, policy, require_approval=require_approval)
    head = (
        run(
            ["git", "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=repo,
            max_output_bytes=128,
        )
        .decode()
        .strip()
    )
    if application_source_revision != head:
        raise EvidenceError(
            "selected application source revision does not match the evidence checkout"
        )
    dockerfile_content = run(
        ["git", "show", f"{application_source_revision}:Dockerfile"],
        cwd=repo,
        max_output_bytes=1024 * 1024,
    )
    verify_dockerfile_base_bytes(
        dockerfile_content,
        f"Git object {application_source_revision}:Dockerfile",
        policy,
    )
    verify_application_artifact_labels(
        inventory,
        source_revision=application_source_revision,
        wheel_sha256=application_wheel_sha256,
        selection_record_sha256=application_selection_record_sha256,
    )
    if require_image_revision:
        verify_image_revision(inventory, version=version, source_revision=head)
    verify_base_layer_binding(files, policy)
    verify_post_base_provenance(
        inventory,
        files,
        policy,
        repo,
        source_revision=application_source_revision,
    )
    application_name, _application_version = validate_application_source_binding(
        inventory,
        files,
        repo,
        source_revision=application_source_revision,
    )
    lock_sources = parse_lock_sources_bytes(lock_bytes, str(lock_path))
    validate_source_policy_coverage(inventory, policy, lock_sources)
    locked_native_wheels = select_locked_native_wheels_bytes(
        lock_bytes,
        str(lock_path),
        inventory,
    )
    native_coverage = verify_native_component_lock_bindings(
        inventory, policy, locked_native_wheels, lock_sources
    )
    with (
        path_boundary,
        tempfile.TemporaryDirectory(
            prefix="extra-codeowners-evidence-",
            dir=path_boundary.work_directory,
        ) as temporary,
        _open_verified_source_store(
            direct_source_store_root,
            expected_plan_sha256=direct_source_plan_sha256,
            expected_plan_size=direct_source_plan_size,
        ) as direct_source_reader,
        _open_verified_source_store(
            alpine_source_store_root,
            expected_plan_sha256=alpine_source_plan_sha256,
            expected_plan_size=alpine_source_plan_size,
        ) as alpine_source_reader,
    ):
        root = Path(temporary) / "evidence"
        root.mkdir()
        budget = BundleBudget()
        _validate_verified_source_stores(
            direct_source_reader,
            alpine_source_reader,
            policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
            lock_sha256=hashlib.sha256(lock_bytes).hexdigest(),
            source_revision=application_source_revision,
        )
        application_artifacts, installation_contract = retain_selected_application_artifacts(
            directory=selected_python_directory,
            output=root / "artifacts" / "application",
            source_revision=application_source_revision,
            wheel_sha256=application_wheel_sha256,
            selection_record_sha256=application_selection_record_sha256,
            budget=budget,
            pass_fds=(path_boundary.work_descriptor,),
        )
        launcher_interpreter = verify_selected_application_installation(
            inventory, installation_contract
        )
        application_artifacts["launcher_interpreter"] = launcher_interpreter

        def direct_source(
            request_id: str,
            url: str,
            expected_hash: str,
            algorithm: str = "sha256",
            *,
            max_bytes: int = MAX_DOWNLOAD_BYTES,
        ) -> VerifiedSource:
            return _read_bounded_verified_source(
                direct_source_reader,
                request_id,
                url,
                expected_hash,
                budget,
                algorithm,
                max_bytes=max_bytes,
            )

        native_wheel_artifacts: list[dict[str, Any]] = []
        for locked_wheel in locked_native_wheels:
            wheel_download = direct_source(
                _python_wheel_request_id(
                    str(locked_wheel["platform"]),
                    locked_wheel["owner"],
                ),
                str(locked_wheel["url"]),
                str(locked_wheel["sha256"]),
            )
            if len(wheel_download.content) != locked_wheel["size"]:
                raise EvidenceError(f"size mismatch for native wheel {locked_wheel['owner']}")
            native_wheel_artifacts.append(
                retain_native_wheel_artifact(
                    root,
                    inventory,
                    locked_wheel,
                    wheel_download.content,
                    budget=budget,
                    urls=wheel_download.urls,
                )
            )

        write_file(root, "inventory/components.json", canonical_json(inventory), budget=budget)
        write_file(
            root,
            "inventory/native-component-coverage.json",
            canonical_json(native_coverage),
            budget=budget,
        )
        write_file(
            root,
            "inventory/all-layer-files.json",
            canonical_json(files),
            budget=budget,
        )
        write_file(
            root,
            "policy/container-policy.json",
            canonical_json(policy),
            budget=budget,
        )

        source_records: list[dict[str, Any]] = []
        license_records: list[dict[str, Any]] = []
        application_tar = deterministic_source_archive(
            repo,
            source_revision=application_source_revision,
        )
        application_path = "sources/application/extra-codeowners.tar"
        write_file(root, application_path, application_tar, budget=budget)
        application_revision = application_source_revision
        source_records.append(
            source_record(
                application_name,
                f"https://github.com/stampbot/extra-codeowners/tree/{application_revision}",
                application_tar,
                application_path,
            )
        )
        license_records.extend(
            {"component": application_name, "path": path}
            for path in extract_license_files(
                application_tar,
                application_name,
                root,
                archive_name=application_path,
                budget=budget,
            )
        )

        docker_recipe = policy.get("docker_python_recipe")
        cpython = policy.get("cpython_source")
        base_source_content: dict[str, bytes] = {}
        base_license_paths: dict[str, list[str]] = {}
        for component, entry in (("docker-python-recipe", docker_recipe), ("cpython", cpython)):
            if not isinstance(entry, dict):
                raise EvidenceError(f"policy is missing {component}")
            download = direct_source(
                BASE_SOURCE_REQUEST_IDS[component],
                str(entry.get("url", "")),
                str(entry.get("sha256", "")),
            )
            content = download.content
            base_source_content[component] = content
            filename = safe_filename(str(entry["url"]))
            relative = f"sources/base/{component}/{filename}"
            write_file(root, relative, content, budget=budget)
            manifest_component = (
                f"runtime:{CPYTHON_RUNTIME_NAME}@{EXPECTED_RUNTIME_PYTHON}"
                if component == "cpython"
                else component
            )
            retention_component = (
                f"runtime-{CPYTHON_RUNTIME_NAME}-{EXPECTED_RUNTIME_PYTHON}"
                if component == "cpython"
                else component
            )
            source_records.append(
                source_record(manifest_component, download.urls, content, relative)
            )
            found_base_licenses = extract_license_files(
                content,
                retention_component,
                root,
                archive_name=filename,
                budget=budget,
            )
            base_license_paths[component] = found_base_licenses
            license_records.extend(
                {"component": manifest_component, "path": license_path}
                for license_path in found_base_licenses
            )
            detached_license = detached_license_source(entry, component)
            if detached_license is not None:
                if component != "docker-python-recipe":
                    raise EvidenceError(
                        f"source plan has no detached license request for {component}"
                    )
                license_url, license_hash = detached_license
                license_download = direct_source(
                    DOCKER_PYTHON_LICENSE_REQUEST_ID,
                    license_url,
                    license_hash,
                    max_bytes=MAX_LICENSE_BYTES,
                )
                license_content = license_download.content
                license_relative = f"licenses/from-source/{component}/LICENSE"
                write_file(root, license_relative, license_content, budget=budget)
                source_records.append(
                    source_record(
                        f"{component}-license",
                        license_download.urls,
                        license_content,
                        license_relative,
                    )
                )
                license_records.append({"component": component, "path": license_relative})
        if not isinstance(cpython, dict):
            raise EvidenceError("policy is missing cpython")
        verify_cpython_source_binding(base_source_content["docker-python-recipe"], cpython)
        cpython_license = verify_cpython_source_archive(base_source_content["cpython"], cpython)
        expected_cpython_license_path = (
            f"licenses/from-source/runtime-{CPYTHON_RUNTIME_NAME}-{EXPECTED_RUNTIME_PYTHON}/"
            f"{sha256_bytes(cpython_license)[:12]}-LICENSE"
        )
        if expected_cpython_license_path not in base_license_paths.get("cpython", []):
            raise EvidenceError("exact CPython source LICENSE was not retained in the bundle")

        python_components = [
            component
            for component in inventory["components"]
            if component["ecosystem"] == "python" and component["name"] != "extra-codeowners"
        ]
        python_source_archives: dict[tuple[str, str], tuple[bytes, Sequence[str], str]] = {}
        for component in python_components:
            key = (component["name"], component["version"])
            source = lock_sources.get(key)
            if source is None:
                source = source_policy_entry(policy, *key)
            url = source.get("url")
            expected = source.get("sha256")
            if not isinstance(url, str) or not isinstance(expected, str):
                raise EvidenceError(f"invalid Python source record: {key[0]} {key[1]}")
            download = direct_source(
                _python_sdist_request_id(key[0], key[1]),
                url,
                expected,
            )
            content = download.content
            expected_size = source.get("size")
            if expected_size is not None and len(content) != expected_size:
                raise EvidenceError(f"size mismatch for Python source {key[0]} {key[1]}")
            component_id = f"python-{key[0]}-{key[1]}"
            relative = f"sources/python/{key[0]}/{key[1]}/{safe_filename(url)}"
            write_file(root, relative, content, budget=budget)
            python_source_archives[key] = (content, download.urls, relative)
            source_records.append(source_record(component_id, download.urls, content, relative))
            found = extract_license_files(
                content,
                component_id,
                root,
                archive_name=relative,
                budget=budget,
            )
            if not found:
                raise EvidenceError(
                    f"Python source contains no license/notice file: {key[0]} {key[1]}"
                )
            license_records.extend({"component": component_id, "path": item} for item in found)

        source_policies = native_component_sources(policy)
        native_components_by_source: dict[str, set[str]] = {}
        native_reviewed_licenses_by_source: dict[str, set[str]] = {}
        native_owner_sdist_bindings_by_source: dict[str, set[OwnerSdistObservationBinding]] = {}
        raw_coverage = policy["native_component_coverage"][inventory["platform"]]
        for owner_record in raw_coverage:
            context = validate_native_owner_review(
                owner_record,
                platform=str(inventory["platform"]),
                sources=source_policies,
                used_sources=set(),
            )
            for source_id, bindings in context["owner_sdist_bindings"].items():
                native_owner_sdist_bindings_by_source.setdefault(source_id, set()).update(bindings)
            if context["cargo_lock"] is not None:
                _owner, owner_name, owner_version = parse_native_owner(
                    owner_record["owner"],
                    "Cargo.lock source owner",
                )
                cached_owner_source = python_source_archives.get((owner_name, owner_version))
                if cached_owner_source is None:
                    raise EvidenceError(
                        "native owner with Cargo.lock context has no retained Python "
                        f"source archive: {owner_record['owner']}"
                    )
                owner_archive, _owner_urls, owner_relative = cached_owner_source
                cargo_lock = verify_owner_cargo_lock(
                    context,
                    source_policies,
                    owner_archive,
                    archive_name=owner_relative,
                )
                assert cargo_lock is not None
                lock_relative = (
                    "sources/cargo-locks/"
                    f"{sha256_bytes(str(owner_record['owner']).encode())[:20]}/Cargo.lock"
                )
                write_file(
                    root,
                    lock_relative,
                    cargo_lock,
                    budget=budget,
                    max_bytes=MAX_CARGO_LOCK_BYTES,
                )
            for component_review in owner_record["component_reviews"]:
                source_id = str(component_review["source"])
                native_reviewed_licenses_by_source.setdefault(source_id, set()).add(
                    str(component_review["reviewed_license"])
                )
                for raw_reference in component_review["observations"]:
                    reference = validate_observation_reference(
                        raw_reference,
                        f"native source consumer {source_id}",
                    )
                    component = context["observations"][reference]
                    identity_kind, identity = cyclonedx_occurrence_identity(component)
                    native_components_by_source.setdefault(source_id, set()).add(
                        f"native:{component['purl']}#{identity_kind}:{identity}"
                    )
        if set(native_components_by_source) != set(source_policies):
            raise EvidenceError(
                "native-component bundle sources differ from reviewed source consumers"
            )
        for source_id in sorted(native_components_by_source):
            native_source = source_policies[source_id]
            kind = str(native_source["kind"])
            native_request_ids = _native_source_request_ids(source_id, kind)
            validate_bundle_source_reviewed_license_binding(
                source_id,
                native_source,
                native_reviewed_licenses_by_source.get(source_id),
            )
            source_directory = sha256_bytes(source_id.encode())[:20]
            expected_notices = {
                str(record["member"]): record for record in native_source["notices"]
            }
            found_notices: dict[str, bytes] = {}

            def collect_notices(
                content: bytes,
                archive_name: str,
                *,
                max_archive_bytes: int,
                selected_source_id: str = source_id,
                selected_expected_notices: Mapping[str, Mapping[str, Any]] = expected_notices,
                selected_found_notices: dict[str, bytes] = found_notices,
            ) -> None:
                for member, notice_content in reviewed_files_from_source_archive(
                    content,
                    archive_name=archive_name,
                    source_id=selected_source_id,
                    expected=selected_expected_notices,
                    max_archive_bytes=max_archive_bytes,
                ).items():
                    if member in selected_found_notices:
                        raise EvidenceError(
                            f"native-component notice appears in multiple archives: "
                            f"{selected_source_id}/{member}"
                        )
                    selected_found_notices[member] = notice_content

            if kind == "alpine-aports":
                recipe = native_source["recipe"]
                recipe_download = direct_source(
                    native_request_ids["recipe"],
                    str(recipe["url"]),
                    str(recipe["sha256"]),
                )
                if len(recipe_download.content) != recipe["size"]:
                    raise EvidenceError(f"size mismatch for native-component recipe {source_id}")
                verify_native_component_recipe(source_id, native_source, recipe_download.content)
                recipe_relative = f"sources/native-components/{source_directory}/recipe.tar.gz"
                write_file(
                    root,
                    recipe_relative,
                    recipe_download.content,
                    budget=budget,
                )
                source_records.append(
                    source_record(
                        f"native-source:{source_id}",
                        recipe_download.urls,
                        recipe_download.content,
                        recipe_relative,
                    )
                )
                collect_notices(
                    recipe_download.content,
                    "recipe.tar.gz",
                    max_archive_bytes=MAX_DOWNLOAD_BYTES,
                )
                for distfile in native_source["distfiles"]:
                    filename = str(distfile["filename"])
                    distfile_download = _read_bounded_alpine_distfile(
                        alpine_source_reader,
                        _alpine_distfile_request_id(
                            str(native_source["distfiles_release"]),
                            filename,
                        ),
                        str(distfile["url"]),
                        str(distfile["sha512"]),
                        budget,
                    )
                    if len(distfile_download.content) != distfile["size"]:
                        raise EvidenceError(
                            f"size mismatch for native-component distfile {source_id}/{filename}"
                        )
                    distfile_relative = (
                        f"sources/native-components/{source_directory}/distfiles/{filename}"
                    )
                    retain_alpine_distfile(
                        root,
                        distfile_relative,
                        distfile_download.content,
                        budget=budget,
                    )
                    source_records.append(
                        source_record(
                            f"native-source:{source_id}",
                            distfile_download.urls,
                            distfile_download.content,
                            distfile_relative,
                            sha512=str(distfile["sha512"]),
                        )
                    )
                    collect_notices(
                        distfile_download.content,
                        filename,
                        max_archive_bytes=MAX_ALPINE_DISTFILE_BYTES,
                    )
            elif kind == "crates-io":
                crate = native_source["crate"]
                crate_download = direct_source(
                    native_request_ids["crate"],
                    str(crate["url"]),
                    str(crate["sha256"]),
                    max_bytes=MAX_NATIVE_COMPONENT_SOURCE_BYTES,
                )
                if len(crate_download.content) != crate["size"]:
                    raise EvidenceError(f"size mismatch for native-component crate {source_id}")
                reviewed_files = verify_crates_io_archive(
                    crate_download.content,
                    source_id=source_id,
                    source=native_source,
                )
                crate_relative = (
                    f"sources/native-components/{source_directory}/"
                    f"{safe_filename(str(crate['url']))}"
                )
                write_file(
                    root,
                    crate_relative,
                    crate_download.content,
                    budget=budget,
                    max_bytes=MAX_NATIVE_COMPONENT_SOURCE_BYTES,
                )
                source_records.append(
                    source_record(
                        f"native-source:{source_id}",
                        crate_download.urls,
                        crate_download.content,
                        crate_relative,
                    )
                )
                found_notices.update(
                    {
                        member: content
                        for member, content in reviewed_files.items()
                        if member in expected_notices
                    }
                )
            elif kind == "owner-sdist-subpath":
                owner_archive, owner_urls, owner_relative = _reuse_owner_sdist_source(
                    native_source,
                    source_id,
                    python_source_archives,
                )
                subtree = verify_owner_sdist_subtree(
                    owner_archive,
                    source_id=source_id,
                    source=native_source,
                    archive_name=owner_relative,
                )
                verify_owner_sdist_cargo_packages(
                    owner_archive,
                    source_id=source_id,
                    source=native_source,
                    archive_name=owner_relative,
                    subtree=subtree,
                    bindings=native_owner_sdist_bindings_by_source.get(source_id, set()),
                )
                manifest_relative = (
                    f"sources/native-components/{source_directory}/subtree-manifest.json"
                )
                manifest_content = canonical_json(subtree)
                write_file(root, manifest_relative, manifest_content, budget=budget)
                source_records.append(
                    source_record(
                        f"native-source:{source_id}",
                        owner_urls,
                        owner_archive,
                        owner_relative,
                    )
                )
                collect_notices(
                    owner_archive,
                    owner_relative,
                    max_archive_bytes=MAX_DOWNLOAD_BYTES,
                )
            elif kind == "checksummed-upstream-release":
                checksum = native_source["checksum_document"]
                checksum_download = direct_source(
                    native_request_ids["checksum_document"],
                    str(checksum["url"]),
                    str(checksum["sha256"]),
                )
                if len(checksum_download.content) != checksum["size"]:
                    raise EvidenceError(f"size mismatch for checksum document {source_id}")
                archive_policy = native_source["archive"]
                archive_download = direct_source(
                    native_request_ids["archive"],
                    str(archive_policy["url"]),
                    str(archive_policy["sha256"]),
                    max_bytes=MAX_NATIVE_COMPONENT_SOURCE_BYTES,
                )
                if len(archive_download.content) != archive_policy["size"]:
                    raise EvidenceError(f"size mismatch for upstream release archive {source_id}")
                verify_upstream_checksum_document(
                    checksum_download.content,
                    filename=str(native_source["checksum_filename"]),
                    expected_sha256=str(archive_policy["sha256"]),
                )
                for artifact_name, artifact, download in (
                    ("checksum", checksum, checksum_download),
                    ("archive", archive_policy, archive_download),
                ):
                    relative = (
                        f"sources/native-components/{source_directory}/{artifact_name}-"
                        f"{safe_filename(str(artifact['url']))}"
                    )
                    write_file(
                        root,
                        relative,
                        download.content,
                        budget=budget,
                        max_bytes=MAX_NATIVE_COMPONENT_SOURCE_BYTES,
                    )
                    source_records.append(
                        source_record(
                            f"native-source:{source_id}",
                            download.urls,
                            download.content,
                            relative,
                        )
                    )
                collect_notices(
                    archive_download.content,
                    str(native_source["checksum_filename"]),
                    max_archive_bytes=MAX_NATIVE_COMPONENT_SOURCE_BYTES,
                )
            else:
                raise EvidenceError(f"unsupported native-component bundle source kind: {kind}")

            if set(found_notices) != set(expected_notices):
                raise EvidenceError(f"native-component source omits reviewed notices: {source_id}")
            notice_paths = retain_reviewed_native_notices(
                found_notices,
                component_directory=f"native-{source_directory}",
                root=root,
                budget=budget,
            )
            license_records.extend(
                {"component": component_id, "path": notice_path}
                for component_id in sorted(native_components_by_source[source_id])
                for notice_path in notice_paths
            )

        alpine_components = [
            component for component in inventory["components"] if component["ecosystem"] == "alpine"
        ]
        origins: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for component in alpine_components:
            origins.setdefault((component["origin"], component["aports_commit"]), []).append(
                component
            )
        alpine_release = policy.get("alpine_distfiles_release")
        if not isinstance(alpine_release, str) or not re.fullmatch(r"v\d+\.\d+", alpine_release):
            raise EvidenceError("invalid Alpine distfiles release in policy")
        expected_recipes = policy.get("alpine_recipe_archives", {})
        recipe_exceptions = policy.get("alpine_recipe_exceptions", {})
        if not isinstance(expected_recipes, dict) or not isinstance(recipe_exceptions, dict):
            raise EvidenceError("invalid Alpine recipe policy")
        unknown_exceptions = sorted(set(recipe_exceptions) - set(expected_recipes))
        if unknown_exceptions:
            raise EvidenceError(
                "Alpine recipe exceptions have no pinned archive: " + ", ".join(unknown_exceptions)
            )
        for (origin, commit), packages in sorted(origins.items()):
            recipe_url = (
                "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
                f"{commit}/aports-{commit}.tar.gz?path=main/{origin}"
            )
            recipe_key = f"{origin}@{commit}"
            expected_recipe_hash = expected_recipes.get(recipe_key)
            if not isinstance(expected_recipe_hash, str):
                raise EvidenceError(f"no reviewed recipe archive hash for {origin}@{commit}")
            recipe_download = direct_source(
                _alpine_recipe_request_id(origin, commit),
                recipe_url,
                expected_recipe_hash,
            )
            recipe = recipe_download.content
            recipe_relative = f"sources/alpine/{origin}/{commit}/recipe.tar.gz"
            write_file(root, recipe_relative, recipe, budget=budget)
            source_records.append(
                source_record(
                    f"alpine-{origin}-recipe",
                    recipe_download.urls,
                    recipe,
                    recipe_relative,
                )
            )
            allow_dynamic_sources, allowed_links = alpine_recipe_exception(policy, recipe_key)
            checksums, local_sources = recipe_checksums(
                recipe,
                origin,
                allow_dynamic_sources=allow_dynamic_sources,
                allowed_links=allowed_links,
            )
            upstream_count = 0
            for filename, expected_sha512 in sorted(checksums.items()):
                if filename in local_sources:
                    continue
                upstream_count += 1
                url = (
                    f"https://distfiles.alpinelinux.org/distfiles/{alpine_release}/"
                    f"{urllib.parse.quote(filename, safe='')}"
                )
                download = _read_bounded_alpine_distfile(
                    alpine_source_reader,
                    _alpine_distfile_request_id(alpine_release, filename),
                    url,
                    expected_sha512,
                    budget,
                )
                content = download.content
                relative = f"sources/alpine/{origin}/{commit}/distfiles/{filename}"
                retain_alpine_distfile(root, relative, content, budget=budget)
                source_records.append(
                    source_record(
                        f"alpine-{origin}",
                        download.urls,
                        content,
                        relative,
                        sha512=expected_sha512,
                    )
                )
                found = extract_license_files(
                    content,
                    f"alpine-{origin}",
                    root,
                    archive_name=filename,
                    budget=budget,
                    max_archive_bytes=MAX_ALPINE_DISTFILE_BYTES,
                )
                license_records.extend(
                    {"component": f"alpine-{origin}", "path": item} for item in found
                )
            if upstream_count == 0:
                # A commit-pinned recipe subtree is the source for Alpine-native data packages.
                found = extract_license_files(
                    recipe,
                    f"alpine-{origin}",
                    root,
                    archive_name="recipe.tar.gz",
                    budget=budget,
                )
                license_records.extend(
                    {"component": f"alpine-{origin}", "path": item} for item in found
                )
            for package in packages:
                package["source_recipe"] = recipe_relative

        for entry in policy.get("license_texts", []):
            if not isinstance(entry, dict):
                raise EvidenceError("invalid license text policy entry")
            identifier = entry.get("id")
            if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9.+-]+", identifier):
                raise EvidenceError("invalid license identifier")
            download = direct_source(
                _license_text_request_id(identifier),
                str(entry.get("url", "")),
                str(entry.get("sha256", "")),
                max_bytes=MAX_LICENSE_BYTES,
            )
            content = download.content
            relative = f"licenses/standard/{identifier}.txt"
            write_file(root, relative, content, budget=budget)
            license_records.append({"component": f"license:{identifier}", "path": relative})
            source_records.append(
                source_record(f"license:{identifier}", download.urls, content, relative)
            )

        unique_license_records = {
            (record["component"], record["path"]): record for record in license_records
        }
        license_records = list(unique_license_records.values())
        for record in license_records:
            retained_path = root / record["path"]
            record["sha256"] = sha256_file(retained_path, max_bytes=MAX_BUNDLE_RETAINED_BYTES)
            record["size"] = retained_path.stat().st_size
        verify_pinned_custom_license_records(inventory["components"], policy, license_records)

        notices = BoundedBytesBuilder()
        notices.append("# Third-party notices\n\n")
        notices.append(
            "This inventory is evidence, not legal advice. License expressions are the reviewed "
            "project policy; the observed upstream metadata is retained separately.\n\n"
        )
        notices.append(
            "| Ecosystem | Component | Version | In effective filesystem | Observed | Reviewed |\n"
        )
        notices.append("| --- | --- | --- | --- | --- | --- |\n")
        for component in sorted(inventory["components"], key=component_sort_key):
            ecosystem = markdown_cell(component["ecosystem"])
            name = markdown_cell(component["name"])
            component_version = markdown_cell(component["version"])
            observed = markdown_cell(component["observed_license"]) or "Not declared"
            approved = markdown_cell(resolved_license(component, policy))
            notices.append(
                f"| {ecosystem} | {name} | {component_version} | "
                f"{'yes' if component['effective'] else 'no; retained in a lower layer'} | "
                f"{observed} | {approved} |\n"
            )
        nested_components: set[tuple[str, ...]] = set()
        native_omissions: list[tuple[str, str, str, str]] = []
        for owner_record in raw_coverage:
            context = validate_native_owner_review(
                owner_record,
                platform=str(inventory["platform"]),
                sources=source_policies,
                used_sources=set(),
            )
            for review in owner_record["component_reviews"]:
                for raw_reference in review["observations"]:
                    reference = validate_observation_reference(
                        raw_reference,
                        "third-party notice observation",
                    )
                    component = context["observations"][reference]
                    nested_components.add(
                        (
                            str(owner_record["owner"]),
                            str(component["name"]),
                            str(component["version"]),
                            str(component["purl"]),
                            str(component["bom_ref"]),
                            str(review["source"]),
                            canonical_json(component["licenses"]).decode("utf-8"),
                            str(review["reviewed_license"]),
                        )
                    )
            native_omissions.extend(
                (
                    str(owner_record["owner"]),
                    str(known_omission["id"]),
                    ", ".join(known_omission["missing_evidence"]),
                    str(known_omission["reason"]),
                )
                for known_omission in owner_record["known_omissions"]
            )
        if nested_components:
            notices.append("\n## Native wheel components\n\n")
            notices.append(
                "These occurrence identities and observed license fields come from the exact "
                "retained embedded SBOM bytes. Reviewed expressions are project policy.\n\n"
            )
            notices.append(
                "| Owner | Component | Version | Package URL | bom-ref | Source | "
                "Observed licenses | Reviewed |\n"
            )
            notices.append("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
            for (
                owner,
                name,
                nested_version,
                purl,
                bom_ref,
                source_id,
                observed_licenses,
                reviewed,
            ) in sorted(nested_components):
                notices.append(
                    f"| {markdown_cell(owner)} | {markdown_cell(name)} | "
                    f"{markdown_cell(nested_version)} | {markdown_cell(purl)} | "
                    f"{markdown_cell(bom_ref)} | {markdown_cell(source_id)} | "
                    f"{markdown_cell(observed_licenses)} | {markdown_cell(reviewed)} |\n"
                )
        if native_omissions:
            notices.append("\n## Open native-component evidence\n\n")
            notices.append(
                "These items are explicit gaps, not inferred approvals. Distribution remains "
                "incomplete while any item is open.\n\n"
            )
            notices.append("| Owner | Item | Missing evidence | Exact reason |\n")
            notices.append("| --- | --- | --- | --- |\n")
            for owner, omission_id, missing, reason in sorted(native_omissions):
                notices.append(
                    f"| {markdown_cell(owner)} | {markdown_cell(omission_id)} | "
                    f"{markdown_cell(missing)} | {markdown_cell(reason)} |\n"
                )
        sbom_anomalies = native_coverage["observed_sbom_anomalies"]
        if sbom_anomalies:
            notices.append("\n## Upstream SBOM anomalies\n\n")
            notices.append("| Owner | SBOM | Observation digest | Anomaly | Review |\n")
            notices.append("| --- | --- | --- | --- | --- |\n")
            for anomaly in sbom_anomalies:
                notices.append(
                    f"| {markdown_cell(anomaly['owner'])} | "
                    f"{markdown_cell(anomaly['sbom_path'])} | "
                    f"{markdown_cell(anomaly['observation_sha256'])} | "
                    f"{markdown_cell(anomaly['kind'])} | "
                    f"{markdown_cell(anomaly['reason'])} |\n"
                )
        notices.append(
            "\nThe archive includes the standard license texts named above, source-carried "
            "license and notice files, exact source archives, and commit-pinned Alpine "
            "recipes.\n"
        )
        write_file(
            root,
            "THIRD_PARTY_NOTICES.md",
            notices.finish(),
            budget=budget,
        )

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "name": "extra-codeowners-container-distribution-evidence",
            "version": version,
            "platform": inventory["platform"],
            "subject_digest": inventory["subject_digest"],
            "base_image_index_digest": policy["base_image_index_digest"],
            "policy_sha256": sha256_bytes(canonical_json(policy)),
            "application_artifacts": application_artifacts,
            "native_wheel_artifacts": native_wheel_artifacts,
            "native_component_coverage": native_coverage,
            "source_completeness": {
                "complete": native_coverage["complete"],
                "remaining_owner_count": native_coverage["remaining_owner_count"],
                "remaining_owner_names": native_coverage["remaining_owner_names"],
            },
            "source_records": sorted(source_records, key=lambda item: item["path"]),
            "license_records": sorted(
                license_records, key=lambda item: (item["component"], item["path"])
            ),
            "legal_status": (
                "Evidence archive; not a legal-compliance determination. "
                "See policy/distribution_approval and the project documentation."
            ),
        }
        write_file(root, "MANIFEST.json", canonical_json(manifest), budget=budget)
        checksum_lines = BoundedBytesBuilder()
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            relative = path.relative_to(root).as_posix()
            checksum_lines.append(
                f"{sha256_file(path, max_bytes=MAX_BUNDLE_RETAINED_BYTES)}  {relative}\n"
            )
        write_file(
            root,
            "SHA256SUMS",
            checksum_lines.finish(),
            budget=budget,
        )
        _close_verified_source_readers(direct_source_reader, alpine_source_reader)
        publication = Path(temporary) / "publication"
        publication.mkdir(mode=0o700)
        staged_bundle = publication / "bundle"
        staged_checksum = publication / "checksum"
        staged_predicate = publication / "predicate"
        create_deterministic_tar(root, staged_bundle, source_date_epoch)
        if staged_bundle.stat().st_size > MAX_BUNDLE_OUTPUT_BYTES:
            raise EvidenceError("compressed evidence bundle exceeds the output-size limit")
        bundle_hash = sha256_file(staged_bundle, max_bytes=MAX_BUNDLE_OUTPUT_BYTES)
        staged_checksum.write_bytes(f"{bundle_hash}  {output.name}\n".encode())
        predicate = {
            "schema_version": SCHEMA_VERSION,
            "media_type": EVIDENCE_MEDIA_TYPE,
            "platform": inventory["platform"],
            "subject_digest": inventory["subject_digest"],
            "artifact": {"filename": output.name, "sha256": bundle_hash},
            "release_url": f"https://github.com/stampbot/extra-codeowners/releases/tag/v{version}",
        }
        staged_predicate.write_bytes(canonical_json(predicate))
        path_boundary.publish(
            bundle=staged_bundle,
            checksum=staged_checksum,
            predicate=staged_predicate,
        )


def build_bundle(
    *,
    inventory_path: Path,
    files_path: Path,
    policy_path: Path,
    lock_path: Path,
    direct_source_store_root: Path,
    direct_source_plan_sha256: str,
    direct_source_plan_size: int,
    alpine_source_store_root: Path,
    alpine_source_plan_sha256: str,
    alpine_source_plan_size: int,
    bundle_work_root: Path,
    repo: Path,
    output: Path,
    predicate_output: Path,
    version: str,
    source_date_epoch: int,
    selected_python_directory: Path,
    application_source_revision: str,
    application_wheel_sha256: str,
    application_selection_record_sha256: str,
    require_approval: bool,
    require_image_revision: bool,
) -> None:
    """Build one evidence trio and leave no final files when the build fails."""

    path_boundary = BundlePathBoundary(
        work_root=bundle_work_root,
        inputs=(
            inventory_path,
            files_path,
            policy_path,
            lock_path,
            direct_source_store_root,
            alpine_source_store_root,
            repo,
            selected_python_directory,
        ),
        output=output,
        predicate_output=predicate_output,
    )
    try:
        _build_bundle_with_boundary(
            path_boundary=path_boundary,
            inventory_path=inventory_path,
            files_path=files_path,
            policy_path=policy_path,
            lock_path=lock_path,
            direct_source_store_root=direct_source_store_root,
            direct_source_plan_sha256=direct_source_plan_sha256,
            direct_source_plan_size=direct_source_plan_size,
            alpine_source_store_root=alpine_source_store_root,
            alpine_source_plan_sha256=alpine_source_plan_sha256,
            alpine_source_plan_size=alpine_source_plan_size,
            repo=repo,
            output=output,
            predicate_output=predicate_output,
            version=version,
            source_date_epoch=source_date_epoch,
            selected_python_directory=selected_python_directory,
            application_source_revision=application_source_revision,
            application_wheel_sha256=application_wheel_sha256,
            application_selection_record_sha256=application_selection_record_sha256,
            require_approval=require_approval,
            require_image_revision=require_image_revision,
        )
    except BaseException:
        path_boundary.abort()
        raise


def source_record(
    component: str,
    urls: str | Sequence[str],
    content: bytes,
    path: str,
    *,
    sha512: str | None = None,
) -> dict[str, Any]:
    url_chain = (urls,) if isinstance(urls, str) else tuple(urls)
    if not url_chain:
        raise EvidenceError(f"source record for {component} has no URL")
    for url in url_chain:
        require_https_source_url(url)
    result = {
        "component": component,
        "url": url_chain[0],
        "urls": list(url_chain),
        "path": path,
        "size": len(content),
        "sha256": sha256_bytes(content),
    }
    if sha512 is not None:
        result["sha512"] = sha512
    return result


def create_deterministic_tar(root: Path, output: Path, source_date_epoch: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        output.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            relative = path.relative_to(root).as_posix()
            info = tarfile.TarInfo(relative)
            size = path.stat().st_size
            limit = bundle_member_size_limit(relative)
            if size > limit:
                raise EvidenceError(f"bundle member exceeds the size limit: {relative}")
            info.size = size
            info.mode = 0o644
            info.mtime = source_date_epoch
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            with path.open("rb") as content:
                archive.addfile(info, content)


def ci_artifact_entry_limits(architecture: str) -> dict[str, int]:
    if architecture not in {"amd64", "arm64"}:
        raise EvidenceError(f"unsupported CI artifact architecture: {architecture!r}")
    bundle = f"extra-codeowners-ci-linux-{architecture}-evidence.tar.gz"
    return {
        f"all-layer-files-{architecture}.json": MAX_JSON_BYTES,
        f"components-{architecture}.json": MAX_JSON_BYTES,
        f"evidence-predicate-{architecture}.json": 1024 * 1024,
        f"run-metadata-{architecture}.json": 1024 * 1024,
        bundle: MAX_BUNDLE_OUTPUT_BYTES,
        f"{bundle}.sha256": 1024,
    }


def preflight_ci_artifact_zip(source: Any, size: int, expected_entries: int) -> int:
    """Bound the ZIP directory before the standard library allocates its entry list."""

    if not ZIP_EOCD.size <= size <= MAX_CI_ARTIFACT_ZIP_BYTES:
        raise EvidenceError("CI artifact ZIP has an invalid size")
    tail_size = min(size, ZIP_EOCD.size + 65_535)
    source.seek(size - tail_size)
    tail = source.read(tail_size)
    candidates: list[tuple[int, tuple[Any, ...]]] = []
    position = 0
    while True:
        position = tail.find(b"PK\x05\x06", position)
        if position < 0:
            break
        if position + ZIP_EOCD.size <= len(tail):
            values = ZIP_EOCD.unpack_from(tail, position)
            absolute = size - tail_size + position
            if absolute + ZIP_EOCD.size + values[-1] == size:
                candidates.append((absolute, values))
        position += 1
    if len(candidates) != 1:
        raise EvidenceError("CI artifact ZIP has no unique end-of-central-directory record")
    eocd_offset, values = candidates[0]
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        _comment_size,
    ) = values
    if signature != b"PK\x05\x06" or disk_number != 0 or central_disk != 0:
        raise EvidenceError("CI artifact ZIP uses unsupported multi-disk metadata")
    if 0xFFFF in {disk_entries, total_entries} or 0xFFFFFFFF in {
        central_size,
        central_offset,
    }:
        raise EvidenceError("CI artifact ZIP64 metadata is not supported")
    if disk_entries != expected_entries or total_entries != expected_entries:
        raise EvidenceError("CI artifact ZIP has an unexpected entry count")
    if (
        central_size > MAX_CI_ARTIFACT_CENTRAL_DIRECTORY_BYTES
        or central_offset + central_size != eocd_offset
    ):
        raise EvidenceError("CI artifact ZIP has an invalid central-directory boundary")
    if eocd_offset >= 20:
        source.seek(eocd_offset - 20)
        if source.read(4) == b"PK\x06\x07":
            raise EvidenceError("CI artifact ZIP64 metadata is not supported")
    return int(central_offset)


def validate_ci_zip_entries(
    source: Any,
    archive: zipfile.ZipFile,
    limits: Mapping[str, int],
    central_offset: int,
) -> list[zipfile.ZipInfo]:
    """Validate exact central and local ZIP records before reading payloads."""

    if archive.comment or archive.start_dir != central_offset:
        raise EvidenceError("CI artifact ZIP has unsupported archive metadata")
    entries = archive.infolist()
    names = [entry.filename for entry in entries]
    if len(entries) != len(limits) or len(names) != len(set(names)) or set(names) != set(limits):
        raise EvidenceError("CI artifact ZIP does not contain the exact expected files")
    expected_central_size = sum(46 + len(name.encode("ascii")) for name in names)
    source.seek(0, os.SEEK_END)
    if central_offset + expected_central_size + ZIP_EOCD.size != source.tell():
        raise EvidenceError("CI artifact ZIP central directory has an unexpected shape")
    declared_total = 0
    ranges: list[tuple[int, int, str]] = []
    for entry in entries:
        name = entry.filename
        try:
            encoded_name = name.encode("ascii")
        except UnicodeEncodeError as exc:
            raise EvidenceError("CI artifact ZIP has a non-ASCII entry name") from exc
        if str(checked_path(name)) != name or len(PurePosixPath(name).parts) != 1:
            raise EvidenceError(f"CI artifact ZIP has an unsafe entry name: {name!r}")
        if (
            entry.is_dir()
            or entry.create_system != 3
            or entry.create_version != 45
            or entry.extract_version != 20
            or entry.reserved != 0
            or entry.volume != 0
            or entry.internal_attr != 0
            or entry.external_attr != CI_ARTIFACT_EXTERNAL_ATTR
            or entry.extra
            or entry.comment
        ):
            raise EvidenceError(f"CI artifact ZIP has unsupported entry metadata: {name}")
        if entry.flag_bits != 0x08:
            raise EvidenceError(f"CI artifact ZIP has unsupported flags: {name}")
        if entry.compress_type != zipfile.ZIP_DEFLATED:
            raise EvidenceError(f"CI artifact ZIP has an unsupported compression method: {name}")
        if (
            entry.file_size < 0
            or entry.compress_size < 0
            or entry.file_size > limits[name]
            or entry.file_size > max(1, entry.compress_size) * MAX_CI_ARTIFACT_COMPRESSION_RATIO
        ):
            raise EvidenceError(f"CI artifact ZIP entry exceeds its resource limits: {name}")
        declared_total += entry.file_size
        if declared_total > MAX_CI_ARTIFACT_EXPANDED_BYTES:
            raise EvidenceError("CI artifact ZIP exceeds the cumulative expansion limit")

        if not 0 <= entry.header_offset < central_offset:
            raise EvidenceError(f"CI artifact ZIP has an invalid local header: {name}")
        source.seek(entry.header_offset)
        raw_header = source.read(ZIP_LOCAL_HEADER.size)
        if len(raw_header) != ZIP_LOCAL_HEADER.size:
            raise EvidenceError(f"CI artifact ZIP has a truncated local header: {name}")
        (
            signature,
            _version,
            flags,
            compression,
            _time,
            _date,
            crc,
            compressed_size,
            file_size,
            name_size,
            extra_size,
        ) = ZIP_LOCAL_HEADER.unpack(raw_header)
        if signature != b"PK\x03\x04" or _version != 20 or flags != 0x08:
            raise EvidenceError(f"CI artifact ZIP local header disagrees: {name}")
        if compression != zipfile.ZIP_DEFLATED:
            raise EvidenceError(f"CI artifact ZIP compression metadata disagrees: {name}")
        year, month, day, hour, minute, second = entry.date_time
        expected_time = (hour << 11) | (minute << 5) | (second // 2)
        expected_date = ((year - 1980) << 9) | (month << 5) | day
        if _time != expected_time or _date != expected_date:
            raise EvidenceError(f"CI artifact ZIP timestamp metadata disagrees: {name}")
        raw_name = source.read(name_size)
        if raw_name != encoded_name:
            raise EvidenceError(f"CI artifact ZIP local name disagrees: {name}")
        if crc != 0 or compressed_size != 0 or file_size != 0 or extra_size != 0:
            raise EvidenceError(f"CI artifact ZIP local record disagrees: {name}")
        data_offset = entry.header_offset + ZIP_LOCAL_HEADER.size + name_size + extra_size
        data_end = data_offset + entry.compress_size
        descriptor_end = data_end + ZIP_DATA_DESCRIPTOR.size
        if data_offset < entry.header_offset or descriptor_end > central_offset:
            raise EvidenceError(f"CI artifact ZIP payload boundary is invalid: {name}")
        source.seek(data_end)
        raw_descriptor = source.read(ZIP_DATA_DESCRIPTOR.size)
        if len(raw_descriptor) != ZIP_DATA_DESCRIPTOR.size:
            raise EvidenceError(f"CI artifact ZIP has a truncated data descriptor: {name}")
        descriptor_signature, descriptor_crc, descriptor_compressed, descriptor_size = (
            ZIP_DATA_DESCRIPTOR.unpack(raw_descriptor)
        )
        if (
            descriptor_signature != b"PK\x07\x08"
            or descriptor_crc != entry.CRC
            or descriptor_compressed != entry.compress_size
            or descriptor_size != entry.file_size
        ):
            raise EvidenceError(f"CI artifact ZIP data descriptor disagrees: {name}")
        ranges.append((entry.header_offset, descriptor_end, name))
    if [start for start, _end, _name in ranges] != sorted(start for start, _end, _name in ranges):
        raise EvidenceError("CI artifact ZIP central directory is not in local-record order")
    ranges.sort()
    if not ranges or ranges[0][0] != 0 or ranges[-1][1] != central_offset:
        raise EvidenceError("CI artifact ZIP has a prefix, gap, or trailing local data")
    for index in range(1, len(ranges)):
        previous, current = ranges[index - 1], ranges[index]
        if current[0] != previous[1]:
            raise EvidenceError(f"CI artifact ZIP entries are not contiguous: {current[2]}")
    return entries


def load_canonical_json(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if read_local_bytes(path, max_bytes=MAX_JSON_BYTES) != canonical_json(value):
        raise EvidenceError(f"CI artifact JSON is not canonical: {path.name}")
    return value


def validate_ci_artifact_contents(root: Path, architecture: str) -> None:
    """Validate every extracted artifact relationship without opening the evidence tar."""

    inventory = load_canonical_json(root / f"components-{architecture}.json")
    files = load_canonical_json(root / f"all-layer-files-{architecture}.json")
    metadata = load_canonical_json(root / f"run-metadata-{architecture}.json")
    predicate = load_canonical_json(root / f"evidence-predicate-{architecture}.json")
    validate_all_layer_inventory(files, inventory)
    validate_run_metadata(metadata, inventory)
    bundle_name = f"extra-codeowners-ci-linux-{architecture}-evidence.tar.gz"
    bundle_path = root / bundle_name
    bundle_hash = sha256_file(bundle_path, max_bytes=MAX_BUNDLE_OUTPUT_BYTES)
    sidecar = read_local_bytes(root / f"{bundle_name}.sha256", max_bytes=1024)
    expected_sidecar = f"{bundle_hash}  {bundle_name}\n".encode("ascii")
    if sidecar != expected_sidecar:
        raise EvidenceError("CI artifact checksum sidecar does not match the evidence archive")
    require_schema(predicate, "CI evidence predicate")
    require_exact_fields(
        predicate,
        {"schema_version", "media_type", "platform", "subject_digest", "artifact", "release_url"},
        "CI evidence predicate",
    )
    artifact = require_exact_fields(
        predicate["artifact"], {"filename", "sha256"}, "CI evidence predicate artifact"
    )
    expected_predicate = {
        "schema_version": SCHEMA_VERSION,
        "media_type": EVIDENCE_MEDIA_TYPE,
        "platform": inventory["platform"],
        "subject_digest": inventory["subject_digest"],
        "artifact": {"filename": bundle_name, "sha256": bundle_hash},
        "release_url": "https://github.com/stampbot/extra-codeowners/releases/tag/v0.0.0-ci",
    }
    if predicate != expected_predicate or artifact != expected_predicate["artifact"]:
        raise EvidenceError("CI evidence predicate does not match the exact artifact inventory")
    if inventory["subject_digest"] != inventory["image_config_digest"]:
        raise EvidenceError("CI inventory subject must be its local image configuration digest")


def validate_ci_artifact_pair(amd64_root: Path, arm64_root: Path) -> None:
    """Require two platform artifacts to describe one identical workflow context."""

    validate_ci_artifact_contents(amd64_root, "amd64")
    validate_ci_artifact_contents(arm64_root, "arm64")
    metadata = {
        "amd64": load_canonical_json(amd64_root / "run-metadata-amd64.json"),
        "arm64": load_canonical_json(arm64_root / "run-metadata-arm64.json"),
    }
    platform_specific = {
        "platform",
        "architecture",
        "inventory_subject_digest",
        "inventory_image_config_digest",
    }
    shared = {
        architecture: {
            field: value for field, value in record.items() if field not in platform_specific
        }
        for architecture, record in metadata.items()
    }
    if shared["amd64"] != shared["arm64"]:
        raise EvidenceError("CI evidence platforms do not share one exact workflow context")
    for field in ("inventory_subject_digest", "inventory_image_config_digest"):
        if metadata["amd64"][field] == metadata["arm64"][field]:
            raise EvidenceError(f"CI evidence platforms unexpectedly share one {field}")


def extract_ci_artifact(archive_path: Path, architecture: str, output: Path) -> None:
    """Extract one raw GitHub artifact ZIP into a fresh atomic review directory."""

    limits = ci_artifact_entry_limits(architecture)
    if not hasattr(os, "O_NOFOLLOW"):
        raise EvidenceError("CI artifact extraction requires O_NOFOLLOW support")
    try:
        parent_stat = output.parent.lstat()
    except OSError as exc:
        raise EvidenceError(f"cannot inspect CI artifact output parent: {exc}") from exc
    if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
        raise EvidenceError("CI artifact output parent must be a real directory")
    if os.path.lexists(output):
        raise EvidenceError("CI artifact output already exists")
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor = os.open(archive_path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        archive_stat = os.fstat(descriptor)
        if not stat.S_ISREG(archive_stat.st_mode):
            raise EvidenceError("CI artifact ZIP input must be a regular file")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            central_offset = preflight_ci_artifact_zip(source, archive_stat.st_size, len(limits))
            source.seek(0)
            with zipfile.ZipFile(source, mode="r") as archive:
                entries = validate_ci_zip_entries(source, archive, limits, central_offset)
                temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
                temporary.chmod(0o700)
                actual_total = 0
                by_name = {entry.filename: entry for entry in entries}
                for name in sorted(limits):
                    entry = by_name[name]
                    destination = temporary / name
                    output_descriptor = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                    )
                    remaining = entry.file_size
                    try:
                        with (
                            os.fdopen(output_descriptor, "wb") as target,
                            archive.open(entry, mode="r") as payload,
                        ):
                            output_descriptor = -1
                            while remaining:
                                chunk = payload.read(min(1024 * 1024, remaining))
                                if not chunk:
                                    raise EvidenceError(
                                        f"CI artifact ZIP entry is truncated: {name}"
                                    )
                                target.write(chunk)
                                remaining -= len(chunk)
                                actual_total += len(chunk)
                                if actual_total > MAX_CI_ARTIFACT_EXPANDED_BYTES:
                                    raise EvidenceError(
                                        "CI artifact ZIP exceeds the cumulative expansion limit"
                                    )
                            if payload.read(1):
                                raise EvidenceError(
                                    f"CI artifact ZIP entry exceeds its declared size: {name}"
                                )
                    finally:
                        if output_descriptor >= 0:
                            os.close(output_descriptor)
                validate_ci_artifact_contents(temporary, architecture)
        os.rename(temporary, output)
        temporary = None
    except EvidenceError:
        raise
    except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error) as exc:
        raise EvidenceError(f"cannot safely extract CI artifact ZIP: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def command_inventory(args: argparse.Namespace) -> None:
    inventory, files = image_inventory(
        args.image,
        args.platform,
        args.subject_digest,
        allow_config_digest_subject=args.allow_config_digest_subject,
    )
    Path(args.output).write_bytes(canonical_json(inventory))
    Path(args.files_output).write_bytes(canonical_json(files))


def command_verify(args: argparse.Namespace) -> None:
    verify_inventory(
        load_json(Path(args.inventory)),
        load_json(Path(args.policy)),
        require_approval=args.require_distribution_approval,
    )


def command_verify_ci_policy(args: argparse.Namespace) -> None:
    """Apply trusted deep policy and Dockerfile gates to extracted CI JSON."""

    inventory = load_json(Path(args.inventory))
    files = load_json(Path(args.files_inventory))
    policy = load_json(Path(args.policy))
    validate_all_layer_inventory(files, inventory)
    verify_inventory(inventory, policy, require_approval=False)
    verify_base_layer_binding(files, policy)
    verify_post_base_filesystem_policy(files, policy)
    verify_dockerfile_base(Path(args.dockerfile), policy)


def validate_filesystem_policy_view_input(files: Mapping[str, Any]) -> None:
    """Validate the standalone all-layer fields used by the policy projection."""

    require_schema(files, "all-layer inventory")
    require_exact_fields(
        files,
        {
            "schema_version",
            "platform",
            "subject_digest",
            "image_config_digest",
            "layers",
            "regular_files",
            "directories",
            "non_regular_files",
            "whiteouts",
        },
        "all-layer inventory",
    )
    platform = files.get("platform")
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise EvidenceError("all-layer inventory has an unsupported platform")
    for field in ("subject_digest", "image_config_digest"):
        value = files.get(field)
        if not isinstance(value, str) or SHA256.fullmatch(value) is None:
            raise EvidenceError(f"all-layer inventory has an invalid {field}")

    layers = files.get("layers")
    if not isinstance(layers, list) or not layers or len(layers) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("all-layer inventory has an invalid layer list")
    layer_digests: list[str] = []
    count_fields = {
        "regular_files": "regular_file_count",
        "directories": "directory_count",
        "non_regular_files": "non_regular_file_count",
        "whiteouts": "whiteout_count",
    }
    for index, layer in enumerate(layers):
        record = require_exact_fields(
            layer,
            {
                "index",
                "digest",
                "regular_file_count",
                "directory_count",
                "non_regular_file_count",
                "whiteout_count",
            },
            "all-layer inventory layer",
        )
        digest = record.get("digest")
        if (
            record.get("index") != index
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise EvidenceError("all-layer inventory has invalid layer identity")
        for count_field in count_fields.values():
            count = record.get(count_field)
            if (
                not isinstance(count, int)
                or isinstance(count, bool)
                or not 0 <= count <= MAX_IMAGE_MEMBERS
            ):
                raise EvidenceError("all-layer inventory has an invalid layer count")
        layer_digests.append(digest)
    if len(set(layer_digests)) != len(layer_digests):
        raise EvidenceError("all-layer inventory repeats a layer digest")

    all_occurrences: set[tuple[int, str]] = set()
    for category, count_field in count_fields.items():
        records = files.get(category)
        if not isinstance(records, list) or len(records) > MAX_IMAGE_MEMBERS:
            raise EvidenceError(f"all-layer inventory has an invalid {category} list")
        observed_counts = [0] * len(layers)
        seen: set[tuple[int, str]] = set()
        for item in records:
            if not isinstance(item, dict):
                raise EvidenceError(f"all-layer inventory has an invalid {category} record")
            kind = item.get("kind")
            if category == "regular_files":
                expected_fields = {
                    "effective",
                    "layer",
                    "layer_digest",
                    "path",
                    "sha256",
                    "size",
                    "mode",
                    "uid",
                    "gid",
                }
            elif category == "directories":
                expected_fields = {
                    "effective",
                    "layer",
                    "layer_digest",
                    "path",
                    "mode",
                    "uid",
                    "gid",
                }
            elif category == "non_regular_files":
                expected_fields = (
                    {"kind", "layer", "layer_digest", "path", "target", "mode", "uid", "gid"}
                    if kind in {"symlink", "hardlink"}
                    else {"kind", "layer", "layer_digest", "path", "mode", "uid", "gid"}
                )
            else:
                expected_fields = {
                    "kind",
                    "layer",
                    "layer_digest",
                    "path",
                    "target",
                    "mode",
                    "uid",
                    "gid",
                }
            if set(item) != expected_fields:
                raise EvidenceError(f"all-layer inventory has an invalid {category} record")
            layer_index = item.get("layer")
            if (
                not isinstance(layer_index, int)
                or isinstance(layer_index, bool)
                or not 0 <= layer_index < len(layers)
                or item.get("layer_digest") != layer_digests[layer_index]
            ):
                raise EvidenceError(f"all-layer inventory has an invalid {category} layer")
            path_value = item.get("path")
            if not isinstance(path_value, str):
                raise EvidenceError(f"all-layer inventory {category} record has no path")
            path = str(checked_canonical_path(path_value, f"all-layer inventory {category} path"))
            occurrence = (layer_index, path)
            if occurrence in seen:
                raise EvidenceError(f"all-layer inventory repeats a {category} path")
            seen.add(occurrence)
            if occurrence in all_occurrences:
                raise EvidenceError("all-layer inventory repeats one path across entry categories")
            all_occurrences.add(occurrence)
            validate_header_identity(item, f"all-layer inventory {category} record")
            if category in {"regular_files", "directories"} and not isinstance(
                item.get("effective"), bool
            ):
                raise EvidenceError(f"all-layer inventory {category} has invalid effective state")
            if category == "regular_files":
                digest = item.get("sha256")
                size = item.get("size")
                if (
                    not isinstance(digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or not isinstance(size, int)
                    or isinstance(size, bool)
                    or not 0 <= size <= MAX_ARCHIVE_MEMBER_BYTES
                ):
                    raise EvidenceError("all-layer inventory has an invalid regular file")
            elif category == "non_regular_files":
                if kind not in {"symlink", "hardlink", "other"}:
                    raise EvidenceError("all-layer inventory has an invalid non-regular kind")
                if kind in {"symlink", "hardlink"}:
                    target = item.get("target")
                    if not isinstance(target, str):
                        raise EvidenceError("all-layer inventory link has no target")
                    checked_image_link_target(target)
            elif category == "whiteouts":
                validate_removal_policy(
                    [{field: item[field] for field in ("kind", "path", "target")}],
                    platform,
                )
            observed_counts[layer_index] += 1
        if observed_counts != [layer[count_field] for layer in layers]:
            raise EvidenceError(f"all-layer inventory {category} counts do not match")
    if sum(len(files[category]) for category in count_fields) > MAX_IMAGE_MEMBERS:
        raise EvidenceError("all-layer inventory exceeds the cumulative entry-count limit")


def command_filesystem_policy_view(args: argparse.Namespace) -> None:
    """Emit the auditable semantic filesystem projection for one raw inventory."""

    files = load_json(Path(args.files_inventory))
    policy = load_json(Path(args.policy))
    validate_filesystem_policy_view_input(files)
    validate_policy_schema(policy)
    verify_base_layer_binding(files, policy)
    platform = files["platform"]
    directory_effects, removals = canonical_post_base_filesystem_changes(
        files, post_base_layer_count(files, policy), platform
    )
    Path(args.output).write_bytes(
        canonical_json(
            {
                "platform": platform,
                "post_base_directory_effects": directory_effects,
                "post_base_removals": removals,
            }
        )
    )


def command_native_component_coverage_view(args: argparse.Namespace) -> None:
    """Emit the validated per-owner native-component closure ledger."""

    inventory = load_json(Path(args.inventory))
    policy = load_json(Path(args.policy))
    verify_inventory(inventory, policy, require_approval=False)
    Path(args.output).write_bytes(
        canonical_json(native_component_coverage_ledger(inventory, policy))
    )


def command_bundle(args: argparse.Namespace) -> None:
    build_bundle(
        inventory_path=Path(args.inventory),
        files_path=Path(args.files_inventory),
        policy_path=Path(args.policy),
        lock_path=Path(args.uv_lock),
        direct_source_store_root=Path(args.direct_source_store_root),
        direct_source_plan_sha256=args.direct_source_plan_sha256,
        direct_source_plan_size=args.direct_source_plan_size,
        alpine_source_store_root=Path(args.alpine_source_store_root),
        alpine_source_plan_sha256=args.alpine_source_plan_sha256,
        alpine_source_plan_size=args.alpine_source_plan_size,
        bundle_work_root=Path(args.bundle_work_root),
        repo=Path(args.repo).resolve(),
        output=Path(args.output),
        predicate_output=Path(args.predicate_output),
        version=args.version,
        source_date_epoch=args.source_date_epoch,
        selected_python_directory=Path(args.selected_python_directory),
        application_source_revision=args.application_source_revision,
        application_wheel_sha256=args.application_wheel_sha256,
        application_selection_record_sha256=args.application_selection_record_sha256,
        require_approval=args.require_distribution_approval,
        require_image_revision=args.require_image_revision,
    )


def command_extract_ci_artifact(args: argparse.Namespace) -> None:
    extract_ci_artifact(Path(args.archive), args.architecture, Path(args.output))


def command_compare_ci_artifacts(args: argparse.Namespace) -> None:
    validate_ci_artifact_pair(Path(args.amd64), Path(args.arm64))


def validate_run_metadata(metadata: Mapping[str, Any], inventory: Mapping[str, Any]) -> None:
    """Validate exact workflow context and its binding to one component inventory."""

    require_schema(metadata, "run metadata")
    require_exact_fields(
        metadata,
        {
            "schema_version",
            "run_id",
            "run_attempt",
            "event_name",
            "repository_id",
            "pr_number",
            "pr_head_sha",
            "pr_base_sha",
            "pr_head_repository_id",
            "github_sha",
            "checkout_sha",
            "workflow_ref",
            "workflow_sha",
            "platform",
            "architecture",
            "inventory_subject_digest",
            "inventory_image_config_digest",
            "python_distribution_artifact_id",
            "python_distribution_artifact_digest",
            "application_source_revision",
            "application_wheel_sha256",
            "application_selection_record_sha256",
        },
        "run metadata",
    )
    validate_component_inventory(inventory)
    sha_fields = {
        "pr_head_sha",
        "pr_base_sha",
        "github_sha",
        "checkout_sha",
        "workflow_sha",
    }
    for field in sha_fields:
        value = metadata[field]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise EvidenceError(f"run metadata has an invalid {field}")
    if metadata["github_sha"] != metadata["checkout_sha"]:
        raise EvidenceError("GitHub workflow SHA does not match the checked-out commit")
    if inventory.get("image_revision") != metadata["checkout_sha"]:
        raise EvidenceError("container revision does not match run metadata checkout SHA")
    if metadata["application_source_revision"] != metadata["checkout_sha"]:
        raise EvidenceError("application source revision does not match run metadata checkout SHA")
    if inventory.get("image_revision") != metadata["application_source_revision"]:
        raise EvidenceError("application source revision does not match the container label")
    for field in (
        "python_distribution_artifact_digest",
        "application_wheel_sha256",
        "application_selection_record_sha256",
    ):
        value = metadata[field]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise EvidenceError(f"run metadata has an invalid {field}")
    if metadata["application_wheel_sha256"] != inventory.get("application_wheel_sha256"):
        raise EvidenceError("application wheel digest does not match the container label")
    if metadata["application_selection_record_sha256"] != inventory.get(
        "application_selection_record_sha256"
    ):
        raise EvidenceError("application selection digest does not match the container label")
    positive_identifier_fields = {
        "run_id",
        "repository_id",
        "pr_head_repository_id",
        "python_distribution_artifact_id",
    }
    for field in positive_identifier_fields:
        value = metadata[field]
        if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,19}", value) is None:
            raise EvidenceError(f"run metadata has an invalid {field}")
    pr_number = metadata["pr_number"]
    if not isinstance(pr_number, str) or re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", pr_number) is None:
        raise EvidenceError("run metadata has an invalid pr_number")
    run_attempt = metadata["run_attempt"]
    if (
        not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or not 1 <= run_attempt <= 1_000_000
    ):
        raise EvidenceError("run metadata has an invalid run_attempt")
    event_name = metadata["event_name"]
    if (
        not isinstance(event_name, str)
        or checked_scalar(event_name, "run metadata event name") != event_name
    ):
        raise EvidenceError("run metadata has an invalid event_name")
    if (event_name == "pull_request") != (pr_number != "0"):
        raise EvidenceError("run metadata event and pull-request number disagree")
    workflow_ref = metadata["workflow_ref"]
    if (
        not isinstance(workflow_ref, str)
        or checked_scalar(
            workflow_ref,
            "run metadata workflow ref",
            max_length=MAX_PATH_BYTES,
        )
        != workflow_ref
    ):
        raise EvidenceError("run metadata has an invalid workflow_ref")
    if (metadata["platform"], metadata["architecture"]) not in {
        ("linux/amd64", "amd64"),
        ("linux/arm64", "arm64"),
    }:
        raise EvidenceError("run metadata platform and architecture disagree")
    if metadata["platform"] != inventory.get("platform"):
        raise EvidenceError("run metadata platform does not match the component inventory")
    if metadata["inventory_subject_digest"] != inventory.get("subject_digest"):
        raise EvidenceError("run metadata subject does not match the component inventory")
    if metadata["inventory_image_config_digest"] != inventory.get("image_config_digest"):
        raise EvidenceError("run metadata config does not match the component inventory")


def command_run_metadata(args: argparse.Namespace) -> None:
    """Emit immutable event and checkout identity beside one platform artifact."""

    inventory = load_json(Path(args.inventory))
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "event_name": args.event_name,
        "repository_id": args.repository_id,
        "pr_number": args.pr_number,
        "pr_head_sha": args.pr_head_sha,
        "pr_base_sha": args.pr_base_sha,
        "pr_head_repository_id": args.pr_head_repository_id,
        "github_sha": args.github_sha,
        "checkout_sha": args.checkout_sha,
        "workflow_ref": args.workflow_ref,
        "workflow_sha": args.workflow_sha,
        "platform": args.platform,
        "architecture": args.architecture,
        "inventory_subject_digest": inventory["subject_digest"],
        "inventory_image_config_digest": inventory["image_config_digest"],
        "python_distribution_artifact_id": args.python_distribution_artifact_id,
        "python_distribution_artifact_digest": args.python_distribution_artifact_digest,
        "application_source_revision": args.application_source_revision,
        "application_wheel_sha256": args.application_wheel_sha256,
        "application_selection_record_sha256": args.application_selection_record_sha256,
    }
    validate_run_metadata(metadata, inventory)
    Path(args.output).write_bytes(canonical_json(metadata))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(required=True)
    inventory = subcommands.add_parser("inventory", help="inventory a local single-platform image")
    inventory.add_argument("--image", required=True)
    inventory.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    inventory.add_argument("--subject-digest", required=True)
    inventory.add_argument("--output", required=True)
    inventory.add_argument("--files-output", required=True)
    inventory.add_argument(
        "--allow-config-digest-subject",
        action="store_true",
        help="allow a local-only config digest instead of a pulled repository manifest digest",
    )
    inventory.set_defaults(function=command_inventory)

    verify = subcommands.add_parser("verify", help="compare an inventory with reviewed policy")
    verify.add_argument("--inventory", required=True)
    verify.add_argument("--policy", default=".compliance/container-policy.json")
    verify.add_argument("--require-distribution-approval", action="store_true")
    verify.set_defaults(function=command_verify)

    verify_ci_policy = subcommands.add_parser(
        "verify-ci-policy",
        help="apply trusted policy, all-layer base, and Dockerfile gates to extracted CI JSON",
    )
    verify_ci_policy.add_argument("--inventory", required=True)
    verify_ci_policy.add_argument("--files-inventory", required=True)
    verify_ci_policy.add_argument("--policy", required=True)
    verify_ci_policy.add_argument("--dockerfile", required=True)
    verify_ci_policy.set_defaults(function=command_verify_ci_policy)

    filesystem_policy_view = subcommands.add_parser(
        "filesystem-policy-view",
        help="emit canonical semantic directory and removal policy input",
    )
    filesystem_policy_view.add_argument("--files-inventory", required=True)
    filesystem_policy_view.add_argument("--policy", required=True)
    filesystem_policy_view.add_argument("--output", required=True)
    filesystem_policy_view.set_defaults(function=command_filesystem_policy_view)

    native_coverage_view = subcommands.add_parser(
        "native-component-coverage-view",
        help="emit the validated per-owner native-component coverage ledger",
    )
    native_coverage_view.add_argument("--inventory", required=True)
    native_coverage_view.add_argument("--policy", required=True)
    native_coverage_view.add_argument("--output", required=True)
    native_coverage_view.set_defaults(function=command_native_component_coverage_view)

    bundle = subcommands.add_parser("bundle", help="collect and archive exact source evidence")
    bundle.add_argument("--inventory", required=True)
    bundle.add_argument("--files-inventory", required=True)
    bundle.add_argument("--policy", default=".compliance/container-policy.json")
    bundle.add_argument("--uv-lock", default="uv.lock")
    bundle.add_argument("--direct-source-store-root", required=True)
    bundle.add_argument("--direct-source-plan-sha256", required=True)
    bundle.add_argument("--direct-source-plan-size", required=True, type=int)
    bundle.add_argument("--alpine-source-store-root", required=True)
    bundle.add_argument("--alpine-source-plan-sha256", required=True)
    bundle.add_argument("--alpine-source-plan-size", required=True, type=int)
    bundle.add_argument("--bundle-work-root", required=True)
    bundle.add_argument("--repo", default=".")
    bundle.add_argument("--output", required=True)
    bundle.add_argument("--predicate-output", required=True)
    bundle.add_argument("--version", required=True)
    bundle.add_argument("--source-date-epoch", required=True, type=int)
    bundle.add_argument("--selected-python-directory", required=True)
    bundle.add_argument("--application-source-revision", required=True)
    bundle.add_argument("--application-wheel-sha256", required=True)
    bundle.add_argument("--application-selection-record-sha256", required=True)
    bundle.add_argument("--require-distribution-approval", action="store_true")
    bundle.add_argument("--require-image-revision", action="store_true")
    bundle.set_defaults(function=command_bundle)

    extract_artifact = subcommands.add_parser(
        "extract-ci-artifact",
        help="safely unpack and validate one raw GitHub Actions evidence artifact",
    )
    extract_artifact.add_argument("--archive", required=True)
    extract_artifact.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    extract_artifact.add_argument("--output", required=True)
    extract_artifact.set_defaults(function=command_extract_ci_artifact)

    compare_artifacts = subcommands.add_parser(
        "compare-ci-artifacts",
        help="validate that two extracted platform artifacts share one workflow context",
    )
    compare_artifacts.add_argument("--amd64", required=True)
    compare_artifacts.add_argument("--arm64", required=True)
    compare_artifacts.set_defaults(function=command_compare_ci_artifacts)

    run_metadata = subcommands.add_parser(
        "run-metadata", help="bind one evidence artifact to immutable workflow context"
    )
    run_metadata.add_argument("--inventory", required=True)
    run_metadata.add_argument("--output", required=True)
    run_metadata.add_argument("--run-id", required=True)
    run_metadata.add_argument("--run-attempt", required=True, type=int)
    run_metadata.add_argument("--event-name", required=True)
    run_metadata.add_argument("--repository-id", required=True)
    run_metadata.add_argument("--pr-number", required=True)
    run_metadata.add_argument("--pr-head-sha", required=True)
    run_metadata.add_argument("--pr-base-sha", required=True)
    run_metadata.add_argument("--pr-head-repository-id", required=True)
    run_metadata.add_argument("--github-sha", required=True)
    run_metadata.add_argument("--checkout-sha", required=True)
    run_metadata.add_argument("--workflow-ref", required=True)
    run_metadata.add_argument("--workflow-sha", required=True)
    run_metadata.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    run_metadata.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    run_metadata.add_argument("--python-distribution-artifact-id", required=True)
    run_metadata.add_argument("--python-distribution-artifact-digest", required=True)
    run_metadata.add_argument("--application-source-revision", required=True)
    run_metadata.add_argument("--application-wheel-sha256", required=True)
    run_metadata.add_argument("--application-selection-record-sha256", required=True)
    run_metadata.set_defaults(function=command_run_metadata)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        args.function(args)
    except EvidenceError as exc:
        sys.stderr.write(f"container evidence error: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
