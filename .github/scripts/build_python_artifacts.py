#!/usr/bin/env python3
"""Build and verify reproducible, hash-constrained Python distributions."""

from __future__ import annotations

import argparse
import base64
import configparser
import contextlib
import csv
import email.parser
import email.policy
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
EXPECTED_BUILD_PACKAGES = {
    "hatchling",
    "packaging",
    "pathspec",
    "pluggy",
    "trove-classifiers",
}
EXPECTED_BACKEND = "hatchling.build"
EXPECTED_PYTHON_REQUIREMENT = ">=3.12"
SUPPORTED_BUILD_PYTHONS = {(3, 12), (3, 13), (3, 14)}
SUPPORTED_BUILD_MACHINES = {"aarch64", "x86_64"}
SAFE_BUILD_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_CONSTRAINT_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_ENTRY_POINTS_BYTES = 64 * 1024
MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
MAX_SOURCE_PATH_BYTES = 4096
MAX_SOURCE_COMPONENT_BYTES = 255
BUILD_TIMEOUT_SECONDS = 300
BUILD_RECORD_NAME = "python-build-record.json"
SELECTION_RECORD_NAME = "python-selection-record.json"
ARCHITECTURE_MACHINES = {"amd64": "x86_64", "arm64": "aarch64"}
SELECTED_BUILD_RECORD_NAMES = {
    "amd64": "python-build-record-amd64.json",
    "arm64": "python-build-record-arm64.json",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
GIT_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
PINNED_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)"
    r"(?P<hashes>(?:\s+--hash=sha256:[0-9a-f]{64})+)$"
)
HASH_OPTION = re.compile(r"--hash=sha256:([0-9a-f]{64})")
WHEEL_FILENAME = re.compile(
    r"^(?P<distribution>[A-Za-z0-9_]+)-(?P<version>[A-Za-z0-9.!+_-]+)"
    r"-py3-none-any\.whl$"
)
ENTRY_POINT = re.compile(
    r"^(?P<module>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
    r":(?P<callable>[A-Za-z_]\w*)$"
)
SCRIPT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class BuildError(RuntimeError):
    """A build input or artifact violated the reviewed contract."""


class CaseSensitiveConfigParser(configparser.ConfigParser):
    """Preserve entry-point script names exactly as declared."""

    def optionxform(self, optionstr: str) -> str:
        return optionstr


@dataclass(frozen=True)
class BuildRequirement:
    """One exact build requirement and its approved PyPI artifacts."""

    name: str
    version: str
    hashes: tuple[str, ...]

    def record(self) -> dict[str, object]:
        return {"name": self.name, "version": self.version, "sha256": list(self.hashes)}


@dataclass(frozen=True)
class SourceEntry:
    """One bounded regular blob from the reviewed Git source tree."""

    mode: str
    object_id: str
    path: str
    size: int


@dataclass(frozen=True)
class ArtifactVerification:
    """Reviewable artifact facts plus a metadata-insensitive content identity."""

    record: dict[str, object]
    semantic_identity: bytes
    members: tuple[tuple[str, str, int], ...] = ()
    scripts: tuple[tuple[str, str, str], ...] = ()
    dist_info: str | None = None


@dataclass(frozen=True)
class DistributionProof:
    """One independently built and fully reverified architecture proof."""

    architecture: str
    directory: Path
    record_path: Path
    record_bytes: bytes
    record: dict[str, Any]
    wheel_path: Path
    wheel: ArtifactVerification
    sdist_path: Path
    sdist: ArtifactVerification


def canonical_name(value: str) -> str:
    """Return the canonical Python distribution name."""

    return re.sub(r"[-_.]+", "-", value).lower()


def canonical_json(value: object) -> bytes:
    """Encode one deterministic JSON value."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise BuildError(f"cannot hash non-regular file: {path}")
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
    except OSError as exc:
        raise BuildError(f"cannot hash file {path}: {exc}") from exc
    return digest.hexdigest()


def bounded_bytes(path: Path, limit: int, description: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BuildError(f"cannot inspect {description}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise BuildError(f"{description} must be a non-symlink regular file")
    size = metadata.st_size
    if not 0 <= size <= limit:
        raise BuildError(f"{description} exceeds its size limit")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise BuildError(f"cannot read {description}: {exc}") from exc


def logical_requirement_lines(value: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    for line_number, raw in enumerate(value.splitlines(), start=1):
        if "\x00" in raw or "\r" in raw:
            raise BuildError(f"build constraints contain invalid text on line {line_number}")
        stripped = raw.strip()
        if not stripped and not pending:
            continue
        if not stripped:
            raise BuildError("build constraint continuation crosses a blank line")
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment}".strip()
        if not continued:
            lines.append(pending)
            pending = ""
    if pending:
        raise BuildError("build constraints end with an incomplete continuation")
    return lines


def parse_build_constraints(path: Path) -> tuple[BuildRequirement, ...]:
    """Parse the intentionally narrow, hash-locked build constraint format."""

    content = bounded_bytes(path, MAX_CONSTRAINT_BYTES, "build constraints")
    try:
        lines = logical_requirement_lines(content.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise BuildError("build constraints are not UTF-8") from exc
    if not lines or lines.pop(0) != "--only-binary=:all:":
        raise BuildError("build constraints must begin with --only-binary=:all:")
    if any(line.startswith("--") for line in lines):
        raise BuildError("build constraints contain an unsupported global option")

    requirements: list[BuildRequirement] = []
    seen: set[str] = set()
    for line in lines:
        match = PINNED_REQUIREMENT.fullmatch(line)
        if match is None:
            raise BuildError("every build requirement must be an exact pin with SHA-256 hashes")
        name = canonical_name(match.group("name"))
        version = match.group("version")
        if name in seen:
            raise BuildError(f"build constraints repeat package {name}")
        seen.add(name)
        hashes = tuple(HASH_OPTION.findall(match.group("hashes")))
        if len(hashes) != 2 or len(set(hashes)) != 2 or hashes != tuple(sorted(hashes)):
            raise BuildError(
                f"build requirement {name} must have two unique, sorted SHA-256 hashes"
            )
        requirements.append(BuildRequirement(name=name, version=version, hashes=hashes))

    names = [requirement.name for requirement in requirements]
    if names != sorted(names):
        raise BuildError("build requirements must be sorted by canonical name")
    if set(names) != EXPECTED_BUILD_PACKAGES:
        raise BuildError("build constraints do not exactly cover the reviewed backend closure")
    return tuple(requirements)


def validate_project(path: Path, requirements: Sequence[BuildRequirement]) -> dict[str, str]:
    """Bind project metadata to the exact constrained build backend."""

    content = bounded_bytes(path, MAX_CONSTRAINT_BYTES, "pyproject.toml")
    try:
        project_file = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BuildError(f"cannot parse pyproject.toml: {exc}") from exc
    build_system = project_file.get("build-system")
    project = project_file.get("project")
    if not isinstance(build_system, dict) or not isinstance(project, dict):
        raise BuildError("pyproject.toml lacks build-system or project metadata")
    if set(build_system) != {"requires", "build-backend"}:
        raise BuildError("build-system may only declare the reviewed backend and requirements")
    if build_system.get("build-backend") != EXPECTED_BACKEND:
        raise BuildError(f"build backend must be {EXPECTED_BACKEND}")
    declared = build_system.get("requires")
    if not isinstance(declared, list) or len(declared) != 1 or not isinstance(declared[0], str):
        raise BuildError("build-system.requires must contain exactly one direct requirement")
    hatchling = next(
        (requirement for requirement in requirements if requirement.name == "hatchling"), None
    )
    if hatchling is None or declared != [f"hatchling=={hatchling.version}"]:
        raise BuildError("pyproject Hatchling pin differs from requirements-build.txt")
    name = project.get("name")
    version = project.get("version")
    requires_python = project.get("requires-python")
    if not isinstance(name, str) or PACKAGE_NAME.fullmatch(name) is None:
        raise BuildError("project name is invalid")
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise BuildError("project version is invalid")
    if requires_python != EXPECTED_PYTHON_REQUIREMENT:
        raise BuildError(
            f"project requires-python must remain {EXPECTED_PYTHON_REQUIREMENT}; "
            "re-audit conditional build dependencies before changing it"
        )
    tool = project_file.get("tool", {})
    hatch = tool.get("hatch", {}) if isinstance(tool, dict) else {}

    def contains_build_hook(value: object) -> bool:
        if not isinstance(value, dict):
            return False
        return "hooks" in value or any(contains_build_hook(child) for child in value.values())

    if contains_build_hook(hatch):
        raise BuildError("repository-defined Hatch build hooks are not permitted")
    return {
        "name": canonical_name(name),
        "version": version,
        "build_backend": EXPECTED_BACKEND,
        "build_requirement": declared[0],
        "requires_python": requires_python,
    }


def checked_archive_name(value: str, *, directory: bool = False) -> str:
    """Return a canonical relative archive member name or fail."""

    if (
        not value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "\\" in value
        or value.startswith("/")
    ):
        raise BuildError(f"archive contains an unsafe member name: {value!r}")
    trimmed = value[:-1] if directory and value.endswith("/") else value
    path = PurePosixPath(trimmed)
    if not trimmed or any(part in {"", ".", ".."} for part in path.parts):
        raise BuildError(f"archive contains an unsafe member name: {value!r}")
    if str(path) != trimmed:
        raise BuildError(f"archive member name is not canonical: {value!r}")
    return trimmed


def single_header(message: Any, name: str, description: str) -> str:
    values = message.get_all(name, [])
    if len(values) != 1 or not isinstance(values[0], str) or not values[0].strip():
        raise BuildError(f"{description} must contain exactly one {name} header")
    return values[0].strip()


def record_digest(content: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()


def validate_wheel_record(
    content: bytes, record_name: str, payloads: Mapping[str, bytes]
) -> list[dict[str, object]]:
    """Validate exact wheel RECORD ownership against the archive payload."""

    if len(content) > MAX_RECORD_BYTES:
        raise BuildError("wheel RECORD exceeds its size limit")
    try:
        rows = csv.reader(content.decode("utf-8").splitlines())
    except UnicodeDecodeError as exc:
        raise BuildError("wheel RECORD is not UTF-8") from exc
    entries: dict[str, tuple[str, str]] = {}
    try:
        for row_number, row in enumerate(rows, start=1):
            if len(row) != 3:
                raise BuildError(f"wheel RECORD row {row_number} does not have three fields")
            name = checked_archive_name(row[0])
            if name in entries:
                raise BuildError(f"wheel RECORD repeats path {name}")
            entries[name] = (row[1], row[2])
    except csv.Error as exc:
        raise BuildError(f"cannot parse wheel RECORD: {exc}") from exc
    if set(entries) != set(payloads):
        raise BuildError("wheel RECORD does not exactly cover wheel files")

    normalized: list[dict[str, object]] = []
    for name in sorted(entries):
        digest, size_text = entries[name]
        payload = payloads[name]
        if name == record_name:
            if digest or size_text:
                raise BuildError("wheel RECORD self-entry must omit digest and size")
        else:
            expected_digest = f"sha256={record_digest(payload)}"
            if digest != expected_digest or size_text != str(len(payload)):
                raise BuildError(f"wheel RECORD does not match {name}")
        normalized.append(
            {
                "path": name,
                "sha256": sha256_bytes(payload),
                "size": len(payload),
                "record_self": name == record_name,
            }
        )
    return normalized


def parse_script_entry_points(
    payloads: Mapping[str, bytes], dist_info: str
) -> tuple[tuple[str, str, str], ...]:
    """Return the exact launchers an installer may create for this wheel."""

    path = f"{dist_info}entry_points.txt"
    content = payloads.get(path)
    if content is None:
        return ()
    if len(content) > MAX_ENTRY_POINTS_BYTES:
        raise BuildError("wheel entry_points.txt exceeds its size limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuildError("wheel entry_points.txt is not UTF-8") from exc
    parser = CaseSensitiveConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
    )
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise BuildError(f"cannot parse wheel entry_points.txt: {exc}") from exc
    if parser.defaults():
        raise BuildError("wheel entry_points.txt must not contain defaults")

    scripts: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for section in ("console_scripts", "gui_scripts"):
        if not parser.has_section(section):
            continue
        for name, raw_value in parser.items(section, raw=True):
            if SCRIPT_NAME.fullmatch(name) is None or name in seen:
                raise BuildError("wheel declares an unsafe or repeated launcher name")
            seen.add(name)
            value = raw_value.strip()
            match = ENTRY_POINT.fullmatch(value)
            if match is None:
                raise BuildError("wheel declares an unsupported launcher entry point")
            scripts.append((name, match.group("module"), match.group("callable")))
    return tuple(sorted(scripts))


def verify_wheel(
    path: Path,
    *,
    expected_name: str | None = None,
    expected_version: str | None = None,
) -> ArtifactVerification:
    """Validate a pure Python wheel without extracting it."""

    try:
        file_metadata = path.lstat()
    except OSError as exc:
        raise BuildError(f"cannot inspect wheel: {exc}") from exc
    if not stat.S_ISREG(file_metadata.st_mode):
        raise BuildError("wheel must be a non-symlink regular file")
    archive_size = file_metadata.st_size
    if not 0 < archive_size <= MAX_ARCHIVE_BYTES:
        raise BuildError("wheel exceeds its size limit")
    filename = WHEEL_FILENAME.fullmatch(path.name)
    if filename is None:
        raise BuildError("wheel filename must use the py3-none-any tag")
    filename_name = canonical_name(filename.group("distribution"))
    filename_version = filename.group("version")
    if expected_name is not None and filename_name != canonical_name(expected_name):
        raise BuildError("wheel filename has the wrong project name")
    if expected_version is not None and filename_version != expected_version:
        raise BuildError("wheel filename has the wrong project version")

    payloads: dict[str, bytes] = {}
    semantic: list[dict[str, object]] = []
    total_size = 0
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                raise BuildError("wheel has an invalid member count")
            seen: set[str] = set()
            for member in members:
                is_directory = member.is_dir()
                name = checked_archive_name(member.filename, directory=is_directory)
                if name in seen:
                    raise BuildError(f"wheel repeats member {name}")
                seen.add(name)
                if member.flag_bits & 0x1:
                    raise BuildError("wheel contains an encrypted member")
                if member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise BuildError(f"wheel uses unsupported compression for {name}")
                mode = (member.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if is_directory:
                    if file_type not in {0, stat.S_IFDIR}:
                        raise BuildError(f"wheel directory has a non-directory type: {name}")
                    if member.file_size != 0:
                        raise BuildError(f"wheel directory has a payload: {name}")
                    continue
                if file_type not in {0, stat.S_IFREG}:
                    raise BuildError(f"wheel contains a non-regular member: {name}")
                if not 0 <= member.file_size <= MAX_MEMBER_BYTES:
                    raise BuildError(f"wheel member exceeds its size limit: {name}")
                total_size += member.file_size
                if total_size > MAX_EXPANDED_BYTES:
                    raise BuildError("wheel exceeds its cumulative expansion limit")
                payload = archive.read(member)
                if len(payload) != member.file_size:
                    raise BuildError(f"wheel member size disagrees: {name}")
                payloads[name] = payload
                semantic.append(
                    {
                        "path": name,
                        "sha256": sha256_bytes(payload),
                        "size": len(payload),
                        "mode": mode & 0o777,
                    }
                )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, BuildError):
            raise
        raise BuildError(f"cannot read wheel: {exc}") from exc

    dist_info = f"{filename.group('distribution')}-{filename_version}.dist-info/"
    metadata_names = sorted(name for name in payloads if name.endswith(".dist-info/METADATA"))
    wheel_names = sorted(name for name in payloads if name.endswith(".dist-info/WHEEL"))
    record_names = sorted(name for name in payloads if name.endswith(".dist-info/RECORD"))
    if metadata_names != [f"{dist_info}METADATA"]:
        raise BuildError("wheel dist-info identity does not match its filename")
    if wheel_names != [f"{dist_info}WHEEL"] or record_names != [f"{dist_info}RECORD"]:
        raise BuildError("wheel must contain one filename-bound WHEEL and RECORD")
    for name in payloads:
        root_component = PurePosixPath(name).parts[0]
        if root_component.endswith(".dist-info") and root_component != dist_info.removesuffix("/"):
            raise BuildError("wheel contains a foreign dist-info directory")
        if root_component.endswith(".data"):
            raise BuildError(
                "application wheel must not contain an installer-routed data directory"
            )
    if any(
        name.lower().endswith((".pyc", ".pyo"))
        or PurePosixPath(name).name
        in {"INSTALLER", "REQUESTED", "direct_url.json", "uv_cache.json"}
        for name in payloads
    ):
        raise BuildError("wheel contains installer metadata or generated bytecode")

    metadata = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        payloads[metadata_names[0]]
    )
    if metadata.defects:
        raise BuildError("wheel METADATA has parser defects")
    project_name = canonical_name(single_header(metadata, "Name", "wheel METADATA"))
    project_version = single_header(metadata, "Version", "wheel METADATA")
    if project_name != filename_name or project_version != filename_version:
        raise BuildError("wheel filename and METADATA identity disagree")

    wheel_metadata = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        payloads[wheel_names[0]]
    )
    if wheel_metadata.defects:
        raise BuildError("wheel WHEEL metadata has parser defects")
    if single_header(wheel_metadata, "Wheel-Version", "WHEEL") != "1.0":
        raise BuildError("wheel format version is unsupported")
    if single_header(wheel_metadata, "Root-Is-Purelib", "WHEEL").lower() != "true":
        raise BuildError("application wheel must be pure Python")
    tags = wheel_metadata.get_all("Tag", [])
    if tags != ["py3-none-any"]:
        raise BuildError("application wheel must have exactly the py3-none-any tag")
    generator = single_header(wheel_metadata, "Generator", "WHEEL")
    scripts = parse_script_entry_points(payloads, dist_info)

    record_rows = validate_wheel_record(payloads[record_names[0]], record_names[0], payloads)
    semantic_identity = canonical_json(sorted(semantic, key=lambda item: str(item["path"])))
    return ArtifactVerification(
        record={
            "filename": path.name,
            "sha256": sha256_file(path),
            "size": archive_size,
            "project": project_name,
            "version": project_version,
            "tag": "py3-none-any",
            "generator": generator,
            "member_count": len(payloads),
            "record_sha256": sha256_bytes(payloads[record_names[0]]),
            "record_identity_sha256": sha256_bytes(canonical_json(record_rows)),
            "semantic_identity_sha256": sha256_bytes(semantic_identity),
            "dist_info": dist_info.removesuffix("/"),
            "scripts": [script[0] for script in scripts],
        },
        semantic_identity=semantic_identity,
        members=tuple(
            (name, sha256_bytes(payload), len(payload))
            for name, payload in sorted(payloads.items())
        ),
        scripts=scripts,
        dist_info=dist_info.removesuffix("/"),
    )


def verify_sdist(
    path: Path,
    *,
    expected_name: str,
    expected_version: str,
    expected_policy: Mapping[str, bytes],
) -> ArtifactVerification:
    """Validate a bounded source distribution without generic extraction."""

    if set(expected_policy) != {"pyproject.toml", "requirements-build.txt"}:
        raise BuildError("source distribution policy comparison is incomplete")

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BuildError(f"cannot inspect source distribution: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise BuildError("source distribution must be a non-symlink regular file")
    archive_size = metadata.st_size
    if not 0 < archive_size <= MAX_ARCHIVE_BYTES:
        raise BuildError("source distribution exceeds its size limit")
    expected_filename = f"{expected_name.replace('-', '_')}-{expected_version}.tar.gz"
    if path.name != expected_filename:
        raise BuildError("source distribution filename has the wrong identity")
    expected_root = expected_filename.removesuffix(".tar.gz")
    semantic: list[dict[str, object]] = []
    regular_names: set[str] = set()
    required_payloads: dict[str, bytes] = {}
    seen: set[str] = set()
    member_count = 0
    total_size = 0
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise BuildError("source distribution has too many members")
                name = checked_archive_name(member.name, directory=member.isdir())
                if name in seen:
                    raise BuildError(f"source distribution repeats member {name}")
                seen.add(name)
                if not PurePosixPath(name).parts or PurePosixPath(name).parts[0] != expected_root:
                    raise BuildError("source distribution member escapes its versioned root")
                if member.isdir():
                    semantic.append({"path": name, "type": "directory", "mode": member.mode})
                    continue
                if not member.isreg():
                    raise BuildError(f"source distribution contains a special member: {name}")
                if not 0 <= member.size <= MAX_MEMBER_BYTES:
                    raise BuildError(f"source distribution member exceeds its size limit: {name}")
                total_size += member.size
                if total_size > MAX_EXPANDED_BYTES:
                    raise BuildError("source distribution exceeds its expansion limit")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BuildError(f"cannot read source distribution member: {name}")
                payload = extracted.read(MAX_MEMBER_BYTES + 1)
                if len(payload) != member.size:
                    raise BuildError(f"source distribution member size disagrees: {name}")
                regular_names.add(name)
                relative_name = name.removeprefix(f"{expected_root}/")
                if relative_name in {"PKG-INFO", "pyproject.toml", "requirements-build.txt"}:
                    required_payloads[relative_name] = payload
                semantic.append(
                    {
                        "path": name,
                        "type": "regular",
                        "sha256": sha256_bytes(payload),
                        "size": len(payload),
                        "mode": member.mode,
                    }
                )
    except (OSError, tarfile.TarError) as exc:
        if isinstance(exc, BuildError):
            raise
        raise BuildError(f"cannot read source distribution: {exc}") from exc
    required = {
        f"{expected_root}/LICENSE",
        f"{expected_root}/PKG-INFO",
        f"{expected_root}/README.md",
        f"{expected_root}/pyproject.toml",
        f"{expected_root}/requirements-build.txt",
    }
    if not required.issubset(regular_names):
        raise BuildError("source distribution omits required project or build-policy files")
    for relative_name, expected_content in expected_policy.items():
        if required_payloads.get(relative_name) != expected_content:
            raise BuildError(f"source distribution changes reviewed {relative_name}")
    package_metadata = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        required_payloads["PKG-INFO"]
    )
    if package_metadata.defects:
        raise BuildError("source distribution PKG-INFO has parser defects")
    if (
        canonical_name(single_header(package_metadata, "Name", "PKG-INFO"))
        != canonical_name(expected_name)
        or single_header(package_metadata, "Version", "PKG-INFO") != expected_version
    ):
        raise BuildError("source distribution PKG-INFO identity disagrees with its filename")
    semantic_identity = canonical_json(sorted(semantic, key=lambda item: str(item["path"])))
    return ArtifactVerification(
        record={
            "filename": path.name,
            "sha256": sha256_file(path),
            "size": archive_size,
            "member_count": member_count,
            "semantic_identity_sha256": sha256_bytes(semantic_identity),
        },
        semantic_identity=semantic_identity,
    )


def require_reproducible(
    first: Path,
    second: Path,
    verifier: Callable[[Path], ArtifactVerification],
    description: str,
) -> ArtifactVerification:
    """Require byte identity and distinguish semantic from archive-metadata drift."""

    first_result = verifier(first)
    second_result = verifier(second)
    if first_result.record["sha256"] == second_result.record["sha256"]:
        return first_result
    if first_result.semantic_identity == second_result.semantic_identity:
        raise BuildError(f"{description} bytes differ while semantic contents match")
    raise BuildError(f"{description} semantic contents differ across clean builds")


def checked_installed_file(candidate: Path, root: Path, raw_path: str) -> os.stat_result:
    """Require one lexical in-environment path with no symlink component."""

    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise BuildError("installed RECORD path escapes the environment") from exc
    current = root
    metadata: os.stat_result | None = None
    for component in relative.parts:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise BuildError(f"installed RECORD path is missing: {raw_path}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise BuildError(f"installed RECORD path crosses a symlink: {raw_path}")
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        raise BuildError(f"installed RECORD path is not regular: {raw_path}")
    return metadata


def expected_launcher(root: Path, module: str, callable_name: str) -> bytes:
    """Return the reviewed uv/distlib POSIX launcher for one entry point."""

    python = root / "bin" / "python"
    if any(character.isspace() for character in str(python)) or len(str(python)) > 120:
        raise BuildError("environment path cannot use the reviewed launcher form")
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


def verify_installed_record(
    record_path: Path,
    environment_root: Path,
    wheel: ArtifactVerification,
) -> dict[str, object]:
    """Bind every installed RECORD owner and launcher to one verified wheel."""

    if not wheel.members or wheel.dist_info is None:
        raise BuildError("installed verification requires a verified wheel manifest")
    root = environment_root.resolve()
    try:
        if not root.is_dir():
            raise BuildError("installed environment root is not a directory")
    except OSError as exc:
        raise BuildError(f"cannot inspect installed environment root: {exc}") from exc
    record = Path(os.path.abspath(record_path))
    try:
        record.relative_to(root)
    except ValueError as exc:
        raise BuildError("installed RECORD is outside the environment root") from exc
    if record.name != "RECORD" or record.parent.name != wheel.dist_info:
        raise BuildError("installed RECORD does not match the verified wheel dist-info")
    checked_installed_file(record, root, str(record))
    site_packages = record.parent.parent
    try:
        site_relative = site_packages.relative_to(root)
    except ValueError as exc:
        raise BuildError("installed site-packages directory is outside the environment") from exc
    if (
        len(site_relative.parts) != 3
        or site_relative.parts[0] != "lib"
        or site_relative.parts[2] != "site-packages"
        or re.fullmatch(r"python3\.(?:12|13|14)", site_relative.parts[1]) is None
    ):
        raise BuildError("installed RECORD is outside the reviewed CPython site-packages layout")

    content = bounded_bytes(record, MAX_RECORD_BYTES, "installed RECORD")
    try:
        rows = csv.reader(content.decode("utf-8").splitlines())
    except UnicodeDecodeError as exc:
        raise BuildError("installed RECORD is not UTF-8") from exc
    seen: set[Path] = set()
    normalized: list[dict[str, object]] = []
    installed_payloads: dict[str, bytes] = {}
    self_entries = 0
    cumulative_size = 0
    try:
        for row_number, row in enumerate(rows, start=1):
            if row_number > MAX_ARCHIVE_MEMBERS:
                raise BuildError("installed RECORD has too many rows")
            if len(row) != 3:
                raise BuildError(f"installed RECORD row {row_number} has the wrong shape")
            raw_path, digest, size_text = row
            if (
                not raw_path
                or any(ord(character) < 32 or ord(character) == 127 for character in raw_path)
                or "\\" in raw_path
                or raw_path.startswith("/")
                or str(PurePosixPath(raw_path)) != raw_path
            ):
                raise BuildError("installed RECORD contains an unsafe path")
            candidate = Path(os.path.normpath(site_packages / PurePosixPath(raw_path)))
            if candidate in seen:
                raise BuildError("installed RECORD repeats a resolved path")
            seen.add(candidate)
            metadata = checked_installed_file(candidate, root, raw_path)
            if metadata.st_size > MAX_MEMBER_BYTES:
                raise BuildError(f"installed RECORD file exceeds its size limit: {raw_path}")
            payload = bounded_bytes(candidate, MAX_MEMBER_BYTES, f"installed file {raw_path}")
            cumulative_size += len(payload)
            if cumulative_size > MAX_EXPANDED_BYTES:
                raise BuildError("installed RECORD exceeds its cumulative file limit")
            is_self = candidate == record
            if is_self:
                self_entries += 1
                if digest or size_text:
                    raise BuildError("installed RECORD self-entry must omit digest and size")
            elif digest != f"sha256={record_digest(payload)}" or size_text != str(len(payload)):
                raise BuildError(f"installed RECORD does not match {raw_path}")
            installed_payloads[raw_path] = payload
            normalized.append(
                {
                    "path": raw_path,
                    "sha256": sha256_bytes(payload),
                    "size": len(payload),
                    "record_self": is_self,
                }
            )
    except csv.Error as exc:
        raise BuildError(f"cannot parse installed RECORD: {exc}") from exc
    if self_entries != 1:
        raise BuildError("installed RECORD must contain exactly one self-entry")

    wheel_record = f"{wheel.dist_info}/RECORD"
    expected_members = {
        name: (digest, size) for name, digest, size in wheel.members if name != wheel_record
    }
    expected_scripts = {
        f"../../../bin/{name}": expected_launcher(root, module, callable_name)
        for name, module, callable_name in wheel.scripts
    }
    expected_paths = set(expected_members) | set(expected_scripts) | {wheel_record}
    if set(installed_payloads) != expected_paths:
        raise BuildError("installed RECORD ownership differs from the verified wheel manifest")
    for name, (digest, size) in expected_members.items():
        payload = installed_payloads[name]
        if sha256_bytes(payload) != digest or len(payload) != size:
            raise BuildError(f"installed file differs from the verified wheel: {name}")
    for name, expected_content in expected_scripts.items():
        candidate = Path(os.path.normpath(site_packages / PurePosixPath(name)))
        if installed_payloads[name] != expected_content:
            raise BuildError(f"installed launcher differs from the verified wheel: {name}")
        if not candidate.stat().st_mode & 0o111:
            raise BuildError(f"installed launcher is not executable: {name}")

    identity = canonical_json(sorted(normalized, key=lambda item: str(item["path"])))
    return {
        "wheel_sha256": wheel.record["sha256"],
        "project": wheel.record["project"],
        "version": wheel.record["version"],
        "record_sha256": sha256_bytes(content),
        "record_identity_sha256": sha256_bytes(identity),
        "entry_count": len(normalized),
        "cumulative_size": cumulative_size,
    }


def minimal_build_environment(scratch: Path, source_date_epoch: int) -> dict[str, str]:
    """Return a credential-free environment for the isolated build backend."""

    environment = {
        "HOME": str(scratch / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": SAFE_BUILD_PATH,
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(source_date_epoch),
        "TMPDIR": str(scratch / "tmp"),
        "TZ": "UTC",
        "UV_CACHE_DIR": str(scratch / "uv-cache"),
        "UV_LINK_MODE": "copy",
        "UV_NO_CACHE": "1",
        "UV_NO_CONFIG": "1",
        "UV_NO_MANAGED_PYTHON": "1",
        "UV_NO_PROGRESS": "1",
        "UV_NO_SOURCES": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "UV_PYTHON_INSTALL_DIR": str(scratch / "managed-python-disabled"),
    }
    for key in ("SSL_CERT_DIR", "SSL_CERT_FILE"):
        if value := os.environ.get(key):
            environment[key] = value
    for directory in (scratch / "home", scratch / "tmp"):
        directory.mkdir(parents=True, exist_ok=False)
    return environment


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: int,
    max_output_bytes: int = MAX_PROCESS_OUTPUT_BYTES,
    truncate_output: bool = True,
    decode_errors: str = "replace",
) -> str:
    """Run one fixed argv with bounded diagnostics and no shell."""

    try:
        process = subprocess.Popen(  # noqa: S603 - argv is constructed internally
            list(command),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        raise BuildError(f"cannot run {command[0]}: {exc}") from exc
    if process.stdout is None:
        process.kill()
        raise BuildError(f"cannot capture output from {command[0]}")

    diagnostics = bytearray()
    deadline = time.monotonic() + timeout
    terminated = False

    def terminate() -> None:
        nonlocal terminated
        if terminated:
            return
        terminated = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    terminate()
                    output = bytes(diagnostics).decode("utf-8", errors="replace")
                    raise BuildError(f"command timed out: {' '.join(command)}\n{output}")
                for key, _ in selector.select(min(remaining, 0.5)):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    diagnostics.extend(chunk)
                    if len(diagnostics) > max_output_bytes:
                        if not truncate_output:
                            terminate()
                            raise BuildError(f"command output exceeds its limit: {command[0]}")
                        del diagnostics[:-max_output_bytes]
        remaining = max(0.0, deadline - time.monotonic())
        return_code = process.wait(timeout=remaining)
    except OSError as exc:
        terminate()
        raise BuildError(f"cannot read output from {command[0]}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        terminate()
        raise BuildError(f"command timed out: {' '.join(command)}") from exc
    except BaseException:
        terminate()
        raise
    finally:
        process.stdout.close()
    output = bytes(diagnostics).decode("utf-8", errors=decode_errors)
    if return_code != 0:
        raise BuildError(f"command failed ({return_code}): {' '.join(command)}\n{output}")
    return output


def build_flags(constraints: Path, python: Path) -> list[str]:
    return [
        "--build-constraints",
        str(constraints),
        "--require-hashes",
        "--no-cache",
        "--no-create-gitignore",
        "--no-config",
        "--no-sources",
        "--default-index",
        "https://pypi.org/simple",
        "--index-strategy",
        "first-index",
        "--no-managed-python",
        "--no-python-downloads",
        "--python",
        str(python),
    ]


def exactly_one(path: Path, pattern: str, description: str) -> Path:
    matches = sorted(path.glob(pattern))
    if len(matches) != 1:
        raise BuildError(f"expected exactly one {description}, found {len(matches)}")
    return matches[0]


def build_once(
    *,
    uv: Path,
    python: Path,
    repo: Path,
    constraints: Path,
    output: Path,
    environment: Mapping[str, str],
) -> tuple[Path, Path]:
    output.mkdir(parents=True, exist_ok=False)
    flags = build_flags(constraints, python)
    run_command(
        [str(uv), "build", "--sdist", *flags, "--out-dir", str(output)],
        cwd=repo,
        environment=environment,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    sdist = exactly_one(output, "*.tar.gz", "source distribution")
    run_command(
        [str(uv), "build", "--wheel", *flags, "--out-dir", str(output), str(sdist)],
        cwd=repo,
        environment=environment,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    return sdist, exactly_one(output, "*.whl", "wheel")


def git_executable() -> str:
    """Return the system Git selected independently of the caller's PATH."""

    git = shutil.which("git", path=SAFE_BUILD_PATH)
    if git is None or not Path(git).is_file() or not os.access(git, os.X_OK):
        raise BuildError("cannot inspect Git source identity: Git is unavailable")
    return git


def git_command(arguments: Sequence[str]) -> list[str]:
    """Return a fixed plumbing command with executable local hooks disabled."""

    return [
        git_executable(),
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        *arguments,
    ]


def git_value(repo: Path, arguments: Sequence[str]) -> str:
    return run_command(
        git_command(arguments),
        cwd=repo,
        environment=local_git_environment(),
        timeout=30,
    ).strip()


def local_git_environment() -> dict[str, str]:
    """Return a local-only Git environment without ambient configuration or fetches."""

    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": SAFE_BUILD_PATH,
    }


def git_source_entries(repo: Path, revision: str) -> tuple[SourceEntry, ...]:
    """List bounded regular blobs from one literal Git tree."""

    if COMMIT.fullmatch(revision) is None:
        raise BuildError("source revision must be a lowercase 40-character Git object ID")
    try:
        listing = run_command(
            git_command(["ls-tree", "-rlz", "--full-tree", revision]),
            cwd=repo,
            environment=local_git_environment(),
            timeout=30,
            max_output_bytes=MAX_RECORD_BYTES,
            truncate_output=False,
            decode_errors="strict",
        )
    except UnicodeDecodeError as exc:
        raise BuildError("Git source listing contains a non-UTF-8 path") from exc

    entries: list[SourceEntry] = []
    seen: set[str] = set()
    aggregate_size = 0
    for raw_entry in listing.split("\0"):
        if not raw_entry:
            continue
        header, separator, raw_path = raw_entry.partition("\t")
        fields = header.split()
        if len(fields) != 4 or not separator:
            raise BuildError("Git source listing has an invalid object record")
        mode, object_type, object_id, raw_size = fields
        path = checked_archive_name(raw_path)
        encoded_path = path.encode("utf-8")
        if len(encoded_path) > MAX_SOURCE_PATH_BYTES or any(
            len(part.encode("utf-8")) > MAX_SOURCE_COMPONENT_BYTES
            for part in PurePosixPath(path).parts
        ):
            raise BuildError(f"Git source path exceeds its size limit: {path}")
        if any(part.casefold() == ".git" for part in PurePosixPath(path).parts):
            raise BuildError("Git source path contains reserved repository metadata")
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or GIT_OBJECT.fullmatch(object_id) is None
            or not raw_size.isascii()
            or not raw_size.isdecimal()
        ):
            raise BuildError(f"Git source is not a regular portable blob: {path}")
        size = int(raw_size)
        if not 0 <= size <= MAX_MEMBER_BYTES:
            raise BuildError(f"Git source blob exceeds its size limit: {path}")
        if path in seen:
            raise BuildError(f"Git source listing repeats path: {path}")
        seen.add(path)
        aggregate_size += size
        if aggregate_size > MAX_EXPANDED_BYTES:
            raise BuildError("Git source tree exceeds its aggregate size limit")
        entries.append(SourceEntry(mode=mode, object_id=object_id, path=path, size=size))
        if len(entries) > MAX_ARCHIVE_MEMBERS:
            raise BuildError("Git source tree has too many blobs")
    if not entries:
        raise BuildError("Git source tree is empty")
    return tuple(entries)


def source_tree_record(entries: Sequence[SourceEntry]) -> dict[str, object]:
    """Return a canonical identity for the exact Git blobs used by the backend."""

    manifest = [
        {
            "mode": entry.mode,
            "object_id": entry.object_id,
            "path": entry.path,
            "size": entry.size,
        }
        for entry in entries
    ]
    return {
        "blob_count": len(entries),
        "byte_count": sum(entry.size for entry in entries),
        "identity_sha256": sha256_bytes(canonical_json(manifest)),
    }


def read_git_blob(repo: Path, entry: SourceEntry) -> bytes:
    """Read one exact Git blob with separate bounded output and timeout handling."""

    try:
        process = subprocess.Popen(  # noqa: S603 - fixed Git plumbing command
            git_command(["cat-file", "blob", entry.object_id]),
            cwd=repo,
            env=local_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise BuildError(f"cannot materialize Git source blob: {entry.path}") from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise BuildError(f"cannot capture Git source blob: {entry.path}")

    content = bytearray()
    diagnostics = bytearray()
    deadline = time.monotonic() + 30
    terminated = False

    def terminate() -> None:
        nonlocal terminated
        if terminated:
            return
        terminated = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    terminate()
                    raise BuildError(f"Git source blob read timed out: {entry.path}")
                for key, _ in selector.select(min(remaining, 0.5)):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        content.extend(chunk)
                        if len(content) > entry.size:
                            terminate()
                            raise BuildError(
                                f"materialized Git source exceeds its declared size: {entry.path}"
                            )
                    else:
                        diagnostics.extend(chunk)
                        if len(diagnostics) > MAX_PROCESS_OUTPUT_BYTES:
                            del diagnostics[:-MAX_PROCESS_OUTPUT_BYTES]
        remaining = max(0.0, deadline - time.monotonic())
        return_code = process.wait(timeout=remaining)
    except OSError as exc:
        terminate()
        raise BuildError(f"cannot read Git source blob: {entry.path}") from exc
    except subprocess.TimeoutExpired as exc:
        terminate()
        raise BuildError(f"Git source blob read timed out: {entry.path}") from exc
    except BaseException:
        terminate()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
    if return_code != 0:
        message = bytes(diagnostics).decode("utf-8", errors="replace")
        raise BuildError(f"cannot materialize Git source blob: {entry.path}\n{message}")
    if len(content) != entry.size:
        raise BuildError(f"materialized Git source size disagrees: {entry.path}")

    return bytes(content)


def git_blob_object_id(repo: Path, path: Path) -> str:
    """Hash a file with Git's repository-native collision-aware implementation."""

    try:
        object_id = run_command(
            git_command(["hash-object", "--no-filters", "--", str(path)]),
            cwd=repo,
            environment=local_git_environment(),
            timeout=30,
            max_output_bytes=128,
            truncate_output=False,
            decode_errors="strict",
        ).strip()
    except UnicodeDecodeError as exc:
        raise BuildError(f"Git returned an invalid object identity for {path}") from exc
    if GIT_OBJECT.fullmatch(object_id) is None:
        raise BuildError(f"Git returned an invalid object identity for {path}")
    return object_id


def materialize_git_source(repo: Path, destination: Path, entries: Sequence[SourceEntry]) -> None:
    """Write exact reviewed Git blobs into a private build-only directory."""

    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for entry in entries:
        source_path = PurePosixPath(entry.path)
        parent = destination
        for component in source_path.parts[:-1]:
            parent /= component
            if not os.path.lexists(parent):
                parent.mkdir(mode=0o700)
            try:
                parent_metadata = parent.lstat()
            except OSError as exc:
                raise BuildError(
                    f"cannot inspect materialized Git directory: {entry.path}"
                ) from exc
            if not stat.S_ISDIR(parent_metadata.st_mode):
                raise BuildError(f"materialized Git source parent is not a directory: {entry.path}")
            os.chmod(parent, 0o700)
        target = parent / source_path.name
        if os.path.lexists(target):
            raise BuildError(f"Git source materialization repeats path: {entry.path}")
        try:
            with target.open("xb") as output:
                output.write(read_git_blob(repo, entry))
        except OSError as exc:
            raise BuildError(f"cannot materialize Git source blob: {entry.path}") from exc
        try:
            metadata = target.lstat()
        except OSError as exc:
            raise BuildError(f"cannot inspect materialized Git source: {entry.path}") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != entry.size:
            raise BuildError(f"materialized Git source size disagrees: {entry.path}")
        os.chmod(target, 0o700 if entry.mode == "100755" else 0o600)
        if git_blob_object_id(repo, target) != entry.object_id:
            raise BuildError(f"materialized Git source object disagrees: {entry.path}")


def verify_materialized_git_source(
    repo: Path, destination: Path, entries: Sequence[SourceEntry]
) -> None:
    """Require a build snapshot to remain the exact private Git blob tree."""

    expected = {entry.path: entry for entry in entries}
    expected_directories = {
        parent.as_posix()
        for entry in entries
        for parent in PurePosixPath(entry.path).parents
        if parent != PurePosixPath(".")
    }
    observed: set[str] = set()
    observed_directories: set[str] = set()
    aggregate_size = 0
    try:
        root_metadata = destination.lstat()
    except OSError as exc:
        raise BuildError("cannot inspect materialized Git source root") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_IMODE(root_metadata.st_mode) != 0o700:
        raise BuildError("materialized Git source root permissions changed")

    for raw_root, directories, filenames in os.walk(destination, topdown=True, followlinks=False):
        current = Path(raw_root)
        for name in directories:
            directory = current / name
            relative = checked_archive_name(directory.relative_to(destination).as_posix())
            if relative not in expected_directories:
                raise BuildError(f"build backend added a source-tree directory: {relative}")
            observed_directories.add(relative)
            try:
                metadata = directory.lstat()
            except OSError as exc:
                raise BuildError(f"cannot inspect materialized Git directory: {relative}") from exc
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise BuildError(f"materialized Git directory changed type or mode: {relative}")
        for name in filenames:
            candidate = current / name
            relative = checked_archive_name(candidate.relative_to(destination).as_posix())
            if relative in observed:
                raise BuildError(f"materialized Git source repeats path: {relative}")
            observed.add(relative)
            entry = expected.get(relative)
            if entry is None:
                raise BuildError(f"build backend added a source-tree path: {relative}")
            content = bounded_bytes(candidate, MAX_MEMBER_BYTES, f"materialized source {relative}")
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise BuildError(f"cannot inspect materialized source: {relative}") from exc
            expected_mode = 0o700 if entry.mode == "100755" else 0o600
            if metadata.st_size != entry.size or stat.S_IMODE(metadata.st_mode) != expected_mode:
                raise BuildError(f"materialized Git source changed size or mode: {relative}")
            aggregate_size += len(content)
            if aggregate_size > MAX_EXPANDED_BYTES:
                raise BuildError("materialized Git source exceeds its aggregate size limit")
            if git_blob_object_id(repo, candidate) != entry.object_id:
                raise BuildError(f"build backend changed a source-tree blob: {relative}")
            if len(observed) > MAX_ARCHIVE_MEMBERS:
                raise BuildError("materialized Git source has too many paths")
    missing = set(expected).difference(observed)
    if missing:
        raise BuildError(f"build backend removed a source-tree path: {min(missing)}")
    missing_directories = expected_directories.difference(observed_directories)
    if missing_directories:
        raise BuildError(
            f"build backend removed a source-tree directory: {min(missing_directories)}"
        )


def repository_file(repo: Path, relative: str, description: str) -> Path:
    """Return one non-symlink regular file contained by the source repository."""

    candidate = repo / relative
    try:
        if candidate.is_symlink() or not candidate.is_file():
            raise BuildError(f"{description} must be a non-symlink regular file")
        resolved = candidate.resolve()
        resolved.relative_to(repo)
    except OSError as exc:
        raise BuildError(f"cannot inspect {description}: {exc}") from exc
    except ValueError as exc:
        raise BuildError(f"{description} is outside the source repository") from exc
    return resolved


def toolchain_identity(
    uv: Path,
    python: Path,
    repo: Path,
    environment: Mapping[str, str],
) -> dict[str, object]:
    """Validate uv and CPython against the repository-reviewed execution matrix."""

    mise_path = repository_file(repo, "mise.toml", "mise.toml")
    mise_content = bounded_bytes(mise_path, MAX_CONSTRAINT_BYTES, "mise.toml")
    try:
        mise = tomllib.loads(mise_content.decode("utf-8"))
        reviewed_uv = mise["tools"]["uv"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise BuildError("mise.toml does not declare the reviewed uv version") from exc
    if (
        not isinstance(reviewed_uv, str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", reviewed_uv) is None
    ):
        raise BuildError("mise.toml uv version is not an exact semantic version")
    uv_identity = run_command(
        [str(uv), "--version"], cwd=repo, environment=environment, timeout=30
    ).strip()
    if re.fullmatch(rf"uv {re.escape(reviewed_uv)}(?: \([^\r\n]+\))?", uv_identity) is None:
        raise BuildError("uv executable does not match the version reviewed in mise.toml")

    raw_python_identity = run_command(
        [
            str(python),
            "-c",
            (
                "import json, platform, sys; "
                "print(json.dumps({'implementation': platform.python_implementation(), "
                "'version': platform.python_version(), "
                "'machine': platform.machine(), "
                "'major': sys.version_info.major, 'minor': sys.version_info.minor}, "
                "sort_keys=True))"
            ),
        ],
        cwd=repo,
        environment=environment,
        timeout=30,
    ).strip()
    try:
        python_identity = json.loads(raw_python_identity)
        implementation = python_identity["implementation"]
        version = python_identity["version"]
        machine = python_identity["machine"]
        major = python_identity["major"]
        minor = python_identity["minor"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise BuildError("Python executable returned an invalid identity") from exc
    if (
        implementation != "CPython"
        or not isinstance(version, str)
        or not isinstance(machine, str)
        or machine not in SUPPORTED_BUILD_MACHINES
        or not isinstance(major, int)
        or not isinstance(minor, int)
        or (major, minor) not in SUPPORTED_BUILD_PYTHONS
    ):
        raise BuildError("Python executable is outside the reviewed CPython 3.12-3.14 matrix")
    return {
        "uv": uv_identity,
        "uv_version": reviewed_uv,
        "python": version,
        "python_implementation": implementation,
        "python_major_minor": f"{major}.{minor}",
        "python_machine": machine,
    }


def write_record(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = canonical_json(value) + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def require_exact_dict(value: object, keys: set[str], description: str) -> dict[str, Any]:
    """Return an object with exactly the reviewed string keys."""

    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise BuildError(f"{description} must be a JSON object")
    result: dict[str, Any] = value
    if set(result) != keys:
        raise BuildError(f"{description} has unexpected or missing fields")
    return result


def require_string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise BuildError(f"{description} must be a non-empty string")
    return value


def require_sha256(value: object, description: str) -> str:
    candidate = require_string(value, description)
    if SHA256.fullmatch(candidate) is None:
        raise BuildError(f"{description} must be a lowercase SHA-256 digest")
    return candidate


def require_integer(value: object, description: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise BuildError(f"{description} is outside its reviewed integer range")
    return value


def read_canonical_json_object(path: Path, description: str) -> tuple[dict[str, Any], bytes]:
    """Read one bounded canonical JSON object with its exact digestable bytes."""

    content = bounded_bytes(path, MAX_RECORD_BYTES, description)
    try:
        value: Any = json.loads(
            content.decode("utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"unsupported JSON constant {constant}")
            ),
        )
        canonical = canonical_json(value) + b"\n"
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise BuildError(f"{description} is not valid canonical JSON") from exc
    if content != canonical or not isinstance(value, dict):
        raise BuildError(f"{description} is not canonical JSON")
    if any(not isinstance(key, str) for key in value):
        raise BuildError(f"{description} contains a non-string key")
    return value, content


def distribution_directory_files(
    directory: Path, *, selected: bool, architecture: str
) -> tuple[Path, Path, Path, Path | None]:
    """Require exactly the reviewed regular files in one proof directory."""

    root = Path(os.path.abspath(directory))
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise BuildError(f"cannot inspect Python distribution directory: {root}") from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise BuildError("Python distribution directory must be a non-symlink directory")
    if architecture not in ARCHITECTURE_MACHINES:
        raise BuildError("unsupported proof architecture")
    expected_count = 5 if selected else 3
    children: list[Path] = []
    try:
        with os.scandir(root) as iterator:
            for entry in iterator:
                children.append(Path(entry.path))
                if len(children) > expected_count:
                    raise BuildError(
                        f"Python distribution directory must contain exactly {expected_count} files"
                    )
    except OSError as exc:
        raise BuildError(f"cannot list Python distribution directory: {root}") from exc
    if len(children) != expected_count:
        raise BuildError(
            f"Python distribution directory must contain exactly {expected_count} files"
        )
    by_name: dict[str, Path] = {}
    for child in children:
        try:
            metadata = child.lstat()
        except OSError as exc:
            raise BuildError(f"cannot inspect Python distribution file: {child.name}") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise BuildError(
                f"Python distribution file must be a non-symlink regular file: {child.name}"
            )
        if child.name in by_name:
            raise BuildError(f"Python distribution directory repeats file: {child.name}")
        by_name[child.name] = child

    record_name = SELECTED_BUILD_RECORD_NAMES[architecture] if selected else BUILD_RECORD_NAME
    record_path = by_name.get(record_name)
    selection_path = by_name.get(SELECTION_RECORD_NAME)
    if (
        record_path is None
        or (selected and selection_path is None)
        or (not selected and selection_path is not None)
    ):
        raise BuildError("Python distribution directory lacks the required record files")
    record_names = (
        {*SELECTED_BUILD_RECORD_NAMES.values(), SELECTION_RECORD_NAME}
        if selected
        else {BUILD_RECORD_NAME}
    )
    if not record_names.issubset(by_name):
        raise BuildError("Python distribution directory lacks the required record files")
    archive_names = set(by_name).difference(record_names)
    wheel_names = [name for name in archive_names if WHEEL_FILENAME.fullmatch(name) is not None]
    sdist_names = [name for name in archive_names if name.endswith(".tar.gz")]
    if len(wheel_names) != 1 or len(sdist_names) != 1 or len(archive_names) != 2:
        raise BuildError("Python distribution directory must contain one wheel and one sdist")
    return (
        record_path,
        by_name[wheel_names[0]],
        by_name[sdist_names[0]],
        selection_path,
    )


def read_sdist_policy(path: Path, *, expected_name: str, expected_version: str) -> dict[str, bytes]:
    """Read reviewed build-policy files from a bounded, untrusted sdist."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BuildError(f"cannot inspect source distribution: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_ARCHIVE_BYTES:
        raise BuildError("source distribution must be a bounded non-symlink regular file")
    expected_filename = f"{expected_name.replace('-', '_')}-{expected_version}.tar.gz"
    if path.name != expected_filename:
        raise BuildError("source distribution filename has the wrong identity")
    expected_root = expected_filename.removesuffix(".tar.gz")
    policy: dict[str, bytes] = {}
    seen: set[str] = set()
    member_count = 0
    total_size = 0
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise BuildError("source distribution has too many members")
                name = checked_archive_name(member.name, directory=member.isdir())
                if name in seen:
                    raise BuildError(f"source distribution repeats member {name}")
                seen.add(name)
                parts = PurePosixPath(name).parts
                if not parts or parts[0] != expected_root:
                    raise BuildError("source distribution member escapes its versioned root")
                if member.isdir():
                    continue
                if not member.isreg():
                    raise BuildError(f"source distribution contains a special member: {name}")
                if not 0 <= member.size <= MAX_MEMBER_BYTES:
                    raise BuildError(f"source distribution member exceeds its size limit: {name}")
                total_size += member.size
                if total_size > MAX_EXPANDED_BYTES:
                    raise BuildError("source distribution exceeds its expansion limit")
                relative = name.removeprefix(f"{expected_root}/")
                if relative not in {"pyproject.toml", "requirements-build.txt"}:
                    continue
                if member.size > MAX_CONSTRAINT_BYTES:
                    raise BuildError(f"source distribution policy file is too large: {relative}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BuildError(f"cannot read source distribution policy: {relative}")
                content = extracted.read(MAX_CONSTRAINT_BYTES + 1)
                if len(content) != member.size:
                    raise BuildError(f"source distribution policy size disagrees: {relative}")
                policy[relative] = content
    except (OSError, tarfile.TarError) as exc:
        if isinstance(exc, BuildError):
            raise
        raise BuildError(f"cannot read source distribution policy: {exc}") from exc
    if set(policy) != {"pyproject.toml", "requirements-build.txt"}:
        raise BuildError("source distribution omits reviewed build-policy files")
    return policy


def validate_embedded_build_policy(
    policy: Mapping[str, bytes],
) -> tuple[dict[str, str], list[dict[str, object]]]:
    """Validate embedded policy with the same parser used by the build command."""

    with tempfile.TemporaryDirectory(prefix="extra-codeowners-selection-policy-") as raw:
        root = Path(raw)
        project_path = root / "pyproject.toml"
        constraints_path = root / "requirements-build.txt"
        try:
            project_path.write_bytes(policy["pyproject.toml"])
            constraints_path.write_bytes(policy["requirements-build.txt"])
            os.chmod(project_path, 0o600)
            os.chmod(constraints_path, 0o600)
        except (KeyError, OSError) as exc:
            raise BuildError("cannot stage embedded build policy") from exc
        requirements = parse_build_constraints(constraints_path)
        project = validate_project(project_path, requirements)
    return project, [requirement.record() for requirement in requirements]


def validate_toolchain_record(value: object, architecture: str) -> dict[str, Any]:
    """Validate one architecture-specific toolchain identity."""

    machine = ARCHITECTURE_MACHINES[architecture]
    record = require_exact_dict(
        value,
        {
            "uv",
            "uv_version",
            "python",
            "python_implementation",
            "python_major_minor",
            "python_machine",
        },
        f"{architecture} toolchain",
    )
    uv_version = require_string(record["uv_version"], f"{architecture} uv version")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", uv_version) is None:
        raise BuildError(f"{architecture} uv version is not exact")
    if record["uv"] != f"uv {uv_version} ({machine}-unknown-linux-gnu)":
        raise BuildError(f"{architecture} uv identity has the wrong target")
    python_version = require_string(record["python"], f"{architecture} Python version")
    match = re.fullmatch(r"(3)\.(12|13|14)\.([0-9]+)", python_version)
    if match is None:
        raise BuildError(f"{architecture} Python version is outside the reviewed matrix")
    major_minor = f"{match.group(1)}.{match.group(2)}"
    if (
        record["python_implementation"] != "CPython"
        or record["python_major_minor"] != major_minor
        or record["python_machine"] != machine
    ):
        raise BuildError(f"{architecture} Python identity has the wrong target")
    return record


def validate_build_record(
    value: object,
    *,
    architecture: str,
    expected_source_revision: str,
    wheel: ArtifactVerification,
    sdist: ArtifactVerification,
    project: Mapping[str, str],
    requirements: Sequence[Mapping[str, object]],
    policy: Mapping[str, bytes],
) -> dict[str, Any]:
    """Validate the complete canonical proof record against reverified artifacts."""

    record = require_exact_dict(
        value,
        {
            "schema_version",
            "source_revision",
            "source_dirty",
            "source_date_epoch",
            "source_tree",
            "project",
            "toolchain",
            "build_constraints",
            "artifacts",
            "reproducibility",
        },
        f"{architecture} build record",
    )
    if type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION:
        raise BuildError(f"{architecture} build record has the wrong schema version")
    if record["source_revision"] != expected_source_revision:
        raise BuildError(f"{architecture} build record has the wrong source revision")
    if record["source_dirty"] is not False:
        raise BuildError(f"{architecture} proof was not built from a clean worktree")
    require_integer(
        record["source_date_epoch"],
        f"{architecture} source date epoch",
        minimum=315532800,
        maximum=2**63 - 1,
    )
    source_tree = require_exact_dict(
        record["source_tree"],
        {"blob_count", "byte_count", "identity_sha256"},
        f"{architecture} source tree",
    )
    require_integer(
        source_tree["blob_count"],
        f"{architecture} source blob count",
        minimum=1,
        maximum=MAX_ARCHIVE_MEMBERS,
    )
    require_integer(
        source_tree["byte_count"],
        f"{architecture} source byte count",
        minimum=0,
        maximum=MAX_EXPANDED_BYTES,
    )
    require_sha256(source_tree["identity_sha256"], f"{architecture} source-tree identity")
    if record["project"] != dict(project):
        raise BuildError(f"{architecture} project record differs from embedded policy")
    validate_toolchain_record(record["toolchain"], architecture)
    constraints = require_exact_dict(
        record["build_constraints"],
        {"path", "sha256", "requirements"},
        f"{architecture} build constraints",
    )
    if (
        constraints["path"] != "requirements-build.txt"
        or constraints["sha256"] != sha256_bytes(policy["requirements-build.txt"])
        or constraints["requirements"] != list(requirements)
    ):
        raise BuildError(f"{architecture} build constraints differ from embedded policy")
    artifacts = require_exact_dict(
        record["artifacts"], {"sdist", "wheel"}, f"{architecture} artifact record"
    )
    if canonical_json(artifacts["wheel"]) != canonical_json(wheel.record) or canonical_json(
        artifacts["sdist"]
    ) != canonical_json(sdist.record):
        raise BuildError(f"{architecture} artifact record differs from the verified archives")
    reproducibility = require_exact_dict(
        record["reproducibility"],
        {"clean_build_count", "byte_identical", "semantic_identity_checked"},
        f"{architecture} reproducibility record",
    )
    if (
        type(reproducibility["clean_build_count"]) is not int
        or reproducibility["clean_build_count"] != 2
        or reproducibility["byte_identical"] is not True
        or reproducibility["semantic_identity_checked"] is not True
    ):
        raise BuildError(f"{architecture} reproducibility proof is incomplete")
    return record


def load_distribution_proof(
    directory: Path,
    *,
    architecture: str,
    expected_source_revision: str,
    selected: bool = False,
) -> DistributionProof:
    """Load and independently verify one architecture's three-file proof."""

    if architecture not in ARCHITECTURE_MACHINES:
        raise BuildError("unsupported proof architecture")
    if COMMIT.fullmatch(expected_source_revision) is None:
        raise BuildError("expected source revision must be a lowercase 40-character Git object ID")
    record_path, wheel_path, sdist_path, _selection_path = distribution_directory_files(
        directory, selected=selected, architecture=architecture
    )
    record, record_bytes = read_canonical_json_object(record_path, f"{architecture} build record")
    project_record = require_exact_dict(
        record.get("project"),
        {"name", "version", "build_backend", "build_requirement", "requires_python"},
        f"{architecture} project record",
    )
    project_name = require_string(project_record["name"], f"{architecture} project name")
    project_version = require_string(project_record["version"], f"{architecture} project version")
    policy = read_sdist_policy(
        sdist_path, expected_name=project_name, expected_version=project_version
    )
    project, requirements = validate_embedded_build_policy(policy)
    wheel = verify_wheel(
        wheel_path, expected_name=project["name"], expected_version=project["version"]
    )
    sdist = verify_sdist(
        sdist_path,
        expected_name=project["name"],
        expected_version=project["version"],
        expected_policy=policy,
    )
    validated = validate_build_record(
        record,
        architecture=architecture,
        expected_source_revision=expected_source_revision,
        wheel=wheel,
        sdist=sdist,
        project=project,
        requirements=requirements,
        policy=policy,
    )
    artifacts = require_exact_dict(
        validated["artifacts"], {"sdist", "wheel"}, f"{architecture} artifact record"
    )
    wheel_record = require_exact_dict(
        artifacts["wheel"], set(wheel.record), f"{architecture} wheel record"
    )
    sdist_record = require_exact_dict(
        artifacts["sdist"], set(sdist.record), f"{architecture} sdist record"
    )
    if wheel_record["filename"] != wheel_path.name or sdist_record["filename"] != sdist_path.name:
        raise BuildError(f"{architecture} archive filenames differ from the build record")
    return DistributionProof(
        architecture=architecture,
        directory=Path(os.path.abspath(directory)),
        record_path=record_path,
        record_bytes=record_bytes,
        record=validated,
        wheel_path=wheel_path,
        wheel=wheel,
        sdist_path=sdist_path,
        sdist=sdist,
    )


def comparable_build_record(proof: DistributionProof) -> dict[str, Any]:
    """Normalize only the two reviewed architecture-specific fields."""

    result = dict(proof.record)
    toolchain = dict(
        require_exact_dict(
            result["toolchain"],
            {
                "uv",
                "uv_version",
                "python",
                "python_implementation",
                "python_major_minor",
                "python_machine",
            },
            f"{proof.architecture} toolchain",
        )
    )
    toolchain["uv"] = "<architecture-specific uv target>"
    toolchain["python_machine"] = "<architecture-specific machine>"
    result["toolchain"] = toolchain
    return result


def regular_files_are_identical(first: Path, second: Path, description: str) -> None:
    """Require exact bytes without trusting record hashes alone."""

    try:
        first_metadata = first.lstat()
        second_metadata = second.lstat()
        if (
            not stat.S_ISREG(first_metadata.st_mode)
            or not stat.S_ISREG(second_metadata.st_mode)
            or first_metadata.st_size != second_metadata.st_size
        ):
            raise BuildError(f"{description} bytes differ across architecture proofs")
        with first.open("rb") as left, second.open("rb") as right:
            while True:
                left_block = left.read(1024 * 1024)
                right_block = right.read(1024 * 1024)
                if left_block != right_block:
                    raise BuildError(f"{description} bytes differ across architecture proofs")
                if not left_block:
                    break
    except OSError as exc:
        raise BuildError(f"cannot compare {description} architecture proofs") from exc


def artifact_binding(path: Path, verification: ArtifactVerification) -> dict[str, object]:
    return {
        "filename": path.name,
        "sha256": verification.record["sha256"],
        "size": verification.record["size"],
    }


def selection_record_for(amd64: DistributionProof, arm64: DistributionProof) -> dict[str, object]:
    """Return the canonical cross-architecture selection record."""

    return {
        "schema_version": SCHEMA_VERSION,
        "source_revision": amd64.record["source_revision"],
        "selected_architecture": "amd64",
        "proofs": {
            "amd64": {
                "record_filename": SELECTED_BUILD_RECORD_NAMES["amd64"],
                "record_sha256": sha256_bytes(amd64.record_bytes),
                "python_machine": ARCHITECTURE_MACHINES["amd64"],
            },
            "arm64": {
                "record_filename": SELECTED_BUILD_RECORD_NAMES["arm64"],
                "record_sha256": sha256_bytes(arm64.record_bytes),
                "python_machine": ARCHITECTURE_MACHINES["arm64"],
            },
        },
        "artifacts": {
            "wheel": artifact_binding(amd64.wheel_path, amd64.wheel),
            "sdist": artifact_binding(amd64.sdist_path, amd64.sdist),
        },
    }


def validate_selection_record(
    value: object,
    *,
    amd64: DistributionProof,
    arm64: DistributionProof,
    expected_source_revision: str,
    expected_wheel_sha256: str,
) -> dict[str, Any]:
    """Bind both retained architecture proofs to their original record digests."""

    record = require_exact_dict(
        value,
        {"schema_version", "source_revision", "selected_architecture", "proofs", "artifacts"},
        "Python selection record",
    )
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != SCHEMA_VERSION
        or record["source_revision"] != expected_source_revision
        or record["selected_architecture"] != "amd64"
    ):
        raise BuildError("Python selection record has the wrong identity")
    proofs = require_exact_dict(record["proofs"], {"amd64", "arm64"}, "selection proofs")
    retained_proofs = {"amd64": amd64, "arm64": arm64}
    proof_digests: dict[str, str] = {}
    for architecture, machine in ARCHITECTURE_MACHINES.items():
        architecture_record = require_exact_dict(
            proofs[architecture],
            {"record_filename", "record_sha256", "python_machine"},
            f"{architecture} selection proof",
        )
        if (
            architecture_record["record_filename"] != SELECTED_BUILD_RECORD_NAMES[architecture]
            or architecture_record["python_machine"] != machine
        ):
            raise BuildError(f"{architecture} selection proof has the wrong identity")
        proof_digests[architecture] = require_sha256(
            architecture_record["record_sha256"], f"{architecture} proof-record digest"
        )
        if proof_digests[architecture] != sha256_bytes(retained_proofs[architecture].record_bytes):
            raise BuildError(f"retained {architecture} build record differs from its proof digest")
    if proof_digests["amd64"] == proof_digests["arm64"]:
        raise BuildError("architecture proof records must have distinct digests")

    artifacts = require_exact_dict(record["artifacts"], {"wheel", "sdist"}, "selected artifacts")
    expected_artifacts = {
        "wheel": artifact_binding(amd64.wheel_path, amd64.wheel),
        "sdist": artifact_binding(amd64.sdist_path, amd64.sdist),
    }
    if canonical_json(artifacts) != canonical_json(expected_artifacts):
        raise BuildError("Python selection record differs from the selected artifacts")
    if amd64.wheel.record["sha256"] != expected_wheel_sha256:
        raise BuildError("selected wheel digest differs from the expected digest")
    return record


def selection_result(record_bytes: bytes, proof: DistributionProof) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source_revision": proof.record["source_revision"],
        "selection_record_sha256": sha256_bytes(record_bytes),
        "wheel_filename": proof.wheel_path.name,
        "wheel_sha256": proof.wheel.record["sha256"],
        "sdist_filename": proof.sdist_path.name,
        "sdist_sha256": proof.sdist.record["sha256"],
    }


def verify_selection(
    directory: Path, *, source_revision: str, wheel_sha256: str
) -> dict[str, object]:
    """Reverify a selected proof without consulting Git or a working tree."""

    if COMMIT.fullmatch(source_revision) is None:
        raise BuildError("expected source revision must be a lowercase 40-character Git object ID")
    if SHA256.fullmatch(wheel_sha256) is None:
        raise BuildError("expected wheel digest must be a lowercase SHA-256 digest")
    _record, _wheel, _sdist, selection_path = distribution_directory_files(
        directory, selected=True, architecture="amd64"
    )
    if selection_path is None:
        raise BuildError("selected distribution lacks its selection record")
    amd64 = load_distribution_proof(
        directory,
        architecture="amd64",
        expected_source_revision=source_revision,
        selected=True,
    )
    arm64 = load_distribution_proof(
        directory,
        architecture="arm64",
        expected_source_revision=source_revision,
        selected=True,
    )
    if comparable_build_record(amd64) != comparable_build_record(arm64):
        raise BuildError("retained architecture proofs differ outside reviewed toolchain fields")
    selection, selection_bytes = read_canonical_json_object(
        selection_path, "Python selection record"
    )
    validate_selection_record(
        selection,
        amd64=amd64,
        arm64=arm64,
        expected_source_revision=source_revision,
        expected_wheel_sha256=wheel_sha256,
    )
    return selection_result(selection_bytes, amd64)


def select_distributions(
    amd64_directory: Path,
    arm64_directory: Path,
    *,
    source_revision: str,
    output: Path,
) -> dict[str, object]:
    """Select byte-identical amd64 artifacts after native cross-architecture proof."""

    if COMMIT.fullmatch(source_revision) is None:
        raise BuildError("expected source revision must be a lowercase 40-character Git object ID")
    amd64 = load_distribution_proof(
        amd64_directory,
        architecture="amd64",
        expected_source_revision=source_revision,
    )
    arm64 = load_distribution_proof(
        arm64_directory,
        architecture="arm64",
        expected_source_revision=source_revision,
    )
    if comparable_build_record(amd64) != comparable_build_record(arm64):
        raise BuildError("architecture proof records differ outside reviewed toolchain fields")
    regular_files_are_identical(amd64.wheel_path, arm64.wheel_path, "wheel")
    regular_files_are_identical(amd64.sdist_path, arm64.sdist_path, "source distribution")
    selection = selection_record_for(amd64, arm64)
    expected_wheel_sha256 = require_sha256(amd64.wheel.record["sha256"], "selected wheel digest")

    destination = Path(os.path.abspath(output))
    if os.path.lexists(destination):
        raise BuildError("selection output directory must be absent")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.select-", dir=destination.parent)
        )
    except OSError as exc:
        raise BuildError(f"cannot stage selected Python distributions: {exc}") from exc
    try:
        retained_records = {
            amd64.record_path: SELECTED_BUILD_RECORD_NAMES["amd64"],
            arm64.record_path: SELECTED_BUILD_RECORD_NAMES["arm64"],
        }
        for source, retained_name in retained_records.items():
            retained = staging / retained_name
            shutil.copyfile(source, retained)
            os.chmod(retained, 0o600)
        for source in (amd64.wheel_path, amd64.sdist_path):
            retained = staging / source.name
            shutil.copyfile(source, retained)
            os.chmod(retained, 0o600)
        write_record(staging / SELECTION_RECORD_NAME, selection)
        result = verify_selection(
            staging,
            source_revision=source_revision,
            wheel_sha256=expected_wheel_sha256,
        )
        if os.path.lexists(destination):
            raise BuildError("selection output directory appeared during publication")
        os.replace(staging, destination)
    except BaseException as exc:
        shutil.rmtree(staging, ignore_errors=True)
        if isinstance(exc, BuildError):
            raise
        if isinstance(exc, OSError):
            raise BuildError(f"cannot publish selected Python distributions: {exc}") from exc
        raise
    return result


def build_artifacts(args: argparse.Namespace) -> dict[str, object]:
    """Execute two clean builds and retain only identical verified artifacts."""

    repo = Path(args.repository).resolve()
    if not repo.is_dir():
        raise BuildError("source repository is not a directory")
    constraints_relative = checked_archive_name(args.constraints)
    if any(part.casefold() == ".git" for part in PurePosixPath(constraints_relative).parts):
        raise BuildError("build constraints path contains reserved repository metadata")
    source_date_epoch = args.source_date_epoch
    if not isinstance(source_date_epoch, int) or not 315532800 <= source_date_epoch <= 2**63 - 1:
        raise BuildError("source-date-epoch must be a valid timestamp no earlier than 1980")
    source_revision = git_value(repo, ["rev-parse", "HEAD"])
    if COMMIT.fullmatch(source_revision) is None:
        raise BuildError("source revision must be a lowercase 40-character Git object ID")
    try:
        repository_root = Path(git_value(repo, ["rev-parse", "--show-toplevel"])).resolve()
    except OSError as exc:
        raise BuildError("cannot resolve the Git repository root") from exc
    if repository_root != repo:
        raise BuildError("source repository must be the Git worktree root")
    if args.source_revision is not None and args.source_revision != source_revision:
        raise BuildError("requested source revision does not match Git HEAD")
    try:
        commit_epoch = int(git_value(repo, ["show", "-s", "--format=%ct", source_revision]))
    except ValueError as exc:
        raise BuildError("Git commit timestamp is invalid") from exc
    if source_date_epoch != commit_epoch:
        raise BuildError("source-date-epoch must equal the Git HEAD commit timestamp")
    source_status = git_value(repo, ["status", "--porcelain", "--untracked-files=all"])
    source_dirty = bool(source_status)
    if not args.allow_dirty and source_dirty:
        raise BuildError("refusing to build from a dirty Git worktree")
    source_entries = git_source_entries(repo, source_revision)
    tree_record = source_tree_record(source_entries)

    uv = Path(args.uv).resolve() if os.sep in args.uv else Path(shutil.which(args.uv) or "")
    python = Path(args.python).resolve()
    if (
        not uv.is_file()
        or not python.is_file()
        or not os.access(uv, os.X_OK)
        or not os.access(python, os.X_OK)
    ):
        raise BuildError("uv and Python must resolve to regular executable files")
    output = Path(os.path.abspath(args.output))
    if os.path.lexists(output):
        raise BuildError("artifact output directory must be absent")

    scratch_parent = Path(args.scratch_directory).resolve() if args.scratch_directory else None
    if scratch_parent is not None:
        try:
            scratch_parent.relative_to(repo)
        except ValueError:
            pass
        else:
            raise BuildError("scratch directory must be outside the source repository")
        scratch_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="extra-codeowners-python-build-", dir=scratch_parent
    ) as raw:
        scratch = Path(raw)
        first_scratch = scratch / "first"
        second_scratch = scratch / "second"
        first_scratch.mkdir()
        second_scratch.mkdir()
        first_source = first_scratch / "source"
        second_source = second_scratch / "source"
        materialize_git_source(repo, first_source, source_entries)
        materialize_git_source(repo, second_source, source_entries)
        first_constraints = repository_file(first_source, constraints_relative, "build constraints")
        second_constraints = repository_file(
            second_source, constraints_relative, "build constraints"
        )
        project_path = repository_file(first_source, "pyproject.toml", "pyproject.toml")
        second_project = repository_file(second_source, "pyproject.toml", "pyproject.toml")
        repository_file(first_source, "mise.toml", "mise.toml")
        repository_file(second_source, "mise.toml", "mise.toml")
        requirements = parse_build_constraints(first_constraints)
        project = validate_project(project_path, requirements)
        expected_sdist_policy = {
            "pyproject.toml": bounded_bytes(
                project_path, MAX_CONSTRAINT_BYTES, "reviewed pyproject.toml"
            ),
            "requirements-build.txt": bounded_bytes(
                first_constraints, MAX_CONSTRAINT_BYTES, "reviewed build constraints"
            ),
        }
        if (
            bounded_bytes(second_project, MAX_CONSTRAINT_BYTES, "second pyproject.toml")
            != expected_sdist_policy["pyproject.toml"]
            or bounded_bytes(second_constraints, MAX_CONSTRAINT_BYTES, "second build constraints")
            != expected_sdist_policy["requirements-build.txt"]
        ):
            raise BuildError("independently materialized Git source trees disagree")
        first_environment = minimal_build_environment(first_scratch, source_date_epoch)
        second_environment = minimal_build_environment(second_scratch, source_date_epoch)
        toolchain = toolchain_identity(uv, python, first_source, first_environment)
        first_sdist, first_wheel = build_once(
            uv=uv,
            python=python,
            repo=first_source,
            constraints=first_constraints,
            output=first_scratch / "artifacts",
            environment=first_environment,
        )
        second_sdist, second_wheel = build_once(
            uv=uv,
            python=python,
            repo=second_source,
            constraints=second_constraints,
            output=second_scratch / "artifacts",
            environment=second_environment,
        )
        verify_materialized_git_source(repo, first_source, source_entries)
        verify_materialized_git_source(repo, second_source, source_entries)
        sdist = require_reproducible(
            first_sdist,
            second_sdist,
            lambda candidate: verify_sdist(
                candidate,
                expected_name=project["name"],
                expected_version=project["version"],
                expected_policy=expected_sdist_policy,
            ),
            "source distribution",
        )
        wheel = require_reproducible(
            first_wheel,
            second_wheel,
            lambda candidate: verify_wheel(
                candidate,
                expected_name=project["name"],
                expected_version=project["version"],
            ),
            "wheel",
        )
        hatchling_version = next(
            requirement.version for requirement in requirements if requirement.name == "hatchling"
        )
        if wheel.record.get("generator") != f"hatchling {hatchling_version}":
            raise BuildError("wheel generator does not match the constrained Hatchling version")
        if (
            git_value(repo, ["rev-parse", "HEAD"]) != source_revision
            or git_value(repo, ["status", "--porcelain", "--untracked-files=all"]) != source_status
            or git_source_entries(repo, source_revision) != source_entries
        ):
            raise BuildError("source repository changed during the reproducibility build")
        record: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "source_revision": source_revision,
            "source_dirty": source_dirty,
            "source_date_epoch": source_date_epoch,
            "source_tree": tree_record,
            "project": project,
            "toolchain": toolchain,
            "build_constraints": {
                "path": constraints_relative,
                "sha256": sha256_bytes(expected_sdist_policy["requirements-build.txt"]),
                "requirements": [requirement.record() for requirement in requirements],
            },
            "artifacts": {"sdist": sdist.record, "wheel": wheel.record},
            "reproducibility": {
                "clean_build_count": 2,
                "byte_identical": True,
                "semantic_identity_checked": True,
            },
        }

        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            if os.path.lexists(output):
                raise BuildError("artifact output directory appeared during the build")
            staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.publish-", dir=output.parent))
        except OSError as exc:
            raise BuildError(f"cannot stage verified artifacts: {exc}") from exc
        try:
            retained_sdist = staging / first_sdist.name
            retained_wheel = staging / first_wheel.name
            shutil.copyfile(first_sdist, retained_sdist)
            shutil.copyfile(first_wheel, retained_wheel)
            os.chmod(retained_sdist, 0o600)
            os.chmod(retained_wheel, 0o600)
            if (
                sha256_file(retained_sdist) != sdist.record["sha256"]
                or sha256_file(retained_wheel) != wheel.record["sha256"]
            ):
                raise BuildError("retained artifact changed during publication")
            write_record(staging / "python-build-record.json", record)
            os.replace(staging, output)
        except BaseException as exc:
            shutil.rmtree(staging, ignore_errors=True)
            if isinstance(exc, BuildError):
                raise
            if isinstance(exc, OSError):
                raise BuildError(f"cannot publish verified artifacts: {exc}") from exc
            raise
    return record


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="build two identical verified distributions")
    build.add_argument("--repository", default=".")
    build.add_argument("--constraints", default="requirements-build.txt")
    build.add_argument("--output", required=True)
    build.add_argument("--scratch-directory")
    build.add_argument("--source-date-epoch", required=True, type=int)
    build.add_argument("--source-revision")
    build.add_argument("--python", required=True)
    build.add_argument("--uv", default="uv")
    build.add_argument("--allow-dirty", action="store_true")

    wheel = commands.add_parser("verify-wheel", help="verify one wheel without extracting it")
    wheel.add_argument("--wheel", required=True)
    wheel.add_argument("--project-name", required=True)
    wheel.add_argument("--project-version", required=True)

    sdist = commands.add_parser("verify-sdist", help="verify one source distribution")
    sdist.add_argument("--sdist", required=True)
    sdist.add_argument("--repository", default=".")
    sdist.add_argument("--constraints", default="requirements-build.txt")
    sdist.add_argument("--project-name", required=True)
    sdist.add_argument("--project-version", required=True)

    installed = commands.add_parser("verify-installed", help="verify an installed RECORD")
    installed.add_argument("--record", required=True)
    installed.add_argument("--environment-root", required=True)
    installed.add_argument("--wheel", required=True)
    installed.add_argument("--project-name", required=True)
    installed.add_argument("--project-version", required=True)

    select = commands.add_parser("select", help="select byte-identical native architecture proofs")
    select.add_argument("--amd64-directory", required=True)
    select.add_argument("--arm64-directory", required=True)
    select.add_argument("--source-revision", required=True)
    select.add_argument("--output", required=True)

    verify_selected = commands.add_parser(
        "verify-selection", help="reverify a selected distribution without Git"
    )
    verify_selected.add_argument("--directory", required=True)
    verify_selected.add_argument("--source-revision", required=True)
    verify_selected.add_argument("--wheel-sha256", required=True)
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        if args.command == "build":
            value: object = build_artifacts(args)
        elif args.command == "verify-wheel":
            value = verify_wheel(
                Path(args.wheel),
                expected_name=args.project_name,
                expected_version=args.project_version,
            ).record
        elif args.command == "verify-sdist":
            repo = Path(args.repository).resolve()
            constraints_path = repository_file(repo, args.constraints, "build constraints")
            project_path = repository_file(repo, "pyproject.toml", "pyproject.toml")
            requirements = parse_build_constraints(constraints_path)
            project = validate_project(project_path, requirements)
            if (
                canonical_name(args.project_name) != project["name"]
                or args.project_version != project["version"]
            ):
                raise BuildError("requested source identity differs from pyproject.toml")
            value = verify_sdist(
                Path(args.sdist),
                expected_name=args.project_name,
                expected_version=args.project_version,
                expected_policy={
                    "pyproject.toml": bounded_bytes(
                        project_path, MAX_CONSTRAINT_BYTES, "reviewed pyproject.toml"
                    ),
                    "requirements-build.txt": bounded_bytes(
                        constraints_path, MAX_CONSTRAINT_BYTES, "reviewed build constraints"
                    ),
                },
            ).record
        elif args.command == "verify-installed":
            wheel = verify_wheel(
                Path(args.wheel),
                expected_name=args.project_name,
                expected_version=args.project_version,
            )
            value = verify_installed_record(Path(args.record), Path(args.environment_root), wheel)
        elif args.command == "select":
            value = select_distributions(
                Path(args.amd64_directory),
                Path(args.arm64_directory),
                source_revision=args.source_revision,
                output=Path(args.output),
            )
        else:
            value = verify_selection(
                Path(args.directory),
                source_revision=args.source_revision,
                wheel_sha256=args.wheel_sha256,
            )
    except BuildError as exc:
        sys.stderr.write(f"Python build error: {exc}\n")
        return 1
    sys.stdout.buffer.write(canonical_json(value) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
