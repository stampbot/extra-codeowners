#!/usr/bin/env python3
"""Build and verify the reproducible native dependency wheelhouse."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

SCHEMA_VERSION = 1
INPUT_KIND = "extra-codeowners/native-wheelhouse-inputs"
MANIFEST_KIND = "extra-codeowners/native-wheelhouse"
CARGO_INVENTORY_KIND = "extra-codeowners/native-wheelhouse-cargo-inputs"
CARGO_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
SETUPTOOLS_RELEASE_CONFIG = b"[egg_info]\ntag_build = \ntag_date = 0\n"

MAX_INPUT_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_MEMBERS = 100_000
MAX_SOURCE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_SOURCE_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_EXTENSION_BYTES = 1024 * 1024
MAX_EXTENSION_TOTAL_BYTES = 8 * 1024 * 1024
MAX_WHEEL_BYTES = 128 * 1024 * 1024
MAX_WHEEL_MEMBERS = 20_000
MAX_WHEEL_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_PROCESS_SECONDS = 45 * 60
COPY_BYTES = 1024 * 1024

LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
LOWER_COMMIT = re.compile(r"[0-9a-f]{40}")
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,63}")
PACKAGE_PIN = re.compile(r"(\.?[a-z0-9][a-z0-9+_.-]*)=([A-Za-z0-9][A-Za-z0-9+_.-]*)")
APK_NAME = re.compile(r"\.?[a-z0-9][a-z0-9+_.-]*")
APK_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]*")
WHEEL_COMPONENT = re.compile(r"[A-Za-z0-9_.]+")
LIBRARY_NAME = re.compile(r"[A-Za-z0-9+_.-]+")
NEEDED_LIBRARY = re.compile(r"Shared library: \[([A-Za-z0-9+_.-]+)\]")
URLSAFE_SHA256 = re.compile(r"sha256=([A-Za-z0-9_-]{43})")
CARGO_CACHE = re.compile(r"index\.crates\.io-[0-9a-f]{16}")

PLATFORM_BY_MACHINE = {
    "aarch64": ("linux/arm64", "linux_aarch64", "AArch64", "libc.musl-aarch64.so.1"),
    "x86_64": (
        "linux/amd64",
        "linux_x86_64",
        "Advanced Micro Devices X86-64",
        "libc.musl-x86_64.so.1",
    ),
}


class WheelhouseError(RuntimeError):
    """The wheelhouse input, build, or output violates its fixed contract."""


@dataclass(frozen=True)
class SourceRemoval:
    """One checksum-bound file removed by a reviewed release transformation."""

    member: str
    sha256: str


@dataclass(frozen=True)
class ReleasePatch:
    """One reviewed release-archive transformation."""

    member: str
    original_sha256: str
    removed_members: tuple[SourceRemoval, ...]
    replacement_sha256: str


@dataclass(frozen=True)
class Source:
    """One checksum-bound source archive."""

    identifier: str
    filename: str
    root: str
    url: str
    sha256: str
    size: int
    upstream: Mapping[str, object]
    release_patch: ReleasePatch | None


@dataclass(frozen=True)
class ExpectedWheel:
    """The identity and native linkage expected from one built wheel."""

    distribution: str
    version: str
    native_payloads: int
    needed_libraries: tuple[str, ...]


@dataclass(frozen=True)
class Inputs:
    """Validated native wheelhouse inputs."""

    raw: bytes
    raw_sha256: str
    raw_size: int
    base_image: Mapping[str, str]
    builder_packages: tuple[str, ...]
    builder_platform_packages: Mapping[str, tuple[str, ...]]
    cargo_source: str
    cargo_registry_packages: int
    expected_wheels: tuple[ExpectedWheel, ...]
    python: Mapping[str, str]
    source_date_epoch: int
    sources: tuple[Source, ...]


class _BoundedTarInfo(tarfile.TarInfo):
    """Bound PAX and GNU extension records before tarfile allocates them."""

    def _charge_extension(self, archive: tarfile.TarFile) -> None:
        if self.size < 0 or self.size > MAX_EXTENSION_BYTES:
            raise WheelhouseError("source archive extension header exceeds its size limit")
        attribute = "_extra_codeowners_wheelhouse_extension_bytes"
        total = int(getattr(archive, attribute, 0)) + self.size
        if total > MAX_EXTENSION_TOTAL_BYTES:
            raise WheelhouseError("source archive extension headers exceed their aggregate limit")
        setattr(archive, attribute, total)

    def _proc_pax(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        self._charge_extension(archive)
        try:
            result: tarfile.TarInfo | None = super()._proc_pax(archive)  # type: ignore[misc]
        except tarfile.HeaderError as exc:
            raise WheelhouseError("source archive has a malformed PAX header") from exc
        return result

    def _proc_gnulong(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        self._charge_extension(archive)
        try:
            result: tarfile.TarInfo | None = super()._proc_gnulong(archive)  # type: ignore[misc]
        except tarfile.HeaderError as exc:
            raise WheelhouseError("source archive has a malformed GNU long-name header") from exc
        return result


def canonical_json(value: object) -> bytes:
    """Return the one human-readable canonical JSON encoding."""

    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise WheelhouseError("value cannot be encoded as canonical JSON") from exc
    return encoded.encode("ascii") + b"\n"


def _reject_constant(value: str) -> NoReturn:
    raise WheelhouseError(f"JSON contains a non-finite number: {value}")


def _reject_float(_value: str) -> NoReturn:
    raise WheelhouseError("JSON contains a floating-point number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise WheelhouseError(f"JSON repeats an object key: {key!r}")
        value[key] = item
    return value


def _load_json(path: Path, source: str, *, maximum: int = MAX_INPUT_BYTES) -> tuple[Any, bytes]:
    try:
        metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= maximum
        ):
            raise WheelhouseError(f"{source} is not one bounded single-link regular file")
        raw = path.read_bytes()
    except OSError as exc:
        raise WheelhouseError(f"cannot read {source}") from exc
    if len(raw) != metadata.st_size:
        raise WheelhouseError(f"{source} changed while it was read")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise WheelhouseError(f"{source} is not strict JSON") from exc
    return value, raw


def _mapping(value: object, source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise WheelhouseError(f"{source} must be an object")
    return cast(Mapping[str, Any], value)


def _exact_fields(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    record = _mapping(value, source)
    if set(record) != fields:
        raise WheelhouseError(f"{source} has unexpected fields")
    return record


def _text(value: object, source: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise WheelhouseError(f"{source} is not bounded text")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise WheelhouseError(f"{source} has an invalid value")
    return value


def _integer(value: object, source: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise WheelhouseError(f"{source} is outside its integer bound")
    return value


def _package_pins(value: object, source: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise WheelhouseError(f"{source} must be a non-empty array")
    packages = tuple(
        _text(item, f"{source} item {index}", pattern=PACKAGE_PIN)
        for index, item in enumerate(value)
    )
    identities = [item.partition("=")[::2] for item in packages]
    names = [item[0] for item in identities]
    if identities != sorted(identities) or len(names) != len(set(names)):
        raise WheelhouseError(f"{source} must be sorted with unique package names")
    return packages


def _https_url(value: object, source: str) -> str:
    text = _text(value, source)
    if (
        not text.startswith("https://")
        or "@" in text.split("/", 3)[2]
        or "#" in text
        or len(text) > 16 * 1024
    ):
        raise WheelhouseError(f"{source} is not an HTTPS artifact URL")
    host = text.split("/", 3)[2].lower()
    if host not in {"github.com", "files.pythonhosted.org"}:
        raise WheelhouseError(f"{source} uses an unapproved host")
    return text


def load_inputs(path: Path) -> Inputs:
    """Load and strictly validate the reviewed wheelhouse inputs."""

    value, raw = _load_json(path, "native wheelhouse inputs")
    record = _exact_fields(
        value,
        {
            "base_image",
            "builder_packages",
            "builder_platform_packages",
            "cargo",
            "expected_wheels",
            "kind",
            "python",
            "schema_version",
            "source_date_epoch",
            "sources",
        },
        "native wheelhouse inputs",
    )
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != SCHEMA_VERSION
        or record["kind"] != INPUT_KIND
    ):
        raise WheelhouseError("native wheelhouse inputs use an unsupported contract")

    base = _exact_fields(record["base_image"], {"digest", "reference"}, "base image")
    base_reference = _text(base["reference"], "base image reference")
    base_digest = _text(base["digest"], "base image digest")
    if (
        not base_digest.startswith("sha256:")
        or LOWER_SHA256.fullmatch(base_digest.removeprefix("sha256:")) is None
    ):
        raise WheelhouseError("base image digest is invalid")

    python = _exact_fields(
        record["python"],
        {"abi", "implementation", "version"},
        "Python build identity",
    )
    python_record = {
        "abi": _text(python["abi"], "Python ABI"),
        "implementation": _text(python["implementation"], "Python implementation"),
        "version": _text(python["version"], "Python version"),
    }
    if python_record != {
        "abi": "cp314",
        "implementation": "cpython",
        "version": "3.14.6",
    }:
        raise WheelhouseError("Python build identity is not the reviewed CPython version")

    packages = _package_pins(record["builder_packages"], "builder packages")
    raw_platform_packages = _exact_fields(
        record["builder_platform_packages"],
        {"linux/amd64", "linux/arm64"},
        "platform builder packages",
    )
    platform_packages = {
        platform_name: _package_pins(
            raw_platform_packages[platform_name],
            f"{platform_name} builder packages",
        )
        for platform_name in ("linux/amd64", "linux/arm64")
    }
    for platform_name in platform_packages:
        combined = tuple(
            sorted(
                (*packages, *platform_packages[platform_name]),
                key=lambda item: item.partition("=")[::2],
            )
        )
        names = [item.partition("=")[0] for item in combined]
        if len(names) != len(set(names)):
            raise WheelhouseError(f"{platform_name} builder package closure repeats a package name")

    cargo = _exact_fields(record["cargo"], {"registry_packages", "source"}, "Cargo inputs")
    cargo_source = _text(cargo["source"], "Cargo registry source")
    cargo_count = _integer(
        cargo["registry_packages"],
        "Cargo registry package count",
        minimum=1,
        maximum=512,
    )
    if cargo_source != CARGO_REGISTRY:
        raise WheelhouseError("Cargo registry source is not the reviewed crates.io registry")

    raw_wheels = record["expected_wheels"]
    if not isinstance(raw_wheels, list) or not raw_wheels:
        raise WheelhouseError("expected wheels must be a non-empty array")
    wheels: list[ExpectedWheel] = []
    for index, raw_wheel in enumerate(raw_wheels):
        wheel = _exact_fields(
            raw_wheel,
            {"distribution", "native_payloads", "needed_libraries", "version"},
            f"expected wheel {index}",
        )
        libraries = wheel["needed_libraries"]
        if not isinstance(libraries, list):
            raise WheelhouseError(f"expected wheel {index} libraries must be an array")
        checked_libraries = tuple(
            _text(item, f"expected wheel {index} library", pattern=LIBRARY_NAME)
            for item in libraries
        )
        if tuple(sorted(checked_libraries)) != checked_libraries or len(
            set(checked_libraries)
        ) != len(checked_libraries):
            raise WheelhouseError(f"expected wheel {index} libraries are not canonical")
        wheels.append(
            ExpectedWheel(
                distribution=_text(
                    wheel["distribution"],
                    f"expected wheel {index} distribution",
                    pattern=IDENTIFIER,
                ),
                version=_text(wheel["version"], f"expected wheel {index} version"),
                native_payloads=_integer(
                    wheel["native_payloads"],
                    f"expected wheel {index} native payload count",
                    minimum=0,
                    maximum=16,
                ),
                needed_libraries=checked_libraries,
            )
        )
    wheel_keys = [item.distribution for item in wheels]
    if wheel_keys != sorted(wheel_keys) or len(set(wheel_keys)) != len(wheel_keys):
        raise WheelhouseError("expected wheels must be sorted and unique")

    raw_sources = record["sources"]
    if not isinstance(raw_sources, list) or not raw_sources:
        raise WheelhouseError("wheelhouse sources must be a non-empty array")
    sources: list[Source] = []
    for index, raw_source in enumerate(raw_sources):
        source_record = _mapping(raw_source, f"wheelhouse source {index}")
        required = {"filename", "id", "root", "sha256", "size", "upstream", "url"}
        optional = {"release_patch"}
        if not required.issubset(source_record) or not set(source_record).issubset(
            required | optional
        ):
            raise WheelhouseError(f"wheelhouse source {index} has unexpected fields")
        identifier = _text(
            source_record["id"],
            f"wheelhouse source {index} id",
            pattern=IDENTIFIER,
        )
        filename = _text(source_record["filename"], f"wheelhouse source {identifier} filename")
        if (
            PurePosixPath(filename).name != filename
            or not filename.endswith(".tar.gz")
            or "\\" in filename
        ):
            raise WheelhouseError(f"wheelhouse source {identifier} filename is invalid")
        root = _safe_member_name(
            _text(source_record["root"], f"wheelhouse source {identifier} root")
        )
        if len(root.parts) != 1:
            raise WheelhouseError(f"wheelhouse source {identifier} root is not one directory")
        upstream = _exact_fields(
            source_record["upstream"],
            {"commit", "repository", "signature_review", "tag", "tag_object"},
            f"wheelhouse source {identifier} upstream",
        )
        commit = _text(
            upstream["commit"],
            f"wheelhouse source {identifier} commit",
            pattern=LOWER_COMMIT,
        )
        tag_object = upstream["tag_object"]
        if tag_object is not None:
            _text(
                tag_object,
                f"wheelhouse source {identifier} tag object",
                pattern=LOWER_COMMIT,
            )
        checked_upstream: Mapping[str, object] = {
            "commit": commit,
            "repository": _https_url(
                upstream["repository"],
                f"wheelhouse source {identifier} repository",
            ),
            "signature_review": _text(
                upstream["signature_review"],
                f"wheelhouse source {identifier} signature review",
            ),
            "tag": _text(upstream["tag"], f"wheelhouse source {identifier} tag"),
            "tag_object": tag_object,
        }
        release_patch = None
        if "release_patch" in source_record:
            patch = _exact_fields(
                source_record["release_patch"],
                {
                    "member",
                    "original_sha256",
                    "removed_members",
                    "replacement_sha256",
                },
                f"wheelhouse source {identifier} release patch",
            )
            raw_removals = patch["removed_members"]
            if not isinstance(raw_removals, list) or not 1 <= len(raw_removals) <= 16:
                raise WheelhouseError(f"wheelhouse source {identifier} removed members are invalid")
            removals: list[SourceRemoval] = []
            for removal_index, raw_removal in enumerate(raw_removals):
                removal = _exact_fields(
                    raw_removal,
                    {"member", "sha256"},
                    (f"wheelhouse source {identifier} removed member {removal_index}"),
                )
                removal_member = _safe_member_name(
                    _text(
                        removal["member"],
                        (f"wheelhouse source {identifier} removed member {removal_index} path"),
                    )
                ).as_posix()
                removals.append(
                    SourceRemoval(
                        member=removal_member,
                        sha256=_text(
                            removal["sha256"],
                            (
                                f"wheelhouse source {identifier} removed member "
                                f"{removal_index} digest"
                            ),
                            pattern=LOWER_SHA256,
                        ),
                    )
                )
            removal_names = [item.member for item in removals]
            if removal_names != sorted(removal_names) or len(
                {item.casefold() for item in removal_names}
            ) != len(removal_names):
                raise WheelhouseError(
                    f"wheelhouse source {identifier} removed members are not canonical"
                )
            release_patch = ReleasePatch(
                member=_text(
                    patch["member"],
                    f"wheelhouse source {identifier} release patch member",
                ),
                original_sha256=_text(
                    patch["original_sha256"],
                    f"wheelhouse source {identifier} release patch original digest",
                    pattern=LOWER_SHA256,
                ),
                removed_members=tuple(removals),
                replacement_sha256=_text(
                    patch["replacement_sha256"],
                    f"wheelhouse source {identifier} release patch replacement digest",
                    pattern=LOWER_SHA256,
                ),
            )
        sources.append(
            Source(
                identifier=identifier,
                filename=filename,
                root=root.as_posix(),
                url=_https_url(source_record["url"], f"wheelhouse source {identifier} URL"),
                sha256=_text(
                    source_record["sha256"],
                    f"wheelhouse source {identifier} digest",
                    pattern=LOWER_SHA256,
                ),
                size=_integer(
                    source_record["size"],
                    f"wheelhouse source {identifier} size",
                    minimum=1,
                    maximum=MAX_SOURCE_BYTES,
                ),
                upstream=checked_upstream,
                release_patch=release_patch,
            )
        )
    source_ids = [item.identifier for item in sources]
    source_names = [item.filename for item in sources]
    if (
        source_ids != sorted(source_ids)
        or len(set(source_ids)) != len(source_ids)
        or len(set(source_names)) != len(source_names)
    ):
        raise WheelhouseError("wheelhouse sources must be sorted with unique IDs and filenames")
    if set(source_ids) != {"cffi", "psycopg", "pydantic-core", "setuptools"}:
        raise WheelhouseError("wheelhouse source inventory is incomplete")
    if next(item for item in sources if item.identifier == "setuptools").release_patch is None:
        raise WheelhouseError("setuptools source is missing its reviewed release patch")
    if any(item.release_patch is not None for item in sources if item.identifier != "setuptools"):
        raise WheelhouseError("only setuptools may carry the reviewed release patch")

    epoch = _integer(
        record["source_date_epoch"],
        "source date epoch",
        minimum=315532800,
        maximum=4_102_444_800,
    )
    return Inputs(
        raw=raw,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_size=len(raw),
        base_image={"digest": base_digest, "reference": base_reference},
        builder_packages=packages,
        builder_platform_packages=platform_packages,
        cargo_source=cargo_source,
        cargo_registry_packages=cargo_count,
        expected_wheels=tuple(wheels),
        python=python_record,
        source_date_epoch=epoch,
        sources=tuple(sources),
    )


def _safe_member_name(value: str) -> PurePosixPath:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or len(value.encode("utf-8")) > MAX_PATH_BYTES
    ):
        raise WheelhouseError("archive member path is invalid")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise WheelhouseError("archive member path is not canonical")
    return path


def _sha256_file(path: Path, *, maximum: int) -> tuple[str, int]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow or not cloexec:
        raise WheelhouseError("secure descriptor flags are unavailable")
    descriptor = -1
    try:
        metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= maximum
        ):
            raise WheelhouseError(f"{path.name} is not one bounded single-link regular file")
        descriptor = os.open(path, os.O_RDONLY | nofollow | cloexec)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise WheelhouseError(f"{path.name} changed before it was opened")
        digest = hashlib.sha256()
        received = 0
        while received <= maximum:
            chunk = os.read(descriptor, min(COPY_BYTES, maximum + 1 - received))
            if not chunk:
                break
            digest.update(chunk)
            received += len(chunk)
        if received != metadata.st_size:
            raise WheelhouseError(f"{path.name} changed while it was read")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise WheelhouseError(f"{path.name} changed while it was hashed")
        return digest.hexdigest(), received
    except OSError as exc:
        raise WheelhouseError(f"cannot hash {path.name}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_sources(inputs: Inputs, directory: Path) -> dict[str, Path]:
    """Verify every configured source artifact and reject extras."""

    expected_names = {item.filename for item in inputs.sources}
    try:
        observed_names = {item.name for item in directory.iterdir()}
    except OSError as exc:
        raise WheelhouseError("cannot inventory wheelhouse source directory") from exc
    if observed_names != expected_names:
        raise WheelhouseError("wheelhouse source directory has an unexpected inventory")
    result: dict[str, Path] = {}
    for source in inputs.sources:
        path = directory / source.filename
        digest, size = _sha256_file(path, maximum=MAX_SOURCE_BYTES)
        if digest != source.sha256 or size != source.size:
            raise WheelhouseError(f"wheelhouse source {source.identifier} differs from its binding")
        result[source.identifier] = path
    return result


def _safe_destination(root: Path, relative: PurePosixPath) -> Path:
    destination = root.joinpath(*relative.parts)
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise WheelhouseError("archive extraction escaped its destination") from exc
    return destination


def _extract_source(archive_path: Path, destination: Path, expected_root: str) -> Path:
    """Extract one verified source archive without following archive links."""

    if destination.exists():
        raise WheelhouseError("source extraction destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    seen: dict[str, str] = {}
    symlinks: list[tuple[PurePosixPath, str]] = []
    directories: set[PurePosixPath] = set()
    expanded = 0
    member_count = 0
    try:
        with tarfile.open(
            archive_path,
            mode="r:gz",
            tarinfo=_BoundedTarInfo,
        ) as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_SOURCE_MEMBERS:
                    raise WheelhouseError("source archive has too many members")
                path = _safe_member_name(member.name.rstrip("/"))
                if path.parts[0] != expected_root:
                    raise WheelhouseError("source archive has an unexpected top-level directory")
                folded = path.as_posix().casefold()
                if folded in seen:
                    raise WheelhouseError("source archive repeats a member path")
                seen[folded] = path.as_posix()
                for depth in range(1, len(path.parts)):
                    directories.add(PurePosixPath(*path.parts[:depth]))
                if member.isdir():
                    directories.add(path)
                    _safe_destination(destination, path).mkdir(mode=0o700, parents=True)
                    continue
                if member.isreg():
                    if member.size < 0 or member.size > MAX_SOURCE_MEMBER_BYTES:
                        raise WheelhouseError("source archive member exceeds its size limit")
                    expanded += member.size
                    if expanded > MAX_SOURCE_EXPANDED_BYTES:
                        raise WheelhouseError("source archive exceeds its expanded size limit")
                    target = _safe_destination(destination, path)
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise WheelhouseError("cannot read source archive member")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    descriptor = os.open(target, flags, 0o600)
                    try:
                        remaining = member.size
                        while remaining:
                            chunk = stream.read(min(COPY_BYTES, remaining))
                            if not chunk:
                                raise WheelhouseError("source archive member is truncated")
                            written = os.write(descriptor, chunk)
                            if written != len(chunk):
                                raise WheelhouseError("cannot write complete source archive member")
                            remaining -= written
                        if stream.read(1):
                            raise WheelhouseError("source archive member exceeds its recorded size")
                        os.fchmod(descriptor, 0o755 if member.mode & 0o111 else 0o644)
                    finally:
                        os.close(descriptor)
                    continue
                if member.issym():
                    symlinks.append((path, member.linkname))
                    continue
                raise WheelhouseError("source archive contains an unsupported member type")
    except (OSError, tarfile.TarError) as exc:
        if isinstance(exc, WheelhouseError):
            raise
        raise WheelhouseError("cannot safely extract source archive") from exc

    root = destination / expected_root
    if not seen or not root.is_dir() or root.is_symlink():
        raise WheelhouseError("source archive omits its expected top-level directory")
    for path, raw_target in symlinks:
        if (
            not raw_target
            or raw_target.startswith("/")
            or "\\" in raw_target
            or "\x00" in raw_target
            or len(raw_target.encode("utf-8")) > MAX_PATH_BYTES
        ):
            raise WheelhouseError("source archive symlink target is invalid")
        components: list[str] = list(path.parent.parts)
        for part in PurePosixPath(raw_target).parts:
            if part in {"", "."}:
                continue
            if part == "..":
                if len(components) <= 1:
                    raise WheelhouseError("source archive symlink escapes its root")
                components.pop()
            else:
                components.append(part)
        if not components or components[0] != expected_root:
            raise WheelhouseError("source archive symlink escapes its root")
        resolved = _safe_destination(destination, PurePosixPath(*components))
        if not resolved.exists() or resolved.is_symlink():
            raise WheelhouseError("source archive symlink does not resolve to a regular member")
        link = _safe_destination(destination, path)
        link.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.symlink(raw_target, link)
        except OSError as exc:
            raise WheelhouseError("cannot create source archive symlink") from exc
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        os.chmod(
            _safe_destination(destination, directory),
            0o700,
        )
    return root


def _reset_private_child(root: Path, name: str) -> Path:
    if PurePosixPath(name).name != name:
        raise WheelhouseError("private work child name is invalid")
    child = root / name
    try:
        child.relative_to(root)
    except ValueError as exc:
        raise WheelhouseError("private work child escaped its root") from exc
    if child.is_symlink():
        raise WheelhouseError("private work child is a symlink")
    if child.exists():
        shutil.rmtree(child)
    child.mkdir(mode=0o700)
    return child


def _run(command: Sequence[str], environment: Mapping[str, str], *, cwd: Path) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - callers pass fixed absolute executables.
            tuple(command),
            cwd=cwd,
            env=dict(environment),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=MAX_PROCESS_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError) and exc.stdout:
            detail = f"\n{exc.stdout[-16_384:]}"
        raise WheelhouseError(f"build command failed: {command[0]}{detail}") from exc
    return result.stdout


def _cargo_packages(lock_path: Path, inputs: Inputs) -> list[dict[str, str]]:
    try:
        raw = lock_path.read_bytes()
        if not 1 <= len(raw) <= 2 * 1024 * 1024:
            raise WheelhouseError("Cargo.lock is outside its byte bound")
        value = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise WheelhouseError("cannot parse the reviewed Cargo.lock") from exc
    packages = value.get("package")
    if not isinstance(packages, list):
        raise WheelhouseError("Cargo.lock has no package array")
    result: list[dict[str, str]] = []
    local = 0
    for index, raw_package in enumerate(packages):
        package = _mapping(raw_package, f"Cargo.lock package {index}")
        name = _text(package.get("name"), f"Cargo.lock package {index} name")
        version = _text(package.get("version"), f"Cargo.lock package {index} version")
        source = package.get("source")
        if source is None:
            local += 1
            continue
        if source != inputs.cargo_source:
            raise WheelhouseError("Cargo.lock uses an unreviewed registry")
        checksum = _text(
            package.get("checksum"),
            f"Cargo.lock package {index} checksum",
            pattern=LOWER_SHA256,
        )
        result.append({"checksum": checksum, "name": name, "version": version})
    result.sort(key=lambda item: (item["name"], item["version"], item["checksum"]))
    if (
        local != 1
        or len(result) != inputs.cargo_registry_packages
        or len({(item["name"], item["version"]) for item in result}) != len(result)
    ):
        raise WheelhouseError("Cargo.lock package inventory differs from reviewed inputs")
    return result


def prepare_cargo(inputs: Inputs, sources: Path, cargo_home: Path, work: Path) -> None:
    """Fetch only the exact Cargo.lock registry closure for later offline builds."""

    paths = verify_sources(inputs, sources)
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    cargo_home.mkdir(mode=0o700, parents=True, exist_ok=False)
    pydantic = next(item for item in inputs.sources if item.identifier == "pydantic-core")
    source_root = _extract_source(paths["pydantic-core"], work / "source", pydantic.root)
    packages = _cargo_packages(source_root / "Cargo.lock", inputs)
    environment = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_HTTP_MULTIPLEXING": "false",
        "CARGO_NET_RETRY": "3",
        "HOME": str(work),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    _run(
        (
            "/usr/bin/cargo",
            "fetch",
            "--locked",
            "--manifest-path",
            str(source_root / "Cargo.toml"),
        ),
        environment,
        cwd=source_root,
    )

    cache_roots = list((cargo_home / "registry" / "cache").glob("index.crates.io-*"))
    if len(cache_roots) != 1 or not cache_roots[0].is_dir():
        raise WheelhouseError("Cargo fetch produced an unexpected registry cache")
    cache = cache_roots[0]
    expected_files = {f"{item['name']}-{item['version']}.crate": item for item in packages}
    observed_files = {item.name for item in cache.iterdir()}
    if observed_files != set(expected_files):
        raise WheelhouseError("Cargo fetch produced a stale or incomplete crate inventory")
    for filename, package in expected_files.items():
        digest, _size = _sha256_file(cache / filename, maximum=MAX_SOURCE_BYTES)
        if digest != package["checksum"]:
            raise WheelhouseError(f"Cargo crate differs from Cargo.lock: {filename}")

    inventory = {
        "kind": CARGO_INVENTORY_KIND,
        "packages": packages,
        "registry_cache": cache.name,
        "schema_version": SCHEMA_VERSION,
        "source": inputs.cargo_source,
    }
    (cargo_home / "extra-codeowners-cargo-inputs.json").write_bytes(canonical_json(inventory))


def _build_environment(inputs: Inputs, work: Path, cargo_home: Path) -> dict[str, str]:
    return {
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "HOME": str(work / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": "/usr/lib/python3.14/site-packages",
        "SOURCE_DATE_EPOCH": str(inputs.source_date_epoch),
        "TZ": "UTC",
    }


def _one_wheel(directory: Path, prefix: str) -> Path:
    wheels = sorted(directory.glob(f"{prefix}-*.whl"))
    if len(wheels) != 1:
        raise WheelhouseError(f"build produced the wrong number of {prefix} wheels")
    return wheels[0]


def _safe_extract_wheel(wheel: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700, parents=True)
    with zipfile.ZipFile(wheel) as archive:
        seen: set[str] = set()
        total = 0
        for index, item in enumerate(archive.infolist()):
            if index >= MAX_WHEEL_MEMBERS:
                raise WheelhouseError("wheel has too many members")
            path = _safe_member_name(item.filename.rstrip("/"))
            folded = path.as_posix().casefold()
            if folded in seen:
                raise WheelhouseError("wheel repeats a member path")
            seen.add(folded)
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise WheelhouseError("wheel contains a symbolic link")
            if item.is_dir():
                _safe_destination(destination, path).mkdir(mode=0o755, parents=True)
                continue
            if item.file_size < 0 or item.file_size > MAX_WHEEL_BYTES:
                raise WheelhouseError("wheel member exceeds its size limit")
            total += item.file_size
            if total > MAX_WHEEL_EXPANDED_BYTES:
                raise WheelhouseError("wheel exceeds its expanded size limit")
            target = _safe_destination(destination, path)
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with archive.open(item) as stream, target.open("xb") as output:
                remaining = item.file_size
                while remaining:
                    chunk = stream.read(min(COPY_BYTES, remaining))
                    if not chunk:
                        raise WheelhouseError("wheel member is truncated")
                    output.write(chunk)
                    remaining -= len(chunk)
                if stream.read(1):
                    raise WheelhouseError("wheel member exceeds its recorded size")
            target.chmod(0o644)


def _apply_setuptools_release_patch(source: Source, root: Path) -> None:
    patch = source.release_patch
    if patch is None or patch.member != "setup.cfg":
        raise WheelhouseError("setuptools release patch contract is invalid")
    removal_directories: dict[PurePosixPath, set[str]] = {}
    for removal in patch.removed_members:
        path = PurePosixPath(removal.member)
        if len(path.parts) < 2:
            raise WheelhouseError("setuptools release removal is not nested")
        removal_directories.setdefault(path.parent, set()).add(path.name)
        target = _safe_destination(root, path)
        digest, _size = _sha256_file(target, maximum=MAX_EXTENSION_BYTES)
        if digest != removal.sha256:
            raise WheelhouseError("setuptools release removal differs from reviewed inputs")
    for directory, expected_names in removal_directories.items():
        target_directory = _safe_destination(root, directory)
        try:
            if target_directory.is_symlink() or not target_directory.is_dir():
                raise WheelhouseError("setuptools release removal directory is invalid")
            if {item.name for item in target_directory.iterdir()} != expected_names:
                raise WheelhouseError(
                    "setuptools release removal directory has an unexpected inventory"
                )
        except OSError as exc:
            raise WheelhouseError("cannot inspect setuptools release removals") from exc
    try:
        for removal in patch.removed_members:
            _safe_destination(root, PurePosixPath(removal.member)).unlink()
        for directory in sorted(
            removal_directories,
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            _safe_destination(root, directory).rmdir()
    except OSError as exc:
        raise WheelhouseError("cannot apply setuptools release removals") from exc
    target = root / patch.member
    try:
        original = target.read_bytes()
    except OSError as exc:
        raise WheelhouseError("cannot read setuptools release configuration") from exc
    if hashlib.sha256(original).hexdigest() != patch.original_sha256:
        raise WheelhouseError("setuptools release configuration differs from signed source")
    if hashlib.sha256(SETUPTOOLS_RELEASE_CONFIG).hexdigest() != patch.replacement_sha256:
        raise WheelhouseError("setuptools release patch differs from reviewed inputs")
    target.write_bytes(SETUPTOOLS_RELEASE_CONFIG)


def _build_once(
    inputs: Inputs,
    source_paths: Mapping[str, Path],
    cargo_home: Path,
    work: Path,
    pass_name: str,
) -> Path:
    source_directory = _reset_private_child(work, "source")
    distribution_directory = _reset_private_child(work, "distribution")
    bootstrap = work / "bootstrap"
    _reset_private_child(work, "target")
    (work / "home").mkdir(mode=0o700, exist_ok=True)
    roots: dict[str, Path] = {}
    for source in inputs.sources:
        roots[source.identifier] = _extract_source(
            source_paths[source.identifier],
            source_directory / source.identifier,
            source.root,
        )
    setuptools_source = next(item for item in inputs.sources if item.identifier == "setuptools")
    _apply_setuptools_release_patch(setuptools_source, roots["setuptools"])

    environment = _build_environment(inputs, work, cargo_home)
    setuptools_output = distribution_directory / "setuptools"
    setuptools_output.mkdir(mode=0o700)
    _run(
        (
            "/usr/local/bin/python",
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(setuptools_output),
            str(roots["setuptools"]),
        ),
        environment,
        cwd=roots["setuptools"],
    )
    setuptools_wheel = _one_wheel(setuptools_output, "setuptools")
    _safe_extract_wheel(setuptools_wheel, bootstrap)
    environment["PYTHONPATH"] = f"{bootstrap}:/usr/lib/python3.14/site-packages"

    cffi_output = distribution_directory / "cffi"
    cffi_output.mkdir(mode=0o700)
    _run(
        (
            "/usr/local/bin/python",
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(cffi_output),
            str(roots["cffi"]),
        ),
        environment,
        cwd=roots["cffi"],
    )

    psycopg_output = distribution_directory / "psycopg"
    psycopg_output.mkdir(mode=0o700)
    _run(
        (
            "/usr/local/bin/python",
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(psycopg_output),
            str(roots["psycopg"] / "psycopg_c"),
        ),
        environment,
        cwd=roots["psycopg"] / "psycopg_c",
    )

    pydantic_output = distribution_directory / "pydantic"
    pydantic_output.mkdir(mode=0o700)
    environment["CARGO_TARGET_DIR"] = str(work / "target")
    _run(
        (
            "/usr/bin/maturin",
            "build",
            "--release",
            "--locked",
            "--offline",
            "--compatibility",
            "linux",
            "--auditwheel",
            "skip",
            "--interpreter",
            "/usr/local/bin/python",
            "--out",
            str(pydantic_output),
        ),
        environment,
        cwd=roots["pydantic-core"],
    )

    pass_output = _reset_private_child(work, pass_name)
    built = (
        setuptools_wheel,
        _one_wheel(cffi_output, "cffi"),
        _one_wheel(psycopg_output, "psycopg_c"),
        _one_wheel(pydantic_output, "pydantic_core"),
    )
    for wheel in built:
        shutil.copyfile(wheel, pass_output / wheel.name)
        (pass_output / wheel.name).chmod(0o444)
    return pass_output


def _normalize_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _wheel_filename(path: Path) -> tuple[str, str, str, str, str]:
    if not path.name.endswith(".whl"):
        raise WheelhouseError("wheel filename does not end in .whl")
    parts = path.name[:-4].rsplit("-", 3)
    if len(parts) != 4:
        raise WheelhouseError("wheel filename has an invalid tag tuple")
    distribution_version, python_tag, abi_tag, platform_tag = parts
    identity = distribution_version.rsplit("-", 1)
    if len(identity) != 2 or any(
        WHEEL_COMPONENT.fullmatch(item) is None
        for item in (identity[0], identity[1], python_tag, abi_tag, platform_tag)
    ):
        raise WheelhouseError("wheel filename has an invalid identity")
    return (
        _normalize_distribution(identity[0]),
        identity[1],
        python_tag,
        abi_tag,
        platform_tag,
    )


def _urlsafe_digest(content: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode("ascii").rstrip("=")


def _verify_record(
    archive: zipfile.ZipFile,
    members: Mapping[str, zipfile.ZipInfo],
    record_name: str,
) -> None:
    try:
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
    except (KeyError, UnicodeDecodeError, csv.Error) as exc:
        raise WheelhouseError("wheel RECORD is invalid") from exc
    observed: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in observed or row[0] not in members:
            raise WheelhouseError("wheel RECORD has an invalid inventory")
        observed.add(row[0])
        if row[0] == record_name:
            if row[1:] != ["", ""]:
                raise WheelhouseError("wheel RECORD self-entry must be unhashed")
            continue
        content = archive.read(row[0])
        match = URLSAFE_SHA256.fullmatch(row[1])
        if (
            match is None
            or match.group(1) != _urlsafe_digest(content)
            or row[2] != str(len(content))
        ):
            raise WheelhouseError("wheel RECORD content binding is invalid")
    if observed != set(members):
        raise WheelhouseError("wheel RECORD does not cover every member")


def _elf_record(content: bytes, name: str, expected_machine: str, work: Path) -> dict[str, object]:
    with tempfile.NamedTemporaryFile(
        mode="w+b",
        dir=work,
        prefix="elf-",
        suffix=".so",
    ) as temporary:
        temporary.write(content)
        temporary.flush()
        output = _run(
            ("/usr/bin/readelf", "--file-header", "--dynamic", temporary.name),
            {
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            cwd=work,
        )
    machine = ""
    needed: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Machine:"):
            machine = stripped.partition(":")[2].strip()
        match = NEEDED_LIBRARY.search(stripped)
        if match is not None:
            needed.append(match.group(1))
    if machine != expected_machine or not needed or len(needed) != len(set(needed)):
        raise WheelhouseError(f"native wheel payload has unexpected ELF metadata: {name}")
    return {
        "machine": machine,
        "needed": sorted(needed),
        "path": name,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def inspect_wheel(
    path: Path,
    expected: ExpectedWheel,
    *,
    machine: str,
    work: Path,
) -> dict[str, object]:
    """Validate one wheel, including RECORD and exact native dependencies."""

    linux_platform, wheel_platform, elf_machine, musl_library = PLATFORM_BY_MACHINE[machine]
    del linux_platform
    distribution, version, python_tag, abi_tag, platform_tag = _wheel_filename(path)
    if distribution != expected.distribution or version != expected.version:
        raise WheelhouseError("wheel filename identity differs from reviewed inputs")
    if expected.native_payloads:
        expected_tags = (_builder_python_abi(),) * 2 + (wheel_platform,)
    else:
        expected_tags = ("py3", "none", "any")
    if (python_tag, abi_tag, platform_tag) != expected_tags:
        raise WheelhouseError(f"wheel has an unexpected compatibility tag: {path.name}")

    digest, size = _sha256_file(path, maximum=MAX_WHEEL_BYTES)
    native: list[dict[str, object]] = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if not 1 <= len(infos) <= MAX_WHEEL_MEMBERS:
            raise WheelhouseError("wheel member count is outside its bound")
        members: dict[str, zipfile.ZipInfo] = {}
        folded: set[str] = set()
        total = 0
        for item in infos:
            name = _safe_member_name(item.filename.rstrip("/")).as_posix()
            if name in members or name.casefold() in folded:
                raise WheelhouseError("wheel repeats a member path")
            folded.add(name.casefold())
            members[name] = item
            if item.file_size < 0 or item.file_size > MAX_WHEEL_BYTES:
                raise WheelhouseError("wheel member exceeds its size limit")
            total += item.file_size
            if total > MAX_WHEEL_EXPANDED_BYTES:
                raise WheelhouseError("wheel exceeds its expanded size limit")
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise WheelhouseError("wheel contains a symbolic link")
        metadata_names = [
            name
            for name in members
            if len(PurePosixPath(name).parts) == 2 and name.endswith(".dist-info/METADATA")
        ]
        wheel_names = [
            name
            for name in members
            if len(PurePosixPath(name).parts) == 2 and name.endswith(".dist-info/WHEEL")
        ]
        record_names = [
            name
            for name in members
            if len(PurePosixPath(name).parts) == 2 and name.endswith(".dist-info/RECORD")
        ]
        if not (len(metadata_names) == len(wheel_names) == len(record_names) == 1):
            raise WheelhouseError(
                f"wheel does not contain one complete dist-info record: {path.name}"
            )
        dist_info_directories = {
            PurePosixPath(name).parent.as_posix()
            for name in (*metadata_names, *wheel_names, *record_names)
        }
        if len(dist_info_directories) != 1:
            raise WheelhouseError("wheel splits its primary dist-info record")
        dist_info = dist_info_directories.pop()
        dist_info_identity = (
            PurePosixPath(dist_info)
            .name.removesuffix(".dist-info")
            .rsplit(
                "-",
                1,
            )
        )
        if (
            len(dist_info_identity) != 2
            or _normalize_distribution(dist_info_identity[0]) != expected.distribution
            or dist_info_identity[1] != expected.version
        ):
            raise WheelhouseError("wheel dist-info identity differs from reviewed inputs")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        if (
            _normalize_distribution(str(metadata.get("Name", ""))) != expected.distribution
            or metadata.get("Version") != expected.version
        ):
            raise WheelhouseError("wheel core metadata differs from reviewed inputs")
        wheel_metadata = BytesParser().parsebytes(archive.read(wheel_names[0]))
        expected_root = "false" if expected.native_payloads else "true"
        expected_tag = f"{python_tag}-{abi_tag}-{platform_tag}"
        wheel_versions = [str(item) for item in wheel_metadata.get_all("Wheel-Version", [])]
        roots = [str(item) for item in wheel_metadata.get_all("Root-Is-Purelib", [])]
        tags = [str(item) for item in wheel_metadata.get_all("Tag", [])]
        if wheel_versions != ["1.0"] or roots != [expected_root] or tags != [expected_tag]:
            raise WheelhouseError("wheel compatibility metadata contradicts its contents")
        _verify_record(archive, members, record_names[0])
        for name, item in members.items():
            if not name.endswith(".so"):
                continue
            native.append(
                _elf_record(
                    archive.read(item),
                    name,
                    elf_machine,
                    work,
                )
            )
    if len(native) != expected.native_payloads:
        raise WheelhouseError("wheel native payload count differs from reviewed inputs")
    expected_needed = sorted((*expected.needed_libraries, musl_library))
    if any(item["needed"] != expected_needed for item in native):
        raise WheelhouseError("wheel native dependency closure differs from reviewed inputs")
    return {
        "abi_tag": abi_tag,
        "distribution": expected.distribution,
        "filename": path.name,
        "native_payloads": sorted(native, key=lambda item: cast(str, item["path"])),
        "platform_tag": platform_tag,
        "python_tag": python_tag,
        "sha256": digest,
        "size": size,
        "version": version,
    }


def _builder_python_abi() -> str:
    """Return the fixed ABI after checking the interpreter used by the builder."""

    if sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 14, 6):
        raise WheelhouseError("wheelhouse builder is not running reviewed CPython 3.14.6")
    return "cp314"


def _expected_builder_packages(inputs: Inputs, platform_name: str) -> tuple[str, ...]:
    platform_packages = inputs.builder_platform_packages.get(platform_name)
    if platform_packages is None:
        raise WheelhouseError("builder package platform is unsupported")
    return tuple(
        sorted(
            (*inputs.builder_packages, *platform_packages),
            key=lambda item: item.partition("=")[::2],
        )
    )


def _installed_apk_packages(inputs: Inputs) -> list[dict[str, str]]:
    path = Path("/lib/apk/db/installed")
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise WheelhouseError("cannot read the installed Alpine package database") from exc
    packages: list[dict[str, str]] = []
    name = ""
    version = ""
    for line in (*raw.splitlines(), ""):
        if line.startswith("P:"):
            name = line[2:]
        elif line.startswith("V:"):
            version = line[2:]
        elif not line:
            if name and version:
                packages.append({"name": name, "version": version})
            name = ""
            version = ""
    packages.sort(key=lambda item: (item["name"], item["version"]))
    if not packages or len({item["name"] for item in packages}) != len(packages):
        raise WheelhouseError("installed Alpine package inventory is invalid")
    machine = platform.machine()
    if machine not in PLATFORM_BY_MACHINE:
        raise WheelhouseError(f"unsupported native build machine: {machine}")
    installed = tuple(f"{item['name']}={item['version']}" for item in packages)
    expected = _expected_builder_packages(inputs, PLATFORM_BY_MACHINE[machine][0])
    if installed != expected:
        raise WheelhouseError("installed builder package closure differs from reviewed pins")
    return packages


def _tool_versions(environment: Mapping[str, str], work: Path) -> dict[str, str]:
    commands = {
        "cargo": ("/usr/bin/cargo", "--version"),
        "cython": ("/usr/bin/cython", "--version"),
        "gcc": ("/usr/bin/gcc", "--version"),
        "maturin": ("/usr/bin/maturin", "--version"),
        "python": ("/usr/local/bin/python", "--version"),
        "readelf": ("/usr/bin/readelf", "--version"),
        "rustc": ("/usr/bin/rustc", "--version"),
    }
    result: dict[str, str] = {}
    for name, command in commands.items():
        output = _run(command, environment, cwd=work).splitlines()
        if not output or not output[0].strip():
            raise WheelhouseError(f"cannot identify builder tool: {name}")
        result[name] = output[0].strip()
    return result


def _cargo_inventory_file(path: Path, inputs: Inputs) -> tuple[dict[str, Any], bytes]:
    value, raw = _load_json(path, "Cargo input inventory")
    record = _exact_fields(
        value,
        {"kind", "packages", "registry_cache", "schema_version", "source"},
        "Cargo input inventory",
    )
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != SCHEMA_VERSION
        or record["kind"] != CARGO_INVENTORY_KIND
        or record["source"] != inputs.cargo_source
        or not isinstance(record["packages"], list)
        or len(record["packages"]) != inputs.cargo_registry_packages
        or not isinstance(record["registry_cache"], str)
        or CARGO_CACHE.fullmatch(record["registry_cache"]) is None
    ):
        raise WheelhouseError("Cargo input inventory differs from reviewed inputs")
    packages: list[tuple[str, str, str]] = []
    for index, raw_package in enumerate(record["packages"]):
        package = _exact_fields(
            raw_package,
            {"checksum", "name", "version"},
            f"Cargo input inventory package {index}",
        )
        packages.append(
            (
                _text(package["name"], f"Cargo input inventory package {index} name"),
                _text(package["version"], f"Cargo input inventory package {index} version"),
                _text(
                    package["checksum"],
                    f"Cargo input inventory package {index} checksum",
                    pattern=LOWER_SHA256,
                ),
            )
        )
    if packages != sorted(packages) or len(set(packages)) != len(packages):
        raise WheelhouseError("Cargo input inventory packages are not canonical")
    if raw != canonical_json(value):
        raise WheelhouseError("Cargo input inventory is not canonical JSON")
    return dict(record), raw


def _cargo_inventory(cargo_home: Path, inputs: Inputs) -> tuple[dict[str, Any], bytes]:
    return _cargo_inventory_file(
        cargo_home / "extra-codeowners-cargo-inputs.json",
        inputs,
    )


def _compare_passes(first: Path, second: Path) -> list[Path]:
    first_names = sorted(item.name for item in first.iterdir())
    second_names = sorted(item.name for item in second.iterdir())
    if first_names != second_names or len(first_names) != 4:
        raise WheelhouseError("clean wheelhouse builds produced different inventories")
    result: list[Path] = []
    for name in first_names:
        first_path = first / name
        second_path = second / name
        first_digest, first_size = _sha256_file(first_path, maximum=MAX_WHEEL_BYTES)
        second_digest, second_size = _sha256_file(second_path, maximum=MAX_WHEEL_BYTES)
        if (first_digest, first_size) != (second_digest, second_size):
            raise WheelhouseError(f"clean wheelhouse builds are not reproducible: {name}")
        result.append(first_path)
    return result


def build_wheelhouse_pass(
    inputs: Inputs,
    sources: Path,
    cargo_home: Path,
    output: Path,
    work: Path,
    pass_name: str,
) -> None:
    """Build one wheel set from one clean container stage."""

    if pass_name not in {"first", "second"}:
        raise WheelhouseError("wheelhouse build pass has an invalid identity")
    source_paths = verify_sources(inputs, sources)
    _cargo_inventory(cargo_home, inputs)
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    output.mkdir(mode=0o755, parents=True, exist_ok=False)
    built = _build_once(inputs, source_paths, cargo_home, work, "built")
    wheels = sorted(built.iterdir())
    if len(wheels) != 4:
        raise WheelhouseError(f"clean wheelhouse {pass_name} build produced the wrong inventory")
    for wheel in wheels:
        target = output / wheel.name
        shutil.copyfile(wheel, target)
        target.chmod(0o444)


def _source_records(inputs: Inputs) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for source in inputs.sources:
        release_patch: dict[str, object] | None = None
        if source.release_patch is not None:
            release_patch = {
                "member": source.release_patch.member,
                "original_sha256": source.release_patch.original_sha256,
                "removed_members": [
                    {
                        "member": removal.member,
                        "sha256": removal.sha256,
                    }
                    for removal in source.release_patch.removed_members
                ],
                "replacement_sha256": source.release_patch.replacement_sha256,
            }
        records.append(
            {
                "filename": source.filename,
                "id": source.identifier,
                "release_patch": release_patch,
                "sha256": source.sha256,
                "size": source.size,
                "upstream": dict(source.upstream),
                "url": source.url,
            }
        )
    return records


def assemble_wheelhouse(
    inputs: Inputs,
    sources: Path,
    cargo_home: Path,
    first: Path,
    second: Path,
    output: Path,
    work: Path,
) -> None:
    """Compare isolated builds, verify their contents, and publish one manifest."""

    verify_sources(inputs, sources)
    cargo_record, cargo_raw = _cargo_inventory(cargo_home, inputs)
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    output.mkdir(mode=0o755, parents=True, exist_ok=False)
    wheels = _compare_passes(first, second)
    machine = platform.machine()
    if machine not in PLATFORM_BY_MACHINE:
        raise WheelhouseError(f"unsupported native build machine: {machine}")
    platform_name = PLATFORM_BY_MACHINE[machine][0]
    expected = {item.distribution: item for item in inputs.expected_wheels}
    wheel_records: list[dict[str, object]] = []
    for wheel in wheels:
        distribution = _wheel_filename(wheel)[0]
        wheel_expectation = expected.get(distribution)
        if wheel_expectation is None:
            raise WheelhouseError("build produced an unexpected wheel")
        wheel_records.append(
            inspect_wheel(
                wheel,
                wheel_expectation,
                machine=machine,
                work=work,
            )
        )
    wheel_records.sort(key=lambda item: cast(str, item["distribution"]))
    if [item["distribution"] for item in wheel_records] != sorted(expected):
        raise WheelhouseError("build did not produce every reviewed wheel")

    build_environment = _build_environment(inputs, work, cargo_home)
    manifest = {
        "builder": {
            "alpine_packages": _installed_apk_packages(inputs),
            "base_image": dict(inputs.base_image),
            "tools": _tool_versions(build_environment, work),
        },
        "cargo": {
            "inventory_sha256": hashlib.sha256(cargo_raw).hexdigest(),
            "inventory_size": len(cargo_raw),
            **cargo_record,
        },
        "inputs": {
            "sha256": inputs.raw_sha256,
            "size": inputs.raw_size,
        },
        "kind": MANIFEST_KIND,
        "platform": platform_name,
        "python": dict(inputs.python),
        "reproducible_builds": 2,
        "schema_version": SCHEMA_VERSION,
        "source_date_epoch": inputs.source_date_epoch,
        "sources": _source_records(inputs),
        "wheels": wheel_records,
    }
    for wheel in wheels:
        target = output / wheel.name
        shutil.copyfile(wheel, target)
        target.chmod(0o444)
    inputs_path = output / "inputs.json"
    inputs_path.write_bytes(inputs.raw)
    inputs_path.chmod(0o444)
    cargo_path = output / "cargo-inputs.json"
    cargo_path.write_bytes(cargo_raw)
    cargo_path.chmod(0o444)
    manifest_path = output / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    manifest_path.chmod(0o444)


def _validate_builder_record(
    value: object,
    inputs: Inputs,
    expected_platform: str,
) -> None:
    builder = _exact_fields(
        value,
        {"alpine_packages", "base_image", "tools"},
        "native wheelhouse builder",
    )
    if builder["base_image"] != dict(inputs.base_image):
        raise WheelhouseError("native wheelhouse builder base image is invalid")
    raw_packages = builder["alpine_packages"]
    if not isinstance(raw_packages, list) or not raw_packages:
        raise WheelhouseError("native wheelhouse builder package inventory is invalid")
    packages: list[tuple[str, str]] = []
    for index, raw_package in enumerate(raw_packages):
        package = _exact_fields(
            raw_package,
            {"name", "version"},
            f"native wheelhouse builder package {index}",
        )
        name = _text(package["name"], f"native wheelhouse builder package {index} name")
        version = _text(
            package["version"],
            f"native wheelhouse builder package {index} version",
        )
        if APK_NAME.fullmatch(name) is None or APK_VERSION.fullmatch(version) is None:
            raise WheelhouseError("native wheelhouse builder package identity is invalid")
        packages.append((name, version))
    if packages != sorted(packages) or len({name for name, _version in packages}) != len(packages):
        raise WheelhouseError("native wheelhouse builder packages are not canonical")
    expected_packages = tuple(
        item.partition("=")[::2] for item in _expected_builder_packages(inputs, expected_platform)
    )
    if tuple(packages) != expected_packages:
        raise WheelhouseError("native wheelhouse builder package closure is invalid")

    tools = _exact_fields(
        builder["tools"],
        {"cargo", "cython", "gcc", "maturin", "python", "readelf", "rustc"},
        "native wheelhouse builder tools",
    )
    for name, version in tools.items():
        _text(version, f"native wheelhouse builder tool {name}")


def verify_wheelhouse(
    inputs: Inputs,
    wheelhouse: Path,
    expected_platform: str,
    work: Path,
) -> None:
    """Verify the published wheelhouse inventory and immutable content bindings."""

    if expected_platform not in {"linux/amd64", "linux/arm64"}:
        raise WheelhouseError("expected wheelhouse platform is unsupported")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    value, raw = _load_json(
        wheelhouse / "manifest.json",
        "native wheelhouse manifest",
        maximum=8 * 1024 * 1024,
    )
    if raw != canonical_json(value):
        raise WheelhouseError("native wheelhouse manifest is not canonical JSON")
    record = _exact_fields(
        value,
        {
            "builder",
            "cargo",
            "inputs",
            "kind",
            "platform",
            "python",
            "reproducible_builds",
            "schema_version",
            "source_date_epoch",
            "sources",
            "wheels",
        },
        "native wheelhouse manifest",
    )
    if (
        record["schema_version"] != SCHEMA_VERSION
        or type(record["schema_version"]) is not int
        or record["kind"] != MANIFEST_KIND
        or record["platform"] != expected_platform
        or record["python"] != dict(inputs.python)
        or record["source_date_epoch"] != inputs.source_date_epoch
        or record["reproducible_builds"] != 2
        or record["inputs"] != {"sha256": inputs.raw_sha256, "size": inputs.raw_size}
        or record["sources"] != _source_records(inputs)
    ):
        raise WheelhouseError("native wheelhouse manifest identity is invalid")
    _validate_builder_record(record["builder"], inputs, expected_platform)

    _embedded_inputs, embedded_inputs_raw = _load_json(
        wheelhouse / "inputs.json",
        "embedded native wheelhouse inputs",
    )
    if embedded_inputs_raw != inputs.raw:
        raise WheelhouseError("embedded native wheelhouse inputs differ from reviewed inputs")
    cargo_record, cargo_raw = _cargo_inventory_file(
        wheelhouse / "cargo-inputs.json",
        inputs,
    )
    expected_cargo = {
        "inventory_sha256": hashlib.sha256(cargo_raw).hexdigest(),
        "inventory_size": len(cargo_raw),
        **cargo_record,
    }
    if record["cargo"] != expected_cargo:
        raise WheelhouseError("native wheelhouse Cargo manifest binding is invalid")

    raw_wheels = record["wheels"]
    if not isinstance(raw_wheels, list) or len(raw_wheels) != len(inputs.expected_wheels):
        raise WheelhouseError("native wheelhouse manifest has the wrong wheel inventory")
    expected_records = {item.distribution: item for item in inputs.expected_wheels}
    machine = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}[expected_platform]
    observed_records: list[dict[str, object]] = []
    expected_files = {"cargo-inputs.json", "inputs.json", "manifest.json"}
    for raw_wheel in raw_wheels:
        wheel_record = _mapping(raw_wheel, "native wheelhouse wheel record")
        filename = _text(wheel_record.get("filename"), "native wheelhouse wheel filename")
        if PurePosixPath(filename).name != filename:
            raise WheelhouseError("native wheelhouse wheel filename is invalid")
        wheel_path = wheelhouse / filename
        distribution = _wheel_filename(wheel_path)[0]
        expectation = expected_records.get(distribution)
        if expectation is None:
            raise WheelhouseError("native wheelhouse contains an unexpected wheel")
        observed = inspect_wheel(
            wheel_path,
            expectation,
            machine=machine,
            work=work,
        )
        if observed != wheel_record:
            raise WheelhouseError("native wheelhouse wheel differs from its manifest")
        observed_records.append(observed)
        expected_files.add(filename)
    if {item.name for item in wheelhouse.iterdir()} != expected_files:
        raise WheelhouseError("native wheelhouse directory has an unexpected inventory")
    if sorted(cast(str, item["distribution"]) for item in observed_records) != sorted(
        expected_records
    ):
        raise WheelhouseError("native wheelhouse omits a reviewed wheel")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-inputs", help="validate reviewed builder inputs")
    validate.add_argument("--inputs", type=Path, required=True)

    packages = commands.add_parser(
        "emit-builder-packages",
        help="emit the exact Alpine package closure for one build platform",
    )
    packages.add_argument("--inputs", type=Path, required=True)
    packages.add_argument(
        "--platform",
        choices=("linux/amd64", "linux/arm64"),
        required=True,
    )

    cargo = commands.add_parser(
        "prepare-cargo",
        help="fetch the exact Cargo.lock closure for a later offline build",
    )
    cargo.add_argument("--inputs", type=Path, required=True)
    cargo.add_argument("--sources", type=Path, required=True)
    cargo.add_argument("--cargo-home", type=Path, required=True)
    cargo.add_argument("--work", type=Path, required=True)

    build = commands.add_parser("build-pass", help="build one isolated offline wheel set")
    build.add_argument("--inputs", type=Path, required=True)
    build.add_argument("--sources", type=Path, required=True)
    build.add_argument("--cargo-home", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--work", type=Path, required=True)
    build.add_argument("--pass-name", choices=("first", "second"), required=True)

    assemble = commands.add_parser(
        "assemble",
        help="compare two isolated builds and assemble the verified wheelhouse",
    )
    assemble.add_argument("--inputs", type=Path, required=True)
    assemble.add_argument("--sources", type=Path, required=True)
    assemble.add_argument("--cargo-home", type=Path, required=True)
    assemble.add_argument("--first", type=Path, required=True)
    assemble.add_argument("--second", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument("--work", type=Path, required=True)

    verify = commands.add_parser("verify", help="verify a published native wheelhouse")
    verify.add_argument("--inputs", type=Path, required=True)
    verify.add_argument("--wheelhouse", type=Path, required=True)
    verify.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    verify.add_argument("--work", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one wheelhouse operation with concise, credential-safe failures."""

    args = _parser().parse_args(argv)
    try:
        inputs = load_inputs(args.inputs)
        if args.command == "validate-inputs":
            return 0
        if args.command == "emit-builder-packages":
            sys.stdout.write(
                "".join(
                    f"{package}\n" for package in _expected_builder_packages(inputs, args.platform)
                )
            )
            return 0
        if args.command == "prepare-cargo":
            prepare_cargo(inputs, args.sources, args.cargo_home, args.work)
            return 0
        if args.command == "build-pass":
            build_wheelhouse_pass(
                inputs,
                args.sources,
                args.cargo_home,
                args.output,
                args.work,
                args.pass_name,
            )
            return 0
        if args.command == "assemble":
            assemble_wheelhouse(
                inputs,
                args.sources,
                args.cargo_home,
                args.first,
                args.second,
                args.output,
                args.work,
            )
            return 0
        if args.command == "verify":
            verify_wheelhouse(inputs, args.wheelhouse, args.platform, args.work)
            return 0
        raise WheelhouseError("unknown wheelhouse operation")
    except WheelhouseError as exc:
        sys.stderr.write(f"native wheelhouse error: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
