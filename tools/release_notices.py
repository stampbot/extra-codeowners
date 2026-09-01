"""Build and verify deterministic recipient notice bundles for release images.

The bundle preserves notice material present in an exact exported filesystem and
binds it to the release inventory and platform digest. It is evidence, not a
legal conclusion or a corresponding-source offer.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import posixpath
import re
import sys
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Final, NoReturn, cast
from urllib.parse import quote

_SCHEMA_VERSION: Final = 2
_INVENTORY_SCHEMA_VERSION: Final = 2
_ARCHITECTURES: Final = frozenset(("amd64", "arm64"))
_DIGEST_PATTERN: Final = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_SHA256_PATTERN: Final = re.compile(r"\A[0-9a-f]{64}\Z")
_SAFE_COMPONENT_PATTERN: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9+._-]*\Z")
_CPYTHON_LICENSE_PATTERN: Final = re.compile(r"\Ausr/local/lib/python\d+\.\d+/LICENSE\.txt\Z")
_LEGACY_NOTICE_FILENAME_PATTERN: Final = re.compile(
    r"\A(?:licen[cs]e|copying|copyright|notice)(?:[._-].*)?\Z", re.IGNORECASE
)
_APPLICATION_LICENSE_PATH: Final = "usr/share/licenses/extra-codeowners/LICENSE"
_MAX_NOTICE_FILE_BYTES: Final = 32 * 1024 * 1024
_MAX_TOTAL_NOTICE_BYTES: Final = 128 * 1024 * 1024
_MAX_BUNDLE_MEMBERS: Final = 10_000
# This includes bounded regular payloads plus tar blocks, padding, and a bounded
# amount of PAX/GNU extension metadata before tarfile is allowed to parse it.
_MAX_BUNDLE_ARCHIVE_BYTES: Final = (
    _MAX_TOTAL_NOTICE_BYTES + (_MAX_BUNDLE_MEMBERS * 2048) + (1024 * 1024)
)
_MAX_BUNDLE_COMPRESSED_BYTES: Final = _MAX_BUNDLE_ARCHIVE_BYTES + (1024 * 1024)
_NOTICE_MANIFEST: Final = "NOTICE-MANIFEST.json"
_NOTICE_README: Final = "NOTICE-README.txt"


class ReleaseNoticeError(ValueError):
    """Raised when notice evidence cannot be bound safely to a release image."""


@dataclass(frozen=True, slots=True)
class _ExpectedFile:
    """One regular file that must be preserved from the exported root filesystem."""

    archive_path: str
    component: str
    expected_sha256: str | None
    expected_size: int | None
    role: str
    source_path: str


@dataclass(frozen=True, slots=True)
class _ExpectedLink:
    """One Debian evidence link bound to a regular file in the same evidence class."""

    archive_path: str
    archive_link_target: str
    archive_target_path: str
    component: str
    kind: str
    source_link_target: str
    source_path: str


@dataclass(frozen=True, slots=True)
class _PendingDebianLink:
    """One Debian link awaiting resolution after all regular evidence is known."""

    archive_path: str
    component: str
    kind: str
    role: str
    source_link_target: str
    source_path: str


@dataclass(frozen=True, slots=True)
class _CollectedFile:
    """A notice file read and verified from the exported filesystem."""

    archive_path: str
    component: str
    contents: bytes
    role: str
    sha256: str
    source_path: str


@dataclass(frozen=True, slots=True)
class _BundleMember:
    """One bounded bundle member retained for non-seeking verification."""

    contents: bytes | None
    kind: str
    linkname: str | None


class _BoundedDecompressedReader:
    """Fail closed before tarfile can consume unbounded decompressed metadata."""

    def __init__(self, stream: BinaryIO, *, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._read = 0

    def tell(self) -> int:
        return self._read

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            _fail("notice bundle decompression requires a bounded read")
        remaining = self._limit - self._read
        contents = self._stream.read(min(size, remaining + 1))
        self._read += len(contents)
        if self._read > self._limit:
            _fail("notice bundle exceeds its decompressed archive size limit")
        return contents


class _BoundedArchiveWriter:
    """Count every tar byte, including headers and padding, before gzip writes it."""

    def __init__(self, stream: BinaryIO, *, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._written = 0

    def tell(self) -> int:
        return self._written

    def write(self, contents: bytes) -> int:
        if len(contents) > self._limit - self._written:
            _fail("notice bundle would exceed its decompressed archive size limit")
        written = self._stream.write(contents)
        if written != len(contents):
            _fail("could not write complete notice bundle archive data")
        self._written += written
        return written

    def flush(self) -> None:
        self._stream.flush()


def _fail(message: str) -> NoReturn:
    raise ReleaseNoticeError(message)


def _mapping(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"{description} must be a JSON object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, description: str) -> Sequence[object]:
    if not isinstance(value, list):
        _fail(f"{description} must be a JSON array")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{description} must be a nonempty string")
    return value


def _nonnegative_int(value: object, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(f"{description} must be a nonnegative integer")
    return value


def _safe_component(value: str, description: str) -> str:
    if _SAFE_COMPONENT_PATTERN.fullmatch(value) is None:
        _fail(f"{description} has an unsafe path component")
    return value


def _encoded_component(value: str, description: str) -> str:
    """Encode an untrusted metadata scalar as one archive path component."""
    if "\x00" in value or "/" in value or "\\" in value or value in {".", ".."} or len(value) > 512:
        _fail(f"{description} has an unsafe path component")
    encoded = quote(value, safe="+._-")
    if encoded.endswith((".", " ")):
        _fail(f"{description} has an unsafe path component")
    return encoded


def _safe_relative_path(value: str, description: str) -> str:
    if "\x00" in value or "\\" in value:
        _fail(f"{description} has an unsafe path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {".", ".."} or part.endswith((".", " ")) for part in path.parts)
    ):
        _fail(f"{description} has an unsafe path")
    return "/".join(path.parts)


def _rootfs_path(value: object, description: str) -> str:
    return _safe_relative_path(_string(value, description), description)


def _link_target(value: object, description: str) -> str:
    """Validate an untrusted link target without resolving it on the host."""
    target = _string(value, description)
    if (
        "\x00" in target
        or "\n" in target
        or "\r" in target
        or "\\" in target
        or len(target) > 4096
        or PurePosixPath(target).is_absolute()
    ):
        _fail(f"{description} has an unsafe link target")
    return target


def _sha256(value: object, description: str) -> str:
    digest = _string(value, description)
    if _SHA256_PATTERN.fullmatch(digest) is None:
        _fail(f"{description} must be a lowercase SHA-256 hex digest")
    return digest


def _normalize_member_path(name: str) -> str:
    """Normalize a POSIX rootfs member without treating it as bundle output.

    A root filesystem can contain names that would be unsafe to emit in a
    portable recipient archive. Those names are not evidence unless the signed
    inventory selects them, so preserve the collector's POSIX-only
    normalization here and apply archive-safe validation only to selected
    paths while interpreting the inventory.
    """
    if "\x00" in name:
        _fail("root filesystem tar contains a NUL in a member path")
    path = PurePosixPath(name)
    if path.is_absolute():
        _fail(f"root filesystem tar contains an absolute member path: {name!r}")
    parts = tuple(part for part in path.parts if part != ".")
    if not parts or any(part == ".." for part in parts):
        _fail(f"root filesystem tar contains an unsafe member path: {name!r}")
    return "/".join(parts)


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile() or member.size < 0 or member.size > _MAX_NOTICE_FILE_BYTES:
        _fail(f"notice source {member.name!r} is not a bounded regular file")
    extracted = archive.extractfile(member)
    if extracted is None:  # pragma: no cover - tarfile documents this as impossible for a file.
        _fail(f"could not read notice source {member.name!r}")
    contents = extracted.read(_MAX_NOTICE_FILE_BYTES + 1)
    if len(contents) != member.size or len(contents) > _MAX_NOTICE_FILE_BYTES:
        _fail(f"notice source {member.name!r} changed or exceeded its size limit")
    return contents


def _payload_expectation(value: Mapping[str, object], description: str) -> tuple[str, int]:
    if value.get("kind") != "regular":
        _fail(f"{description} must describe a regular file")
    return (
        _sha256(value.get("sha256"), f"{description}.sha256"),
        _nonnegative_int(value.get("size"), f"{description}.size"),
    )


def _append_expected_file(expected: dict[str, _ExpectedFile], entry: _ExpectedFile) -> None:
    previous = expected.get(entry.source_path)
    if previous is not None and previous != entry:
        _fail(f"release inventory names {entry.source_path!r} with conflicting notice evidence")
    if entry.archive_path in {item.archive_path for item in expected.values()}:
        _fail(f"release inventory produces duplicate notice archive path {entry.archive_path!r}")
    expected[entry.source_path] = entry


def _append_expected_link(
    links: dict[str, _ExpectedLink],
    expected_files: Mapping[str, _ExpectedFile],
    entry: _ExpectedLink,
) -> None:
    if entry.source_path in expected_files:
        _fail(f"release inventory names {entry.source_path!r} as both a file and a link")
    previous = links.get(entry.source_path)
    if previous is not None:
        _fail(f"release inventory names {entry.source_path!r} with duplicate link evidence")
    if entry.archive_path in {
        item.archive_path for item in expected_files.values()
    } or entry.archive_path in {item.archive_path for item in links.values()}:
        _fail(f"release inventory produces duplicate notice archive path {entry.archive_path!r}")
    if entry.archive_target_path not in {item.archive_path for item in expected_files.values()}:
        _fail(f"release inventory link {entry.source_path!r} targets absent notice material")
    links[entry.source_path] = entry


def _resolve_relative_link_target(*, source_path: str, target: str, description: str) -> str:
    """Resolve a POSIX relative link target without allowing it to escape rootfs."""
    parts = list(PurePosixPath(source_path).parent.parts)
    for part in PurePosixPath(target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                _fail(f"{description} escapes the root filesystem")
            parts.pop()
            continue
        parts.append(part)
    if not parts:
        _fail(f"{description} does not name a root filesystem entry")
    return "/".join(parts)


def _debian_link_candidates(link: _PendingDebianLink) -> frozenset[str]:
    """Return the possible rootfs paths named by an inventory Debian link.

    Symlink targets use POSIX relative-link semantics. Tar hard-link targets are
    commonly recorded as a rootfs member name, but some producers use a relative
    name, so both unambiguous safe interpretations are considered.
    """
    description = f"release inventory link target for {link.source_path!r}"
    target = _link_target(link.source_link_target, description)
    candidates = {
        _resolve_relative_link_target(
            source_path=link.source_path, target=target, description=description
        )
    }
    if link.kind == "hardlink" and ".." not in PurePosixPath(target).parts:
        candidates.add(_safe_relative_path(target, description))
    return frozenset(candidates)


def _archive_link_target(*, link: _PendingDebianLink, target: _ExpectedFile) -> str:
    """Create a deterministic archive-local target for a resolved evidence link."""
    if link.kind == "hardlink":
        return target.archive_path
    source_parent = str(PurePosixPath(link.archive_path).parent)
    return posixpath.relpath(target.archive_path, start=source_parent)


def _resolve_debian_links(
    *,
    expected_files: Mapping[str, _ExpectedFile],
    pending_links: Sequence[_PendingDebianLink],
) -> dict[str, _ExpectedLink]:
    """Resolve safe Debian link chains to regular selected evidence.

    A link may only resolve to another selected Debian entry with the same role.
    This avoids following arbitrary rootfs paths while supporting normal Debian
    package documentation links and hard links.
    """
    pending_by_path = {item.source_path: item for item in pending_links}
    if len(pending_by_path) != len(pending_links):
        _fail("release inventory contains duplicate Debian link evidence")
    resolved: dict[str, _ExpectedFile] = {}
    resolving: set[str] = set()

    def resolve(link: _PendingDebianLink) -> _ExpectedFile:
        if link.source_path in resolved:
            return resolved[link.source_path]
        if link.source_path in resolving:
            _fail(f"release inventory contains a Debian notice-link cycle at {link.source_path!r}")
        resolving.add(link.source_path)
        matches: dict[str, _ExpectedFile] = {}
        for candidate in _debian_link_candidates(link):
            target_file = expected_files.get(candidate)
            if target_file is not None:
                if target_file.role == link.role:
                    matches[target_file.source_path] = target_file
                continue
            target_link = pending_by_path.get(candidate)
            if target_link is not None and target_link.role == link.role:
                resolved_target = resolve(target_link)
                matches[resolved_target.source_path] = resolved_target
        resolving.remove(link.source_path)
        if len(matches) != 1:
            _fail(
                f"release inventory link {link.source_path!r} does not resolve to one "
                "selected regular notice file"
            )
        target = next(iter(matches.values()))
        resolved[link.source_path] = target
        return target

    links: dict[str, _ExpectedLink] = {}
    for pending in pending_links:
        target = resolve(pending)
        _append_expected_link(
            links,
            expected_files,
            _ExpectedLink(
                archive_path=pending.archive_path,
                archive_link_target=_archive_link_target(link=pending, target=target),
                archive_target_path=target.archive_path,
                component=pending.component,
                kind=pending.kind,
                source_link_target=pending.source_link_target,
                source_path=pending.source_path,
            ),
        )
    return links


def _expected_from_inventory(
    inventory: Mapping[str, object], *, architecture: str, platform_digest: str
) -> tuple[dict[str, _ExpectedFile], dict[str, _ExpectedLink], list[dict[str, str]], str]:
    if inventory.get("schema_version") != _INVENTORY_SCHEMA_VERSION:
        _fail("release inventory has an unsupported schema version")
    image = _mapping(inventory.get("image"), "release inventory.image")
    if image.get("architecture") != architecture:
        _fail("release inventory architecture does not match the requested notice bundle")
    if image.get("platform_digest") != platform_digest:
        _fail("release inventory platform digest does not match the requested notice bundle")
    distro = _string(image.get("distro"), "release inventory.image.distro")

    expected: dict[str, _ExpectedFile] = {}
    pending_debian_links: list[_PendingDebianLink] = []
    unresolved: list[dict[str, str]] = []
    debian = _mapping(inventory.get("debian"), "release inventory.debian")
    for index, raw_file in enumerate(
        _sequence(debian.get("copyright_files"), "release inventory.debian.copyright_files")
    ):
        record = _mapping(raw_file, f"release inventory.debian.copyright_files[{index}]")
        package = _safe_component(
            _string(
                record.get("package"), f"release inventory.debian.copyright_files[{index}].package"
            ),
            f"release inventory.debian.copyright_files[{index}].package",
        )
        source_path = _rootfs_path(
            record.get("path"), f"release inventory.debian.copyright_files[{index}].path"
        )
        if source_path != f"usr/share/doc/{package}/copyright":
            _fail("release inventory has an unsupported Debian copyright path")
        archive_path = f"notices/debian/copyright/{package}.txt"
        component = f"deb:{package}"
        role = "debian-copyright"
        kind = _string(
            record.get("kind"), f"release inventory.debian.copyright_files[{index}].kind"
        )
        if kind == "regular":
            digest, size = _payload_expectation(
                record, f"release inventory.debian.copyright_files[{index}]"
            )
            _append_expected_file(
                expected,
                _ExpectedFile(
                    archive_path=archive_path,
                    component=component,
                    expected_sha256=digest,
                    expected_size=size,
                    role=role,
                    source_path=source_path,
                ),
            )
        elif kind in {"symlink", "hardlink"}:
            pending_debian_links.append(
                _PendingDebianLink(
                    archive_path=archive_path,
                    component=component,
                    kind=kind,
                    role=role,
                    source_link_target=_link_target(
                        record.get("link_target"),
                        f"release inventory.debian.copyright_files[{index}].link_target",
                    ),
                    source_path=source_path,
                )
            )
        else:
            _fail("release inventory has an unsupported Debian copyright kind")

    common_names: set[str] = set()
    for index, raw_file in enumerate(
        _sequence(
            debian.get("shared_license_files"), "release inventory.debian.shared_license_files"
        )
    ):
        record = _mapping(raw_file, f"release inventory.debian.shared_license_files[{index}]")
        name = _safe_component(
            _string(
                record.get("name"), f"release inventory.debian.shared_license_files[{index}].name"
            ),
            f"release inventory.debian.shared_license_files[{index}].name",
        )
        if name in common_names:
            _fail(f"release inventory contains duplicate Debian shared license {name!r}")
        common_names.add(name)
        source_path = _rootfs_path(
            record.get("path"), f"release inventory.debian.shared_license_files[{index}].path"
        )
        if source_path != f"usr/share/common-licenses/{name}":
            _fail("release inventory has an unsupported Debian shared-license path")
        archive_path = f"notices/debian/common/{name}"
        kind = _string(
            record.get("kind"), f"release inventory.debian.shared_license_files[{index}].kind"
        )
        if kind == "regular":
            digest, size = _payload_expectation(
                record, f"release inventory.debian.shared_license_files[{index}]"
            )
            _append_expected_file(
                expected,
                _ExpectedFile(
                    archive_path=archive_path,
                    component=f"debian-common-license:{name}",
                    expected_sha256=digest,
                    expected_size=size,
                    role="debian-shared-license",
                    source_path=source_path,
                ),
            )
        elif kind in {"symlink", "hardlink"}:
            pending_debian_links.append(
                _PendingDebianLink(
                    archive_path=archive_path,
                    component=f"debian-common-license:{name}",
                    kind=kind,
                    role="debian-shared-license",
                    source_link_target=_link_target(
                        record.get("link_target"),
                        f"release inventory.debian.shared_license_files[{index}].link_target",
                    ),
                    source_path=source_path,
                )
            )
        else:
            _fail("release inventory has an unsupported Debian shared-license kind")

    python = _mapping(inventory.get("python"), "release inventory.python")
    for index, raw_distribution in enumerate(
        _sequence(python.get("distributions"), "release inventory.python.distributions")
    ):
        distribution = _mapping(
            raw_distribution, f"release inventory.python.distributions[{index}]"
        )
        name = _safe_component(
            _string(
                distribution.get("normalized_name"),
                f"release inventory.python.distributions[{index}].normalized_name",
            ),
            f"release inventory.python.distributions[{index}].normalized_name",
        )
        raw_version = _string(
            distribution.get("version"),
            f"release inventory.python.distributions[{index}].version",
        )
        version = _encoded_component(
            raw_version,
            f"release inventory.python.distributions[{index}].version",
        )
        component = f"pypi:{name}@{raw_version}"
        metadata_path = _rootfs_path(
            distribution.get("metadata_path"),
            f"release inventory.python.distributions[{index}].metadata_path",
        )
        if not metadata_path.endswith("/METADATA"):
            _fail("release inventory has an unsupported Python metadata path")
        distribution_root = metadata_path.rsplit("/", maxsplit=1)[0]
        if (
            not distribution_root.startswith("opt/venv/lib/python")
            or "/site-packages/" not in distribution_root
        ):
            _fail("release inventory has an unsupported Python metadata path")
        for field in ("license_files", "unreferenced_license_files"):
            for file_index, raw_file in enumerate(
                _sequence(
                    distribution.get(field),
                    f"release inventory.python.distributions[{index}].{field}",
                )
            ):
                record = _mapping(
                    raw_file,
                    f"release inventory.python.distributions[{index}].{field}[{file_index}]",
                )
                raw_path = record.get("installed_path")
                if raw_path is None:
                    raw_path = record.get("path")
                source_path = _rootfs_path(
                    raw_path,
                    f"release inventory.python.distributions[{index}].{field}[{file_index}].path",
                )
                if field == "license_files":
                    license_path = _safe_relative_path(
                        _string(
                            record.get("declared_path"),
                            "release inventory Python declared license path",
                        ),
                        "release inventory Python declared license path",
                    )
                    modern_path = f"{distribution_root}/licenses/{license_path}"
                    legacy_path = f"{distribution_root}/{license_path}"
                    if source_path == modern_path:
                        # Keep every modern license under an outer namespace.
                        # A License-File may itself begin with "legacy-direct",
                        # so no direct-file namespace alone could avoid a
                        # collision with arbitrary valid modern subpaths.
                        archive_suffix = f"licenses/{license_path}"
                    elif "/" not in license_path and source_path == legacy_path:
                        archive_suffix = f"legacy-direct/{license_path}"
                    else:
                        _fail("release inventory has an unsupported Python license path")
                else:
                    modern_prefix = f"{distribution_root}/licenses/"
                    legacy_prefix = f"{distribution_root}/"
                    if source_path.startswith(modern_prefix):
                        license_path = _safe_relative_path(
                            source_path.removeprefix(modern_prefix), "Python license path"
                        )
                        archive_suffix = f"licenses/{license_path}"
                    elif source_path.startswith(legacy_prefix):
                        license_path = _safe_relative_path(
                            source_path.removeprefix(legacy_prefix), "Python legacy license path"
                        )
                        if (
                            "/" in license_path
                            or _LEGACY_NOTICE_FILENAME_PATTERN.fullmatch(license_path) is None
                        ):
                            _fail("release inventory has an unsupported Python license path")
                        archive_suffix = f"legacy-direct/{license_path}"
                    else:
                        _fail("release inventory has an unsupported Python license path")
                kind = _string(
                    record.get("kind"),
                    f"release inventory.python.distributions[{index}].{field}[{file_index}].kind",
                )
                if kind == "missing":
                    if field != "license_files":
                        _fail("release inventory has an unsupported missing Python license file")
                    unresolved.append(
                        {
                            "component": component,
                            "reason": "declared-license-file-missing-from-image",
                            "source_path": source_path,
                        }
                    )
                    continue
                if kind in {"symlink", "hardlink"}:
                    # Python package links can point anywhere in the image. Do
                    # not follow them while producing an evidence archive; make
                    # their omission explicit instead.
                    _string(
                        record.get("link_target"),
                        "release inventory Python linked license target",
                    )
                    unresolved.append(
                        {
                            "component": component,
                            "reason": "linked-python-license-file-not-preserved",
                            "source_path": source_path,
                        }
                    )
                    continue
                if kind != "regular":
                    _fail("release inventory has an unsupported Python license-file kind")
                digest, size = _payload_expectation(
                    record,
                    f"release inventory.python.distributions[{index}].{field}[{file_index}]",
                )
                archive_path = f"notices/python/{name}/{version}/{archive_suffix}"
                _append_expected_file(
                    expected,
                    _ExpectedFile(
                        archive_path=archive_path,
                        component=component,
                        expected_sha256=digest,
                        expected_size=size,
                        role="python-license",
                        source_path=source_path,
                    ),
                )

    unresolved.sort(key=lambda item: (item["component"], item["source_path"]))
    return (
        expected,
        _resolve_debian_links(expected_files=expected, pending_links=pending_debian_links),
        unresolved,
        distro,
    )


def _automatic_file(path: str) -> _ExpectedFile | None:
    if path == _APPLICATION_LICENSE_PATH:
        return _ExpectedFile(
            archive_path="notices/application/LICENSE",
            component="extra-codeowners",
            expected_sha256=None,
            expected_size=None,
            role="application-license",
            source_path=path,
        )
    if _CPYTHON_LICENSE_PATTERN.fullmatch(path) is not None:
        return _ExpectedFile(
            archive_path="notices/cpython/LICENSE.txt",
            component="cpython-runtime",
            expected_sha256=None,
            expected_size=None,
            role="cpython-license",
            source_path=path,
        )
    return None


def _notice_readme(*, architecture: str, distro: str, platform_digest: str) -> bytes:
    return (
        "Extra CODEOWNERS recipient notice bundle\n"
        "\n"
        f"Platform: linux/{architecture}\n"
        f"Distribution: {distro}\n"
        f"Platform digest: {platform_digest}\n"
        "\n"
        "NOTICE-MANIFEST.json maps every preserved file to its path in the exported "
        "runtime filesystem and records its SHA-256 digest. This bundle preserves "
        "notice material from the image. It does not decide whether that material "
        "satisfies a license obligation, and it is not a corresponding-source offer.\n"
    ).encode()


def _tar_regular(archive: tarfile.TarFile, path: str, contents: bytes) -> None:
    info = tarfile.TarInfo(path)
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.size = len(contents)
    archive.addfile(info, io.BytesIO(contents))


def _tar_link(archive: tarfile.TarFile, *, kind: str, path: str, target: str) -> None:
    info = tarfile.TarInfo(path)
    if kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.mode = 0o777
    elif kind == "hardlink":
        info.type = tarfile.LNKTYPE
        info.mode = 0o644
    else:  # pragma: no cover - _ExpectedLink only permits the two inventory kinds.
        _fail(f"unsupported notice link kind {kind!r}")
    info.linkname = target
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info)


def _render_bundle(
    *,
    files: Sequence[_CollectedFile],
    links: Sequence[_ExpectedLink],
    unresolved: Sequence[Mapping[str, str]],
    architecture: str,
    distro: str,
    inventory_sha256: str,
    platform_digest: str,
) -> bytes:
    if len(files) + len(links) + 2 > _MAX_BUNDLE_MEMBERS:
        _fail("notice bundle would exceed its member limit")
    for link in links:
        if link.archive_target_path not in {file.archive_path for file in files}:
            _fail(f"Debian notice link {link.source_path!r} targets absent notice material")
    manifest = {
        "files": [
            {
                "archive_path": file.archive_path,
                "component": file.component,
                "role": file.role,
                "sha256": file.sha256,
                "size": len(file.contents),
                "source_path": file.source_path,
            }
            for file in sorted(files, key=lambda item: item.archive_path)
        ],
        "image": {
            "architecture": architecture,
            "distro": distro,
            "platform_digest": platform_digest,
        },
        "inventory_sha256": inventory_sha256,
        "links": [
            {
                "archive_path": link.archive_path,
                "archive_link_target": link.archive_link_target,
                "archive_target_path": link.archive_target_path,
                "component": link.component,
                "kind": link.kind,
                "source_link_target": link.source_link_target,
                "source_path": link.source_path,
            }
            for link in sorted(links, key=lambda item: item.archive_path)
        ],
        "schema_version": _SCHEMA_VERSION,
        "unresolved_notice_evidence": list(unresolved),
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    readme = _notice_readme(
        architecture=architecture, distro=distro, platform_digest=platform_digest
    )
    if len(manifest_bytes) > _MAX_NOTICE_FILE_BYTES or len(readme) > _MAX_NOTICE_FILE_BYTES:
        _fail("notice bundle control file exceeds its size limit")
    if sum(len(file.contents) for file in files) + len(manifest_bytes) + len(readme) > (
        _MAX_TOTAL_NOTICE_BYTES
    ):
        _fail("notice bundle would exceed its total size limit")
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as gzip_stream:
        bounded_archive = _BoundedArchiveWriter(
            cast(BinaryIO, gzip_stream), limit=_MAX_BUNDLE_ARCHIVE_BYTES
        )
        with tarfile.open(
            fileobj=cast(Any, bounded_archive), mode="w", format=tarfile.PAX_FORMAT
        ) as archive:
            _tar_regular(archive, _NOTICE_MANIFEST, manifest_bytes)
            _tar_regular(archive, _NOTICE_README, readme)
            for file in sorted(files, key=lambda item: item.archive_path):
                _tar_regular(archive, file.archive_path, file.contents)
            for link in sorted(links, key=lambda item: item.archive_path):
                _tar_link(
                    archive,
                    kind=link.kind,
                    path=link.archive_path,
                    target=link.archive_link_target,
                )
    bundle = output.getvalue()
    if len(bundle) > _MAX_BUNDLE_COMPRESSED_BYTES:
        _fail("notice bundle would exceed its compressed size limit")
    return bundle


def build_notice_bundle(
    stream: BinaryIO,
    inventory_bytes: bytes,
    *,
    architecture: str,
    platform_digest: str,
) -> bytes:
    """Create one deterministic notice archive from an exact exported root filesystem."""
    if architecture not in _ARCHITECTURES:
        _fail(f"unsupported architecture: {architecture!r}")
    if _DIGEST_PATTERN.fullmatch(platform_digest) is None:
        _fail("platform digest must be a lowercase sha256 digest")
    try:
        raw_inventory = json.loads(inventory_bytes)
    except json.JSONDecodeError as error:
        raise ReleaseNoticeError(f"could not parse release inventory: {error}") from error
    inventory = _mapping(raw_inventory, "release inventory")
    expected, expected_links, unresolved, distro = _expected_from_inventory(
        inventory, architecture=architecture, platform_digest=platform_digest
    )
    collected: dict[str, _CollectedFile] = {}
    seen_paths: set[str] = set()
    total_size = 0
    cpython_license_count = 0

    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            path = _normalize_member_path(member.name)
            selected_link = expected_links.get(path)
            selected_file = expected.get(path)
            automatic_file = _automatic_file(path)
            if path in seen_paths and (
                selected_link is not None or selected_file is not None or automatic_file is not None
            ):
                _fail(f"root filesystem tar contains duplicate notice path {path!r}")
            if selected_link is not None:
                seen_paths.add(path)
                if (
                    (selected_link.kind == "symlink" and not member.issym())
                    or (selected_link.kind == "hardlink" and not member.islnk())
                    or member.linkname != selected_link.source_link_target
                ):
                    _fail(f"notice source link {path!r} does not match the release inventory")
                continue
            selected = selected_file or automatic_file
            if selected is None:
                continue
            seen_paths.add(path)
            if path in expected and member.issym():
                _fail(f"notice source {path!r} became a symlink")
            contents = _read_member(archive, member)
            total_size += len(contents)
            if total_size > _MAX_TOTAL_NOTICE_BYTES:
                _fail("notice material exceeds its total size limit")
            digest = hashlib.sha256(contents).hexdigest()
            if selected.expected_sha256 is not None and digest != selected.expected_sha256:
                _fail(f"notice source {path!r} does not match the release inventory hash")
            if selected.expected_size is not None and len(contents) != selected.expected_size:
                _fail(f"notice source {path!r} does not match the release inventory size")
            if selected.archive_path in {item.archive_path for item in collected.values()}:
                _fail(
                    "root filesystem produces duplicate notice archive path "
                    f"{selected.archive_path!r}"
                )
            collected[path] = _CollectedFile(
                archive_path=selected.archive_path,
                component=selected.component,
                contents=contents,
                role=selected.role,
                sha256=digest,
                source_path=path,
            )
            if selected.role == "cpython-license":
                cpython_license_count += 1

    missing = sorted(set(expected) - set(collected))
    if missing:
        _fail(f"root filesystem tar omitted notice material: {missing}")
    missing_links = sorted(set(expected_links) - seen_paths)
    if missing_links:
        _fail(f"root filesystem tar omitted notice links: {missing_links}")
    if _APPLICATION_LICENSE_PATH not in collected:
        _fail("root filesystem tar omitted the application license")
    if cpython_license_count != 1:
        _fail("root filesystem tar must contain exactly one CPython license file")
    return _render_bundle(
        files=list(collected.values()),
        links=list(expected_links.values()),
        unresolved=unresolved,
        architecture=architecture,
        distro=distro,
        inventory_sha256=hashlib.sha256(inventory_bytes).hexdigest(),
        platform_digest=platform_digest,
    )


def _read_archive_members(
    bundle: Path,
) -> tuple[Mapping[str, object], Mapping[str, _BundleMember]]:
    try:
        if bundle.stat().st_size > _MAX_BUNDLE_COMPRESSED_BYTES:
            _fail("notice bundle exceeds its compressed size limit")
        with (
            bundle.open("rb") as compressed_file,
            gzip.GzipFile(fileobj=compressed_file, mode="rb") as gzip_stream,
        ):
            bounded_stream = _BoundedDecompressedReader(
                cast(BinaryIO, gzip_stream), limit=_MAX_BUNDLE_ARCHIVE_BYTES
            )
            with tarfile.open(fileobj=cast(Any, bounded_stream), mode="r|") as archive:
                members: dict[str, _BundleMember] = {}
                manifest_bytes: bytes | None = None
                total_size = 0
                for member in archive:
                    if len(members) >= _MAX_BUNDLE_MEMBERS:
                        _fail("notice bundle exceeds its member limit")
                    if not member.isfile() and not member.issym() and not member.islnk():
                        _fail(f"notice bundle member {member.name!r} has an unsupported type")
                    if member.size < 0 or member.size > _MAX_NOTICE_FILE_BYTES:
                        _fail(f"notice bundle member {member.name!r} has an unsafe size")
                    if (member.issym() or member.islnk()) and member.size != 0:
                        _fail(f"notice bundle link {member.name!r} has an unsafe size")
                    total_size += member.size
                    if total_size > _MAX_TOTAL_NOTICE_BYTES:
                        _fail("notice bundle exceeds its total size limit")
                    path = _safe_relative_path(member.name, "notice bundle member path")
                    if member.name != path:
                        _fail(f"notice bundle member {member.name!r} is not canonical")
                    if path in members:
                        _fail(f"notice bundle contains duplicate member {path!r}")
                    if member.isfile():
                        contents = _read_member(archive, member)
                        members[path] = _BundleMember(
                            contents=contents,
                            kind="regular",
                            linkname=None,
                        )
                        if path == _NOTICE_MANIFEST:
                            manifest_bytes = contents
                    elif member.issym():
                        members[path] = _BundleMember(
                            contents=None,
                            kind="symlink",
                            linkname=member.linkname,
                        )
                    else:
                        members[path] = _BundleMember(
                            contents=None,
                            kind="hardlink",
                            linkname=member.linkname,
                        )
                if manifest_bytes is None:
                    _fail("notice bundle omitted its manifest")
            while bounded_stream.read(64 * 1024):
                pass
    except (EOFError, OSError, tarfile.TarError) as error:
        raise ReleaseNoticeError(f"could not read notice bundle {bundle}: {error}") from error
    try:
        parsed = json.loads(manifest_bytes)
    except json.JSONDecodeError as error:
        raise ReleaseNoticeError(f"could not parse notice bundle manifest: {error}") from error
    return _mapping(parsed, "notice bundle manifest"), members


def _expected_manifest_files(
    raw_files: Sequence[object],
    *,
    expected: Mapping[str, _ExpectedFile],
) -> dict[str, Mapping[str, object]]:
    """Validate that the manifest covers the inventory evidence exactly once."""
    records: dict[str, Mapping[str, object]] = {}
    cpython_source: str | None = None
    for index, raw_file in enumerate(raw_files):
        record = _mapping(raw_file, f"notice bundle manifest.files[{index}]")
        source_path = _rootfs_path(
            record.get("source_path"), f"notice bundle manifest.files[{index}].source_path"
        )
        if source_path in records:
            _fail(f"notice bundle manifest repeats source path {source_path!r}")
        selected = expected.get(source_path)
        if selected is None:
            selected = _automatic_file(source_path)
            if selected is None:
                _fail(f"notice bundle manifest includes unrecognized source path {source_path!r}")
            if selected.role == "cpython-license":
                if cpython_source is not None:
                    _fail("notice bundle manifest contains multiple CPython license files")
                cpython_source = source_path
        archive_path = _safe_relative_path(
            _string(
                record.get("archive_path"), f"notice bundle manifest.files[{index}].archive_path"
            ),
            f"notice bundle manifest.files[{index}].archive_path",
        )
        component = _string(
            record.get("component"), f"notice bundle manifest.files[{index}].component"
        )
        role = _string(record.get("role"), f"notice bundle manifest.files[{index}].role")
        if (
            archive_path != selected.archive_path
            or component != selected.component
            or role != selected.role
        ):
            _fail(f"notice bundle manifest has wrong evidence identity for {source_path!r}")
        size = _nonnegative_int(record.get("size"), f"notice bundle manifest.files[{index}].size")
        digest = _sha256(record.get("sha256"), f"notice bundle manifest.files[{index}].sha256")
        if selected.expected_size is not None and size != selected.expected_size:
            _fail(f"notice bundle manifest has wrong evidence size for {source_path!r}")
        if selected.expected_sha256 is not None and digest != selected.expected_sha256:
            _fail(f"notice bundle manifest has wrong evidence digest for {source_path!r}")
        records[source_path] = record

    missing = sorted(set(expected) - set(records))
    if missing:
        _fail(f"notice bundle manifest omitted inventory evidence: {missing}")
    if _APPLICATION_LICENSE_PATH not in records:
        _fail("notice bundle manifest omitted the application license")
    if cpython_source is None:
        _fail("notice bundle manifest omitted the CPython license")
    return records


def _verify_manifest_links(
    raw_links: Sequence[object], *, expected: Mapping[str, _ExpectedLink]
) -> dict[str, Mapping[str, object]]:
    records: dict[str, Mapping[str, object]] = {}
    for index, raw_link in enumerate(raw_links):
        record = _mapping(raw_link, f"notice bundle manifest.links[{index}]")
        source_path = _rootfs_path(
            record.get("source_path"), f"notice bundle manifest.links[{index}].source_path"
        )
        if source_path in records:
            _fail(f"notice bundle manifest repeats source link {source_path!r}")
        selected = expected.get(source_path)
        if selected is None:
            _fail(f"notice bundle manifest includes unrecognized source link {source_path!r}")
        archive_path = _safe_relative_path(
            _string(
                record.get("archive_path"), f"notice bundle manifest.links[{index}].archive_path"
            ),
            f"notice bundle manifest.links[{index}].archive_path",
        )
        component = _string(
            record.get("component"), f"notice bundle manifest.links[{index}].component"
        )
        archive_link_target = _string(
            record.get("archive_link_target"),
            f"notice bundle manifest.links[{index}].archive_link_target",
        )
        archive_target_path = _safe_relative_path(
            _string(
                record.get("archive_target_path"),
                f"notice bundle manifest.links[{index}].archive_target_path",
            ),
            f"notice bundle manifest.links[{index}].archive_target_path",
        )
        kind = _string(record.get("kind"), f"notice bundle manifest.links[{index}].kind")
        source_link_target = _link_target(
            record.get("source_link_target"),
            f"notice bundle manifest.links[{index}].source_link_target",
        )
        if (
            archive_path != selected.archive_path
            or archive_link_target != selected.archive_link_target
            or archive_target_path != selected.archive_target_path
            or component != selected.component
            or kind != selected.kind
            or source_link_target != selected.source_link_target
        ):
            _fail(f"notice bundle manifest has wrong link evidence for {source_path!r}")
        records[source_path] = record
    if set(records) != set(expected):
        _fail("notice bundle manifest links do not cover the release inventory")
    return records


def verify_notice_bundle(
    bundle: Path,
    inventory_bytes: bytes,
    *,
    architecture: str,
    platform_digest: str,
) -> None:
    """Verify a recipient notice bundle against an exact signed inventory identity."""
    if architecture not in _ARCHITECTURES:
        _fail(f"unsupported architecture: {architecture!r}")
    if _DIGEST_PATTERN.fullmatch(platform_digest) is None:
        _fail("platform digest must be a lowercase sha256 digest")
    try:
        raw_inventory = json.loads(inventory_bytes)
    except json.JSONDecodeError as error:
        raise ReleaseNoticeError(f"could not parse release inventory: {error}") from error
    inventory = _mapping(raw_inventory, "release inventory")
    expected_files, expected_links, expected_unresolved, distro = _expected_from_inventory(
        inventory, architecture=architecture, platform_digest=platform_digest
    )
    manifest, members = _read_archive_members(bundle)
    if manifest.get("schema_version") != _SCHEMA_VERSION:
        _fail("notice bundle has an unsupported schema version")
    if manifest.get("inventory_sha256") != hashlib.sha256(inventory_bytes).hexdigest():
        _fail("notice bundle does not bind this release inventory")
    image = _mapping(manifest.get("image"), "notice bundle manifest.image")
    if (
        image.get("architecture") != architecture
        or image.get("distro") != distro
        or image.get("platform_digest") != platform_digest
    ):
        _fail("notice bundle does not bind the requested platform identity")
    files = _sequence(manifest.get("files"), "notice bundle manifest.files")
    links = _sequence(manifest.get("links"), "notice bundle manifest.links")
    unresolved = _sequence(
        manifest.get("unresolved_notice_evidence"),
        "notice bundle manifest.unresolved_notice_evidence",
    )
    if unresolved != expected_unresolved:
        _fail("notice bundle unresolved evidence does not match the release inventory")
    file_records = _expected_manifest_files(files, expected=expected_files)
    link_records = _verify_manifest_links(links, expected=expected_links)
    expected_names = {_NOTICE_MANIFEST, _NOTICE_README}
    readme_member = members.get(_NOTICE_README)
    if readme_member is None or readme_member.kind != "regular" or readme_member.contents is None:
        _fail("notice bundle README is not a regular file")
    expected_readme = _notice_readme(
        architecture=architecture, distro=distro, platform_digest=platform_digest
    )
    if readme_member.contents != expected_readme:
        _fail("notice bundle README does not match its platform identity")
    for record in file_records.values():
        path = _safe_relative_path(
            _string(record.get("archive_path"), "notice bundle manifest file archive_path"),
            "notice bundle manifest file archive_path",
        )
        if path in expected_names:
            _fail(f"notice bundle manifest has duplicate file path {path!r}")
        expected_names.add(path)
        member = members.get(path)
        if member is None or member.kind != "regular" or member.contents is None:
            _fail(f"notice bundle omitted regular file {path!r}")
        if len(member.contents) != _nonnegative_int(
            record.get("size"), f"notice bundle file {path}.size"
        ):
            _fail(f"notice bundle member {path!r} has the wrong size")
        if hashlib.sha256(member.contents).hexdigest() != _sha256(
            record.get("sha256"), f"notice bundle file {path}.sha256"
        ):
            _fail(f"notice bundle member {path!r} has the wrong SHA-256 digest")
    for record in link_records.values():
        path = _safe_relative_path(
            _string(record.get("archive_path"), "notice bundle manifest link archive_path"),
            "notice bundle manifest link archive_path",
        )
        if path in expected_names:
            _fail(f"notice bundle manifest has duplicate link path {path!r}")
        expected_names.add(path)
        link_member = members.get(path)
        kind = _string(record.get("kind"), "notice bundle manifest link kind")
        target = _string(
            record.get("archive_link_target"), "notice bundle manifest link archive target"
        )
        if link_member is None or link_member.kind != kind or link_member.linkname != target:
            _fail(f"notice bundle link {path!r} does not match its manifest")
    if set(members) != expected_names:
        _fail("notice bundle members do not match its manifest")


def _read_bytes(path: Path, description: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise ReleaseNoticeError(f"could not read {description} {path}: {error}") from error


def _open_rootfs(path: str) -> tuple[BinaryIO, bool]:
    if path == "-":
        return sys.stdin.buffer, False
    return Path(path).open("rb"), True


def _write_bundle(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    path.chmod(0o444)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="build or verify deterministic recipient notice bundles for release images"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    build = subcommands.add_parser(
        "build", help="build one notice bundle from an exported root filesystem"
    )
    build.add_argument("--architecture", choices=sorted(_ARCHITECTURES), required=True)
    build.add_argument("--platform-digest", required=True)
    build.add_argument("--inventory", required=True)
    build.add_argument("--rootfs-tar", required=True)
    build.add_argument("--output", required=True)
    verify = subcommands.add_parser("verify", help="verify one notice bundle against an inventory")
    verify.add_argument("--architecture", choices=sorted(_ARCHITECTURES), required=True)
    verify.add_argument("--platform-digest", required=True)
    verify.add_argument("--inventory", required=True)
    verify.add_argument("--bundle", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the notice-bundle command without executing image content."""
    parsed = _build_parser().parse_args(arguments)
    try:
        inventory_bytes = _read_bytes(Path(parsed.inventory), "release inventory")
        if parsed.command == "build":
            stream, close_stream = _open_rootfs(parsed.rootfs_tar)
            try:
                bundle = build_notice_bundle(
                    stream,
                    inventory_bytes,
                    architecture=parsed.architecture,
                    platform_digest=parsed.platform_digest,
                )
            finally:
                if close_stream:
                    stream.close()
            _write_bundle(Path(parsed.output), bundle)
        else:
            verify_notice_bundle(
                Path(parsed.bundle),
                inventory_bytes,
                architecture=parsed.architecture,
                platform_digest=parsed.platform_digest,
            )
    except (OSError, ReleaseNoticeError, tarfile.TarError) as error:
        sys.stderr.write(f"release notice error: {error}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
