"""Collect a deterministic raw inventory from an exported OCI root filesystem.

The inventory records what the release image contains. It deliberately does not
decide whether a component's metadata satisfies a notice or source obligation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from email.message import Message
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final, NoReturn

SCHEMA_VERSION: Final = 2
_PLATFORM_DIGEST_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ARCHITECTURES: Final = frozenset(("amd64", "arm64"))
_SITE_PACKAGES_PATTERN: Final = re.compile(r"\Aopt/venv/lib/python\d+\.\d+/site-packages/")
_METADATA_PATTERN: Final = re.compile(
    r"\Aopt/venv/lib/python\d+\.\d+/site-packages/(?P<distribution>[^/]+\.dist-info)/METADATA\Z"
)
_LICENSE_PATTERN: Final = re.compile(
    r"\Aopt/venv/lib/python\d+\.\d+/site-packages/(?P<distribution>[^/]+\.dist-info)/"
    r"licenses/(?P<license_path>.+)\Z"
)
_SBOM_PATTERN: Final = re.compile(
    r"\Aopt/venv/lib/python\d+\.\d+/site-packages/(?P<distribution>[^/]+\.dist-info)/"
    r"sboms/(?P<sbom_path>.+\.json)\Z"
)
_NATIVE_LIBRARY_PATTERN: Final = re.compile(r"\.so(?:\..+)?\Z")
_COPYRIGHT_PATTERN: Final = re.compile(r"\Ausr/share/doc/(?P<package>[^/]+)/copyright\Z")
_COMMON_LICENSE_PATTERN: Final = re.compile(r"\Ausr/share/common-licenses/(?P<name>[^/]+)\Z")
_MAX_STATUS_BYTES: Final = 4 * 1024 * 1024
_MAX_OS_RELEASE_BYTES: Final = 64 * 1024
_MAX_METADATA_BYTES: Final = 1024 * 1024
_MAX_AUXILIARY_FILE_BYTES: Final = 64 * 1024 * 1024
_MAX_COMPONENTS: Final = 10_000


class InventoryError(ValueError):
    """Raised when an exported filesystem cannot produce an unambiguous inventory."""


@dataclass(frozen=True, slots=True)
class _Payload:
    """One selected filesystem entry, without resolving links from the artifact."""

    kind: str
    link_target: str | None
    sha256: str | None
    size: int | None


@dataclass(slots=True)
class _Distribution:
    directory: str
    metadata_path: str
    metadata_sha256: str
    metadata_size: int
    name: str
    normalized_name: str
    version: str
    metadata_version: str
    license_expressions: tuple[str, ...]
    legacy_licenses: tuple[str, ...]
    declared_license_files: tuple[str, ...]
    licenses: dict[str, _Payload] = field(default_factory=dict)
    sboms: dict[str, _Payload] = field(default_factory=dict)


def _fail(message: str) -> NoReturn:
    raise InventoryError(message)


def _normalize_member_path(name: str) -> str:
    if "\x00" in name:
        _fail("root filesystem tar contains a NUL in a member path")
    path = PurePosixPath(name)
    if path.is_absolute():
        _fail(f"root filesystem tar contains an absolute member path: {name!r}")
    parts = tuple(part for part in path.parts if part != ".")
    if not parts or any(part == ".." for part in parts):
        _fail(f"root filesystem tar contains an unsafe member path: {name!r}")
    return "/".join(parts)


def _read_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    limit: int,
    contents: bool,
) -> tuple[int, str, bytes | None]:
    if not member.isfile():
        _fail(f"inventory member {member.name!r} is not a regular file")
    if member.size < 0 or member.size > limit:
        _fail(f"inventory member {member.name!r} has an unsafe size")
    extracted = archive.extractfile(member)
    if (
        extracted is None
    ):  # pragma: no cover - tarfile documents this as impossible for regular files.
        _fail(f"could not read inventory member {member.name!r}")

    digest = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    while chunk := extracted.read(64 * 1024):
        total += len(chunk)
        if total > limit:
            _fail(f"inventory member {member.name!r} exceeded its size limit")
        digest.update(chunk)
        if contents:
            chunks.append(chunk)
    if total != member.size:
        _fail(f"inventory member {member.name!r} changed while it was read")
    return total, digest.hexdigest(), b"".join(chunks) if contents else None


def _link_target(member: tarfile.TarInfo) -> str:
    target = member.linkname
    if not target or "\x00" in target or "\n" in target or "\r" in target:
        _fail(f"inventory link {member.name!r} has an unsafe target")
    if len(target) > 4096:
        _fail(f"inventory link {member.name!r} has an oversized target")
    return target


def _read_auxiliary_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> _Payload:
    if member.isfile():
        size, sha256, _ = _read_member(
            archive, member, limit=_MAX_AUXILIARY_FILE_BYTES, contents=False
        )
        return _Payload(kind="regular", link_target=None, sha256=sha256, size=size)
    if member.issym():
        return _Payload(kind="symlink", link_target=_link_target(member), sha256=None, size=None)
    if member.islnk():
        return _Payload(kind="hardlink", link_target=_link_target(member), sha256=None, size=None)
    return _fail(f"inventory member {member.name!r} is not a regular file or link")


def _plain_header(message: Message, field: str, *, required: bool = False) -> str:
    value = message.get(field)
    if value is None:
        if required:
            _fail(f"Python distribution metadata omitted {field}")
        return ""
    if not isinstance(value, str):  # pragma: no cover - email's public API returns str.
        _fail(f"Python distribution metadata has an invalid {field}")
    normalized = value.strip()
    if not normalized or "\x00" in normalized or "\n" in normalized or "\r" in normalized:
        _fail(f"Python distribution metadata has an unsafe {field}")
    if len(normalized) > 4096:
        _fail(f"Python distribution metadata has an oversized {field}")
    return normalized


def _plain_headers(message: Message, field: str) -> tuple[str, ...]:
    values = message.get_all(field, [])
    if not isinstance(values, list):  # pragma: no cover - email's public API returns list[str].
        _fail(f"Python distribution metadata has an invalid {field}")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):  # pragma: no cover - email's public API returns str.
            _fail(f"Python distribution metadata has an invalid {field}")
        item = value.strip()
        if not item:
            continue
        if "\x00" in item or "\n" in item or "\r" in item or len(item) > 4096:
            _fail(f"Python distribution metadata has an unsafe {field}")
        normalized.append(item)
    return tuple(normalized)


def _normalized_distribution_name(name: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", normalized):
        _fail(f"Python distribution name is invalid: {name!r}")
    return normalized


def _license_file_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {".", ".."} for part in path.parts):
        _fail(f"Python distribution metadata has an unsafe License-File path: {value!r}")
    return "/".join(path.parts)


def _parse_distribution(
    *,
    path: str,
    directory: str,
    metadata: bytes,
    metadata_size: int,
    metadata_sha256: str,
) -> _Distribution:
    parsed = BytesParser().parsebytes(metadata)
    name = _plain_header(parsed, "Name", required=True)
    version = _plain_header(parsed, "Version", required=True)
    metadata_version = _plain_header(parsed, "Metadata-Version", required=True)
    declared_license_files = tuple(
        _license_file_path(value) for value in _plain_headers(parsed, "License-File")
    )
    if len(set(declared_license_files)) != len(declared_license_files):
        _fail(f"Python distribution {name!r} declares a license file more than once")
    return _Distribution(
        directory=directory,
        metadata_path=path,
        metadata_sha256=metadata_sha256,
        metadata_size=metadata_size,
        name=name,
        normalized_name=_normalized_distribution_name(name),
        version=version,
        metadata_version=metadata_version,
        license_expressions=_plain_headers(parsed, "License-Expression"),
        legacy_licenses=_plain_headers(parsed, "License"),
        declared_license_files=declared_license_files,
    )


def _parse_debian_status(status: bytes) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    for stanza in status.split(b"\n\n"):
        if not stanza.strip():
            continue
        parsed = BytesParser().parsebytes(stanza + b"\n")
        if _plain_header(parsed, "Status", required=True) != "install ok installed":
            continue
        package = _plain_header(parsed, "Package", required=True)
        version = _plain_header(parsed, "Version", required=True)
        architecture = _plain_header(parsed, "Architecture", required=True)
        source = _plain_header(parsed, "Source") or package
        packages.append(
            {
                "architecture": architecture,
                "package": package,
                "source": source,
                "version": version,
            }
        )
    if not packages:
        _fail("Debian status file contains no installed packages")
    packages.sort(key=lambda item: (item["package"], item["architecture"], item["version"]))
    package_keys = [(item["package"], item["architecture"]) for item in packages]
    if len(package_keys) != len(set(package_keys)):
        _fail("Debian status file contains duplicate installed package records")
    return packages


def _os_release_value(value: str, field: str) -> str:
    value = value.strip()
    if value.startswith('"'):
        if len(value) < 2 or not value.endswith('"'):
            _fail(f"os-release has an unterminated {field} value")
        value = value[1:-1]
    elif value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            _fail(f"os-release has an unterminated {field} value")
        value = value[1:-1]
    if not value or "\\" in value or "\x00" in value or "\n" in value or "\r" in value:
        _fail(f"os-release has an unsafe {field} value")
    return value


def _parse_debian_distro(os_release: bytes) -> str:
    try:
        content = os_release.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InventoryError(f"could not decode os-release: {error}") from error

    fields: dict[str, str] = {}
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if key not in {"ID", "VERSION_ID"}:
            continue
        if not separator or key in fields:
            _fail(f"os-release has an invalid {key or 'required'} field")
        fields[key] = _os_release_value(value, key)

    distribution_id = fields.get("ID")
    version_id = fields.get("VERSION_ID")
    if distribution_id != "debian":
        _fail(f"release inventory requires Debian os-release ID, got {distribution_id!r}")
    if version_id is None or re.fullmatch(r"[0-9]+", version_id) is None:
        _fail("os-release has an invalid VERSION_ID")
    return f"{distribution_id}-{version_id}"


def _payload_record(path: str, payload: _Payload) -> dict[str, object]:
    return {
        "kind": payload.kind,
        "link_target": payload.link_target,
        "path": path,
        "sha256": payload.sha256,
        "size": payload.size,
    }


def collect_inventory(
    stream: BinaryIO,
    *,
    architecture: str,
    platform_digest: str,
) -> dict[str, object]:
    """Return canonical raw package evidence from a Docker-export root filesystem."""
    if architecture not in _ARCHITECTURES:
        _fail(f"unsupported architecture: {architecture!r}")
    if _PLATFORM_DIGEST_PATTERN.fullmatch(platform_digest) is None:
        _fail("platform digest must be a lowercase sha256 digest")

    status: tuple[int, str, bytes] | None = None
    os_release: tuple[int, str, bytes] | None = None
    distributions: dict[str, _Distribution] = {}
    pending_licenses: dict[str, dict[str, _Payload]] = {}
    pending_sboms: dict[str, dict[str, _Payload]] = {}
    native_files: list[dict[str, object]] = []
    copyright_files: list[dict[str, object]] = []
    common_license_files: list[dict[str, object]] = []
    seen_selected_paths: set[str] = set()

    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            path = _normalize_member_path(member.name)
            metadata_match = _METADATA_PATTERN.fullmatch(path)
            license_match = _LICENSE_PATTERN.fullmatch(path)
            sbom_match = _SBOM_PATTERN.fullmatch(path)
            copyright_match = _COPYRIGHT_PATTERN.fullmatch(path)
            common_license_match = _COMMON_LICENSE_PATTERN.fullmatch(path)
            site_match = _SITE_PACKAGES_PATTERN.match(path)
            native = site_match is not None and _NATIVE_LIBRARY_PATTERN.search(path) is not None
            selected = any(
                (
                    metadata_match is not None,
                    license_match is not None,
                    sbom_match is not None,
                    copyright_match is not None,
                    common_license_match is not None,
                    native,
                    path == "usr/lib/os-release",
                    path == "var/lib/dpkg/status",
                )
            )
            if not selected:
                continue
            if path in seen_selected_paths:
                _fail(f"root filesystem tar contains duplicate inventory path {path!r}")
            seen_selected_paths.add(path)

            if path == "usr/lib/os-release":
                if os_release is not None:
                    _fail("root filesystem tar contains more than one os-release file")
                size, digest, contents = _read_member(
                    archive, member, limit=_MAX_OS_RELEASE_BYTES, contents=True
                )
                if contents is None:  # pragma: no cover - requested contents always returns bytes.
                    _fail("could not read os-release file")
                os_release = (size, digest, contents)
            elif path == "var/lib/dpkg/status":
                if status is not None:
                    _fail("root filesystem tar contains more than one Debian status file")
                size, digest, contents = _read_member(
                    archive, member, limit=_MAX_STATUS_BYTES, contents=True
                )
                if contents is None:  # pragma: no cover - requested contents always returns bytes.
                    _fail("could not read Debian status file")
                status = (size, digest, contents)
            elif metadata_match is not None:
                directory = metadata_match.group("distribution")
                if directory in distributions:
                    _fail(f"root filesystem has duplicate Python metadata for {directory!r}")
                size, digest, contents = _read_member(
                    archive, member, limit=_MAX_METADATA_BYTES, contents=True
                )
                if contents is None:  # pragma: no cover - requested contents always returns bytes.
                    _fail(f"could not read Python metadata for {directory!r}")
                distribution = _parse_distribution(
                    path=path,
                    directory=directory,
                    metadata=contents,
                    metadata_size=size,
                    metadata_sha256=digest,
                )
                distribution.licenses.update(pending_licenses.pop(directory, {}))
                distribution.sboms.update(pending_sboms.pop(directory, {}))
                distributions[directory] = distribution
            else:
                payload = _read_auxiliary_member(archive, member)
                if license_match is not None:
                    directory = license_match.group("distribution")
                    licenses = distributions.get(directory)
                    if licenses is None:
                        pending_licenses.setdefault(directory, {})[
                            license_match.group("license_path")
                        ] = payload
                    else:
                        licenses.licenses[license_match.group("license_path")] = payload
                elif sbom_match is not None:
                    directory = sbom_match.group("distribution")
                    sboms = distributions.get(directory)
                    if sboms is None:
                        pending_sboms.setdefault(directory, {})[sbom_match.group("sbom_path")] = (
                            payload
                        )
                    else:
                        sboms.sboms[sbom_match.group("sbom_path")] = payload
                elif copyright_match is not None:
                    copyright_files.append(
                        {
                            "package": copyright_match.group("package"),
                            **_payload_record(path, payload),
                        }
                    )
                elif common_license_match is not None:
                    common_license_files.append(
                        {
                            "name": common_license_match.group("name"),
                            **_payload_record(path, payload),
                        }
                    )
                elif native:
                    native_files.append(_payload_record(path, payload))

    if status is None:
        _fail("root filesystem tar omitted var/lib/dpkg/status")
    if os_release is None:
        _fail("root filesystem tar omitted usr/lib/os-release")
    orphaned_directories = sorted(set(pending_licenses) | set(pending_sboms))
    if orphaned_directories:
        _fail(
            f"Python distributions have licenses or SBOMs but no METADATA: {orphaned_directories}"
        )
    if not distributions:
        _fail("root filesystem tar contains no Python distribution metadata")
    if len(distributions) > _MAX_COMPONENTS:
        _fail("root filesystem tar exceeds the Python distribution limit")
    complete_distributions = list(distributions.values())
    complete_distributions.sort(
        key=lambda item: (item.normalized_name, item.version, item.directory)
    )
    normalized_names = [item.normalized_name for item in complete_distributions]
    if len(normalized_names) != len(set(normalized_names)):
        _fail("root filesystem has duplicate normalized Python distribution names")

    distribution_records: list[dict[str, object]] = []
    for distribution in complete_distributions:
        distribution_root = distribution.metadata_path.rsplit("/", maxsplit=1)[0]
        license_files: list[dict[str, object]] = []
        for declared_path in distribution.declared_license_files:
            installed = distribution.licenses.get(declared_path)
            record: dict[str, object] = {
                "declared_path": declared_path,
                "installed_path": f"{distribution_root}/licenses/{declared_path}",
                "kind": "missing",
                "link_target": None,
                "sha256": None,
                "size": None,
            }
            if installed is not None:
                record.update(
                    {
                        "kind": installed.kind,
                        "link_target": installed.link_target,
                        "sha256": installed.sha256,
                        "size": installed.size,
                    }
                )
            license_files.append(record)
        extra_license_files = sorted(
            path
            for path in distribution.licenses
            if path not in distribution.declared_license_files
        )
        distribution_records.append(
            {
                "directory": distribution.directory,
                "legacy_license": list(distribution.legacy_licenses),
                "license_expression": list(distribution.license_expressions),
                "license_files": license_files,
                "metadata_path": distribution.metadata_path,
                "metadata_sha256": distribution.metadata_sha256,
                "metadata_size": distribution.metadata_size,
                "metadata_version": distribution.metadata_version,
                "name": distribution.name,
                "normalized_name": distribution.normalized_name,
                "unreferenced_license_files": [
                    _payload_record(
                        f"{distribution_root}/licenses/{path}", distribution.licenses[path]
                    )
                    for path in extra_license_files
                ],
                "version": distribution.version,
            }
        )

    embedded_sboms = [
        {
            "distribution": distribution.normalized_name,
            **_payload_record(
                f"{distribution.metadata_path.rsplit('/', maxsplit=1)[0]}/sboms/{path}",
                distribution.sboms[path],
            ),
        }
        for distribution in complete_distributions
        for path in sorted(distribution.sboms)
    ]
    native_files.sort(key=lambda item: str(item["path"]))
    copyright_files.sort(key=lambda item: (str(item["package"]), str(item["path"])))
    common_license_files.sort(key=lambda item: str(item["name"]))
    os_release_size, os_release_sha256, os_release_contents = os_release
    status_size, status_sha256, status_contents = status

    return {
        "debian": {
            "copyright_files": copyright_files,
            "packages": _parse_debian_status(status_contents),
            "shared_license_files": common_license_files,
            "status_path": "var/lib/dpkg/status",
            "status_sha256": status_sha256,
            "status_size": status_size,
        },
        "image": {
            "architecture": architecture,
            "distro": _parse_debian_distro(os_release_contents),
            "os_release_path": "usr/lib/os-release",
            "os_release_sha256": os_release_sha256,
            "os_release_size": os_release_size,
            "platform_digest": platform_digest,
        },
        "python": {
            "distributions": distribution_records,
            "embedded_sboms": embedded_sboms,
            "native_files": native_files,
        },
        "schema_version": SCHEMA_VERSION,
    }


def render_inventory(inventory: dict[str, object]) -> str:
    """Render a canonical JSON inventory suitable for signing and release assets."""
    return json.dumps(inventory, indent=2, sort_keys=True) + "\n"


def _open_input(path: str) -> tuple[BinaryIO, bool]:
    if path == "-":
        return sys.stdin.buffer, False
    return Path(path).open("rb"), True


def _write_output(path: str | None, content: str) -> None:
    if path is None or path == "-":
        sys.stdout.write(content)
        return
    destination = Path(path)
    destination.write_text(content, encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="collect a deterministic raw inventory from a Docker-export root filesystem"
    )
    parser.add_argument("--architecture", choices=sorted(_ARCHITECTURES), required=True)
    parser.add_argument("--platform-digest", required=True)
    parser.add_argument(
        "--rootfs-tar",
        required=True,
        help="Docker-export tar path, or - to read the export from standard input",
    )
    parser.add_argument("--output", help="JSON output path, or - for standard output")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the command-line collector without executing content from the image."""
    parsed = _parser().parse_args(arguments)
    stream, close_stream = _open_input(parsed.rootfs_tar)
    try:
        inventory = collect_inventory(
            stream,
            architecture=parsed.architecture,
            platform_digest=parsed.platform_digest,
        )
    except (InventoryError, OSError, tarfile.TarError) as error:
        sys.stderr.write(f"release inventory error: {error}\n")
        return 2
    finally:
        if close_stream:
            stream.close()
    _write_output(parsed.output, render_inventory(inventory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
