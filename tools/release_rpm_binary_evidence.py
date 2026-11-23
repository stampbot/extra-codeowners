"""Bind a reviewed RPM origin to the wheel files and source already verified."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import PurePosixPath
from typing import Any

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RPM_PATH = re.compile(r"/(?:usr/)?lib64/([A-Za-z0-9_+-]+)\.so\.[A-Za-z0-9.]+\Z")
_LICENSE_PATH = re.compile(r"/usr/share/licenses/[A-Za-z0-9_.+/-]+\Z")
_WHEEL_PATH = re.compile(r"opt/venv/lib/python3\.[0-9]+/site-packages/psycopg_binary\.libs/")


class RpmBinaryEvidenceError(ValueError):
    """The binary attribution requires review for this release."""


def _checksum(value: object) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise RpmBinaryEvidenceError("invalid RPM evidence checksum")
    return value


def _locked_wheel(platform: dict[str, Any], lock: bytes, wheel_version: str) -> None:
    filename = platform["wheel_filename"]
    digest = _checksum(platform["wheel_sha256"])
    packages = [
        package
        for package in tomllib.loads(lock.decode())["package"]
        if package["name"] == "psycopg-binary" and package.get("version") == wheel_version
    ]
    if len(packages) != 1 or not any(
        wheel["url"].rsplit("/", 1)[-1] == filename and wheel["hash"] == f"sha256:{digest}"
        for wheel in packages[0]["wheels"]
    ):
        raise RpmBinaryEvidenceError("reviewed binary RPM evidence needs the locked Psycopg wheel")


def _shipped_files(native_files: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    for file in native_files:
        path = file["path"]
        prefix = _WHEEL_PATH.match(path)
        if prefix is None:
            continue
        basename = path[prefix.end() :]
        if not basename or "/" in basename or basename in files:
            raise RpmBinaryEvidenceError("ambiguous shipped Psycopg library")
        files[basename] = file
    return files


def _check_file(
    filename: str, evidence: dict[str, Any], shipped: dict[str, Any] | None, purl: str
) -> str:
    rpm_path = evidence["rpm_path"]
    match = _RPM_PATH.fullmatch(rpm_path)
    if match is None:
        raise RpmBinaryEvidenceError("invalid RPM library path")
    original_basename = PurePosixPath(rpm_path).name
    basename, suffix = original_basename.split(".so.", 1)
    prefix = _checksum(evidence["original_sha256"])[:8]
    if filename != f"{basename}-{prefix}.so.{suffix}":
        raise RpmBinaryEvidenceError("RPM original hash does not match the grafted name")
    digest = _checksum(evidence["sha256"])
    size = evidence["size"]
    if (
        shipped is None
        or shipped["kind"] != "regular"
        or (shipped["sha256"], shipped["size"]) != (digest, size)
        or type(size) is not int
        or size <= 0
    ):
        raise RpmBinaryEvidenceError(f"shipped library needs RPM evidence review: {filename}")
    # The two reviewed wheels use /lib64 after resolving the builder's lib64 layout.
    path_digest = hashlib.sha256(f"/lib64/{original_basename}".encode()).hexdigest()
    return f"{purl}#{path_digest}"


def _rpm_references(sbom: dict[str, Any]) -> set[str]:
    refs = [item["bom-ref"] for item in sbom["components"] if item["purl"].startswith("pkg:rpm/")]
    if not refs or len(refs) != len(set(refs)):
        raise RpmBinaryEvidenceError("invalid wheel RPM component references")
    return set(refs)


def review(
    platform: dict[str, Any],
    lock: bytes,
    sbom: bytes,
    native_files: list[dict[str, Any]],
    distribution_version: str,
) -> dict[str, dict[str, Any]]:
    """Verify that every RPM declaration maps to one named, hashed wheel file."""
    if hashlib.sha256(sbom).hexdigest() != _checksum(platform["wheel_sbom_sha256"]):
        raise RpmBinaryEvidenceError("the Psycopg wheel SBOM needs RPM evidence review")
    declaration = json.loads(sbom)
    basename = platform["wheel_filename"]
    parent = declaration["metadata"]["component"]["purl"]
    if parent != f"pkg:pypi/psycopg_binary@{distribution_version}?file_name={basename}":
        raise RpmBinaryEvidenceError("wheel SBOM filename differs from reviewed RPM evidence")
    _locked_wheel(platform, lock, distribution_version)
    remaining = _rpm_references(declaration)
    shipped = _shipped_files(native_files)
    consumed: set[str] = set()
    for purl, package in platform["packages"].items():
        if not package["files"]:
            raise RpmBinaryEvidenceError("RPM attribution is missing every file")
        for filename, evidence in package["files"].items():
            ref = _check_file(filename, evidence, shipped.get(filename), purl)
            if filename in consumed or ref not in remaining:
                raise RpmBinaryEvidenceError("duplicate or unreported RPM library")
            remaining.remove(ref)
            consumed.add(filename)
    if remaining:
        raise RpmBinaryEvidenceError("wheel SBOM has unmapped RPM library references")
    packages: dict[str, dict[str, Any]] = platform["packages"]
    return packages


def package_properties(
    package: dict[str, Any], source: dict[str, Any], selected_notices: list[dict[str, Any]]
) -> dict[str, str]:
    """Keep vendor declarations distinct from a binary license conclusion."""
    if (package["source_archive"], _checksum(package["source_sha256"])) != (
        source["path"],
        source["sha256"],
    ):
        raise RpmBinaryEvidenceError("binary RPM names a different source RPM")
    notice_hashes = {notice["sha256"] for notice in selected_notices}
    for path, checksum in package["notices"].items():
        if (
            not _LICENSE_PATH.fullmatch(path)
            or any(part in {"", ".", ".."} for part in path[1:].split("/"))
            or _checksum(checksum) not in notice_hashes
        ):
            raise RpmBinaryEvidenceError("vendor RPM notice does not match a selected source file")
    return {
        "identity-evidence": "reviewed vendor binary RPM and wheel file bindings",
        "binary-rpm-filename": package["rpm_filename"],
        "binary-rpm-sha256": _checksum(package["rpm_sha256"]),
        "binary-rpm-declared-license": package["rpm_declared_license"],
        "binary-rpm-license-files": json.dumps(package["notices"], sort_keys=True),
        "binary-rpm-library-bindings": json.dumps(package["files"], sort_keys=True),
    }
