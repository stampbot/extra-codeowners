"""Catalog reviewed C-library identities from wheel SBOMs and source recipes.

This offline catalog supplements the image SBOM. It can include reviewed
source license texts. It does not conclude binary licenses, prove exact
upstream build inputs, or assess vulnerability reachability.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import quote, unquote

MAX_METADATA = 4 * 1024 * 1024
MAX_COMPONENTS = 128
_WHEELS = frozenset({"cryptography", "psycopg-binary"})
_RPM_PURL = re.compile(r"pkg:rpm/(?:centos|almalinux)/([^/@?#]+)@([^/?#]+)\Z")
_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!~%-]{0,199}\Z")
_NOTICE_PATH = re.compile(r"[A-Za-z0-9_.+/-]{1,512}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RPM_NOTICE_RECEIPT = Path(__file__).with_name("release_rpm_notice_evidence.json")
_RPM_BINARY_RECEIPT = Path(__file__).with_name("release_rpm_binary_evidence.json")
_STATIC_WHEEL_RECEIPT = Path(__file__).with_name("release_crypto_static_evidence.json")
_STATIC_EXTENSION = "cryptography/hazmat/bindings/_rust.abi3.so"


class NativeComponentError(ValueError):
    """The selected wheel, source recipe or retained evidence disagrees."""


def _sibling(name: str) -> ModuleType:
    module_name = f"_extra_codeowners_native_{name}"
    spec = importlib.util.spec_from_file_location(
        module_name, Path(__file__).resolve().with_name(f"{name}.py")
    )
    if spec is None or spec.loader is None:
        raise NativeComponentError("could not load the evidence verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_python = _sibling("release_python_sources")
_notices = _sibling("release_notices")
_native_notices = _sibling("release_native_notices")
_rpm_binaries = _sibling("release_rpm_binary_evidence")


def _json(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = _python._json(data)
    return result


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise NativeComponentError("component metadata exceeds its size limit")
    return data


def _properties(values: dict[str, str]) -> list[dict[str, str]]:
    return [
        {"name": f"extra-codeowners:{name}", "value": value}
        for name, value in sorted(values.items())
    ]


def _identity(value: object) -> str:
    if not isinstance(value, str) or _TEXT.fullmatch(value) is None:
        raise NativeComponentError("invalid native component identity")
    return value


def _relative_notice_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or _NOTICE_PATH.fullmatch(value) is None
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise NativeComponentError("invalid RPM notice member path")
    return value


def _rpm_notice_files(archives: dict[str, Any], source: dict[str, Any]) -> list[dict[str, Any]]:
    """Use a receipt only for the SRPM bytes and reported package it records."""
    entry = archives.get(source["path"])
    if (
        not isinstance(entry, dict)
        or set(entry) != {"archive_sha256", "reported_package", "files"}
        or entry["archive_sha256"] != source["sha256"]
        or entry["reported_package"] != source["reported_package"]
    ):
        raise NativeComponentError(f"RPM source notice needs review: {source['path']}")
    files = entry["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= 32:
        raise NativeComponentError("invalid RPM notice file list")
    seen = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"member", "path", "size", "sha256"}:
            raise NativeComponentError("invalid RPM notice file record")
        member = _relative_notice_path(item["member"])
        path = _relative_notice_path(item["path"])
        identity = member, path
        if identity in seen:
            raise NativeComponentError("duplicate RPM notice path")
        seen.add(identity)
        size, checksum = item["size"], item["sha256"]
        if type(size) is not int or not 0 < size <= _native_notices.MAX_NOTICE:
            raise NativeComponentError("invalid RPM notice size")
        if not isinstance(checksum, str) or _SHA256.fullmatch(checksum) is None:
            raise NativeComponentError("invalid RPM notice checksum")
    return sorted(files, key=lambda item: (item["member"], item["path"]))


def _rpm_notice_receipt(path: Path) -> tuple[dict[str, Any], str]:
    data = _read(path)
    record = _json(data)
    archives = record.get("archives")
    if (
        set(record) != {"schema_version", "archives"}
        or type(record["schema_version"]) is not int
        or record["schema_version"] != 1
        or not isinstance(archives, dict)
        or not 1 <= len(archives) <= MAX_COMPONENTS
    ):
        raise NativeComponentError("invalid RPM notice receipt")
    return archives, hashlib.sha256(data).hexdigest()


def _reported_components(
    source_plan: dict[str, Any], notice_files: dict[str, bytes]
) -> tuple[dict[tuple[str, str, str], str], bytes | None]:
    """Keep only the exact reviewed C-library SBOMs, not unrelated build SBOMs."""
    sources = [*source_plan["native_sources"], *source_plan["embedded_sources"]]
    expected = {(source["distribution"], source["sbom_sha256"]) for source in sources}
    wheel_versions = {source["distribution"]: source["distribution_version"] for source in sources}
    manifest = _json(notice_files["NOTICE-MANIFEST.json"])
    found: set[tuple[str, str]] = set()
    result: dict[tuple[str, str, str], str] = {}
    rpm_sbom: bytes | None = None
    for notice in manifest["files"]:
        if notice["role"] != "python-embedded-sbom":
            continue
        distribution = notice["component"].removeprefix("pypi:").partition("@")[0]
        key = (distribution, notice["sha256"])
        if key not in expected:
            continue
        if key in found:
            raise NativeComponentError("ambiguous reviewed wheel SBOM")
        found.add(key)
        data = notice_files[notice["archive_path"]]
        if distribution == "psycopg-binary":
            if rpm_sbom is not None:
                raise NativeComponentError("ambiguous RPM wheel SBOM")
            rpm_sbom = data
        sbom = _json(data)
        components = sbom.get("components")
        if (
            sbom.get("bomFormat") != "CycloneDX"
            or sbom.get("specVersion") not in {"1.4", "1.5"}
            or not isinstance(components, list)
            or not 1 <= len(components) <= MAX_COMPONENTS
        ):
            raise NativeComponentError("unsupported reviewed wheel SBOM")
        for component in components:
            if not isinstance(component, dict) or component.get("type") != "library":
                raise NativeComponentError("invalid declared native component")
            name, version = _identity(component.get("name")), _identity(component.get("version"))
            purl = component.get("purl")
            if not isinstance(purl, str) or len(purl) > 2048:
                raise NativeComponentError("native declaration omitted its package URL")
            if distribution == "psycopg-binary" and name == "psycopg_binary":
                if (
                    version != wheel_versions[distribution]
                    or purl.partition("?")[0] != f"pkg:pypi/psycopg_binary@{version}"
                ):
                    raise NativeComponentError("SBOM parent differs from the reviewed wheel")
                continue
            if distribution == "psycopg-binary":
                match = _RPM_PURL.fullmatch(purl)
                if match is None or tuple(map(unquote, match.groups())) != (name, version):
                    raise NativeComponentError("RPM package URL disagrees with its declaration")
            elif name != "openssl" or not purl.startswith(f"pkg:generic/openssl@{version}?"):
                raise NativeComponentError("unreviewed Cryptography native component")
            identity = (distribution, name, version)
            if identity in result and result[identity] != purl:
                raise NativeComponentError("conflicting declared package URLs")
            result[identity] = purl
    if found != expected:
        raise NativeComponentError("notice bundle omitted a reviewed native SBOM")
    return result, rpm_sbom


def _rpm_binary_packages(
    receipt: Path,
    architecture: str,
    lock: bytes,
    sbom: bytes | None,
    python: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], str]:
    data = _read(receipt)
    record = _json(data)
    platforms = record.get("platforms")
    if (
        type(record.get("schema_version")) is not int
        or record["schema_version"] != 1
        or not isinstance(platforms, dict)
        or architecture not in platforms
        or sbom is None
    ):
        raise NativeComponentError("binary RPM evidence needs a supported receipt and wheel SBOM")
    version = next(
        item["version"]
        for item in python["distributions"]
        if item["normalized_name"] == "psycopg-binary"
    )
    packages: dict[str, dict[str, Any]] = _rpm_binaries.review(
        platforms[architecture], lock, sbom, python["native_files"], version
    )
    return packages, hashlib.sha256(data).hexdigest()


def _require_locked_crypto_wheel(lock: bytes, version: str, filename: str, digest: str) -> None:
    packages = tomllib.loads(lock.decode())["package"]
    urls = [
        wheel["url"]
        for package in packages
        if package.get("name") == "cryptography" and package.get("version") == version
        for wheel in package.get("wheels", [])
        if wheel["hash"] == f"sha256:{digest}" and wheel["url"].rsplit("/", 1)[-1] == filename
    ]
    if len(urls) != 1:
        raise NativeComponentError("reviewed static OpenSSL evidence needs its locked wheel")


def _static_wheel_properties(
    receipt: dict[str, Any],
    architecture: str,
    source: dict[str, Any],
    lock: bytes,
    native_files: object,
) -> dict[str, str]:
    platforms = receipt.get("platforms")
    if (
        type(receipt.get("schema_version")) is not int
        or receipt["schema_version"] != 1
        or not isinstance(platforms, dict)
        or not isinstance(platforms.get(architecture), dict)
    ):
        raise NativeComponentError("invalid static wheel evidence receipt")
    record = platforms[architecture]
    version = _identity(receipt.get("distribution_version"))
    component = receipt.get("component")
    expected = source["source_component"]
    if (
        not isinstance(component, dict)
        or source["distribution"] != "cryptography"
        or source["distribution_version"] != version
        or expected != {"name": "openssl", "version": component.get("version")}
        or component.get("name") != "openssl"
        or component.get("source_sha256") != source["sha256"]
        or record.get("sbom_sha256") != source["sbom_sha256"]
    ):
        raise NativeComponentError("static wheel receipt differs from reviewed OpenSSL source")
    extension = record.get("extension")
    if not isinstance(extension, dict) or extension.get("path") != _STATIC_EXTENSION:
        raise NativeComponentError("static wheel evidence names a different extension")
    digest = record.get("wheel_sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise NativeComponentError("invalid reviewed Cryptography wheel checksum")
    filename = _identity(record.get("wheel_filename"))
    _require_locked_crypto_wheel(lock, version, filename, digest)
    _python._verify_wheel_file(native_files, _STATIC_EXTENSION, extension)
    return {
        "identity-evidence": "reviewed OpenSSL code in the exact compiled Cryptography extension",
        "native-files": json.dumps([extension], sort_keys=True),
        "wheel-filename": filename,
        "wheel-sha256": digest,
        "native-linkage": "static",
    }


def build(
    inventory: bytes,
    lock: bytes,
    notice_bundle: Path,
    architecture: str,
    digest: str,
    python_sources: Path | None = None,
    *,
    rpm_notices: bool = False,
    rpm_notice_receipt: Path | None = None,
    source_licenses: bool = False,
    rpm_binary_receipt: Path | None = None,
    static_wheel_receipt: Path | None = None,
) -> bytes:
    """Bind a deterministic CycloneDX catalog to verified platform evidence."""
    raw = _json(inventory)
    python = raw.get("python")
    if (
        not isinstance(python, dict)
        or type(python.get("source_recipe_schema")) is not int
        or python["source_recipe_schema"] not in {4, 5, 6, 7}
    ):
        raise NativeComponentError("native component catalog requires source recipe schema 4 to 7")
    source_plan: dict[str, Any] = _python.plan(inventory, lock, architecture, digest)
    source_payloads = None
    if source_licenses and python_sources is None:
        raise NativeComponentError("source license evidence requires the verified Python sources")
    rpm_archives = None
    rpm_receipt_hash = None
    if rpm_notices:
        if python_sources is None:
            raise NativeComponentError("RPM notice evidence requires the verified Python sources")
        rpm_archives, rpm_receipt_hash = _rpm_notice_receipt(
            rpm_notice_receipt if rpm_notice_receipt is not None else _RPM_NOTICE_RECEIPT
        )
    if python_sources is not None:
        with python_sources.open("rb") as stream:
            bundle = stream.read(_python.MAX_BUNDLE + 1)
        source_payloads = _python.verify(source_plan, bundle)
    notice_files: dict[str, bytes] = _notices.verify_notice_bundle(
        notice_bundle, inventory, architecture=architecture, platform_digest=digest
    )
    reported, rpm_sbom = _reported_components(source_plan, notice_files)
    rpm_packages = None
    rpm_binary_hash = None
    if rpm_binary_receipt is not None:
        if rpm_archives is None:
            raise NativeComponentError("binary RPM evidence requires RPM source notices")
        rpm_packages, rpm_binary_hash = _rpm_binary_packages(
            rpm_binary_receipt, architecture, lock, rpm_sbom, python
        )
    sources = [*source_plan["native_sources"], *source_plan["embedded_sources"]]
    if not 1 <= len(sources) <= MAX_COMPONENTS:
        raise NativeComponentError("invalid reviewed native component count")
    static_properties: dict[str, str] = {}
    static_receipt_hash: str | None = None
    if static_wheel_receipt is not None:
        crypto_sources = [source for source in sources if source["distribution"] == "cryptography"]
        if source_payloads is None or len(crypto_sources) != 1:
            raise NativeComponentError("static wheel evidence requires verified OpenSSL source")
        receipt = _read(static_wheel_receipt)
        static_properties = _static_wheel_properties(
            _json(receipt), architecture, crypto_sources[0], lock, python["native_files"]
        )
        static_receipt_hash = hashlib.sha256(receipt).hexdigest()
    parents = {
        item["normalized_name"]: item["version"]
        for item in raw["python"]["distributions"]
        if item["normalized_name"] in _WHEELS
    }
    if set(parents) != _WHEELS:
        raise NativeComponentError("catalog requires both reviewed native wheels")
    components: list[dict[str, Any]] = []
    dependencies: dict[str, list[str]] = {}
    for name, version in sorted(parents.items()):
        parent = f"pkg:pypi/{name}@{version}"
        components.append(
            {"type": "library", "bom-ref": parent, "name": name, "version": version, "purl": parent}
        )
        dependencies[parent] = []
    consumed: set[tuple[str, str, str]] = set()
    refs: set[str] = set()
    for source in sorted(sources, key=lambda item: item["path"]):
        distribution, version = source["distribution"], source["distribution_version"]
        if parents.get(distribution) != version:
            raise NativeComponentError("native source refers to another wheel version")
        parent = f"pkg:pypi/{distribution}@{version}"
        custom = source.get("source_component")
        package = source.get("reported_package", custom)
        name, component_version = _identity(package["name"]), _identity(package["version"])
        key = (distribution, name, component_version)
        purl = reported.get(key)
        if purl is not None:
            consumed.add(key)
        elif custom is None or distribution != "psycopg-binary":
            raise NativeComponentError("source recipe lacks its declared native component")
        else:
            purl = f"pkg:generic/{quote(name, safe='')}@{quote(component_version, safe='')}"
        # A source archive checksum is not a checksum of a compiled library.
        properties = {
            "parent-wheel": parent,
            "source-archive": source["path"],
            "source-sha256": source["sha256"],
            "source-url": source["url"],
            "wheel-sbom-sha256": source["sbom_sha256"],
            "identity-evidence": "reviewed native-file bindings"
            if source.get("wheel_files")
            else "reviewed wheel SBOM declaration",
            "license-review": "unresolved; do not inherit the parent wheel license",
        }
        if source.get("wheel_files"):
            properties["native-files"] = json.dumps(source["wheel_files"], sort_keys=True)
        if distribution == "cryptography":
            properties.update(static_properties)
        if "build_recipe" in source:
            properties["build-recipe"] = json.dumps(source["build_recipe"], sort_keys=True)
            properties["builder-image"] = source["builder_image"]
            properties["builder-library-sha256"] = source["builder_library_sha256"]
            properties["wheel-sha256"] = source["wheel_sha256"]
        license_evidence: dict[str, Any] = {}
        if source_payloads is not None:
            if custom is None:
                if rpm_archives is None:
                    properties["source-notice-review"] = (
                        "unresolved; RPM component notices not selected"
                    )
                else:
                    selected_notices = _rpm_notice_files(rpm_archives, source)
                    properties["source-notice-files"] = json.dumps(selected_notices, sort_keys=True)
                    if rpm_packages is not None:
                        if purl not in rpm_packages:
                            raise NativeComponentError("source RPM is missing a binary attribution")
                        properties.update(
                            _rpm_binaries.package_properties(
                                rpm_packages.pop(purl), source, selected_notices
                            )
                        )
                    properties["source-notice-review"] = (
                        "selected SRPM upstream texts only; "
                        "not complete binary attribution or approval"
                    )
            else:
                texts = _native_notices.read_notices(source, source_payloads[source["path"]])
                properties["source-notice-files"] = json.dumps(
                    _native_notices.describe_notices(texts), sort_keys=True
                )
                properties["source-notice-review"] = (
                    "selected upstream texts only; not complete binary attribution or approval"
                )
                if source_licenses:
                    license_evidence = _native_notices.source_license_evidence(source, texts)
                    properties["source-license-scope"] = (
                        "top-level license text from verified upstream source; "
                        "not a license conclusion for the compiled library"
                    )
        ref = "native:" + hashlib.sha256(f"{parent}\n{purl}".encode()).hexdigest()
        if ref in refs:
            raise NativeComponentError("duplicate native source component")
        refs.add(ref)
        component_record: dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": component_version,
            "purl": purl,
            "properties": _properties(properties),
        }
        if license_evidence:
            component_record["evidence"] = license_evidence
        components.append(component_record)
        dependencies[parent].append(ref)
    if consumed != set(reported):
        raise NativeComponentError("wheel SBOM has a native component without a reviewed source")
    if rpm_packages:
        raise NativeComponentError("binary RPM attribution without a reviewed source")
    evidence_properties = {}
    if source_payloads is not None:
        evidence_properties["source-notice-evidence"] = "2" if rpm_archives is not None else "1"
    if rpm_receipt_hash is not None:
        evidence_properties["rpm-notice-receipt-sha256"] = rpm_receipt_hash
    if source_licenses:
        evidence_properties["source-license-evidence"] = "1"
    if rpm_binary_hash is not None:
        evidence_properties["rpm-binary-evidence"] = "1"
        evidence_properties["rpm-binary-receipt-sha256"] = rpm_binary_hash
    if static_receipt_hash is not None:
        evidence_properties["static-wheel-evidence"] = "1"
        evidence_properties["static-wheel-receipt-sha256"] = static_receipt_hash
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "properties": _properties(
                {
                    **evidence_properties,
                    "architecture": architecture,
                    "platform-digest": digest,
                    "inventory-sha256": hashlib.sha256(inventory).hexdigest(),
                    "notice-manifest-sha256": hashlib.sha256(
                        notice_files["NOTICE-MANIFEST.json"]
                    ).hexdigest(),
                    "uv-lock-sha256": hashlib.sha256(lock).hexdigest(),
                    "scope": (
                        "Reviewed Cryptography/Psycopg C-library identities only; not a complete "
                        "image or Rust catalog, license approval, source adequacy or "
                        "vulnerability assessment."
                    ),
                }
            )
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "dependencies": [
            {"ref": parent, "dependsOn": sorted(children)}
            for parent, children in sorted(dependencies.items())
        ],
    }
    result = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    if len(result) > MAX_METADATA:
        raise NativeComponentError("native catalog exceeds its size limit")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "verify"))
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--notices", type=Path, required=True)
    parser.add_argument("--python-sources", type=Path)
    parser.add_argument(
        "--rpm-notices", action="store_true", help="require RPM source notice evidence (version 2)"
    )
    parser.add_argument("--rpm-notice-receipt", type=Path, help="receipt from the release revision")
    parser.add_argument("--rpm-binaries", action="store_true", help="require RPM binary evidence")
    parser.add_argument("--rpm-binary-receipt", type=Path, help="receipt from the release revision")
    parser.add_argument(
        "--static-wheel-receipt",
        type=Path,
        help="reviewed static wheel receipt from the release revision",
    )
    parser.add_argument(
        "--source-licenses", action="store_true", help="require reviewed upstream license texts"
    )
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--platform-digest", required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "generate" and args.python_sources is None:
        parser.error("generation requires --python-sources for native notice evidence")
    if args.command == "generate" and args.rpm_notice_receipt is not None:
        parser.error("generation uses the checked-in RPM notice receipt")
    if args.command == "generate" and args.rpm_binary_receipt is not None:
        parser.error("generation uses the checked-in binary RPM receipt")
    try:
        existing = _read(args.catalog) if args.command == "verify" else None
        rpm_notices = args.rpm_notices
        source_licenses = args.source_licenses
        rpm_binaries = args.rpm_binaries
        static_receipt = args.static_wheel_receipt
        if existing is not None:
            metadata = _json(existing).get("metadata")
            if not isinstance(metadata, dict) or not isinstance(metadata.get("properties"), list):
                raise NativeComponentError("invalid catalog metadata")
            rpm_notices |= {
                "name": "extra-codeowners:source-notice-evidence",
                "value": "2",
            } in metadata["properties"]
            source_licenses |= {
                "name": "extra-codeowners:source-license-evidence",
                "value": "1",
            } in metadata["properties"]
            rpm_binaries |= {
                "name": "extra-codeowners:rpm-binary-evidence",
                "value": "1",
            } in metadata["properties"]
            if {
                "name": "extra-codeowners:static-wheel-evidence",
                "value": "1",
            } in metadata["properties"]:
                static_receipt = static_receipt or _STATIC_WHEEL_RECEIPT
        if args.rpm_binary_receipt is not None and not rpm_binaries:
            raise NativeComponentError("binary RPM receipt supplied without its evidence contract")
        data = build(
            _read(args.inventory),
            _read(args.lock),
            args.notices,
            args.architecture,
            args.platform_digest,
            args.python_sources,
            rpm_notices=rpm_notices,
            rpm_notice_receipt=args.rpm_notice_receipt,
            source_licenses=source_licenses,
            rpm_binary_receipt=(args.rpm_binary_receipt or _RPM_BINARY_RECEIPT)
            if rpm_binaries
            else None,
            static_wheel_receipt=static_receipt,
        )
        if args.command == "generate":
            with args.catalog.open("xb") as output:
                output.write(data)
        elif existing != data:
            raise NativeComponentError("native catalog differs from verified platform evidence")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Native component evidence: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
