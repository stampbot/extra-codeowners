"""Catalog reviewed C-library identities from wheel SBOMs and source recipes.

This offline catalog supplements the image SBOM. It does not infer licenses,
prove exact upstream build inputs, or assess vulnerability reachability.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
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


def _reported_components(
    source_plan: dict[str, Any], notice_files: dict[str, bytes]
) -> dict[tuple[str, str, str], str]:
    """Keep only the exact reviewed C-library SBOMs, not unrelated build SBOMs."""
    sources = [*source_plan["native_sources"], *source_plan["embedded_sources"]]
    expected = {(source["distribution"], source["sbom_sha256"]) for source in sources}
    wheel_versions = {source["distribution"]: source["distribution_version"] for source in sources}
    manifest = _json(notice_files["NOTICE-MANIFEST.json"])
    found: set[tuple[str, str]] = set()
    result: dict[tuple[str, str, str], str] = {}
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
        sbom = _json(notice_files[notice["archive_path"]])
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
    return result


def build(
    inventory: bytes,
    lock: bytes,
    notice_bundle: Path,
    architecture: str,
    digest: str,
    python_sources: Path | None = None,
) -> bytes:
    """Bind a deterministic CycloneDX catalog to verified platform evidence."""
    raw = _json(inventory)
    python = raw.get("python")
    if not isinstance(python, dict) or python.get("source_recipe_schema") != 4:
        raise NativeComponentError("native component catalog requires source recipe schema 4")
    source_plan: dict[str, Any] = _python.plan(inventory, lock, architecture, digest)
    source_payloads = None
    if python_sources is not None:
        with python_sources.open("rb") as stream:
            bundle = stream.read(_python.MAX_BUNDLE + 1)
        source_payloads = _python.verify(source_plan, bundle)
    notice_files: dict[str, bytes] = _notices.verify_notice_bundle(
        notice_bundle, inventory, architecture=architecture, platform_digest=digest
    )
    reported = _reported_components(source_plan, notice_files)
    sources = [*source_plan["native_sources"], *source_plan["embedded_sources"]]
    if not 1 <= len(sources) <= MAX_COMPONENTS:
        raise NativeComponentError("invalid reviewed native component count")
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
        if source_payloads is not None:
            if custom is None:
                properties["source-notice-review"] = (
                    "unresolved; RPM component notices not selected"
                )
            else:
                properties["source-notice-files"] = json.dumps(
                    _native_notices.inspect(source, source_payloads[source["path"]]), sort_keys=True
                )
                properties["source-notice-review"] = (
                    "selected upstream texts only; not complete binary attribution or approval"
                )
        ref = "native:" + hashlib.sha256(f"{parent}\n{purl}".encode()).hexdigest()
        if ref in refs:
            raise NativeComponentError("duplicate native source component")
        refs.add(ref)
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": name,
                "version": component_version,
                "purl": purl,
                "properties": _properties(properties),
            }
        )
        dependencies[parent].append(ref)
    if consumed != set(reported):
        raise NativeComponentError("wheel SBOM has a native component without a reviewed source")
    evidence_properties = {}
    if source_payloads is not None:
        evidence_properties["source-notice-evidence"] = "1"
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
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--platform-digest", required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "generate" and args.python_sources is None:
        parser.error("generation requires --python-sources for native notice evidence")
    try:
        data = build(
            _read(args.inventory),
            _read(args.lock),
            args.notices,
            args.architecture,
            args.platform_digest,
            args.python_sources,
        )
        if args.command == "generate":
            with args.catalog.open("xb") as output:
                output.write(data)
        elif _read(args.catalog) != data:
            raise NativeComponentError("native catalog differs from verified platform evidence")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Native component evidence: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
