"""Retain Cargo sources identified by wheel SBOMs and verified Python sdists.

No upstream code is executed or extracted to the filesystem. The source
archives include their upstream notices; license approval remains separate.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import importlib.util
import io
import json
import re
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType
from typing import Any

MAX_METADATA = 4 * 1024 * 1024
MAX_SOURCE = 16 * 1024 * 1024
MAX_BUNDLE = 128 * 1024 * 1024
MAX_SDIST_EXPANDED = 128 * 1024 * 1024
MAX_COMPONENTS = 1000
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,99}\Z")
VERSION_CORE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
VERSION_IDENTIFIER = re.compile(r"[A-Za-z0-9-]+\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


class RustSourceError(ValueError):
    """The retained source and the installed wheel's component evidence disagree."""


def _sibling(name: str) -> ModuleType:
    # Resolve only the verified checkout's sibling tools. Do not add the
    # repository or working directory to Python's isolated import path.
    module_name = f"_extra_codeowners_{name}"
    path = Path(__file__).resolve().with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RustSourceError("could not load the source-evidence verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_python_sources = _sibling("release_python_sources")
_notices = _sibling("release_notices")


def _json(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = _python_sources._json(data)
    return result


def _read(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise RustSourceError("source evidence exceeds its size limit")
    return value


def _cargo_components(value: dict[str, Any]) -> Iterator[dict[str, Any]]:
    pending: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > 50_000 or depth > 32:
            raise RustSourceError("embedded SBOM exceeds traversal limits")
        if isinstance(item, dict):
            purl = item.get("purl")
            if isinstance(purl, str) and purl.startswith("pkg:cargo/"):
                if value.get("bomFormat") != "CycloneDX":
                    raise RustSourceError("unsupported Cargo SBOM format")
                yield item
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str) and item.startswith("pkg:cargo/"):
            # CycloneDX also repeats PURLs in dependency references. These
            # references carry no additional component or license evidence.
            if value.get("bomFormat") != "CycloneDX":
                raise RustSourceError("unsupported Cargo SBOM reference")


def _valid_version(value: str) -> bool:
    if len(value) > 200:
        return False
    release, plus, build = value.partition("+")
    core, minus, prerelease = release.partition("-")
    if VERSION_CORE.fullmatch(core) is None:
        return False
    for separator, suffix in ((minus, prerelease), (plus, build)):
        if separator and any(
            VERSION_IDENTIFIER.fullmatch(part) is None for part in suffix.split(".")
        ):
            return False
    return not minus or all(
        not part.isdecimal() or len(part) == 1 or not part.startswith("0")
        for part in prerelease.split(".")
    )


def _cargo_identity(purl: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(purl)
    if parsed.scheme != "pkg" or parsed.netloc or not parsed.path.startswith("cargo/"):
        raise RustSourceError("invalid Cargo package URL")
    identity = urllib.parse.unquote(parsed.path.removeprefix("cargo/"))
    name, separator, version = identity.partition("@")
    if not separator or NAME.fullmatch(name) is None or not _valid_version(version):
        raise RustSourceError("invalid Cargo component identity")
    return name, version


def _cargo_lock(source: dict[str, Any], contents: bytes) -> tuple[str, bytes]:
    filename = source["path"].rsplit("/", 1)[-1]
    selected: list[bytes] = []
    if filename.endswith(".tar.gz"):
        path = f"{filename.removesuffix('.tar.gz')}/Cargo.lock"
        with gzip.GzipFile(fileobj=io.BytesIO(contents)) as compressed:
            raw = compressed.read(MAX_SDIST_EXPANDED + 1)
        if len(raw) > MAX_SDIST_EXPANDED:
            raise RustSourceError("expanded Python source exceeds its size limit")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for index, member in enumerate(archive):
                if index > 50_000:
                    raise RustSourceError("Python source has too many archive members")
                if member.name != path:
                    continue
                if not member.isfile() or not 0 < member.size <= MAX_METADATA:
                    raise RustSourceError("Cargo.lock is not a bounded regular file")
                stream = archive.extractfile(member)
                assert stream is not None
                selected.append(stream.read(MAX_METADATA + 1))
    elif filename.endswith(".zip"):
        path = f"{filename.removesuffix('.zip')}/Cargo.lock"
        with zipfile.ZipFile(io.BytesIO(contents)) as archive:
            if len(archive.infolist()) > 50_000:
                raise RustSourceError("Python source has too many archive members")
            for zip_member in archive.infolist():
                if zip_member.filename != path:
                    continue
                file_type = (zip_member.external_attr >> 16) & 0o170000
                if (
                    zip_member.is_dir()
                    or file_type not in {0, 0o100000}
                    or not 0 < zip_member.file_size <= MAX_METADATA
                    or zip_member.flag_bits & 1
                ):
                    raise RustSourceError("Cargo.lock is not a bounded regular ZIP member")
                selected.append(archive.read(zip_member))
    else:
        raise RustSourceError("unsupported Python archive for Cargo source evidence")
    if len(selected) != 1 or len(selected[0]) > MAX_METADATA:
        raise RustSourceError("Python source must contain one bounded top-level Cargo.lock")
    return path, selected[0]


def plan(
    inventory: bytes,
    lock: bytes,
    python_bundle: bytes,
    notice_bundle: Path,
    architecture: str,
    digest: str,
) -> dict[str, Any]:
    """Bind every reported Cargo component to its retained lockfile or workspace."""
    python_plan: dict[str, Any] = _python_sources.plan(inventory, lock, architecture, digest)
    payloads: dict[str, bytes] = _python_sources.verify(python_plan, python_bundle)
    notice_files: dict[str, bytes] = _notices.verify_notice_bundle(
        notice_bundle, inventory, architecture=architecture, platform_digest=digest
    )
    notice_manifest = _json(notice_files["NOTICE-MANIFEST.json"])
    sources = {(item["name"], item["version"]): item for item in python_plan["sources"]}
    locks: dict[tuple[str, str], tuple[str, bytes, dict[tuple[str, str], dict[str, Any]]]] = {}
    crates: dict[tuple[str, str], dict[str, Any]] = {}
    components: list[dict[str, Any]] = []
    for notice in notice_manifest["files"]:
        if notice["role"] != "python-embedded-sbom":
            continue
        sbom = _json(notice_files[notice["archive_path"]])
        for component in _cargo_components(sbom):
            if len(components) >= MAX_COMPONENTS:
                raise RustSourceError("too many Cargo components")
            distribution = notice["component"].removeprefix("pypi:")
            name, separator, version = distribution.partition("@")
            key = (name, version)
            if not separator or key not in sources:
                raise RustSourceError("Cargo wheel has no retained version-matched Python source")
            source = sources[key]
            if key not in locks:
                lock_path, lock_bytes = _cargo_lock(source, payloads[source["path"]])
                cargo = tomllib.loads(lock_bytes.decode())
                packages: dict[tuple[str, str], dict[str, Any]] = {}
                if cargo.get("version") not in {3, 4} or not isinstance(cargo.get("package"), list):
                    raise RustSourceError("unsupported Cargo.lock schema")
                for package in cargo["package"]:
                    if not isinstance(package, dict):
                        raise RustSourceError("invalid Cargo.lock package")
                    package_name, package_version = package.get("name"), package.get("version")
                    if not isinstance(package_name, str) or not isinstance(package_version, str):
                        raise RustSourceError("invalid Cargo.lock package identity")
                    package_key = (package_name, package_version)
                    if package_key in packages:
                        raise RustSourceError("ambiguous Cargo.lock package identity")
                    packages[package_key] = package
                locks[key] = (lock_path, lock_bytes, packages)
            lock_path, lock_bytes, packages = locks[key]
            crate_name, crate_version = _cargo_identity(component["purl"])
            package = packages.get((crate_name, crate_version))
            if package is None:
                raise RustSourceError("wheel Cargo component is absent from its source lockfile")
            record = {
                "distribution": name,
                "distribution_version": version,
                "purl": component["purl"],
                "name": crate_name,
                "version": crate_version,
                "declared_licenses": component.get("licenses", []),
                "python_source": source["path"],
                "cargo_lock": lock_path,
                "cargo_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
                "sbom": notice["source_path"],
                "sbom_sha256": notice["sha256"],
            }
            if "source" not in package:
                if "checksum" in package:
                    raise RustSourceError("workspace Cargo package unexpectedly has a checksum")
                record["source_kind"] = "retained-python-workspace"
            else:
                checksum = package.get("checksum")
                if (
                    package["source"] != REGISTRY
                    or not isinstance(checksum, str)
                    or SHA256.fullmatch(checksum) is None
                ):
                    raise RustSourceError("Cargo source is not checksum-pinned crates.io evidence")
                crate = {
                    "name": crate_name,
                    "version": crate_version,
                    "sha256": checksum,
                    "path": f"sources/{crate_name}/{crate_name}-{crate_version}.crate",
                    "url": f"https://static.crates.io/crates/{crate_name}/{crate_name}-{crate_version}.crate",
                }
                crate_key = (crate_name, crate_version)
                if crate_key in crates and crates[crate_key] != crate:
                    raise RustSourceError("source lockfiles disagree about a Cargo archive")
                crates[crate_key] = crate
                record["source_kind"] = "crates-io-archive"
                record["crate_source"] = crate["path"]
            components.append(record)
    return {
        "schema_version": 1,
        "image": {"architecture": architecture, "platform_digest": digest},
        "inventory_sha256": hashlib.sha256(inventory).hexdigest(),
        "python_source_bundle_sha256": hashlib.sha256(python_bundle).hexdigest(),
        "notice_manifest_sha256": hashlib.sha256(notice_files["NOTICE-MANIFEST.json"]).hexdigest(),
        "components": sorted(components, key=lambda item: (item["distribution"], item["purl"])),
        "sources": [crates[key] for key in sorted(crates)],
        "scope": (
            "Version-matched Cargo sources and upstream notices identified by wheel SBOMs; "
            "not a complete native-library inventory or license approval."
        ),
    }


def _validate_source(source: dict[str, Any]) -> None:
    name, version, checksum = (source.get(key) for key in ("name", "version", "sha256"))
    if (
        not isinstance(name, str)
        or NAME.fullmatch(name) is None
        or not isinstance(version, str)
        or not _valid_version(version)
        or not isinstance(checksum, str)
        or SHA256.fullmatch(checksum) is None
        or source.get("path") != f"sources/{name}/{name}-{version}.crate"
        or source.get("url") != f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    ):
        raise RustSourceError("invalid pinned Cargo archive identity")


def _check(source: dict[str, Any], contents: bytes) -> None:
    _validate_source(source)
    if not 0 < len(contents) <= MAX_SOURCE:
        raise RustSourceError("Cargo archive exceeds its size limit or is empty")
    if hashlib.sha256(contents).hexdigest() != source["sha256"]:
        raise RustSourceError("Cargo archive differs from its source lockfile checksum")


def fetch(source: dict[str, Any]) -> bytes:
    """Download only a checksum-pinned static.crates.io archive; reject redirects."""
    _validate_source(source)
    opener = urllib.request.build_opener(_python_sources._NoRedirect())
    request = urllib.request.Request(  # noqa: S310 - exact HTTPS origin and path validated above.
        source["url"], headers={"User-Agent": "extra-codeowners-source-evidence"}
    )
    for attempt in range(3):
        try:
            with opener.open(request, timeout=20) as response:
                if response.status != 200 or response.geturl() != source["url"]:
                    raise RustSourceError("unexpected Cargo source response")
                length = response.headers.get("Content-Length")
                if length is not None and (
                    not length.isascii()
                    or not length.isdecimal()
                    or not 0 < int(length) <= MAX_SOURCE
                ):
                    raise RustSourceError("unsafe Cargo source response size")
                contents: bytes = response.read(MAX_SOURCE + 1)
                if length is not None and len(contents) != int(length):
                    raise RustSourceError("Cargo source response length differs from its header")
            _check(source, contents)
            return contents
        except urllib.error.HTTPError as error:
            if error.code not in {408, 429, 500, 502, 503, 504} or attempt == 2:
                raise RustSourceError("could not download the pinned Cargo source") from error
            retry_after = error.headers.get("Retry-After")
            if retry_after is not None:
                if (
                    not retry_after.isascii()
                    or not retry_after.isdecimal()
                    or int(retry_after) > 60
                ):
                    raise RustSourceError(
                        "Cargo source provider requested a later retry"
                    ) from error
                time.sleep(max(int(retry_after), attempt + 1))
            else:
                time.sleep(attempt + 1)
        except (TimeoutError, urllib.error.URLError, http.client.IncompleteRead) as error:
            if attempt == 2:
                raise RustSourceError("Cargo source download did not complete") from error
            time.sleep(attempt + 1)
    raise AssertionError("unreachable")  # pragma: no cover


def fetch_all(manifest: dict[str, Any]) -> dict[str, bytes]:
    sources = manifest["sources"]
    if len(sources) > MAX_COMPONENTS:
        raise RustSourceError("too many Cargo source archives")
    payloads: dict[str, bytes] = {}
    total = 0
    with ThreadPoolExecutor(max_workers=4) as pool:
        # Submit only one bounded batch at a time. An oversized response must
        # not leave hundreds of queued downloads running after rejection.
        for offset in range(0, len(sources), 4):
            batch = sources[offset : offset + 4]
            for source, contents in zip(batch, pool.map(fetch, batch), strict=True):
                total += len(contents)
                if total > MAX_BUNDLE - MAX_METADATA:
                    raise RustSourceError("Cargo sources exceed the bundle size limit")
                if source["path"] in payloads:
                    raise RustSourceError("duplicate Cargo source path")
                payloads[source["path"]] = contents
    return payloads


def build(manifest: dict[str, Any], payloads: dict[str, bytes]) -> bytes:
    """Package verified source archives and their component mapping deterministically."""
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > MAX_METADATA or len(manifest["sources"]) > MAX_COMPONENTS:
        raise RustSourceError("Cargo source manifest exceeds its size limit")
    expected = {source["path"] for source in manifest["sources"]}
    if len(expected) != len(manifest["sources"]) or set(payloads) != expected:
        raise RustSourceError("Cargo source payloads do not match the plan")
    for source in manifest["sources"]:
        _check(source, payloads[source["path"]])
    if sum(map(len, payloads.values())) > MAX_BUNDLE - MAX_METADATA:
        raise RustSourceError("Cargo sources exceed the bundle size limit")
    output = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for path, contents in sorted({"manifest.json": encoded, **payloads}.items()):
            member = tarfile.TarInfo(path)
            member.size = len(contents)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(contents))
    return output.getvalue()


def verify(manifest: dict[str, Any], bundle: bytes) -> None:
    """Verify all bytes against a plan derived again from the signed inputs."""
    if len(bundle) > MAX_BUNDLE:
        raise RustSourceError("Cargo source bundle exceeds its size limit")
    expected = {source["path"]: source for source in manifest["sources"]}
    if len(expected) != len(manifest["sources"]) or len(expected) > MAX_COMPONENTS:
        raise RustSourceError("invalid Cargo source plan")
    for source in expected.values():
        _validate_source(source)
    seen: set[str] = set()
    with gzip.GzipFile(fileobj=io.BytesIO(bundle)) as compressed:
        raw = compressed.read(MAX_BUNDLE + 1)
    if len(raw) > MAX_BUNDLE:
        raise RustSourceError("expanded Cargo source bundle exceeds its size limit")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        offset = 0
        for member in archive:
            if (
                member.name in seen
                or member.name not in {*expected, "manifest.json"}
                or not member.isfile()
                or member.pax_headers
                or member.offset != offset
                or member.offset_data != member.offset + 512
            ):
                raise RustSourceError("unexpected Cargo source bundle member")
            limit = MAX_METADATA if member.name == "manifest.json" else MAX_SOURCE
            if not 0 < member.size <= limit:
                raise RustSourceError("unsafe Cargo source member size")
            stream = archive.extractfile(member)
            assert stream is not None
            contents = stream.read(limit + 1)
            if member.name == "manifest.json":
                if json.dumps(_json(contents), sort_keys=True) != json.dumps(
                    manifest, sort_keys=True
                ):
                    raise RustSourceError("Cargo source manifest differs from its signed inputs")
            else:
                _check(expected[member.name], contents)
            seen.add(member.name)
            offset = member.offset_data + ((member.size + 511) // 512) * 512
        padding = raw[offset:]
        if len(padding) < 1024 or len(padding) % 512 or any(padding):
            raise RustSourceError("Cargo source bundle has invalid end markers")
    if seen != {*expected, "manifest.json"}:
        raise RustSourceError("Cargo source bundle is incomplete")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "fetch", "verify"])
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--python-sources", type=Path, required=True)
    parser.add_argument("--notices", type=Path, required=True)
    parser.add_argument("--architecture", choices=["amd64", "arm64"], required=True)
    parser.add_argument("--platform-digest", required=True)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args(argv)
    if args.command != "plan" and args.bundle is None:
        parser.error("--bundle is required for fetch and verify")
    try:
        manifest = plan(
            _read(args.inventory, MAX_METADATA),
            _read(args.lock, MAX_METADATA),
            _read(args.python_sources, _python_sources.MAX_BUNDLE),
            args.notices,
            args.architecture,
            args.platform_digest,
        )
        if args.command == "plan":
            sys.stdout.write(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        elif args.command == "fetch":
            bundle = build(manifest, fetch_all(manifest))
            verify(manifest, bundle)
            args.bundle.write_bytes(bundle)
            args.bundle.chmod(0o444)
        else:
            verify(manifest, _read(args.bundle, MAX_BUNDLE))
    except (ValueError, OSError, EOFError, tarfile.TarError, zipfile.BadZipFile) as error:
        sys.stderr.write(f"Cargo source evidence failed: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
