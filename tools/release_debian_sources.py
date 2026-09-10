"""Retain version-matched Debian sources without extracting or building them.

Debian Snapshot is the HTTPS source of descriptor metadata. Its SHA-1 URLs
locate files; SHA-256 from each .dsc verifies the source archives. Descriptor
signatures are preserved, not verified against Debian developer keyrings.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import re
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import IO, Any

MAX_METADATA = 2 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_BUNDLE = 512 * 1024 * 1024
MAX_PACKAGES = 256
MAX_FILES = 32
ORIGIN = "https://snapshot.debian.org"
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,199}\Z")
VERSION = re.compile(r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+~\-]{0,199}\Z")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~\-]{0,249}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
PROVENANCE = (
    "Version-matched Debian Snapshot sources over HTTPS; "
    "descriptor signatures are retained, not verified."
)
SCOPE = "Installed Debian packages only; excludes CPython and Python wheel contents."


class DebianSourceError(ValueError):
    """Source collection or verification cannot establish a complete bundle."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise DebianSourceError("duplicate JSON key")
        result[name] = value
    return result


def _json(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_METADATA:
        raise DebianSourceError("metadata exceeds size limit")
    try:
        value = json.loads(data, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise DebianSourceError("invalid JSON metadata") from error
    if not isinstance(value, dict):
        raise DebianSourceError("metadata must be an object")
    return value


def _encoded(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DebianSourceError(f"invalid {field}")
    return value


def identities(
    inventories: dict[str, bytes], digests: dict[str, str]
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Resolve binary Source fields, including epochs and binary-only rebuilds."""
    if set(inventories) != {"amd64", "arm64"} or set(digests) != set(inventories):
        raise DebianSourceError("both platform inventories and digests are required")
    images = {}
    sources: set[tuple[str, str]] = set()
    for architecture in sorted(inventories):
        inventory = _json(inventories[architecture])
        if type(inventory.get("schema_version")) is not int or inventory["schema_version"] != 2:
            raise DebianSourceError("unsupported inventory schema")
        image = inventory.get("image")
        digest = digests[architecture]
        if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise DebianSourceError("invalid platform digest")
        if (
            not isinstance(image, dict)
            or image.get("architecture") != architecture
            or image.get("platform_digest") != digest
            or image.get("distro") != "debian-13"
        ):
            raise DebianSourceError("inventory does not match the selected Debian platform")
        debian = inventory.get("debian")
        if not isinstance(debian, dict):
            raise DebianSourceError("inventory omitted Debian metadata")
        packages = debian.get("packages")
        if not isinstance(packages, list) or not 0 < len(packages) <= MAX_PACKAGES:
            raise DebianSourceError("invalid Debian package count")
        binary_names = set()
        for package in packages:
            if not isinstance(package, dict):
                raise DebianSourceError("invalid Debian package record")
            name = _encoded(package.get("package"), PACKAGE, "binary package name")
            if name in binary_names or package.get("architecture") not in {architecture, "all"}:
                raise DebianSourceError("duplicate package or unexpected package architecture")
            binary_names.add(name)
            version = _encoded(package.get("version"), VERSION, "binary package version")
            source = package.get("source")
            if not isinstance(source, str):
                raise DebianSourceError("invalid Debian Source field")
            match = re.fullmatch(r"([^ ()]+)(?: \(([^ ()]+)\))?", source)
            if match is None:
                raise DebianSourceError("invalid Debian Source field")
            sources.add(
                (
                    _encoded(match[1], PACKAGE, "source package name"),
                    _encoded(match[2] or version, VERSION, "source package version"),
                )
            )
        images[architecture] = {
            "platform_digest": digest,
            "inventory_sha256": hashlib.sha256(inventories[architecture]).hexdigest(),
        }
    if len(sources) > MAX_PACKAGES:
        raise DebianSourceError("source package count exceeds limit")
    return images, sorted(sources)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        raise DebianSourceError("Debian Snapshot unexpectedly redirected the download")


def _download(url: str, output: IO[bytes], limit: int) -> None:
    if not url.startswith(ORIGIN + "/"):
        raise DebianSourceError("unexpected download origin")
    opener = urllib.request.build_opener(_NoRedirect())
    for attempt in range(3):
        output.seek(0)
        output.truncate()
        try:
            started = time.monotonic()
            with opener.open(url, timeout=30) as response:
                if response.status != 200:
                    raise DebianSourceError("source download did not return HTTP 200")
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > limit:
                        raise DebianSourceError("source download exceeds size limit")
                    if time.monotonic() - started > 180:
                        raise TimeoutError("source download exceeded deadline")
                    output.write(chunk)
            return
        except (urllib.error.URLError, TimeoutError, http.client.IncompleteRead) as error:
            if attempt == 2:
                raise DebianSourceError(f"source download failed: {url}") from error
            time.sleep(2 ** (attempt + 1))


def _metadata(url: str) -> bytes:
    output = io.BytesIO()
    _download(url, output, MAX_METADATA)
    return output.getvalue()


def descriptor(data: bytes, name: str, version: str) -> list[dict[str, Any]]:
    """Read source identities and SHA-256 rows from a retained Debian descriptor."""
    if len(data) > MAX_METADATA:
        raise DebianSourceError("descriptor exceeds size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise DebianSourceError("descriptor is not UTF-8") from error
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
        try:
            _, text = text.split("\n\n", 1)
            text, signature = text.split("\n-----BEGIN PGP SIGNATURE-----\n", 1)
        except ValueError as error:
            raise DebianSourceError("malformed signed descriptor") from error
        if not signature.rstrip().endswith("-----END PGP SIGNATURE-----"):
            raise DebianSourceError("descriptor has no signature end marker")
        text = "\n".join(line.removeprefix("- ") for line in text.splitlines())
    fields: dict[str, str] = {}
    key = ""
    for line in text.strip().splitlines():
        if line.startswith((" ", "\t")) and key:
            fields[key] += "\n" + line.strip()
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)", line)
        if match is None or match[1].lower() in fields:
            raise DebianSourceError("invalid or duplicate descriptor field")
        key = match[1].lower()
        fields[key] = match[2]
    if fields.get("source") != name or fields.get("version") != version:
        raise DebianSourceError("descriptor differs from installed source package identity")
    files = []
    names = set()
    for line in fields.get("checksums-sha256", "").strip().splitlines():
        parts = line.split()
        if len(parts) != 3 or re.fullmatch(r"[0-9]{1,12}", parts[1]) is None:
            raise DebianSourceError("invalid descriptor checksum row")
        checksum = _encoded(parts[0], SHA256, "source checksum")
        filename = _encoded(parts[2], FILENAME, "source filename")
        size = int(parts[1])
        if filename in names or not 0 < size <= MAX_FILE:
            raise DebianSourceError("duplicate source filename or unsafe source size")
        names.add(filename)
        files.append({"name": filename, "sha256": checksum, "size": size})
    if not 0 < len(files) < MAX_FILES:
        raise DebianSourceError("descriptor requires bounded SHA-256 source records")
    return sorted(files, key=lambda item: item["name"])


def resolve_source(identity: tuple[str, str]) -> tuple[dict[str, Any], bytes]:
    """Find exactly one descriptor and every archive it names in Debian Snapshot."""
    name, version = identity
    metadata = _json(
        _metadata(
            f"{ORIGIN}/mr/package/{name}/{urllib.parse.quote(version, safe='')}/srcfiles?fileinfo=1"
        )
    )
    if metadata.get("package") != name or metadata.get("version") != version:
        raise DebianSourceError("Snapshot returned the wrong source identity")
    result = metadata.get("result")
    info = metadata.get("fileinfo")
    if (
        not isinstance(result, list)
        or not 1 < len(result) <= MAX_FILES
        or not isinstance(info, dict)
    ):
        raise DebianSourceError("invalid Snapshot file inventory")
    locators: dict[str, tuple[str, int]] = {}
    hashes = set()
    for row in result:
        if not isinstance(row, dict):
            raise DebianSourceError("invalid Snapshot file record")
        locator = _encoded(row.get("hash"), SHA1, "Snapshot file locator")
        if locator in hashes:
            raise DebianSourceError("duplicate Snapshot file locator")
        hashes.add(locator)
        variants = info.get(locator)
        if not isinstance(variants, list) or not 0 < len(variants) <= 128:
            raise DebianSourceError("missing or oversized Snapshot filename list")
        for variant in variants:
            if not isinstance(variant, dict):
                raise DebianSourceError("invalid Snapshot filename record")
            filename = _encoded(variant.get("name"), FILENAME, "Snapshot filename")
            size = variant.get("size")
            if type(size) is not int or not 0 < size <= MAX_FILE:
                raise DebianSourceError("invalid Snapshot file size")
            if filename in locators and locators[filename] != (locator, size):
                raise DebianSourceError("ambiguous Snapshot filename")
            locators[filename] = (locator, size)
    dsc_name = f"{name}_{version.split(':', 1)[-1]}.dsc"
    if dsc_name not in locators:
        raise DebianSourceError("Snapshot omitted the version-matched descriptor")
    locator, size = locators[dsc_name]
    if size > MAX_METADATA:
        raise DebianSourceError("descriptor exceeds size limit")
    data = _metadata(f"{ORIGIN}/file/{locator}")
    if len(data) != size or hashlib.sha1(data, usedforsecurity=False).hexdigest() != locator:
        raise DebianSourceError("descriptor differs from Snapshot locator")
    files = descriptor(data, name, version)
    for file in files:
        match = locators.get(file["name"])
        if match is None or match[1] != file["size"]:
            raise DebianSourceError("Snapshot omitted an archive named by the descriptor")
        file["snapshot_sha1"] = match[0]
    return {
        "name": name,
        "version": version,
        "descriptor": {
            "name": dsc_name,
            "size": size,
            "snapshot_sha1": locator,
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "files": files,
    }, data


def _hash_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _archive_path(package: dict[str, Any], filename: str) -> str:
    return f"sources/{package['name']}/{urllib.parse.quote(package['version'], safe='')}/{filename}"


def collect_bundle(
    inventories: dict[str, bytes], digests: dict[str, str], bundle: Path, cache: Path
) -> dict[str, Any]:
    """Fetch all installed Debian source packages, reusing checksum-checked files."""
    images, packages = identities(inventories, digests)
    if bundle.exists():
        raise DebianSourceError("refusing to overwrite an existing source bundle")
    cache.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        resolved = list(pool.map(resolve_source, packages))
    manifest = {
        "schema_version": 1,
        "images": images,
        "packages": [package for package, _ in resolved],
        "provenance": PROVENANCE,
        "scope": SCOPE,
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    if len(manifest_bytes) > MAX_METADATA:
        raise DebianSourceError("source manifest exceeds size limit")
    total = len(manifest_bytes) + sum(
        file["size"]
        for package, _ in resolved
        for file in [package["descriptor"], *package["files"]]
    )
    if total + (MAX_PACKAGES * MAX_FILES + 10) * 1024 > MAX_BUNDLE:
        raise DebianSourceError("source bundle would exceed size limit")
    with tempfile.TemporaryDirectory(prefix="debian-sources-", dir=bundle.parent) as directory:
        staged = Path(directory) / "bundle.tar"
        with tarfile.open(staged, mode="w", format=tarfile.USTAR_FORMAT) as archive:

            def add(name: str, data: bytes) -> None:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))

            add("manifest.json", manifest_bytes)
            for package, data in resolved:
                sys.stderr.write(
                    f"Retaining Debian source {package['name']} {package['version']}\n"
                )
                add(_archive_path(package, package["descriptor"]["name"]), data)
                for file in package["files"]:
                    target = cache / file["sha256"]
                    if target.is_symlink():
                        raise DebianSourceError("source cache contains a symlink")
                    if (
                        not target.is_file()
                        or target.stat().st_size != file["size"]
                        or _hash_file(target) != file["sha256"]
                    ):
                        with tempfile.TemporaryDirectory(prefix=".download-", dir=cache) as partial:
                            temporary = Path(partial) / "archive"
                            with temporary.open("w+b") as output:
                                _download(
                                    f"{ORIGIN}/file/{file['snapshot_sha1']}", output, file["size"]
                                )
                            if (
                                temporary.stat().st_size != file["size"]
                                or _hash_file(temporary) != file["sha256"]
                            ):
                                raise DebianSourceError(
                                    "download differs from descriptor SHA-256 or size"
                                )
                            temporary.replace(target)
                    member = tarfile.TarInfo(_archive_path(package, file["name"]))
                    member.size = file["size"]
                    member.mode = 0o644
                    with target.open("rb") as contents:
                        archive.addfile(member, contents)
        verify_bundle(inventories, digests, staged)
        # A hard link publishes the complete verified file without overwriting
        # an existing destination. The temporary copy is removed on every exit.
        bundle.hardlink_to(staged)
    retained = {file["sha256"] for package, _ in resolved for file in package["files"]}
    for candidate in cache.iterdir():
        if (
            SHA256.fullmatch(candidate.name)
            and candidate.name not in retained
            and candidate.is_file()
        ):
            candidate.unlink()
    return manifest


def verify_bundle(
    inventories: dict[str, bytes], digests: dict[str, str], bundle: Path
) -> dict[str, Any]:
    """Verify every descriptor and source archive with bounded, non-extracting reads."""
    images, identities_expected = identities(inventories, digests)
    if not 0 < bundle.stat().st_size <= MAX_BUNDLE:
        raise DebianSourceError("invalid source bundle size")
    try:
        with tarfile.open(bundle, mode="r:") as archive:
            first = archive.next()
            if (
                first is None
                or first.name != "manifest.json"
                or not first.isfile()
                or first.size > MAX_METADATA
                or first.offset_data != 512
            ):
                raise DebianSourceError("source bundle must start with a bounded regular manifest")
            stream = archive.extractfile(first)
            assert stream is not None
            manifest = _json(stream.read(MAX_METADATA + 1))
            if (
                set(manifest) != {"schema_version", "images", "packages", "provenance", "scope"}
                or manifest["provenance"] != PROVENANCE
                or manifest["scope"] != SCOPE
            ):
                raise DebianSourceError("unsupported source manifest fields or evidence scope")
            packages = manifest.get("packages")
            if (
                type(manifest.get("schema_version")) is not int
                or manifest["schema_version"] != 1
                or manifest.get("images") != images
                or not isinstance(packages, list)
                or len(packages) != len(identities_expected)
            ):
                raise DebianSourceError("source manifest differs from the selected inventories")
            expected: dict[str, dict[str, Any]] = {}
            for package, identity in zip(packages, identities_expected, strict=True):
                if (
                    not isinstance(package, dict)
                    or set(package) != {"name", "version", "descriptor", "files"}
                    or (package.get("name"), package.get("version")) != identity
                ):
                    raise DebianSourceError(
                        "source manifest omits or changes an installed source package"
                    )
                dsc = package.get("descriptor")
                files = package.get("files")
                if (
                    not isinstance(dsc, dict)
                    or not isinstance(files, list)
                    or not 0 < len(files) < MAX_FILES
                ):
                    raise DebianSourceError("source manifest omitted descriptor or archives")
                for file in [dsc, *files]:
                    if not isinstance(file, dict) or set(file) != {
                        "name",
                        "sha256",
                        "size",
                        "snapshot_sha1",
                    }:
                        raise DebianSourceError("invalid source manifest file record")
                    _encoded(file["name"], FILENAME, "source filename")
                    _encoded(file["sha256"], SHA256, "source checksum")
                    _encoded(file["snapshot_sha1"], SHA1, "Snapshot locator")
                    if type(file["size"]) is not int or not 0 < file["size"] <= MAX_FILE:
                        raise DebianSourceError("invalid source manifest file size")
                    path = _archive_path(package, file["name"])
                    if path in expected:
                        raise DebianSourceError("duplicate source manifest file")
                    expected[path] = file
                if (
                    dsc["size"] > MAX_METADATA
                    or dsc["name"] != f"{identity[0]}_{identity[1].split(':', 1)[-1]}.dsc"
                ):
                    raise DebianSourceError("invalid source descriptor record")
            descriptors = {}
            seen = set()
            next_header = first.offset_data + ((first.size + 511) // 512) * 512
            while member := archive.next():
                file = expected.get(member.name)
                if (
                    file is None
                    or member.name in seen
                    or not member.isfile()
                    or member.pax_headers
                    or member.size != file["size"]
                    or member.offset != next_header
                    or member.offset_data != member.offset + 512
                ):
                    raise DebianSourceError(
                        "unexpected, duplicate, modified, or non-regular source entry"
                    )
                seen.add(member.name)
                contents = archive.extractfile(member)
                assert contents is not None
                sha256 = hashlib.sha256()
                sha1 = hashlib.sha1(usedforsecurity=False)
                data = bytearray()
                is_dsc = member.name.endswith(".dsc")
                while chunk := contents.read(1024 * 1024):
                    sha256.update(chunk)
                    sha1.update(chunk)
                    if is_dsc:
                        if len(data) + len(chunk) > MAX_METADATA:
                            raise DebianSourceError("descriptor exceeds size limit")
                        data.extend(chunk)
                if (
                    sha256.hexdigest() != file["sha256"]
                    or sha1.hexdigest() != file["snapshot_sha1"]
                ):
                    raise DebianSourceError("source file checksum mismatch")
                if is_dsc:
                    descriptors[member.name] = bytes(data)
                next_header = member.offset_data + ((member.size + 511) // 512) * 512
            if seen != set(expected):
                raise DebianSourceError("source bundle is missing files")
            for package in packages:
                rows = descriptor(
                    descriptors[_archive_path(package, package["descriptor"]["name"])],
                    package["name"],
                    package["version"],
                )
                recorded = [
                    {k: file[k] for k in ("name", "sha256", "size")} for file in package["files"]
                ]
                if rows != recorded:
                    raise DebianSourceError(
                        "source manifest differs from descriptor checksum records"
                    )
            archive.fileobj.seek(next_header)
            padding = archive.fileobj.read(10240)
            if len(padding) < 1024 or len(padding) % 512 or any(padding) or archive.fileobj.read(1):
                raise DebianSourceError("source bundle has trailing data or missing end markers")
    except (tarfile.TarError, EOFError) as error:
        raise DebianSourceError("invalid source tar archive") from error
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "verify"))
    for architecture in ("amd64", "arm64"):
        parser.add_argument(f"--inventory-{architecture}", type=Path, required=True)
        parser.add_argument(f"--digest-{architecture}", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args(argv)
    try:
        inventories = {}
        digests = {}
        for architecture in ("amd64", "arm64"):
            with getattr(args, f"inventory_{architecture}").open("rb") as stream:
                inventories[architecture] = stream.read(MAX_METADATA + 1)
            digests[architecture] = getattr(args, f"digest_{architecture}")
        if args.command == "verify":
            verify_bundle(inventories, digests, args.bundle)
        elif args.cache is None:
            raise DebianSourceError("fetch requires a dedicated --cache directory")
        else:
            collect_bundle(inventories, digests, args.bundle, args.cache)
    except (DebianSourceError, OSError) as error:
        sys.stderr.write(f"Debian source evidence: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
