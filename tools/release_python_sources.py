"""Retain locked Python source archives without extracting or executing them.

These are version-matched upstream sdists, not a claim that their build inputs
reproduce the installed wheels. Binary-only distributions remain explicit gaps.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import io
import json
import re
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import IO, Any

MAX_METADATA = 4 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_BUNDLE = 256 * 1024 * 1024
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,99}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,99}\Z")
URL = re.compile(
    r"https://files\.pythonhosted\.org/packages/[0-9a-f]{2}/[0-9a-f]{2}/"
    r"[0-9a-f]{60}/([A-Za-z0-9][A-Za-z0-9._+-]{0,199}\.(?:tar\.gz|zip))\Z"
)


class PythonSourceError(ValueError):
    """The selected image, lock, or retained source bytes do not agree."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PythonSourceError("duplicate JSON key")
        result[key] = value
    return result


def _json(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_METADATA:
        raise PythonSourceError("metadata exceeds size limit")
    try:
        value = json.loads(data, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise PythonSourceError("invalid source metadata") from error
    if not isinstance(value, dict):
        raise PythonSourceError("metadata must be an object")
    return value


def _text(value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PythonSourceError("invalid source identity")
    return value


def plan(inventory: bytes, lock: bytes, architecture: str, digest: str) -> dict[str, Any]:
    """Select only installed distributions, matching exact locked versions."""
    if architecture not in {"amd64", "arm64"}:
        raise PythonSourceError("unsupported architecture")
    _text(digest, re.compile(r"sha256:[0-9a-f]{64}\Z"))
    raw = _json(inventory)
    if type(raw.get("schema_version")) is not int or raw["schema_version"] != 2:
        raise PythonSourceError("unsupported inventory schema")
    image = raw.get("image")
    if not isinstance(image, dict) or (image.get("architecture"), image.get("platform_digest")) != (
        architecture,
        digest,
    ):
        raise PythonSourceError("inventory does not match the selected platform")
    if len(lock) > MAX_METADATA:
        raise PythonSourceError("lock exceeds size limit")
    try:
        locked = tomllib.loads(lock.decode())
    except (ValueError, UnicodeError, RecursionError) as error:
        raise PythonSourceError("invalid uv lock") from error
    packages = locked.get("package")
    if not isinstance(packages, list) or len(packages) > 4096:
        raise PythonSourceError("invalid locked package list")
    lookup: dict[tuple[str, str], dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise PythonSourceError("invalid locked package")
        name = _text(package.get("name"), NAME)
        if name == "extra-codeowners" and package.get("source") == {"editable": "."}:
            continue
        version = _text(package.get("version"), VERSION)
        if (name, version) in lookup:
            raise PythonSourceError("ambiguous locked package identity")
        lookup[name, version] = package
    python = raw.get("python")
    if (
        isinstance(python, dict)
        and "source_bundle" in python
        and python["source_bundle"] != f"python-source-{architecture}.tar.gz"
    ):
        raise PythonSourceError("unexpected Python source bundle name")
    distributions = python.get("distributions") if isinstance(python, dict) else None
    if not isinstance(distributions, list) or not 1 <= len(distributions) <= 512:
        raise PythonSourceError("invalid installed distribution list")
    sources: list[dict[str, Any]] = []
    unresolved = []
    own = []
    seen = set()
    for distribution in distributions:
        if not isinstance(distribution, dict):
            raise PythonSourceError("invalid distribution")
        name = _text(distribution.get("normalized_name"), NAME)
        version = _text(distribution.get("version"), VERSION)
        if name in seen:
            raise PythonSourceError("duplicate installed distribution")
        seen.add(name)
        identity = {"name": name, "version": version}
        if name == "extra-codeowners":
            own.append({**identity, "delivery": "application sdist in the same release"})
            continue
        package = lookup.get((name, version))
        if package is None:
            raise PythonSourceError(f"installed distribution absent from lock: {name} {version}")
        if package.get("source") != {"registry": "https://pypi.org/simple"}:
            raise PythonSourceError("source collection only supports locked PyPI packages")
        sdist = package.get("sdist")
        if sdist is None:
            unresolved.append({**identity, "reason": "lock contains no source archive"})
            continue
        if not isinstance(sdist, dict):
            raise PythonSourceError("invalid locked sdist")
        url = _text(sdist.get("url"), URL)
        if len(url.rsplit("/", 1)[1]) > 100:
            raise PythonSourceError("source filename exceeds the archive format limit")
        checksum = _text(sdist.get("hash"), re.compile(r"sha256:[0-9a-f]{64}\Z"))[7:]
        size = sdist.get("size")
        if type(size) is not int or not 0 < size <= MAX_FILE:
            raise PythonSourceError("invalid source archive size")
        sources.append(
            {
                **identity,
                "url": url,
                "sha256": checksum,
                "size": size,
                "path": f"sources/{name}/{url.rsplit('/', 1)[1]}",
            }
        )
    if sum(source["size"] for source in sources) > MAX_BUNDLE - MAX_METADATA:
        raise PythonSourceError("source archives exceed bundle size limit")
    return {
        "schema_version": 1,
        "image": {"architecture": architecture, "platform_digest": digest},
        "inventory_sha256": hashlib.sha256(inventory).hexdigest(),
        "uv_lock_sha256": hashlib.sha256(lock).hexdigest(),
        "sources": sorted(sources, key=lambda item: item["name"]),
        "unresolved_sources": sorted(unresolved, key=lambda item: item["name"]),
        "separately_delivered": own,
        "scope": "Locked Python sdists only; embedded native dependencies are not covered.",
    }


def _check(data: bytes, source: dict[str, Any]) -> None:
    if len(data) != source["size"] or hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise PythonSourceError("source archive differs from locked size or SHA-256")


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
        raise PythonSourceError("source download unexpectedly redirected")


def fetch(source: dict[str, Any]) -> bytes:
    """Fetch an opaque archive from the fixed PyPI file origin with retries."""
    url = _text(source.get("url"), URL)
    opener = urllib.request.build_opener(_NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(url, timeout=30) as response:
                if response.status != 200:
                    raise PythonSourceError("source download did not return HTTP 200")
                data: bytes = response.read(source["size"] + 1)
            _check(data, source)
            return data
        except (urllib.error.URLError, TimeoutError, http.client.IncompleteRead) as error:
            if attempt == 2:
                raise PythonSourceError("source download failed after three attempts") from error
            time.sleep(2 ** (attempt + 1))
    raise AssertionError("unreachable")  # pragma: no cover


def build(manifest: dict[str, Any], payloads: dict[str, bytes]) -> bytes:
    """Create a deterministic archive; never extract any upstream sdist."""
    if set(payloads) != {item["path"] for item in manifest["sources"]}:
        raise PythonSourceError("source payload set differs from the plan")
    for source in manifest["sources"]:
        _check(payloads[source["path"]], source)
    files = {
        "manifest.json": (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(),
        **payloads,
    }
    output = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for path, contents in sorted(files.items()):
            member = tarfile.TarInfo(path)
            member.size = len(contents)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(contents))
    return output.getvalue()


def verify(manifest: dict[str, Any], bundle: bytes) -> None:
    """Check a bundle against a freshly derived plan, without filesystem writes."""
    if len(bundle) > MAX_BUNDLE:
        raise PythonSourceError("source bundle exceeds size limit")
    expected = {source["path"]: source for source in manifest["sources"]}
    seen = set()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(bundle)) as stream:
            raw = stream.read(MAX_BUNDLE + 1)
        if len(raw) > MAX_BUNDLE:
            raise PythonSourceError("expanded source bundle exceeds size limit")
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
                    raise PythonSourceError("unexpected source bundle member")
                limit = (
                    MAX_METADATA
                    if member.name == "manifest.json"
                    else expected[member.name]["size"]
                )
                if not 0 < member.size <= limit:
                    raise PythonSourceError("unsafe source bundle member size")
                extracted = archive.extractfile(member)
                assert extracted is not None
                data = extracted.read(limit + 1)
                if member.name == "manifest.json":
                    if json.dumps(_json(data), sort_keys=True) != json.dumps(
                        manifest, sort_keys=True
                    ):
                        raise PythonSourceError("source manifest differs from the image and lock")
                else:
                    _check(data, expected[member.name])
                seen.add(member.name)
                offset = member.offset_data + ((member.size + 511) // 512) * 512
            padding = raw[offset:]
            if len(padding) < 1024 or len(padding) % 512 or any(padding):
                raise PythonSourceError("source bundle lacks end markers or contains trailing data")
        if seen != {*expected, "manifest.json"}:
            raise PythonSourceError("source bundle is incomplete")
    except (OSError, EOFError, tarfile.TarError) as error:
        raise PythonSourceError("invalid compressed source bundle") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "verify"))
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--platform-digest", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.inventory.open("rb") as stream:
            inventory = stream.read(MAX_METADATA + 1)
        with args.lock.open("rb") as stream:
            lock = stream.read(MAX_METADATA + 1)
        manifest = plan(inventory, lock, args.architecture, args.platform_digest)
        if args.command == "fetch":
            with ThreadPoolExecutor(max_workers=4) as executor:
                payloads = dict(
                    zip(
                        (source["path"] for source in manifest["sources"]),
                        executor.map(fetch, manifest["sources"]),
                        strict=True,
                    )
                )
            bundle = build(manifest, payloads)
            verify(manifest, bundle)
            with args.bundle.open("xb") as output:
                output.write(bundle)
        else:
            with args.bundle.open("rb") as stream:
                bundle = stream.read(MAX_BUNDLE + 1)
            verify(manifest, bundle)
    except (PythonSourceError, OSError) as error:
        sys.stderr.write(f"Python source evidence: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
