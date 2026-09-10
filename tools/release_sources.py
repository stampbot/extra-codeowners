"""Retain the CPython archive identified by a platform's distribution inventory.

This delivers upstream source bytes, not an assertion that they reproduce the
image or satisfy every component's distribution requirements. Archives remain
opaque: neither collection nor verification extracts or runs upstream code.
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
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Protocol

MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = MAX_SOURCE_BYTES + 1024 * 1024
MAX_INVENTORY_BYTES = 16 * 1024 * 1024


class SourceError(ValueError):
    """The source bytes or their image identity could not be verified."""


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SourceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json(contents: bytes) -> dict[str, object]:
    try:
        value = json.loads(contents, object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise SourceError("invalid source evidence JSON") from error
    if not isinstance(value, dict):
        raise SourceError("source evidence must be a JSON object")
    return value


def _identity(inventory: bytes, architecture: str, platform_digest: str) -> tuple[str, str, str]:
    if architecture not in {"amd64", "arm64"}:
        raise SourceError("unsupported architecture")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", platform_digest) is None:
        raise SourceError("invalid platform digest")
    if len(inventory) > MAX_INVENTORY_BYTES:
        raise SourceError("inventory exceeds size limit")
    value = _json(inventory)
    if type(value.get("schema_version")) is not int or value["schema_version"] != 2:
        raise SourceError("unsupported inventory schema")
    image = value.get("image")
    if (
        not isinstance(image, dict)
        or image.get("architecture") != architecture
        or image.get("platform_digest") != platform_digest
    ):
        raise SourceError("inventory does not match the selected platform")
    source = value.get("cpython")
    if not isinstance(source, dict):
        raise SourceError("inventory omitted CPython source identity")
    version = source.get("version")
    checksum = source.get("source_sha256")
    if not isinstance(version, str) or re.fullmatch(r"3\.\d+\.\d+", version) is None:
        raise SourceError("invalid CPython version")
    if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
        raise SourceError("invalid CPython source checksum")
    url = f"https://www.python.org/ftp/python/{version}/Python-{version}.tar.xz"
    if source.get("source_url") != url:
        raise SourceError("unexpected CPython source URL")
    if (
        "source_bundle" in source
        and source["source_bundle"] != f"cpython-source-{architecture}.tar.gz"
    ):
        raise SourceError("unexpected CPython source bundle name")
    return version, checksum, url


def _manifest(
    inventory: bytes, architecture: str, platform_digest: str, source: bytes
) -> dict[str, object]:
    version, checksum, url = _identity(inventory, architecture, platform_digest)
    if not 0 < len(source) <= MAX_SOURCE_BYTES:
        raise SourceError("source archive has an unsafe size")
    if hashlib.sha256(source).hexdigest() != checksum:
        raise SourceError("source archive checksum differs from the image inventory")
    return {
        "schema_version": 1,
        "image": {"architecture": architecture, "platform_digest": platform_digest},
        "inventory_sha256": hashlib.sha256(inventory).hexdigest(),
        "component": "cpython",
        "version": version,
        "source": {
            "path": f"Python-{version}.tar.xz",
            "sha256": checksum,
            "size": len(source),
            "url": url,
        },
        "evidence": "source archive identified by the Docker Official Python image",
        "scope": "CPython upstream source only; not the complete container source",
    }


def build_bundle(
    inventory: bytes, source: bytes, *, architecture: str, platform_digest: str
) -> bytes:
    """Return a deterministic bundle after checking the upstream archive hash."""
    manifest = _manifest(inventory, architecture, platform_digest, source)
    version, _, _ = _identity(inventory, architecture, platform_digest)
    output = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for name, contents in (
            ("manifest.json", (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()),
            (f"Python-{version}.tar.xz", source),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(contents)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(contents))
    return output.getvalue()


class _Reader(Protocol):
    def read(self, size: int = -1, /) -> bytes:
        """Read at most size bytes from the stream."""


def _bounded_read(stream: _Reader, limit: int) -> bytes:
    contents = stream.read(limit + 1)
    if len(contents) > limit:
        raise SourceError("source evidence exceeds size limit")
    return contents


def verify_bundle(
    inventory: bytes, bundle: bytes, *, architecture: str, platform_digest: str
) -> dict[str, object]:
    """Check identity, manifest, and archive bytes without filesystem extraction."""
    version, _, _ = _identity(inventory, architecture, platform_digest)
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise SourceError("source bundle exceeds size limit")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(bundle), mode="rb") as compressed:
            uncompressed = _bounded_read(compressed, MAX_BUNDLE_BYTES)
        with tarfile.open(fileobj=io.BytesIO(uncompressed), mode="r:") as archive:
            files: dict[str, bytes] = {}
            expected_paths = {"manifest.json", f"Python-{version}.tar.xz"}
            next_header = 0
            for member in archive:
                if (
                    member.name not in expected_paths
                    or member.name in files
                    or not member.isfile()
                    or member.pax_headers
                    or member.offset != next_header
                    or member.offset_data != member.offset + 512
                ):
                    raise SourceError("unexpected, duplicate, or non-regular source bundle member")
                limit = 64 * 1024 if member.name == "manifest.json" else MAX_SOURCE_BYTES
                if not 0 < member.size <= limit:
                    raise SourceError("source bundle member has an unsafe size")
                extracted = archive.extractfile(member)
                if extracted is None:  # pragma: no cover - regular files always return a reader.
                    raise SourceError("could not read source bundle member")
                files[member.name] = _bounded_read(extracted, limit)
                next_header = member.offset_data + ((member.size + 511) // 512) * 512
            if set(files) != expected_paths:
                raise SourceError("source bundle is incomplete")
            padding = uncompressed[next_header:]
            if len(padding) < 1024 or len(padding) % 512 or any(padding):
                raise SourceError("source bundle contains trailing data or lacks end markers")
    except (OSError, EOFError, tarfile.TarError) as error:
        raise SourceError("invalid compressed source bundle") from error
    expected = _manifest(
        inventory, architecture, platform_digest, files[f"Python-{version}.tar.xz"]
    )
    actual = _json(files["manifest.json"])
    if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise SourceError("source manifest differs from the selected inventory and archive")
    return actual


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
        raise SourceError("CPython source download unexpectedly redirected")


def fetch_source(inventory: bytes, *, architecture: str, platform_digest: str) -> bytes:
    """Download from the fixed python.org path, retrying transient network errors."""
    _, _, url = _identity(inventory, architecture, platform_digest)
    opener = urllib.request.build_opener(_NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(url, timeout=30) as response:
                if response.status != 200:
                    raise SourceError("CPython source download did not return HTTP 200")
                source = _bounded_read(response, MAX_SOURCE_BYTES)
            _manifest(inventory, architecture, platform_digest, source)
            return source
        except (urllib.error.URLError, TimeoutError, http.client.IncompleteRead) as error:
            if attempt == 2:
                raise SourceError("CPython source download failed after three attempts") from error
            time.sleep(2 ** (attempt + 1))
    raise AssertionError("unreachable")  # pragma: no cover


def main(argv: Sequence[str] | None = None) -> int:
    """Fetch or verify one platform's CPython source bundle."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "verify"))
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--platform-digest", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.inventory.open("rb") as stream:
            inventory = _bounded_read(stream, MAX_INVENTORY_BYTES)
        if args.command == "fetch":
            source = fetch_source(
                inventory, architecture=args.architecture, platform_digest=args.platform_digest
            )
            bundle = build_bundle(
                inventory,
                source,
                architecture=args.architecture,
                platform_digest=args.platform_digest,
            )
            # Never leave an output artifact after a failed download or validation.
            verify_bundle(
                inventory,
                bundle,
                architecture=args.architecture,
                platform_digest=args.platform_digest,
            )
            with args.bundle.open("xb") as output:
                output.write(bundle)
        else:
            with args.bundle.open("rb") as stream:
                bundle = _bounded_read(stream, MAX_BUNDLE_BYTES)
            verify_bundle(
                inventory,
                bundle,
                architecture=args.architecture,
                platform_digest=args.platform_digest,
            )
    except (SourceError, OSError) as error:
        sys.stderr.write(f"source evidence: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
