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
MAX_LEGACY_BUNDLE_BYTES = MAX_SOURCE_BYTES + 1024 * 1024
MAX_IMAGE_MANIFEST_BYTES = 64 * 1024
MAX_LAYER_SOURCE_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = MAX_LEGACY_BUNDLE_BYTES + MAX_IMAGE_MANIFEST_BYTES + MAX_LAYER_SOURCE_BYTES
MAX_INVENTORY_BYTES = 16 * 1024 * 1024
CURRENT_NOTICE_SCHEMA = 3
LAYER_SOURCE_SCHEMA = 4
INCORPORATED_NOTICES_SCHEMA = 5
IMAGE_MANIFEST_PATH = "image-manifest.json"
_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_OCI_GZIP_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
_CPYTHON_31410 = ("3.14.10", "de414a57119abef52784d8993e341d53aed635fc2b05c2607d9f98a2c5b72032")
_HACL_REVISION = "8ba599b2f6c9701b3dc961db895b0856a2210f76"
_INCORPORATED_NOTICES = {
    _CPYTHON_31410: "8a7329b25131f64b2bea284155f0824876b1af9f4a2f970e6335751d97dfa6dd"
}

# Both shipped layers contain the identical wheel, even though a later layer
# hides it with a whiteout. The version and byte comparison are recorded at:
# https://github.com/stampbot/extra-codeowners/issues/18#issuecomment-7093616573
_PIP_LAYERS = {
    "amd64": ("sha256:57257d6d8137dab325b25390b3711f8dd1a2a3a45fef1686d0177e058fc68403", 12412045),
    "arm64": ("sha256:e232ddaa6e0a0a5a10b926f127d51b67808609aae0cc160e61ae61ed96373170", 12325172),
}
_PIP_VERSION = "26.2.2"
_PIP_WHEEL_PATH = "usr/local/lib/python3.14/ensurepip/_bundled/pip-26.2.2-py3-none-any.whl"
_PIP_WHEEL_SHA256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
_PIP_SOURCE_PATH = "layer-sources/pip-26.2.2.tar.gz"
_PIP_SOURCE_SHA256 = "3a8e5c800492787f33a4114ef54444546c340df428974ebba17e0fd47e11af2f"
_PIP_SOURCE_SIZE = 1863336
_PIP_SOURCE_URL = (
    "https://files.pythonhosted.org/packages/fa/e8/"
    "0842d757e483e895e670f655084cfe8b8c72580c6769a76b30b2789a0608/pip-26.2.2.tar.gz"
)

# Bind the reviewed file paths and hashes to the exact upstream archive, not
# just to a version string. The two-platform runtime evidence is in #18:
# https://github.com/stampbot/extra-codeowners/issues/18#issuecomment-7069586882
# https://github.com/stampbot/extra-codeowners/issues/18#issuecomment-7083094097
_BUNDLED_NOTICES: dict[tuple[str, str], tuple[tuple[str, str, str, str], ...]] = {
    _CPYTHON_31410: (
        (
            "expat",
            "2.9.0",
            "Modules/expat/COPYING",
            "31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87",
        ),
        (
            "hacl-star",
            _HACL_REVISION,
            "Modules/_hacl/Hacl_Hash_SHA3.c",
            "8744f5b6e054c3e5c44f413a60f9154b76dd7230135dcee26fd063755ec64be1",
        ),
        (
            "libmpdec",
            "2.5.1",
            "Modules/_decimal/libmpdec/mpdecimal.c",
            "4f89b8095e408a18deff79cfb605299e615bae747898eb105d8936064f7fb626",
        ),
        (
            "libmpdec",
            "2.5.1",
            "Modules/_decimal/libmpdec/mpdecimal.h",
            "ea0b9c6b296c13aed6ecaa50b463e39a9c1bdc059b84f50507fd8247b2e660f9",
        ),
    ),
}

# These paths are relative to the retained CPython archive root. Its build
# templates and the generated configs for both alpha.100 images were checked:
# https://github.com/stampbot/extra-codeowners/issues/18#issuecomment-7093155810
_HACL_NOTICES = {
    _CPYTHON_31410: {
        "common": (
            ("Hacl_Hash_MD5.c", "5b91ed0339074e2e546119833398e2cdb7190c33a59c405bf43b2417c789547d"),
            (
                "Hacl_Hash_SHA1.c",
                "ce08721d491f3b8a9bd4cde6c27bfcc8fc01471512ccca4bd3c0b764cb551d29",
            ),
            (
                "Hacl_Hash_SHA2.c",
                "f8af382de7e29a73c726f9c70770498ddd99e2c4702489ed6e634f0b68597c95",
            ),
            (
                "Hacl_Hash_Blake2b.c",
                "6a492aa586f2d10b1b300ce8ce4c72c976ff7548fee667aded2253f99969ac87",
            ),
            (
                "Hacl_Hash_Blake2s.c",
                "f3204f3e60734d811b6630f879b69ce54eaf367f3fca5889c1026e7a1f3ee1e4",
            ),
            ("Hacl_HMAC.c", "142adb769ff02b8a5327f0eb837e1f9a797bdf9a1684d21acd749dbb5b2e5be2"),
            (
                "Hacl_Streaming_HMAC.c",
                "29fcf948a3715e09cbbd434cebb6105f276236a6e4947d237b7bf06634bf2432",
            ),
        ),
        "amd64": (
            (
                "Hacl_Hash_Blake2b_Simd256.c",
                "9eb22953ce60dde9dc970fec9dfce9d94235f4b7ccd8f0151cad4707dc835d1d",
            ),
            (
                "Hacl_Hash_Blake2s_Simd128.c",
                "c93746df2f219cbb1634ee6fb0ab1c4cbd381d1f36c637114c68346c9935326d",
            ),
        ),
        "arm64": (),
    },
}


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


def _pip_layer(architecture: str, platform_digest: str, manifest: bytes) -> dict[str, object]:
    if (
        not 0 < len(manifest) <= MAX_IMAGE_MANIFEST_BYTES
        or "sha256:" + hashlib.sha256(manifest).hexdigest() != platform_digest
    ):
        raise SourceError("OCI image manifest does not match the selected child digest")
    image = _json(manifest)
    layers = image.get("layers")
    if (
        type(image.get("schemaVersion")) is not int
        or image["schemaVersion"] != 2
        or image.get("mediaType") != _OCI_MANIFEST
        or "manifests" in image
        or not isinstance(layers, list)
        or not 0 < len(layers) <= 256
        or any(not isinstance(layer, dict) for layer in layers)
    ):
        raise SourceError("expected one OCI image manifest with a bounded layer list")
    digest, size = _PIP_LAYERS[architecture]
    matches = [layer for layer in layers if layer.get("digest") == digest]
    if (
        len(matches) != 1
        or matches[0].get("mediaType") != _OCI_GZIP_LAYER
        or type(matches[0].get("size")) is not int
        or matches[0]["size"] != size
    ):
        raise SourceError("image no longer contains the reviewed pip layer for this architecture")
    return {"digest": digest, "mediaType": _OCI_GZIP_LAYER, "size": size}


def _pip_record(
    architecture: str, platform_digest: str, manifest: bytes, pip_source: bytes
) -> dict[str, object]:
    layer = _pip_layer(architecture, platform_digest, manifest)
    if (
        not 0 < len(pip_source) <= MAX_LAYER_SOURCE_BYTES
        or len(pip_source) != _PIP_SOURCE_SIZE
        or hashlib.sha256(pip_source).hexdigest() != _PIP_SOURCE_SHA256
    ):
        raise SourceError("pip source differs from the reviewed size or checksum")
    return {
        "component": "pip",
        "version": _PIP_VERSION,
        "layer": layer,
        "wheel": {"path": _PIP_WHEEL_PATH, "sha256": _PIP_WHEEL_SHA256},
        "source": {
            "path": _PIP_SOURCE_PATH,
            "size": _PIP_SOURCE_SIZE,
            "sha256": _PIP_SOURCE_SHA256,
            "url": _PIP_SOURCE_URL,
        },
    }


def _manifest(
    inventory: bytes,
    architecture: str,
    platform_digest: str,
    source: bytes,
    *,
    notice_schema: int = 1,
    layer_evidence: tuple[bytes, bytes] | None = None,
) -> dict[str, object]:
    version, checksum, url = _identity(inventory, architecture, platform_digest)
    if not 0 < len(source) <= MAX_SOURCE_BYTES:
        raise SourceError("source archive has an unsafe size")
    if hashlib.sha256(source).hexdigest() != checksum:
        raise SourceError("source archive checksum differs from the image inventory")
    manifest: dict[str, object] = {
        "schema_version": notice_schema,
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
    if notice_schema >= 2:
        notices = _BUNDLED_NOTICES.get((version, checksum))
        if not notices:
            raise SourceError("no bundled notice review for this exact CPython source archive")
        if notice_schema >= 3:
            platform_notices = _HACL_NOTICES.get((version, checksum))
            if not platform_notices or architecture not in platform_notices:
                raise SourceError("no HACL notice review for this CPython source and platform")
            additional = (*platform_notices["common"], *platform_notices[architecture])
            notices = (
                *notices,
                *(
                    ("hacl-star", _HACL_REVISION, f"Modules/_hacl/{path}", digest)
                    for path, digest in additional
                ),
            )
        if notice_schema >= INCORPORATED_NOTICES_SCHEMA:
            doc_checksum = _INCORPORATED_NOTICES.get((version, checksum))
            if not doc_checksum:
                raise SourceError("no incorporated-software notice review for this CPython archive")
            notices = (
                *notices,
                ("cpython-incorporated-software", version, "Doc/license.rst", doc_checksum),
            )
        manifest["bundled_notices"] = [
            {
                "component": component,
                "version": component_version,
                "path": f"Python-{version}/{path}",
                "sha256": digest,
            }
            for component, component_version, path, digest in notices
        ]
    if notice_schema >= LAYER_SOURCE_SCHEMA:
        if layer_evidence is None:
            raise SourceError("source bundle omitted the OCI manifest or pip source archive")
        manifest["image_manifest"] = IMAGE_MANIFEST_PATH
        manifest["layer_sources"] = [_pip_record(architecture, platform_digest, *layer_evidence)]
        manifest["scope"] = (
            "CPython and reviewed pip layer source; not the complete container source"
        )
    return manifest


def build_bundle(
    inventory: bytes,
    source: bytes,
    *,
    architecture: str,
    platform_digest: str,
    require_bundled_notices: bool = False,
    layer_evidence: tuple[bytes, bytes] | None = None,
) -> bytes:
    """Return a deterministic bundle after checking the upstream archive hash."""
    schema = CURRENT_NOTICE_SCHEMA if require_bundled_notices else 1
    if layer_evidence is not None:
        schema = INCORPORATED_NOTICES_SCHEMA
    manifest = _manifest(
        inventory,
        architecture,
        platform_digest,
        source,
        notice_schema=schema,
        layer_evidence=layer_evidence,
    )
    version, _, _ = _identity(inventory, architecture, platform_digest)
    members = [
        ("manifest.json", (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()),
        (f"Python-{version}.tar.xz", source),
    ]
    if layer_evidence is not None:
        members.extend(
            ((IMAGE_MANIFEST_PATH, layer_evidence[0]), (_PIP_SOURCE_PATH, layer_evidence[1]))
        )
    output = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for name, contents in members:
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
    inventory: bytes,
    bundle: bytes,
    *,
    architecture: str,
    platform_digest: str,
    require_bundled_notices: bool = False,
    require_layer_sources: bool = False,
) -> dict[str, object]:
    """Check identity, manifest, and archive bytes without filesystem extraction."""
    version, _, _ = _identity(inventory, architecture, platform_digest)
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise SourceError("source bundle exceeds size limit")
    cpython_path = f"Python-{version}.tar.xz"
    expected_paths = {"manifest.json", cpython_path}
    layer_paths = {IMAGE_MANIFEST_PATH, _PIP_SOURCE_PATH}
    limits = {
        "manifest.json": 64 * 1024,
        cpython_path: MAX_SOURCE_BYTES,
        IMAGE_MANIFEST_PATH: MAX_IMAGE_MANIFEST_BYTES,
        _PIP_SOURCE_PATH: MAX_LAYER_SOURCE_BYTES,
    }
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(bundle), mode="rb") as compressed:
            uncompressed = _bounded_read(compressed, MAX_BUNDLE_BYTES)
        with tarfile.open(fileobj=io.BytesIO(uncompressed), mode="r:") as archive:
            files: dict[str, bytes] = {}
            next_header = 0
            for member in archive:
                if (
                    member.name not in limits
                    or member.name in files
                    or not member.isfile()
                    or member.pax_headers
                    or member.offset != next_header
                    or member.offset_data != member.offset + 512
                ):
                    raise SourceError("unexpected, duplicate, or non-regular source bundle member")
                limit = limits[member.name]
                if not 0 < member.size <= limit:
                    raise SourceError("source bundle member has an unsafe size")
                extracted = archive.extractfile(member)
                if extracted is None:  # pragma: no cover - regular files always return a reader.
                    raise SourceError("could not read source bundle member")
                files[member.name] = _bounded_read(extracted, limit)
                next_header = member.offset_data + ((member.size + 511) // 512) * 512
            if not expected_paths <= files.keys():
                raise SourceError("source bundle is incomplete")
            padding = uncompressed[next_header:]
            if len(padding) < 1024 or len(padding) % 512 or any(padding):
                raise SourceError("source bundle contains trailing data or lacks end markers")
    except (OSError, EOFError, tarfile.TarError) as error:
        raise SourceError("invalid compressed source bundle") from error
    actual = _json(files["manifest.json"])
    schema = actual.get("schema_version")
    if type(schema) is not int or schema not in {
        1,
        2,
        CURRENT_NOTICE_SCHEMA,
        LAYER_SOURCE_SCHEMA,
        INCORPORATED_NOTICES_SCHEMA,
    }:
        raise SourceError("unsupported source manifest schema")
    if require_bundled_notices and schema < CURRENT_NOTICE_SCHEMA:
        raise SourceError("source manifest omitted the required bundled notices")
    if require_layer_sources and schema < LAYER_SOURCE_SCHEMA:
        raise SourceError("source manifest omitted the required layer sources")
    if schema >= LAYER_SOURCE_SCHEMA:
        if set(files) != expected_paths | layer_paths:
            raise SourceError("source bundle omitted the OCI manifest or pip source archive")
        layer_evidence = (files[IMAGE_MANIFEST_PATH], files[_PIP_SOURCE_PATH])
    else:
        if set(files) != expected_paths:
            raise SourceError("older source bundle schema contains unexpected layer evidence")
        if max(len(bundle), len(uncompressed)) > MAX_LEGACY_BUNDLE_BYTES:
            raise SourceError("older source bundle exceeds its size limit")
        layer_evidence = None
    expected = _manifest(
        inventory,
        architecture,
        platform_digest,
        files[cpython_path],
        notice_schema=schema,
        layer_evidence=layer_evidence,
    )
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
        raise SourceError("source download unexpectedly redirected")


def _download(url: str, limit: int, label: str) -> bytes:
    opener = urllib.request.build_opener(_NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(url, timeout=30) as response:
                if response.status != 200:
                    raise SourceError(f"{label} source download did not return HTTP 200")
                return _bounded_read(response, limit)
        except (urllib.error.URLError, TimeoutError, http.client.IncompleteRead) as error:
            if attempt == 2:
                raise SourceError(f"{label} source download failed after three attempts") from error
            time.sleep(2 ** (attempt + 1))
    raise AssertionError("unreachable")  # pragma: no cover


def fetch_source(inventory: bytes, *, architecture: str, platform_digest: str) -> bytes:
    """Download from the fixed python.org path, retrying transient network errors."""
    _, _, url = _identity(inventory, architecture, platform_digest)
    source = _download(url, MAX_SOURCE_BYTES, "CPython")
    _manifest(inventory, architecture, platform_digest, source)
    return source


def main(argv: Sequence[str] | None = None) -> int:
    """Fetch or verify one platform's CPython source bundle."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "verify"))
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--platform-digest", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument(
        "--require-bundled-notices",
        action="store_true",
        help="include the current reviewed notice index when fetching; require it when verifying",
    )
    parser.add_argument(
        "--image-manifest",
        type=Path,
        help="include layer source evidence using the raw OCI child manifest (fetch only)",
    )
    parser.add_argument(
        "--require-layer-sources",
        action="store_true",
        help="reject bundles without the reviewed layer source contract",
    )
    args = parser.parse_args(argv)
    if args.command == "verify" and args.image_manifest is not None:
        parser.error("--image-manifest is only valid with fetch")
    if args.command == "fetch" and args.require_layer_sources and args.image_manifest is None:
        parser.error("--require-layer-sources with fetch needs --image-manifest")
    try:
        with args.inventory.open("rb") as stream:
            inventory = _bounded_read(stream, MAX_INVENTORY_BYTES)
        if args.command == "fetch":
            layer_evidence = None
            if args.image_manifest is not None:
                with args.image_manifest.open("rb") as stream:
                    manifest = _bounded_read(stream, MAX_IMAGE_MANIFEST_BYTES)
                _identity(inventory, args.architecture, args.platform_digest)
                _pip_layer(args.architecture, args.platform_digest, manifest)
                pip_source = _download(_PIP_SOURCE_URL, MAX_LAYER_SOURCE_BYTES, "pip")
                layer_evidence = (manifest, pip_source)
            source = fetch_source(
                inventory, architecture=args.architecture, platform_digest=args.platform_digest
            )
            bundle = build_bundle(
                inventory,
                source,
                architecture=args.architecture,
                platform_digest=args.platform_digest,
                require_bundled_notices=args.require_bundled_notices,
                layer_evidence=layer_evidence,
            )
            # Never leave an output artifact after a failed download or validation.
            verify_bundle(
                inventory,
                bundle,
                architecture=args.architecture,
                platform_digest=args.platform_digest,
                require_bundled_notices=args.require_bundled_notices,
                require_layer_sources=args.require_layer_sources,
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
                require_bundled_notices=args.require_bundled_notices,
                require_layer_sources=args.require_layer_sources,
            )
    except (SourceError, OSError) as error:
        sys.stderr.write(f"source evidence: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
