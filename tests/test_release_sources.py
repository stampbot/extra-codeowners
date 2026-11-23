"""Source delivery checks use inert bytes, never an upstream build."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import json
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TypedDict
from unittest.mock import Mock

import pytest

from tools import release_sources as sources

DIGEST = "sha256:" + "a" * 64
SOURCE = b"opaque upstream source archive"
SOURCE_NAME = "Python-3.14.7.tar.xz"


class _PlatformArgs(TypedDict):
    architecture: str
    platform_digest: str


def _inventory() -> bytes:
    return json.dumps(
        {
            "schema_version": 2,
            "image": {"architecture": "amd64", "platform_digest": DIGEST},
            "cpython": {
                "version": "3.14.7",
                "source_sha256": hashlib.sha256(SOURCE).hexdigest(),
                "source_url": f"https://www.python.org/ftp/python/3.14.7/{SOURCE_NAME}",
            },
        }
    ).encode()


def _bundle(inventory: bytes | None = None) -> bytes:
    return sources.build_bundle(
        inventory or _inventory(), SOURCE, architecture="amd64", platform_digest=DIGEST
    )


def _verify(bundle: bytes, inventory: bytes | None = None) -> dict[str, object]:
    return sources.verify_bundle(
        inventory or _inventory(), bundle, architecture="amd64", platform_digest=DIGEST
    )


def _repack(bundle: bytes, name: str, contents: bytes, *, append: bool = False) -> bytes:
    output = io.BytesIO()
    with (
        tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as old,
        tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as new,
    ):
        for member in old:
            extracted = old.extractfile(member)
            assert extracted is not None
            data = extracted.read()
            if member.name == name and not append:
                data = contents
            member.size = len(data)
            new.addfile(member, io.BytesIO(data))
        if append:
            member = tarfile.TarInfo(name)
            member.size = len(contents)
            new.addfile(member, io.BytesIO(contents))
    return output.getvalue()


def test_bundle_is_deterministic_and_bound_to_inventory_and_platform() -> None:
    bundle = _bundle()
    assert bundle == _bundle()
    manifest = _verify(bundle)
    assert manifest["inventory_sha256"] == hashlib.sha256(_inventory()).hexdigest()
    assert manifest["image"] == {"architecture": "amd64", "platform_digest": DIGEST}
    assert manifest["source"] == {
        "path": SOURCE_NAME,
        "size": len(SOURCE),
        "sha256": hashlib.sha256(SOURCE).hexdigest(),
        "url": f"https://www.python.org/ftp/python/3.14.7/{SOURCE_NAME}",
    }
    # Verification cannot depend on another host's gzip/zlib implementation.
    assert _verify(gzip.compress(gzip.decompress(bundle), compresslevel=1)) == manifest


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        (None, "schema_version", True),
        ("image", "architecture", "arm64"),
        ("image", "platform_digest", "sha256:" + "b" * 64),
        ("cpython", "version", "../../evil"),
        ("cpython", "source_sha256", "invalid"),
        ("cpython", "source_url", "http://127.0.0.1/secrets"),
        ("cpython", "source_url", "https://www.python.org@evil.example/source"),
        ("cpython", "source_bundle", "cpython-source-arm64.tar.gz"),
    ],
)
def test_rejects_invalid_identity(section: str | None, key: str, value: object) -> None:
    inventory = json.loads(_inventory())
    target = inventory if section is None else inventory[section]
    target[key] = value
    with pytest.raises(sources.SourceError):
        _bundle(json.dumps(inventory).encode())


def test_rejects_missing_source_and_duplicate_json_keys() -> None:
    inventory = json.loads(_inventory())
    del inventory["cpython"]
    with pytest.raises(sources.SourceError, match="omitted CPython"):
        _bundle(json.dumps(inventory).encode())
    with pytest.raises(sources.SourceError, match="JSON"):
        _bundle(
            _inventory().replace(b'"schema_version": 2', b'"schema_version": 1,"schema_version": 2')
        )


def test_rejects_source_checksum_mismatch_before_packaging() -> None:
    with pytest.raises(sources.SourceError, match="checksum"):
        sources.build_bundle(
            _inventory(), b"modified", architecture="amd64", platform_digest=DIGEST
        )


def test_rejects_changed_inventory_even_when_source_identity_matches() -> None:
    with pytest.raises(sources.SourceError, match="manifest differs"):
        _verify(_bundle(), _inventory() + b"\n")


@pytest.mark.parametrize("path", ["manifest.json", SOURCE_NAME, "../outside", "extra-file"])
def test_rejects_extra_or_duplicate_entries(path: str) -> None:
    with pytest.raises(sources.SourceError, match="unexpected, duplicate"):
        _verify(_repack(_bundle(), path, b"extra", append=True))


def test_rejects_tampered_manifest_and_source() -> None:
    with pytest.raises(sources.SourceError, match="unsupported source manifest schema"):
        _verify(_repack(_bundle(), "manifest.json", b"{}"))
    with pytest.raises(sources.SourceError, match="checksum"):
        _verify(_repack(_bundle(), SOURCE_NAME, b"tampered"))


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE])
def test_rejects_links_and_directories(kind: bytes) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("manifest.json")
        member.type = kind
        member.linkname = "/etc/passwd"
        archive.addfile(member)
    with pytest.raises(sources.SourceError, match="non-regular"):
        _verify(output.getvalue())


def test_rejects_missing_members_invalid_compression_and_hidden_trailing_data() -> None:
    for invalid in (b"garbage", _bundle()[:100], gzip.compress(b"\0" * 10240)):
        with pytest.raises(sources.SourceError):
            _verify(invalid)
    with pytest.raises(sources.SourceError, match="trailing data"):
        _verify(gzip.compress(gzip.decompress(_bundle()) + b"hidden"))


def test_enforces_download_and_decompression_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _bundle()
    monkeypatch.setattr(sources, "MAX_SOURCE_BYTES", 2)
    with pytest.raises(sources.SourceError, match="unsafe size"):
        _bundle()
    monkeypatch.setattr(sources, "MAX_BUNDLE_BYTES", 1000)
    with pytest.raises(sources.SourceError, match="size limit"):
        _verify(bundle)


def test_fetch_retries_network_errors_but_not_checksum_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = SOURCE
    opener = Mock()
    opener.open.side_effect = [urllib.error.URLError("temporary"), response]
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: opener)
    sleeps = Mock()
    monkeypatch.setattr(time, "sleep", sleeps)
    assert (
        sources.fetch_source(_inventory(), architecture="amd64", platform_digest=DIGEST) == SOURCE
    )
    assert opener.open.call_count == 2
    sleeps.assert_called_once_with(2)
    response.read.return_value = b"tampered"
    opener.open.side_effect = None
    opener.open.return_value = response
    opener.open.reset_mock()
    with pytest.raises(sources.SourceError, match="checksum"):
        sources.fetch_source(_inventory(), architecture="amd64", platform_digest=DIGEST)
    assert opener.open.call_count == 1


@pytest.mark.parametrize(
    "error", [urllib.error.URLError("offline"), http.client.IncompleteRead(b"")]
)
def test_fetch_exhausts_retries_without_creating_evidence(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    opener = Mock()
    opener.open.side_effect = error
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: opener)
    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    with pytest.raises(sources.SourceError, match="three attempts"):
        sources.fetch_source(_inventory(), architecture="amd64", platform_digest=DIGEST)
    assert opener.open.call_count == 3


def test_source_downloader_rejects_redirects() -> None:
    handler = sources._NoRedirect()
    request = urllib.request.Request("https://www.python.org/source")
    with pytest.raises(sources.SourceError, match="redirected"):
        handler.redirect_request(request, io.BytesIO(), 302, "Found", {}, "http://127.0.0.1/")


def test_manifest_rejects_boolean_schema_and_floating_point_size() -> None:
    manifest = _verify(_bundle())
    manifest["schema_version"] = True
    with pytest.raises(sources.SourceError, match="unsupported source manifest schema"):
        _verify(_repack(_bundle(), "manifest.json", json.dumps(manifest).encode()))
    manifest = _verify(_bundle())
    source = manifest["source"]
    assert isinstance(source, dict)
    source["size"] = float(source["size"])
    with pytest.raises(sources.SourceError, match="manifest differs"):
        _verify(_repack(_bundle(), "manifest.json", json.dumps(manifest).encode()))


def test_cli_fetch_and_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_bytes(_inventory())
    bundle = tmp_path / "source.tar.gz"
    arguments = [
        "--inventory",
        str(inventory),
        "--architecture",
        "amd64",
        "--platform-digest",
        DIGEST,
        "--bundle",
        str(bundle),
    ]
    monkeypatch.setattr(sources, "fetch_source", lambda *args, **kwargs: SOURCE)
    assert sources.main(["fetch", *arguments]) == 0
    assert sources.main(["verify", *arguments]) == 0
    assert sources.main(["fetch", *arguments]) == 1  # Refuse to overwrite existing evidence.
    bundle.write_bytes(b"tampered")
    assert sources.main(["verify", *arguments]) == 1


def test_notice_manifest_is_bound_to_exact_source_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    archive_hash = hashlib.sha256(SOURCE).hexdigest()
    notice_hash = hashlib.sha256(b"fixture notice").hexdigest()
    monkeypatch.setattr(
        sources,
        "_BUNDLED_NOTICES",
        {("3.14.7", archive_hash): (("fixture", "1.2.3", "Modules/fixture/NOTICE", notice_hash),)},
    )
    monkeypatch.setattr(
        sources, "_HACL_NOTICES", {("3.14.7", archive_hash): {"common": (), "amd64": ()}}
    )
    bundle = sources.build_bundle(
        _inventory(),
        SOURCE,
        architecture="amd64",
        platform_digest=DIGEST,
        require_bundled_notices=True,
    )
    manifest = _verify(bundle)
    assert manifest["schema_version"] == 3
    assert manifest["bundled_notices"] == [
        {
            "component": "fixture",
            "version": "1.2.3",
            "path": "Python-3.14.7/Modules/fixture/NOTICE",
            "sha256": notice_hash,
        }
    ]
    manifest["bundled_notices"] = []
    with pytest.raises(sources.SourceError, match="manifest differs"):
        _verify(_repack(bundle, "manifest.json", json.dumps(manifest).encode()))

    modified_source = SOURCE + b" changed with the same version"
    inventory = _inventory().replace(
        archive_hash.encode(), hashlib.sha256(modified_source).hexdigest().encode()
    )
    with pytest.raises(sources.SourceError, match="no bundled notice review"):
        sources.build_bundle(
            inventory,
            modified_source,
            architecture="amd64",
            platform_digest=DIGEST,
            require_bundled_notices=True,
        )


def test_release_verifier_requires_notices_but_legacy_bundles_still_verify() -> None:
    legacy = _bundle()
    assert _verify(legacy)["schema_version"] == 1
    with pytest.raises(sources.SourceError, match="omitted the required bundled notices"):
        sources.verify_bundle(
            _inventory(),
            legacy,
            architecture="amd64",
            platform_digest=DIGEST,
            require_bundled_notices=True,
        )


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_current_notice_index_keeps_the_platform_scope_and_preserves_schema_two(
    monkeypatch: pytest.MonkeyPatch, architecture: str
) -> None:
    key = ("3.14.7", hashlib.sha256(SOURCE).hexdigest())
    monkeypatch.setattr(
        sources,
        "_BUNDLED_NOTICES",
        {key: (("fixture", "1.2.3", "Modules/fixture/NOTICE", "a" * 64),)},
    )
    monkeypatch.setattr(
        sources,
        "_HACL_NOTICES",
        {key: {"common": (("Common.c", "b" * 64),), "amd64": (("Simd.c", "c" * 64),), "arm64": ()}},
    )
    inventory = _inventory().replace(b"amd64", architecture.encode())
    args = _PlatformArgs(architecture=architecture, platform_digest=DIGEST)
    bundle = sources.build_bundle(inventory, SOURCE, require_bundled_notices=True, **args)
    observed = sources.verify_bundle(inventory, bundle, require_bundled_notices=True, **args)
    assert observed["schema_version"] == 3
    records = observed["bundled_notices"]
    assert isinstance(records, list)
    paths = [record["path"] for record in records]
    assert paths == [
        "Python-3.14.7/Modules/fixture/NOTICE",
        "Python-3.14.7/Modules/_hacl/Common.c",
        *(["Python-3.14.7/Modules/_hacl/Simd.c"] if architecture == "amd64" else []),
    ]
    forged = {**observed, "bundled_notices": records[:-1]}
    with pytest.raises(sources.SourceError, match="manifest differs"):
        sources.verify_bundle(
            inventory,
            _repack(bundle, "manifest.json", json.dumps(forged).encode()),
            require_bundled_notices=False,
            **args,
        )
    legacy = {**observed, "schema_version": 2, "bundled_notices": records[:1]}
    legacy_bundle = _repack(bundle, "manifest.json", json.dumps(legacy).encode())
    assert sources.verify_bundle(
        inventory, legacy_bundle, require_bundled_notices=False, **args
    ) == (legacy)
    with pytest.raises(sources.SourceError, match="omitted the required bundled notices"):
        sources.verify_bundle(inventory, legacy_bundle, require_bundled_notices=True, **args)


def test_current_notice_index_needs_matching_hacl_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    key = ("3.14.7", hashlib.sha256(SOURCE).hexdigest())
    monkeypatch.setattr(
        sources,
        "_BUNDLED_NOTICES",
        {key: (("fixture", "1.2.3", "Modules/fixture/NOTICE", "a" * 64),)},
    )
    with pytest.raises(sources.SourceError, match="no HACL notice review"):
        sources.build_bundle(
            _inventory(),
            SOURCE,
            architecture="amd64",
            platform_digest=DIGEST,
            require_bundled_notices=True,
        )


@pytest.fixture
def layer_case(monkeypatch: pytest.MonkeyPatch) -> tuple[bytes, str, bytes, bytes]:
    source_key = ("3.14.7", hashlib.sha256(SOURCE).hexdigest())
    layer_digest = "sha256:" + "c" * 64
    child = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": sources._OCI_MANIFEST,
            "layers": [
                {"digest": layer_digest, "size": 12345, "mediaType": sources._OCI_GZIP_LAYER}
            ],
        }
    ).encode()
    child_digest = "sha256:" + hashlib.sha256(child).hexdigest()
    pip_source = b"fictional pip source distribution"
    monkeypatch.setattr(sources, "_PIP_SOURCE_SHA256", hashlib.sha256(pip_source).hexdigest())
    monkeypatch.setattr(sources, "_PIP_SOURCE_SIZE", len(pip_source))
    monkeypatch.setattr(sources, "_PIP_LAYERS", {"amd64": (layer_digest, 12345)})
    monkeypatch.setattr(
        sources,
        "_BUNDLED_NOTICES",
        {source_key: (("fixture", "1.2.3", "Modules/fixture/NOTICE", "a" * 64),)},
    )
    monkeypatch.setattr(sources, "_HACL_NOTICES", {source_key: {"common": (), "amd64": ()}})
    inventory = _inventory().replace(DIGEST.encode(), child_digest.encode())
    return inventory, child_digest, child, pip_source


def test_layer_sources_round_trip_and_are_required_only_for_new_releases(
    layer_case: tuple[bytes, str, bytes, bytes],
) -> None:
    inventory, digest, child, pip_source = layer_case
    bundle = sources.build_bundle(
        inventory,
        SOURCE,
        architecture="amd64",
        platform_digest=digest,
        layer_evidence=(child, pip_source),
    )
    manifest = sources.verify_bundle(
        inventory,
        bundle,
        architecture="amd64",
        platform_digest=digest,
        require_layer_sources=True,
    )
    assert manifest["schema_version"] == 4
    assert manifest["image_manifest"] == "image-manifest.json"
    assert manifest["layer_sources"] == [sources._pip_record("amd64", digest, child, pip_source)]
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tar:
        for name, expected in [
            ("image-manifest.json", child),
            (sources._PIP_SOURCE_PATH, pip_source),
        ]:
            member = tar.extractfile(name)
            assert member is not None and member.read() == expected

    historical = sources.build_bundle(
        inventory,
        SOURCE,
        architecture="amd64",
        platform_digest=digest,
        require_bundled_notices=True,
    )
    assert (
        sources.verify_bundle(inventory, historical, architecture="amd64", platform_digest=digest)[
            "schema_version"
        ]
        == 3
    )
    with pytest.raises(sources.SourceError, match="omitted the required layer sources"):
        sources.verify_bundle(
            inventory,
            historical,
            architecture="amd64",
            platform_digest=digest,
            require_layer_sources=True,
        )
    with pytest.raises(sources.SourceError, match="older source bundle schema"):
        sources.verify_bundle(
            inventory,
            _repack(historical, "image-manifest.json", child, append=True),
            architecture="amd64",
            platform_digest=digest,
        )


@pytest.mark.parametrize("member", ["image-manifest.json", sources._PIP_SOURCE_PATH])
def test_layer_verification_rejects_altered_retained_bytes(
    layer_case: tuple[bytes, str, bytes, bytes], member: str
) -> None:
    inventory, digest, child, pip_source = layer_case
    bundle = sources.build_bundle(
        inventory,
        SOURCE,
        architecture="amd64",
        platform_digest=digest,
        layer_evidence=(child, pip_source),
    )
    with pytest.raises(sources.SourceError, match=r"child digest|reviewed size or checksum"):
        sources.verify_bundle(
            inventory,
            _repack(bundle, member, b"forged"),
            architecture="amd64",
            platform_digest=digest,
            require_layer_sources=True,
        )


@pytest.mark.parametrize("change", ["removed", "duplicated", "different-size", "different-media"])
def test_layer_identity_drift_fails_even_with_a_matching_child_digest(
    layer_case: tuple[bytes, str, bytes, bytes], change: str
) -> None:
    inventory, digest, child, pip_source = layer_case
    altered = json.loads(child)
    layer = altered["layers"][0]
    if change == "removed":
        layer["digest"] = "sha256:" + "d" * 64
    elif change == "duplicated":
        altered["layers"].append(layer)
    elif change == "different-size":
        layer["size"] += 1
    else:
        layer["mediaType"] = "application/vnd.oci.image.layer.v1.tar"
    forged = json.dumps(altered).encode()
    forged_digest = "sha256:" + hashlib.sha256(forged).hexdigest()
    with pytest.raises(sources.SourceError, match="reviewed pip layer"):
        sources.build_bundle(
            inventory.replace(digest.encode(), forged_digest.encode()),
            SOURCE,
            architecture="amd64",
            platform_digest=forged_digest,
            layer_evidence=(forged, pip_source),
        )
