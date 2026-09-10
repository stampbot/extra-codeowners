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
from unittest.mock import Mock

import pytest

from tools import release_sources as sources

DIGEST = "sha256:" + "a" * 64
SOURCE = b"opaque upstream source archive"
SOURCE_NAME = "Python-3.14.7.tar.xz"


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
    with pytest.raises(sources.SourceError, match="manifest differs"):
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
    with pytest.raises(sources.SourceError, match="manifest differs"):
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
