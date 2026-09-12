"""Debian source delivery uses descriptors and opaque files, never a build."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tools import release_debian_sources as source

DIGESTS = {"amd64": "sha256:" + "a" * 64, "arm64": "sha256:" + "b" * 64}
PAYLOADS = {"example_1.2.orig.tar.xz": b"upstream", "example_1.2-3.debian.tar.xz": b"recipes"}
VERSION = "2:1.2-3"


def _inventories() -> dict[str, bytes]:
    return {
        architecture: json.dumps(
            {
                "schema_version": 2,
                "image": {
                    "architecture": architecture,
                    "platform_digest": digest,
                    "distro": "debian-13",
                },
                "debian": {
                    "packages": [
                        {
                            "package": "libexample",
                            "version": VERSION + "+b1",
                            "architecture": architecture,
                            "source": f"example ({VERSION})",
                        }
                    ],
                },
            },
        ).encode()
        for architecture, digest in DIGESTS.items()
    }


def _descriptor() -> bytes:
    return (
        f"Format: 3.0 (quilt)\nSource: example\nVersion: {VERSION}\nChecksums-Sha256:\n"
        + "".join(
            f" {hashlib.sha256(data).hexdigest()} {len(data)} {name}\n"
            for name, data in sorted(PAYLOADS.items())
        )
    ).encode()


def _file(name: str, data: bytes) -> dict[str, Any]:
    return {
        "name": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "snapshot_sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "size": len(data),
    }


def _resolved() -> tuple[dict[str, Any], bytes]:
    return {
        "name": "example",
        "version": VERSION,
        "descriptor": _file("example_1.2-3.dsc", _descriptor()),
        "files": [_file(name, data) for name, data in sorted(PAYLOADS.items())],
    }, _descriptor()


def _collect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str = "sources.tar"
) -> Path:
    monkeypatch.setattr(source, "resolve_source", lambda identity: _resolved())
    by_locator = {
        f"{source.ORIGIN}/file/{_file(name, data)['snapshot_sha1']}": data
        for name, data in PAYLOADS.items()
    }

    def download(url: str, output: Any, limit: int) -> None:
        output.write(by_locator[url])

    monkeypatch.setattr(source, "_download", download)
    bundle = tmp_path / filename
    source.collect_bundle(_inventories(), DIGESTS, bundle, tmp_path / "cache")
    return bundle


def _rewrite(
    bundle: Path,
    *,
    manifest: dict[str, Any] | None = None,
    omit: str = "",
    extra: str = "",
    kind: bytes = tarfile.REGTYPE,
) -> None:
    contents = []
    with tarfile.open(bundle) as archive:
        for member in archive:
            stream = archive.extractfile(member)
            assert stream is not None
            contents.append((member.name, stream.read()))
    with tarfile.open(bundle, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in contents:
            if name == omit:
                continue
            if name == "manifest.json" and manifest is not None:
                data = json.dumps(manifest).encode()
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if extra:
            member = tarfile.TarInfo(extra)
            member.type = kind
            member.linkname = "/etc/passwd"
            archive.addfile(member, io.BytesIO())


def test_source_identity_uses_explicit_version_and_deduplicates_platforms() -> None:
    images, packages = source.identities(_inventories(), DIGESTS)
    assert packages == [("example", VERSION)]
    assert images["arm64"]["platform_digest"] == DIGESTS["arm64"]
    assert (
        images["amd64"]["inventory_sha256"] == hashlib.sha256(_inventories()["amd64"]).hexdigest()
    )
    inventories = _inventories()
    value = json.loads(inventories["amd64"])
    value["debian"]["packages"][0]["source"] = "example"
    inventories["amd64"] = json.dumps(value).encode()
    assert source.identities(inventories, DIGESTS)[1] == [
        ("example", VERSION),
        ("example", VERSION + "+b1"),
    ]


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "../evil (1)"),
        ("source", "example (1/2)"),
        ("source", "example (1) junk"),
        ("version", "--option"),
        ("architecture", "ppc64el"),
        ("package", "a/b"),
    ],
)
def test_rejects_invalid_inventory_package_fields(field: str, value: object) -> None:
    inventories = _inventories()
    document = json.loads(inventories["amd64"])
    document["debian"]["packages"][0][field] = value
    inventories["amd64"] = json.dumps(document).encode()
    with pytest.raises(source.DebianSourceError):
        source.identities(inventories, DIGESTS)


def test_rejects_duplicate_packages_and_wrong_platform_identity() -> None:
    inventories = _inventories()
    document = json.loads(inventories["amd64"])
    document["debian"]["packages"] *= 2
    inventories["amd64"] = json.dumps(document).encode()
    with pytest.raises(source.DebianSourceError, match="duplicate"):
        source.identities(inventories, DIGESTS)
    with pytest.raises(source.DebianSourceError, match="platform"):
        source.identities(_inventories(), dict.fromkeys(DIGESTS, DIGESTS["amd64"]))


def test_descriptor_preserves_recipe_and_upstream_files_without_extraction() -> None:
    rows = source.descriptor(_descriptor(), "example", VERSION)
    assert {row["name"] for row in rows} == set(PAYLOADS)
    signed = (
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        + _descriptor()
        + b"\n-----BEGIN PGP SIGNATURE-----\nretained-not-authenticated\n"
        b"-----END PGP SIGNATURE-----\n"
    )
    assert source.descriptor(signed, "example", VERSION) == rows


@pytest.mark.parametrize(
    "old,new",
    [
        (b"Source: example", b"Source: another"),
        (VERSION.encode(), b"1.2"),
        (b"Format:", b"Source:"),
        (b"Checksums-Sha256:", b"Checksums-Sha1:"),
        (b"example_1.2.orig.tar.xz", b"../source.tar"),
        (b" 8 example", b" -1 example"),
    ],
)
def test_rejects_invalid_descriptor(old: bytes, new: bytes) -> None:
    with pytest.raises(source.DebianSourceError):
        source.descriptor(_descriptor().replace(old, new), "example", VERSION)


def test_snapshot_resolver_binds_every_descriptor_file(monkeypatch: pytest.MonkeyPatch) -> None:
    resolved, dsc = _resolved()
    all_files = [resolved["descriptor"], *resolved["files"]]
    document: dict[str, Any] = {
        "package": "example",
        "version": VERSION,
        "result": [{"hash": file["snapshot_sha1"]} for file in all_files],
        "fileinfo": {
            file["snapshot_sha1"]: [{"name": file["name"], "size": file["size"]}]
            for file in all_files
        },
    }
    monkeypatch.setattr(
        source, "_metadata", lambda url: json.dumps(document).encode() if "/mr/" in url else dsc
    )
    assert source.resolve_source(("example", VERSION)) == (resolved, dsc)
    document["fileinfo"].pop(resolved["files"][0]["snapshot_sha1"])
    with pytest.raises(source.DebianSourceError, match="filename list"):
        source.resolve_source(("example", VERSION))


def test_collect_verify_deterministic_and_warm_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _collect(tmp_path, monkeypatch)
    manifest = source.verify_bundle(_inventories(), DIGESTS, first)
    assert len(manifest["packages"]) == 1
    download = Mock(side_effect=AssertionError("warm cache must not fetch archive bytes"))
    monkeypatch.setattr(source, "_download", download)
    second = tmp_path / "second.tar"
    source.collect_bundle(_inventories(), DIGESTS, second, tmp_path / "cache")
    assert first.read_bytes() == second.read_bytes()
    assert not download.called
    with pytest.raises(source.DebianSourceError, match="overwrite"):
        source.collect_bundle(_inventories(), DIGESTS, second, tmp_path / "cache")


def test_download_staging_shares_cache_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replace = Path.replace
    destinations = []

    def same_filesystem(self: Path, target: Path) -> Path:
        assert self.parent.parent == target.parent == tmp_path / "cache"
        destinations.append(target)
        return replace(self, target)

    monkeypatch.setattr(Path, "replace", same_filesystem)
    _collect(tmp_path, monkeypatch)
    assert len(destinations) == len(PAYLOADS)
    assert not list((tmp_path / "cache").glob(".download-*"))


def test_download_retries_discard_partial_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    response = MagicMock()
    response.__enter__.return_value = response
    response.status = 200
    response.read.side_effect = [b"partial", TimeoutError(), b"complete", b""]
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(
        "tools.release_debian_sources.urllib.request.build_opener", lambda handler: opener
    )
    sleep = Mock()
    monkeypatch.setattr("tools.release_debian_sources.time.sleep", sleep)
    output = io.BytesIO()
    source._download(source.ORIGIN + "/file/example", output, 100)
    assert output.getvalue() == b"complete"
    assert opener.open.call_count == 2
    sleep.assert_called_once_with(2)


def test_download_limits_and_retry_exhaustion(monkeypatch: pytest.MonkeyPatch) -> None:
    response = MagicMock()
    response.__enter__.return_value = response
    response.status = 200
    response.read.return_value = b"oversize"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(
        "tools.release_debian_sources.urllib.request.build_opener", lambda handler: opener
    )
    monkeypatch.setattr("tools.release_debian_sources.time.sleep", lambda seconds: None)
    with pytest.raises(source.DebianSourceError, match="size limit"):
        source._download(source.ORIGIN + "/file/example", io.BytesIO(), 1)
    assert opener.open.call_count == 1
    opener.reset_mock()
    opener.open.side_effect = TimeoutError()
    with pytest.raises(source.DebianSourceError, match="download failed"):
        source._download(source.ORIGIN + "/file/example", io.BytesIO(), 100)
    assert opener.open.call_count == 3
    with pytest.raises(source.DebianSourceError, match="origin"):
        source._download("https://snapshot.debian.org.attacker.invalid/file", io.BytesIO(), 100)
    assert opener.open.call_count == 3


def test_corrupt_cache_is_refetched_and_unused_entries_are_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _collect(tmp_path, monkeypatch)
    cache = tmp_path / "cache"
    cached = next(cache.iterdir())
    cached.write_bytes(b"wrong")
    unused = cache / ("c" * 64)
    unused.write_bytes(b"old")
    second = _collect(tmp_path, monkeypatch, "second.tar")
    assert first.read_bytes() == second.read_bytes()
    assert not unused.exists()


def test_checksum_failure_never_publishes_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(source, "resolve_source", lambda identity: _resolved())
    monkeypatch.setattr(source, "_download", lambda url, output, limit: output.write(b"wrong"))
    bundle = tmp_path / "sources.tar"
    with pytest.raises(source.DebianSourceError, match="SHA-256 or size"):
        source.collect_bundle(_inventories(), DIGESTS, bundle, tmp_path / "cache")
    assert not bundle.exists()
    assert not list(tmp_path.glob("debian-sources-*"))
    assert not list((tmp_path / "cache").glob(".download-*"))


@pytest.mark.parametrize(
    "extra,kind",
    [
        ("manifest.json", tarfile.REGTYPE),
        ("../escape", tarfile.REGTYPE),
        ("link", tarfile.SYMTYPE),
        ("hardlink", tarfile.LNKTYPE),
        ("directory", tarfile.DIRTYPE),
    ],
)
def test_rejects_extra_duplicate_and_link_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: str, kind: bytes
) -> None:
    bundle = _collect(tmp_path, monkeypatch)
    _rewrite(bundle, extra=extra, kind=kind)
    with pytest.raises(source.DebianSourceError, match="unexpected, duplicate"):
        source.verify_bundle(_inventories(), DIGESTS, bundle)


def test_rejects_omitted_source_and_altered_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _collect(tmp_path, monkeypatch)
    inventories = _inventories()
    inventories["amd64"] += b"\n"
    with pytest.raises(source.DebianSourceError, match="selected inventories"):
        source.verify_bundle(inventories, DIGESTS, bundle)
    _rewrite(bundle, omit="sources/example/2%3A1.2-3/example_1.2.orig.tar.xz")
    with pytest.raises(source.DebianSourceError, match="missing files"):
        source.verify_bundle(_inventories(), DIGESTS, bundle)


@pytest.mark.parametrize(
    "change",
    [
        "omit-package",
        "wrong-version",
        "boolean-schema",
        "forged-checksum",
        "float-size",
        "changed-scope",
    ],
)
def test_rejects_manifest_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    bundle = _collect(tmp_path, monkeypatch)
    manifest = source.verify_bundle(_inventories(), DIGESTS, bundle)
    match change:
        case "omit-package":
            manifest["packages"] = []
        case "wrong-version":
            manifest["packages"][0]["version"] = "1.2"
        case "boolean-schema":
            manifest["schema_version"] = True
        case "forged-checksum":
            manifest["packages"][0]["files"][0]["sha256"] = "a" * 64
        case "float-size":
            manifest["packages"][0]["files"][0]["size"] = 8.0
        case "changed-scope":
            manifest["scope"] = "Complete legal approval"
    _rewrite(bundle, manifest=manifest)
    with pytest.raises(source.DebianSourceError):
        source.verify_bundle(_inventories(), DIGESTS, bundle)


def test_rejects_trailing_data_and_oversized_bundles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _collect(tmp_path, monkeypatch)
    with bundle.open("ab") as stream:
        stream.write(b"hidden")
    with pytest.raises(source.DebianSourceError, match="trailing data"):
        source.verify_bundle(_inventories(), DIGESTS, bundle)
    monkeypatch.setattr(source, "MAX_BUNDLE", 1)
    with pytest.raises(source.DebianSourceError, match="bundle size"):
        source.verify_bundle(_inventories(), DIGESTS, bundle)
