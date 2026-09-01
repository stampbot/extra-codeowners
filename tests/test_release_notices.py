"""Tests for recipient notice bundles bound to release-image inventories."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from tools import release_notices
from tools.release_inventory import collect_inventory, render_inventory
from tools.release_notices import ReleaseNoticeError, build_notice_bundle, verify_notice_bundle

PLATFORM_DIGEST = "sha256:" + "a" * 64
SITE = "opt/venv/lib/python3.14/site-packages"


def _rootfs_tar(
    members: list[tuple[str, bytes]],
    *,
    hardlinks: tuple[tuple[str, str], ...] = (),
    links: tuple[tuple[str, str], ...] = (),
) -> io.BytesIO:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path, contents in members:
            member = tarfile.TarInfo(path)
            member.size = len(contents)
            archive.addfile(member, io.BytesIO(contents))
        for path, target in links:
            member = tarfile.TarInfo(path)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            archive.addfile(member)
        for path, target in hardlinks:
            member = tarfile.TarInfo(path)
            member.type = tarfile.LNKTYPE
            member.linkname = target
            archive.addfile(member)
    stream.seek(0)
    return stream


def _status() -> bytes:
    return b"""Package: example-runtime
Status: install ok installed
Architecture: amd64
Version: 1.2.3-4
Source: example-source (1.2.3-4)

"""


def _os_release() -> bytes:
    return b"""PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
ID=debian
"""


def _metadata(
    name: str,
    version: str,
    *,
    license_files: tuple[str, ...] = ("LICENSE",),
    metadata_version: str = "2.4",
) -> bytes:
    return (
        f"Metadata-Version: {metadata_version}\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        "License-Expression: MIT\n"
        + "".join(f"License-File: {license_file}\n" for license_file in license_files)
    ).encode()


def _members(*, copyright_text: bytes = b"Copyright example\n") -> list[tuple[str, bytes]]:
    return [
        ("usr/lib/os-release", _os_release()),
        ("var/lib/dpkg/status", _status()),
        ("usr/share/doc/example-runtime/copyright", copyright_text),
        ("usr/share/common-licenses/GPL-3", b"GPL text\n"),
        ("usr/local/lib/python3.14/LICENSE.txt", b"CPython license\n"),
        ("usr/share/licenses/extra-codeowners/LICENSE", b"Apache-2.0\n"),
        (f"{SITE}/example_pkg-1.0.dist-info/licenses/LICENSE", b"example license\n"),
        (
            f"{SITE}/example_pkg-1.0.dist-info/licenses/vendor/licenses/LICENSE",
            b"nested example license\n",
        ),
        (
            f"{SITE}/example_pkg-1.0.dist-info/METADATA",
            _metadata("Example_Pkg", "1.0", license_files=("LICENSE", "vendor/licenses/LICENSE")),
        ),
        (f"{SITE}/odd-1!2+build.dist-info/licenses/LICENSE", b"odd license\n"),
        (f"{SITE}/odd-1!2+build.dist-info/METADATA", _metadata("odd", "1!2+build")),
        (f"{SITE}/legacy-2.0.dist-info/LICENSE", b"legacy license\n"),
        (f"{SITE}/legacy-2.0.dist-info/METADATA", _metadata("legacy", "2.0")),
        (f"{SITE}/missing-1.0.dist-info/METADATA", _metadata("missing", "1.0")),
    ]


def _inventory_bytes(
    members: list[tuple[str, bytes]],
    *,
    hardlinks: tuple[tuple[str, str], ...] = (),
    links: tuple[tuple[str, str], ...],
) -> bytes:
    inventory = collect_inventory(
        _rootfs_tar(members, hardlinks=hardlinks, links=links),
        architecture="amd64",
        platform_digest=PLATFORM_DIGEST,
    )
    return render_inventory(inventory).encode()


def _bundle(
    members: list[tuple[str, bytes]],
    *,
    hardlinks: tuple[tuple[str, str], ...] = (),
    links: tuple[tuple[str, str], ...] = (("usr/share/common-licenses/GPL", "GPL-3"),),
) -> tuple[bytes, bytes]:
    inventory = _inventory_bytes(members, hardlinks=hardlinks, links=links)
    bundle = build_notice_bundle(
        _rootfs_tar(members, hardlinks=hardlinks, links=links),
        inventory,
        architecture="amd64",
        platform_digest=PLATFORM_DIGEST,
    )
    return inventory, bundle


def _manifest(bundle: bytes) -> dict[str, object]:
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
        member = archive.getmember("NOTICE-MANIFEST.json")
        extracted = archive.extractfile(member)
        assert extracted is not None
        return cast(dict[str, object], json.loads(extracted.read()))


def _rewrite_bundle(bundle: bytes, mutate_manifest: Callable[[dict[str, object]], None]) -> bytes:
    output = io.BytesIO()
    with (
        tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as source,
        gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target,
    ):
        for member in source:
            replacement = member
            contents: bytes | None = None
            if member.isfile():
                extracted = source.extractfile(member)
                assert extracted is not None
                contents = extracted.read()
            if member.name == "NOTICE-MANIFEST.json":
                assert contents is not None
                manifest = json.loads(contents)
                mutate_manifest(manifest)
                contents = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
                replacement = tarfile.TarInfo(member.name)
                replacement.mode = 0o644
                replacement.size = len(contents)
            if replacement.issym() or replacement.islnk():
                target.addfile(replacement)
            else:
                assert contents is not None
                target.addfile(replacement, io.BytesIO(contents))
    return output.getvalue()


def test_notice_bundle_is_deterministic_and_verifiably_covers_inventory(tmp_path: Path) -> None:
    members = _members()
    inventory, first = _bundle(members)
    _, second = _bundle(list(reversed(members)))

    assert first == second
    bundle_path = tmp_path / "recipient-notices-amd64.tar.gz"
    bundle_path.write_bytes(first)
    verify_notice_bundle(
        bundle_path, inventory, architecture="amd64", platform_digest=PLATFORM_DIGEST
    )

    manifest = _manifest(first)
    files = manifest["files"]
    assert isinstance(files, list)
    assert {item["component"] for item in files if isinstance(item, dict)} >= {
        "cpython-runtime",
        "extra-codeowners",
        "pypi:example-pkg@1.0",
    }
    assert any(
        isinstance(item, dict) and item["archive_path"] == "notices/python/odd/1%212+build/LICENSE"
        for item in files
    )
    assert any(
        isinstance(item, dict)
        and item["archive_path"] == "notices/python/example-pkg/1.0/vendor/licenses/LICENSE"
        for item in files
    )
    assert any(
        isinstance(item, dict)
        and item["archive_path"] == "notices/python/legacy/2.0/LICENSE"
        and item["source_path"] == f"{SITE}/legacy-2.0.dist-info/LICENSE"
        for item in files
    )
    assert manifest["unresolved_notice_evidence"] == [
        {
            "component": "pypi:missing@1.0",
            "reason": "declared-license-file-missing-from-image",
            "source_path": f"{SITE}/missing-1.0.dist-info/licenses/LICENSE",
        }
    ]


def test_notice_bundle_preserves_undeclared_legacy_python_license(tmp_path: Path) -> None:
    metadata_path = f"{SITE}/legacy-2.0.dist-info/METADATA"
    members = [
        member
        if member[0] != metadata_path
        else (
            member[0],
            _metadata("legacy", "2.0", license_files=(), metadata_version="2.1"),
        )
        for member in _members()
    ]
    inventory, bundle = _bundle(members)
    _, reordered_bundle = _bundle(list(reversed(members)))
    assert bundle == reordered_bundle

    bundle_path = tmp_path / "recipient-notices-amd64.tar.gz"
    bundle_path.write_bytes(bundle)
    verify_notice_bundle(
        bundle_path, inventory, architecture="amd64", platform_digest=PLATFORM_DIGEST
    )
    files = _manifest(bundle)["files"]
    assert isinstance(files, list)
    assert any(
        isinstance(item, dict)
        and item["archive_path"] == "notices/python/legacy/2.0/legacy-direct/LICENSE"
        and item["source_path"] == f"{SITE}/legacy-2.0.dist-info/LICENSE"
        for item in files
    )


def test_notice_bundle_preserves_direct_legacy_copy_when_modern_license_exists(
    tmp_path: Path,
) -> None:
    direct_path = f"{SITE}/example_pkg-1.0.dist-info/LICENSE"
    members = [*_members(), (direct_path, b"legacy copy\n")]
    inventory, bundle = _bundle(members)
    _, reordered_bundle = _bundle(list(reversed(members)))
    assert bundle == reordered_bundle

    bundle_path = tmp_path / "recipient-notices-amd64.tar.gz"
    bundle_path.write_bytes(bundle)
    verify_notice_bundle(
        bundle_path, inventory, architecture="amd64", platform_digest=PLATFORM_DIGEST
    )
    files = _manifest(bundle)["files"]
    assert isinstance(files, list)
    assert any(
        isinstance(item, dict)
        and item["archive_path"] == "notices/python/example-pkg/1.0/LICENSE"
        and item["source_path"] == f"{SITE}/example_pkg-1.0.dist-info/licenses/LICENSE"
        for item in files
    )
    assert any(
        isinstance(item, dict)
        and item["archive_path"] == "notices/python/example-pkg/1.0/legacy-direct/LICENSE"
        and item["source_path"] == direct_path
        for item in files
    )


def test_notice_bundle_rejects_trailing_dot_distribution_version() -> None:
    unsafe_members = [
        *_members(),
        (f"{SITE}/unsafe-1.dist-info/licenses/LICENSE", b"unsafe license\n"),
        (f"{SITE}/unsafe-1.dist-info/METADATA", _metadata("unsafe", "1.")),
    ]
    links = (("usr/share/common-licenses/GPL", "GPL-3"),)
    inventory = _inventory_bytes(unsafe_members, links=links)

    with pytest.raises(ReleaseNoticeError, match="unsafe path component"):
        build_notice_bundle(
            _rootfs_tar(unsafe_members, links=links),
            inventory,
            architecture="amd64",
            platform_digest=PLATFORM_DIGEST,
        )


def test_notice_bundle_rejects_rootfs_material_that_no_longer_matches_inventory() -> None:
    inventory = _inventory_bytes(_members(), links=(("usr/share/common-licenses/GPL", "GPL-3"),))

    with pytest.raises(ReleaseNoticeError, match="does not match the release inventory hash"):
        build_notice_bundle(
            _rootfs_tar(
                _members(copyright_text=b"tampered\n"),
                links=(("usr/share/common-licenses/GPL", "GPL-3"),),
            ),
            inventory,
            architecture="amd64",
            platform_digest=PLATFORM_DIGEST,
        )


def test_notice_bundle_rejects_tampered_shared_license_link() -> None:
    inventory = _inventory_bytes(_members(), links=(("usr/share/common-licenses/GPL", "GPL-3"),))

    with pytest.raises(ReleaseNoticeError, match="does not match the release inventory"):
        build_notice_bundle(
            _rootfs_tar(_members(), links=(("usr/share/common-licenses/GPL", "Apache-2.0"),)),
            inventory,
            architecture="amd64",
            platform_digest=PLATFORM_DIGEST,
        )


@pytest.mark.parametrize(
    ("kind", "links", "hardlinks", "source_target", "archive_target"),
    [
        (
            "symlink",
            (("usr/share/doc/example-alias/copyright", "../example-runtime/copyright"),),
            (),
            "../example-runtime/copyright",
            "example-runtime.txt",
        ),
        (
            "hardlink",
            (),
            (
                (
                    "usr/share/doc/example-alias/copyright",
                    "usr/share/doc/example-runtime/copyright",
                ),
            ),
            "usr/share/doc/example-runtime/copyright",
            "notices/debian/copyright/example-runtime.txt",
        ),
    ],
)
def test_notice_bundle_preserves_linked_debian_copyright_evidence(
    tmp_path: Path,
    kind: str,
    links: tuple[tuple[str, str], ...],
    hardlinks: tuple[tuple[str, str], ...],
    source_target: str,
    archive_target: str,
) -> None:
    common_link = (("usr/share/common-licenses/GPL", "GPL-3"),)
    inventory, bundle = _bundle(_members(), hardlinks=hardlinks, links=common_link + links)
    bundle_path = tmp_path / "recipient-notices-amd64.tar.gz"
    bundle_path.write_bytes(bundle)
    verify_notice_bundle(
        bundle_path, inventory, architecture="amd64", platform_digest=PLATFORM_DIGEST
    )

    manifest = _manifest(bundle)
    manifest_links = manifest["links"]
    assert isinstance(manifest_links, list)
    record = next(
        item
        for item in manifest_links
        if isinstance(item, dict)
        and item.get("source_path") == "usr/share/doc/example-alias/copyright"
    )
    assert record == {
        "archive_link_target": archive_target,
        "archive_path": "notices/debian/copyright/example-alias.txt",
        "archive_target_path": "notices/debian/copyright/example-runtime.txt",
        "component": "deb:example-alias",
        "kind": kind,
        "source_link_target": source_target,
        "source_path": "usr/share/doc/example-alias/copyright",
    }
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
        member = archive.getmember("notices/debian/copyright/example-alias.txt")
        assert member.issym() if kind == "symlink" else member.islnk()
        assert member.linkname == archive_target


def test_notice_bundle_rejects_debian_link_that_escapes_selected_evidence() -> None:
    links = (
        ("usr/share/common-licenses/GPL", "GPL-3"),
        ("usr/share/doc/example-alias/copyright", "../../../etc/shadow"),
    )
    inventory = _inventory_bytes(_members(), links=links)

    with pytest.raises(ReleaseNoticeError, match="does not resolve to one selected"):
        build_notice_bundle(
            _rootfs_tar(_members(), links=links),
            inventory,
            architecture="amd64",
            platform_digest=PLATFORM_DIGEST,
        )


def test_notice_bundle_rejects_windows_unsafe_python_license_path() -> None:
    unsafe_license_path = r"..\..\recipient-overwrite.txt"
    unsafe_members = [
        *_members(),
        (
            f"{SITE}/unsafe-1.0.dist-info/licenses/{unsafe_license_path}",
            b"unsafe license\n",
        ),
        (
            f"{SITE}/unsafe-1.0.dist-info/METADATA",
            _metadata("unsafe", "1.0", license_files=(unsafe_license_path,)),
        ),
    ]
    links = (("usr/share/common-licenses/GPL", "GPL-3"),)
    inventory = _inventory_bytes(unsafe_members, links=links)

    with pytest.raises(ReleaseNoticeError, match="unsafe path"):
        build_notice_bundle(
            _rootfs_tar(unsafe_members, links=links),
            inventory,
            architecture="amd64",
            platform_digest=PLATFORM_DIGEST,
        )


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "notices/python/example/1.0/.. /recipient-overwrite.txt",
        "notices/python/example. /1.0/LICENSE",
    ),
    ids=("dot-segment", "trailing-dot"),
)
def test_notice_bundle_path_validator_rejects_windows_normalized_paths(unsafe_path: str) -> None:
    with pytest.raises(ReleaseNoticeError, match="unsafe path"):
        release_notices._safe_relative_path(unsafe_path, "notice bundle member path")


def test_notice_builder_applies_member_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release_notices, "_MAX_BUNDLE_MEMBERS", 2)

    with pytest.raises(ReleaseNoticeError, match="would exceed its member limit"):
        _bundle(_members())


def test_notice_builder_reserves_space_for_control_members(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(release_notices, "_MAX_TOTAL_NOTICE_BYTES", 1)
    file = release_notices._CollectedFile(
        archive_path="notices/test.txt",
        component="test-component",
        contents=b"x",
        role="test-notice",
        sha256=hashlib.sha256(b"x").hexdigest(),
        source_path="test.txt",
    )

    with pytest.raises(ReleaseNoticeError, match="would exceed its total size limit"):
        release_notices._render_bundle(
            files=[file],
            links=[],
            unresolved=[],
            architecture="amd64",
            distro="debian-13",
            inventory_sha256="a" * 64,
            platform_digest=PLATFORM_DIGEST,
        )


def test_notice_builder_counts_tar_metadata_before_compression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def render(archive_path: str) -> bytes:
        file = release_notices._CollectedFile(
            archive_path=archive_path,
            component="test-component",
            contents=b"x",
            role="test-notice",
            sha256=hashlib.sha256(b"x").hexdigest(),
            source_path="test.txt",
        )
        return release_notices._render_bundle(
            files=[file],
            links=[],
            unresolved=[],
            architecture="amd64",
            distro="debian-13",
            inventory_sha256="a" * 64,
            platform_digest=PLATFORM_DIGEST,
        )

    monkeypatch.setattr(release_notices, "_MAX_BUNDLE_ARCHIVE_BYTES", 15 * 1024)
    assert render("notices/short.txt")

    with pytest.raises(ReleaseNoticeError, match="decompressed archive size limit"):
        render(f"notices/{'x' * 6000}.txt")


def test_verifier_bounds_pax_extension_headers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as gzip_stream,
        tarfile.open(fileobj=gzip_stream, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        manifest = tarfile.TarInfo("NOTICE-MANIFEST.json")
        manifest.pax_headers = {"comment": "x" * (20 * 1024)}
        manifest.size = len(b"{}")
        archive.addfile(manifest, io.BytesIO(b"{}"))
    bundle_path = tmp_path / "oversized-pax.tar.gz"
    bundle_path.write_bytes(output.getvalue())
    monkeypatch.setattr(release_notices, "_MAX_BUNDLE_ARCHIVE_BYTES", 10 * 1024)

    with pytest.raises(ReleaseNoticeError, match="decompressed archive size limit"):
        verify_notice_bundle(
            bundle_path,
            _inventory_bytes(_members(), links=(("usr/share/common-licenses/GPL", "GPL-3"),)),
            architecture="amd64",
            platform_digest=PLATFORM_DIGEST,
        )


@pytest.mark.parametrize("corrupt", (False, True), ids=("truncated", "bad-crc"))
def test_verifier_rejects_invalid_gzip_trailer(tmp_path: Path, corrupt: bool) -> None:
    inventory, bundle = _bundle(_members())
    if corrupt:
        invalid_bundle = bytearray(bundle)
        invalid_bundle[-8] ^= 1
        contents = bytes(invalid_bundle)
    else:
        contents = bundle[:-1]
    bundle_path = tmp_path / "invalid-trailer.tar.gz"
    bundle_path.write_bytes(contents)

    with pytest.raises(ReleaseNoticeError, match="could not read notice bundle"):
        verify_notice_bundle(
            bundle_path, inventory, architecture="amd64", platform_digest=PLATFORM_DIGEST
        )


def test_verifier_rejects_manifest_that_omits_inventory_evidence(tmp_path: Path) -> None:
    inventory, bundle = _bundle(_members())

    def omit_copyright(manifest: dict[str, object]) -> None:
        files = manifest["files"]
        assert isinstance(files, list)
        manifest["files"] = [
            item
            for item in files
            if not (isinstance(item, dict) and item.get("role") == "debian-copyright")
        ]

    bundle_path = tmp_path / "tampered.tar.gz"
    bundle_path.write_bytes(_rewrite_bundle(bundle, omit_copyright))

    with pytest.raises(ReleaseNoticeError, match="omitted inventory evidence"):
        verify_notice_bundle(
            bundle_path, inventory, architecture="amd64", platform_digest=PLATFORM_DIGEST
        )


def test_verifier_rejects_bytes_that_differ_from_the_manifest(tmp_path: Path) -> None:
    inventory, bundle = _bundle(_members())

    def alter_digest(manifest: dict[str, object]) -> None:
        files = manifest["files"]
        assert isinstance(files, list)
        record = next(
            item
            for item in files
            if isinstance(item, dict) and item.get("role") == "application-license"
        )
        assert isinstance(record, dict)
        record["sha256"] = hashlib.sha256(b"wrong bytes\n").hexdigest()

    bundle_path = tmp_path / "bad-digest.tar.gz"
    bundle_path.write_bytes(_rewrite_bundle(bundle, alter_digest))

    with pytest.raises(ReleaseNoticeError, match="wrong SHA-256"):
        verify_notice_bundle(
            bundle_path, inventory, architecture="amd64", platform_digest=PLATFORM_DIGEST
        )
