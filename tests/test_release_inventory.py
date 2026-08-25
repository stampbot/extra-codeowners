"""Tests for deterministic, non-executing release filesystem inventory."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from tools.release_inventory import InventoryError, collect_inventory, main, render_inventory

PLATFORM_DIGEST = "sha256:" + "a" * 64
SITE = "opt/venv/lib/python3.14/site-packages"


def _rootfs_tar(
    members: list[tuple[str, bytes]], *, links: tuple[tuple[str, str], ...] = ()
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
    stream.seek(0)
    return stream


def _status() -> bytes:
    return b"""Package: example-runtime
Status: install ok installed
Architecture: amd64
Version: 1.2.3-4
Source: example-source (1.2.3-4)

Package: not-installed
Status: deinstall ok config-files
Architecture: amd64
Version: 9.9.9

"""


def _metadata(
    name: str,
    version: str,
    *,
    license_expression: str = "MIT",
    license_file: str = "LICENSE",
) -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        f"License-Expression: {license_expression}\n"
        f"License-File: {license_file}\n"
    ).encode()


def _members() -> list[tuple[str, bytes]]:
    return [
        ("var/lib/dpkg/status", _status()),
        (f"{SITE}/example_pkg-1.0.dist-info/licenses/LICENSE", b"example license\n"),
        (
            f"{SITE}/example_pkg-1.0.dist-info/sboms/runtime.cdx.json",
            b'{"bomFormat":"CycloneDX"}\n',
        ),
        (f"{SITE}/example_pkg/native-extension.so", b"native payload\n"),
        (f"{SITE}/example_pkg-1.0.dist-info/METADATA", _metadata("Example_Pkg", "1.0")),
        (f"{SITE}/legacy-2.0.dist-info/METADATA", _metadata("legacy", "2.0")),
        ("usr/share/doc/example-runtime/copyright", b"Copyright example\n"),
        ("usr/share/common-licenses/GPL-3", b"GPL text\n"),
    ]


def test_collect_inventory_records_raw_os_python_and_native_evidence() -> None:
    inventory = collect_inventory(
        _rootfs_tar(_members()), architecture="amd64", platform_digest=PLATFORM_DIGEST
    )

    assert inventory["schema_version"] == 1
    assert inventory["image"] == {
        "architecture": "amd64",
        "platform_digest": PLATFORM_DIGEST,
    }
    debian = inventory["debian"]
    assert isinstance(debian, dict)
    assert debian["packages"] == [
        {
            "architecture": "amd64",
            "package": "example-runtime",
            "source": "example-source (1.2.3-4)",
            "version": "1.2.3-4",
        }
    ]
    assert debian["status_sha256"] == hashlib.sha256(_status()).hexdigest()

    python = inventory["python"]
    assert isinstance(python, dict)
    distributions = python["distributions"]
    assert isinstance(distributions, list)
    example = next(item for item in distributions if item["normalized_name"] == "example-pkg")
    assert example["license_expression"] == ["MIT"]
    assert example["license_files"] == [
        {
            "declared_path": "LICENSE",
            "installed_path": f"{SITE}/example_pkg-1.0.dist-info/licenses/LICENSE",
            "kind": "regular",
            "link_target": None,
            "sha256": hashlib.sha256(b"example license\n").hexdigest(),
            "size": len(b"example license\n"),
        }
    ]
    legacy = next(item for item in distributions if item["normalized_name"] == "legacy")
    assert legacy["license_files"] == [
        {
            "declared_path": "LICENSE",
            "installed_path": f"{SITE}/legacy-2.0.dist-info/licenses/LICENSE",
            "kind": "missing",
            "link_target": None,
            "sha256": None,
            "size": None,
        }
    ]
    assert python["embedded_sboms"] == [
        {
            "distribution": "example-pkg",
            "kind": "regular",
            "link_target": None,
            "path": f"{SITE}/example_pkg-1.0.dist-info/sboms/runtime.cdx.json",
            "sha256": hashlib.sha256(b'{"bomFormat":"CycloneDX"}\n').hexdigest(),
            "size": len(b'{"bomFormat":"CycloneDX"}\n'),
        }
    ]
    assert python["native_files"] == [
        {
            "kind": "regular",
            "link_target": None,
            "path": "opt/venv/lib/python3.14/site-packages/example_pkg/native-extension.so",
            "sha256": hashlib.sha256(b"native payload\n").hexdigest(),
            "size": len(b"native payload\n"),
        }
    ]


def test_collector_records_links_without_resolving_them() -> None:
    inventory = collect_inventory(
        _rootfs_tar(
            _members(),
            links=(("usr/share/common-licenses/GPL", "GPL-3"),),
        ),
        architecture="amd64",
        platform_digest=PLATFORM_DIGEST,
    )

    debian = inventory["debian"]
    assert isinstance(debian, dict)
    links = debian["shared_license_files"]
    assert isinstance(links, list)
    assert next(item for item in links if item["name"] == "GPL") == {
        "kind": "symlink",
        "link_target": "GPL-3",
        "name": "GPL",
        "path": "usr/share/common-licenses/GPL",
        "sha256": None,
        "size": None,
    }


def test_inventory_output_is_stable_when_tar_member_order_changes() -> None:
    first = collect_inventory(
        _rootfs_tar(_members()), architecture="amd64", platform_digest=PLATFORM_DIGEST
    )
    second = collect_inventory(
        _rootfs_tar(list(reversed(_members()))),
        architecture="amd64",
        platform_digest=PLATFORM_DIGEST,
    )

    assert render_inventory(first) == render_inventory(second)
    assert json.loads(render_inventory(first)) == first


@pytest.mark.parametrize(
    ("architecture", "platform_digest", "message"),
    (
        ("ppc64le", PLATFORM_DIGEST, "unsupported architecture"),
        ("amd64", "sha256:" + "A" * 64, "platform digest"),
    ),
)
def test_collector_rejects_invalid_identity(
    architecture: str, platform_digest: str, message: str
) -> None:
    with pytest.raises(InventoryError, match=message):
        collect_inventory(
            _rootfs_tar(_members()), architecture=architecture, platform_digest=platform_digest
        )


def test_collector_rejects_missing_or_duplicate_status_files() -> None:
    missing = [member for member in _members() if member[0] != "var/lib/dpkg/status"]
    with pytest.raises(InventoryError, match="omitted var/lib/dpkg/status"):
        collect_inventory(
            _rootfs_tar(missing), architecture="amd64", platform_digest=PLATFORM_DIGEST
        )

    duplicate = [*_members(), ("var/lib/dpkg/status", _status())]
    with pytest.raises(InventoryError, match="duplicate inventory path"):
        collect_inventory(
            _rootfs_tar(duplicate), architecture="amd64", platform_digest=PLATFORM_DIGEST
        )

    duplicate_package_status = (
        _status()
        + b"""Package: example-runtime
Status: install ok installed
Architecture: amd64
Version: 9.9.9

"""
    )
    duplicate_package = [
        (path, duplicate_package_status if path == "var/lib/dpkg/status" else contents)
        for path, contents in _members()
    ]
    with pytest.raises(InventoryError, match="duplicate installed package records"):
        collect_inventory(
            _rootfs_tar(duplicate_package),
            architecture="amd64",
            platform_digest=PLATFORM_DIGEST,
        )


def test_collector_rejects_unsafe_tar_and_metadata_paths() -> None:
    traversal = [*_members(), ("../outside", b"not selected\n")]
    with pytest.raises(InventoryError, match="unsafe member path"):
        collect_inventory(
            _rootfs_tar(traversal), architecture="amd64", platform_digest=PLATFORM_DIGEST
        )

    unsafe_license = [
        member
        if member[0] != f"{SITE}/example_pkg-1.0.dist-info/METADATA"
        else (
            member[0],
            _metadata("Example_Pkg", "1.0", license_file="../../outside"),
        )
        for member in _members()
    ]
    with pytest.raises(InventoryError, match="unsafe License-File path"):
        collect_inventory(
            _rootfs_tar(unsafe_license), architecture="amd64", platform_digest=PLATFORM_DIGEST
        )


def test_collector_rejects_auxiliary_files_without_distribution_metadata() -> None:
    members = [
        ("var/lib/dpkg/status", _status()),
        (f"{SITE}/missing-1.0.dist-info/licenses/LICENSE", b"license\n"),
    ]

    with pytest.raises(InventoryError, match="no METADATA"):
        collect_inventory(
            _rootfs_tar(members), architecture="amd64", platform_digest=PLATFORM_DIGEST
        )


def test_command_writes_canonical_json_to_the_requested_path(tmp_path: Path) -> None:
    archive = tmp_path / "rootfs.tar"
    archive.write_bytes(_rootfs_tar(_members()).read())
    output = tmp_path / "inventory.json"

    assert (
        main(
            [
                "--architecture",
                "amd64",
                "--platform-digest",
                PLATFORM_DIGEST,
                "--rootfs-tar",
                str(archive),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert output.read_text(encoding="utf-8") == render_inventory(
        collect_inventory(
            _rootfs_tar(_members()), architecture="amd64", platform_digest=PLATFORM_DIGEST
        )
    )
