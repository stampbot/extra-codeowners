from __future__ import annotations

import base64
import copy
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import zipfile
import zlib
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evidence = load_script("container_evidence")
readiness = load_script("release_readiness")
DEMO_METADATA_PATH = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA"
PYVENV_CONFIG = (
    b"home = /usr/local/bin\n"
    b"implementation = CPython\n"
    b"uv = 0.11.28\n"
    b"version_info = 3.14.6\n"
    b"include-system-site-packages = false\n"
    b"prompt = extra-codeowners\n"
)
VENV_LINKS = {
    "opt/venv/bin/python": "/usr/local/bin/python3",
    "opt/venv/bin/python3": "python",
    "opt/venv/bin/python3.14": "python",
}


def tar_bytes(
    files: dict[str, bytes],
    *,
    links: dict[str, str] | None = None,
    hardlinks: dict[str, str] | None = None,
    directories: list[str] | None = None,
    headers: dict[str, dict[str, Any]] | None = None,
) -> bytes:
    def apply_header(member: tarfile.TarInfo) -> None:
        for field, value in (headers or {}).get(member.name, {}).items():
            setattr(member, field, value)

    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name in directories or []:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            apply_header(member)
            archive.addfile(member)
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            apply_header(member)
            archive.addfile(member, io.BytesIO(content))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            member.mode = 0o777
            apply_header(member)
            archive.addfile(member)
        for name, target in (hardlinks or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.LNKTYPE
            member.linkname = target
            member.mode = 0o777
            apply_header(member)
            archive.addfile(member)
    return result.getvalue()


def tar_sequence(files: list[tuple[str, bytes]]) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, content in files:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return result.getvalue()


def explicit_parent_directories(paths: Iterable[str]) -> list[str]:
    """Return portable parent headers for synthetic post-base layer fixtures."""

    parents = {
        str(parent)
        for path in paths
        for parent in PurePosixPath(path).parents
        if str(parent) != "."
    }
    return sorted(parents, key=lambda path: (len(PurePosixPath(path).parts), path))


def apk_database(
    architecture: str = "x86_64",
    version: str = "1.37.0-r1",
    *,
    name: str = "busybox",
    origin: str | None = None,
) -> bytes:
    selected_origin = name if origin is None else origin
    return (
        f"P:{name}\n"
        f"V:{version}\n"
        f"A:{architecture}\n"
        "L:GPL-2.0-only\n"
        f"o:{selected_origin}\n"
        "c:1111111111111111111111111111111111111111\n\n"
    ).encode()


def metadata(name: str, version: str, license_value: str = "MIT") -> bytes:
    return (
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
        f"License-Expression: {license_value}\n\n"
    ).encode()


def wheel_record(files: dict[str, bytes], record_path: str) -> bytes:
    rows = []
    for path, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(evidence.hashlib.sha256(content).digest()).rstrip(b"=")
        rows.append(f"{path},sha256={digest.decode()},{len(content)}\n")
    rows.append(f"{record_path},,\n")
    return "".join(rows).encode()


def cyclonedx_sbom(
    *,
    components: list[dict[str, Any]] | None = None,
    metadata_component: dict[str, Any] | None = None,
) -> bytes:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:12345678-1234-4234-9234-123456789abc",
        "version": 1,
        "components": components
        if components is not None
        else [
            {
                "type": "library",
                "name": "libdemo",
                "version": "1.2.3",
                "purl": "pkg:generic/libdemo@1.2.3",
                "bom-ref": "pkg:generic/libdemo@1.2.3",
            }
        ],
    }
    if metadata_component is not None:
        document["metadata"] = {"component": metadata_component}
    return json.dumps(document, sort_keys=True).encode()


def elf64_payload(architecture: str = "amd64") -> bytes:
    machine = {"amd64": 62, "arm64": 183}[architecture]
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\0" * 7
    return cast(
        bytes,
        evidence.ELF64_HEADER.pack(
            ident,
            3,
            machine,
            1,
            0,
            0,
            0,
            0,
            evidence.ELF64_HEADER.size,
            0,
            0,
            0,
            0,
            0,
        )
        + b"native payload",
    )


def empty_unexpanded_payload_policy() -> dict[str, dict[str, list[dict[str, Any]]]]:
    return {
        platform: {
            "embedded_sboms": [],
            "native_payloads": [],
            "wheel_identity_files": [],
        }
        for platform in ("linux/amd64", "linux/arm64")
    }


def empty_filesystem_baselines() -> dict[str, dict[str, list[dict[str, Any]]]]:
    return {
        platform: {
            "apk_database_occurrences": [],
            "post_base_directory_effects": [],
            "post_base_removals": [],
        }
        for platform in ("linux/amd64", "linux/arm64")
    }


def standalone_inventory(component: dict[str, Any]) -> dict[str, Any]:
    apk_record = {
        "effective": True,
        "layer": 0,
        "path": "lib/apk/db/installed",
        "sha256": "d" * 64,
        "size": 0,
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
    }
    return {
        "schema_version": evidence.SCHEMA_VERSION,
        "platform": "linux/amd64",
        "subject_digest": "sha256:" + "a" * 64,
        "image_config_digest": "sha256:" + "b" * 64,
        "image_revision": "c" * 40,
        "image_version": "1.0",
        "application_wheel_sha256": "e" * 64,
        "application_selection_record_sha256": "f" * 64,
        "apk_database_sha256": "d" * 64,
        "components": [component],
        "embedded_sboms": [],
        "native_payloads": [],
        "wheel_identity_files": [],
        "apk_database_occurrences": [apk_record],
        "wheel_installations": [],
        "python_record_ownership": [],
        "source_completeness": {
            "complete": False,
            "reason": evidence.SOURCE_COMPLETENESS_REASON,
        },
    }


def standalone_policy(
    component: dict[str, Any], expression: str, *, license_texts: list[dict[str, Any]]
) -> dict[str, Any]:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    policy["platforms"] = {
        "linux/amd64": [copy.deepcopy(component)],
        "linux/arm64": [copy.deepcopy(component)],
    }
    policy["distribution_approval"] = {
        "approved": False,
        "approved_by": "",
        "approved_on": "",
        "rationale": "Distribution remains denied for this test fixture.",
    }
    policy["license_resolutions"] = {
        "python:demo@1": {
            "expression": expression,
            "rationale": "Reviewed test fixture.",
        }
    }
    policy["license_texts"] = license_texts
    policy["custom_license_evidence"] = {}
    policy["unexpanded_python_payloads"] = empty_unexpanded_payload_policy()
    policy["filesystem_baselines"] = empty_filesystem_baselines()
    policy["filesystem_baselines"]["linux/amd64"]["apk_database_occurrences"] = [
        copy.deepcopy(standalone_inventory(component)["apk_database_occurrences"][0])
    ]
    return policy


def saved_image_layers(path: Path, layers: list[bytes], *, architecture: str = "amd64") -> None:
    layer_names = [f"blobs/sha256/{evidence.hashlib.sha256(layer).hexdigest()}" for layer in layers]
    config_content = json.dumps(
        {
            "architecture": architecture,
            "config": {
                "Labels": {
                    "org.opencontainers.image.revision": "a" * 40,
                    "org.opencontainers.image.version": "1.0",
                    evidence.APPLICATION_WHEEL_LABEL: "e" * 64,
                    evidence.APPLICATION_SELECTION_LABEL: "f" * 64,
                }
            },
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": [f"sha256:{name.rsplit('/', 1)[-1]}" for name in layer_names],
            },
        }
    ).encode()
    config_name = f"blobs/sha256/{evidence.hashlib.sha256(config_content).hexdigest()}"
    contents = {
        "manifest.json": json.dumps([{"Config": config_name, "Layers": layer_names}]).encode(),
        config_name: config_content,
    }
    contents.update(zip(layer_names, layers, strict=True))
    path.write_bytes(tar_bytes(contents))


def saved_image(path: Path, *, architecture: str = "amd64") -> None:
    apk_architecture = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(apk_architecture),
            "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA": metadata(
                "demo", "1.0"
            ),
            "usr/local/lib/python3.14/site-packages/pip-26.1.dist-info/METADATA": metadata(
                "pip", "26.1"
            ),
        }
    )
    second = tar_bytes(
        {
            "usr/local/lib/python3.14/site-packages/.wh.pip-26.1.dist-info": b"",
            "empty": b"",
        }
    )
    saved_image_layers(path, [first, second], architecture=architecture)


def ci_artifact_files(tmp_path: Path, architecture: str = "amd64") -> dict[str, bytes]:
    image = tmp_path / "ci-image.tar"
    saved_image(image, architecture=architecture)
    inventory, files = evidence._inventory_saved_image(
        image,
        f"linux/{architecture}",
        "sha256:" + "a" * 64,
    )
    inventory["subject_digest"] = inventory["image_config_digest"]
    files["subject_digest"] = inventory["subject_digest"]
    bundle_name = f"extra-codeowners-ci-linux-{architecture}-evidence.tar.gz"
    bundle = b"bounded evidence bundle"
    bundle_hash = evidence.sha256_bytes(bundle)
    metadata_record = {
        "schema_version": evidence.SCHEMA_VERSION,
        "run_id": "1234",
        "run_attempt": 2,
        "event_name": "pull_request",
        "repository_id": "5678",
        "pr_number": "27",
        "pr_head_sha": "b" * 40,
        "pr_base_sha": "c" * 40,
        "pr_head_repository_id": "5678",
        "github_sha": "a" * 40,
        "checkout_sha": "a" * 40,
        "workflow_ref": "stampbot/extra-codeowners/.github/workflows/ci.yml@refs/pull/27/merge",
        "workflow_sha": "a" * 40,
        "platform": f"linux/{architecture}",
        "architecture": architecture,
        "inventory_subject_digest": inventory["subject_digest"],
        "inventory_image_config_digest": inventory["image_config_digest"],
        "python_distribution_artifact_id": "9012",
        "python_distribution_artifact_digest": "d" * 64,
        "application_source_revision": "a" * 40,
        "application_wheel_sha256": "e" * 64,
        "application_selection_record_sha256": "f" * 64,
    }
    predicate = {
        "schema_version": evidence.SCHEMA_VERSION,
        "media_type": evidence.EVIDENCE_MEDIA_TYPE,
        "platform": f"linux/{architecture}",
        "subject_digest": inventory["subject_digest"],
        "artifact": {"filename": bundle_name, "sha256": bundle_hash},
        "release_url": "https://github.com/stampbot/extra-codeowners/releases/tag/v0.0.0-ci",
    }
    return {
        f"all-layer-files-{architecture}.json": evidence.canonical_json(files),
        f"components-{architecture}.json": evidence.canonical_json(inventory),
        f"evidence-predicate-{architecture}.json": evidence.canonical_json(predicate),
        f"run-metadata-{architecture}.json": evidence.canonical_json(metadata_record),
        bundle_name: bundle,
        f"{bundle_name}.sha256": f"{bundle_hash}  {bundle_name}\n".encode(),
    }


class NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, *_args: Any, **_kwargs: Any) -> int:
        raise OSError("fixture is intentionally non-seekable")


def ci_artifact_zip_bytes(
    entries: list[tuple[str, bytes]],
    *,
    modifier: Any | None = None,
    archive_comment: bytes = b"",
) -> bytes:
    output = NonSeekableBytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.create_version = 45
            info.extract_version = 20
            info.external_attr = evidence.CI_ARTIFACT_EXTERNAL_ATTR
            info.compress_type = zipfile.ZIP_DEFLATED
            if modifier is not None:
                modifier(name, info)
            archive.writestr(info, content)
        archive.comment = archive_comment
    return output.getvalue()


def write_ci_artifact_zip(path: Path, files: dict[str, bytes]) -> None:
    path.write_bytes(ci_artifact_zip_bytes(list(files.items())))


def zip_record_offsets(content: bytes | bytearray, name: str) -> tuple[int, int]:
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as archive:
        local_offset = archive.getinfo(name).header_offset
    eocd_offset = content.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    central_offset = evidence.ZIP_EOCD.unpack_from(content, eocd_offset)[-2]
    position = central_offset
    while position < eocd_offset:
        assert content[position : position + 4] == b"PK\x01\x02"
        name_size = int.from_bytes(content[position + 28 : position + 30], "little")
        extra_size = int.from_bytes(content[position + 30 : position + 32], "little")
        comment_size = int.from_bytes(content[position + 32 : position + 34], "little")
        entry_name = bytes(content[position + 46 : position + 46 + name_size]).decode("ascii")
        if entry_name == name:
            return local_offset, position
        position += 46 + name_size + extra_size + comment_size
    raise AssertionError(f"missing central record for {name}")


def source_zip_bytes(
    entries: list[tuple[str, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
    extra: bytes = b"",
    entry_comment: bytes = b"",
    archive_comment: bytes = b"",
) -> bytes:
    """Build the narrow Unix source-ZIP dialect accepted by the collector."""

    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w") as archive:
        archive.comment = archive_comment
        for name, content in entries:
            directory = name.endswith("/")
            method = zipfile.ZIP_STORED if directory else compression
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.create_version = 20
            member.extract_version = 10 if method == zipfile.ZIP_STORED else 20
            member.external_attr = (
                ((stat.S_IFDIR | 0o755) << 16 | 0x10) if directory else (stat.S_IFREG | 0o644) << 16
            )
            member.compress_type = method
            member.extra = extra
            member.comment = entry_comment
            archive.writestr(member, content)
    return output.getvalue()


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "a/../../escape",
        "a\\b",
        ".",
        "./",
        "././file",
        "a//b",
    ],
)
def test_checked_path_rejects_unsafe_names(path: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.checked_path(path)


@pytest.mark.parametrize(
    "path", ["LICENSE\nforged", "LICENSE\rforged", "LICENSE\tforged", "x\x7fy"]
)
def test_checked_path_rejects_control_characters(path: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.checked_path(path)


def test_checked_path_rejects_oversized_names() -> None:
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.checked_path("a" * (evidence.MAX_PATH_BYTES + 1))


@pytest.mark.parametrize("path", ["./retained/path", "retained/path/"])
def test_retained_paths_reject_archive_name_aliases(path: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="not a canonical archive path"):
        evidence.checked_canonical_path(path, "retained test path")


def test_link_and_record_paths_use_utf8_byte_limits() -> None:
    oversized = "é" * (evidence.MAX_PATH_BYTES // 2 + 1)
    with pytest.raises(evidence.EvidenceError, match="archive link target"):
        evidence.checked_link_target(oversized)
    with pytest.raises(evidence.EvidenceError, match="image link target"):
        evidence.checked_image_link_target(oversized)
    with pytest.raises(evidence.EvidenceError, match="Python RECORD path"):
        evidence.resolve_wheel_record_path(
            evidence.PurePosixPath("opt/venv/lib/python3.14/site-packages"),
            oversized,
        )


def test_strict_json_rejects_duplicates_and_non_finite_numbers(tmp_path: Path) -> None:
    for content, message in (
        ('{"distribution_approval": false, "distribution_approval": true}', "duplicate"),
        ('{"value": NaN}', "non-finite"),
        ('{"value": Infinity}', "non-finite"),
    ):
        path = tmp_path / "hostile.json"
        path.write_text(content)
        with pytest.raises(evidence.EvidenceError, match=message):
            evidence.load_json(path)
    with pytest.raises(ValueError, match="Out of range float values"):
        evidence.canonical_json({"value": float("nan")})


def test_strict_json_rejects_floats_and_excessive_nesting() -> None:
    with pytest.raises(evidence.EvidenceError, match="floating-point"):
        evidence.strict_json_loads(b'{"value":1e400}', "test")
    deeply_nested = b"[" * (evidence.MAX_JSON_DEPTH + 1) + b"]" * (evidence.MAX_JSON_DEPTH + 1)
    with pytest.raises(evidence.EvidenceError, match="nesting-depth"):
        evidence.strict_json_loads(deeply_nested, "test")


def test_strict_json_rejects_lone_unicode_surrogates() -> None:
    with pytest.raises(evidence.EvidenceError, match="invalid Unicode"):
        evidence.strict_json_loads(b'{"value":"\\ud800"}', "test")
    with pytest.raises(evidence.EvidenceError, match="invalid Unicode"):
        evidence.canonical_json({"value": "\ud800"})


def test_schema_version_requires_exact_v2_integer_and_media_type() -> None:
    evidence.require_schema({"schema_version": 2}, "test")
    for unsupported in (True, 1, 3):
        with pytest.raises(evidence.EvidenceError, match="unsupported test schema"):
            evidence.require_schema({"schema_version": unsupported}, "test")
    assert evidence.EVIDENCE_MEDIA_TYPE == (
        "application/vnd.stampbot.container-evidence.v2+tar+gzip"
    )


def test_saved_image_inventory_tracks_whiteouts_and_all_layers(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    components = {(item["ecosystem"], item["name"]): item for item in inventory["components"]}
    assert components[("alpine", "busybox")]["aports_commit"] == "1" * 40
    assert components[("python", "demo")]["effective"] is True
    assert components[("python", "pip")]["effective"] is False
    assert inventory["image_revision"] == "a" * 40
    assert [layer["regular_file_count"] for layer in files["layers"]] == [3, 1]
    assert len(files["regular_files"]) == 4


def test_all_layer_validators_reject_cross_kind_path_duplicates(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    duplicate = copy.deepcopy(files)
    regular = duplicate["regular_files"][0]
    duplicate["directories"].append(
        {
            "effective": regular["effective"],
            "layer": regular["layer"],
            "layer_digest": regular["layer_digest"],
            "path": regular["path"],
            "mode": 0o755,
            "uid": 0,
            "gid": 0,
        }
    )
    duplicate["layers"][regular["layer"]]["directory_count"] += 1

    with pytest.raises(evidence.EvidenceError, match="across entry categories"):
        evidence.validate_all_layer_inventory(duplicate, inventory)
    with pytest.raises(evidence.EvidenceError, match="across entry categories"):
        evidence.validate_filesystem_policy_view_input(duplicate)


def test_saved_image_binds_config_and_layer_blob_names_to_bytes(tmp_path: Path) -> None:
    layer = tar_bytes({"lib/apk/db/installed": apk_database()})
    valid = tmp_path / "valid.tar"
    saved_image_layers(valid, [layer])
    with pytest.raises(evidence.EvidenceError, match="inspected image"):
        evidence._inventory_saved_image(
            valid,
            "linux/amd64",
            "sha256:" + "a" * 64,
            expected_config_digest="sha256:" + "b" * 64,
        )

    config = json.dumps(
        {
            "architecture": "amd64",
            "config": {"Labels": {}},
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "c" * 64]},
        }
    ).encode()
    config_name = f"blobs/sha256/{evidence.hashlib.sha256(config).hexdigest()}"
    hostile_layer_name = "blobs/sha256/" + "c" * 64
    hostile = tmp_path / "hostile.tar"
    hostile.write_bytes(
        tar_bytes(
            {
                "manifest.json": json.dumps(
                    [{"Config": config_name, "Layers": [hostile_layer_name]}]
                ).encode(),
                config_name: config,
                hostile_layer_name: layer,
            }
        )
    )
    with pytest.raises(evidence.EvidenceError, match="layer digest does not match"):
        evidence._inventory_saved_image(hostile, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("rootfs_kind", ["missing", "mismatched"])
def test_saved_image_requires_exact_config_rootfs_binding(rootfs_kind: str, tmp_path: Path) -> None:
    layer = tar_bytes({"lib/apk/db/installed": apk_database()})
    layer_hash = evidence.hashlib.sha256(layer).hexdigest()
    layer_name = f"blobs/sha256/{layer_hash}"
    config: dict[str, Any] = {
        "architecture": "amd64",
        "config": {"Labels": {}},
        "os": "linux",
    }
    if rootfs_kind == "mismatched":
        config["rootfs"] = {"type": "layers", "diff_ids": ["sha256:" + "b" * 64]}
    config_content = json.dumps(config).encode()
    config_name = f"blobs/sha256/{evidence.hashlib.sha256(config_content).hexdigest()}"
    image = tmp_path / "image.tar"
    image.write_bytes(
        tar_bytes(
            {
                "manifest.json": json.dumps(
                    [{"Config": config_name, "Layers": [layer_name]}]
                ).encode(),
                config_name: config_content,
                layer_name: layer,
            }
        )
    )

    message = "no layered root" if rootfs_kind == "missing" else "rootfs diff IDs"
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_docker_save_stream_has_an_exact_output_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_docker = tmp_path / "docker"
    fake_docker.write_text("#!/bin/sh\nprintf abc")
    fake_docker.chmod(0o755)
    monkeypatch.setattr(evidence, "executable", lambda _name: str(fake_docker))
    monkeypatch.setattr(evidence, "MAX_DOCKER_SAVE_BYTES", 3)
    output = tmp_path / "image.tar"

    evidence.save_docker_image_bounded("sha256:" + "a" * 64, output)
    assert output.read_bytes() == b"abc"

    fake_docker.write_text("#!/bin/sh\nprintf abcd")
    with pytest.raises(evidence.EvidenceError, match="exceeds the size limit"):
        evidence.save_docker_image_bounded("sha256:" + "a" * 64, output)


def test_docker_save_outer_members_are_bounded_before_random_access(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes({"lib/apk/db/installed": apk_database()})])
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBERS", 2)

    with pytest.raises(evidence.EvidenceError, match="too many entries"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_whiteouts_remove_only_lower_layer_files_independent_of_order(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            f"{site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0", "MIT"),
            f"{site}/stale-1.0.dist-info/METADATA": metadata("stale", "1.0", "MIT"),
        }
    )
    second = tar_sequence(
        [
            (f"{site}/demo-1.0.dist-info/METADATA", metadata("demo", "1.0", "MIT")),
            (f"{site}/.wh.demo-1.0.dist-info", b""),
            (f"{site}/.wh..wh..opq", b""),
        ]
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    inventory, _ = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    components = {(item["ecosystem"], item["name"]): item for item in inventory["components"]}
    assert components[("python", "demo")]["effective"] is True
    assert components[("python", "demo")]["observed_license"] == "MIT"
    assert components[("python", "stale")]["effective"] is False


def test_conflicting_metadata_for_one_python_release_fails_closed(tmp_path: Path) -> None:
    path = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA"
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    path: metadata("demo", "1.0", "MIT"),
                }
            ),
            tar_bytes({path: metadata("demo", "1.0", "Apache-2.0")}),
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="conflicting Python metadata"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_python_component_is_effective_when_any_identical_occurrence_survives(
    tmp_path: Path,
) -> None:
    system_site = "usr/local/lib/python3.14/site-packages"
    venv_site = "opt/venv/lib/python3.14/site-packages"
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            f"{system_site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        }
    )
    second = tar_bytes({f"{venv_site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0")})
    third = tar_bytes({f"{venv_site}/.wh.demo-1.0.dist-info": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second, third])

    inventory, _ = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    demo = next(item for item in inventory["components"] if item["name"] == "demo")
    assert demo["effective"] is True


def test_removed_apk_database_fails_closed(tmp_path: Path) -> None:
    first = tar_bytes({"lib/apk/db/installed": apk_database()})
    second = tar_bytes({"lib/apk/db/.wh.installed": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="no effective Alpine"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_replaced_apk_database_retains_packages_distributed_in_lower_layers(
    tmp_path: Path,
) -> None:
    lower_database = apk_database(version="1.0-r0") + apk_database(version="2.0-r0", name="retired")
    upper_database = apk_database(version="2.0-r0")
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": lower_database,
                    "usr/lib/libretired.so": b"distributed lower-layer bytes",
                }
            ),
            tar_bytes(
                {
                    "lib/apk/db/installed": upper_database,
                    "usr/lib/.wh.libretired.so": b"",
                }
            ),
        ],
    )

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    alpine = {
        (item["name"], item["version"]): item
        for item in inventory["components"]
        if item["ecosystem"] == "alpine"
    }
    assert alpine[("busybox", "1.0-r0")]["effective"] is False
    assert alpine[("busybox", "2.0-r0")]["effective"] is True
    retired = alpine[("retired", "2.0-r0")]
    assert retired["effective"] is False
    assert retired["origin"] == "retired"
    assert retired["aports_commit"] == "1" * 40
    retired_file = next(
        item for item in files["regular_files"] if item["path"] == "usr/lib/libretired.so"
    )
    assert retired_file["effective"] is False


def test_conflicting_alpine_metadata_across_layers_fails_closed(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes({"lib/apk/db/installed": apk_database()}),
            tar_bytes({"lib/apk/db/installed": apk_database(origin="other-origin")}),
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="conflicting Alpine metadata"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_duplicate_paths_in_one_image_layer_fail_closed(tmp_path: Path) -> None:
    layer = tar_sequence(
        [
            ("lib/apk/db/installed", apk_database(version="1.0-r0")),
            ("lib/apk/db/installed", apk_database(version="2.0-r0")),
        ]
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])

    with pytest.raises(evidence.EvidenceError, match="image layer repeats path"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("kind", ["nonempty", "symlink", "empty-basename"])
def test_invalid_oci_whiteouts_fail_closed(kind: str, tmp_path: Path) -> None:
    first = tar_bytes({"lib/apk/db/installed": apk_database(), "removed": b"old"})
    if kind == "nonempty":
        second = tar_bytes({".wh.removed": b"not empty"})
        message = "empty regular file"
    elif kind == "symlink":
        second = tar_bytes({}, links={".wh.removed": "safe-target"})
        message = "empty regular file"
    else:
        second = tar_bytes({".wh.": b""})
        message = "no target basename"
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("ancestor_kind", ["regular", "symlink"])
def test_whiteout_cannot_traverse_a_lower_non_directory_parent(
    ancestor_kind: str, tmp_path: Path
) -> None:
    first_files = {"lib/apk/db/installed": apk_database()}
    if ancestor_kind == "regular":
        first = tar_bytes({**first_files, "parent": b"not a directory"})
    else:
        first = tar_bytes(first_files, links={"parent": "elsewhere"})
    second = tar_bytes({"parent/.wh.child": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="non-directory parent topology"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_opaque_whiteout_requires_lower_layer_children(tmp_path: Path) -> None:
    first = tar_bytes({"lib/apk/db/installed": apk_database(), "parent": b"not a directory"})
    second = tar_bytes(
        {"parent/.wh..wh..opq": b"", "parent/current": b"kept"},
        directories=["parent"],
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="does not remove any lower-layer entries"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_regular_file_replacing_a_directory_removes_its_descendants(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    package_directory = f"{site}/demo-1.0.dist-info"
    first = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            f"{package_directory}/METADATA": metadata("demo", "1.0"),
        }
    )
    second = tar_bytes({package_directory: b"replacement"})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    demo = next(item for item in inventory["components"] if item["name"] == "demo")
    assert demo["effective"] is False
    metadata_record = next(
        item for item in files["regular_files"] if item["path"].endswith("/METADATA")
    )
    assert metadata_record["effective"] is False


@pytest.mark.parametrize("ancestor_kind", ["regular", "symlink"])
def test_layer_entries_cannot_traverse_a_non_directory_ancestor(
    ancestor_kind: str, tmp_path: Path
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    first_files = {"lib/apk/db/installed": apk_database()}
    if ancestor_kind == "regular":
        first_files[site] = b"not a directory"
        first = tar_bytes(first_files)
    else:
        first = tar_bytes(first_files, links={site: "elsewhere"})
    second = tar_bytes({f"{site}/demo-1.0.dist-info/METADATA": metadata("demo", "1.0")})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="non-directory ancestor"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_non_regular_replacement_of_python_metadata_fails_closed(
    link_kind: str, tmp_path: Path
) -> None:
    path = "opt/venv/lib/python3.14/site-packages/demo-1.0.dist-info/METADATA"
    first = tar_bytes({"lib/apk/db/installed": apk_database(), path: metadata("demo", "1.0")})
    links = {path: "other"} if link_kind == "symlink" else None
    hardlinks = {path: "other"} if link_kind == "hardlink" else None
    second = tar_bytes({}, links=links, hardlinks=hardlinks)
    image = tmp_path / "image.tar"
    saved_image_layers(image, [first, second])

    with pytest.raises(evidence.EvidenceError, match="metadata path is not a regular file"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_image_size_limit_is_cumulative_across_layers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [tar_bytes({"lib/apk/db/installed": apk_database()}), tar_bytes({"second": b"x"})],
    )
    monkeypatch.setattr(evidence, "MAX_IMAGE_TOTAL_BYTES", 15_000)

    with pytest.raises(evidence.EvidenceError, match="cumulative size limit"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_image_member_limit_is_cumulative_across_layers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes({"lib/apk/db/installed": apk_database(), "first": b"x"}),
            tar_bytes({"second": b"x"}),
        ],
    )
    monkeypatch.setattr(evidence, "MAX_IMAGE_MEMBERS", 2)

    with pytest.raises(evidence.EvidenceError, match="too many cumulative entries"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_apk_architecture_must_match_image_platform(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes({"lib/apk/db/installed": apk_database("aarch64")})])

    with pytest.raises(evidence.EvidenceError, match="does not match linux/amd64"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_claimed_subject_must_match_a_local_repository_digest() -> None:
    config_digest = "sha256:" + "a" * 64
    manifest_digest = "sha256:" + "b" * 64
    info = {
        "Id": config_digest,
        "RepoDigests": [f"ghcr.io/stampbot/extra-codeowners@{manifest_digest}"],
    }

    assert (
        evidence.verify_local_image_subject(
            info, manifest_digest, allow_config_digest_subject=False
        )
        == config_digest
    )
    with pytest.raises(evidence.EvidenceError, match="claimed subject digest"):
        evidence.verify_local_image_subject(
            info, "sha256:" + "c" * 64, allow_config_digest_subject=False
        )
    with pytest.raises(evidence.EvidenceError, match="claimed subject digest"):
        evidence.verify_local_image_subject(info, config_digest, allow_config_digest_subject=False)
    assert (
        evidence.verify_local_image_subject(
            {"Id": config_digest, "RepoDigests": []},
            config_digest,
            allow_config_digest_subject=True,
        )
        == config_digest
    )


def test_apk_database_requires_commit_provenance() -> None:
    broken = apk_database().replace(b"c:" + b"1" * 40 + b"\n", b"")
    with pytest.raises(evidence.EvidenceError, match="immutable source provenance"):
        evidence.parse_apk_database(broken)


def test_exact_apk_database_baseline_covers_virtual_records(tmp_path: Path) -> None:
    virtual = b"P:.python-rundeps\nV:20260714.000000\nA:noarch\n\n"
    clean_image = tmp_path / "clean-apk.tar"
    saved_image_layers(
        clean_image,
        [tar_bytes({"lib/apk/db/installed": apk_database() + virtual})],
    )
    clean_inventory, _files = evidence._inventory_saved_image(
        clean_image, "linux/amd64", "sha256:" + "a" * 64
    )
    policy = {
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": clean_inventory["apk_database_occurrences"],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        }
    }
    evidence.verify_apk_database_baseline(clean_inventory, policy)

    hostile_image = tmp_path / "hostile-apk.tar"
    saved_image_layers(
        hostile_image,
        [
            tar_bytes(
                {"lib/apk/db/installed": apk_database() + virtual + b"P:.evil\nV:1\nA:noarch\n\n"}
            )
        ],
    )
    hostile_inventory, _files = evidence._inventory_saved_image(
        hostile_image, "linux/amd64", "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="APK databases differ"):
        evidence.verify_apk_database_baseline(hostile_inventory, policy)


@pytest.mark.parametrize("field", ["P", "V", "A", "L", "o", "c"])
def test_apk_database_rejects_duplicate_authoritative_fields(field: str) -> None:
    value = next(
        line.removeprefix(f"{field}:")
        for line in apk_database().decode().splitlines()
        if line.startswith(f"{field}:")
    )
    hostile = apk_database().replace(
        f"{field}:{value}\n".encode(), f"{field}:{value}\n{field}:{value}\n".encode()
    )
    with pytest.raises(evidence.EvidenceError, match=f"repeats field {field}"):
        evidence.parse_apk_database(hostile)


@pytest.mark.parametrize(
    "field", ["Metadata-Version", "Name", "Version", "License-Expression", "License"]
)
def test_python_metadata_rejects_duplicate_authoritative_fields(field: str) -> None:
    base = metadata("demo", "1.0")
    value = "demo" if field == "Name" else "1.0" if field == "Version" else "MIT"
    if field == "License":
        hostile = b"Name: demo\nVersion: 1.0\nLicense: MIT\nLicense: MIT\n\n"
    else:
        hostile = f"{field}: {value}\n".encode() + base
    with pytest.raises(evidence.EvidenceError, match=f"repeats {field}"):
        evidence.parse_python_metadata(hostile, DEMO_METADATA_PATH)


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("a/b", "1.0"),
        ("..", "1.0"),
        ("a@b", "1.0"),
        ("-demo", "1.0"),
        ("demo", "../escape"),
        ("demo", "1/2"),
        ("demo", "1\t2"),
        ("demo", "1\x7f2"),
    ],
)
def test_python_metadata_rejects_unsafe_identity_fields(name: str, version: str) -> None:
    hostile = (
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nLicense-Expression: MIT\n\n"
    ).encode()
    with pytest.raises(
        evidence.EvidenceError,
        match=r"(?:invalid (?:name|version)|control characters)",
    ):
        evidence.parse_python_metadata(hostile, DEMO_METADATA_PATH)


def test_python_metadata_rejects_control_characters_and_oversized_fields() -> None:
    with pytest.raises(evidence.EvidenceError, match="control characters"):
        evidence.parse_python_metadata(
            b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\nLicense-Expression: MIT\tforged\n\n",
            DEMO_METADATA_PATH,
        )

    with pytest.raises(evidence.EvidenceError, match="invalid length"):
        evidence.parse_python_metadata(metadata("a" * 513, "1.0"), DEMO_METADATA_PATH)


@pytest.mark.parametrize(
    "hostile",
    [
        metadata("demo", "1.0").replace(b"Metadata-Version: 2.4\n", b""),
        metadata("demo", "1.0").replace(b"Metadata-Version: 2.4\n", b"Metadata-Version: 9.9\n"),
        b"Metadata-Version: 2.4\nMalformed Header\nName: demo\nVersion: 1.0\n\n",
    ],
)
def test_python_metadata_requires_supported_well_formed_core_metadata(
    hostile: bytes,
) -> None:
    with pytest.raises(
        evidence.EvidenceError, match=r"(invalid length|unsupported|parser defects)"
    ):
        evidence.parse_python_metadata(hostile, DEMO_METADATA_PATH)


def test_python_metadata_must_match_its_dist_info_directory() -> None:
    hostile_path = "opt/venv/lib/python3.14/site-packages/not_demo-999.dist-info/METADATA"
    with pytest.raises(evidence.EvidenceError, match="does not match its dist-info directory"):
        evidence.parse_python_metadata(metadata("demo", "1.0"), hostile_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("P", "../busybox", "invalid name"),
        ("V", "../escape", "invalid version"),
        ("A", "x86/64", "invalid architecture"),
        ("o", "../busybox", "invalid origin"),
        ("L", "MIT\tforged", "control characters"),
    ],
)
def test_apk_database_rejects_unsafe_component_fields(field: str, value: str, message: str) -> None:
    original = next(
        line for line in apk_database().decode().splitlines() if line.startswith(f"{field}:")
    )
    hostile = apk_database().replace(f"{original}\n".encode(), f"{field}:{value}\n".encode())
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.parse_apk_database(hostile)


@pytest.mark.parametrize("second_version", ["1.37.0-r1", "2.0-r0"])
def test_apk_database_rejects_duplicate_package_names(second_version: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="repeats name"):
        evidence.parse_apk_database(apk_database() + apk_database(version=second_version))


def test_apk_database_enforces_component_count_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    second = (
        apk_database().replace(b"P:busybox\n", b"P:other\n").replace(b"o:busybox\n", b"o:other\n")
    )
    monkeypatch.setattr(evidence, "MAX_COMPONENTS", 1)
    with pytest.raises(evidence.EvidenceError, match="too many records"):
        evidence.parse_apk_database(apk_database() + second)


def test_lock_sources_reject_duplicate_normalized_name_and_version(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text(
        '[[package]]\nname = "Demo_Pkg"\nversion = "1.0"\n'
        'sdist = { url = "https://example.com/one.tar.gz", '
        f'hash = "sha256:{"a" * 64}", size = 1 }}\n\n'
        '[[package]]\nname = "demo-pkg"\nversion = "1.0"\n'
        'sdist = { url = "https://example.com/two.tar.gz", '
        f'hash = "sha256:{"b" * 64}", size = 1 }}\n'
    )

    with pytest.raises(evidence.EvidenceError, match="repeats Python source"):
        evidence.parse_lock_sources(lock)


def test_recipe_checksum_parser_does_not_execute_recipe() -> None:
    remote_digest = "a" * 128
    local_digest = evidence.hashlib.sha512(b"patch").hexdigest()
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/demo-$pkgver.tar.gz\nlocal.patch"\n'
                f'sha512sums="\n{remote_digest}  demo-1.0.tar.gz\n'
                f'{local_digest}  local.patch\n"\n'
            ).encode(),
            "aports/main/demo/local.patch": b"patch",
        }
    )
    checksums, local = evidence.recipe_checksums(recipe, "demo")
    assert checksums == {
        "demo-1.0.tar.gz": remote_digest,
        "local.patch": local_digest,
    }
    assert local == {"local.patch"}


def test_recipe_checksum_parser_rejects_links() -> None:
    recipe = tar_bytes(
        {"aports/main/demo/APKBUILD": f'sha512sums="\n{"a" * 128}  demo.tar.gz\n"\n'.encode()},
        links={"aports/main/demo/escape": "../../secret"},
    )
    with pytest.raises(evidence.EvidenceError, match="unsafe archive link target"):
        evidence.recipe_checksums(recipe, "demo")


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_recipe_checksum_parser_rejects_even_safe_links(link_kind: str) -> None:
    apkbuild = (
        'source="local.patch"\n'
        f'sha512sums="\n{evidence.hashlib.sha512(b"patch").hexdigest()}  local.patch\n"\n'
    ).encode()
    links = {"aports/main/demo/local.patch": "target.patch"} if link_kind == "symlink" else None
    hardlinks = (
        {"aports/main/demo/local.patch": "aports/main/demo/target.patch"}
        if link_kind == "hardlink"
        else None
    )
    recipe = tar_bytes({"aports/main/demo/APKBUILD": apkbuild}, links=links, hardlinks=hardlinks)
    with pytest.raises(evidence.EvidenceError, match="links are not allowed"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_checksum_parser_requires_an_exact_pinned_link_exception() -> None:
    path = "aports/main/demo/post-upgrade"
    recipe = tar_bytes(
        {"aports/main/demo/APKBUILD": b""},
        links={path: "post-install"},
    )
    exception = {"path": path, "target": "post-install", "type": "symlink"}

    assert evidence.recipe_checksums(recipe, "demo", allowed_links=[exception]) == ({}, set())
    with pytest.raises(evidence.EvidenceError, match="missing="):
        evidence.recipe_checksums(
            tar_bytes({"aports/main/demo/APKBUILD": b""}),
            "demo",
            allowed_links=[exception],
        )


def test_dynamic_recipe_sources_require_an_explicit_exception() -> None:
    local = b"key"
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'for key in $keys; do\n\tsource="$source $key"\ndone\n'
                f'sha512sums="\n{evidence.hashlib.sha512(local).hexdigest()}  key.pub\n"\n'
            ).encode(),
            "aports/main/demo/key.pub": local,
        }
    )

    with pytest.raises(evidence.EvidenceError, match="one literal source block"):
        evidence.recipe_checksums(recipe, "demo")
    assert evidence.recipe_checksums(recipe, "demo", allow_dynamic_sources=True) == (
        {"key.pub": evidence.hashlib.sha512(local).hexdigest()},
        {"key.pub"},
    )


def test_recipe_checksum_parser_verifies_local_bytes() -> None:
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                f'source="local.patch"\nsha512sums="\n{"a" * 128}  local.patch\n"\n'
            ).encode(),
            "aports/main/demo/local.patch": b"different",
        }
    )
    with pytest.raises(evidence.EvidenceError, match="local recipe source checksum mismatch"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_checksum_parser_rejects_duplicate_basenames() -> None:
    recipe = tar_bytes(
        {
            "aports/main/demo/APKBUILD": b'source="local.patch"\n',
            "aports/main/demo/a/local.patch": b"one",
            "aports/main/demo/b/local.patch": b"two",
        }
    )
    with pytest.raises(evidence.EvidenceError, match="repeats regular-file basename"):
        evidence.recipe_checksums(recipe, "demo")


def test_recipe_source_and_checksums_must_have_exact_coverage() -> None:
    extra_source = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/one.tar.gz https://example.com/two.tar.gz"\n'
                f'sha512sums="\n{"a" * 128}  one.tar.gz\n"\n'
            ).encode()
        }
    )
    with pytest.raises(evidence.EvidenceError, match="counts differ"):
        evidence.recipe_checksums(extra_source, "demo")

    wrong_name = tar_bytes(
        {
            "aports/main/demo/APKBUILD": (
                'source="https://example.com/one-$pkgver.tar.gz"\n'
                f'sha512sums="\n{"a" * 128}  unrelated.zip\n"\n'
            ).encode()
        }
    )
    with pytest.raises(evidence.EvidenceError, match="does not match source"):
        evidence.recipe_checksums(wrong_name, "demo")


def test_recipe_checksum_parser_enforces_aggregate_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = tar_bytes({"aports/main/demo/APKBUILD": b"source=demo.tar.gz\n"})
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_TOTAL_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="recipe archive is too large"):
        evidence.recipe_checksums(recipe, "demo")


def test_fetch_rejects_an_invalid_expected_digest_before_network() -> None:
    with pytest.raises(evidence.EvidenceError, match="invalid expected sha256 digest"):
        evidence.fetch("https://example.com/source.tar.gz", "not-a-digest")


def test_source_url_rejects_an_out_of_range_port_before_network() -> None:
    with pytest.raises(evidence.EvidenceError, match="source URL is invalid"):
        evidence.require_https_source_url("https://example.com:65536/source.tar.gz")


def test_cpython_source_is_bound_to_official_recipe_version_and_hash() -> None:
    digest = "a" * 64
    recipe = f"ENV PYTHON_VERSION 3.14.6\nENV PYTHON_SHA256 {digest}\n".encode()
    source = {
        "url": "https://www.python.org/ftp/python/3.14.6/Python-3.14.6.tar.xz",
        "sha256": digest,
    }
    evidence.verify_cpython_source_binding(recipe, source)

    with pytest.raises(evidence.EvidenceError, match="source URL"):
        evidence.verify_cpython_source_binding(
            recipe,
            {**source, "url": "https://www.python.org/ftp/python/3.14.5/Python-3.14.5.tar.xz"},
        )
    with pytest.raises(evidence.EvidenceError, match="SHA-256"):
        evidence.verify_cpython_source_binding(recipe, {**source, "sha256": "b" * 64})
    with pytest.raises(evidence.EvidenceError, match="one literal"):
        evidence.verify_cpython_source_binding(
            b"ENV PYTHON_VERSION $VERSION\nENV PYTHON_SHA256 $HASH\n", source
        )


def test_fetch_records_every_https_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"verified content"

    class Response:
        def __init__(self) -> None:
            self.headers = {"Content-Length": str(len(content))}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://cdn.example.com/source.tar.gz"

        def read(self, _limit: int) -> bytes:
            return content

    class Opener:
        def __init__(self, handler: Any) -> None:
            self.handler = handler

        def open(self, _request: Any, *, timeout: int) -> Response:
            assert timeout == 60
            self.handler.urls.append("https://cdn.example.com/source.tar.gz")
            return Response()

    monkeypatch.setattr(
        evidence.urllib.request,
        "build_opener",
        lambda handler: Opener(handler),
    )
    download = evidence.fetch(
        "https://example.com/source.tar.gz",
        evidence.hashlib.sha256(content).hexdigest(),
    )

    assert download.content == content
    assert download.urls == (
        "https://example.com/source.tar.gz",
        "https://cdn.example.com/source.tar.gz",
    )
    record = evidence.source_record("demo", download.urls, content, "sources/demo.tar.gz")
    assert record["url"] == download.urls[0]
    assert record["urls"] == list(download.urls)


def test_fetch_rejects_a_final_url_away_from_https(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "http://example.com/source.tar.gz"

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> Response:
            return Response()

    monkeypatch.setattr(evidence.urllib.request, "build_opener", lambda *_args: Opener())
    with pytest.raises(evidence.EvidenceError, match="credential-free HTTPS"):
        evidence.fetch("https://example.com/source.tar.gz", "a" * 64)


def test_redirect_handler_rejects_downgrades_and_too_many_redirects() -> None:
    handler = evidence.AuditedRedirectHandler("https://example.com/source.tar.gz")
    request = evidence.urllib.request.Request("https://example.com/source.tar.gz")
    with pytest.raises(evidence.EvidenceError, match="credential-free HTTPS"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/next")

    handler.urls.extend(f"https://example.com/{index}" for index in range(5))
    with pytest.raises(evidence.EvidenceError, match="exceeded 5 redirects"):
        handler.redirect_request(request, None, 302, "Found", {}, "https://example.com/final")


def test_license_extraction_rejects_control_paths_in_tar_and_zip(tmp_path: Path) -> None:
    hostile_tar = tar_bytes({"LICENSE\nforged": b"text"})
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.extract_license_files(hostile_tar, "demo", tmp_path)

    hostile_zip = io.BytesIO()
    with zipfile.ZipFile(hostile_zip, mode="w") as archive:
        archive.writestr("LICENSE\nforged", b"text")
    with pytest.raises(evidence.EvidenceError, match="unsafe archive path"):
        evidence.extract_license_files(hostile_zip.getvalue(), "demo", tmp_path)


def test_license_extraction_rejects_zip_symlink_evidence(tmp_path: Path) -> None:
    hostile_zip = io.BytesIO()
    with zipfile.ZipFile(hostile_zip, mode="w") as archive:
        member = zipfile.ZipInfo("LICENSE")
        member.create_system = 3
        member.extract_version = 10
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "target")
    with pytest.raises(evidence.EvidenceError, match="unsupported entry type"):
        evidence.extract_license_files(hostile_zip.getvalue(), "demo", tmp_path)


def test_license_extraction_reads_bounded_regular_zip_evidence(tmp_path: Path) -> None:
    source_zip = io.BytesIO()
    with zipfile.ZipFile(source_zip, mode="w") as archive:
        for name, content in {
            "demo/LICENSE.md": b"license text\n",
            "demo/src/app.py": b"APP = True\n",
        }.items():
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, content)

    retained = evidence.extract_license_files(source_zip.getvalue(), "demo", tmp_path)

    assert len(retained) == 1
    assert retained[0].endswith("-LICENSE.md")
    assert (tmp_path / retained[0]).read_bytes() == b"license text\n"


def test_license_extraction_reads_stored_zip_evidence(tmp_path: Path) -> None:
    content = source_zip_bytes([("LICENSE", b"stored license\n")], compression=zipfile.ZIP_STORED)

    retained = evidence.extract_license_files(content, "demo", tmp_path)

    assert len(retained) == 1
    assert (tmp_path / retained[0]).read_bytes() == b"stored license\n"


def test_source_zip_inflater_uses_the_declared_output_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    real_decompressobj = evidence.zlib.decompressobj
    output_caps: list[int] = []

    class DecoderProxy:
        def __init__(self, wbits: int) -> None:
            self.decoder = real_decompressobj(wbits)

        def decompress(self, payload: bytes, max_length: int) -> bytes:
            output_caps.append(max_length)
            return cast(bytes, self.decoder.decompress(payload, max_length))

        @property
        def eof(self) -> bool:
            return cast(bool, self.decoder.eof)

        @property
        def unused_data(self) -> bytes:
            return cast(bytes, self.decoder.unused_data)

        @property
        def unconsumed_tail(self) -> bytes:
            return cast(bytes, self.decoder.unconsumed_tail)

    monkeypatch.setattr(evidence.zlib, "decompressobj", DecoderProxy)
    payload = b"bounded license\n"
    content = source_zip_bytes([("LICENSE", payload)])

    retained = evidence.extract_license_files(content, "demo", tmp_path)

    assert len(retained) == 1
    assert output_caps == [len(payload) + 1]


def test_license_extraction_rejects_underdeclared_deflate_output(tmp_path: Path) -> None:
    source_zip = io.BytesIO()
    with zipfile.ZipFile(source_zip, mode="w") as archive:
        member = zipfile.ZipInfo("LICENSE")
        member.create_system = 3
        member.external_attr = (stat.S_IFREG | 0o644) << 16
        member.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(member, b"ABCD")

    content = bytearray(source_zip.getvalue())
    local, central = zip_record_offsets(content, "LICENSE")
    declared = b"AB"
    crc = zlib.crc32(declared) & 0xFFFFFFFF
    content[local + 14 : local + 18] = crc.to_bytes(4, "little")
    content[local + 22 : local + 26] = len(declared).to_bytes(4, "little")
    content[central + 16 : central + 20] = crc.to_bytes(4, "little")
    content[central + 24 : central + 28] = len(declared).to_bytes(4, "little")

    # ZipFile.open() silently returns only the declared prefix for this archive.
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as permissive:
        assert permissive.read("LICENSE") == declared
    with pytest.raises(evidence.EvidenceError, match="license payload disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("entry-comment", "unsupported entry metadata"),
        ("archive-comment", "comments are not supported"),
        ("unsupported-extra", "unsupported extra metadata"),
        ("duplicate-extra", "malformed extra metadata"),
        ("descriptor", "unsupported entry metadata"),
        ("dos-directory-bit", "unsupported entry type"),
        ("special-mode-bit", "unsupported entry type"),
        ("invalid-timestamp", "invalid DOS timestamp"),
        ("invalid-calendar-date", "invalid DOS timestamp"),
        ("non-ascii-name", "non-ASCII entry name"),
        ("nul-name", "NUL-containing entry name"),
        ("stored-size", "stored entry has inconsistent sizes"),
    ],
)
def test_license_extraction_rejects_unsupported_source_zip_dialects(
    mutation: str, message: str, tmp_path: Path
) -> None:
    unix_owner = b"ux\x05\x00\x01\x01\x01\x01\x01"
    if mutation == "entry-comment":
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], entry_comment=b"x"))
    elif mutation == "archive-comment":
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], archive_comment=b"x"))
    elif mutation == "unsupported-extra":
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], extra=b"\xfe\xca\x00\x00"))
    elif mutation == "duplicate-extra":
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], extra=unix_owner + unix_owner))
    else:
        compression = zipfile.ZIP_STORED if mutation == "stored-size" else zipfile.ZIP_DEFLATED
        content = bytearray(source_zip_bytes([("LICENSE", b"text")], compression=compression))
        local, central = zip_record_offsets(content, "LICENSE")
        if mutation == "descriptor":
            content[local + 6 : local + 8] = (8).to_bytes(2, "little")
            content[central + 8 : central + 10] = (8).to_bytes(2, "little")
        elif mutation == "dos-directory-bit":
            attributes = int.from_bytes(content[central + 38 : central + 42], "little") | 0x10
            content[central + 38 : central + 42] = attributes.to_bytes(4, "little")
        elif mutation == "special-mode-bit":
            attributes = int.from_bytes(content[central + 38 : central + 42], "little")
            attributes |= stat.S_ISUID << 16
            content[central + 38 : central + 42] = attributes.to_bytes(4, "little")
        elif mutation == "invalid-timestamp":
            invalid_time = 31 << 11
            content[local + 10 : local + 12] = invalid_time.to_bytes(2, "little")
            content[central + 12 : central + 14] = invalid_time.to_bytes(2, "little")
        elif mutation == "invalid-calendar-date":
            february_31 = 2 << 5 | 31
            content[local + 12 : local + 14] = february_31.to_bytes(2, "little")
            content[central + 14 : central + 16] = february_31.to_bytes(2, "little")
        elif mutation == "non-ascii-name":
            content[central + evidence.ZIP_CENTRAL_HEADER.size] = 0xFF
        elif mutation == "nul-name":
            content[central + evidence.ZIP_CENTRAL_HEADER.size] = 0
        else:
            content[central + 20 : central + 24] = (3).to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_source_zip_infozip_extra_fields_are_strictly_parsed() -> None:
    central = bytes.fromhex("55540500031b80206a75780b000104e803000004e8030000")
    local = bytes.fromhex("55540900031b80206a1c80206a75780b000104e803000004e8030000")

    assert evidence.validate_source_zip_extra(central, "entry", central=True) == {
        0x5455: (3, 0x6A20801B),
        0x7875: (4, 1000, 4, 1000),
    }
    assert evidence.validate_source_zip_extra(local, "entry", central=False) == {
        0x5455: (3, 0x6A20801B, 0x6A20801C),
        0x7875: (4, 1000, 4, 1000),
    }


@pytest.mark.parametrize(
    "extra",
    [
        b"U",
        b"UT\x01\x00",
        b"UT\x05\x00\x00\x00\x00\x00\x00",
        b"ux\x02\x00\x01\x00",
        b"ux\x05\x00\x02\x01\x01\x01\x01",
    ],
)
def test_source_zip_extra_fields_reject_malformed_payloads(extra: bytes) -> None:
    with pytest.raises(evidence.EvidenceError, match=r"malformed|unsupported"):
        evidence.validate_source_zip_extra(extra, "entry", central=True)


def test_license_extraction_rejects_local_extra_field_disagreement(tmp_path: Path) -> None:
    unix_owner = b"ux\x05\x00\x01\x01\x01\x01\x01"
    content = bytearray(source_zip_bytes([("LICENSE", b"text")], extra=unix_owner))
    local, _central = zip_record_offsets(content, "LICENSE")
    local_header = evidence.ZIP_LOCAL_HEADER.unpack_from(content, local)
    local_extra = local + evidence.ZIP_LOCAL_HEADER.size + local_header[-2]
    content[local_extra + 6] = 2

    with pytest.raises(evidence.EvidenceError, match="local Unix-owner metadata disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_duplicate_source_zip_names(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"a"), ("COPYING", b"b")]))
    _local, central = zip_record_offsets(content, "COPYING")
    name_start = central + evidence.ZIP_CENTRAL_HEADER.size
    content[name_start : name_start + len("COPYING")] = b"LICENSE"

    with pytest.raises(evidence.EvidenceError, match="duplicate or non-canonical entry name"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_file_directory_source_zip_aliases(tmp_path: Path) -> None:
    content = source_zip_bytes([("LICENSE", b"text"), ("LICENSE/", b"")])

    with pytest.raises(evidence.EvidenceError, match="duplicate or non-canonical entry name"):
        evidence.extract_license_files(content, "demo", tmp_path)


def test_license_extraction_rejects_local_source_zip_name_disagreement(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    local, _central = zip_record_offsets(content, "LICENSE")
    content[local + evidence.ZIP_LOCAL_HEADER.size] = ord("C")

    with pytest.raises(evidence.EvidenceError, match="local entry boundary disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_reordered_source_zip_central_records(
    tmp_path: Path,
) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"a"), ("NOTICE", b"b")]))
    eocd = content.rfind(b"PK\x05\x06")
    assert eocd >= 0
    central = evidence.ZIP_EOCD.unpack_from(content, eocd)[-2]
    records: list[bytes] = []
    position = central
    while position < eocd:
        assert content[position : position + 4] == b"PK\x01\x02"
        name_size = int.from_bytes(content[position + 28 : position + 30], "little")
        extra_size = int.from_bytes(content[position + 30 : position + 32], "little")
        comment_size = int.from_bytes(content[position + 32 : position + 34], "little")
        end = position + evidence.ZIP_CENTRAL_HEADER.size + name_size + extra_size + comment_size
        records.append(bytes(content[position:end]))
        position = end
    content[central:eocd] = b"".join(reversed(records))

    with pytest.raises(evidence.EvidenceError, match="local-record order"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


@pytest.mark.parametrize("mutation", ["prefix", "gap"])
def test_license_extraction_rejects_source_zip_prefixes_and_gaps(
    mutation: str, tmp_path: Path
) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    local, central = zip_record_offsets(content, "LICENSE")
    eocd = content.rfind(b"PK\x05\x06")
    assert local == 0 and eocd > central
    if mutation == "prefix":
        content[:0] = b"X"
        central += 1
        eocd += 1
        content[central + 42 : central + 46] = (1).to_bytes(4, "little")
    else:
        content[central:central] = b"X"
        central += 1
        eocd += 1
    content[eocd + 16 : eocd + 20] = central.to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match=r"prefix|gap|trailing"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_expected_zip_rejects_a_prefixed_truncated_archive(tmp_path: Path) -> None:
    content = b"X" + source_zip_bytes([("LICENSE", b"text")])[:-1]

    with pytest.raises(evidence.EvidenceError, match="source ZIP"):
        evidence.extract_license_files(content, "demo", tmp_path, archive_name="source.zip")


def test_archive_name_parse_errors_are_normalized(tmp_path: Path) -> None:
    with pytest.raises(evidence.EvidenceError, match="source archive name is invalid"):
        evidence.extract_license_files(b"text", "demo", tmp_path, archive_name="https://[")


def test_license_extraction_rejects_trailing_deflate_bytes(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    local, central = zip_record_offsets(content, "LICENSE")
    eocd = content.rfind(b"PK\x05\x06")
    local_compressed_size = int.from_bytes(content[local + 18 : local + 22], "little")
    content[central:central] = b"X"
    central += 1
    eocd += 1
    content[local + 18 : local + 22] = (local_compressed_size + 1).to_bytes(4, "little")
    content[central + 20 : central + 24] = (local_compressed_size + 1).to_bytes(4, "little")
    content[eocd + 16 : eocd + 20] = central.to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match="license payload disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_source_zip_crc_disagreement(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    local, central = zip_record_offsets(content, "LICENSE")
    content[local + 14 : local + 18] = (0).to_bytes(4, "little")
    content[central + 16 : central + 20] = (0).to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match="payload CRC disagrees"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_rejects_invalid_source_zip_directory_payload(tmp_path: Path) -> None:
    content = bytearray(source_zip_bytes([("source/", b"")]))
    local, central = zip_record_offsets(content, "source/")
    content[local + 14 : local + 18] = (1).to_bytes(4, "little")
    content[central + 16 : central + 20] = (1).to_bytes(4, "little")

    with pytest.raises(evidence.EvidenceError, match="directory has invalid payload metadata"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


@pytest.mark.parametrize("sentinel", [0xFFFF, 0xFFFFFFFF])
def test_license_extraction_rejects_source_zip64_eocd_sentinels(
    sentinel: int, tmp_path: Path
) -> None:
    content = bytearray(source_zip_bytes([("LICENSE", b"text")]))
    eocd = content.rfind(b"PK\x05\x06")
    assert eocd >= 0
    if sentinel == 0xFFFF:
        content[eocd + 8 : eocd + 12] = sentinel.to_bytes(2, "little") * 2
    else:
        content[eocd + 12 : eocd + 20] = sentinel.to_bytes(4, "little") * 2

    with pytest.raises(evidence.EvidenceError, match="ZIP64"):
        evidence.extract_license_files(bytes(content), "demo", tmp_path)


def test_license_extraction_bounds_source_zip_metadata_and_licenses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    one_license = source_zip_bytes([("LICENSE", b"text")])
    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_ENTRIES", 0)
    with pytest.raises(evidence.EvidenceError, match="entry count"):
        evidence.extract_license_files(one_license, "demo", tmp_path)

    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_ENTRIES", 10)
    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_CENTRAL_DIRECTORY_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="central-directory boundary"):
        evidence.extract_license_files(one_license, "demo", tmp_path)

    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_CENTRAL_DIRECTORY_BYTES", 1024)
    monkeypatch.setattr(evidence, "MAX_SOURCE_LICENSE_FILES", 1)
    two_licenses = source_zip_bytes([("LICENSE", b"a"), ("NOTICE", b"b")])
    with pytest.raises(evidence.EvidenceError, match="too many license files"):
        evidence.extract_license_files(two_licenses, "demo", tmp_path)

    monkeypatch.setattr(evidence, "MAX_SOURCE_LICENSE_FILES", 10)
    monkeypatch.setattr(evidence, "MAX_SOURCE_LICENSE_TOTAL_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="license files exceed size limit"):
        evidence.extract_license_files(one_license, "demo", tmp_path)


def test_license_extraction_bounds_source_zip_expansion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    content = source_zip_bytes([("LICENSE", b"A" * 100)])
    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_COMPRESSION_RATIO", 1)
    with pytest.raises(evidence.EvidenceError, match="resource limits"):
        evidence.extract_license_files(content, "demo", tmp_path)

    monkeypatch.setattr(evidence, "MAX_SOURCE_ZIP_COMPRESSION_RATIO", 1_000)
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_TOTAL_BYTES", 99)
    with pytest.raises(evidence.EvidenceError, match="cumulative expansion limit"):
        evidence.extract_license_files(content, "demo", tmp_path)


def test_license_extraction_ignores_safe_non_license_tar_symlinks(tmp_path: Path) -> None:
    archive = tar_bytes(
        {
            "demo/LICENSE": b"license text\n",
            "demo/src/tool.c": b"int main(void) { return 0; }\n",
        },
        links={"demo/src/tool-static.c": "tool.c"},
    )

    retained = evidence.extract_license_files(archive, "demo", tmp_path)

    assert len(retained) == 1
    assert retained[0].endswith("-LICENSE")
    assert (tmp_path / retained[0]).read_bytes() == b"license text\n"


def test_license_extraction_rejects_tar_symlink_license_evidence(tmp_path: Path) -> None:
    archive = tar_bytes(
        {"demo/COPYING": b"license text\n"},
        links={"demo/LICENSE": "COPYING"},
    )

    with pytest.raises(evidence.EvidenceError, match="license entry is not regular"):
        evidence.extract_license_files(archive, "demo", tmp_path)


def test_license_extraction_rejects_tar_symlink_payloads(tmp_path: Path) -> None:
    member = tarfile.TarInfo("demo/src/alias")
    member.type = tarfile.SYMTYPE
    member.linkname = "target"
    member.size = 1
    archive = member.tobuf(format=tarfile.USTAR_FORMAT) + b"x" + b"\0" * 511 + b"\0" * 1024

    with pytest.raises(evidence.EvidenceError, match="symlink has a payload"):
        evidence.extract_license_files(archive, "demo", tmp_path)


@pytest.mark.parametrize("target", ("../outside", "/absolute", "dir\\alias"))
def test_license_extraction_rejects_unsafe_tar_symlink_targets(target: str, tmp_path: Path) -> None:
    archive = tar_bytes(
        {"demo/LICENSE": b"license text\n"},
        links={"demo/src/alias": target},
    )

    with pytest.raises(evidence.EvidenceError, match="unsafe archive link target"):
        evidence.extract_license_files(archive, "demo", tmp_path)


def test_license_extraction_still_rejects_tar_hardlinks(tmp_path: Path) -> None:
    archive = tar_bytes(
        {"demo/LICENSE": b"license text\n"},
        hardlinks={"demo/src/alias": "demo/LICENSE"},
    )

    with pytest.raises(evidence.EvidenceError, match="unsupported entry"):
        evidence.extract_license_files(archive, "demo", tmp_path)


@pytest.mark.parametrize("signature", (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
def test_license_extraction_rejects_every_zip_signature(signature: bytes, tmp_path: Path) -> None:
    with pytest.raises(evidence.EvidenceError, match="source ZIP"):
        evidence.extract_license_files(signature, "demo", tmp_path)


def test_tar_extension_payload_is_bounded_before_materialization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("LICENSE")
        member.size = 4
        member.pax_headers = {"comment": "x" * 2048}
        archive.addfile(member, io.BytesIO(b"text"))
    monkeypatch.setattr(evidence, "MAX_TAR_EXTENSION_BYTES", 1024)

    with pytest.raises(evidence.EvidenceError, match="extension header"):
        evidence.extract_license_files(archive_bytes.getvalue(), "demo", tmp_path)


def test_gnu_sparse_tar_entries_are_rejected(tmp_path: Path) -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("LICENSE")
        member.size = 4
        member.pax_headers = {
            "GNU.sparse.map": "0,4",
            "GNU.sparse.size": "4",
        }
        archive.addfile(member, io.BytesIO(b"text"))

    with pytest.raises(evidence.EvidenceError, match="GNU sparse"):
        evidence.extract_license_files(archive_bytes.getvalue(), "demo", tmp_path)


def test_negative_pax_member_size_fails_closed(tmp_path: Path) -> None:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        hostile = tarfile.TarInfo("hostile")
        hostile.pax_headers = {"size": "-512"}
        archive.addfile(hostile)
        license_member = tarfile.TarInfo("LICENSE")
        license_member.size = 4
        archive.addfile(license_member, io.BytesIO(b"text"))

    with pytest.raises(evidence.EvidenceError, match=r"PAX|negative"):
        evidence.extract_license_files(archive_bytes.getvalue(), "demo", tmp_path)


def test_policy_comparison_and_human_approval_are_separate() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = standalone_inventory(component)
    policy = standalone_policy(
        component,
        "MIT",
        license_texts=[
            {
                "id": "MIT",
                "sha256": "e5" * 32,
                "url": "https://example.com/MIT.txt",
            }
        ],
    )
    evidence.verify_inventory(inventory, policy, require_approval=False)
    with pytest.raises(evidence.EvidenceError, match="maintainer approval"):
        evidence.verify_inventory(inventory, policy, require_approval=True)

    policy["distribution_approval"] = {
        "approved": True,
        "approved_by": "maintainer",
        "approved_on": "2026-07-14",
        "rationale": "Test-only approval.",
    }
    with pytest.raises(evidence.EvidenceError, match="evidence is incomplete"):
        evidence.verify_inventory(inventory, policy, require_approval=True)

    policy["platforms"]["linux/amd64"][0] = {**component, "version": "2"}
    with pytest.raises(evidence.EvidenceError, match="differs from the reviewed policy"):
        evidence.verify_inventory(inventory, policy, require_approval=False)


def test_license_refs_require_exact_pinned_custom_evidence() -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "Custom",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory = standalone_inventory(component)
    policy = standalone_policy(component, "LicenseRef-Demo", license_texts=[])
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    requirement = {
        "components": ["python:demo@1"],
        "evidence": {
            "python:demo@1": {
                "path": "licenses/from-source/python-demo-1/notice-LICENSE",
                "sha256": "a" * 64,
            }
        },
        "rationale": "Exact source-carried notice reviewed.",
        "require_source_notice": True,
    }
    policy["custom_license_evidence"] = {"LicenseRef-Demo": requirement}
    evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {
        "LicenseRef-Demo": requirement,
        "LicenseRef-Unused": requirement,
    }
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {"LicenseRef-Demo": {**requirement, "rationale": ""}}
    with pytest.raises(evidence.EvidenceError, match="has no rationale"):
        evidence.verify_inventory(inventory, policy, require_approval=False)

    policy["custom_license_evidence"] = {"LicenseRef-Demo": requirement}
    unrelated = [
        {
            "component": "python-demo-1",
            "path": "licenses/from-source/python-demo-1/COPYING.GPL",
            "sha256": "b" * 64,
        }
    ]
    with pytest.raises(evidence.EvidenceError, match="pinned source-carried notice"):
        evidence.verify_pinned_custom_license_records(inventory["components"], policy, unrelated)


def test_image_revision_and_version_must_match_source() -> None:
    revision = "a" * 40
    inventory = {"image_revision": revision, "image_version": "1.2.3"}
    evidence.verify_image_revision(inventory, version="1.2.3", source_revision=revision)
    with pytest.raises(evidence.EvidenceError, match="does not match source revision"):
        evidence.verify_image_revision(inventory, version="1.2.3", source_revision="b" * 40)
    with pytest.raises(evidence.EvidenceError, match="image version"):
        evidence.verify_image_revision(inventory, version="1.2.4", source_revision=revision)


def test_application_artifact_labels_require_exact_proof_binding() -> None:
    inventory = standalone_inventory(
        {
            "ecosystem": "python",
            "name": "demo",
            "version": "1",
            "observed_license": "MIT",
            "effective": True,
            "metadata_sha256": "a" * 64,
        }
    )
    evidence.verify_application_artifact_labels(
        inventory,
        source_revision="c" * 40,
        wheel_sha256="e" * 64,
        selection_record_sha256="f" * 64,
    )

    for field, value in (
        ("image_revision", "d" * 40),
        ("application_wheel_sha256", "1" * 64),
        ("application_selection_record_sha256", "2" * 64),
    ):
        changed = copy.deepcopy(inventory)
        changed[field] = value
        with pytest.raises(evidence.EvidenceError, match="does not match selected"):
            evidence.verify_application_artifact_labels(
                changed,
                source_revision="c" * 40,
                wheel_sha256="e" * 64,
                selection_record_sha256="f" * 64,
            )

    for field in ("application_wheel_sha256", "application_selection_record_sha256"):
        changed = copy.deepcopy(inventory)
        changed[field] = ""
        with pytest.raises(evidence.EvidenceError, match=f"invalid {field}"):
            evidence.validate_component_inventory(changed)


def test_selected_wheel_contract_binds_every_application_owned_file() -> None:
    component = {
        "ecosystem": "python",
        "name": "extra-codeowners",
        "version": "1",
        "observed_license": "Apache-2.0",
        "effective": True,
        "metadata_sha256": "a" * 64,
    }
    inventory = standalone_inventory(component)
    alternatives: list[dict[str, Any]] = []
    for index, interpreter in enumerate(("python", "python3", "python3.14"), start=1):
        alternatives.append(
            {
                "launcher_interpreter": interpreter,
                "files": [
                    {
                        "path": "bin/extra-codeowners",
                        "sha256": str(index) * 64,
                        "size": 300 + index,
                        "mode": 0o755,
                    },
                    {
                        "path": "lib/python3.14/site-packages/extra_codeowners-1.dist-info/RECORD",
                        "sha256": str(index + 3) * 64,
                        "size": 500 + index,
                        "mode": 0o644,
                    },
                    {
                        "path": "lib/python3.14/site-packages/extra_codeowners/app.py",
                        "sha256": "a" * 64,
                        "size": 10,
                        "mode": 0o644,
                    },
                ],
            }
        )
    contract = {
        "environment_root": "/opt/venv",
        "project": "extra-codeowners",
        "version": "1",
        "python_directory": "python3.14",
        "alternatives": alternatives,
    }
    selected = alternatives[1]["files"]
    inventory["python_record_ownership"] = [
        {
            "owner": "extra-codeowners",
            "effective": True,
            "layer": 1,
            "path": f"opt/venv/{record['path']}",
            "sha256": record["sha256"],
            "size": record["size"],
            "mode": record["mode"],
            "uid": 0,
            "gid": 0,
        }
        for record in selected
    ]
    # Exercise the compatibility projection separately from the historical
    # installation evidence asserted below.
    inventory["wheel_installations"] = None

    assert evidence.verify_selected_application_installation(inventory, contract) == "python3"

    for path_suffix in ("app.py", "bin/extra-codeowners", ".dist-info/RECORD"):
        changed = copy.deepcopy(inventory)
        owned = next(
            record
            for record in changed["python_record_ownership"]
            if record["path"].endswith(path_suffix)
        )
        owned["sha256"] = "f" * 64
        with pytest.raises(evidence.EvidenceError, match="differs from every"):
            evidence.verify_selected_application_installation(changed, contract)

    self_consistent_rewrite = copy.deepcopy(inventory)
    application = next(
        record
        for record in self_consistent_rewrite["python_record_ownership"]
        if record["path"].endswith("app.py")
    )
    installed_record = next(
        record
        for record in self_consistent_rewrite["python_record_ownership"]
        if record["path"].endswith(".dist-info/RECORD")
    )
    application.update({"sha256": "e" * 64, "size": 11})
    installed_record.update({"sha256": "d" * 64, "size": 502})
    with pytest.raises(evidence.EvidenceError, match="differs from every"):
        evidence.verify_selected_application_installation(self_consistent_rewrite, contract)

    historical_occurrence = copy.deepcopy(inventory)
    hidden = copy.deepcopy(historical_occurrence["python_record_ownership"][0])
    hidden.update({"effective": False, "layer": 0, "sha256": "c" * 64})
    historical_occurrence["python_record_ownership"].append(hidden)
    with pytest.raises(evidence.EvidenceError, match="invalid runtime identity"):
        evidence.verify_selected_application_installation(historical_occurrence, contract)

    def historical_installation(
        files: list[dict[str, Any]],
        *,
        layer: int,
        effective: bool,
        owner: str = "python:extra-codeowners@1",
    ) -> dict[str, Any]:
        entries = []
        for file in files:
            occurrence = {
                "effective": effective,
                "layer": layer,
                "path": f"opt/venv/{file['path']}",
                "sha256": file["sha256"],
                "size": file["size"],
                "mode": file["mode"],
                "uid": 0,
                "gid": 0,
            }
            entries.append({"path": occurrence["path"], "occurrence": occurrence})
        record = next(
            entry["occurrence"] for entry in entries if entry["path"].endswith(".dist-info/RECORD")
        )
        return {"owner": owner, "record": record, "entries": entries}

    occurrence_inventory = copy.deepcopy(inventory)
    occurrence_inventory["wheel_installations"] = [
        historical_installation(alternatives[0]["files"], layer=1, effective=False),
        historical_installation(alternatives[1]["files"], layer=2, effective=True),
    ]
    assert (
        evidence.verify_selected_application_installation(occurrence_inventory, contract)
        == "python3"
    )

    rewritten_history = copy.deepcopy(occurrence_inventory)
    historical_entries = rewritten_history["wheel_installations"][0]["entries"]
    historical_app = next(entry for entry in historical_entries if entry["path"].endswith("app.py"))
    historical_record = next(
        entry for entry in historical_entries if entry["path"].endswith(".dist-info/RECORD")
    )
    historical_app["occurrence"].update({"sha256": "b" * 64, "size": 12})
    historical_record["occurrence"].update({"sha256": "c" * 64, "size": 503})
    with pytest.raises(evidence.EvidenceError, match="distributed application installation"):
        evidence.verify_selected_application_installation(rewritten_history, contract)

    old_application = copy.deepcopy(occurrence_inventory)
    old_application["wheel_installations"][0]["owner"] = "python:extra-codeowners@0.9"
    with pytest.raises(evidence.EvidenceError, match="selected version"):
        evidence.verify_selected_application_installation(old_application, contract)


def test_dockerfile_builder_and_final_runtime_match_reviewed_base(tmp_path: Path) -> None:
    digest = "sha256:" + "b" * 64
    policy = {"base_image": "python:3.14-alpine", "base_image_index_digest": digest}
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        f"FROM python:3.14-alpine@{digest} AS builder\n"
        "FROM builder AS test\n"
        f"FROM python:3.14-alpine@{digest} AS runtime\n"
    )
    evidence.verify_dockerfile_base(dockerfile, policy)

    policy["base_image_index_digest"] = "sha256:" + "c" * 64
    with pytest.raises(evidence.EvidenceError, match="builder stage"):
        evidence.verify_dockerfile_base(dockerfile, policy)

    policy["base_image_index_digest"] = digest
    dockerfile.write_text(
        dockerfile.read_text() + "FROM python:3.14-alpine@" + digest + " AS debug\n"
    )
    with pytest.raises(evidence.EvidenceError, match="final build stage"):
        evidence.verify_dockerfile_base(dockerfile, policy)


def test_committed_dockerfile_matches_the_reviewed_base_policy() -> None:
    policy = json.loads(Path(".compliance/container-policy.json").read_text())
    evidence.verify_dockerfile_base(Path("Dockerfile"), policy)


def test_final_image_layers_must_begin_with_the_reviewed_platform_base() -> None:
    policy = {
        "base_image_platforms": {
            platform: {
                "layer_diff_ids": ["sha256:" + character * 64],
            }
            for platform, character in (
                ("linux/amd64", "a"),
                ("linux/arm64", "b"),
            )
        }
    }
    files: dict[str, Any] = {
        "platform": "linux/amd64",
        "layers": [
            {"digest": "sha256:" + "a" * 64},
            {"digest": "sha256:" + "c" * 64},
        ],
    }

    evidence.verify_base_layer_binding(files, policy)
    files["layers"][0]["digest"] = "sha256:" + "d" * 64
    with pytest.raises(evidence.EvidenceError, match="do not begin with"):
        evidence.verify_base_layer_binding(files, policy)


@pytest.mark.parametrize(
    "hostile_path",
    (
        "usr/local/lib/python3.14/sitecustomize.py",
        "usr/local/bin/unreviewed-executable",
    ),
)
def test_post_base_provenance_rejects_unclassified_regular_files(
    hostile_path: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    license_content = b"reviewed application license\n"
    installed = {
        "demo.py": b"VALUE = 'reviewed'\n",
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    base = tar_bytes({"lib/apk/db/installed": apk_database()})
    application_files = {
        "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
        "usr/share/licenses/extra-codeowners/LICENSE": license_content,
        **{f"{site}/{path}": content for path, content in installed.items()},
    }
    application = tar_bytes(
        application_files,
        links=VENV_LINKS,
        directories=explicit_parent_directories((*application_files, *VENV_LINKS)),
    )
    clean_image = tmp_path / "clean.tar"
    saved_image_layers(clean_image, [base, application])
    clean_inventory, clean_files = evidence._inventory_saved_image(
        clean_image, "linux/amd64", "sha256:" + "a" * 64
    )
    base_digest = clean_files["layers"][0]["digest"]
    clean_directory_effects, _clean_removals = evidence.canonical_post_base_filesystem_changes(
        clean_files, 1, "linux/amd64"
    )
    policy = {
        "base_image_platforms": {
            "linux/amd64": {
                "layer_diff_ids": [base_digest],
            },
            "linux/arm64": {
                "layer_diff_ids": ["sha256:" + "e" * 64],
            },
        },
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": clean_inventory["apk_database_occurrences"],
                "post_base_directory_effects": clean_directory_effects,
                "post_base_removals": [],
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        },
    }
    monkeypatch.setattr(
        evidence,
        "run",
        lambda *_args, **_kwargs: license_content,
    )
    evidence.verify_post_base_provenance(clean_inventory, clean_files, policy, tmp_path)

    hostile_image = tmp_path / "hostile.tar"
    saved_image_layers(hostile_image, [base, application, tar_bytes({hostile_path: b"payload"})])
    hostile_inventory, hostile_files = evidence._inventory_saved_image(
        hostile_image, "linux/amd64", "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="unclassified post-base regular file"):
        evidence.verify_post_base_provenance(hostile_inventory, hostile_files, policy, tmp_path)

    hostile = evidence.PurePosixPath(hostile_path)
    marker = str(hostile.parent / f".wh.{hostile.name}")
    hidden_image = tmp_path / "hidden-hostile.tar"
    saved_image_layers(
        hidden_image,
        [base, application, tar_bytes({hostile_path: b"payload"}), tar_bytes({marker: b""})],
    )
    hidden_inventory, hidden_files = evidence._inventory_saved_image(
        hidden_image, "linux/amd64", "sha256:" + "a" * 64
    )
    hidden_policy = copy.deepcopy(policy)
    hidden_policy["filesystem_baselines"]["linux/amd64"]["post_base_removals"] = [
        {field: record[field] for field in ("kind", "path", "target")}
        for record in hidden_files["whiteouts"]
        if record["layer"] >= 1
    ]
    with pytest.raises(evidence.EvidenceError, match="unclassified post-base regular file"):
        evidence.verify_post_base_provenance(
            hidden_inventory, hidden_files, hidden_policy, tmp_path
        )

    altered_license_image = tmp_path / "altered-license.tar"
    saved_image_layers(
        altered_license_image,
        [
            base,
            application,
            tar_bytes({"usr/share/licenses/extra-codeowners/LICENSE": b"altered license\n"}),
        ],
    )
    altered_inventory, altered_files = evidence._inventory_saved_image(
        altered_license_image, "linux/amd64", "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="LICENSE differs from Git HEAD"):
        evidence.verify_post_base_provenance(altered_inventory, altered_files, policy, tmp_path)

    extra_link_image = tmp_path / "extra-link.tar"
    saved_image_layers(
        extra_link_image,
        [base, application, tar_bytes({}, links={"usr/local/bin/unreviewed": "python3"})],
    )
    link_inventory, link_files = evidence._inventory_saved_image(
        extra_link_image, "linux/amd64", "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="unreviewed post-base non-regular"):
        evidence.verify_post_base_provenance(link_inventory, link_files, policy, tmp_path)

    whiteout_path = "usr/local/bin/.wh.unreviewed"
    whiteout_image = tmp_path / "unreviewed-whiteout.tar"
    saved_image_layers(
        whiteout_image,
        [base, application, tar_bytes({whiteout_path: b""})],
    )
    with pytest.raises(evidence.EvidenceError, match="absent from lower layers"):
        evidence._inventory_saved_image(whiteout_image, "linux/amd64", "sha256:" + "a" * 64)


def test_directory_effects_ignore_portable_repeated_headers(tmp_path: Path) -> None:
    base = tar_bytes(
        {"lib/apk/db/installed": apk_database()},
        directories=["etc"],
    )
    without_repeated_header = tmp_path / "without-repeated-directory.tar"
    saved_image_layers(without_repeated_header, [base, tar_bytes({})])
    _inventory, without_files = evidence._inventory_saved_image(
        without_repeated_header, "linux/amd64", "sha256:" + "a" * 64
    )
    with_repeated_header = tmp_path / "with-repeated-directory.tar"
    saved_image_layers(with_repeated_header, [base, tar_bytes({}, directories=["etc"])])
    _inventory, with_files = evidence._inventory_saved_image(
        with_repeated_header, "linux/amd64", "sha256:" + "a" * 64
    )

    without_effects, without_removals = evidence.canonical_post_base_filesystem_changes(
        without_files, 1, "linux/amd64"
    )
    with_effects, with_removals = evidence.canonical_post_base_filesystem_changes(
        with_files, 1, "linux/amd64"
    )

    assert len(with_files["directories"]) == len(without_files["directories"]) + 1
    assert with_effects == without_effects == []
    assert with_removals == without_removals == []


def test_directory_effects_retain_real_transitions_and_reject_hostile_noops(
    tmp_path: Path,
) -> None:
    base = tar_bytes(
        {"lib/apk/db/installed": apk_database()},
        directories=["etc", "opt"],
        headers={"etc": {"mode": 0o777}},
    )
    image = tmp_path / "hostile-noop-directory.tar"
    saved_image_layers(
        image,
        [
            base,
            tar_bytes(
                {},
                directories=["etc", "opt/application"],
                headers={"etc": {"mode": 0o777}},
            ),
        ],
    )
    _inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    with pytest.raises(evidence.EvidenceError, match="root-owned"):
        evidence.canonical_post_base_filesystem_changes(files, 1, "linux/amd64")

    safe_image = tmp_path / "safe-directory-effect.tar"
    saved_image_layers(
        safe_image,
        [
            tar_bytes({"lib/apk/db/installed": apk_database()}, directories=["etc", "opt"]),
            tar_bytes({}, directories=["etc", "opt/application"]),
        ],
    )
    _inventory, safe_files = evidence._inventory_saved_image(
        safe_image, "linux/amd64", "sha256:" + "a" * 64
    )
    effects, removals = evidence.canonical_post_base_filesystem_changes(
        safe_files, 1, "linux/amd64"
    )
    assert effects == [
        {
            "layer": 1,
            "path": "opt/application",
            "mode": 0o755,
            "uid": 0,
            "gid": 0,
        }
    ]
    assert removals == []
    with pytest.raises(evidence.EvidenceError, match="invalid post-base directory-effect"):
        evidence.validate_directory_effect_policy(
            [{**effects[0], "effective": True}], "linux/amd64"
        )

    policy = {
        "base_image_platforms": {
            "linux/amd64": {"layer_diff_ids": [safe_files["layers"][0]["digest"]]},
            "linux/arm64": {"layer_diff_ids": ["sha256:" + "b" * 64]},
        },
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": effects,
                "post_base_removals": [],
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        },
    }
    evidence.verify_post_base_filesystem_policy(safe_files, policy)
    policy["filesystem_baselines"]["linux/amd64"]["post_base_directory_effects"] = []
    with pytest.raises(evidence.EvidenceError, match="directory effects differ"):
        evidence.verify_post_base_filesystem_policy(safe_files, policy)


def test_post_base_semantic_replay_rejects_implicit_parent_directories(
    tmp_path: Path,
) -> None:
    image = tmp_path / "implicit-post-base-parent.tar"
    saved_image_layers(
        image,
        [
            tar_bytes({"lib/apk/db/installed": apk_database()}),
            tar_bytes({"unreviewed-parent/payload": b"content"}),
        ],
    )
    _inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    with pytest.raises(evidence.EvidenceError, match="implicit parent directory"):
        evidence.canonical_post_base_filesystem_changes(files, 1, "linux/amd64")


def test_removal_policy_ignores_whiteout_marker_header_metadata(tmp_path: Path) -> None:
    expected = [
        {
            "kind": "whiteout",
            "path": ".wh.removed",
            "target": "removed",
        }
    ]
    observed_modes: list[int] = []
    for mode in (0, 0o600, 0o644):
        image = tmp_path / f"whiteout-{mode:o}.tar"
        saved_image_layers(
            image,
            [
                tar_bytes(
                    {
                        "lib/apk/db/installed": apk_database(),
                        "removed": b"lower-layer content",
                    }
                ),
                tar_bytes({".wh.removed": b""}, headers={".wh.removed": {"mode": mode}}),
            ],
        )
        _inventory, files = evidence._inventory_saved_image(
            image, "linux/amd64", "sha256:" + "a" * 64
        )
        _effects, removals = evidence.canonical_post_base_filesystem_changes(
            files, 1, "linux/amd64"
        )
        observed_modes.append(files["whiteouts"][0]["mode"])
        assert removals == expected

    assert observed_modes == [0, 0o600, 0o644]
    with pytest.raises(evidence.EvidenceError, match="invalid post-base removal"):
        evidence.validate_removal_policy([{**expected[0], "mode": 0}], "linux/amd64")

    policy: dict[str, Any] = {
        "base_image_platforms": {
            "linux/amd64": {"layer_diff_ids": [files["layers"][0]["digest"]]},
            "linux/arm64": {"layer_diff_ids": ["sha256:" + "b" * 64]},
        },
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": expected,
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        },
    }
    evidence.verify_post_base_filesystem_policy(files, policy)
    for reviewed_removals in (
        [],
        [{"kind": "whiteout", "path": ".wh.other", "target": "other"}],
        [*expected, {"kind": "whiteout", "path": ".wh.other", "target": "other"}],
    ):
        altered = copy.deepcopy(policy)
        altered["filesystem_baselines"]["linux/amd64"]["post_base_removals"] = reviewed_removals
        with pytest.raises(evidence.EvidenceError, match="removals differ"):
            evidence.verify_post_base_filesystem_policy(files, altered)


def test_post_base_provenance_rejects_hostile_tar_security_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    source_path = f"{site}/demo.py"
    license_path = "usr/share/licenses/extra-codeowners/LICENSE"
    license_content = b"reviewed application license\n"
    installed = {
        "demo.py": b"VALUE = 'reviewed'\n",
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    application_files = {
        "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
        license_path: license_content,
        **{f"{site}/{path}": content for path, content in installed.items()},
    }
    base = tar_bytes({"lib/apk/db/installed": apk_database()})

    def collect(
        name: str,
        *,
        headers: dict[str, dict[str, Any]] | None = None,
        directories: list[str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        image = tmp_path / name
        selected_directories = set(explicit_parent_directories((*application_files, *VENV_LINKS)))
        for directory in directories or []:
            selected_directories.add(directory)
            selected_directories.update(explicit_parent_directories([directory]))
        application = tar_bytes(
            application_files,
            links=VENV_LINKS,
            directories=sorted(
                selected_directories,
                key=lambda path: (len(PurePosixPath(path).parts), path),
            ),
            headers=headers,
        )
        saved_image_layers(image, [base, application])
        return cast(
            tuple[dict[str, Any], dict[str, Any]],
            evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64),
        )

    clean_inventory, clean_files = collect("clean-metadata.tar")
    base_digest = clean_files["layers"][0]["digest"]
    clean_directory_effects, _clean_removals = evidence.canonical_post_base_filesystem_changes(
        clean_files, 1, "linux/amd64"
    )
    policy = {
        "base_image_platforms": {
            "linux/amd64": {"layer_diff_ids": [base_digest]},
            "linux/arm64": {"layer_diff_ids": ["sha256:" + "b" * 64]},
        },
        "filesystem_baselines": {
            "linux/amd64": {
                "apk_database_occurrences": clean_inventory["apk_database_occurrences"],
                "post_base_directory_effects": clean_directory_effects,
                "post_base_removals": [],
            },
            "linux/arm64": {
                "apk_database_occurrences": [],
                "post_base_directory_effects": [],
                "post_base_removals": [],
            },
        },
    }
    monkeypatch.setattr(evidence, "run", lambda *_args, **_kwargs: license_content)

    for index, target in enumerate((source_path, license_path)):
        hostile_inventory, hostile_files = collect(
            f"hostile-header-{index}.tar",
            headers={target: {"mode": 0o4777, "uid": 1234, "gid": 5678}},
        )
        with pytest.raises(evidence.EvidenceError, match="must be root-owned"):
            evidence.verify_post_base_provenance(hostile_inventory, hostile_files, policy, tmp_path)

    with pytest.raises(evidence.EvidenceError, match="unsupported PAX fields"):
        collect(
            "hostile-capability.tar",
            headers={source_path: {"pax_headers": {"SCHILY.xattr.security.capability": "hostile"}}},
        )

    directory_inventory, directory_files = collect(
        "hostile-directory.tar",
        directories=["etc/extra-codeowners-hostile"],
        headers={"etc/extra-codeowners-hostile": {"mode": 0o777}},
    )
    with pytest.raises(evidence.EvidenceError, match="root-owned"):
        evidence.verify_post_base_provenance(directory_inventory, directory_files, policy, tmp_path)


def test_deep_inventory_validation_rejects_truncated_or_rebound_records(
    tmp_path: Path,
) -> None:
    image = tmp_path / "image.tar"
    saved_image(image)
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    evidence.validate_all_layer_inventory(files, inventory)

    truncated = copy.deepcopy(files)
    truncated["regular_files"].pop()
    with pytest.raises(evidence.EvidenceError, match="counts do not match"):
        evidence.validate_all_layer_inventory(truncated, inventory)

    rebound = copy.deepcopy(files)
    rebound["image_config_digest"] = "sha256:" + "b" * 64
    with pytest.raises(evidence.EvidenceError, match="disagree about image_config_digest"):
        evidence.validate_all_layer_inventory(rebound, inventory)

    fabricated = copy.deepcopy(files)
    fabricated["regular_files"][0]["layer_digest"] = "sha256:" + "c" * 64
    with pytest.raises(evidence.EvidenceError, match="wrong layer digest"):
        evidence.validate_all_layer_inventory(fabricated, inventory)

    noncanonical = copy.deepcopy(files)
    noncanonical["regular_files"][0]["path"] = "./" + noncanonical["regular_files"][0]["path"]
    with pytest.raises(evidence.EvidenceError, match="canonical archive path"):
        evidence.validate_all_layer_inventory(noncanonical, inventory)


def test_inventory_reports_unexpanded_wheel_sboms_and_native_payloads(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
        "demo-1.0.dist-info/sboms/auditwheel.cdx.json": cyclonedx_sbom(),
        "demo.libs/libdemo.so.1": elf64_payload(),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
        },
        links=VENV_LINKS,
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    assert inventory["source_completeness"]["complete"] is False
    assert [item["path"] for item in inventory["embedded_sboms"]] == [
        f"{site}/demo-1.0.dist-info/sboms/auditwheel.cdx.json"
    ]
    assert [item["path"] for item in inventory["native_payloads"]] == [
        f"{site}/demo.libs/libdemo.so.1"
    ]
    assert inventory["embedded_sboms"][0]["owner"] == "python:demo@1.0"
    assert inventory["embedded_sboms"][0]["cyclonedx"]["components"] == [
        {
            "type": "library",
            "name": "libdemo",
            "version": "1.2.3",
            "purl": "pkg:generic/libdemo@1.2.3",
        }
    ]
    assert inventory["native_payloads"][0]["owner"] == "python:demo@1.0"
    assert inventory["native_payloads"][0]["elf"] == {
        "bits": 64,
        "endianness": "little",
        "machine": "x86_64",
        "machine_id": 62,
    }
    assert {item["path"] for item in inventory["wheel_identity_files"]} == {
        f"{site}/demo-1.0.dist-info/RECORD",
        f"{site}/demo-1.0.dist-info/WHEEL",
    }
    evidence.validate_all_layer_inventory(files, inventory)

    omitted = copy.deepcopy(inventory)
    omitted["embedded_sboms"] = []
    with pytest.raises(evidence.EvidenceError, match="omits or alters embedded wheel SBOMs"):
        evidence.validate_all_layer_inventory(files, omitted)

    payload_policy = {"unexpanded_python_payloads": empty_unexpanded_payload_policy()}
    payload_policy["unexpanded_python_payloads"]["linux/amd64"] = {
        "embedded_sboms": [
            evidence.payload_record_projection(record) for record in inventory["embedded_sboms"]
        ],
        "native_payloads": [
            evidence.payload_record_projection(record) for record in inventory["native_payloads"]
        ],
        "wheel_identity_files": copy.deepcopy(inventory["wheel_identity_files"]),
    }
    evidence.verify_unexpanded_payload_policy(inventory, payload_policy)

    changed_native = copy.deepcopy(inventory)
    changed_native["native_payloads"][0]["sha256"] = "a" * 64
    with pytest.raises(evidence.EvidenceError, match="differ from policy"):
        evidence.verify_unexpanded_payload_policy(changed_native, payload_policy)

    changed_sbom = copy.deepcopy(inventory)
    changed_sbom["embedded_sboms"][0]["sha256"] = "b" * 64
    with pytest.raises(evidence.EvidenceError, match="differ from policy"):
        evidence.verify_unexpanded_payload_policy(changed_sbom, payload_policy)

    changed_wheel = copy.deepcopy(inventory)
    changed_wheel["wheel_identity_files"][0]["sha256"] = "c" * 64
    with pytest.raises(evidence.EvidenceError, match="differ from policy"):
        evidence.verify_unexpanded_payload_policy(changed_wheel, payload_policy)


def test_cyclonedx_projection_deduplicates_exact_components_and_rejects_conflicts() -> None:
    component = {
        "type": "library",
        "name": "libdemo",
        "version": "1.2.3",
        "purl": "pkg:generic/libdemo@1.2.3",
        "bom-ref": "libdemo",
    }
    parsed = evidence.parse_cyclonedx_sbom(
        cyclonedx_sbom(components=[component, copy.deepcopy(component)]), "demo.cdx.json"
    )
    assert parsed["components"] == [
        {
            "type": "library",
            "name": "libdemo",
            "version": "1.2.3",
            "purl": "pkg:generic/libdemo@1.2.3",
        }
    ]

    conflicting_purl = copy.deepcopy(component)
    conflicting_purl["purl"] = "pkg:generic/libdemo@9.9.9"
    with pytest.raises(evidence.EvidenceError, match="conflicting purls"):
        evidence.parse_cyclonedx_sbom(
            cyclonedx_sbom(components=[component, conflicting_purl]), "conflict.cdx.json"
        )

    conflicting_identity = copy.deepcopy(component)
    conflicting_identity["name"] = "other"
    with pytest.raises(evidence.EvidenceError, match="conflicting component identities"):
        evidence.parse_cyclonedx_sbom(
            cyclonedx_sbom(components=[component, conflicting_identity]), "conflict.cdx.json"
        )


def test_inventory_retains_document_scoped_cyclonedx_purl_observations(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    sboms = {
        "cryptography": cyclonedx_sbom(
            components=[
                {
                    "type": "library",
                    "name": "libgcc",
                    "version": "14.2.0-r6",
                    "purl": "pkg:apk/NotpineForGHA/libgcc@14.2.0-r6",
                    "bom-ref": "notpine-libgcc",
                }
            ]
        ),
        "greenlet": cyclonedx_sbom(
            components=[
                {
                    "type": "library",
                    "name": "libgcc",
                    "version": "14.2.0-r6",
                    "purl": "pkg:apk/alpine/libgcc@14.2.0-r6",
                    "bom-ref": "alpine-libgcc",
                }
            ]
        ),
    }
    installed: dict[str, bytes] = {}
    for owner, sbom in sboms.items():
        dist_info = f"{owner}-1.0.dist-info"
        wheel = {
            f"{dist_info}/METADATA": metadata(owner, "1.0"),
            f"{dist_info}/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
            ),
            f"{dist_info}/sboms/auditwheel.cdx.json": sbom,
        }
        record_path = f"{dist_info}/RECORD"
        wheel[record_path] = wheel_record(wheel, record_path)
        installed.update(wheel)

    image = tmp_path / "document-scoped-sboms.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                },
                links=VENV_LINKS,
            )
        ],
    )

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    observations = {
        record["owner"]: (
            record["cyclonedx"]["components"][0]["purl"],
            record["sha256"],
            record["size"],
        )
        for record in inventory["embedded_sboms"]
    }
    assert observations == {
        "python:cryptography@1.0": (
            "pkg:apk/NotpineForGHA/libgcc@14.2.0-r6",
            evidence.sha256_bytes(sboms["cryptography"]),
            len(sboms["cryptography"]),
        ),
        "python:greenlet@1.0": (
            "pkg:apk/alpine/libgcc@14.2.0-r6",
            evidence.sha256_bytes(sboms["greenlet"]),
            len(sboms["greenlet"]),
        ),
    }
    evidence.validate_component_inventory(inventory)
    evidence.validate_all_layer_inventory(files, inventory)

    payload_policy = {"unexpanded_python_payloads": empty_unexpanded_payload_policy()}
    payload_policy["unexpanded_python_payloads"]["linux/amd64"] = {
        "embedded_sboms": [
            evidence.payload_record_projection(record) for record in inventory["embedded_sboms"]
        ],
        "native_payloads": [],
        "wheel_identity_files": copy.deepcopy(inventory["wheel_identity_files"]),
    }
    evidence.verify_unexpanded_payload_policy(inventory, payload_policy)


@pytest.mark.parametrize(
    ("content", "message"),
    (
        (b"{}", "not CycloneDX"),
        (
            b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}',
            "duplicate JSON object key",
        ),
        (
            b'{"bomFormat":"CycloneDX","specVersion":"1.5","version":1.5}',
            "floating-point",
        ),
    ),
)
def test_cyclonedx_parser_rejects_malformed_documents(content: bytes, message: str) -> None:
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.parse_cyclonedx_sbom(content, "malformed.cdx.json")


@pytest.mark.parametrize(
    ("offset", "value", "message"),
    (
        (4, 1, "not ELF64"),
        (5, 2, "not little-endian"),
        (6, 0, "identity version"),
        (52, 0, "malformed ELF header"),
    ),
)
def test_elf_parser_rejects_wrong_class_endianness_and_header(
    offset: int, value: int, message: str
) -> None:
    payload = bytearray(elf64_payload())
    payload[offset] = value
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.parse_elf_identity(bytes(payload), "linux/amd64", "demo/native")


def test_inventory_detects_extensionless_elf_and_binds_payload_owners(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    native = elf64_payload()
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
        "demo-1.0.dist-info/sboms/demo.cdx.json": cyclonedx_sbom(),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(
        {**installed, "../../../bin/extensionless-native": native},
        "demo-1.0.dist-info/RECORD",
    )
    image = tmp_path / "extensionless.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                    "opt/venv/bin/extensionless-native": native,
                },
                links=VENV_LINKS,
            )
        ],
    )

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    assert [record["path"] for record in inventory["native_payloads"]] == [
        "opt/venv/bin/extensionless-native"
    ]
    assert {record["owner"] for record in inventory["embedded_sboms"]} == {"python:demo@1.0"}
    assert {record["owner"] for record in inventory["native_payloads"]} == {"python:demo@1.0"}
    evidence.validate_component_inventory(inventory)
    evidence.validate_all_layer_inventory(files, inventory)


@pytest.mark.parametrize(
    ("payload_path", "payload", "message"),
    (
        ("demo/native.so", b"not ELF", "not ELF"),
        ("demo/native.so", elf64_payload("arm64"), "architecture does not match"),
        ("demo/native.so", b"\x7fELF", "truncated ELF"),
        (
            "demo-1.0.dist-info/sboms/demo.cdx.json",
            b"{}",
            "not CycloneDX",
        ),
    ),
)
def test_inventory_rejects_malformed_structured_wheel_payloads(
    tmp_path: Path, payload_path: str, payload: bytes, message: str
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
        payload_path: payload,
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    image = tmp_path / "malformed.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                },
                links=VENV_LINKS,
            )
        ],
    )
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize(
    ("payload_path", "payload"),
    (
        ("demo/unowned-native", elf64_payload()),
        ("demo-1.0.dist-info/sboms/unowned.cdx.json", cyclonedx_sbom()),
    ),
)
def test_inventory_rejects_unowned_structured_payload_occurrences(
    tmp_path: Path, payload_path: str, payload: bytes
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    image = tmp_path / "unowned.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                    f"{site}/{payload_path}": payload,
                },
                links=VENV_LINKS,
            )
        ],
    )
    with pytest.raises(evidence.EvidenceError, match="not owned by a wheel RECORD"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_structured_payload_validation_rejects_owner_and_identity_tampering(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
        ),
        "demo-1.0.dist-info/sboms/demo.cdx.json": cyclonedx_sbom(),
        "demo/native.so": elf64_payload(),
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{f"{site}/{path}": content for path, content in installed.items()},
                },
                links=VENV_LINKS,
            )
        ],
    )
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    wrong_owner = copy.deepcopy(inventory)
    wrong_owner["embedded_sboms"][0]["owner"] = "python:other@1.0"
    with pytest.raises(evidence.EvidenceError, match="invalid Python RECORD owner"):
        evidence.validate_component_inventory(wrong_owner)

    wrong_component_digest = copy.deepcopy(inventory)
    wrong_component_digest["embedded_sboms"][0]["cyclonedx"]["component_identity_sha256"] = "0" * 64
    with pytest.raises(evidence.EvidenceError, match="component-identity digest"):
        evidence.validate_all_layer_inventory(files, wrong_component_digest)

    wrong_elf = copy.deepcopy(inventory)
    wrong_elf["native_payloads"][0]["elf"] = {
        "bits": 64,
        "endianness": "little",
        "machine": "aarch64",
        "machine_id": 183,
    }
    with pytest.raises(evidence.EvidenceError, match="ELF architecture mismatch"):
        evidence.validate_all_layer_inventory(files, wrong_elf)


def test_effective_record_ownership_is_bound_to_historical_wheel_claims(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"

    def installed(name: str) -> dict[str, bytes]:
        files = {
            f"{name}-1.0.dist-info/METADATA": metadata(name, "1.0"),
            f"{name}-1.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            f"{name}.py": f"NAME = {name!r}\n".encode(),
        }
        record_name = f"{name}-1.0.dist-info/RECORD"
        files[record_name] = wheel_record(files, record_name)
        return files

    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    **{
                        f"{site}/{path}": content
                        for path, content in {**installed("alpha"), **installed("beta")}.items()
                    },
                },
                links=VENV_LINKS,
            )
        ],
    )
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    evidence.validate_component_inventory(inventory)
    evidence.validate_all_layer_inventory(files, inventory)

    relabeled = copy.deepcopy(inventory)
    alpha = next(
        record
        for record in relabeled["python_record_ownership"]
        if record["path"].endswith("/alpha.py")
    )
    alpha["owner"] = "beta"
    for validator in (
        evidence.validate_component_inventory,
        lambda candidate: evidence.validate_all_layer_inventory(files, candidate),
    ):
        with pytest.raises(evidence.EvidenceError, match="effective historical claim"):
            validator(relabeled)

    omitted = copy.deepcopy(inventory)
    omitted["python_record_ownership"] = omitted["python_record_ownership"][1:]
    with pytest.raises(evidence.EvidenceError, match="omits an effective historical claim"):
        evidence.validate_component_inventory(omitted)


def test_wheel_record_binds_effective_files_and_policy_detects_consistent_rewrite(
    tmp_path: Path,
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    metadata_content = metadata("demo", "1.0")
    wheel_content = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"

    def installed(source: bytes) -> dict[str, bytes]:
        result = {
            "demo-1.0.dist-info/METADATA": metadata_content,
            "demo-1.0.dist-info/WHEEL": wheel_content,
            "demo.py": source,
        }
        result["demo-1.0.dist-info/RECORD"] = wheel_record(result, "demo-1.0.dist-info/RECORD")
        return result

    trusted = installed(b"VALUE = 'trusted'\n")
    base_layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in trusted.items()},
        },
        links=VENV_LINKS,
    )
    base_image = tmp_path / "base.tar"
    saved_image_layers(base_image, [base_layer])
    base_inventory, _base_files = evidence._inventory_saved_image(
        base_image, "linux/amd64", "sha256:" + "a" * 64
    )

    changed_source = b"VALUE = 'tampered'\n"
    stale_image = tmp_path / "stale.tar"
    saved_image_layers(stale_image, [base_layer, tar_bytes({f"{site}/demo.py": changed_source})])
    with pytest.raises(evidence.EvidenceError, match="RECORD does not match installed file"):
        evidence._inventory_saved_image(stale_image, "linux/amd64", "sha256:" + "a" * 64)

    changed = installed(changed_source)
    consistent_image = tmp_path / "consistent.tar"
    saved_image_layers(
        consistent_image,
        [
            base_layer,
            tar_bytes(
                {
                    f"{site}/demo.py": changed_source,
                    f"{site}/demo-1.0.dist-info/RECORD": changed["demo-1.0.dist-info/RECORD"],
                }
            ),
        ],
    )
    consistent_inventory, _consistent_files = evidence._inventory_saved_image(
        consistent_image, "linux/amd64", "sha256:" + "a" * 64
    )
    installations = consistent_inventory["wheel_installations"]
    assert [item["owner"] for item in installations] == [
        "python:demo@1.0",
        "python:demo@1.0",
    ]
    assert [item["record"]["effective"] for item in installations] == [False, True]
    first_demo = next(
        item for item in installations[0]["entries"] if item["path"].endswith("demo.py")
    )
    replacement_demo = next(
        item for item in installations[1]["entries"] if item["path"].endswith("demo.py")
    )
    assert first_demo["occurrence"]["layer"] == 0
    assert first_demo["occurrence"]["effective"] is False
    assert replacement_demo["occurrence"]["layer"] == 1
    assert replacement_demo["occurrence"]["effective"] is True
    payload_policy = {"unexpanded_python_payloads": empty_unexpanded_payload_policy()}
    payload_policy["unexpanded_python_payloads"]["linux/amd64"] = {
        "embedded_sboms": [
            evidence.payload_record_projection(record)
            for record in base_inventory["embedded_sboms"]
        ],
        "native_payloads": [
            evidence.payload_record_projection(record)
            for record in base_inventory["native_payloads"]
        ],
        "wheel_identity_files": copy.deepcopy(base_inventory["wheel_identity_files"]),
    }
    with pytest.raises(evidence.EvidenceError, match="differ from policy"):
        evidence.verify_unexpanded_payload_policy(consistent_inventory, payload_policy)


def test_historical_record_replay_survives_complete_whiteout(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
            b"Tag: py3-none-any\nTag: cp314-cp314-musllinux_1_2_x86_64\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    base = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
        },
        links=VENV_LINKS,
    )
    removal = tar_bytes(
        {
            f"{site}/.wh.demo.py": b"",
            f"{site}/demo-1.0.dist-info/.wh.METADATA": b"",
            f"{site}/demo-1.0.dist-info/.wh.WHEEL": b"",
            f"{site}/demo-1.0.dist-info/.wh.RECORD": b"",
        }
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [base, removal])

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    installation = inventory["wheel_installations"][0]
    assert installation["owner"] == "python:demo@1.0"
    assert installation["record"]["effective"] is False
    assert installation["root_is_purelib"] is True
    assert installation["tags"] == [
        "cp314-cp314-musllinux_1_2_x86_64",
        "py3-none-any",
    ]
    assert {entry["path"] for entry in installation["entries"]} == {
        f"{site}/demo.py",
        f"{site}/demo-1.0.dist-info/METADATA",
        f"{site}/demo-1.0.dist-info/WHEEL",
        f"{site}/demo-1.0.dist-info/RECORD",
    }
    assert all(entry["occurrence"]["effective"] is False for entry in installation["entries"])
    assert inventory["python_record_ownership"] == []
    evidence.validate_all_layer_inventory(files, inventory)

    tampered = copy.deepcopy(inventory)
    tampered["wheel_installations"][0]["entries"][0]["occurrence"]["sha256"] = "f" * 64
    with pytest.raises(evidence.EvidenceError, match=r"conflicting identity|all-layer inventory"):
        evidence.validate_all_layer_inventory(files, tampered)

    omitted = copy.deepcopy(inventory)
    omitted["wheel_installations"] = []
    with pytest.raises(evidence.EvidenceError, match="omits a historical Python RECORD"):
        evidence.validate_all_layer_inventory(files, omitted)


def test_record_replay_uses_complete_layer_snapshot_not_tar_order(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    record = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            f"{site}/demo-1.0.dist-info/RECORD": record,
            f"{site}/demo.py": installed["demo.py"],
            f"{site}/demo-1.0.dist-info/WHEEL": installed["demo-1.0.dist-info/WHEEL"],
            f"{site}/demo-1.0.dist-info/METADATA": installed["demo-1.0.dist-info/METADATA"],
        },
        links=VENV_LINKS,
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])

    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)

    assert inventory["wheel_installations"][0]["owner"] == "python:demo@1.0"
    evidence.validate_all_layer_inventory(files, inventory)


def test_replacement_requires_same_layer_record_before_later_whiteout(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    base = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
        },
        links=VENV_LINKS,
    )
    replacement = tar_bytes({f"{site}/demo.py": b"VALUE = 2\n"})
    later_removal = tar_bytes({f"{site}/.wh.demo.py": b""})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [base, replacement, later_removal])

    with pytest.raises(evidence.EvidenceError, match="matching replacement RECORD"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_record_replay_rejects_duplicate_active_owner(tmp_path: Path) -> None:
    sites = [
        "opt/venv/lib/python3.14/site-packages",
        "opt/venv/alternate/site-packages",
    ]
    files: dict[str, bytes] = {
        "lib/apk/db/installed": apk_database(),
        "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
    }
    for index, site in enumerate(sites):
        installed = {
            "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
            "demo-1.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            f"demo_{index}.py": str(index).encode(),
        }
        installed["demo-1.0.dist-info/RECORD"] = wheel_record(
            installed, "demo-1.0.dist-info/RECORD"
        )
        files.update({f"{site}/{path}": content for path, content in installed.items()})
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes(files, links=VENV_LINKS)])

    with pytest.raises(evidence.EvidenceError, match="duplicate Python owner"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_record_replay_rejects_overlapping_distribution_ownership(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    shared = b"VALUE = 1\n"
    files: dict[str, bytes] = {
        "lib/apk/db/installed": apk_database(),
        "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
        f"{site}/shared.py": shared,
    }
    for name in ("demo", "other"):
        installed = {
            f"{name}-1.0.dist-info/METADATA": metadata(name, "1.0"),
            f"{name}-1.0.dist-info/WHEEL": (
                b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            "shared.py": shared,
        }
        record_path = f"{name}-1.0.dist-info/RECORD"
        files.update({f"{site}/{path}": content for path, content in installed.items()})
        files[f"{site}/{record_path}"] = wheel_record(installed, record_path)
    image = tmp_path / "image.tar"
    saved_image_layers(image, [tar_bytes(files, links=VENV_LINKS)])

    with pytest.raises(evidence.EvidenceError, match="claim the same RECORD path"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize(
    ("extra_path", "message"),
    (
        ("demo.pyc", "executable bytecode"),
        ("unowned.pth", "not owned by a wheel RECORD"),
    ),
)
def test_wheel_validation_rejects_unrecorded_executable_surfaces(
    tmp_path: Path, extra_path: str, message: str
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    installed["demo-1.0.dist-info/RECORD"] = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
            f"{site}/{extra_path}": b"unrecorded",
        },
        links=VENV_LINKS,
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_wheel_record_parser_rejects_traversal_and_invalid_hash() -> None:
    site_root = evidence.PurePosixPath("opt/venv/lib/python3.14/site-packages")
    record_path = f"{site_root}/demo-1.0.dist-info/RECORD"
    with pytest.raises(evidence.EvidenceError, match="escapes /opt/venv"):
        evidence.parse_wheel_record(
            b"../../../../escape,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1\n"
            b"demo-1.0.dist-info/RECORD,,\n",
            site_root,
            record_path,
        )
    with pytest.raises(evidence.EvidenceError, match="invalid hash"):
        evidence.parse_wheel_record(
            b"demo.py,sha256=not-a-digest,1\ndemo-1.0.dist-info/RECORD,,\n",
            site_root,
            record_path,
        )
    with pytest.raises(evidence.EvidenceError, match="invalid size"):
        evidence.parse_wheel_record(
            (
                "demo.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,"
                + "9" * 5000
                + "\ndemo-1.0.dist-info/RECORD,,\n"
            ).encode(),
            site_root,
            record_path,
        )


def test_wheel_record_parser_rejects_aliases_malformed_and_oversized_csv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site_root = evidence.PurePosixPath("opt/venv/lib/python3.14/site-packages")
    record_path = f"{site_root}/demo-1.0.dist-info/RECORD"
    digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(evidence.EvidenceError, match="repeats path"):
        evidence.parse_wheel_record(
            (
                f"demo.py,sha256={digest},1\n"
                f"subdir/../demo.py,sha256={digest},1\n"
                "demo-1.0.dist-info/RECORD,,\n"
            ).encode(),
            site_root,
            record_path,
        )
    with pytest.raises(evidence.EvidenceError, match="cannot parse Python RECORD"):
        evidence.parse_wheel_record(
            b'"unterminated,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1\n',
            site_root,
            record_path,
        )
    monkeypatch.setattr(evidence, "MAX_RECORD_BYTES", 16)
    with pytest.raises(evidence.EvidenceError, match="exceeds its size limit"):
        evidence.parse_wheel_record(b"x" * 17, site_root, record_path)


def test_record_replay_rejects_symlink_owned_as_regular_file(tmp_path: Path) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    installed = {
        "demo-1.0.dist-info/METADATA": metadata("demo", "1.0"),
        "demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo.py": b"VALUE = 1\n",
    }
    record = wheel_record(installed, "demo-1.0.dist-info/RECORD")
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
                    f"{site}/demo-1.0.dist-info/METADATA": installed["demo-1.0.dist-info/METADATA"],
                    f"{site}/demo-1.0.dist-info/WHEEL": installed["demo-1.0.dist-info/WHEEL"],
                    f"{site}/demo-1.0.dist-info/RECORD": record,
                },
                links={**VENV_LINKS, f"{site}/demo.py": "elsewhere.py"},
            )
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="target is not a regular file"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize("suffix", ("pyc", "pyo"))
def test_historical_venv_bytecode_is_rejected_before_whiteout(tmp_path: Path, suffix: str) -> None:
    bytecode_path = f"opt/venv/lib/python3.14/site-packages/demo.{suffix}"
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    bytecode_path: b"executable",
                }
            ),
            tar_bytes(
                {
                    f"{PurePosixPath(bytecode_path).parent}/"
                    f".wh.{PurePosixPath(bytecode_path).name}": b""
                }
            ),
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="executable bytecode"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


def test_effective_interpreter_bytecode_is_rejected(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "usr/local/lib/python3.14/__pycache__/site.cpython-314.pyc": b"executable",
                }
            )
        ],
    )

    with pytest.raises(evidence.EvidenceError, match="effective interpreter path"):
        evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)


@pytest.mark.parametrize(
    "content",
    (
        b'{"schema_version":1,"platform":"linux/amd64","components":[null]}',
        b'{"schema_version":' + b"9" * 5000 + b"}",
        b'{"schema_version":1e400}',
    ),
)
def test_verify_cli_rejects_malformed_json_without_traceback(
    tmp_path: Path, content: bytes
) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_bytes(content)
    result = subprocess.run(  # noqa: S603 - fixed interpreter and reviewed script
        [
            sys.executable,
            ".github/scripts/container_evidence.py",
            "verify",
            "--inventory",
            str(inventory),
            "--policy",
            ".compliance/container-policy.json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stderr.startswith("container evidence error:")
    assert "Traceback" not in result.stderr


def test_application_source_binding_is_exact_and_effective(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site = "opt/venv/lib/python3.14/site-packages"
    trusted_source = b"VALUE = 'trusted'\n"
    installed = {
        "extra_codeowners-0.1.0.dist-info/METADATA": metadata("extra-codeowners", "0.1.0"),
        "extra_codeowners-0.1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "extra_codeowners/app.py": trusted_source,
    }
    installed["extra_codeowners-0.1.0.dist-info/RECORD"] = wheel_record(
        installed, "extra_codeowners-0.1.0.dist-info/RECORD"
    )
    layer = tar_bytes(
        {
            "lib/apk/db/installed": apk_database(),
            "opt/venv/pyvenv.cfg": PYVENV_CONFIG,
            **{f"{site}/{path}": content for path, content in installed.items()},
        },
        links=VENV_LINKS,
    )
    image = tmp_path / "image.tar"
    saved_image_layers(image, [layer])
    inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    monkeypatch.setattr(
        evidence, "project_identity_at_head", lambda _repo: ("extra-codeowners", "0.1.0")
    )
    monkeypatch.setattr(
        evidence,
        "application_sources_at_head",
        lambda _repo: {"extra_codeowners/app.py": trusted_source},
    )

    assert evidence.validate_application_source_binding(inventory, files, tmp_path) == (
        "extra-codeowners",
        "0.1.0",
    )
    assert {item["path"] for item in inventory["wheel_identity_files"]} == {
        f"{site}/extra_codeowners-0.1.0.dist-info/RECORD",
        f"{site}/extra_codeowners-0.1.0.dist-info/WHEEL",
    }

    alternate = copy.deepcopy(inventory)
    application = next(
        item for item in alternate["components"] if item["name"] == "extra-codeowners"
    )
    application["version"] = "0.2.0"
    with pytest.raises(evidence.EvidenceError, match="does not match pyproject"):
        evidence.validate_application_source_binding(alternate, files, tmp_path)

    duplicate = copy.deepcopy(files)
    duplicate["regular_files"].append(
        copy.deepcopy(
            next(
                record
                for record in duplicate["regular_files"]
                if record["path"].endswith(".dist-info/METADATA")
            )
        )
    )
    with pytest.raises(evidence.EvidenceError, match="exactly one effective"):
        evidence.validate_application_source_binding(inventory, duplicate, tmp_path)

    tampered = copy.deepcopy(files)
    app_record = next(
        record for record in tampered["regular_files"] if record["path"].endswith("/app.py")
    )
    app_record["sha256"] = "f" * 64
    with pytest.raises(evidence.EvidenceError, match="differs from Git HEAD"):
        evidence.validate_application_source_binding(inventory, tampered, tmp_path)

    consistently_tampered = copy.deepcopy(tampered)
    record_file = next(
        record
        for record in consistently_tampered["regular_files"]
        if record["path"].endswith(".dist-info/RECORD")
    )
    record_file["sha256"] = "e" * 64
    with pytest.raises(evidence.EvidenceError, match="differs from Git HEAD"):
        evidence.validate_application_source_binding(inventory, consistently_tampered, tmp_path)

    absent = copy.deepcopy(inventory)
    absent["components"] = [
        item for item in absent["components"] if item["name"] != "extra-codeowners"
    ]
    with pytest.raises(evidence.EvidenceError, match="exactly one application"):
        evidence.validate_application_source_binding(absent, files, tmp_path)


def initialize_git_fixture(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    git = evidence.executable("git")
    evidence.run([git, "init", "--quiet", str(repo)], max_output_bytes=1024 * 1024)
    evidence.run(
        [git, "-C", str(repo), "config", "user.email", "test@example.com"],
        max_output_bytes=1024 * 1024,
    )
    evidence.run(
        [git, "-C", str(repo), "config", "user.name", "Test"],
        max_output_bytes=1024 * 1024,
    )
    evidence.run(
        [git, "-C", str(repo), "config", "commit.gpgSign", "false"],
        max_output_bytes=1024 * 1024,
    )
    evidence.run(
        [git, "-C", str(repo), "config", "core.hooksPath", "/dev/null"],
        max_output_bytes=1024 * 1024,
    )
    return repo, git


def commit_git_fixture(repo: Path, git: str) -> None:
    evidence.run([git, "-C", str(repo), "add", "."], max_output_bytes=1024 * 1024)
    evidence.run(
        [git, "-C", str(repo), "commit", "--quiet", "-m", "fixture"],
        max_output_bytes=1024 * 1024,
    )


def test_project_identity_is_read_from_git_head(tmp_path: Path) -> None:
    repo, git = initialize_git_fixture(tmp_path)
    pyproject = repo / "pyproject.toml"
    pyproject.write_text('[project]\nname = "extra-codeowners"\nversion = "0.1.0"\n')
    commit_git_fixture(repo, git)
    pyproject.write_text('[project]\nname = "tampered"\nversion = "9.9.9"\n')

    assert evidence.project_identity_at_head(repo) == ("extra-codeowners", "0.1.0")


def test_project_identity_rejects_oversized_version_without_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    oversized = "1." + "0" * evidence.MAX_COMPONENT_FIELD_LENGTH
    monkeypatch.setattr(
        evidence,
        "run",
        lambda *_args, **_kwargs: (
            f'[project]\nname = "extra-codeowners"\nversion = "{oversized}"\n'.encode()
        ),
    )
    with pytest.raises(evidence.EvidenceError, match="invalid length"):
        evidence.project_identity_at_head(tmp_path)


def test_portable_git_tree_reader_works_in_a_fixture_repository(tmp_path: Path) -> None:
    repo, git = initialize_git_fixture(tmp_path)
    package = repo / "extra_codeowners"
    package.mkdir()
    (package / "app.py").write_text("APP = True\n")
    executable = package / "entrypoint"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    (repo / "outside.txt").write_text("not part of the requested tree\n")
    commit_git_fixture(repo, git)

    assert evidence.git_regular_tree_at_head(repo, "extra_codeowners") == [
        ("100644", "extra_codeowners/app.py"),
        ("100755", "extra_codeowners/entrypoint"),
    ]


def test_application_archive_ignores_export_transforms(tmp_path: Path) -> None:
    repo, git = initialize_git_fixture(tmp_path)
    (repo / "extra_codeowners").mkdir()
    (repo / "extra_codeowners" / "app.py").write_text("REV = '$Format:%H$'\n")
    (repo / "LICENSE").write_text("license\n")
    (repo / ".gitattributes").write_text(
        "extra_codeowners/app.py export-subst\nLICENSE export-ignore\n"
    )
    commit_git_fixture(repo, git)

    archive_bytes = evidence.deterministic_source_archive(repo)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        names = {member.name for member in archive}
        source = archive.extractfile("extra_codeowners/app.py")
        assert source is not None
        assert source.read() == b"REV = '$Format:%H$'\n"
    assert "LICENSE" in names


def test_runtime_identity_expectations_match_dockerfile_and_mise() -> None:
    dockerfile = Path("Dockerfile").read_text()
    mise = evidence.tomllib.loads(Path("mise.toml").read_text())
    builder_stage = dockerfile.split(" AS builder\n", 1)[1].split("\nFROM builder AS test", 1)[0]
    test_stage = dockerfile.split("FROM builder AS test\n", 1)[1].split("\nFROM python:", 1)[0]
    assert mise["tools"]["uv"] == evidence.EXPECTED_UV_VERSION
    assert f"ghcr.io/astral-sh/uv:{evidence.EXPECTED_UV_VERSION}@sha256:" in dockerfile
    assert (
        dockerfile.count(f"FROM python:{evidence.EXPECTED_RUNTIME_PYTHON}-alpine3.24@sha256:") == 2
    )
    assert "ENV UV_COMPILE_BYTECODE=0" in dockerfile
    assert (
        "test -z \"$(find /opt/venv \\( -name '*.pyc' -o -name '*.pyo' \\) -print -quit)\""
    ) in builder_stage
    assert dockerfile.count("UV_NO_INSTALLER_METADATA=1") == 1
    assert builder_stage.index("UV_NO_INSTALLER_METADATA=1") < builder_stage.index("uv sync")
    assert "RUN apk add --no-cache git=2.54.0-r0" in test_stage


def test_container_job_uses_the_locked_evidence_environment() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text()
    container_job = workflow.split("  container:\n", 1)[1]
    evidence_step = container_job.split(
        "      - name: Collect and verify container distribution evidence\n", 1
    )[1].split("      - name: Upload container distribution evidence\n", 1)[0]
    assert "astral-sh/setup-uv@" in container_job
    assert "uv sync --all-groups --frozen" in container_job
    assert container_job.count("uv run --frozen python .github/scripts/container_evidence.py") == 4
    assert evidence_step.index(" inventory \\") < evidence_step.index(" run-metadata \\")
    assert evidence_step.index(" run-metadata \\") < evidence_step.index(" verify \\")
    assert evidence_step.index(" verify \\") < evidence_step.index(" bundle \\")
    assert "packages: write" not in workflow
    assert "publish-container:" not in workflow


def test_container_build_toolchain_is_exactly_pinned_and_renovate_managed() -> None:
    ci = Path(".github/workflows/ci.yml").read_text()
    release = Path(".github/workflows/release.yml").read_text()
    qemu = (
        "tonistiigi/binfmt:qemu-v10.2.3@sha256:"
        "400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
    )
    buildkit = (
        "image=moby/buildkit:v0.30.0@sha256:"
        "0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
    )
    qemu_action = "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8"
    buildx_action = "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c"
    for workflow, expected_count in ((ci, 1), (release, 2)):
        assert workflow.count(qemu_action) == expected_count
        assert workflow.count(buildx_action) == expected_count
        assert workflow.count(qemu) == expected_count
        assert workflow.count("cache-binary: false") == expected_count
        assert workflow.count("version: v0.35.0") == expected_count
        assert workflow.count(buildkit) == expected_count

    renovate = json.loads(Path("renovate.json").read_text())
    managers = {manager["description"]: manager for manager in renovate["customManagers"]}
    workflow_pattern = [r"/^\.github/workflows/(?:ci|release)\.yml$/"]

    utility = managers["Update digest-pinned kubeconform and BuildKit utility containers"]
    assert utility["managerFilePatterns"] == workflow_pattern
    assert utility["datasourceTemplate"] == "docker"
    assert utility["versioningTemplate"] == "docker"
    assert utility["matchStrings"] == [
        r"(?<depName>ghcr.io/yannh/kubeconform):(?<currentValue>[^@\s]+)"
        + r"@(?<currentDigest>sha256:[a-f0-9]{64})",
        r"(?<depName>moby/buildkit):(?<currentValue>[^@\s]+)"
        + r"@(?<currentDigest>sha256:[a-f0-9]{64})",
    ]

    qemu_manager = managers["Update digest-pinned QEMU binfmt images"]
    assert qemu_manager["managerFilePatterns"] == workflow_pattern
    assert qemu_manager["matchStrings"] == [
        r"(?<depName>tonistiigi/binfmt):"
        r"(?<currentValue>qemu-v[0-9]+\.[0-9]+\.[0-9]+)"
        r"@(?<currentDigest>sha256:[a-f0-9]{64})"
    ]
    assert qemu_manager["datasourceTemplate"] == "docker"
    assert qemu_manager["versioningTemplate"] == (
        r"regex:^qemu-v(?<major>[0-9]+)\.(?<minor>[0-9]+)\.(?<patch>[0-9]+)$"
    )

    buildx_manager = managers["Update the pinned Docker Buildx client"]
    assert buildx_manager["managerFilePatterns"] == workflow_pattern
    assert buildx_manager["depNameTemplate"] == "docker/buildx"
    assert buildx_manager["datasourceTemplate"] == "github-releases"
    assert buildx_manager["extractVersionTemplate"] == (r"^v(?<version>[0-9]+\.[0-9]+\.[0-9]+)$")
    assert buildx_manager["versioningTemplate"] == "semver"

    shellcheck_manager = managers[
        "Open reviewed ShellCheck release updates; CI requires a matching asset digest"
    ]
    assert shellcheck_manager["managerFilePatterns"] == [r"/^\.github/workflows/ci\.yml$/"]
    assert shellcheck_manager["matchStrings"] == [
        r"SHELLCHECK_VERSION: v(?<currentValue>\d+\.\d+\.\d+)"
    ]
    assert shellcheck_manager["depNameTemplate"] == "koalaman/shellcheck"
    assert shellcheck_manager["datasourceTemplate"] == "github-releases"
    assert shellcheck_manager["versioningTemplate"] == "semver"
    assert "SHELLCHECK_VERSION: v0.11.0" in ci
    assert (
        "SHELLCHECK_SHA256: 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198" in ci
    )
    assert "koalaman/shellcheck:" not in ci


def test_run_metadata_binds_event_checkout_and_inventory(tmp_path: Path) -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_bytes(evidence.canonical_json(standalone_inventory(component)))
    output = tmp_path / "run-metadata.json"
    arguments = SimpleNamespace(
        inventory=str(inventory_path),
        output=str(output),
        run_id="1234",
        run_attempt=2,
        event_name="pull_request",
        repository_id="5678",
        pr_number="27",
        pr_head_sha="a" * 40,
        pr_base_sha="b" * 40,
        pr_head_repository_id="5678",
        github_sha="c" * 40,
        checkout_sha="c" * 40,
        workflow_ref="stampbot/extra-codeowners/.github/workflows/ci.yml@refs/pull/27/merge",
        workflow_sha="d" * 40,
        platform="linux/amd64",
        architecture="amd64",
        python_distribution_artifact_id="9012",
        python_distribution_artifact_digest="d" * 64,
        application_source_revision="c" * 40,
        application_wheel_sha256="e" * 64,
        application_selection_record_sha256="f" * 64,
    )
    evidence.command_run_metadata(arguments)
    metadata_record = json.loads(output.read_text())
    assert metadata_record["checkout_sha"] == "c" * 40
    assert metadata_record["pr_head_sha"] == "a" * 40
    assert metadata_record["inventory_subject_digest"] == "sha256:" + "a" * 64
    assert metadata_record["python_distribution_artifact_id"] == "9012"
    assert metadata_record["python_distribution_artifact_digest"] == "d" * 64
    assert metadata_record["application_selection_record_sha256"] == "f" * 64

    arguments.github_sha = "e" * 40
    with pytest.raises(evidence.EvidenceError, match="does not match"):
        evidence.command_run_metadata(arguments)

    arguments.github_sha = "c" * 40
    for field in ("run_id", "repository_id", "pr_head_repository_id"):
        original = getattr(arguments, field)
        setattr(arguments, field, "0")
        with pytest.raises(evidence.EvidenceError, match=field):
            evidence.command_run_metadata(arguments)
        setattr(arguments, field, original)

    arguments.pr_number = "0"
    with pytest.raises(evidence.EvidenceError, match="event and pull-request"):
        evidence.command_run_metadata(arguments)
    arguments.event_name = "push"
    evidence.command_run_metadata(arguments)
    arguments.pr_number = "27"
    with pytest.raises(evidence.EvidenceError, match="event and pull-request"):
        evidence.command_run_metadata(arguments)

    arguments.event_name = "pull_request"
    for field in (
        "python_distribution_artifact_digest",
        "application_wheel_sha256",
        "application_selection_record_sha256",
    ):
        original = getattr(arguments, field)
        setattr(arguments, field, "0")
        with pytest.raises(evidence.EvidenceError, match=field):
            evidence.command_run_metadata(arguments)
        setattr(arguments, field, original)

    arguments.python_distribution_artifact_id = "0"
    with pytest.raises(evidence.EvidenceError, match="python_distribution_artifact_id"):
        evidence.command_run_metadata(arguments)
    arguments.python_distribution_artifact_id = "9012"

    arguments.application_source_revision = "a" * 40
    with pytest.raises(evidence.EvidenceError, match="application source revision"):
        evidence.command_run_metadata(arguments)


def test_ci_artifact_extractor_validates_and_atomically_unpacks(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    output = tmp_path / "review-input"
    evidence.extract_ci_artifact(archive, "amd64", output)
    assert sorted(path.name for path in output.iterdir()) == sorted(
        evidence.ci_artifact_entry_limits("amd64")
    )
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())

    with pytest.raises(evidence.EvidenceError, match="already exists"):
        evidence.extract_ci_artifact(archive, "amd64", output)


def test_ci_artifact_extractor_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "artifact.fifo"
    os.mkfifo(fifo)
    command = [
        sys.executable,
        ".github/scripts/container_evidence.py",
        "extract-ci-artifact",
        "--archive",
        str(fifo),
        "--architecture",
        "amd64",
        "--output",
        str(tmp_path / "output"),
    ]
    # Starting a second emulated Python process can exceed two seconds in the
    # arm64 CI job. Ten seconds remains a strict upper bound for the FIFO-open
    # regression this test protects against.
    completed = subprocess.run(  # noqa: S603 - sys.executable is the trusted interpreter.
        command, capture_output=True, check=False, timeout=10
    )
    assert completed.returncode == 1
    assert b"input must be a regular file" in completed.stderr


def test_ci_artifact_extractor_rejects_symlinked_boundaries(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    archive_link = tmp_path / "artifact-link.zip"
    archive_link.symlink_to(archive)
    with pytest.raises(evidence.EvidenceError, match="safely extract"):
        evidence.extract_ci_artifact(archive_link, "amd64", tmp_path / "input-link-output")

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(evidence.EvidenceError, match="output parent"):
        evidence.extract_ci_artifact(archive, "amd64", parent_link / "output")

    output_link = tmp_path / "output-link"
    output_link.symlink_to(tmp_path / "absent")
    with pytest.raises(evidence.EvidenceError, match="already exists"):
        evidence.extract_ci_artifact(archive, "amd64", output_link)


def test_ci_artifact_pair_requires_one_shared_workflow_context(tmp_path: Path) -> None:
    roots: dict[str, Path] = {}
    for architecture in ("amd64", "arm64"):
        archive = tmp_path / f"{architecture}.zip"
        write_ci_artifact_zip(archive, ci_artifact_files(tmp_path, architecture))
        roots[architecture] = tmp_path / architecture
        evidence.extract_ci_artifact(archive, architecture, roots[architecture])
    evidence.validate_ci_artifact_pair(roots["amd64"], roots["arm64"])

    metadata_path = roots["arm64"] / "run-metadata-arm64.json"
    metadata_record = json.loads(metadata_path.read_text())
    metadata_record["run_attempt"] = 3
    metadata_path.write_bytes(evidence.canonical_json(metadata_record))
    with pytest.raises(evidence.EvidenceError, match="one exact workflow context"):
        evidence.validate_ci_artifact_pair(roots["amd64"], roots["arm64"])


@pytest.mark.parametrize(
    "field",
    [
        "python_distribution_artifact_id",
        "python_distribution_artifact_digest",
        "application_wheel_sha256",
        "application_selection_record_sha256",
        "application_source_revision",
    ],
)
def test_ci_artifact_pair_rejects_cross_platform_application_proof_mismatch(
    field: str, tmp_path: Path
) -> None:
    roots: dict[str, Path] = {}
    for architecture in ("amd64", "arm64"):
        archive = tmp_path / f"{architecture}.zip"
        write_ci_artifact_zip(archive, ci_artifact_files(tmp_path, architecture))
        roots[architecture] = tmp_path / architecture
        evidence.extract_ci_artifact(archive, architecture, roots[architecture])

    metadata_path = roots["arm64"] / "run-metadata-arm64.json"
    inventory_path = roots["arm64"] / "components-arm64.json"
    metadata = json.loads(metadata_path.read_text())
    inventory = json.loads(inventory_path.read_text())
    if field == "python_distribution_artifact_id":
        metadata[field] = "9013"
    elif field == "python_distribution_artifact_digest":
        metadata[field] = "0" * 64
    elif field in {
        "application_wheel_sha256",
        "application_selection_record_sha256",
    }:
        metadata[field] = "0" * 64
        inventory[field] = "0" * 64
    else:
        metadata["application_source_revision"] = "0" * 40
        metadata["github_sha"] = "0" * 40
        metadata["checkout_sha"] = "0" * 40
        inventory["image_revision"] = "0" * 40
    metadata_path.write_bytes(evidence.canonical_json(metadata))
    inventory_path.write_bytes(evidence.canonical_json(inventory))

    with pytest.raises(evidence.EvidenceError, match="one exact workflow context"):
        evidence.validate_ci_artifact_pair(roots["amd64"], roots["arm64"])


def test_ci_artifact_pair_rejects_shared_platform_digests(tmp_path: Path) -> None:
    roots: dict[str, Path] = {}
    for architecture in ("amd64", "arm64"):
        archive = tmp_path / f"{architecture}.zip"
        write_ci_artifact_zip(archive, ci_artifact_files(tmp_path, architecture))
        roots[architecture] = tmp_path / architecture
        evidence.extract_ci_artifact(archive, architecture, roots[architecture])

    amd64_inventory = json.loads((roots["amd64"] / "components-amd64.json").read_text())
    shared_digests = {
        field: amd64_inventory[field] for field in ("subject_digest", "image_config_digest")
    }
    for filename in ("components-arm64.json", "all-layer-files-arm64.json"):
        path = roots["arm64"] / filename
        record = json.loads(path.read_text())
        record.update(shared_digests)
        path.write_bytes(evidence.canonical_json(record))
    metadata_path = roots["arm64"] / "run-metadata-arm64.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["inventory_subject_digest"] = shared_digests["subject_digest"]
    metadata["inventory_image_config_digest"] = shared_digests["image_config_digest"]
    metadata_path.write_bytes(evidence.canonical_json(metadata))
    predicate_path = roots["arm64"] / "evidence-predicate-arm64.json"
    predicate = json.loads(predicate_path.read_text())
    predicate["subject_digest"] = shared_digests["subject_digest"]
    predicate_path.write_bytes(evidence.canonical_json(predicate))

    with pytest.raises(evidence.EvidenceError, match="unexpectedly share"):
        evidence.validate_ci_artifact_pair(roots["amd64"], roots["arm64"])


@pytest.mark.parametrize(
    "hostile_name",
    ("../components-amd64.json", "dir/components-amd64.json", "bad\\name", "bad\nname"),
)
def test_ci_artifact_extractor_rejects_unsafe_or_unexpected_names(
    hostile_name: str, tmp_path: Path
) -> None:
    files = ci_artifact_files(tmp_path)
    files[hostile_name] = files.pop("components-amd64.json")
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, files)
    with pytest.raises(evidence.EvidenceError, match="exact expected files"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_ci_artifact_extractor_rejects_links_and_resource_bombs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = ci_artifact_files(tmp_path)
    archive = tmp_path / "symlink.zip"
    write_ci_artifact_zip(archive, files)
    content = bytearray(archive.read_bytes())
    _local, central = zip_record_offsets(content, "components-amd64.json")
    content[central + 38 : central + 42] = ((stat.S_IFLNK | 0o777) << 16).to_bytes(4, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match="entry metadata"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "link-output")

    ratio_archive = tmp_path / "ratio.zip"
    ratio_files = copy.deepcopy(files)
    ratio_files["components-amd64.json"] = b"0" * 10_000
    write_ci_artifact_zip(ratio_archive, ratio_files)
    monkeypatch.setattr(evidence, "MAX_CI_ARTIFACT_COMPRESSION_RATIO", 2)
    with pytest.raises(evidence.EvidenceError, match="resource limits"):
        evidence.extract_ci_artifact(ratio_archive, "amd64", tmp_path / "ratio-output")


def test_ci_artifact_extractor_enforces_central_directory_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    monkeypatch.setattr(evidence, "MAX_CI_ARTIFACT_CENTRAL_DIRECTORY_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="central-directory boundary"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_ci_artifact_extractor_enforces_per_entry_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    monkeypatch.setattr(evidence, "MAX_JSON_BYTES", 1)
    with pytest.raises(evidence.EvidenceError, match="entry exceeds its resource limits"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_ci_artifact_extractor_rejects_duplicate_names(tmp_path: Path) -> None:
    files = ci_artifact_files(tmp_path)
    files.pop("evidence-predicate-amd64.json")
    archive = tmp_path / "duplicate.zip"
    entries = [*files.items(), ("components-amd64.json", files["components-amd64.json"])]
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive.write_bytes(ci_artifact_zip_bytes(entries))
    with pytest.raises(evidence.EvidenceError, match="exact expected files"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize(
    "mutation",
    ["stored", "seekable", "extra", "entry-comment", "archive-comment", "windows"],
)
def test_ci_artifact_extractor_rejects_non_provider_envelopes(
    mutation: str, tmp_path: Path
) -> None:
    files = ci_artifact_files(tmp_path)
    archive = tmp_path / "artifact.zip"
    if mutation == "seekable":
        with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as output:
            for name, content in files.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.create_version = 45
                info.extract_version = 20
                info.external_attr = evidence.CI_ARTIFACT_EXTERNAL_ATTR
                info.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(info, content)
    else:

        def modifier(name: str, info: zipfile.ZipInfo) -> None:
            if name != "components-amd64.json":
                return
            if mutation == "stored":
                info.compress_type = zipfile.ZIP_STORED
            elif mutation == "extra":
                info.extra = b"\xfe\xca\x00\x00"
            elif mutation == "entry-comment":
                info.comment = b"unexpected"
            elif mutation == "windows":
                info.create_system = 0

        archive.write_bytes(
            ci_artifact_zip_bytes(
                list(files.items()),
                modifier=modifier,
                archive_comment=b"unexpected" if mutation == "archive-comment" else b"",
            )
        )
    with pytest.raises(
        evidence.EvidenceError,
        match=r"metadata|flags|compression|central directory|end-of-central-directory",
    ):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize("mutation", ["descriptor", "timestamp", "local-crc"])
def test_ci_artifact_extractor_rejects_local_descriptor_disagreement(
    mutation: str, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    name = "components-amd64.json"
    local, _central = zip_record_offsets(content, name)
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as source:
        entry = source.getinfo(name)
    header = evidence.ZIP_LOCAL_HEADER.unpack_from(content, local)
    data_offset = local + evidence.ZIP_LOCAL_HEADER.size + header[-2] + header[-1]
    descriptor_offset = data_offset + entry.compress_size
    if mutation == "descriptor":
        content[descriptor_offset] ^= 0xFF
    elif mutation == "timestamp":
        content[local + 10 : local + 14] = b"\x00\x00\x00\x00"
    else:
        content[local + 14 : local + 18] = (1).to_bytes(4, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match=r"descriptor|timestamp|local record"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize("mutation", ["prefix", "gap"])
def test_ci_artifact_extractor_rejects_prefixes_and_gaps(mutation: str, tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    eocd = content.rfind(b"PK\x05\x06")
    assert eocd >= 0
    central = int(evidence.ZIP_EOCD.unpack_from(content, eocd)[-2])
    if mutation == "prefix":
        content = bytearray(b"X") + content
        eocd += 1
        central += 1
        content[eocd + 16 : eocd + 20] = central.to_bytes(4, "little")
        position = central
        while position < eocd:
            assert content[position : position + 4] == b"PK\x01\x02"
            local_offset = int.from_bytes(content[position + 42 : position + 46], "little") + 1
            content[position + 42 : position + 46] = local_offset.to_bytes(4, "little")
            name_size = int.from_bytes(content[position + 28 : position + 30], "little")
            position += 46 + name_size
    else:
        content[central:central] = b"X"
        eocd += 1
        central += 1
        content[eocd + 16 : eocd + 20] = central.to_bytes(4, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match=r"prefix|gap|central-directory boundary"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_ci_artifact_extractor_rejects_reordered_central_records(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    eocd = content.rfind(b"PK\x05\x06")
    assert eocd >= 0
    central = int(evidence.ZIP_EOCD.unpack_from(content, eocd)[-2])
    records: list[bytes] = []
    position = central
    while position < eocd:
        assert content[position : position + 4] == b"PK\x01\x02"
        name_size = int.from_bytes(content[position + 28 : position + 30], "little")
        extra_size = int.from_bytes(content[position + 30 : position + 32], "little")
        comment_size = int.from_bytes(content[position + 32 : position + 34], "little")
        end = position + 46 + name_size + extra_size + comment_size
        records.append(bytes(content[position:end]))
        position = end
    assert len(records) == len(evidence.ci_artifact_entry_limits("amd64"))
    content[central:eocd] = b"".join(reversed(records))
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match="local-record order"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize("mutation", ["encrypted", "utf8", "method", "overlap"])
def test_ci_artifact_extractor_rejects_hostile_local_and_central_records(
    mutation: str, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    first_name = "components-amd64.json"
    local, central = zip_record_offsets(content, first_name)
    if mutation == "encrypted":
        local_flags = int.from_bytes(content[local + 6 : local + 8], "little") | 1
        central_flags = int.from_bytes(content[central + 8 : central + 10], "little") | 1
        content[local + 6 : local + 8] = local_flags.to_bytes(2, "little")
        content[central + 8 : central + 10] = central_flags.to_bytes(2, "little")
    elif mutation == "utf8":
        content[local + 6 : local + 8] = (0x808).to_bytes(2, "little")
        content[central + 8 : central + 10] = (0x808).to_bytes(2, "little")
    elif mutation == "method":
        content[local + 8 : local + 10] = (99).to_bytes(2, "little")
        content[central + 10 : central + 12] = (99).to_bytes(2, "little")
    else:
        _second_local, second_central = zip_record_offsets(content, "run-metadata-amd64.json")
        content[second_central + 42 : second_central + 46] = local.to_bytes(4, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match=r"flags|compression|disagrees|overlap"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


@pytest.mark.parametrize("sentinel", [7, 0xFFFF])
def test_ci_artifact_extractor_rejects_entry_count_and_zip64_sentinels(
    sentinel: int, tmp_path: Path
) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    offset = content.rfind(b"PK\x05\x06")
    assert offset >= 0
    content[offset + 8 : offset + 10] = sentinel.to_bytes(2, "little")
    content[offset + 10 : offset + 12] = sentinel.to_bytes(2, "little")
    archive.write_bytes(content)
    with pytest.raises(evidence.EvidenceError, match=r"entry count|ZIP64"):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_ci_artifact_extractor_rejects_corrupt_payload_and_cleans_output(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, ci_artifact_files(tmp_path))
    content = bytearray(archive.read_bytes())
    with zipfile.ZipFile(io.BytesIO(content), mode="r") as source:
        entry = source.getinfo("extra-codeowners-ci-linux-amd64-evidence.tar.gz")
        header = evidence.ZIP_LOCAL_HEADER.unpack_from(content, entry.header_offset)
        payload_offset = (
            entry.header_offset + evidence.ZIP_LOCAL_HEADER.size + header[-2] + header[-1]
        )
    content[payload_offset] ^= 0xFF
    archive.write_bytes(content)
    output = tmp_path / "output"
    with pytest.raises(evidence.EvidenceError, match=r"safely extract|CRC|decompress"):
        evidence.extract_ci_artifact(archive, "amd64", output)
    assert not output.exists()
    assert not list(tmp_path.glob(".output.*"))


@pytest.mark.parametrize("mutation", ["metadata", "predicate", "sidecar"])
def test_ci_artifact_extractor_rejects_content_tampering(mutation: str, tmp_path: Path) -> None:
    files = ci_artifact_files(tmp_path)
    if mutation == "metadata":
        metadata = json.loads(files["run-metadata-amd64.json"])
        metadata["untrusted"] = True
        files["run-metadata-amd64.json"] = evidence.canonical_json(metadata)
        message = "run metadata has an unexpected schema shape"
    elif mutation == "predicate":
        predicate = json.loads(files["evidence-predicate-amd64.json"])
        predicate["subject_digest"] = "sha256:" + "0" * 64
        files["evidence-predicate-amd64.json"] = evidence.canonical_json(predicate)
        message = "predicate does not match"
    else:
        name = "extra-codeowners-ci-linux-amd64-evidence.tar.gz.sha256"
        files[name] = b"0" * 64 + b"  extra-codeowners-ci-linux-amd64-evidence.tar.gz\n"
        message = "checksum sidecar does not match"
    archive = tmp_path / "artifact.zip"
    write_ci_artifact_zip(archive, files)
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.extract_ci_artifact(archive, "amd64", tmp_path / "output")


def test_source_policy_has_exact_nonduplicated_coverage() -> None:
    policy = json.loads(Path(".compliance/container-policy.json").read_text())
    inventory = {"components": policy["platforms"]["linux/amd64"]}
    lock_sources = evidence.parse_lock_sources(Path("uv.lock"))
    evidence.validate_source_policy_coverage(inventory, policy, lock_sources)

    duplicate_python = copy.deepcopy(policy)
    duplicate_python["python_sources"].append(copy.deepcopy(duplicate_python["python_sources"][0]))
    with pytest.raises(evidence.EvidenceError, match="repeats Python source"):
        evidence.validate_source_policy_coverage(inventory, duplicate_python, lock_sources)

    extra_recipe = copy.deepcopy(policy)
    extra_recipe["alpine_recipe_archives"]["unused@" + "a" * 40] = "b" * 64
    with pytest.raises(evidence.EvidenceError, match="does not exactly cover"):
        evidence.validate_source_policy_coverage(inventory, extra_recipe, lock_sources)

    stale_exception = copy.deepcopy(policy)
    stale_exception["alpine_recipe_exceptions"]["unused@" + "a" * 40] = {
        "allow_dynamic_sources": True,
        "rationale": "Unused test record.",
    }
    with pytest.raises(evidence.EvidenceError, match="unused origin"):
        evidence.validate_source_policy_coverage(inventory, stale_exception, lock_sources)

    duplicate_license = copy.deepcopy(policy)
    duplicate_license["license_texts"].append(copy.deepcopy(duplicate_license["license_texts"][0]))
    with pytest.raises(evidence.EvidenceError, match="repeats standard license"):
        evidence.validate_source_policy_coverage(inventory, duplicate_license, lock_sources)


def test_policy_schema_rejects_unknown_fields_at_every_boundary() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    evidence.validate_policy_schema(policy)
    assert "paid_hosting_legal_review" not in policy
    for platform_policy in policy["base_image_platforms"].values():
        assert set(platform_policy) == {"layer_diff_ids"}

    unknown_top_level = copy.deepcopy(policy)
    unknown_top_level["unknown"] = True
    with pytest.raises(evidence.EvidenceError, match="policy has an unexpected schema shape"):
        evidence.validate_policy_schema(unknown_top_level)

    unknown_base_field = copy.deepcopy(policy)
    unknown_base_field["base_image_platforms"]["linux/amd64"]["config_digest"] = (
        "sha256:" + "a" * 64
    )
    with pytest.raises(evidence.EvidenceError, match="base-image platform policy"):
        evidence.validate_policy_schema(unknown_base_field)

    unknown_resolution_field = copy.deepcopy(policy)
    resolution = next(iter(unknown_resolution_field["license_resolutions"].values()))
    resolution["reviewer"] = "untrusted"
    with pytest.raises(evidence.EvidenceError, match="license resolution"):
        evidence.validate_policy_schema(unknown_resolution_field)


def test_policy_schema_rejects_malformed_nested_strings_and_recipe_links() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))

    malformed_link = copy.deepcopy(policy)
    exception = next(iter(malformed_link["alpine_recipe_exceptions"].values()))
    exception["allowed_links"] = [{"path": None, "target": 1, "type": []}]
    with pytest.raises(evidence.EvidenceError, match="allowed recipe link"):
        evidence.validate_policy_schema(malformed_link)

    malformed_rationale = copy.deepcopy(policy)
    exception = next(iter(malformed_rationale["alpine_recipe_exceptions"].values()))
    exception["rationale"] = "\ud800"
    with pytest.raises(evidence.EvidenceError, match="valid UTF-8"):
        evidence.validate_policy_schema(malformed_rationale)

    malformed_custom = copy.deepcopy(policy)
    requirement = next(iter(malformed_custom["custom_license_evidence"].values()))
    requirement["rationale"] = "\ud800"
    with pytest.raises(evidence.EvidenceError, match="valid UTF-8"):
        evidence.validate_policy_schema(malformed_custom)

    malformed_base = copy.deepcopy(policy)
    malformed_base["base_image"] = "\ud800"
    with pytest.raises(evidence.EvidenceError, match="valid UTF-8"):
        evidence.validate_policy_schema(malformed_base)

    mismatched_platform = copy.deepcopy(policy)
    alpine = next(
        component
        for component in mismatched_platform["platforms"]["linux/amd64"]
        if component["ecosystem"] == "alpine"
    )
    alpine["architecture"] = "aarch64"
    with pytest.raises(evidence.EvidenceError, match="architecture mismatch"):
        evidence.validate_policy_schema(mismatched_platform)


def test_policy_schema_rejects_noncanonical_retained_paths() -> None:
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    variants: list[dict[str, Any]] = []

    custom = copy.deepcopy(policy)
    custom_record = next(
        iter(next(iter(custom["custom_license_evidence"].values()))["evidence"].values())
    )
    custom_record["path"] = "./" + custom_record["path"]
    variants.append(custom)

    unexpanded = copy.deepcopy(policy)
    unexpanded_record = unexpanded["unexpanded_python_payloads"]["linux/amd64"]["embedded_sboms"][0]
    unexpanded_record["path"] += "/"
    variants.append(unexpanded)

    for category in ("apk_database_occurrences", "post_base_directory_effects"):
        filesystem = copy.deepcopy(policy)
        record = filesystem["filesystem_baselines"]["linux/amd64"][category][0]
        record["path"] = "./" + record["path"]
        variants.append(filesystem)

    whiteout = copy.deepcopy(policy)
    whiteout_record = whiteout["filesystem_baselines"]["linux/amd64"]["post_base_removals"][0]
    whiteout_record["path"] = "./" + whiteout_record["path"]
    variants.append(whiteout)

    for variant in variants:
        with pytest.raises(evidence.EvidenceError, match="canonical archive path"):
            evidence.validate_policy_schema(variant)


def test_standalone_inventory_enforces_platform_and_python_ownership_invariants() -> None:
    alpine = {
        "ecosystem": "alpine",
        "name": "demo",
        "version": "1-r0",
        "architecture": "aarch64",
        "observed_license": "MIT",
        "origin": "demo",
        "aports_commit": "e" * 40,
        "effective": True,
    }
    with pytest.raises(evidence.EvidenceError, match="architecture mismatch"):
        evidence.validate_component_inventory(standalone_inventory(alpine))

    first = {
        "ecosystem": "python",
        "name": "first",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    second = {**first, "name": "second", "metadata_sha256": "f" * 64}
    duplicate_hash = standalone_inventory(first)
    duplicate_hash["components"].append(second)
    with pytest.raises(evidence.EvidenceError, match="reuses a Python metadata digest"):
        evidence.validate_component_inventory(duplicate_hash)

    second_version = {**first, "version": "2", "metadata_sha256": "e" * 64}
    ambiguous_owner = standalone_inventory(first)
    ambiguous_owner["components"].append(second_version)
    with pytest.raises(evidence.EvidenceError, match="multiple effective versions"):
        evidence.validate_component_inventory(ambiguous_owner)

    noncanonical = standalone_inventory(first)
    payload = copy.deepcopy(noncanonical["apk_database_occurrences"][0])
    payload["path"] = "./embedded/sbom.json"
    payload["owner"] = "python:first@1"
    payload["cyclonedx"] = evidence.parse_cyclonedx_sbom(cyclonedx_sbom(), "embedded/sbom.json")
    noncanonical["embedded_sboms"] = [payload]
    with pytest.raises(evidence.EvidenceError, match="canonical archive path"):
        evidence.validate_component_inventory(noncanonical)


@pytest.mark.parametrize("field", ["name", "version"])
def test_python_component_identity_is_bounded(field: str) -> None:
    component = {
        "ecosystem": "python",
        "name": "demo",
        "version": "1",
        "observed_license": "MIT",
        "effective": True,
        "metadata_sha256": "f" * 64,
    }
    component[field] = "a" * (evidence.MAX_COMPONENT_FIELD_LENGTH + 1)
    with pytest.raises(evidence.EvidenceError, match="invalid length"):
        evidence.validate_component_inventory(standalone_inventory(component))


def selected_retention_fixture(
    command: list[str], *, mutation: str = ""
) -> tuple[dict[str, Any], bytes]:
    output = Path(command[command.index("--output") + 1])
    output.mkdir(parents=True)
    payloads = {
        "extra_codeowners-1-py3-none-any.whl": b"wheel",
        "extra_codeowners-1.tar.gz": b"source",
        "python-build-record-amd64.json": b"amd64-record",
        "python-build-record-arm64.json": b"arm64-record",
        "python-selection-record.json": b"selection-record",
    }
    for name, content in payloads.items():
        (output / name).write_bytes(content)
    files = [
        {
            "filename": name,
            "sha256": evidence.sha256_bytes(content),
            "size": len(content),
        }
        for name, content in sorted(payloads.items())
    ]
    result = {
        "schema_version": 1,
        "source_revision": "a" * 40,
        "selection_record_sha256": evidence.sha256_bytes(payloads["python-selection-record.json"]),
        "wheel_filename": "extra_codeowners-1-py3-none-any.whl",
        "wheel_sha256": evidence.sha256_bytes(payloads["extra_codeowners-1-py3-none-any.whl"]),
        "sdist_filename": "extra_codeowners-1.tar.gz",
        "sdist_sha256": evidence.sha256_bytes(payloads["extra_codeowners-1.tar.gz"]),
        "files": files,
        "installation": {"contract": "opaque to retention"},
    }
    if mutation == "schema":
        result["schema_version"] = 2
    elif mutation == "missing":
        result["files"] = files[:-1]
        (output / files[-1]["filename"]).unlink()
    elif mutation == "extra":
        extra = output / "unreviewed"
        extra.write_bytes(b"extra")
        result["files"] = [
            *files,
            {
                "filename": extra.name,
                "sha256": evidence.sha256_bytes(b"extra"),
                "size": 5,
            },
        ]
    elif mutation == "symlink":
        name = "python-build-record-arm64.json"
        linked = output / name
        content = linked.read_bytes()
        target = output.parent / "outside-record"
        target.write_bytes(content)
        linked.unlink()
        linked.symlink_to(target)
    elif mutation == "tampered":
        cast(list[dict[str, Any]], result["files"])[0]["sha256"] = "0" * 64
    compact = json.dumps(
        result,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    if mutation == "noncanonical":
        compact = json.dumps(result, indent=2, sort_keys=True).encode()
    return result, compact + b"\n"


def test_retains_exact_selected_proof_for_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result: dict[str, Any] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> bytes:
        nonlocal result
        result, output = selected_retention_fixture(command)
        return output

    monkeypatch.setattr(evidence, "run", fake_run)
    budget = evidence.BundleBudget()
    expected_payloads = {
        "wheel": evidence.sha256_bytes(b"wheel"),
        "selection": evidence.sha256_bytes(b"selection-record"),
    }
    binding, installation = evidence.retain_selected_application_artifacts(
        directory=tmp_path / "incoming",
        output=tmp_path / "bundle" / "artifacts" / "application",
        repo=tmp_path,
        source_revision="a" * 40,
        wheel_sha256=expected_payloads["wheel"],
        selection_record_sha256=expected_payloads["selection"],
        budget=budget,
    )

    assert len(binding["files"]) == 5
    assert {record["path"] for record in binding["files"]} == {
        f"artifacts/application/{record['filename']}" for record in result["files"]
    }
    assert binding["wheel_sha256"] == expected_payloads["wheel"]
    assert binding["selection_record_sha256"] == expected_payloads["selection"]
    assert installation == {"contract": "opaque to retention"}
    assert budget.retained_file_count == 5


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("noncanonical", "noncanonical JSON"),
        ("schema", "unsupported schema"),
        ("missing", "exactly five"),
        ("extra", "exactly five"),
        ("symlink", "cannot read retained"),
        ("tampered", "differs from its canonical hash"),
    ],
)
def test_selected_proof_retention_fails_closed(
    mutation: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(command: list[str], **_kwargs: Any) -> bytes:
        _result, output = selected_retention_fixture(command, mutation=mutation)
        return output

    monkeypatch.setattr(evidence, "run", fake_run)
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.retain_selected_application_artifacts(
            directory=tmp_path / "incoming",
            output=tmp_path / "bundle" / "artifacts" / "application",
            repo=tmp_path,
            source_revision="a" * 40,
            wheel_sha256=evidence.sha256_bytes(b"wheel"),
            selection_record_sha256=evidence.sha256_bytes(b"selection-record"),
            budget=evidence.BundleBudget(),
        )


def test_bundle_budget_enforces_cumulative_download_and_retained_limits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(evidence, "MAX_BUNDLE_DOWNLOAD_BYTES", 3)
    download_budget = evidence.BundleBudget()
    download_budget.record_download(b"ab")
    with pytest.raises(evidence.EvidenceError, match="cumulative download-size"):
        download_budget.record_download(b"cd")

    monkeypatch.setattr(evidence, "MAX_BUNDLE_FILES", 1)
    retained_budget = evidence.BundleBudget()
    evidence.write_file(tmp_path, "first", b"one", budget=retained_budget)
    with pytest.raises(evidence.EvidenceError, match="cumulative file-count"):
        evidence.write_file(tmp_path, "second", b"two", budget=retained_budget)


def test_bundle_member_producer_enforces_exact_size_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(evidence, "MAX_ARCHIVE_MEMBER_BYTES", 3)
    evidence.write_file(tmp_path, "exact", b"abc")
    with pytest.raises(evidence.EvidenceError, match="bundle member exceeds"):
        evidence.write_file(tmp_path, "too-large", b"abcd")


def test_deterministic_archive_has_normalized_metadata(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "b").write_bytes(b"second")
    (root / "a").write_bytes(b"first")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    evidence.create_deterministic_tar(root, first, 123)
    evidence.create_deterministic_tar(root, second, 123)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        members = archive.getmembers()
    assert [item.name for item in members] == ["a", "b"]
    assert {(item.uid, item.gid, item.mode, item.mtime) for item in members} == {(0, 0, 0o644, 123)}


def test_release_milestone_must_match_pinned_number_and_be_open_and_empty() -> None:
    ready = {
        "number": 1,
        "title": "First supported release",
        "state": "open",
        "open_issues": 0,
        "closed_issues": 2,
    }
    checked = readiness.validate_milestone(ready, 1, "First supported release")
    readiness.require_ready(checked)

    for changed, message in (
        ({**ready, "number": 2}, "expected milestone #1"),
        ({**ready, "title": "Other"}, "expected 'First supported release'"),
        ({**ready, "closed_issues": True}, "invalid closed_issues"),
    ):
        with pytest.raises(readiness.ReadinessError, match=message):
            readiness.validate_milestone(changed, 1, "First supported release")

    for changed, message in (
        ({**ready, "open_issues": 1}, "still has 1 open"),
        ({**ready, "state": "closed"}, "is not open"),
    ):
        checked = readiness.validate_milestone(changed, 1, "First supported release")
        with pytest.raises(readiness.ReadinessError, match=message):
            readiness.require_ready(checked)


def test_release_policy_is_exact(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone": "First supported release"}'
    )
    assert readiness.configured_milestone(policy) == (1, "First supported release")
    policy.write_text(
        '{"schema_version": 2, "milestone_number": 1, "milestone": "First supported release"}'
    )
    with pytest.raises(readiness.ReadinessError, match="unsupported"):
        readiness.configured_milestone(policy)
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone_number": 2, '
        '"milestone": "First supported release"}'
    )
    with pytest.raises(readiness.ReadinessError, match="duplicate JSON object key"):
        readiness.configured_milestone(policy)


def test_release_summary_links_exact_run_commit_and_counts(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    milestone = {
        "number": 1,
        "title": "First supported release",
        "open_issues": 0,
        "closed_issues": 2,
    }
    readiness.write_summary(
        summary,
        milestone,
        repository="stampbot/extra-codeowners",
        commit="a" * 40,
        run_id="12345",
    )
    content = summary.read_text()
    assert "stampbot/extra-codeowners" in content
    assert f"/commit/{'a' * 40}" in content
    assert "/actions/runs/12345" in content
    assert "milestone/1" in content
    assert "Open issues: **0**" in content
    assert "Closed issues: **2**" in content


def test_release_query_gets_the_pinned_milestone_directly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[str] = []
    response_body = json.dumps(
        {
            "number": 1,
            "title": "First supported release",
            "state": "open",
            "open_issues": 0,
            "closed_issues": 2,
        }
    ).encode()

    class Response:
        status = 200

        def __init__(self) -> None:
            self.remaining = response_body

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            result = self.remaining[:size]
            self.remaining = self.remaining[size:]
            return result

    def urlopen(request: Any, *, timeout: int) -> Response:
        assert timeout == 30
        requests.append(request.full_url)
        return Response()

    monkeypatch.setattr(readiness.urllib.request, "urlopen", urlopen)
    result = readiness.github_milestone("stampbot/extra-codeowners", 1, "token")

    assert result["number"] == 1
    assert requests == ["https://api.github.com/repos/stampbot/extra-codeowners/milestones/1"]


def test_blocked_release_still_writes_the_workflow_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"schema_version": 1, "milestone_number": 1, "milestone": "First supported release"}'
    )
    summary = tmp_path / "summary.md"
    milestone = {
        "number": 1,
        "title": "First supported release",
        "state": "open",
        "open_issues": 5,
        "closed_issues": 2,
    }
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(readiness, "github_milestone", lambda *_args: milestone)

    result = readiness.main(
        [
            "--repository",
            "stampbot/extra-codeowners",
            "--policy",
            str(policy),
            "--commit",
            "a" * 40,
            "--run-id",
            "12345",
            "--summary",
            str(summary),
        ]
    )

    assert result == 1
    assert "Open issues: **5**" in summary.read_text()


def test_workflows_keep_release_blocked_and_collect_review_evidence_in_ci() -> None:
    release = Path(".github/workflows/release.yml").read_text()
    ci = Path(".github/workflows/ci.yml").read_text()
    mise = Path("mise.toml").read_text()

    assert "issues: read" in release
    assert "release_readiness.py" in release
    release_block = "Keep tagged publication disabled pending isolated evidence collection"
    assert release_block in release
    assert "https://github.com/stampbot/extra-codeowners/issues/28" in release
    assert release.index(release_block) < release.index("Publish release image")
    assert "exit 1" in release[release.index(release_block) : release.index("  quality:")]
    assert '--summary "${GITHUB_STEP_SUMMARY}"' in release
    assert "Build digest-bound distribution evidence" not in release
    assert "--require-distribution-approval" not in release
    assert "container-distribution-evidence" not in release
    assert "evidence-predicate-amd64.json" not in release
    assert "evidence-predicate-arm64.json" not in release

    assert "container-evidence-${{ matrix.architecture }}-${{ github.sha }}-attempt-" in ci
    assert "${{ github.run_attempt }}" in ci
    assert '--platform "$PLATFORM"' in ci
    assert "--require-image-revision" in ci
    assert "--allow-config-digest-subject" in ci
    assert (
        "Upload container distribution evidence\n        if: ${{ always() && !cancelled() }}" in ci
    )
    assert "if-no-files-found: warn" in ci
    assert "retention-days: 5" in ci
    assert "run-metadata-${ARCHITECTURE}.json" in ci
    assert "publish-container:" not in ci
    assert "packages: write" not in ci
    assert "push: true" not in ci

    for checked_scope in (ci, release, mise):
        assert ".github/scripts/container_evidence.py" in checked_scope
        assert ".github/scripts/release_readiness.py" in checked_scope


def test_verify_ci_policy_command_composes_every_trusted_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = {
        "inventory.json": {"kind": "inventory"},
        "files.json": {"kind": "files"},
        "policy.json": {"kind": "policy"},
    }
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(evidence, "load_json", lambda path: records[path.name])
    monkeypatch.setattr(
        evidence,
        "validate_all_layer_inventory",
        lambda files, inventory: calls.append(("deep", files, inventory)),
    )
    monkeypatch.setattr(
        evidence,
        "verify_inventory",
        lambda inventory, policy, *, require_approval: calls.append(
            ("policy", inventory, policy, require_approval)
        ),
    )
    monkeypatch.setattr(
        evidence,
        "verify_base_layer_binding",
        lambda files, policy: calls.append(("base", files, policy)),
    )
    monkeypatch.setattr(
        evidence,
        "verify_post_base_filesystem_policy",
        lambda files, policy: calls.append(("filesystem", files, policy)),
    )
    monkeypatch.setattr(
        evidence,
        "verify_dockerfile_base",
        lambda dockerfile, policy: calls.append(("dockerfile", dockerfile, policy)),
    )

    evidence.command_verify_ci_policy(
        SimpleNamespace(
            inventory="inventory.json",
            files_inventory="files.json",
            policy="policy.json",
            dockerfile="Dockerfile",
        )
    )

    assert calls == [
        ("deep", records["files.json"], records["inventory.json"]),
        ("policy", records["inventory.json"], records["policy.json"], False),
        ("base", records["files.json"], records["policy.json"]),
        ("filesystem", records["files.json"], records["policy.json"]),
        ("dockerfile", Path("Dockerfile"), records["policy.json"]),
    ]


def test_filesystem_policy_view_emits_validated_semantic_projection(tmp_path: Path) -> None:
    image = tmp_path / "image.tar"
    saved_image_layers(
        image,
        [
            tar_bytes(
                {
                    "lib/apk/db/installed": apk_database(),
                    "removed": b"lower-layer content",
                },
                directories=["etc", "opt"],
            ),
            tar_bytes(
                {".wh.removed": b""},
                directories=["etc", "opt/application"],
                headers={".wh.removed": {"mode": 0o600}},
            ),
        ],
    )
    _inventory, files = evidence._inventory_saved_image(image, "linux/amd64", "sha256:" + "a" * 64)
    files_path = tmp_path / "all-layer-files.json"
    files_path.write_bytes(evidence.canonical_json(files))
    policy = cast(dict[str, Any], json.loads(Path(".compliance/container-policy.json").read_text()))
    policy["base_image_platforms"]["linux/amd64"]["layer_diff_ids"] = [files["layers"][0]["digest"]]
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(evidence.canonical_json(policy))
    output = tmp_path / "filesystem-policy-view.json"
    arguments = evidence.parser().parse_args(
        [
            "filesystem-policy-view",
            "--files-inventory",
            str(files_path),
            "--policy",
            str(policy_path),
            "--output",
            str(output),
        ]
    )

    arguments.function(arguments)

    assert output.read_bytes() == evidence.canonical_json(
        {
            "platform": "linux/amd64",
            "post_base_directory_effects": [
                {
                    "layer": 1,
                    "path": "opt/application",
                    "mode": 0o755,
                    "uid": 0,
                    "gid": 0,
                }
            ],
            "post_base_removals": [
                {
                    "kind": "whiteout",
                    "path": ".wh.removed",
                    "target": "removed",
                }
            ],
        }
    )


def test_bundle_command_forwards_image_revision_requirement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, Any] = {}
    monkeypatch.setattr(evidence, "build_bundle", lambda **kwargs: observed.update(kwargs))
    args = SimpleNamespace(
        inventory="inventory.json",
        files_inventory="files.json",
        policy="policy.json",
        uv_lock="uv.lock",
        repo=str(tmp_path),
        output="bundle.tar.gz",
        predicate_output="predicate.json",
        version="1.2.3",
        source_date_epoch=123,
        selected_python_directory="selected-python",
        application_source_revision="a" * 40,
        application_wheel_sha256="b" * 64,
        application_selection_record_sha256="c" * 64,
        require_distribution_approval=True,
        require_image_revision=True,
    )

    evidence.command_bundle(args)

    assert observed["require_approval"] is True
    assert observed["require_image_revision"] is True
    assert observed["selected_python_directory"] == Path("selected-python")
    assert observed["application_selection_record_sha256"] == "c" * 64


def test_evidence_cli_requires_selected_proof_identity() -> None:
    with pytest.raises(SystemExit):
        evidence.parser().parse_args(
            [
                "bundle",
                "--inventory",
                "inventory.json",
                "--files-inventory",
                "files.json",
                "--output",
                "bundle.tar.gz",
                "--predicate-output",
                "predicate.json",
                "--version",
                "1.0.0",
                "--source-date-epoch",
                "1",
            ]
        )
