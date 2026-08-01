"""Adversarial tests for offline OCI platform selection."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
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


controller: Any = load_script("release_controller")
index_acquisition: Any = load_script("acquire_oci_index")
verifier: Any = load_script("select_oci_platforms")

REPOSITORY = "stampbot/extra-codeowners"
REPOSITORY_ID = 1_299_090_885
OWNER_ID = 1_234_567
WORKFLOW_ID = 44_556_677
RUN_ID = 12_345_678
RUN_ATTEMPT = 2
TAG = "v0.1.0"
COMMIT = "a" * 40
WORKFLOW_PATH = ".github/workflows/release.yml"
WORKFLOW_FILE_SHA256 = "b" * 64
MANIFEST_SHA256 = "c" * 64
WORKFLOW_RECORD_SHA256 = "d" * 64
PLATFORM_DIGESTS = {
    "linux/amd64": "sha256:" + "1" * 64,
    "linux/arm64": "sha256:" + "2" * 64,
}
ATTESTATION_DIGESTS = {
    "linux/amd64": "sha256:" + "3" * 64,
    "linux/arm64": "sha256:" + "4" * 64,
}
SIGNATURE_BYTES = b'{"opaque":"already authenticated"}\n'


def canonical(value: object) -> bytes:
    return cast(bytes, controller.canonical_json(value))


def platform_descriptor(platform: str, digest: str) -> dict[str, object]:
    os_name, architecture = platform.split("/")
    return {
        "digest": digest,
        "mediaType": verifier.OCI_MANIFEST_MEDIA_TYPE,
        "platform": {"architecture": architecture, "os": os_name},
        "size": 481,
    }


def attestation_descriptor(platform: str, digest: str) -> dict[str, object]:
    return {
        "annotations": {
            verifier.DOCKER_REFERENCE_DIGEST: PLATFORM_DIGESTS[platform],
            verifier.DOCKER_REFERENCE_TYPE: verifier.ATTESTATION_MANIFEST,
        },
        "digest": digest,
        "mediaType": verifier.OCI_MANIFEST_MEDIA_TYPE,
        "platform": {"architecture": "unknown", "os": "unknown"},
        "size": 565,
    }


def index_value() -> dict[str, object]:
    return {
        "manifests": [
            platform_descriptor("linux/amd64", PLATFORM_DIGESTS["linux/amd64"]),
            platform_descriptor("linux/arm64", PLATFORM_DIGESTS["linux/arm64"]),
            attestation_descriptor(
                "linux/amd64",
                ATTESTATION_DIGESTS["linux/amd64"],
            ),
            attestation_descriptor(
                "linux/arm64",
                ATTESTATION_DIGESTS["linux/arm64"],
            ),
        ],
        "mediaType": index_acquisition.OCI_INDEX_MEDIA_TYPE,
        "schemaVersion": 2,
    }


def record_value(raw_index: bytes) -> dict[str, object]:
    index_sha256 = hashlib.sha256(raw_index).hexdigest()
    image_digest = f"sha256:{index_sha256}"
    signature_sha256 = hashlib.sha256(SIGNATURE_BYTES).hexdigest()
    image_repository = f"ghcr.io/{REPOSITORY}"
    image_reference = f"{image_repository}@{image_digest}"
    workflow_ref = f"refs/tags/{TAG}"
    signer = f"https://github.com/{REPOSITORY}/{WORKFLOW_PATH}@{workflow_ref}"
    manifest_url = f"https://ghcr.io/v2/{REPOSITORY}/manifests/{image_digest}"
    token_url = (
        "https://ghcr.io/token?"
        f"service=ghcr.io&scope=repository%3A{REPOSITORY.replace('/', '%2F')}%3Apull"
    )
    return {
        "authenticated_workflow": {"sha256": WORKFLOW_RECORD_SHA256},
        "controller_manifest": {"sha256": MANIFEST_SHA256},
        "cosign": {
            "maximum_major_version": 3,
            "minimum_version": "3.0.6",
            "version": "3.0.6",
        },
        "image": {
            "digest": image_digest,
            "index": {
                "descriptor_count": 4,
                "media_type": index_acquisition.OCI_INDEX_MEDIA_TYPE,
                "path": verifier.INDEX_NAME,
                "sha256": index_sha256,
                "size": len(raw_index),
            },
            "reference": image_reference,
            "repository": image_repository,
        },
        "kind": index_acquisition.RECORD_KIND,
        "publication_allowed": False,
        "registry": {
            "host": "ghcr.io",
            "manifest_url": manifest_url,
            "redirects": [],
            "token_url": token_url,
        },
        "repository": {
            "id": REPOSITORY_ID,
            "name": REPOSITORY,
            "owner_id": OWNER_ID,
        },
        "schema_version": 1,
        "signature_bundle": {
            "certificate_sha256": "5" * 64,
            "envelope_sha256": "6" * 64,
            "integrated_time": 1_788_000_000,
            "log_id": "bG9nLWlk",
            "log_index": 0,
            "media_type": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "path": verifier.SIGNATURE_NAME,
            "payload_sha256": "7" * 64,
            "sha256": signature_sha256,
            "signature_sha256": "8" * 64,
            "size": len(SIGNATURE_BYTES),
            "timestamp_count": 1,
            "transparency_log_entry_count": 1,
            "tree_size": 1,
        },
        "tag": {"name": TAG, "target_commit": COMMIT},
        "workflow": {
            "file_sha256": WORKFLOW_FILE_SHA256,
            "id": WORKFLOW_ID,
            "path": WORKFLOW_PATH,
            "ref": workflow_ref,
            "run_attempt": RUN_ATTEMPT,
            "run_id": RUN_ID,
            "sha": COMMIT,
            "signer_identity": signer,
            "url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        },
    }


@dataclass
class Fixture:
    directory: Path
    record_path: Path
    record: dict[str, object]
    record_sha256: str
    index: bytes


def write_private(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


def rewrite_record(item: Fixture) -> None:
    raw = canonical(item.record)
    item.record_path.write_bytes(raw)
    item.record_sha256 = hashlib.sha256(raw).hexdigest()


def replace_index(
    item: Fixture,
    value: object,
    *,
    descriptor_count: int | None = None,
) -> None:
    raw = canonical(value)
    item.index = raw
    write_private(item.directory / verifier.INDEX_NAME, raw)
    digest = hashlib.sha256(raw).hexdigest()
    image = cast(dict[str, object], item.record["image"])
    index = cast(dict[str, object], image["index"])
    index["sha256"] = digest
    index["size"] = len(raw)
    if descriptor_count is not None:
        index["descriptor_count"] = descriptor_count
    image_digest = f"sha256:{digest}"
    image["digest"] = image_digest
    image["reference"] = f"ghcr.io/{REPOSITORY}@{image_digest}"
    registry = cast(dict[str, object], item.record["registry"])
    registry["manifest_url"] = f"https://ghcr.io/v2/{REPOSITORY}/manifests/{image_digest}"
    rewrite_record(item)


def fixture(tmp_path: Path) -> Fixture:
    raw_index = canonical(index_value())
    directory = tmp_path / "authenticated-index"
    directory.mkdir(mode=0o700)
    write_private(directory / verifier.INDEX_NAME, raw_index)
    write_private(directory / verifier.SIGNATURE_NAME, SIGNATURE_BYTES)
    record = record_value(raw_index)
    record_path = tmp_path / "authenticated-index.json"
    item = Fixture(
        directory=directory,
        record_path=record_path,
        record=record,
        record_sha256="",
        index=raw_index,
    )
    rewrite_record(item)
    return item


def authenticate(item: Fixture) -> Any:
    return verifier.load_authenticated_index(
        item.record_path,
        expected_sha256=item.record_sha256,
    )


def select(item: Fixture) -> dict[str, object]:
    return cast(
        dict[str, object],
        verifier.select_oci_platforms(
            authenticate(item),
            directory=item.directory,
        ),
    )


def nested(record: dict[str, object], path: str) -> dict[str, object]:
    current = record
    for field in path.split("."):
        current = cast(dict[str, object], current[field])
    return current


def test_selects_exact_platform_and_attestation_descriptors(tmp_path: Path) -> None:
    item = fixture(tmp_path)

    result = select(item)

    assert result["schema_version"] == 1
    assert result["kind"] == verifier.RECORD_KIND
    assert result["publication_allowed"] is False
    assert result["authenticated_oci_index"] == {"sha256": item.record_sha256}
    assert result["controller_manifest"] == {"sha256": MANIFEST_SHA256}
    image = cast(dict[str, object], result["image"])
    assert image["digest"] == f"sha256:{hashlib.sha256(item.index).hexdigest()}"
    assert image["signature_bundle"] == {
        "path": verifier.SIGNATURE_NAME,
        "sha256": hashlib.sha256(SIGNATURE_BYTES).hexdigest(),
        "size": len(SIGNATURE_BYTES),
    }
    platforms = cast(dict[str, dict[str, object]], image["platforms"])
    assert list(platforms) == ["linux/amd64", "linux/arm64"]
    for position, platform in enumerate(platforms):
        assert platforms[platform]["image_manifest"] == {
            "digest": PLATFORM_DIGESTS[platform],
            "media_type": verifier.OCI_MANIFEST_MEDIA_TYPE,
            "position": position,
            "size": 481,
        }
        assert platforms[platform]["attestation_manifest"] == {
            "digest": ATTESTATION_DIGESTS[platform],
            "media_type": verifier.OCI_MANIFEST_MEDIA_TYPE,
            "position": position + 2,
            "size": 565,
        }
    assert stat.S_IMODE(item.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((item.directory / verifier.INDEX_NAME).stat().st_mode) == 0o600


def test_output_is_deterministic(tmp_path: Path) -> None:
    item = fixture(tmp_path)

    first = canonical(select(item))
    second = canonical(select(item))

    assert first == second


def test_cli_emits_one_canonical_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    item = fixture(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "select_oci_platforms.py",
            "--authenticated-index-record",
            str(item.record_path),
            "--authenticated-index-record-sha256",
            item.record_sha256,
            "--authenticated-index-directory",
            str(item.directory),
        ],
    )

    assert verifier.main() == 0

    captured = capsys.readouterr()
    value = json.loads(captured.out)
    assert canonical(value).decode() == captured.out
    assert captured.err == ""


def test_cli_fails_closed_without_a_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    item = fixture(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "select_oci_platforms.py",
            "--authenticated-index-record",
            str(item.record_path.with_name("missing.json")),
            "--authenticated-index-record-sha256",
            item.record_sha256,
            "--authenticated-index-directory",
            str(item.directory),
        ],
    )

    assert verifier.main() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("OCI platform selection failed:")


def test_rejects_wrong_trusted_record_hash(tmp_path: Path) -> None:
    item = fixture(tmp_path)

    with pytest.raises(verifier.OCIPlatformError, match="record is invalid"):
        verifier.load_authenticated_index(
            item.record_path,
            expected_sha256="f" * 64,
        )


def test_rejects_noncanonical_record(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    raw = json.dumps(item.record, indent=2).encode()
    item.record_path.write_bytes(raw)
    item.record_sha256 = hashlib.sha256(raw).hexdigest()

    with pytest.raises(verifier.OCIPlatformError, match="record is invalid"):
        authenticate(item)


@pytest.mark.parametrize(
    ("container", "field", "replacement"),
    [
        ("", "schema_version", True),
        ("", "kind", "other"),
        ("", "publication_allowed", True),
        ("controller_manifest", "sha256", "F" * 64),
        ("authenticated_workflow", "sha256", "F" * 64),
        ("cosign", "maximum_major_version", 4),
        ("cosign", "minimum_version", "3.0.5"),
        ("cosign", "version", "3.0.5"),
        ("cosign", "version", "4.0.0"),
        ("repository", "id", True),
        ("repository", "name", "Stampbot/extra-codeowners"),
        ("repository", "owner_id", 0),
        ("tag", "name", "latest"),
        ("tag", "target_commit", "F" * 40),
        ("workflow", "id", 0),
        ("workflow", "path", "../release.yml"),
        ("workflow", "ref", "refs/heads/main"),
        ("workflow", "run_attempt", True),
        ("workflow", "run_id", 0),
        ("workflow", "sha", "e" * 40),
        ("workflow", "signer_identity", "https://example.invalid"),
        ("workflow", "url", "https://example.invalid"),
        ("workflow", "file_sha256", "F" * 64),
        ("image", "digest", "sha256:" + "F" * 64),
        ("image", "reference", "ghcr.io/stampbot/other@sha256:" + "1" * 64),
        ("image", "repository", "ghcr.io/stampbot/other"),
        ("image.index", "media_type", "application/json"),
        ("image.index", "path", "../index.json"),
        ("image.index", "sha256", "F" * 64),
        ("image.index", "size", True),
        ("registry", "host", "registry.example"),
        ("registry", "redirects", ["https://example.invalid"]),
        ("registry", "manifest_url", "https://example.invalid"),
        ("registry", "token_url", "https://example.invalid"),
        ("signature_bundle", "media_type", "application/json"),
        ("signature_bundle", "path", "../signature.json"),
        ("signature_bundle", "sha256", "F" * 64),
        ("signature_bundle", "size", 0),
        ("signature_bundle", "log_index", -1),
        ("signature_bundle", "tree_size", 0),
        ("signature_bundle", "timestamp_count", 9),
        ("signature_bundle", "transparency_log_entry_count", True),
        ("signature_bundle", "transparency_log_entry_count", 2),
    ],
)
def test_rejects_mutated_authenticated_record(
    tmp_path: Path,
    container: str,
    field: str,
    replacement: object,
) -> None:
    item = fixture(tmp_path)
    target = item.record if not container else nested(item.record, container)
    target[field] = replacement
    rewrite_record(item)

    with pytest.raises(verifier.OCIPlatformError):
        authenticate(item)


@pytest.mark.parametrize("field", ["schema_version", "image", "signature_bundle"])
def test_rejects_missing_authenticated_record_field(
    tmp_path: Path,
    field: str,
) -> None:
    item = fixture(tmp_path)
    del item.record[field]
    rewrite_record(item)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        authenticate(item)


def test_rejects_unknown_authenticated_record_field(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    item.record["unknown"] = "field"
    rewrite_record(item)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        authenticate(item)


def test_requires_absolute_acquisition_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = fixture(tmp_path)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(verifier.OCIPlatformError, match="must be absolute"):
        verifier.select_oci_platforms(
            authenticate(item),
            directory=Path(item.directory.name),
        )


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770])
def test_rejects_nonprivate_acquisition_directory(
    tmp_path: Path,
    mode: int,
) -> None:
    item = fixture(tmp_path)
    item.directory.chmod(mode)

    with pytest.raises(verifier.OCIPlatformError, match="mode-0700"):
        select(item)


@pytest.mark.parametrize("name", [verifier.INDEX_NAME, verifier.SIGNATURE_NAME])
def test_rejects_missing_acquisition_file(tmp_path: Path, name: str) -> None:
    item = fixture(tmp_path)
    (item.directory / name).unlink()

    with pytest.raises(verifier.OCIPlatformError, match="incomplete"):
        select(item)


def test_cli_fails_closed_when_a_retained_file_disappears_before_opening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    item = fixture(tmp_path)
    original_open = verifier.os.open

    def remove_after_inventory(*arguments: Any, **keywords: Any) -> int:
        if arguments[0] == verifier.INDEX_NAME and keywords.get("dir_fd") is not None:
            raise FileNotFoundError("test retained-file race")
        return cast(int, original_open(*arguments, **keywords))

    monkeypatch.setattr(verifier.os, "open", remove_after_inventory)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "select_oci_platforms.py",
            "--authenticated-index-record",
            str(item.record_path),
            "--authenticated-index-record-sha256",
            item.record_sha256,
            "--authenticated-index-directory",
            str(item.directory),
        ],
    )

    assert verifier.main() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("OCI platform selection failed: cannot open")
    assert "Traceback" not in captured.err


def test_rejects_extra_acquisition_file(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    write_private(item.directory / "extra.json", b"{}\n")

    with pytest.raises(verifier.OCIPlatformError, match="unexpected entry"):
        select(item)


@pytest.mark.parametrize("name", [verifier.INDEX_NAME, verifier.SIGNATURE_NAME])
def test_rejects_symlinked_acquisition_file(tmp_path: Path, name: str) -> None:
    item = fixture(tmp_path)
    target = item.directory / name
    replacement = item.directory / f"{name}.real"
    target.rename(replacement)
    target.symlink_to(replacement.name)

    with pytest.raises(
        verifier.OCIPlatformError,
        match=r"unsafe identity|unexpected entry",
    ):
        select(item)


@pytest.mark.parametrize("name", [verifier.INDEX_NAME, verifier.SIGNATURE_NAME])
def test_rejects_nonprivate_acquisition_file(tmp_path: Path, name: str) -> None:
    item = fixture(tmp_path)
    (item.directory / name).chmod(0o644)

    with pytest.raises(verifier.OCIPlatformError, match="unsafe identity"):
        select(item)


def test_rejects_hardlinked_acquisition_file(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    os.link(
        item.directory / verifier.INDEX_NAME,
        item.directory / "second-index.json",
    )

    with pytest.raises(
        verifier.OCIPlatformError,
        match=r"unsafe identity|unexpected entry",
    ):
        select(item)


@pytest.mark.parametrize("name", [verifier.INDEX_NAME, verifier.SIGNATURE_NAME])
def test_rejects_changed_acquisition_bytes(tmp_path: Path, name: str) -> None:
    item = fixture(tmp_path)
    path = item.directory / name
    raw = path.read_bytes()
    write_private(path, b"x" * len(raw))

    with pytest.raises(verifier.OCIPlatformError, match="wrong SHA-256"):
        select(item)


def test_rejects_index_path_replacement_during_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = fixture(tmp_path)
    original = verifier._select_descriptors

    def replace(raw: bytes, authenticated: Any) -> Any:
        path = item.directory / verifier.INDEX_NAME
        path.unlink()
        write_private(path, raw)
        return original(raw, authenticated)

    monkeypatch.setattr(verifier, "_select_descriptors", replace)

    with pytest.raises(verifier.OCIPlatformError, match=r"changed|unsafe identity"):
        select(item)


def test_rejects_directory_replacement_during_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = fixture(tmp_path)
    original = verifier._select_descriptors
    moved = item.directory.with_name("authenticated-index-original")

    def replace(raw: bytes, authenticated: Any) -> Any:
        item.directory.rename(moved)
        item.directory.mkdir(mode=0o700)
        write_private(item.directory / verifier.INDEX_NAME, raw)
        write_private(item.directory / verifier.SIGNATURE_NAME, SIGNATURE_BYTES)
        return original(raw, authenticated)

    monkeypatch.setattr(verifier, "_select_descriptors", replace)

    with pytest.raises(verifier.OCIPlatformError, match="directory changed"):
        select(item)
    assert moved.is_dir()
    assert item.directory.is_dir()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schemaVersion", True),
        ("schemaVersion", 3),
        ("mediaType", "application/json"),
        ("manifests", {}),
        ("manifests", []),
    ],
)
def test_rejects_invalid_root_index_fields(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    item = fixture(tmp_path)
    value = index_value()
    value[field] = replacement
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError):
        select(item)


@pytest.mark.parametrize("field", ["schemaVersion", "mediaType", "manifests"])
def test_rejects_missing_root_index_field(tmp_path: Path, field: str) -> None:
    item = fixture(tmp_path)
    value = index_value()
    del value[field]
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        select(item)


def test_rejects_unknown_root_index_field(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    value = index_value()
    value["annotations"] = {}
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        select(item)


def manifest_at(value: dict[str, object], position: int) -> dict[str, object]:
    return cast(list[dict[str, object]], value["manifests"])[position]


@pytest.mark.parametrize(
    ("position", "field", "replacement"),
    [
        (0, "mediaType", "application/json"),
        (0, "digest", "sha256:" + "F" * 64),
        (0, "size", True),
        (0, "size", 0),
        (0, "size", verifier.MAX_CHILD_MANIFEST_BYTES + 1),
        (1, "digest", PLATFORM_DIGESTS["linux/amd64"]),
        (2, "mediaType", "application/json"),
        (2, "digest", "sha256:" + "F" * 64),
        (2, "size", 0),
        (3, "digest", ATTESTATION_DIGESTS["linux/amd64"]),
    ],
)
def test_rejects_invalid_descriptor_identity(
    tmp_path: Path,
    position: int,
    field: str,
    replacement: object,
) -> None:
    item = fixture(tmp_path)
    value = index_value()
    manifest_at(value, position)[field] = replacement
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError):
        select(item)


@pytest.mark.parametrize("position", [0, 1, 2, 3])
def test_rejects_unknown_descriptor_field(tmp_path: Path, position: int) -> None:
    item = fixture(tmp_path)
    value = index_value()
    manifest_at(value, position)["unknown"] = "field"
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        select(item)


@pytest.mark.parametrize("position", [0, 1, 2, 3])
def test_rejects_missing_descriptor_field(tmp_path: Path, position: int) -> None:
    item = fixture(tmp_path)
    value = index_value()
    del manifest_at(value, position)["size"]
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        select(item)


def test_rejects_platform_descriptor_annotations(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    value = index_value()
    manifest_at(value, 0)["annotations"] = {}
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        select(item)


@pytest.mark.parametrize(
    ("position", "field", "replacement"),
    [
        (0, "architecture", "arm64"),
        (0, "os", "windows"),
        (1, "architecture", "amd64"),
        (2, "architecture", "amd64"),
        (2, "os", "linux"),
    ],
)
def test_rejects_wrong_descriptor_platform(
    tmp_path: Path,
    position: int,
    field: str,
    replacement: str,
) -> None:
    item = fixture(tmp_path)
    value = index_value()
    platform = cast(dict[str, object], manifest_at(value, position)["platform"])
    platform[field] = replacement
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="wrong platform"):
        select(item)


def test_rejects_platform_variant(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    value = index_value()
    platform = cast(dict[str, object], manifest_at(value, 1)["platform"])
    platform["variant"] = "v8"
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        select(item)


@pytest.mark.parametrize(
    ("position", "field", "replacement"),
    [
        (2, verifier.DOCKER_REFERENCE_TYPE, "other"),
        (2, verifier.DOCKER_REFERENCE_DIGEST, PLATFORM_DIGESTS["linux/arm64"]),
        (3, verifier.DOCKER_REFERENCE_TYPE, ""),
        (3, verifier.DOCKER_REFERENCE_DIGEST, "sha256:" + "F" * 64),
    ],
)
def test_rejects_wrong_attestation_link(
    tmp_path: Path,
    position: int,
    field: str,
    replacement: str,
) -> None:
    item = fixture(tmp_path)
    value = index_value()
    annotations = cast(
        dict[str, object],
        manifest_at(value, position)["annotations"],
    )
    annotations[field] = replacement
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="attestation manifest"):
        select(item)


def test_rejects_extra_attestation_annotation(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    value = index_value()
    annotations = cast(dict[str, object], manifest_at(value, 2)["annotations"])
    annotations["unknown"] = "field"
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="contain exactly"):
        select(item)


def test_rejects_out_of_order_descriptors(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    value = index_value()
    manifests = cast(list[dict[str, object]], value["manifests"])
    manifests[0], manifests[1] = manifests[1], manifests[0]
    replace_index(item, value)

    with pytest.raises(verifier.OCIPlatformError, match="wrong platform"):
        select(item)


def test_rejects_record_and_index_descriptor_count_disagreement(
    tmp_path: Path,
) -> None:
    item = fixture(tmp_path)
    index = cast(dict[str, object], nested(item.record, "image")["index"])
    index["descriptor_count"] = 5
    rewrite_record(item)

    with pytest.raises(verifier.OCIPlatformError, match="required four descriptors"):
        select(item)


def test_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    item = fixture(tmp_path)
    raw = item.index.replace(
        b'"schemaVersion":2',
        b'"schemaVersion":2,"schemaVersion":2',
    )
    assert raw != item.index
    write_private(item.directory / verifier.INDEX_NAME, raw)
    digest = hashlib.sha256(raw).hexdigest()
    image = cast(dict[str, object], item.record["image"])
    index = cast(dict[str, object], image["index"])
    index["sha256"] = digest
    index["size"] = len(raw)
    image["digest"] = f"sha256:{digest}"
    image["reference"] = f"ghcr.io/{REPOSITORY}@sha256:{digest}"
    registry = cast(dict[str, object], item.record["registry"])
    registry["manifest_url"] = f"https://ghcr.io/v2/{REPOSITORY}/manifests/sha256:{digest}"
    rewrite_record(item)

    with pytest.raises(verifier.OCIPlatformError, match="not strict JSON"):
        select(item)


def test_platform_selection_has_no_registry_or_cosign_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = fixture(tmp_path)

    class Forbidden:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("platform selection attempted external access")

    monkeypatch.setattr(index_acquisition, "GHCRClient", Forbidden)
    monkeypatch.setattr(index_acquisition, "CosignCLI", Forbidden)

    assert select(item)["publication_allowed"] is False


def test_script_is_packaged_but_not_invoked_by_workflows() -> None:
    root = Path(__file__).parents[1]
    script = ".github/scripts/select_oci_platforms.py"
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    release = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    mise = (root / "mise.toml").read_text(encoding="utf-8")

    assert f"!{script}" in dockerignore
    assert script in dockerfile
    assert ci.count(script) == 1
    assert release.count(script) == 1
    assert mise.count(script) == 1
    assert f"python {script}" not in ci
    assert f"python {script}" not in release
    assert release.count("version: v0.35.0") == 2
    assert release.count("image=moby/buildkit:v0.30.0@sha256:") == 2
    assert "platforms: linux/amd64,linux/arm64" in release
    assert "provenance: mode=max" in release
    assert "sbom: true" in release


def test_reference_documents_cli_policy_and_nonclaims() -> None:
    root = Path(__file__).parents[1]
    reference = (root / "docs/reference/selected-oci-platforms.md").read_text(encoding="utf-8")

    assert ".github/scripts/select_oci_platforms.py" in reference
    assert "--authenticated-index-record" in reference
    assert "--authenticated-index-record-sha256" in reference
    assert "--authenticated-index-directory" in reference
    assert "`0` | `linux/amd64`" in reference
    assert "`1` | `linux/arm64`" in reference
    assert reference.count("`unknown/unknown`") >= 3
    assert "vnd.docker.reference.digest" in reference
    assert "publication_allowed" in reference
    assert "fetch or hash either runnable image manifest" in reference
    assert "No workflow calls this command" in reference
    assert "https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md" in reference
    assert "https://docs.docker.com/build/metadata/attestations/attestation-storage/" in reference


def test_how_to_runs_selector_and_navigation_exposes_reference() -> None:
    root = Path(__file__).parents[1]
    how_to = (root / "docs/how-to/verify-container-release-evidence.md").read_text(encoding="utf-8")
    navigation = (root / "mkdocs.yml").read_text(encoding="utf-8")
    maintainers = (root / "docs/maintainers/index.md").read_text(encoding="utf-8")

    assert "eight non-publishing boundaries" in how_to
    assert ".github/scripts/select_oci_platforms.py" in how_to
    assert "OCI_SUMMARY_SHA256" in how_to
    assert "PLATFORM_SUMMARY_TMP" in how_to
    assert "selected-oci-platforms.md" in how_to
    assert "Selected OCI platforms: reference/selected-oci-platforms.md" in navigation
    assert "reference/selected-oci-platforms.md" in maintainers
