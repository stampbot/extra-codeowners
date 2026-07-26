"""Tests for the Docker-only image exporter."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "export_container_image.py"


def load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


exporter: Any = load_script(SCRIPT, "export_container_image_for_test")


def image_info(
    *,
    architecture: str = "amd64",
    config_digest: str = "sha256:" + "a" * 64,
    repository_digest: str = "sha256:" + "b" * 64,
) -> dict[str, object]:
    return {
        "Architecture": architecture,
        "Id": config_digest,
        "Os": "linux",
        "RepoDigests": [f"ghcr.io/stampbot/extra-codeowners@{repository_digest}"],
    }


def test_exporter_has_no_archive_parser_or_network_client_imports() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert imports.isdisjoint(
        {
            "container_evidence",
            "email",
            "email.parser",
            "gzip",
            "http",
            "shutil",
            "socket",
            "tarfile",
            "urllib",
            "urllib.request",
            "zipfile",
        }
    )
    for forbidden_call in (
        "TarFile",
        "ZipFile",
        "unpack_archive",
        "urlopen",
        "docker load",
    ):
        assert forbidden_call not in source


def test_local_image_identity_requires_exact_platform_and_subject_binding() -> None:
    config_digest = "sha256:" + "a" * 64
    repository_digest = "sha256:" + "b" * 64
    info = image_info(
        config_digest=config_digest,
        repository_digest=repository_digest,
    )

    assert (
        exporter._validate_local_image(
            info,
            platform="linux/amd64",
            subject_digest=repository_digest,
            allow_config_digest_subject=False,
        )
        == config_digest
    )
    assert (
        exporter._validate_local_image(
            info,
            platform="linux/amd64",
            subject_digest=config_digest,
            allow_config_digest_subject=True,
        )
        == config_digest
    )
    with pytest.raises(exporter.ImageExportError, match="subject digest"):
        exporter._validate_local_image(
            info,
            platform="linux/amd64",
            subject_digest=config_digest,
            allow_config_digest_subject=False,
        )
    with pytest.raises(exporter.ImageExportError, match="platform"):
        exporter._validate_local_image(
            info,
            platform="linux/arm64",
            subject_digest=repository_digest,
            allow_config_digest_subject=False,
        )


def test_export_local_image_creates_only_the_exact_bound_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_digest = "sha256:" + "a" * 64
    subject_digest = "sha256:" + "b" * 64
    info = image_info(
        config_digest=config_digest,
        repository_digest=subject_digest,
    )
    inspections: list[str] = []

    def inspect(image: str) -> dict[str, object]:
        inspections.append(image)
        return info

    archive_content = b"opaque docker archive bytes"

    def stream(digest: str, destination: Path) -> tuple[str, int]:
        assert digest == config_digest
        destination.write_bytes(archive_content)
        return hashlib.sha256(archive_content).hexdigest(), len(archive_content)

    monkeypatch.setattr(exporter, "_docker_inspect", inspect)
    monkeypatch.setattr(exporter, "_stream_image_archive", stream)
    output = tmp_path / "image-export"

    record = exporter.export_local_image(
        image="extra-codeowners:ci-amd64",
        platform="linux/amd64",
        subject_digest=subject_digest,
        allow_config_digest_subject=False,
        output=output,
    )

    assert inspections == ["extra-codeowners:ci-amd64", config_digest]
    assert sorted(path.name for path in output.iterdir()) == ["image-export.json", "image.tar"]
    assert (output / "image.tar").read_bytes() == archive_content
    assert json.loads((output / "image-export.json").read_bytes()) == record
    assert cast(dict[str, object], record["archive"]) == {
        "filename": "image.tar",
        "sha256": hashlib.sha256(archive_content).hexdigest(),
        "size": len(archive_content),
    }
    assert cast(dict[str, object], record["image"]) == {
        "config_digest": config_digest,
        "platform": "linux/amd64",
        "subject_digest": subject_digest,
    }
    assert stat.S_IMODE(output.stat().st_mode) == 0o755
    assert stat.S_IMODE((output / "image.tar").stat().st_mode) == 0o644
    assert stat.S_IMODE((output / "image-export.json").stat().st_mode) == 0o644


def test_failed_export_leaves_no_consumable_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_digest = "sha256:" + "a" * 64
    subject_digest = "sha256:" + "b" * 64
    monkeypatch.setattr(
        exporter,
        "_docker_inspect",
        lambda _image: image_info(
            config_digest=config_digest,
            repository_digest=subject_digest,
        ),
    )

    def fail(_digest: str, destination: Path) -> tuple[str, int]:
        destination.write_bytes(b"partial")
        raise exporter.ImageExportError("simulated failure")

    monkeypatch.setattr(exporter, "_stream_image_archive", fail)
    output = tmp_path / "failed-export"

    with pytest.raises(exporter.ImageExportError, match="simulated"):
        exporter.export_local_image(
            image="extra-codeowners:ci-amd64",
            platform="linux/amd64",
            subject_digest=subject_digest,
            allow_config_digest_subject=False,
            output=output,
        )
    assert not output.exists()


def test_docker_save_stream_has_an_exact_create_once_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_docker = tmp_path / "docker"
    fake_docker.write_text("#!/bin/sh\nprintf abc\n", encoding="utf-8")
    fake_docker.chmod(0o755)
    monkeypatch.setattr(exporter, "DOCKER_BINARY", str(fake_docker))
    monkeypatch.setattr(exporter, "MAX_IMAGE_ARCHIVE_BYTES", 3)
    output = tmp_path / "image.tar"

    digest, size = exporter._stream_image_archive("sha256:" + "a" * 64, output)
    assert output.read_bytes() == b"abc"
    assert digest == hashlib.sha256(b"abc").hexdigest()
    assert size == 3

    second = tmp_path / "second.tar"
    fake_docker.write_text("#!/bin/sh\nprintf abcd\n", encoding="utf-8")
    with pytest.raises(exporter.ImageExportError, match="exceeds its byte limit"):
        exporter._stream_image_archive("sha256:" + "a" * 64, second)
    assert not second.exists()

    with pytest.raises(exporter.ImageExportError, match="cannot create"):
        exporter._stream_image_archive("sha256:" + "a" * 64, output)
    assert output.read_bytes() == b"abc"


def test_record_writer_never_replaces_or_unlinks_an_existing_file(tmp_path: Path) -> None:
    record = tmp_path / "image-export.json"
    record.write_bytes(b"pre-existing")

    with pytest.raises(exporter.ImageExportError, match="cannot create"):
        exporter._write_record(record, {"schema_version": 1})

    assert record.read_bytes() == b"pre-existing"


def test_strict_docker_json_rejects_duplicate_keys_and_non_finite_numbers() -> None:
    with pytest.raises(exporter.ImageExportError, match="strict JSON"):
        exporter.strict_json_object(b'{"Id":"first","Id":"second"}', "fixture")
    with pytest.raises(exporter.ImageExportError, match="strict JSON"):
        exporter.strict_json_object(b'{"value":NaN}', "fixture")


def test_image_reference_rejects_option_and_shell_like_tokens() -> None:
    for value in (
        "--help",
        "demo:tag$HOME",
        "demo:`id`",
        "demo:'tag'",
        "demo\\tag",
        "x" * 513,
    ):
        with pytest.raises(exporter.ImageExportError, match="image reference"):
            exporter._validate_image_reference(value)
    assert exporter._validate_image_reference("extra-codeowners:ci-amd64") == (
        "extra-codeowners:ci-amd64"
    )
