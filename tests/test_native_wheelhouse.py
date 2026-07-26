"""Tests for the reproducible native wheelhouse boundary."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "native_wheelhouse.py"
INPUTS = ROOT / "containers" / "native-wheelhouse" / "inputs.json"
DOCKERFILE = ROOT / "containers" / "native-wheelhouse" / "Dockerfile"
PUBLISH_DOCKERFILE = ROOT / "containers" / "native-wheelhouse" / "Publish.Dockerfile"
WORKFLOW = ROOT / ".github" / "workflows" / "native-wheelhouse.yml"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("native_wheelhouse", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


wheelhouse: Any = load_script()


def write_json(path: Path, value: object) -> Path:
    path.write_bytes(wheelhouse.canonical_json(value))
    return path


def real_input_value() -> dict[str, Any]:
    value = json.loads(INPUTS.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def tar_bytes(
    files: dict[str, bytes],
    *,
    symlinks: dict[str, str] | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        for name, target in (symlinks or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.mode = 0o777
            member.linkname = target
            archive.addfile(member)
    return output.getvalue()


def wheel_digest(content: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")


def pure_wheel(
    path: Path,
    *,
    complete_record: bool = True,
    compatibility_metadata: bytes = (
        b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    ),
    extra_files: dict[str, bytes] | None = None,
) -> Path:
    files = {
        "setuptools/__init__.py": b'"""Synthetic package."""\n',
        "setuptools/_vendor/demo-1.0.dist-info/METADATA": (
            b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n"
        ),
        "setuptools/_vendor/demo-1.0.dist-info/RECORD": b"",
        "setuptools/_vendor/demo-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "setuptools-80.3.1.dist-info/METADATA": (
            b"Metadata-Version: 2.4\nName: setuptools\nVersion: 80.3.1\n"
        ),
        "setuptools-80.3.1.dist-info/WHEEL": (compatibility_metadata),
    }
    files.update(extra_files or {})
    record_name = "setuptools-80.3.1.dist-info/RECORD"
    rows = [
        [name, f"sha256={wheel_digest(content)}", str(len(content))]
        for name, content in files.items()
        if complete_record or "_vendor/" not in name
    ]
    rows.append([record_name, "", ""])
    record = io.StringIO()
    csv.writer(record, lineterminator="\n").writerows(rows)
    files[record_name] = record.getvalue().encode()
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


def test_reviewed_inputs_are_strict_and_complete() -> None:
    inputs = wheelhouse.load_inputs(INPUTS)

    assert inputs.raw == INPUTS.read_bytes()
    assert inputs.python == {
        "abi": "cp314",
        "implementation": "cpython",
        "version": "3.14.6",
    }
    assert len(wheelhouse._expected_builder_packages(inputs, "linux/amd64")) == 91
    assert len(wheelhouse._expected_builder_packages(inputs, "linux/arm64")) == 91
    assert inputs.builder_platform_packages == {
        "linux/amd64": (".python-rundeps=20260616.002228",),
        "linux/arm64": (".python-rundeps=20260616.002107",),
    }
    assert [source.identifier for source in inputs.sources] == [
        "cffi",
        "psycopg",
        "pydantic-core",
        "setuptools",
    ]
    setuptools = inputs.sources[-1]
    assert setuptools.upstream["signature_review"] == "verified-tag-and-commit"
    assert [item.member for item in setuptools.release_patch.removed_members] == [
        "bootstrap.egg-info/PKG-INFO",
        "bootstrap.egg-info/entry_points.txt",
    ]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value.update({"unexpected": True}),
            "unexpected fields",
        ),
        (
            lambda value: value["sources"][0].update({"url": "https://example.com/source.tar.gz"}),
            "unapproved host",
        ),
        (
            lambda value: value["sources"][0]["upstream"].update(
                {"signature": value["sources"][0]["upstream"].pop("signature_review")}
            ),
            "unexpected fields",
        ),
        (
            lambda value: value["builder_platform_packages"]["linux/amd64"].append(
                "alpine-baselayout=3.7.2-r1"
            ),
            "closure repeats a package name",
        ),
    ],
)
def test_inputs_reject_unreviewed_fields_and_hosts(
    tmp_path: Path,
    mutation: Any,
    message: str,
) -> None:
    value = real_input_value()
    mutation(value)

    with pytest.raises(wheelhouse.WheelhouseError, match=message):
        wheelhouse.load_inputs(write_json(tmp_path / "inputs.json", value))


def test_inputs_reject_duplicate_keys_and_floats(tmp_path: Path) -> None:
    duplicate = INPUTS.read_text(encoding="utf-8").replace(
        "{",
        '{"kind": "extra-codeowners/native-wheelhouse-inputs",',
        1,
    )
    (tmp_path / "duplicate.json").write_text(duplicate, encoding="utf-8")
    value = real_input_value()
    value["source_date_epoch"] = 1.5
    (tmp_path / "float.json").write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(wheelhouse.WheelhouseError, match="repeats an object key"):
        wheelhouse.load_inputs(tmp_path / "duplicate.json")
    with pytest.raises(wheelhouse.WheelhouseError, match="floating-point"):
        wheelhouse.load_inputs(tmp_path / "float.json")


def test_source_extraction_accepts_an_implicit_root_directory(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(tar_bytes({"project/file.txt": b"content"}))

    root = wheelhouse._extract_source(archive, tmp_path / "output", "project")

    assert root == tmp_path / "output" / "project"
    assert (root / "file.txt").read_bytes() == b"content"
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


@pytest.mark.parametrize(
    "archive",
    [
        tar_bytes({"project/../escape": b"content"}),
        tar_bytes({"project/File": b"a", "project/file": b"b"}),
        tar_bytes(
            {"project/file": b"content"},
            symlinks={"project/link": "../../escape"},
        ),
    ],
)
def test_source_extraction_rejects_unsafe_members(tmp_path: Path, archive: bytes) -> None:
    source = tmp_path / "source.tar.gz"
    source.write_bytes(archive)

    with pytest.raises(wheelhouse.WheelhouseError):
        wheelhouse._extract_source(source, tmp_path / "output", "project")


def test_source_directory_requires_exact_checksum_bound_inventory(tmp_path: Path) -> None:
    content = b"source"
    source = wheelhouse.Source(
        identifier="source",
        filename="source.tar.gz",
        root="source",
        url="https://github.com/example/source",
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
        upstream={},
        release_patch=None,
    )
    inputs = replace(wheelhouse.load_inputs(INPUTS), sources=(source,))
    directory = tmp_path / "sources"
    directory.mkdir()
    (directory / source.filename).write_bytes(content)

    assert wheelhouse.verify_sources(inputs, directory) == {"source": directory / source.filename}
    (directory / "extra").write_bytes(b"unexpected")
    with pytest.raises(wheelhouse.WheelhouseError, match="unexpected inventory"):
        wheelhouse.verify_sources(inputs, directory)


def setuptools_patch(root: Path, *, extra_removal_file: bool = False) -> Any:
    original = b"[egg_info]\ntag_build = .post\ntag_date = 1\n"
    first = b"bootstrap"
    second = b"entry points"
    (root / "setup.cfg").write_bytes(original)
    removal = root / "bootstrap.egg-info"
    removal.mkdir()
    (removal / "PKG-INFO").write_bytes(first)
    (removal / "entry_points.txt").write_bytes(second)
    if extra_removal_file:
        (removal / "unexpected").write_bytes(b"hidden")
    patch = wheelhouse.ReleasePatch(
        member="setup.cfg",
        original_sha256=hashlib.sha256(original).hexdigest(),
        removed_members=(
            wheelhouse.SourceRemoval(
                "bootstrap.egg-info/PKG-INFO",
                hashlib.sha256(first).hexdigest(),
            ),
            wheelhouse.SourceRemoval(
                "bootstrap.egg-info/entry_points.txt",
                hashlib.sha256(second).hexdigest(),
            ),
        ),
        replacement_sha256=hashlib.sha256(wheelhouse.SETUPTOOLS_RELEASE_CONFIG).hexdigest(),
    )
    return wheelhouse.Source(
        identifier="setuptools",
        filename="setuptools.tar.gz",
        root="setuptools",
        url="https://github.com/pypa/setuptools",
        sha256="0" * 64,
        size=1,
        upstream={},
        release_patch=patch,
    )


def test_setuptools_release_patch_binds_every_removed_file(tmp_path: Path) -> None:
    source = setuptools_patch(tmp_path)

    wheelhouse._apply_setuptools_release_patch(source, tmp_path)

    assert (tmp_path / "setup.cfg").read_bytes() == wheelhouse.SETUPTOOLS_RELEASE_CONFIG
    assert not (tmp_path / "bootstrap.egg-info").exists()


def test_setuptools_release_patch_rejects_hidden_removal_content(tmp_path: Path) -> None:
    source = setuptools_patch(tmp_path, extra_removal_file=True)

    with pytest.raises(wheelhouse.WheelhouseError, match="unexpected inventory"):
        wheelhouse._apply_setuptools_release_patch(source, tmp_path)


def test_wheel_inspection_accepts_nested_vendored_metadata(tmp_path: Path) -> None:
    path = pure_wheel(tmp_path / "setuptools-80.3.1-py3-none-any.whl")
    expected = wheelhouse.ExpectedWheel("setuptools", "80.3.1", 0, ())

    record = wheelhouse.inspect_wheel(
        path,
        expected,
        machine="x86_64",
        work=tmp_path,
    )

    assert record["distribution"] == "setuptools"
    assert record["native_payloads"] == []


@pytest.mark.parametrize(
    "metadata",
    [
        b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n",
        b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: cp314-cp314-linux_x86_64\n",
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
            b"Tag: py3-none-any\nTag: cp314-cp314-linux_x86_64\n"
        ),
    ],
)
def test_wheel_inspection_rejects_contradictory_compatibility_metadata(
    tmp_path: Path,
    metadata: bytes,
) -> None:
    path = pure_wheel(
        tmp_path / "setuptools-80.3.1-py3-none-any.whl",
        compatibility_metadata=metadata,
    )

    with pytest.raises(
        wheelhouse.WheelhouseError,
        match="compatibility metadata contradicts",
    ):
        wheelhouse.inspect_wheel(
            path,
            wheelhouse.ExpectedWheel("setuptools", "80.3.1", 0, ()),
            machine="x86_64",
            work=tmp_path,
        )


@pytest.mark.parametrize("name", ["lib/libexample.so.1", "bin/native-tool"])
def test_wheel_inspection_detects_elf_payloads_without_a_dot_so_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    path = pure_wheel(
        tmp_path / "setuptools-80.3.1-py3-none-any.whl",
        extra_files={name: wheelhouse.ELF_MAGIC + b"synthetic"},
    )
    inspected: list[str] = []

    def inspect_elf(
        content: bytes,
        member: str,
        expected_machine: str,
        work: Path,
    ) -> dict[str, object]:
        del content, expected_machine, work
        inspected.append(member)
        return {"needed": [], "path": member}

    monkeypatch.setattr(wheelhouse, "_elf_record", inspect_elf)

    with pytest.raises(wheelhouse.WheelhouseError, match="native payload count"):
        wheelhouse.inspect_wheel(
            path,
            wheelhouse.ExpectedWheel("setuptools", "80.3.1", 0, ()),
            machine="x86_64",
            work=tmp_path,
        )

    assert inspected == [name]


def test_wheel_inspection_requires_record_coverage(tmp_path: Path) -> None:
    path = pure_wheel(
        tmp_path / "setuptools-80.3.1-py3-none-any.whl",
        complete_record=False,
    )

    with pytest.raises(wheelhouse.WheelhouseError, match="does not cover every member"):
        wheelhouse.inspect_wheel(
            path,
            wheelhouse.ExpectedWheel("setuptools", "80.3.1", 0, ()),
            machine="x86_64",
            work=tmp_path,
        )


def test_cargo_lock_requires_one_local_package_and_exact_registry(tmp_path: Path) -> None:
    inputs = replace(
        wheelhouse.load_inputs(INPUTS),
        cargo_registry_packages=1,
    )
    lock = tmp_path / "Cargo.lock"
    lock.write_text(
        "version = 3\n\n"
        '[[package]]\nname = "local"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "crate"\nversion = "2.0.0"\n'
        f'source = "{wheelhouse.CARGO_REGISTRY}"\n'
        f'checksum = "{"a" * 64}"\n',
        encoding="utf-8",
    )

    assert wheelhouse._cargo_packages(lock, inputs) == [
        {"checksum": "a" * 64, "name": "crate", "version": "2.0.0"}
    ]
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            wheelhouse.CARGO_REGISTRY,
            "registry+https://example.com/index",
        ),
        encoding="utf-8",
    )
    with pytest.raises(wheelhouse.WheelhouseError, match="unreviewed registry"):
        wheelhouse._cargo_packages(lock, inputs)


def synthetic_published_wheelhouse(tmp_path: Path) -> tuple[Any, Path]:
    real = wheelhouse.load_inputs(INPUTS)
    expected_wheel = wheelhouse.ExpectedWheel("setuptools", "80.3.1", 0, ())
    inputs = replace(
        real,
        cargo_registry_packages=1,
        expected_wheels=(expected_wheel,),
    )
    published = tmp_path / "published"
    published.mkdir()
    path = pure_wheel(published / "setuptools-80.3.1-py3-none-any.whl")
    wheel_record = wheelhouse.inspect_wheel(
        path,
        expected_wheel,
        machine="x86_64",
        work=tmp_path,
    )
    cargo = {
        "kind": wheelhouse.CARGO_INVENTORY_KIND,
        "packages": [
            {
                "checksum": "a" * 64,
                "name": "crate",
                "version": "1.0.0",
            }
        ],
        "registry_cache": "index.crates.io-1949cf8c6b5b557f",
        "schema_version": wheelhouse.SCHEMA_VERSION,
        "source": wheelhouse.CARGO_REGISTRY,
    }
    cargo_raw = wheelhouse.canonical_json(cargo)
    (published / "cargo-inputs.json").write_bytes(cargo_raw)
    (published / "inputs.json").write_bytes(inputs.raw)
    packages = [
        {"name": item.split("=", 1)[0], "version": item.split("=", 1)[1]}
        for item in wheelhouse._expected_builder_packages(inputs, "linux/amd64")
    ]
    manifest = {
        "builder": {
            "alpine_packages": packages,
            "base_image": dict(inputs.base_image),
            "tools": {
                "cargo": "cargo 1",
                "cython": "Cython 1",
                "gcc": "gcc 1",
                "maturin": "maturin 1",
                "python": "Python 3.14.6",
                "readelf": "readelf 1",
                "rustc": "rustc 1",
            },
        },
        "cargo": {
            "inventory_sha256": hashlib.sha256(cargo_raw).hexdigest(),
            "inventory_size": len(cargo_raw),
            **cargo,
        },
        "inputs": {"sha256": inputs.raw_sha256, "size": inputs.raw_size},
        "kind": wheelhouse.MANIFEST_KIND,
        "platform": "linux/amd64",
        "python": dict(inputs.python),
        "reproducible_builds": 2,
        "schema_version": wheelhouse.SCHEMA_VERSION,
        "source_date_epoch": inputs.source_date_epoch,
        "sources": wheelhouse._source_records(inputs),
        "wheels": [wheel_record],
    }
    write_json(published / "manifest.json", manifest)
    return inputs, published


def test_published_verifier_uses_private_work_and_exact_inventory(tmp_path: Path) -> None:
    inputs, published = synthetic_published_wheelhouse(tmp_path)

    wheelhouse.verify_wheelhouse(
        inputs,
        published,
        "linux/amd64",
        tmp_path / "verify-work",
    )

    assert (tmp_path / "verify-work").is_dir()
    (published / "unexpected").write_bytes(b"unexpected")
    with pytest.raises(wheelhouse.WheelhouseError, match="unexpected inventory"):
        wheelhouse.verify_wheelhouse(
            inputs,
            published,
            "linux/amd64",
            tmp_path / "second-work",
        )


def test_published_verifier_rejects_manifest_extensions(tmp_path: Path) -> None:
    inputs, published = synthetic_published_wheelhouse(tmp_path)
    manifest = json.loads((published / "manifest.json").read_text(encoding="utf-8"))
    manifest["unreviewed"] = True
    write_json(published / "manifest.json", manifest)

    with pytest.raises(wheelhouse.WheelhouseError, match="unexpected fields"):
        wheelhouse.verify_wheelhouse(
            inputs,
            published,
            "linux/amd64",
            tmp_path / "verify-work",
        )


def test_published_verifier_rejects_an_unreviewed_builder_package(tmp_path: Path) -> None:
    inputs, published = synthetic_published_wheelhouse(tmp_path)
    manifest = json.loads((published / "manifest.json").read_text(encoding="utf-8"))
    manifest["builder"]["alpine_packages"].append({"name": "zz-unreviewed", "version": "1-r0"})
    write_json(published / "manifest.json", manifest)

    with pytest.raises(wheelhouse.WheelhouseError, match="package closure is invalid"):
        wheelhouse.verify_wheelhouse(
            inputs,
            published,
            "linux/amd64",
            tmp_path / "verify-work",
        )


def test_native_wheelhouse_dockerfile_enforces_isolated_offline_builds() -> None:
    inputs = real_input_value()
    source = DOCKERFILE.read_text(encoding="utf-8")

    assert source.startswith(
        "# syntax=docker/dockerfile:1.18@sha256:"
        "dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf\n"
    )
    assert (
        f"FROM {inputs['base_image']['reference']}@{inputs['base_image']['digest']} AS toolchain"
        in source
    )
    package_block = source.split("RUN apk add --no-cache \\\n", 1)[1].split(
        " && \\\n    addgroup",
        1,
    )[0]
    docker_packages = [
        line.strip().removesuffix("\\").strip() for line in package_block.splitlines()
    ]
    assert docker_packages == inputs["builder_packages"]
    inputs_copy = "COPY --chown=0:0 --chmod=0444 containers/native-wheelhouse/inputs.json"
    assert source.index("RUN apk add --no-cache") < source.index(inputs_copy)
    for item in inputs["sources"]:
        assert f"--checksum=sha256:{item['sha256']}" in source
        assert item["url"] in source
        assert f"/wheelhouse-build/sources/{item['filename']}" in source

    assert source.count("FROM toolchain AS build-") == 2
    assert source.count("--network=none python ./native_wheelhouse.py build-pass") == 2
    assert source.count("--pass-name first") == 1
    assert source.count("--pass-name second") == 1
    assert source.count("--network=none python ./native_wheelhouse.py assemble") == 1
    cargo_stage = source.split("FROM toolchain AS cargo-inputs\n", 1)[1].split(
        "\nFROM ",
        1,
    )[0]
    assert "--network=none" not in cargo_stage
    assert "prepare-cargo" in cargo_stage
    final = source.split("FROM scratch AS wheelhouse\n", 1)[1]
    assert "apk add" not in final
    assert "org.opencontainers.image.licenses" not in final
    assert "COPY --from=assemble /build-root/wheelhouse/ /wheelhouse/" in final
    assert "USER 65532:65532" in source.split("FROM toolchain AS cargo-inputs", 1)[0]


def test_publish_dockerfile_only_wraps_verified_platform_artifacts() -> None:
    source = PUBLISH_DOCKERFILE.read_text(encoding="utf-8")

    assert "FROM wheelhouse-amd64 AS amd64" in source
    assert "FROM wheelhouse-arm64 AS arm64" in source
    assert "FROM ${TARGETARCH} AS selected" in source
    final = source.rsplit("\nFROM scratch\n", 1)[1]
    assert "RUN " not in final
    assert "ADD " not in final
    assert "org.opencontainers.image.licenses" not in final
    assert "COPY --from=selected / /wheelhouse/" in final


def test_published_sbom_artifacts_are_unique_across_run_attempts() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert "name: native-wheelhouse-sboms-${{ github.sha }}-${{ github.run_attempt }}" in source


def producer_artifact(
    name: str,
    artifact_id: int,
    *,
    revision: str,
    run_id: int,
    expired: bool = False,
) -> dict[str, object]:
    return {
        "digest": f"sha256:{artifact_id:064x}",
        "expired": expired,
        "id": artifact_id,
        "name": name,
        "size_in_bytes": 4096,
        "workflow_run": {
            "head_sha": revision,
            "id": run_id,
        },
    }


def test_producer_artifact_selection_survives_failed_jobs_only_reruns() -> None:
    revision = "a" * 40
    run_id = 12345
    artifacts = [
        producer_artifact(
            f"native-wheelhouse-{revision}-amd64-1",
            101,
            revision=revision,
            run_id=run_id,
        ),
        producer_artifact(
            f"native-wheelhouse-{revision}-arm64-1",
            201,
            revision=revision,
            run_id=run_id,
        ),
    ]

    selected = wheelhouse.select_producer_artifacts(
        json.dumps(artifacts),
        revision,
        str(run_id),
        "2",
    )

    assert selected == {
        "amd64": wheelhouse.ProducerArtifact(artifact_id=101, producer_attempt=1),
        "arm64": wheelhouse.ProducerArtifact(artifact_id=201, producer_attempt=1),
    }


def test_producer_artifact_selection_prefers_each_platforms_newest_attempt() -> None:
    revision = "b" * 40
    run_id = 23456
    artifacts = [
        producer_artifact(
            f"native-wheelhouse-{revision}-amd64-1",
            101,
            revision=revision,
            run_id=run_id,
        ),
        producer_artifact(
            f"native-wheelhouse-{revision}-amd64-3",
            103,
            revision=revision,
            run_id=run_id,
        ),
        producer_artifact(
            f"native-wheelhouse-{revision}-arm64-1",
            201,
            revision=revision,
            run_id=run_id,
        ),
        producer_artifact(
            f"native-wheelhouse-{revision}-arm64-2",
            202,
            revision=revision,
            run_id=run_id,
        ),
        producer_artifact(
            f"native-wheelhouse-{revision}-arm64-3",
            203,
            revision=revision,
            run_id=run_id,
            expired=True,
        ),
    ]

    selected = wheelhouse.select_producer_artifacts(
        json.dumps(artifacts),
        revision,
        str(run_id),
        "3",
    )

    assert selected == {
        "amd64": wheelhouse.ProducerArtifact(artifact_id=103, producer_attempt=3),
        "arm64": wheelhouse.ProducerArtifact(artifact_id=202, producer_attempt=2),
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate", "duplicated"),
        ("future", "newer than the workflow"),
        ("wrong-run", "different workflow run"),
        ("wrong-revision", "different workflow run"),
        ("invalid-digest", "digest has an invalid value"),
        ("expired-arm64", "no usable arm64"),
    ],
)
def test_producer_artifact_selection_rejects_ambiguous_or_foreign_inputs(
    mutation: str,
    message: str,
) -> None:
    revision = "c" * 40
    run_id = 34567
    amd64 = producer_artifact(
        f"native-wheelhouse-{revision}-amd64-1",
        101,
        revision=revision,
        run_id=run_id,
    )
    arm64 = producer_artifact(
        f"native-wheelhouse-{revision}-arm64-1",
        201,
        revision=revision,
        run_id=run_id,
    )
    artifacts = [amd64, arm64]
    if mutation == "duplicate":
        artifacts.append(
            producer_artifact(
                f"native-wheelhouse-{revision}-amd64-1",
                102,
                revision=revision,
                run_id=run_id,
            )
        )
    elif mutation == "future":
        amd64["name"] = f"native-wheelhouse-{revision}-amd64-3"
    elif mutation == "wrong-run":
        assert isinstance(amd64["workflow_run"], dict)
        amd64["workflow_run"]["id"] = run_id + 1
    elif mutation == "wrong-revision":
        assert isinstance(amd64["workflow_run"], dict)
        amd64["workflow_run"]["head_sha"] = "d" * 40
    elif mutation == "invalid-digest":
        amd64["digest"] = "sha256:" + ("A" * 64)
    elif mutation == "expired-arm64":
        arm64["expired"] = True
    else:
        raise AssertionError(f"unsupported mutation: {mutation}")

    with pytest.raises(wheelhouse.WheelhouseError, match=message):
        wheelhouse.select_producer_artifacts(
            json.dumps(artifacts),
            revision,
            str(run_id),
            "2",
        )


def test_producer_artifact_cli_emits_only_fixed_digit_outputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    revision = "e" * 40
    run_id = 45678
    artifacts = [
        producer_artifact(
            f"native-wheelhouse-{revision}-amd64-1",
            101,
            revision=revision,
            run_id=run_id,
        ),
        producer_artifact(
            f"native-wheelhouse-{revision}-arm64-2",
            202,
            revision=revision,
            run_id=run_id,
        ),
    ]
    monkeypatch.setenv("NATIVE_WHEELHOUSE_ARTIFACTS", json.dumps(artifacts))

    result = wheelhouse.main(
        [
            "select-producer-artifacts",
            "--source-revision",
            revision,
            "--run-id",
            str(run_id),
            "--current-attempt",
            "2",
        ]
    )

    assert result == 0
    assert capsys.readouterr().out == (
        "amd64-artifact-id=101\n"
        "amd64-producer-attempt=1\n"
        "arm64-artifact-id=202\n"
        "arm64-producer-attempt=2\n"
    )


def test_publication_downloads_immutable_ids_from_verified_producer_attempts() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    publish = source.split("\n  publish:\n", 1)[1]
    inventory = publish.split("      - name: List producer artifact identities\n", 1)[1].split(
        "      - name: Select verified producer artifacts by immutable ID\n",
        1,
    )[0]
    downloads = publish.split(
        "      - name: Download the verified amd64 wheelhouse\n",
        1,
    )[1].split("      - name: Reverify both transported wheelhouses\n", 1)[0]

    assert "      actions: read\n" in publish
    assert "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3" in inventory
    assert "github.rest.actions.listWorkflowRunArtifacts" in inventory
    assert 'Buffer.byteLength(encoded, "utf8") > 512 * 1024' in inventory
    assert "native_wheelhouse.py select-producer-artifacts" in publish
    assert '>> "$GITHUB_OUTPUT"' in publish
    assert downloads.count("artifact-ids:") == 2
    assert "steps.producer-artifacts.outputs.amd64-artifact-id" in downloads
    assert "steps.producer-artifacts.outputs.arm64-artifact-id" in downloads
    assert "\n          name:" not in downloads
    assert "github.run_attempt" not in downloads
    assert "AMD64_PRODUCER_ATTEMPT" in publish
    assert "ARM64_PRODUCER_ATTEMPT" in publish


def test_publication_retry_reuses_only_a_verified_commit_digest() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    retry = source.split("      - name: Add verified wheelhouse tags\n", 1)[1]

    assert source.count('map(select(. != ["unknown", "unknown"]))') == 2
    assert "cosign verify" in retry
    assert "org.opencontainers.image.revision" in retry
    assert "docker cp" in retry
    assert "/wheelhouse-not-executed" in retry
    assert "native_wheelhouse.py verify" in retry
    assert "--no-dereference" in retry
    assert "--recursive" in retry
    assert retry.index("cosign verify") < retry.index('selected_digest="$existing_commit_digest"')
    assert 'tag_and_wait "$immutable_tag" "$selected_digest" false' in retry
    assert 'tag_and_wait "${IMAGE}:latest" "$selected_digest" true' in retry
    assert '"$may_move" != "true"' in retry
    assert 'echo "\\`${IMAGE}@${selected_digest}\\`"' in retry


def test_native_wheelhouse_script_is_in_the_narrow_docker_context() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")

    assert "!.github/scripts/native_wheelhouse.py" in dockerignore


def test_application_test_image_contains_native_wheelhouse_contract() -> None:
    application_dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "     .github/scripts/native_wheelhouse.py \\\n" in application_dockerfile
    assert "COPY containers/native-wheelhouse/ ./containers/native-wheelhouse/\n" in (
        application_dockerfile
    )
