"""Adversarial tests for the publication-inert release asset assembler."""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".github" / "scripts"
REVISION = "1" * 40
SELECTED_ARTIFACT_SHA256 = "2" * 64
VERSION = "0.1.0"
WHEEL_NAME = f"extra_codeowners-{VERSION}-py3-none-any.whl"
SDIST_NAME = f"extra_codeowners-{VERSION}.tar.gz"


def load_script(name: str) -> ModuleType:
    path = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build_python_artifacts = load_script("build_python_artifacts")
python_distribution_spine = load_script("python_distribution_spine")
release_controller = load_script("release_controller")
spine_builder = load_script("build_python_distribution_spine")
assembler = load_script("release_asset_assembler")


@dataclass(frozen=True)
class Fixture:
    record: Path
    spine: Path
    signed_python: Path
    image_security: Path
    chart: Path
    output_parent: Path
    identity: Any
    record_digest: str
    spine_digest: str
    verification_calls: list[dict[str, object]]


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def selected_files() -> dict[str, bytes]:
    files = {
        "python-build-record-amd64.json": b'{"architecture":"amd64"}\n',
        "python-build-record-arm64.json": b'{"architecture":"arm64"}\n',
        SDIST_NAME: b"\x1f\x8bopaque-source-distribution",
        WHEEL_NAME: b"PK\x03\x04opaque-wheel",
    }
    selection = {
        "schema_version": 1,
        "source_revision": REVISION,
        "selected_architecture": "amd64",
        "proofs": {
            "amd64": {
                "record_filename": "python-build-record-amd64.json",
                "record_sha256": sha256_bytes(files["python-build-record-amd64.json"]),
                "python_machine": "x86_64",
            },
            "arm64": {
                "record_filename": "python-build-record-arm64.json",
                "record_sha256": sha256_bytes(files["python-build-record-arm64.json"]),
                "python_machine": "aarch64",
            },
        },
        "artifacts": {
            "sdist": {
                "filename": SDIST_NAME,
                "sha256": sha256_bytes(files[SDIST_NAME]),
                "size": len(files[SDIST_NAME]),
            },
            "wheel": {
                "filename": WHEEL_NAME,
                "sha256": sha256_bytes(files[WHEEL_NAME]),
                "size": len(files[WHEEL_NAME]),
            },
        },
    }
    files["python-selection-record.json"] = python_distribution_spine.canonical_json(selection)
    return files


def real_selected_files(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    """Build the same valid five-file proof used by the artifact-verifier tests."""

    helper_name = "_release_asset_real_proof_helpers"
    helper_path = ROOT / "tests" / "test_python_build_artifacts.py"
    spec = importlib.util.spec_from_file_location(helper_name, helper_path)
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    previous_helper = sys.modules.get(helper_name)
    previous_builder = sys.modules.get("build_python_artifacts")
    try:
        sys.modules[helper_name] = helper
        spec.loader.exec_module(helper)
        amd64 = tmp_path / "real-amd64"
        arm64 = tmp_path / "real-arm64"
        helper.write_distribution_proof(amd64, "amd64")
        helper.write_distribution_proof(arm64, "arm64")
        selected = tmp_path / "selected"
        result = cast(
            dict[str, object],
            helper.build.select_distributions(
                amd64,
                arm64,
                source_revision=REVISION,
                output=selected,
            ),
        )
        return selected, result
    finally:
        if previous_helper is None:
            sys.modules.pop(helper_name, None)
        else:
            sys.modules[helper_name] = previous_helper
        if previous_builder is None:
            sys.modules.pop("build_python_artifacts", None)
        else:
            sys.modules["build_python_artifacts"] = previous_builder


def make_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    real_selection: bool = False,
) -> Fixture:
    if real_selection:
        selected, expected_verification = real_selected_files(tmp_path)
        files = {path.name: path.read_bytes() for path in selected.iterdir()}
    else:
        selected = tmp_path / "selected"
        selected.mkdir()
        files = selected_files()
        for name, content in reversed(tuple(files.items())):
            (selected / name).write_bytes(content)
        expected_verification = {
            "schema_version": 1,
            "source_revision": REVISION,
            "selection_record_sha256": sha256_bytes(files["python-selection-record.json"]),
            "wheel_filename": WHEEL_NAME,
            "wheel_sha256": sha256_bytes(files[WHEEL_NAME]),
            "sdist_filename": SDIST_NAME,
            "sdist_sha256": sha256_bytes(files[SDIST_NAME]),
        }
    identity = python_distribution_spine.ExpectedIdentity(
        repository_id="123456",
        repository_name="stampbot/extra-codeowners",
        run_id="777777",
        run_attempt="2",
        source_revision=REVISION,
        workflow_path=".github/workflows/python-distribution.yml",
        workflow_ref=(
            "stampbot/extra-codeowners/.github/workflows/python-distribution.yml@refs/tags/v0.1.0"
        ),
        workflow_sha=REVISION,
        selected_artifact_id="888888",
        selected_artifact_sha256=SELECTED_ARTIFACT_SHA256,
        wheel_sha256=sha256_bytes(files[WHEEL_NAME]),
        selection_record_sha256=sha256_bytes(files["python-selection-record.json"]),
    )
    if not real_selection:
        monkeypatch.setattr(
            spine_builder.build_python_artifacts,
            "verify_selection",
            lambda *args, **kwargs: expected_verification,
        )
    basename = python_distribution_spine.expected_spine_filename(
        REVISION,
        identity.selected_artifact_id,
        identity.run_attempt,
    )
    spine = tmp_path / basename
    record = tmp_path / python_distribution_spine.expected_record_filename(
        REVISION,
        identity.selected_artifact_id,
        identity.run_attempt,
    )
    spine_builder.build(selected, spine, record, identity)

    calls: list[dict[str, object]] = []

    if not real_selection:

        def verify_selection(path: Path, **kwargs: object) -> dict[str, object]:
            calls.append({"directory": path, **kwargs})
            return expected_verification

        monkeypatch.setattr(
            assembler.build_python_artifacts,
            "verify_selection",
            verify_selection,
        )

    signed_python = tmp_path / "signed-python"
    signed_python.mkdir()
    for name in (WHEEL_NAME, SDIST_NAME):
        (signed_python / name).write_bytes(files[name])
        (signed_python / f"{name}.sigstore.json").write_bytes(
            b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
        )

    image_security = tmp_path / "image-security"
    image_security.mkdir()
    for name in (
        "image-sbom-linux-amd64.spdx.json",
        "image-sbom-linux-amd64.spdx.json.sigstore.json",
        "image-sbom-linux-arm64.spdx.json",
        "image-sbom-linux-arm64.spdx.json.sigstore.json",
        f"extra-codeowners-{VERSION}.openvex.json",
        f"extra-codeowners-{VERSION}.openvex.json.sigstore.json",
    ):
        (image_security / name).write_bytes(f"{name}\n".encode())

    chart = tmp_path / "chart"
    chart.mkdir()
    chart_name = f"extra-codeowners-{VERSION}.tgz"
    (chart / chart_name).write_bytes(b"\x1f\x8bopaque-chart")
    (chart / f"{chart_name}.sigstore.json").write_bytes(
        b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
    )

    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    output_parent.chmod(0o700)
    return Fixture(
        record=record,
        spine=spine,
        signed_python=signed_python,
        image_security=image_security,
        chart=chart,
        output_parent=output_parent,
        identity=identity,
        record_digest=sha256(record),
        spine_digest=sha256(spine),
        verification_calls=calls,
    )


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    return make_fixture(tmp_path, monkeypatch)


def assemble(
    fixture: Fixture,
    *,
    output_name: str = "plan",
    output_directory: Path | None = None,
    identity: Any | None = None,
    release_identity: Any | None = None,
) -> Any:
    return assembler.assemble(
        record_path=fixture.record,
        spine_path=fixture.spine,
        output_directory=(
            fixture.output_parent / output_name if output_directory is None else output_directory
        ),
        python_signed_directory=fixture.signed_python,
        image_security_directory=fixture.image_security,
        chart_directory=fixture.chart,
        python_identity=fixture.identity if identity is None else identity,
        record_artifact_sha256=fixture.record_digest,
        spine_artifact_sha256=fixture.spine_digest,
        release_identity=release_identity
        or assembler.ReleaseIdentity(
            tag=f"v{VERSION}",
            version=VERSION,
            workflow_path=".github/workflows/release.yml",
            workflow_sha=REVISION,
        ),
    )


def expected_asset_names() -> set[str]:
    return {
        *assembler.PYTHON_RECORD_NAMES,
        WHEEL_NAME,
        f"{WHEEL_NAME}.sigstore.json",
        SDIST_NAME,
        f"{SDIST_NAME}.sigstore.json",
        "image-sbom-linux-amd64.spdx.json",
        "image-sbom-linux-amd64.spdx.json.sigstore.json",
        "image-sbom-linux-arm64.spdx.json",
        "image-sbom-linux-arm64.spdx.json.sigstore.json",
        f"extra-codeowners-{VERSION}.openvex.json",
        f"extra-codeowners-{VERSION}.openvex.json.sigstore.json",
        f"extra-codeowners-{VERSION}.tgz",
        f"extra-codeowners-{VERSION}.tgz.sigstore.json",
    }


def mismatched_arm_machine(fixture: Fixture) -> Fixture:
    """Keep the raw transport self-consistent while corrupting the arm64 proof."""

    record = cast(
        dict[str, Any],
        json.loads(fixture.record.read_text(encoding="utf-8")),
    )
    file_records = {
        cast(str, item["kind"]): item for item in cast(list[dict[str, Any]], record["files"])
    }
    arm_record = file_records["build-record-arm64"]
    selection_record = file_records["selection-record"]
    spine = bytearray(fixture.spine.read_bytes())

    arm_start = cast(int, arm_record["offset"])
    arm_end = arm_start + cast(int, arm_record["size"])
    original_arm = bytes(spine[arm_start:arm_end])
    changed_arm = original_arm.replace(b"aarch64", b"aarch65")
    assert changed_arm != original_arm
    assert len(changed_arm) == len(original_arm)
    spine[arm_start:arm_end] = changed_arm
    old_arm_digest = cast(str, arm_record["sha256"])
    new_arm_digest = sha256_bytes(changed_arm)
    arm_record["sha256"] = new_arm_digest

    selection_start = cast(int, selection_record["offset"])
    selection_end = selection_start + cast(int, selection_record["size"])
    original_selection = bytes(spine[selection_start:selection_end])
    assert original_selection.count(old_arm_digest.encode()) == 1
    changed_selection = original_selection.replace(
        old_arm_digest.encode(),
        new_arm_digest.encode(),
    )
    assert len(changed_selection) == len(original_selection)
    spine[selection_start:selection_end] = changed_selection
    new_selection_digest = sha256_bytes(changed_selection)
    selection_record["sha256"] = new_selection_digest
    cast(dict[str, Any], record["selection"])["record_sha256"] = new_selection_digest
    cast(dict[str, Any], record["spine"])["sha256"] = sha256_bytes(bytes(spine))

    record_bytes = python_distribution_spine.canonical_json(record)
    fixture.spine.write_bytes(spine)
    fixture.record.write_bytes(record_bytes)
    return dataclasses.replace(
        fixture,
        identity=dataclasses.replace(
            fixture.identity,
            selection_record_sha256=new_selection_digest,
        ),
        record_digest=sha256_bytes(record_bytes),
        spine_digest=sha256_bytes(bytes(spine)),
    )


def test_cli_assembles_candidate_and_reports_record_digest(
    fixture: Fixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = fixture.output_parent / "cli"
    result = assembler.main(
        [
            "--record",
            str(fixture.record),
            "--spine",
            str(fixture.spine),
            "--output",
            str(output),
            "--python-signed-directory",
            str(fixture.signed_python),
            "--image-security-directory",
            str(fixture.image_security),
            "--chart-directory",
            str(fixture.chart),
            "--record-artifact-sha256",
            fixture.record_digest,
            "--spine-artifact-sha256",
            fixture.spine_digest,
            "--repository-id",
            fixture.identity.repository_id,
            "--repository-name",
            fixture.identity.repository_name,
            "--run-id",
            fixture.identity.run_id,
            "--run-attempt",
            fixture.identity.run_attempt,
            "--source-revision",
            fixture.identity.source_revision,
            "--workflow-path",
            fixture.identity.workflow_path,
            "--workflow-ref",
            fixture.identity.workflow_ref,
            "--workflow-sha",
            fixture.identity.workflow_sha,
            "--selected-artifact-id",
            fixture.identity.selected_artifact_id,
            "--selected-artifact-sha256",
            fixture.identity.selected_artifact_sha256,
            "--wheel-sha256",
            fixture.identity.wheel_sha256,
            "--selection-record-sha256",
            fixture.identity.selection_record_sha256,
            "--tag",
            f"v{VERSION}",
            "--version",
            VERSION,
            "--release-workflow-path",
            assembler.RELEASE_WORKFLOW_PATH,
            "--release-workflow-sha",
            REVISION,
        ]
    )

    assert result == 0
    record = assembler.load_candidate_record(output / assembler.RECORD_NAME)
    assert capsys.readouterr().out == (f"candidate-record-sha256={record.record_sha256}\n")


def test_assembles_deterministic_complete_scoped_candidate(fixture: Fixture) -> None:
    first = assemble(fixture, output_name="first")
    second = assemble(fixture, output_name="second")

    expected = expected_asset_names()
    assert len(expected) == assembler.EXPECTED_ASSET_COUNT
    assert first.record == second.record
    assert (first.directory / assembler.RECORD_NAME).read_bytes() == (
        second.directory / assembler.RECORD_NAME
    ).read_bytes()
    assert [asset.name for asset in first.record.assets] == sorted(expected)
    assert {asset.name for asset in first.record.assets} == expected
    assert first.record.repository_id == 123456
    assert first.record.repository == "stampbot/extra-codeowners"
    assert first.record.run_id == 777777
    assert first.record.tag == f"v{VERSION}"
    assert first.record.target_commit == REVISION
    assert first.record.workflow_path == ".github/workflows/release.yml"
    assert first.record.workflow_sha == REVISION
    for directory in (first.directory, second.directory):
        assert {path.name for path in directory.iterdir()} == {
            assembler.ASSET_DIRECTORY_NAME,
            assembler.RECORD_NAME,
        }
        assets = directory / assembler.ASSET_DIRECTORY_NAME
        assert {path.name for path in assets.iterdir()} == expected
        for path in (assets, directory):
            assert path.stat().st_mode & 0o777 == 0o700
        for path in (*assets.iterdir(), directory / assembler.RECORD_NAME):
            assert path.stat().st_mode & 0o777 == 0o600
            assert path.stat().st_nlink == 1
        assert assembler.load_candidate_record(directory / assembler.RECORD_NAME) == (first.record)
    assert len(fixture.verification_calls) == 2
    for call in fixture.verification_calls:
        assert isinstance(call["directory"], Path)
        assert call["directory"].name == "python-materialized"
        assert call["source_revision"] == REVISION
        assert call["wheel_sha256"] == fixture.identity.wheel_sha256
        assert call["selection_record_sha256"] == fixture.identity.selection_record_sha256


def test_assembles_one_real_five_file_python_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = make_fixture(tmp_path, monkeypatch, real_selection=True)

    result = assemble(fixture)

    assets = {asset.name: asset for asset in result.record.assets}
    assert assets[WHEEL_NAME].sha256 == fixture.identity.wheel_sha256
    assert assets["python-selection-record.json"].sha256 == fixture.identity.selection_record_sha256
    assert not fixture.verification_calls


def test_real_verifier_rejects_self_consistent_transport_with_wrong_arm_machine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = mismatched_arm_machine(make_fixture(tmp_path, monkeypatch, real_selection=True))

    with pytest.raises(assembler.AssemblyError, match=r"arm64 .*wrong target"):
        assemble(fixture)

    assert not tuple(fixture.output_parent.iterdir())


@pytest.mark.parametrize(
    ("source_name", "mutate", "message"),
    [
        (
            "image_security",
            lambda root: (root / "unexpected").write_bytes(b"unexpected\n"),
            "wrong exact file set",
        ),
        (
            "chart",
            lambda root: (root / f"extra-codeowners-{VERSION}.tgz").rename(
                root / f"EXTRA-codeowners-{VERSION}.tgz"
            ),
            "wrong exact file set",
        ),
        (
            "signed_python",
            lambda root: (root / f"{WHEEL_NAME}.sigstore.json").write_bytes(b""),
            "outside its size limit",
        ),
    ],
)
def test_rejects_extra_renamed_and_empty_inputs(
    fixture: Fixture,
    source_name: str,
    mutate: Callable[[Path], object],
    message: str,
) -> None:
    mutate(getattr(fixture, source_name))

    with pytest.raises(assembler.AssemblyError, match=message):
        assemble(fixture)

    assert not (fixture.output_parent / "plan").exists()
    assert not tuple(fixture.output_parent.iterdir())


def test_rejects_symlinked_and_hardlinked_inputs(fixture: Fixture) -> None:
    signature = fixture.signed_python / f"{WHEEL_NAME}.sigstore.json"
    retained = fixture.signed_python.parent / "retained-signature"
    retained.write_bytes(signature.read_bytes())
    signature.unlink()
    signature.symlink_to(retained)

    with pytest.raises(assembler.AssemblyError, match="cannot open"):
        assemble(fixture, output_name="symlink")

    signature.unlink()
    signature.hardlink_to(retained)
    with pytest.raises(assembler.AssemblyError, match="single-link regular file"):
        assemble(fixture, output_name="hardlink")
    assert not tuple(fixture.output_parent.iterdir())


def test_rejects_signed_archive_drift(fixture: Fixture) -> None:
    (fixture.signed_python / WHEEL_NAME).write_bytes(b"PK\x03\x04different-wheel")

    with pytest.raises(assembler.AssemblyError, match="differs from the raw spine"):
        assemble(fixture)

    assert not tuple(fixture.output_parent.iterdir())


def test_rejects_raw_spine_and_provider_digest_tampering(fixture: Fixture) -> None:
    spine = bytearray(fixture.spine.read_bytes())
    spine[-1] ^= 1
    fixture.spine.write_bytes(spine)
    changed = dataclasses.replace(fixture, spine_digest=sha256(fixture.spine))

    with pytest.raises(assembler.AssemblyError, match=r"provider digest|digest mismatch"):
        assemble(changed, output_name="spine-tamper")

    fixture.spine.write_bytes(bytes(spine[:-1]) + bytes([spine[-1] ^ 1]))
    wrong_provider = dataclasses.replace(fixture, spine_digest="f" * 64)
    with pytest.raises(assembler.AssemblyError, match="provider digest"):
        assemble(wrong_provider, output_name="provider-tamper")
    assert not tuple(fixture.output_parent.iterdir())


def test_rejects_architecture_revalidation_failure(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(*args: object, **kwargs: object) -> dict[str, object]:
        raise build_python_artifacts.BuildError("arm64 toolchain has the wrong target")

    monkeypatch.setattr(assembler.build_python_artifacts, "verify_selection", reject)

    with pytest.raises(assembler.AssemblyError, match="arm64 toolchain"):
        assemble(fixture)

    assert not tuple(fixture.output_parent.iterdir())


@pytest.mark.parametrize(
    "release_identity",
    [
        assembler.ReleaseIdentity(
            tag="v0.1.1",
            version=VERSION,
            workflow_path=".github/workflows/release.yml",
            workflow_sha=REVISION,
        ),
        assembler.ReleaseIdentity(
            tag=f"v{VERSION}",
            version=VERSION,
            workflow_path=".github/workflows/release.yml",
            workflow_sha="3" * 40,
        ),
    ],
)
def test_rejects_release_identity_disagreement(
    fixture: Fixture,
    release_identity: Any,
) -> None:
    with pytest.raises(assembler.AssemblyError, match="disagree"):
        assemble(fixture, release_identity=release_identity)
    assert not tuple(fixture.output_parent.iterdir())


def test_rejects_python_workflow_identity_disagreement(fixture: Fixture) -> None:
    identity = dataclasses.replace(fixture.identity, workflow_sha="4" * 40)

    with pytest.raises(assembler.AssemblyError, match="workflow SHA"):
        assemble(fixture, identity=identity)

    assert not tuple(fixture.output_parent.iterdir())


def test_rejects_unreviewed_release_workflow_path(fixture: Fixture) -> None:
    release_identity = assembler.ReleaseIdentity(
        tag=f"v{VERSION}",
        version=VERSION,
        workflow_path=".github/workflows/other.yml",
        workflow_sha=REVISION,
    )

    with pytest.raises(assembler.AssemblyError, match="reviewed tagged workflow"):
        assemble(fixture, release_identity=release_identity)

    assert not tuple(fixture.output_parent.iterdir())


@pytest.mark.parametrize("unsafe_kind", ["relative", "parent-traversal"])
def test_rejects_unsafe_output_path_before_normalizing(
    fixture: Fixture,
    unsafe_kind: str,
) -> None:
    output = (
        Path("relative-release-candidate")
        if unsafe_kind == "relative"
        else fixture.output_parent / "nested" / ".." / "plan"
    )

    with pytest.raises(assembler.AssemblyError, match="safe absolute child path"):
        assemble(fixture, output_directory=output)

    assert not tuple(fixture.output_parent.iterdir())


def test_never_replaces_existing_output(fixture: Fixture) -> None:
    output = fixture.output_parent / "plan"
    output.mkdir()
    marker = output / "keep"
    marker.write_text("keep\n", encoding="utf-8")

    with pytest.raises(assembler.AssemblyError, match="already exists"):
        assemble(fixture)

    assert marker.read_text(encoding="utf-8") == "keep\n"
    assert {path.name for path in fixture.output_parent.iterdir()} == {"plan"}


def test_rejects_input_changed_during_descriptor_copy(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = fixture.image_security / "image-sbom-linux-amd64.spdx.json"
    actual_pread = assembler.os.pread
    mutated = False

    def mutating_pread(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal mutated
        result = actual_pread(descriptor, size, offset)
        metadata = os.fstat(descriptor)
        if not mutated and metadata.st_ino == target.stat().st_ino and offset == 0 and result:
            mutated = True
            with target.open("ab") as stream:
                stream.write(b"changed\n")
        return cast(bytes, result)

    monkeypatch.setattr(assembler.os, "pread", mutating_pread)

    with pytest.raises(assembler.AssemblyError, match=r"trailing bytes|changed"):
        assemble(fixture)

    assert mutated
    assert not tuple(fixture.output_parent.iterdir())


def test_record_is_explicitly_non_publishable_and_not_a_controller_manifest(
    fixture: Fixture,
) -> None:
    result = assemble(fixture)
    path = result.directory / assembler.RECORD_NAME
    record = json.loads(path.read_text(encoding="utf-8"))

    assert record["schema_version"] == assembler.SCHEMA_VERSION
    assert record["media_type"] == assembler.RECORD_MEDIA_TYPE
    assert assembler.BLOCKING_ISSUES == (1, 18, 25, 28, 30, 32)
    assert set(record) == {
        "assets",
        "candidate",
        "identity",
        "media_type",
        "schema_version",
    }
    assert record["candidate"] == {
        "asset_count": assembler.EXPECTED_ASSET_COUNT,
        "asset_policy": assembler.ASSET_POLICY,
        "asset_scope": assembler.ASSET_SCOPE,
        "blocking_issues": list(assembler.BLOCKING_ISSUES),
        "controller_manifest": False,
        "final_asset_policy_frozen": False,
        "non_python_payload_semantics_verified": False,
        "publication_allowed": False,
        "source_completeness": False,
    }
    assert {
        "python-build-record-amd64.json",
        "python-build-record-arm64.json",
        "python-selection-record.json",
    }.issubset(asset["name"] for asset in record["assets"])
    with pytest.raises(release_controller.ControllerError, match="must contain exactly"):
        release_controller.validate_manifest(record, sha256(path))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("publication_allowed", True),
        ("source_completeness", True),
        ("final_asset_policy_frozen", True),
        ("controller_manifest", True),
        ("non_python_payload_semantics_verified", True),
        ("blocking_issues", [18, 25, 28, 32]),
    ],
)
def test_candidate_record_cannot_claim_release_readiness(
    fixture: Fixture,
    field: str,
    value: object,
) -> None:
    result = assemble(fixture)
    path = result.directory / assembler.RECORD_NAME
    record = json.loads(path.read_text(encoding="utf-8"))
    record["candidate"][field] = value

    with pytest.raises(assembler.AssemblyError, match="not publication-blocked"):
        assembler.validate_candidate_record(record, sha256(path))


@pytest.mark.parametrize("invalid_issue", [True, 1.0])
def test_candidate_record_rejects_non_integer_blocking_issue(
    fixture: Fixture,
    invalid_issue: object,
) -> None:
    result = assemble(fixture)
    path = result.directory / assembler.RECORD_NAME
    record = json.loads(path.read_text(encoding="utf-8"))
    record["candidate"]["blocking_issues"][0] = invalid_issue
    content = python_distribution_spine.canonical_json(record)

    with pytest.raises(assembler.AssemblyError, match="integer bounds"):
        assembler.validate_candidate_record(record, sha256_bytes(content))


def test_candidate_record_loader_rejects_boolean_blocking_issue(
    fixture: Fixture,
) -> None:
    result = assemble(fixture)
    record = json.loads((result.directory / assembler.RECORD_NAME).read_text(encoding="utf-8"))
    record["candidate"]["blocking_issues"][0] = True
    path = result.directory / "boolean-blocker.json"
    path.write_bytes(python_distribution_spine.canonical_json(record))
    path.chmod(0o600)

    with pytest.raises(assembler.AssemblyError, match="integer bounds"):
        assembler.load_candidate_record(path)


@pytest.mark.parametrize(
    "invalid_count",
    [True, float(assembler.EXPECTED_ASSET_COUNT)],
)
def test_candidate_record_rejects_non_integer_asset_count(
    fixture: Fixture,
    invalid_count: object,
) -> None:
    result = assemble(fixture)
    path = result.directory / assembler.RECORD_NAME
    record = json.loads(path.read_text(encoding="utf-8"))
    record["candidate"]["asset_count"] = invalid_count
    content = python_distribution_spine.canonical_json(record)

    with pytest.raises(assembler.AssemblyError, match=r"asset count.*integer bounds"):
        assembler.validate_candidate_record(record, sha256_bytes(content))


def test_candidate_record_loader_rejects_boolean_asset_count(
    fixture: Fixture,
) -> None:
    result = assemble(fixture)
    record = json.loads((result.directory / assembler.RECORD_NAME).read_text(encoding="utf-8"))
    record["candidate"]["asset_count"] = True
    path = result.directory / "boolean-asset-count.json"
    path.write_bytes(python_distribution_spine.canonical_json(record))
    path.chmod(0o600)

    with pytest.raises(assembler.AssemblyError, match=r"asset count.*integer bounds"):
        assembler.load_candidate_record(path)


def test_candidate_record_rejects_boolean_schema_version(fixture: Fixture) -> None:
    result = assemble(fixture)
    path = result.directory / assembler.RECORD_NAME
    record = json.loads(path.read_text(encoding="utf-8"))
    record["schema_version"] = True

    with pytest.raises(assembler.AssemblyError, match="schema version"):
        assembler.validate_candidate_record(record, sha256(path))


def test_candidate_record_binds_its_canonical_digest(fixture: Fixture) -> None:
    result = assemble(fixture)
    path = result.directory / assembler.RECORD_NAME
    record = json.loads(path.read_text(encoding="utf-8"))

    with pytest.raises(assembler.AssemblyError, match="supplied SHA-256"):
        assembler.validate_candidate_record(record, "f" * 64)


def test_rejects_aggregate_size_before_copying_assets(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(assembler, "MAX_TOTAL_ASSET_BYTES", 1)
    copies = 0
    actual_copy = assembler._copy_retained

    def observed_copy(*args: object, **kwargs: object) -> Any:
        nonlocal copies
        copies += 1
        return actual_copy(*args, **kwargs)

    monkeypatch.setattr(assembler, "_copy_retained", observed_copy)

    with pytest.raises(assembler.AssemblyError, match="total size limit"):
        assemble(fixture)

    assert copies == 0
    assert not tuple(fixture.output_parent.iterdir())


def test_candidate_record_loader_rejects_duplicate_keys_and_noncanonical_json(
    fixture: Fixture,
) -> None:
    result = assemble(fixture)
    canonical = result.directory / assembler.RECORD_NAME
    duplicate = result.directory / "duplicate.json"
    duplicate.write_bytes(
        canonical.read_bytes().replace(
            b'{"assets":',
            b'{"schema_version":1,"assets":',
            1,
        )
    )
    noncanonical = result.directory / "noncanonical.json"
    value = json.loads(canonical.read_text(encoding="utf-8"))
    noncanonical.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(assembler.AssemblyError, match="strict canonical JSON"):
        assembler.load_candidate_record(duplicate)
    with pytest.raises(assembler.AssemblyError, match="strict canonical JSON"):
        assembler.load_candidate_record(noncanonical)


def test_release_workflow_keeps_candidate_unprivileged_blocked_and_unconsumed() -> None:
    source = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    candidate = source.split("  release-asset-candidate:\n", 1)[1].split(
        "\n  release:\n",
        1,
    )[0]
    release = source.split("\n  release:\n", 1)[1]
    blocker = source.split("  publication-block:\n", 1)[1].split("\n  python:\n", 1)[0]

    assert "      - publication-block\n" in candidate
    assert "      - python-distribution-proof\n" in candidate
    assert "      contents: read\n" in candidate
    assert "contents: write" not in candidate
    for authority in (
        "attestations: write",
        "id-token: write",
        "packages: write",
        "GH_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST",
    ):
        assert authority not in candidate
    assert ".github/scripts/release_asset_assembler.py" in candidate
    assert "release_controller.py" not in candidate
    assert "github_release_api.py" not in candidate
    assert "gh release" not in candidate
    assert "docker.sock" not in candidate
    assert "find " not in candidate
    assert (
        "artifact-ids: ${{ needs.python-distribution-proof.outputs.spine-artifact-id }}"
        in candidate
    )
    assert (
        "artifact-ids: ${{ needs.python-distribution-proof.outputs.record-artifact-id }}"
        in candidate
    )
    assert "RECORD_ARTIFACT_DIGEST" in candidate
    assert "SPINE_ARTIFACT_DIGEST" in candidate
    assert candidate.count("digest-mismatch: error") == 5
    assert "RELEASE_WORKFLOW_SHA: ${{ github.workflow_sha }}" in candidate
    assert "--release-workflow-path .github/workflows/release.yml" in candidate
    assert "name: blocked-release-asset-candidate" in candidate

    assert "blocked-release-asset-candidate" not in release
    assert assembler.RECORD_NAME not in release
    assert "release_asset_assembler.py" not in release
    assert "release_controller.py" not in release
    assert "      - publication-block\n" in release
    assert "permissions: {}\n" in blocker
    assert "exit 1" in blocker


def test_assembler_is_in_every_strict_typecheck_and_test_image() -> None:
    path = ".github/scripts/release_asset_assembler.py"
    for source_path in (
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / ".github" / "workflows" / "release.yml",
        ROOT / "mise.toml",
    ):
        assert path in source_path.read_text(encoding="utf-8")
    assert f"!{path}" in (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert path in (ROOT / "Dockerfile").read_text(encoding="utf-8")
