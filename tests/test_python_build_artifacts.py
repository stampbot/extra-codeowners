"""Adversarial tests for the hash-constrained Python artifact builder."""

from __future__ import annotations

import copy
import csv
import gzip
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "extra-codeowners"
PROJECT_VERSION = "0.1.0"
WHEEL_NAME = "extra_codeowners-0.1.0-py3-none-any.whl"
DIST_INFO = "extra_codeowners-0.1.0.dist-info"
SDIST_POLICY = {
    "pyproject.toml": b"[build-system]\nrequires = ['hatchling==1.31.0']\n",
    "requirements-build.txt": b"hatchling==1.31.0\n",
}
ENTRY_POINTS = b"[console_scripts]\nextra-codeowners = extra_codeowners.cli:main\n"
PROOF_REVISION = "1" * 40


def load_script() -> ModuleType:
    path = ROOT / ".github" / "scripts" / "build_python_artifacts.py"
    spec = importlib.util.spec_from_file_location("build_python_artifacts", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


build = load_script()


def run_git(repo: Path, *arguments: str) -> str:
    git = shutil.which("git")
    assert git is not None
    result = subprocess.run(  # noqa: S603 - fixed executable with test-controlled arguments
        [git, *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def initialize_git_source(repo: Path) -> None:
    repo.mkdir()
    run_git(repo, "init", "--quiet")
    run_git(repo, "config", "user.email", "tests@example.invalid")
    run_git(repo, "config", "user.name", "Tests")
    run_git(repo, "config", "commit.gpgsign", "false")


def csv_bytes(rows: list[tuple[str, str, str]]) -> bytes:
    destination = io.StringIO(newline="")
    csv.writer(destination, lineterminator="\n").writerows(rows)
    return destination.getvalue().encode()


def write_wheel(
    path: Path,
    *,
    timestamp: tuple[int, int, int, int, int, int] = (2026, 1, 2, 3, 4, 6),
    wheel_metadata: bytes | None = None,
    additions: Mapping[str, bytes] | None = None,
    tamper_after_record: Mapping[str, bytes] | None = None,
    modes: Mapping[str, int] | None = None,
    omit_record: bool = False,
    duplicate: str | None = None,
) -> None:
    files = {
        "extra_codeowners/__init__.py": b'__version__ = "0.1.0"\n',
        f"{DIST_INFO}/METADATA": (
            b"Metadata-Version: 2.4\nName: extra-codeowners\nVersion: 0.1.0\n\n"
        ),
        f"{DIST_INFO}/WHEEL": wheel_metadata
        or (
            b"Wheel-Version: 1.0\n"
            b"Generator: hatchling 1.31.0\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
            b"\n"
        ),
    }
    files.update(additions or {})
    record_name = f"{DIST_INFO}/RECORD"
    rows = [
        (name, f"sha256={build.record_digest(content)}", str(len(content)))
        for name, content in sorted(files.items())
    ]
    rows.append((record_name, "", ""))
    if not omit_record:
        files[record_name] = csv_bytes(rows)
    files.update(tamper_after_record or {})

    with zipfile.ZipFile(path, "w") as archive:
        entries = list(files.items())
        if duplicate is not None:
            entries.append((duplicate, files[duplicate]))
        for name, content in entries:
            member = zipfile.ZipInfo(name, date_time=timestamp)
            member.create_system = 3
            mode = (modes or {}).get(name, stat.S_IFREG | 0o644)
            member.external_attr = (mode & 0xFFFF) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, content)


def sdist_files() -> dict[str, bytes]:
    root = "extra_codeowners-0.1.0"
    return {
        f"{root}/LICENSE": b"Apache-2.0\n",
        f"{root}/PKG-INFO": (b"Metadata-Version: 2.4\nName: extra-codeowners\nVersion: 0.1.0\n\n"),
        f"{root}/README.md": b"# Extra CODEOWNERS\n",
        f"{root}/pyproject.toml": SDIST_POLICY["pyproject.toml"],
        f"{root}/requirements-build.txt": SDIST_POLICY["requirements-build.txt"],
        f"{root}/extra_codeowners/__init__.py": b"",
    }


def write_sdist(
    path: Path,
    *,
    files: Mapping[str, bytes] | None = None,
    member_mtime: int = 1_700_000_000,
    gzip_mtime: int = 1_700_000_000,
    links: Mapping[str, str] | None = None,
) -> None:
    uncompressed = io.BytesIO()
    with tarfile.open(fileobj=uncompressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, content in (files or sdist_files()).items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644
            member.mtime = member_mtime
            archive.addfile(member, io.BytesIO(content))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            member.mode = 0o777
            member.mtime = member_mtime
            archive.addfile(member)
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=gzip_mtime) as archive:
        archive.write(uncompressed.getvalue())
    path.write_bytes(compressed.getvalue())


def write_installed_record(
    root: Path,
    wheel_path: Path,
    wheel: Any,
    *,
    digest_override: str | None = None,
    extra_rows: list[tuple[str, str, str]] | None = None,
) -> Path:
    site_packages = root / "lib" / "python3.12" / "site-packages"
    dist_info_name = cast(str, wheel.dist_info)
    dist_info = site_packages / dist_info_name
    dist_info.mkdir(parents=True)
    rows: list[tuple[str, str, str]] = []
    with zipfile.ZipFile(wheel_path) as archive:
        payloads = {
            member.filename: archive.read(member)
            for member in archive.infolist()
            if not member.is_dir()
        }
    wheel_record = f"{dist_info_name}/RECORD"
    for index, (name, content) in enumerate(sorted(payloads.items())):
        if name == wheel_record:
            continue
        destination = site_packages / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        digest = f"sha256={build.record_digest(content)}"
        if digest_override is not None and index == 0:
            digest = digest_override
        rows.append((name, digest, str(len(content))))
    for name, module, callable_name in wheel.scripts:
        raw_path = f"../../../bin/{name}"
        destination = root / "bin" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = build.expected_launcher(root, module, callable_name)
        destination.write_bytes(content)
        destination.chmod(0o755)
        rows.append((raw_path, f"sha256={build.record_digest(content)}", str(len(content))))
    rows.append((wheel_record, "", ""))
    rows.extend(extra_rows or [])
    record = dist_info / "RECORD"
    record.write_bytes(csv_bytes(rows))
    return record


def installed_wheel(tmp_path: Path) -> tuple[Path, Any]:
    wheel_path = tmp_path / WHEEL_NAME
    write_wheel(
        wheel_path,
        additions={
            "extra_codeowners/cli.py": b"def main():\n    return 0\n",
            f"{DIST_INFO}/entry_points.txt": ENTRY_POINTS,
        },
    )
    return wheel_path, build.verify_wheel(
        wheel_path, expected_name=PROJECT_NAME, expected_version=PROJECT_VERSION
    )


def write_distribution_proof(
    directory: Path,
    architecture: str,
    *,
    source_revision: str = PROOF_REVISION,
) -> dict[str, object]:
    """Write one small but fully valid canonical native-build proof fixture."""

    directory.mkdir()
    wheel_path = directory / WHEEL_NAME
    write_wheel(
        wheel_path,
        additions={
            "extra_codeowners/cli.py": b"def main():\n    return 0\n",
            f"{DIST_INFO}/entry_points.txt": ENTRY_POINTS,
        },
    )
    policy = {
        "pyproject.toml": (ROOT / "pyproject.toml").read_bytes(),
        "requirements-build.txt": (ROOT / "requirements-build.txt").read_bytes(),
    }
    files = sdist_files()
    root = "extra_codeowners-0.1.0"
    files[f"{root}/pyproject.toml"] = policy["pyproject.toml"]
    files[f"{root}/requirements-build.txt"] = policy["requirements-build.txt"]
    sdist_path = directory / "extra_codeowners-0.1.0.tar.gz"
    write_sdist(sdist_path, files=files)

    requirements = build.parse_build_constraints(ROOT / "requirements-build.txt")
    project = build.validate_project(ROOT / "pyproject.toml", requirements)
    wheel = build.verify_wheel(
        wheel_path, expected_name=PROJECT_NAME, expected_version=PROJECT_VERSION
    )
    sdist = build.verify_sdist(
        sdist_path,
        expected_name=PROJECT_NAME,
        expected_version=PROJECT_VERSION,
        expected_policy=policy,
    )
    machine = build.ARCHITECTURE_MACHINES[architecture]
    record: dict[str, object] = {
        "schema_version": build.SCHEMA_VERSION,
        "source_revision": source_revision,
        "source_dirty": False,
        "source_date_epoch": 1_700_000_000,
        "source_tree": {
            "blob_count": 100,
            "byte_count": 1_000_000,
            "identity_sha256": "2" * 64,
        },
        "project": project,
        "toolchain": {
            "uv": f"uv 0.11.28 ({machine}-unknown-linux-gnu)",
            "uv_version": "0.11.28",
            "python": "3.14.6",
            "python_implementation": "CPython",
            "python_major_minor": "3.14",
            "python_machine": machine,
        },
        "build_constraints": {
            "path": "requirements-build.txt",
            "sha256": build.sha256_bytes(policy["requirements-build.txt"]),
            "requirements": [requirement.record() for requirement in requirements],
        },
        "artifacts": {"sdist": sdist.record, "wheel": wheel.record},
        "reproducibility": {
            "clean_build_count": 2,
            "byte_identical": True,
            "semantic_identity_checked": True,
        },
    }
    build.write_record(directory / build.BUILD_RECORD_NAME, record)
    return record


def replace_proof_record(directory: Path, record: Mapping[str, object]) -> None:
    build.write_record(directory / build.BUILD_RECORD_NAME, record)


def test_reviewed_build_constraints_and_project_pin_are_bound_together() -> None:
    requirements = build.parse_build_constraints(ROOT / "requirements-build.txt")
    assert [requirement.name for requirement in requirements] == [
        "hatchling",
        "packaging",
        "pathspec",
        "pluggy",
        "trove-classifiers",
    ]
    assert all(len(requirement.hashes) == 2 for requirement in requirements)
    project = build.validate_project(ROOT / "pyproject.toml", requirements)
    assert project == {
        "name": PROJECT_NAME,
        "version": PROJECT_VERSION,
        "build_backend": "hatchling.build",
        "build_requirement": "hatchling==1.31.0",
        "requires_python": ">=3.12",
    }


def test_materialized_source_uses_only_exact_git_blobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    initialize_git_source(repo)
    package = repo / "extra_codeowners"
    package.mkdir()
    source = package / "app.py"
    source.write_text("REV = '$Format:%H$'\n", encoding="utf-8")
    executable = package / "entrypoint"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    (repo / ".gitattributes").write_text(
        "extra_codeowners/app.py export-subst\nextra_codeowners/entrypoint export-ignore\n",
        encoding="utf-8",
    )
    (repo / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "--quiet", "-m", "fixture")
    revision = run_git(repo, "rev-parse", "HEAD")

    source.write_text("ambient tracked change\n", encoding="utf-8")
    ignored = repo / "ignored" / "ambient.txt"
    ignored.parent.mkdir()
    ignored.write_text("must not enter the build\n", encoding="utf-8")
    (repo / "untracked.txt").write_text("must not enter the build\n", encoding="utf-8")
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    fake_git.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))

    entries = build.git_source_entries(repo, revision)
    destination = tmp_path / "source"
    build.materialize_git_source(repo, destination, entries)

    assert (destination / "extra_codeowners" / "app.py").read_bytes() == (b"REV = '$Format:%H$'\n")
    assert (destination / "extra_codeowners" / "entrypoint").read_bytes() == b"#!/bin/sh\n"
    assert not (destination / "ignored").exists()
    assert not (destination / "untracked.txt").exists()
    assert stat.S_IMODE((destination / "extra_codeowners" / "app.py").stat().st_mode) == 0o600
    assert stat.S_IMODE((destination / "extra_codeowners" / "entrypoint").stat().st_mode) == 0o700
    tree_record = build.source_tree_record(entries)
    assert tree_record["blob_count"] == 4
    assert tree_record["byte_count"] == sum(entry.size for entry in entries)
    assert re.fullmatch(r"[0-9a-f]{64}", cast(str, tree_record["identity_sha256"]))
    build.verify_materialized_git_source(repo, destination, entries)
    backend_output = destination / "ambient-backend-output"
    backend_output.write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(build.BuildError, match="backend added"):
        build.verify_materialized_git_source(repo, destination, entries)
    backend_output.unlink()
    (destination / "ambient-backend-directory").mkdir(mode=0o700)
    with pytest.raises(build.BuildError, match="backend added a source-tree directory"):
        build.verify_materialized_git_source(repo, destination, entries)


def test_git_source_tree_rejects_symlinks(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    initialize_git_source(repo)
    (repo / "target").write_text("target\n", encoding="utf-8")
    (repo / "link").symlink_to("target")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "--quiet", "-m", "fixture")
    revision = run_git(repo, "rev-parse", "HEAD")

    with pytest.raises(build.BuildError, match="not a regular portable blob: link"):
        build.git_source_entries(repo, revision)


@pytest.mark.parametrize(
    ("listing", "message"),
    [
        (
            f"160000 commit {'0' * 40} -\tvendor\0",
            "not a regular portable blob: vendor",
        ),
        (
            f"100644 blob {'0' * 40} 0\t{'a' * (build.MAX_SOURCE_PATH_BYTES + 1)}\0",
            "path exceeds its size limit",
        ),
    ],
)
def test_git_source_listing_rejects_gitlinks_and_oversized_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    listing: str,
    message: str,
) -> None:
    monkeypatch.setattr(build, "run_command", lambda *args, **kwargs: listing)
    with pytest.raises(build.BuildError, match=message):
        build.git_source_entries(tmp_path, "0" * 40)


def test_selects_and_reverifies_exact_native_distribution_proofs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    amd64 = tmp_path / "amd64"
    arm64 = tmp_path / "arm64"
    write_distribution_proof(amd64, "amd64")
    write_distribution_proof(arm64, "arm64")
    output = tmp_path / "selected"

    result = build.select_distributions(
        amd64,
        arm64,
        source_revision=PROOF_REVISION,
        output=output,
    )

    assert {path.name for path in output.iterdir()} == {
        build.SELECTED_BUILD_RECORD_NAMES["amd64"],
        build.SELECTED_BUILD_RECORD_NAMES["arm64"],
        build.SELECTION_RECORD_NAME,
        WHEEL_NAME,
        "extra_codeowners-0.1.0.tar.gz",
    }
    assert (output / WHEEL_NAME).read_bytes() == (amd64 / WHEEL_NAME).read_bytes()
    assert (output / "extra_codeowners-0.1.0.tar.gz").read_bytes() == (
        amd64 / "extra_codeowners-0.1.0.tar.gz"
    ).read_bytes()
    selection_path = output / build.SELECTION_RECORD_NAME
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    assert selection_path.read_bytes() == build.canonical_json(selection) + b"\n"
    assert selection["selected_architecture"] == "amd64"
    assert selection["proofs"]["amd64"]["record_sha256"] == build.sha256_file(
        output / build.SELECTED_BUILD_RECORD_NAMES["amd64"]
    )
    assert selection["proofs"]["arm64"]["record_sha256"] == build.sha256_file(
        output / build.SELECTED_BUILD_RECORD_NAMES["arm64"]
    )
    assert result["wheel_sha256"] == build.sha256_file(output / WHEEL_NAME)

    monkeypatch.setattr(
        build,
        "git_executable",
        lambda: (_ for _ in ()).throw(AssertionError("verify-selection consulted Git")),
    )
    assert (
        build.verify_selection(
            output,
            source_revision=PROOF_REVISION,
            wheel_sha256=cast(str, result["wheel_sha256"]),
        )
        == result
    )


def test_proof_directory_rejects_missing_extra_symlink_and_noncanonical_files(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    write_distribution_proof(missing, "amd64")
    (missing / WHEEL_NAME).unlink()
    with pytest.raises(build.BuildError, match="exactly 3 files"):
        build.load_distribution_proof(
            missing,
            architecture="amd64",
            expected_source_revision=PROOF_REVISION,
        )

    extra = tmp_path / "extra"
    write_distribution_proof(extra, "amd64")
    (extra / "unexpected").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(build.BuildError, match="exactly 3 files"):
        build.load_distribution_proof(
            extra,
            architecture="amd64",
            expected_source_revision=PROOF_REVISION,
        )

    linked = tmp_path / "linked"
    write_distribution_proof(linked, "amd64")
    record = linked / build.BUILD_RECORD_NAME
    retained = tmp_path / "retained-record.json"
    retained.write_bytes(record.read_bytes())
    record.unlink()
    record.symlink_to(retained)
    with pytest.raises(build.BuildError, match="non-symlink regular file"):
        build.load_distribution_proof(
            linked,
            architecture="amd64",
            expected_source_revision=PROOF_REVISION,
        )

    noncanonical = tmp_path / "noncanonical"
    proof = write_distribution_proof(noncanonical, "amd64")
    (noncanonical / build.BUILD_RECORD_NAME).write_text(
        json.dumps(proof, indent=2) + "\n", encoding="utf-8"
    )
    with pytest.raises(build.BuildError, match="not canonical JSON"):
        build.load_distribution_proof(
            noncanonical,
            architecture="amd64",
            expected_source_revision=PROOF_REVISION,
        )

    wrong_schema = tmp_path / "wrong-schema"
    schema_record = write_distribution_proof(wrong_schema, "amd64")
    schema_record["schema_version"] = True
    replace_proof_record(wrong_schema, schema_record)
    with pytest.raises(build.BuildError, match="wrong schema version"):
        build.load_distribution_proof(
            wrong_schema,
            architecture="amd64",
            expected_source_revision=PROOF_REVISION,
        )


def test_select_rejects_swapped_architectures_and_source_drift(tmp_path: Path) -> None:
    amd64 = tmp_path / "amd64"
    arm64 = tmp_path / "arm64"
    write_distribution_proof(amd64, "amd64")
    write_distribution_proof(arm64, "arm64")

    with pytest.raises(build.BuildError, match=r"amd64 .*wrong target"):
        build.select_distributions(
            arm64,
            amd64,
            source_revision=PROOF_REVISION,
            output=tmp_path / "swapped",
        )
    with pytest.raises(build.BuildError, match="wrong source revision"):
        build.select_distributions(
            amd64,
            arm64,
            source_revision="3" * 40,
            output=tmp_path / "wrong-source",
        )


def test_select_rejects_unreviewed_toolchain_and_source_tree_differences(
    tmp_path: Path,
) -> None:
    amd64 = tmp_path / "amd64"
    arm64 = tmp_path / "arm64"
    write_distribution_proof(amd64, "amd64")
    arm_record = write_distribution_proof(arm64, "arm64")
    changed_toolchain = copy.deepcopy(arm_record)
    cast(dict[str, object], changed_toolchain["toolchain"])["python"] = "3.14.7"
    replace_proof_record(arm64, changed_toolchain)
    with pytest.raises(build.BuildError, match="outside reviewed toolchain fields"):
        build.select_distributions(
            amd64,
            arm64,
            source_revision=PROOF_REVISION,
            output=tmp_path / "toolchain-drift",
        )

    replace_proof_record(arm64, arm_record)
    changed_source = copy.deepcopy(arm_record)
    cast(dict[str, object], changed_source["source_tree"])["identity_sha256"] = "4" * 64
    replace_proof_record(arm64, changed_source)
    with pytest.raises(build.BuildError, match="outside reviewed toolchain fields"):
        build.select_distributions(
            amd64,
            arm64,
            source_revision=PROOF_REVISION,
            output=tmp_path / "source-tree-drift",
        )


@pytest.mark.parametrize("archive_name", [WHEEL_NAME, "extra_codeowners-0.1.0.tar.gz"])
def test_select_rejects_altered_archives(tmp_path: Path, archive_name: str) -> None:
    amd64 = tmp_path / "amd64"
    arm64 = tmp_path / "arm64"
    write_distribution_proof(amd64, "amd64")
    write_distribution_proof(arm64, "arm64")
    archive = arm64 / archive_name
    archive.write_bytes(archive.read_bytes() + b"tampered")

    with pytest.raises(build.BuildError, match="artifact record differs"):
        build.select_distributions(
            amd64,
            arm64,
            source_revision=PROOF_REVISION,
            output=tmp_path / "altered",
        )


def test_select_rejects_preexisting_output_and_verify_binds_expected_values(
    tmp_path: Path,
) -> None:
    amd64 = tmp_path / "amd64"
    arm64 = tmp_path / "arm64"
    write_distribution_proof(amd64, "amd64")
    write_distribution_proof(arm64, "arm64")
    output = tmp_path / "selected"
    output.mkdir()
    with pytest.raises(build.BuildError, match="output directory must be absent"):
        build.select_distributions(
            amd64,
            arm64,
            source_revision=PROOF_REVISION,
            output=output,
        )

    output.rmdir()
    result = build.select_distributions(
        amd64,
        arm64,
        source_revision=PROOF_REVISION,
        output=output,
    )
    with pytest.raises(build.BuildError, match="wrong source revision"):
        build.verify_selection(
            output,
            source_revision="3" * 40,
            wheel_sha256=cast(str, result["wheel_sha256"]),
        )
    with pytest.raises(build.BuildError, match="expected digest"):
        build.verify_selection(
            output,
            source_revision=PROOF_REVISION,
            wheel_sha256="5" * 64,
        )
    selected_arm_record = output / build.SELECTED_BUILD_RECORD_NAMES["arm64"]
    retained_arm_record = selected_arm_record.read_bytes()
    selected_arm_record.write_bytes(
        (output / build.SELECTED_BUILD_RECORD_NAMES["amd64"]).read_bytes()
    )
    with pytest.raises(build.BuildError, match=r"arm64 .*wrong target"):
        build.verify_selection(
            output,
            source_revision=PROOF_REVISION,
            wheel_sha256=cast(str, result["wheel_sha256"]),
        )
    selected_arm_record.write_bytes(retained_arm_record)
    selection_path = output / build.SELECTION_RECORD_NAME
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    selection_path.write_text(json.dumps(selection, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(build.BuildError, match="not canonical JSON"):
        build.verify_selection(
            output,
            source_revision=PROOF_REVISION,
            wheel_sha256=cast(str, result["wheel_sha256"]),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.replace("hatchling==", "hatchling~=", 1), "exact pin"),
        (
            lambda value: value.replace("--only-binary=:all:", "--index-url=https://example.test"),
            "only-binary",
        ),
        (
            lambda value: value.replace("hatchling==1.31.0", "zatchling==1.31.0", 1),
            "sorted",
        ),
        (
            lambda value: value.replace("pathspec==1.1.1", "packaging2==1.1.1", 1),
            "reviewed backend closure",
        ),
    ],
)
def test_build_constraints_reject_policy_drift(tmp_path: Path, mutation: Any, message: str) -> None:
    source = (ROOT / "requirements-build.txt").read_text(encoding="utf-8")
    candidate = tmp_path / "requirements-build.txt"
    candidate.write_text(cast(Any, mutation)(source), encoding="utf-8")
    with pytest.raises(build.BuildError, match=message):
        build.parse_build_constraints(candidate)


def test_build_constraints_reject_a_missing_or_reused_hash(tmp_path: Path) -> None:
    source = (ROOT / "requirements-build.txt").read_text(encoding="utf-8")
    first, second = cast(list[str], build.HASH_OPTION.findall(source))[:2]
    candidate = tmp_path / "requirements-build.txt"
    candidate.write_text(source.replace(second, first, 1), encoding="utf-8")
    with pytest.raises(build.BuildError, match="two unique, sorted"):
        build.parse_build_constraints(candidate)


def test_project_rejects_build_pin_and_python_policy_drift(tmp_path: Path) -> None:
    requirements = build.parse_build_constraints(ROOT / "requirements-build.txt")
    source = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project = tmp_path / "pyproject.toml"
    project.write_text(source.replace("hatchling==1.31.0", "hatchling>=1.31.0"), encoding="utf-8")
    with pytest.raises(build.BuildError, match="Hatchling pin"):
        build.validate_project(project, requirements)
    project.write_text(
        source.replace('requires-python = ">=3.12"', 'requires-python = ">=3.13"'), encoding="utf-8"
    )
    with pytest.raises(build.BuildError, match="requires-python"):
        build.validate_project(project, requirements)

    project.write_text(
        source.replace(
            'build-backend = "hatchling.build"',
            'build-backend = "hatchling.build"\nbackend-path = ["."]',
        ),
        encoding="utf-8",
    )
    with pytest.raises(build.BuildError, match="may only declare"):
        build.validate_project(project, requirements)

    project.write_text(
        source + '\n[tool.hatch.build.hooks.custom]\npath = "build_hook.py"\n',
        encoding="utf-8",
    )
    with pytest.raises(build.BuildError, match="build hooks"):
        build.validate_project(project, requirements)

    project.write_text(
        source + '\n[tool.hatch.metadata.hooks.custom]\npath = "metadata_hook.py"\n',
        encoding="utf-8",
    )
    with pytest.raises(build.BuildError, match="build hooks"):
        build.validate_project(project, requirements)


def test_valid_wheel_has_verified_identity_and_exact_record(tmp_path: Path) -> None:
    wheel = tmp_path / WHEEL_NAME
    write_wheel(wheel)
    result = build.verify_wheel(wheel, expected_name=PROJECT_NAME, expected_version=PROJECT_VERSION)
    assert result.record["project"] == PROJECT_NAME
    assert result.record["version"] == PROJECT_VERSION
    assert result.record["generator"] == "hatchling 1.31.0"
    assert result.record["member_count"] == 4


@pytest.mark.parametrize(
    ("configuration", "message"),
    [
        ({"tamper_after_record": {"extra_codeowners/__init__.py": b"changed\n"}}, "RECORD"),
        ({"additions": {"../escape": b"bad\n"}}, "unsafe member"),
        ({"additions": {"extra_codeowners/cache.pyc": b"bytecode"}}, "generated bytecode"),
        ({"additions": {f"{DIST_INFO}/INSTALLER": b"uv\n"}}, "installer metadata"),
        (
            {"additions": {"foreign-9.0.dist-info/METADATA": b"Name: foreign\nVersion: 9\n\n"}},
            "dist-info identity",
        ),
        ({"additions": {"extra_codeowners-0.1.0.data/data/file": b"data"}}, "data directory"),
        ({"omit_record": True}, "filename-bound WHEEL and RECORD"),
    ],
)
def test_wheel_rejects_hostile_or_unowned_members(
    tmp_path: Path, configuration: dict[str, Any], message: str
) -> None:
    wheel = tmp_path / WHEEL_NAME
    write_wheel(wheel, **configuration)
    with pytest.raises(build.BuildError, match=message):
        build.verify_wheel(wheel)


def test_wheel_rejects_duplicates_links_and_tag_drift(tmp_path: Path) -> None:
    wheel = tmp_path / WHEEL_NAME
    with pytest.warns(UserWarning, match="Duplicate name"):
        write_wheel(wheel, duplicate="extra_codeowners/__init__.py")
    with pytest.raises(build.BuildError, match="repeats member"):
        build.verify_wheel(wheel)

    link_name = "extra_codeowners/link.py"
    write_wheel(
        wheel,
        additions={link_name: b"target.py"},
        modes={link_name: stat.S_IFLNK | 0o777},
    )
    with pytest.raises(build.BuildError, match="non-regular member"):
        build.verify_wheel(wheel)

    write_wheel(
        wheel,
        modes={"extra_codeowners/__init__.py": stat.S_IFDIR | 0o755},
    )
    with pytest.raises(build.BuildError, match="non-regular member"):
        build.verify_wheel(wheel)

    write_wheel(
        wheel,
        additions={"extra_codeowners/": b""},
        modes={"extra_codeowners/": stat.S_IFREG | 0o644},
    )
    with pytest.raises(build.BuildError, match="non-directory type"):
        build.verify_wheel(wheel)

    write_wheel(
        wheel,
        wheel_metadata=(
            b"Wheel-Version: 1.0\n"
            b"Generator: hatchling 1.31.0\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: cp312-cp312-manylinux_2_17_x86_64\n\n"
        ),
    )
    with pytest.raises(build.BuildError, match="py3-none-any"):
        build.verify_wheel(wheel)


def test_artifact_verifiers_reject_symlink_and_fifo_inputs_without_opening_them(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target" / WHEEL_NAME
    target.parent.mkdir()
    write_wheel(target)
    linked = tmp_path / "linked" / WHEEL_NAME
    linked.parent.mkdir()
    linked.symlink_to(target)
    with pytest.raises(build.BuildError, match="non-symlink regular file"):
        build.verify_wheel(linked)

    fifo = tmp_path / "fifo" / WHEEL_NAME
    fifo.parent.mkdir()
    os.mkfifo(fifo)
    with pytest.raises(build.BuildError, match="non-symlink regular file"):
        build.verify_wheel(fifo)


def test_reproducibility_diagnoses_archive_metadata_and_content_drift(tmp_path: Path) -> None:
    first = tmp_path / "first" / WHEEL_NAME
    second = tmp_path / "second" / WHEEL_NAME
    first.parent.mkdir()
    second.parent.mkdir()
    write_wheel(first, timestamp=(2026, 1, 2, 3, 4, 6))
    write_wheel(second, timestamp=(2026, 1, 2, 3, 4, 8))
    with pytest.raises(build.BuildError, match="bytes differ while semantic contents match"):
        build.require_reproducible(first, second, build.verify_wheel, "wheel")

    write_wheel(
        second,
        timestamp=(2026, 1, 2, 3, 4, 6),
        additions={"extra_codeowners/new.py": b"new\n"},
    )
    with pytest.raises(build.BuildError, match="semantic contents differ"):
        build.require_reproducible(first, second, build.verify_wheel, "wheel")


def test_valid_sdist_and_archive_metadata_drift(tmp_path: Path) -> None:
    first = tmp_path / "first" / "extra_codeowners-0.1.0.tar.gz"
    second = tmp_path / "second" / "extra_codeowners-0.1.0.tar.gz"
    first.parent.mkdir()
    second.parent.mkdir()
    write_sdist(first, member_mtime=10, gzip_mtime=10)
    write_sdist(second, member_mtime=20, gzip_mtime=20)
    verification = build.verify_sdist(
        first,
        expected_name=PROJECT_NAME,
        expected_version=PROJECT_VERSION,
        expected_policy=SDIST_POLICY,
    )
    assert verification.record["member_count"] == 6

    def verifier(candidate: Path) -> Any:
        return build.verify_sdist(
            candidate,
            expected_name=PROJECT_NAME,
            expected_version=PROJECT_VERSION,
            expected_policy=SDIST_POLICY,
        )

    with pytest.raises(build.BuildError, match="bytes differ while semantic contents match"):
        build.require_reproducible(first, second, verifier, "source distribution")


def test_sdist_rejects_escapes_links_and_missing_build_policy(tmp_path: Path) -> None:
    sdist = tmp_path / "extra_codeowners-0.1.0.tar.gz"
    files = sdist_files()
    files["extra_codeowners-0.1.0/../escape"] = b"bad"
    write_sdist(sdist, files=files)
    with pytest.raises(build.BuildError, match="unsafe member"):
        build.verify_sdist(
            sdist,
            expected_name=PROJECT_NAME,
            expected_version=PROJECT_VERSION,
            expected_policy=SDIST_POLICY,
        )

    write_sdist(sdist, links={"extra_codeowners-0.1.0/link": "README.md"})
    with pytest.raises(build.BuildError, match="special member"):
        build.verify_sdist(
            sdist,
            expected_name=PROJECT_NAME,
            expected_version=PROJECT_VERSION,
            expected_policy=SDIST_POLICY,
        )

    files = sdist_files()
    del files["extra_codeowners-0.1.0/requirements-build.txt"]
    write_sdist(sdist, files=files)
    with pytest.raises(build.BuildError, match="omits required"):
        build.verify_sdist(
            sdist,
            expected_name=PROJECT_NAME,
            expected_version=PROJECT_VERSION,
            expected_policy=SDIST_POLICY,
        )

    files = sdist_files()
    files["extra_codeowners-0.1.0/requirements-build.txt"] = b"hatchling==9.9.9\n"
    write_sdist(sdist, files=files)
    with pytest.raises(build.BuildError, match=r"changes reviewed requirements-build\.txt"):
        build.verify_sdist(
            sdist,
            expected_name=PROJECT_NAME,
            expected_version=PROJECT_VERSION,
            expected_policy=SDIST_POLICY,
        )


def test_installed_record_supports_scripts_and_verifies_every_owned_file(tmp_path: Path) -> None:
    wheel_path, wheel = installed_wheel(tmp_path)
    root = tmp_path / "venv"
    record = write_installed_record(root, wheel_path, wheel)
    result = build.verify_installed_record(record, root, wheel)
    assert result["entry_count"] == 7
    assert result["wheel_sha256"] == wheel.record["sha256"]
    assert len(cast(str, result["record_identity_sha256"])) == 64


def test_installed_record_rejects_digest_escape_alias_and_symlink(
    tmp_path: Path,
) -> None:
    wheel_path, wheel = installed_wheel(tmp_path)
    digest_root = tmp_path / "digest"
    record = write_installed_record(
        digest_root, wheel_path, wheel, digest_override="sha256=invalid"
    )
    with pytest.raises(build.BuildError, match="does not match"):
        build.verify_installed_record(record, digest_root, wheel)

    escape_root = tmp_path / "escape"
    record = write_installed_record(
        escape_root,
        wheel_path,
        wheel,
        extra_rows=[("../../../../outside", "sha256=unused", "0")],
    )
    with pytest.raises(build.BuildError, match="escapes the environment"):
        build.verify_installed_record(record, escape_root, wheel)

    alias_root = tmp_path / "alias"
    package = (
        alias_root / "lib" / "python3.12" / "site-packages" / "extra_codeowners" / "__init__.py"
    )
    record = write_installed_record(alias_root, wheel_path, wheel)
    duplicate = (
        "alias/../extra_codeowners/__init__.py",
        f"sha256={build.record_digest(package.read_bytes())}",
        str(package.stat().st_size),
    )
    record.write_bytes(record.read_bytes() + csv_bytes([duplicate]))
    with pytest.raises(build.BuildError, match="repeats a resolved path"):
        build.verify_installed_record(record, alias_root, wheel)

    link_root = tmp_path / "link"
    record = write_installed_record(link_root, wheel_path, wheel)
    package = (
        link_root / "lib" / "python3.12" / "site-packages" / "extra_codeowners" / "__init__.py"
    )
    target = package.with_name("target.py")
    target.write_bytes(package.read_bytes())
    package.unlink()
    package.symlink_to(target.name)
    with pytest.raises(build.BuildError, match="crosses a symlink"):
        build.verify_installed_record(record, link_root, wheel)


def test_installed_record_rejects_unowned_or_tampered_launchers(tmp_path: Path) -> None:
    wheel_path, wheel = installed_wheel(tmp_path)
    root = tmp_path / "venv"
    record = write_installed_record(root, wheel_path, wheel)
    launcher = root / "bin" / "extra-codeowners"
    launcher.write_bytes(b"#!/bin/sh\necho compromised\n")
    rows = list(csv.reader(record.read_text(encoding="utf-8").splitlines()))
    for row in rows:
        if row[0] == "../../../bin/extra-codeowners":
            row[1] = f"sha256={build.record_digest(launcher.read_bytes())}"
            row[2] = str(launcher.stat().st_size)
    record.write_bytes(csv_bytes([cast(tuple[str, str, str], tuple(row)) for row in rows]))
    with pytest.raises(build.BuildError, match="launcher differs"):
        build.verify_installed_record(record, root, wheel)

    self_only_root = tmp_path / "self-only"
    self_only_record = write_installed_record(self_only_root, wheel_path, wheel)
    self_only_record.write_bytes(csv_bytes([(f"{wheel.dist_info}/RECORD", "", "")]))
    with pytest.raises(build.BuildError, match="ownership differs"):
        build.verify_installed_record(self_only_record, self_only_root, wheel)


def test_build_invocation_is_fixed_hash_required_and_credential_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flags = build.build_flags(Path("/policy/requirements-build.txt"), Path("/python"))
    assert flags == [
        "--build-constraints",
        "/policy/requirements-build.txt",
        "--require-hashes",
        "--no-cache",
        "--no-create-gitignore",
        "--no-config",
        "--no-sources",
        "--default-index",
        "https://pypi.org/simple",
        "--index-strategy",
        "first-index",
        "--no-managed-python",
        "--no-python-downloads",
        "--python",
        "/python",
    ]
    monkeypatch.setenv("PATH", "/usr/bin:relative-bin")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-leak")
    environment = build.minimal_build_environment(tmp_path / "scratch", 1_700_000_000)
    assert "GITHUB_TOKEN" not in environment
    assert environment["UV_NO_SOURCES"] == "1"
    assert environment["SOURCE_DATE_EPOCH"] == "1700000000"
    assert environment["PATH"] == build.SAFE_BUILD_PATH


def test_process_diagnostics_are_bounded_and_timeouts_kill_the_process(tmp_path: Path) -> None:
    marker = "bounded-tail"
    noisy_process = (
        f"import sys; sys.stdout.write('x' * {build.MAX_PROCESS_OUTPUT_BYTES * 2} + {marker!r})"
    )
    output = build.run_command(
        [
            sys.executable,
            "-c",
            noisy_process,
        ],
        cwd=tmp_path,
        environment=os.environ,
        timeout=10,
    )
    assert output.endswith(marker)
    assert len(output.encode()) <= build.MAX_PROCESS_OUTPUT_BYTES

    with pytest.raises(build.BuildError, match="command timed out"):
        build.run_command(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            cwd=tmp_path,
            environment=os.environ,
            timeout=0,
        )


def test_toolchain_identity_records_and_restricts_the_build_architecture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "mise.toml").write_text('[tools]\nuv = "0.11.28"\n', encoding="utf-8")
    python_identity: dict[str, object] = {
        "implementation": "CPython",
        "version": "3.14.5",
        "major": 3,
        "minor": 14,
        "machine": "x86_64",
    }

    def fake_run(command: Sequence[str], **kwargs: Any) -> str:
        del kwargs
        if command[1:] == ["--version"]:
            return "uv 0.11.28 (x86_64-unknown-linux-gnu)\n"
        return json.dumps(python_identity)

    monkeypatch.setattr(build, "run_command", fake_run)
    identity = build.toolchain_identity(Path("/uv"), Path("/python"), tmp_path, os.environ)
    assert identity["python_machine"] == "x86_64"
    assert identity["python_major_minor"] == "3.14"

    python_identity["machine"] = "sparc64"
    with pytest.raises(build.BuildError, match="reviewed CPython"):
        build.toolchain_identity(Path("/uv"), Path("/python"), tmp_path, os.environ)


def test_build_record_json_is_canonical_and_atomic(tmp_path: Path) -> None:
    record = tmp_path / "nested" / "record.json"
    build.write_record(record, {"z": 1, "a": [2]})
    assert record.read_bytes() == b'{"a":[2],"z":1}\n'
    assert json.loads(record.read_text(encoding="utf-8")) == {"a": [2], "z": 1}
    assert stat.S_IMODE(record.stat().st_mode) == 0o600
