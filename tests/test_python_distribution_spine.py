"""Adversarial tests for the raw Python-distribution spine transport."""

from __future__ import annotations

import ast
import copy
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
WORKFLOWS = ROOT / ".github" / "workflows"
REVISION = "1" * 40
WORKFLOW_SHA = "2" * 40
SELECTED_ARTIFACT_SHA256 = "3" * 64


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
builder = load_script("build_python_distribution_spine")


@dataclass(frozen=True)
class BuiltSpine:
    directory: Path
    spine: Path
    record: Path
    expected: Any
    verification_calls: list[dict[str, object]]


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def create_selection(directory: Path, *, reverse_creation: bool = True) -> dict[str, bytes]:
    directory.mkdir()
    files = {
        "python-build-record-amd64.json": b'{"architecture":"amd64"}\n',
        "python-build-record-arm64.json": b'{"architecture":"arm64"}\n',
        "extra_codeowners-0.1.0.tar.gz": b"\x1f\x8bopaque-source-distribution",
        "extra_codeowners-0.1.0-py3-none-any.whl": b"PK\x03\x04opaque-wheel",
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
                "filename": "extra_codeowners-0.1.0.tar.gz",
                "sha256": sha256_bytes(files["extra_codeowners-0.1.0.tar.gz"]),
                "size": len(files["extra_codeowners-0.1.0.tar.gz"]),
            },
            "wheel": {
                "filename": "extra_codeowners-0.1.0-py3-none-any.whl",
                "sha256": sha256_bytes(files["extra_codeowners-0.1.0-py3-none-any.whl"]),
                "size": len(files["extra_codeowners-0.1.0-py3-none-any.whl"]),
            },
        },
    }
    files["python-selection-record.json"] = python_distribution_spine.canonical_json(selection)
    entries = tuple(files.items())
    if reverse_creation:
        entries = tuple(reversed(entries))
    for filename, content in entries:
        (directory / filename).write_bytes(content)
    return files


def expected_identity(files: dict[str, bytes]) -> Any:
    return python_distribution_spine.ExpectedIdentity(
        repository_id="123456",
        repository_name="stampbot/extra-codeowners",
        run_id="777777",
        run_attempt="2",
        source_revision=REVISION,
        workflow_path=".github/workflows/python-distribution.yml",
        workflow_ref=(
            "stampbot/extra-codeowners/.github/workflows/python-distribution.yml@refs/heads/main"
        ),
        workflow_sha=WORKFLOW_SHA,
        selected_artifact_id="888888",
        selected_artifact_sha256=SELECTED_ARTIFACT_SHA256,
        wheel_sha256=sha256_bytes(files["extra_codeowners-0.1.0-py3-none-any.whl"]),
        selection_record_sha256=sha256_bytes(files["python-selection-record.json"]),
    )


def build_spine(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    verification: Callable[..., dict[str, object]] | None = None,
    prepare: Callable[[Path], None] | None = None,
    reverse_creation: bool = True,
) -> BuiltSpine:
    directory = root / "selected"
    files = create_selection(directory, reverse_creation=reverse_creation)
    if prepare is not None:
        prepare(directory)
    expected = expected_identity(files)
    calls: list[dict[str, object]] = []

    def valid_verification(path: Path, **kwargs: object) -> dict[str, object]:
        calls.append({"directory": path, **kwargs})
        return {
            "wheel_sha256": expected.wheel_sha256,
            "selection_record_sha256": expected.selection_record_sha256,
        }

    monkeypatch.setattr(
        builder.build_python_artifacts,
        "verify_selection",
        verification or valid_verification,
    )
    spine_path = root / python_distribution_spine.expected_spine_filename(
        REVISION, expected.selected_artifact_id, expected.run_attempt
    )
    record_path = root / python_distribution_spine.expected_record_filename(
        REVISION, expected.selected_artifact_id, expected.run_attempt
    )
    builder.build(directory, spine_path, record_path, expected)
    return BuiltSpine(directory, spine_path, record_path, expected, calls)


@pytest.fixture
def built_spine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BuiltSpine:
    return build_spine(tmp_path, monkeypatch)


def verify(bundle: BuiltSpine, expected: Any | None = None) -> Any:
    return python_distribution_spine.verify(
        bundle.record,
        bundle.spine,
        bundle.expected if expected is None else expected,
        record_artifact_sha256=sha256(bundle.record),
        spine_artifact_sha256=sha256(bundle.spine),
    )


def materialize(bundle: BuiltSpine, output: Path) -> Any:
    return python_distribution_spine.materialize(
        bundle.record,
        bundle.spine,
        output,
        bundle.expected,
        record_artifact_sha256=sha256(bundle.record),
        spine_artifact_sha256=sha256(bundle.spine),
    )


def private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def write_record(bundle: BuiltSpine, record: object) -> str:
    bundle.record.write_bytes(python_distribution_spine.canonical_json(record))
    return sha256(bundle.record)


def verify_changed_record(bundle: BuiltSpine, record: object) -> Any:
    return python_distribution_spine.verify(
        bundle.record,
        bundle.spine,
        bundle.expected,
        record_artifact_sha256=write_record(bundle, record),
        spine_artifact_sha256=sha256(bundle.spine),
    )


def test_build_and_verify_exact_five_file_spine(built_spine: BuiltSpine) -> None:
    record = verify(built_spine)

    assert built_spine.spine.stat().st_mode & 0o777 == 0o600
    assert built_spine.record.stat().st_mode & 0o777 == 0o600
    assert built_spine.record.read_bytes() == python_distribution_spine.canonical_json(record)
    assert [item["kind"] for item in record["files"]] == list(python_distribution_spine.KIND_ORDER)
    expected_offset = 0
    for item in record["files"]:
        assert item["offset"] == expected_offset
        expected_offset += item["size"]
    assert expected_offset == record["spine"]["size"] == built_spine.spine.stat().st_size
    assert record["spine"]["sha256"] == sha256(built_spine.spine)
    assert built_spine.verification_calls == [
        {
            "directory": built_spine.directory,
            "source_revision": REVISION,
            "wheel_sha256": built_spine.expected.wheel_sha256,
            "selection_record_sha256": built_spine.expected.selection_record_sha256,
        }
    ]


def test_materialize_atomically_exposes_exact_verified_files(built_spine: BuiltSpine) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    output = parent / "files"

    materialized = materialize(built_spine, output)

    assert output.stat().st_mode & 0o777 == 0o700
    assert [item.filename for item in materialized] == [
        item["filename"] for item in verify(built_spine)["files"]
    ]
    assert {path.name for path in output.iterdir()} == {
        path.name for path in built_spine.directory.iterdir()
    }
    for path in output.iterdir():
        assert path.is_file()
        assert not path.is_symlink()
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.read_bytes() == (built_spine.directory / path.name).read_bytes()


def test_materialized_files_use_nofollow_exclusive_creation(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    output = parent / "files"
    actual_open = os.open
    output_opens: list[tuple[int, tuple[int, ...]]] = []
    expected_names = {path.name for path in built_spine.directory.iterdir()}

    def observed_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        *mode: int,
        dir_fd: int | None = None,
    ) -> int:
        if isinstance(path, str) and path in expected_names and flags & os.O_WRONLY:
            output_opens.append((flags, mode))
        return actual_open(path, flags, *mode, dir_fd=dir_fd)

    monkeypatch.setattr(python_distribution_spine.os, "open", observed_open)

    materialize(built_spine, output)

    assert len(output_opens) == 5
    for flags, mode in output_opens:
        assert flags & os.O_NOFOLLOW
        assert flags & os.O_EXCL
        assert flags & os.O_CREAT
        assert mode == (0o600,)


def test_materialization_ancestry_is_opened_descriptor_relative(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    actual_open = os.open
    directory_opens: list[tuple[str, int, int | None]] = []

    def observed_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        *mode: int,
        dir_fd: int | None = None,
    ) -> int:
        if flags & os.O_DIRECTORY:
            directory_opens.append((os.fsdecode(path), flags, dir_fd))
        return actual_open(path, flags, *mode, dir_fd=dir_fd)

    monkeypatch.setattr(python_distribution_spine.os, "open", observed_open)

    materialize(built_spine, parent / "files")

    assert directory_opens[0][0] == "/"
    assert directory_opens[0][2] is None
    for name, flags, parent_descriptor in directory_opens[1:]:
        assert "/" not in name
        assert parent_descriptor is not None
        assert flags & os.O_DIRECTORY
        assert flags & os.O_NOFOLLOW


def test_materialize_verifies_every_range_before_creating_staging(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    output = parent / "files"
    record = copy.deepcopy(verify(built_spine))
    wheel = next(item for item in record["files"] if item["kind"] == "wheel")
    content = bytearray(built_spine.spine.read_bytes())
    content[wheel["offset"]] ^= 1
    built_spine.spine.write_bytes(content)
    record["spine"]["sha256"] = sha256(built_spine.spine)
    record_artifact_sha256 = write_record(built_spine, record)
    staging_calls = 0
    actual_create = python_distribution_spine._create_staging_directory

    def observed_create(parent_descriptor: int) -> tuple[int, str]:
        nonlocal staging_calls
        staging_calls += 1
        descriptor, name = actual_create(parent_descriptor)
        assert isinstance(descriptor, int)
        assert isinstance(name, str)
        return descriptor, name

    monkeypatch.setattr(
        python_distribution_spine,
        "_create_staging_directory",
        observed_create,
    )

    with pytest.raises(python_distribution_spine.SpineError, match="digest mismatch"):
        python_distribution_spine.materialize(
            built_spine.record,
            built_spine.spine,
            output,
            built_spine.expected,
            record_artifact_sha256=record_artifact_sha256,
            spine_artifact_sha256=sha256(built_spine.spine),
        )

    assert staging_calls == 0
    assert not output.exists()
    assert not tuple(parent.iterdir())


def test_materialize_cleans_private_staging_after_partial_write(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    output = parent / "files"
    actual_write = os.write
    writes = 0

    def fail_second_write(descriptor: int, content: bytes | memoryview) -> int:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("synthetic materialization failure")
        return actual_write(descriptor, content)

    monkeypatch.setattr(python_distribution_spine.os, "write", fail_second_write)

    with pytest.raises(python_distribution_spine.SpineError, match="cannot write"):
        materialize(built_spine, output)

    assert writes == 2
    assert not output.exists()
    assert not tuple(parent.iterdir())


def test_materialize_cleans_staging_when_source_changes_before_exposure(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    output = parent / "files"
    actual_write = python_distribution_spine._write_materialized_file
    metadata = built_spine.spine.stat()

    def mutate_after_last_file(
        descriptor: int,
        item: Any,
        chunks: tuple[bytes, ...],
        created: list[str],
    ) -> None:
        actual_write(descriptor, item, chunks, created)
        if item.filename.endswith(".whl"):
            os.utime(
                built_spine.spine,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
            )

    monkeypatch.setattr(
        python_distribution_spine,
        "_write_materialized_file",
        mutate_after_last_file,
    )

    with pytest.raises(python_distribution_spine.SpineError, match="changed"):
        materialize(built_spine, output)

    assert not output.exists()
    assert not tuple(parent.iterdir())


def test_materialize_never_replaces_an_existing_destination(built_spine: BuiltSpine) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    output = parent / "files"
    output.mkdir()
    marker = output / "keep"
    marker.write_text("do not replace", encoding="utf-8")

    with pytest.raises(python_distribution_spine.SpineError, match="already exists"):
        materialize(built_spine, output)

    assert marker.read_text(encoding="utf-8") == "do not replace"
    assert {path.name for path in parent.iterdir()} == {"files"}


def test_materialize_requires_an_owner_private_parent(built_spine: BuiltSpine) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    parent.chmod(0o750)

    with pytest.raises(python_distribution_spine.SpineError, match="owner-controlled private"):
        materialize(built_spine, parent / "files")


def test_materialize_rejects_a_symlink_in_nonfinal_ancestry(built_spine: BuiltSpine) -> None:
    base = private_directory(built_spine.directory.parent / "ancestry")
    actual = private_directory(base / "actual")
    parent = private_directory(actual / "materialized")
    linked = base / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(python_distribution_spine.SpineError, match="without symlinks"):
        materialize(built_spine, linked / "materialized" / "files")

    assert not tuple(parent.iterdir())


def test_materialize_rejects_a_nonsticky_writable_ancestor(built_spine: BuiltSpine) -> None:
    base = private_directory(built_spine.directory.parent / "ancestry")
    writable = private_directory(base / "writable")
    parent = private_directory(writable / "materialized")
    writable.chmod(0o770)

    with pytest.raises(python_distribution_spine.SpineError, match="unsafe writable"):
        materialize(built_spine, parent / "files")

    assert not tuple(parent.iterdir())


def test_root_owned_sticky_ancestor_allows_a_current_user_child(tmp_path: Path) -> None:
    root = python_distribution_spine._directory_identity(os.stat("/"), "test root")
    root_uid = python_distribution_spine._root_authority_uid(root)
    temporary_root = Path(tmp_path.anchor) / tmp_path.parts[1]
    sticky = python_distribution_spine._directory_identity(
        os.stat(temporary_root), "test temporary root"
    )
    child = python_distribution_spine._directory_identity(os.stat(tmp_path), "test child")

    assert sticky.uid == root_uid
    assert sticky.mode & python_distribution_spine.stat.S_ISVTX
    python_distribution_spine._require_trusted_transition(sticky, child, root_uid)


def test_sticky_writable_ancestor_requires_root_ownership(tmp_path: Path) -> None:
    root = python_distribution_spine._directory_identity(os.stat("/"), "test root")
    root_uid = python_distribution_spine._root_authority_uid(root)
    if os.geteuid() == root_uid:
        pytest.skip("root and current-user ownership are identical")
    child = python_distribution_spine._directory_identity(os.stat(tmp_path), "test child")
    user_sticky = dataclasses.replace(
        child,
        mode=(child.mode & ~0o7777) | 0o41777,
        uid=os.geteuid(),
    )

    with pytest.raises(python_distribution_spine.SpineError, match="unsafe writable"):
        python_distribution_spine._require_trusted_transition(user_sticky, child, root_uid)


def test_root_sticky_ancestor_rejects_an_untrusted_child_owner(tmp_path: Path) -> None:
    root = python_distribution_spine._directory_identity(os.stat("/"), "test root")
    root_uid = python_distribution_spine._root_authority_uid(root)
    temporary_root = Path(tmp_path.anchor) / tmp_path.parts[1]
    sticky = python_distribution_spine._directory_identity(
        os.stat(temporary_root), "test temporary root"
    )
    child = python_distribution_spine._directory_identity(os.stat(tmp_path), "test child")
    untrusted = dataclasses.replace(child, uid=424242)

    with pytest.raises(python_distribution_spine.SpineError, match="untrusted owner"):
        python_distribution_spine._require_trusted_transition(sticky, untrusted, root_uid)


def test_current_overflow_uid_is_rejected_before_the_root_owner_fast_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = python_distribution_spine._directory_identity(os.stat("/"), "test root")
    ordinary_root = dataclasses.replace(root, uid=python_distribution_spine.ROOT_UID)
    monkeypatch.setattr(
        python_distribution_spine.os,
        "geteuid",
        lambda: python_distribution_spine.LINUX_OVERFLOW_UID,
    )
    monkeypatch.setattr(
        python_distribution_spine,
        "_linux_uid_map",
        lambda: pytest.fail("ordinary root ownership must not read the namespace map"),
    )

    with pytest.raises(python_distribution_spine.SpineError, match="cannot run"):
        python_distribution_spine._root_authority_uid(ordinary_root)


def test_overflow_root_accepts_an_ordinary_mapped_effective_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = python_distribution_spine._directory_identity(os.stat("/"), "test root")
    overflow_root = dataclasses.replace(
        root,
        mode=(root.mode & ~0o7777) | 0o40755,
        uid=python_distribution_spine.LINUX_OVERFLOW_UID,
    )
    effective_uid = 1000
    monkeypatch.setattr(python_distribution_spine.os, "geteuid", lambda: effective_uid)
    monkeypatch.setattr(
        python_distribution_spine,
        "_linux_uid_map",
        lambda: ((effective_uid, 100000, 1),),
    )

    assert (
        python_distribution_spine._root_authority_uid(overflow_root)
        == python_distribution_spine.LINUX_OVERFLOW_UID
    )


def test_overflow_root_rejects_group_or_other_write_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = python_distribution_spine._directory_identity(os.stat("/"), "test root")
    writable_overflow_root = dataclasses.replace(
        root,
        mode=root.mode | 0o022,
        uid=python_distribution_spine.LINUX_OVERFLOW_UID,
    )
    monkeypatch.setattr(python_distribution_spine.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        python_distribution_spine,
        "_linux_uid_map",
        lambda: pytest.fail("an unsafe root must be rejected before reading the namespace map"),
    )

    with pytest.raises(python_distribution_spine.SpineError, match="untrusted owner"):
        python_distribution_spine._root_authority_uid(writable_overflow_root)


def test_materialize_rejects_ancestor_rebind_before_publication(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = built_spine.directory.parent
    ancestor = private_directory(root / "ancestry")
    private_directory(ancestor / "materialized")
    detached = root / "detached-ancestry"
    actual_write = python_distribution_spine._write_materialized_file

    def rebind_after_last_file(
        descriptor: int,
        item: Any,
        chunks: tuple[bytes, ...],
        created: list[str],
    ) -> None:
        actual_write(descriptor, item, chunks, created)
        if item.filename.endswith(".whl"):
            ancestor.rename(detached)
            replacement = private_directory(root / "ancestry")
            private_directory(replacement / "materialized")

    monkeypatch.setattr(
        python_distribution_spine,
        "_write_materialized_file",
        rebind_after_last_file,
    )

    with pytest.raises(python_distribution_spine.SpineError, match="ancestry changed"):
        materialize(built_spine, ancestor / "materialized" / "files")

    assert not (ancestor / "materialized" / "files").exists()
    assert not tuple((detached / "materialized").iterdir())


def test_materialize_rejects_ancestor_rebind_after_publication(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = built_spine.directory.parent
    ancestor = private_directory(root / "ancestry")
    parent = private_directory(ancestor / "materialized")
    output = parent / "files"
    detached = root / "detached-ancestry"
    actual_rename = python_distribution_spine._rename_noreplace

    def publish_then_rebind(
        source_descriptor: int,
        source_name: str,
        destination_descriptor: int,
        destination_name: str,
    ) -> None:
        actual_rename(
            source_descriptor,
            source_name,
            destination_descriptor,
            destination_name,
        )
        ancestor.rename(detached)
        replacement = private_directory(root / "ancestry")
        private_directory(replacement / "materialized")

    monkeypatch.setattr(
        python_distribution_spine,
        "_rename_noreplace",
        publish_then_rebind,
    )

    with pytest.raises(python_distribution_spine.SpineError, match="ancestry changed"):
        materialize(built_spine, output)

    assert not output.exists()
    assert not tuple((detached / "materialized").iterdir())


def test_rename_noreplace_preserves_a_racing_empty_destination(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")
    output = parent / "files"
    actual_rename = python_distribution_spine._rename_noreplace
    competing_inode: int | None = None

    def create_destination_then_rename(
        source_descriptor: int,
        source_name: str,
        destination_descriptor: int,
        destination_name: str,
    ) -> None:
        nonlocal competing_inode
        os.mkdir(destination_name, 0o700, dir_fd=destination_descriptor)
        competing_inode = os.stat(
            destination_name,
            dir_fd=destination_descriptor,
            follow_symlinks=False,
        ).st_ino
        actual_rename(
            source_descriptor,
            source_name,
            destination_descriptor,
            destination_name,
        )

    monkeypatch.setattr(
        python_distribution_spine,
        "_rename_noreplace",
        create_destination_then_rename,
    )

    with pytest.raises(python_distribution_spine.SpineError, match="appeared"):
        materialize(built_spine, output)

    assert competing_inode is not None
    assert output.stat().st_ino == competing_inode
    assert not tuple(output.iterdir())
    assert {path.name for path in parent.iterdir()} == {"files"}


def test_materialize_fails_closed_without_linux_renameat2(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = private_directory(built_spine.directory.parent / "materialized")

    class MissingRenameat2:
        pass

    monkeypatch.setattr(
        python_distribution_spine.ctypes,
        "CDLL",
        lambda *args, **kwargs: MissingRenameat2(),
    )

    with pytest.raises(python_distribution_spine.SpineError, match="refusing to publish"):
        materialize(built_spine, parent / "files")

    assert not tuple(parent.iterdir())


@pytest.mark.parametrize(
    "mappings",
    [
        ((0, 0, 1), (os.geteuid(), os.geteuid(), 1)),
        (
            (os.geteuid(), os.geteuid(), 1),
            (
                python_distribution_spine.LINUX_OVERFLOW_UID,
                python_distribution_spine.LINUX_OVERFLOW_UID,
                1,
            ),
        ),
        ((424242, 424242, 1),),
    ],
)
def test_overflow_root_uid_requires_an_unmapped_root_namespace(
    monkeypatch: pytest.MonkeyPatch,
    mappings: tuple[tuple[int, int, int], ...],
) -> None:
    root = python_distribution_spine._directory_identity(os.stat("/"), "test root")
    overflow_root = dataclasses.replace(
        root,
        uid=python_distribution_spine.LINUX_OVERFLOW_UID,
    )
    monkeypatch.setattr(
        python_distribution_spine,
        "_linux_uid_map",
        lambda: mappings,
    )

    with pytest.raises(python_distribution_spine.SpineError, match="not an unmapped-root"):
        python_distribution_spine._root_authority_uid(overflow_root)


def test_current_root_authority_is_numerically_proven() -> None:
    root = python_distribution_spine._directory_identity(os.stat("/"), "test root")
    authority = python_distribution_spine._root_authority_uid(root)

    assert authority in {
        python_distribution_spine.ROOT_UID,
        python_distribution_spine.LINUX_OVERFLOW_UID,
    }
    if authority == python_distribution_spine.LINUX_OVERFLOW_UID:
        mappings = python_distribution_spine._linux_uid_map()
        assert not python_distribution_spine._uid_is_mapped(
            python_distribution_spine.ROOT_UID,
            mappings,
        )
        assert not python_distribution_spine._uid_is_mapped(
            python_distribution_spine.LINUX_OVERFLOW_UID,
            mappings,
        )
        assert python_distribution_spine._uid_is_mapped(os.geteuid(), mappings)


def test_verified_file_exposure_is_an_immutable_tuple(built_spine: BuiltSpine) -> None:
    record = verify(built_spine)
    wheel = next(item for item in record["files"] if item["kind"] == "wheel")
    with python_distribution_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=sha256(built_spine.spine),
    ) as verified:
        chunks = verified.file_chunks(wheel["filename"])
        assert isinstance(chunks, tuple)
        assert b"".join(chunks) == (built_spine.directory / wheel["filename"]).read_bytes()
        with pytest.raises(python_distribution_spine.SpineError, match="not uniquely present"):
            verified.file_chunks("absent.whl")


def test_final_chunk_corruption_exposes_no_partial_file(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = verify(built_spine)
    wheel = next(item for item in record["files"] if item["kind"] == "wheel")
    actual_pread = os.pread
    read_offsets: list[int] = []

    with python_distribution_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=sha256(built_spine.spine),
    ) as verified:
        monkeypatch.setattr(
            python_distribution_spine,
            "READ_CHUNK_BYTES",
            max(1, wheel["size"] - 1),
        )

        def corrupt_final_pread(descriptor: int, size: int, offset: int) -> bytes:
            chunk = actual_pread(descriptor, size, offset)
            read_offsets.append(offset)
            if offset + len(chunk) == wheel["offset"] + wheel["size"]:
                return chunk[:-1] + bytes([chunk[-1] ^ 1])
            return chunk

        monkeypatch.setattr(python_distribution_spine.os, "pread", corrupt_final_pread)
        exposed: tuple[bytes, ...] | None = None
        with pytest.raises(python_distribution_spine.SpineError, match="before a file was exposed"):
            exposed = verified.file_chunks(wheel["filename"])

        assert exposed is None
        assert len(read_offsets) == 2


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("eof", "changed while a range was read"),
        ("error", "cannot stage a verified Python distribution file"),
    ],
)
def test_incomplete_file_read_exposes_no_partial_file(
    built_spine: BuiltSpine,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    message: str,
) -> None:
    record = verify(built_spine)
    wheel = next(item for item in record["files"] if item["kind"] == "wheel")
    actual_pread = os.pread
    calls = 0

    with python_distribution_spine.open_verified_spine(
        built_spine.spine,
        record,
        artifact_sha256=sha256(built_spine.spine),
    ) as verified:
        monkeypatch.setattr(
            python_distribution_spine,
            "READ_CHUNK_BYTES",
            max(1, wheel["size"] - 1),
        )

        def fail_second_pread(descriptor: int, size: int, offset: int) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 2:
                if failure == "eof":
                    return b""
                raise OSError("synthetic read failure")
            return actual_pread(descriptor, size, offset)

        monkeypatch.setattr(python_distribution_spine.os, "pread", fail_second_pread)
        exposed: tuple[bytes, ...] | None = None
        with pytest.raises(python_distribution_spine.SpineError, match=message):
            exposed = verified.file_chunks(wheel["filename"])

        assert exposed is None
        assert calls == 2


def test_context_rechecks_spine_after_file_exposure(built_spine: BuiltSpine) -> None:
    record = verify(built_spine)
    wheel = next(item for item in record["files"] if item["kind"] == "wheel")
    metadata = built_spine.spine.stat()

    with (
        pytest.raises(python_distribution_spine.SpineError, match="changed"),
        python_distribution_spine.open_verified_spine(
            built_spine.spine,
            record,
            artifact_sha256=sha256(built_spine.spine),
        ) as verified,
    ):
        chunks = verified.file_chunks(wheel["filename"])
        assert isinstance(chunks, tuple)
        os.utime(
            built_spine.spine,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
        )


def test_build_is_deterministic_across_directory_order_and_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    changed_time = 1_900_000_000_000_000_000

    def change_metadata(directory: Path) -> None:
        for path in directory.iterdir():
            os.utime(path, ns=(changed_time, changed_time))
        os.utime(directory, ns=(changed_time, changed_time))

    outputs: list[tuple[bytes, bytes]] = []
    for index in range(2):
        root = tmp_path / str(index)
        root.mkdir()
        bundle = build_spine(
            root,
            monkeypatch,
            prepare=change_metadata if index else None,
            reverse_creation=not bool(index),
        )
        outputs.append((bundle.spine.read_bytes(), bundle.record.read_bytes()))

    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("kind", python_distribution_spine.KIND_ORDER)
def test_each_tampered_range_is_rejected(built_spine: BuiltSpine, kind: str) -> None:
    record = copy.deepcopy(verify(built_spine))
    item = next(candidate for candidate in record["files"] if candidate["kind"] == kind)
    content = bytearray(built_spine.spine.read_bytes())
    content[item["offset"]] ^= 1
    built_spine.spine.write_bytes(content)
    record["spine"]["sha256"] = sha256(built_spine.spine)

    with pytest.raises(python_distribution_spine.SpineError, match="digest mismatch"):
        verify_changed_record(built_spine, record)


@pytest.mark.parametrize("kind", ["build-record-amd64", "build-record-arm64", "sdist"])
def test_selection_record_projection_anchors_other_ranges(
    built_spine: BuiltSpine, kind: str
) -> None:
    record = copy.deepcopy(verify(built_spine))
    item = next(candidate for candidate in record["files"] if candidate["kind"] == kind)
    content = bytearray(built_spine.spine.read_bytes())
    content[item["offset"]] ^= 1
    built_spine.spine.write_bytes(content)
    item["sha256"] = sha256_bytes(bytes(content[item["offset"] : item["offset"] + item["size"]]))
    record["spine"]["sha256"] = sha256(built_spine.spine)

    with pytest.raises(python_distribution_spine.SpineError, match=r"proof|selected sdist"):
        verify_changed_record(built_spine, record)


def test_selection_record_requires_distinct_proof_digests(built_spine: BuiltSpine) -> None:
    record = copy.deepcopy(verify(built_spine))
    selection_item = next(item for item in record["files"] if item["kind"] == "selection-record")
    content = bytearray(built_spine.spine.read_bytes())
    start = selection_item["offset"]
    stop = start + selection_item["size"]
    selection = json.loads(content[start:stop])
    selection["proofs"]["arm64"]["record_sha256"] = selection["proofs"]["amd64"]["record_sha256"]
    replacement = python_distribution_spine.canonical_json(selection)
    assert len(replacement) == selection_item["size"]
    content[start:stop] = replacement
    built_spine.spine.write_bytes(content)
    selection_item["sha256"] = sha256_bytes(replacement)
    record["selection"]["record_sha256"] = selection_item["sha256"]
    record["spine"]["sha256"] = sha256(built_spine.spine)
    changed_expected = dataclasses.replace(
        built_spine.expected,
        selection_record_sha256=selection_item["sha256"],
    )
    write_record(built_spine, record)

    with pytest.raises(python_distribution_spine.SpineError, match=r"wrong digest|must differ"):
        verify(built_spine, changed_expected)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda record: record["files"][0].update(offset=1), "prefix, gap, overlap"),
        (lambda record: record["files"][1].update(offset=0), "prefix, gap, overlap"),
        (lambda record: record["files"][0].update(size=False), "integer bounds"),
        (lambda record: record["files"][0].update(kind="unknown"), "out of order"),
        (
            lambda record: record["files"][1].update(sha256=record["files"][0]["sha256"]),
            "digest is repeated",
        ),
        (lambda record: record["spine"].update(size=1), "exact spine size"),
        (
            lambda record: record["files"][-1].update(
                filename="another_project-0.1.0-py3-none-any.whl"
            ),
            "different projects",
        ),
        (lambda record: record.update(extra="unsupported"), "must contain exactly"),
        (lambda record: record["files"].append(copy.deepcopy(record["files"][-1])), "five"),
    ],
)
def test_record_rejects_ambiguous_or_extended_ranges(
    built_spine: BuiltSpine,
    mutation: Callable[[Any], None],
    message: str,
) -> None:
    record = copy.deepcopy(verify(built_spine))
    mutation(record)

    with pytest.raises(python_distribution_spine.SpineError, match=message):
        verify_changed_record(built_spine, record)


@pytest.mark.parametrize(
    "changes",
    [
        {"repository_id": "654321"},
        {"repository_name": "stampbot/different"},
        {"run_id": "777778"},
        {"run_attempt": "3"},
        {"source_revision": "4" * 40},
        {
            "workflow_path": ".github/workflows/other.yml",
            "workflow_ref": "stampbot/extra-codeowners/.github/workflows/other.yml@refs/heads/main",
        },
        {
            "workflow_ref": (
                "stampbot/extra-codeowners/.github/workflows/python-distribution.yml@"
                "refs/tags/v0.1.0"
            )
        },
        {"workflow_sha": "5" * 40},
        {"selected_artifact_id": "888889"},
        {"selected_artifact_sha256": "6" * 64},
        {"wheel_sha256": "7" * 64},
        {"selection_record_sha256": "8" * 64},
    ],
)
def test_record_is_bound_to_every_trusted_identity(
    built_spine: BuiltSpine, changes: dict[str, str]
) -> None:
    changed = dataclasses.replace(built_spine.expected, **changes)
    with pytest.raises(python_distribution_spine.SpineError):
        verify(built_spine, changed)


@pytest.mark.parametrize("artifact", ["record", "spine"])
def test_provider_digest_is_required(built_spine: BuiltSpine, artifact: str) -> None:
    kwargs = {
        "record_artifact_sha256": sha256(built_spine.record),
        "spine_artifact_sha256": sha256(built_spine.spine),
    }
    kwargs[f"{artifact}_artifact_sha256"] = "9" * 64
    with pytest.raises(python_distribution_spine.SpineError, match="provider digest"):
        python_distribution_spine.verify(
            built_spine.record,
            built_spine.spine,
            built_spine.expected,
            **kwargs,
        )


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"a":1,"a":2}\n', "repeats JSON key"),
        (b'{"a":1.0}\n', "floating-point"),
        (b'{"a":NaN}\n', "non-finite"),
        (b"[[[[[[[[[1]]]]]]]]]", "depth limit"),
        (b'"\xff"', "not UTF-8"),
    ],
)
def test_strict_json_rejects_ambiguous_values(raw: bytes, message: str) -> None:
    with pytest.raises(python_distribution_spine.SpineError, match=message):
        python_distribution_spine.strict_json_bytes(raw, "test JSON", canonical=False)


@pytest.mark.parametrize("raw", [b'{"a": 1}\n', b'{"a":1}', b'\xef\xbb\xbf{"a":1}\n'])
def test_canonical_json_rejects_alternate_encodings(raw: bytes) -> None:
    with pytest.raises(python_distribution_spine.SpineError):
        python_distribution_spine.strict_json_bytes(raw, "test JSON", canonical=True)


@pytest.mark.parametrize("artifact", ["record", "spine"])
def test_verifier_rejects_symlink_artifacts(
    built_spine: BuiltSpine, tmp_path: Path, artifact: str
) -> None:
    original = getattr(built_spine, artifact)
    target = tmp_path / f"real-{original.name}"
    original.rename(target)
    original.symlink_to(target)

    with pytest.raises(python_distribution_spine.SpineError, match="cannot open"):
        verify(built_spine)


@pytest.mark.parametrize("artifact", ["record", "spine"])
def test_verifier_rejects_hardlinked_artifacts(
    built_spine: BuiltSpine, tmp_path: Path, artifact: str
) -> None:
    original = getattr(built_spine, artifact)
    os.link(original, tmp_path / f"linked-{original.name}")

    with pytest.raises(python_distribution_spine.SpineError, match="single-link"):
        verify(built_spine)


def test_verifier_normalizes_a_disappearing_path(
    built_spine: BuiltSpine, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_stat = os.stat

    def disappeared(path: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> os.stat_result:
        if Path(path) == built_spine.record:
            raise FileNotFoundError(path)
        return actual_stat(path, *args, **kwargs)

    monkeypatch.setattr(python_distribution_spine.os, "stat", disappeared)

    with pytest.raises(python_distribution_spine.SpineError, match="path changed"):
        verify(built_spine)


@pytest.mark.parametrize(
    ("link_type", "message"),
    [
        ("symlink", "cannot open"),
        ("hardlink", "single-link"),
    ],
)
def test_builder_rechecks_selected_files_after_selection_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    link_type: str,
    message: str,
) -> None:
    directory = tmp_path / "selected"
    files = create_selection(directory)
    expected = expected_identity(files)
    monkeypatch.setattr(
        builder.build_python_artifacts,
        "verify_selection",
        lambda *args, **kwargs: {
            "wheel_sha256": expected.wheel_sha256,
            "selection_record_sha256": expected.selection_record_sha256,
        },
    )
    selected_file_records = builder.build_python_artifacts.selected_file_records

    def mutate_after_recording(path: Path) -> list[dict[str, object]]:
        records = cast(list[dict[str, object]], selected_file_records(path))
        wheel = path / "extra_codeowners-0.1.0-py3-none-any.whl"
        link = tmp_path / f"linked-{wheel.name}"
        if link_type == "symlink":
            wheel.rename(link)
            wheel.symlink_to(link)
        else:
            os.link(wheel, link)
        return records

    monkeypatch.setattr(
        builder.build_python_artifacts,
        "selected_file_records",
        mutate_after_recording,
    )

    with pytest.raises(python_distribution_spine.SpineError, match=message):
        builder.build(
            directory,
            tmp_path
            / python_distribution_spine.expected_spine_filename(
                REVISION, expected.selected_artifact_id, expected.run_attempt
            ),
            tmp_path
            / python_distribution_spine.expected_record_filename(
                REVISION, expected.selected_artifact_id, expected.run_attempt
            ),
            expected,
        )


def test_builder_rejects_preexisting_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "selected"
    files = create_selection(directory)
    expected = expected_identity(files)
    monkeypatch.setattr(
        builder.build_python_artifacts,
        "verify_selection",
        lambda *args, **kwargs: {
            "wheel_sha256": expected.wheel_sha256,
            "selection_record_sha256": expected.selection_record_sha256,
        },
    )
    spine_path = tmp_path / python_distribution_spine.expected_spine_filename(
        REVISION, expected.selected_artifact_id, expected.run_attempt
    )
    record_path = tmp_path / python_distribution_spine.expected_record_filename(
        REVISION, expected.selected_artifact_id, expected.run_attempt
    )
    spine_path.write_bytes(b"do not overwrite")

    with pytest.raises(python_distribution_spine.SpineError, match="cannot create"):
        builder.build(directory, spine_path, record_path, expected)
    assert spine_path.read_bytes() == b"do not overwrite"


def test_builder_normalizes_deep_selection_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject(*args: object, **kwargs: object) -> dict[str, object]:
        raise build_python_artifacts.BuildError("hostile archive")

    directory = tmp_path / "selected"
    files = create_selection(directory)
    expected = expected_identity(files)
    monkeypatch.setattr(builder.build_python_artifacts, "verify_selection", reject)

    with pytest.raises(python_distribution_spine.SpineError, match="hostile archive"):
        builder.build(
            directory,
            tmp_path
            / python_distribution_spine.expected_spine_filename(
                REVISION, expected.selected_artifact_id, expected.run_attempt
            ),
            tmp_path
            / python_distribution_spine.expected_record_filename(
                REVISION, expected.selected_artifact_id, expected.run_attempt
            ),
            expected,
        )


def test_consumer_has_an_explicit_module_and_call_surface() -> None:
    source = (SCRIPTS / "python_distribution_spine.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported_modules == {
        "argparse",
        "contextlib",
        "ctypes",
        "dataclasses",
        "errno",
        "hashlib",
        "json",
        "os",
        "re",
        "stat",
        "sys",
    }
    from_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert from_modules == {"__future__", "collections.abc", "pathlib", "typing"}
    allowed_calls = {
        "argparse": {"ArgumentParser"},
        "contextlib": {"suppress"},
        "ctypes": {"CDLL", "get_errno"},
        "dataclasses": {"dataclass"},
        "errno": set(),
        "hashlib": {"sha256"},
        "json": {"dumps", "loads"},
        "os": {
            "close",
            "fchmod",
            "fsencode",
            "fsync",
            "fstat",
            "geteuid",
            "getpid",
            "mkdir",
            "open",
            "pread",
            "read",
            "rmdir",
            "stat",
            "unlink",
            "urandom",
            "write",
        },
        "re": {"compile"},
        "stat": {"S_ISDIR", "S_ISREG", "S_IMODE"},
        "sys": set(),
    }
    observed: dict[str, set[str]] = {module: set() for module in allowed_calls}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in observed
        ):
            observed[node.func.value.id].add(node.func.attr)
    assert observed == allowed_calls
    forbidden_builtins = {"__import__", "compile", "eval", "exec", "open"}
    assert not {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }.intersection(forbidden_builtins)
    forbidden_high_level_file_calls = {
        "open",
        "read_bytes",
        "read_text",
        "write_bytes",
        "write_text",
    }
    assert not {
        node.func.attr
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and not (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "open"
            )
        )
    }.intersection(forbidden_high_level_file_calls)
    assert not imported_modules.intersection(
        {"gzip", "shutil", "subprocess", "tarfile", "tempfile", "zipfile"}
    )
    assert "os.rename(" not in source
    assert "libc.renameat2" in source
    assert "RENAME_NOREPLACE" in source


def test_raw_workflow_uses_immutable_two_artifact_transport() -> None:
    source = (WORKFLOWS / "python-distribution.yml").read_text(encoding="utf-8")
    producer, consumer = source.split("\n  raw-producer:\n", 1)[1].split("\n  raw-consumer:\n", 1)
    selected_download = producer.split(
        "      - name: Download selected distribution by immutable ID\n", 1
    )[1].split("      - name: Build bounded raw distribution artifacts\n", 1)[0]
    raw_downloads = consumer.split("      - name: Verify bounded raw distribution transport\n", 1)[
        0
    ]

    assert "artifact-ids: ${{ needs.select.outputs.artifact-id }}" in selected_download
    assert "digest-mismatch: error" in selected_download
    assert "name:" not in selected_download
    assert "pattern:" not in selected_download
    assert "${{ steps.selected.outputs.download-path }}" in producer
    assert producer.count("archive: false") == 2
    assert producer.count("retention-days: 5") == 2
    assert producer.count("actions/upload-artifact@") == 2
    assert "overwrite:" not in producer
    assert consumer.count("actions/download-artifact@") == 2
    assert raw_downloads.count("skip-decompress: true") == 2
    assert raw_downloads.count("digest-mismatch: error") == 2
    assert "artifact-ids: ${{ needs.raw-producer.outputs.spine-artifact-id }}" in raw_downloads
    assert "artifact-ids: ${{ needs.raw-producer.outputs.record-artifact-id }}" in raw_downloads
    assert "needs.select.outputs.artifact-id" not in raw_downloads
    assert "build_python_artifacts.py" not in consumer
    assert "python_distribution_spine.py materialize" in consumer
    assert '--output "$materialized"' in consumer
    assert 'mkdir "$materialization_parent"' in consumer
    assert 'materialized_files=("$materialized"/*)' in consumer
    assert "skip-decompress: false" not in consumer
    assert "run-attempt: ${{ steps.build.outputs.run-attempt }}" in producer
    assert "PRODUCER_RUN_ATTEMPT: ${{ needs.raw-producer.outputs.run-attempt }}" in consumer
    assert "-artifact-${SELECTED_ARTIFACT_ID}" in producer
    assert 'basename="${basename}-attempt-${GITHUB_RUN_ATTEMPT}"' in producer
    assert "-artifact-${SELECTED_ARTIFACT_ID}" in consumer
    assert 'basename="${basename}-attempt-${PRODUCER_RUN_ATTEMPT}"' in consumer
    workflow_ref = "${{ fromJSON(toJSON(job)).workflow_ref || github.workflow_ref }}"
    workflow_sha = "${{ fromJSON(toJSON(job)).workflow_sha || github.workflow_sha }}"
    assert workflow_ref in producer
    assert workflow_sha in producer
    assert workflow_ref in consumer
    assert workflow_sha in consumer
    assert "\npermissions:\n  contents: read\n" in source
    for authority in (
        "attestations: write",
        "contents: write",
        "id-token: write",
        "packages: write",
        "pull-requests: write",
    ):
        assert authority not in consumer


def test_reusable_outputs_are_gated_by_the_raw_consumer() -> None:
    source = (WORKFLOWS / "python-distribution.yml").read_text(encoding="utf-8")
    call = source.split("  workflow_call:\n", 1)[1].split("  workflow_dispatch:\n", 1)[0]
    consumer = source.split("\n  raw-consumer:\n", 1)[1]
    consumer_outputs = consumer.split("    outputs:\n", 1)[1].split("    steps:\n", 1)[0]
    verified_outputs = consumer.split(
        "      - name: Verify bounded raw distribution transport\n", 1
    )[1]

    for output in (
        "artifact-id",
        "artifact-digest",
        "wheel-sha256",
        "selection-record-sha256",
        "spine-artifact-id",
        "spine-artifact-digest",
        "record-artifact-id",
        "record-artifact-digest",
        "producer-run-attempt",
        "workflow-ref",
        "workflow-sha",
    ):
        assert f"value: ${{{{ jobs.raw-consumer.outputs.{output} }}}}" in call
        assert f"{output}: ${{{{ steps.verify.outputs.{output} }}}}" in consumer_outputs

    for output in ("producer-run-attempt", "workflow-ref", "workflow-sha"):
        assert f"printf '{output}=%s\\n'" in verified_outputs


def test_blocked_release_job_consumes_only_the_same_run_raw_spine() -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    privileged = source.split("\n  python:\n", 1)[1].split("\n  image:\n", 1)[0]
    downloads, materializer = privileged.split(
        "      - name: Materialize the same-run verified distribution\n", 1
    )

    assert "python .github/scripts/build_python_distribution_spine.py" not in source
    assert "python .github/scripts/python_distribution_spine.py verify" not in source
    assert "      - publication-block" in privileged
    assert "      - python-distribution-proof" in privileged
    assert downloads.count("actions/download-artifact@") == 2
    assert downloads.count("skip-decompress: true") == 2
    assert downloads.count("digest-mismatch: error") == 2
    assert (
        "artifact-ids: ${{ needs.python-distribution-proof.outputs.spine-artifact-id }}"
        in downloads
    )
    assert (
        "artifact-ids: ${{ needs.python-distribution-proof.outputs.record-artifact-id }}"
        in downloads
    )
    assert "python_distribution_spine.py materialize" in materializer
    assert '--run-id "$GITHUB_RUN_ID"' in materializer
    assert '--source-revision "$GITHUB_SHA"' in materializer
    assert '--workflow-ref "$WORKFLOW_REF"' in materializer
    assert '--workflow-sha "$WORKFLOW_SHA"' in materializer
    assert "uv sync" not in privileged
    assert "uv build" not in privileged
    assert "setup-uv" not in privileged
    assert "build_python_artifacts.py" not in privileged
    assert "verify-selection" not in privileged
    assert " unzip " not in privileged
    assert " tar " not in privileged


def test_blocked_release_job_attests_only_materialized_archives_and_retains_records() -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    privileged = source.split("\n  python:\n", 1)[1].split("\n  image:\n", 1)[0]
    release = source.split("\n  release:\n", 1)[1]

    assert "${{ steps.materialize.outputs.wheel }}" in privileged
    assert "${{ steps.materialize.outputs.sdist }}" in privileged
    assert 'for artifact in "$WHEEL" "$SDIST"; do' in privileged
    for record in (
        "python-build-record-amd64.json",
        "python-build-record-arm64.json",
        "python-selection-record.json",
    ):
        assert f"${{{{ steps.materialize.outputs.directory }}}}/{record}" in privileged
    assert "name: python-distribution-selection-evidence" in privileged
    assert "python-distribution-selection-evidence" not in release


def test_cli_requires_all_out_of_band_identities() -> None:
    with pytest.raises(SystemExit):
        python_distribution_spine.main(["verify"])
    with pytest.raises(SystemExit):
        python_distribution_spine.main(["materialize"])
    with pytest.raises(SystemExit):
        builder.main([])
