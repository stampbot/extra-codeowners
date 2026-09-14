"""Exercise fail-closed runtime binding without installing or scanning an image."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.release_vex import ReleaseVexError, bind_runtime, main, validate_runtime_binding

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runtime(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "runtime"
    root.mkdir()
    for name in ("Dockerfile", ".dockerignore", "pyproject.toml", "uv.lock"):
        (root / name).write_text(name, encoding="utf-8")
    package = root / "extra_codeowners"
    package.mkdir()
    (package / "app.py").write_text("print('reviewed')\n", encoding="utf-8")
    source = root / "runtime.openvex.json"
    source.write_text(
        json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}),
        encoding="utf-8",
    )
    bind_runtime(source, root, "Reviewed application and native API reachability.")
    return source, root


def test_binding_is_deterministic_and_checks_the_current_runtime(
    runtime: tuple[Path, Path],
) -> None:
    source, root = runtime
    before = source.read_bytes()
    validate_runtime_binding(source, root)
    bind_runtime(source, root, "Reviewed application and native API reachability.")
    assert source.read_bytes() == before
    validate_runtime_binding(ROOT / "security/vex/runtime.openvex.json", ROOT)


@pytest.mark.parametrize(
    "name", ["Dockerfile", ".dockerignore", "uv.lock", "pyproject.toml", "extra_codeowners/app.py"]
)
def test_runtime_change_invalidates_review(runtime: tuple[Path, Path], name: str) -> None:
    source, root = runtime
    (root / name).write_text("changed", encoding="utf-8")
    with pytest.raises(ReleaseVexError, match="stale"):
        validate_runtime_binding(source, root)


@pytest.mark.parametrize("operation", ["add", "delete"])
def test_source_file_set_changes_invalidate_review(
    runtime: tuple[Path, Path], operation: str
) -> None:
    source, root = runtime
    if operation == "add":
        (root / "extra_codeowners/new.py").write_text("new", encoding="utf-8")
    else:
        (root / "extra_codeowners/app.py").unlink()
    with pytest.raises(ReleaseVexError):
        validate_runtime_binding(source, root)


def test_docs_and_excluded_bytecode_do_not_invalidate_review(runtime: tuple[Path, Path]) -> None:
    source, root = runtime
    (root / "README.md").write_text("Documentation change", encoding="utf-8")
    cache = root / "extra_codeowners/__pycache__"
    cache.mkdir()
    (cache / "app.cpython-312.pyc").write_bytes(b"compiled")
    validate_runtime_binding(source, root)
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "**/__pycache__/" in dockerignore
    assert "**/*.pyc" in dockerignore
    assert "**/*.pyo" in dockerignore


def test_source_symlinks_are_rejected(runtime: tuple[Path, Path]) -> None:
    source, root = runtime
    (root / "extra_codeowners/link.py").symlink_to(root / "README.md")
    with pytest.raises(ReleaseVexError, match="symlinks"):
        validate_runtime_binding(source, root)


@pytest.mark.parametrize(
    "binding", [None, {}, {"schema_version": 2}, {"schema_version": 1, "review": ""}]
)
def test_missing_or_malformed_binding_fails_closed(
    runtime: tuple[Path, Path], binding: object
) -> None:
    source, root = runtime
    document = json.loads(source.read_text(encoding="utf-8"))
    document["x_extra_codeowners_runtime"] = binding
    source.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ReleaseVexError):
        validate_runtime_binding(source, root)


def test_check_command_never_rewrites_stale_evidence(runtime: tuple[Path, Path]) -> None:
    source, root = runtime
    before = source.read_bytes()
    (root / "extra_codeowners/app.py").write_text("changed", encoding="utf-8")
    arguments = ["--source", str(source), "--runtime-root", str(root)]
    assert main(["check-runtime", *arguments]) == 2
    assert source.read_bytes() == before
    assert (
        main(["bind-runtime", *arguments, "--review", "Rechecked the changed runtime paths."]) == 0
    )
    assert main(["check-runtime", *arguments]) == 0


def test_publication_checks_runtime_before_loading_inventories(runtime: tuple[Path, Path]) -> None:
    source, root = runtime
    (root / "extra_codeowners/app.py").write_text("changed", encoding="utf-8")
    output = root / "published.json"
    assert (
        main(
            [
                "stage",
                "--source",
                str(source),
                "--runtime-root",
                str(root),
                "--inventory",
                str(root / "absent.json"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()
