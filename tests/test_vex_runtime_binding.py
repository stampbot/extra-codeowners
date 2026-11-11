"""Exercise fail-closed runtime binding without installing or scanning an image."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from tools.release_vex import ReleaseVexError, bind_runtime, main, validate_runtime_binding

ROOT = Path(__file__).resolve().parents[1]


def test_local_preflight_checks_binding_without_refreshing_it() -> None:
    mise = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))
    commands = mise["tasks"]["lint:python"]["run"]
    assert "tools/release_vex.py check-runtime" in commands[0]
    assert "--source security/vex/runtime.openvex.json --runtime-root ." in commands[0]
    assert all("bind-runtime" not in command for command in commands)
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "tools/release_vex.py check-runtime" in makefile
    assert "bind-runtime" not in makefile


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
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "version": 1,
                "timestamp": "2026-09-01T00:00:00Z",
                "statements": [],
            }
        ),
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


def test_rebinding_advances_revision_and_preserves_statement_dates(
    runtime: tuple[Path, Path],
) -> None:
    source, root = runtime
    document = json.loads(source.read_text())
    previous_version = document["version"]
    previous_date = document["timestamp"]
    document["statements"] = [
        {"status": "fixed", "timestamp": previous_date},
        {"status": "fixed", "timestamp": "2026-09-02T00:00:00Z"},
    ]
    source.write_text(json.dumps(document))
    bind_runtime(source, root, "Reviewed application and native API reachability.")
    updated = json.loads(source.read_text())
    assert updated["version"] == previous_version + 1
    assert updated["timestamp"] == updated["last_updated"]
    assert [s["timestamp"] for s in updated["statements"]] == [
        previous_date,
        "2026-09-02T00:00:00Z",
    ]
    stable = source.read_bytes()
    bind_runtime(source, root, "Reviewed application and native API reachability.")
    assert source.read_bytes() == stable


def test_post_bind_statement_edit_requires_another_review(runtime: tuple[Path, Path]) -> None:
    source, root = runtime
    document = json.loads(source.read_text())
    document["statements"] = [{"status": "fixed", "timestamp": "2026-09-02T00:00:00Z"}]
    source.write_text(json.dumps(document))
    with pytest.raises(ReleaseVexError, match="content changed"):
        validate_runtime_binding(source, root)
    bind_runtime(source, root, "Reviewed the new statement.")
    validate_runtime_binding(source, root)


def test_new_statement_cannot_inherit_an_old_assessment_date(runtime: tuple[Path, Path]) -> None:
    source, root = runtime
    document = json.loads(source.read_text())
    document["statements"] = [{"status": "fixed"}]
    source.write_text(json.dumps(document))
    before = source.read_bytes()
    with pytest.raises(ReleaseVexError, match="statement timestamp"):
        bind_runtime(source, root, "Reviewed the new statement.")
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    "relative",
    ["tools/source_recipes/fictional-99.json", "security/vex/native-openssl-callers.json"],
)
def test_native_review_inputs_cannot_change_without_another_review(
    runtime: tuple[Path, Path], relative: str
) -> None:
    source, root = runtime
    evidence = root / relative
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"fictional": 1}\n', encoding="utf-8")
    bind_runtime(source, root, "Reviewed fictional native evidence.")
    validate_runtime_binding(source, root)
    before = source.read_bytes()
    evidence.write_text('{"fictional": 2}\n', encoding="utf-8")
    with pytest.raises(ReleaseVexError, match="stale"):
        validate_runtime_binding(source, root)
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    "timestamp",
    [
        "not-a-date",
        "2026-02-30T00:00:00Z",
        "2026-09-02",
        "2026-09-02T00:00:00",
        "2026-09-02 00:00:00Z",
        "2026-09-02T00:00:00+24:00",
        "2026-09-02T00:00:00+00:60",
    ],
)
def test_rebinding_rejects_malformed_statement_dates_without_rewriting(
    runtime: tuple[Path, Path], timestamp: str
) -> None:
    source, root = runtime
    document = json.loads(source.read_text())
    document["statements"] = [{"status": "fixed", "timestamp": timestamp}]
    source.write_text(json.dumps(document))
    before = source.read_bytes()
    with pytest.raises(ReleaseVexError, match=r"timestamp.*date-time"):
        bind_runtime(source, root, "Reviewed the new statement.")
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    "timestamp", ["2026-09-02T00:00:00Z", "2026-09-02t00:00:00.123z", "2026-09-02T10:30:00+05:30"]
)
def test_rebinding_preserves_valid_statement_dates(
    runtime: tuple[Path, Path], timestamp: str
) -> None:
    source, root = runtime
    document = json.loads(source.read_text())
    document["statements"] = [{"status": "fixed", "timestamp": timestamp}]
    source.write_text(json.dumps(document))
    bind_runtime(source, root, "Reviewed the new statement.")
    assert json.loads(source.read_text())["statements"][0]["timestamp"] == timestamp


def test_runtime_only_change_advances_vex_revision(runtime: tuple[Path, Path]) -> None:
    source, root = runtime
    before = json.loads(source.read_text())["version"]
    (root / "extra_codeowners/app.py").write_text("changed")
    bind_runtime(source, root, "Reviewed application and native API reachability.")
    assert json.loads(source.read_text())["version"] == before + 1


@pytest.mark.parametrize("version", [0, -1, True, "3"])
def test_rebinding_rejects_invalid_revision_without_rewriting(
    runtime: tuple[Path, Path], version: object
) -> None:
    source, root = runtime
    document = json.loads(source.read_text())
    document["version"] = version
    source.write_text(json.dumps(document))
    before = source.read_bytes()
    with pytest.raises(ReleaseVexError, match="positive OpenVEX"):
        bind_runtime(source, root, "Reviewed application and native API reachability.")
    assert source.read_bytes() == before


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
