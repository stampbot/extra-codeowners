"""Tests for the maintainer-only alpha release preparation command."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from tools import prepare_prerelease as preparation


def test_parse_alpha_version_normalizes_the_project_form() -> None:
    version = preparation.parse_alpha_version("1.2.3-alpha.4")

    assert version.release == "1.2.3-alpha.4"
    assert version.project == "1.2.3a4"


@pytest.mark.parametrize(
    "value",
    ["1.2.3", "1.2.3-alpha.0", "1.2.3-alpha.04", "01.2.3-alpha.4", "1.2-alpha.4"],
)
def test_parse_alpha_version_rejects_noncanonical_targets(value: str) -> None:
    with pytest.raises(preparation.PreparationError):
        preparation.parse_alpha_version(value)


def test_update_changelog_moves_unreleased_notes_to_the_target_version() -> None:
    content = """# Changelog

## [Unreleased]

### Fixed

- Correct the thing.

## [0.1.0-alpha.4] - 2026-08-10

- Previous release.
"""

    updated = preparation.update_changelog(
        content,
        preparation.parse_alpha_version("0.1.0-alpha.5"),
        dt.date(2026, 8, 11),
    )

    assert (
        updated
        == """# Changelog

## [Unreleased]

## [0.1.0-alpha.5] - 2026-08-11

### Fixed

- Correct the thing.

## [0.1.0-alpha.4] - 2026-08-10

- Previous release.
"""
    )


def test_update_changelog_rejects_an_existing_release() -> None:
    content = """# Changelog

## [Unreleased]

## [0.1.0-alpha.5] - 2026-08-11
"""

    with pytest.raises(preparation.PreparationError, match="already contains"):
        preparation.update_changelog(
            content,
            preparation.parse_alpha_version("0.1.0-alpha.5"),
            dt.date(2026, 8, 11),
        )


def test_prepare_in_requires_a_monotonic_target_before_running_commands(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0a4"\n')
    (tmp_path / "uv.lock").write_text("version = 1\n")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [Unreleased]\n\n## [0.1.0-alpha.4] - 2026-08-10\n"
    )

    with pytest.raises(preparation.PreparationError, match="not newer"):
        preparation.prepare_in(
            tmp_path,
            preparation.parse_alpha_version("0.1.0-alpha.4"),
            dt.date(2026, 8, 11),
        )


def test_prepare_in_validates_the_changelog_before_changing_the_project(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0a4"\n')
    (tmp_path / "uv.lock").write_text("version = 1\n")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [Unreleased]\n\n## [0.1.0-alpha.5] - 2026-08-11\n"
    )
    commands: list[list[str]] = []
    monkeypatch.setattr(
        preparation,
        "run",
        lambda command, *, cwd: commands.append(command),
    )

    with pytest.raises(preparation.PreparationError, match="already contains"):
        preparation.prepare_in(
            tmp_path,
            preparation.parse_alpha_version("0.1.0-alpha.5"),
            dt.date(2026, 8, 11),
        )

    assert commands == []


def test_prepare_in_updates_changelog_and_runs_the_focused_contracts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0a4"\n')
    (tmp_path / "uv.lock").write_text("version = 1\n")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## [Unreleased]\n\n- Change.\n\n## [0.1.0-alpha.4]\n")
    commands: list[tuple[list[str], Path]] = []
    monkeypatch.setattr(preparation, "run", lambda command, *, cwd: commands.append((command, cwd)))

    preparation.prepare_in(
        tmp_path,
        preparation.parse_alpha_version("0.1.0-alpha.5"),
        dt.date(2026, 8, 11),
    )

    assert commands == [
        (["uv", "version", "0.1.0a5", "--no-sync"], tmp_path),
        (["uv", "lock", "--check"], tmp_path),
        (
            [
                "uv",
                "run",
                "--frozen",
                "pytest",
                "--no-cov",
                "tests/test_container_source_plan.py",
                "tests/test_toolchain_configuration.py",
            ],
            tmp_path,
        ),
    ]
    assert "## [0.1.0-alpha.5] - 2026-08-11" in changelog.read_text()


def test_prepare_in_restores_all_tracked_files_after_a_relock_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = tmp_path / "pyproject.toml"
    lock = tmp_path / "uv.lock"
    changelog = tmp_path / "CHANGELOG.md"
    project.write_text('[project]\nversion = "0.1.0a4"\n')
    lock.write_text("version = 1\n")
    changelog.write_text("# Changelog\n\n## [Unreleased]\n\n- Change.\n\n## [0.1.0-alpha.4]\n")
    originals = {path: path.read_bytes() for path in (project, lock, changelog)}

    def fail_after_writing_project(command: list[str], *, cwd: Path) -> None:
        assert command == ["uv", "version", "0.1.0a5", "--no-sync"]
        assert cwd == tmp_path
        project.write_text('[project]\nversion = "0.1.0a5"\n')
        raise preparation.PreparationError("simulated relock failure")

    monkeypatch.setattr(preparation, "run", fail_after_writing_project)

    with pytest.raises(preparation.PreparationError, match="simulated relock failure"):
        preparation.prepare_in(
            tmp_path,
            preparation.parse_alpha_version("0.1.0-alpha.5"),
            dt.date(2026, 8, 11),
        )

    assert {path: path.read_bytes() for path in originals} == originals
