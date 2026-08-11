#!/usr/bin/env python3
"""Prepare one alpha release without publishing it.

The signed tag remains the only way to publish an image, chart, or GitHub
release. This command changes the project version, lock file, and changelog in
one clean checkout, then runs the focused checks that cover those changes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "pyproject.toml"
LOCK = ROOT / "uv.lock"
CHANGELOG = ROOT / "CHANGELOG.md"


class PreparationError(RuntimeError):
    """The requested prerelease cannot be prepared safely."""


@dataclass(frozen=True)
class AlphaVersion:
    """The two public forms of one alpha version."""

    release: str
    project: str


def parse_alpha_version(value: str) -> AlphaVersion:
    """Validate one public alpha version and return its PEP 440 counterpart."""

    prefix, separator, sequence = value.partition("-alpha.")
    if not separator or not prefix or not sequence.isdecimal() or sequence.startswith("0"):
        raise PreparationError("target must be MAJOR.MINOR.PATCH-alpha.N, where N is at least one")
    parts = prefix.split(".")
    if len(parts) != 3 or any(not part.isdecimal() for part in parts):
        raise PreparationError("target must be MAJOR.MINOR.PATCH-alpha.N, where N is at least one")
    normalized = ".".join(str(int(part)) for part in parts)
    if normalized != prefix:
        raise PreparationError("target version must not contain leading zeroes")
    project = f"{prefix}a{sequence}"
    try:
        if str(Version(project)) != project:
            raise PreparationError("target version is not a canonical PEP 440 alpha version")
    except InvalidVersion as exc:
        raise PreparationError("target version is not a valid PEP 440 alpha version") from exc
    return AlphaVersion(release=value, project=project)


def project_version(path: Path) -> Version:
    """Read the canonical static project version from pyproject.toml."""

    try:
        project = tomllib.loads(path.read_text(encoding="utf-8"))["project"]
        raw = project["version"]
    except (KeyError, OSError, tomllib.TOMLDecodeError) as exc:
        raise PreparationError(f"cannot read project version from {path}") from exc
    if not isinstance(raw, str):
        raise PreparationError("project version must be a string")
    try:
        return Version(raw)
    except InvalidVersion as exc:
        raise PreparationError("project version is not valid PEP 440") from exc


def update_changelog(content: str, version: AlphaVersion, release_date: dt.date) -> str:
    """Move Unreleased notes under one new Keep a Changelog alpha heading."""

    marker = "## [Unreleased]\n"
    if content.count(marker) != 1:
        raise PreparationError(
            "CHANGELOG.md must contain one empty-line-terminated Unreleased heading"
        )
    heading = f"## [{version.release}] - {release_date.isoformat()}\n"
    if heading in content or f"## [{version.release}]" in content:
        raise PreparationError(f"CHANGELOG.md already contains {version.release}")
    before, after_marker = content.split(marker, 1)
    next_heading = after_marker.find("\n## [")
    if next_heading < 0:
        raise PreparationError("CHANGELOG.md has no prior release heading after Unreleased")
    unreleased = after_marker[: next_heading + 1].lstrip("\n")
    history = after_marker[next_heading + 1 :]
    return f"{before}{marker}\n{heading}\n{unreleased}{history}"


def run(command: list[str], *, cwd: Path) -> None:
    """Run one required local command without a shell."""

    try:
        subprocess.run(command, cwd=cwd, check=True)  # noqa: S603
    except (OSError, subprocess.CalledProcessError) as exc:
        rendered = " ".join(command)
        raise PreparationError(f"required command failed: {rendered}") from exc


def require_clean_checkout(root: Path) -> None:
    """Refuse to mix release preparation with unrelated changes."""

    git = shutil.which("git")
    if git is None:
        raise PreparationError("git is required to verify a clean checkout")
    try:
        result = subprocess.run(  # noqa: S603
            [git, "status", "--porcelain"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PreparationError("cannot verify whether the checkout is clean") from exc
    if result.stdout:
        raise PreparationError("checkout is not clean; commit or stash unrelated work first")


def prepare_in(
    root: Path, version: AlphaVersion, release_date: dt.date, *, run_focused_checks: bool = True
) -> None:
    """Update versioned files and prove their focused local contracts."""

    current = project_version(root / PROJECT.name)
    target = Version(version.project)
    if target <= current:
        raise PreparationError(
            f"target {version.release} is not newer than project version {current}"
        )
    changelog = root / CHANGELOG.name
    updated_changelog = update_changelog(
        changelog.read_text(encoding="utf-8"), version, release_date
    )
    run(["uv", "version", version.project, "--no-sync"], cwd=root)
    changelog.write_text(updated_changelog, encoding="utf-8")
    run(["uv", "lock", "--check"], cwd=root)
    if run_focused_checks:
        run(
            [
                "uv",
                "run",
                "--frozen",
                "--no-sync",
                "pytest",
                "--no-cov",
                "tests/test_container_source_plan.py",
                "tests/test_toolchain_configuration.py",
            ],
            cwd=root,
        )


def dry_run(root: Path, version: AlphaVersion, release_date: dt.date) -> str:
    """Prepare a temporary copy and return the exact tracked-file diff."""

    with tempfile.TemporaryDirectory(prefix="extra-codeowners-release-") as temporary:
        candidate = Path(temporary)
        for source in (PROJECT, LOCK, CHANGELOG):
            shutil.copy2(source, candidate / source.name)
        prepare_in(candidate, version, release_date, run_focused_checks=False)
        lines: list[str] = []
        for source in (PROJECT, LOCK, CHANGELOG):
            before = source.read_text(encoding="utf-8").splitlines(keepends=True)
            after = (candidate / source.name).read_text(encoding="utf-8").splitlines(keepends=True)
            lines.extend(
                difflib.unified_diff(before, after, fromfile=str(source), tofile=str(source))
            )
        return "".join(lines)


def parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""

    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("version", help="target version as MAJOR.MINOR.PATCH-alpha.N")
    result.add_argument(
        "--date",
        type=dt.date.fromisoformat,
        default=dt.datetime.now(tz=dt.UTC).date(),
        help="release-note date in YYYY-MM-DD format (default: today)",
    )
    result.add_argument("--dry-run", action="store_true", help="show changes without writing them")
    return result


def main(argv: list[str] | None = None) -> int:
    """Run release preparation and return a conventional process status."""

    arguments = parser().parse_args(argv)
    try:
        version = parse_alpha_version(arguments.version)
        if arguments.dry_run:
            sys.stdout.write(dry_run(ROOT, version, arguments.date))
            return 0
        require_clean_checkout(ROOT)
        prepare_in(ROOT, version, arguments.date)
    except PreparationError as exc:
        sys.stderr.write(f"Release preparation error: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
