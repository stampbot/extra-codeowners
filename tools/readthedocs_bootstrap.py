#!/usr/bin/env python3
"""Install the project-owned uv version for a Read the Docs build."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXACT_VERSION = re.compile(r"==(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")


def required_uv_requirement(pyproject: Path = ROOT / "pyproject.toml") -> str:
    """Return one validated pip requirement from the canonical uv constraint."""
    with pyproject.open("rb") as source:
        project = tomllib.load(source)
    try:
        required = project["tool"]["uv"]["required-version"]
    except (KeyError, TypeError) as error:
        raise RuntimeError("pyproject.toml has no uv required-version") from error
    if not isinstance(required, str) or EXACT_VERSION.fullmatch(required) is None:
        raise RuntimeError("uv required-version must be one exact semantic version")
    return f"uv{required}"


def install_command(pyproject: Path = ROOT / "pyproject.toml") -> list[str]:
    """Build the binary-only pip command used by the hosted docs environment."""
    return [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-deps",
        "--only-binary=:all:",
        required_uv_requirement(pyproject),
    ]


def main() -> int:
    """Install uv into the active Read the Docs virtual environment."""
    subprocess.run(install_command(), check=True)  # noqa: S603
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
