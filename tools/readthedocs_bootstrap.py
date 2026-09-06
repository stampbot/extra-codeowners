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


def required_uv_requirement(lockfile: Path = ROOT / "uv.lock") -> str:
    """Return the exact uv requirement used by CI and documentation builds."""
    with lockfile.open("rb") as source:
        lock = tomllib.load(source)
    try:
        packages = [package for package in lock["package"] if package["name"] == "uv"]
        if len(packages) != 1:
            raise RuntimeError("uv.lock must contain exactly one uv package")
        required = f"=={packages[0]['version']}"
    except (KeyError, TypeError) as error:
        raise RuntimeError("uv.lock has no valid uv package") from error
    if EXACT_VERSION.fullmatch(required) is None:
        raise RuntimeError("locked uv must be one exact semantic version")
    return f"uv{required}"


def install_command(lockfile: Path = ROOT / "uv.lock") -> list[str]:
    """Build the binary-only pip command used by the hosted docs environment."""
    return [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-deps",
        "--only-binary=:all:",
        required_uv_requirement(lockfile),
    ]


def main() -> int:
    """Install uv into the active Read the Docs virtual environment."""
    subprocess.run(install_command(), check=True)  # noqa: S603
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
