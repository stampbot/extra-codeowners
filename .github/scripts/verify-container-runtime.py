"""Verify the supported container runtime and every locked distribution import."""

from __future__ import annotations

import importlib
import importlib.metadata
import platform
import re
import sys

EXPECTED_PYTHON = (3, 14, 6)
EXPECTED_MODULES = {
    "annotated-doc": "annotated_doc",
    "annotated-types": "annotated_types",
    "anyio": "anyio",
    "certifi": "certifi",
    "cffi": "cffi",
    "click": "click",
    "cryptography": "cryptography",
    "extra-codeowners": "extra_codeowners",
    "fastapi": "fastapi",
    "greenlet": "greenlet",
    "h11": "h11",
    "httpcore": "httpcore",
    "httpx": "httpx",
    "idna": "idna",
    "markdown-it-py": "markdown_it",
    "mdurl": "mdurl",
    "prometheus-client": "prometheus_client",
    "psycopg": "psycopg",
    "psycopg-binary": "psycopg_binary",
    "pycparser": "pycparser",
    "pydantic": "pydantic",
    "pydantic-settings": "pydantic_settings",
    "pydantic-core": "pydantic_core",
    "pygments": "pygments",
    "pyjwt": "jwt",
    "python-dotenv": "dotenv",
    "rich": "rich",
    "shellingham": "shellingham",
    "sqlalchemy": "sqlalchemy",
    "starlette": "starlette",
    "structlog": "structlog",
    "typer": "typer",
    "typing-inspection": "typing_inspection",
    "typing-extensions": "typing_extensions",
    "uvicorn": "uvicorn",
}


def canonicalize_distribution(name: str) -> str:
    """Apply Python package-name normalization without another runtime dependency."""
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> int:
    """Fail when the runtime, inventory, or any representative import drifts."""
    if sys.version_info[:3] != EXPECTED_PYTHON:
        sys.stderr.write(f"Expected Python {EXPECTED_PYTHON}, found {sys.version_info[:3]}\n")
        return 1
    if platform.libc_ver()[0] != "musl":
        sys.stderr.write(f"Expected musl runtime, found {platform.libc_ver()}\n")
        return 1

    installed = {
        canonicalize_distribution(distribution.metadata["Name"])
        for distribution in importlib.metadata.distributions()
    }
    expected = set(EXPECTED_MODULES)
    if installed != expected:
        sys.stderr.write(f"Unexpected distributions: {sorted(installed - expected)}\n")
        sys.stderr.write(f"Missing distributions: {sorted(expected - installed)}\n")
        return 1

    failed: list[tuple[str, str, str]] = []
    for distribution, module in EXPECTED_MODULES.items():
        try:
            importlib.import_module(module)
        except Exception as error:
            failed.append((distribution, module, repr(error)))

    if failed:
        for distribution, module, error in failed:
            sys.stderr.write(f"Could not import {distribution} via {module}: {error}\n")
        return 1

    sys.stdout.write(
        f"Verified Python {'.'.join(map(str, EXPECTED_PYTHON))} on musl and imported "
        f"all {len(EXPECTED_MODULES)} locked runtime distributions.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
