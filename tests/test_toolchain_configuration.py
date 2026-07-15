"""Regression tests for the reviewed uv toolchain configuration."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
SETUP_UV = re.compile(r"^(?P<indent>\s*)uses: astral-sh/setup-uv@(?P<sha>[0-9a-f]{40})(?:\s+#.*)?$")


def _mise_uv_version() -> str:
    with (ROOT / "mise.toml").open("rb") as source:
        config = tomllib.load(source)
    return cast(str, config["tools"]["uv"])


def _workflow_uv_versions() -> list[tuple[Path, str]]:
    versions: list[tuple[Path, str]] = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            action = SETUP_UV.fullmatch(line)
            if action is None:
                continue
            action_indent = len(action.group("indent"))
            step_prefix = " " * (action_indent - 2) + "- "
            input_prefix = " " * (action_indent + 2) + 'version: "'
            version: str | None = None
            for candidate in lines[index + 1 :]:
                if candidate.startswith(step_prefix):
                    break
                if candidate.startswith(input_prefix) and candidate.endswith('" # uv runtime'):
                    version = candidate.removeprefix(input_prefix).removesuffix('" # uv runtime')
            assert version is not None, f"{path}: setup-uv must pin the reviewed uv version"
            versions.append((path.relative_to(ROOT), version))
    return versions


def test_uv_version_is_identical_locally_in_containers_and_in_workflows() -> None:
    reviewed_version = _mise_uv_version()
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    image = re.search(
        r"^FROM ghcr\.io/astral-sh/uv:(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"
        r"@sha256:[0-9a-f]{64} AS uv$",
        dockerfile,
        flags=re.MULTILINE,
    )
    assert image is not None, "Dockerfile must use a digest-pinned uv image"
    assert image.group("version") == reviewed_version

    workflow_versions = _workflow_uv_versions()
    assert workflow_versions, "at least one setup-uv invocation is required"
    assert {version for _, version in workflow_versions} == {reviewed_version}


def test_dependency_audit_uses_locked_mode_without_frozen_mode() -> None:
    workflow = (ROOT / ".github" / "workflows" / "dependency-audit.yml").read_text(encoding="utf-8")
    assert "UV_FROZEN" not in workflow
    assert "--locked" in workflow
    assert "--no-cache" in workflow
    assert "--no-python-downloads" in workflow
    assert "--preview-features audit-command" in workflow


def test_renovate_owns_the_complete_uv_toolchain_update() -> None:
    raw_config = json.loads((ROOT / "renovate.json").read_text(encoding="utf-8"))
    config = cast(dict[str, Any], raw_config)
    rules = cast(list[dict[str, Any]], config["packageRules"])
    grouped_rules = [rule for rule in rules if rule.get("groupName") == "uv toolchain"]
    assert len(grouped_rules) == 1
    grouped_packages = set(cast(list[str], grouped_rules[0]["matchPackageNames"]))
    assert grouped_packages == {
        "astral-sh/setup-uv",
        "astral-sh/uv",
        "ghcr.io/astral-sh/uv",
    }
    assert grouped_rules[0].get("enabled") is True

    dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^\s+- dependency-name: astral-sh/setup-uv$", dependabot), (
        "Dependabot must not compete with Renovate for setup-uv"
    )
