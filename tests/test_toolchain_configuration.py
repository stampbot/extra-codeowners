"""Regression tests for the reviewed uv toolchain configuration."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
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
    assert "COPY pyproject.toml uv.lock README.md mise.toml requirements-build.txt ./" in dockerfile
    assert "COPY .github/scripts/build_python_artifacts.py ./.github/scripts/" in dockerfile
    assert (
        "COPY .github/scripts/container_evidence.py .github/scripts/release_readiness.py "
        "./.github/scripts/"
    ) in dockerfile
    assert '["uv", "--version"]' in dockerfile
    assert "if actual != expected:" in dockerfile
    assert "digest-selected uv is" in dockerfile

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


def test_ci_checks_lockfile_freshness_outside_frozen_mode() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    lock_check = workflow.split("      - name: Verify lockfile is current\n", 1)[1].split(
        "\n      - name:", 1
    )[0]

    assert 'UV_FROZEN: "false"' in lock_check
    assert "run: uv lock --check" in lock_check


def test_pinned_uv_exposes_the_scheduled_audit_interface_without_network() -> None:
    uv = shutil.which("uv")
    assert uv is not None, "the pinned uv executable must be available to the test suite"
    result = subprocess.run(  # noqa: S603
        [uv, "--preview-features", "audit-command", "audit", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "Audit the project's dependencies" in result.stdout
    assert "--locked" in result.stdout
    assert "--python-version" in result.stdout


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


def test_renovate_groups_the_hash_locked_python_build_closure() -> None:
    raw_config = json.loads((ROOT / "renovate.json").read_text(encoding="utf-8"))
    config = cast(dict[str, Any], raw_config)
    rules = cast(list[dict[str, Any]], config["packageRules"])
    grouped_rules = [rule for rule in rules if rule.get("groupSlug") == "python-build-toolchain"]
    assert grouped_rules == [
        {
            "description": "Update the complete isolated Python build toolchain together",
            "matchManagers": ["pip_requirements"],
            "matchFileNames": ["requirements-build.txt"],
            "groupName": "Python build toolchain",
            "groupSlug": "python-build-toolchain",
            "rangeStrategy": "replace",
            "separateMajorMinor": False,
        },
        {
            "description": "Keep the project backend pin with its hashed build closure",
            "matchManagers": ["pep621"],
            "matchFileNames": ["pyproject.toml"],
            "matchDepTypes": ["build-system.requires"],
            "matchPackageNames": ["hatchling"],
            "groupName": "Python build toolchain",
            "groupSlug": "python-build-toolchain",
            "rangeStrategy": "replace",
            "separateMajorMinor": False,
        },
    ]


def test_reusable_workflow_proves_one_native_cross_architecture_distribution() -> None:
    workflow = (ROOT / ".github" / "workflows" / "python-distribution.yml").read_text(
        encoding="utf-8"
    )
    proof = workflow.split("  native-proof:\n", 1)[1].split("  select:\n", 1)[0]
    selector = workflow.split("  select:\n", 1)[1]

    assert "  workflow_call:\n" in workflow
    assert "  workflow_dispatch:\n" in workflow
    for output in (
        "artifact-id",
        "artifact-digest",
        "wheel-sha256",
        "selection-record-sha256",
    ):
        assert f"value: ${{{{ jobs.select.outputs.{output} }}}}" in workflow

    assert "name: Native proof (${{ matrix.architecture }})" in proof
    assert proof.count("runner: ubuntu-24.04\n") == 1
    assert proof.count("runner: ubuntu-24.04-arm\n") == 1
    assert 'python-version: "3.14.6"' in proof
    assert "timeout-minutes: 20" in proof
    assert '--source-revision "$GITHUB_SHA"' in proof
    assert '--scratch-directory "$scratch"' in proof
    assert "compression-level: 0" in proof
    assert "python-distributions-${{ matrix.architecture }}-${{ github.sha }}-attempt-" in proof
    assert "${{ github.run_attempt }}" in proof

    assert "needs: native-proof" in selector
    assert "if: ${{ always() }}" in selector
    assert 'if [ "$PROOF_RESULT" != success ]; then' in selector
    assert selector.count("actions/download-artifact@3e5f45b2") == 2
    assert "python-distributions-amd64-${{ github.sha }}-attempt-" in selector
    assert "python-distributions-arm64-${{ github.sha }}-attempt-" in selector
    assert "merge-multiple" not in selector
    assert selector.count("digest-mismatch: error") == 2
    assert "artifact-id: ${{ steps.upload-selected.outputs.artifact-id }}" in selector
    assert "artifact-digest: ${{ steps.upload-selected.outputs.artifact-digest }}" in selector
    assert "wheel-sha256: ${{ steps.select.outputs.wheel-sha256 }}" in selector
    assert (
        "selection-record-sha256: ${{ steps.select.outputs.selection-record-sha256 }}" in selector
    )
    assert "jq -er '.selection_record_sha256'" in selector


def test_ci_calls_the_reusable_proof_and_preserves_the_required_check() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    caller = workflow.split("  python-distribution-proof:\n", 1)[1].split(
        "  python-distribution:\n", 1
    )[0]
    required_check = workflow.split("  python-distribution:\n", 1)[1].split("  container:\n", 1)[0]
    container = workflow.split("  container:\n", 1)[1]

    assert "name: Build Python distribution proof" in caller
    assert "permissions:\n      contents: read" in caller
    assert "uses: ./.github/workflows/python-distribution.yml" in caller
    assert "secrets:" not in caller

    assert "name: Python distribution reproducibility" in required_check
    assert "needs: python-distribution-proof" in required_check
    assert "if: ${{ always() }}" in required_check
    assert "id: accept" in required_check
    assert 'if [ "$PROOF_RESULT" != success ]; then' in required_check
    assert '[[ "$ARTIFACT_ID" =~ ^[1-9][0-9]*$ ]]' in required_check
    assert '[[ "$ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]' in required_check
    assert '[[ "$WHEEL_SHA256" =~ ^[0-9a-f]{64}$ ]]' in required_check
    assert '[[ "$SELECTION_RECORD_SHA256" =~ ^[0-9a-f]{64}$ ]]' in required_check
    for output in (
        "artifact-id",
        "artifact-digest",
        "wheel-sha256",
        "selection-record-sha256",
    ):
        assert f"{output}: ${{{{ steps.accept.outputs.{output} }}}}" in required_check
        assert f"printf '{output}=%s\\n'" in required_check

    assert "needs: python-distribution" in container
    assert "if: ${{ always() }}" in container
    assert 'if [ "$DISTRIBUTION_RESULT" != success ]; then' in container
    assert "artifact-ids: ${{ needs.python-distribution.outputs.artifact-id }}" in container
    assert (
        container.count("verified-python=${{ steps.python-distribution.outputs.download-path }}")
        == 2
    )
    assert container.count("APPLICATION_SOURCE_REVISION=${{ github.sha }}") == 2
    assert (
        container.count(
            "APPLICATION_WHEEL_SHA256=${{ needs.python-distribution.outputs.wheel-sha256 }}"
        )
        == 2
    )
    assert (
        container.count(
            "APPLICATION_SELECTION_RECORD_SHA256=${{ "
            "needs.python-distribution.outputs.selection-record-sha256 }}"
        )
        == 2
    )
    assert "--python-distribution-artifact-id" in container
    assert "--python-distribution-artifact-digest" in container
    assert "--application-selection-record-sha256" in container
    assert "--selected-python-directory" in container


def test_release_scan_consumes_only_the_same_run_selected_distribution() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    caller = workflow.split("  python-distribution-proof:\n", 1)[1].split("  quality:\n", 1)[0]
    scan = workflow.split("  security-scan:\n", 1)[1].split("  publication-block:\n", 1)[0]
    download = scan.split("      - name: Download the selected Python distribution\n", 1)[1].split(
        "      - name: Verify the selected Python distribution\n", 1
    )[0]

    assert "needs: validate" in caller
    assert "permissions:\n      contents: read" in caller
    assert "uses: ./.github/workflows/python-distribution.yml" in caller
    assert "secrets:" not in caller

    assert "      - python-distribution-proof" in scan
    assert "artifact-ids: ${{ needs.python-distribution-proof.outputs.artifact-id }}" in download
    assert "digest-mismatch: error" in download
    for mutable_input in ("name:", "pattern:", "run-id:", "repository:", "github-token:"):
        assert mutable_input not in download
    assert "verify-selection" in scan
    assert '--source-revision "$GITHUB_SHA"' in scan
    assert '--wheel-sha256 "$WHEEL_SHA256"' in scan
    assert '--selection-record-sha256 "$SELECTION_RECORD_SHA256"' in scan
    assert "verified-python=${{ steps.python-distribution.outputs.download-path }}" in scan
    assert "APPLICATION_SOURCE_REVISION=${{ github.sha }}" in scan
    assert (
        "APPLICATION_WHEEL_SHA256=${{ needs.python-distribution-proof.outputs.wheel-sha256 }}"
        in scan
    )
    assert (
        "APPLICATION_SELECTION_RECORD_SHA256=${{ "
        "needs.python-distribution-proof.outputs.selection-record-sha256 }}" in scan
    )

    privileged = workflow.split("  publication-block:\n", 1)[1]
    assert (
        "artifact-ids: ${{ needs.python-distribution-proof.outputs.artifact-id }}" not in privileged
    )
    assert (
        "verified-python=${{ steps.python-distribution.outputs.download-path }}" not in privileged
    )


def test_dockerfile_can_only_install_the_selected_application_wheel() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    builder = dockerfile.split(" AS builder\n", 1)[1].split("\nFROM builder AS test", 1)[0]
    test_stage = dockerfile.split("FROM builder AS test\n", 1)[1].split("\nFROM python:", 1)[0]

    assert "COPY extra_codeowners/" not in builder
    assert "extra_codeowners" in dockerignore
    assert "uv build" not in dockerfile
    assert "reinstall-package extra-codeowners" not in dockerfile
    assert "uv sync --frozen --no-dev --no-install-project --no-build" in builder
    assert "--mount=from=verified-python,target=/verified-python,ro" in builder
    assert "--network=none" in builder
    assert "verify-selection" in builder
    assert "--selection-record-sha256" in builder
    assert "uv pip install" in builder
    assert "--offline" in builder
    assert "--no-index" in builder
    assert "--no-deps" in builder
    assert "--no-build" in builder
    assert "--strict" in builder
    assert "verify-installed" in builder
    assert "uv sync --frozen --group dev --no-install-project --inexact --no-build" in test_stage
    assert "verify-installed" in test_stage
    assert "COPY extra_codeowners/" not in test_stage
    assert "test ! -e /build/extra_codeowners" in test_stage
    assert 'Path("/opt/venv/lib/python3.14/site-packages")' in test_stage
    assert dockerfile.count("org.stampbot.extra-codeowners.application-wheel.sha256") == 2
    assert dockerfile.count("org.stampbot.extra-codeowners.python-selection-record.sha256") == 2
    assert "ARTIFACT_ID" not in dockerfile
    assert "RUN_ATTEMPT" not in dockerfile
    assert "VCS_REF" not in dockerfile


def test_workflows_do_not_pass_the_removed_vcs_ref_build_argument() -> None:
    workflows = "\n".join(path.read_text() for path in Path(".github/workflows").glob("*.yml"))
    assert "VCS_REF" not in workflows
