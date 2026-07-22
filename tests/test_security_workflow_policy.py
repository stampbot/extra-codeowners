"""Regression tests for pull-request security workflow boundaries."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SECURITY_WORKFLOWS = (
    "dco.yml",
    "codeql.yml",
    "dependency-review.yml",
    "workflow-security.yml",
)
PULL_REQUEST_TYPES = "    types: [opened, reopened, synchronize, edited]"
FULL_SHA_ACTION = re.compile(r"uses: [^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")
GIT = shutil.which("git")
BASH = shutil.which("bash")


def _top_level_block(source: str, key: str) -> str:
    """Return one top-level YAML mapping block without interpreting YAML 1.1 keys."""
    marker = f"  {key}:\n"
    _, separator, tail = source.partition(marker)
    assert separator, f"missing {key!r} trigger"
    lines: list[str] = []
    for line in tail.splitlines():
        if line and not line.startswith(" "):
            break
        if line.startswith("  ") and not line.startswith("    "):
            break
        lines.append(line)
    return "\n".join(lines)


def _job_block(source: str, job: str, next_job: str | None = None) -> str:
    marker = f"  {job}:\n"
    _, separator, tail = source.partition(marker)
    assert separator, f"missing {job!r} job"
    if next_job is not None:
        tail, separator, _ = tail.partition(f"\n  {next_job}:\n")
        assert separator, f"missing {next_job!r} job"
    return tail


def _run_script(source: str, step_name: str) -> str:
    step = f"      - name: {step_name}\n"
    _, separator, tail = source.partition(step)
    assert separator, f"missing {step_name!r} step"
    _, separator, tail = tail.partition("        run: |\n")
    assert separator, f"missing run script for {step_name!r}"
    lines: list[str] = []
    for line in tail.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:] if line else "")
    return "\n".join(lines)


def _workflow_jobs(source: str) -> dict[str, str]:
    """Return top-level job bodies from one workflow source file."""
    _, separator, jobs_source = source.partition("\njobs:\n")
    assert separator, "missing jobs mapping"
    matches = list(re.finditer(r"(?m)^  (?P<name>[A-Za-z_][A-Za-z0-9_-]*):\n", jobs_source))
    assert matches, "workflow has no jobs"
    return {
        match.group("name"): jobs_source[
            match.end() : matches[index + 1].start() if index + 1 < len(matches) else None
        ]
        for index, match in enumerate(matches)
    }


@pytest.mark.parametrize("workflow_name", SECURITY_WORKFLOWS)
def test_security_workflows_run_for_every_pull_request_base_and_retarget(
    workflow_name: str,
) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    assert "pull_request_target:" not in source
    pull_request = _top_level_block(source, "pull_request")
    assert "branches:" not in pull_request
    assert PULL_REQUEST_TYPES in pull_request


@pytest.mark.parametrize("workflow_name", SECURITY_WORKFLOWS)
def test_security_workflows_do_not_expose_secrets_or_broad_write_permissions(
    workflow_name: str,
) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    assert "secrets:" not in source
    assert "id-token: write" not in source
    assert "contents: write" not in source
    assert "pull-requests: write" not in source
    assert "actions/cache" not in source
    assert "environment:" not in source
    assert "permissions:\n  contents: read" in source

    if workflow_name == "codeql.yml":
        assert source.count("security-events: write") == 1
        pull_request_job = _job_block(source, "analyze", "analyze-trusted")
        trusted_job = _job_block(source, "analyze-trusted")
        assert "if: github.event_name == 'pull_request'" in pull_request_job
        assert "security-events: write" not in pull_request_job
        assert "if: github.event_name != 'pull_request'" in trusted_job
        assert "security-events: write" in trusted_job
    else:
        assert "security-events: write" not in source


@pytest.mark.parametrize("workflow_name", SECURITY_WORKFLOWS)
def test_security_workflows_bound_execution_and_checkout_authority(workflow_name: str) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    assert "concurrency:" in source
    assert "cancel-in-progress: true" in source
    assert "timeout-minutes:" in source
    for line in source.splitlines():
        if "uses:" in line:
            assert FULL_SHA_ACTION.search(line.strip()), f"mutable action reference: {line}"
    assert source.count("persist-credentials: false") == source.count("actions/checkout@")


@pytest.mark.parametrize("workflow_name", ("codeql.yml", "workflow-security.yml"))
def test_trusted_push_trigger_remains_main_only(workflow_name: str) -> None:
    source = (WORKFLOWS / workflow_name).read_text(encoding="utf-8")

    assert _top_level_block(source, "push") == "    branches:\n      - main"


def test_dco_uses_the_event_base_and_head_for_its_commit_range() -> None:
    source = (WORKFLOWS / "dco.yml").read_text(encoding="utf-8")

    assert "BASE_SHA: ${{ github.event.pull_request.base.sha }}" in source
    assert "HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in source
    assert 'git rev-list "${BASE_SHA}..${HEAD_SHA}" --' in source
    assert "done < <(git rev-list" not in source
    assert 'git cat-file -e "${BASE_SHA}^{commit}"' in source
    assert 'git cat-file -e "${HEAD_SHA}^{commit}"' in source
    assert "${#commits[@]} != 10#$PR_COMMIT_COUNT" in source


def _git(repo: Path, *arguments: str) -> str:
    assert GIT is not None
    result = subprocess.run(  # noqa: S603 - arguments are fixed by each test
        [GIT, *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _dco_environment(base_sha: str, head_sha: str, commit_count: int) -> dict[str, str]:
    return os.environ | {
        "BASE_REPOSITORY_ID": "1",
        "BASE_SHA": base_sha,
        "GH_TOKEN": "unused",
        "HEAD_REF": "test/stacked-child",
        "HEAD_REPOSITORY_ID": "1",
        "HEAD_SHA": head_sha,
        "PR_AUTHOR_ID": "2",
        "PR_AUTHOR_LOGIN": "test-contributor",
        "PR_AUTHOR_TYPE": "User",
        "PR_COMMIT_COUNT": str(commit_count),
        "REPOSITORY": "example/extra-codeowners",
        "REPOSITORY_ID": "1",
    }


def _stacked_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repository"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.name", "Test Contributor")
    _git(repo, "config", "user.email", "test-contributor@example.com")
    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "base.txt")
    _git(repo, "commit", "-m", "test: add stacked base", "-s")
    base_sha = _git(repo, "rev-parse", "HEAD")
    (repo / "child.txt").write_text("child\n", encoding="utf-8")
    _git(repo, "add", "child.txt")
    _git(repo, "commit", "-m", "test: add stacked child", "-s")
    return repo, base_sha, _git(repo, "rev-parse", "HEAD")


@pytest.mark.skipif(BASH is None, reason="the hardened runtime intentionally contains no shell")
def test_dco_script_accepts_an_exact_stacked_range(tmp_path: Path) -> None:
    source = (WORKFLOWS / "dco.yml").read_text(encoding="utf-8")
    script = _run_script(source, "Verify every commit sign-off")
    repo, base_sha, head_sha = _stacked_repository(tmp_path)

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed workflow script
        [BASH, "-c", script],
        cwd=repo,
        env=_dco_environment(base_sha, head_sha, 1),
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure", ("missing-base", "commit-count"))
@pytest.mark.skipif(BASH is None, reason="the hardened runtime intentionally contains no shell")
def test_dco_script_fails_closed_when_the_range_cannot_be_proven(
    failure: str, tmp_path: Path
) -> None:
    source = (WORKFLOWS / "dco.yml").read_text(encoding="utf-8")
    script = _run_script(source, "Verify every commit sign-off")
    repo, base_sha, head_sha = _stacked_repository(tmp_path)
    if failure == "missing-base":
        base_sha = "f" * 40
    commit_count = 2 if failure == "commit-count" else 1

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed workflow script
        [BASH, "-c", script],
        cwd=repo,
        env=_dco_environment(base_sha, head_sha, commit_count),
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    if failure == "missing-base":
        assert "is not an available commit" in result.stderr
    else:
        assert "does not match enumerated range count" in result.stderr


def test_dependency_review_uses_the_pull_request_delta_without_fixed_refs() -> None:
    source = (WORKFLOWS / "dependency-review.yml").read_text(encoding="utf-8")

    assert "actions/dependency-review-action@" in source
    assert "base-ref:" not in source
    assert "head-ref:" not in source
    assert "retry-on-snapshot-warnings: true" in source
    assert "retry-on-snapshot-warnings-timeout: 120" in source
    assert "x-github-dependency-graph-snapshot-warnings" in source.lower()
    assert "Dependency graph comparison is incomplete" in source


def test_workflow_security_keeps_every_expected_gate() -> None:
    source = (WORKFLOWS / "workflow-security.yml").read_text(encoding="utf-8")

    assert "raven-actions/actionlint@" in source
    assert "zgosalvez/github-actions-ensure-sha-pinned-actions@" in source
    assert "zizmorcore/zizmor-action@" in source


def test_reusable_python_distribution_workflow_has_only_read_authority() -> None:
    source = (WORKFLOWS / "python-distribution.yml").read_text(encoding="utf-8")

    assert "  workflow_call:\n" in source
    assert "  workflow_dispatch:\n" in source
    assert (
        "concurrency:\n"
        "  group: python-distribution-${{ github.workflow }}-${{ github.ref }}\n"
        "  cancel-in-progress: false\n" in source
    )
    assert source.count("\npermissions:\n") == 1
    permission_block = source.split("\npermissions:\n", 1)[1].split("\nenv:\n", 1)[0]
    assert permission_block == "  contents: read\n"
    assert not re.search(r"(?m)^    permissions:", source)
    assert "write-all" not in source
    assert not re.search(r"(?m)^\s+[A-Za-z-]+:\s*write(?:\s*#.*)?$", source)
    for forbidden in (
        "secrets:",
        "id-token: write",
        "attestations: write",
        "contents: write",
        "packages: write",
        "environment:",
        "pull_request_target:",
    ):
        assert forbidden not in source
    assert source.count("timeout-minutes:") == 2
    assert source.count("persist-credentials: false") == source.count("actions/checkout@")
    for line in source.splitlines():
        if "uses:" in line:
            assert FULL_SHA_ACTION.search(line.strip()), f"mutable action reference: {line}"


def test_release_publication_authority_is_directly_blocked() -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    jobs = _workflow_jobs(source)
    blocker = jobs["publication-block"]

    assert "    needs: validate\n" in blocker
    assert "    permissions: {}\n" in blocker
    assert "    timeout-minutes: 1\n" in blocker
    assert blocker.count("      - name:") == 1
    assert "uses:" not in blocker
    assert "${{" not in blocker
    assert "secrets." not in blocker
    assert "continue-on-error:" not in blocker
    assert not re.search(r"(?m)^    if:|^        if:", blocker)
    assert (
        "Tagged publication is blocked by "
        "https://github.com/stampbot/extra-codeowners/issues/28" in blocker
    )
    assert "exit 1" in blocker
    assert "Keep tagged publication disabled" not in jobs["validate"]

    privileged_jobs = {
        name for name, body in jobs.items() if re.search(r"(?m)^      [a-z-]+: write$", body)
    }
    assert privileged_jobs == {"python", "image", "chart", "release"}
    for name in privileged_jobs:
        assert "      - publication-block\n" in jobs[name]
        assert not re.search(r"(?m)^    if:", jobs[name])

    for name in ("validate", "quality", "python-distribution-proof", "security-scan"):
        assert not re.search(r"(?m)^      [a-z-]+: write$", jobs[name])


@pytest.mark.skipif(BASH is None, reason="the hardened runtime intentionally contains no shell")
def test_release_publication_blocker_exits_nonzero() -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    script = _run_script(
        source, "Keep tagged publication disabled pending isolated evidence collection"
    )

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed workflow script
        [BASH, "-c", script],
        cwd=ROOT,
        env=os.environ,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "https://github.com/stampbot/extra-codeowners/issues/28" in (
        result.stdout + result.stderr
    )


def test_python_proof_handoffs_never_query_mutable_workflow_artifacts() -> None:
    proof = (WORKFLOWS / "python-distribution.yml").read_text(encoding="utf-8")
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    scan = _workflow_jobs(release)["security-scan"]
    selected_download = scan.split("      - name: Download the selected Python distribution\n", 1)[
        1
    ].split("      - name: Verify the selected Python distribution\n", 1)[0]

    for forbidden in (
        "workflow_run",
        "/actions/runs",
        "gh run",
        "latest",
        "conclusion",
        "github-token:",
        "run-id:",
    ):
        assert forbidden not in proof
        assert forbidden not in selected_download
    assert "artifact-ids: ${{ needs.python-distribution-proof.outputs.artifact-id }}" in (
        selected_download
    )
    assert "digest-mismatch: error" in selected_download


def _distribution_wrapper_environment(output: Path) -> dict[str, str]:
    return os.environ | {
        "ARTIFACT_DIGEST": "a" * 64,
        "ARTIFACT_ID": "12345",
        "GITHUB_OUTPUT": str(output),
        "PROOF_RESULT": "success",
        "SELECTION_RECORD_SHA256": "b" * 64,
        "WHEEL_SHA256": "c" * 64,
    }


@pytest.mark.skipif(BASH is None, reason="the hardened runtime intentionally contains no shell")
def test_ci_distribution_wrapper_forwards_only_validated_outputs(tmp_path: Path) -> None:
    source = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    script = _run_script(source, "Require a complete reusable distribution proof")
    output = tmp_path / "github-output"

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed workflow script
        [BASH, "-c", script],
        cwd=ROOT,
        env=_distribution_wrapper_environment(output),
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8").splitlines() == [
        "artifact-id=12345",
        f"artifact-digest={'a' * 64}",
        f"wheel-sha256={'c' * 64}",
        f"selection-record-sha256={'b' * 64}",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("PROOF_RESULT", "failure"),
        ("ARTIFACT_ID", "01"),
        ("ARTIFACT_DIGEST", f"sha256:{'a' * 64}"),
        ("WHEEL_SHA256", "C" * 64),
        ("SELECTION_RECORD_SHA256", "b" * 63),
    ),
)
@pytest.mark.skipif(BASH is None, reason="the hardened runtime intentionally contains no shell")
def test_ci_distribution_wrapper_rejects_incomplete_or_malformed_outputs(
    field: str, value: str, tmp_path: Path
) -> None:
    source = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    script = _run_script(source, "Require a complete reusable distribution proof")
    output = tmp_path / "github-output"
    environment = _distribution_wrapper_environment(output)
    environment[field] = value

    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - deliberately exercises the reviewed workflow script
        [BASH, "-c", script],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert not output.exists()
