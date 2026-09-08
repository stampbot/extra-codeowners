"""Exercise main advancing during the release tag API calls."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"
GIT = shutil.which("git")
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(GIT is None or BASH is None, reason="git and bash are required")


def _git(repo: Path, *args: str) -> str:
    assert GIT is not None
    return subprocess.run(  # noqa: S603
        [GIT, *args], cwd=repo, capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()


def _script(name: str) -> str:
    source = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1]
    source = source.split("        run: |\n", 1)[1]
    lines = []
    for line in source.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:])
    return "\n".join(lines)


@pytest.fixture
def release_env(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-b", "main")
    _git(origin, "config", "user.name", "Release Test")
    _git(origin, "config", "user.email", "test@example.com")
    _git(origin, "commit", "--allow-empty", "-m", "fix: original")
    revision = _git(origin, "rev-parse", "HEAD")
    _git(origin, "commit", "--allow-empty", "-m", "fix: newer")
    newer = _git(origin, "rev-parse", "HEAD")
    _git(origin, "checkout", "--detach")
    _git(origin, "update-ref", "refs/heads/main", revision)
    _git(tmp_path, "clone", "--branch", "main", str(origin), "runner")
    repo = tmp_path / "runner"
    _git(repo, "config", "user.name", "Release Test")
    _git(repo, "config", "user.email", "test@example.com")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    assert BASH is not None
    gh.write_text(
        f"#!{BASH}\n"
        'printf "%s\\n" "$*" >>"${API_LOG}"\n'
        'case "$*" in\n'
        '  *"/git/ref/tags/"*)\n'
        '    printf "HTTP/2 %s\\n\\n" "${REF_STATUS:-404}"\n'
        '    test "${REF_STATUS:-404}" = 200; exit $? ;;\n'
        '  *"/git/tags"*) phase=object ;;\n'
        '  *"/git/refs"*) phase=ref ;;\n'
        "  *) exit 99 ;;\n"
        "esac\n"
        'if [[ "${FAIL_PHASE:-}" == "${phase}" ]]; then\n'
        '  if [[ "${ADVANCE:-}" == true ]]; then\n'
        '    git -C "${TEST_ORIGIN}" update-ref refs/heads/main "${NEWER}"\n'
        "  fi\n"
        '  printf "HTTP/2 %s\\n\\nwrite rejected\\n" "${FAIL_STATUS:-403}"\n'
        "  exit 1\n"
        "fi\n"
        'printf "HTTP/2 201\\n\\n%s\\n" "${REVISION}"\n'
    )
    gh.chmod(0o755)
    return repo, {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "REVISION": revision,
        "NEWER": newer,
        "TAG": "v0.1.0-alpha.36",
        "GITHUB_REPOSITORY": "example/test",
        "TEST_ORIGIN": str(origin),
        "API_LOG": str(tmp_path / "api.log"),
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
    }


def _run(repo: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    return subprocess.run(  # noqa: S603
        [BASH, "-c", _script("Create immutable Git tag")],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )


def test_current_main_creates_the_tag(release_env: tuple[Path, dict[str, str]]) -> None:
    repo, env = release_env
    result = _run(repo, env)
    assert result.returncode == 0, result.stderr
    calls = Path(env["API_LOG"]).read_text().splitlines()
    assert len(calls) == 2
    assert f"object={env['REVISION']}" in calls[0]
    assert f"ref=refs/tags/{env['TAG']}" in calls[1]
    assert not Path(env["GITHUB_OUTPUT"]).exists()


def test_advance_before_tagging_defers_without_api_writes(
    release_env: tuple[Path, dict[str, str]],
) -> None:
    repo, env = release_env
    _git(Path(env["TEST_ORIGIN"]), "update-ref", "refs/heads/main", env["NEWER"])
    result = _run(repo, env)
    assert result.returncode == 0, result.stderr
    assert not Path(env["API_LOG"]).exists()
    assert Path(env["GITHUB_OUTPUT"]).read_text() == "deferred=true\n"
    assert "No release was published" in Path(env["GITHUB_STEP_SUMMARY"]).read_text()


@pytest.mark.parametrize("phase", ["object", "ref"])
@pytest.mark.parametrize("status", ["403", "404"])
def test_advance_during_either_api_write_defers_only_without_a_ref(
    release_env: tuple[Path, dict[str, str]], phase: str, status: str
) -> None:
    repo, env = release_env
    env.update(FAIL_PHASE=phase, ADVANCE="true", FAIL_STATUS=status)
    result = _run(repo, env)
    assert result.returncode == 0, result.stderr
    assert Path(env["GITHUB_OUTPUT"]).read_text() == "deferred=true\n"
    assert "/git/ref/tags/" in Path(env["API_LOG"]).read_text()


@pytest.mark.parametrize(
    "overrides",
    [
        {"ADVANCE": "false"},
        {"FAIL_STATUS": "500"},
        {"FAIL_STATUS": "422"},
        {"REF_STATUS": "200"},
        {"REF_STATUS": "403"},
        {"REF_STATUS": "500"},
    ],
)
def test_unrelated_or_ambiguous_api_failures_do_not_claim_deferral(
    release_env: tuple[Path, dict[str, str]], overrides: dict[str, str]
) -> None:
    repo, env = release_env
    env.update(FAIL_PHASE="ref", ADVANCE="true")
    env.update(overrides)
    result = _run(repo, env)
    assert result.returncode != 0
    assert not Path(env["GITHUB_OUTPUT"]).exists()


@pytest.mark.parametrize("kind", ["annotated", "lightweight", "wrong-revision"])
def test_existing_tag_is_never_abandoned_or_moved(
    release_env: tuple[Path, dict[str, str]], kind: str
) -> None:
    repo, env = release_env
    if kind == "lightweight":
        _git(repo, "tag", env["TAG"])
    else:
        revision = env["NEWER"] if kind == "wrong-revision" else env["REVISION"]
        _git(repo, "tag", "-a", env["TAG"], revision, "-m", "release")
    _git(Path(env["TEST_ORIGIN"]), "update-ref", "refs/heads/main", env["NEWER"])
    result = _run(repo, env)
    assert (result.returncode == 0) == (kind == "annotated")
    assert not Path(env["GITHUB_OUTPUT"]).exists()
    assert not Path(env["API_LOG"]).exists()


def test_every_publication_step_is_gated_on_the_tag_outcome() -> None:
    source = WORKFLOW.read_text()
    publish = source.split("  publish:\n", 1)[1].split("  verify-existing:\n", 1)[0]
    after_tag = publish.split("      - name: Publish or verify multiarch image\n", 1)[1]
    steps = re.split(r"\n      - name: [^\n]+\n", after_tag)
    assert len(steps) >= 10
    assert all("if: steps.tag.outputs.deferred != 'true'" in step for step in steps)
    assert "deferred: ${{ steps.tag.outputs.deferred }}" in publish
    assert "'Release deferred' || 'Release complete'" in source
    assert 'test "${PUBLISH_RESULT}" = success' in _script(
        "Require new or previously completed release"
    )


def test_a_rewritten_main_fails_instead_of_deferring(
    release_env: tuple[Path, dict[str, str]],
) -> None:
    repo, env = release_env
    origin = Path(env["TEST_ORIGIN"])
    _git(origin, "checkout", "--orphan", "unrelated")
    _git(origin, "commit", "--allow-empty", "-m", "unrelated history")
    _git(origin, "update-ref", "refs/heads/main", _git(origin, "rev-parse", "HEAD"))
    result = _run(repo, env)
    assert result.returncode != 0
    assert "no longer on main" in result.stderr
    assert not Path(env["GITHUB_OUTPUT"]).exists()
    assert not Path(env["API_LOG"]).exists()


def test_a_failed_fetch_does_not_turn_into_deferral(
    release_env: tuple[Path, dict[str, str]],
) -> None:
    repo, env = release_env
    _git(repo, "remote", "set-url", "origin", str(repo / "missing"))
    result = _run(repo, env)
    assert result.returncode != 0
    assert not Path(env["GITHUB_OUTPUT"]).exists()


@pytest.mark.parametrize(
    "override",
    [{}, {"PUBLISH_RESULT": "failure"}, {"IMAGE_RESULT": "failure"}, {"ALREADY_RELEASED": "true"}],
)
def test_final_outcome_does_not_hide_a_failed_job(override: dict[str, str], tmp_path: Path) -> None:
    assert BASH is not None
    env = {
        **os.environ,
        "DEFERRED": "true",
        "SUPERSEDED": "false",
        "ALREADY_RELEASED": "false",
        "PACKAGE_RESULT": "success",
        "CHART_RESULT": "success",
        "IMAGE_RESULT": "success",
        "PUBLISH_RESULT": "success",
        "VERIFY_RESULT": "skipped",
        **override,
    }
    result = subprocess.run(  # noqa: S603
        [BASH, "-euo", "pipefail", "-c", _script("Require new or previously completed release")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert (result.returncode == 0) == (not override)
    if not override:
        assert "no release is claimed" in result.stdout
