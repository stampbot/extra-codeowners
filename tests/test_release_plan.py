from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "release_plan.py"
_git = shutil.which("git")
if _git is None:
    raise RuntimeError("git is required to test the release planner")
GIT: str = _git


def load_release_plan() -> ModuleType:
    spec = importlib.util.spec_from_file_location("release_plan", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


release_plan = load_release_plan()


def git(repository: Path, *arguments: str) -> str:
    result: subprocess.CompletedProcess[str] = subprocess.run(  # noqa: S603
        [GIT, *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> Iterator[Path]:
    git(tmp_path, "init", "--initial-branch=main")
    git(tmp_path, "config", "user.name", "Release Planner Tests")
    git(tmp_path, "config", "user.email", "release-planner@example.invalid")
    commit(tmp_path, "chore: initial source")
    yield tmp_path


def commit(repository: Path, subject: str, body: str = "") -> str:
    marker = repository / "history.txt"
    previous = marker.read_text(encoding="utf-8") if marker.exists() else ""
    marker.write_text(previous + subject + "\n", encoding="utf-8")
    git(repository, "add", "history.txt")
    command = ["commit", "-m", subject]
    if body:
        command.extend(["-m", body])
    git(repository, *command)
    return git(repository, "rev-parse", "HEAD")


def tag(repository: Path, name: str) -> None:
    git(repository, "tag", "-a", name, "-m", name)


def output_map(plan: object) -> dict[str, str]:
    return dict(line.split("=", 1) for line in release_plan.render_outputs(plan))


def test_bootstrap_starts_numeric_alpha(repository: Path) -> None:
    plan = release_plan.calculate_release_plan(repository)

    assert output_map(plan) == {
        "tag": "v0.1.0-alpha.1",
        "version": "0.1.0-alpha.1",
        "python_version": "0.1.0a1",
        "previous_tag": "",
        "superseded": "false",
    }


def test_alpha_release_increments_numeric_suffix(repository: Path) -> None:
    tag(repository, "v0.1.0-alpha.7")
    commit(repository, "ci: replace release pipeline")

    plan = release_plan.calculate_release_plan(repository)

    assert output_map(plan) == {
        "tag": "v0.1.0-alpha.8",
        "version": "0.1.0-alpha.8",
        "python_version": "0.1.0a8",
        "previous_tag": "v0.1.0-alpha.7",
        "superseded": "false",
    }


def test_release_channel_trailer_enters_alpha_from_a_stable_release(repository: Path) -> None:
    tag(repository, "v1.2.3")
    commit(
        repository,
        "fix: begin a shadow release line",
        "Release-Channel: alpha\n"
        "Signed-off-by: Release Planner Tests <release-planner@example.invalid>",
    )

    assert release_plan.calculate_release_plan(repository).tag == "v1.2.4-alpha.1"


def test_release_channel_trailer_promotes_alpha_to_stable(repository: Path) -> None:
    tag(repository, "v1.2.4-alpha.7")
    commit(repository, "fix: promote the release line", "Release-Channel: stable")

    assert release_plan.calculate_release_plan(repository).tag == "v1.2.4"


def test_promoted_release_is_reused_on_retry(repository: Path) -> None:
    tag(repository, "v1.2.4-alpha.7")
    commit(repository, "fix: promote the release line", "Release-Channel: stable")
    tag(repository, "v1.2.4")

    plan = release_plan.calculate_release_plan(repository)

    assert plan.tag == "v1.2.4"
    assert plan.previous_tag == "v1.2.4-alpha.7"
    assert plan.superseded is False


def test_promoted_release_supersedes_an_older_queued_run(repository: Path) -> None:
    tag(repository, "v1.2.4-alpha.7")
    older_run = commit(repository, "fix: promote the release line", "Release-Channel: stable")
    commit(repository, "fix: newer queued run")
    tag(repository, "v1.2.4")
    git(repository, "checkout", "--detach", older_run)

    plan = release_plan.calculate_release_plan(repository)

    assert plan.tag == "v1.2.4"
    assert plan.previous_tag == "v1.2.4-alpha.7"
    assert plan.superseded is True


def test_promoted_stable_release_returns_to_conventional_bumps(repository: Path) -> None:
    tag(repository, "v1.2.4-alpha.7")
    commit(repository, "fix: promote the release line", "Release-Channel: stable")
    tag(repository, "v1.2.4")
    commit(repository, "feat: begin the next minor release")

    assert release_plan.calculate_release_plan(repository).tag == "v1.3.0"


def test_release_channel_trailers_replay_in_history_order(repository: Path) -> None:
    tag(repository, "v1.2.3")
    commit(repository, "fix: enter alpha", "Release-Channel: alpha")
    commit(repository, "fix: leave alpha", "Release-Channel: stable")

    assert release_plan.calculate_release_plan(repository).tag == "v1.2.4"


def test_bootstrap_can_promote_to_stable_with_a_trailer(repository: Path) -> None:
    commit(repository, "fix: first stable release", "Release-Channel: stable")

    assert release_plan.calculate_release_plan(repository).tag == "v0.1.0"


@pytest.mark.parametrize(
    ("initial_tag", "body", "match"),
    [
        ("v1.2.3", "Release-Channel: stable", "does not change"),
        ("v1.2.3-alpha.7", "Release-Channel: alpha", "does not change"),
        ("v1.2.3", "Release-Channel: candidate", "invalid Release-Channel"),
        (
            "v1.2.3-alpha.7",
            "Release-Channel=stable\n"
            "Signed-off-by: Release Planner Tests <release-planner@example.invalid>",
            "malformed Release-Channel",
        ),
        ("v1.2.3-alpha.7", "Release-Channel = stable", "malformed Release-Channel"),
        (
            "v1.2.3",
            "Release-Channel: alpha\nRelease-Channel: stable",
            "at most one Release-Channel",
        ),
    ],
)
def test_release_channel_rejects_ambiguous_or_noop_transitions(
    repository: Path, initial_tag: str, body: str, match: str
) -> None:
    tag(repository, initial_tag)
    commit(repository, "fix: change release channel", body)

    with pytest.raises(release_plan.ReleasePlanError, match=match):
        release_plan.calculate_release_plan(repository)


def test_release_channel_ignores_prose_that_is_not_a_trailer(repository: Path) -> None:
    tag(repository, "v1.2.3")
    commit(
        repository,
        "fix: explain alpha",
        "This prose mentions Release-Channel: alpha, but it is not a trailer.\n\nMore prose.",
    )

    assert release_plan.calculate_release_plan(repository).tag == "v1.2.4"


def test_existing_head_tag_is_reused_even_when_newer_release_exists(repository: Path) -> None:
    old_commit = git(repository, "rev-parse", "HEAD")
    tag(repository, "v0.1.0-alpha.1")
    commit(repository, "fix: later release")
    tag(repository, "v0.1.0-alpha.2")
    git(repository, "checkout", "--detach", old_commit)

    plan = release_plan.calculate_release_plan(repository)

    assert plan.tag == "v0.1.0-alpha.1"
    assert plan.previous_tag is None
    assert plan.superseded is False


def test_untagged_older_run_is_superseded_by_a_descendant_release(repository: Path) -> None:
    tag(repository, "v0.1.0-alpha.1")
    older_run = commit(repository, "fix: older queued run")
    commit(repository, "fix: newer queued run")
    tag(repository, "v0.1.0-alpha.2")
    git(repository, "checkout", "--detach", older_run)

    plan = release_plan.calculate_release_plan(repository)

    assert output_map(plan) == {
        "tag": "v0.1.0-alpha.2",
        "version": "0.1.0-alpha.2",
        "python_version": "0.1.0a2",
        "previous_tag": "v0.1.0-alpha.1",
        "superseded": "true",
    }


@pytest.mark.parametrize(
    ("subject", "body", "expected"),
    [
        ("docs: clarify installation", "", "v1.2.4"),
        ("feat(api): support another event", "", "v1.3.0"),
        ("fix!: remove obsolete behavior", "", "v2.0.0"),
        ("fix: reject invalid policy", "BREAKING CHANGE: policy files are stricter", "v2.0.0"),
    ],
)
def test_stable_release_uses_conventional_commits(
    repository: Path,
    subject: str,
    body: str,
    expected: str,
) -> None:
    tag(repository, "v1.2.3")
    commit(repository, subject, body)

    assert release_plan.calculate_release_plan(repository).tag == expected


def test_breaking_commit_wins_over_feature(repository: Path) -> None:
    tag(repository, "v1.2.3")
    commit(repository, "feat: add a feature")
    commit(repository, "refactor(core)!: remove compatibility")

    assert release_plan.calculate_release_plan(repository).tag == "v2.0.0"


@pytest.mark.parametrize(
    "malformed",
    [
        "v1",
        "v1.2",
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
        "v1.2.3-alpha",
        "v1.2.3-alpha.0",
        "v1.2.3-alpha.01",
        "v1.2.3-beta.1",
        "v1.2.3+build.1",
    ],
)
def test_malformed_release_like_tags_are_rejected(repository: Path, malformed: str) -> None:
    tag(repository, malformed)

    with pytest.raises(release_plan.ReleasePlanError, match="malformed release tag"):
        release_plan.calculate_release_plan(repository)


def test_unrelated_tags_are_ignored(repository: Path) -> None:
    tag(repository, "vendor-snapshot")

    assert release_plan.calculate_release_plan(repository).tag == "v0.1.0-alpha.1"


def test_multiple_release_tags_on_head_are_ambiguous(repository: Path) -> None:
    tag(repository, "v1.0.0-alpha.1")
    tag(repository, "v1.0.0-alpha.2")

    with pytest.raises(release_plan.ReleasePlanError, match="multiple release tags identify HEAD"):
        release_plan.calculate_release_plan(repository)


def test_latest_release_tag_must_be_an_ancestor(repository: Path) -> None:
    tag(repository, "v1.0.0")
    git(repository, "checkout", "-b", "other")
    commit(repository, "feat: future branch")
    tag(repository, "v2.0.0")
    git(repository, "checkout", "main")
    commit(repository, "fix: main branch")

    with pytest.raises(
        release_plan.ReleasePlanError, match=r"latest release tag .* is not an ancestor"
    ):
        release_plan.calculate_release_plan(repository)


def test_release_versions_must_increase_with_history(repository: Path) -> None:
    tag(repository, "v1.2.0")
    commit(repository, "fix: later commit")
    tag(repository, "v1.1.0")
    commit(repository, "fix: next release")

    with pytest.raises(release_plan.ReleasePlanError, match="release versions are non-monotonic"):
        release_plan.calculate_release_plan(repository)


def test_linear_history_validation_scales_with_adjacent_tags(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tag(repository, "v1.0.0")
    for patch in range(1, 20):
        commit(repository, f"fix: release {patch}")
        tag(repository, f"v1.0.{patch}")
    tags = release_plan.read_release_tags(repository)
    original = release_plan._is_ancestor
    calls = 0

    def count_calls(repository: Path, ancestor: str, descendant: str) -> bool:
        nonlocal calls
        calls += 1
        result = original(repository, ancestor, descendant)
        assert isinstance(result, bool)
        return result

    monkeypatch.setattr(release_plan, "_is_ancestor", count_calls)

    release_plan.validate_linear_history(repository, tags)

    assert calls == len(tags) - 1


def test_parallel_release_histories_are_rejected(repository: Path) -> None:
    base = git(repository, "rev-parse", "HEAD")
    git(repository, "checkout", "-b", "release-one")
    commit(repository, "fix: first branch")
    tag(repository, "v1.0.0")
    git(repository, "checkout", "-b", "release-two", base)
    commit(repository, "fix: second branch")
    tag(repository, "v1.1.0")
    git(repository, "checkout", "main")
    git(repository, "merge", "--no-ff", "-s", "ours", "release-one", "-m", "merge: release one")
    git(repository, "merge", "--no-ff", "-s", "ours", "release-two", "-m", "merge: release two")

    with pytest.raises(release_plan.ReleasePlanError, match="do not form a linear history"):
        release_plan.calculate_release_plan(repository)


def test_cli_writes_stdout_and_github_output(repository: Path, tmp_path: Path) -> None:
    tag(repository, "v0.1.0-alpha.7")
    commit(repository, "fix: ready for release")
    github_output = tmp_path / "github-output"
    environment = os.environ.copy()
    environment["GITHUB_OUTPUT"] = str(github_output)

    result = subprocess.run(  # noqa: S603 - the checked-in script path is trusted.
        [sys.executable, str(SCRIPT)],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    expected = (
        "tag=v0.1.0-alpha.8\n"
        "version=0.1.0-alpha.8\n"
        "python_version=0.1.0a8\n"
        "previous_tag=v0.1.0-alpha.7\n"
        "superseded=false\n"
    )
    assert result.stdout == expected
    assert github_output.read_text(encoding="utf-8") == expected
