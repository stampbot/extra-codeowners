#!/usr/bin/env python3
"""Calculate the next immutable release tag from Git history."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

SEMVER_TAG = re.compile(
    r"^v(?P<major>0|[1-9]\d*)\."
    r"(?P<minor>0|[1-9]\d*)\."
    r"(?P<patch>0|[1-9]\d*)"
    r"(?:-alpha\.(?P<alpha>[1-9]\d*))?$"
)
RELEVANT_TAG = re.compile(r"^v\d")
BREAKING_SUBJECT = re.compile(r"^[A-Za-z]+(?:\([^)]+\))?!:")
BREAKING_BODY = re.compile(r"^BREAKING(?: CHANGE|-CHANGE):", re.MULTILINE)
FEATURE_SUBJECT = re.compile(r"^feat(?:\([^)]+\))?:")
RELEASE_CHANNEL_TRAILER = "release-channel"
RELEASE_CHANNELS = frozenset({"alpha", "stable"})
_git_path = shutil.which("git")
if _git_path is None:
    raise RuntimeError("git is required to calculate a release plan")
GIT: str = _git_path


class ReleasePlanError(RuntimeError):
    """Raised when Git history cannot produce one safe release plan."""


@dataclass(frozen=True)
class Version:
    """A strict stable or numeric-alpha semantic version."""

    major: int
    minor: int
    patch: int
    alpha: int | None = None

    @classmethod
    def from_tag(cls, tag: str) -> Version:
        """Parse a strict release tag."""
        match = SEMVER_TAG.fullmatch(tag)
        if match is None:
            raise ReleasePlanError(f"malformed release tag: {tag}")
        alpha = match.group("alpha")
        return cls(
            major=int(match.group("major")),
            minor=int(match.group("minor")),
            patch=int(match.group("patch")),
            alpha=int(alpha) if alpha is not None else None,
        )

    @property
    def sort_key(self) -> tuple[int, int, int, int, int]:
        """Return a key following SemVer precedence for supported versions."""
        return (
            self.major,
            self.minor,
            self.patch,
            1 if self.alpha is None else 0,
            self.alpha or 0,
        )

    @property
    def semver(self) -> str:
        """Render the version without the Git tag prefix."""
        base = f"{self.major}.{self.minor}.{self.patch}"
        return base if self.alpha is None else f"{base}-alpha.{self.alpha}"

    @property
    def tag(self) -> str:
        """Render the canonical Git tag."""
        return f"v{self.semver}"

    @property
    def python(self) -> str:
        """Render the normalized PEP 440 version."""
        base = f"{self.major}.{self.minor}.{self.patch}"
        return base if self.alpha is None else f"{base}a{self.alpha}"


@dataclass(frozen=True)
class ReleaseTag:
    """A parsed release tag and the commit it names."""

    name: str
    version: Version
    commit: str


@dataclass(frozen=True)
class Commit:
    """Commit text used to select a conventional version bump."""

    subject: str
    body: str


@dataclass(frozen=True)
class ReleasePlan:
    """The release identity calculated for the checked-out commit."""

    version: Version
    previous_tag: str | None
    superseded: bool = False

    @property
    def tag(self) -> str:
        """Return the canonical Git tag."""
        return self.version.tag


def _git(repository: Path, *arguments: str, input_text: str | None = None) -> str:
    """Run a read-only Git command."""
    try:
        result: subprocess.CompletedProcess[str] = subprocess.run(  # noqa: S603
            [GIT, *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
            input=input_text,
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip() or "Git command failed"
        raise ReleasePlanError(detail) from error
    return result.stdout


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    """Return whether one commit is an ancestor of another."""
    result: subprocess.CompletedProcess[str] = subprocess.run(  # noqa: S603
        [GIT, "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    detail = result.stderr.strip() or result.stdout.strip() or "Git ancestry check failed"
    raise ReleasePlanError(detail)


def read_release_tags(repository: Path) -> list[ReleaseTag]:
    """Read and validate every release-like Git tag."""
    names = _git(repository, "tag", "--list").splitlines()
    malformed = sorted(
        name for name in names if RELEVANT_TAG.match(name) and not SEMVER_TAG.fullmatch(name)
    )
    if malformed:
        raise ReleasePlanError(f"malformed release tag(s): {', '.join(malformed)}")

    tags: list[ReleaseTag] = []
    for name in names:
        if not SEMVER_TAG.fullmatch(name):
            continue
        commit = _git(
            repository,
            "rev-parse",
            "--verify",
            f"refs/tags/{name}^{{commit}}",
        ).strip()
        tags.append(ReleaseTag(name=name, version=Version.from_tag(name), commit=commit))
    return tags


def validate_linear_history(repository: Path, tags: Sequence[ReleaseTag]) -> None:
    """Require release tags to form one ancestry-ordered, increasing chain."""
    tags_by_commit: dict[str, list[str]] = {}
    for tag in tags:
        tags_by_commit.setdefault(tag.commit, []).append(tag.name)
    ambiguous = [sorted(names) for names in tags_by_commit.values() if len(names) > 1]
    if ambiguous:
        rendered = "; ".join(", ".join(names) for names in ambiguous)
        raise ReleasePlanError(f"multiple release tags identify the same commit: {rendered}")

    ordered = sorted(tags, key=lambda tag: tag.version.sort_key)
    for older, newer in pairwise(ordered):
        if _is_ancestor(repository, older.commit, newer.commit):
            continue
        if _is_ancestor(repository, newer.commit, older.commit):
            raise ReleasePlanError(
                f"release versions are non-monotonic: {newer.name} precedes {older.name}"
            )
        raise ReleasePlanError(
            "release tags do not form a linear history: "
            f"{older.name} and {newer.name} are on separate branches"
        )


def read_commits(
    repository: Path, revision_range: str, *, oldest_first: bool = False
) -> list[Commit]:
    """Read commit subjects and bodies without line-oriented delimiters."""
    arguments = ["log"]
    if oldest_first:
        arguments.append("--reverse")
    arguments.extend([revision_range, "--format=%x1e%s%x1f%b"])
    raw = _git(repository, *arguments)
    commits: list[Commit] = []
    for record in raw.split("\x1e"):
        if not record:
            continue
        subject, separator, body = record.partition("\x1f")
        if separator:
            commits.append(Commit(subject=subject.strip(), body=body.strip()))
    return commits


def reject_malformed_release_channel_trailer(commit: Commit, message: str) -> None:
    """Reject malformed release-channel fields in the terminal trailer block."""
    lines = message.rstrip().splitlines()
    start = len(lines)
    while start and lines[start - 1].strip():
        start -= 1

    trailer_name = "Release-Channel"
    for line in lines[start:]:
        candidate = line.lstrip()
        if not candidate.casefold().startswith(RELEASE_CHANNEL_TRAILER):
            continue
        remainder = candidate[len(trailer_name) :]
        if remainder and (remainder[0].isalnum() or remainder[0] in {"-", "_"}):
            continue
        if remainder.startswith(":"):
            continue
        raise ReleasePlanError(
            f"malformed Release-Channel trailer in {commit.subject}; use "
            "Release-Channel: alpha or Release-Channel: stable"
        )


def read_release_channel(repository: Path, commit: Commit) -> str | None:
    """Read the one optional release-channel trailer from a commit message."""
    message = f"{commit.subject}\n\n{commit.body}\n"
    reject_malformed_release_channel_trailer(commit, message)
    trailers = _git(repository, "interpret-trailers", "--parse", input_text=message)
    channels: list[str] = []
    for trailer in trailers.splitlines():
        key, separator, value = trailer.partition(":")
        if separator and key.casefold() == RELEASE_CHANNEL_TRAILER:
            channels.append(value.strip())

    if len(channels) > 1:
        raise ReleasePlanError(
            f"a commit may contain at most one Release-Channel trailer: {commit.subject}"
        )
    if not channels:
        return None

    channel = channels[0]
    if channel not in RELEASE_CHANNELS:
        choices = ", ".join(sorted(RELEASE_CHANNELS))
        raise ReleasePlanError(
            f"invalid Release-Channel trailer {channel!r} in {commit.subject}; "
            f"expected one of: {choices}"
        )
    return channel


def select_release_channel(
    repository: Path, commits: Sequence[Commit], *, initial_channel: str
) -> str:
    """Replay meaningful, terminal Git-trailer transitions in commit order."""
    channel = initial_channel
    for commit in commits:
        requested = read_release_channel(repository, commit)
        if requested is None:
            continue
        if requested == channel:
            raise ReleasePlanError(
                f"Release-Channel: {requested} in {commit.subject} does not change the "
                "current release channel"
            )
        channel = requested
    return channel


def bump_stable(version: Version, commits: Sequence[Commit]) -> Version:
    """Apply a conventional-commit bump to a stable version."""
    breaking = any(
        BREAKING_SUBJECT.match(commit.subject) or BREAKING_BODY.search(commit.body)
        for commit in commits
    )
    if breaking:
        return Version(version.major + 1, 0, 0)
    if any(FEATURE_SUBJECT.match(commit.subject) for commit in commits):
        return Version(version.major, version.minor + 1, 0)
    return Version(version.major, version.minor, version.patch + 1)


def calculate_release_plan(repository: Path) -> ReleasePlan:
    """Calculate one safe release identity for the repository's HEAD."""
    repository = repository.resolve()
    head = _git(repository, "rev-parse", "--verify", "HEAD^{commit}").strip()
    tags = read_release_tags(repository)
    tags_at_head = [tag for tag in tags if tag.commit == head]
    if len(tags_at_head) > 1:
        names = ", ".join(sorted(tag.name for tag in tags_at_head))
        raise ReleasePlanError(f"multiple release tags identify HEAD: {names}")

    reachable = [tag for tag in tags if _is_ancestor(repository, tag.commit, head)]
    validate_linear_history(repository, reachable)

    if tags_at_head:
        current = tags_at_head[0]
        predecessors = [tag for tag in reachable if tag.commit != head]
        previous = (
            max(predecessors, key=lambda tag: tag.version.sort_key).name if predecessors else None
        )
        return ReleasePlan(version=current.version, previous_tag=previous)

    descendants = [tag for tag in tags if _is_ancestor(repository, head, tag.commit)]
    if descendants:
        validate_linear_history(repository, tags)
        latest_descendant = max(descendants, key=lambda tag: tag.version.sort_key)
        predecessors = [
            tag
            for tag in tags
            if tag.commit != latest_descendant.commit
            and _is_ancestor(repository, tag.commit, latest_descendant.commit)
        ]
        previous = (
            max(predecessors, key=lambda tag: tag.version.sort_key).name if predecessors else None
        )
        return ReleasePlan(
            version=latest_descendant.version,
            previous_tag=previous,
            superseded=True,
        )

    if not tags:
        commits = read_commits(repository, "HEAD", oldest_first=True)
        channel = select_release_channel(repository, commits, initial_channel="alpha")
        version = Version(0, 1, 0, alpha=1 if channel == "alpha" else None)
        return ReleasePlan(version=version, previous_tag=None)

    latest = max(tags, key=lambda tag: tag.version.sort_key)
    if latest not in reachable:
        raise ReleasePlanError(
            f"latest release tag {latest.name} is not an ancestor of HEAD; refusing a tag collision"
        )

    unreachable = sorted(tag.name for tag in tags if tag not in reachable)
    if unreachable:
        raise ReleasePlanError(
            "release tags exist outside the current release history: " + ", ".join(unreachable)
        )

    commits = read_commits(repository, f"refs/tags/{latest.name}..HEAD", oldest_first=True)
    if not commits:
        raise ReleasePlanError(f"no commits follow {latest.name}")

    initial_channel = "alpha" if latest.version.alpha is not None else "stable"
    channel = select_release_channel(repository, commits, initial_channel=initial_channel)
    if latest.version.alpha is not None:
        next_version = (
            Version(latest.version.major, latest.version.minor, latest.version.patch)
            if channel == "stable"
            else Version(
                latest.version.major,
                latest.version.minor,
                latest.version.patch,
                alpha=latest.version.alpha + 1,
            )
        )
    else:
        stable_version = bump_stable(latest.version, commits)
        next_version = (
            Version(
                stable_version.major,
                stable_version.minor,
                stable_version.patch,
                alpha=1,
            )
            if channel == "alpha"
            else stable_version
        )

    collision = next((tag for tag in tags if tag.name == next_version.tag), None)
    if collision is not None:
        raise ReleasePlanError(
            f"release tag {next_version.tag} already identifies {collision.commit}, not HEAD"
        )
    if next_version.sort_key <= latest.version.sort_key:
        raise ReleasePlanError(
            f"calculated release {next_version.tag} does not follow {latest.name}"
        )
    return ReleasePlan(version=next_version, previous_tag=latest.name)


def render_outputs(plan: ReleasePlan) -> list[str]:
    """Render scalar GitHub Actions outputs."""
    return [
        f"tag={plan.tag}",
        f"version={plan.version.semver}",
        f"python_version={plan.version.python}",
        f"previous_tag={plan.previous_tag or ''}",
        f"superseded={'true' if plan.superseded else 'false'}",
    ]


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the release planner CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="Git worktree to inspect (default: current directory)",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        help="GitHub Actions output file (default: GITHUB_OUTPUT when set)",
    )
    args = parser.parse_args(arguments)

    try:
        plan = calculate_release_plan(args.repository)
    except ReleasePlanError as error:
        parser.exit(1, f"release-plan: {error}\n")

    lines = render_outputs(plan)
    sys.stdout.write("\n".join(lines) + "\n")
    output_path = args.github_output
    if output_path is None and os.environ.get("GITHUB_OUTPUT"):
        output_path = Path(os.environ["GITHUB_OUTPUT"])
    if output_path is not None:
        with output_path.open("a", encoding="utf-8") as output:
            output.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
