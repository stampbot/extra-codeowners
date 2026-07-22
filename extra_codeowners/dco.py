"""Pure, bounded evidence evaluation for Developer Certificate of Origin checks.

This module has no Git checkout, shell, workflow, database, or network behavior.
Callers must fetch current GitHub evidence, construct the immutable models, and
publish a result only after applying their own exact-head publication guard.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

MAX_PULL_COMMITS = 250
MAX_COMMIT_PARENTS = 64
MAX_COMMIT_MESSAGE_BYTES = 1_000_000
MAX_VERIFICATION_TEXT_BYTES = 2_000_000

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_DEPENDABOT_AUTHOR_LOGIN = "dependabot[bot]"
_DEPENDABOT_AUTHOR_ID = 49_699_333
_DEPENDABOT_AUTHOR_TYPE = "Bot"
_DEPENDABOT_AUTHOR_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"
_DEPENDABOT_SIGNOFF = "Signed-off-by: dependabot[bot] <support@github.com>"
_DEPENDABOT_COMMITTER_LOGIN = "web-flow"
_DEPENDABOT_COMMITTER_ID = 19_864_447
_DEPENDABOT_COMMITTER_TYPE = "User"
_DEPENDABOT_COMMITTER_NAME = "GitHub"
_DEPENDABOT_COMMITTER_EMAIL = "noreply@github.com"

StrictPositiveInt = Annotated[int, Field(strict=True, gt=0)]
StrictCommitCount = Annotated[int, Field(strict=True, gt=0, le=MAX_PULL_COMMITS)]


def _text_bytes(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValueError("text must be valid Unicode") from error


def _validate_bounded_text(
    value: str,
    *,
    field: str,
    max_bytes: int,
    forbid_controls: bool = True,
    forbid_whitespace: bool = False,
) -> str:
    if not value:
        raise ValueError(f"{field} must not be empty")
    if _text_bytes(value) > max_bytes:
        raise ValueError(f"{field} exceeds the {max_bytes}-byte limit")
    if forbid_controls and any(
        unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"} for character in value
    ):
        raise ValueError(f"{field} must not contain control or formatting characters")
    if forbid_whitespace and any(character.isspace() for character in value):
        raise ValueError(f"{field} must not contain whitespace")
    return value


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _required(value: Mapping[str, Any], key: str, field: str) -> Any:
    if key not in value:
        raise ValueError(f"{field} omitted {key}")
    return value[key]


class StrictFrozenModel(BaseModel):
    """Reject unknown fields and mutation in authorization evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RepositoryIdentity(StrictFrozenModel):
    """Immutable GitHub repository identity."""

    id: StrictPositiveInt
    full_name: str

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        _validate_bounded_text(
            value,
            field="repository full_name",
            max_bytes=512,
            forbid_whitespace=True,
        )
        if value != value.strip() or not _REPOSITORY_FULL_NAME_RE.fullmatch(value):
            raise ValueError("repository full_name must be an exact owner/repository name")
        owner, repository = value.split("/")
        if owner in {"", ".", ".."} or repository in {"", ".", ".."}:
            raise ValueError("repository full_name must be an exact owner/repository name")
        return value


class GitHubActor(StrictFrozenModel):
    """The stable actor fields consumed by the DCO contract."""

    login: str
    id: StrictPositiveInt
    type: str

    @field_validator("login")
    @classmethod
    def validate_login(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            field="actor login",
            max_bytes=256,
            forbid_whitespace=True,
        )

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            field="actor type",
            max_bytes=64,
            forbid_whitespace=True,
        )

    @classmethod
    def from_github(cls, payload: Mapping[str, Any]) -> Self:
        """Read only the actor fields used by this contract."""
        return cls(
            login=_required(payload, "login", "actor"),
            id=_required(payload, "id", "actor"),
            type=_required(payload, "type", "actor"),
        )


class PullRequestSnapshot(StrictFrozenModel):
    """Current pull-request identity and revisions at one observation point."""

    number: StrictPositiveInt
    state: Literal["open", "closed"]
    repository: RepositoryIdentity
    base_repository: RepositoryIdentity
    base_ref: str
    base_sha: str
    head_repository: RepositoryIdentity
    head_ref: str
    head_sha: str
    author: GitHubActor
    commit_count: StrictCommitCount

    @field_validator("base_ref", "head_ref")
    @classmethod
    def validate_ref(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            field="GitHub ref",
            max_bytes=1024,
            forbid_whitespace=True,
        )

    @field_validator("base_sha", "head_sha")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if not _SHA_RE.fullmatch(value):
            raise ValueError("commit SHA must be exactly 40 lowercase hexadecimal characters")
        return value

    @model_validator(mode="after")
    def repository_identities_are_consistent(self) -> Self:
        if self.base_repository != self.repository:
            raise ValueError("pull-request base repository must match the evaluated repository")
        if (
            self.head_repository.id == self.repository.id
            and self.head_repository != self.repository
        ):
            raise ValueError("same-repository head identity is contradictory")
        if (
            self.head_repository.id != self.repository.id
            and self.head_repository.full_name == self.repository.full_name
        ):
            raise ValueError("fork head identity is contradictory")
        return self

    @classmethod
    def from_github(
        cls,
        payload: Mapping[str, Any],
        *,
        repository: RepositoryIdentity,
    ) -> Self:
        """Parse the fields shared by webhook and pull-request API payloads."""
        base = _mapping(_required(payload, "base", "pull request"), "pull request base")
        head = _mapping(_required(payload, "head", "pull request"), "pull request head")
        base_repository = _mapping(
            _required(base, "repo", "pull request base"), "pull request base repository"
        )
        head_repository = _mapping(
            _required(head, "repo", "pull request head"), "pull request head repository"
        )
        author = _mapping(_required(payload, "user", "pull request"), "pull request author")
        return cls(
            number=_required(payload, "number", "pull request"),
            state=_required(payload, "state", "pull request"),
            repository=repository,
            base_repository=RepositoryIdentity(
                id=_required(base_repository, "id", "pull request base repository"),
                full_name=_required(base_repository, "full_name", "pull request base repository"),
            ),
            base_ref=_required(base, "ref", "pull request base"),
            base_sha=_required(base, "sha", "pull request base"),
            head_repository=RepositoryIdentity(
                id=_required(head_repository, "id", "pull request head repository"),
                full_name=_required(head_repository, "full_name", "pull request head repository"),
            ),
            head_ref=_required(head, "ref", "pull request head"),
            head_sha=_required(head, "sha", "pull request head"),
            author=GitHubActor.from_github(author),
            commit_count=_required(payload, "commits", "pull request"),
        )


class PullCommit(StrictFrozenModel):
    """One SHA from GitHub's chronological compare response."""

    sha: str

    @field_validator("sha")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if not _SHA_RE.fullmatch(value):
            raise ValueError("commit SHA must be exactly 40 lowercase hexadecimal characters")
        return value

    @classmethod
    def from_github(cls, payload: Mapping[str, Any]) -> Self:
        """Parse one commit item from a compare response."""
        return cls(sha=_required(payload, "sha", "compared commit"))


class PullCommitComparison(StrictFrozenModel):
    """A complete compare result bound to one exact pull-request snapshot."""

    repository: RepositoryIdentity
    pull_number: StrictPositiveInt
    base_sha: str
    head_sha: str
    base_commit_sha: str
    total_commits: StrictCommitCount
    ahead_by: StrictCommitCount
    commits: tuple[PullCommit, ...] = Field(max_length=MAX_PULL_COMMITS)

    @field_validator("base_sha", "head_sha", "base_commit_sha")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if not _SHA_RE.fullmatch(value):
            raise ValueError("commit SHA must be exactly 40 lowercase hexadecimal characters")
        return value


class GitCommitIdentity(StrictFrozenModel):
    """Raw Git author or committer identity from a commit object."""

    name: str
    email: str

    @field_validator("name", "email")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        _validate_bounded_text(value, field="Git commit identity", max_bytes=1024)
        if "<" in value or ">" in value:
            raise ValueError("Git commit identity must not contain '<' or '>'")
        return value


class CommitVerification(StrictFrozenModel):
    """GitHub's commit-signature verification fields used for Dependabot."""

    verified: StrictBool
    reason: str
    signature: str | None
    payload: str | None
    verified_at: str | None

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _validate_bounded_text(
            value,
            field="verification reason",
            max_bytes=128,
            forbid_whitespace=True,
        )

    @field_validator("signature", "payload")
    @classmethod
    def validate_verification_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if "\0" in value:
            raise ValueError("verification text must not contain NUL")
        if _text_bytes(value) > MAX_VERIFICATION_TEXT_BYTES:
            raise ValueError(
                f"verification text exceeds the {MAX_VERIFICATION_TEXT_BYTES}-byte limit"
            )
        return value

    @field_validator("verified_at")
    @classmethod
    def validate_verified_at(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        return _validate_bounded_text(
            value,
            field="verification timestamp",
            max_bytes=128,
            forbid_whitespace=True,
        )


class CommitEvidence(StrictFrozenModel):
    """Bounded fields from one exact individual GitHub commit response."""

    sha: str
    parents: tuple[str, ...] = Field(max_length=MAX_COMMIT_PARENTS)
    author: GitCommitIdentity
    committer: GitCommitIdentity
    message: str
    github_author: GitHubActor | None
    github_committer: GitHubActor | None
    verification: CommitVerification

    @field_validator("sha")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if not _SHA_RE.fullmatch(value):
            raise ValueError("commit SHA must be exactly 40 lowercase hexadecimal characters")
        return value

    @field_validator("parents")
    @classmethod
    def validate_parents(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("commit parents must be unique")
        if any(not _SHA_RE.fullmatch(parent) for parent in value):
            raise ValueError("parent SHA must be exactly 40 lowercase hexadecimal characters")
        return value

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        if "\0" in value:
            raise ValueError("commit message must not contain NUL")
        if _text_bytes(value) > MAX_COMMIT_MESSAGE_BYTES:
            raise ValueError(f"commit message exceeds the {MAX_COMMIT_MESSAGE_BYTES}-byte limit")
        return value

    @classmethod
    def from_github(cls, payload: Mapping[str, Any]) -> Self:
        """Parse the exact fields consumed from an individual commit response."""
        commit = _mapping(_required(payload, "commit", "commit response"), "Git commit")
        author = _mapping(_required(commit, "author", "Git commit"), "Git commit author")
        committer = _mapping(_required(commit, "committer", "Git commit"), "Git commit committer")
        verification = _mapping(
            _required(commit, "verification", "Git commit"), "commit verification"
        )
        raw_parents = _required(payload, "parents", "commit response")
        if not isinstance(raw_parents, list):
            raise ValueError("commit parents must be a list")
        parents = tuple(
            _required(_mapping(parent, "commit parent"), "sha", "commit parent")
            for parent in raw_parents
        )

        raw_github_author = payload.get("author")
        raw_github_committer = payload.get("committer")
        github_author = (
            None
            if raw_github_author is None
            else GitHubActor.from_github(_mapping(raw_github_author, "GitHub author"))
        )
        github_committer = (
            None
            if raw_github_committer is None
            else GitHubActor.from_github(_mapping(raw_github_committer, "GitHub committer"))
        )
        return cls(
            sha=_required(payload, "sha", "commit response"),
            parents=parents,
            author=GitCommitIdentity(
                name=_required(author, "name", "Git commit author"),
                email=_required(author, "email", "Git commit author"),
            ),
            committer=GitCommitIdentity(
                name=_required(committer, "name", "Git commit committer"),
                email=_required(committer, "email", "Git commit committer"),
            ),
            message=_required(commit, "message", "Git commit"),
            github_author=github_author,
            github_committer=github_committer,
            verification=CommitVerification(
                verified=_required(verification, "verified", "commit verification"),
                reason=_required(verification, "reason", "commit verification"),
                signature=verification.get("signature"),
                payload=verification.get("payload"),
                verified_at=verification.get("verified_at"),
            ),
        )


class DcoEvidenceInput(StrictFrozenModel):
    """All evidence needed for a race-conscious, exact-head DCO decision."""

    event: PullRequestSnapshot
    before: PullRequestSnapshot
    after: PullRequestSnapshot
    comparison: PullCommitComparison
    commits: tuple[CommitEvidence, ...] = Field(max_length=MAX_PULL_COMMITS)


class DcoCommitOutcome(StrEnum):
    """How one commit satisfied, or failed to satisfy, DCO."""

    AUTHOR_SIGNOFF = "author-signoff"
    OFFICIAL_DEPENDABOT = "official-dependabot"
    MISSING_SIGNOFF = "missing-signoff"


class DcoFailure(StrEnum):
    """Stable fail-closed reasons that contain no untrusted text."""

    PULL_REQUEST_NOT_OPEN = "pull-request-not-open"
    PULL_REQUEST_CHANGED = "pull-request-changed"
    COMPARISON_MISMATCH = "comparison-mismatch"
    COMMIT_COUNT_MISMATCH = "commit-count-mismatch"
    DUPLICATE_COMMIT = "duplicate-commit"
    HEAD_MISMATCH = "head-mismatch"
    COMMIT_ORDER_MISMATCH = "commit-order-mismatch"
    MISSING_SIGNOFF = "missing-signoff"


class DcoCommitResult(StrictFrozenModel):
    """A bounded decision for one commit SHA."""

    sha: str
    outcome: DcoCommitOutcome

    @field_validator("sha")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if not _SHA_RE.fullmatch(value):
            raise ValueError("commit SHA must be exactly 40 lowercase hexadecimal characters")
        return value


class DcoEvaluationResult(StrictFrozenModel):
    """A complete DCO decision bound to one pull-request head."""

    passed: StrictBool
    repository: RepositoryIdentity
    pull_number: StrictPositiveInt
    base_sha: str
    head_sha: str
    failure: DcoFailure | None
    commits: tuple[DcoCommitResult, ...] = Field(max_length=MAX_PULL_COMMITS)

    @field_validator("base_sha", "head_sha")
    @classmethod
    def validate_head_sha(cls, value: str) -> str:
        if not _SHA_RE.fullmatch(value):
            raise ValueError("commit SHA must be exactly 40 lowercase hexadecimal characters")
        return value

    @model_validator(mode="after")
    def result_is_consistent(self) -> Self:
        if self.passed == (self.failure is not None):
            raise ValueError("a passing result cannot have a failure reason")
        if self.passed and any(
            commit.outcome is DcoCommitOutcome.MISSING_SIGNOFF for commit in self.commits
        ):
            raise ValueError("a passing result cannot contain a missing sign-off")
        return self


def _failed(
    evidence: DcoEvidenceInput,
    failure: DcoFailure,
    *,
    commits: tuple[DcoCommitResult, ...] = (),
) -> DcoEvaluationResult:
    return DcoEvaluationResult(
        passed=False,
        repository=evidence.event.repository,
        pull_number=evidence.event.number,
        base_sha=evidence.event.base_sha,
        head_sha=evidence.event.head_sha,
        failure=failure,
        commits=commits,
    )


def _has_author_signoff(commit: CommitEvidence) -> bool:
    expected = f"Signed-off-by: {commit.author.name} <{commit.author.email}>".casefold()
    return any(line.casefold() == expected for line in commit.message.split("\n"))


def _is_official_dependabot_pull(pull: PullRequestSnapshot) -> bool:
    return (
        pull.author.login == _DEPENDABOT_AUTHOR_LOGIN
        and pull.author.id == _DEPENDABOT_AUTHOR_ID
        and pull.author.type == _DEPENDABOT_AUTHOR_TYPE
        and pull.base_repository.id == pull.repository.id
        and pull.head_repository.id == pull.repository.id
        and pull.head_ref.startswith("dependabot/")
        and pull.commit_count == 1
    )


def _is_official_dependabot_commit(
    commit: CommitEvidence,
    pull: PullRequestSnapshot,
) -> bool:
    verification = commit.verification
    return (
        commit.sha == pull.head_sha
        and commit.parents == (pull.base_sha,)
        and commit.github_author
        == GitHubActor(
            login=_DEPENDABOT_AUTHOR_LOGIN,
            id=_DEPENDABOT_AUTHOR_ID,
            type=_DEPENDABOT_AUTHOR_TYPE,
        )
        and commit.github_committer
        == GitHubActor(
            login=_DEPENDABOT_COMMITTER_LOGIN,
            id=_DEPENDABOT_COMMITTER_ID,
            type=_DEPENDABOT_COMMITTER_TYPE,
        )
        and commit.author
        == GitCommitIdentity(
            name=_DEPENDABOT_AUTHOR_LOGIN,
            email=_DEPENDABOT_AUTHOR_EMAIL,
        )
        and commit.committer
        == GitCommitIdentity(
            name=_DEPENDABOT_COMMITTER_NAME,
            email=_DEPENDABOT_COMMITTER_EMAIL,
        )
        and verification.verified is True
        and verification.reason == "valid"
        and verification.signature is not None
        and len(verification.signature) > 0
        and verification.payload is not None
        and len(verification.payload) > 0
        and verification.verified_at is not None
        and len(verification.verified_at) > 0
        and _DEPENDABOT_SIGNOFF in commit.message.split("\n")
    )


def _commit_order_is_valid(
    pull_commits: tuple[PullCommit, ...],
    commits: tuple[CommitEvidence, ...],
) -> bool:
    ordered_shas = tuple(item.sha for item in pull_commits)
    if any(
        commit.sha != expected_sha
        for commit, expected_sha in zip(commits, ordered_shas, strict=True)
    ):
        return False

    positions = {sha: index for index, sha in enumerate(ordered_shas)}
    for index, commit in enumerate(commits):
        if any(parent in positions and positions[parent] >= index for parent in commit.parents):
            return False

    by_sha = {commit.sha: commit for commit in commits}
    reachable = {ordered_shas[-1]}
    pending = [ordered_shas[-1]]
    while pending:
        current = by_sha[pending.pop()]
        for parent in current.parents:
            if parent in by_sha and parent not in reachable:
                reachable.add(parent)
                pending.append(parent)
    return reachable == set(ordered_shas)


def evaluate_dco(evidence: DcoEvidenceInput) -> DcoEvaluationResult:
    """Evaluate bounded GitHub evidence without performing side effects."""
    pull = evidence.event
    if pull.state != "open":
        return _failed(evidence, DcoFailure.PULL_REQUEST_NOT_OPEN)
    if evidence.before != pull or evidence.after != pull:
        return _failed(evidence, DcoFailure.PULL_REQUEST_CHANGED)

    comparison = evidence.comparison
    if (
        comparison.repository != pull.repository
        or comparison.pull_number != pull.number
        or comparison.base_sha != pull.base_sha
        or comparison.head_sha != pull.head_sha
        or comparison.base_commit_sha != pull.base_sha
    ):
        return _failed(evidence, DcoFailure.COMPARISON_MISMATCH)

    expected_count = pull.commit_count
    if (
        comparison.total_commits != expected_count
        or comparison.ahead_by != expected_count
        or len(comparison.commits) != expected_count
        or len(evidence.commits) != expected_count
    ):
        return _failed(evidence, DcoFailure.COMMIT_COUNT_MISMATCH)

    ordered_shas = tuple(commit.sha for commit in comparison.commits)
    if len(set(ordered_shas)) != len(ordered_shas):
        return _failed(evidence, DcoFailure.DUPLICATE_COMMIT)
    if ordered_shas[-1] != pull.head_sha:
        return _failed(evidence, DcoFailure.HEAD_MISMATCH)
    if not _commit_order_is_valid(comparison.commits, evidence.commits):
        return _failed(evidence, DcoFailure.COMMIT_ORDER_MISMATCH)

    official_dependabot_pull = _is_official_dependabot_pull(pull)
    results: list[DcoCommitResult] = []
    for commit in evidence.commits:
        if _has_author_signoff(commit):
            outcome = DcoCommitOutcome.AUTHOR_SIGNOFF
        elif official_dependabot_pull and _is_official_dependabot_commit(commit, pull):
            outcome = DcoCommitOutcome.OFFICIAL_DEPENDABOT
        else:
            outcome = DcoCommitOutcome.MISSING_SIGNOFF
        results.append(DcoCommitResult(sha=commit.sha, outcome=outcome))

    bounded_results = tuple(results)
    if any(result.outcome is DcoCommitOutcome.MISSING_SIGNOFF for result in results):
        return _failed(evidence, DcoFailure.MISSING_SIGNOFF, commits=bounded_results)
    return DcoEvaluationResult(
        passed=True,
        repository=pull.repository,
        pull_number=pull.number,
        base_sha=pull.base_sha,
        head_sha=pull.head_sha,
        failure=None,
        commits=bounded_results,
    )
