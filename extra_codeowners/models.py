"""Typed, immutable models shared by the Extra CODEOWNERS policy engine.

The models in this module deliberately contain no GitHub or network behavior.  A
caller is expected to fetch repository state, resolve team membership, and then
provide that evidence to :class:`EvaluationInput`.
"""

from __future__ import annotations

import html
import re
import string
import tomllib
import unicodedata
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

SCHEMA_VERSION: Literal[1] = 1
StrictPositiveInt = Annotated[int, Field(strict=True, gt=0)]

_APP_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_APP_ALIAS_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$")
_OWNER_RE = re.compile(
    r"^@[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*)?$",
    re.IGNORECASE,
)
_MARKDOWN_META = frozenset(string.punctuation)


def _visible_text(value: str) -> str:
    """Render controls explicitly so untrusted evidence cannot forge layout."""
    rendered: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if character == "\n":
            rendered.append(r"\n")
        elif character == "\r":
            rendered.append(r"\r")
        elif character == "\t":
            rendered.append(r"\t")
        elif category in {"Cc", "Cf", "Zl", "Zp"}:
            rendered.append(f"<U+{ord(character):04X}>")
        else:
            rendered.append(character)
    return "".join(rendered)


def _markdown_text(value: str) -> str:
    """Escape untrusted text for a Markdown prose position."""
    return "".join(
        f"\\{character}" if character in _MARKDOWN_META else character
        for character in _visible_text(value)
    )


def _markdown_code(value: str) -> str:
    """Render untrusted text in an HTML code element without delimiter ambiguity."""
    return f"<code>{html.escape(_visible_text(value), quote=True)}</code>"


def normalize_owner(value: str) -> str:
    """Return a canonical CODEOWNERS identity or raise ``ValueError``.

    GitHub identity comparisons are case-insensitive. Email CODEOWNERS entries
    are intentionally unsupported because they cannot be resolved safely to a
    review actor.
    """

    owner = value.strip().lower()
    if "@" in owner and not owner.startswith("@"):
        msg = f"email CODEOWNER {value!r} is unsupported; use an @user or @org/team"
        raise ValueError(msg)
    if not _OWNER_RE.fullmatch(owner):
        msg = f"invalid CODEOWNER identity {value!r}; expected @user or @org/team"
        raise ValueError(msg)
    return owner


def normalize_repository_path(value: str) -> str:
    """Normalize a GitHub repository-relative path and reject unsafe forms."""

    # Repository filenames are exact, case-sensitive evidence. Never normalize
    # one path into another. Edge whitespace is rejected because the supported
    # CODEOWNERS parser cannot represent it unambiguously.
    path = value
    if not path:
        raise ValueError("repository path must not be empty")
    if path != path.strip():
        raise ValueError("repository paths with leading or trailing whitespace are unsupported")
    if path.startswith("/") or "\\" in path:
        raise ValueError("repository paths must be relative POSIX paths")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("repository paths must not contain empty, '.' or '..' segments")
    return path


def _normalize_pattern(value: str) -> str:
    pattern = value.strip()
    if not pattern:
        raise ValueError("path pattern must not be empty")
    if "\\" in pattern:
        raise ValueError("path patterns must use POSIX '/' separators")
    return pattern


def _normalize_label(value: str) -> str:
    label = value.strip().lower()
    if not label:
        raise ValueError("label must not be empty")
    return label


class StrictModel(BaseModel):
    """Base class for policy data that must reject misspelled fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class EnrolledApplication(StrictModel):
    """A GitHub App identity trusted by organization policy."""

    slug: str
    app_id: StrictPositiveInt
    bot_user_id: StrictPositiveInt

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        slug = value.strip().lower()
        if not _APP_SLUG_RE.fullmatch(slug):
            raise ValueError("GitHub App slug must contain lowercase letters, digits, and hyphens")
        return slug


class Guardrails(StrictModel):
    """Organization-enforced restrictions repositories cannot weaken."""

    non_delegable_paths: tuple[str, ...] = Field(default=(), max_length=100)

    @field_validator("non_delegable_paths")
    @classmethod
    def validate_non_delegable_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_normalize_pattern(pattern) for pattern in value)


class OrganizationPolicy(StrictModel):
    """Organization-owned application enrollment and mandatory guardrails."""

    schema_version: Literal[1] = SCHEMA_VERSION
    apps: dict[str, EnrolledApplication] = Field(default_factory=dict, max_length=50)
    guardrails: Guardrails = Field(default_factory=Guardrails)

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_schema_version_type(cls, value: Any) -> Any:
        if type(value) is not int:  # bool is an int subclass and must not select a schema.
            raise ValueError("schema_version must be the integer 1")
        return value

    @field_validator("apps", mode="before")
    @classmethod
    def normalize_app_aliases(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        normalized: dict[str, Any] = {}
        for raw_alias, app in value.items():
            alias = str(raw_alias).strip().lower()
            if not _APP_ALIAS_RE.fullmatch(alias):
                raise ValueError(f"invalid application alias {raw_alias!r}")
            if alias in normalized:
                raise ValueError(f"duplicate application alias {alias!r}")
            normalized[alias] = app
        return normalized

    @model_validator(mode="after")
    def identities_are_unique(self) -> Self:
        seen_app_ids: set[int] = set()
        seen_bot_ids: set[int] = set()
        seen_slugs: set[str] = set()
        for alias, app in self.apps.items():
            if app.app_id in seen_app_ids:
                raise ValueError(f"duplicate GitHub App id {app.app_id} (at {alias!r})")
            if app.bot_user_id in seen_bot_ids:
                raise ValueError(f"duplicate GitHub bot user id {app.bot_user_id} (at {alias!r})")
            if app.slug in seen_slugs:
                raise ValueError(f"duplicate GitHub App slug {app.slug!r}")
            seen_app_ids.add(app.app_id)
            seen_bot_ids.add(app.bot_user_id)
            seen_slugs.add(app.slug)
        return self

    @classmethod
    def from_toml(cls, content: str | bytes) -> Self:
        """Parse and validate an organization policy TOML document."""

        raw = content.encode() if isinstance(content, str) else content
        values = tomllib.loads(raw.decode())
        if "schema_version" not in values:
            raise ValueError("organization policy requires schema_version")
        return cls.model_validate(values)


class Delegation(StrictModel):
    """Allow one enrolled application to stand in for selected CODEOWNERS.

    ``for_owners`` follows GitHub CODEOWNERS alternatives: matching any listed
    owner is sufficient. ``["*"]`` must be written explicitly to delegate for
    every owner; an omitted or empty list is rejected.
    """

    app: str
    paths: tuple[str, ...] = Field(min_length=1, max_length=100)
    for_owners: tuple[str, ...] = Field(min_length=1, max_length=100)
    required_labels: frozenset[str] = Field(default_factory=frozenset, max_length=50)
    forbidden_labels: frozenset[str] = Field(default_factory=frozenset, max_length=50)

    @field_validator("app")
    @classmethod
    def normalize_app(cls, value: str) -> str:
        alias = value.strip().lower()
        if not _APP_ALIAS_RE.fullmatch(alias):
            raise ValueError("delegation app must be a valid application alias")
        return alias

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("delegation paths must not be empty")
        return tuple(_normalize_pattern(pattern) for pattern in value)

    @field_validator("for_owners", mode="before")
    @classmethod
    def normalize_for_owners(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple, set, frozenset)):
            return value
        owners: list[str] = []
        for raw_owner in value:
            owner = str(raw_owner).strip()
            owners.append("*" if owner == "*" else normalize_owner(owner))
        return owners

    @field_validator("for_owners")
    @classmethod
    def validate_for_owners(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("for_owners must list owners or contain an explicit '*'")
        if "*" in value and len(value) != 1:
            raise ValueError("'*' cannot be combined with named CODEOWNERS")
        if len(set(value)) != len(value):
            raise ValueError("for_owners contains duplicate entries")
        return value

    @field_validator("required_labels", "forbidden_labels", mode="before")
    @classmethod
    def normalize_labels(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple, set, frozenset)):
            return value
        return frozenset(_normalize_label(str(label)) for label in value)

    @model_validator(mode="after")
    def label_sets_do_not_overlap(self) -> Self:
        overlap = self.required_labels & self.forbidden_labels
        if overlap:
            raise ValueError(f"labels cannot be both required and forbidden: {sorted(overlap)!r}")
        return self


class RepositoryPolicy(StrictModel):
    """Repository policy read from ``.github/extra-codeowners.toml``."""

    schema_version: Literal[1] = SCHEMA_VERSION
    enabled: StrictBool = False
    delegations: tuple[Delegation, ...] = Field(default=(), max_length=100)

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_schema_version_type(cls, value: Any) -> Any:
        if type(value) is not int:  # bool is an int subclass and must not select a schema.
            raise ValueError("schema_version must be the integer 1")
        return value

    @model_validator(mode="after")
    def delegation_complexity_is_bounded(self) -> Self:
        if sum(len(delegation.paths) for delegation in self.delegations) > 1000:
            raise ValueError("repository policy may contain at most 1,000 delegation patterns")
        return self

    @classmethod
    def from_toml(cls, content: str | bytes) -> Self:
        """Parse and validate a repository policy TOML document."""

        raw = content.encode() if isinstance(content, str) else content
        values = tomllib.loads(raw.decode())
        if "schema_version" not in values:
            raise ValueError("repository policy requires schema_version")
        if "enabled" not in values:
            raise ValueError("repository policy requires an explicit enabled setting")
        return cls.model_validate(values)


class ChangedFileStatus(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"
    RENAMED = "renamed"
    COPIED = "copied"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


class ChangedFile(StrictModel):
    """A changed PR file, including the prior name when GitHub reports a rename."""

    path: str
    status: ChangedFileStatus = ChangedFileStatus.MODIFIED
    previous_path: str | None = None

    @field_validator("path", "previous_path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        return None if value is None else normalize_repository_path(value)

    @model_validator(mode="after")
    def rename_has_previous_path(self) -> Self:
        if self.status is ChangedFileStatus.RENAMED and self.previous_path is None:
            raise ValueError(
                "renamed files require previous_path so both ownership rules are evaluated"
            )
        if self.previous_path is not None and self.status is not ChangedFileStatus.RENAMED:
            raise ValueError("previous_path is only valid for renamed files")
        if self.previous_path == self.path:
            raise ValueError("renamed file path and previous_path must differ")
        return self


class ActorKind(StrEnum):
    HUMAN = "human"
    APPLICATION = "application"


class ReviewActor(StrictModel):
    """A review actor plus caller-resolved CODEOWNER identities.

    ``owner_aliases`` is the trusted result of resolving team membership. A
    human's own ``@login`` identity is added automatically by the evaluator.
    Application actors must carry all three enrolled identity attributes.
    """

    kind: ActorKind
    login: str
    user_id: StrictPositiveInt
    app_id: StrictPositiveInt | None = None
    app_slug: str | None = None
    owner_aliases: frozenset[str] = frozenset()
    direct_owner_eligible: StrictBool = True

    @field_validator("login")
    @classmethod
    def validate_login(cls, value: str) -> str:
        login = value.strip().lower()
        if not login:
            raise ValueError("review actor login must not be empty")
        return login

    @field_validator("app_slug")
    @classmethod
    def normalize_app_slug(cls, value: str | None) -> str | None:
        if value is None:
            return None
        slug = value.strip().lower()
        if not _APP_SLUG_RE.fullmatch(slug):
            raise ValueError("invalid GitHub App slug on review actor")
        return slug

    @field_validator("owner_aliases", mode="before")
    @classmethod
    def normalize_owner_aliases(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple, set, frozenset)):
            return value
        return frozenset(normalize_owner(str(owner)) for owner in value)

    @model_validator(mode="after")
    def validate_kind_fields(self) -> Self:
        if self.kind is ActorKind.APPLICATION:
            if self.app_id is None or self.app_slug is None:
                raise ValueError("application review actors require app_id and app_slug")
            if self.owner_aliases:
                raise ValueError("application review actors cannot carry human owner aliases")
        elif self.app_id is not None or self.app_slug is not None:
            raise ValueError("human review actors cannot carry GitHub App identity fields")
        return self


class ReviewState(StrEnum):
    APPROVED = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    COMMENTED = "COMMENTED"
    DISMISSED = "DISMISSED"
    PENDING = "PENDING"


class PullRequestReview(StrictModel):
    """Review evidence as returned by GitHub and normalized by the adapter."""

    review_id: StrictPositiveInt
    actor: ReviewActor
    state: ReviewState
    commit_sha: str | None
    submitted_at: datetime

    @field_validator("commit_sha")
    @classmethod
    def validate_commit_sha(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sha = value.strip().lower()
        if not sha:
            raise ValueError("review commit_sha must not be blank")
        return sha

    @field_validator("submitted_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("submitted_at must include a timezone")
        return value


class EvaluationOptions(StrictModel):
    """Runtime safety controls, normally populated from process settings."""

    exact_head_reviews: bool = True
    allow_insecure_changes: bool = False
    repository_policy_path: str = ".github/extra-codeowners.toml"

    @field_validator("repository_policy_path")
    @classmethod
    def validate_repository_policy_path(cls, value: str) -> str:
        path = value.strip()
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or any(character in path for character in "*?[]!")
        ):
            raise ValueError("repository_policy_path must be a literal relative POSIX path")
        return path


class EvaluationInput(StrictModel):
    """Complete, network-free evidence needed for one PR evaluation."""

    head_sha: str
    codeowners_text: str
    changed_files: tuple[ChangedFile, ...]
    reviews: tuple[PullRequestReview, ...] = ()
    labels: frozenset[str] = frozenset()
    organization_policy: OrganizationPolicy
    repository_policy: RepositoryPolicy
    options: EvaluationOptions = Field(default_factory=EvaluationOptions)

    @field_validator("head_sha")
    @classmethod
    def validate_head_sha(cls, value: str) -> str:
        sha = value.strip().lower()
        if not sha:
            raise ValueError("head_sha must not be empty")
        return sha

    @field_validator("labels", mode="before")
    @classmethod
    def normalize_input_labels(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple, set, frozenset)):
            return value
        return frozenset(_normalize_label(str(label)) for label in value)


class EvaluationConclusion(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class EvaluationMessage(StrictModel):
    """A stable machine code and human-readable check annotation."""

    code: str
    message: str
    paths: tuple[str, ...] = ()


class PathEvidence(StrictModel):
    """How one path within an owner-set requirement was evaluated."""

    path: str
    non_delegable: bool
    eligible_apps: tuple[str, ...] = ()
    approved_apps: tuple[str, ...] = ()
    explanation: str


class OwnerSetResult(StrictModel):
    """The result for one distinct CODEOWNERS owner set."""

    owners: tuple[str, ...]
    paths: tuple[str, ...]
    satisfied: bool
    satisfied_by: tuple[str, ...] = ()
    explanation: str
    path_evidence: tuple[PathEvidence, ...] = ()


class EvaluationResult(StrictModel):
    """Policy result ready to render into a GitHub Check Run."""

    conclusion: EvaluationConclusion
    summary: str
    requirements: tuple[OwnerSetResult, ...] = ()
    errors: tuple[EvaluationMessage, ...] = ()
    warnings: tuple[EvaluationMessage, ...] = ()
    unowned_paths: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        """Whether the result is an affirmative policy success."""

        return self.conclusion is EvaluationConclusion.SUCCESS

    def check_output(self) -> str:
        """Render concise Markdown suitable for a GitHub Check Run body."""

        lines = [_markdown_text(self.summary)]
        if self.errors:
            lines.extend(["", "### Errors"])
            lines.extend(
                f"- {_markdown_code(item.code)}: {_markdown_text(item.message)}"
                for item in self.errors
            )
        if self.warnings:
            lines.extend(["", "### Warnings"])
            lines.extend(
                f"- {_markdown_code(item.code)}: {_markdown_text(item.message)}"
                for item in self.warnings
            )
        if self.requirements:
            lines.extend(["", "### CODEOWNER requirements"])
            for requirement in self.requirements:
                marker = "✅" if requirement.satisfied else "❌"
                owners = ", ".join(_markdown_code(owner) for owner in requirement.owners)
                lines.append(f"- {marker} {owners}: {_markdown_text(requirement.explanation)}")
                lines.extend(
                    f"  - {_markdown_code(evidence.path)}: {_markdown_text(evidence.explanation)}"
                    for evidence in requirement.path_evidence
                )
        if self.unowned_paths:
            lines.extend(["", "### Unowned paths"])
            lines.extend(f"- {_markdown_code(path)}" for path in self.unowned_paths)
        return "\n".join(lines)
