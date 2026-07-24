"""Fail-closed, read-only preflight for the disposable evaluation beta.

The preflight reads GitHub state, deployment health, and a PostgreSQL database.
It doesn't use ambient ``gh`` credentials. Classic branch-protection evidence
uses a dedicated fine-grained PAT from a locked-down file; every other GitHub
read is public or authenticated as one of the two disposable Apps. The only
GitHub writes mint short-lived, metadata-only installation tokens.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import pwd
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast
from urllib.parse import quote, urlsplit

import httpx
import jwt
from prometheus_client.parser import text_string_to_metric_families
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from extra_codeowners import __version__
from extra_codeowners.codeowners import MAX_CODEOWNERS_BYTES, parse_codeowners
from extra_codeowners.database import (
    DATABASE_MIGRATION_HEAD,
    isolated_postgresql_connect_args,
    validate_database_schema,
)
from extra_codeowners.models import (
    EvaluationOptions,
    OrganizationPolicy,
    RepositoryPolicy,
    normalize_repository_path,
)
from extra_codeowners.policy import compile_policy
from extra_codeowners.settings import validate_production_database_transport
from tools.live_github_contract import API_URL, API_VERSION

CONFIG_SCHEMA_VERSION: Final = 1
REPORT_SCHEMA_VERSION: Final = 1
MAX_CONFIG_BYTES: Final = 64 * 1024
MAX_PRIVATE_KEY_BYTES: Final = 64 * 1024
MAX_ALLOWED_SIGNERS_BYTES: Final = 64 * 1024
MAX_OPERATOR_TOKEN_BYTES: Final = 4096
MAX_GITHUB_RESPONSE_BYTES: Final = 6 * 1024 * 1024
MAX_SERVICE_JSON_BYTES: Final = 64 * 1024
MAX_METRICS_BYTES: Final = 1024 * 1024
MAX_REMOTE_FILE_BYTES: Final = MAX_CODEOWNERS_BYTES
MAX_REPORT_BYTES: Final = 128 * 1024
MAX_DETAIL_CHARACTERS: Final = 300
HTTP_TIMEOUT_SECONDS: Final = 10.0
GIT_OUTPUT_BYTES: Final = 4096
GIT_INDEX_OUTPUT_BYTES: Final = 6 * 1024 * 1024
GIT_TIMEOUT_SECONDS: Final = 10.0
GIT_BINARY: Final = "/usr/bin/git"
MAX_TRACKED_FILES: Final = 10_000
MAX_TRACKED_PATH_BYTES: Final = 4096
MAX_TRACKED_FILE_BYTES: Final = 64 * 1024 * 1024
MAX_TRACKED_SOURCE_BYTES: Final = 512 * 1024 * 1024
METRIC_NAME: Final = "extra_codeowners_insecure_changes_enabled"
CHECK_NAME_DEFAULT: Final = "Extra CODEOWNERS / approval"
CODEOWNERS_PATH: Final = ".github/CODEOWNERS"
CHECKER_PERMISSIONS: Final[dict[str, str]] = {
    "checks": "write",
    "contents": "read",
    "members": "read",
    "metadata": "read",
    "pull_requests": "read",
    "statuses": "write",
}
CHECKER_EVENTS: Final[frozenset[str]] = frozenset(
    {
        "check_run",
        "installation_target",
        "label",
        "member",
        "membership",
        "organization",
        "pull_request",
        "pull_request_review",
        "push",
        "repository",
        "team",
        "team_add",
    }
)
APPROVER_PERMISSIONS: Final[dict[str, str]] = {
    "contents": "read",
    "metadata": "read",
    "pull_requests": "write",
}
APPROVER_EVENTS: Final[frozenset[str]] = frozenset()
REVISION: Final = re.compile(r"^[0-9a-f]{40}$")
SOURCE_REVISION: Final = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
HEX_FINGERPRINT: Final = re.compile(r"^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$")
SSH_FINGERPRINT: Final = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
VERSION_TEXT: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
APP_SLUG: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$")
REPOSITORY: Final = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$"
)
SAFE_BRANCH: Final = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9._-])?$")
SAFE_PATH: Final = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
POSTGRES_VERSION_NUMBER: Final = re.compile(r"^[1-9][0-9]{4,5}$")

JsonObject = dict[str, Any]
Evidence = dict[str, object]


class PreflightError(RuntimeError):
    """A prerequisite could not be proved."""


class ConfigurationError(ValueError):
    """The preflight configuration is absent, malformed, or unsafe."""


def _safe_text(value: object, *, limit: int = MAX_DETAIL_CHARACTERS) -> str:
    """Return one bounded line that cannot forge report or terminal layout."""

    raw = str(value)
    rendered = "".join(
        character if 0x20 <= ord(character) <= 0x7E else f"<U+{ord(character):04X}>"
        for character in raw
    )
    return rendered[:limit]


def _positive_integer(value: object, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PreflightError(f"{description} is not a positive integer")
    return value


def _required_string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise PreflightError(f"{description} is missing")
    return value


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return metadata which must not change while a secret file is read."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_owned_stable_file(
    path: Path,
    *,
    limit: int,
    modes: frozenset[int],
    description: str,
) -> bytes:
    """Read one current-user trust file through a stable, non-blocking descriptor."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise PreflightError(f"{description} cannot be opened safely on this platform")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PreflightError(f"{description} is not a regular file")
        if before.st_uid != os.geteuid():
            raise PreflightError(f"{description} must be owned by the current user")
        if before.st_nlink != 1:
            raise PreflightError(f"{description} must have exactly one hard link")
        if stat.S_IMODE(before.st_mode) not in modes:
            rendered_modes = " or ".join(f"{mode:04o}" for mode in sorted(modes))
            raise PreflightError(f"{description} must have mode {rendered_modes}")
        if before.st_size <= 0 or before.st_size > limit:
            raise PreflightError(f"{description} must contain 1-{limit} bytes")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        path_metadata = os.stat(path, follow_symlinks=False)
    except PreflightError:
        raise
    except OSError as error:
        raise PreflightError(f"{description} is not safely readable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        _stable_file_identity(before) != _stable_file_identity(after)
        or _stable_file_identity(after) != _stable_file_identity(path_metadata)
        or len(content) != after.st_size
    ):
        raise PreflightError(f"{description} changed while it was being read")
    return content


def _read_private_key_file(path: Path, description: str) -> bytes:
    """Read one private key exactly once without following its final path component."""

    return _read_owned_stable_file(
        path,
        limit=MAX_PRIVATE_KEY_BYTES,
        modes=frozenset({0o600}),
        description=description,
    )


def _read_operator_token_file(path: Path, description: str) -> str:
    """Read one dedicated fine-grained PAT without following its final path."""

    content = _read_owned_stable_file(
        path,
        limit=MAX_OPERATOR_TOKEN_BYTES,
        modes=frozenset({0o400, 0o600}),
        description=description,
    )
    if content.endswith(b"\n"):
        content = content[:-1]
    if (
        b"\n" in content
        or b"\r" in content
        or any(byte <= 0x20 or byte >= 0x7F for byte in content)
    ):
        raise PreflightError(f"{description} must contain one printable ASCII token")
    try:
        token = content.decode("ascii")
    except UnicodeDecodeError as error:
        raise PreflightError(f"{description} must contain one ASCII token") from error
    if not token.startswith("github_pat_") or len(token) == len("github_pat_"):
        raise PreflightError(f"{description} must contain a fine-grained GitHub PAT")
    return token


def _object(value: object, description: str) -> JsonObject:
    if not isinstance(value, dict):
        raise PreflightError(f"{description} is not an object")
    return cast(JsonObject, value)


def _objects(value: object, description: str) -> list[JsonObject]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise PreflightError(f"{description} is not a list of objects")
    return cast(list[JsonObject], value)


def _repository_name(value: str) -> str:
    normalized = value.strip().lower()
    repository_name = normalized.rsplit("/", maxsplit=1)[-1]
    if REPOSITORY.fullmatch(normalized) is None or repository_name in {".", ".."}:
        raise ValueError("must be one GitHub owner/repository name")
    return normalized


def _policy_path(value: str) -> str:
    normalized = value.strip().removeprefix("/")
    if (
        SAFE_PATH.fullmatch(normalized) is None
        or any(part in {".", ".."} for part in normalized.split("/"))
        or len(normalized) > 255
    ):
        raise ValueError("must be a relative repository path")
    return normalized


class BetaConfig(BaseModel):
    """Strict, non-secret configuration for one beta preflight."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = CONFIG_SCHEMA_VERSION
    source_revision: str
    source_signer_fingerprint: str
    source_ssh_allowed_signers_file: Path | None = None
    source_checkout: Path = Path(".")
    python_version: str
    uv_version: str
    extra_codeowners_version: str
    postgres_server_version_num: StrictInt = Field(gt=0)
    organization_id: StrictInt = Field(gt=0)
    target_repository: str
    target_repository_id: StrictInt = Field(gt=0)
    organization_policy_repository: str
    organization_policy_repository_id: StrictInt = Field(gt=0)
    target_default_branch: str
    target_default_branch_sha: str
    organization_policy_default_branch: str
    organization_policy_default_branch_sha: str
    checker_app_id: StrictInt = Field(gt=0)
    checker_app_slug: str
    checker_installation_id: StrictInt = Field(gt=0)
    approver_app_id: StrictInt = Field(gt=0)
    approver_app_slug: str
    approver_installation_id: StrictInt = Field(gt=0)
    approver_bot_user_id: StrictInt = Field(gt=0)
    service_url: str
    checker_webhook_url: str
    check_name: str = CHECK_NAME_DEFAULT
    policy_path: str = ".github/extra-codeowners.toml"
    delegation_test_path: str
    delegation_test_labels: frozenset[str] = Field(min_length=1, max_length=10)

    @field_validator("schema_version", mode="before")
    @classmethod
    def schema_version_is_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be the integer 1")
        return value

    @field_validator("source_revision")
    @classmethod
    def source_revision_is_full_object_id(cls, value: str) -> str:
        normalized = value.strip().lower()
        if SOURCE_REVISION.fullmatch(normalized) is None:
            raise ValueError("source revision must be a full SHA-1 or SHA-256 commit ID")
        return normalized

    @field_validator(
        "target_default_branch_sha",
        "organization_policy_default_branch_sha",
    )
    @classmethod
    def github_revision_is_full_sha(cls, value: str) -> str:
        normalized = value.strip().lower()
        if REVISION.fullmatch(normalized) is None:
            raise ValueError("GitHub revision must be a full SHA-1 commit ID")
        return normalized

    @field_validator("source_signer_fingerprint")
    @classmethod
    def signer_fingerprint_is_full(cls, value: str) -> str:
        normalized = value.strip()
        if HEX_FINGERPRINT.fullmatch(normalized) is not None:
            return normalized.upper()
        if SSH_FINGERPRINT.fullmatch(normalized) is not None:
            return normalized
        raise ValueError(
            "source_signer_fingerprint must be an exact 40/64-digit hexadecimal "
            "or SSH SHA256 fingerprint"
        )

    @field_validator("python_version", "uv_version", "extra_codeowners_version")
    @classmethod
    def tool_version_is_bounded(cls, value: str) -> str:
        normalized = value.strip()
        if VERSION_TEXT.fullmatch(normalized) is None:
            raise ValueError("tool versions must be explicit bounded version strings")
        return normalized

    @field_validator("postgres_server_version_num")
    @classmethod
    def postgres_version_is_canonical(cls, value: int) -> int:
        if POSTGRES_VERSION_NUMBER.fullmatch(str(value)) is None:
            raise ValueError("postgres_server_version_num must be PostgreSQL's numeric version")
        return value

    @field_validator("target_repository", "organization_policy_repository")
    @classmethod
    def repository_is_canonical(cls, value: str) -> str:
        return _repository_name(value)

    @field_validator("target_default_branch", "organization_policy_default_branch")
    @classmethod
    def branch_is_bounded(cls, value: str) -> str:
        normalized = value.strip()
        if (
            SAFE_BRANCH.fullmatch(normalized) is None
            or ".." in normalized
            or "//" in normalized
            or normalized.endswith((".", ".lock"))
        ):
            raise ValueError("default branch is not a safe Git reference name")
        return normalized

    @field_validator("checker_app_slug", "approver_app_slug")
    @classmethod
    def app_slug_is_canonical(cls, value: str) -> str:
        normalized = value.strip().lower()
        if APP_SLUG.fullmatch(normalized) is None:
            raise ValueError("App slug must contain lowercase letters, digits, and hyphens")
        return normalized

    @field_validator("service_url")
    @classmethod
    def service_url_is_https_origin(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        try:
            parsed = urlsplit(normalized)
            port = parsed.port
        except ValueError as error:
            raise ValueError("service_url must be one HTTPS origin") from error
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not 1 <= (port or 443) <= 65535
        ):
            raise ValueError("service_url must be one HTTPS origin without credentials or a path")
        return normalized

    @field_validator("checker_webhook_url")
    @classmethod
    def checker_webhook_url_is_exact_https_endpoint(cls, value: str) -> str:
        normalized = value.strip()
        try:
            parsed = urlsplit(normalized)
            port = parsed.port
        except ValueError as error:
            raise ValueError("checker_webhook_url must be one HTTPS URL") from error
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/webhooks/github"
            or not 1 <= (port or 443) <= 65535
        ):
            raise ValueError(
                "checker_webhook_url must be an HTTPS origin followed by /webhooks/github"
            )
        return normalized

    @field_validator("check_name")
    @classmethod
    def check_name_is_bounded(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 100 or any(ord(char) < 0x20 for char in normalized):
            raise ValueError("check_name must contain 1-100 visible characters")
        return normalized

    @field_validator("policy_path")
    @classmethod
    def policy_path_is_safe(cls, value: str) -> str:
        return _policy_path(value)

    @field_validator("delegation_test_path")
    @classmethod
    def delegation_test_path_is_harmless_docs_path(cls, value: str) -> str:
        try:
            normalized = normalize_repository_path(value)
        except ValueError as error:
            raise ValueError("delegation_test_path must be a safe repository path") from error
        if (
            not normalized.startswith("docs/")
            or len(normalized) > 255
            or any(not character.isprintable() for character in normalized)
        ):
            raise ValueError("delegation_test_path must name a file below docs/")
        return normalized

    @field_validator("delegation_test_labels", mode="before")
    @classmethod
    def delegation_test_labels_are_explicit(cls, value: object) -> object:
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise ValueError("delegation_test_labels must be an explicit list")
        labels: list[str] = []
        for raw_label in value:
            if not isinstance(raw_label, str):
                raise ValueError("delegation_test_labels must contain strings")
            label = raw_label.strip().lower()
            if (
                not label
                or len(label) > 50
                or any(not character.isprintable() for character in label)
            ):
                raise ValueError("delegation_test_labels contain an invalid label")
            labels.append(label)
        if len(set(labels)) != len(labels):
            raise ValueError("delegation_test_labels contain duplicates")
        return frozenset(labels)

    @model_validator(mode="after")
    def beta_boundary_is_separate_and_disposable(self) -> BetaConfig:
        target_owner, target_name = self.target_repository.split("/", maxsplit=1)
        policy_owner, policy_name = self.organization_policy_repository.split("/", maxsplit=1)
        if target_owner != policy_owner:
            raise ValueError("target and organization-policy repositories must share one owner")
        if target_name == ".github" or policy_name != ".github":
            raise ValueError(
                "the target must be separate from the owner's .github policy repository"
            )
        if self.checker_app_id == self.approver_app_id:
            raise ValueError("checker and approver App IDs must be different")
        if self.checker_installation_id == self.approver_installation_id:
            raise ValueError("checker and approver installation IDs must be different")
        if self.checker_app_slug == self.approver_app_slug:
            raise ValueError("checker and approver App slugs must be different")
        if self.target_repository_id == self.organization_policy_repository_id:
            raise ValueError("target and organization-policy repository IDs must be different")
        uses_ssh_signature = SSH_FINGERPRINT.fullmatch(self.source_signer_fingerprint) is not None
        if uses_ssh_signature != (self.source_ssh_allowed_signers_file is not None):
            raise ValueError(
                "source_ssh_allowed_signers_file is required exactly when "
                "source_signer_fingerprint is an SSH SHA256 fingerprint"
            )
        if self.checker_webhook_url != f"{self.service_url}/webhooks/github":
            raise ValueError(
                "checker_webhook_url must be the inspected service_url followed by /webhooks/github"
            )
        return self

    @classmethod
    def from_file(cls, path: Path) -> BetaConfig:
        """Load a bounded TOML file and resolve its checkout path."""

        try:
            raw = _read_owned_stable_file(
                path,
                limit=MAX_CONFIG_BYTES,
                modes=frozenset({0o400, 0o600}),
                description="configuration file",
            )
            values = tomllib.loads(raw.decode("utf-8"))
        except (PreflightError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise ConfigurationError(
                f"configuration file could not be parsed ({type(error).__name__})"
            ) from error
        try:
            config = cls.model_validate(values)
        except ValidationError as error:
            fields: list[str] = []
            for issue in error.errors(
                include_url=False,
                include_context=False,
                include_input=False,
            )[:20]:
                first_location = issue["loc"][0] if issue["loc"] else None
                location = (
                    str(first_location)
                    if isinstance(first_location, str) and first_location in cls.model_fields
                    else "configuration"
                )
                fields.append(f"{location}:{issue['type']}")
            suffix = ", ".join(fields)
            raise ConfigurationError(f"invalid configuration fields: {suffix}") from error
        checkout = config.source_checkout
        if not checkout.is_absolute():
            checkout = path.parent / checkout
        updates: dict[str, object] = {"source_checkout": checkout.resolve()}
        allowed_signers = config.source_ssh_allowed_signers_file
        if allowed_signers is not None:
            if not allowed_signers.is_absolute():
                allowed_signers = path.parent / allowed_signers
            updates["source_ssh_allowed_signers_file"] = allowed_signers.absolute()
        return config.model_copy(update=updates)


@dataclass(frozen=True, slots=True)
class OperatorCredential:
    """Dedicated administrator credential for classic-protection evidence."""

    path: Path
    token: str = field(repr=False)

    @classmethod
    def from_environment(cls) -> OperatorCredential:
        variable = "EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE"
        value = os.getenv(variable, "").strip()
        if not value:
            raise PreflightError(f"{variable} is required")
        path = Path(value).absolute()
        token = _read_operator_token_file(path, variable)
        for ambient_variable in ("GH_TOKEN", "GITHUB_TOKEN"):
            ambient = os.getenv(ambient_variable, "").strip()
            if ambient and secrets.compare_digest(token, ambient):
                raise PreflightError(
                    f"{variable} must not reuse the ambient {ambient_variable} credential"
                )
        return cls(path=path, token=token)


@dataclass(frozen=True, slots=True)
class AppIdentity:
    """Expected identity and private key for a disposable GitHub App."""

    role: str
    app_id: int
    slug: str
    installation_id: int
    private_key_file: Path
    private_key: bytes = field(repr=False)

    @classmethod
    def from_environment(
        cls,
        role: str,
        *,
        app_id: int,
        slug: str,
        installation_id: int,
    ) -> AppIdentity:
        variable = f"EXTRA_CODEOWNERS_BETA_{role.upper()}_PRIVATE_KEY_FILE"
        value = os.getenv(variable, "").strip()
        if not value:
            raise PreflightError(f"{variable} is required")
        path = Path(value).absolute()
        private_key = _read_private_key_file(path, variable)
        return cls(role, app_id, slug, installation_id, path, private_key)


@dataclass(frozen=True, slots=True)
class AppIdentities:
    """Private runtime inputs loaded once before remote checks begin."""

    checker: AppIdentity
    approver: AppIdentity

    @classmethod
    def from_environment(cls, config: BetaConfig) -> AppIdentities:
        checker_path = os.getenv(
            "EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE",
            "",
        ).strip()
        approver_path = os.getenv(
            "EXTRA_CODEOWNERS_BETA_APPROVER_PRIVATE_KEY_FILE",
            "",
        ).strip()
        if (
            checker_path
            and approver_path
            and Path(checker_path).absolute() == Path(approver_path).absolute()
        ):
            raise PreflightError("checker and approver Apps must use different private-key files")
        return cls(
            checker=AppIdentity.from_environment(
                "checker",
                app_id=config.checker_app_id,
                slug=config.checker_app_slug,
                installation_id=config.checker_installation_id,
            ),
            approver=AppIdentity.from_environment(
                "approver",
                app_id=config.approver_app_id,
                slug=config.approver_app_slug,
                installation_id=config.approver_installation_id,
            ),
        )


class GitHubProbe(Protocol):
    """Read-only GitHub evidence used by the checks."""

    def verify_installation(
        self,
        identity: AppIdentity,
        expected_repositories: Mapping[str, int],
        *,
        organization_id: int,
        checker_webhook_url: str | None,
    ) -> Evidence:
        raise NotImplementedError

    def repository(self, full_name: str) -> JsonObject:
        raise NotImplementedError

    def branch_head(self, full_name: str, branch: str) -> str:
        raise NotImplementedError

    def branch_rules(self, full_name: str, branch: str) -> list[JsonObject]:
        raise NotImplementedError

    def classic_branch_protection(self, full_name: str, branch: str) -> JsonObject | None:
        raise NotImplementedError

    def codeowners_errors(self, full_name: str, ref: str) -> list[JsonObject]:
        raise NotImplementedError

    def repository_file(self, full_name: str, path: str, ref: str) -> bytes:
        raise NotImplementedError

    def bot_user(self, user_id: int) -> JsonObject:
        raise NotImplementedError

    def repository_label(self, full_name: str, label: str) -> JsonObject:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class ServiceProbe(Protocol):
    """Read-only deployment evidence used by the checks."""

    def json(self, path: str) -> JsonObject: ...

    def metrics(self) -> str: ...

    def close(self) -> None: ...


class SystemProbe(Protocol):
    """Local source, tool, and database evidence used by the checks."""

    def source(self, config: BetaConfig) -> Evidence: ...

    def tools(self, config: BetaConfig) -> Evidence: ...

    def database(self, config: BetaConfig) -> Evidence: ...


class _BoundedHttp:
    """Synchronous HTTP client that bounds every response before parsing it."""

    def __init__(self, *, base_url: str, user_agent: str) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": user_agent},
        )

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        limit: int,
        expected_status: int = 200,
        headers: Mapping[str, str] | None = None,
        body: JsonObject | None = None,
    ) -> tuple[bytes, str]:
        _, content, content_type = self.request_status(
            method,
            path,
            operation=operation,
            limit=limit,
            expected_statuses=frozenset({expected_status}),
            headers=headers,
            body=body,
        )
        return content, content_type

    def request_status(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        limit: int,
        expected_statuses: frozenset[int],
        headers: Mapping[str, str] | None = None,
        body: JsonObject | None = None,
    ) -> tuple[int, bytes, str]:
        try:
            with self._client.stream(method, path, headers=headers, json=body) as response:
                if response.status_code not in expected_statuses:
                    expected = ", ".join(str(status) for status in sorted(expected_statuses))
                    raise PreflightError(
                        f"{operation} returned HTTP {response.status_code}, not one of {expected}"
                    )
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > limit:
                        raise PreflightError(f"{operation} exceeded its response-size limit")
                content_type = response.headers.get("content-type", "")
        except PreflightError:
            raise
        except (httpx.HTTPError, OSError) as error:
            raise PreflightError(f"{operation} failed with {type(error).__name__}") from error
        return response.status_code, bytes(content), content_type

    def json(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        expected_status: int = 200,
        headers: Mapping[str, str] | None = None,
        body: JsonObject | None = None,
        limit: int = MAX_GITHUB_RESPONSE_BYTES,
    ) -> object:
        content, content_type = self.request(
            method,
            path,
            operation=operation,
            limit=limit,
            expected_status=expected_status,
            headers=headers,
            body=body,
        )
        if "json" not in content_type.lower():
            raise PreflightError(f"{operation} did not return JSON")
        try:
            return json.loads(content)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise PreflightError(f"{operation} returned malformed JSON") from error


class GitHubRestProbe:
    """GitHub.com reader with explicit disposable-App authentication."""

    def __init__(self) -> None:
        self._http = _BoundedHttp(
            base_url=API_URL,
            user_agent="extra-codeowners-evaluation-beta-preflight",
        )
        self._base_headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        self._operator_credential: OperatorCredential | None = None

    def close(self) -> None:
        self._http.close()

    def _json(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        token: str | None = None,
        body: JsonObject | None = None,
        expected_status: int = 200,
    ) -> object:
        headers = dict(self._base_headers)
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return self._http.json(
            method,
            path,
            operation=operation,
            expected_status=expected_status,
            headers=headers,
            body=body,
        )

    @staticmethod
    def _app_jwt(identity: AppIdentity) -> str:
        now = datetime.now(UTC)
        try:
            encoded = jwt.encode(
                {
                    "iat": int((now - timedelta(seconds=60)).timestamp()),
                    "exp": int((now + timedelta(minutes=9)).timestamp()),
                    "iss": str(identity.app_id),
                },
                identity.private_key,
                algorithm="RS256",
            )
        except Exception as error:
            raise PreflightError(
                f"{identity.role} App private key could not sign a GitHub JWT"
            ) from error
        return encoded

    def verify_installation(
        self,
        identity: AppIdentity,
        expected_repositories: Mapping[str, int],
        *,
        organization_id: int,
        checker_webhook_url: str | None,
    ) -> Evidence:
        if identity.role not in {"checker", "approver"}:
            raise PreflightError("GitHub App role is not supported by this preflight")
        expected_names = frozenset(expected_repositories)
        if not expected_names:
            raise PreflightError(f"{identity.role} expected repository set is empty")
        owners = {name.split("/", maxsplit=1)[0] for name in expected_names}
        if len(owners) != 1:
            raise PreflightError(f"{identity.role} expected repositories span multiple owners")
        owner = next(iter(owners))

        app_jwt = self._app_jwt(identity)
        app = _object(
            self._json("GET", "/app", operation=f"read {identity.role} App", token=app_jwt),
            f"{identity.role} App response",
        )
        if _positive_integer(app.get("id"), f"{identity.role} App ID") != identity.app_id:
            raise PreflightError(f"{identity.role} private key belongs to a different App ID")
        if _required_string(app.get("slug"), f"{identity.role} App slug").lower() != identity.slug:
            raise PreflightError(f"{identity.role} private key belongs to a different App slug")
        app_owner = _object(app.get("owner"), f"{identity.role} App owner")
        if (
            _positive_integer(app_owner.get("id"), f"{identity.role} App owner ID")
            != organization_id
            or _required_string(app_owner.get("login"), f"{identity.role} App owner login").lower()
            != owner
            or app_owner.get("type") != "Organization"
        ):
            raise PreflightError(f"{identity.role} App is owned by a different organization")
        app_permissions = self._permissions(app.get("permissions"), f"{identity.role} App")
        app_events = self._events(app.get("events"), f"{identity.role} App")
        self._verify_app_contract(
            identity,
            permissions=app_permissions,
            events=app_events,
        )
        installation_count = _positive_integer(
            app.get("installations_count"),
            f"{identity.role} App installation count",
        )
        if installation_count != 1:
            raise PreflightError(
                f"{identity.role} App must have exactly one installation for the disposable beta"
            )
        installations = _objects(
            self._json(
                "GET",
                "/app/installations?per_page=100&page=1",
                operation=f"list {identity.role} App installations",
                token=app_jwt,
            ),
            f"{identity.role} App installations",
        )
        if (
            len(installations) != 1
            or _positive_integer(
                installations[0].get("id"),
                f"{identity.role} listed installation ID",
            )
            != identity.installation_id
        ):
            raise PreflightError(
                f"{identity.role} App installation inventory does not match the disposable beta"
            )
        installation_requests = _objects(
            self._json(
                "GET",
                "/app/installation-requests?per_page=100&page=1",
                operation=f"list {identity.role} App installation requests",
                token=app_jwt,
            ),
            f"{identity.role} App installation requests",
        )
        if installation_requests:
            raise PreflightError(
                f"{identity.role} App has pending installation requests outside the beta boundary"
            )
        if identity.role == "checker":
            if checker_webhook_url is None:
                raise PreflightError("checker webhook URL is required")
            hook = _object(
                self._json(
                    "GET",
                    "/app/hook/config",
                    operation="read checker App webhook configuration",
                    token=app_jwt,
                ),
                "checker App webhook configuration",
            )
            insecure_ssl = hook.get("insecure_ssl")
            secret = hook.get("secret")
            if (
                hook.get("url") != checker_webhook_url
                or hook.get("content_type") != "json"
                or isinstance(insecure_ssl, bool)
                or insecure_ssl not in (0, "0")
                or not isinstance(secret, str)
                or not secret
                or set(secret) != {"*"}
            ):
                raise PreflightError(
                    "checker App webhook URL, JSON format, TLS verification, or secret is unsafe"
                )
        elif checker_webhook_url is not None:
            raise PreflightError("approver App must not be checked against a checker webhook URL")

        installation = _object(
            self._json(
                "GET",
                f"/app/installations/{identity.installation_id}",
                operation=f"read {identity.role} installation",
                token=app_jwt,
            ),
            f"{identity.role} installation response",
        )
        if (
            _positive_integer(installation.get("id"), f"{identity.role} installation ID")
            != identity.installation_id
            or _positive_integer(installation.get("app_id"), f"{identity.role} installation App ID")
            != identity.app_id
            or _required_string(
                installation.get("app_slug"),
                f"{identity.role} installation App slug",
            ).lower()
            != identity.slug
        ):
            raise PreflightError(f"{identity.role} installation identity does not match config")
        if installation.get("repository_selection") != "selected":
            raise PreflightError(f"{identity.role} installation must use selected repositories")
        if installation.get("suspended_at") is not None:
            raise PreflightError(f"{identity.role} installation is suspended")
        account = _object(installation.get("account"), f"{identity.role} installation account")
        if (
            installation.get("target_type") != "Organization"
            or _positive_integer(
                installation.get("target_id"),
                f"{identity.role} installation target ID",
            )
            != organization_id
            or _positive_integer(
                account.get("id"),
                f"{identity.role} installation account ID",
            )
            != organization_id
            or _required_string(
                account.get("login"),
                f"{identity.role} installation account login",
            ).lower()
            != owner
            or account.get("type") != "Organization"
        ):
            raise PreflightError(f"{identity.role} installation belongs to a different account")
        installation_permissions = self._permissions(
            installation.get("permissions"),
            f"{identity.role} installation",
        )
        installation_events = self._events(
            installation.get("events"),
            f"{identity.role} installation",
        )
        self._verify_app_contract(
            identity,
            permissions=installation_permissions,
            events=installation_events,
        )

        token_response = _object(
            self._json(
                "POST",
                f"/app/installations/{identity.installation_id}/access_tokens",
                operation=f"mint {identity.role} metadata-only installation token",
                token=app_jwt,
                body={"permissions": {"metadata": "read"}},
                expected_status=201,
            ),
            f"{identity.role} installation-token response",
        )
        token = _required_string(token_response.get("token"), "installation token")
        if len(token) > 4096:
            raise PreflightError("GitHub returned an oversized installation token")
        permissions = _object(
            token_response.get("permissions"), f"{identity.role} token permissions"
        )
        if permissions != {"metadata": "read"}:
            raise PreflightError(
                f"{identity.role} installation token was not limited to metadata read"
            )

        inventory = _object(
            self._json(
                "GET",
                "/installation/repositories?per_page=100&page=1",
                operation=f"list {identity.role} installation repositories",
                token=token,
            ),
            f"{identity.role} repository inventory",
        )
        total = _positive_integer(inventory.get("total_count"), f"{identity.role} repository count")
        repositories = _objects(
            inventory.get("repositories"), f"{identity.role} installation repositories"
        )
        observed: dict[str, int] = {}
        for repository in repositories:
            name = _required_string(
                repository.get("full_name"),
                "installation repository name",
            ).lower()
            repository_id = _positive_integer(
                repository.get("id"),
                "installation repository ID",
            )
            if name in observed:
                raise PreflightError(
                    f"{identity.role} installation repository inventory contains duplicates"
                )
            observed[name] = repository_id
        if (
            total != len(repositories)
            or observed != dict(expected_repositories)
            or frozenset(observed) != expected_names
        ):
            raise PreflightError(
                f"{identity.role} installation repository selection is not the expected exact set"
            )
        evidence: Evidence = {
            "app_id": identity.app_id,
            "app_slug": identity.slug,
            "installation_id": identity.installation_id,
            "app_installation_count": installation_count,
            "pending_installation_request_count": 0,
            "repository_selection": "selected",
            "repository_count": total,
            "repository_ids": dict(sorted(observed.items())),
            "permissions": dict(sorted(installation_permissions.items())),
            "events": sorted(installation_events),
            "token_permissions": "metadata:read",
        }
        if identity.role == "checker":
            evidence["webhook_url"] = checker_webhook_url
        return evidence

    @staticmethod
    def _permissions(value: object, description: str) -> dict[str, str]:
        permissions = _object(value, f"{description} permissions")
        if any(
            not isinstance(name, str) or not isinstance(access, str)
            for name, access in permissions.items()
        ):
            raise PreflightError(f"{description} permissions are malformed")
        return cast(dict[str, str], permissions)

    @staticmethod
    def _events(value: object, description: str) -> frozenset[str]:
        if not isinstance(value, list) or any(not isinstance(event, str) for event in value):
            raise PreflightError(f"{description} events are malformed")
        events = cast(list[str], value)
        if len(set(events)) != len(events):
            raise PreflightError(f"{description} events contain duplicates")
        return frozenset(events)

    @staticmethod
    def _verify_app_contract(
        identity: AppIdentity,
        *,
        permissions: Mapping[str, str],
        events: frozenset[str],
    ) -> None:
        if identity.role == "checker":
            if permissions != CHECKER_PERMISSIONS:
                raise PreflightError("checker App permissions do not match the exact contract")
            if events != CHECKER_EVENTS:
                raise PreflightError("checker App events do not match the exact contract")
        elif permissions != APPROVER_PERMISSIONS or events != APPROVER_EVENTS:
            raise PreflightError(
                "approver App permissions or events do not match the exact contract"
            )

    def repository(self, full_name: str) -> JsonObject:
        return _object(
            self._json(
                "GET",
                f"/repos/{full_name}",
                operation=f"read public repository {full_name}",
            ),
            f"repository {full_name}",
        )

    def branch_head(self, full_name: str, branch: str) -> str:
        response = _object(
            self._json(
                "GET",
                f"/repos/{full_name}/git/ref/heads/{quote(branch, safe='/')}",
                operation=f"read {full_name} branch head",
            ),
            f"{full_name} branch head",
        )
        if response.get("ref") != f"refs/heads/{branch}":
            raise PreflightError(f"GitHub returned a different branch ref for {full_name}")
        target = _object(response.get("object"), f"{full_name} branch target")
        sha = _required_string(target.get("sha"), f"{full_name} branch SHA").lower()
        if target.get("type") != "commit" or REVISION.fullmatch(sha) is None:
            raise PreflightError(f"{full_name} branch does not point to a full commit SHA")
        return sha

    def branch_rules(self, full_name: str, branch: str) -> list[JsonObject]:
        rules = _objects(
            self._json(
                "GET",
                (f"/repos/{full_name}/rules/branches/{quote(branch, safe='')}?per_page=100&page=1"),
                operation=f"read active rules for {full_name}",
            ),
            f"active branch rules for {full_name}",
        )
        if len(rules) >= 100:
            raise PreflightError("active branch rules reached the bounded first-page limit")
        return rules

    def _operator_token(self) -> str:
        if self._operator_credential is None:
            self._operator_credential = OperatorCredential.from_environment()
        return self._operator_credential.token

    def classic_branch_protection(
        self,
        full_name: str,
        branch: str,
    ) -> JsonObject | None:
        token = self._operator_token()
        _object(
            self._json(
                "GET",
                f"/repos/{full_name}/actions/permissions",
                operation=f"prove repository-administration read access for {full_name}",
                token=token,
            ),
            "repository Actions permissions",
        )
        headers = dict(self._base_headers)
        headers["Authorization"] = f"Bearer {token}"
        status, content, content_type = self._http.request_status(
            "GET",
            f"/repos/{full_name}/branches/{quote(branch, safe='')}/protection",
            operation=f"read classic branch protection for {full_name}",
            limit=MAX_GITHUB_RESPONSE_BYTES,
            expected_statuses=frozenset({200, 404}),
            headers=headers,
        )
        if status == 404:
            return None
        if "json" not in content_type.lower():
            raise PreflightError("classic branch protection did not return JSON")
        try:
            return _object(json.loads(content), "classic branch protection")
        except (UnicodeError, json.JSONDecodeError) as error:
            raise PreflightError("classic branch protection returned malformed JSON") from error

    def codeowners_errors(self, full_name: str, ref: str) -> list[JsonObject]:
        response = _object(
            self._json(
                "GET",
                f"/repos/{full_name}/codeowners/errors?ref={quote(ref, safe='')}",
                operation=f"read CODEOWNERS errors for {full_name}",
            ),
            f"CODEOWNERS errors for {full_name}",
        )
        return _objects(response.get("errors"), f"CODEOWNERS errors for {full_name}")

    def repository_file(self, full_name: str, path: str, ref: str) -> bytes:
        response = _object(
            self._json(
                "GET",
                (f"/repos/{full_name}/contents/{quote(path, safe='/')}?ref={quote(ref, safe='')}"),
                operation=f"read {path} from {full_name}",
            ),
            f"{path} content response",
        )
        if response.get("type") != "file" or response.get("encoding") != "base64":
            raise PreflightError(f"{path} in {full_name} is not an inline base64 file")
        size = _positive_integer(response.get("size"), f"{path} size")
        if size > MAX_REMOTE_FILE_BYTES:
            raise PreflightError(f"{path} in {full_name} exceeds the preflight size limit")
        encoded = _required_string(response.get("content"), f"{path} content")
        if any(character.isspace() and character not in "\r\n" for character in encoded):
            raise PreflightError(f"{path} in {full_name} has invalid base64 whitespace")
        try:
            decoded = base64.b64decode(encoded.replace("\r", "").replace("\n", ""), validate=True)
        except (ValueError, binascii.Error) as error:
            raise PreflightError(f"{path} in {full_name} has invalid base64 content") from error
        if len(decoded) != size:
            raise PreflightError(f"{path} in {full_name} has inconsistent size metadata")
        return decoded

    def bot_user(self, user_id: int) -> JsonObject:
        return _object(
            self._json(
                "GET",
                f"/user/{user_id}",
                operation=f"read approver bot user {user_id}",
            ),
            "approver bot user",
        )

    def repository_label(self, full_name: str, label: str) -> JsonObject:
        return _object(
            self._json(
                "GET",
                f"/repos/{full_name}/labels/{quote(label, safe='')}",
                operation=f"read label {label} from {full_name}",
            ),
            f"label {label}",
        )


class DeploymentServiceProbe:
    """Bounded reader for one operator-selected HTTPS service origin."""

    def __init__(self, service_url: str) -> None:
        self._http = _BoundedHttp(
            base_url=service_url,
            user_agent="extra-codeowners-evaluation-beta-preflight",
        )

    def close(self) -> None:
        self._http.close()

    def json(self, path: str) -> JsonObject:
        return _object(
            self._http.json(
                "GET",
                path,
                operation=f"read deployment endpoint {path}",
                limit=MAX_SERVICE_JSON_BYTES,
            ),
            f"deployment endpoint {path}",
        )

    def metrics(self) -> str:
        body, content_type = self._http.request(
            "GET",
            "/metrics",
            operation="read deployment metrics",
            limit=MAX_METRICS_BYTES,
        )
        if "text/plain" not in content_type.lower():
            raise PreflightError("deployment metrics did not return text/plain")
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PreflightError("deployment metrics was not UTF-8") from error


class LocalSystemProbe:
    """Read-only local source, toolchain, and PostgreSQL checks."""

    @staticmethod
    def _run(arguments: Sequence[str], *, cwd: Path | None = None) -> str:
        try:
            result = subprocess.run(  # noqa: S603 - every caller supplies fixed arguments.
                arguments,
                cwd=cwd,
                check=False,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise PreflightError(
                f"{arguments[0]} probe failed with {type(error).__name__}"
            ) from error
        if len(result.stdout) > GIT_OUTPUT_BYTES or len(result.stderr) > GIT_OUTPUT_BYTES:
            raise PreflightError(f"{arguments[0]} probe exceeded its output limit")
        if result.returncode != 0:
            raise PreflightError(f"{arguments[0]} probe exited {result.returncode}")
        try:
            return result.stdout.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise PreflightError(f"{arguments[0]} probe output was not UTF-8") from error

    @staticmethod
    def _git_environment() -> dict[str, str]:
        """Return the complete, intentionally small environment for Git."""

        try:
            home = pwd.getpwuid(os.geteuid()).pw_dir
        except (KeyError, OSError) as error:
            raise PreflightError("current user has no stable home directory") from error
        return {
            "GIT_ASKPASS": "/bin/false",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": home,
            "LANG": "C",
            "LC_ALL": "C",
            "PAGER": "cat",
            "PATH": "/usr/bin:/bin",
            "SSH_ASKPASS": "/bin/false",
            "TZ": "UTC",
        }

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
        """Kill a probe and any descendants without signalling this process."""

        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(OSError, subprocess.SubprocessError):
            process.wait(timeout=1)

    @classmethod
    def _run_git(
        cls,
        arguments: Sequence[str],
        *,
        checkout_fd: int,
        output_limit: int = GIT_OUTPUT_BYTES,
        extra_fds: Sequence[int] = (),
    ) -> str:
        """Run fixed Git with bounded I/O, time, configuration, and descendants."""

        fixed_configuration = (
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "credential.helper=",
            "-c",
            "credential.interactive=never",
            "-c",
            "protocol.allow=never",
            "-c",
            "submodule.recurse=false",
            "-c",
            "fetch.recurseSubmodules=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gpg.program=/usr/bin/gpg",
            "-c",
            "gpg.ssh.program=/usr/bin/ssh-keygen",
            "-c",
            "gpg.x509.program=/usr/bin/gpgsm",
        )
        command = (GIT_BINARY, "--no-pager", *fixed_configuration, *arguments)
        inherited_fds = tuple(dict.fromkeys((checkout_fd, *extra_fds)))
        try:
            process = subprocess.Popen(  # noqa: S603 - executable and options are fixed.
                command,
                cwd=f"/proc/self/fd/{checkout_fd}",
                env=cls._git_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=inherited_fds,
                start_new_session=True,
            )
        except OSError as error:
            raise PreflightError("fixed Git probe could not start") from error
        assert process.stdout is not None
        assert process.stderr is not None
        streams = (process.stdout, process.stderr)
        output = (bytearray(), bytearray())
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        try:
            for index, stream in enumerate(streams):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PreflightError("fixed Git probe exceeded its time limit")
                events = selector.select(remaining)
                if not events:
                    raise PreflightError("fixed Git probe exceeded its time limit")
                for key, _ in events:
                    stream = cast(Any, key.fileobj)
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    output[cast(int, key.data)].extend(chunk)
                    if len(output[0]) + len(output[1]) > output_limit:
                        raise PreflightError("fixed Git probe exceeded its output limit")
            try:
                return_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise PreflightError("fixed Git probe exceeded its time limit") from error
        except BaseException:
            cls._kill_process_group(process)
            raise
        finally:
            selector.close()
            for stream in streams:
                stream.close()
        if return_code != 0:
            raise PreflightError(f"fixed Git probe exited {return_code}")
        try:
            return bytes(output[0]).decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise PreflightError("fixed Git probe output was not UTF-8") from error

    @staticmethod
    def _require_safe_directory(metadata: os.stat_result, description: str) -> None:
        if not stat.S_ISDIR(metadata.st_mode):
            raise PreflightError(f"{description} is not a directory")
        if metadata.st_uid != os.geteuid():
            raise PreflightError(f"{description} is not owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PreflightError(f"{description} is group/world-writable")

    @classmethod
    def _hash_tracked_file(
        cls,
        checkout_fd: int,
        path: str,
        *,
        expected_mode: str,
        object_format: str,
    ) -> tuple[str, int]:
        """Hash one bounded tracked file without following repository symlinks."""

        try:
            normalized_path = normalize_repository_path(path)
        except ValueError as error:
            raise PreflightError("source tree contains an unsafe tracked-file path") from error
        if (
            normalized_path != path
            or SAFE_PATH.fullmatch(path) is None
            or len(path.encode("utf-8")) > MAX_TRACKED_PATH_BYTES
            or path.split("/", 1)[0] == ".git"
        ):
            raise PreflightError("source tree contains an unsafe tracked-file path")

        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise PreflightError("tracked source files cannot be opened safely on this platform")
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow | directory
        file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow
        directory_fd = -1
        file_fd = -1
        try:
            directory_fd = os.dup(checkout_fd)
            components = path.split("/")
            for component in components[:-1]:
                child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child_fd
                cls._require_safe_directory(
                    os.fstat(directory_fd),
                    "tracked source parent directory",
                )

            file_fd = os.open(components[-1], file_flags, dir_fd=directory_fd)
            before = os.fstat(file_fd)
            mode = stat.S_IMODE(before.st_mode)
            expected_executable = expected_mode == "100755"
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or mode & 0o022
                or bool(mode & 0o111) != expected_executable
            ):
                raise PreflightError(
                    "tracked source file has an unsafe type, owner, link count, or mode"
                )
            if before.st_size < 0 or before.st_size > MAX_TRACKED_FILE_BYTES:
                raise PreflightError(
                    f"tracked source file exceeds the {MAX_TRACKED_FILE_BYTES}-byte limit"
                )

            digest = hashlib.new(object_format)
            digest.update(f"blob {before.st_size}\0".encode())
            observed_size = 0
            while observed_size <= MAX_TRACKED_FILE_BYTES:
                chunk = os.read(
                    file_fd,
                    min(64 * 1024, MAX_TRACKED_FILE_BYTES + 1 - observed_size),
                )
                if not chunk:
                    break
                observed_size += len(chunk)
                digest.update(chunk)
            after = os.fstat(file_fd)
            path_after = os.stat(
                components[-1],
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                observed_size != before.st_size
                or _stable_file_identity(before) != _stable_file_identity(after)
                or _stable_file_identity(after) != _stable_file_identity(path_after)
            ):
                raise PreflightError("tracked source file changed while it was being hashed")
            return digest.hexdigest(), observed_size
        except PreflightError:
            raise
        except (OSError, ValueError) as error:
            raise PreflightError("tracked source file could not be inspected safely") from error
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if directory_fd >= 0:
                os.close(directory_fd)

    @staticmethod
    def _require_safe_repository_file(
        directory_fd: int,
        name: str,
        description: str,
    ) -> os.stat_result:
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise PreflightError(f"{description} is not safely readable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise PreflightError(
                f"{description} must be a current-user, single-link, non-writable regular file"
            )
        return metadata

    @staticmethod
    def _open_allowed_signers_file(path: Path) -> tuple[int, os.stat_result]:
        """Open and bound one explicit SSH trust file without following it."""

        if not path.is_absolute():
            raise PreflightError("source SSH allowed-signers path is not absolute")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise PreflightError("source SSH allowed-signers file cannot be opened safely")
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o022
            ):
                raise PreflightError(
                    "source SSH allowed-signers file must be a current-user, "
                    "single-link, non-group/world-writable regular file"
                )
            if before.st_size <= 0 or before.st_size > MAX_ALLOWED_SIGNERS_BYTES:
                raise PreflightError(
                    f"source SSH allowed-signers file must contain "
                    f"1-{MAX_ALLOWED_SIGNERS_BYTES} bytes"
                )
            content = bytearray()
            while len(content) <= MAX_ALLOWED_SIGNERS_BYTES:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, MAX_ALLOWED_SIGNERS_BYTES + 1 - len(content)),
                )
                if not chunk:
                    break
                content.extend(chunk)
            after_read = os.fstat(descriptor)
            path_metadata = os.stat(path, follow_symlinks=False)
            if (
                len(content) != after_read.st_size
                or _stable_file_identity(before) != _stable_file_identity(after_read)
                or _stable_file_identity(after_read) != _stable_file_identity(path_metadata)
            ):
                raise PreflightError("source SSH allowed-signers file changed while it was read")
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor, before
        except PreflightError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise PreflightError(
                "source SSH allowed-signers file is not safely readable"
            ) from error

    @staticmethod
    def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
        return left.st_dev == right.st_dev and left.st_ino == right.st_ino

    @staticmethod
    def _one_line(value: str, description: str) -> str:
        if not value or "\n" in value or "\r" in value or "\0" in value:
            raise PreflightError(f"{description} is not one bounded line")
        return value

    def source(self, config: BetaConfig) -> Evidence:
        checkout = config.source_checkout
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise PreflightError("source checkout cannot be opened safely on this platform")
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | nofollow | directory
        checkout_fd = -1
        git_fd = -1
        objects_fd = -1
        allowed_signers_fd = -1
        allowed_signers_before: os.stat_result | None = None
        allowed_signers_path = config.source_ssh_allowed_signers_file
        signature_format = (
            "ssh"
            if SSH_FINGERPRINT.fullmatch(config.source_signer_fingerprint) is not None
            else "openpgp"
        )
        try:
            if signature_format == "ssh":
                if allowed_signers_path is None:
                    raise PreflightError(
                        "source SSH signature requires an explicit allowed-signers file"
                    )
                allowed_signers_fd, allowed_signers_before = self._open_allowed_signers_file(
                    allowed_signers_path
                )
            elif allowed_signers_path is not None:
                raise PreflightError(
                    "source OpenPGP signature must not use an SSH allowed-signers file"
                )
            checkout_fd = os.open(checkout, directory_flags)
            checkout_before = os.fstat(checkout_fd)
            checkout_path_before = os.stat(checkout, follow_symlinks=False)
            self._require_safe_directory(checkout_before, "source checkout")
            if not self._same_object(checkout_before, checkout_path_before):
                raise PreflightError("source checkout path changed while it was opened")

            git_fd = os.open(".git", directory_flags, dir_fd=checkout_fd)
            git_before = os.fstat(git_fd)
            self._require_safe_directory(git_before, "source Git directory")
            config_before = self._require_safe_repository_file(
                git_fd,
                "config",
                "source repository config",
            )
            head_file_before = self._require_safe_repository_file(
                git_fd,
                "HEAD",
                "source repository HEAD",
            )
            objects_fd = os.open("objects", directory_flags, dir_fd=git_fd)
            objects_before = os.fstat(objects_fd)
            self._require_safe_directory(objects_before, "source object directory")
            for unsafe_name, description in (
                ("commondir", "linked-worktree common directory"),
                ("shallow", "shallow-repository marker"),
                ("worktrees", "linked-worktree metadata"),
            ):
                try:
                    os.stat(unsafe_name, dir_fd=git_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise PreflightError(f"{description} could not be inspected") from error
                else:
                    raise PreflightError(f"source checkout contains {description}")
            try:
                os.stat("info/alternates", dir_fd=objects_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise PreflightError("source object alternates could not be inspected") from error
            else:
                raise PreflightError("source checkout uses an alternate object store")

            top_level = self._one_line(
                self._run_git(["rev-parse", "--show-toplevel"], checkout_fd=checkout_fd),
                "source top-level path",
            )
            git_directory = self._one_line(
                self._run_git(
                    ["rev-parse", "--path-format=absolute", "--absolute-git-dir"],
                    checkout_fd=checkout_fd,
                ),
                "source Git directory path",
            )
            common_directory = self._one_line(
                self._run_git(
                    ["rev-parse", "--path-format=absolute", "--git-common-dir"],
                    checkout_fd=checkout_fd,
                ),
                "source common Git directory path",
            )
            object_directory = self._one_line(
                self._run_git(
                    ["rev-parse", "--path-format=absolute", "--git-path", "objects"],
                    checkout_fd=checkout_fd,
                ),
                "source object directory path",
            )
            try:
                observed_top = os.stat(top_level)
                observed_git = os.stat(git_directory)
                observed_common = os.stat(common_directory)
                observed_objects = os.stat(object_directory)
            except OSError as error:
                raise PreflightError("Git reported an inaccessible repository topology") from error
            if (
                not self._same_object(observed_top, checkout_before)
                or not self._same_object(observed_git, git_before)
                or not self._same_object(observed_common, git_before)
                or not self._same_object(observed_objects, objects_before)
            ):
                raise PreflightError("source checkout uses an indirect repository topology")
            shallow = self._run_git(
                ["rev-parse", "--is-shallow-repository"],
                checkout_fd=checkout_fd,
            )
            if shallow != "false":
                raise PreflightError("source checkout is shallow or has indeterminate topology")

            object_format = self._run_git(
                ["rev-parse", "--show-object-format"],
                checkout_fd=checkout_fd,
            )
            expected_object_format = "sha1" if len(config.source_revision) == 40 else "sha256"
            if object_format != expected_object_format:
                raise PreflightError("source revision does not match repository object format")
            object_type = self._run_git(
                ["cat-file", "-t", config.source_revision],
                checkout_fd=checkout_fd,
            )
            resolved_revision = self._run_git(
                ["rev-parse", "--verify", f"{config.source_revision}^{{commit}}"],
                checkout_fd=checkout_fd,
            )
            if object_type != "commit" or resolved_revision != config.source_revision:
                raise PreflightError("source_revision is not the exact pinned commit object")

            head_ref = self._one_line(
                self._run_git(
                    ["rev-parse", "--symbolic-full-name", "HEAD"],
                    checkout_fd=checkout_fd,
                ),
                "source HEAD binding",
            )
            if head_ref != "HEAD":
                if not head_ref.startswith("refs/heads/"):
                    raise PreflightError("source HEAD is bound to an unsafe ref namespace")
                self._run_git(["check-ref-format", head_ref], checkout_fd=checkout_fd)
            head = self._run_git(["rev-parse", "--verify", "HEAD"], checkout_fd=checkout_fd)
            if head != config.source_revision:
                raise PreflightError("source checkout HEAD does not match source_revision")
            replacements = self._run_git(
                ["for-each-ref", "--format=%(refname)", "refs/replace"],
                checkout_fd=checkout_fd,
            )
            if replacements:
                raise PreflightError("source checkout contains replacement refs")
            self._run_git(
                ["fsck", "--strict", "--no-dangling", "--no-reflogs", config.source_revision],
                checkout_fd=checkout_fd,
            )

            signature_configuration = [
                "-c",
                f"gpg.format={signature_format}",
            ]
            signature_fds: tuple[int, ...] = ()
            if signature_format == "ssh":
                signature_configuration.extend(
                    (
                        "-c",
                        (f"gpg.ssh.allowedSignersFile=/proc/self/fd/{allowed_signers_fd}"),
                    )
                )
                signature_fds = (allowed_signers_fd,)
            signature = self._run_git(
                [
                    *signature_configuration,
                    "show",
                    "-s",
                    "--format=%G?%x00%GF",
                    config.source_revision,
                ],
                checkout_fd=checkout_fd,
                extra_fds=signature_fds,
            ).split("\0")
            observed_fingerprint = signature[1] if len(signature) == 2 else ""
            fingerprints_match = (
                secrets.compare_digest(
                    observed_fingerprint,
                    config.source_signer_fingerprint,
                )
                if signature_format == "ssh"
                else secrets.compare_digest(
                    observed_fingerprint.upper(),
                    config.source_signer_fingerprint,
                )
            )
            if len(signature) != 2 or signature[0] != "G" or not fingerprints_match:
                raise PreflightError(
                    "source commit signature does not match the configured exact fingerprint"
                )
            self._run_git(
                [
                    *signature_configuration,
                    "verify-commit",
                    "--raw",
                    config.source_revision,
                ],
                checkout_fd=checkout_fd,
                extra_fds=signature_fds,
            )

            def require_clean_checkout() -> tuple[int, int]:
                tracked_changes = self._run_git(
                    [
                        "status",
                        "--porcelain=v1",
                        "-z",
                        "--untracked-files=all",
                        "--ignore-submodules=none",
                    ],
                    checkout_fd=checkout_fd,
                )
                untracked_files = self._run_git(
                    ["ls-files", "--others", "--exclude-standard", "-z", "--"],
                    checkout_fd=checkout_fd,
                )
                index_entries = self._run_git(
                    ["ls-files", "--stage", "-z", "--"],
                    checkout_fd=checkout_fd,
                    output_limit=GIT_INDEX_OUTPUT_BYTES,
                )
                index_flags = self._run_git(
                    ["ls-files", "-v", "-f", "-z", "--"],
                    checkout_fd=checkout_fd,
                    output_limit=GIT_INDEX_OUTPUT_BYTES,
                )
                signed_tree = self._run_git(
                    [
                        "ls-tree",
                        "-r",
                        "--full-tree",
                        "-z",
                        config.source_revision,
                    ],
                    checkout_fd=checkout_fd,
                    output_limit=GIT_INDEX_OUTPUT_BYTES,
                )
                if tracked_changes or untracked_files:
                    raise PreflightError("source checkout has tracked or untracked modifications")

                tree: dict[str, tuple[str, str]] = {}
                for entry in (item for item in signed_tree.split("\0") if item):
                    metadata, separator, path = entry.partition("\t")
                    fields = metadata.split()
                    if (
                        not separator
                        or len(fields) != 3
                        or fields[0] not in {"100644", "100755"}
                        or fields[1] != "blob"
                        or re.fullmatch(
                            rf"[0-9a-f]{{{len(config.source_revision)}}}",
                            fields[2],
                        )
                        is None
                        or path in tree
                    ):
                        raise PreflightError(
                            "signed source tree contains a symlink, gitlink, duplicate, "
                            "or unsupported tracked-file entry"
                        )
                    tree[path] = (fields[0], fields[2])
                if not tree or len(tree) > MAX_TRACKED_FILES:
                    raise PreflightError(
                        f"signed source tree must contain 1-{MAX_TRACKED_FILES} tracked files"
                    )

                index: dict[str, tuple[str, str]] = {}
                for entry in (item for item in index_entries.split("\0") if item):
                    metadata, separator, path = entry.partition("\t")
                    fields = metadata.split()
                    if (
                        not separator
                        or len(fields) != 3
                        or fields[0] not in {"100644", "100755"}
                        or fields[2] != "0"
                        or path in index
                    ):
                        raise PreflightError(
                            "source checkout contains a symlink, gitlink, conflict, "
                            "or unsupported tracked-file mode"
                        )
                    index[path] = (fields[0], fields[1])
                if index != tree:
                    raise PreflightError(
                        "source index does not exactly match the signed source tree"
                    )

                flagged_paths: set[str] = set()
                for entry in (item for item in index_flags.split("\0") if item):
                    tag, separator, path = entry.partition(" ")
                    if not separator or tag != "H" or path in flagged_paths or path not in tree:
                        raise PreflightError(
                            "source checkout contains assume-unchanged, skip-worktree, "
                            "or fsmonitor-valid index flags"
                        )
                    flagged_paths.add(path)
                if flagged_paths != set(tree):
                    raise PreflightError(
                        "source checkout index flags do not cover the signed source tree"
                    )

                total_bytes = 0
                for path, (mode, expected_object_id) in sorted(tree.items()):
                    observed_object_id, observed_size = self._hash_tracked_file(
                        checkout_fd,
                        path,
                        expected_mode=mode,
                        object_format=expected_object_format,
                    )
                    if not secrets.compare_digest(
                        observed_object_id,
                        expected_object_id,
                    ):
                        raise PreflightError(
                            "tracked source content does not match the signed source tree"
                        )
                    total_bytes += observed_size
                    if total_bytes > MAX_TRACKED_SOURCE_BYTES:
                        raise PreflightError(
                            f"tracked source exceeds the {MAX_TRACKED_SOURCE_BYTES}-byte limit"
                        )
                return len(tree), total_bytes

            tracked_file_count, tracked_source_bytes = require_clean_checkout()
            final_head = self._run_git(
                ["rev-parse", "--verify", "HEAD"],
                checkout_fd=checkout_fd,
            )
            final_ref = self._run_git(
                ["rev-parse", "--symbolic-full-name", "HEAD"],
                checkout_fd=checkout_fd,
            )
            final_resolved_revision = self._run_git(
                ["rev-parse", "--verify", f"{config.source_revision}^{{commit}}"],
                checkout_fd=checkout_fd,
            )
            self._run_git(
                ["fsck", "--strict", "--no-dangling", "--no-reflogs", config.source_revision],
                checkout_fd=checkout_fd,
            )
            final_file_count, final_source_bytes = require_clean_checkout()
            if (
                final_head != config.source_revision
                or final_ref != head_ref
                or final_resolved_revision != config.source_revision
                or final_file_count != tracked_file_count
                or final_source_bytes != tracked_source_bytes
            ):
                raise PreflightError("source HEAD or its pinned ref moved during the preflight")

            checkout_after = os.fstat(checkout_fd)
            git_after = os.fstat(git_fd)
            objects_after = os.fstat(objects_fd)
            config_after = os.stat("config", dir_fd=git_fd, follow_symlinks=False)
            head_file_after = os.stat("HEAD", dir_fd=git_fd, follow_symlinks=False)
            checkout_path_after = os.stat(checkout, follow_symlinks=False)
            allowed_signers_changed = False
            if (
                allowed_signers_fd >= 0
                and allowed_signers_before is not None
                and allowed_signers_path is not None
            ):
                allowed_signers_after = os.fstat(allowed_signers_fd)
                allowed_signers_path_after = os.stat(
                    allowed_signers_path,
                    follow_symlinks=False,
                )
                allowed_signers_changed = _stable_file_identity(
                    allowed_signers_before
                ) != _stable_file_identity(allowed_signers_after) or _stable_file_identity(
                    allowed_signers_after
                ) != _stable_file_identity(allowed_signers_path_after)
            if allowed_signers_changed:
                raise PreflightError("source SSH allowed-signers file changed during the preflight")
            if (
                not self._same_object(checkout_before, checkout_after)
                or not self._same_object(checkout_after, checkout_path_after)
                or not self._same_object(git_before, git_after)
                or not self._same_object(objects_before, objects_after)
                or _stable_file_identity(config_before) != _stable_file_identity(config_after)
                or _stable_file_identity(head_file_before) != _stable_file_identity(head_file_after)
            ):
                raise PreflightError("source repository topology changed during the preflight")
        except PreflightError:
            raise
        except OSError as error:
            raise PreflightError("source checkout could not be inspected safely") from error
        finally:
            for descriptor in (
                allowed_signers_fd,
                objects_fd,
                git_fd,
                checkout_fd,
            ):
                if descriptor >= 0:
                    os.close(descriptor)
        return {
            "scope": "local-checkout-self-consistency",
            "independent_source_attestation": False,
            "revision": config.source_revision,
            "object_format": expected_object_format,
            "signature": "valid-and-exact-fingerprint-match",
            "signature_format": signature_format,
            "signer_fingerprint": config.source_signer_fingerprint,
            "checkout_clean_observations": 2,
            "safe_index_flags_and_file_modes": True,
            "tracked_file_count": tracked_file_count,
            "tracked_source_bytes": tracked_source_bytes,
            "tracked_content": "hashed-twice-against-signed-tree",
            "repository_topology": "standalone-without-object-alternates",
            "head_binding": "detached" if head_ref == "HEAD" else "symbolic",
        }

    def tools(self, config: BetaConfig) -> Evidence:
        python_version = ".".join(str(part) for part in sys.version_info[:3])
        if python_version != config.python_version:
            raise PreflightError("Python version does not match the pinned beta config")
        uv_binary = shutil.which("uv")
        if uv_binary is None:
            raise PreflightError("uv is not installed")
        uv_output = self._run([uv_binary, "--version"])
        match = re.fullmatch(r"uv ([0-9A-Za-z][0-9A-Za-z.+_-]{0,63})(?: .*)?", uv_output)
        if match is None or match.group(1) != config.uv_version:
            raise PreflightError("uv version does not match the pinned beta config")
        if __version__ != config.extra_codeowners_version:
            raise PreflightError(
                "installed Extra CODEOWNERS version does not match the pinned beta config"
            )
        package_file = Path(cast(str, sys.modules["extra_codeowners"].__file__)).resolve()
        try:
            package_file.relative_to(config.source_checkout)
        except ValueError as error:
            raise PreflightError("Extra CODEOWNERS was imported outside source_checkout") from error
        return {
            "python": python_version,
            "uv": config.uv_version,
            "extra_codeowners": __version__,
            "package_loaded_from_checkout": True,
        }

    def database(self, config: BetaConfig) -> Evidence:
        database_url = os.getenv("EXTRA_CODEOWNERS_BETA_DATABASE_URL", "").strip()
        if not database_url:
            raise PreflightError("EXTRA_CODEOWNERS_BETA_DATABASE_URL is required")
        try:
            validate_production_database_transport(database_url)
            parsed = make_url(database_url)
        except Exception as error:
            raise PreflightError("beta database URL is invalid") from error
        if parsed.drivername != "postgresql+psycopg":
            raise PreflightError("beta database must use the postgresql+psycopg driver")
        query_host = parsed.query.get("host")
        if query_host is not None and not isinstance(query_host, str):
            raise PreflightError("beta database URL contains an ambiguous host")
        ssl_mode = parsed.query.get("sslmode")
        if ssl_mode is not None and not isinstance(ssl_mode, str):
            raise PreflightError("beta database URL contains an ambiguous sslmode")
        if query_host is not None and parsed.host is not None:
            raise PreflightError("beta database URL contains multiple host routes")
        effective_host = query_host if isinstance(query_host, str) else parsed.host
        if (
            not effective_host
            or not parsed.database
            or not parsed.username
            or not parsed.password
            or "options" in parsed.query
        ):
            raise PreflightError(
                "beta database URL must explicitly pin one host, database, username, "
                "password, and no options override"
            )
        connection_options = (
            "-cdefault_transaction_read_only=on "
            "-cstatement_timeout=5000 "
            "-clock_timeout=5000 "
            "-cidle_in_transaction_session_timeout=5000 "
            "-csearch_path=public"
        )
        try:
            engine = create_engine(
                parsed,
                poolclass=NullPool,
                pool_pre_ping=False,
                pool_reset_on_return="rollback",
                hide_parameters=True,
                connect_args={
                    **isolated_postgresql_connect_args(database_url),
                    "application_name": "extra-codeowners-evaluation-beta",
                    "connect_timeout": 5,
                    "options": connection_options,
                },
            )
        except Exception as error:
            raise PreflightError(
                f"read-only PostgreSQL engine failed with {type(error).__name__}"
            ) from error
        try:
            with engine.connect() as connection:
                default_read_only = connection.execute(
                    text("SHOW default_transaction_read_only")
                ).scalar_one()
                read_only = connection.execute(text("SHOW transaction_read_only")).scalar_one()
                statement_timeout = connection.execute(text("SHOW statement_timeout")).scalar_one()
                lock_timeout = connection.execute(text("SHOW lock_timeout")).scalar_one()
                idle_timeout = connection.execute(
                    text("SHOW idle_in_transaction_session_timeout")
                ).scalar_one()
                search_path = connection.execute(text("SHOW search_path")).scalar_one()
                version_value = connection.execute(text("SHOW server_version_num")).scalar_one()
            validate_database_schema(engine)
        except Exception as error:
            raise PreflightError(
                f"read-only PostgreSQL probe failed with {type(error).__name__}"
            ) from error
        finally:
            engine.dispose()
        try:
            server_version_num = int(version_value)
        except (TypeError, ValueError) as error:
            raise PreflightError("PostgreSQL returned an invalid server_version_num") from error
        if server_version_num != config.postgres_server_version_num:
            raise PreflightError("PostgreSQL version does not match the pinned beta config")
        if default_read_only != "on" or read_only != "on":
            raise PreflightError("PostgreSQL probe and default transaction are not read-only")
        if statement_timeout != "5s" or lock_timeout != "5s" or idle_timeout != "5s":
            raise PreflightError("PostgreSQL probe timeouts are not the fixed five-second bounds")
        if search_path != "public":
            raise PreflightError("PostgreSQL probe does not use the fixed safe search_path")
        return {
            "backend": "postgresql",
            "server_version_num": server_version_num,
            "database_revision": DATABASE_MIGRATION_HEAD,
            "schema_contract": "required-release-contract",
            "transaction_mode": "read-only",
            "search_path": "public",
            "statement_timeout_ms": 5000,
            "lock_timeout_ms": 5000,
            "idle_in_transaction_session_timeout_ms": 5000,
        }


def _check_installations(
    config: BetaConfig,
    github: GitHubProbe,
    identities: AppIdentities,
) -> Evidence:
    owner = config.target_repository.split("/", maxsplit=1)[0]
    checker_evidence = github.verify_installation(
        identities.checker,
        {
            config.target_repository: config.target_repository_id,
            config.organization_policy_repository: config.organization_policy_repository_id,
        },
        organization_id=config.organization_id,
        checker_webhook_url=config.checker_webhook_url,
    )
    approver_evidence = github.verify_installation(
        identities.approver,
        {config.target_repository: config.target_repository_id},
        organization_id=config.organization_id,
        checker_webhook_url=None,
    )
    bot = github.bot_user(config.approver_bot_user_id)
    expected_bot_login = f"{config.approver_app_slug}[bot]"
    if (
        _positive_integer(bot.get("id"), "approver bot user ID") != config.approver_bot_user_id
        or _required_string(bot.get("login"), "approver bot login").lower() != expected_bot_login
        or bot.get("type") != "Bot"
        or bot.get("site_admin") is not False
    ):
        raise PreflightError("approver bot user identity does not match the configured App")
    return {
        "account": owner,
        "organization_id": config.organization_id,
        "apps_are_distinct": True,
        "installations_are_distinct": True,
        "approver_bot": {
            "id": config.approver_bot_user_id,
            "login": expected_bot_login,
            "type": "Bot",
        },
        "checker": checker_evidence,
        "approver": approver_evidence,
    }


def _check_repositories(config: BetaConfig, github: GitHubProbe) -> Evidence:
    expected = (
        (
            config.target_repository,
            config.target_repository_id,
            config.target_default_branch,
            config.target_default_branch_sha,
        ),
        (
            config.organization_policy_repository,
            config.organization_policy_repository_id,
            config.organization_policy_default_branch,
            config.organization_policy_default_branch_sha,
        ),
    )
    repository_ids: dict[str, int] = {}
    branch_heads: dict[str, str] = {}
    expected_owner = config.target_repository.split("/", maxsplit=1)[0]
    for full_name, repository_id, branch, branch_sha in expected:
        repository = github.repository(full_name)
        observed_name = _required_string(
            repository.get("full_name"), "repository full_name"
        ).lower()
        owner = _object(repository.get("owner"), f"{full_name} owner")
        if (
            observed_name != full_name
            or _positive_integer(repository.get("id"), f"{full_name} repository ID")
            != repository_id
            or _positive_integer(owner.get("id"), f"{full_name} owner ID") != config.organization_id
            or _required_string(owner.get("login"), f"{full_name} owner login").lower()
            != expected_owner
            or owner.get("type") != "Organization"
        ):
            raise PreflightError(f"GitHub returned a different identity for {full_name}")
        if repository.get("private") is not False or repository.get("visibility") != "public":
            raise PreflightError(f"{full_name} is not public")
        if repository.get("archived") is not False or repository.get("disabled") is not False:
            raise PreflightError(
                f"{full_name} is archived, disabled, or omitted availability state"
            )
        if (
            _required_string(repository.get("default_branch"), "repository default branch")
            != branch
        ):
            raise PreflightError(f"{full_name} default branch does not match config")
        observed_head = github.branch_head(full_name, branch)
        if observed_head != branch_sha:
            raise PreflightError(f"{full_name} default branch SHA does not match config")
        repository_ids[full_name] = repository_id
        branch_heads[full_name] = observed_head
    return {
        "visibility": "public",
        "repositories": repository_ids,
        "default_branches": {full_name: branch for full_name, _, branch, _ in expected},
        "branch_heads": branch_heads,
    }


def _nonnegative_integer(value: object, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PreflightError(f"{description} is not a non-negative integer")
    return value


def _check_branch_rules(config: BetaConfig, github: GitHubProbe) -> Evidence:
    rules = github.branch_rules(config.target_repository, config.target_default_branch)
    classic = github.classic_branch_protection(
        config.target_repository,
        config.target_default_branch,
    )
    codeowner_sources: list[str] = []
    review_counts: list[int] = []
    check_sources: list[str] = []
    merge_queue = False
    rule_types: list[str] = []
    for rule in rules:
        rule_type = _required_string(rule.get("type"), "active branch rule type")
        rule_types.append(rule_type)
        parameters_value = rule.get("parameters")
        if rule_type == "pull_request":
            parameters = _object(parameters_value, "pull_request rule parameters")
            codeowner_value = parameters.get("require_code_owner_review")
            if not isinstance(codeowner_value, bool):
                raise PreflightError("pull_request rule omitted code-owner review state")
            if codeowner_value:
                codeowner_sources.append("ruleset")
            review_count = _nonnegative_integer(
                parameters.get("required_approving_review_count"),
                "pull_request required approving review count",
            )
            review_counts.append(review_count)
        elif rule_type == "required_status_checks":
            parameters = _object(parameters_value, "required_status_checks parameters")
            required = _objects(parameters.get("required_status_checks"), "required status checks")
            for entry in required:
                context = _required_string(entry.get("context"), "required check context")
                if context == config.check_name:
                    check_sources.append("ruleset")
        elif rule_type == "merge_queue":
            merge_queue = True

    if classic is not None:
        reviews_value = classic.get("required_pull_request_reviews")
        if reviews_value is not None:
            reviews = _object(reviews_value, "classic required pull-request reviews")
            codeowner_value = reviews.get("require_code_owner_reviews")
            if not isinstance(codeowner_value, bool):
                raise PreflightError("classic protection omitted code-owner review state")
            if codeowner_value:
                codeowner_sources.append("classic")
            review_counts.append(
                _nonnegative_integer(
                    reviews.get("required_approving_review_count"),
                    "classic required approving review count",
                )
            )
        status_value = classic.get("required_status_checks")
        if status_value is not None:
            status = _object(status_value, "classic required status checks")
            contexts = status.get("contexts")
            checks = status.get("checks")
            if (
                not isinstance(contexts, list)
                or any(not isinstance(context, str) for context in contexts)
                or not isinstance(checks, list)
                or any(not isinstance(check, dict) for check in checks)
            ):
                raise PreflightError("classic required status checks are malformed")
            classic_contexts = set(cast(list[str], contexts))
            for check in cast(list[JsonObject], checks):
                classic_contexts.add(
                    _required_string(check.get("context"), "classic required check context")
                )
            if config.check_name in classic_contexts:
                check_sources.append("classic")

    if not codeowner_sources:
        raise PreflightError("native code-owner review is not active on the target branch")
    if not any(count >= 1 for count in review_counts):
        raise PreflightError("at least one approving pull-request review is not required")
    if check_sources:
        raise PreflightError("Extra CODEOWNERS is already a required check")
    if merge_queue:
        raise PreflightError("the target branch has a merge queue")
    return {
        "native_codeowner_review_required": True,
        "minimum_approving_review_count": max(review_counts),
        "extra_codeowners_check_required": False,
        "merge_queue_enabled": False,
        "active_rule_types": sorted(rule_types),
        "codeowner_sources": sorted(set(codeowner_sources)),
        "protection_sources": [
            *(["rulesets"] if rules else []),
            *(["classic"] if classic is not None else []),
        ],
        "classic_admin_read_capability_proved": True,
    }


def _decode_utf8(content: bytes, description: str) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PreflightError(f"{description} is not UTF-8") from error


def _check_codeowners(config: BetaConfig, github: GitHubProbe) -> Evidence:
    errors = github.codeowners_errors(
        config.target_repository,
        config.target_default_branch_sha,
    )
    if errors:
        raise PreflightError(f"GitHub reports {len(errors)} CODEOWNERS syntax error(s)")
    content = github.repository_file(
        config.target_repository,
        CODEOWNERS_PATH,
        config.target_default_branch_sha,
    )
    try:
        document = parse_codeowners(_decode_utf8(content, "CODEOWNERS"))
    except ValueError as error:
        raise PreflightError("local CODEOWNERS parser rejected the target file") from error
    if not document.rules:
        raise PreflightError("CODEOWNERS contains no ownership rules")
    test_owners = document.owners_for(config.delegation_test_path)
    if not test_owners:
        raise PreflightError("delegation test path has no CODEOWNERS")
    return {
        "path": CODEOWNERS_PATH,
        "github_error_count": 0,
        "parsed_rule_count": len(document.rules),
        "delegation_test_path": config.delegation_test_path,
        "delegation_test_owners": list(test_owners),
    }


def _check_policy(config: BetaConfig, github: GitHubProbe) -> Evidence:
    repository_content = github.repository_file(
        config.target_repository,
        config.policy_path,
        config.target_default_branch_sha,
    )
    organization_content = github.repository_file(
        config.organization_policy_repository,
        config.policy_path,
        config.organization_policy_default_branch_sha,
    )
    codeowners_content = github.repository_file(
        config.target_repository,
        CODEOWNERS_PATH,
        config.target_default_branch_sha,
    )
    try:
        repository = RepositoryPolicy.from_toml(
            _decode_utf8(repository_content, "repository policy")
        )
        organization = OrganizationPolicy.from_toml(
            _decode_utf8(organization_content, "organization policy")
        )
        document = parse_codeowners(_decode_utf8(codeowners_content, "CODEOWNERS"))
        compiled = compile_policy(
            organization,
            repository,
            EvaluationOptions(
                repository_policy_path=config.policy_path,
                allow_insecure_changes=False,
            ),
        )
    except ValueError as error:
        raise PreflightError("organization and repository policy did not compile") from error
    if not repository.enabled:
        raise PreflightError("repository policy is not enabled")
    if len(organization.apps) != 1:
        raise PreflightError("organization policy must enroll exactly one App for the beta")
    if len(compiled.delegations) != 1:
        raise PreflightError("repository policy must contain exactly one delegation for the beta")
    approver_aliases = sorted(
        alias
        for alias, app in organization.apps.items()
        if (
            app.app_id == config.approver_app_id
            and app.slug == config.approver_app_slug
            and app.bot_user_id == config.approver_bot_user_id
        )
    )
    if len(approver_aliases) != 1:
        raise PreflightError("organization policy does not enroll the configured approver App")
    alias = approver_aliases[0]
    github.repository_file(
        config.target_repository,
        config.delegation_test_path,
        config.target_default_branch_sha,
    )
    labels: set[str] = set()
    for label in sorted(config.delegation_test_labels):
        response = github.repository_label(config.target_repository, label)
        observed = _required_string(response.get("name"), f"label {label} name").lower()
        if observed != label:
            raise PreflightError(f"GitHub returned a different label for {label}")
        labels.add(observed)
    owners = frozenset(document.owners_for(config.delegation_test_path))
    if not owners:
        raise PreflightError("delegation test path has no CODEOWNERS")
    if compiled.is_non_delegable(config.delegation_test_path):
        raise PreflightError("delegation test path is non-delegable")
    delegation = compiled.delegations[0].rule
    if (
        delegation.app != alias
        or delegation.paths != (config.delegation_test_path,)
        or frozenset(delegation.for_owners) != owners
        or "*" in delegation.for_owners
        or delegation.required_labels != frozenset(labels)
    ):
        raise PreflightError(
            "beta delegation must exactly match the configured App, test path, "
            "CODEOWNERS, and required labels"
        )

    def alias_is_eligible(selected_labels: frozenset[str]) -> bool:
        return any(
            decision.app_alias == alias and decision.eligible
            for decision in compiled.delegation_decisions(
                config.delegation_test_path,
                owners,
                selected_labels,
            )
        )

    selected_labels = frozenset(labels)
    if not alias_is_eligible(selected_labels):
        raise PreflightError(
            "repository policy does not make the approver eligible for the test path and labels"
        )
    if alias_is_eligible(frozenset()):
        raise PreflightError("approver remains eligible without the configured labels")
    for label in selected_labels:
        if alias_is_eligible(selected_labels - {label}):
            raise PreflightError(
                f"approver remains eligible when configured label {label} is absent"
            )
    return {
        "repository_policy_enabled": True,
        "organization_app_count": len(organization.apps),
        "delegation_count": len(compiled.delegations),
        "approver_alias": alias,
        "approver_bot_user_id": config.approver_bot_user_id,
        "delegation_test_path": config.delegation_test_path,
        "delegation_test_labels": sorted(selected_labels),
        "delegation_test_owners": sorted(owners),
        "configured_labels_affect_evaluator_eligibility": True,
        "labels_are_independent_approver_authority": False,
        "policy_scope_exact": True,
        "builtin_non_delegable_paths_enabled": True,
        "effective_non_delegable_pattern_count": len(compiled.non_delegable_patterns),
    }


def _check_final_refs(config: BetaConfig, github: GitHubProbe) -> Evidence:
    try:
        observed = _check_repositories(config, github)
    except PreflightError as error:
        raise PreflightError(
            "repository identity, visibility, default branch, or head changed during the preflight"
        ) from error
    return {
        "repository_identity_unchanged": True,
        "visibility_unchanged": True,
        "repositories": observed["repositories"],
        "default_branches": observed["default_branches"],
        "branch_heads_unchanged": True,
        "branch_heads": observed["branch_heads"],
    }


def _check_service(config: BetaConfig, service: ServiceProbe) -> Evidence:
    root = service.json("/")
    identity = service.json("/api/runtime-identity")
    live = service.json("/health/live")
    ready = service.json("/health/ready")
    if root.get("version") != config.extra_codeowners_version:
        raise PreflightError("deployed service version does not match the pinned beta config")
    expected_identity: JsonObject = {
        "schema_version": 1,
        "environment": "production",
        "github_api_url": f"{API_URL.rstrip('/')}/",
        "github_app_id": config.checker_app_id,
        "database_backend": "postgresql",
        "check_name": config.check_name,
        "policy_path": config.policy_path,
        "organization_policy_repository_name": (
            config.organization_policy_repository.rsplit("/", maxsplit=1)[1]
        ),
        "application_version": config.extra_codeowners_version,
        "build_revision": None,
    }
    if identity != expected_identity:
        raise PreflightError(
            "runtime identity self-report does not match the pinned checker deployment"
        )
    expected_live = {
        "status": "alive",
        "worker_enabled": True,
        "reconciler_enabled": True,
        "worker": True,
        "reconciler": True,
    }
    if any(live.get(name) != value for name, value in expected_live.items()):
        raise PreflightError("liveness does not prove enabled, healthy worker and reconciler tasks")
    expected_ready = {
        "status": "ready",
        "github_credentials": True,
        "database": True,
        "worker_enabled": True,
        "reconciler_enabled": True,
        "worker": True,
        "reconciler": True,
    }
    if any(ready.get(name) != value for name, value in expected_ready.items()):
        raise PreflightError("readiness does not prove GitHub, PostgreSQL, worker, and reconciler")
    return {
        "service_version": config.extra_codeowners_version,
        "liveness": "healthy",
        "readiness": "ready",
        "worker_enabled_and_healthy": True,
        "reconciler_enabled_and_healthy": True,
        "database_ready": True,
        "github_credentials_ready": True,
        "deployment_kind": "source",
        "self_reported_runtime_identity_consistent": True,
        "self_reported_build_revision": None,
    }


def _check_insecure_metric(service: ServiceProbe) -> Evidence:
    try:
        families = tuple(text_string_to_metric_families(service.metrics()))
    except ValueError as error:
        raise PreflightError("deployment metrics are malformed") from error
    samples = [
        sample for family in families for sample in family.samples if sample.name == METRIC_NAME
    ]
    if len(samples) != 1 or samples[0].labels or samples[0].value != 0:
        raise PreflightError(f"{METRIC_NAME} is absent, duplicated, labelled, or non-zero")
    return {
        "metric": METRIC_NAME,
        "value": 0,
        "insecure_changes_enabled": False,
    }


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One bounded prerequisite result."""

    check_id: str
    outcome: Literal["passed", "failed"]
    evidence: Evidence | None = None
    failure: str | None = None

    def as_json(self) -> JsonObject:
        value: JsonObject = {"id": self.check_id, "outcome": self.outcome}
        if self.evidence is not None:
            value["evidence"] = self.evidence
        if self.failure is not None:
            value["failure"] = self.failure
        return value


def _capture_check(check_id: str, operation: Callable[[], Evidence]) -> CheckResult:
    try:
        evidence = operation()
    except PreflightError as error:
        return CheckResult(check_id, "failed", failure=_safe_text(error))
    except Exception as error:
        return CheckResult(
            check_id,
            "failed",
            failure=f"unexpected {_safe_text(type(error).__name__)}",
        )
    return CheckResult(check_id, "passed", evidence=evidence)


def evaluate_preflight(
    config: BetaConfig,
    *,
    github: GitHubProbe | None = None,
    service: ServiceProbe | None = None,
    system: SystemProbe | None = None,
    identities: AppIdentities | None = None,
    run_nonce: str | None = None,
) -> JsonObject:
    """Evaluate every independent prerequisite and return a sanitized report."""

    active_identities = identities or AppIdentities.from_environment(config)
    owns_github = github is None
    owns_service = service is None
    active_github = github or GitHubRestProbe()
    active_service = service or DeploymentServiceProbe(config.service_url)
    active_system = system or LocalSystemProbe()
    try:
        checks = [
            _capture_check("source", lambda: active_system.source(config)),
            _capture_check("tool_versions", lambda: active_system.tools(config)),
            _capture_check(
                "app_installations",
                lambda: _check_installations(config, active_github, active_identities),
            ),
            _capture_check(
                "public_repositories",
                lambda: _check_repositories(config, active_github),
            ),
            _capture_check(
                "branch_safety",
                lambda: _check_branch_rules(config, active_github),
            ),
            _capture_check(
                "codeowners",
                lambda: _check_codeowners(config, active_github),
            ),
            _capture_check("policy", lambda: _check_policy(config, active_github)),
            _capture_check(
                "service_health",
                lambda: _check_service(config, active_service),
            ),
            _capture_check("postgresql", lambda: active_system.database(config)),
            _capture_check(
                "insecure_changes_metric",
                lambda: _check_insecure_metric(active_service),
            ),
            _capture_check(
                "final_branch_refs",
                lambda: _check_final_refs(config, active_github),
            ),
        ]
    finally:
        if owns_service:
            active_service.close()
        if owns_github:
            active_github.close()

    passed = all(check.outcome == "passed" for check in checks)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "kind": "extra-codeowners-disposable-evaluation-beta-preflight",
        "run_nonce": run_nonce or secrets.token_hex(16),
        "captured_at": datetime.now(UTC).isoformat(),
        "result": "passed" if passed else "failed",
        "preflight_passed": passed,
        "source_revision": config.source_revision,
        "scope": {
            "organization_id": config.organization_id,
            "target_repository": config.target_repository,
            "target_repository_id": config.target_repository_id,
            "target_default_branch_sha": config.target_default_branch_sha,
            "organization_policy_repository": config.organization_policy_repository,
            "organization_policy_repository_id": config.organization_policy_repository_id,
            "organization_policy_default_branch_sha": (
                config.organization_policy_default_branch_sha
            ),
            "checker_app_id": config.checker_app_id,
            "checker_app_slug": config.checker_app_slug,
            "checker_installation_id": config.checker_installation_id,
            "approver_app_id": config.approver_app_id,
            "approver_app_slug": config.approver_app_slug,
            "approver_installation_id": config.approver_installation_id,
            "approver_bot_user_id": config.approver_bot_user_id,
            "checker_webhook_url": config.checker_webhook_url,
            "check_name": config.check_name,
            "policy_path": config.policy_path,
            "delegation_test_path": config.delegation_test_path,
            "delegation_test_labels": sorted(config.delegation_test_labels),
            "deployment_kind": "source",
        },
        "checks": [check.as_json() for check in checks],
        "limitations": [
            "preflight evidence does not execute an approval or publish a Check Run",
            (
                "the source check establishes local checkout self-consistency; "
                "it is not independent source attestation"
            ),
            (
                "GitHub does not expose a token introspection API; successful "
                "repository-administration reads prove capability, not an exact "
                "fine-grained PAT scope or read-only setting"
            ),
            "GitHub does not expose whether the configured App webhook is currently active",
            (
                "preflight does not prove that the deployment and GitHub App use the "
                "same webhook secret or that a delivery reaches the service"
            ),
            (
                "required labels are evaluator inputs, not independent authority; an "
                "App with pull-request write access can change pull-request labels"
            ),
            (
                "runtime identity is an unauthenticated self-report; it does not prove "
                "that the running process loaded the reviewed source checkout"
            ),
            (
                "beta acceptance requires separate operator evidence which binds the "
                "running source deployment to the reviewed revision"
            ),
            (
                "GitHub REST proves one current installation and no pending installation "
                "requests, but it does not expose the App's only-this-account setting"
            ),
            (
                "GitHub state is read sequentially rather than from one atomic snapshot; "
                "rules, installations, labels, webhook configuration, and repository "
                "metadata can change after their individual checks"
            ),
            "passing preflight is not production-readiness or release evidence",
            "native code-owner enforcement must remain enabled throughout the beta",
        ],
    }


def _canonical_comparison_path(path: Path, description: str) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise PreflightError(f"{description} could not be resolved safely") from error


def validate_report_destination(
    path: Path,
    *,
    config_path: Path,
    key_paths: Sequence[Path] = (),
    source_checkout: Path | None = None,
) -> None:
    """Reject report locations which overlap any local preflight input."""

    report_path = _canonical_comparison_path(path, "report path")
    protected_paths = (
        _canonical_comparison_path(config_path, "configuration path"),
        *(_canonical_comparison_path(key_path, "private-key path") for key_path in key_paths),
    )
    if report_path in protected_paths:
        raise PreflightError("report path collides with a preflight input")
    if source_checkout is not None:
        checkout = _canonical_comparison_path(source_checkout, "source checkout")
        if report_path == checkout or report_path.is_relative_to(checkout):
            raise PreflightError(
                "report path must be outside the source checkout and its tracked files"
            )


def write_report_exclusive(path: Path, report: JsonObject) -> None:
    """Publish one bounded mode-0600 JSON report without replacing any path."""

    try:
        encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    except (TypeError, ValueError) as error:
        raise PreflightError("report contains non-JSON evidence") from error
    if len(encoded) > MAX_REPORT_BYTES:
        raise PreflightError("sanitized report exceeded its size limit")
    parent = path.parent
    name = path.name
    if name in {"", ".", ".."}:
        raise PreflightError("report path must name a file")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise PreflightError("report cannot be published safely on this platform")
    directory_descriptor = -1
    descriptor = -1
    temporary_name: str | None = None
    published_identity: tuple[int, int] | None = None
    publication_complete = False
    try:
        directory_descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow,
        )
        directory_before = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory_before.st_mode):
            raise PreflightError("report parent is not a directory")
        if (
            directory_before.st_uid != os.geteuid()
            or stat.S_IMODE(directory_before.st_mode) & 0o022
        ):
            raise PreflightError(
                "report parent must be current-user-owned and not group/world-writable"
            )
        try:
            os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PreflightError("report already exists; refusing to overwrite it")
        for _ in range(128):
            candidate = f".{name}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if descriptor < 0 or temporary_name is None:
            raise PreflightError("could not allocate an exclusive report temporary file")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_metadata = os.stat(
            temporary_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_uid != os.geteuid()
            or temporary_metadata.st_nlink != 1
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
            or temporary_metadata.st_size != len(encoded)
        ):
            raise PreflightError("exclusive report temporary file failed its identity checks")
        os.link(
            temporary_name,
            name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        published_identity = (temporary_metadata.st_dev, temporary_metadata.st_ino)
        published_metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            published_metadata.st_dev,
            published_metadata.st_ino,
        ) != published_identity:
            raise PreflightError("published report identity did not match its verified content")
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_name = None
        final_metadata = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            (final_metadata.st_dev, final_metadata.st_ino) != published_identity
            or not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_uid != os.geteuid()
            or final_metadata.st_nlink != 1
            or stat.S_IMODE(final_metadata.st_mode) != 0o600
            or final_metadata.st_size != len(encoded)
        ):
            raise PreflightError("published report failed its final identity checks")
        os.fsync(directory_descriptor)
        directory_after = os.fstat(directory_descriptor)
        if (
            directory_before.st_dev,
            directory_before.st_ino,
            stat.S_IFMT(directory_before.st_mode),
            directory_before.st_uid,
            stat.S_IMODE(directory_before.st_mode),
        ) != (
            directory_after.st_dev,
            directory_after.st_ino,
            stat.S_IFMT(directory_after.st_mode),
            directory_after.st_uid,
            stat.S_IMODE(directory_after.st_mode),
        ):
            raise PreflightError("report parent changed while the report was published")
        publication_complete = True
    except OSError as error:
        raise PreflightError(
            f"could not publish exclusive report: {type(error).__name__}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if (
            published_identity is not None
            and not publication_complete
            and directory_descriptor >= 0
        ):
            with suppress(FileNotFoundError, OSError):
                failed_metadata = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if (failed_metadata.st_dev, failed_metadata.st_ino) == published_identity:
                    os.unlink(name, dir_fd=directory_descriptor)
        if temporary_name is not None and directory_descriptor >= 0:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.evaluation_beta",
        description="Read-only safety tooling for the disposable evaluation beta.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser(
        "preflight",
        help="verify prerequisites and write a sanitized fail-closed report",
    )
    preflight.add_argument(
        "--config",
        type=Path,
        default=Path(
            os.getenv("EXTRA_CODEOWNERS_BETA_CONFIG_FILE", "evaluation-beta-preflight.toml")
        ),
        help="non-secret TOML configuration file",
    )
    preflight.add_argument(
        "--report",
        type=Path,
        default=Path(
            os.getenv(
                "EXTRA_CODEOWNERS_BETA_REPORT_FILE",
                "evaluation-beta-preflight-report.json",
            )
        ),
        help="sanitized JSON report path",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested evaluation-beta operation."""

    arguments = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    if arguments.command != "preflight":  # pragma: no cover - argparse owns this invariant.
        return 2
    run_nonce = secrets.token_hex(16)
    config_path = cast(Path, arguments.config)
    report_path = cast(Path, arguments.report)
    secret_path_variables = (
        "EXTRA_CODEOWNERS_BETA_CHECKER_PRIVATE_KEY_FILE",
        "EXTRA_CODEOWNERS_BETA_APPROVER_PRIVATE_KEY_FILE",
        "EXTRA_CODEOWNERS_BETA_OPERATOR_TOKEN_FILE",
    )
    key_paths = tuple(
        Path(value).absolute()
        for variable in secret_path_variables
        if (value := os.getenv(variable, "").strip())
    )
    try:
        validate_report_destination(
            report_path,
            config_path=config_path,
            key_paths=key_paths,
        )
        config = BetaConfig.from_file(config_path)
    except ConfigurationError as error:
        report = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "kind": "extra-codeowners-disposable-evaluation-beta-preflight",
            "run_nonce": run_nonce,
            "captured_at": datetime.now(UTC).isoformat(),
            "result": "configuration_error",
            "preflight_passed": False,
            "failure": _safe_text(error),
        }
        try:
            write_report_exclusive(report_path, report)
        except PreflightError as report_error:
            sys.stderr.write(f"configuration error; report failed: {_safe_text(report_error)}\n")
            return 2
        sys.stderr.write(f"configuration error: {_safe_text(error)}\n")
        sys.stdout.write(f"Wrote sanitized preflight report to {report_path}\n")
        return 2
    except PreflightError as error:
        sys.stderr.write(f"unsafe report destination: {_safe_text(error)}\n")
        return 2

    try:
        protected_input_paths = key_paths
        if config.source_ssh_allowed_signers_file is not None:
            protected_input_paths = (
                *protected_input_paths,
                config.source_ssh_allowed_signers_file,
            )
        validate_report_destination(
            report_path,
            config_path=config_path,
            key_paths=protected_input_paths,
            source_checkout=config.source_checkout,
        )
    except PreflightError as error:
        sys.stderr.write(f"unsafe report destination: {_safe_text(error)}\n")
        return 2

    try:
        identities = AppIdentities.from_environment(config)
        report = evaluate_preflight(
            config,
            identities=identities,
            run_nonce=run_nonce,
        )
    except Exception as error:
        report = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "kind": "extra-codeowners-disposable-evaluation-beta-preflight",
            "run_nonce": run_nonce,
            "captured_at": datetime.now(UTC).isoformat(),
            "result": "failed",
            "preflight_passed": False,
            "source_revision": config.source_revision,
            "failure": f"preflight setup failed with {_safe_text(type(error).__name__)}",
        }
    try:
        write_report_exclusive(report_path, report)
    except PreflightError as error:
        sys.stderr.write(f"preflight report failed: {_safe_text(error)}\n")
        return 1
    sys.stdout.write(f"Wrote sanitized preflight report to {report_path}\n")
    if report["preflight_passed"] is not True:
        sys.stderr.write("evaluation-beta preflight failed; inspect the sanitized report\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
