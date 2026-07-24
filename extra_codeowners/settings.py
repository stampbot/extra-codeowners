"""Process-level configuration loaded from environment variables."""

from __future__ import annotations

import os
import stat
from functools import cached_property
from pathlib import Path
from typing import Literal, Self

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from extra_codeowners.database import isolated_postgresql_connect_args

MAX_SECRET_FILE_BYTES = 64 * 1024
MAX_SECRET_SYMLINKS = 16
MAX_SECRET_PATH_COMPONENTS = 256
POSTGRESQL_CONNECTION_ENVIRONMENT = frozenset(
    {
        "PGAPPNAME",
        "PGCHANNELBINDING",
        "PGCLIENTENCODING",
        "PGCONNECT_TIMEOUT",
        "PGDATABASE",
        "PGDATESTYLE",
        "PGGSSENCMODE",
        "PGGSSDELEGATION",
        "PGGSSLIB",
        "PGHOST",
        "PGHOSTADDR",
        "PGKRBSRVNAME",
        "PGLOADBALANCEHOSTS",
        "PGMAXPROTOCOLVERSION",
        "PGMINPROTOCOLVERSION",
        "PGOPTIONS",
        "PGPASSFILE",
        "PGPASSWORD",
        "PGPORT",
        "PGREQUIREPEER",
        "PGREQUIREAUTH",
        "PGREQUIRESSL",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGSSLCERT",
        "PGSSLCERTMODE",
        "PGSSLCOMPRESSION",
        "PGSSLCRL",
        "PGSSLCRLDIR",
        "PGSSLKEY",
        "PGSSLMAXPROTOCOLVERSION",
        "PGSSLMINPROTOCOLVERSION",
        "PGSSLMODE",
        "PGSSLNEGOTIATION",
        "PGSSLROOTCERT",
        "PGSSLSNI",
        "PGSYSCONFDIR",
        "PGTARGETSESSIONATTRS",
        "PGTZ",
        "PGUSER",
    }
)


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _resolved_secret_components(path: Path) -> tuple[str, ...]:
    """Resolve a bounded symlink chain without using the eventual data descriptor."""
    absolute = Path(os.path.abspath(path))
    pending = list(absolute.parts[1:])
    resolved: list[str] = []
    symlinks = 0
    operations = 0
    while pending:
        operations += 1
        if operations > MAX_SECRET_PATH_COMPONENTS:
            raise ValueError("secret file path exceeds its component limit")
        component = pending.pop(0)
        candidate = Path("/").joinpath(*resolved, component)
        try:
            metadata = os.lstat(candidate)
        except OSError as error:
            raise ValueError("secret file path could not be inspected safely") from error
        if stat.S_ISLNK(metadata.st_mode):
            symlinks += 1
            if symlinks > MAX_SECRET_SYMLINKS:
                raise ValueError("secret file path exceeds its symlink limit")
            try:
                target = Path(os.readlink(candidate))
            except OSError as error:
                raise ValueError("secret file symlink could not be read safely") from error
            if target.is_absolute():
                expanded = Path(os.path.abspath(target))
            else:
                expanded = Path(os.path.abspath(candidate.parent / target))
            pending = [*expanded.parts[1:], *pending]
            resolved.clear()
            continue
        if pending and not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("secret file path traverses a non-directory")
        resolved.append(component)
    if not resolved:
        raise ValueError("secret file path must name a file")
    return tuple(resolved)


def _open_resolved_secret(components: tuple[str, ...]) -> int:
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required_flags):
        raise ValueError("secret files require secure descriptor flags")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = -1
    try:
        descriptor = os.open("/", directory_flags)
        for component in components[:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        result = os.open(components[-1], file_flags, dir_fd=descriptor)
    except OSError as error:
        raise ValueError("secret file could not be opened safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return result


def _read_bounded_secret_file(path: Path) -> str:
    components = _resolved_secret_components(path)
    descriptor = _open_resolved_secret(components)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("secret file must resolve to a regular file")
        if not 0 <= before.st_size <= MAX_SECRET_FILE_BYTES:
            raise ValueError("secret file exceeds its size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            content = source.read(MAX_SECRET_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        if _stable_file_identity(before) != _stable_file_identity(after):
            raise ValueError("secret file changed while it was read")
        if len(content) != before.st_size:
            raise ValueError("secret file changed while it was read")
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("secret file is not UTF-8") from error
    except OSError as error:
        raise ValueError("secret file could not be read safely") from error
    finally:
        os.close(descriptor)


def validate_production_database_transport(database_url_value: str) -> None:
    """Reject a database URL whose transport is unsafe for production."""
    ambient = sorted(name for name in POSTGRESQL_CONNECTION_ENVIRONMENT if name in os.environ)
    if ambient:
        raise ValueError(
            "production PostgreSQL forbids ambient libpq connection settings; "
            f"unset {', '.join(ambient)} and put explicit values in the database URL"
        )
    try:
        database_url = make_url(database_url_value)
    except ArgumentError as error:
        msg = "production requires a valid PostgreSQL database URL"
        raise ValueError(msg) from error
    if database_url.drivername != "postgresql+psycopg":
        msg = "production requires PostgreSQL with the postgresql+psycopg driver"
        raise ValueError(msg)
    ssl_mode = database_url.query.get("sslmode")
    query_host = database_url.query.get("host")
    hostaddr = database_url.query.get("hostaddr")
    if (
        (query_host is not None and not isinstance(query_host, str))
        or (hostaddr is not None and not isinstance(hostaddr, str))
        or (ssl_mode is not None and not isinstance(ssl_mode, str))
        or (query_host is not None and database_url.host is not None)
        or "service" in database_url.query
    ):
        raise ValueError("production PostgreSQL requires one unambiguous explicit route")
    effective_host = query_host if query_host is not None else database_url.host
    if (
        not isinstance(effective_host, str)
        or not effective_host
        or "," in effective_host
        or (hostaddr is not None and (not hostaddr or "," in hostaddr))
    ):
        msg = "production PostgreSQL requires one explicit host or Unix-socket path"
        raise ValueError(msg)
    try:
        isolated_postgresql_connect_args(database_url_value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "production PostgreSQL requires an explicit database, username, and password"
        ) from error
    local_transport = hostaddr is None and (
        effective_host in {"localhost", "127.0.0.1", "::1"} or effective_host.startswith("/")
    )
    if ssl_mode != "verify-full" and not local_transport:
        msg = (
            "remote production PostgreSQL must use sslmode=verify-full; a local "
            "socket/proxy transport may omit TLS"
        )
        raise ValueError(msg)


class Settings(BaseSettings):
    """Runtime settings.

    Repository policy can narrow delegated authority but cannot alter these
    deployment-level trust settings.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="EXTRA_CODEOWNERS_",
        extra="forbid",
        hide_input_in_errors=True,
        validate_default=True,
    )

    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    github_app_id: int | None = Field(default=None, gt=0)
    github_private_key: SecretStr | None = None
    github_private_key_file: Path | None = None
    github_webhook_secret: SecretStr | None = None
    github_webhook_secret_file: Path | None = None
    github_api_url: AnyHttpUrl = AnyHttpUrl("https://api.github.com")
    github_api_version: str = "2026-03-10"
    github_identity_probe_interval_seconds: float = Field(default=30, ge=5, le=300)
    github_identity_freshness_seconds: float = Field(default=90, ge=10, le=900)
    public_url: AnyHttpUrl | None = None

    database_url: SecretStr = SecretStr("sqlite:///./extra-codeowners.db")
    worker_enabled: bool = True
    worker_poll_seconds: float = Field(default=0.5, ge=0.05, le=60)
    worker_lease_seconds: int = Field(default=120, ge=30, le=3600)
    worker_retry_max_seconds: int = Field(default=60, ge=5, le=3600)
    webhook_invalidation_timeout_seconds: float = Field(default=5.0, ge=0.1, le=8.0)
    reconcile_enabled: bool = True
    reconcile_interval_seconds: int = Field(default=300, ge=60, le=86400)
    webhook_delivery_retention_days: int = Field(default=30, ge=1, le=3650)

    org_config_repository: str = ".github"
    policy_path: str = ".github/extra-codeowners.toml"
    check_name: str = "Extra CODEOWNERS / approval"
    allow_insecure_changes: bool = False

    setup_enabled: bool = False
    setup_state_secret: SecretStr | None = None
    setup_state_ttl_seconds: int = Field(default=600, ge=60, le=3600)

    @field_validator("github_api_url")
    @classmethod
    def validate_github_api_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if (
            value.username is not None
            or value.password is not None
            or value.query is not None
            or value.fragment is not None
        ):
            raise ValueError("github_api_url must not contain credentials, a query, or a fragment")
        return value

    @field_validator("org_config_repository")
    @classmethod
    def validate_org_config_repository(cls, value: str) -> str:
        name = value.strip()
        if not name or len(name) > 100 or name in {".", ".."} or "/" in name or "\\" in name:
            raise ValueError("org_config_repository must be a literal repository name")
        return name.lower()

    @field_validator("policy_path")
    @classmethod
    def validate_policy_path(cls, value: str) -> str:
        path = value.strip()
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or any(character in path for character in "*?[]!")
        ):
            raise ValueError("policy_path must be a literal relative POSIX path")
        return path

    @field_validator("check_name")
    @classmethod
    def validate_check_name(cls, value: str) -> str:
        name = value.strip()
        if not name or len(name) > 255 or not name.isprintable():
            raise ValueError("check_name must be a printable value containing 1..255 characters")
        return name

    @model_validator(mode="after")
    def validate_secret_sources(self) -> Self:
        """Reject ambiguous secret sources and incomplete setup mode."""
        if self.github_identity_freshness_seconds < 2 * self.github_identity_probe_interval_seconds:
            raise ValueError(
                "github_identity_freshness_seconds must be at least twice "
                "github_identity_probe_interval_seconds"
            )
        pairs = (
            ("github_private_key", self.github_private_key, self.github_private_key_file),
            (
                "github_webhook_secret",
                self.github_webhook_secret,
                self.github_webhook_secret_file,
            ),
        )
        for name, inline, file_path in pairs:
            if inline is not None and file_path is not None:
                msg = f"set only one of {name} and {name}_file"
                raise ValueError(msg)
        if self.setup_enabled:
            if self.setup_state_secret is None:
                msg = "setup_state_secret is required when setup_enabled is true"
                raise ValueError(msg)
            if len(self.setup_state_secret.get_secret_value().encode()) < 32:
                msg = "setup_state_secret must contain at least 32 bytes"
                raise ValueError(msg)
            if self.public_url is None:
                msg = "public_url is required when setup_enabled is true"
                raise ValueError(msg)
            if self.public_url.scheme != "https":
                msg = "public_url must use HTTPS when setup_enabled is true"
                raise ValueError(msg)
            if (
                self.public_url.username is not None
                or self.public_url.password is not None
                or self.public_url.query is not None
                or self.public_url.fragment is not None
                or self.public_url.path not in {None, "", "/"}
            ):
                msg = "public_url must be an origin without credentials, path, query, or fragment"
                raise ValueError(msg)
        return self

    @staticmethod
    def _read_secret(
        inline: SecretStr | None,
        file_path: Path | None,
        *,
        expand_newlines: bool = False,
    ) -> str | None:
        if inline is not None:
            value = inline.get_secret_value()
        elif file_path is not None:
            value = _read_bounded_secret_file(file_path)
            # Kubernetes and Docker secret files conventionally contain one
            # terminal line ending. Preserve every other byte, including
            # intentional spaces in webhook secrets.
            if value.endswith("\r\n"):
                value = value[:-2]
            elif value.endswith("\n"):
                value = value[:-1]
        else:
            return None
        return value.replace("\\n", "\n") if expand_newlines else value

    @cached_property
    def private_key_value(self) -> str | None:
        """Return the App private key without exposing it in model output."""
        return self._read_secret(
            self.github_private_key,
            self.github_private_key_file,
            expand_newlines=True,
        )

    @cached_property
    def webhook_secret_value(self) -> str | None:
        """Return the webhook secret without exposing it in model output."""
        return self._read_secret(self.github_webhook_secret, self.github_webhook_secret_file)

    @property
    def github_ready(self) -> bool:
        """Whether required credentials for webhook processing are present."""
        return (
            self.github_app_id is not None
            and bool(self.private_key_value)
            and bool(self.webhook_secret_value)
        )

    def validate_for_service(self) -> None:
        """Fail startup when a production service lacks GitHub credentials."""
        if self.environment == "production" and not self.github_ready:
            msg = "production requires GitHub App ID, private key, and webhook secret"
            raise ValueError(msg)
        if self.environment == "production":
            assert self.webhook_secret_value is not None
            if len(self.webhook_secret_value.encode()) < 32:
                msg = "production requires a webhook secret containing at least 32 bytes"
                raise ValueError(msg)
            if self.github_api_url.scheme != "https":
                msg = "production requires an HTTPS GitHub API URL"
                raise ValueError(msg)
        self.validate_database()

    def validate_database(self) -> None:
        """Reject database transports that are unsafe for production commands."""
        if self.environment == "production":
            validate_production_database_transport(self.database_url.get_secret_value())

    def is_organization_config_repository(self, repository_full_name: str) -> bool:
        """Return whether a repository is this owner's shared policy source."""
        _, separator, repository_name = repository_full_name.partition("/")
        return bool(separator) and repository_name.lower() == self.org_config_repository.lower()


def get_settings() -> Settings:
    """Construct settings from the current process environment."""
    return Settings()
