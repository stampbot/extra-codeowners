"""Process-level configuration loaded from environment variables."""

from __future__ import annotations

from functools import cached_property
from pathlib import Path
from typing import Literal, Self

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


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
            value = file_path.read_text(encoding="utf-8")
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
            try:
                database_url = make_url(self.database_url.get_secret_value())
            except ArgumentError as error:
                msg = "production requires a valid PostgreSQL database URL"
                raise ValueError(msg) from error
            if database_url.get_backend_name() != "postgresql":
                msg = "production requires a PostgreSQL database URL"
                raise ValueError(msg)
            ssl_mode = database_url.query.get("sslmode")
            query_host = database_url.query.get("host")
            effective_host = query_host if query_host is not None else database_url.host
            has_routing_override = (
                "hostaddr" in database_url.query or "service" in database_url.query
            )
            local_transport = not has_routing_override and (
                (
                    isinstance(effective_host, str)
                    and (
                        effective_host in {"localhost", "127.0.0.1", "::1"}
                        or effective_host.startswith("/")
                    )
                )
                or effective_host is None
            )
            if ssl_mode != "verify-full" and not local_transport:
                msg = (
                    "remote production PostgreSQL must use sslmode=verify-full; a local "
                    "socket/proxy transport may omit TLS"
                )
                raise ValueError(msg)

    def is_organization_config_repository(self, repository_full_name: str) -> bool:
        """Return whether a repository is this owner's shared policy source."""
        _, separator, repository_name = repository_full_name.partition("/")
        return bool(separator) and repository_name.lower() == self.org_config_repository.lower()


def get_settings() -> Settings:
    """Construct settings from the current process environment."""
    return Settings()
