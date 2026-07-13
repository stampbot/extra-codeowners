from pathlib import Path

import pytest
from pydantic import ValidationError

from extra_codeowners.settings import Settings


def test_defaults_keep_insecure_escape_hatch_disabled() -> None:
    settings = Settings(_env_file=None)

    assert settings.allow_insecure_changes is False
    assert settings.github_ready is False
    assert settings.check_name == "Extra CODEOWNERS / approval"
    assert settings.worker_retry_max_seconds == 60
    assert settings.is_organization_config_repository("example/.github") is True
    assert settings.is_organization_config_repository("example/project") is False


def test_org_config_repository_is_normalized_case_insensitively() -> None:
    settings = Settings(_env_file=None, org_config_repository="Policies")

    assert settings.org_config_repository == "policies"
    assert settings.is_organization_config_repository("Example/POLICIES") is True


def test_secret_files_are_loaded_without_model_exposure(tmp_path: Path) -> None:
    key_path = tmp_path / "private-key.pem"
    secret_path = tmp_path / "webhook-secret"
    key_path.write_text("private-key-value\n", encoding="utf-8")
    secret_path.write_text("webhook-secret-value\n", encoding="utf-8")

    settings = Settings(
        _env_file=None,
        github_app_id=123,
        github_private_key_file=key_path,
        github_webhook_secret_file=secret_path,
    )

    assert settings.private_key_value == "private-key-value"
    assert settings.webhook_secret_value == "webhook-secret-value"
    assert settings.github_ready is True
    assert "private-key-value" not in str(settings)
    assert "webhook-secret-value" not in str(settings)


def test_ambiguous_secret_sources_are_rejected(tmp_path: Path) -> None:
    secret_path = tmp_path / "secret"
    secret_path.write_text("from-file", encoding="utf-8")

    with pytest.raises(ValidationError, match="set only one"):
        Settings(
            _env_file=None,
            github_private_key="inline",
            github_private_key_file=secret_path,
        )


def test_production_requires_github_credentials() -> None:
    settings = Settings(_env_file=None, environment="production")

    with pytest.raises(ValueError, match="production requires"):
        settings.validate_for_service()


def test_production_requires_postgresql() -> None:
    settings = Settings(
        _env_file=None,
        environment="production",
        github_app_id=123,
        github_private_key="key",
        github_webhook_secret="s" * 32,
    )

    with pytest.raises(ValueError, match="PostgreSQL"):
        settings.validate_for_service()


@pytest.mark.parametrize("ssl_mode", [None, "require", "verify-ca"])
def test_remote_production_postgresql_requires_hostname_verification(
    ssl_mode: str | None,
) -> None:
    suffix = "" if ssl_mode is None else f"?sslmode={ssl_mode}"
    settings = Settings(
        _env_file=None,
        environment="production",
        github_app_id=123,
        github_private_key="key",
        github_webhook_secret="s" * 32,
        database_url=f"postgresql+psycopg://user:password@db.example.test/database{suffix}",
    )

    with pytest.raises(ValueError, match="sslmode=verify-full"):
        settings.validate_for_service()


def test_production_postgresql_accepts_verified_remote_or_local_proxy() -> None:
    verified = Settings(
        _env_file=None,
        environment="production",
        github_app_id=123,
        github_private_key="key",
        github_webhook_secret="s" * 32,
        database_url=(
            "postgresql+psycopg://user:password@db.example.test/database?sslmode=verify-full"
        ),
    )
    local_proxy = Settings(
        _env_file=None,
        environment="production",
        github_app_id=123,
        github_private_key="key",
        github_webhook_secret="s" * 32,
        database_url="postgresql+psycopg://user:password@127.0.0.1/database",
    )
    local_socket = Settings(
        _env_file=None,
        environment="production",
        github_app_id=123,
        github_private_key="key",
        github_webhook_secret="s" * 32,
        database_url=(
            "postgresql+psycopg://user:password@/database?host=%2Fcloudsql%2Fexample-instance"
        ),
    )

    verified.validate_for_service()
    local_proxy.validate_for_service()
    local_socket.validate_for_service()


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://user:password@/database?host=db.example.test",
        ("postgresql+psycopg://user:password@127.0.0.1/database?host=db.example.test"),
        "postgresql+psycopg://user:password@/database?hostaddr=203.0.113.1",
        ("postgresql+psycopg://user:password@127.0.0.1/database?hostaddr=203.0.113.1"),
        "postgresql+psycopg://user:password@/database?service=remote-database",
        ("postgresql+psycopg://user:password@127.0.0.1/database?service=remote-database"),
    ],
)
def test_production_postgresql_does_not_misclassify_routed_remote_hosts(
    database_url: str,
) -> None:
    settings = Settings(
        _env_file=None,
        environment="production",
        github_app_id=123,
        github_private_key="key",
        github_webhook_secret="s" * 32,
        database_url=database_url,
    )

    with pytest.raises(ValueError, match="sslmode=verify-full"):
        settings.validate_for_service()


def test_setup_requires_state_secret() -> None:
    with pytest.raises(ValidationError, match="setup_state_secret"):
        Settings(_env_file=None, setup_enabled=True)


def test_setup_requires_long_state_secret_and_https_public_url() -> None:
    with pytest.raises(ValidationError, match="32 bytes"):
        Settings(
            _env_file=None,
            setup_enabled=True,
            setup_state_secret="short",
            public_url="https://example.com",
        )
    with pytest.raises(ValidationError, match="HTTPS"):
        Settings(
            _env_file=None,
            setup_enabled=True,
            setup_state_secret="x" * 32,
            public_url="http://example.com",
        )


def test_webhook_secret_preserves_literal_backslash_n_and_spaces(tmp_path: Path) -> None:
    secret_path = tmp_path / "webhook-secret"
    secret_path.write_text("literal\\n value \n", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        github_webhook_secret_file=secret_path,
        github_private_key="line-1\\nline-2",
    )

    assert settings.webhook_secret_value == "literal\\n value "
    assert settings.private_key_value == "line-1\nline-2"
