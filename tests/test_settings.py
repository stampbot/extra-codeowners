import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from psycopg.pq import Conninfo
from pydantic import ValidationError

from extra_codeowners.settings import (
    MAX_SECRET_FILE_BYTES,
    MAX_SECRET_SYMLINKS,
    POSTGRESQL_CONNECTION_ENVIRONMENT,
    Settings,
    validate_production_database_transport,
)


def test_defaults_keep_insecure_escape_hatch_disabled() -> None:
    settings = Settings(_env_file=None)

    assert settings.allow_insecure_changes is False
    assert settings.github_ready is False
    assert settings.check_name == "Extra CODEOWNERS / approval"
    assert settings.worker_retry_max_seconds == 60
    assert settings.github_identity_probe_interval_seconds == 30
    assert settings.github_identity_freshness_seconds == 90
    assert settings.is_organization_config_repository("example/.github") is True
    assert settings.is_organization_config_repository("example/project") is False


def test_github_identity_freshness_covers_at_least_two_probe_intervals() -> None:
    with pytest.raises(ValidationError, match="at least twice"):
        Settings(
            _env_file=None,
            github_identity_probe_interval_seconds=60,
            github_identity_freshness_seconds=90,
        )


def test_validation_errors_never_echo_secret_input() -> None:
    sentinel = "DO-NOT-ECHO-THIS-SENTINEL"

    with pytest.raises(ValidationError) as captured:
        Settings(_env_file=None, policy_path=f"../{sentinel}")

    assert sentinel not in str(captured.value)
    assert sentinel not in repr(captured.value)


def test_org_config_repository_is_normalized_case_insensitively() -> None:
    settings = Settings(_env_file=None, org_config_repository="Policies")

    assert settings.org_config_repository == "policies"
    assert settings.is_organization_config_repository("Example/POLICIES") is True


@pytest.mark.parametrize(
    "github_api_url",
    [
        "https://user:password@api.github.com",
        "https://api.github.com?token=secret",
        "https://api.github.com#secret",
    ],
)
def test_github_api_url_rejects_secret_bearing_components(github_api_url: str) -> None:
    with pytest.raises(ValidationError, match="must not contain credentials"):
        Settings(_env_file=None, github_api_url=github_api_url)


def test_github_api_url_allows_a_github_enterprise_api_path() -> None:
    settings = Settings(
        _env_file=None,
        github_api_url="https://github.example.test/api/v3",
    )

    assert str(settings.github_api_url) == "https://github.example.test/api/v3"


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


def test_projected_kubernetes_secret_symlink_chain_is_supported(tmp_path: Path) -> None:
    version = tmp_path / "..2026_07_24"
    version.mkdir()
    (version / "private-key.pem").write_text("projected-private-key\n", encoding="utf-8")
    (tmp_path / "..data").symlink_to(version.name, target_is_directory=True)
    projected = tmp_path / "private-key.pem"
    projected.symlink_to("..data/private-key.pem")

    settings = Settings(_env_file=None, github_private_key_file=projected)

    assert settings.private_key_value == "projected-private-key"


def test_secret_file_reader_rejects_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "private-key.pem"
    os.mkfifo(fifo)
    settings = Settings(_env_file=None, github_private_key_file=fifo)

    with pytest.raises(ValueError, match="regular file"):
        _ = settings.private_key_value


def test_secret_file_reader_rejects_a_device() -> None:
    settings = Settings(_env_file=None, github_private_key_file=Path("/dev/null"))

    with pytest.raises(ValueError, match="regular file"):
        _ = settings.private_key_value


def test_secret_file_reader_rejects_oversized_content(tmp_path: Path) -> None:
    secret = tmp_path / "private-key.pem"
    secret.write_bytes(b"x" * (MAX_SECRET_FILE_BYTES + 1))
    settings = Settings(_env_file=None, github_private_key_file=secret)

    with pytest.raises(ValueError, match="size limit"):
        _ = settings.private_key_value


def test_secret_file_reader_rejects_an_unbounded_symlink_chain(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("secret", encoding="utf-8")
    for index in reversed(range(MAX_SECRET_SYMLINKS + 1)):
        destination = target.name if index == MAX_SECRET_SYMLINKS else f"link-{index + 1}"
        (tmp_path / f"link-{index}").symlink_to(destination)
    settings = Settings(_env_file=None, github_private_key_file=tmp_path / "link-0")

    with pytest.raises(ValueError, match="symlink limit"):
        _ = settings.private_key_value


def test_secret_file_reader_rejects_metadata_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = tmp_path / "private-key.pem"
    secret.write_text("secret", encoding="utf-8")
    settings = Settings(_env_file=None, github_private_key_file=secret)
    real_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = real_fstat(descriptor)
        if calls == 1:
            return metadata
        return SimpleNamespace(
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_mode=metadata.st_mode,
            st_nlink=metadata.st_nlink,
            st_uid=metadata.st_uid,
            st_gid=metadata.st_gid,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns + 1,
            st_ctime_ns=metadata.st_ctime_ns,
        )

    monkeypatch.setattr("extra_codeowners.settings.os.fstat", changing_fstat)

    with pytest.raises(ValueError, match="changed while it was read"):
        _ = settings.private_key_value


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


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://user:password@db.example.test/database?sslmode=verify-full",
        "postgresql+psycopg://user:password@localhost/database",
        "postgresql+psycopg://user:password@127.0.0.1/database",
        "postgresql+psycopg://user:password@[::1]/database",
        "postgresql+psycopg://user:password@/database?host=%2Frun%2Fpostgresql",
        (
            "postgresql+psycopg://user:password@db.example.test/database?"
            "hostaddr=203.0.113.1&sslmode=verify-full"
        ),
        (
            "postgresql+psycopg://user:password@db.example.test/database?"
            "sslmode=verify-full&sslrootcert=%2Frun%2Fsecrets%2Fdatabase-ca%2Froot.pem"
        ),
    ],
)
def test_production_database_transport_validator_accepts_safe_routes(
    database_url: str,
) -> None:
    validate_production_database_transport(database_url)


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite:///extra-codeowners.db",
        "postgresql://user:password@localhost/database",
        "postgresql+psycopg2://user:password@localhost/database",
        "postgresql+psycopg://user:password@db.example.test/database",
        "postgresql+psycopg://user:password@/database",
        "postgresql+psycopg://user:@localhost/database",
        "postgresql+psycopg://user:password@localhost/database?hostaddr=203.0.113.1",
        "postgresql+psycopg://user:password@/database?service=remote-database",
        (
            "postgresql+psycopg://user:password@db.example.test/database?"
            "sslmode=verify-full&options=-csearch_path%3Dunsafe"
        ),
        (
            "postgresql+psycopg://user:password@db.example.test/database?"
            "sslmode=verify-full&sslrootcert=relative.pem"
        ),
        (
            "postgresql+psycopg://user:password@db-1.example.test,"
            "db-2.example.test/database?sslmode=verify-full"
        ),
        (
            "postgresql+psycopg://user:password@/database?"
            "host=%2Frun%2Fpostgresql%2Cdb.example.test&sslmode=verify-full"
        ),
    ],
)
def test_production_database_transport_validator_rejects_unsafe_routes(
    database_url: str,
) -> None:
    with pytest.raises(ValueError, match=r"PostgreSQL|sslmode=verify-full"):
        validate_production_database_transport(database_url)


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

    with pytest.raises(
        ValueError,
        match=r"one explicit host|one unambiguous explicit route|sslmode=verify-full",
    ):
        settings.validate_for_service()


def test_production_postgresql_rejects_every_ambient_libpq_connection_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PGHOSTADDR", "203.0.113.1")

    with pytest.raises(ValueError, match=r"ambient libpq.*PGHOSTADDR"):
        validate_production_database_transport(
            "postgresql+psycopg://user:password@localhost/database"
        )


def test_ambient_libpq_denylist_covers_the_bundled_client() -> None:
    libpq_environment = {
        item.envvar.decode() for item in Conninfo.get_defaults() if item.envvar is not None
    }

    assert libpq_environment <= POSTGRESQL_CONNECTION_ENVIRONMENT


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
