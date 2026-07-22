import subprocess
import sys
from pathlib import Path
from typing import Any

import uvicorn
from typer.testing import CliRunner

from extra_codeowners import cli as cli_module
from extra_codeowners.database import (
    DATABASE_MIGRATION_HEAD,
    EvaluationJob,
    JobRequest,
    QueueStore,
)
from extra_codeowners.migrations import upgrade_database


def test_module_help_has_no_startup_log_noise() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "extra_codeowners", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Usage:" in result.stdout
    assert "setup plugin alembic." not in result.stdout


def test_validate_policy_command(tmp_path: Path) -> None:
    repository = tmp_path / "repository.toml"
    organization = tmp_path / "organization.toml"
    repository.write_text("schema_version = 1\nenabled = false\n", encoding="utf-8")
    organization.write_text("schema_version = 1\n", encoding="utf-8")

    result = CliRunner().invoke(
        cli_module.cli,
        [
            "validate-policy",
            "--repository",
            str(repository),
            "--organization",
            str(organization),
        ],
    )

    assert result.exit_code == 0
    assert result.stdout == "Policy files are valid.\n"


def test_validate_policy_rejects_invalid_pattern_without_org(tmp_path: Path) -> None:
    repository = tmp_path / "repository.toml"
    repository.write_text(
        """schema_version = 1
enabled = true
[[delegations]]
app = "stampbot"
paths = ["!unsafe"]
for_owners = ["*"]
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli_module.cli,
        ["validate-policy", "--repository", str(repository)],
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, ValueError)


def test_validate_policy_rejects_unenrolled_app_with_org(tmp_path: Path) -> None:
    repository = tmp_path / "repository.toml"
    organization = tmp_path / "organization.toml"
    repository.write_text(
        """schema_version = 1
enabled = true
[[delegations]]
app = "missing"
paths = ["**"]
for_owners = ["*"]
""",
        encoding="utf-8",
    )
    organization.write_text("schema_version = 1\n", encoding="utf-8")

    result = CliRunner().invoke(
        cli_module.cli,
        [
            "validate-policy",
            "--repository",
            str(repository),
            "--organization",
            str(organization),
        ],
    )

    assert result.exit_code != 0
    assert "not enrolled" in str(result.exception)


def test_serve_passes_safe_defaults_to_uvicorn(monkeypatch: Any) -> None:
    calls: list[dict[str, Any]] = []
    sentinel = object()
    monkeypatch.setattr(cli_module, "_create_service_app", lambda settings: sentinel)
    monkeypatch.setattr(
        uvicorn,
        "run",
        lambda app, **kwargs: calls.append({"app": app, **kwargs}),
    )

    result = CliRunner().invoke(
        cli_module.cli,
        ["serve", "--host", "127.0.0.1", "--port", "9000"],
    )

    assert result.exit_code == 0
    assert calls == [
        {
            "app": sentinel,
            "host": "127.0.0.1",
            "port": 9000,
            "access_log": False,
            "proxy_headers": True,
        }
    ]


def test_database_migrate_and_check_commands(tmp_path: Path, monkeypatch: Any) -> None:
    database_url = f"sqlite:///{tmp_path / 'commands.db'}"
    monkeypatch.setenv("EXTRA_CODEOWNERS_DATABASE_URL", database_url)

    migrate = CliRunner().invoke(cli_module.cli, ["database", "migrate"])
    check = CliRunner().invoke(cli_module.cli, ["database", "check"])

    assert migrate.exit_code == 0
    assert f"Database is at migration {DATABASE_MIGRATION_HEAD}." in migrate.stdout
    assert check.exit_code == 0
    assert f"Database migration {DATABASE_MIGRATION_HEAD} is compatible." in check.stdout


def test_queue_status_is_read_only_and_manual_requeue_recovers_dead_rows(
    tmp_path: Path, monkeypatch: Any
) -> None:
    database_url = f"sqlite:///{tmp_path / 'queue.db'}"
    monkeypatch.setenv("EXTRA_CODEOWNERS_DATABASE_URL", database_url)
    upgrade_database(database_url)
    store = QueueStore(database_url)
    store.initialize()
    store.enqueue(
        JobRequest(
            installation_id=1,
            repository_full_name="example/project",
            pull_number=2,
            reason="test",
        )
    )
    claimed = store.claim("worker", 60)
    assert claimed is not None
    with store.session() as session:
        row = session.get(EvaluationJob, claimed.id)
        assert row is not None
        row.state = "dead"
        row.lease_owner = None
        row.lease_until = None
    store.close()

    before = CliRunner().invoke(cli_module.cli, ["queue-status"])
    requeue = CliRunner().invoke(cli_module.cli, ["requeue-dead", "--limit", "1"])
    after = CliRunner().invoke(cli_module.cli, ["queue-status"])

    assert before.stdout == "pending=0 dead=1\n"
    assert requeue.stdout == "requeued=1\n"
    assert after.stdout == "pending=1 dead=0\n"
