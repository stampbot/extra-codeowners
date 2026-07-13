"""Extra CODEOWNERS command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
import uvicorn

from extra_codeowners.app import create_app
from extra_codeowners.codeowners import validate_pattern
from extra_codeowners.database import QueueStore
from extra_codeowners.models import OrganizationPolicy, RepositoryPolicy
from extra_codeowners.policy import compile_policy
from extra_codeowners.settings import Settings

cli = typer.Typer(
    name="extra-codeowners",
    help="Run and validate the Extra CODEOWNERS GitHub App.",
    no_args_is_help=True,
)


@cli.command()
def serve(
    host: str | None = typer.Option(None, help="Bind address; overrides the environment."),
    port: int | None = typer.Option(
        None, min=1, max=65535, help="Port; overrides the environment."
    ),
) -> None:
    """Run the webhook API, durable worker, and reconciler."""
    settings = Settings()
    updates: dict[str, object] = {}
    if host is not None:
        updates["host"] = host
    if port is not None:
        updates["port"] = port
    if updates:
        settings = settings.model_copy(update=updates)
    # Access logs are disabled because GitHub's one-use manifest conversion
    # code arrives in a callback query string. Structured application logs do
    # not record request URLs or secret values.
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        access_log=False,
        proxy_headers=True,
    )


@cli.command("validate-policy")
def validate_policy(
    repository: Annotated[Path, typer.Option(exists=True, dir_okay=False, readable=True)],
    organization: Annotated[
        Path | None, typer.Option(exists=True, dir_okay=False, readable=True)
    ] = None,
) -> None:
    """Compile repository and optional organization TOML policy files."""
    repository_policy = RepositoryPolicy.from_toml(repository.read_text(encoding="utf-8"))
    if organization is not None:
        organization_policy = OrganizationPolicy.from_toml(organization.read_text(encoding="utf-8"))
        compile_policy(organization_policy, repository_policy)
    else:
        # Cross-file App enrollment requires --organization, but standalone
        # validation must still reject path syntax the runtime cannot compile.
        for delegation in repository_policy.delegations:
            for pattern in delegation.paths:
                validate_pattern(pattern)
    typer.echo("Policy files are valid.")


@cli.command("queue-status")
def queue_status() -> None:
    """Report pending jobs and any legacy terminal rows."""
    settings = Settings()
    store = QueueStore(settings.database_url.get_secret_value())
    try:
        store.initialize()
        typer.echo(f"pending={store.pending_count()} dead={store.dead_count()}")
    finally:
        store.close()


@cli.command("requeue-dead")
def requeue_dead(
    limit: Annotated[int, typer.Option(min=1, max=10_000)] = 100,
) -> None:
    """Recover a bounded batch of legacy/manual terminal rows."""
    settings = Settings()
    store = QueueStore(settings.database_url.get_secret_value())
    try:
        store.initialize()
        count = store.requeue_dead(limit)
        typer.echo(f"requeued={count}")
    finally:
        store.close()


def main() -> None:
    """Invoke the Typer command group."""
    cli()
