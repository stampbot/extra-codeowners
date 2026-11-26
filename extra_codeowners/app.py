"""FastAPI application factory and lifecycle."""

from __future__ import annotations

import asyncio
import os
import socket
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Literal

import structlog
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, ConfigDict, Field

from extra_codeowners import __version__
from extra_codeowners.api_budget import RecoveryApiBudget
from extra_codeowners.build_identity import load_build_identity
from extra_codeowners.database import QueueStore
from extra_codeowners.github import GitHubClient, GitHubRateLimitError
from extra_codeowners.logging import configure_logging
from extra_codeowners.manifest import ManifestError, ManifestService
from extra_codeowners.metrics import INSECURE_MODE
from extra_codeowners.service import EvaluationService, Reconciler, Worker
from extra_codeowners.settings import Settings, get_settings
from extra_codeowners.tracing import Tracing
from extra_codeowners.webhook_ingress import WebhookDependencies, create_webhook_router

log = structlog.get_logger()
NO_STORE_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "form-action https://github.com; base-uri 'none'; frame-ancestors 'none'"
    ),
}


class LivenessResponse(BaseModel):
    """Process and local background-task liveness."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["alive", "not_alive"] = Field(
        description="Whether the process meets its liveness conditions."
    )
    worker_enabled: bool = Field(
        description="Whether the evaluation worker is enabled in this process's configuration."
    )
    reconciler_enabled: bool = Field(
        description="Whether the reconciler is enabled in this process's configuration."
    )
    worker: bool = Field(
        description=(
            "Whether the local worker meets its liveness condition. "
            "A disabled worker reports true. A worker without a GitHub client also reports true."
        )
    )
    reconciler: bool = Field(
        description=(
            "Whether the local reconciler meets its liveness condition. "
            "A disabled reconciler reports true. "
            "A reconciler without a GitHub client also reports true."
        )
    )


class ReadinessResponse(BaseModel):
    """Dependency and local background-task readiness."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ready", "not_ready"] = Field(
        description="Whether the process meets its readiness conditions."
    )
    github_credentials: bool = Field(
        title="GitHub credentials",
        description=(
            "Whether the credentials recently authenticated as the configured GitHub App ID."
        ),
    )
    setup_bootstrap: bool = Field(
        description=(
            "Whether the service is intentionally reachable only to complete built-in "
            "App setup before GitHub credentials are configured."
        )
    )
    database: bool = Field(description="Whether the service can query its database.")
    worker_enabled: bool = Field(
        description="Whether the evaluation worker is enabled in this process's configuration."
    )
    reconciler_enabled: bool = Field(
        description="Whether the reconciler is enabled in this process's configuration."
    )
    worker: bool = Field(
        description="Whether the local worker is ready. A disabled worker reports true."
    )
    reconciler: bool = Field(
        description="Whether the local reconciler is ready. A disabled reconciler reports true."
    )


class RuntimeIdentityResponse(BaseModel):
    """Non-secret identity of the effective running service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = Field(
        default=1,
        description="Schema version of this runtime identity contract.",
    )
    environment: Literal["development", "test", "production"] = Field(
        description="Effective service environment.",
    )
    github_api_url: str = Field(
        description="Effective GitHub API base URL used by the service.",
    )
    github_app_id: int | None = Field(
        description="Configured GitHub App ID, or null when the service is not configured.",
    )
    database_backend: Literal["postgresql", "sqlite"] = Field(
        description="SQLAlchemy dialect of the initialized queue store.",
    )
    check_name: str = Field(
        description="Effective name used when the service publishes a Check Run.",
    )
    policy_path: str = Field(
        description="Effective repository-relative path used for both policy files.",
    )
    organization_policy_repository_name: str = Field(
        description=(
            "Configured organization-policy repository name. Its owner is derived "
            "from each target repository."
        ),
    )
    application_version: str = Field(
        description="Version of the installed Extra CODEOWNERS distribution.",
    )
    build_revision: str | None = Field(
        description=(
            "Verified Git source revision baked into the official image, "
            "or null for a source installation."
        ),
    )


class GitHubIdentityProbe:
    """Track a bounded, renewable proof of the authenticated GitHub App ID."""

    def __init__(
        self,
        github: GitHubClient,
        store: QueueStore,
        *,
        interval_seconds: float,
        freshness_seconds: float,
    ) -> None:
        self._github = github
        self._store = store
        self._interval_seconds = interval_seconds
        self._freshness_seconds = freshness_seconds
        self._last_success_monotonic: float | None = None

    @property
    def fresh(self) -> bool:
        """Whether a successful identity proof remains inside its freshness window."""
        last_success = self._last_success_monotonic
        return last_success is not None and (
            time.monotonic() - last_success <= self._freshness_seconds
        )

    async def refresh(self, *, stop: asyncio.Event) -> bool:
        """Attempt one identity proof without discarding a still-fresh prior proof."""
        try:
            if await asyncio.to_thread(self._store.provider_is_backpressured, None):
                log.info("github_app_identity_probe_deferred", scope="global")
                return False
            await self._github.verify_app_identity(stop=stop)
        except GitHubRateLimitError as error:
            try:
                await asyncio.to_thread(
                    self._store.record_provider_backpressure,
                    None,
                    str(error),
                    error.retry_after_seconds,
                )
            except Exception as record_error:
                log.warning(
                    "github_app_identity_probe_backpressure_record_failed",
                    error_type=type(record_error).__name__,
                )
            log.warning(
                "github_app_identity_probe_rate_limited",
                scope="global",
                retry_after_seconds=error.retry_after_seconds,
            )
            return False
        except Exception as error:
            log.warning(
                "github_app_identity_probe_failed",
                error_type=type(error).__name__,
            )
            return False
        self._last_success_monotonic = time.monotonic()
        return True

    async def run(self, stop: asyncio.Event) -> None:
        """Refresh the proof periodically until service shutdown."""
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
            except TimeoutError:
                await self.refresh(stop=stop)


def create_app(
    settings: Settings | None = None,
    *,
    github: GitHubClient | None = None,
    store: QueueStore | None = None,
) -> FastAPI:
    """Build an independently testable service instance."""
    runtime = settings or get_settings()
    build_identity = load_build_identity()
    configure_logging(runtime.log_level, json_logs=runtime.environment == "production")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        runtime.validate_for_service()
        owned_store = store is None
        github_client = github
        queue_store: QueueStore | None = None
        manifest_service: ManifestService | None = None
        stop = asyncio.Event()
        tasks: list[asyncio.Task[None]] = []
        tracing = Tracing.from_settings(runtime)

        app.state.github = github_client
        app.state.stop = stop
        app.state.tasks = tasks
        app.state.worker_task = None
        app.state.reconciler_task = None
        app.state.github_identity_task = None
        app.state.github_identity_probe = None
        app.state.evaluator = None
        app.state.manifest = manifest_service
        app.state.tracing = tracing

        async def stop_background_tasks() -> None:
            stop.set()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        async with AsyncExitStack() as resources:
            resources.callback(tracing.shutdown)
            queue_store = store or QueueStore(runtime.database_url.get_secret_value())
            if owned_store:
                resources.push_async_callback(asyncio.to_thread, queue_store.close)
            await asyncio.to_thread(queue_store.initialize)
            app.state.store = queue_store
            database_backend = queue_store.engine.dialect.name
            if database_backend not in {"postgresql", "sqlite"}:
                raise RuntimeError(f"unsupported initialized database backend {database_backend!r}")
            if runtime.require_postgresql and database_backend != "postgresql":
                raise RuntimeError(
                    "require_postgresql is enabled, but the configured database is not PostgreSQL"
                )
            app.state.runtime_identity = RuntimeIdentityResponse(
                environment=runtime.environment,
                github_api_url=str(runtime.github_api_url),
                github_app_id=runtime.github_app_id,
                database_backend=database_backend,
                check_name=runtime.check_name,
                policy_path=runtime.policy_path,
                organization_policy_repository_name=runtime.org_config_repository,
                application_version=__version__,
                build_revision=(
                    build_identity.source_revision if build_identity is not None else None
                ),
            )

            if github_client is None and runtime.github_ready:
                assert runtime.github_app_id is not None
                assert runtime.private_key_value is not None
                github_client = GitHubClient(
                    runtime.github_app_id,
                    runtime.private_key_value,
                    api_url=str(runtime.github_api_url),
                    api_version=runtime.github_api_version,
                    max_in_flight_requests=runtime.github_max_in_flight_requests,
                    recovery_budget=RecoveryApiBudget(
                        queue_store, runtime.github_recovery_reserve_percent
                    ),
                    tracing=tracing,
                )
                resources.push_async_callback(github_client.close)
            app.state.github = github_client

            INSECURE_MODE.set(int(runtime.allow_insecure_changes))
            if runtime.allow_insecure_changes:
                log.warning(
                    "insecure_changes_enabled",
                    warning=(
                        "built-in non-delegable paths are disabled; organization guardrails remain"
                    ),
                )

            if runtime.setup_enabled:
                manifest_service = ManifestService(runtime)
                resources.push_async_callback(manifest_service.close)
            app.state.manifest = manifest_service

            # Register task cleanup after dependency cleanup so LIFO shutdown
            # always stops background work before closing its clients or store.
            resources.push_async_callback(stop_background_tasks)

            if github_client is not None:
                identity_probe = GitHubIdentityProbe(
                    github_client,
                    queue_store,
                    interval_seconds=runtime.github_identity_probe_interval_seconds,
                    freshness_seconds=runtime.github_identity_freshness_seconds,
                )
                app.state.github_identity_probe = identity_probe
                await identity_probe.refresh(stop=stop)
                identity_task = asyncio.create_task(
                    identity_probe.run(stop),
                    name="github-app-identity-probe",
                )
                app.state.github_identity_task = identity_task
                tasks.append(identity_task)

                owner = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:12]}"
                evaluator = EvaluationService(runtime, github_client, queue_store)
                app.state.evaluator = evaluator
                if runtime.worker_enabled:
                    worker = Worker(runtime, queue_store, evaluator, owner, tracing=tracing)
                    worker_task = asyncio.create_task(worker.run(stop), name="evaluation-worker")
                    app.state.worker_task = worker_task
                    tasks.append(worker_task)
                if runtime.reconcile_enabled:
                    reconciler = Reconciler(
                        runtime,
                        github_client,
                        queue_store,
                        owner,
                        tracing=tracing,
                    )
                    reconciler_task = asyncio.create_task(
                        reconciler.run(stop), name="open-pr-reconciler"
                    )
                    app.state.reconciler_task = reconciler_task
                    tasks.append(reconciler_task)

            yield

    app = FastAPI(
        title="Extra CODEOWNERS",
        summary="Human or delegated-application CODEOWNER approval checks",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = runtime
    app.state.tracing = Tracing(enabled=False)

    @app.get("/", include_in_schema=False)
    async def index() -> JSONResponse:
        return JSONResponse(
            {
                "name": "Extra CODEOWNERS",
                "version": __version__,
                "documentation": "https://extra-codeowners.readthedocs.io/",
            },
            headers=NO_STORE_HEADERS,
        )

    @app.get(
        "/api/runtime-identity",
        tags=["operations"],
        response_model=RuntimeIdentityResponse,
    )
    async def runtime_identity(request: Request) -> JSONResponse:
        """Return non-secret effective configuration and immutable build identity."""
        identity: RuntimeIdentityResponse = request.app.state.runtime_identity
        return JSONResponse(
            identity.model_dump(mode="json"),
            headers=NO_STORE_HEADERS,
        )

    @app.get(
        "/health/live",
        tags=["operations"],
        response_model=LivenessResponse,
        responses={
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": LivenessResponse,
                "description": "An enabled local background task has stopped",
            }
        },
    )
    async def live(request: Request) -> JSONResponse:
        """Return liveness, including critical in-process background tasks."""
        worker_task: asyncio.Task[None] | None = request.app.state.worker_task
        worker_expected = runtime.worker_enabled and request.app.state.github is not None
        worker_alive = not worker_expected or (worker_task is not None and not worker_task.done())
        reconciler_task: asyncio.Task[None] | None = request.app.state.reconciler_task
        reconciler_expected = runtime.reconcile_enabled and request.app.state.github is not None
        reconciler_alive = not reconciler_expected or (
            reconciler_task is not None and not reconciler_task.done()
        )
        alive = worker_alive and reconciler_alive
        payload = LivenessResponse(
            status="alive" if alive else "not_alive",
            worker_enabled=runtime.worker_enabled,
            reconciler_enabled=runtime.reconcile_enabled,
            worker=worker_alive,
            reconciler=reconciler_alive,
        )
        return JSONResponse(
            payload.model_dump(mode="json"),
            status_code=status.HTTP_200_OK if alive else status.HTTP_503_SERVICE_UNAVAILABLE,
            headers=NO_STORE_HEADERS,
        )

    @app.get(
        "/health/ready",
        tags=["operations"],
        response_model=ReadinessResponse,
        responses={
            status.HTTP_503_SERVICE_UNAVAILABLE: {
                "model": ReadinessResponse,
                "description": (
                    "GitHub credentials, the database, or an enabled local task is unavailable"
                ),
            }
        },
    )
    async def ready(request: Request) -> JSONResponse:
        """Return readiness when normal dependencies or setup bootstrap are usable."""
        queue_store: QueueStore = request.app.state.store
        database_ready = await asyncio.to_thread(queue_store.database_available)
        identity_probe: GitHubIdentityProbe | None = request.app.state.github_identity_probe
        github_ready = runtime.github_ready and identity_probe is not None and identity_probe.fresh
        setup_bootstrap = runtime.setup_bootstrap_mode
        worker_task: asyncio.Task[None] | None = request.app.state.worker_task
        worker_ready = (
            setup_bootstrap
            or not runtime.worker_enabled
            or (worker_task is not None and not worker_task.done())
        )
        reconciler_task: asyncio.Task[None] | None = request.app.state.reconciler_task
        reconciler_ready = (
            setup_bootstrap
            or not runtime.reconcile_enabled
            or (reconciler_task is not None and not reconciler_task.done())
        )
        ready_state = bool(
            (github_ready or setup_bootstrap)
            and database_ready
            and worker_ready
            and reconciler_ready
        )
        payload = ReadinessResponse(
            status="ready" if ready_state else "not_ready",
            github_credentials=github_ready,
            setup_bootstrap=setup_bootstrap,
            database=database_ready,
            worker_enabled=runtime.worker_enabled,
            reconciler_enabled=runtime.reconcile_enabled,
            worker=worker_ready,
            reconciler=reconciler_ready,
        )
        return JSONResponse(
            payload.model_dump(mode="json"),
            status_code=status.HTTP_200_OK if ready_state else status.HTTP_503_SERVICE_UNAVAILABLE,
            headers=NO_STORE_HEADERS,
        )

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        """Expose Prometheus metrics without repository or secret labels."""
        return Response(
            generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
            headers=NO_STORE_HEADERS,
        )

    def resolve_webhook(request: Request) -> WebhookDependencies:
        state = request.app.state
        return WebhookDependencies(
            runtime, state.store, state.evaluator, state.worker_task, state.tracing
        )

    app.include_router(create_webhook_router(resolve_webhook))

    @app.get("/setup", response_class=HTMLResponse, include_in_schema=False)
    async def setup(
        request: Request, organization: str | None = Query(default=None)
    ) -> HTMLResponse:
        """Start the operator-controlled GitHub App Manifest flow."""
        service: ManifestService | None = request.app.state.manifest
        if service is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return HTMLResponse(service.registration_page(organization), headers=NO_STORE_HEADERS)

    @app.get("/setup/callback", response_class=HTMLResponse, include_in_schema=False)
    async def setup_callback(request: Request, code: str, state: str) -> HTMLResponse:
        """Exchange a one-use manifest code and display credentials exactly once."""
        service: ManifestService | None = request.app.state.manifest
        if service is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        try:
            credentials = await service.exchange(code, state)
        except ManifestError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        return HTMLResponse(service.credentials_page(credentials), headers=NO_STORE_HEADERS)

    return app


app = create_app()
