"""FastAPI application factory and lifecycle."""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from extra_codeowners import __version__
from extra_codeowners.database import JobRequest, QueueStore
from extra_codeowners.github import GitHubClient
from extra_codeowners.logging import configure_logging
from extra_codeowners.manifest import ManifestError, ManifestService
from extra_codeowners.metrics import INSECURE_MODE, WEBHOOK_FAILURES, WEBHOOKS
from extra_codeowners.service import EvaluationService, Reconciler, Worker
from extra_codeowners.settings import Settings, get_settings
from extra_codeowners.webhooks import (
    MAX_WEBHOOK_BYTES,
    WebhookError,
    evaluation_job,
    verify_webhook,
)

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


def create_app(
    settings: Settings | None = None,
    *,
    github: GitHubClient | None = None,
    store: QueueStore | None = None,
) -> FastAPI:
    """Build an independently testable service instance."""
    runtime = settings or get_settings()
    configure_logging(runtime.log_level, json_logs=runtime.environment == "production")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        runtime.validate_for_service()
        owned_store = store is None
        queue_store = store or QueueStore(runtime.database_url.get_secret_value())
        await asyncio.to_thread(queue_store.initialize)
        app.state.store = queue_store

        owned_github = github is None
        github_client = github
        if github_client is None and runtime.github_ready:
            assert runtime.github_app_id is not None
            assert runtime.private_key_value is not None
            github_client = GitHubClient(
                runtime.github_app_id,
                runtime.private_key_value,
                api_url=str(runtime.github_api_url),
                api_version=runtime.github_api_version,
            )
        app.state.github = github_client
        app.state.stop = asyncio.Event()
        app.state.tasks = []
        app.state.worker_task = None
        app.state.reconciler_task = None
        app.state.evaluator = None
        INSECURE_MODE.set(int(runtime.allow_insecure_changes))
        if runtime.allow_insecure_changes:
            log.warning(
                "insecure_changes_enabled",
                warning=(
                    "built-in non-delegable paths are disabled; organization guardrails remain"
                ),
            )

        manifest_service: ManifestService | None = None
        if runtime.setup_enabled:
            manifest_service = ManifestService(runtime)
        app.state.manifest = manifest_service

        if github_client is not None:
            owner = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:12]}"
            evaluator = EvaluationService(runtime, github_client, queue_store)
            app.state.evaluator = evaluator
            if runtime.worker_enabled:
                worker = Worker(runtime, queue_store, evaluator, owner)
                worker_task = asyncio.create_task(
                    worker.run(app.state.stop), name="evaluation-worker"
                )
                app.state.worker_task = worker_task
                app.state.tasks.append(worker_task)
            if runtime.reconcile_enabled:
                reconciler = Reconciler(runtime, github_client, queue_store, owner)
                reconciler_task = asyncio.create_task(
                    reconciler.run(app.state.stop), name="open-pr-reconciler"
                )
                app.state.reconciler_task = reconciler_task
                app.state.tasks.append(reconciler_task)

        try:
            yield
        finally:
            app.state.stop.set()
            if app.state.tasks:
                await asyncio.gather(*app.state.tasks, return_exceptions=True)
            if manifest_service is not None:
                await manifest_service.close()
            if owned_github and github_client is not None:
                await github_client.close()
            if owned_store:
                await asyncio.to_thread(queue_store.close)

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

    @app.get("/", include_in_schema=False)
    async def index() -> dict[str, str]:
        return {
            "name": "Extra CODEOWNERS",
            "version": __version__,
            "documentation": "https://extra-codeowners.readthedocs.io/",
        }

    @app.get("/health/live", tags=["operations"])
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
        return JSONResponse(
            {
                "status": "alive" if alive else "not_alive",
                "worker": worker_alive,
                "reconciler": reconciler_alive,
            },
            status_code=status.HTTP_200_OK if alive else status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.get("/health/ready", tags=["operations"])
    async def ready(request: Request) -> JSONResponse:
        """Return readiness only when credentials, database, and worker are usable."""
        queue_store: QueueStore = request.app.state.store
        database_ready = await asyncio.to_thread(queue_store.database_available)
        worker_task: asyncio.Task[None] | None = request.app.state.worker_task
        worker_ready = not runtime.worker_enabled or (
            worker_task is not None and not worker_task.done()
        )
        reconciler_task: asyncio.Task[None] | None = request.app.state.reconciler_task
        reconciler_ready = not runtime.reconcile_enabled or (
            reconciler_task is not None and not reconciler_task.done()
        )
        ready_state = bool(
            runtime.github_ready and database_ready and worker_ready and reconciler_ready
        )
        payload = {
            "status": "ready" if ready_state else "not_ready",
            "github_credentials": runtime.github_ready,
            "database": database_ready,
            "worker": worker_ready,
            "reconciler": reconciler_ready,
        }
        return JSONResponse(
            payload,
            status_code=status.HTTP_200_OK if ready_state else status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        """Expose Prometheus metrics without repository or secret labels."""
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post(
        "/webhooks/github",
        status_code=status.HTTP_202_ACCEPTED,
        tags=["github"],
        responses={
            400: {"description": "Malformed delivery"},
            401: {"description": "Invalid signature"},
            503: {
                "description": (
                    "Receiver/evaluator unavailable, or delivery could not be durably stored"
                )
            },
        },
    )
    async def github_webhook(request: Request) -> JSONResponse:
        """Authenticate, de-duplicate, and durably enqueue a GitHub delivery."""
        secret = runtime.webhook_secret_value
        if secret is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "webhook receiver is not configured"
            )
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                parsed_length = int(content_length)
                if parsed_length < 0:
                    raise ValueError
                if parsed_length > MAX_WEBHOOK_BYTES:
                    raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "payload too large")
            except ValueError as error:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, "invalid Content-Length"
                ) from error
        body_buffer = bytearray()
        async for chunk in request.stream():
            body_buffer.extend(chunk)
            if len(body_buffer) > MAX_WEBHOOK_BYTES:
                raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "payload too large")
        body = bytes(body_buffer)
        try:
            webhook = verify_webhook(
                body,
                signature=request.headers.get("x-hub-signature-256"),
                delivery_id=request.headers.get("x-github-delivery"),
                event=request.headers.get("x-github-event"),
                secret=secret,
            )
            job = evaluation_job(
                webhook,
                policy_path=runtime.policy_path,
                org_config_repository=runtime.org_config_repository,
            )
            if isinstance(job, JobRequest) and runtime.is_organization_config_repository(
                job.repository_full_name
            ):
                # The shared organization policy occupies the repository
                # policy path in ORG/.github, so that repository is protected
                # by native human CODEOWNERS rules instead of this check.
                job = None
        except WebhookError as error:
            reason = "signature" if "signature" in str(error).lower() else "payload"
            WEBHOOK_FAILURES.labels(reason).inc()
            status_code = (
                status.HTTP_401_UNAUTHORIZED
                if reason == "signature"
                else status.HTTP_400_BAD_REQUEST
            )
            raise HTTPException(status_code, str(error)) from error
        if job is None:
            # Ignored actions (including this App's own check_run updates) do
            # not need durable de-duplication. Persisting them would amplify
            # every evaluation into retained database traffic.
            log.info(
                "webhook_ignored",
                delivery_id=webhook.delivery_id,
                github_event=webhook.event,
                action=webhook.action or "received",
            )
            WEBHOOKS.labels(webhook.event, webhook.action or "received").inc()
            return JSONResponse(
                {"accepted": True, "queued": False},
                status_code=status.HTTP_202_ACCEPTED,
            )
        queue_store: QueueStore = request.app.state.store
        try:
            accepted = await asyncio.to_thread(
                queue_store.accept_delivery,
                webhook.delivery_id,
                webhook.event,
                job,
                runtime.webhook_invalidation_timeout_seconds,
            )
        except Exception as error:
            WEBHOOK_FAILURES.labels("durable_acceptance").inc()
            log.exception(
                "webhook_durable_acceptance_failed",
                delivery_id=webhook.delivery_id,
                github_event=webhook.event,
                error_type=type(error).__name__,
            )
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "delivery could not be durably accepted; redeliver it after recovery",
            ) from error
        queued = accepted and job is not None
        needs_invalidation = accepted
        if (
            isinstance(job, JobRequest)
            and not needs_invalidation
            and await asyncio.to_thread(
                queue_store.delivery_needs_invalidation,
                webhook.delivery_id,
            )
        ):
            needs_invalidation = True
        if isinstance(job, JobRequest) and needs_invalidation:
            evaluator: EvaluationService | None = request.app.state.evaluator
            if evaluator is None:
                WEBHOOK_FAILURES.labels("invalidation_unavailable").inc()
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "delivery was stored, but check revocation is temporarily unavailable",
                )
            try:
                invalidated = await asyncio.wait_for(
                    evaluator.invalidate_for_trigger(job),
                    timeout=runtime.webhook_invalidation_timeout_seconds,
                )
                if invalidated:
                    # Always create a newer generation after the PATCH. This
                    # fences a worker that published immediately before the
                    # revocation and prevents it from deleting the only queued
                    # re-evaluation as it completes.
                    await asyncio.to_thread(queue_store.enqueue, job)
                    queued = True
                await asyncio.to_thread(queue_store.mark_delivery_invalidated, webhook.delivery_id)
            except Exception as error:
                # Durable work is authoritative. GitHub terminates webhook
                # requests after ten seconds and does not automatically retry
                # failures, so the synchronous revocation is a bounded fast
                # path rather than part of delivery acceptance.
                WEBHOOK_FAILURES.labels("invalidation_fast_path").inc()
                log.warning(
                    "webhook_check_invalidation_deferred",
                    delivery_id=webhook.delivery_id,
                    github_event=webhook.event,
                    repository=job.repository_full_name,
                    pull_number=job.pull_number,
                    error_type=type(error).__name__,
                )
        log.info(
            "webhook_accepted",
            delivery_id=webhook.delivery_id,
            github_event=webhook.event,
            action=webhook.action or "received",
            repository=job.repository_full_name,
            pull_number=job.pull_number if isinstance(job, JobRequest) else None,
            accepted=accepted,
            queued=queued,
        )
        WEBHOOKS.labels(webhook.event, webhook.action or "received").inc()
        return JSONResponse(
            {"accepted": accepted, "queued": queued},
            status_code=status.HTTP_202_ACCEPTED,
        )

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

    @app.get("/setup/complete", response_class=HTMLResponse, include_in_schema=False)
    async def setup_complete() -> HTMLResponse:
        """Confirm installation and point the operator to repository configuration."""
        if not runtime.setup_enabled:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        body = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Extra CODEOWNERS installed</title></head>
<body><main><h1>Extra CODEOWNERS is installed</h1>
<p>Add <code>.github/extra-codeowners.toml</code> to each repository you want to enable.</p>
<p><a href="https://extra-codeowners.readthedocs.io/">Read the configuration guide</a>.</p>
</main></body></html>"""
        return HTMLResponse(body, headers=NO_STORE_HEADERS)

    return app


app = create_app()
