"""Authenticate and enqueue GitHub deliveries at the HTTP boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from extra_codeowners.database import AuthorityRequest, JobRequest, QueueStore
from extra_codeowners.github import GitHubRateLimitError
from extra_codeowners.merge_queue import MergeGroupTrigger
from extra_codeowners.metrics import WEBHOOK_FAILURES, record_webhook
from extra_codeowners.service import EvaluationService
from extra_codeowners.settings import Settings
from extra_codeowners.tracing import Tracing
from extra_codeowners.webhooks import (
    MAX_WEBHOOK_BYTES,
    VerifiedWebhook,
    WebhookError,
    evaluation_job,
    merge_group_trigger,
    validate_webhook_headers,
    verify_webhook,
)

log = structlog.get_logger()
BODY_READ_SLOTS = 8
BODY_READ_TIMEOUT_SECONDS = 4.0


@dataclass(frozen=True, slots=True)
class WebhookDependencies:
    settings: Settings
    store: QueueStore
    evaluator: EvaluationService | None
    worker_task: asyncio.Task[None] | None
    tracing: Tracing


async def _read_verified_webhook(
    request: Request, signature: str, delivery_id: str, event: str, secret: str
) -> VerifiedWebhook:
    body = bytearray()
    try:
        async with asyncio.timeout(BODY_READ_TIMEOUT_SECONDS):
            async for chunk in request.stream():
                if len(chunk) > MAX_WEBHOOK_BYTES - len(body):
                    raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "payload too large")
                body.extend(chunk)
    except TimeoutError as error:
        raise HTTPException(
            status.HTTP_408_REQUEST_TIMEOUT, "webhook body read timed out"
        ) from error
    return verify_webhook(
        bytes(body), signature=signature, delivery_id=delivery_id, event=event, secret=secret
    )


def create_webhook_router(resolve: Callable[[Request], WebhookDependencies]) -> APIRouter:
    router = APIRouter()
    # Only an available slot admits a read. Don't queue untrusted requests.
    body_slots = asyncio.BoundedSemaphore(BODY_READ_SLOTS)

    @router.post(
        "/webhooks/github",
        status_code=status.HTTP_202_ACCEPTED,
        tags=["github"],
        responses={
            400: {"description": "Malformed delivery"},
            401: {"description": "Invalid signature"},
            408: {"description": "Webhook body read timed out"},
            413: {"description": "Webhook body too large"},
            503: {
                "description": (
                    "Receiver busy or unavailable, or delivery could not be durably stored"
                )
            },
        },
    )
    async def github_webhook(request: Request) -> JSONResponse:
        """Authenticate, de-duplicate, and durably enqueue a GitHub delivery."""
        dependencies = resolve(request)
        runtime = dependencies.settings
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
        try:
            signature, delivery_id, event = validate_webhook_headers(
                request.headers.get("x-hub-signature-256"),
                request.headers.get("x-github-delivery"),
                request.headers.get("x-github-event"),
            )
            if body_slots.locked():
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "webhook receiver is busy")
            async with body_slots:
                webhook = await _read_verified_webhook(
                    request, signature, delivery_id, event, secret
                )
            job: JobRequest | AuthorityRequest | MergeGroupTrigger | None
            if webhook.event == "merge_group":
                candidate = (
                    merge_group_trigger(webhook)
                    if runtime.experimental_merge_queue_repository is not None
                    else None
                )
                job = (
                    candidate
                    if candidate is not None
                    and candidate.repository == runtime.experimental_merge_queue_repository
                    and candidate.repository_id == runtime.experimental_merge_queue_repository_id
                    else None
                )
            else:
                job = evaluation_job(
                    webhook,
                    policy_path=runtime.policy_path,
                    org_config_repository=runtime.org_config_repository,
                    expected_app_id=runtime.github_app_id,
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
            record_webhook(webhook.event, webhook.action)
            return JSONResponse(
                {"accepted": True, "queued": False},
                status_code=status.HTTP_202_ACCEPTED,
            )
        queue_store = dependencies.store
        if isinstance(job, MergeGroupTrigger):
            worker_task = dependencies.worker_task
            if worker_task is None or worker_task.done():
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "candidate worker is unavailable; redeliver after recovery",
                )
        repository = (
            job.repository if isinstance(job, MergeGroupTrigger) else job.repository_full_name
        )
        tracing = dependencies.tracing
        producer_trace_context = None
        try:
            with tracing.span(
                "webhook.accept",
                attributes={
                    "github.event": webhook.event,
                    "github.action": webhook.action or "received",
                },
                private_attributes=(
                    {
                        "github.delivery_id": webhook.delivery_id,
                        "github.repository": job.repository_full_name,
                        "github.pull_number": job.pull_number,
                    }
                    if isinstance(job, JobRequest)
                    else {
                        "github.delivery_id": webhook.delivery_id,
                        "github.scope": repository or "*",
                    }
                ),
                root=True,
            ) as span:
                # This context is generated only after HMAC verification. The
                # service never accepts GitHub's inbound trace headers.
                producer_trace_context = tracing.capture_trusted_context(span)
                acceptance = await asyncio.to_thread(
                    queue_store.accept_delivery,
                    webhook.delivery_id,
                    webhook.event,
                    job,
                    runtime.webhook_invalidation_timeout_seconds,
                    trace_context=producer_trace_context,
                    invalidate_merge_groups=(
                        runtime.experimental_merge_queue_repository is not None
                        and (
                            repository is None
                            or repository == runtime.experimental_merge_queue_repository
                        )
                    ),
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
        accepted = acceptance.accepted
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
            evaluator = dependencies.evaluator
            if evaluator is None:
                WEBHOOK_FAILURES.labels("invalidation_unavailable").inc()
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "delivery was stored, but check revocation is temporarily unavailable",
                )
            if await asyncio.to_thread(
                queue_store.provider_is_backpressured,
                job.installation_id,
            ):
                # Durable work remains queued. Do not turn every incoming
                # webhook into another GitHub request while an installation or
                # App-wide provider circuit is deliberately open.
                log.info(
                    "webhook_check_invalidation_deferred_for_provider_backpressure",
                    delivery_id=webhook.delivery_id,
                    installation_id=job.installation_id,
                )
            else:
                try:
                    invalidated = await asyncio.wait_for(
                        evaluator.invalidate_for_trigger(
                            job,
                            acceptance.shared_head_generation,
                        ),
                        timeout=runtime.webhook_invalidation_timeout_seconds,
                    )
                    queued = queued or invalidated
                    await asyncio.to_thread(
                        queue_store.mark_delivery_invalidated, webhook.delivery_id
                    )
                except GitHubRateLimitError as error:
                    try:
                        await error.persist_backpressure(queue_store, job.installation_id)
                    except Exception as record_error:
                        log.warning(
                            "webhook_provider_backpressure_record_failed",
                            error_type=type(record_error).__name__,
                        )
                    # Durable work is authoritative. GitHub terminates
                    # webhook requests after ten seconds and does not
                    # automatically retry failures, so this synchronous reset
                    # is a bounded fast path rather than delivery acceptance.
                    WEBHOOK_FAILURES.labels("invalidation_fast_path").inc()
                    log.warning(
                        "webhook_check_invalidation_rate_limited",
                        delivery_id=webhook.delivery_id,
                        github_event=webhook.event,
                        repository=job.repository_full_name,
                        pull_number=job.pull_number,
                        scope="global" if error.global_scope else "installation",
                        retry_after_seconds=error.retry_after_seconds,
                    )
                except Exception as error:
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
            repository=repository,
            pull_number=job.pull_number if isinstance(job, JobRequest) else None,
            accepted=accepted,
            queued=queued,
            **(
                {
                    "trace_id": producer_trace_context.trace_id,
                    "span_id": producer_trace_context.span_id,
                }
                if producer_trace_context is not None
                else {}
            ),
        )
        record_webhook(webhook.event, webhook.action)
        return JSONResponse(
            {"accepted": accepted, "queued": queued},
            status_code=status.HTTP_202_ACCEPTED,
        )

    return router
