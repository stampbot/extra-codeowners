"""Publish an experimental merge candidate check under the existing writer guards."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import TYPE_CHECKING

import structlog

from extra_codeowners.api_budget import request_lane
from extra_codeowners.github import GitHubError, GitHubRateLimitError
from extra_codeowners.merge_group_work import ClaimedMergeGroup, MergeGroupQueue
from extra_codeowners.merge_queue import MergeGroupTrigger
from extra_codeowners.models import EvaluationConclusion

if TYPE_CHECKING:
    from extra_codeowners.service import EvaluationService

log = structlog.get_logger()


class MergeGroupWorker:
    """Run the leased candidate queue for one explicitly configured repository."""

    def __init__(
        self, evaluator: EvaluationService, owner: str, repository: tuple[str, int]
    ) -> None:
        self.evaluator = evaluator
        self.queue = MergeGroupQueue(evaluator.store)
        self.github = evaluator.github
        self.settings = evaluator.settings
        self.owner = owner
        self.repository = repository

    async def _require_repository(self, trigger: MergeGroupTrigger) -> None:
        if (trigger.repository, trigger.repository_id) != self.repository:
            raise GitHubError("candidate is outside the configured test repository")
        if not await self.github.installation_includes_repository(
            trigger.installation_id, trigger.repository, refresh=True
        ):
            raise GitHubError("candidate repository is outside the installation")
        repo = await self.github.get_repository(trigger.installation_id, trigger.repository)
        name = repo.get("full_name")
        if (
            type(repo.get("id")) is not int
            or repo["id"] != trigger.repository_id
            or not isinstance(name, str)
            or name.lower() != trigger.repository
        ):
            raise GitHubError("candidate repository identity changed")

    async def _require_attempt(self, job: ClaimedMergeGroup) -> None:
        if not await asyncio.to_thread(self.queue.is_current, job):
            raise GitHubError("merge candidate lease or generation changed")

    async def _revoke(self, trigger: MergeGroupTrigger, check_id: int) -> None:
        await self.github.write_merge_group_check(
            trigger,
            self.settings.check_name,
            check_id=check_id,
            approved=False,
            summary="This merge candidate is no longer approved. Queue a fresh candidate.",
        )

    async def _compensate_uncertain_write(self, trigger: MergeGroupTrigger) -> None:
        async def reset() -> None:
            await self._require_repository(trigger)
            check_id = await self.github.existing_merge_group_check(
                trigger, self.settings.check_name
            )
            if check_id is not None:
                await self._revoke(trigger, check_id)

        cleanup = asyncio.create_task(reset(), name="restore-blocking-candidate-check")
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                # Keep the writer guard until the bounded compensation ends.
                continue
            except Exception:
                break
        try:
            cleanup.result()
        except (Exception, asyncio.CancelledError) as error:
            log.warning("merge_group_check_reset_uncertain", error_type=type(error).__name__)

    async def process(self, job: ClaimedMergeGroup) -> None:
        """Revoke a previous result or publish once for a new, still-waiting candidate."""
        trigger = job.trigger
        name = self.settings.check_name
        async with self.evaluator._check_write_guard(trigger.installation_id, trigger.head_sha):
            await self._require_attempt(job)
            await self._require_repository(trigger)
            existing = await self.github.existing_merge_group_check(trigger, name)
            await self._require_attempt(job)
            if existing is not None or trigger.action == "destroyed":
                if existing is not None:
                    await self._revoke(trigger, existing)
                if not await asyncio.to_thread(self.queue.complete, job):
                    raise GitHubError("merge candidate changed during revocation")
                return

        identity = await self.github.get_merge_candidate(trigger)
        if not await asyncio.to_thread(self.queue.bind, job, identity):
            raise GitHubError("merge candidate no longer has this lease or queue entry")
        epoch = await asyncio.to_thread(self.queue.evidence_epoch, job, identity)
        if epoch is None:
            raise GitHubError("merge candidate awaits authority or PR-head invalidation")
        assessment = await self.evaluator.assess_merge_candidate(
            trigger, authority_generation=epoch.installation
        )
        if assessment.identity != identity:
            raise GitHubError("merge candidate changed during policy assessment")

        async with (
            self.evaluator._authority_publish_guard(trigger.installation_id),
            self.evaluator._check_write_guard(trigger.installation_id, trigger.head_sha),
        ):
            await self._require_attempt(job)
            if await self.github.get_merge_candidate(trigger) != identity:
                raise GitHubError("merge candidate changed before publication")
            if await self.github.existing_merge_group_check(trigger, name) is not None:
                raise GitHubError("a different writer published this merge group check")
            if await asyncio.to_thread(self.queue.evidence_epoch, job, identity) != epoch:
                raise GitHubError("merge candidate authorization evidence changed")
            approved = assessment.result.conclusion is EvaluationConclusion.SUCCESS
            try:
                await self.github.write_merge_group_check(
                    trigger, name, approved=approved, summary=assessment.result.summary
                )
                if await asyncio.to_thread(
                    self.queue.evidence_epoch, job, identity
                ) != epoch or not await asyncio.to_thread(self.queue.complete, job):
                    raise GitHubError("merge candidate changed during check publication")
            except (Exception, asyncio.CancelledError):
                if approved:
                    await self._compensate_uncertain_write(trigger)
                raise

    async def _renew(self, job: ClaimedMergeGroup) -> None:
        lease_seconds = self.settings.worker_lease_seconds
        while True:
            await asyncio.sleep(lease_seconds / 3)
            if not await asyncio.to_thread(self.queue.renew, job, lease_seconds):
                return

    async def _run_attempt(self, job: ClaimedMergeGroup) -> None:
        renew = asyncio.create_task(self._renew(job), name="merge-group-lease")
        try:
            with request_lane("authority"):
                await self.process(job)
        except Exception as error:
            delay = min(self.settings.worker_retry_max_seconds, 2 ** min(job.attempts, 10))
            if isinstance(error, GitHubRateLimitError):
                delay = max(delay, error.retry_after_seconds)
                await asyncio.to_thread(
                    self.evaluator.store.record_provider_backpressure,
                    None if error.global_scope else job.trigger.installation_id,
                    "merge candidate request rate limited",
                    delay,
                )
            await asyncio.to_thread(self.queue.retry, job, delay)
            log.warning("merge_group_attempt_deferred", error_type=type(error).__name__)
        finally:
            renew.cancel()
            with suppress(asyncio.CancelledError):
                await renew

    async def run(self, stop: asyncio.Event) -> None:
        """Claim one candidate at a time per replica until the service stops."""
        while not stop.is_set():
            try:
                job = await asyncio.to_thread(
                    self.queue.claim,
                    self.owner,
                    self.settings.worker_lease_seconds,
                    repository_scope=self.repository,
                )
                if job is not None:
                    await self._run_attempt(job)
                    continue
            except Exception as error:
                log.error("merge_group_worker_retry", error_type=type(error).__name__)
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.settings.worker_poll_seconds)
