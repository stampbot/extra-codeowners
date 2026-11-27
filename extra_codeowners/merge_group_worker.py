"""Publish an experimental merge candidate check under the existing writer guards."""

from __future__ import annotations

import asyncio
import time
from contextlib import AbstractAsyncContextManager, suppress
from typing import Protocol

import structlog

from extra_codeowners.api_budget import request_lane
from extra_codeowners.database import QueueStore
from extra_codeowners.github import (
    GitHubAPIError,
    GitHubClient,
    GitHubError,
    GitHubRateLimitError,
    MergeCandidateReplacedError,
)
from extra_codeowners.merge_group_work import (
    ClaimedMergeGroup,
    MergeGroupEvidenceEpoch,
    MergeGroupQueue,
)
from extra_codeowners.merge_queue import (
    MERGE_CANDIDATE_CHECK_NAME,
    MergeCandidateAssessment,
    MergeCandidateIdentity,
    MergeGroupTrigger,
    candidate_pull_is_closed,
)
from extra_codeowners.metrics import WORK_ATTEMPT_SECONDS, WORK_ATTEMPTS
from extra_codeowners.models import EvaluationConclusion
from extra_codeowners.settings import Settings

log = structlog.get_logger()


class CandidateEvaluator(Protocol):
    """The policy read and writer guards used by the candidate lane."""

    store: QueueStore
    github: GitHubClient
    settings: Settings

    def _check_write_guard(
        self, installation_id: int, head_sha: str
    ) -> AbstractAsyncContextManager[None]:
        raise NotImplementedError

    def _authority_publish_guard(self, installation_id: int) -> AbstractAsyncContextManager[None]:
        raise NotImplementedError

    async def assess_merge_candidate(
        self,
        identity: MergeCandidateIdentity,
        *,
        authority_generation: int,
        rechecking: bool = False,
    ) -> MergeCandidateAssessment:
        raise NotImplementedError


class MergeGroupWorker:
    """Run the leased candidate queue for one explicitly configured repository."""

    def __init__(
        self, evaluator: CandidateEvaluator, owner: str, repository: tuple[str, int]
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
            MERGE_CANDIDATE_CHECK_NAME,
            check_id=check_id,
            approved=False,
            summary="This merge candidate is no longer approved. Queue a fresh candidate.",
        )

    async def _compensate_uncertain_write(self, trigger: MergeGroupTrigger) -> None:
        async def reset() -> None:
            await self._require_repository(trigger)
            check_id = await self.github.existing_merge_group_check(
                trigger, MERGE_CANDIDATE_CHECK_NAME
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

    async def _complete(self, job: ClaimedMergeGroup, *, keep_check: int | None = None) -> None:
        if not await asyncio.to_thread(
            self.queue.complete,
            job,
            check_id=keep_check,
            recheck_seconds=(
                self.settings.experimental_merge_queue_recheck_seconds
                if keep_check is not None
                else None
            ),
            retire=keep_check is None,
        ):
            raise GitHubError("merge candidate lease or generation changed before completion")

    async def _read_assessment(
        self, job: ClaimedMergeGroup, *, rechecking: bool = False
    ) -> tuple[MergeCandidateAssessment, MergeGroupEvidenceEpoch]:
        flags = {"rechecking": True} if rechecking else {}
        identity = await self.github.get_merge_candidate(job.trigger, **flags)
        if not await asyncio.to_thread(self.queue.bind, job, identity):
            raise GitHubError("merge candidate no longer has this lease or queue entry")
        epoch = await asyncio.to_thread(self.queue.evidence_epoch, job, identity)
        if epoch is None:
            raise GitHubError("merge candidate awaits authority or PR-head invalidation")
        assessment = await self.evaluator.assess_merge_candidate(
            identity, authority_generation=epoch.installation, **flags
        )
        if assessment.identity != identity:
            raise GitHubError("merge candidate changed during policy assessment")
        return assessment, epoch

    async def _require_recorded_check(self, job: ClaimedMergeGroup) -> None:
        published = job.published
        if published is None:
            raise ValueError("candidate recheck has no confirmed check")
        existing = await self.github.existing_merge_group_check(
            job.trigger, MERGE_CANDIDATE_CHECK_NAME
        )
        if existing != published.check_id:
            raise GitHubError("the current candidate check is not the recorded pass")

    async def _bound_pull_is_closed(
        self, trigger: MergeGroupTrigger, pull_identity: tuple[str, int] | None
    ) -> bool:
        if pull_identity is None:
            return False
        pull_id, pull_number = pull_identity
        try:
            pull = await self.github.get_pull(
                trigger.installation_id, trigger.repository, pull_number
            )
            return candidate_pull_is_closed(trigger, pull_id, pull_number, pull)
        except GitHubRateLimitError:
            raise
        except Exception:
            return False  # A failed read isn't proof that the check is historical.

    async def _withdraw_or_retire(self, job: ClaimedMergeGroup) -> None:
        trigger, published = job.trigger, job.published
        if published is None:
            raise ValueError("candidate recheck has no confirmed check")
        async with self.evaluator._check_write_guard(trigger.installation_id, trigger.head_sha):
            await self._require_attempt(job)
            await self._require_repository(trigger)
            closed = await self._bound_pull_is_closed(
                trigger, (published.pull_id, published.pull_number)
            )
            await self._require_attempt(job)
            if not closed:
                await self._require_recorded_check(job)
                await self._require_attempt(job)
                await self._revoke(trigger, published.check_id)
            await self._complete(job)

    async def _process_recheck(self, job: ClaimedMergeGroup) -> None:
        """Revalidate a previously confirmed pass; never publish or restore success."""
        trigger, published = job.trigger, job.published
        if published is None:
            raise ValueError("candidate recheck has no confirmed check")
        await self._require_attempt(job)
        await self._require_repository(trigger)
        try:
            await self._require_recorded_check(job)
            if not await self.github.merge_group_check_is_passing(
                trigger, MERGE_CANDIDATE_CHECK_NAME, published.check_id
            ):
                await self._complete(job)
                return
            if job.attempts == 1:
                assessment, epoch = await self._read_assessment(job, rechecking=True)
                if assessment.result.conclusion is EvaluationConclusion.SUCCESS:
                    async with (
                        self.evaluator._authority_publish_guard(trigger.installation_id),
                        self.evaluator._check_write_guard(
                            trigger.installation_id, trigger.head_sha
                        ),
                    ):
                        await self._require_attempt(job)
                        if (
                            await self.github.get_merge_candidate(trigger, rechecking=True)
                            == assessment.identity
                            and await asyncio.to_thread(
                                self.queue.evidence_epoch, job, assessment.identity
                            )
                            == epoch
                        ):
                            await self._complete(job, keep_check=published.check_id)
                            return
        except GitHubRateLimitError:
            raise
        except Exception as error:
            log.warning("merge_group_recheck_unconfirmed", error_type=type(error).__name__)

        # A reclaimed or failed recheck does not leave a pass active while we
        # try to reconstruct its evidence. A proved closed PR is history.
        await self._withdraw_or_retire(job)

    async def process(self, job: ClaimedMergeGroup) -> None:
        """Revoke a previous result or publish once for a new, still-waiting candidate."""
        if job.published is not None:
            await self._process_recheck(job)
            return
        trigger = job.trigger
        name = MERGE_CANDIDATE_CHECK_NAME
        async with self.evaluator._check_write_guard(trigger.installation_id, trigger.head_sha):
            await self._require_attempt(job)
            await self._require_repository(trigger)
            if job.pull_identity is not None and await self._bound_pull_is_closed(
                trigger, job.pull_identity
            ):
                await self._complete(job)
                return
            try:
                existing = await self.github.existing_merge_group_check(trigger, name)
            except GitHubAPIError as error:
                if error.status_code not in {404, 422} or trigger.action != "checks_requested":
                    raise
                # A missing old commit alone can't establish retirement.
                try:
                    await self.github.get_merge_candidate(trigger)
                except MergeCandidateReplacedError:
                    await self._complete(job)
                    return
                raise
            await self._require_attempt(job)
            if existing is not None or trigger.action == "destroyed":
                if existing is not None:
                    await self._revoke(trigger, existing)
                await self._complete(job)
                return

        try:
            await self._assess_and_publish(job)
        except MergeCandidateReplacedError:
            # The provider confirmed another live candidate on this ref. There
            # is nothing to revoke if the original candidate never got a check.
            async with self.evaluator._check_write_guard(trigger.installation_id, trigger.head_sha):
                await self._require_attempt(job)
                if await self.github.existing_merge_group_check(trigger, name) is not None:
                    raise
                await self._complete(job)

    async def _assess_and_publish(self, job: ClaimedMergeGroup) -> None:
        trigger = job.trigger
        name = MERGE_CANDIDATE_CHECK_NAME
        assessment, epoch = await self._read_assessment(job)
        identity = assessment.identity

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
                check_id = await self.github.write_merge_group_check(
                    trigger, name, approved=approved, summary=assessment.result.summary
                )
                if await asyncio.to_thread(self.queue.evidence_epoch, job, identity) != epoch:
                    raise GitHubError("merge candidate changed during check publication")
                if approved and type(check_id) is not int:
                    raise GitHubError("a confirmed candidate pass must identify its Check Run")
                await self._complete(job, keep_check=check_id if approved else None)
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
        started = time.perf_counter()
        work_class = "recheck" if job.published else "withdrawal" if job.withdrawal else "event"
        outcome = "completed"
        try:
            with request_lane("authority"):
                await self.process(job)
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        except Exception as error:
            outcome = "retry"
            delay = min(self.settings.worker_retry_max_seconds, 2 ** min(job.attempts, 10))
            if isinstance(error, GitHubRateLimitError):
                outcome = "rate_limited"
                delay = max(delay, error.retry_after_seconds)
                await error.persist_backpressure(self.evaluator.store, job.trigger.installation_id)
            await asyncio.to_thread(self.queue.retry, job, delay)
            log.warning("merge_group_attempt_deferred", error_type=type(error).__name__)
        finally:
            WORK_ATTEMPTS.labels("candidate", work_class, outcome).inc()
            WORK_ATTEMPT_SECONDS.labels("candidate", work_class, outcome).observe(
                time.perf_counter() - started
            )
            renew.cancel()
            with suppress(asyncio.CancelledError):
                await renew

    async def run(self, stop: asyncio.Event) -> None:
        """Claim one candidate at a time per replica until the service stops."""
        prefer_recheck = False
        while not stop.is_set():
            try:
                job = await asyncio.to_thread(
                    self.queue.claim,
                    self.owner,
                    self.settings.worker_lease_seconds,
                    repository_scope=self.repository,
                    recheck=prefer_recheck,
                )
                if job is None:
                    job = await asyncio.to_thread(
                        self.queue.claim,
                        self.owner,
                        self.settings.worker_lease_seconds,
                        repository_scope=self.repository,
                        recheck=not prefer_recheck,
                    )
                if job is not None:
                    prefer_recheck = job.published is None
                    await self._run_attempt(job)
                    continue
            except Exception as error:
                log.error("merge_group_worker_retry", error_type=type(error).__name__)
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.settings.worker_poll_seconds)
