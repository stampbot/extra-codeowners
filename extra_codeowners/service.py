"""GitHub evidence collection and policy evaluation orchestration."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import structlog
from pydantic import ValidationError

from extra_codeowners.codeowners import CodeownersDocument, parse_codeowners
from extra_codeowners.database import (
    AuthorityRequest,
    CheckWriteGuard,
    ClaimedAuthorityJob,
    ClaimedJob,
    ClaimedSharedHeadInvalidation,
    JobRequest,
    QueueStore,
    normalize_repository_full_name,
    validate_head_sha,
)
from extra_codeowners.evaluator import evaluate
from extra_codeowners.github import (
    MAX_CODEOWNERS_BYTES,
    MAX_PULL_FILES,
    GitHubClient,
    GitHubError,
    GitHubRateLimitError,
    PullRequestTooLargeError,
)
from extra_codeowners.metrics import (
    DEAD_JOBS,
    EVALUATION_SECONDS,
    EVALUATIONS,
    QUEUE_DEPTH,
    RECONCILIATION_LAST_SUCCESS,
    RECONCILIATIONS,
    SHARED_HEAD_INVALIDATION_DEPTH,
    SHARED_HEAD_INVALIDATIONS,
)
from extra_codeowners.models import (
    ActorKind,
    ChangedFile,
    ChangedFileStatus,
    EnrolledApplication,
    EvaluationConclusion,
    EvaluationInput,
    EvaluationMessage,
    EvaluationOptions,
    EvaluationResult,
    OrganizationPolicy,
    PullRequestReview,
    RepositoryPolicy,
    ReviewActor,
    ReviewState,
)
from extra_codeowners.policy import BUILTIN_NON_DELEGABLE_PATHS
from extra_codeowners.settings import Settings

CODEOWNERS_LOCATIONS: Final = (
    ".github/CODEOWNERS",
    "CODEOWNERS",
    "docs/CODEOWNERS",
)
log = structlog.get_logger()
MAX_TEAM_MEMBERSHIP_LOOKUPS: Final = 250
MAX_PATH_MATCH_OPERATIONS: Final = 2_000_000


class EvidenceLimitError(GitHubError):
    """Trusted evidence exceeds a bounded evaluation budget."""


class AuthorityChangePendingError(RuntimeError):
    """An accepted authority change must fan out before evaluation can finish."""


class SharedHeadLeaseLostError(RuntimeError):
    """An exact-head reset lost its generation or lease before completion."""


class SharedHeadInvalidationPendingError(RuntimeError):
    """A current evaluation must wait for its exact-head reset and fan-out."""


def _failure(code: str, message: str) -> EvaluationResult:
    return EvaluationResult(
        conclusion=EvaluationConclusion.FAILURE,
        summary="Extra CODEOWNERS could not evaluate safely; approval is denied.",
        errors=(EvaluationMessage(code=code, message=message),),
    )


def _required_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        msg = f"GitHub response omitted {field}"
        raise GitHubError(msg)
    return value


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        msg = f"GitHub response omitted {field}"
        raise GitHubError(msg)
    return value


def _required_nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        msg = f"GitHub response omitted {field}"
        raise GitHubError(msg)
    return int(value)


def _required_positive_int(value: Any, field: str) -> int:
    result = _required_nonnegative_int(value, field)
    if result == 0:
        raise GitHubError(f"GitHub response omitted {field}")
    return result


def _label_names(pull: dict[str, Any]) -> frozenset[str]:
    labels = pull.get("labels")
    if not isinstance(labels, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in labels
    ):
        raise GitHubError("GitHub pull response omitted a valid labels list")
    return frozenset(str(item["name"]).lower() for item in labels)


def _associated_pull_identity(value: Any) -> tuple[int, str, str]:
    """Return a strictly validated commit-associated pull snapshot."""
    associated_pull = _required_object(value, "associated pull_request")
    state_value = _required_string(associated_pull.get("state"), "associated pull_request.state")
    if state_value not in {"open", "closed"}:
        raise GitHubError(f"GitHub returned unknown associated pull request state {state_value!r}")
    associated_head = _required_object(associated_pull.get("head"), "associated pull_request.head")
    raw_sha = _required_string(
        associated_head.get("sha"),
        "associated pull_request.head.sha",
    )
    try:
        associated_sha = validate_head_sha(raw_sha)
    except ValueError as error:
        raise GitHubError("GitHub returned malformed associated pull request head SHA") from error
    number_value = _required_positive_int(
        associated_pull.get("number"),
        "associated pull_request.number",
    )
    return number_value, state_value, associated_sha


class EvaluationService:
    """Collect trusted evidence, run the pure evaluator, and publish one check."""

    def __init__(self, settings: Settings, github: GitHubClient, store: QueueStore) -> None:
        self.settings = settings
        self.github = github
        self.store = store
        self._cleanup_tasks: set[asyncio.Task[None]] = set()

    async def _current_associated_pulls(
        self,
        installation_id: int,
        repository_full_name: str,
        head_sha: str,
        *,
        before_github_read: Callable[[], Awaitable[None]] | None = None,
    ) -> dict[int, tuple[str, str]]:
        """Return authoritative current state for every commit-associated PR."""
        if before_github_read is not None:
            await before_github_read()
        associated = await self.github.list_commit_pulls(
            installation_id,
            repository_full_name,
            head_sha,
        )
        observed: dict[int, tuple[str, str]] = {}
        for associated_pull in associated:
            number_value, state_value, associated_sha = _associated_pull_identity(associated_pull)
            identity = (state_value, associated_sha)
            previous = observed.setdefault(number_value, identity)
            if previous != identity:
                raise GitHubError("GitHub returned conflicting associated pull-request snapshots")

        current: dict[int, tuple[str, str]] = {}
        for number_value in sorted(observed):
            if before_github_read is not None:
                await before_github_read()
            current_pull = await self.github.get_pull(
                installation_id,
                repository_full_name,
                number_value,
            )
            current_number = _required_positive_int(
                current_pull.get("number"),
                "pull_request.number",
            )
            current_state = _required_string(current_pull.get("state"), "pull_request.state")
            if current_state not in {"open", "closed"}:
                raise GitHubError(f"GitHub returned unknown pull request state {current_state!r}")
            current_head = _required_object(current_pull.get("head"), "pull_request.head")
            try:
                current_sha = validate_head_sha(
                    _required_string(current_head.get("sha"), "pull_request.head.sha")
                )
            except ValueError as error:
                raise GitHubError("GitHub returned malformed pull request head SHA") from error
            current_base = _required_object(current_pull.get("base"), "pull_request.base")
            current_repository = _required_object(
                current_base.get("repo"),
                "pull_request.base.repo",
            )
            try:
                canonical_repository = normalize_repository_full_name(
                    _required_string(
                        current_repository.get("full_name"),
                        "pull_request.base.repo.full_name",
                    )
                )
            except ValueError as error:
                raise GitHubError("GitHub returned malformed base repository identity") from error
            if current_number != number_value:
                raise GitHubError("GitHub changed the associated pull request number")
            if canonical_repository != repository_full_name:
                raise GitHubError("GitHub changed the associated pull request repository")
            current[number_value] = (current_state, current_sha)
        return current

    @asynccontextmanager
    async def _check_write_guard(self, installation_id: int, head_sha: str) -> AsyncIterator[None]:
        """Serialize commit-scoped check writes across every service replica."""
        acquisition = asyncio.create_task(
            asyncio.to_thread(
                self.store.acquire_check_write_guard,
                f"installation:{installation_id}",
                head_sha,
                30.0,
            )
        )
        try:
            guard = await asyncio.shield(acquisition)
        except asyncio.CancelledError:
            # asyncio cannot cancel a running executor thread. Arrange to
            # release any guard it eventually returns instead of leaking a
            # PostgreSQL session advisory lock.
            cleanup = asyncio.create_task(self._release_abandoned_guard(acquisition))
            self._cleanup_tasks.add(cleanup)
            cleanup.add_done_callback(self._cleanup_tasks.discard)
            raise
        if guard is None:
            raise GitHubError("timed out waiting for the pull request check writer")
        try:
            yield
        finally:
            await asyncio.to_thread(self.store.release_check_write_guard, guard)

    @asynccontextmanager
    async def _authority_publish_guard(self, installation_id: int) -> AsyncIterator[None]:
        """Order final publications against accepted installation authority changes."""
        acquisition = asyncio.create_task(
            asyncio.to_thread(
                self.store.acquire_authority_guard,
                installation_id,
                shared=True,
                timeout_seconds=30.0,
            )
        )
        try:
            guard = await asyncio.shield(acquisition)
        except asyncio.CancelledError:
            cleanup = asyncio.create_task(self._release_abandoned_guard(acquisition))
            self._cleanup_tasks.add(cleanup)
            cleanup.add_done_callback(self._cleanup_tasks.discard)
            raise
        if guard is None:
            raise GitHubError("timed out waiting for the authority publication guard")
        try:
            yield
        finally:
            await asyncio.to_thread(self.store.release_check_write_guard, guard)

    async def _release_abandoned_guard(
        self, acquisition: asyncio.Task[CheckWriteGuard | None]
    ) -> None:
        try:
            guard = await acquisition
            if guard is not None:
                await asyncio.to_thread(self.store.release_check_write_guard, guard)
        except Exception:
            log.exception("abandoned_check_writer_cleanup_failed")

    async def _restore_blocking_after_uncertain_completion(
        self,
        job: ClaimedJob,
        head_sha: str,
        details_url: str | None,
        external_id: str,
    ) -> bool:
        """Best-effort reset a completed check without releasing its writer guard.

        The caller holds the head writer guard. Shielding keeps cancellation
        from interrupting the GitHub request and exposing a completed result
        before that guard is released.
        """
        reset = asyncio.create_task(
            self.github.upsert_check_run(
                job.installation_id,
                job.repository_full_name,
                head_sha,
                self.settings.check_name,
                status="in_progress",
                title="Re-evaluating CODEOWNER approvals",
                summary=(
                    "Completed check publication could not be verified; approval is blocked "
                    "pending re-evaluation."
                ),
                details_url=details_url,
                external_id=external_id,
            ),
            name=f"restore-blocking-check-{job.id}",
        )
        cancellation: asyncio.CancelledError | None = None
        while not reset.done():
            try:
                await asyncio.shield(reset)
            except asyncio.CancelledError as error:
                # Preserve shutdown, but finish this bounded GitHub request
                # while the advisory guard still orders every check writer.
                cancellation = error
            except Exception:
                # Read and log the task exception below.
                break
        succeeded = True
        try:
            reset.result()
        except asyncio.CancelledError:
            succeeded = False
            log.warning(
                "completed_check_blocking_reset_cancelled",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
                head_sha=head_sha,
            )
        except Exception as error:
            succeeded = False
            log.exception(
                "completed_check_blocking_reset_failed",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
                head_sha=head_sha,
                error_type=type(error).__name__,
            )
        if cancellation is not None:
            raise cancellation
        return succeeded

    async def _find_codeowners(
        self, installation_id: int, repository: str, base_sha: str
    ) -> tuple[str, str] | None:
        for path in CODEOWNERS_LOCATIONS:
            content = await self.github.get_file_text(
                installation_id,
                repository,
                path,
                ref=base_sha,
                max_bytes=MAX_CODEOWNERS_BYTES,
            )
            if content is not None:
                return path, content
        return None

    async def _load_organization_policy(
        self,
        installation_id: int,
        repository: str,
    ) -> OrganizationPolicy:
        owner = repository.split("/", 1)[0]
        organization_repository = f"{owner}/{self.settings.org_config_repository}"
        org_text = await self.github.get_file_text(
            installation_id,
            organization_repository,
            self.settings.policy_path,
        )
        return OrganizationPolicy() if org_text is None else OrganizationPolicy.from_toml(org_text)

    async def _repository_policy_text(
        self,
        installation_id: int,
        repository: str,
        base_sha: str,
    ) -> str | None:
        return await self.github.get_file_text(
            installation_id,
            repository,
            self.settings.policy_path,
            ref=base_sha,
        )

    @staticmethod
    def _changed_files(values: list[dict[str, Any]]) -> tuple[ChangedFile, ...]:
        files: list[ChangedFile] = []
        for value in values:
            status = _required_string(value.get("status"), "pull file status")
            previous = value.get("previous_filename")
            files.append(
                ChangedFile(
                    path=_required_string(value.get("filename"), "pull file filename"),
                    status=ChangedFileStatus(status),
                    previous_path=previous if isinstance(previous, str) else None,
                )
            )
        return tuple(files)

    async def _human_team_aliases(
        self,
        installation_id: int,
        repository: str,
        repository_owner: str,
        login: str,
        document: CodeownersDocument,
    ) -> frozenset[str]:
        team_owners = {
            owner
            for rule in document.rules
            for owner in rule.owners
            if "/" in owner
            and owner.split("/", 1)[0].removeprefix("@").lower() == repository_owner.lower()
        }
        semaphore = asyncio.Semaphore(10)

        async def is_member(owner: str) -> bool:
            async with semaphore:
                team_slug = owner.split("/", 1)[1]
                member, can_own = await asyncio.gather(
                    self.github.team_member(
                        installation_id,
                        repository_owner,
                        team_slug,
                        login,
                    ),
                    self.github.team_can_own_repository(
                        installation_id,
                        repository_owner,
                        team_slug,
                        repository,
                    ),
                )
                return member and can_own

        membership = await asyncio.gather(*(is_member(owner) for owner in sorted(team_owners)))
        return frozenset(
            owner
            for owner, is_member in zip(sorted(team_owners), membership, strict=True)
            if is_member
        )

    async def _validated_apps(
        self,
        installation_id: int,
        organization: OrganizationPolicy,
        bot_user_ids: frozenset[int],
    ) -> dict[int, tuple[str, EnrolledApplication, int, str]]:
        """Bind configured bot users to independently fetched App identities."""
        validated: dict[int, tuple[str, EnrolledApplication, int, str]] = {}
        for alias, app in organization.apps.items():
            if app.bot_user_id not in bot_user_ids:
                continue
            metadata = await self.github.get_app(installation_id, app.slug)
            observed_id = metadata.get("id")
            observed_slug = metadata.get("slug")
            if observed_id != app.app_id or str(observed_slug).lower() != app.slug:
                log.warning(
                    "enrolled_app_identity_mismatch",
                    alias=alias,
                    configured_app_id=app.app_id,
                    observed_app_id=observed_id,
                    configured_slug=app.slug,
                    observed_slug=observed_slug,
                )
                continue
            validated[app.bot_user_id] = (alias, app, int(observed_id), str(observed_slug))
        return validated

    async def _reviews(
        self,
        installation_id: int,
        repository: str,
        values: list[dict[str, Any]],
        organization: OrganizationPolicy,
        document: CodeownersDocument,
        head_sha: str,
    ) -> tuple[PullRequestReview, ...]:
        reviews: list[PullRequestReview] = []
        repository_owner = repository.split("/", 1)[0]
        valid_states = {state.value for state in ReviewState}
        latest: dict[tuple[str, int], tuple[datetime, int, dict[str, Any]]] = {}
        for value in values:
            state_value = value.get("state")
            if state_value not in valid_states:
                msg = f"GitHub returned unknown review state {state_value!r}"
                raise GitHubError(msg)
            if state_value in {ReviewState.COMMENTED.value, ReviewState.PENDING.value}:
                continue
            user = value.get("user")
            if not isinstance(user, dict):
                raise GitHubError("opinionated review omitted its user")
            user_id = user.get("id")
            login = user.get("login")
            review_id = value.get("id")
            submitted_at = value.get("submitted_at")
            if (
                isinstance(user_id, bool)
                or not isinstance(user_id, int)
                or not isinstance(login, str)
                or isinstance(review_id, bool)
                or not isinstance(review_id, int)
                or not isinstance(submitted_at, str)
            ):
                raise GitHubError("opinionated review omitted actor, ID, or submission time")
            actor_type = user.get("type")
            if actor_type not in {"Bot", "User"}:
                msg = f"opinionated review has unsupported actor type {actor_type!r}"
                raise GitHubError(msg)
            try:
                submitted = datetime.fromisoformat(submitted_at.replace("Z", "+00:00"))
            except ValueError as error:
                raise GitHubError("opinionated review has an invalid submission time") from error
            key = (str(actor_type), user_id)
            previous = latest.get(key)
            if previous is None or (submitted, review_id) > (previous[0], previous[1]):
                latest[key] = (submitted, review_id, value)

        current = [
            value
            for _, _, value in latest.values()
            if value.get("state") == ReviewState.APPROVED.value
            and value.get("commit_id") == head_sha
        ]
        team_owners = {
            owner
            for rule in document.rules
            for owner in rule.owners
            if "/" in owner
            and owner.split("/", 1)[0].removeprefix("@").lower() == repository_owner.lower()
        }
        human_approvals = sum(
            1
            for value in current
            if isinstance(value.get("user"), dict) and value["user"].get("type") == "User"
        )
        if human_approvals * len(team_owners) > MAX_TEAM_MEMBERSHIP_LOOKUPS:
            raise EvidenceLimitError(
                "current approvals and CODEOWNERS teams exceed the membership lookup budget"
            )
        current_bot_ids = frozenset(
            int(value["user"]["id"])
            for value in current
            if isinstance(value.get("user"), dict) and value["user"].get("type") == "Bot"
        )
        validated_apps = (
            await self._validated_apps(installation_id, organization, current_bot_ids)
            if current_bot_ids
            else {}
        )
        for value in current:
            user = _required_object(value.get("user"), "opinionated review user")
            user_id = int(value["user"]["id"])
            login = str(user["login"])
            review_id = int(value["id"])
            submitted_at = str(value["submitted_at"])
            if user.get("type") == "Bot":
                enrolled = validated_apps.get(user_id)
                if enrolled is None:
                    continue
                _, app, observed_id, observed_slug = enrolled
                if login.lower() != f"{app.slug}[bot]":
                    log.warning(
                        "enrolled_app_bot_login_mismatch",
                        configured_slug=app.slug,
                        bot_user_id=user_id,
                        observed_login=login,
                    )
                    continue
                actor = ReviewActor(
                    kind=ActorKind.APPLICATION,
                    login=login,
                    user_id=user_id,
                    app_id=observed_id,
                    app_slug=observed_slug,
                )
            elif user.get("type") == "User":
                direct_owner_eligible, aliases = await asyncio.gather(
                    self.github.user_can_own_repository(
                        installation_id,
                        repository,
                        login,
                    ),
                    self._human_team_aliases(
                        installation_id,
                        repository,
                        repository_owner,
                        login,
                        document,
                    ),
                )
                actor = ReviewActor(
                    kind=ActorKind.HUMAN,
                    login=login,
                    user_id=user_id,
                    owner_aliases=aliases,
                    direct_owner_eligible=direct_owner_eligible,
                )
            reviews.append(
                PullRequestReview(
                    review_id=review_id,
                    actor=actor,
                    state=ReviewState.APPROVED,
                    commit_sha=head_sha,
                    submitted_at=datetime.fromisoformat(submitted_at.replace("Z", "+00:00")),
                )
            )
        return tuple(reviews)

    async def _evaluate_current(
        self,
        job: ClaimedJob,
        pull: dict[str, Any],
        head_sha: str,
        base_sha: str,
        expected_changed_files: int,
        repository_policy: RepositoryPolicy,
    ) -> EvaluationResult:
        if not repository_policy.enabled:
            return evaluate(
                EvaluationInput(
                    head_sha=head_sha,
                    codeowners_text="",
                    changed_files=(),
                    organization_policy=OrganizationPolicy(),
                    repository_policy=repository_policy,
                )
            )

        if expected_changed_files >= MAX_PULL_FILES:
            return _failure(
                "pull_request_too_large",
                f"pull request has at least GitHub's {MAX_PULL_FILES:,}-file API limit",
            )

        try:
            organization = await self._load_organization_policy(
                job.installation_id,
                job.repository_full_name,
            )
        except (ValidationError, ValueError) as error:
            return _failure("invalid_policy", str(error))

        codeowners = await self._find_codeowners(
            job.installation_id, job.repository_full_name, base_sha
        )
        if codeowners is None:
            return _failure(
                "codeowners_missing",
                "enabled repository has no CODEOWNERS file in .github/, the root, or docs/",
            )
        _, codeowners_text = codeowners
        try:
            document = parse_codeowners(codeowners_text)
        except ValueError:
            # The pure evaluator renders the parser's detailed line errors.
            document = CodeownersDocument(())

        changed_path_upper_bound = expected_changed_files * 2
        policy_pattern_count = (
            sum(len(delegation.paths) for delegation in repository_policy.delegations)
            + len(organization.guardrails.non_delegable_paths)
            + (0 if self.settings.allow_insecure_changes else len(BUILTIN_NON_DELEGABLE_PATHS) + 1)
        )
        if (
            changed_path_upper_bound * (len(document.rules) + policy_pattern_count)
            > MAX_PATH_MATCH_OPERATIONS
        ):
            return _failure(
                "evaluation_complexity_exceeded",
                "changed paths and policy patterns exceed the bounded evaluation budget",
            )

        files_task = self.github.get_pull_files(
            job.installation_id, job.repository_full_name, job.pull_number
        )
        reviews_task = self.github.get_reviews(
            job.installation_id, job.repository_full_name, job.pull_number
        )
        errors_task = self.github.get_codeowners_errors(
            job.installation_id, job.repository_full_name, base_sha
        )
        try:
            file_values, review_values, github_errors = await asyncio.gather(
                files_task, reviews_task, errors_task
            )
        except PullRequestTooLargeError as error:
            return _failure("evidence_limit_exceeded", str(error))
        if len(file_values) != expected_changed_files:
            return _failure(
                "incomplete_changed_files",
                "GitHub's pull files response did not match pull_request.changed_files",
            )
        if github_errors:
            messages = []
            for item in github_errors:
                line = item.get("line")
                message = item.get("message", "invalid CODEOWNERS entry")
                prefix = f"line {line}: " if isinstance(line, int) else ""
                messages.append(prefix + str(message))
            return _failure("github_codeowners_error", "; ".join(messages))

        try:
            reviews = await self._reviews(
                job.installation_id,
                job.repository_full_name,
                review_values,
                organization,
                document,
                head_sha,
            )
            changed_files = self._changed_files(file_values)
        except EvidenceLimitError as error:
            return _failure("evidence_limit_exceeded", str(error))
        except (ValidationError, ValueError) as error:
            return _failure("malformed_github_evidence", str(error))
        labels = _label_names(pull)
        return evaluate(
            EvaluationInput(
                head_sha=head_sha,
                codeowners_text=codeowners_text,
                changed_files=changed_files,
                reviews=reviews,
                labels=labels,
                organization_policy=organization,
                repository_policy=repository_policy,
                options=EvaluationOptions(
                    exact_head_reviews=True,
                    allow_insecure_changes=self.settings.allow_insecure_changes,
                    repository_policy_path=self.settings.policy_path,
                ),
            )
        )

    async def invalidate_for_trigger(
        self,
        job: JobRequest,
        shared_head_generation: int | None = None,
    ) -> bool:
        """Best-effort synchronous reset without weakening durable recovery."""
        if self.settings.is_organization_config_repository(job.repository_full_name):
            return False
        pull = await self.github.get_pull(
            job.installation_id,
            job.repository_full_name,
            job.pull_number,
        )
        head = _required_object(pull.get("head"), "pull_request.head")
        base = _required_object(pull.get("base"), "pull_request.base")
        head_sha = _required_string(head.get("sha"), "pull_request.head.sha")
        base_sha = _required_string(base.get("sha"), "pull_request.base.sha")
        pull_state = _required_string(pull.get("state"), "pull_request.state")
        if pull_state not in {"open", "closed"}:
            raise GitHubError(f"GitHub returned unknown pull request state {pull_state!r}")

        if pull_state == "open" and job.head_sha_hint is not None and job.head_sha_hint != head_sha:
            # The exact webhook head remains durable in its own invalidation
            # row. Independently fence the live head instead of replacing that
            # recovery with a latest-PR-only queue row.
            await asyncio.to_thread(
                self.store.enqueue_shared_head_trigger,
                JobRequest(
                    installation_id=job.installation_id,
                    repository_full_name=job.repository_full_name,
                    pull_number=job.pull_number,
                    reason="head_changed_before_fast_invalidation",
                    head_sha_hint=head_sha,
                ),
            )

        if shared_head_generation is not None:
            accepted_head = validate_head_sha(job.head_sha_hint or "")
            async with self._check_write_guard(job.installation_id, accepted_head):
                if not await asyncio.to_thread(
                    self.store.shared_head_invalidation_is_pending,
                    job.installation_id,
                    job.repository_full_name,
                    accepted_head,
                    shared_head_generation,
                ):
                    return False
                check_run_id = await self.github.existing_check_run_id(
                    job.installation_id,
                    job.repository_full_name,
                    accepted_head,
                    self.settings.check_name,
                )
                if check_run_id is None:
                    if pull_state != "open" or head_sha != accepted_head:
                        return False
                    repository_text = await self._repository_policy_text(
                        job.installation_id,
                        job.repository_full_name,
                        base_sha,
                    )
                    if repository_text is None:
                        return False
                # The GitHub lookup can outlive this delivery generation. Do
                # not let an old handler reset a newer completed result.
                if not await asyncio.to_thread(
                    self.store.shared_head_invalidation_is_pending,
                    job.installation_id,
                    job.repository_full_name,
                    accepted_head,
                    shared_head_generation,
                ):
                    return False
                details_url = (
                    pull.get("html_url") if isinstance(pull.get("html_url"), str) else None
                )
                if check_run_id is None:
                    await self.github.upsert_check_run(
                        job.installation_id,
                        job.repository_full_name,
                        accepted_head,
                        self.settings.check_name,
                        status="in_progress",
                        title="Re-evaluating CODEOWNER approvals",
                        summary=(
                            "New review or pull-request evidence arrived; approval is "
                            "blocked pending re-evaluation."
                        ),
                        details_url=details_url,
                        external_id=f"{job.repository_full_name}@{accepted_head}",
                    )
                else:
                    await self.github.reset_check_run(
                        job.installation_id,
                        job.repository_full_name,
                        check_run_id,
                        self.settings.check_name,
                        title="Re-evaluating CODEOWNER approvals",
                        summary=(
                            "New review or pull-request evidence arrived; approval is "
                            "blocked pending re-evaluation."
                        ),
                        details_url=details_url,
                        external_id=f"{job.repository_full_name}@{accepted_head}",
                    )
            return True

        if pull_state == "closed":
            return False

        managed_check = await self.github.has_check_run(
            job.installation_id,
            job.repository_full_name,
            head_sha,
            self.settings.check_name,
        )
        if not managed_check:
            repository_text = await self._repository_policy_text(
                job.installation_id,
                job.repository_full_name,
                base_sha,
            )
            if repository_text is None:
                return False

        details_url = pull.get("html_url") if isinstance(pull.get("html_url"), str) else None
        async with self._check_write_guard(job.installation_id, head_sha):
            await self.github.upsert_check_run(
                job.installation_id,
                job.repository_full_name,
                head_sha,
                self.settings.check_name,
                status="in_progress",
                title="Re-evaluating CODEOWNER approvals",
                summary=(
                    "New review or pull-request evidence arrived; approval is blocked pending "
                    "re-evaluation."
                ),
                details_url=details_url,
                external_id=f"{job.repository_full_name}#{job.pull_number}@{head_sha}",
            )
        return True

    async def invalidate_shared_head(
        self,
        job: ClaimedSharedHeadInvalidation,
        lease_lost: asyncio.Event,
    ) -> None:
        """Reset and fan out one exact durable commit generation."""

        async def require_current_claim() -> None:
            if lease_lost.is_set() or not await asyncio.to_thread(
                self.store.is_current_shared_head_invalidation,
                job,
            ):
                raise SharedHeadLeaseLostError(
                    "shared-head invalidation lease or generation is no longer current"
                )

        async with self._check_write_guard(job.installation_id, job.head_sha):
            await require_current_claim()
            check_run_id = await self.github.existing_check_run_id(
                job.installation_id,
                job.repository_full_name,
                job.head_sha,
                self.settings.check_name,
            )
            # Recheck after the GitHub read and immediately before the only
            # mutating request. An expired lease must never reset a result
            # published by its replacement.
            await require_current_claim()
            if check_run_id is not None:
                await self.github.reset_check_run(
                    job.installation_id,
                    job.repository_full_name,
                    check_run_id,
                    self.settings.check_name,
                    title="Re-evaluating CODEOWNER approvals",
                    summary=(
                        "Accepted evidence for this commit is awaiting durable re-evaluation."
                    ),
                    external_id=f"{job.repository_full_name}@{job.head_sha}",
                )

        current_associated = await self._current_associated_pulls(
            job.installation_id,
            job.repository_full_name,
            job.head_sha,
            before_github_read=require_current_claim,
        )
        for number_value, (state_value, associated_sha) in current_associated.items():
            if state_value != "open" or associated_sha != job.head_sha:
                continue
            await require_current_claim()
            current = await asyncio.to_thread(
                self.store.enqueue_for_shared_head_generation,
                JobRequest(
                    installation_id=job.installation_id,
                    repository_full_name=job.repository_full_name,
                    pull_number=number_value,
                    reason="shared_head_invalidation",
                    head_sha_hint=job.head_sha,
                ),
                job.generation,
            )
            if not current:
                raise SharedHeadLeaseLostError(
                    "shared-head generation changed during pull-request fan-out"
                )
        await require_current_claim()

    async def _head_is_unique_to_pull(self, job: ClaimedJob, head_sha: str) -> bool:
        current_associated = await self._current_associated_pulls(
            job.installation_id,
            job.repository_full_name,
            head_sha,
        )
        open_head_pulls = {
            number_value
            for number_value, (state_value, associated_sha) in current_associated.items()
            if state_value == "open" and associated_sha == head_sha
        }
        return open_head_pulls == {job.pull_number}

    async def evaluate_job(self, job: ClaimedJob) -> None:
        """Evaluate a leased job and publish only against stable PR revisions."""
        if self.settings.is_organization_config_repository(job.repository_full_name):
            return
        with EVALUATION_SECONDS.time():
            pull = await self.github.get_pull(
                job.installation_id, job.repository_full_name, job.pull_number
            )
            head = _required_object(pull.get("head"), "pull_request.head")
            base = _required_object(pull.get("base"), "pull_request.base")
            base_repository = _required_object(base.get("repo"), "pull_request.base.repo")
            canonical_repository = normalize_repository_full_name(
                _required_string(
                    base_repository.get("full_name"), "pull_request.base.repo.full_name"
                )
            )
            if canonical_repository != job.repository_full_name:
                log.info(
                    "stale_repository_alias_discarded",
                    queued_repository=job.repository_full_name,
                    canonical_repository=canonical_repository,
                    pull_number=job.pull_number,
                )
                return
            head_sha = _required_string(head.get("sha"), "pull_request.head.sha")
            base_sha = _required_string(base.get("sha"), "pull_request.base.sha")
            base_ref = _required_string(base.get("ref"), "pull_request.base.ref")
            pull_state = _required_string(pull.get("state"), "pull_request.state")
            if pull_state not in {"open", "closed"}:
                raise GitHubError(f"GitHub returned unknown pull request state {pull_state!r}")
            if pull_state == "closed":
                return

            if job.head_sha_hint is not None and job.head_sha_hint != head_sha:
                await asyncio.to_thread(
                    self.store.enqueue_shared_head_trigger,
                    JobRequest(
                        installation_id=job.installation_id,
                        repository_full_name=job.repository_full_name,
                        pull_number=job.pull_number,
                        reason="head_changed_before_evaluation",
                        head_sha_hint=head_sha,
                    ),
                )
                return
            bound_job = await asyncio.to_thread(self.store.bind_claim_to_head, job, head_sha)
            if bound_job is None:
                return
            job = bound_job

            managed_check = await self.github.has_check_run(
                job.installation_id,
                job.repository_full_name,
                head_sha,
                self.settings.check_name,
            )
            repository_text: str | None = None
            if not managed_check:
                repository_text = await self._repository_policy_text(
                    job.installation_id,
                    job.repository_full_name,
                    base_sha,
                )
                if repository_text is None:
                    return
            details_url = pull.get("html_url") if isinstance(pull.get("html_url"), str) else None
            external_id = f"{job.repository_full_name}#{job.pull_number}@{head_sha}"

            # Revoke any previous success before collecting mutable review and
            # label evidence. A retry remains blocking instead of leaving a
            # stale success visible while GitHub or the database is unavailable.
            async with self._check_write_guard(job.installation_id, head_sha):
                if not await asyncio.to_thread(self.store.is_current_claim, job):
                    return
                if not await asyncio.to_thread(
                    self.store.shared_head_generation_is_current,
                    job,
                    head_sha,
                ):
                    return
                await self.github.upsert_check_run(
                    job.installation_id,
                    job.repository_full_name,
                    head_sha,
                    self.settings.check_name,
                    status="in_progress",
                    title="Evaluating CODEOWNER approvals",
                    summary=(
                        "A current evaluation is in progress; approval is blocked until it "
                        "completes."
                    ),
                    details_url=details_url,
                    external_id=external_id,
                )
            if job.last_delivery_id is not None:
                await asyncio.to_thread(self.store.mark_delivery_invalidated, job.last_delivery_id)
            if not await asyncio.to_thread(
                self.store.shared_head_generation_is_publishable,
                job,
                head_sha,
            ):
                raise SharedHeadInvalidationPendingError(
                    "exact-head invalidation must complete before evaluation"
                )
            if await asyncio.to_thread(self.store.has_blocking_authority, job, base_ref):
                raise AuthorityChangePendingError(
                    "accepted authority change is still awaiting durable fan-out"
                )

            if managed_check:
                # Fetch only after revoking a prior success. Oversized,
                # malformed, or unavailable policy content must leave the
                # required check blocking while the durable job retries.
                repository_text = await self._repository_policy_text(
                    job.installation_id,
                    job.repository_full_name,
                    base_sha,
                )
            expected_changed_files = _required_nonnegative_int(
                pull.get("changed_files"), "pull_request.changed_files"
            )

            labels = _label_names(pull)
            try:
                repository_policy = (
                    RepositoryPolicy()
                    if repository_text is None
                    else RepositoryPolicy.from_toml(repository_text)
                )
            except (ValidationError, ValueError) as error:
                result = _failure("invalid_policy", str(error))
            else:
                result = await self._evaluate_current(
                    job,
                    pull,
                    head_sha,
                    base_sha,
                    expected_changed_files,
                    repository_policy,
                )

            # Close the check-after-race window: evidence collected for an old
            # head or base is never published as current.
            current = await self.github.get_pull(
                job.installation_id, job.repository_full_name, job.pull_number
            )
            current_head = _required_object(current.get("head"), "pull_request.head")
            current_base = _required_object(current.get("base"), "pull_request.base")
            current_head_sha = _required_string(current_head.get("sha"), "pull_request.head.sha")
            current_base_sha = _required_string(current_base.get("sha"), "pull_request.base.sha")
            current_base_ref = _required_string(current_base.get("ref"), "pull_request.base.ref")
            current_state = _required_string(current.get("state"), "pull_request.state")
            if current_state not in {"open", "closed"}:
                raise GitHubError(f"GitHub returned unknown pull request state {current_state!r}")
            if current_state == "closed":
                return
            if (
                current_head_sha != head_sha
                or current_base_sha != base_sha
                or current_base_ref != base_ref
                or _required_nonnegative_int(
                    current.get("changed_files"), "pull_request.changed_files"
                )
                != expected_changed_files
                or _label_names(current) != labels
            ):
                await asyncio.to_thread(
                    self.store.enqueue_shared_head_trigger,
                    JobRequest(
                        installation_id=job.installation_id,
                        repository_full_name=job.repository_full_name,
                        pull_number=job.pull_number,
                        reason="pull_request_changed_during_evaluation",
                        head_sha_hint=current_head_sha,
                    ),
                )
                return

            # A review, label, or policy trigger can arrive without changing
            # either SHA. Never publish evidence collected before that trigger.
            title = {
                EvaluationConclusion.SUCCESS: "CODEOWNER approval requirement satisfied",
                EvaluationConclusion.FAILURE: "CODEOWNER approval required",
            }[result.conclusion]
            warning = ""
            if self.settings.allow_insecure_changes:
                warning = (
                    "\n\n> **Warning:** `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` "
                    "disabled built-in non-delegable paths. Organization guardrails still apply."
                )
            # A shared installation authority guard lets normal evaluations
            # publish concurrently while ordering every final result against
            # the exclusive guard used by authority webhook acceptance.
            async with self._authority_publish_guard(job.installation_id):
                async with self._check_write_guard(job.installation_id, head_sha):
                    # Check the generation while holding the same cross-process
                    # writer lock used by webhook revocation. If a trigger arrived
                    # before this lock, stale evidence is never published. If it
                    # arrives while this lock is held, its revocation PATCH is
                    # ordered after this completion, even if this process dies.
                    if not await asyncio.to_thread(self.store.is_current_claim, job):
                        return
                    if not await asyncio.to_thread(
                        self.store.shared_head_generation_is_publishable,
                        job,
                        head_sha,
                    ):
                        return
                    if await asyncio.to_thread(self.store.has_blocking_authority, job, base_ref):
                        raise AuthorityChangePendingError(
                            "accepted authority change arrived during evaluation"
                        )
                    if (
                        result.conclusion is EvaluationConclusion.SUCCESS
                        and not await self._head_is_unique_to_pull(job, head_sha)
                    ):
                        result = _failure(
                            "shared_head_commit",
                            "the head commit is shared by multiple open pull requests; push a "
                            "distinct commit before approval",
                        )
                        title = "CODEOWNER approval required"
                    if not await asyncio.to_thread(
                        self.store.shared_head_generation_is_publishable,
                        job,
                        head_sha,
                    ):
                        return
                    # Authoritative shared-head discovery may require many
                    # GitHub reads. Fence a lease owner that expired or was
                    # replaced while those reads were in flight.
                    if not await asyncio.to_thread(self.store.is_current_claim, job):
                        return
                    try:
                        await self.github.upsert_check_run(
                            job.installation_id,
                            job.repository_full_name,
                            head_sha,
                            self.settings.check_name,
                            status="completed",
                            conclusion=result.conclusion.value,
                            title=title,
                            summary=result.summary + warning,
                            text=result.check_output(),
                            details_url=details_url,
                            external_id=external_id,
                        )
                    except asyncio.CancelledError:
                        await self._restore_blocking_after_uncertain_completion(
                            job,
                            head_sha,
                            details_url,
                            external_id,
                        )
                        raise
                    except Exception:
                        await self._restore_blocking_after_uncertain_completion(
                            job,
                            head_sha,
                            details_url,
                            external_id,
                        )
                        raise
                    try:
                        claim_current = await asyncio.to_thread(
                            self.store.is_current_claim,
                            job,
                        )
                        shared_head_current = await asyncio.to_thread(
                            self.store.shared_head_generation_is_publishable,
                            job,
                            head_sha,
                        )
                    except asyncio.CancelledError:
                        await self._restore_blocking_after_uncertain_completion(
                            job,
                            head_sha,
                            details_url,
                            external_id,
                        )
                        raise
                    except Exception:
                        await self._restore_blocking_after_uncertain_completion(
                            job,
                            head_sha,
                            details_url,
                            external_id,
                        )
                        raise
                    if not claim_current or not shared_head_current:
                        # A different pull request can accept a direct trigger
                        # for this commit, or this evaluation's lease can be
                        # replaced, while the GitHub request is in flight.
                        # Restore a blocking result before releasing the shared
                        # head writer.
                        await self._restore_blocking_after_uncertain_completion(
                            job,
                            head_sha,
                            details_url,
                            external_id,
                        )
                        return

                # If a trigger committed while the completion request was in
                # flight, restore a blocking state ourselves. The shared writer
                # guard prevents this reset from overwriting a newer generation
                # that has already completed and removed its queue row.
                superseded = await asyncio.to_thread(self.store.has_superseding_job, job)
                authority_pending = await asyncio.to_thread(
                    self.store.has_blocking_authority, job, base_ref
                )
                if superseded or authority_pending:
                    async with self._check_write_guard(job.installation_id, head_sha):
                        superseded = await asyncio.to_thread(self.store.has_superseding_job, job)
                        authority_pending = await asyncio.to_thread(
                            self.store.has_blocking_authority, job, base_ref
                        )
                        if superseded or authority_pending:
                            await self.github.upsert_check_run(
                                job.installation_id,
                                job.repository_full_name,
                                head_sha,
                                self.settings.check_name,
                                status="in_progress",
                                title="Re-evaluating CODEOWNER approvals",
                                summary=(
                                    "New review, pull-request, or authority evidence arrived; "
                                    "approval is blocked pending re-evaluation."
                                ),
                                details_url=details_url,
                                external_id=external_id,
                            )
                            if authority_pending:
                                raise AuthorityChangePendingError(
                                    "accepted authority change arrived during check publication"
                                )
                            return

            await asyncio.to_thread(
                self.store.record_audit,
                job.repository_full_name,
                job.pull_number,
                head_sha,
                result.conclusion.value,
                {
                    **result.model_dump(mode="json"),
                    "trigger": {
                        "reason": job.reason,
                        "delivery_id": job.last_delivery_id,
                    },
                },
            )
            EVALUATIONS.labels(result.conclusion.value).inc()


class Worker:
    """Lease and execute durable jobs until stopped."""

    def __init__(
        self,
        settings: Settings,
        store: QueueStore,
        evaluator: EvaluationService,
        owner: str,
    ) -> None:
        self.settings = settings
        self.store = store
        self.evaluator = evaluator
        self.owner = owner

    async def _renew_shared_head_lease(
        self,
        job: ClaimedSharedHeadInvalidation,
        done: asyncio.Event,
        lost: asyncio.Event,
    ) -> None:
        """Keep exact-head work owned without reviving an expired lease."""
        interval = max(1.0, self.settings.worker_lease_seconds / 3)
        while not done.is_set():
            try:
                await asyncio.wait_for(done.wait(), interval)
                return
            except TimeoutError:
                pass
            try:
                renewed = await asyncio.to_thread(
                    self.store.renew_shared_head_invalidation,
                    job,
                    self.settings.worker_lease_seconds,
                )
            except Exception:
                log.exception(
                    "shared_head_invalidation_lease_renewal_failed",
                    installation_id=job.installation_id,
                    repository=job.repository_full_name,
                )
                lost.set()
                return
            if not renewed:
                log.warning(
                    "shared_head_invalidation_lease_lost",
                    installation_id=job.installation_id,
                    repository=job.repository_full_name,
                    generation=job.generation,
                )
                lost.set()
                return

    async def _process_shared_head(
        self,
        job: ClaimedSharedHeadInvalidation,
    ) -> None:
        done = asyncio.Event()
        lost = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._renew_shared_head_lease(job, done, lost),
            name=(f"shared-head-lease-{job.installation_id}-{job.head_sha[:12]}-{job.generation}"),
        )
        try:
            await self.evaluator.invalidate_shared_head(job, lost)
        except SharedHeadLeaseLostError:
            SHARED_HEAD_INVALIDATIONS.labels("superseded").inc()
            log.info(
                "shared_head_invalidation_superseded",
                installation_id=job.installation_id,
                repository=job.repository_full_name,
                generation=job.generation,
            )
        except GitHubRateLimitError as error:
            updated = await asyncio.to_thread(
                self.store.defer_shared_head_invalidation,
                job,
                str(error),
                error.retry_after_seconds,
            )
            SHARED_HEAD_INVALIDATIONS.labels("rate_limited" if updated else "superseded").inc()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            log.exception(
                "shared_head_invalidation_failed",
                installation_id=job.installation_id,
                repository=job.repository_full_name,
                generation=job.generation,
                attempt=job.attempts,
            )
            updated = await asyncio.to_thread(
                self.store.fail_shared_head_invalidation,
                job,
                str(error),
                self.settings.worker_retry_max_seconds,
            )
            SHARED_HEAD_INVALIDATIONS.labels("failed" if updated else "superseded").inc()
        else:
            completed = False
            if not lost.is_set():
                completed = await asyncio.to_thread(
                    self.store.complete_shared_head_invalidation,
                    job,
                )
            SHARED_HEAD_INVALIDATIONS.labels("completed" if completed else "superseded").inc()
            if completed:
                log.info(
                    "shared_head_invalidation_completed",
                    installation_id=job.installation_id,
                    repository=job.repository_full_name,
                    generation=job.generation,
                )
        finally:
            done.set()
            await asyncio.gather(heartbeat)

    async def _renew_lease(self, job: ClaimedJob, done: asyncio.Event) -> None:
        """Keep a live evaluation fenced to this worker until it finishes."""
        interval = max(1.0, self.settings.worker_lease_seconds / 3)
        while not done.is_set():
            try:
                await asyncio.wait_for(done.wait(), interval)
                return
            except TimeoutError:
                pass
            try:
                renewed = await asyncio.to_thread(
                    self.store.renew_claim,
                    job,
                    self.settings.worker_lease_seconds,
                )
            except Exception:
                log.exception(
                    "evaluation_lease_renewal_failed",
                    repository=job.repository_full_name,
                    pull_number=job.pull_number,
                )
                return
            if not renewed:
                log.warning(
                    "evaluation_lease_lost",
                    repository=job.repository_full_name,
                    pull_number=job.pull_number,
                    generation=job.generation,
                )
                return

    async def _process(self, job: ClaimedJob) -> None:
        done = asyncio.Event()
        heartbeat = asyncio.create_task(self._renew_lease(job, done), name=f"job-lease-{job.id}")
        try:
            await self.evaluator.evaluate_job(job)
        except GitHubRateLimitError as error:
            log.warning(
                "evaluation_rate_limited",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
                retry_after_seconds=error.retry_after_seconds,
            )
            await asyncio.to_thread(
                self.store.defer,
                job,
                self.owner,
                str(error),
                error.retry_after_seconds,
            )
        except AuthorityChangePendingError as error:
            log.info(
                "evaluation_deferred_for_authority",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
            )
            await asyncio.to_thread(
                self.store.defer,
                job,
                self.owner,
                str(error),
                max(5, int(self.settings.worker_poll_seconds * 10)),
            )
        except SharedHeadInvalidationPendingError as error:
            log.info(
                "evaluation_deferred_for_shared_head_invalidation",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
            )
            await asyncio.to_thread(
                self.store.defer,
                job,
                self.owner,
                str(error),
                max(1, int(self.settings.worker_poll_seconds * 2)),
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            log.exception(
                "evaluation_failed",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
                attempt=job.attempts,
                delivery_id=job.last_delivery_id,
            )
            await asyncio.to_thread(
                self.store.fail,
                job,
                self.owner,
                str(error),
                self.settings.worker_retry_max_seconds,
            )
        else:
            await asyncio.to_thread(self.store.complete, job, self.owner)
        finally:
            done.set()
            await asyncio.gather(heartbeat)

    async def _renew_authority_lease(self, job: ClaimedAuthorityJob, done: asyncio.Event) -> None:
        interval = max(1.0, self.settings.worker_lease_seconds / 3)
        while not done.is_set():
            try:
                await asyncio.wait_for(done.wait(), interval)
                return
            except TimeoutError:
                pass
            renewed = await asyncio.to_thread(
                self.store.renew_authority_claim,
                job,
                self.settings.worker_lease_seconds,
            )
            if not renewed:
                log.warning(
                    "authority_lease_lost",
                    installation_id=job.installation_id,
                    scope=job.repository_full_name or "installation",
                )
                return

    async def _execute_authority(self, job: ClaimedAuthorityJob) -> None:
        if job.repository_full_name is None:
            repositories = await self.evaluator.github.list_installation_repositories(
                job.installation_id
            )
            # Split broad work into independently retryable repository fences.
            # The installation row continues to block every publication until
            # all repository rows have been durably created.
            for repository in repositories:
                full_name = repository.get("full_name")
                if not isinstance(full_name, str) or repository.get("archived") is True:
                    continue
                if self.settings.is_organization_config_repository(full_name):
                    continue
                await asyncio.to_thread(
                    self.store.enqueue_authority,
                    AuthorityRequest(
                        installation_id=job.installation_id,
                        repository_full_name=full_name,
                        base_ref=None,
                        reason=job.reason,
                    ),
                )
            return

        requests: list[JobRequest] = []
        full_name = job.repository_full_name
        pulls = await self.evaluator.github.list_open_pulls(job.installation_id, full_name)
        for pull in pulls:
            number = pull.get("number")
            head = pull.get("head")
            base = pull.get("base")
            if not isinstance(number, int) or isinstance(number, bool):
                raise GitHubError("open pull response omitted its number")
            if not isinstance(head, dict) or not isinstance(head.get("sha"), str):
                raise GitHubError("open pull response omitted its head SHA")
            if job.base_ref is not None:
                if not isinstance(base, dict) or not isinstance(base.get("ref"), str):
                    raise GitHubError("open pull response omitted its base ref")
                if base["ref"] != job.base_ref:
                    continue
            request = JobRequest(
                installation_id=job.installation_id,
                repository_full_name=full_name,
                pull_number=number,
                reason=job.reason,
                head_sha_hint=str(head["sha"]),
            )
            await asyncio.to_thread(self.store.enqueue, request)
            requests.append(request)

        semaphore = asyncio.Semaphore(10)

        async def revoke(request: JobRequest) -> None:
            async with semaphore:
                try:
                    invalidated = await self.evaluator.invalidate_for_trigger(request)
                    if invalidated:
                        await asyncio.to_thread(self.store.enqueue, request)
                except GitHubRateLimitError:
                    raise
                except Exception:
                    # Every PR was durably queued before this best-effort
                    # fast path. Its evaluation will revoke before collecting
                    # mutable authority evidence.
                    log.exception(
                        "authority_fast_revocation_deferred",
                        repository=request.repository_full_name,
                        pull_number=request.pull_number,
                        reason=job.reason,
                    )

        for offset in range(0, len(requests), 100):
            outcomes = await asyncio.gather(
                *(revoke(request) for request in requests[offset : offset + 100]),
                return_exceptions=True,
            )
            rate_limits = [
                outcome for outcome in outcomes if isinstance(outcome, GitHubRateLimitError)
            ]
            if rate_limits:
                raise max(rate_limits, key=lambda error: error.retry_after_seconds)

    async def _process_authority(self, job: ClaimedAuthorityJob) -> None:
        done = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._renew_authority_lease(job, done),
            name=f"authority-lease-{job.id}",
        )
        try:
            await self._execute_authority(job)
        except GitHubRateLimitError as error:
            await asyncio.to_thread(
                self.store.defer_authority,
                job,
                self.owner,
                str(error),
                error.retry_after_seconds,
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            log.exception(
                "authority_fanout_failed",
                installation_id=job.installation_id,
                scope=job.repository_full_name or "installation",
                reason=job.reason,
            )
            await asyncio.to_thread(
                self.store.fail_authority,
                job,
                self.owner,
                str(error),
                self.settings.worker_retry_max_seconds,
            )
        else:
            await asyncio.to_thread(self.store.complete_authority, job, self.owner)
        finally:
            done.set()
            await asyncio.gather(heartbeat)

    async def run(self, stop: asyncio.Event) -> None:
        """Run the worker loop."""
        while not stop.is_set():
            try:
                QUEUE_DEPTH.set(await asyncio.to_thread(self.store.pending_count))
                DEAD_JOBS.set(await asyncio.to_thread(self.store.dead_count))
                SHARED_HEAD_INVALIDATION_DEPTH.set(
                    await asyncio.to_thread(self.store.pending_shared_head_invalidation_count)
                )
                shared_head_job = await asyncio.to_thread(
                    self.store.claim_shared_head_invalidation,
                    self.owner,
                    self.settings.worker_lease_seconds,
                )
                if shared_head_job is not None:
                    await self._process_shared_head(shared_head_job)
                    continue
                authority_job = await asyncio.to_thread(
                    self.store.claim_authority,
                    self.owner,
                    self.settings.worker_lease_seconds,
                )
                if authority_job is not None:
                    await self._process_authority(authority_job)
                    continue
                job = await asyncio.to_thread(
                    self.store.claim, self.owner, self.settings.worker_lease_seconds
                )
                if job is not None:
                    await self._process(job)
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                # A transient database failure must not silently kill the task
                # while process liveness continues to report healthy.
                log.exception("worker_loop_failed")

            if not stop.is_set():
                with suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), self.settings.worker_poll_seconds)


class Reconciler:
    """Periodically enqueue every open pull request to recover missed webhooks."""

    def __init__(
        self, settings: Settings, github: GitHubClient, store: QueueStore, owner: str
    ) -> None:
        self.settings = settings
        self.github = github
        self.store = store
        self.owner = owner

    async def _renew_lease(
        self,
        done: asyncio.Event,
        lost: asyncio.Event,
        lease_seconds: int,
    ) -> None:
        interval = max(1.0, lease_seconds / 3)
        while not done.is_set():
            try:
                await asyncio.wait_for(done.wait(), interval)
                return
            except TimeoutError:
                pass
            try:
                renewed = await asyncio.to_thread(
                    self.store.acquire_service_lease,
                    "open-pr-reconciler",
                    self.owner,
                    lease_seconds,
                )
            except Exception:
                log.exception("reconciliation_lease_renewal_failed")
                lost.set()
                return
            if not renewed:
                log.warning("reconciliation_lease_lost")
                lost.set()
                return

    async def reconcile_once(self) -> int:
        """Discover and enqueue open pull requests across installations."""
        lease_seconds = max(300, self.settings.reconcile_interval_seconds * 2)
        acquired = await asyncio.to_thread(
            self.store.acquire_service_lease, "open-pr-reconciler", self.owner, lease_seconds
        )
        if not acquired:
            return 0
        done = asyncio.Event()
        lost = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._renew_lease(done, lost, lease_seconds),
            name="reconciler-lease",
        )
        try:
            return await self._reconcile_owned(lost)
        finally:
            done.set()
            await asyncio.gather(heartbeat)

    async def _reconcile_owned(self, lost: asyncio.Event) -> int:
        """Perform one reconciliation while the heartbeat owns the lease."""
        retention_boundary = datetime.now(UTC) - timedelta(
            days=self.settings.webhook_delivery_retention_days
        )
        pruned = await asyncio.to_thread(self.store.prune_deliveries, retention_boundary)
        if pruned:
            log.info("webhook_deliveries_pruned", deliveries=pruned)
        pruned_epochs = await asyncio.to_thread(
            self.store.prune_shared_head_epochs,
            retention_boundary,
        )
        if pruned_epochs:
            log.info("shared_head_epochs_pruned", epochs=pruned_epochs)
        queued = 0
        for installation in await self.github.list_installations():
            if lost.is_set():
                return queued
            installation_id = installation.get("id")
            if not isinstance(installation_id, int) or installation.get("suspended_at") is not None:
                continue
            try:
                repositories = await self.github.list_installation_repositories(installation_id)
                for repository in repositories:
                    if lost.is_set():
                        return queued
                    full_name = repository.get("full_name")
                    if not isinstance(full_name, str) or repository.get("archived") is True:
                        continue
                    if self.settings.is_organization_config_repository(full_name):
                        continue
                    for pull in await self.github.list_open_pulls(installation_id, full_name):
                        number = pull.get("number")
                        head = pull.get("head")
                        if not isinstance(number, int):
                            continue
                        added = await asyncio.to_thread(
                            self.store.enqueue_if_absent,
                            JobRequest(
                                installation_id=installation_id,
                                repository_full_name=full_name,
                                pull_number=number,
                                reason="periodic_reconciliation",
                                head_sha_hint=(
                                    head.get("sha")
                                    if isinstance(head, dict) and isinstance(head.get("sha"), str)
                                    else None
                                ),
                            ),
                        )
                        queued += int(added)
            except Exception:
                log.exception("installation_reconciliation_failed", installation_id=installation_id)
        return queued

    async def run(self, stop: asyncio.Event) -> None:
        """Reconcile immediately and then at the configured interval."""
        while not stop.is_set():
            try:
                count = await self.reconcile_once()
                RECONCILIATIONS.labels("success").inc()
                RECONCILIATION_LAST_SUCCESS.set_to_current_time()
                log.info("reconciliation_complete", pull_requests_queued=count)
            except Exception:
                RECONCILIATIONS.labels("failure").inc()
                log.exception("reconciliation_failed")
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.settings.reconcile_interval_seconds)
