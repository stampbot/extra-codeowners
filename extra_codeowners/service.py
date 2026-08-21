"""GitHub evidence collection and policy evaluation orchestration."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any, Final, Literal

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
    WorkClass,
    normalize_repository_full_name,
    validate_head_sha,
)
from extra_codeowners.evaluator import evaluate
from extra_codeowners.github import (
    MAX_CODEOWNERS_BYTES,
    MAX_PULL_FILES,
    GitHubAPIError,
    GitHubClient,
    GitHubError,
    GitHubOperationStoppedError,
    GitHubRateLimitError,
    PullRequestTooLargeError,
)
from extra_codeowners.metrics import (
    DEAD_JOBS,
    EVALUATION_SECONDS,
    EVALUATIONS,
    QUEUE_DEPTH,
    QUEUE_WAIT_SECONDS,
    QUEUE_WORK_CLASS_DEPTH,
    QUEUE_WORK_CLASS_OLDEST_AGE_SECONDS,
    RECONCILIATION_LAST_SUCCESS,
    RECONCILIATION_SECONDS,
    RECONCILIATIONS,
    SHARED_HEAD_INVALIDATION_DEPTH,
    SHARED_HEAD_INVALIDATIONS,
    WEBHOOK_TO_CHECK_COMPLETION_SECONDS,
    WORK_ATTEMPT_SECONDS,
    WORK_ATTEMPTS,
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
    PullRequestAuthor,
    PullRequestReview,
    RepositoryPolicy,
    ReviewActor,
    ReviewState,
)
from extra_codeowners.policy import BUILTIN_NON_DELEGABLE_PATHS
from extra_codeowners.settings import Settings
from extra_codeowners.trace_context import TrustedTraceContext
from extra_codeowners.tracing import Tracing

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


class OrganizationPolicyRepositoryUnavailableError(ValueError):
    """The installation cannot safely read its configured policy repository."""


@dataclass(frozen=True, slots=True)
class ReconciliationOutcome:
    """Result of one elected open-pull-request reconciliation."""

    queued: int
    failed_installations: int = 0
    lease_lost: bool = False
    stopped: bool = False
    deferred: bool = False

    @property
    def complete(self) -> bool:
        """Whether the reconciler inspected every visible, unsuspended installation."""
        return (
            self.failed_installations == 0
            and not self.lease_lost
            and not self.stopped
            and not self.deferred
        )


class _CombinedEvent(asyncio.Event):
    """An event whose state follows any of its source events."""

    def __init__(self, *sources: asyncio.Event) -> None:
        super().__init__()
        self._sources = sources

    def is_set(self) -> bool:
        """Return immediately when this event or any source event is set."""
        return super().is_set() or any(source.is_set() for source in self._sources)


@asynccontextmanager
async def _combine_events(*sources: asyncio.Event) -> AsyncIterator[asyncio.Event]:
    """Yield one event that wakes and reads as set when any source is set."""
    combined = _CombinedEvent(*sources)

    async def relay(source: asyncio.Event) -> None:
        await source.wait()
        combined.set()

    relays = [
        asyncio.create_task(relay(source), name=f"combined-event-{index}")
        for index, source in enumerate(sources)
    ]
    try:
        yield combined
    finally:
        for task in relays:
            task.cancel()
        await asyncio.gather(*relays, return_exceptions=True)


class _ReconciliationPayloadError(ValueError):
    """A GitHub reconciliation record failed local structural validation."""

    def __init__(
        self,
        reason: Literal[
            "invalid_installation_batch",
            "invalid_installation_record",
            "invalid_installation_id",
            "duplicate_installation_id",
            "invalid_installation_suspended_at",
            "invalid_repository_batch",
            "invalid_repository_record",
            "invalid_repository_full_name",
            "duplicate_repository_full_name",
            "invalid_repository_archived",
            "invalid_pull_batch",
            "invalid_pull_record",
            "invalid_pull_number",
            "duplicate_pull_number",
            "invalid_pull_head",
        ],
    ) -> None:
        super().__init__(reason)
        self.reason = reason


def _reconciliation_installation_id(value: Any) -> int:
    """Return a valid GitHub installation ID without coercing untrusted data."""
    if type(value) is not int or value <= 0:
        raise _ReconciliationPayloadError("invalid_installation_id")
    return value


def _reconciliation_repository_full_name(value: Any) -> str:
    """Return a canonical GitHub repository identity for reconciliation."""
    if not isinstance(value, str):
        raise _ReconciliationPayloadError("invalid_repository_full_name")
    try:
        full_name = normalize_repository_full_name(value)
    except ValueError:
        raise _ReconciliationPayloadError("invalid_repository_full_name") from None
    if not full_name.isascii() or any(
        not (character.isalnum() or character in "._-/") for character in full_name
    ):
        raise _ReconciliationPayloadError("invalid_repository_full_name")
    return full_name


def _reconciliation_suspended(value: Any) -> bool:
    """Return whether a well-formed installation record is suspended."""
    if value is None:
        return False
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 64
        or "T" not in value
    ):
        raise _ReconciliationPayloadError("invalid_installation_suspended_at")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError:
        raise _ReconciliationPayloadError("invalid_installation_suspended_at") from None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise _ReconciliationPayloadError("invalid_installation_suspended_at")
    return True


def _as_utc(timestamp: datetime) -> datetime:
    """Normalize SQLite's naive stored timestamps for elapsed-time metrics."""
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        return timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


def _reconciliation_installations(value: Any) -> tuple[tuple[int, bool], ...]:
    """Validate the complete top-level installation response before using it."""
    if not isinstance(value, list):
        raise _ReconciliationPayloadError("invalid_installation_batch")
    installations: list[tuple[int, bool]] = []
    seen_ids: set[int] = set()
    for record in value:
        if not isinstance(record, dict):
            raise _ReconciliationPayloadError("invalid_installation_record")
        if "suspended_at" not in record:
            raise _ReconciliationPayloadError("invalid_installation_suspended_at")
        installation_id = _reconciliation_installation_id(record.get("id"))
        if installation_id in seen_ids:
            raise _ReconciliationPayloadError("duplicate_installation_id")
        seen_ids.add(installation_id)
        installations.append(
            (
                installation_id,
                _reconciliation_suspended(record["suspended_at"]),
            )
        )
    return tuple(installations)


def _reconciliation_repository(value: Any) -> tuple[str, bool]:
    """Validate one repository record without coercing provider data."""
    if not isinstance(value, dict):
        raise _ReconciliationPayloadError("invalid_repository_record")
    archived = value.get("archived")
    if type(archived) is not bool:
        raise _ReconciliationPayloadError("invalid_repository_archived")
    return _reconciliation_repository_full_name(value.get("full_name")), archived


def _reconciliation_repositories(value: Any) -> tuple[tuple[str, bool], ...]:
    """Validate an installation's complete repository batch."""
    if not isinstance(value, list):
        raise _ReconciliationPayloadError("invalid_repository_batch")
    repositories: list[tuple[str, bool]] = []
    seen_names: set[str] = set()
    for record in value:
        repository = _reconciliation_repository(record)
        if repository[0] in seen_names:
            raise _ReconciliationPayloadError("duplicate_repository_full_name")
        seen_names.add(repository[0])
        repositories.append(repository)
    return tuple(repositories)


def _reconciliation_head_sha(value: Any) -> str:
    """Return a canonical full Git object ID from an open-pull record."""
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _ReconciliationPayloadError("invalid_pull_head")
    return value


def _reconciliation_pull(value: Any) -> tuple[int, str]:
    """Validate one open-pull record without accepting Python bools as integers."""
    if not isinstance(value, dict):
        raise _ReconciliationPayloadError("invalid_pull_record")
    number = value.get("number")
    if type(number) is not int or number <= 0:
        raise _ReconciliationPayloadError("invalid_pull_number")
    head = value.get("head")
    if not isinstance(head, dict):
        raise _ReconciliationPayloadError("invalid_pull_head")
    return number, _reconciliation_head_sha(head.get("sha"))


def _reconciliation_pulls(value: Any) -> tuple[tuple[int, str], ...]:
    """Validate one repository's complete open-pull batch."""
    if not isinstance(value, list):
        raise _ReconciliationPayloadError("invalid_pull_batch")
    pulls: list[tuple[int, str]] = []
    seen_numbers: set[int] = set()
    for record in value:
        pull = _reconciliation_pull(record)
        if pull[0] in seen_numbers:
            raise _ReconciliationPayloadError("duplicate_pull_number")
        seen_numbers.add(pull[0])
        pulls.append(pull)
    return tuple(pulls)


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

    async def _finish_closed_pull_check(
        self,
        job: ClaimedJob,
        head_sha: str,
        details_url: str | None,
    ) -> None:
        """Finish a known check when no open pull request still needs this commit.

        A Check Run belongs to a commit rather than a pull request. Before
        cancelling it, re-read every associated pull request while holding the
        same cross-replica writer guard used for normal check publication. This
        prevents a closed pull request from cancelling a shared commit's check
        while another pull request is still open.
        """
        async with self._check_write_guard(job.installation_id, head_sha):
            current_associated = await self._current_associated_pulls(
                job.installation_id,
                job.repository_full_name,
                head_sha,
            )
            if any(
                state_value == "open" and associated_sha == head_sha
                for state_value, associated_sha in current_associated.values()
            ):
                return
            check_run_id = await self.github.existing_check_run_id(
                job.installation_id,
                job.repository_full_name,
                head_sha,
                self.settings.check_name,
            )
            if check_run_id is None:
                return
            await self.github.complete_check_run(
                job.installation_id,
                job.repository_full_name,
                check_run_id,
                self.settings.check_name,
                conclusion="cancelled",
                title="Pull request closed",
                summary=(
                    "The pull request closed before Extra CODEOWNERS finished evaluating approvals."
                ),
                details_url=details_url,
                external_id=f"{job.repository_full_name}#{job.pull_number}@{head_sha}",
            )

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
        authority_generation: int,
    ) -> OrganizationPolicy:
        owner = repository.split("/", 1)[0]
        organization_repository = f"{owner}/{self.settings.org_config_repository}"
        if not await self.github.installation_includes_repository(
            installation_id,
            organization_repository,
            authority_generation=authority_generation,
        ):
            raise OrganizationPolicyRepositoryUnavailableError(
                f"the configured organization policy repository {organization_repository} is not "
                "available to this GitHub App installation; confirm that it exists, add it to the "
                "installation's repository selection, and re-evaluate"
            )
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
        semaphore = asyncio.Semaphore(self.settings.authority_fanout_concurrency)

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

    async def _human_owner_evidence(
        self,
        installation_id: int,
        repository: str,
        repository_owner: str,
        login: str,
        document: CodeownersDocument,
    ) -> tuple[bool, frozenset[str]]:
        """Resolve direct and team CODEOWNER evidence for one GitHub user."""

        return await asyncio.gather(
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

    async def _validated_apps(
        self,
        installation_id: int,
        organization: OrganizationPolicy,
        bot_user_ids: frozenset[int],
    ) -> dict[int, tuple[str, EnrolledApplication, int, str]]:
        """Bind configured bot users to GitHub's installation-visible bot identity."""
        validated: dict[int, tuple[str, EnrolledApplication, int, str]] = {}
        for alias, app in organization.apps.items():
            if app.bot_user_id not in bot_user_ids:
                continue
            expected_login = f"{app.slug}[bot]"
            metadata = await self.github.get_user(installation_id, expected_login)
            observed_id = metadata.get("id")
            observed_login = metadata.get("login")
            observed_type = metadata.get("type")
            if (
                observed_id != app.bot_user_id
                or not isinstance(observed_login, str)
                or observed_login.lower() != expected_login
                or observed_type != "Bot"
            ):
                log.warning(
                    "enrolled_app_bot_identity_mismatch",
                    alias=alias,
                    configured_bot_user_id=app.bot_user_id,
                    observed_bot_user_id=observed_id,
                    configured_login=expected_login,
                    observed_login=observed_login,
                    observed_type=observed_type,
                )
                continue
            validated[app.bot_user_id] = (alias, app, app.app_id, app.slug)
        return validated

    @staticmethod
    def _pull_request_author_identity(pull: dict[str, Any]) -> tuple[int, str] | None:
        """Return a human PR author identity, never treating a bot as human evidence."""

        user_value = pull.get("user")
        # GitHub returns ``null`` for a pull request whose author account was
        # deleted.  That author cannot establish evidence, but valid review or
        # App evidence must remain usable.
        if user_value is None:
            return None
        user = _required_object(user_value, "pull_request.user")
        actor_type = user.get("type")
        if actor_type == "Bot":
            return None
        if actor_type != "User":
            raise GitHubError(f"pull request author has unsupported actor type {actor_type!r}")
        return (
            _required_positive_int(user.get("id"), "pull_request.user.id"),
            _required_string(user.get("login"), "pull_request.user.login"),
        )

    async def _reviews(
        self,
        installation_id: int,
        repository: str,
        values: list[dict[str, Any]],
        organization: OrganizationPolicy,
        document: CodeownersDocument,
        head_sha: str,
        *,
        additional_human_identity_count: int = 0,
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
        if (human_approvals + additional_human_identity_count) * len(
            team_owners
        ) > MAX_TEAM_MEMBERSHIP_LOOKUPS:
            raise EvidenceLimitError(
                "current human evidence and CODEOWNERS teams exceed the membership lookup budget"
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
                direct_owner_eligible, aliases = await self._human_owner_evidence(
                    installation_id,
                    repository,
                    repository_owner,
                    login,
                    document,
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
                job.authority_generation,
            )
        except OrganizationPolicyRepositoryUnavailableError as error:
            return _failure("organization_policy_repository_unavailable", str(error))
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
            author_identity = (
                self._pull_request_author_identity(pull)
                if repository_policy.allow_author_as_codeowner
                else None
            )
            reviews = await self._reviews(
                job.installation_id,
                job.repository_full_name,
                review_values,
                organization,
                document,
                head_sha,
                additional_human_identity_count=int(author_identity is not None),
            )
            author = None
            if author_identity is not None:
                author_id, author_login = author_identity
                direct_owner_eligible, aliases = await self._human_owner_evidence(
                    job.installation_id,
                    job.repository_full_name,
                    job.repository_full_name.split("/", 1)[0],
                    author_login,
                    document,
                )
                author = PullRequestAuthor(
                    login=author_login,
                    user_id=author_id,
                    owner_aliases=aliases,
                    direct_owner_eligible=direct_owner_eligible,
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
                author=author,
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
        """Report whether the fast path reset a check or queued a newer live head."""
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
        if pull_state == "closed":
            # The durable evaluation finishes a known blocking check if one
            # exists. Never create or reset a check for a closed pull request.
            return False

        live_head_queued = False
        if job.head_sha_hint is not None and job.head_sha_hint != head_sha:
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
                    work_class=job.work_class,
                ),
            )
            live_head_queued = True

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
                    return live_head_queued
                check_run_id = await self.github.existing_check_run_id(
                    job.installation_id,
                    job.repository_full_name,
                    accepted_head,
                    self.settings.check_name,
                )
                if check_run_id is None:
                    if pull_state != "open" or head_sha != accepted_head:
                        return live_head_queued
                    repository_text = await self._repository_policy_text(
                        job.installation_id,
                        job.repository_full_name,
                        base_sha,
                    )
                    if repository_text is None:
                        return live_head_queued
                # The GitHub lookup can outlive this delivery generation. Do
                # not let an old handler reset a newer completed result.
                if not await asyncio.to_thread(
                    self.store.shared_head_invalidation_is_pending,
                    job.installation_id,
                    job.repository_full_name,
                    accepted_head,
                    shared_head_generation,
                ):
                    return live_head_queued
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
                    work_class=job.work_class,
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
                check_head = validate_head_sha(job.head_sha_hint or head_sha)
                details_url = (
                    pull.get("html_url") if isinstance(pull.get("html_url"), str) else None
                )
                await self._finish_closed_pull_check(job, check_head, details_url)
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
                        work_class=job.work_class,
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
                await self._finish_closed_pull_check(job, head_sha, details_url)
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
                        work_class=job.work_class,
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
                            include_re_evaluate_action=True,
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
        *,
        tracing: Tracing | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.evaluator = evaluator
        self.owner = owner
        self.tracing = tracing or Tracing(enabled=False)

    def _slot_owner(self, lane: str, slot: int) -> str:
        """Return a distinct durable lease owner for one logical consumer."""
        # Lease owners are stored in a 128-character column. Keep enough
        # room for the lane suffix even when a caller supplied a long base.
        return f"{self.owner[:96]}:{lane}:{slot}"

    async def _run_work_attempt(
        self,
        *,
        kind: Literal["authority", "evaluation", "invalidation"],
        work_class: str,
        private_attributes: dict[str, int | str],
        operation: Callable[[], Awaitable[str]],
        producer_trace_context: TrustedTraceContext | None = None,
    ) -> str:
        """Trace and measure one durable attempt without high-cardinality metrics.

        The durable queue remains the coordination point across replicas. The
        private trace attributes make one sampled attempt diagnosable, while
        Prometheus receives only fixed class and outcome labels.
        """
        started = time.perf_counter()
        outcome = "failed"
        with self.tracing.span(
            f"worker.{kind}",
            attributes={
                "queue.kind": kind,
                "queue.work_class": work_class,
                "queue.producer_trace_linked": producer_trace_context is not None,
            },
            private_attributes=private_attributes,
            links=(producer_trace_context,) if producer_trace_context is not None else (),
            root=True,
        ):
            try:
                outcome = await operation()
                return outcome
            except asyncio.CancelledError:
                outcome = "cancelled"
                raise
            finally:
                WORK_ATTEMPTS.labels(kind, work_class, outcome).inc()
                WORK_ATTEMPT_SECONDS.labels(kind, work_class, outcome).observe(
                    time.perf_counter() - started
                )

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
    ) -> str:
        # Measure time spent ready for this attempt, not age since the
        # generation was first accepted. Retries retain requested_at, so using
        # it here would turn one delayed job into repeated, misleading SLO
        # samples.
        QUEUE_WAIT_SECONDS.labels("invalidation", job.work_class).observe(
            max(0.0, (datetime.now(UTC) - _as_utc(job.available_at)).total_seconds())
        )
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
            return "superseded"
        except GitHubRateLimitError as error:
            await asyncio.to_thread(
                self.store.record_provider_backpressure,
                None if error.global_scope else job.installation_id,
                str(error),
                error.retry_after_seconds,
            )
            updated = await asyncio.to_thread(
                self.store.defer_shared_head_invalidation,
                job,
                str(error),
                error.retry_after_seconds,
            )
            outcome = "rate_limited" if updated else "superseded"
            SHARED_HEAD_INVALIDATIONS.labels(outcome).inc()
            return outcome
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
            outcome = "failed" if updated else "superseded"
            SHARED_HEAD_INVALIDATIONS.labels(outcome).inc()
            return outcome
        else:
            completed = False
            if not lost.is_set():
                completed = await asyncio.to_thread(
                    self.store.complete_shared_head_invalidation,
                    job,
                )
            outcome = "completed" if completed else "superseded"
            SHARED_HEAD_INVALIDATIONS.labels(outcome).inc()
            if completed:
                log.info(
                    "shared_head_invalidation_completed",
                    installation_id=job.installation_id,
                    repository=job.repository_full_name,
                    generation=job.generation,
                )
            return outcome
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

    async def _process(
        self,
        job: ClaimedJob,
        owner: str | None = None,
        slot: int | None = None,
    ) -> str:
        owner = self.owner if owner is None else owner
        # See _process_shared_head: this histogram represents queue scheduling
        # for each ready attempt rather than accumulated retry backoff.
        QUEUE_WAIT_SECONDS.labels("evaluation", job.work_class).observe(
            max(0.0, (datetime.now(UTC) - _as_utc(job.available_at)).total_seconds())
        )
        log.info(
            "evaluation_started",
            slot=slot,
            work_class=job.work_class,
            job_id=job.id,
            repository=job.repository_full_name,
            pull_number=job.pull_number,
            head_sha=job.head_sha_hint,
            generation=job.generation,
            last_delivery_id=job.last_delivery_id,
        )
        done = asyncio.Event()
        heartbeat = asyncio.create_task(self._renew_lease(job, done), name=f"job-lease-{job.id}")
        try:
            await self.evaluator.evaluate_job(job)
        except GitHubRateLimitError as error:
            await asyncio.to_thread(
                self.store.record_provider_backpressure,
                None if error.global_scope else job.installation_id,
                str(error),
                error.retry_after_seconds,
            )
            log.warning(
                "evaluation_rate_limited",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
                retry_after_seconds=error.retry_after_seconds,
            )
            await asyncio.to_thread(
                self.store.defer,
                job,
                owner,
                str(error),
                error.retry_after_seconds,
            )
            return "rate_limited"
        except AuthorityChangePendingError as error:
            log.info(
                "evaluation_deferred_for_authority",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
            )
            await asyncio.to_thread(
                self.store.defer,
                job,
                owner,
                str(error),
                max(5, int(self.settings.worker_poll_seconds * 10)),
            )
            return "authority_deferred"
        except SharedHeadInvalidationPendingError as error:
            log.info(
                "evaluation_deferred_for_shared_head_invalidation",
                repository=job.repository_full_name,
                pull_number=job.pull_number,
            )
            await asyncio.to_thread(
                self.store.defer,
                job,
                owner,
                str(error),
                max(1, int(self.settings.worker_poll_seconds * 2)),
            )
            return "invalidation_deferred"
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
                owner,
                str(error),
                self.settings.worker_retry_max_seconds,
            )
            return "failed"
        else:
            try:
                completed = await asyncio.to_thread(self.store.complete, job, owner)
            except Exception:
                # A Check Run can be correct while a database outage prevents
                # the durable acknowledgment. Do not claim completion in logs
                # or metrics: a later lease holder must retry the work.
                log.exception(
                    "evaluation_completion_persistence_failed",
                    job_id=job.id,
                    work_class=job.work_class,
                    repository=job.repository_full_name,
                    pull_number=job.pull_number,
                    generation=job.generation,
                )
                raise
            if not completed:
                log.info(
                    "evaluation_completion_superseded",
                    job_id=job.id,
                    work_class=job.work_class,
                    repository=job.repository_full_name,
                    pull_number=job.pull_number,
                    generation=job.generation,
                )
                return "superseded"
            completed_at = datetime.now(UTC)
            accepted_age_seconds = max(
                0.0, (completed_at - _as_utc(job.requested_at)).total_seconds()
            )
            WEBHOOK_TO_CHECK_COMPLETION_SECONDS.labels(job.work_class).observe(accepted_age_seconds)
            log.info(
                "evaluation_completed",
                job_id=job.id,
                work_class=job.work_class,
                repository=job.repository_full_name,
                pull_number=job.pull_number,
                head_sha=job.head_sha_hint,
                generation=job.generation,
                last_delivery_id=job.last_delivery_id,
                accepted_age_seconds=accepted_age_seconds,
            )
            return "completed"
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

        semaphore = asyncio.Semaphore(self.settings.authority_fanout_concurrency)

        async def revoke(request: JobRequest) -> None:
            async with semaphore:
                try:
                    await self.evaluator.invalidate_for_trigger(request)
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
                global_limits = [error for error in rate_limits if error.global_scope]
                if global_limits:
                    global_error = max(
                        global_limits,
                        key=lambda error: error.retry_after_seconds,
                    )
                    # The job's own retry can use the longest observed delay,
                    # but a shorter App-wide secondary limit must still stop
                    # other installations and pods immediately.
                    await asyncio.to_thread(
                        self.store.record_provider_backpressure,
                        None,
                        str(global_error),
                        global_error.retry_after_seconds,
                    )
                raise max(rate_limits, key=lambda error: error.retry_after_seconds)

    async def _process_authority(
        self,
        job: ClaimedAuthorityJob,
        owner: str | None = None,
    ) -> str:
        owner = self.owner if owner is None else owner
        done = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._renew_authority_lease(job, done),
            name=f"authority-lease-{job.id}",
        )
        try:
            await self._execute_authority(job)
        except GitHubRateLimitError as error:
            await asyncio.to_thread(
                self.store.record_provider_backpressure,
                None if error.global_scope else job.installation_id,
                str(error),
                error.retry_after_seconds,
            )
            await asyncio.to_thread(
                self.store.defer_authority,
                job,
                owner,
                str(error),
                error.retry_after_seconds,
            )
            return "rate_limited"
        except asyncio.CancelledError:
            raise
        except GitHubAPIError as error:
            # A repository outside the installation returns 404. Keep the
            # authority fence fail-closed, but retry it on an hours-scale
            # cadence until an installation/repository event coalesces and
            # wakes the same row immediately.
            retry_max = (
                self.settings.authority_inaccessible_retry_max_seconds
                if error.status_code in {404, 410}
                else self.settings.worker_retry_max_seconds
            )
            log.warning(
                "authority_fanout_api_failure",
                installation_id=job.installation_id,
                scope=job.repository_full_name or "installation",
                status_code=error.status_code,
                retry_max_seconds=retry_max,
            )
            await asyncio.to_thread(
                self.store.fail_authority,
                job,
                owner,
                str(error),
                retry_max,
                300 if error.status_code in {404, 410} else 1,
            )
            return "inaccessible" if error.status_code in {404, 410} else "failed"
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
                owner,
                str(error),
                self.settings.worker_retry_max_seconds,
            )
            return "failed"
        else:
            try:
                completed = await asyncio.to_thread(self.store.complete_authority, job, owner)
            except Exception:
                log.exception(
                    "authority_completion_persistence_failed",
                    authority_job_id=job.id,
                    installation_id=job.installation_id,
                    scope=job.repository_full_name or "installation",
                    generation=job.generation,
                )
                raise
            if not completed:
                log.info(
                    "authority_completion_superseded",
                    authority_job_id=job.id,
                    installation_id=job.installation_id,
                    scope=job.repository_full_name or "installation",
                    generation=job.generation,
                )
                return "superseded"
            log.info(
                "authority_fanout_completed",
                authority_job_id=job.id,
                installation_id=job.installation_id,
                scope=job.repository_full_name or "installation",
                generation=job.generation,
            )
            return "completed"
        finally:
            done.set()
            await asyncio.gather(heartbeat)

    async def _wait_for_work(self, stop: asyncio.Event) -> None:
        """Sleep between empty durable claims without delaying shutdown."""
        if not stop.is_set():
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.settings.worker_poll_seconds)

    async def _run_invalidation_slot(
        self,
        stop: asyncio.Event,
        slot: int,
        *,
        recovery_first: bool,
    ) -> None:
        """Run one exact-head lane with guaranteed capacity for its first class."""
        owner = self._slot_owner("invalidation", slot)
        classes: tuple[WorkClass, WorkClass] = (
            ("recovery", "interactive") if recovery_first else ("interactive", "recovery")
        )
        while not stop.is_set():
            try:
                job = None
                for work_class in classes:
                    job = await asyncio.to_thread(
                        self.store.claim_shared_head_invalidation,
                        owner,
                        self.settings.worker_lease_seconds,
                        work_class,
                    )
                    if job is not None:
                        break
                if job is not None:
                    log.info(
                        "shared_head_invalidation_started",
                        slot=slot,
                        work_class=job.work_class,
                        repository=job.repository_full_name,
                        head_sha=job.head_sha,
                        generation=job.generation,
                    )
                    await self._run_work_attempt(
                        kind="invalidation",
                        work_class=job.work_class,
                        private_attributes={
                            "queue.installation_id": job.installation_id,
                            "queue.repository": job.repository_full_name,
                            "queue.head_sha": job.head_sha,
                            "queue.generation": job.generation,
                        },
                        operation=partial(self._process_shared_head, job),
                    )
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("shared_head_invalidation_slot_failed", slot=slot)
            await self._wait_for_work(stop)

    async def _run_foreground_slot(self, stop: asyncio.Event, slot: int) -> None:
        """Run webhook-triggered evaluations without consuming recovery capacity."""
        owner = self._slot_owner("foreground", slot)
        while not stop.is_set():
            try:
                job = await asyncio.to_thread(
                    self.store.claim,
                    owner,
                    self.settings.worker_lease_seconds,
                    "interactive",
                    require_shared_head_ready=True,
                )
                if job is not None:
                    await self._run_work_attempt(
                        kind="evaluation",
                        work_class=job.work_class,
                        private_attributes={
                            "queue.job_id": job.id,
                            "queue.installation_id": job.installation_id,
                            "queue.repository": job.repository_full_name,
                            "queue.pull_number": job.pull_number,
                            "queue.generation": job.generation,
                        },
                        operation=partial(self._process, job, owner, slot),
                        producer_trace_context=job.webhook_trace_context,
                    )
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("foreground_evaluation_slot_failed", slot=slot)
            await self._wait_for_work(stop)

    async def _run_recovery_slot(self, stop: asyncio.Event, slot: int) -> None:
        """Keep missed-webhook recovery moving, borrowing foreground work when idle."""
        owner = self._slot_owner("recovery", slot)
        while not stop.is_set():
            try:
                job = await asyncio.to_thread(
                    self.store.claim,
                    owner,
                    self.settings.worker_lease_seconds,
                    "recovery",
                    require_shared_head_ready=True,
                )
                if job is None:
                    job = await asyncio.to_thread(
                        self.store.claim,
                        owner,
                        self.settings.worker_lease_seconds,
                        "interactive",
                        require_shared_head_ready=True,
                    )
                if job is not None:
                    await self._run_work_attempt(
                        kind="evaluation",
                        work_class=job.work_class,
                        private_attributes={
                            "queue.job_id": job.id,
                            "queue.installation_id": job.installation_id,
                            "queue.repository": job.repository_full_name,
                            "queue.pull_number": job.pull_number,
                            "queue.generation": job.generation,
                        },
                        operation=partial(self._process, job, owner, slot),
                        producer_trace_context=job.webhook_trace_context,
                    )
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("recovery_evaluation_slot_failed", slot=slot)
            await self._wait_for_work(stop)

    async def _run_authority_slot(self, stop: asyncio.Event, slot: int) -> None:
        """Run coalesced authority fan-out independently from PR evaluation."""
        owner = self._slot_owner("authority", slot)
        while not stop.is_set():
            try:
                job = await asyncio.to_thread(
                    self.store.claim_authority,
                    owner,
                    self.settings.worker_lease_seconds,
                )
                if job is not None:
                    log.info(
                        "authority_fanout_started",
                        slot=slot,
                        installation_id=job.installation_id,
                        scope=job.repository_full_name or "installation",
                        generation=job.generation,
                    )
                    await self._run_work_attempt(
                        kind="authority",
                        work_class="authority",
                        private_attributes={
                            "queue.authority_job_id": job.id,
                            "queue.installation_id": job.installation_id,
                            "queue.scope": job.repository_full_name or "installation",
                            "queue.generation": job.generation,
                        },
                        operation=partial(self._process_authority, job, owner),
                    )
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("authority_fanout_slot_failed", slot=slot)
            await self._wait_for_work(stop)

    async def _sample_metrics(self, stop: asyncio.Event) -> None:
        """Publish cheap queue gauges once per process instead of per worker slot."""
        interval = max(1.0, self.settings.worker_poll_seconds * 10)
        while not stop.is_set():
            try:
                QUEUE_DEPTH.set(await asyncio.to_thread(self.store.pending_count))
                DEAD_JOBS.set(await asyncio.to_thread(self.store.dead_count))
                SHARED_HEAD_INVALIDATION_DEPTH.set(
                    await asyncio.to_thread(self.store.pending_shared_head_invalidation_count)
                )
                snapshot = await asyncio.to_thread(self.store.pending_work_class_snapshot)
                now = datetime.now(UTC)
                for kind, work_class in (
                    ("evaluation", "interactive"),
                    ("evaluation", "recovery"),
                    ("invalidation", "interactive"),
                    ("invalidation", "recovery"),
                    ("authority", "authority"),
                ):
                    count, oldest = snapshot.get((kind, work_class), (0, None))
                    QUEUE_WORK_CLASS_DEPTH.labels(kind, work_class).set(count)
                    age = 0.0 if oldest is None else max(0.0, (now - oldest).total_seconds())
                    QUEUE_WORK_CLASS_OLDEST_AGE_SECONDS.labels(kind, work_class).set(age)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("worker_metrics_sample_failed")
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), interval)

    async def run(self, stop: asyncio.Event) -> None:
        """Run bounded, replica-safe async worker lanes until stopped.

        Every lane claims durable rows through the same database lease and
        generation checks. More than one pod may run this method; PostgreSQL
        ``SKIP LOCKED`` and the conditional claim update ensure a row still
        belongs to only one active consumer.
        """
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(self._sample_metrics(stop), name="worker-metrics")
            for slot in range(self.settings.worker_invalidation_concurrency):
                tasks.create_task(
                    self._run_invalidation_slot(stop, slot, recovery_first=slot == 0),
                    name=(
                        f"shared-head-recovery-worker-{slot}"
                        if slot == 0
                        else f"shared-head-foreground-worker-{slot}"
                    ),
                )
            for slot in range(self.settings.worker_foreground_concurrency):
                tasks.create_task(
                    self._run_foreground_slot(stop, slot),
                    name=f"foreground-evaluation-worker-{slot}",
                )
            for slot in range(self.settings.worker_recovery_concurrency):
                tasks.create_task(
                    self._run_recovery_slot(stop, slot),
                    name=f"recovery-evaluation-worker-{slot}",
                )
            for slot in range(self.settings.worker_authority_concurrency):
                tasks.create_task(
                    self._run_authority_slot(stop, slot),
                    name=f"authority-worker-{slot}",
                )
            await stop.wait()


class Reconciler:
    """Periodically enqueue every open pull request to recover missed webhooks."""

    def __init__(
        self,
        settings: Settings,
        github: GitHubClient,
        store: QueueStore,
        owner: str,
        *,
        tracing: Tracing | None = None,
    ) -> None:
        self.settings = settings
        self.github = github
        self.store = store
        self.owner = owner
        self.tracing = tracing or Tracing(enabled=False)

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

    async def reconcile_once(
        self,
        stop: asyncio.Event | None = None,
    ) -> ReconciliationOutcome | None:
        """Discover open pull requests, or return ``None`` when another process is elected."""
        stop_event = stop or asyncio.Event()
        if stop_event.is_set():
            return None
        lease_seconds = max(300, self.settings.reconcile_interval_seconds * 2)
        acquired = await asyncio.to_thread(
            self.store.acquire_service_lease, "open-pr-reconciler", self.owner, lease_seconds
        )
        if not acquired:
            return None
        if stop_event.is_set():
            await asyncio.to_thread(
                self.store.release_service_lease,
                "open-pr-reconciler",
                self.owner,
            )
            return None
        done = asyncio.Event()
        lost = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._renew_lease(done, lost, lease_seconds),
            name="reconciler-lease",
        )
        try:
            outcome = await self._reconcile_owned(lost, stop_event)
        finally:
            done.set()
            await asyncio.gather(heartbeat)
        if lost.is_set() and not outcome.lease_lost:
            outcome = replace(outcome, lease_lost=True)
        if stop_event.is_set() and not outcome.stopped:
            outcome = replace(outcome, stopped=True)
        return outcome

    async def _reconcile_owned(
        self,
        lost: asyncio.Event,
        stop: asyncio.Event | None = None,
    ) -> ReconciliationOutcome:
        """Perform one reconciliation while the heartbeat owns the lease."""
        stop_event = stop or asyncio.Event()
        async with _combine_events(lost, stop_event) as request_stop:
            return await self._reconcile_owned_scan(lost, stop_event, request_stop)

    async def _reconcile_owned_scan(
        self,
        lost: asyncio.Event,
        stop_event: asyncio.Event,
        request_stop: asyncio.Event,
    ) -> ReconciliationOutcome:
        """Perform the elected scan with one request-level interruption signal."""
        queued = 0
        failed_installations = 0

        def interrupted() -> bool:
            return lost.is_set() or stop_event.is_set()

        def interruption_outcome(*, operation_stopped: bool = False) -> ReconciliationOutcome:
            return ReconciliationOutcome(
                queued=queued,
                failed_installations=failed_installations,
                lease_lost=lost.is_set(),
                stopped=stop_event.is_set() or operation_stopped,
            )

        if interrupted():
            return interruption_outcome()
        now = datetime.now(UTC)
        retention_boundary = now - timedelta(days=self.settings.webhook_delivery_retention_days)
        # A fingerprint must outlive both a full scan interval and the
        # recheck interval. Otherwise a slow daily scan can prune state before
        # it sees the same pull request again and refill the recovery queue.
        state_retention_seconds = max(
            self.settings.webhook_delivery_retention_days * 86_400,
            self.settings.reconcile_interval_seconds + self.settings.reconcile_recheck_seconds,
        )
        state_retention_boundary = now - timedelta(seconds=state_retention_seconds)
        pruned = await asyncio.to_thread(self.store.prune_deliveries, retention_boundary)
        if pruned:
            log.info("webhook_deliveries_pruned", deliveries=pruned)
        if interrupted():
            return interruption_outcome()
        pruned_epochs = await asyncio.to_thread(
            self.store.prune_shared_head_epochs,
            retention_boundary,
        )
        if pruned_epochs:
            log.info("shared_head_epochs_pruned", epochs=pruned_epochs)
        if interrupted():
            return interruption_outcome()
        pruned_states = await asyncio.to_thread(
            self.store.prune_reconciliation_states,
            state_retention_boundary,
        )
        if pruned_states:
            log.info("reconciliation_states_pruned", states=pruned_states)
        if interrupted():
            return interruption_outcome()
        if await asyncio.to_thread(self.store.provider_is_backpressured, None):
            log.info("reconciliation_deferred_for_provider_backpressure", scope="global")
            return ReconciliationOutcome(
                queued=queued,
                failed_installations=failed_installations,
                lease_lost=lost.is_set(),
                stopped=stop_event.is_set(),
                deferred=True,
            )
        try:
            installation_records = await self.github.list_installations(stop=request_stop)
        except GitHubOperationStoppedError:
            return interruption_outcome(operation_stopped=not interrupted())
        except GitHubRateLimitError as error:
            await asyncio.to_thread(
                self.store.record_provider_backpressure,
                None,
                str(error),
                error.retry_after_seconds,
            )
            log.warning(
                "reconciliation_rate_limited",
                scope="global",
                retry_after_seconds=error.retry_after_seconds,
            )
            return ReconciliationOutcome(
                queued=queued,
                failed_installations=1,
                lease_lost=lost.is_set(),
                stopped=stop_event.is_set(),
            )
        if interrupted():
            return interruption_outcome()
        installations = _reconciliation_installations(installation_records)
        for installation_id, suspended in installations:
            if interrupted():
                return interruption_outcome()
            if suspended:
                continue
            if await asyncio.to_thread(self.store.provider_is_backpressured, installation_id):
                failed_installations += 1
                log.info(
                    "reconciliation_deferred_for_provider_backpressure",
                    installation_id=installation_id,
                )
                continue
            try:
                repository_records = await self.github.list_installation_repositories(
                    installation_id,
                    stop=request_stop,
                )
                if interrupted():
                    return interruption_outcome()
                repositories = _reconciliation_repositories(repository_records)
                for full_name, archived in repositories:
                    if interrupted():
                        return interruption_outcome()
                    if archived:
                        continue
                    if self.settings.is_organization_config_repository(full_name):
                        continue
                    # This boundary must precede every paginated API page. A
                    # direct webhook accepted while the listing is in flight
                    # is newer durable evidence than any page in its result.
                    observed_at = datetime.now(UTC)
                    pull_records = await self.github.list_open_pulls(
                        installation_id,
                        full_name,
                        stop=request_stop,
                    )
                    if interrupted():
                        return interruption_outcome()
                    pulls = _reconciliation_pulls(pull_records)
                    for number, head_sha in pulls:
                        if interrupted():
                            return interruption_outcome()
                        added = await asyncio.to_thread(
                            self.store.enqueue_reconciliation_if_due,
                            JobRequest(
                                installation_id=installation_id,
                                repository_full_name=full_name,
                                pull_number=number,
                                reason="periodic_reconciliation",
                                head_sha_hint=head_sha,
                                work_class="recovery",
                                observed_at=observed_at,
                            ),
                            self.settings.reconcile_recheck_seconds,
                        )
                        queued += int(added)
            except GitHubOperationStoppedError:
                return interruption_outcome(operation_stopped=not interrupted())
            except GitHubRateLimitError as error:
                failed_installations += 1
                await asyncio.to_thread(
                    self.store.record_provider_backpressure,
                    None if error.global_scope else installation_id,
                    str(error),
                    error.retry_after_seconds,
                )
                log.warning(
                    "reconciliation_rate_limited",
                    installation_id=installation_id,
                    retry_after_seconds=error.retry_after_seconds,
                )
            except _ReconciliationPayloadError as error:
                failed_installations += 1
                log.warning(
                    "installation_reconciliation_payload_invalid",
                    installation_id=installation_id,
                    reason=error.reason,
                )
            except Exception:
                failed_installations += 1
                log.exception("installation_reconciliation_failed", installation_id=installation_id)
        return ReconciliationOutcome(
            queued=queued,
            failed_installations=failed_installations,
            lease_lost=lost.is_set(),
            stopped=stop_event.is_set(),
        )

    async def run_iteration(self, stop: asyncio.Event | None = None) -> None:
        """Run and report one scheduled reconciliation attempt."""
        started = time.perf_counter()
        result = "failure"
        try:
            with self.tracing.span(
                "reconciliation.run",
                attributes={"reconciliation.component": "open_pull_scan"},
            ) as span:
                try:
                    outcome = await self.reconcile_once(stop)
                except Exception as error:
                    result = "failure"
                    self.tracing.mark_error(span, type(error).__name__)
                    RECONCILIATIONS.labels(result).inc()
                    log.exception("reconciliation_failed")
                    return
                if outcome is None:
                    result = "not_elected"
                    return
                if not outcome.complete:
                    result = "partial"
                    RECONCILIATIONS.labels(result).inc()
                    log.warning(
                        "reconciliation_partial",
                        pull_requests_queued=outcome.queued,
                        failed_installations=outcome.failed_installations,
                        lease_lost=outcome.lease_lost,
                        stopped=outcome.stopped,
                        deferred=outcome.deferred,
                    )
                    return
                result = "success"
                RECONCILIATIONS.labels(result).inc()
                RECONCILIATION_LAST_SUCCESS.set_to_current_time()
                log.info("reconciliation_complete", pull_requests_queued=outcome.queued)
        finally:
            # A non-elected replica is intentionally a distinct, low-cost
            # outcome rather than a failed scan. This finally also preserves
            # the duration sample when shutdown interrupts an in-flight scan.
            RECONCILIATION_SECONDS.labels(result).observe(time.perf_counter() - started)

    async def run(self, stop: asyncio.Event) -> None:
        """Reconcile immediately and then at the configured interval."""
        while not stop.is_set():
            await self.run_iteration(stop)
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.settings.reconcile_interval_seconds)
