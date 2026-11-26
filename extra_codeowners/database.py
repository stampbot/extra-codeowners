"""Durable evaluation queue and delivery de-duplication storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    and_,
    case,
    create_engine,
    delete,
    exists,
    false,
    func,
    literal,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy.sql.elements import ColumnElement

from extra_codeowners.database_audit import EvaluationAudit, record_audit
from extra_codeowners.database_metadata import Base as Base
from extra_codeowners.database_metadata import utcnow as utcnow
from extra_codeowners.database_schema import validate_database_schema_contract
from extra_codeowners.merge_queue import MergeGroupTrigger
from extra_codeowners.trace_context import TrustedTraceContext

SCHEMA_VERSION = 11
DATABASE_MIGRATION_HEAD = "0012_merge_candidate_recheck"
DATABASE_CONNECT_TIMEOUT_SECONDS = 3
DATABASE_POOL_TIMEOUT_SECONDS = 2
DATABASE_STATEMENT_TIMEOUT_MILLISECONDS = 3_000
MAX_BASE_SCOPED_AUTHORITY_JOBS_PER_REPOSITORY = 100
MAX_AUTHORITY_BASE_REF_LENGTH = 255
WORK_CLASS_INTERACTIVE: Final = "interactive"
WORK_CLASS_RECOVERY: Final = "recovery"
# A timer-driven recheck of a head whose last evaluation completed. It carries
# no new evidence, so the evaluator keeps the published result until the new
# evaluation differs. Any trigger that coalesces into the row replaces it.
SCHEDULED_RECHECK_REASON: Final = "scheduled_recheck"
BASE_RECHECK_REASON: Final = "base_branch_recheck"
PRESERVING_RECHECK_REASONS: Final = frozenset({SCHEDULED_RECHECK_REASON, BASE_RECHECK_REASON})
# Reconciler work the scan cannot vouch for: a missed head change, an
# unconfirmed completion, or a pull request with no completion record.
PERIODIC_RECONCILIATION_REASON: Final = "periodic_reconciliation"
WorkClass = Literal["interactive", "recovery"]
# ``sslmode=require`` normally skips server-certificate verification, but libpq
# upgrades it to ``verify-ca`` when its default root certificate exists. Point
# it at a child of the platform null device instead: the device cannot contain
# children, so the path cannot exist or be created. This preserves the
# deliberate encryption-only production contract without trusting a CA file
# that happened to be present in the process account's home directory.
LIBPQ_DISABLED_ROOT_CERT = os.path.join(os.devnull, "extra-codeowners-root.crt")


def isolated_postgresql_connect_args(database_url: str) -> dict[str, object]:
    """Pin every libpq route selector that could otherwise fall back to the environment."""

    if "PGSERVICE" in os.environ:
        raise ValueError("ambient PGSERVICE is not allowed")
    parsed = make_url(database_url)
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("PostgreSQL URL port must be between 1 and 65535")
    allowed_query_parameters = {"host", "hostaddr", "sslmode"}
    if set(parsed.query) - allowed_query_parameters:
        raise ValueError("PostgreSQL URL contains unsupported connection parameters")
    query_host = parsed.query.get("host")
    hostaddr = parsed.query.get("hostaddr")
    sslmode = parsed.query.get("sslmode")
    if (
        parsed.drivername != "postgresql+psycopg"
        or (query_host is not None and not isinstance(query_host, str))
        or (hostaddr is not None and not isinstance(hostaddr, str))
        or (sslmode is not None and not isinstance(sslmode, str))
        or sslmode not in {None, "disable", "require"}
        or (query_host is not None and parsed.host is not None)
    ):
        raise ValueError(
            "PostgreSQL URL has an unsupported route, an ambiguous route, or an unsupported "
            "TLS mode"
        )
    host = query_host if isinstance(query_host, str) else parsed.host
    if (
        not host
        or "," in host
        or (hostaddr is not None and (not hostaddr or "," in hostaddr))
        or not parsed.database
        or not parsed.username
        or not parsed.password
    ):
        raise ValueError("PostgreSQL URL must pin one route, database, username, and password")
    local = host in {"localhost", "127.0.0.1", "::1"} or host.startswith("/")
    arguments: dict[str, object] = {
        "dbname": parsed.database,
        "host": host,
        # An explicit empty value suppresses PGHOSTADDR fallback. Ambient
        # PGSERVICE is rejected above because libpq has no safe empty override.
        "hostaddr": hostaddr or "",
        "password": parsed.password,
        "port": 5432 if port is None else port,
        # libpq otherwise prefers GSSAPI encryption to SSL when credentials
        # are available, bypassing the configured SSL transport.
        "gssencmode": "disable",
        "sslmode": sslmode or ("disable" if local and not hostaddr else "require"),
        "sslrootcert": LIBPQ_DISABLED_ROOT_CERT,
        "user": parsed.username,
    }
    return arguments


def normalize_repository_full_name(value: str) -> str:
    """Return the case-insensitive canonical key for ``owner/repository``."""
    if (
        not value
        or value != value.strip()
        or len(value) > 512
        or value.count("/") != 1
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("repository_full_name must be a valid owner/repository name")
    return value.lower()


def validate_base_ref_hint(value: str | None) -> str | None:
    """Validate an optional scheduling-only base ref without requiring it."""
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_AUTHORITY_BASE_REF_LENGTH
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("base_ref_hint must be a valid branch ref of at most 255 characters")
    return value


def validate_head_sha(value: str) -> str:
    """Return a canonical Git object ID suitable for a durable key."""
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("head_sha must be exactly 40 or 64 lowercase ASCII hexadecimal characters")
    return value


class SchemaMetadata(Base):
    """Explicit compatibility marker for the durable database schema."""

    __tablename__ = "schema_metadata"

    singleton_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=False,
        default=1,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class EvaluationJob(Base):
    """Latest requested evaluation for one pull request."""

    __tablename__ = "evaluation_jobs"
    __table_args__ = (
        UniqueConstraint(
            "installation_id",
            "repository_full_name",
            "pull_number",
            name="uq_evaluation_job_pr",
        ),
        CheckConstraint(
            "work_class IN ('interactive', 'recovery')",
            name="ck_evaluation_jobs_work_class",
        ),
        Index(
            "ix_evaluation_jobs_claim",
            "state",
            "work_class",
            "available_at",
            "lease_until",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    installation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    repository_full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    pull_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha_hint: Mapped[str | None] = mapped_column(String(64))
    base_ref_hint: Mapped[str | None] = mapped_column(String(255))
    last_delivery_id: Mapped[str | None] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    work_class: Mapped[WorkClass] = mapped_column(
        String(16), nullable=False, default=WORK_CLASS_INTERACTIVE
    )
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    authority_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    shared_head_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(2000))


class WebhookDelivery(Base):
    """A GitHub delivery retained for replay-safe ingestion and trace linkage."""

    __tablename__ = "webhook_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event: Mapped[str] = mapped_column(String(128), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    invalidation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    invalidation_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    installation_id: Mapped[int | None] = mapped_column(Integer)
    repository_full_name: Mapped[str | None] = mapped_column(String(512))
    pull_number: Mapped[int | None] = mapped_column(Integer)
    head_sha: Mapped[str | None] = mapped_column(String(64))
    shared_head_generation: Mapped[int | None] = mapped_column(Integer)
    producer_trace_id: Mapped[str | None] = mapped_column(String(32))
    producer_span_id: Mapped[str | None] = mapped_column(String(16))
    producer_trace_flags: Mapped[int | None] = mapped_column(Integer)
    merge_group_digest: Mapped[str | None] = mapped_column(String(64))


class MergeGroupWork(Base):
    """Latest work for an immutable candidate, including its cancellation."""

    __tablename__ = "merge_group_work"
    __table_args__ = (
        Index("ix_merge_group_claim", "available_at", "lease_until"),
        Index("ix_merge_group_pull", "installation_id", "repository_full_name", "pull_number"),
        Index(
            "ix_merge_group_recheck",
            "repository_id",
            "available_at",
            sqlite_where=text("recheck_check_id > 0"),
            postgresql_where=text("recheck_check_id > 0"),
        ),
        CheckConstraint(
            "generation >= 1 AND completed_generation >= 0 AND completed_generation <= generation",
            name="ck_merge_group_generation",
        ),
    )

    installation_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    repository_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    head_sha: Mapped[str] = mapped_column(String(40), primary_key=True)
    repository_full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    base_ref: Mapped[str] = mapped_column(String(1024), nullable=False)
    base_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    head_ref: Mapped[str] = mapped_column(String(1024), nullable=False)
    destroyed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    pull_number: Mapped[int | None] = mapped_column(BigInteger)
    # Bind an observed queue entry, not only a possibly reused ref or commit.
    entry_id: Mapped[str | None] = mapped_column(String(256))
    pull_id: Mapped[str | None] = mapped_column(String(256))
    pull_head_sha: Mapped[str | None] = mapped_column(String(40))
    recheck_check_id: Mapped[int | None] = mapped_column(BigInteger)
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    completed_generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


def _merge_group_delivery_digest(request: MergeGroupTrigger) -> str:
    data = (
        request.action,
        request.installation_id,
        request.repository_id,
        normalize_repository_full_name(request.repository),
        request.base_ref,
        request.base_sha,
        request.head_ref,
        request.head_sha,
    )
    return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


def _enqueue_merge_group(session: Session, request: MergeGroupTrigger) -> None:
    work = session.get(
        MergeGroupWork,
        (request.installation_id, request.repository_id, request.head_sha),
        with_for_update=True,
    )
    repo = normalize_repository_full_name(request.repository)
    requested_identity = (repo, request.base_ref, request.base_sha, request.head_ref)
    destroyed = request.action == "destroyed"
    now = utcnow()
    if work is None:
        session.add(
            MergeGroupWork(
                installation_id=request.installation_id,
                repository_id=request.repository_id,
                head_sha=request.head_sha,
                repository_full_name=repo,
                base_ref=request.base_ref,
                base_sha=request.base_sha,
                head_ref=request.head_ref,
                destroyed=destroyed,
                requested_at=now,
                available_at=now,
            )
        )
        return
    if (
        work.repository_full_name,
        work.base_ref,
        work.base_sha,
        work.head_ref,
    ) != requested_identity:
        raise RuntimeError("merge group delivery disagrees with the recorded candidate identity")
    if not work.destroyed:
        work.destroyed = destroyed
        work.generation += 1
        work.attempts = 0
        work.requested_at = now
        work.available_at = now
        work.lease_owner = None
        work.lease_until = None
        work.recheck_check_id = None


def _requeue_merge_groups(
    session: Session, installation_id: int, repository: str | None, pull_number: int | None = None
) -> None:
    now = utcnow()
    scope = [
        MergeGroupWork.installation_id == installation_id,
        MergeGroupWork.destroyed.is_(False),
    ]
    if repository is not None:
        scope.append(MergeGroupWork.repository_full_name == repository)
    if pull_number is not None:
        scope.append(MergeGroupWork.pull_number == pull_number)
    session.execute(
        update(MergeGroupWork)
        .where(*scope)
        .values(
            generation=MergeGroupWork.generation + 1,
            requested_at=now,
            available_at=now,
            attempts=0,
            lease_owner=None,
            lease_until=None,
            recheck_check_id=None,
        )
    )


class ServiceLease(Base):
    """A database-coordinated singleton lease such as the reconciler."""

    __tablename__ = "service_leases"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner: Mapped[str] = mapped_column(String(128), nullable=False)
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuthorityJob(Base):
    """Coalesced repository or installation authority-change fan-out."""

    __tablename__ = "authority_jobs"
    __table_args__ = (
        UniqueConstraint(
            "installation_id",
            "scope_key",
            "base_ref",
            name="uq_authority_job_scope",
        ),
        Index("ix_authority_jobs_claim", "state", "available_at", "lease_until"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    installation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    scope_key: Mapped[str] = mapped_column(String(512), nullable=False)
    base_ref: Mapped[str] = mapped_column(
        String(MAX_AUTHORITY_BASE_REF_LENGTH), nullable=False, default=""
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    pull_cursor_number: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    handled_pull_fingerprints: Mapped[dict[str, str]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    listing_next_page: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    listing_last_number: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    listing_expected_total: Mapped[int | None] = mapped_column(Integer)
    membership_next_page: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    membership_expected_total: Mapped[int | None] = mapped_column(Integer)
    target_base_refs: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    # Direct PR events and coalesced authority evidence share this wake serial.
    interactive_wake_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pending_base_refs: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    pending_full_rescan: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pending_rescan_reason: Mapped[str | None] = mapped_column(String(255))
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(2000))


class AuthorityEpoch(Base):
    """Monotonic installation fence for broad authority/identity changes."""

    __tablename__ = "authority_epochs"

    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class SharedHeadEpoch(Base):
    """Monotonic fence shared by every pull request on one head commit."""

    __tablename__ = "shared_head_epochs"
    __table_args__ = (
        CheckConstraint(
            "generation >= 1",
            name="ck_shared_head_epochs_generation_positive",
        ),
        CheckConstraint(
            "invalidated_generation >= 0 AND invalidated_generation <= generation",
            name="ck_shared_head_epochs_invalidation_bounds",
        ),
        CheckConstraint(
            "attempts >= 0",
            name="ck_shared_head_epochs_attempts_nonnegative",
        ),
        CheckConstraint(
            "work_class IN ('interactive', 'recovery')",
            name="ck_shared_head_epochs_work_class",
        ),
        Index("ix_shared_head_epochs_changed_at", "changed_at"),
        Index(
            "ix_shared_head_epochs_claim",
            "work_class",
            "available_at",
            "lease_until",
            postgresql_where=text("invalidated_generation < generation"),
            sqlite_where=text("invalidated_generation < generation"),
        ),
    )

    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_full_name: Mapped[str] = mapped_column(String(512), primary_key=True)
    head_sha: Mapped[str] = mapped_column(String(64), primary_key=True)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    invalidated_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    work_class: Mapped[WorkClass] = mapped_column(
        String(16), nullable=False, default=WORK_CLASS_INTERACTIVE
    )
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(2000))


class ReconciliationState(Base):
    """Last successful evaluation observed for one open pull request.

    This is intentionally separate from the human-facing evaluation audit.
    A successful no-policy or closed-pull evaluation still proves that the
    reconciler saw the requested head and should not immediately refill the
    queue on its next scan.
    """

    __tablename__ = "reconciliation_states"
    __table_args__ = (Index("ix_reconciliation_states_observed_at", "observed_at"),)

    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_full_name: Mapped[str] = mapped_column(String(512), primary_key=True)
    pull_number: Mapped[int] = mapped_column(Integer, primary_key=True)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    # Older workers can complete a discarded stale-generation evaluation.
    # Trust a completion only when its writer also confirmed this timestamp.
    confirmed_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class InstallationApiBudget(Base):
    """REST core quota and discovery position shared by installation replicas."""

    __tablename__ = "installation_api_budgets"

    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    remaining: Mapped[int] = mapped_column(Integer, nullable=False)
    reset_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    probe_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    repository_cursor: Mapped[str] = mapped_column(String(512), nullable=False)
    accounting_revision: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    pull_cursor_repository: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    pull_cursor_number: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class ProviderBackpressure(Base):
    """A durable GitHub rate-limit circuit shared by every application pod."""

    __tablename__ = "provider_backpressure"

    # ``0`` is the App-wide circuit; positive values are GitHub installation
    # IDs. A numeric key keeps every claim query portable across PostgreSQL
    # and SQLite without building dynamic scope strings in SQL.
    installation_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    blocked_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str] = mapped_column(String(2000), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


@dataclass(frozen=True, slots=True)
class JobRequest:
    """Input used to enqueue or coalesce an evaluation."""

    installation_id: int
    repository_full_name: str
    pull_number: int
    reason: str
    head_sha_hint: str | None = None
    work_class: WorkClass = WORK_CLASS_INTERACTIVE
    # Reconciliation records when GitHub supplied this head. A direct webhook
    # accepted after that instant is newer durable evidence and must win over
    # the scan's eventually consistent listing.
    observed_at: datetime | None = None
    base_ref_hint: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "repository_full_name",
            normalize_repository_full_name(self.repository_full_name),
        )
        if (
            self.reason in {PERIODIC_RECONCILIATION_REASON, SCHEDULED_RECHECK_REASON}
            and self.work_class == WORK_CLASS_INTERACTIVE
        ):
            # Keep the public request type safe for older call sites. Periodic
            # work is never allowed to impersonate a webhook-triggered job.
            object.__setattr__(self, "work_class", WORK_CLASS_RECOVERY)
        if self.work_class not in {WORK_CLASS_INTERACTIVE, WORK_CLASS_RECOVERY}:
            raise ValueError("work_class must be interactive or recovery")
        if self.observed_at is not None:
            if self.observed_at.tzinfo is None:
                raise ValueError("observed_at must include a timezone")
            object.__setattr__(self, "observed_at", self.observed_at.astimezone(UTC))
        validate_base_ref_hint(self.base_ref_hint)


@dataclass(frozen=True, slots=True)
class AuthorityRequest:
    """An authority change that must re-evaluate a repository or installation."""

    installation_id: int
    repository_full_name: str | None
    base_ref: str | None
    reason: str

    def __post_init__(self) -> None:
        if self.repository_full_name is not None:
            object.__setattr__(
                self,
                "repository_full_name",
                normalize_repository_full_name(self.repository_full_name),
            )

    @property
    def scope_key(self) -> str:
        """Return a non-null key suitable for database uniqueness."""
        return self.repository_full_name or "*"


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    """Leased immutable view of an evaluation job."""

    id: int
    installation_id: int
    repository_full_name: str
    pull_number: int
    reason: str
    work_class: WorkClass
    head_sha_hint: str | None
    last_delivery_id: str | None
    webhook_trace_context: TrustedTraceContext | None
    generation: int
    authority_generation: int
    shared_head_generation: int
    attempts: int
    requested_at: datetime
    available_at: datetime
    lease_owner: str
    base_ref_hint: str | None = None

    @property
    def keeps_published_check(self) -> bool:
        """Whether this attempt may leave the published result in place.

        A timer or base recheck requests a fresh assessment, so it keeps the result
        until its evaluation differs. Stronger triggers replace the reason, and
        ``QueueStore.fail`` and a long ``defer`` turn it into revoke-first
        work. Only the first attempt qualifies: a lease reclaimed after a
        crash or shutdown blocks first as well.
        """
        return self.reason in PRESERVING_RECHECK_REASONS and self.attempts <= 1


@dataclass(frozen=True, slots=True)
class ClaimedAuthorityJob:
    """Leased immutable authority fan-out job."""

    id: int
    installation_id: int
    repository_full_name: str | None
    base_ref: str | None
    reason: str
    generation: int
    attempts: int
    lease_owner: str
    pull_cursor_number: int = 0
    handled_pull_fingerprints: tuple[tuple[str, str], ...] = ()
    listing_next_page: int = 1
    listing_last_number: int = 0
    interactive_wake_generation: int = 0
    listing_expected_total: int | None = None
    membership_next_page: int = 1
    membership_expected_total: int | None = None
    target_base_refs: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class ClaimedSharedHeadInvalidation:
    """Leased immutable work item for one exact commit-scoped check."""

    installation_id: int
    repository_full_name: str
    head_sha: str
    generation: int
    work_class: WorkClass
    attempts: int
    requested_at: datetime
    available_at: datetime
    lease_owner: str


@dataclass(frozen=True, slots=True)
class DeliveryAcceptance:
    """Durable acceptance result and exact shared-head generation token."""

    accepted: bool
    shared_head_generation: int | None = None

    def __bool__(self) -> bool:
        """Preserve boolean acceptance checks at internal call sites."""
        return self.accepted


@dataclass(frozen=True, slots=True)
class CheckWriteGuard:
    """Held per-pull-request GitHub check writer guard."""

    key: int
    connection: Connection | None = None
    local_lock: threading.Lock | None = None
    shared: bool = False


class _EvaluationJobAlreadyPresentError(Exception):
    """Abort reconciliation so a tentative shared-head epoch bump rolls back."""


class _EvaluationJobBindingLostError(Exception):
    """Abort a hintless bind so its tentative exact-head bump rolls back."""


def validate_database_schema(bind: Engine | Connection) -> None:
    """Validate the deployed database against this release's metadata."""
    validate_database_schema_contract(
        bind, Base.metadata, revision=DATABASE_MIGRATION_HEAD, version=SCHEMA_VERSION
    )


class QueueStore:
    """Database-backed latest-wins work queue.

    A job is unique per installation/repository/pull request. New triggers bump
    its generation, so a worker cannot delete work that arrived during an
    earlier evaluation.
    """

    def __init__(self, database_url: str) -> None:
        is_postgresql = database_url.startswith("postgresql")
        connect_args: dict[str, Any]
        engine_options: dict[str, Any] = {"pool_pre_ping": True}
        if database_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
        elif is_postgresql:
            # Webhook ingestion is time-bounded. A dead database endpoint or an
            # exhausted application pool must fail within that budget so GitHub
            # can redeliver instead of holding a request indefinitely.
            connect_args = {
                **isolated_postgresql_connect_args(database_url),
                "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
                "options": (
                    f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MILLISECONDS} "
                    "-c search_path=public"
                ),
            }
            engine_options["pool_timeout"] = DATABASE_POOL_TIMEOUT_SECONDS
        else:
            connect_args = {}
        self.engine = create_engine(
            database_url,
            connect_args=connect_args,
            **engine_options,
        )
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)
        self._lock_engine: Engine | None = None
        if self.engine.dialect.name == "postgresql":
            # Advisory locks must never return to a reusable connection pool:
            # an uncertain unlock would otherwise poison that pooled session.
            self._lock_engine = create_engine(
                database_url,
                connect_args={
                    **isolated_postgresql_connect_args(database_url),
                    "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
                    "options": (
                        f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MILLISECONDS} "
                        "-c search_path=public"
                    ),
                },
                poolclass=NullPool,
                pool_pre_ping=True,
            )
        # SQLite is development/test-only. A bounded stripe set provides
        # in-process ordering there; production PostgreSQL uses exact advisory
        # locks shared by every replica.
        self._check_write_locks = tuple(threading.Lock() for _ in range(256))
        # Authority publication guards can be nested around check-writer
        # guards. A distinct local namespace prevents deterministic stripe
        # self-deadlocks in SQLite development and tests.
        self._authority_locks = tuple(threading.Lock() for _ in range(256))

    def initialize(self) -> None:
        """Reject a database that has not been explicitly migrated to this release."""
        self.validate_schema()

    def validate_schema(self) -> None:
        """Validate the Alembic head, compatibility marker, and required schema."""
        validate_database_schema(self.engine)

    def close(self) -> None:
        """Dispose pooled connections."""
        self.engine.dispose()
        if self._lock_engine is not None:
            self._lock_engine.dispose()

    @staticmethod
    def _check_write_key(repository: str, scope: str | int) -> int:
        digest = hashlib.blake2b(
            f"extra-codeowners\0{repository}\0{scope}".encode(),
            digest_size=8,
        ).digest()
        return int.from_bytes(digest, byteorder="big", signed=True)

    def acquire_check_write_guard(
        self,
        repository: str,
        scope: str | int,
        timeout_seconds: float = 30.0,
    ) -> CheckWriteGuard | None:
        """Become the sole check writer, returning ``None`` after a bounded wait.

        PostgreSQL session advisory locks are released by the server if a
        process or connection dies, closing the publish/revoke crash window.
        """
        key = self._check_write_key(repository, scope)
        return self._acquire_guard(
            key,
            timeout_seconds=timeout_seconds,
            shared=False,
            local_locks=self._check_write_locks,
        )

    def acquire_authority_guard(
        self,
        installation_id: int,
        *,
        shared: bool,
        timeout_seconds: float = 30.0,
    ) -> CheckWriteGuard | None:
        """Acquire the installation authority publication/ingress guard.

        PostgreSQL publishers take a shared lock, so normal evaluations remain
        concurrent. Authority webhook ingestion takes the exclusive variant,
        ordering its durable fence before or after every final Check Run write.
        SQLite uses the same exclusive local lock for both modes.
        """
        key = self._check_write_key(
            "__extra_codeowners_authority__", f"installation:{installation_id}"
        )
        return self._acquire_guard(
            key,
            timeout_seconds=timeout_seconds,
            shared=shared,
            local_locks=self._authority_locks,
        )

    def _acquire_guard(
        self,
        key: int,
        *,
        timeout_seconds: float,
        shared: bool,
        local_locks: tuple[threading.Lock, ...],
    ) -> CheckWriteGuard | None:
        """Acquire one exact advisory/local lock key."""
        if self._lock_engine is not None:
            connection = self._lock_engine.connect()
            try:
                connection.execute(
                    text("SELECT set_config('statement_timeout', :timeout, false)"),
                    {"timeout": f"{max(1, int(timeout_seconds * 1000))}ms"},
                )
                lock_function = "pg_advisory_lock_shared" if shared else "pg_advisory_lock"
                connection.execute(text(f"SELECT {lock_function}(:key)"), {"key": key})
                # PostgreSQL advisory locks are session-scoped, so committing
                # here retains the lock while preventing a network/API wait
                # from leaving an idle transaction open on the database.
                connection.commit()
                return CheckWriteGuard(key=key, connection=connection, shared=shared)
            except Exception:
                connection.invalidate()
                connection.close()
                raise

        local_lock = local_locks[key % len(local_locks)]
        if not local_lock.acquire(timeout=max(0.0, timeout_seconds)):
            return None
        return CheckWriteGuard(key=key, local_lock=local_lock)

    @staticmethod
    def release_check_write_guard(guard: CheckWriteGuard) -> None:
        """Release a guard acquired by :meth:`acquire_check_write_guard`."""
        if guard.connection is not None:
            try:
                unlock_function = (
                    "pg_advisory_unlock_shared" if guard.shared else "pg_advisory_unlock"
                )
                unlocked = guard.connection.execute(
                    text(f"SELECT {unlock_function}(:key)"), {"key": guard.key}
                ).scalar_one()
                if unlocked is not True:
                    raise RuntimeError("PostgreSQL advisory guard was not held by this session")
                guard.connection.commit()
            except Exception:
                # Physically discard an uncertain session; PostgreSQL releases
                # its advisory locks when that connection is terminated.
                guard.connection.invalidate()
                raise
            finally:
                guard.connection.close()
            return
        if guard.local_lock is None:  # pragma: no cover - dataclass is internal
            raise RuntimeError("check write guard has no lock")
        guard.local_lock.release()

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Open a transactional session."""
        with self._sessions.begin() as session:
            yield session

    @staticmethod
    def _shared_head_generation_in_session(
        session: Session,
        installation_id: int,
        repository_full_name: str,
        head_sha: str | None,
    ) -> int:
        if head_sha is None:
            return 0
        return int(
            session.scalar(
                select(SharedHeadEpoch.generation).where(
                    SharedHeadEpoch.installation_id == installation_id,
                    SharedHeadEpoch.repository_full_name == repository_full_name,
                    SharedHeadEpoch.head_sha == head_sha,
                )
            )
            or 0
        )

    @staticmethod
    def _touch_shared_head_epoch_in_session(session: Session, request: JobRequest) -> int:
        """Return the current head generation and keep its fence out of pruning.

        An open pull request's epoch must not age into retention pruning. A
        real write also makes a concurrent prune re-check the row's age
        instead of deleting a fence that a recheck was just bound to.
        """
        head_sha = validate_head_sha(request.head_sha_hint or "")
        session.execute(
            update(SharedHeadEpoch)
            .where(
                SharedHeadEpoch.installation_id == request.installation_id,
                SharedHeadEpoch.repository_full_name == request.repository_full_name,
                SharedHeadEpoch.head_sha == head_sha,
            )
            .values(changed_at=utcnow())
        )
        return QueueStore._shared_head_generation_in_session(
            session, request.installation_id, request.repository_full_name, head_sha
        )

    @staticmethod
    def _advance_shared_head_epoch_in_session(
        session: Session,
        request: JobRequest,
        *,
        shared_head_locked: bool = False,
    ) -> int:
        if not shared_head_locked:
            QueueStore._lock_shared_head_epoch_in_session(session, request)
        head_sha = validate_head_sha(request.head_sha_hint or "")
        now = utcnow()
        foreground_waiting = bool(
            session.scalar(
                select(
                    exists(
                        select(EvaluationJob.id).where(
                            EvaluationJob.installation_id == request.installation_id,
                            EvaluationJob.repository_full_name == request.repository_full_name,
                            EvaluationJob.state == "pending",
                            EvaluationJob.work_class == WORK_CLASS_INTERACTIVE,
                            or_(
                                EvaluationJob.head_sha_hint == head_sha,
                                and_(
                                    EvaluationJob.head_sha_hint.is_(None),
                                    EvaluationJob.pull_number == request.pull_number,
                                ),
                            ),
                        )
                    )
                )
            )
        )
        key = (
            SharedHeadEpoch.installation_id == request.installation_id,
            SharedHeadEpoch.repository_full_name == request.repository_full_name,
            SharedHeadEpoch.head_sha == head_sha,
        )
        updated = session.execute(
            update(SharedHeadEpoch)
            .where(*key)
            .values(
                generation=SharedHeadEpoch.generation + 1,
                # Preserve a pending direct invalidation or evaluation. Once
                # both finish, later bulk rechecks can use recovery again.
                work_class=case(
                    (
                        or_(
                            literal(foreground_waiting),
                            and_(
                                SharedHeadEpoch.work_class == WORK_CLASS_INTERACTIVE,
                                SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation,
                            ),
                        ),
                        WORK_CLASS_INTERACTIVE,
                    ),
                    else_=request.work_class,
                ),
                changed_at=now,
                available_at=now,
                attempts=0,
                lease_owner=None,
                lease_until=None,
                last_error=None,
            )
        )
        if getattr(updated, "rowcount", 0) == 1:
            generation = session.scalar(select(SharedHeadEpoch.generation).where(*key))
            if generation is None:  # pragma: no cover - protected by this transaction
                raise RuntimeError("shared-head epoch disappeared during advancement")
            return int(generation)
        epoch = SharedHeadEpoch(
            installation_id=request.installation_id,
            repository_full_name=request.repository_full_name,
            head_sha=head_sha,
            generation=1,
            invalidated_generation=0,
            work_class=WORK_CLASS_INTERACTIVE if foreground_waiting else request.work_class,
            changed_at=now,
            available_at=now,
        )
        session.add(epoch)
        # Preserve the shared-head -> evaluation-job lock order even when this
        # transaction creates the epoch. Without an explicit flush, SQLAlchemy
        # may defer the INSERT until a later evaluation-job statement.
        session.flush((epoch,))
        return 1

    @staticmethod
    def _lock_shared_head_epoch_in_session(session: Session, request: JobRequest) -> None:
        """Serialize one head key before the pull-request queue-row lock.

        A row lock alone cannot protect an absent epoch. PostgreSQL's
        transaction-scoped advisory lock covers both the absent and present
        cases, then the row lock orders a later epoch update with every other
        operation on that head. SQLite is deliberately single-process only;
        its write transaction provides the corresponding local ordering.
        """

        head_sha = validate_head_sha(request.head_sha_hint or "")
        if session.get_bind().dialect.name == "postgresql":
            key = QueueStore._check_write_key(
                "__extra_codeowners_shared_head_epoch__",
                f"{request.installation_id}:{request.repository_full_name}:{head_sha}",
            )
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
        session.scalar(
            select(SharedHeadEpoch.installation_id)
            .where(
                SharedHeadEpoch.installation_id == request.installation_id,
                SharedHeadEpoch.repository_full_name == request.repository_full_name,
                SharedHeadEpoch.head_sha == head_sha,
            )
            .with_for_update()
        )

    @staticmethod
    def _enqueue_in_session(
        session: Session,
        request: JobRequest,
        delivery_id: str | None = None,
        shared_head_generation: int | None = None,
        *,
        preserve_different_head: bool = False,
        preserve_work_class: bool = True,
    ) -> None:
        now = utcnow()
        authority_generation = (
            session.scalar(
                select(AuthorityEpoch.generation).where(
                    AuthorityEpoch.installation_id == request.installation_id
                )
            )
            or 0
        )
        if shared_head_generation is None:
            shared_head_generation = QueueStore._shared_head_generation_in_session(
                session,
                request.installation_id,
                request.repository_full_name,
                request.head_sha_hint,
            )
        values: dict[str, Any] = {
            "generation": EvaluationJob.generation + 1,
            # Work class is monotonic until the row completes, except when a
            # scan has proof that its different head is newer than an old
            # interactive row. In that case the direct row is stale and the
            # recovery scan replaces it at recovery priority.
            "work_class": (
                case(
                    (
                        EvaluationJob.work_class == WORK_CLASS_INTERACTIVE,
                        WORK_CLASS_INTERACTIVE,
                    ),
                    else_=request.work_class,
                )
                if preserve_work_class
                else request.work_class
            ),
            "authority_generation": authority_generation,
            "shared_head_generation": shared_head_generation,
            "reason": request.reason,
            "head_sha_hint": request.head_sha_hint,
            "base_ref_hint": request.base_ref_hint,
            "requested_at": now,
            "available_at": now,
            "state": "pending",
            "attempts": 0,
            # A newer durable trigger fences any old claimant by generation.
            # Release its lease too, so a direct webhook can be claimed by a
            # foreground lane immediately instead of waiting for a recovery
            # lease to expire.
            "lease_owner": None,
            "lease_until": None,
            "last_error": None,
        }
        if delivery_id is not None:
            values["last_delivery_id"] = delivery_id
        key = (
            EvaluationJob.installation_id == request.installation_id,
            EvaluationJob.repository_full_name == request.repository_full_name,
            EvaluationJob.pull_number == request.pull_number,
        )
        update_conditions = list(key)
        if preserve_different_head:
            update_conditions.append(
                or_(
                    EvaluationJob.head_sha_hint.is_(None),
                    EvaluationJob.head_sha_hint == request.head_sha_hint,
                )
            )
        updated = session.execute(update(EvaluationJob).where(*update_conditions).values(**values))
        if getattr(updated, "rowcount", 0) == 1:
            QueueStore._wake_authority_for_interactive(session, request)
            return
        if preserve_different_head:
            existing_id = session.scalar(select(EvaluationJob.id).where(*key))
            if existing_id is not None:
                return
        session.add(
            EvaluationJob(
                installation_id=request.installation_id,
                repository_full_name=request.repository_full_name,
                pull_number=request.pull_number,
                reason=request.reason,
                work_class=request.work_class,
                head_sha_hint=request.head_sha_hint,
                base_ref_hint=request.base_ref_hint,
                last_delivery_id=delivery_id,
                authority_generation=authority_generation,
                shared_head_generation=shared_head_generation,
                requested_at=now,
                available_at=now,
            )
        )
        QueueStore._wake_authority_for_interactive(session, request)

    @staticmethod
    def _wake_authority_for_interactive(session: Session, request: JobRequest) -> None:
        """Wake covering fences for direct events and internal revocation retries."""
        if request.work_class == WORK_CLASS_INTERACTIVE:
            branch_match = (
                AuthorityJob.base_ref == request.base_ref_hint
                if request.base_ref_hint is not None
                else false()
            )
            base_scope = or_(
                AuthorityJob.scope_key == "*",
                and_(
                    AuthorityJob.scope_key == request.repository_full_name,
                    or_(
                        AuthorityJob.base_ref == "",
                        branch_match,
                    ),
                ),
            )
            session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.installation_id == request.installation_id,
                    base_scope,
                    AuthorityJob.state == "pending",
                )
                .values(
                    available_at=utcnow(),
                    interactive_wake_generation=AuthorityJob.interactive_wake_generation + 1,
                )
            )

    def enqueue(self, request: JobRequest) -> None:
        """Enqueue an evaluation, fencing a known head in the same transaction.

        Known-head callers must not be able to create an evaluation that
        references an epoch concurrently removed by pruning. Hintless work has
        no exact head to fence and retains the ordinary coalescing path.
        """
        if request.head_sha_hint is not None:
            self.enqueue_shared_head_trigger(request)
            return
        for _ in range(5):
            try:
                with self.session() as session:
                    self._enqueue_in_session(session, request)
                return
            except IntegrityError:
                # A concurrent first trigger inserted the unique PR job. Retry
                # as an update after the losing transaction has rolled back.
                continue
        raise RuntimeError("could not enqueue evaluation after concurrent inserts")

    def enqueue_shared_head_trigger(self, request: JobRequest) -> None:
        """Atomically advance a live-head fence and enqueue its evaluation."""
        for _ in range(5):
            try:
                with self.session() as session:
                    shared_head_generation = self._advance_shared_head_epoch_in_session(
                        session,
                        request,
                    )
                    self._enqueue_in_session(
                        session,
                        request,
                        shared_head_generation=shared_head_generation,
                    )
                return
            except IntegrityError:
                # Roll back the tentative epoch when another transaction wins
                # either first insert, then retry in the common lock order.
                continue
        raise RuntimeError("could not enqueue shared-head trigger after concurrent inserts")

    def enqueue_for_shared_head_generation(
        self,
        request: JobRequest,
        shared_head_generation: int,
    ) -> bool:
        """Bind fan-out work to one still-current head generation.

        A different-head row for the same pull request is preserved. GitHub's
        commit-to-pulls response is eventually consistent, while a directly
        accepted newer head is durable evidence that must not be overwritten
        by stale fan-out.
        """
        head_sha = validate_head_sha(request.head_sha_hint or "")
        if shared_head_generation <= 0:
            raise ValueError("shared_head_generation must be positive")
        for _ in range(5):
            try:
                with self.session() as session:
                    current_generation = session.scalar(
                        select(SharedHeadEpoch.generation)
                        .where(
                            SharedHeadEpoch.installation_id == request.installation_id,
                            SharedHeadEpoch.repository_full_name == request.repository_full_name,
                            SharedHeadEpoch.head_sha == head_sha,
                        )
                        .with_for_update()
                    )
                    if current_generation != shared_head_generation:
                        return False
                    existing_head = session.scalar(
                        select(EvaluationJob.head_sha_hint)
                        .where(
                            EvaluationJob.installation_id == request.installation_id,
                            EvaluationJob.repository_full_name == request.repository_full_name,
                            EvaluationJob.pull_number == request.pull_number,
                        )
                        .with_for_update()
                    )
                    if existing_head is not None and existing_head != head_sha:
                        return True
                    self._enqueue_in_session(
                        session,
                        request,
                        shared_head_generation=shared_head_generation,
                        preserve_different_head=True,
                    )
                return True
            except IntegrityError:
                # A direct trigger can insert the pull row between the two
                # reads. Retry so a different current head remains preserved.
                continue
        raise RuntimeError("could not enqueue shared-head fan-out after concurrent inserts")

    def enqueue_if_absent(self, request: JobRequest) -> bool:
        """Atomically fence and enqueue genuinely missing reconciliation work."""
        for _ in range(5):
            try:
                with self.session() as session:
                    shared_head_generation = 0
                    if request.head_sha_hint is not None:
                        shared_head_generation = self._advance_shared_head_epoch_in_session(
                            session,
                            request,
                        )
                    now = utcnow()
                    authority_generation = (
                        session.scalar(
                            select(AuthorityEpoch.generation).where(
                                AuthorityEpoch.installation_id == request.installation_id
                            )
                        )
                        or 0
                    )
                    values: dict[str, Any] = {
                        "installation_id": request.installation_id,
                        "repository_full_name": request.repository_full_name,
                        "pull_number": request.pull_number,
                        "reason": request.reason,
                        "work_class": request.work_class,
                        "head_sha_hint": request.head_sha_hint,
                        "base_ref_hint": request.base_ref_hint,
                        "generation": 1,
                        "authority_generation": authority_generation,
                        "shared_head_generation": shared_head_generation,
                        "state": "pending",
                        "attempts": 0,
                        "requested_at": now,
                        "available_at": now,
                    }
                    index_elements = (
                        "installation_id",
                        "repository_full_name",
                        "pull_number",
                    )
                    dialect_name = session.get_bind().dialect.name
                    if dialect_name == "postgresql":
                        inserted_id = session.scalar(
                            postgresql_insert(EvaluationJob)
                            .values(**values)
                            .on_conflict_do_nothing(index_elements=index_elements)
                            .returning(EvaluationJob.id)
                        )
                    elif dialect_name == "sqlite":
                        inserted_id = session.scalar(
                            sqlite_insert(EvaluationJob)
                            .values(**values)
                            .on_conflict_do_nothing(index_elements=index_elements)
                            .returning(EvaluationJob.id)
                        )
                    else:  # pragma: no cover - QueueStore supports SQLite and PostgreSQL
                        raise RuntimeError(
                            f"reconciliation insert does not support {dialect_name!r}"
                        )
                    if inserted_id is None:
                        # Raising inside the context rolls back the epoch
                        # increment that preceded this conflicting insert.
                        raise _EvaluationJobAlreadyPresentError
                return True
            except _EvaluationJobAlreadyPresentError:
                return False
            except IntegrityError:
                # Different pull requests can race to create the same
                # shared-head epoch. Retry the complete atomic insert so the
                # losing epoch transaction is not mistaken for durable work.
                continue
        raise RuntimeError("could not reconcile evaluation after concurrent inserts")

    def enqueue_reconciliation_if_due(
        self,
        request: JobRequest,
        recheck_seconds: int,
    ) -> bool:
        """Revalidate one visible pull request without continuously refilling work.

        The scan still compares every open pull request returned by GitHub.
        A changed head is queued immediately, even when an older row is
        pending. An unchanged head is queued only when it has never completed
        or its successful evaluation is older than ``recheck_seconds``. A
        recheck of a confirmed, unchanged head is queued as
        ``SCHEDULED_RECHECK_REASON`` without advancing the exact-head epoch,
        so a quiet pull request's published check is not reset on a timer.
        """
        if recheck_seconds < 1:
            raise ValueError("recheck_seconds must be positive")
        return self._enqueue_recheck(request, recheck_seconds) != "unchanged"

    def base_recheck_fingerprint(self, request: JobRequest) -> str | None:
        """Return a prior successful base fingerprint, never raw audit evidence."""
        with self._sessions() as session:
            row = session.scalar(
                select(EvaluationAudit).where(
                    EvaluationAudit.repository_full_name == request.repository_full_name,
                    EvaluationAudit.pull_number == request.pull_number,
                    EvaluationAudit.head_sha == request.head_sha_hint,
                    EvaluationAudit.conclusion == "success",
                )
            )
            value = None if row is None else row.details.get("base_evidence_fingerprint")
            return (
                value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None
            )

    def enqueue_base_recheck(
        self, request: JobRequest, recheck_seconds: int, *, fingerprint: str | None = None
    ) -> bool:
        """Reassess a base push without revoking a confirmed unchanged head.

        Supersede older queued observations, but preserve a stronger trigger
        and the oldest recheck deadline. Publication still waits for authority
        discovery and fetches current approval and policy evidence. Return
        whether the queued work may retain the published check; false means
        the caller must also run its usual fast invalidation.
        """
        if request.reason != "push.repository_base":
            raise ValueError("base rechecks require a repository base push")
        if recheck_seconds < 1:
            raise ValueError("recheck_seconds must be positive")
        return (
            self._enqueue_recheck(
                replace(request, observed_at=utcnow()),
                recheck_seconds,
                force=True,
                fingerprint=fingerprint,
            )
            == "preserving"
        )

    def _enqueue_recheck(
        self,
        request: JobRequest,
        recheck_seconds: int,
        *,
        force: bool = False,
        fingerprint: str | None = None,
    ) -> Literal["unchanged", "preserving", "revoking"]:
        if request.work_class != WORK_CLASS_RECOVERY:
            raise ValueError("reconciliation work must use the recovery class")
        if request.head_sha_hint is None:
            raise ValueError("reconciliation work requires an exact head SHA")
        if request.observed_at is None:
            raise ValueError("reconciliation work requires a GitHub observation timestamp")
        key = (
            EvaluationJob.installation_id == request.installation_id,
            EvaluationJob.repository_full_name == request.repository_full_name,
            EvaluationJob.pull_number == request.pull_number,
        )
        state_key = {
            "installation_id": request.installation_id,
            "repository_full_name": request.repository_full_name,
            "pull_number": request.pull_number,
        }
        for _ in range(5):
            try:
                with self.session() as session:
                    now = utcnow()
                    # Webhooks advance their exact-head fence before they
                    # touch this PR row. Take that same lock first so a scan
                    # cannot deadlock with delivery acceptance.
                    self._lock_shared_head_epoch_in_session(session, request)
                    existing = session.scalar(select(EvaluationJob).where(*key).with_for_update())
                    state = session.get(ReconciliationState, state_key, with_for_update=True)
                    proven = False
                    if (
                        force
                        and fingerprint is not None
                        and re.fullmatch(r"[0-9a-f]{64}", fingerprint)
                    ):
                        audit = session.scalar(
                            select(EvaluationAudit)
                            .where(
                                EvaluationAudit.repository_full_name
                                == request.repository_full_name,
                                EvaluationAudit.pull_number == request.pull_number,
                                EvaluationAudit.head_sha == request.head_sha_hint,
                                EvaluationAudit.conclusion == "success",
                            )
                            .with_for_update()
                        )
                        proven = (
                            audit is not None
                            and audit.details.get("base_evidence_fingerprint") == fingerprint
                            and state is not None
                            and state.head_sha == request.head_sha_hint
                            and state.confirmed_completed_at == state.completed_at
                        )
                    if existing is not None:
                        if existing.head_sha_hint == request.head_sha_hint:
                            disposition: Literal["unchanged", "preserving", "revoking"] = (
                                "unchanged"
                            )
                            if force:
                                disposition = self._refresh_recheck_in_session(
                                    session, request, existing, recheck_seconds, now, proven=proven
                                )
                            if state is not None:
                                state.observed_at = now
                            return disposition
                        if existing.work_class == WORK_CLASS_INTERACTIVE:
                            requested_at = existing.requested_at
                            if requested_at.tzinfo is None:
                                requested_at = requested_at.replace(tzinfo=UTC)
                            if requested_at > request.observed_at:
                                # The direct webhook arrived after GitHub
                                # supplied this scan result. It is newer
                                # durable evidence than an eventually
                                # consistent listing, so preserve it.
                                if state is not None:
                                    state.observed_at = now
                                return "unchanged"
                        # GitHub shows a different current head than the job
                        # durable state. This is the missed-webhook repair
                        # case; advance the exact head fence now rather than
                        # waiting for the old row to reach the evaluator.
                        generation = self._advance_shared_head_epoch_in_session(
                            session,
                            request,
                            shared_head_locked=True,
                        )
                        self._enqueue_in_session(
                            session,
                            request,
                            shared_head_generation=generation,
                            preserve_work_class=existing.work_class != WORK_CLASS_INTERACTIVE,
                        )
                        if state is not None:
                            state.observed_at = now
                        return "revoking"
                    # A confirmed completion of this exact head is the only
                    # state that lets a scan skip work or keep the result.
                    confirmed_at = (
                        state.completed_at
                        if state is not None
                        and state.head_sha == request.head_sha_hint
                        and state.confirmed_completed_at == state.completed_at
                        and (not force or proven)
                        else None
                    )
                    if confirmed_at is not None and confirmed_at.tzinfo is None:
                        confirmed_at = confirmed_at.replace(tzinfo=UTC)
                    if (
                        not force
                        and confirmed_at is not None
                        and confirmed_at > now - timedelta(seconds=recheck_seconds)
                    ):
                        assert state is not None
                        state.observed_at = now
                        return "unchanged"
                    if confirmed_at is not None:
                        # A confirmed head can be reassessed without resetting
                        # its published check. Bind to the current generation
                        # and let the evaluator keep
                        # the result unless the new evaluation differs.
                        request = replace(
                            request,
                            reason=BASE_RECHECK_REASON if force else SCHEDULED_RECHECK_REASON,
                        )
                        generation = self._touch_shared_head_epoch_in_session(session, request)
                    else:
                        generation = self._advance_shared_head_epoch_in_session(
                            session,
                            request,
                            shared_head_locked=True,
                        )
                    authority_generation = (
                        session.scalar(
                            select(AuthorityEpoch.generation).where(
                                AuthorityEpoch.installation_id == request.installation_id
                            )
                        )
                        or 0
                    )
                    values: dict[str, Any] = {
                        **state_key,
                        "reason": request.reason,
                        "work_class": request.work_class,
                        "head_sha_hint": request.head_sha_hint,
                        "base_ref_hint": request.base_ref_hint,
                        "generation": 1,
                        "authority_generation": authority_generation,
                        "shared_head_generation": generation,
                        "state": "pending",
                        "attempts": 0,
                        "requested_at": now,
                        "available_at": now,
                    }
                    index_elements = (
                        "installation_id",
                        "repository_full_name",
                        "pull_number",
                    )
                    dialect_name = session.get_bind().dialect.name
                    if dialect_name == "postgresql":
                        inserted_id = session.scalar(
                            postgresql_insert(EvaluationJob)
                            .values(**values)
                            .on_conflict_do_nothing(index_elements=index_elements)
                            .returning(EvaluationJob.id)
                        )
                    elif dialect_name == "sqlite":
                        inserted_id = session.scalar(
                            sqlite_insert(EvaluationJob)
                            .values(**values)
                            .on_conflict_do_nothing(index_elements=index_elements)
                            .returning(EvaluationJob.id)
                        )
                    else:  # pragma: no cover - QueueStore supports SQLite and PostgreSQL
                        raise RuntimeError(
                            f"reconciliation insert does not support {dialect_name!r}"
                        )
                    if inserted_id is None:
                        # The exact-head update above must roll back if a
                        # webhook won the unique-row race.
                        raise _EvaluationJobAlreadyPresentError
                return "preserving" if confirmed_at is not None else "revoking"
            except _EvaluationJobAlreadyPresentError:
                return "unchanged"
            except IntegrityError:
                continue
        raise RuntimeError("could not enqueue due reconciliation work after concurrent inserts")

    def _refresh_recheck_in_session(
        self,
        session: Session,
        request: JobRequest,
        existing: EvaluationJob,
        recheck_seconds: int,
        now: datetime,
        *,
        proven: bool,
    ) -> Literal["preserving", "revoking"]:
        """Supersede one same-head observation under the epoch and queue locks."""
        original_requested_at = existing.requested_at
        requested_at = original_requested_at
        if requested_at.tzinfo is None:
            requested_at = requested_at.replace(tzinfo=UTC)
        lease_until = existing.lease_until
        if lease_until is not None and lease_until.tzinfo is None:
            lease_until = lease_until.replace(tzinfo=UTC)
        was_preserving = existing.reason in PRESERVING_RECHECK_REASONS
        preserving = (
            was_preserving
            and proven
            and existing.attempts <= 1
            and (lease_until is None or lease_until >= now)
            and requested_at > now - timedelta(seconds=recheck_seconds)
        )
        reason = existing.reason
        if preserving:
            reason = BASE_RECHECK_REASON
        elif was_preserving:
            reason = PERIODIC_RECONCILIATION_REASON
        generation = (
            self._advance_shared_head_epoch_in_session(session, request, shared_head_locked=True)
            if was_preserving and not preserving
            else self._touch_shared_head_epoch_in_session(session, request)
        )
        self._enqueue_in_session(
            session, replace(request, reason=reason), shared_head_generation=generation
        )
        if preserving:
            session.execute(
                update(EvaluationJob)
                .where(EvaluationJob.id == existing.id)
                .values(requested_at=original_requested_at)
            )
        return "preserving" if preserving else "revoking"

    @staticmethod
    def _authority_reason(*reasons: str) -> str:
        """A base refresh must not weaken coalesced revoke-first authority."""
        return next(
            (reason for reason in reversed(reasons) if reason != "push.repository_base"),
            reasons[-1],
        )

    @staticmethod
    def _enqueue_authority_in_session(
        session: Session,
        request: AuthorityRequest,
    ) -> None:
        now = utcnow()
        scope_key = request.scope_key
        # All branches share one repository listing and uniqueness key. An
        # empty target set means all branches; otherwise it is a bounded batch.
        base_ref = ""
        target_ref = request.base_ref if request.repository_full_name is not None else None
        if target_ref is not None and len(target_ref) > MAX_AUTHORITY_BASE_REF_LENGTH:
            target_ref = None
        existing = session.scalar(
            select(AuthorityJob)
            .where(
                AuthorityJob.installation_id == request.installation_id,
                AuthorityJob.scope_key == scope_key,
                AuthorityJob.base_ref == base_ref,
            )
            .with_for_update()
        )
        if existing is not None:
            existing.available_at = now
            existing.interactive_wake_generation += 1
            unstarted = (
                existing.lease_owner is None
                and existing.attempts == 0
                and existing.listing_next_page == 1
                and existing.listing_last_number == 0
                and not existing.handled_pull_fingerprints
            )
            if unstarted:
                # No observation exists yet, so widening this queued pass
                # cannot omit evidence or discard a completed prefix.
                if target_ref is None:
                    existing.target_base_refs = {}
                elif existing.target_base_refs:
                    targets = dict(existing.target_base_refs)
                    targets[target_ref] = QueueStore._authority_reason(
                        targets.get(target_ref, request.reason), request.reason
                    )
                    existing.target_base_refs = (
                        targets
                        if len(targets) <= MAX_BASE_SCOPED_AUTHORITY_JOBS_PER_REPOSITORY
                        else {}
                    )
                existing.reason = QueueStore._authority_reason(existing.reason, request.reason)
            elif target_ref is None:
                existing.pending_full_rescan = True
                existing.pending_rescan_reason = QueueStore._authority_reason(
                    *existing.pending_base_refs.values(),
                    existing.pending_rescan_reason or request.reason,
                    request.reason,
                )
                existing.pending_base_refs = {}
            else:
                if not existing.pending_full_rescan:
                    pending_refs = dict(existing.pending_base_refs)
                    pending_refs[target_ref] = QueueStore._authority_reason(
                        pending_refs.get(target_ref, request.reason), request.reason
                    )
                    if len(pending_refs) > MAX_BASE_SCOPED_AUTHORITY_JOBS_PER_REPOSITORY:
                        existing.pending_full_rescan = True
                        existing.pending_rescan_reason = QueueStore._authority_reason(
                            *pending_refs.values(), request.reason
                        )
                        existing.pending_base_refs = {}
                    else:
                        existing.pending_base_refs = pending_refs
            return
        # A concurrent first insertion must take the caller's IntegrityError
        # retry path and then coalesce under its row lock. An UPDATE here could
        # overwrite a newly inserted row that has already begun discovery.
        session.add(
            AuthorityJob(
                installation_id=request.installation_id,
                scope_key=scope_key,
                base_ref=base_ref,
                target_base_refs=({target_ref: request.reason} if target_ref is not None else {}),
                reason=request.reason,
                requested_at=now,
                available_at=now,
            )
        )

    @staticmethod
    def _bump_authority_epoch_in_session(session: Session, installation_id: int) -> None:
        now = utcnow()
        updated = session.execute(
            update(AuthorityEpoch)
            .where(AuthorityEpoch.installation_id == installation_id)
            .values(
                generation=AuthorityEpoch.generation + 1,
                changed_at=now,
            )
        )
        if getattr(updated, "rowcount", 0) == 0:
            session.add(
                AuthorityEpoch(
                    installation_id=installation_id,
                    generation=1,
                    changed_at=now,
                )
            )

    def accept_delivery(
        self,
        delivery_id: str,
        event: str,
        request: JobRequest | AuthorityRequest | MergeGroupTrigger | None,
        authority_guard_timeout_seconds: float = 5.0,
        *,
        trace_context: TrustedTraceContext | None = None,
        invalidate_merge_groups: bool = False,
    ) -> DeliveryAcceptance:
        """Record and enqueue one webhook atomically.

        The returned generation binds synchronous invalidation to the exact
        head fence accepted in this transaction. A duplicate delivery returns
        its original token instead of borrowing a newer head generation.
        """
        merge_group_digest = (
            _merge_group_delivery_digest(request)
            if isinstance(request, MergeGroupTrigger)
            else None
        )
        if (event == "merge_group") != (merge_group_digest is not None):
            raise ValueError("merge group delivery must have a matching candidate trigger")
        authority_guard: CheckWriteGuard | None = None
        if isinstance(request, (AuthorityRequest, MergeGroupTrigger)):
            authority_guard = self.acquire_authority_guard(
                request.installation_id,
                shared=False,
                timeout_seconds=authority_guard_timeout_seconds,
            )
            if authority_guard is None:
                raise RuntimeError("timed out waiting to record an authority change")
        try:
            for _ in range(5):
                try:
                    with self.session() as session:
                        existing_delivery = session.get(WebhookDelivery, delivery_id)
                        if existing_delivery is not None:
                            if existing_delivery.event != event:
                                raise RuntimeError(
                                    "accepted delivery ID was replayed with a different event"
                                )
                            if existing_delivery.merge_group_digest != merge_group_digest:
                                raise RuntimeError(
                                    "accepted delivery ID was replayed with different "
                                    "merge group evidence"
                                )
                            if isinstance(request, JobRequest):
                                expected_identity = (
                                    request.installation_id,
                                    request.repository_full_name,
                                    request.pull_number,
                                    request.head_sha_hint,
                                )
                                stored_identity = (
                                    existing_delivery.installation_id,
                                    existing_delivery.repository_full_name,
                                    existing_delivery.pull_number,
                                    existing_delivery.head_sha,
                                )
                                legacy_identity = (
                                    existing_delivery.invalidation_required
                                    and all(value is None for value in stored_identity)
                                    and existing_delivery.shared_head_generation is None
                                )
                                if not legacy_identity and stored_identity != expected_identity:
                                    raise RuntimeError(
                                        "accepted delivery ID was replayed with different "
                                        "pull-request identity"
                                    )
                            return DeliveryAcceptance(
                                accepted=False,
                                shared_head_generation=existing_delivery.shared_head_generation,
                            )
                        delivery = WebhookDelivery(
                            delivery_id=delivery_id,
                            event=event,
                            merge_group_digest=merge_group_digest,
                            invalidation_required=isinstance(request, JobRequest),
                            producer_trace_id=(
                                trace_context.trace_id if trace_context is not None else None
                            ),
                            producer_span_id=(
                                trace_context.span_id if trace_context is not None else None
                            ),
                            producer_trace_flags=(
                                trace_context.trace_flags if trace_context is not None else None
                            ),
                        )
                        session.add(delivery)
                        shared_head_generation: int | None = None
                        if isinstance(request, JobRequest):
                            shared_head_generation = self._advance_shared_head_epoch_in_session(
                                session, request
                            )
                            delivery.installation_id = request.installation_id
                            delivery.repository_full_name = request.repository_full_name
                            delivery.pull_number = request.pull_number
                            delivery.head_sha = request.head_sha_hint
                            delivery.shared_head_generation = shared_head_generation
                            self._enqueue_in_session(
                                session,
                                request,
                                delivery_id,
                                shared_head_generation,
                            )
                            if invalidate_merge_groups:
                                _requeue_merge_groups(
                                    session,
                                    request.installation_id,
                                    request.repository_full_name,
                                    request.pull_number,
                                )
                        elif isinstance(request, AuthorityRequest):
                            delivery.installation_id = request.installation_id
                            delivery.repository_full_name = request.repository_full_name
                            if request.repository_full_name is None:
                                self._bump_authority_epoch_in_session(
                                    session, request.installation_id
                                )
                            self._enqueue_authority_in_session(session, request)
                            if invalidate_merge_groups:
                                _requeue_merge_groups(
                                    session, request.installation_id, request.repository_full_name
                                )
                        elif isinstance(request, MergeGroupTrigger):
                            _enqueue_merge_group(session, request)
                    return DeliveryAcceptance(
                        accepted=True,
                        shared_head_generation=shared_head_generation,
                    )
                except IntegrityError:
                    # This may be either the same delivery racing or a different
                    # delivery racing to create the unique PR job. Retry so the
                    # latter delivery and its trigger are not silently discarded.
                    continue
            raise RuntimeError("could not accept webhook delivery after concurrent inserts")
        finally:
            if authority_guard is not None:
                self.release_check_write_guard(authority_guard)

    def enqueue_authority(self, request: AuthorityRequest) -> None:
        """Coalesce internal installation-to-repository authority fan-out."""
        for _ in range(5):
            try:
                with self.session() as session:
                    self._enqueue_authority_in_session(session, request)
                return
            except IntegrityError:
                continue
        raise RuntimeError("could not enqueue authority work after concurrent inserts")

    def delivery_needs_invalidation(self, delivery_id: str) -> bool:
        """Return whether an accepted PR trigger still needs check revocation."""
        with self._sessions() as session:
            delivery = session.get(WebhookDelivery, delivery_id)
            return bool(
                delivery is not None
                and delivery.invalidation_required
                and delivery.invalidation_completed_at is None
            )

    def mark_delivery_invalidated(self, delivery_id: str) -> bool:
        """Record successful check revocation for replay-safe webhook retries."""
        with self.session() as session:
            result = session.execute(
                update(WebhookDelivery)
                .where(
                    WebhookDelivery.delivery_id == delivery_id,
                    WebhookDelivery.invalidation_required.is_(True),
                    WebhookDelivery.invalidation_completed_at.is_(None),
                )
                .values(invalidation_completed_at=utcnow())
            )
            return getattr(result, "rowcount", 0) == 1

    def is_current_generation(self, job: ClaimedJob) -> bool:
        """Return whether no newer trigger has superseded a claimed evaluation."""
        with self._sessions() as session:
            generation = session.scalar(
                select(EvaluationJob.generation).where(EvaluationJob.id == job.id)
            )
            return generation == job.generation

    def bind_claim_to_head(self, job: ClaimedJob, head_sha: str) -> ClaimedJob | None:
        """Bind a hintless internal claim to the head observed from GitHub.

        Direct webhook work is already bound transactionally at acceptance.
        Internal fan-out can lack a trustworthy head until it fetches current
        state, so binding advances that head and creates durable invalidation
        work in the same transaction.
        """
        head_sha = validate_head_sha(head_sha)
        if job.head_sha_hint is not None:
            return job if job.head_sha_hint == head_sha else None
        try:
            with self.session() as session:
                shared_head_generation = self._advance_shared_head_epoch_in_session(
                    session,
                    JobRequest(
                        installation_id=job.installation_id,
                        repository_full_name=job.repository_full_name,
                        pull_number=job.pull_number,
                        reason=job.reason,
                        head_sha_hint=head_sha,
                        work_class=job.work_class,
                    ),
                )
                bound = session.execute(
                    update(EvaluationJob)
                    .where(
                        EvaluationJob.id == job.id,
                        EvaluationJob.generation == job.generation,
                        EvaluationJob.lease_owner == job.lease_owner,
                        EvaluationJob.state == "pending",
                        EvaluationJob.head_sha_hint.is_(None),
                    )
                    .values(
                        head_sha_hint=head_sha,
                        shared_head_generation=shared_head_generation,
                    )
                )
                if getattr(bound, "rowcount", 0) != 1:
                    raise _EvaluationJobBindingLostError
        except _EvaluationJobBindingLostError:
            return None
        return replace(
            job,
            head_sha_hint=head_sha,
            shared_head_generation=shared_head_generation,
        )

    def shared_head_generation_is_current(self, job: ClaimedJob, head_sha: str) -> bool:
        """Return whether no accepted trigger superseded this head evidence."""
        head_sha = validate_head_sha(head_sha)
        if job.head_sha_hint != head_sha:
            return False
        with self._sessions() as session:
            current = self._shared_head_generation_in_session(
                session,
                job.installation_id,
                job.repository_full_name,
                head_sha,
            )
        return current == job.shared_head_generation

    def shared_head_generation_is_publishable(self, job: ClaimedJob, head_sha: str) -> bool:
        """Return whether this exact head generation was durably invalidated."""
        head_sha = validate_head_sha(head_sha)
        if job.head_sha_hint != head_sha:
            return False
        with self._sessions() as session:
            row = session.execute(
                select(
                    SharedHeadEpoch.generation,
                    SharedHeadEpoch.invalidated_generation,
                ).where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == head_sha,
                )
            ).one_or_none()
        if row is None:
            return job.shared_head_generation == 0
        return bool(
            row.generation == job.shared_head_generation
            and row.invalidated_generation == job.shared_head_generation
        )

    def shared_head_invalidation_is_pending(
        self,
        installation_id: int,
        repository_full_name: str,
        head_sha: str,
        generation: int,
    ) -> bool:
        """Bind a synchronous reset to one exact still-pending generation."""
        repository_full_name = normalize_repository_full_name(repository_full_name)
        head_sha = validate_head_sha(head_sha)
        with self._sessions() as session:
            row = session.execute(
                select(
                    SharedHeadEpoch.generation,
                    SharedHeadEpoch.invalidated_generation,
                ).where(
                    SharedHeadEpoch.installation_id == installation_id,
                    SharedHeadEpoch.repository_full_name == repository_full_name,
                    SharedHeadEpoch.head_sha == head_sha,
                )
            ).one_or_none()
        return bool(
            row is not None
            and row.generation == generation
            and row.invalidated_generation < generation
        )

    def shared_head_generation(
        self,
        installation_id: int,
        repository_full_name: str,
        head_sha: str,
    ) -> int:
        """Return the current durable generation for one commit-scoped check."""
        repository_full_name = normalize_repository_full_name(repository_full_name)
        head_sha = validate_head_sha(head_sha)
        with self._sessions() as session:
            return self._shared_head_generation_in_session(
                session,
                installation_id,
                repository_full_name,
                head_sha,
            )

    def shared_head_invalidation_generation(
        self,
        installation_id: int,
        repository_full_name: str,
        head_sha: str,
    ) -> int:
        """Return the latest generation whose exact-head reset completed."""
        repository_full_name = normalize_repository_full_name(repository_full_name)
        head_sha = validate_head_sha(head_sha)
        with self._sessions() as session:
            return int(
                session.scalar(
                    select(SharedHeadEpoch.invalidated_generation).where(
                        SharedHeadEpoch.installation_id == installation_id,
                        SharedHeadEpoch.repository_full_name == repository_full_name,
                        SharedHeadEpoch.head_sha == head_sha,
                    )
                )
                or 0
            )

    def has_superseding_job(self, job: ClaimedJob) -> bool:
        """Return whether a newer generation still needs evaluation."""
        with self._sessions() as session:
            return bool(
                session.scalar(
                    select(EvaluationJob.id).where(
                        EvaluationJob.id == job.id,
                        EvaluationJob.generation > job.generation,
                        EvaluationJob.state == "pending",
                    )
                )
            )

    def has_blocking_authority(self, job: ClaimedJob, base_ref: str) -> bool:
        """Return whether unresolved authority work can affect this pull request.

        Authority rows remain present while pending, leased, retrying, or dead.
        Every such state blocks publication because the evaluation may have
        collected membership, policy, label, CODEOWNERS, or merge-base evidence
        from before the accepted authority change.
        """
        with self._sessions() as session:
            return bool(
                session.scalar(
                    select(AuthorityJob.id)
                    .where(
                        AuthorityJob.installation_id == job.installation_id,
                        AuthorityJob.scope_key.in_(("*", job.repository_full_name)),
                        AuthorityJob.base_ref.in_(("", base_ref)),
                    )
                    .limit(1)
                )
            )

    def is_current_claim(self, job: ClaimedJob) -> bool:
        """Return whether a claim still owns the current, unexpired generation."""
        now = utcnow()
        with self._sessions() as session:
            row = session.execute(
                select(
                    EvaluationJob.generation,
                    EvaluationJob.authority_generation,
                    EvaluationJob.lease_owner,
                    EvaluationJob.lease_until,
                ).where(EvaluationJob.id == job.id)
            ).one_or_none()
            if row is None or row.lease_until is None:
                return False
            current_authority_generation = (
                session.scalar(
                    select(AuthorityEpoch.generation).where(
                        AuthorityEpoch.installation_id == job.installation_id
                    )
                )
                or 0
            )
            expiry = row.lease_until
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            return bool(
                row.generation == job.generation
                and row.authority_generation == job.authority_generation
                and current_authority_generation == job.authority_generation
                and row.lease_owner == job.lease_owner
                and expiry >= now
            )

    def renew_claim(self, job: ClaimedJob, lease_seconds: int) -> bool:
        """Extend a current claim without reviving a superseded generation."""
        with self.session() as session:
            renewed = session.execute(
                update(EvaluationJob)
                .where(
                    EvaluationJob.id == job.id,
                    EvaluationJob.generation == job.generation,
                    EvaluationJob.lease_owner == job.lease_owner,
                    EvaluationJob.state == "pending",
                )
                .values(lease_until=utcnow() + timedelta(seconds=lease_seconds))
            )
            return getattr(renewed, "rowcount", 0) == 1

    @staticmethod
    def _provider_available_condition(installation_id: int | Any, now: datetime) -> Any:
        """Build a portable predicate for App-wide and installation rate circuits."""
        return ~exists(
            select(ProviderBackpressure.installation_id).where(
                ProviderBackpressure.installation_id.in_((0, installation_id)),
                ProviderBackpressure.blocked_until > now,
            )
        )

    def record_provider_backpressure(
        self,
        installation_id: int | None,
        error: str,
        delay_seconds: int,
    ) -> None:
        """Open or extend a durable GitHub rate-limit circuit.

        A global App-authenticated limit uses installation ID zero. A worker
        never shortens a circuit another replica has already observed.
        """
        key = 0 if installation_id is None else installation_id
        if key < 0:
            raise ValueError("installation_id must be positive or None")
        delay_seconds = max(1, min(delay_seconds, 86_400))
        now = utcnow()
        blocked_until = now + timedelta(seconds=delay_seconds)
        for _ in range(3):
            try:
                with self.session() as session:
                    row = session.get(
                        ProviderBackpressure,
                        key,
                        with_for_update=True,
                    )
                    if row is None:
                        session.add(
                            ProviderBackpressure(
                                installation_id=key,
                                blocked_until=blocked_until,
                                reason=error[:2000],
                                updated_at=now,
                            )
                        )
                    else:
                        existing_blocked_until = row.blocked_until
                        if existing_blocked_until.tzinfo is None:
                            existing_blocked_until = existing_blocked_until.replace(tzinfo=UTC)
                        row.blocked_until = max(existing_blocked_until, blocked_until)
                        row.reason = error[:2000]
                        row.updated_at = now
                return
            except IntegrityError:
                continue
        raise RuntimeError("could not record provider backpressure after concurrent inserts")

    def provider_is_backpressured(self, installation_id: int | None) -> bool:
        """Return whether App-wide or installation-scoped GitHub work must pause."""
        if installation_id is not None and installation_id <= 0:
            raise ValueError("installation_id must be positive or None")
        now = utcnow()
        scopes = (0,) if installation_id is None else (0, installation_id)
        with self._sessions() as session:
            return bool(
                session.scalar(
                    select(ProviderBackpressure.installation_id)
                    .where(
                        ProviderBackpressure.installation_id.in_(scopes),
                        ProviderBackpressure.blocked_until > now,
                    )
                    .limit(1)
                )
                is not None
            )

    def claim_shared_head_invalidation(
        self,
        owner: str,
        lease_seconds: int,
        work_class: WorkClass | None = None,
    ) -> ClaimedSharedHeadInvalidation | None:
        """Lease the oldest available exact-head reset in an optional work class."""
        now = utcnow()
        lease_until = now + timedelta(seconds=lease_seconds)
        for _ in range(3):
            with self.session() as session:
                conditions = [
                    SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation,
                    SharedHeadEpoch.available_at <= now,
                    or_(
                        SharedHeadEpoch.lease_until.is_(None),
                        SharedHeadEpoch.lease_until < now,
                    ),
                    self._provider_available_condition(
                        SharedHeadEpoch.installation_id,
                        now,
                    ),
                ]
                if work_class is not None:
                    conditions.append(SharedHeadEpoch.work_class == work_class)
                candidate = session.scalar(
                    select(SharedHeadEpoch)
                    .where(*conditions)
                    .order_by(
                        SharedHeadEpoch.available_at,
                        SharedHeadEpoch.changed_at,
                        SharedHeadEpoch.installation_id,
                        SharedHeadEpoch.repository_full_name,
                        SharedHeadEpoch.head_sha,
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if candidate is None:
                    return None
                claimed_attempts = int(candidate.attempts) + 1
                claimed = session.execute(
                    update(SharedHeadEpoch)
                    .where(
                        SharedHeadEpoch.installation_id == candidate.installation_id,
                        SharedHeadEpoch.repository_full_name == candidate.repository_full_name,
                        SharedHeadEpoch.head_sha == candidate.head_sha,
                        SharedHeadEpoch.generation == candidate.generation,
                        SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation,
                        or_(
                            SharedHeadEpoch.lease_until.is_(None),
                            SharedHeadEpoch.lease_until < now,
                        ),
                    )
                    .values(
                        lease_owner=owner,
                        lease_until=lease_until,
                        attempts=SharedHeadEpoch.attempts + 1,
                    )
                    .execution_options(synchronize_session=False)
                )
                if getattr(claimed, "rowcount", 0) != 1:
                    continue
                return ClaimedSharedHeadInvalidation(
                    installation_id=candidate.installation_id,
                    repository_full_name=candidate.repository_full_name,
                    head_sha=candidate.head_sha,
                    generation=candidate.generation,
                    work_class=candidate.work_class,
                    attempts=claimed_attempts,
                    requested_at=candidate.changed_at,
                    available_at=candidate.available_at,
                    lease_owner=owner,
                )
        return None

    def is_current_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
    ) -> bool:
        """Return whether an unexpired lease still owns this pending generation."""
        now = utcnow()
        with self._sessions() as session:
            row = session.execute(
                select(
                    SharedHeadEpoch.generation,
                    SharedHeadEpoch.invalidated_generation,
                    SharedHeadEpoch.lease_owner,
                    SharedHeadEpoch.lease_until,
                ).where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                )
            ).one_or_none()
        if row is None or row.lease_until is None:
            return False
        lease_until = row.lease_until
        if lease_until.tzinfo is None:
            lease_until = lease_until.replace(tzinfo=UTC)
        return bool(
            row.generation == job.generation
            and row.invalidated_generation < job.generation
            and row.lease_owner == job.lease_owner
            and lease_until >= now
        )

    def renew_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
        lease_seconds: int,
    ) -> bool:
        """Renew only an unexpired lease for the same pending generation."""
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(SharedHeadEpoch)
                .where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                    SharedHeadEpoch.generation == job.generation,
                    SharedHeadEpoch.invalidated_generation < job.generation,
                    SharedHeadEpoch.lease_owner == job.lease_owner,
                    SharedHeadEpoch.lease_until >= now,
                )
                .values(lease_until=now + timedelta(seconds=lease_seconds))
            )
            return getattr(result, "rowcount", 0) == 1

    def complete_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
    ) -> bool:
        """Mark the claimed generation reset only while its lease is valid."""
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(SharedHeadEpoch)
                .where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                    SharedHeadEpoch.generation == job.generation,
                    SharedHeadEpoch.invalidated_generation < job.generation,
                    SharedHeadEpoch.lease_owner == job.lease_owner,
                    SharedHeadEpoch.lease_until >= now,
                )
                .values(
                    invalidated_generation=job.generation,
                    lease_owner=None,
                    lease_until=None,
                    last_error=None,
                )
            )
            return getattr(result, "rowcount", 0) == 1

    def fail_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
        error: str,
        max_delay_seconds: int,
    ) -> bool:
        """Retry an exact-head reset indefinitely with bounded backoff."""
        delay_seconds = max(1, min(max_delay_seconds, 2 ** min(job.attempts, 30)))
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(SharedHeadEpoch)
                .where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                    SharedHeadEpoch.generation == job.generation,
                    SharedHeadEpoch.invalidated_generation < job.generation,
                    SharedHeadEpoch.lease_owner == job.lease_owner,
                    SharedHeadEpoch.lease_until >= now,
                )
                .values(
                    available_at=now + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            return getattr(result, "rowcount", 0) == 1

    def defer_shared_head_invalidation(
        self,
        job: ClaimedSharedHeadInvalidation,
        error: str,
        delay_seconds: int,
    ) -> bool:
        """Release a rate-limited reset without consuming its retry budget."""
        delay_seconds = max(1, min(delay_seconds, 86_400))
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(SharedHeadEpoch)
                .where(
                    SharedHeadEpoch.installation_id == job.installation_id,
                    SharedHeadEpoch.repository_full_name == job.repository_full_name,
                    SharedHeadEpoch.head_sha == job.head_sha,
                    SharedHeadEpoch.generation == job.generation,
                    SharedHeadEpoch.invalidated_generation < job.generation,
                    SharedHeadEpoch.lease_owner == job.lease_owner,
                    SharedHeadEpoch.lease_until >= now,
                )
                .values(
                    attempts=case(
                        (SharedHeadEpoch.attempts > 0, SharedHeadEpoch.attempts - 1),
                        else_=0,
                    ),
                    available_at=now + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            return getattr(result, "rowcount", 0) == 1

    def claim(
        self,
        owner: str,
        lease_seconds: int,
        work_class: WorkClass | None = None,
        *,
        require_shared_head_ready: bool = False,
    ) -> ClaimedJob | None:
        """Atomically lease the oldest available job in an optional work class."""
        now = utcnow()
        lease_until = now + timedelta(seconds=lease_seconds)
        for _ in range(3):
            with self.session() as session:
                conditions = [
                    EvaluationJob.state == "pending",
                    EvaluationJob.available_at <= now,
                    or_(EvaluationJob.lease_until.is_(None), EvaluationJob.lease_until < now),
                    ~exists(
                        select(AuthorityJob.id).where(
                            AuthorityJob.installation_id == EvaluationJob.installation_id,
                            or_(
                                AuthorityJob.scope_key == "*",
                                and_(
                                    AuthorityJob.scope_key == EvaluationJob.repository_full_name,
                                    or_(
                                        AuthorityJob.base_ref == "",
                                        and_(
                                            EvaluationJob.base_ref_hint.is_not(None),
                                            AuthorityJob.base_ref == EvaluationJob.base_ref_hint,
                                        ),
                                    ),
                                ),
                            ),
                        )
                    ),
                    self._provider_available_condition(EvaluationJob.installation_id, now),
                ]
                if require_shared_head_ready:
                    # A bounded concurrent worker must not spend API budget
                    # evaluating a row whose own exact-head reset is still
                    # pending. The public default stays compatible with the
                    # lower-level claim contract used by recovery tooling.
                    conditions.append(
                        ~exists(
                            select(SharedHeadEpoch.installation_id).where(
                                EvaluationJob.shared_head_generation > 0,
                                SharedHeadEpoch.installation_id == EvaluationJob.installation_id,
                                SharedHeadEpoch.repository_full_name
                                == EvaluationJob.repository_full_name,
                                SharedHeadEpoch.head_sha == EvaluationJob.head_sha_hint,
                                SharedHeadEpoch.invalidated_generation
                                < EvaluationJob.shared_head_generation,
                            )
                        )
                    )
                if work_class is not None:
                    conditions.append(EvaluationJob.work_class == work_class)
                candidate = session.scalar(
                    select(EvaluationJob.id)
                    .where(*conditions)
                    .order_by(
                        EvaluationJob.available_at,
                        EvaluationJob.id,
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if candidate is None:
                    return None
                claimed = session.execute(
                    update(EvaluationJob)
                    .where(
                        EvaluationJob.id == candidate,
                        EvaluationJob.state == "pending",
                        or_(EvaluationJob.lease_until.is_(None), EvaluationJob.lease_until < now),
                    )
                    .values(
                        lease_owner=owner,
                        lease_until=lease_until,
                        attempts=EvaluationJob.attempts + 1,
                        # Reclaiming an expired lease fences the previous
                        # worker even when no webhook generation changed.
                        generation=case(
                            (
                                EvaluationJob.lease_owner.is_not(None),
                                EvaluationJob.generation + 1,
                            ),
                            else_=EvaluationJob.generation,
                        ),
                    )
                )
                if getattr(claimed, "rowcount", 0) != 1:
                    continue
                row = session.get(EvaluationJob, candidate)
                if row is None:  # pragma: no cover - protected by the transaction
                    continue
                delivery = (
                    session.get(WebhookDelivery, row.last_delivery_id)
                    if row.last_delivery_id is not None
                    else None
                )
                return ClaimedJob(
                    id=row.id,
                    installation_id=row.installation_id,
                    repository_full_name=row.repository_full_name,
                    pull_number=row.pull_number,
                    reason=row.reason,
                    work_class=row.work_class,
                    head_sha_hint=row.head_sha_hint,
                    base_ref_hint=row.base_ref_hint,
                    last_delivery_id=row.last_delivery_id,
                    webhook_trace_context=TrustedTraceContext.from_values(
                        delivery.producer_trace_id if delivery is not None else None,
                        delivery.producer_span_id if delivery is not None else None,
                        delivery.producer_trace_flags if delivery is not None else None,
                    ),
                    generation=row.generation,
                    authority_generation=row.authority_generation,
                    shared_head_generation=row.shared_head_generation,
                    attempts=row.attempts,
                    requested_at=row.requested_at,
                    available_at=row.available_at,
                    lease_owner=owner,
                )
        return None

    def observe_evaluation_base(self, job: ClaimedJob, base_ref: str) -> bool:
        """Persist fresh scheduling context without treating it as authority evidence."""
        hint = (
            base_ref
            if isinstance(base_ref, str)
            and base_ref
            and len(base_ref) <= MAX_AUTHORITY_BASE_REF_LENGTH
            and not any(ord(char) < 32 or ord(char) == 127 for char in base_ref)
            else None
        )
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(EvaluationJob)
                .where(
                    EvaluationJob.id == job.id,
                    EvaluationJob.generation == job.generation,
                    EvaluationJob.lease_owner == job.lease_owner,
                    EvaluationJob.lease_until > now,
                    EvaluationJob.state == "pending",
                )
                .values(base_ref_hint=hint)
            )
            if getattr(result, "rowcount", 0) != 1:
                return False
            if hint is not None and job.work_class == WORK_CLASS_INTERACTIVE:
                self._wake_authority_for_interactive(
                    session,
                    JobRequest(
                        installation_id=job.installation_id,
                        repository_full_name=job.repository_full_name,
                        pull_number=job.pull_number,
                        reason=job.reason,
                        head_sha_hint=job.head_sha_hint,
                        work_class=job.work_class,
                        base_ref_hint=hint,
                    ),
                )
            return True

    @staticmethod
    def _authority_direct_waiter() -> ColumnElement[bool]:
        return exists(
            select(EvaluationJob.id).where(
                EvaluationJob.installation_id == AuthorityJob.installation_id,
                or_(
                    AuthorityJob.scope_key == "*",
                    and_(
                        EvaluationJob.repository_full_name == AuthorityJob.scope_key,
                        or_(
                            AuthorityJob.base_ref == "",
                            and_(
                                EvaluationJob.base_ref_hint.is_not(None),
                                AuthorityJob.base_ref == EvaluationJob.base_ref_hint,
                            ),
                        ),
                    ),
                ),
                EvaluationJob.state == "pending",
                EvaluationJob.work_class == WORK_CLASS_INTERACTIVE,
            )
        )

    def authority_has_direct_waiter(self, job: ClaimedAuthorityJob) -> bool:
        """Whether this fence blocks a direct event or promoted revocation retry."""
        with self.session() as session:
            return bool(
                session.scalar(
                    select(self._authority_direct_waiter()).where(AuthorityJob.id == job.id)
                )
            )

    def claim_authority(
        self, owner: str, lease_seconds: int, *, prioritize_interactive: bool = True
    ) -> ClaimedAuthorityJob | None:
        """Lease authority work, preferring fences blocking direct PR events."""
        now = utcnow()
        lease_until = now + timedelta(seconds=lease_seconds)
        for _ in range(3):
            with self.session() as session:
                direct_waiter = self._authority_direct_waiter()
                targets = func.json_each(AuthorityJob.target_base_refs).table_valued("key", "value")
                all_bases = ~exists(select(literal(1)).select_from(targets).correlate(AuthorityJob))
                candidate = session.scalar(
                    select(AuthorityJob.id)
                    .where(
                        AuthorityJob.state == "pending",
                        AuthorityJob.available_at <= now,
                        or_(AuthorityJob.lease_until.is_(None), AuthorityJob.lease_until < now),
                        self._provider_available_condition(AuthorityJob.installation_id, now),
                    )
                    .order_by(
                        case(
                            (AuthorityJob.scope_key == "*", 0),
                            (direct_waiter if prioritize_interactive else false(), 1),
                            else_=2,
                        ),
                        case(
                            (AuthorityJob.scope_key == "*", 0),
                            (and_(AuthorityJob.base_ref == "", all_bases), 1),
                            else_=2,
                        ),
                        AuthorityJob.available_at,
                        AuthorityJob.id,
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if candidate is None:
                    return None
                claimed = session.execute(
                    update(AuthorityJob)
                    .where(
                        AuthorityJob.id == candidate,
                        AuthorityJob.state == "pending",
                        or_(AuthorityJob.lease_until.is_(None), AuthorityJob.lease_until < now),
                    )
                    .values(
                        lease_owner=owner,
                        lease_until=lease_until,
                        attempts=AuthorityJob.attempts + 1,
                        generation=case(
                            (
                                AuthorityJob.lease_owner.is_not(None),
                                AuthorityJob.generation + 1,
                            ),
                            else_=AuthorityJob.generation,
                        ),
                    )
                )
                if getattr(claimed, "rowcount", 0) != 1:
                    continue
                row = session.get(AuthorityJob, candidate)
                if row is None:  # pragma: no cover - protected by transaction
                    continue
                return ClaimedAuthorityJob(
                    id=row.id,
                    installation_id=row.installation_id,
                    repository_full_name=(None if row.scope_key == "*" else row.scope_key),
                    base_ref=row.base_ref or None,
                    reason=row.reason,
                    generation=row.generation,
                    attempts=row.attempts,
                    lease_owner=owner,
                    pull_cursor_number=row.pull_cursor_number,
                    handled_pull_fingerprints=tuple(row.handled_pull_fingerprints.items()),
                    listing_next_page=row.listing_next_page,
                    listing_last_number=row.listing_last_number,
                    interactive_wake_generation=row.interactive_wake_generation,
                    listing_expected_total=row.listing_expected_total,
                    membership_next_page=row.membership_next_page,
                    membership_expected_total=row.membership_expected_total,
                    target_base_refs=tuple(row.target_base_refs.items()),
                )
        return None

    def renew_authority_claim(self, job: ClaimedAuthorityJob, lease_seconds: int) -> bool:
        """Extend a current authority claim without reviving stale work."""
        with self.session() as session:
            result = session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == job.lease_owner,
                    AuthorityJob.state == "pending",
                )
                .values(lease_until=utcnow() + timedelta(seconds=lease_seconds))
            )
            return getattr(result, "rowcount", 0) == 1

    def advance_authority_cursor(
        self,
        job: ClaimedAuthorityJob,
        number: int,
        handled_pull_fingerprints: Mapping[str, str] | None = None,
        *,
        listing_next_page: int | None = None,
        listing_last_number: int | None = None,
    ) -> bool:
        """Checkpoint handled observations only while this authority claim is current."""
        values: dict[str, Any] = {
            "pull_cursor_number": case(
                (AuthorityJob.pull_cursor_number < number, number),
                else_=AuthorityJob.pull_cursor_number,
            )
        }
        if handled_pull_fingerprints is not None:
            values["handled_pull_fingerprints"] = dict(handled_pull_fingerprints)
        if listing_next_page is not None:
            values["listing_next_page"] = listing_next_page
        if listing_last_number is not None:
            values["listing_last_number"] = listing_last_number
        with self.session() as session:
            result = session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == job.lease_owner,
                    AuthorityJob.lease_until > utcnow(),
                )
                .values(**values)
            )
            return getattr(result, "rowcount", 0) == 1

    def advance_installation_authority_page(
        self,
        job: ClaimedAuthorityJob,
        requests: Sequence[AuthorityRequest],
        *,
        next_page: int,
        expected_total: int | None,
    ) -> bool:
        """Create child fences and checkpoint their page in one fenced transaction."""
        if job.repository_full_name is not None:
            raise ValueError("installation pagination requires an installation authority job")
        if any(
            request.installation_id != job.installation_id or request.repository_full_name is None
            for request in requests
        ):
            raise ValueError("installation page contains a child outside its installation")
        with self.session() as session:
            row = session.scalar(
                select(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == job.lease_owner,
                    AuthorityJob.lease_until > utcnow(),
                )
                .with_for_update()
            )
            if row is None:
                return False
            for request in requests:
                self._enqueue_authority_in_session(session, request)
            row.listing_next_page = next_page
            row.listing_expected_total = expected_total
            return True

    def advance_authority_membership_page(
        self, job: ClaimedAuthorityJob, *, next_page: int, expected_total: int | None
    ) -> bool:
        """Checkpoint a repository fence's complete-membership corroboration."""
        with self.session() as session:
            result = session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == job.lease_owner,
                    AuthorityJob.lease_until > utcnow(),
                )
                .values(membership_next_page=next_page, membership_expected_total=expected_total)
            )
            return getattr(result, "rowcount", 0) == 1

    def complete_authority(self, job: ClaimedAuthorityJob, owner: str) -> bool:
        """Finish a generation and atomically retain any later branch evidence."""
        with self.session() as session:
            row = session.scalar(
                select(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == owner,
                )
                .with_for_update()
            )
            if row is None:
                return False
            if row.pending_full_rescan or row.pending_base_refs:
                # One next batch shares history across every later branch.
                # Never fan out a separate historical scan for each ref.
                targets = {} if row.pending_full_rescan else dict(row.pending_base_refs)
                reason = row.pending_rescan_reason or (
                    next(reversed(targets.values())) if targets else "push.repository_base"
                )
                now = utcnow()
                row.generation += 1
                row.base_ref = ""
                row.target_base_refs = targets
                row.pull_cursor_number = 0
                row.handled_pull_fingerprints = {}
                row.listing_next_page = 1
                row.listing_last_number = 0
                row.listing_expected_total = None
                row.membership_next_page = 1
                row.membership_expected_total = None
                row.interactive_wake_generation = 0
                row.pending_base_refs = {}
                row.pending_full_rescan = False
                row.reason = reason
                row.pending_rescan_reason = None
                row.requested_at = now
                row.available_at = now
                row.state = "pending"
                row.attempts = 0
                row.lease_owner = None
                row.lease_until = None
                row.last_error = None
            else:
                session.delete(row)
            return True

    def fail_authority(
        self,
        job: ClaimedAuthorityJob,
        owner: str,
        error: str,
        max_delay_seconds: int,
        minimum_delay_seconds: int = 1,
    ) -> None:
        """Retry authority fan-out indefinitely with bounded exponential backoff."""
        delay_seconds = max(
            1,
            min(
                max_delay_seconds,
                max(minimum_delay_seconds, 2 ** min(job.attempts, 30)),
            ),
        )
        now = utcnow()
        with self.session() as session:
            result = session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == owner,
                )
                .values(
                    state="pending",
                    # Preserve an arrival during this claim, not every old
                    # waiter: an unchanged persistent failure must still back off.
                    available_at=case(
                        (
                            AuthorityJob.interactive_wake_generation
                            > job.interactive_wake_generation,
                            now,
                        ),
                        else_=now + timedelta(seconds=delay_seconds),
                    ),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            if getattr(result, "rowcount", 0) == 0:
                session.execute(
                    update(AuthorityJob)
                    .where(
                        AuthorityJob.id == job.id,
                        AuthorityJob.generation == job.generation,
                        AuthorityJob.lease_owner == owner,
                    )
                    .values(lease_owner=None, lease_until=None)
                )

    def defer_authority(
        self,
        job: ClaimedAuthorityJob,
        owner: str,
        error: str,
        delay_seconds: int,
        *,
        preserve_direct_wakeup: bool = False,
    ) -> bool:
        """Defer a rate-limited fan-out without consuming its retry budget."""
        delay_seconds = max(1, min(delay_seconds, 86_400))
        with self.session() as session:
            result = session.execute(
                update(AuthorityJob)
                .where(
                    AuthorityJob.id == job.id,
                    AuthorityJob.generation == job.generation,
                    AuthorityJob.lease_owner == owner,
                )
                .values(
                    attempts=case(
                        (AuthorityJob.attempts > 0, AuthorityJob.attempts - 1),
                        else_=0,
                    ),
                    available_at=case(
                        (self._authority_direct_waiter(), utcnow()),
                        else_=utcnow() + timedelta(seconds=delay_seconds),
                    )
                    if preserve_direct_wakeup
                    else utcnow() + timedelta(seconds=delay_seconds),
                    lease_owner=None,
                    lease_until=None,
                    last_error=error[:2000],
                )
            )
            updated = getattr(result, "rowcount", 0) == 1
            if not updated:
                session.execute(
                    update(AuthorityJob)
                    .where(
                        AuthorityJob.id == job.id,
                        AuthorityJob.generation == job.generation,
                        AuthorityJob.lease_owner == owner,
                    )
                    .values(lease_owner=None, lease_until=None)
                )
            return updated

    def complete(self, job: ClaimedJob, owner: str) -> bool:
        """Delete only the claimed generation and report whether it completed."""
        with self.session() as session:
            completed = session.scalar(
                select(EvaluationJob)
                .where(
                    EvaluationJob.id == job.id,
                    EvaluationJob.generation == job.generation,
                    EvaluationJob.lease_owner == owner,
                )
                .with_for_update()
            )
            removed = session.execute(
                delete(EvaluationJob).where(
                    EvaluationJob.id == job.id,
                    EvaluationJob.generation == job.generation,
                    EvaluationJob.lease_owner == owner,
                )
            )
            if getattr(removed, "rowcount", 0) == 0:
                session.execute(
                    update(EvaluationJob)
                    .where(
                        EvaluationJob.id == job.id,
                        EvaluationJob.generation == job.generation,
                        EvaluationJob.lease_owner == owner,
                    )
                    .values(lease_owner=None, lease_until=None)
                )
                return False
            if completed is not None and completed.head_sha_hint is not None:
                state_key = {
                    "installation_id": completed.installation_id,
                    "repository_full_name": completed.repository_full_name,
                    "pull_number": completed.pull_number,
                }
                state = session.get(ReconciliationState, state_key, with_for_update=True)
                now = utcnow()
                if state is None:
                    session.add(
                        ReconciliationState(
                            **state_key,
                            head_sha=completed.head_sha_hint,
                            completed_at=now,
                            confirmed_completed_at=now,
                            observed_at=now,
                        )
                    )
                else:
                    state.head_sha = completed.head_sha_hint
                    state.completed_at = now
                    state.confirmed_completed_at = now
                    state.observed_at = now
            return True

    @staticmethod
    def _recheck_revocation(job: ClaimedJob) -> JobRequest | None:
        """Return the revoke-first request that replaces a preserving recheck."""
        if job.reason not in PRESERVING_RECHECK_REASONS or job.head_sha_hint is None:
            return None
        return JobRequest(
            installation_id=job.installation_id,
            repository_full_name=job.repository_full_name,
            pull_number=job.pull_number,
            reason=PERIODIC_RECONCILIATION_REASON,
            head_sha_hint=job.head_sha_hint,
            work_class=job.work_class,
            base_ref_hint=job.base_ref_hint,
        )

    def _release_claim_in_session(
        self,
        session: Session,
        job: ClaimedJob,
        owner: str,
        revocation: JobRequest | None,
        **values: Any,
    ) -> bool:
        """Release a claim with ``values``, optionally ending a scheduled recheck.

        A scheduled recheck keeps the published result only while it can
        replace it promptly. With ``revocation``, the same transaction advances
        the exact-head epoch and rewrites the row as revoke-first work, so
        invalidation blocks the check before the retry runs.
        """
        if revocation is not None:
            # Webhooks lock the exact-head epoch before the PR row.
            self._lock_shared_head_epoch_in_session(session, revocation)
        claim = (
            EvaluationJob.id == job.id,
            EvaluationJob.generation == job.generation,
            EvaluationJob.lease_owner == owner,
        )
        result = session.execute(update(EvaluationJob).where(*claim).values(**values))
        updated = getattr(result, "rowcount", 0) == 1
        if not updated:
            session.execute(
                update(EvaluationJob).where(*claim).values(lease_owner=None, lease_until=None)
            )
        elif revocation is not None:
            generation = self._advance_shared_head_epoch_in_session(
                session, revocation, shared_head_locked=True
            )
            session.execute(
                update(EvaluationJob)
                .where(EvaluationJob.id == job.id, EvaluationJob.generation == job.generation)
                .values(reason=revocation.reason, shared_head_generation=generation)
            )
        return updated

    def fail(
        self,
        job: ClaimedJob,
        owner: str,
        error: str,
        max_delay_seconds: int,
    ) -> None:
        """Retry evaluation indefinitely with bounded exponential backoff.

        A failed scheduled recheck always becomes revoke-first work: the
        failure may last hours, and the recheck may be the only signal of a
        missed webhook.
        """
        delay_seconds = max(1, min(max_delay_seconds, 2 ** min(job.attempts, 30)))
        with self.session() as session:
            self._release_claim_in_session(
                session,
                job,
                owner,
                self._recheck_revocation(job),
                state="pending",
                available_at=utcnow() + timedelta(seconds=delay_seconds),
                lease_owner=None,
                lease_until=None,
                last_error=error[:2000],
            )

    def defer(
        self,
        job: ClaimedJob,
        owner: str,
        error: str,
        delay_seconds: int,
        *,
        scheduled_recheck_limit_seconds: int | None,
    ) -> bool:
        """Release a claim until a provider-supplied retry time without spending an attempt.

        A scheduled recheck keeps the published result through a deferral
        unless ``scheduled_recheck_limit_seconds`` is set and the retry would
        land later than that many seconds after the recheck was queued. Budget
        pressure alone is not evidence, so short deferrals don't flap the check.
        Callers pass ``None`` only when a reset is already in flight.
        """
        delay_seconds = max(1, min(delay_seconds, 86_400))
        revocation = None
        if scheduled_recheck_limit_seconds is not None:
            requested_at = job.requested_at
            if requested_at.tzinfo is None:
                requested_at = requested_at.replace(tzinfo=UTC)
            retry_at = utcnow() + timedelta(seconds=delay_seconds)
            if retry_at - requested_at > timedelta(seconds=scheduled_recheck_limit_seconds):
                revocation = self._recheck_revocation(job)
        with self.session() as session:
            return self._release_claim_in_session(
                session,
                job,
                owner,
                revocation,
                attempts=case(
                    (EvaluationJob.attempts > 0, EvaluationJob.attempts - 1),
                    else_=0,
                ),
                available_at=utcnow() + timedelta(seconds=delay_seconds),
                lease_owner=None,
                lease_until=None,
                last_error=error[:2000],
            )

    def acquire_service_lease(self, name: str, owner: str, lease_seconds: int) -> bool:
        """Atomically acquire or renew a named cross-process lease."""
        for _ in range(3):
            now = utcnow()
            lease_until = now + timedelta(seconds=lease_seconds)
            try:
                with self.session() as session:
                    renewed = session.execute(
                        update(ServiceLease)
                        .where(
                            ServiceLease.name == name,
                            or_(ServiceLease.owner == owner, ServiceLease.lease_until <= now),
                        )
                        .values(owner=owner, lease_until=lease_until)
                    )
                    if getattr(renewed, "rowcount", 0) == 1:
                        return True

                    existing = session.scalar(
                        select(ServiceLease.name).where(ServiceLease.name == name)
                    )
                    if existing is not None:
                        return False
                    session.add(ServiceLease(name=name, owner=owner, lease_until=lease_until))
                return True
            except IntegrityError:
                # Two first-time contenders may race to insert the primary key.
                # Retry through the conditional UPDATE after the winner commits.
                continue
        return False

    def release_service_lease(self, name: str, owner: str) -> bool:
        """Release a named lease only while it still belongs to the caller."""
        with self.session() as session:
            released = session.execute(
                delete(ServiceLease).where(
                    ServiceLease.name == name,
                    ServiceLease.owner == owner,
                )
            )
            return getattr(released, "rowcount", 0) == 1

    def pending_count(self) -> int:
        """Return queued and leased pending work count."""
        with self._sessions() as session:
            evaluations = int(
                session.scalar(
                    select(func.count())
                    .select_from(EvaluationJob)
                    .where(EvaluationJob.state == "pending")
                )
                or 0
            )
            authorities = int(
                session.scalar(
                    select(func.count())
                    .select_from(AuthorityJob)
                    .where(AuthorityJob.state == "pending")
                )
                or 0
            )
            shared_heads = int(
                session.scalar(
                    select(func.count())
                    .select_from(SharedHeadEpoch)
                    .where(SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation)
                )
                or 0
            )
            return evaluations + authorities + shared_heads

    def pending_work_class_snapshot(self) -> dict[tuple[str, str], tuple[int, datetime | None]]:
        """Return cheap, low-cardinality queue state for Prometheus sampling."""
        snapshot: dict[tuple[str, str], tuple[int, datetime | None]] = {}
        with self._sessions() as session:
            evaluations = session.execute(
                select(
                    EvaluationJob.work_class,
                    func.count(),
                    func.min(EvaluationJob.requested_at),
                )
                .where(EvaluationJob.state == "pending")
                .group_by(EvaluationJob.work_class)
            )
            for work_class, count, oldest in evaluations:
                if oldest is not None and oldest.tzinfo is None:
                    oldest = oldest.replace(tzinfo=UTC)
                snapshot[("evaluation", str(work_class))] = (int(count), oldest)
            invalidations = session.execute(
                select(
                    SharedHeadEpoch.work_class,
                    func.count(),
                    func.min(SharedHeadEpoch.changed_at),
                )
                .where(SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation)
                .group_by(SharedHeadEpoch.work_class)
            )
            for work_class, count, oldest in invalidations:
                if oldest is not None and oldest.tzinfo is None:
                    oldest = oldest.replace(tzinfo=UTC)
                snapshot[("invalidation", str(work_class))] = (int(count), oldest)
            authority_count, authority_oldest = session.execute(
                select(func.count(), func.min(AuthorityJob.requested_at)).where(
                    AuthorityJob.state == "pending"
                )
            ).one()
            if authority_count:
                if authority_oldest is not None and authority_oldest.tzinfo is None:
                    authority_oldest = authority_oldest.replace(tzinfo=UTC)
                snapshot[("authority", "authority")] = (
                    int(authority_count),
                    authority_oldest,
                )
        return snapshot

    def pending_shared_head_invalidation_count(self) -> int:
        """Return exact-head generations still awaiting a durable reset."""
        with self._sessions() as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(SharedHeadEpoch)
                    .where(SharedHeadEpoch.invalidated_generation < SharedHeadEpoch.generation)
                )
                or 0
            )

    def dead_count(self) -> int:
        """Return legacy terminal rows, which startup normally reactivates."""
        with self._sessions() as session:
            evaluations = int(
                session.scalar(
                    select(func.count())
                    .select_from(EvaluationJob)
                    .where(EvaluationJob.state == "dead")
                )
                or 0
            )
            authorities = int(
                session.scalar(
                    select(func.count())
                    .select_from(AuthorityJob)
                    .where(AuthorityJob.state == "dead")
                )
                or 0
            )
            return evaluations + authorities

    def requeue_dead(self, limit: int = 100) -> int:
        """Recover legacy/manual terminal rows, prioritizing authority work."""
        with self.session() as session:
            authority_ids = tuple(
                session.scalars(
                    select(AuthorityJob.id)
                    .where(AuthorityJob.state == "dead")
                    .order_by(AuthorityJob.requested_at, AuthorityJob.id)
                    .limit(limit)
                )
            )
            authority_count = 0
            if authority_ids:
                authority_result = session.execute(
                    update(AuthorityJob)
                    .where(AuthorityJob.id.in_(authority_ids))
                    .values(
                        state="pending",
                        attempts=0,
                        available_at=utcnow(),
                        last_error=None,
                        lease_owner=None,
                        lease_until=None,
                    )
                )
                authority_count = int(getattr(authority_result, "rowcount", 0) or 0)
            remaining = max(0, limit - authority_count)
            ids = tuple(
                session.scalars(
                    select(EvaluationJob.id)
                    .where(EvaluationJob.state == "dead")
                    .order_by(EvaluationJob.requested_at, EvaluationJob.id)
                    .limit(remaining)
                )
            )
            evaluation_count = 0
            if ids:
                result = session.execute(
                    update(EvaluationJob)
                    .where(EvaluationJob.id.in_(ids))
                    .values(
                        state="pending",
                        attempts=0,
                        available_at=utcnow(),
                        last_error=None,
                        lease_owner=None,
                        lease_until=None,
                    )
                )
                evaluation_count = int(getattr(result, "rowcount", 0) or 0)
            return evaluation_count + authority_count

    def prune_deliveries(self, older_than: datetime) -> int:
        """Remove delivery de-duplication records older than a retention boundary."""
        with self.session() as session:
            result = session.execute(
                delete(WebhookDelivery).where(WebhookDelivery.received_at < older_than)
            )
            return int(getattr(result, "rowcount", 0) or 0)

    def prune_shared_head_epochs(self, older_than: datetime) -> int:
        """Remove old head fences after every referencing job has finished."""
        with self.session() as session:
            referenced = exists(
                select(EvaluationJob.id).where(
                    EvaluationJob.installation_id == SharedHeadEpoch.installation_id,
                    EvaluationJob.repository_full_name == SharedHeadEpoch.repository_full_name,
                    EvaluationJob.head_sha_hint == SharedHeadEpoch.head_sha,
                )
            )
            result = session.execute(
                delete(SharedHeadEpoch).where(
                    SharedHeadEpoch.changed_at < older_than,
                    SharedHeadEpoch.invalidated_generation == SharedHeadEpoch.generation,
                    SharedHeadEpoch.lease_owner.is_(None),
                    SharedHeadEpoch.lease_until.is_(None),
                    ~referenced,
                )
            )
            return int(getattr(result, "rowcount", 0) or 0)

    def prune_reconciliation_states(self, older_than: datetime) -> int:
        """Remove old fingerprints once they can no longer suppress a recheck."""

        with self.session() as session:
            result = session.execute(
                delete(ReconciliationState).where(ReconciliationState.observed_at < older_than)
            )
            return int(getattr(result, "rowcount", 0) or 0)

    def record_audit(
        self,
        repository_full_name: str,
        pull_number: int,
        head_sha: str,
        conclusion: str,
        details: dict[str, Any],
    ) -> None:
        """Upsert the most recent evaluation evidence."""
        record_audit(
            self._sessions, repository_full_name, pull_number, head_sha, conclusion, details
        )

    def database_available(self) -> bool:
        """Test connectivity and schema compatibility for readiness checks."""
        try:
            with self._sessions() as session:
                revision = session.scalar(text("SELECT version_num FROM alembic_version"))
                if revision != DATABASE_MIGRATION_HEAD:
                    return False
                version = session.scalar(
                    select(SchemaMetadata.version).where(SchemaMetadata.singleton_id == 1)
                )
                if version != SCHEMA_VERSION:
                    return False
                session.execute(
                    select(
                        EvaluationJob.id,
                        EvaluationJob.generation,
                        EvaluationJob.shared_head_generation,
                        EvaluationJob.lease_owner,
                        AuthorityJob.generation,
                        SharedHeadEpoch.generation,
                        SharedHeadEpoch.invalidated_generation,
                        SharedHeadEpoch.lease_owner,
                        SharedHeadEpoch.lease_until,
                        WebhookDelivery.invalidation_required,
                        WebhookDelivery.invalidation_completed_at,
                        WebhookDelivery.shared_head_generation,
                        WebhookDelivery.producer_trace_id,
                        WebhookDelivery.producer_span_id,
                        WebhookDelivery.producer_trace_flags,
                    )
                    .select_from(EvaluationJob)
                    .join(
                        WebhookDelivery,
                        EvaluationJob.last_delivery_id == WebhookDelivery.delivery_id,
                        isouter=True,
                    )
                    .join(AuthorityJob, AuthorityJob.id == EvaluationJob.id, isouter=True)
                    .join(
                        SharedHeadEpoch,
                        (SharedHeadEpoch.installation_id == EvaluationJob.installation_id)
                        & (
                            SharedHeadEpoch.repository_full_name
                            == EvaluationJob.repository_full_name
                        )
                        & (SharedHeadEpoch.head_sha == EvaluationJob.head_sha_hint),
                        isouter=True,
                    )
                    .limit(1)
                )
            return True
        except Exception:
            return False
