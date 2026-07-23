from datetime import timedelta
from pathlib import Path
from time import monotonic
from typing import Any, cast

import pytest
from sqlalchemy import Table, inspect, select, update
from sqlalchemy.exc import IntegrityError

from extra_codeowners.database import (
    AuthorityJob,
    AuthorityRequest,
    EvaluationJob,
    JobRequest,
    QueueStore,
    SchemaMetadata,
    ServiceLease,
    SharedHeadEpoch,
    utcnow,
)
from extra_codeowners.migrations import upgrade_database


def make_store(tmp_path: Path) -> QueueStore:
    database_url = f"sqlite:///{tmp_path / 'queue.db'}"
    upgrade_database(database_url)
    store = QueueStore(database_url)
    store.initialize()
    return store


def test_schema_version_is_required_for_readiness(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.database_available() is True

    with store.session() as session:
        session.execute(update(SchemaMetadata).values(version=999))

    assert store.database_available() is False
    try:
        store.initialize()
    except RuntimeError as error:
        assert "schema version 999" in str(error)
    else:  # pragma: no cover - a mismatched schema must fail closed
        raise AssertionError("incompatible schema was accepted")


def test_legacy_schema_is_rejected_without_mutating_it(tmp_path: Path) -> None:
    store = QueueStore(f"sqlite:///{tmp_path / 'legacy.db'}")
    cast(Table, EvaluationJob.__table__).create(store.engine)

    try:
        store.initialize()
    except RuntimeError as error:
        assert "has not been migrated" in str(error)
    else:  # pragma: no cover - legacy adoption would be unsafe
        raise AssertionError("legacy schema was adopted")

    assert SchemaMetadata.__tablename__ not in set(inspect(store.engine).get_table_names())


def test_startup_does_not_mutate_pre_release_dead_jobs(tmp_path: Path) -> None:
    database_path = tmp_path / "retry-upgrade.db"
    database_url = f"sqlite:///{database_path}"
    upgrade_database(database_url)
    store = QueueStore(database_url)
    store.initialize()
    store.enqueue(JobRequest(17, "example/project", 42, "pre-release-retry"))
    with store.session() as session:
        session.execute(update(EvaluationJob).values(state="dead"))
    store.close()

    restarted = QueueStore(f"sqlite:///{database_path}")
    restarted.initialize()

    assert restarted.pending_count() == 0
    assert restarted.dead_count() == 1


def request(*, reason: str = "pull_request.opened", head: str = "a" * 40) -> JobRequest:
    return JobRequest(
        installation_id=17,
        repository_full_name="example/project",
        pull_number=42,
        reason=reason,
        head_sha_hint=head,
    )


def authority_request() -> AuthorityRequest:
    return AuthorityRequest(
        installation_id=17,
        repository_full_name="example/project",
        base_ref="main",
        reason="push.repository_authority",
    )


def test_repository_queue_keys_are_case_insensitive() -> None:
    first = JobRequest(1, "Example/Project", 2, "test")
    second = AuthorityRequest(1, "EXAMPLE/PROJECT", None, "test")

    assert first.repository_full_name == "example/project"
    assert second.repository_full_name == "example/project"


def test_mixed_case_triggers_coalesce_in_one_queue_row(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(JobRequest(17, "Example/Project", 42, "first"))
    store.enqueue(JobRequest(17, "EXAMPLE/PROJECT", 42, "second"))

    assert store.pending_count() == 1
    assert store.pending_shared_head_invalidation_count() == 0
    claimed = store.claim("worker", 60)
    assert claimed is not None
    assert claimed.repository_full_name == "example/project"
    assert claimed.generation == 2


def test_known_head_enqueue_creates_a_durable_invalidation_fence(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    store.enqueue(request())

    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1
    assert store.pending_shared_head_invalidation_count() == 1
    claimed = store.claim("worker", 60)
    assert claimed is not None
    assert claimed.shared_head_generation == 1
    assert store.shared_head_generation_is_current(claimed, "a" * 40) is True
    assert store.shared_head_generation_is_publishable(claimed, "a" * 40) is False


def test_delivery_acceptance_is_atomic_and_idempotent(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    assert store.accept_delivery("delivery-1", "pull_request", request()).accepted is True
    assert store.accept_delivery("delivery-1", "pull_request", request()).accepted is False
    assert store.pending_count() == 2
    assert store.pending_shared_head_invalidation_count() == 1
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1


def test_duplicate_delivery_does_not_advance_shared_head_epoch(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    first = store.accept_delivery("same-delivery", "pull_request", request())
    duplicate = store.accept_delivery("same-delivery", "pull_request", request())

    assert first.accepted is True
    assert duplicate.accepted is False
    assert first.shared_head_generation == duplicate.shared_head_generation == 1
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1
    claimed = store.claim("worker", 60)
    assert claimed is not None
    assert claimed.shared_head_generation == 1


def test_shared_head_invalidation_gates_publication_until_completion(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    assert store.accept_delivery("delivery-1", "pull_request", request())
    evaluation = store.claim("evaluation-worker", 60)
    invalidation = store.claim_shared_head_invalidation("head-worker", 60)

    assert evaluation is not None
    assert invalidation is not None
    assert store.shared_head_generation_is_current(evaluation, "a" * 40) is True
    assert store.shared_head_generation_is_publishable(evaluation, "a" * 40) is False
    assert store.complete_shared_head_invalidation(invalidation) is True
    assert store.shared_head_generation_is_publishable(evaluation, "a" * 40) is True


def test_expired_shared_head_lease_cannot_complete_after_replacement(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    assert store.accept_delivery("delivery-1", "pull_request", request())
    expired = store.claim_shared_head_invalidation("old-worker", 60)
    assert expired is not None
    with store.session() as session:
        session.execute(update(SharedHeadEpoch).values(lease_until=utcnow() - timedelta(seconds=1)))

    replacement = store.claim_shared_head_invalidation("new-worker", 60)

    assert replacement is not None
    assert replacement.generation == expired.generation
    assert store.complete_shared_head_invalidation(expired) is False
    assert store.complete_shared_head_invalidation(replacement) is True


def test_new_shared_head_generation_fences_old_lease_and_completion(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    assert store.accept_delivery("delivery-1", "pull_request", request())
    stale = store.claim_shared_head_invalidation("old-worker", 60)
    assert stale is not None

    second = store.accept_delivery(
        "delivery-2",
        "pull_request_review",
        request(reason="pull_request_review.submitted"),
    )
    current = store.claim_shared_head_invalidation("new-worker", 60)

    assert second.shared_head_generation == 2
    assert current is not None
    assert current.generation == 2
    assert store.is_current_shared_head_invalidation(stale) is False
    assert store.complete_shared_head_invalidation(stale) is False
    assert store.complete_shared_head_invalidation(current) is True
    assert store.shared_head_invalidation_generation(17, "example/project", "a" * 40) == 2


def test_shared_head_fanout_preserves_a_newer_different_head(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    first_head = "a" * 40
    second_head = "b" * 40
    first = store.accept_delivery(
        "first-head",
        "pull_request",
        JobRequest(17, "example/project", 42, "pull_request.opened", first_head),
    )
    store.accept_delivery(
        "second-head",
        "pull_request",
        JobRequest(17, "example/project", 42, "pull_request.synchronize", second_head),
    )

    assert first.shared_head_generation == 1
    assert store.enqueue_for_shared_head_generation(
        JobRequest(17, "example/project", 42, "shared_head_invalidation", first_head),
        first.shared_head_generation,
    )
    assert store.enqueue_for_shared_head_generation(
        JobRequest(17, "example/project", 43, "shared_head_invalidation", first_head),
        first.shared_head_generation,
    )
    with store.session() as session:
        rows = {
            row.pull_number: row.head_sha_hint for row in session.scalars(select(EvaluationJob))
        }

    assert rows == {42: second_head, 43: first_head}


def test_returning_to_an_old_head_advances_its_epoch_without_aba(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    first_head = "a" * 40
    second_head = "b" * 40

    assert store.accept_delivery(
        "first-head",
        "pull_request",
        JobRequest(17, "example/project", 41, "pull_request.opened", first_head),
    )
    stale_first = store.claim("first-worker", 60)
    assert stale_first is not None
    assert stale_first.shared_head_generation == 1

    assert store.accept_delivery(
        "second-head",
        "pull_request",
        JobRequest(17, "example/project", 42, "pull_request.synchronize", second_head),
    )
    assert store.accept_delivery(
        "first-head-again",
        "pull_request",
        JobRequest(17, "example/project", 43, "pull_request.synchronize", first_head),
    )

    assert store.shared_head_generation(17, "example/project", first_head) == 2
    assert store.shared_head_generation(17, "example/project", second_head) == 1
    assert store.shared_head_generation_is_current(stale_first, first_head) is False


def test_shared_head_epoch_cleanup_waits_for_queued_or_leased_jobs(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.accept_delivery("delivery-1", "pull_request", request())
    boundary = utcnow() - timedelta(days=1)
    with store.session() as session:
        epoch = session.scalar(select(SharedHeadEpoch))
        assert epoch is not None
        epoch.changed_at = boundary - timedelta(days=1)

    assert store.prune_shared_head_epochs(boundary) == 0
    invalidation = store.claim_shared_head_invalidation("head-worker", 60)
    assert invalidation is not None
    assert store.prune_shared_head_epochs(boundary) == 0
    assert store.complete_shared_head_invalidation(invalidation) is True
    assert store.prune_shared_head_epochs(boundary) == 0

    claimed = store.claim("worker", 60)
    assert claimed is not None
    assert store.prune_shared_head_epochs(boundary) == 0

    store.complete(claimed, "worker")

    assert store.prune_shared_head_epochs(boundary) == 1
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 0


@pytest.mark.parametrize(
    "head",
    [
        None,
        "",
        "a" * 39,
        "a" * 41,
        "a" * 63,
        "a" * 65,
        "A" * 40,
        "a" * 39 + " ",
        "a" * 39 + "/",
        "é" * 40,
    ],
)
def test_accepted_direct_trigger_requires_a_canonical_head(
    tmp_path: Path,
    head: str | None,
) -> None:
    store = make_store(tmp_path)

    with pytest.raises(ValueError, match="head_sha"):
        store.accept_delivery(
            "missing-head",
            "pull_request",
            JobRequest(17, "example/project", 42, "pull_request.opened", head),
        )

    assert store.pending_count() == 0


def test_sha256_head_uses_an_independent_durable_key(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    head = "b" * 64

    assert store.accept_delivery(
        "sha256-head",
        "pull_request",
        JobRequest(17, "example/project", 42, "pull_request.opened", head),
    )

    assert store.shared_head_generation(17, "example/project", head) == 1


def test_delivery_invalidation_state_is_replay_safe(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    assert store.accept_delivery("delivery-1", "pull_request", request())
    assert store.delivery_needs_invalidation("delivery-1") is True
    assert store.mark_delivery_invalidated("delivery-1") is True
    assert store.mark_delivery_invalidated("delivery-1") is False
    assert store.delivery_needs_invalidation("delivery-1") is False

    assert store.accept_delivery("ping-1", "ping", None)
    assert store.delivery_needs_invalidation("ping-1") is False


def test_delivery_retries_a_racing_job_insert_without_dropping_trigger(
    tmp_path: Path, monkeypatch: object
) -> None:
    store = make_store(tmp_path)
    original = store._enqueue_in_session
    calls = 0

    def collide_once(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise IntegrityError("INSERT", {}, RuntimeError("simulated unique race"))
        original(*args, **kwargs)  # type: ignore[arg-type]

    # Assigning on the instance avoids affecting other stores in this test process.
    store._enqueue_in_session = collide_once  # type: ignore[method-assign]

    assert store.accept_delivery("delivery-race", "pull_request", request()).accepted is True
    assert store.pending_count() == 2
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1


def test_delivery_epoch_and_enqueue_roll_back_together(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.accept_delivery("first", "pull_request", request())
    original = store._enqueue_in_session

    def fail_enqueue(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("simulated enqueue failure")

    store._enqueue_in_session = fail_enqueue  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="simulated enqueue failure"):
        store.accept_delivery(
            "rolled-back",
            "pull_request_review",
            request(reason="pull_request_review.submitted"),
        )
    store._enqueue_in_session = original  # type: ignore[method-assign]

    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1
    assert store.delivery_needs_invalidation("rolled-back") is False


def test_internal_head_trigger_stales_prior_shared_head_claims(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    head = "a" * 40
    assert store.accept_delivery(
        "other-pull",
        "pull_request",
        JobRequest(17, "example/project", 41, "pull_request.opened", head),
    )
    prior = store.claim("worker", 60)
    assert prior is not None

    store.enqueue_shared_head_trigger(
        JobRequest(17, "example/project", 42, "head_changed_before_evaluation", head)
    )

    assert store.shared_head_generation(17, "example/project", head) == 2
    assert store.shared_head_generation_is_current(prior, head) is False


def test_internal_head_trigger_epoch_and_enqueue_roll_back_together(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original = store._enqueue_in_session

    def fail_enqueue(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("simulated internal enqueue failure")

    store._enqueue_in_session = fail_enqueue  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="simulated internal enqueue failure"):
        store.enqueue_shared_head_trigger(request(reason="pull_request_changed_during_evaluation"))
    store._enqueue_in_session = original  # type: ignore[method-assign]

    assert store.shared_head_generation(17, "example/project", "a" * 40) == 0
    assert store.pending_count() == 0


def test_hintless_internal_claim_advances_shared_head_invalidation(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(JobRequest(17, "example/project", 41, "periodic_reconciliation"))
    assert store.accept_delivery(
        "direct-other-pull",
        "pull_request",
        JobRequest(17, "example/project", 42, "pull_request.opened", "a" * 40),
    )
    claimed = store.claim("worker", 60)
    assert claimed is not None
    assert claimed.pull_number == 41
    assert claimed.head_sha_hint is None

    bound = store.bind_claim_to_head(claimed, "a" * 40)

    assert bound is not None
    assert bound.head_sha_hint == "a" * 40
    assert bound.shared_head_generation == 2
    assert store.shared_head_generation_is_current(bound, "a" * 40) is True
    assert store.shared_head_generation_is_publishable(bound, "a" * 40) is False
    assert store.pending_shared_head_invalidation_count() == 1


def test_lost_hintless_bind_rolls_back_tentative_shared_head_invalidation(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    request_value = JobRequest(17, "example/project", 41, "periodic_reconciliation")
    store.enqueue(request_value)
    claimed = store.claim("old-worker", 60)
    assert claimed is not None
    store.enqueue(request_value)

    bound = store.bind_claim_to_head(claimed, "a" * 40)

    assert bound is None
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 0
    assert store.pending_shared_head_invalidation_count() == 0
    assert store.pending_count() == 1


def test_jobs_coalesce_and_new_generation_survives_old_completion(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    first = store.claim("worker-1", 60)
    assert first is not None

    store.enqueue(request(reason="pull_request.synchronize", head="b" * 40))
    store.complete(first, "worker-1")

    second = store.claim("worker-2", 60)
    assert second is not None
    assert second.generation == first.generation + 1
    assert second.reason == "pull_request.synchronize"
    assert second.head_sha_hint == "b" * 40


def test_reconciliation_does_not_supersede_active_or_retrying_work(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    invalidation = store.claim_shared_head_invalidation("head-worker", 60)
    assert invalidation is not None
    assert store.complete_shared_head_invalidation(invalidation)
    active = store.claim("worker", 60)
    assert active is not None

    assert store.enqueue_if_absent(request(reason="periodic_reconciliation")) is False
    assert store.is_current_generation(active) is True

    store.fail(active, "worker", "failed", max_delay_seconds=1)
    assert store.pending_count() == 1
    assert store.dead_count() == 0
    assert store.enqueue_if_absent(request(reason="periodic_reconciliation")) is False
    assert store.pending_count() == 1


def test_reconciliation_advances_epoch_only_when_it_inserts_missing_head_work(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    reconciliation = request(reason="periodic_reconciliation")

    assert store.enqueue_if_absent(reconciliation) is True
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1
    claimed = store.claim("worker", 60)
    assert claimed is not None
    assert claimed.shared_head_generation == 1

    assert store.enqueue_if_absent(reconciliation) is False
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1


def test_existing_job_reconciliation_rolls_back_tentative_epoch(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    reconciliation = request(reason="periodic_reconciliation")
    store.enqueue(reconciliation)

    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1
    assert store.enqueue_if_absent(reconciliation) is False
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 1


def test_hintless_reconciliation_does_not_create_a_shared_head_epoch(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    assert store.enqueue_if_absent(JobRequest(17, "example/project", 42, "periodic_reconciliation"))

    with store.session() as session:
        assert session.scalar(select(SharedHeadEpoch)) is None


def test_reconciliation_epoch_and_missing_job_roll_back_together(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original_advance = store._advance_shared_head_epoch_in_session

    def fail_after_epoch(session: Any, request_to_enqueue: JobRequest) -> int:
        original_advance(session, request_to_enqueue)
        raise RuntimeError("simulated reconciliation enqueue failure")

    store._advance_shared_head_epoch_in_session = fail_after_epoch  # type: ignore[assignment]
    with pytest.raises(RuntimeError, match="simulated reconciliation enqueue failure"):
        store.enqueue_if_absent(request(reason="periodic_reconciliation"))

    assert store.pending_count() == 0
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 0


def test_failed_evaluation_retries_indefinitely_with_bounded_backoff(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    invalidation = store.claim_shared_head_invalidation("head-worker", 60)
    assert invalidation is not None
    assert store.complete_shared_head_invalidation(invalidation)
    job = store.claim("worker", 60)
    assert job is not None

    store.fail(job, "worker", "temporary failure", max_delay_seconds=1)

    assert store.pending_count() == 1
    assert store.dead_count() == 0
    with store.session() as session:
        session.execute(
            update(EvaluationJob).where(EvaluationJob.id == job.id).values(available_at=utcnow())
        )
    retry = store.claim("worker", 60)
    assert retry is not None
    assert retry.attempts == 2
    store.fail(retry, "worker", "still failing", max_delay_seconds=1)
    assert store.pending_count() == 1
    assert store.dead_count() == 0


def test_failed_authority_job_retries_indefinitely(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.accept_delivery("authority-1", "push", authority_request()).accepted is True
    assert store.pending_count() == 1
    assert store.dead_count() == 0

    job = store.claim_authority("worker", 60)
    assert job is not None
    store.fail_authority(job, "worker", "failed", max_delay_seconds=1)

    assert store.pending_count() == 1
    assert store.dead_count() == 0


def test_authority_jobs_coalesce_and_new_generation_survives_old_completion(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    assert store.accept_delivery("authority-1", "push", authority_request()).accepted is True
    first = store.claim_authority("worker-one", 60)
    assert first is not None

    changed = AuthorityRequest(
        installation_id=17,
        repository_full_name="example/project",
        base_ref="main",
        reason="label.edited",
    )
    assert store.accept_delivery("authority-2", "label", changed).accepted is True
    store.complete_authority(first, "worker-one")

    second = store.claim_authority("worker-two", 60)
    assert second is not None
    assert second.generation == first.generation + 1
    assert second.reason == "label.edited"


def test_authority_scope_blocks_only_affected_evaluations(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    claimed = store.claim("worker", 60)
    assert claimed is not None

    store.accept_delivery("base", "push", authority_request())

    assert store.has_blocking_authority(claimed, "main") is True
    assert store.has_blocking_authority(claimed, "release") is False

    installation_scope = AuthorityRequest(
        installation_id=17,
        repository_full_name=None,
        base_ref=None,
        reason="membership.removed",
    )
    store.accept_delivery("membership", "membership", installation_scope)

    assert store.has_blocking_authority(claimed, "release") is True


def test_authority_epoch_permanently_fences_prechange_claim_after_fanout(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    before_change = store.claim("evaluation-worker", 60)
    assert before_change is not None
    assert before_change.authority_generation == 0

    broad_authority = AuthorityRequest(17, None, None, "repository.renamed")
    store.accept_delivery("authority-epoch", "repository", broad_authority)
    assert store.is_current_claim(before_change) is False
    authority = store.claim_authority("authority-worker", 60)
    assert authority is not None
    store.complete_authority(authority, "authority-worker")

    assert store.is_current_claim(before_change) is False
    store.enqueue(request(reason="authority fanout"))
    store.complete(before_change, "evaluation-worker")
    after_change = store.claim("evaluation-worker", 60)
    assert after_change is not None
    assert after_change.authority_generation == 1


def test_authority_epoch_fences_prechange_job_claimed_after_fanout(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())

    broad_authority = AuthorityRequest(17, None, None, "repository.renamed")
    store.accept_delivery("authority-before-claim", "repository", broad_authority)
    assert store.claim("evaluation-worker", 60) is None

    authority = store.claim_authority("authority-worker", 60)
    assert authority is not None
    store.complete_authority(authority, "authority-worker")

    stale = store.claim("evaluation-worker", 60)
    assert stale is not None
    assert stale.authority_generation == 0
    assert store.is_current_claim(stale) is False


def test_repository_authority_epoch_does_not_cancel_unrelated_repository(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue(JobRequest(17, "example/other", 7, "test"))
    unrelated = store.claim("evaluation-worker", 60)
    assert unrelated is not None

    store.accept_delivery("label-project", "label", authority_request())

    assert store.is_current_claim(unrelated) is True


def test_unresolved_authority_prevents_evaluation_claim_churn(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    store.accept_delivery("authority", "push", authority_request())

    assert store.claim("evaluation-worker", 60) is None
    authority = store.claim_authority("authority-worker", 60)
    assert authority is not None
    store.complete_authority(authority, "authority-worker")

    assert store.claim("evaluation-worker", 60) is not None


def test_security_sensitive_authority_work_preempts_older_base_pushes(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.accept_delivery(
        "old-base-push",
        "push",
        AuthorityRequest(17, "example/project", "main", "push.repository_base"),
    )
    store.accept_delivery(
        "new-repository-wide",
        "label",
        AuthorityRequest(17, "example/other", None, "label.edited"),
    )
    store.accept_delivery(
        "new-installation-wide",
        "membership",
        AuthorityRequest(17, None, None, "membership.removed"),
    )

    installation = store.claim_authority("worker", 60)
    assert installation is not None
    assert installation.repository_full_name is None
    store.complete_authority(installation, "worker")

    repository = store.claim_authority("worker", 60)
    assert repository is not None
    assert repository.repository_full_name == "example/other"
    assert repository.base_ref is None
    store.complete_authority(repository, "worker")

    base_push = store.claim_authority("worker", 60)
    assert base_push is not None
    assert base_push.repository_full_name == "example/project"
    assert base_push.base_ref == "main"


def test_unique_base_push_backlog_coalesces_to_bounded_repository_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "extra_codeowners.database.MAX_BASE_SCOPED_AUTHORITY_JOBS_PER_REPOSITORY", 2
    )
    store = make_store(tmp_path)
    for index, branch in enumerate(("main", "release", "third")):
        store.accept_delivery(
            f"push-{index}",
            "push",
            AuthorityRequest(17, "example/project", branch, "push.repository_base"),
        )

    assert store.pending_count() == 1
    coalesced = store.claim_authority("worker", 60)
    assert coalesced is not None
    assert coalesced.repository_full_name == "example/project"
    assert coalesced.base_ref is None


def test_authority_ingress_guard_timeout_is_bounded(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    guard = store.acquire_authority_guard(17, shared=True, timeout_seconds=1)
    assert guard is not None
    started = monotonic()
    try:
        with pytest.raises(RuntimeError, match="timed out"):
            store.accept_delivery(
                "blocked-authority",
                "push",
                authority_request(),
                authority_guard_timeout_seconds=0.05,
            )
    finally:
        store.release_check_write_guard(guard)

    assert monotonic() - started < 1
    assert store.pending_count() == 0


def test_nested_sqlite_authority_and_check_guards_use_separate_lock_namespaces(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    authority_key = store._check_write_key("__extra_codeowners_authority__", "installation:2")
    colliding_scope = next(
        f"{candidate:040x}"
        for candidate in range(10_000)
        if store._check_write_key("example/project", f"{candidate:040x}") % 256
        == authority_key % 256
    )

    authority = store.acquire_authority_guard(2, shared=True, timeout_seconds=1)
    assert authority is not None
    try:
        writer = store.acquire_check_write_guard(
            "example/project", colliding_scope, timeout_seconds=0.1
        )
        assert writer is not None
        store.release_check_write_guard(writer)
    finally:
        store.release_check_write_guard(authority)


def test_dead_requeue_prioritizes_authority_revocation(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    store.accept_delivery("authority", "push", authority_request())
    # Retain recovery support for legacy/manual dead rows even though runtime
    # failures now retry indefinitely and never create this state.
    with store.session() as session:
        session.execute(update(EvaluationJob).values(state="dead"))
        session.execute(update(AuthorityJob).values(state="dead"))

    assert store.requeue_dead(limit=1) == 1
    assert store.claim_authority("other-worker", 60) is not None
    assert store.claim("other-worker", 60) is None


def test_expired_claim_is_generation_fenced_before_reuse(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    first = store.claim("worker-one", 60)
    assert first is not None
    with store.session() as session:
        session.execute(
            update(EvaluationJob)
            .where(EvaluationJob.id == first.id)
            .values(lease_until=utcnow() - timedelta(seconds=1))
        )

    second = store.claim("worker-two", 60)

    assert second is not None
    assert second.generation == first.generation + 1
    assert store.is_current_claim(first) is False
    assert store.is_current_claim(second) is True
    assert store.renew_claim(second, 120) is True


def test_rate_limit_defer_releases_superseded_generation(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(request())
    first = store.claim("worker-one", 60)
    assert first is not None
    store.enqueue(request(reason="pull_request_review.submitted"))

    assert store.defer(first, "worker-one", "rate limited", 30) is False
    second = store.claim("worker-two", 60)

    assert second is not None
    assert second.generation == first.generation + 1
    assert second.attempts == 1


def test_service_lease_can_be_renewed_only_by_owner_until_expiry(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    assert store.acquire_service_lease("reconciler", "one", 60) is True
    assert store.acquire_service_lease("reconciler", "two", 60) is False
    assert store.acquire_service_lease("reconciler", "one", 60) is True

    with store.session() as session:
        session.execute(
            update(ServiceLease)
            .where(ServiceLease.name == "reconciler")
            .values(lease_until=utcnow() - timedelta(seconds=1))
        )
    assert store.acquire_service_lease("reconciler", "two", 60) is True


def test_check_write_guard_is_exclusive_and_releasable(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    first = store.acquire_check_write_guard("example/project", 42, 0.05)
    assert first is not None
    assert store.acquire_check_write_guard("example/project", 42, 0.05) is None
    store.release_check_write_guard(first)

    second = store.acquire_check_write_guard("example/project", 42, 0.05)
    assert second is not None
    store.release_check_write_guard(second)


def test_delivery_pruning_removes_only_old_records(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.accept_delivery("delivery-1", "ping", None)

    assert store.prune_deliveries(utcnow() - timedelta(days=1)) == 0
    assert store.prune_deliveries(utcnow() + timedelta(days=1)) == 1
