from datetime import UTC, timedelta
from pathlib import Path
from time import monotonic
from typing import Any, cast

import pytest
from sqlalchemy import Table, create_engine, inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SQLAlchemySession

from extra_codeowners.database import (
    LIBPQ_DISABLED_ROOT_CERT,
    AuthorityJob,
    AuthorityRequest,
    EvaluationJob,
    JobRequest,
    QueueStore,
    ReconciliationState,
    SchemaMetadata,
    ServiceLease,
    SharedHeadEpoch,
    WebhookDelivery,
    _normalize_schema_expression,
    isolated_postgresql_connect_args,
    utcnow,
    validate_database_schema,
)
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.trace_context import TrustedTraceContext
from extra_codeowners.webhooks import VerifiedWebhook, evaluation_job


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


def test_complete_schema_contract_accepts_a_supplied_read_only_engine(tmp_path: Path) -> None:
    database_path = tmp_path / "read-only-preflight.db"
    upgrade_database(f"sqlite:///{database_path}")
    engine = create_engine(f"sqlite:///file:{database_path}?mode=ro&uri=true")

    try:
        validate_database_schema(engine)
    finally:
        engine.dispose()


def test_schema_contract_rejects_same_named_index_with_wrong_definition(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "wrong-index.db"
    database_url = f"sqlite:///{database_path}"
    upgrade_database(database_url)
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_evaluation_jobs_claim"))
        connection.execute(text("CREATE INDEX ix_evaluation_jobs_claim ON evaluation_jobs (state)"))

    try:
        with pytest.raises(RuntimeError, match="incompatible indexes"):
            validate_database_schema(engine)
    finally:
        engine.dispose()


def test_schema_expression_contract_handles_only_equivalent_parentheses() -> None:
    expected = _normalize_schema_expression(
        "invalidated_generation >= 0 AND invalidated_generation <= generation"
    )

    assert expected == _normalize_schema_expression(
        "((invalidated_generation >= 0) AND (invalidated_generation <= generation))"
    )
    assert expected != _normalize_schema_expression(
        "invalidated_generation >= 0 AND invalidated_generation < generation"
    )
    with pytest.raises(RuntimeError, match="unsupported SQL"):
        _normalize_schema_expression(
            "invalidated_generation >= 0 OR invalidated_generation <= generation"
        )


def test_schema_expression_contract_accepts_postgresql_in_array_deparse() -> None:
    expected = _normalize_schema_expression("work_class IN ('interactive', 'recovery')")

    assert expected == _normalize_schema_expression(
        "work_class::text = ANY "
        "(ARRAY['interactive'::character varying, 'recovery'::character varying]::text[])"
    )
    assert expected == _normalize_schema_expression(
        "work_class::text = ANY "
        "(ARRAY['interactive'::character varying::text, "
        "'recovery'::character varying::text])"
    )


def test_isolated_postgresql_connect_args_neutralize_ambient_hostaddr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PGHOSTADDR", "203.0.113.1")

    arguments = isolated_postgresql_connect_args(
        "postgresql+psycopg://user:password@localhost/database"
    )

    assert arguments["host"] == "localhost"
    assert arguments["hostaddr"] == ""
    assert arguments["port"] == 5432
    assert arguments["gssencmode"] == "disable"
    assert arguments["sslmode"] == "disable"
    assert arguments["sslrootcert"] == LIBPQ_DISABLED_ROOT_CERT
    assert not Path(LIBPQ_DISABLED_ROOT_CERT).exists()


@pytest.mark.parametrize("port", [1, 65535])
def test_isolated_postgresql_connect_args_preserve_valid_explicit_ports(port: int) -> None:
    arguments = isolated_postgresql_connect_args(
        f"postgresql+psycopg://user:password@localhost:{port}/database"
    )

    assert arguments["port"] == port


@pytest.mark.parametrize("port", [-1, 0, 65536])
def test_isolated_postgresql_connect_args_reject_invalid_explicit_ports(port: int) -> None:
    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        isolated_postgresql_connect_args(
            f"postgresql+psycopg://user:password@localhost:{port}/database"
        )


def test_isolated_postgresql_connect_args_default_remote_transport_uses_tls() -> None:
    arguments = isolated_postgresql_connect_args(
        "postgresql+psycopg://user:password@db.example.test/database"
    )

    assert arguments["sslmode"] == "require"
    assert arguments["sslrootcert"] == LIBPQ_DISABLED_ROOT_CERT
    assert not Path(LIBPQ_DISABLED_ROOT_CERT).exists()


@pytest.mark.parametrize("sslmode", ("allow", "prefer", "verify-ca", "verify-full"))
def test_isolated_postgresql_connect_args_rejects_unsupported_tls_modes(sslmode: str) -> None:
    with pytest.raises(ValueError, match="unsupported TLS mode"):
        isolated_postgresql_connect_args(
            f"postgresql+psycopg://user:password@localhost/database?sslmode={sslmode}"
        )


def test_isolated_postgresql_connect_args_rejects_certificate_configuration() -> None:
    with pytest.raises(ValueError, match="unsupported connection parameters"):
        isolated_postgresql_connect_args(
            "postgresql+psycopg://user:password@db.example.test/database?"
            "sslmode=require&sslrootcert=%2Frun%2Fsecrets%2Fdatabase-ca%2Froot.pem"
        )


def test_isolated_postgresql_connect_args_reject_an_empty_password() -> None:
    with pytest.raises(ValueError, match="password"):
        isolated_postgresql_connect_args("postgresql+psycopg://user:@localhost/database")


@pytest.mark.parametrize(
    "database_url",
    (
        "postgresql://user:password@localhost/database",
        "postgresql+psycopg2://user:password@localhost/database",
    ),
)
def test_isolated_postgresql_connect_args_requires_the_psycopg_driver(
    database_url: str,
) -> None:
    with pytest.raises(ValueError, match="unsupported route"):
        isolated_postgresql_connect_args(database_url)


def test_isolated_postgresql_connect_args_reject_even_empty_ambient_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PGSERVICE", "")

    with pytest.raises(ValueError, match="PGSERVICE"):
        isolated_postgresql_connect_args("postgresql+psycopg://user:password@localhost/database")


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


def request(
    *,
    reason: str = "pull_request.opened",
    head: str = "a" * 40,
    base_ref_hint: str | None = "main",
) -> JobRequest:
    return JobRequest(
        installation_id=17,
        repository_full_name="example/project",
        pull_number=42,
        reason=reason,
        head_sha_hint=head,
        base_ref_hint=base_ref_hint,
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


def test_claimed_job_keeps_the_original_trusted_webhook_trace_context(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original = TrustedTraceContext("a" * 32, "b" * 16, 1)
    replay = TrustedTraceContext("c" * 32, "d" * 16, 1)

    assert store.accept_delivery(
        "delivery-trace-link",
        "pull_request",
        request(),
        trace_context=original,
    ).accepted
    assert not store.accept_delivery(
        "delivery-trace-link",
        "pull_request",
        request(),
        trace_context=replay,
    ).accepted

    with store.session() as session:
        delivery = session.get(WebhookDelivery, "delivery-trace-link")
        assert delivery is not None
        assert (
            delivery.producer_trace_id,
            delivery.producer_span_id,
            delivery.producer_trace_flags,
        ) == (original.trace_id, original.span_id, original.trace_flags)

    claimed = store.claim("worker", 60)
    assert claimed is not None
    assert claimed.webhook_trace_context == original


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


def test_direct_work_is_selected_ahead_of_large_recovery_backlog(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    for pull_number in range(1, 101):
        assert store.enqueue_if_absent(
            JobRequest(
                17,
                "example/project",
                pull_number,
                "periodic_reconciliation",
                f"{pull_number:040x}",
            )
        )

    direct = JobRequest(
        17,
        "example/project",
        101,
        "pull_request_review.submitted",
        "f" * 40,
    )
    store.enqueue(direct)

    invalidation = store.claim_shared_head_invalidation("head-worker", 60, "interactive")
    assert invalidation is not None
    assert invalidation.head_sha == direct.head_sha_hint
    assert invalidation.work_class == "interactive"
    assert store.complete_shared_head_invalidation(invalidation)

    claimed = store.claim(
        "foreground-worker",
        60,
        "interactive",
        require_shared_head_ready=True,
    )
    assert claimed is not None
    assert claimed.pull_number == direct.pull_number
    assert claimed.work_class == "interactive"
    assert store.pending_count() >= 200


def test_direct_webhook_promotes_and_releases_a_leased_recovery_job(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    recovery = JobRequest(
        17,
        "example/project",
        41,
        "periodic_reconciliation",
        "a" * 40,
    )
    store.enqueue(recovery)
    first_reset = store.claim_shared_head_invalidation("reset-worker", 60, "recovery")
    assert first_reset is not None
    assert store.complete_shared_head_invalidation(first_reset)
    leased_recovery = store.claim(
        "recovery-worker", 600, "recovery", require_shared_head_ready=True
    )
    assert leased_recovery is not None

    direct = JobRequest(
        17,
        "example/project",
        41,
        "pull_request_review.submitted",
        "a" * 40,
    )
    store.enqueue(direct)

    promoted_reset = store.claim_shared_head_invalidation("reset-worker", 60, "interactive")
    assert promoted_reset is not None
    assert store.complete_shared_head_invalidation(promoted_reset)
    foreground = store.claim(
        "recovery-worker",
        60,
        "interactive",
        require_shared_head_ready=True,
    )
    assert foreground is not None
    assert foreground.generation > leased_recovery.generation
    assert foreground.work_class == "interactive"

    # A stale completion cannot release or delete a newer generation even if
    # the same process-owner string is reused.
    assert store.complete(leased_recovery, "recovery-worker") is False
    assert store.pending_count() == 1
    assert store.renew_claim(foreground, 60)


def test_reconciliation_rechecks_unchanged_heads_on_a_bounded_cadence(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original = JobRequest(
        17,
        "example/project",
        41,
        "periodic_reconciliation",
        "a" * 40,
        observed_at=utcnow(),
    )

    assert store.enqueue_reconciliation_if_due(original, recheck_seconds=600)
    invalidation = store.claim_shared_head_invalidation("head-worker", 60, "recovery")
    assert invalidation is not None
    assert store.complete_shared_head_invalidation(invalidation)
    claimed = store.claim("recovery-worker", 60, "recovery", require_shared_head_ready=True)
    assert claimed is not None
    store.complete(claimed, "recovery-worker")

    # The next scan still observes the PR, but an identical recently checked
    # head does not refill the queue.
    assert store.enqueue_reconciliation_if_due(original, recheck_seconds=600) is False
    assert store.pending_count() == 0

    # A missed synchronize webhook changes the head and queues a new recovery
    # generation immediately, without waiting for the periodic deadline.
    changed = JobRequest(
        17,
        "example/project",
        41,
        "periodic_reconciliation",
        "b" * 40,
        observed_at=utcnow(),
    )
    assert store.enqueue_reconciliation_if_due(changed, recheck_seconds=600)
    assert store.shared_head_generation(17, "example/project", "b" * 40) == 1


@pytest.mark.parametrize("old_writer_updates_existing", [False, True])
def test_reconciliation_rechecks_unconfirmed_old_worker_completion(
    tmp_path: Path, old_writer_updates_existing: bool
) -> None:
    store = make_store(tmp_path)
    request = JobRequest(
        17,
        "example/project",
        41,
        "periodic_reconciliation",
        "a" * 40,
        observed_at=utcnow(),
    )
    if old_writer_updates_existing:
        store.enqueue(request)
        claimed = store.claim("new-worker", 60, "recovery")
        assert claimed is not None
        assert store.complete(claimed, "new-worker")
        assert not store.enqueue_reconciliation_if_due(request, 604800)

    # Execute only the columns written by the old worker. It either inserts
    # an unconfirmed row or changes completed_at without the confirmation.
    with store.engine.begin() as connection:
        if old_writer_updates_existing:
            connection.execute(
                text("UPDATE reconciliation_states SET completed_at = :now"),
                {"now": utcnow() + timedelta(seconds=1)},
            )
        else:
            connection.execute(
                text("""
                    INSERT INTO reconciliation_states
                    (installation_id, repository_full_name, pull_number,
                     head_sha, completed_at, observed_at)
                    VALUES (17, 'example/project', 41, :head, :now, :now)
                """),
                {"head": request.head_sha_hint, "now": utcnow()},
            )
    assert store.enqueue_reconciliation_if_due(request, 604800)
    claimed = store.claim("new-worker", 60, "recovery")
    assert claimed is not None
    assert store.complete(claimed, "new-worker")
    assert not store.enqueue_reconciliation_if_due(request, 604800)


@pytest.mark.parametrize("in_flight", [False, True])
def test_recovery_keeps_invalidation_foreground_for_pending_direct_evaluation(
    tmp_path: Path, in_flight: bool
) -> None:
    store = make_store(tmp_path)
    direct = JobRequest(17, "example/project", 41, "pull_request.opened", "a" * 40)
    store.enqueue(direct)
    invalidation = store.claim_shared_head_invalidation("head-worker", 60, "interactive")
    assert invalidation is not None and store.complete_shared_head_invalidation(invalidation)
    if in_flight:
        assert store.claim("foreground", 60, "interactive", require_shared_head_ready=True)
    store.enqueue(
        JobRequest(17, "example/project", 41, "member.removed", "a" * 40, work_class="recovery")
    )
    assert store.claim_shared_head_invalidation("background", 60, "recovery") is None
    current = store.claim_shared_head_invalidation("foreground", 60, "interactive")
    assert current is not None and current.generation > invalidation.generation


def test_first_recovery_epoch_preserves_a_direct_job_with_unknown_head(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue(JobRequest(17, "example/project", 41, "pull_request.opened"))
    store.enqueue(
        JobRequest(17, "example/project", 41, "member.removed", "a" * 40, work_class="recovery")
    )
    invalidation = store.claim_shared_head_invalidation("foreground", 60, "interactive")
    assert invalidation is not None and invalidation.head_sha == "a" * 40


def test_completed_direct_epoch_becomes_recovery_work_on_later_recheck(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    direct = JobRequest(17, "example/project", 41, "pull_request.opened", "a" * 40)
    store.enqueue(direct)
    invalidation = store.claim_shared_head_invalidation("head-worker", 60, "interactive")
    assert invalidation is not None
    assert store.complete_shared_head_invalidation(invalidation)
    claimed = store.claim("foreground-worker", 60, "interactive", require_shared_head_ready=True)
    assert claimed is not None
    assert store.complete(claimed, "foreground-worker") is True
    with store.session() as session:
        state = session.get(ReconciliationState, (17, "example/project", 41))
        assert state is not None
        state.completed_at = utcnow() - timedelta(seconds=601)

    assert store.enqueue_reconciliation_if_due(
        JobRequest(
            17,
            "example/project",
            41,
            "periodic_reconciliation",
            "a" * 40,
            observed_at=utcnow(),
        ),
        recheck_seconds=600,
    )
    recheck_invalidation = store.claim_shared_head_invalidation("head-worker", 60, "recovery")
    assert recheck_invalidation is not None
    assert recheck_invalidation.work_class == "recovery"


def test_reconciliation_does_not_replace_newer_interactive_head(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    observed_at = utcnow()
    direct = JobRequest(17, "example/project", 41, "pull_request.synchronize", "b" * 40)
    store.enqueue(direct)

    assert (
        store.enqueue_reconciliation_if_due(
            JobRequest(
                17,
                "example/project",
                41,
                "periodic_reconciliation",
                "a" * 40,
                observed_at=observed_at,
            ),
            recheck_seconds=600,
        )
        is False
    )
    claimed = store.claim("foreground-worker", 60, "interactive")
    assert claimed is not None
    assert claimed.head_sha_hint == "b" * 40
    assert store.shared_head_generation(17, "example/project", "a" * 40) == 0


def test_reconciliation_replaces_an_older_interactive_head_after_a_missed_webhook(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue(JobRequest(17, "example/project", 41, "pull_request.opened", "a" * 40))
    observed_at = utcnow()

    assert store.enqueue_reconciliation_if_due(
        JobRequest(
            17,
            "example/project",
            41,
            "periodic_reconciliation",
            "b" * 40,
            observed_at=observed_at,
        ),
        recheck_seconds=600,
    )

    invalidation = store.claim_shared_head_invalidation("recovery-head", 60, "recovery")
    assert invalidation is not None
    assert invalidation.head_sha == "b" * 40
    assert store.complete_shared_head_invalidation(invalidation)
    claimed = store.claim("recovery-worker", 60, "recovery", require_shared_head_ready=True)
    assert claimed is not None
    assert claimed.head_sha_hint == "b" * 40


def test_reconciliation_states_are_pruned_after_retention(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    request_to_complete = JobRequest(17, "example/project", 41, "pull_request.opened", "a" * 40)
    store.enqueue(request_to_complete)
    invalidation = store.claim_shared_head_invalidation("head-worker", 60)
    assert invalidation is not None
    assert store.complete_shared_head_invalidation(invalidation)
    claimed = store.claim("worker", 60, require_shared_head_ready=True)
    assert claimed is not None
    assert store.complete(claimed, "worker") is True
    with store.session() as session:
        state = session.get(ReconciliationState, (17, "example/project", 41))
        assert state is not None
        state.observed_at = utcnow() - timedelta(days=31)

    assert store.prune_reconciliation_states(utcnow() - timedelta(days=30)) == 1


def test_provider_backpressure_is_shared_by_independent_queue_stores(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'shared-backpressure.db'}"
    upgrade_database(database_url)
    first = QueueStore(database_url)
    second = QueueStore(database_url)
    first.initialize()
    second.initialize()
    try:
        first.enqueue(JobRequest(17, "example/project", 41, "pull_request.opened"))
        first.enqueue(JobRequest(18, "example/other", 42, "pull_request.opened"))
        first.record_provider_backpressure(17, "GitHub asked us to wait", 60)

        claimed = second.claim("other-pod", 60)

        assert claimed is not None
        assert claimed.installation_id == 18
        assert first.provider_is_backpressured(17) is True
        assert second.provider_is_backpressured(17) is True

        first.record_provider_backpressure(None, "secondary rate limit", 60)
        assert second.provider_is_backpressured(18) is True
        assert second.claim("second-pod", 60) is None
        first.record_provider_backpressure(None, "extended secondary rate limit", 120)
        assert second.provider_is_backpressured(None) is True
    finally:
        first.close()
        second.close()


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

    with store.session() as session:
        session.execute(
            update(AuthorityJob).where(AuthorityJob.id == job.id).values(available_at=utcnow())
        )
    retry = store.claim_authority("worker", 60)
    assert retry is not None
    store.fail_authority(retry, "worker", "still failing", max_delay_seconds=1)
    assert store.pending_count() == 1
    assert store.dead_count() == 0


def test_failed_authority_with_only_an_old_interactive_waiter_backs_off(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(authority_request())
    store.enqueue(request())
    job = store.claim_authority("worker", 60)
    assert job is not None and job.interactive_wake_generation > 0
    assert store.authority_has_direct_waiter(job)

    store.fail_authority(
        job,
        "worker",
        "persistent API failure",
        max_delay_seconds=60,
        minimum_delay_seconds=30,
    )

    with store.session() as session:
        row = session.get(AuthorityJob, job.id)
        assert row is not None
        assert row.interactive_wake_generation == job.interactive_wake_generation
        assert row.available_at.replace(tzinfo=UTC) > utcnow() + timedelta(seconds=25)
    assert store.claim_authority("retry-too-soon", 60) is None


def test_new_interactive_enqueue_during_authority_claim_wakes_failed_retry(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(authority_request())
    job = store.claim_authority("worker", 60)
    assert job is not None

    assert store.accept_delivery("arrival-during-failure", "pull_request", request()).accepted
    store.fail_authority(
        job,
        "worker",
        "API failed after the new event",
        max_delay_seconds=60,
        minimum_delay_seconds=30,
    )

    with store.session() as session:
        row = session.get(AuthorityJob, job.id)
        assert row is not None
        assert row.interactive_wake_generation > job.interactive_wake_generation
        assert row.available_at.replace(tzinfo=UTC) <= utcnow() + timedelta(seconds=1)
    retry = store.claim_authority("retry-new-event", 60)
    assert retry is not None


@pytest.mark.parametrize(
    ("repository", "existing_base", "incoming_base"),
    [
        ("example/project", None, None),
        ("example/project", "main", "main"),
        (None, None, None),
        ("example/project", None, "release"),
    ],
)
@pytest.mark.parametrize("during_claim", [False, True])
def test_coalesced_authority_evidence_wakes_failed_scan_without_restarting_progress(
    tmp_path: Path,
    repository: str | None,
    existing_base: str | None,
    incoming_base: str | None,
    during_claim: bool,
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, repository, existing_base, "installation.created"))
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    assert store.advance_authority_cursor(
        claimed, 73, {"73": "f" * 64}, listing_next_page=4, listing_last_number=300
    )
    if not during_claim:
        store.fail_authority(claimed, "worker", "old 404", 21_600, 600)
        assert store.claim_authority("too-soon", 60) is None

    with store.session() as session:
        before = session.get(AuthorityJob, claimed.id)
        assert before is not None
        lease = (before.lease_owner, before.lease_until)
    new_evidence = AuthorityRequest(17, repository, incoming_base, "push.repository_base")
    assert store.accept_delivery("authority-wake", "push", new_evidence).accepted
    assert not store.accept_delivery("authority-wake", "push", new_evidence).accepted
    with store.session() as session:
        row = session.get(AuthorityJob, claimed.id)
        assert row is not None
        assert row.generation == claimed.generation
        assert row.interactive_wake_generation == claimed.interactive_wake_generation + 1
        assert (row.lease_owner, row.lease_until) == lease
        assert row.pull_cursor_number == 73 and row.handled_pull_fingerprints == {"73": "f" * 64}
        assert row.listing_next_page == 4 and row.listing_last_number == 300
        assert row.available_at.replace(tzinfo=UTC) <= utcnow() + timedelta(seconds=1)
    if during_claim:
        store.fail_authority(claimed, "worker", "404 after arrival", 21_600, 600)

    resumed = store.claim_authority("retry-new-evidence", 60)
    assert resumed is not None and resumed.id == claimed.id
    assert resumed.generation == claimed.generation
    assert resumed.listing_next_page == 4 and resumed.listing_last_number == 300
    # The old arrival is consumed by this claim, not an indefinite hot retry.
    store.fail_authority(resumed, "retry-new-evidence", "still 404", 21_600, 600)
    assert not store.accept_delivery("authority-wake", "push", new_evidence).accepted
    assert store.claim_authority("unchanged-retry", 60) is None
    store.close()


def test_coalesced_authority_wakeup_does_not_bypass_provider_backpressure(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    original = authority_request()
    store.enqueue_authority(original)
    claimed = store.claim_authority("worker", 60)
    assert claimed is not None
    store.record_provider_backpressure(17, "provider reset", 600)
    assert store.defer_authority(claimed, "worker", "provider reset", 600)

    assert store.accept_delivery("authority-during-provider-limit", "push", original).accepted
    assert store.provider_is_backpressured(17)
    assert store.claim_authority("cannot-bypass-provider", 60) is None
    store.close()


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


@pytest.mark.parametrize("deferred", [False, True])
def test_narrow_push_preserves_repository_authority_progress_and_claim(
    tmp_path: Path, deferred: bool
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/project", None, "member.removed"))
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    handled = {"20": "a" * 64}
    assert store.advance_authority_cursor(
        claim, 20, handled, listing_next_page=3, listing_last_number=200
    )
    if deferred:
        assert store.defer_authority(claim, "worker", "quota pause", 600)

    with store.session() as session:
        before = session.get(AuthorityJob, claim.id)
        assert before is not None
        baseline = {
            "generation": before.generation,
            "pull_cursor_number": before.pull_cursor_number,
            "handled_pull_fingerprints": dict(before.handled_pull_fingerprints),
            "listing_next_page": before.listing_next_page,
            "listing_last_number": before.listing_last_number,
            "lease_owner": before.lease_owner,
            "lease_until": before.lease_until,
            "available_at": before.available_at,
        }

    store.enqueue_authority(
        AuthorityRequest(17, "example/project", "release", "push.repository_base")
    )

    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        assert row.base_ref == ""
        assert row.generation == baseline["generation"]
        assert row.pull_cursor_number == baseline["pull_cursor_number"]
        assert row.handled_pull_fingerprints == baseline["handled_pull_fingerprints"]
        assert row.listing_next_page == baseline["listing_next_page"]
        assert row.listing_last_number == baseline["listing_last_number"]
        assert row.lease_owner == baseline["lease_owner"]
        assert row.lease_until == baseline["lease_until"]
        assert row.available_at.replace(tzinfo=UTC) <= utcnow() + timedelta(seconds=1)
        assert row.pending_base_refs == {"release": "push.repository_base"}
        assert row.pending_full_rescan is False
    if not deferred:
        assert store.advance_authority_cursor(claim, 21, {**handled, "21": "b" * 64})
    else:
        resumed = store.claim_authority("new-evidence", 60)
        assert resumed is not None and resumed.id == claim.id
        assert resumed.listing_next_page == 3 and resumed.listing_last_number == 200


def test_completed_repository_authority_hands_off_deduplicated_base_refs(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/project", None, "member.removed"))
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    assert store.advance_authority_cursor(
        claim,
        12,
        {"12": "a" * 64},
        listing_next_page=2,
        listing_last_number=100,
    )
    store.enqueue_authority(AuthorityRequest(17, "example/project", "main", "push.main-first"))
    store.enqueue_authority(AuthorityRequest(17, "example/project", "release", "push.release"))
    store.enqueue_authority(AuthorityRequest(17, "example/project", "main", "push.main-latest"))

    assert store.complete_authority(claim, "worker")
    assert store.pending_count() == 2
    narrow = {
        (job.base_ref, job.reason)
        for job in (
            store.claim_authority("followup-worker", 60),
            store.claim_authority("followup-worker", 60),
        )
        if job is not None
    }
    assert narrow == {("main", "push.main-latest"), ("release", "push.release")}


def test_repository_authority_bounds_narrow_followups_with_one_full_rescan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "extra_codeowners.database.MAX_BASE_SCOPED_AUTHORITY_JOBS_PER_REPOSITORY", 2
    )
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/project", None, "member.removed"))
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    assert store.advance_authority_cursor(
        claim,
        45,
        {"45": "c" * 64},
        listing_next_page=4,
        listing_last_number=300,
    )
    for branch in ("main", "release", "third", "fourth"):
        store.enqueue_authority(AuthorityRequest(17, "example/project", branch, f"push.{branch}"))

    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        assert row.generation == claim.generation
        assert row.lease_owner == claim.lease_owner
        assert row.pull_cursor_number == 45
        assert row.listing_next_page == 4 and row.listing_last_number == 300
        assert row.handled_pull_fingerprints == {"45": "c" * 64}
        assert row.pending_base_refs == {}
        assert row.pending_full_rescan is True

    assert store.complete_authority(claim, "worker")
    assert store.pending_count() == 1
    rescan = store.claim_authority("next-worker", 60)
    assert rescan is not None
    assert rescan.id == claim.id and rescan.base_ref is None
    assert rescan.generation == claim.generation + 1
    assert rescan.pull_cursor_number == 0
    assert rescan.listing_next_page == 1 and rescan.listing_last_number == 0
    assert rescan.handled_pull_fingerprints == ()
    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        assert row.pending_base_refs == {} and row.pending_full_rescan is False


def test_overlong_narrow_followup_saturates_without_resetting_broad_claim(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/project", None, "member.removed"))
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    assert store.advance_authority_cursor(
        claim, 31, {"31": "f" * 64}, listing_next_page=3, listing_last_number=200
    )
    branch = "b" * 256

    store.enqueue_authority(AuthorityRequest(17, "example/project", branch, "push.overlong"))

    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        assert row.generation == claim.generation
        assert row.lease_owner == claim.lease_owner
        assert row.pull_cursor_number == 31
        assert row.handled_pull_fingerprints == {"31": "f" * 64}
        assert row.listing_next_page == 3 and row.listing_last_number == 200
        assert row.pending_base_refs == {}
        assert row.pending_full_rescan is True


def test_overlong_base_push_without_broad_row_uses_bounded_repository_scope(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/project", "b" * 256, "push.overlong"))

    assert store.pending_count() == 1
    broad = store.claim_authority("worker", 60)
    assert broad is not None
    assert broad.repository_full_name == "example/project"
    assert broad.base_ref is None


def test_new_repository_authority_resets_pending_narrow_followups(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/project", None, "member.removed"))
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    assert store.advance_authority_cursor(
        claim, 23, {"23": "d" * 64}, listing_next_page=3, listing_last_number=200
    )
    store.enqueue_authority(AuthorityRequest(17, "example/project", "main", "push.repository_base"))
    store.enqueue_authority(
        AuthorityRequest(17, "example/project", None, "push.organization_policy")
    )

    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        assert row.generation == claim.generation
        assert row.pull_cursor_number == 23
        assert row.handled_pull_fingerprints == {"23": "d" * 64}
        assert row.listing_next_page == 3 and row.listing_last_number == 200
        assert row.lease_owner == claim.lease_owner and row.lease_until is not None
        assert row.pending_base_refs == {} and row.pending_full_rescan is True
        assert row.pending_rescan_reason == "push.organization_policy"
    assert store.complete_authority(claim, claim.lease_owner)
    rescan = store.claim_authority("rescan", 60)
    assert rescan is not None and rescan.generation > claim.generation
    assert rescan.reason == "push.organization_policy"
    assert rescan.listing_next_page == 1 and rescan.listing_last_number == 0


def test_authority_insert_race_retries_into_locked_coalescing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = make_store(tmp_path)
    request_value = AuthorityRequest(17, "example/project", None, "member.removed")
    store.enqueue_authority(request_value)
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    assert store.advance_authority_cursor(
        claim,
        73,
        {"73": "f" * 64},
        listing_next_page=4,
        listing_last_number=300,
    )
    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        baseline = (row.generation, row.lease_owner, row.lease_until)

    original_scalar = SQLAlchemySession.scalar
    hidden_once = False

    def hide_first_existing_authority(
        session: SQLAlchemySession, statement: Any, *args: Any, **kwargs: Any
    ) -> Any:
        nonlocal hidden_once
        descriptions = getattr(statement, "column_descriptions", ())
        if not hidden_once and descriptions and descriptions[0].get("entity") is AuthorityJob:
            hidden_once = True
            return None
        return original_scalar(session, statement, *args, **kwargs)

    monkeypatch.setattr(SQLAlchemySession, "scalar", hide_first_existing_authority)
    store.enqueue_authority(AuthorityRequest(17, "example/project", None, "team_add.received"))

    assert hidden_once
    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        assert row.pending_full_rescan is True
        assert row.pending_rescan_reason == "team_add.received"
        assert row.generation == baseline[0]
        assert row.lease_owner == baseline[1] and row.lease_until == baseline[2]
        assert row.pull_cursor_number == 73
        assert row.listing_next_page == 4 and row.listing_last_number == 300
        assert row.handled_pull_fingerprints == {"73": "f" * 64}
    store.close()


@pytest.mark.parametrize("stale_completion", [False, True])
def test_stale_repository_claim_cannot_consume_pending_base_followups(
    tmp_path: Path, stale_completion: bool
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/project", None, "member.removed"))
    old_claim = store.claim_authority("old-worker", 60)
    assert old_claim is not None
    with store.session() as session:
        row = session.get(AuthorityJob, old_claim.id)
        assert row is not None
        row.lease_until = utcnow() - timedelta(seconds=1)
    current = store.claim_authority("current-worker", 60)
    assert current is not None and current.generation > old_claim.generation
    store.enqueue_authority(AuthorityRequest(17, "example/project", "main", "push.repository_base"))
    if stale_completion:
        assert not store.complete_authority(old_claim, "old-worker")
        with store.session() as session:
            row = session.get(AuthorityJob, current.id)
            assert row is not None
            assert row.pending_base_refs == {"main": "push.repository_base"}
        assert store.complete_authority(current, "current-worker")
    else:
        assert store.complete_authority(current, "current-worker")
    followup = store.claim_authority("followup-worker", 60)
    assert followup is not None and followup.base_ref == "main"


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


def test_single_repository_addition_is_durable_without_fencing_existing_targets(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    payload = {
        "action": "added",
        "installation": {"id": 17, "account": {"login": "example"}},
        "repositories_added": [{"id": 42, "name": "new", "full_name": "example/new"}],
        "repositories_removed": [],
    }
    webhook = VerifiedWebhook("new-repository", "installation_repositories", "added", payload)
    authority = evaluation_job(webhook)
    assert isinstance(authority, AuthorityRequest)
    assert store.accept_delivery(webhook.delivery_id, webhook.event, authority).accepted
    assert not store.accept_delivery(webhook.delivery_id, webhook.event, authority).accepted
    store.enqueue(JobRequest(17, "example/new", 1, "pull_request.opened", "a" * 40))
    store.enqueue(JobRequest(17, "example/existing", 2, "pull_request.opened", "b" * 40))

    unaffected = store.claim("existing-worker", 60)
    assert unaffected is not None and unaffected.repository_full_name == "example/existing"
    assert not store.has_blocking_authority(unaffected, "main")
    assert store.claim("new-worker", 60) is None
    fence = store.claim_authority("authority-worker", 60)
    assert fence is not None and fence.repository_full_name == "example/new"
    assert store.complete_authority(fence, "authority-worker")
    added = store.claim("new-worker", 60)
    assert added is not None and added.repository_full_name == "example/new"


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


@pytest.mark.parametrize("prioritize", [True, False])
def test_direct_event_prioritizes_its_authority_fence(tmp_path: Path, prioritize: bool) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/older", None, "installation.created"))
    store.enqueue_authority(AuthorityRequest(17, "example/active", "main", "push.repository_base"))
    store.accept_delivery(
        "direct-pr",
        "pull_request",
        JobRequest(
            17,
            "example/active",
            1,
            "pull_request.opened",
            head_sha_hint="a" * 40,
            base_ref_hint="main",
        ),
    )
    assert store.claim("evaluation", 60) is None
    authority = store.claim_authority("worker", 60, prioritize_interactive=prioritize)
    assert authority is not None
    assert authority.repository_full_name == ("example/active" if prioritize else "example/older")
    assert store.claim("evaluation", 60) is None
    if prioritize:
        assert store.complete_authority(authority, "worker")
        assert store.claim("evaluation", 60) is not None


@pytest.mark.parametrize(
    ("base_ref_hint", "expected_woken"),
    [
        (
            "main",
            {
                ("example/project", ""),
                ("example/project", "main"),
                ("*", ""),
                ("*", "install-main"),
            },
        ),
        (None, {("example/project", ""), ("*", ""), ("*", "install-main")}),
    ],
)
def test_direct_event_wakes_only_covering_base_authority_rows(
    tmp_path: Path,
    base_ref_hint: str | None,
    expected_woken: set[tuple[str, str]],
) -> None:
    store = make_store(tmp_path)
    deferred_until = utcnow() + timedelta(seconds=60)
    with store.session() as session:
        for scope_key, base_ref in (
            ("example/project", ""),
            ("example/project", "main"),
            ("example/project", "release"),
            ("*", ""),
            ("*", "install-main"),
        ):
            session.add(
                AuthorityJob(
                    installation_id=17,
                    scope_key=scope_key,
                    base_ref=base_ref,
                    reason="direct-wake-test",
                    requested_at=utcnow(),
                    available_at=deferred_until,
                )
            )
        before = {
            (row.scope_key, row.base_ref): row.interactive_wake_generation
            for row in session.query(AuthorityJob)
        }

    store.enqueue(request(base_ref_hint=base_ref_hint))

    with store.session() as session:
        rows = session.query(AuthorityJob).all()
        woken = {
            (row.scope_key, row.base_ref)
            for row in rows
            if row.interactive_wake_generation > before[(row.scope_key, row.base_ref)]
        }
        assert woken == expected_woken
        for row in rows:
            if (row.scope_key, row.base_ref) in expected_woken:
                assert row.available_at.replace(tzinfo=UTC) <= utcnow() + timedelta(seconds=1)
            else:
                assert row.available_at.replace(tzinfo=UTC) > utcnow() + timedelta(seconds=55)


def test_unknown_direct_event_can_claim_and_fresh_base_observation_wakes_exact_fence(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/project", "release", "push.release"))
    store.enqueue_authority(AuthorityRequest(17, "example/project", "main", "push.main"))
    for owner in ("release-worker", "main-worker"):
        authority = store.claim_authority(owner, 60)
        assert authority is not None
        assert store.defer_authority(authority, owner, "quota pause", 600)

    store.enqueue(request(base_ref_hint=None))
    assert store.claim_authority("unknown-priority", 60) is None
    claimed = store.claim("evaluation-worker", 60)
    assert claimed is not None and claimed.base_ref_hint is None
    with store.session() as session:
        before = {
            row.base_ref: row.interactive_wake_generation for row in session.query(AuthorityJob)
        }

    assert store.observe_evaluation_base(claimed, "main")

    with store.session() as session:
        rows = {row.base_ref: row for row in session.query(AuthorityJob)}
        assert rows["main"].interactive_wake_generation == before["main"] + 1
        assert rows["release"].interactive_wake_generation == before["release"]
    with store.session() as session:
        row = session.get(EvaluationJob, claimed.id)
        assert row is not None and row.base_ref_hint == "main"
    main_fence = store.claim_authority("main-authority-worker", 60)
    assert main_fence is not None and main_fence.base_ref == "main"
    assert store.authority_has_direct_waiter(main_fence)
    assert store.has_blocking_authority(claimed, "main")
    # The hint is scheduling context only; publication checks the actual base.
    assert store.has_blocking_authority(claimed, "release")


def test_base_hint_coalescing_clears_stale_value_and_rejects_invalid_explicit_values(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    store.enqueue(request(base_ref_hint="main"))
    store.enqueue(request(reason="pull_request.synchronize", base_ref_hint=None))
    with store.session() as session:
        row = session.query(EvaluationJob).one()
        assert row.base_ref_hint is None

    for invalid in ("", "x" * 256, "bad\nref"):
        with pytest.raises(ValueError, match="base_ref_hint"):
            JobRequest(17, "example/project", 42, "invalid-hint", base_ref_hint=invalid)


@pytest.mark.parametrize("reason", ["periodic_reconciliation", "installation.created"])
def test_background_fanout_does_not_get_direct_event_priority(tmp_path: Path, reason: str) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/older", None, "installation.created"))
    store.enqueue_authority(
        AuthorityRequest(17, "example/background", None, "installation.created")
    )
    store.enqueue(JobRequest(17, "example/background", 1, reason, work_class="recovery"))
    job = store.claim_authority("worker", 60)
    assert job is not None and job.repository_full_name == "example/older"


def test_installation_fence_still_preempts_direct_event_priority(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/active", None, "installation.created"))
    store.accept_delivery(
        "direct-pr",
        "pull_request",
        JobRequest(
            17,
            "example/active",
            1,
            "pull_request.opened",
            head_sha_hint="a" * 40,
        ),
    )
    store.enqueue_authority(AuthorityRequest(17, None, None, "membership.removed"))
    job = store.claim_authority("worker", 60)
    assert job is not None and job.repository_full_name is None


def test_direct_event_priority_does_not_cross_installations(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.enqueue_authority(AuthorityRequest(17, "example/older", None, "installation.created"))
    store.enqueue_authority(AuthorityRequest(17, "example/active", None, "installation.created"))
    store.accept_delivery(
        "other-installation",
        "pull_request",
        JobRequest(
            99,
            "example/active",
            1,
            "pull_request.opened",
            head_sha_hint="a" * 40,
        ),
    )
    job = store.claim_authority("worker", 60)
    assert job is not None and job.repository_full_name == "example/older"


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
    assert store.release_service_lease("reconciler", "two") is False
    assert store.acquire_service_lease("reconciler", "one", 60) is True
    assert store.release_service_lease("reconciler", "one") is True
    assert store.acquire_service_lease("reconciler", "two", 60) is True
    assert store.release_service_lease("reconciler", "one") is False

    with store.session() as session:
        session.execute(
            update(ServiceLease)
            .where(ServiceLease.name == "reconciler")
            .values(lease_until=utcnow() - timedelta(seconds=1))
        )
    assert store.acquire_service_lease("reconciler", "one", 60) is True


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
