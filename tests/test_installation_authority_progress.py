from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, select, update
from test_service import FakeGitHub, migrated_store, settings

from extra_codeowners.database import (
    AuthorityJob,
    AuthorityRequest,
    QueueStore,
    utcnow,
)
from extra_codeowners.github import (
    InstallationRepositoriesChangedError,
    InstallationRepositoryPage,
)
from extra_codeowners.service import EvaluationService, Worker


def installation_fixture(tmp_path: Path) -> tuple[QueueStore, Any, Worker]:
    store = migrated_store(f"sqlite:///{tmp_path / 'installation-authority.db'}")
    github = FakeGitHub(changed_path="uv.lock")
    runtime = settings()
    evaluator = EvaluationService(runtime, github, store)  # type: ignore[arg-type]
    worker = Worker(runtime, store, evaluator, "worker")
    store.enqueue_authority(AuthorityRequest(2, None, None, "membership.removed"))
    return store, github, worker


def test_installation_page_atomically_enqueues_children_and_checkpoints_parent(
    tmp_path: Path,
) -> None:
    store, _, _ = installation_fixture(tmp_path)
    claim = store.claim_authority("worker", 60)
    assert claim is not None and claim.repository_full_name is None
    children = [
        AuthorityRequest(2, "example/one", None, claim.reason),
        AuthorityRequest(2, "example/two", None, claim.reason),
    ]

    assert store.advance_installation_authority_page(
        claim, children, next_page=2, expected_total=150
    )

    with store.session() as session:
        parent = session.get(AuthorityJob, claim.id)
        assert parent is not None
        assert parent.listing_next_page == 2
        assert parent.listing_expected_total == 150
        rows = session.query(AuthorityJob).filter(AuthorityJob.scope_key != "*").all()
        assert {(row.scope_key, row.generation) for row in rows} == {
            ("example/one", 1),
            ("example/two", 1),
        }


def test_installation_page_batch_failure_rolls_back_children_and_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, _ = installation_fixture(tmp_path)
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    original = QueueStore._enqueue_authority_in_session
    inserted = 0

    def fail_second(session: Any, request: AuthorityRequest) -> None:
        nonlocal inserted
        inserted += 1
        original(session, request)
        if inserted == 2:
            raise RuntimeError("injected child insert failure")

    monkeypatch.setattr(QueueStore, "_enqueue_authority_in_session", staticmethod(fail_second))
    with pytest.raises(RuntimeError, match="injected child insert failure"):
        store.advance_installation_authority_page(
            claim,
            [
                AuthorityRequest(2, "example/one", None, claim.reason),
                AuthorityRequest(2, "example/two", None, claim.reason),
            ],
            next_page=2,
            expected_total=150,
        )

    with store.session() as session:
        parent = session.get(AuthorityJob, claim.id)
        assert parent is not None
        assert parent.listing_next_page == 1
        assert parent.listing_expected_total is None
        assert session.query(AuthorityJob).filter(AuthorityJob.scope_key != "*").count() == 0


def test_expired_installation_claim_cannot_checkpoint_children(
    tmp_path: Path,
) -> None:
    store, _, _ = installation_fixture(tmp_path)
    stale = store.claim_authority("first-replica", 60)
    assert stale is not None
    with store.session() as session:
        row = session.get(AuthorityJob, stale.id)
        assert row is not None
        row.lease_until = utcnow() - timedelta(seconds=1)

    current = store.claim_authority("second-replica", 60)
    assert current is not None and current.generation > stale.generation
    child = AuthorityRequest(2, "example/one", None, current.reason)
    assert not store.advance_installation_authority_page(
        stale, [child], next_page=2, expected_total=150
    )
    with store.session() as session:
        parent = session.get(AuthorityJob, current.id)
        assert parent is not None and parent.listing_next_page == 1
        assert session.query(AuthorityJob).filter(AuthorityJob.scope_key != "*").count() == 0


@pytest.mark.asyncio
async def test_installation_takeover_resumes_next_page_without_reenqueuing_children(
    tmp_path: Path,
) -> None:
    store, github, worker = installation_fixture(tmp_path)
    first = store.claim_authority("worker", 60)
    assert first is not None
    first_child = AuthorityRequest(2, "example/one", None, first.reason)
    assert store.advance_installation_authority_page(
        first, [first_child], next_page=2, expected_total=150
    )
    with store.session() as session:
        child = session.scalar(select(AuthorityJob).where(AuthorityJob.scope_key == "example/one"))
        assert child is not None
        child_generation = child.generation
        parent = session.get(AuthorityJob, first.id)
        assert parent is not None
        parent.lease_until = utcnow() - timedelta(seconds=1)

    calls: list[tuple[int, int | None]] = []

    async def list_page(
        _installation: int,
        *,
        page: int = 1,
        expected_total: int | None = None,
    ) -> InstallationRepositoryPage:
        calls.append((page, expected_total))
        return InstallationRepositoryPage(
            repositories=[{"full_name": "example/two", "archived": False}],
            total_count=150,
            next_page=0,
        )

    github.list_installation_repository_page = AsyncMock(side_effect=list_page)
    second = store.claim_authority("second-replica", 60)
    assert second is not None
    assert second.listing_next_page == 2
    assert second.listing_expected_total == 150
    worker = Worker(worker.settings, store, worker.evaluator, "second-replica")

    assert await worker._process_authority(second) == "completed"
    assert calls == [(2, 150)]
    with store.session() as session:
        child = session.scalar(select(AuthorityJob).where(AuthorityJob.scope_key == "example/one"))
        assert child is not None and child.generation == child_generation
        assert (
            session.scalar(select(AuthorityJob.id).where(AuthorityJob.scope_key == "example/two"))
            is not None
        )


@pytest.mark.asyncio
async def test_changed_installation_total_resets_checkpoint_before_retry(
    tmp_path: Path,
) -> None:
    store, github, worker = installation_fixture(tmp_path)
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    assert store.advance_installation_authority_page(claim, [], next_page=2, expected_total=150)
    github.list_installation_repository_page = AsyncMock(
        side_effect=InstallationRepositoriesChangedError("membership changed")
    )

    assert await worker._process_authority(claim) == "failed"

    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        assert row.listing_next_page == 1
        assert row.listing_expected_total is None
        assert row.lease_owner is None


@pytest.mark.parametrize("installation_scope", [False, True])
def test_repeated_broad_events_preserve_active_progress_and_schedule_one_followup(
    tmp_path: Path,
    installation_scope: bool,
) -> None:
    store, _, _ = installation_fixture(tmp_path)
    request = AuthorityRequest(
        2,
        None if installation_scope else "example/project",
        None,
        "label.edited",
    )
    if not installation_scope:
        with store.session() as session:
            session.execute(delete(AuthorityJob).where(AuthorityJob.scope_key == "*"))
        store.enqueue_authority(request)
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    if installation_scope:
        assert store.advance_installation_authority_page(claim, [], next_page=2, expected_total=150)
    else:
        assert store.advance_authority_cursor(
            claim, 0, {}, listing_next_page=2, listing_last_number=0
        )
        with store.session() as session:
            session.execute(
                update(AuthorityJob)
                .where(AuthorityJob.id == claim.id)
                .values(listing_expected_total=150)
            )
    with store.session() as session:
        before = session.get(AuthorityJob, claim.id)
        assert before is not None
        progress = (
            before.generation,
            before.listing_next_page,
            before.listing_expected_total,
            before.lease_owner,
            before.lease_until,
        )

    for index in range(100):
        store.accept_delivery(
            f"label-delivery-{index}",
            "label" if not installation_scope else "membership",
            AuthorityRequest(
                request.installation_id,
                request.repository_full_name,
                request.base_ref,
                f"label.edit-{index}",
            ),
        )

    with store.session() as session:
        active = session.get(AuthorityJob, claim.id)
        assert active is not None
        assert (
            active.generation,
            active.listing_next_page,
            active.listing_expected_total,
            active.lease_owner,
            active.lease_until,
        ) == progress
        assert active.pending_full_rescan is True
        assert active.pending_rescan_reason == "label.edit-99"

    assert store.complete_authority(claim, "worker")
    followup = store.claim_authority("followup", 60)
    assert followup is not None
    assert followup.id == claim.id
    assert followup.generation == claim.generation + 1
    assert followup.reason == "label.edit-99"
    assert followup.listing_next_page == 1
    assert followup.listing_expected_total is None
    with store.session() as session:
        assert session.get(AuthorityJob, followup.id) is not None
