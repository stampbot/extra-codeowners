from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select, update
from test_service import FakeGitHub, migrated_store, settings

from extra_codeowners.api_budget import RecoveryBudgetDeferredError
from extra_codeowners.database import AuthorityJob, AuthorityRequest, QueueStore, utcnow
from extra_codeowners.github import (
    InstallationRepositoriesChangedError,
    InstallationRepositoryPage,
)
from extra_codeowners.service import EvaluationService, Worker


def membership_fixture(tmp_path: Path) -> tuple[QueueStore, Any, Worker]:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-membership.db'}")
    github = FakeGitHub(changed_path="uv.lock")
    github.installation_includes_repository = AsyncMock(return_value=False)  # type: ignore[method-assign]
    runtime = settings()
    evaluator = EvaluationService(runtime, github, store)  # type: ignore[arg-type]
    worker = Worker(runtime, store, evaluator, "worker")
    store.enqueue_authority(AuthorityRequest(2, "example/project", None, "repository.renamed"))
    return store, github, worker


def repository_page(start: int, stop: int, *, next_page: int) -> InstallationRepositoryPage:
    return InstallationRepositoryPage(
        repositories=[
            {"full_name": f"example/repo-{number:03d}", "archived": False}
            for number in range(start, stop)
        ],
        total_count=150,
        next_page=next_page,
    )


@pytest.mark.asyncio
async def test_absence_membership_listing_resumes_after_quota_pause_without_page_replay(
    tmp_path: Path,
) -> None:
    store, github, worker = membership_fixture(tmp_path)
    first = store.claim_authority("worker", 60)
    assert first is not None
    calls: list[tuple[int, int | None]] = []

    async def listing(
        _installation: int,
        *,
        page: int,
        expected_total: int | None,
    ) -> InstallationRepositoryPage:
        calls.append((page, expected_total))
        if page == 1:
            return repository_page(0, 100, next_page=2)
        if len(calls) == 2:
            raise RecoveryBudgetDeferredError(60)
        return repository_page(100, 150, next_page=0)

    github.list_installation_repository_page = AsyncMock(side_effect=listing)

    with pytest.raises(RecoveryBudgetDeferredError):
        await worker._authority_repository_absent(first)

    with store.session() as session:
        row = session.get(AuthorityJob, first.id)
        assert row is not None
        assert row.membership_next_page == 2
        assert row.membership_expected_total == 150
    assert store.defer_authority(first, first.lease_owner, "quota pause", 60)
    with store.session() as session:
        session.execute(
            update(AuthorityJob)
            .where(AuthorityJob.id == first.id)
            .values(available_at=utcnow() - timedelta(seconds=1))
        )

    second = store.claim_authority("second-replica", 60)
    assert second is not None
    assert second.membership_next_page == 2
    assert second.membership_expected_total == 150
    assert await worker._authority_repository_absent(second) is True
    assert calls == [(1, None), (2, 150), (2, 150)]
    github.installation_includes_repository.assert_awaited_once_with(
        2, "example/project", refresh=True
    )


@pytest.mark.asyncio
async def test_membership_page_total_change_resets_cursor_for_a_fresh_enumeration(
    tmp_path: Path,
) -> None:
    store, github, worker = membership_fixture(tmp_path)
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    assert store.advance_authority_membership_page(claim, next_page=2, expected_total=150)
    github.list_installation_repository_page = AsyncMock(
        side_effect=InstallationRepositoriesChangedError("membership changed")
    )

    with pytest.raises(InstallationRepositoriesChangedError):
        await worker._authority_repository_absent(claim)

    with store.session() as session:
        row = session.get(AuthorityJob, claim.id)
        assert row is not None
        assert row.membership_next_page == 1
        assert row.membership_expected_total is None
    github.installation_includes_repository.assert_not_awaited()


@pytest.mark.asyncio
async def test_repository_found_in_membership_page_is_not_declared_absent(
    tmp_path: Path,
) -> None:
    _, github, worker = membership_fixture(tmp_path)
    claim = worker.store.claim_authority("worker", 60)
    assert claim is not None
    github.list_installation_repository_page = AsyncMock(
        return_value=InstallationRepositoryPage(
            repositories=[{"full_name": "example/project", "archived": False}],
            total_count=1,
            next_page=0,
        )
    )

    assert await worker._authority_repository_absent(claim) is False

    github.installation_includes_repository.assert_not_awaited()


@pytest.mark.asyncio
async def test_terminal_membership_checkpoint_still_requires_fresh_route_confirmation(
    tmp_path: Path,
) -> None:
    store, github, worker = membership_fixture(tmp_path)
    claim = store.claim_authority("worker", 60)
    assert claim is not None
    assert store.advance_authority_membership_page(claim, next_page=0, expected_total=150)
    assert store.defer_authority(claim, claim.lease_owner, "fresh proof retry", 60)
    with store.session() as session:
        session.execute(
            update(AuthorityJob)
            .where(AuthorityJob.id == claim.id)
            .values(available_at=utcnow() - timedelta(seconds=1))
        )
    resumed = store.claim_authority("resumed-worker", 60)
    assert resumed is not None and resumed.membership_next_page == 0
    github.list_installation_repository_page = AsyncMock()
    github.installation_includes_repository.return_value = False

    assert await worker._authority_repository_absent(resumed) is True

    github.list_installation_repository_page.assert_not_awaited()
    github.installation_includes_repository.assert_awaited_once_with(
        2, "example/project", refresh=True
    )


def test_stale_claim_cannot_advance_membership_cursor(tmp_path: Path) -> None:
    store, _, _ = membership_fixture(tmp_path)
    stale = store.claim_authority("first-replica", 60)
    assert stale is not None
    with store.session() as session:
        row = session.get(AuthorityJob, stale.id)
        assert row is not None
        row.lease_until = utcnow() - timedelta(seconds=1)

    current = store.claim_authority("second-replica", 60)
    assert current is not None and current.generation > stale.generation
    assert not store.advance_authority_membership_page(stale, next_page=2, expected_total=150)

    with store.session() as session:
        row = session.scalar(select(AuthorityJob).where(AuthorityJob.id == current.id))
        assert row is not None
        assert row.membership_next_page == 1
        assert row.membership_expected_total is None
