"""Exercise advisory retry timing against real leases and quota accounting."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from extra_codeowners import service as service_module
from extra_codeowners.api_budget import CoreQuota, RecoveryApiBudget, RecoveryBudgetDeferredError
from extra_codeowners.database import Base, QueueStore, utcnow
from extra_codeowners.github import GitHubClient
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.reconciliation_cadence import ReconciliationCadence
from extra_codeowners.service import Reconciler, ReconciliationOutcome
from extra_codeowners.settings import Settings


@pytest.fixture(params=["sqlite", "postgresql"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[QueueStore]:
    url = f"sqlite:///{tmp_path / 'scheduling.db'}"
    if request.param == "postgresql":
        request.node.add_marker(pytest.mark.integration)
        url = os.environ.get("TEST_POSTGRES_URL", "")
        if not url:
            pytest.skip("TEST_POSTGRES_URL is not configured")
        database = make_url(url).database
        assert database is not None and database.endswith("_test")
    store = QueueStore(url)
    if request.param == "postgresql":
        Base.metadata.drop_all(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    upgrade_database(url)
    store.initialize()
    try:
        yield store
    finally:
        store.close()


def reconciler_for(store: QueueStore, owner: str = "one") -> tuple[Reconciler, Any]:
    github = MagicMock(spec=GitHubClient)
    github.list_installations.return_value = [
        {"id": 17, "suspended_at": None},
        {"id": 18, "suspended_at": None},
    ]
    github.list_installation_repositories.return_value = []
    settings = Settings(
        _env_file=None,
        environment="test",
        worker_enabled=False,
        reconcile_enabled=False,
        reconcile_interval_seconds=300,
    )
    return Reconciler(settings, github, store, owner), github


@pytest.mark.asyncio
async def test_deferred_retry_skips_healthy_installation_without_false_full_success(
    store: QueueStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Verifies XCO-014: cadence is not cached authorization or GitHub evidence.
    reconciler, github = reconciler_for(store)
    now = 0.0
    reconciler._cadence = ReconciliationCadence(lambda: now)
    visits: list[int] = []

    async def repositories(installation: int, **kwargs: Any) -> list[Any]:
        visits.append(installation)
        if installation == 18 and now == 0:
            raise RecoveryBudgetDeferredError(60, reason="probe_pending")
        return []

    github.list_installation_repositories.side_effect = repositories
    successes = MagicMock()
    attempts = MagicMock()
    monkeypatch.setattr(service_module, "RECONCILIATION_LAST_SUCCESS", successes)
    monkeypatch.setattr(service_module, "RECONCILIATIONS", attempts)

    first = await reconciler.run_iteration()
    assert first is not None and first.deferred and not first.complete
    assert first.retry_after_seconds == 60
    successes.set_to_current_time.assert_not_called()
    assert visits == [17, 18]

    now = 60
    resumed = await reconciler.run_iteration()
    assert resumed is not None and resumed.complete
    assert resumed.installations_skipped == 1 and resumed.retry_after_seconds == 240
    assert visits == [17, 18, 18]
    successes.set_to_current_time.assert_called_once_with()

    now = 61
    idle = await reconciler.run_iteration()
    assert idle is not None and idle.idle and not idle.complete
    assert idle.installations_skipped == 2 and idle.retry_after_seconds == 239
    successes.set_to_current_time.assert_called_once_with()
    assert visits == [17, 18, 18]
    assert github.list_installations.await_count == 3
    assert [call.args for call in attempts.labels.call_args_list] == [
        ("partial",),
        ("success",),
        ("idle",),
    ]

    now = 300
    partial = await reconciler.run_iteration()
    assert partial is not None and not partial.complete and not partial.idle
    assert visits == [17, 18, 18, 17]
    successes.set_to_current_time.assert_called_once_with()
    now = 360
    result = await reconciler.run_iteration()
    assert result is not None and result.complete
    assert visits == [17, 18, 18, 17, 18]
    assert successes.set_to_current_time.call_count == 2


@pytest.mark.asyncio
async def test_slow_other_installation_does_not_restart_an_elapsed_retry(store: QueueStore) -> None:
    reconciler, github = reconciler_for(store)
    now = 0.0
    reconciler._cadence = ReconciliationCadence(lambda: now)

    async def repositories(installation: int, **kwargs: Any) -> list[Any]:
        nonlocal now
        if installation == 17:
            raise RecoveryBudgetDeferredError(60)
        now = 180
        return []

    github.list_installation_repositories.side_effect = repositories
    result = await reconciler.reconcile_once()
    assert result is not None and result.retry_after_seconds == 1 and not result.complete


@pytest.mark.asyncio
async def test_cold_leader_revalidates_but_cannot_bypass_shared_budget(store: QueueStore) -> None:
    # Verifies XCO-014: losing election discards local progress; budgets remain durable.
    leader, github = reconciler_for(store)
    result = await leader.reconcile_once()
    assert result is not None and result.complete
    peer, peer_github = reconciler_for(store, "two")
    assert await peer.reconcile_once() is None
    peer_github.list_installations.assert_not_called()
    budget = RecoveryApiBudget(store)
    budget.observe(17, CoreQuota(100, 20, utcnow() + timedelta(hours=1)))

    async def repositories(installation: int, **kwargs: Any) -> list[Any]:
        budget.admit(installation, recovery=True)
        return []

    peer_github.list_installation_repositories.side_effect = repositories
    assert store.release_service_lease("open-pr-reconciler", "one")
    result = await peer.reconcile_once()
    assert result is not None and result.deferred and not result.complete
    assert peer_github.list_installations.await_count == 1
    assert [
        call.args[0] for call in peer_github.list_installation_repositories.await_args_list
    ] == [17, 18]
    assert not store.provider_is_backpressured(17)
    assert await leader.reconcile_once() is None
    assert leader._cadence.begin([17, 18]) == {17, 18}
    github.list_installations.assert_awaited_once()


@pytest.mark.asyncio
async def test_invalid_current_scope_drops_advisory_state_before_retry(store: QueueStore) -> None:
    reconciler, github = reconciler_for(store)
    result = await reconciler.reconcile_once()
    assert result is not None and result.complete
    github.list_installations.return_value = [
        {"id": 17, "suspended_at": None},
        {"id": 17, "suspended_at": None},
    ]
    with pytest.raises(ValueError, match="duplicate_installation_id"):
        await reconciler.reconcile_once()
    github.list_installations.return_value = [{"id": 17, "suspended_at": None}]
    result = await reconciler.reconcile_once()
    assert result is not None and result.complete
    assert github.list_installation_repositories.await_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("late_loss", [False, True])
async def test_lost_lease_never_reports_idle_or_keeps_cycle_progress(
    store: QueueStore, monkeypatch: pytest.MonkeyPatch, late_loss: bool
) -> None:
    reconciler, _ = reconciler_for(store)
    reconciler._cadence.begin([17])
    reconciler._cadence.record(17, 300, complete=True)
    reconciler._cadence.finish()

    async def renewal(done: asyncio.Event, lost: asyncio.Event, lease_seconds: int) -> None:
        await done.wait()
        if late_loss:
            lost.set()

    stop = asyncio.Event()
    monkeypatch.setattr(reconciler, "_renew_lease", renewal)
    if not late_loss:
        stop.set()
    outcome = await reconciler.reconcile_once(stop)
    if late_loss:
        assert outcome is not None and outcome.lease_lost and not outcome.idle
        assert not outcome.complete and not outcome.cycle_complete
    else:
        assert outcome is None
    assert reconciler._cadence.begin([17]) == {17}


@pytest.mark.asyncio
async def test_loop_honors_retry_hint_without_globally_shortening_the_interval(
    store: QueueStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    reconciler, _ = reconciler_for(store)
    stop = asyncio.Event()
    iteration = AsyncMock(
        return_value=ReconciliationOutcome(0, deferred=True, retry_after_seconds=60)
    )
    monkeypatch.setattr(reconciler, "run_iteration", iteration)
    delays: list[int] = []

    async def wait_for(awaitable: Any, seconds: int) -> None:
        delays.append(seconds)
        stop.set()
        await awaitable

    monkeypatch.setattr(asyncio, "wait_for", wait_for)
    await reconciler.run(stop)
    assert delays == [60]
    assert reconciler.settings.reconcile_interval_seconds == 300
