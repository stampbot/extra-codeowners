"""Release sticky scan leadership only after a cooperative, drained exit."""

import asyncio
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from extra_codeowners import service as service_module
from extra_codeowners.database import QueueStore
from extra_codeowners.github import GitHubClient, GitHubOperationStoppedError
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.service import Reconciler, ReconciliationOutcome
from extra_codeowners.settings import Settings


@pytest.fixture
def reconciler(tmp_path: Path) -> Iterator[Reconciler]:
    url = f"sqlite:///{tmp_path / 'shutdown.db'}"
    upgrade_database(url)
    store = QueueStore(url)
    store.initialize()
    github = MagicMock(spec=GitHubClient)
    github.list_installations = AsyncMock(return_value=[])
    value = Reconciler(Settings(_env_file=None, environment="test"), github, store, "first")
    try:
        yield value
    finally:
        store.close()


# Verifies XCO-019: normal continuations retain progress; process exit does not.
@pytest.mark.asyncio
async def test_cooperative_stop_releases_after_an_attempt_but_not_between_attempts(
    reconciler: Reconciler, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = asyncio.Event()
    completed = asyncio.Event()
    original = reconciler.run_iteration

    async def iteration(event: asyncio.Event) -> ReconciliationOutcome | None:
        result = await original(event)
        completed.set()
        return result

    monkeypatch.setattr(reconciler, "run_iteration", iteration)
    task = asyncio.create_task(reconciler.run(stop))
    try:
        await asyncio.wait_for(completed.wait(), 5)
        assert not reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)
        stop.set()
        await asyncio.wait_for(task, 5)
        assert reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)
    finally:
        stop.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_stop_during_discovery_releases_after_scan_and_heartbeat_exit(
    reconciler: Reconciler,
) -> None:
    stop = asyncio.Event()

    async def installations(**kwargs: Any) -> list[dict[str, Any]]:
        stop.set()
        return []

    reconciler.github.list_installations = AsyncMock(side_effect=installations)  # type: ignore[method-assign]
    await asyncio.wait_for(reconciler.run(stop), 5)
    assert reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)


@pytest.mark.asyncio
async def test_shutdown_delete_follows_prefetch_and_heartbeat_cleanup(
    reconciler: Reconciler, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = asyncio.Event()
    readers_started = asyncio.Event()
    heartbeat_done = asyncio.Event()
    active: set[str] = set()
    reconciler.github.list_installations = AsyncMock(return_value=[{"id": 2, "suspended_at": None}])  # type: ignore[method-assign]
    reconciler.github.list_installation_repositories = AsyncMock(  # type: ignore[method-assign]
        return_value=[
            {"id": n, "full_name": f"example/repo-{n}", "archived": False} for n in range(1, 4)
        ]
    )

    async def pulls(
        installation_id: int, name: str, *, stop: asyncio.Event
    ) -> list[dict[str, Any]]:
        active.add(name)
        if len(active) == 3:
            readers_started.set()
        try:
            await stop.wait()
            raise GitHubOperationStoppedError("cooperative fixture stop")
        finally:
            active.remove(name)

    reconciler.github.list_open_pulls = AsyncMock(side_effect=pulls)  # type: ignore[method-assign]
    original_renew = reconciler._renew_lease

    async def heartbeat(done: asyncio.Event, lost: asyncio.Event, seconds: int) -> None:
        try:
            await original_renew(done, lost, seconds)
        finally:
            heartbeat_done.set()

    monkeypatch.setattr(reconciler, "_renew_lease", heartbeat)
    original_release = reconciler.store.release_service_lease

    def release(name: str, owner: str) -> bool:
        assert not active
        assert heartbeat_done.is_set()
        return original_release(name, owner)

    monkeypatch.setattr(reconciler.store, "release_service_lease", release)
    task = asyncio.create_task(reconciler.run(stop))
    try:
        await asyncio.wait_for(readers_started.wait(), 5)
        stop.set()
        await asyncio.wait_for(task, 5)
        assert reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)
    finally:
        stop.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_cancelled_scan_keeps_expiry_fallback_instead_of_racing_pending_database_work(
    reconciler: Reconciler, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered = asyncio.Event()

    async def installations(**kwargs: Any) -> list[dict[str, Any]]:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("blocked fixture unexpectedly resumed")

    reconciler.github.list_installations = AsyncMock(side_effect=installations)  # type: ignore[method-assign]
    release = MagicMock(wraps=reconciler.store.release_service_lease)
    monkeypatch.setattr(reconciler.store, "release_service_lease", release)
    task = asyncio.create_task(reconciler.run(asyncio.Event()))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    release.assert_not_called()
    assert not reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)


@pytest.mark.asyncio
async def test_late_stopping_replica_cannot_delete_another_owners_lease(
    reconciler: Reconciler,
) -> None:
    assert reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)
    stop = asyncio.Event()
    stop.set()
    await reconciler.run(stop)
    assert not reconciler.store.acquire_service_lease("open-pr-reconciler", "third", 600)
    assert reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)


@pytest.mark.asyncio
async def test_release_failure_is_bounded_logged_and_retains_expiry_fallback(
    reconciler: Reconciler, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert reconciler.store.acquire_service_lease("open-pr-reconciler", "first", 600)
    logger = MagicMock()
    monkeypatch.setattr(service_module, "log", logger)
    monkeypatch.setattr(
        reconciler.store,
        "release_service_lease",
        MagicMock(side_effect=RuntimeError("private database detail")),
    )
    stop = asyncio.Event()
    stop.set()
    await reconciler.run(stop)
    logger.warning.assert_called_once_with(
        "reconciliation_shutdown_lease_release_failed", error_type="RuntimeError"
    )
    assert not reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)


@pytest.mark.asyncio
async def test_cancellation_during_release_drains_the_started_delete_before_returning(
    reconciler: Reconciler, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert reconciler.store.acquire_service_lease("open-pr-reconciler", "first", 600)
    entered = threading.Event()
    proceed = threading.Event()
    original = reconciler.store.release_service_lease

    def release(name: str, owner: str) -> bool:
        entered.set()
        assert proceed.wait(5)
        return original(name, owner)

    monkeypatch.setattr(reconciler.store, "release_service_lease", release)
    stop = asyncio.Event()
    stop.set()
    task = asyncio.create_task(reconciler.run(stop))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        proceed.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        assert reconciler.store.acquire_service_lease("open-pr-reconciler", "second", 600)
    finally:
        proceed.set()
        await asyncio.gather(task, return_exceptions=True)
