"""Active sweeps avoid replay without losing new identities or cold recovery."""

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from extra_codeowners.api_budget import RecoveryApiBudget, RecoveryBudgetDeferredError
from extra_codeowners.database import QueueStore
from extra_codeowners.github import GitHubClient
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.service import Reconciler
from extra_codeowners.settings import Settings


# Verifies XCO-019.
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["unchanged", "new_id", "renamed", "missing_id", "new_member", "cold"]
)
async def test_continuation_uses_current_immutable_scope_and_does_not_replay_completed_prefix(
    tmp_path: Path, change: str
) -> None:
    github = MagicMock(spec=GitHubClient)
    github.list_installations = AsyncMock(return_value=[{"id": 2, "suspended_at": None}])
    repositories = [
        {"id": index, "full_name": f"example/{name}", "archived": False}
        for index, name in enumerate(("a", "b", "c"), start=101)
    ]
    if change == "missing_id":
        repositories[0].pop("id")
    github.list_installation_repositories = AsyncMock(return_value=repositories)
    visited: list[str] = []
    defer = True

    async def pulls(installation_id: int, name: str, **kwargs: Any) -> list[dict[str, Any]]:
        visited.append(name)
        if defer and name == "example/b":
            raise RecoveryBudgetDeferredError(1)
        return [{"number": 1, "head": {"sha": "a" * 40}}]

    github.list_open_pulls = AsyncMock(side_effect=pulls)
    url = f"sqlite:///{tmp_path / 'continuation.db'}"
    upgrade_database(url)
    store = QueueStore(url)
    store.initialize()
    configuration = Settings(_env_file=None, environment="test", github_max_in_flight_requests=1)
    reconciler = Reconciler(configuration, github, store, "one")
    now = 0.0
    reconciler._cadence._clock = lambda: now
    try:
        first = await reconciler.reconcile_once()
        assert first is not None and first.deferred and not first.complete
        assert visited == ["example/a", "example/b"]
        assert RecoveryApiBudget(store).repository_cursor(2) == "example/a"
        if change == "new_id":
            repositories[0]["id"] = 999
        elif change == "renamed":
            repositories[0]["full_name"] = "example/renamed"
        elif change == "new_member":
            repositories.append({"id": 999, "full_name": "example/new", "archived": False})
        elif change == "cold":
            store.release_service_lease("open-pr-reconciler", "one")
            reconciler = Reconciler(configuration, github, store, "two")
            reconciler._cadence._clock = lambda: now
        defer = False
        visited.clear()
        now = 1
        second = await reconciler.reconcile_once()
        assert second is not None and second.complete
        assert second.active_sweep_skips == int(change in {"unchanged", "new_member"})
        assert visited[:2] == ["example/b", "example/c"]
        if change in {"new_id", "missing_id", "cold"}:
            assert "example/a" in visited
        else:
            assert "example/a" not in visited
        if change == "renamed":
            assert "example/renamed" in visited
        if change == "new_member":
            assert "example/new" in visited
        assert github.list_installations.await_count == 2
        assert github.list_installation_repositories.await_count == 2
        # Finishing the sweep never suppresses the next periodic scan.
        visited.clear()
        now += configuration.reconcile_interval_seconds
        third = await reconciler.reconcile_once()
        assert third is not None and third.complete
        assert set(visited) == {str(record["full_name"]) for record in repositories}
    finally:
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_id", [True, 0, "102", 101])
async def test_bad_repository_ids_invalidate_the_whole_batch_before_read_ahead(
    tmp_path: Path, invalid_id: Any
) -> None:
    github = MagicMock(spec=GitHubClient)
    github.list_installations = AsyncMock(
        return_value=[{"id": 2, "suspended_at": None}, {"id": 3, "suspended_at": None}]
    )
    github.list_installation_repositories = AsyncMock(
        side_effect=[
            [
                {"id": 101, "full_name": "example/a", "archived": False},
                {"id": invalid_id, "full_name": "example/b", "archived": False},
            ],
            [{"id": 103, "full_name": "example/healthy", "archived": False}],
        ]
    )
    github.list_open_pulls = AsyncMock(return_value=[])
    url = f"sqlite:///{tmp_path / 'bad-identities.db'}"
    upgrade_database(url)
    store = QueueStore(url)
    store.initialize()
    try:
        reconciler = Reconciler(Settings(_env_file=None, environment="test"), github, store, "one")
        result = await reconciler.reconcile_once()
        assert result is not None and result.failed_installations == 1 and not result.complete
        github.list_open_pulls.assert_awaited_once()
        assert github.list_open_pulls.await_args.args == (3, "example/healthy")
    finally:
        store.close()


@pytest.mark.asyncio
async def test_work_quantum_visits_other_installations_then_resumes_tail(tmp_path: Path) -> None:
    github = MagicMock(spec=GitHubClient)
    github.list_installations = AsyncMock(
        return_value=[{"id": 2, "suspended_at": None}, {"id": 3, "suspended_at": None}]
    )
    github.list_installation_repositories = AsyncMock(
        return_value=[
            {"id": index, "full_name": f"example/{name}", "archived": False}
            for index, name in enumerate(("a", "b", "c"), start=101)
        ]
    )
    now = 0.0
    visited: list[tuple[int, str]] = []

    async def pulls(installation_id: int, name: str, **kwargs: Any) -> list[Any]:
        nonlocal now
        visited.append((installation_id, name))
        if installation_id == 2 and name == "example/a":
            now += 301
        return []

    github.list_open_pulls = AsyncMock(side_effect=pulls)
    url = f"sqlite:///{tmp_path / 'fairness.db'}"
    upgrade_database(url)
    store = QueueStore(url)
    store.initialize()
    configuration = Settings(_env_file=None, environment="test", github_max_in_flight_requests=1)
    reconciler = Reconciler(configuration, github, store, "one")
    reconciler._cadence._clock = lambda: now
    reconciler._work_clock = lambda: now
    try:
        first = await reconciler.reconcile_once()
        assert first is not None and not first.complete and first.retry_after_seconds == 1
        assert first.installation_yields == 1
        assert visited == [(2, "example/a"), (3, "example/a"), (3, "example/b"), (3, "example/c")]
        now += 1
        visited.clear()
        second = await reconciler.reconcile_once()
        assert second is not None and second.complete
        assert visited == [(2, "example/b"), (2, "example/c")]
    finally:
        store.close()
