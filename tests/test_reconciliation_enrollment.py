"""Exercise enrollment discovery through real HTTP and queue interfaces."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from extra_codeowners.api_budget import RecoveryApiBudget
from extra_codeowners.database import InstallationApiBudget, JobRequest, QueueStore
from extra_codeowners.github import GitHubClient, GitHubError
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.service import Reconciler, ReconciliationOutcome
from extra_codeowners.settings import Settings


class DiscoveryProvider:
    def __init__(self, count: int = 3) -> None:
        self.count = count
        self.base = "b" * 40
        self.bases: dict[int, str] = {}
        self.policies: dict[str, tuple[int, str]] = {}
        self.policy_status = 404
        self.policy_body = "enabled = true"
        self.managed: set[str] = set()
        self.requests: Counter[str] = Counter()
        self.limit = 15000
        self.remaining = 15000
        self.reset = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
        self.store: QueueStore | None = None
        self.inject_direct_event = False
        self.empty_tail_repository = False
        self.reverse_pulls = False
        self.repository_visible = True
        self.repository_archived = False
        self.installation_suspended = False

    def respond(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests[path] += 1
        if path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "test-token",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        if path == "/app/installations":
            suspended_at = datetime.now(UTC).isoformat() if self.installation_suspended else None
            return httpx.Response(200, json=[{"id": 17, "suspended_at": suspended_at}])
        headers: dict[str, str] = {}
        status = 200
        body: Any
        if path == "/installation/repositories":
            repositories = (
                [{"full_name": "example/project", "archived": self.repository_archived}]
                if self.repository_visible
                else []
            )
            if self.empty_tail_repository:
                repositories.append({"full_name": "example/zempty", "archived": False})
            body = {
                "total_count": len(repositories),
                "repositories": repositories,
            }
            headers["ETag"] = '"repos"'
        elif path.endswith("/pulls"):
            count = 0 if "/example/zempty/" in path else self.count
            page = int(request.url.params["page"])
            start = (page - 1) * 100 + 1
            end = min(start + 100, count + 1)
            body = [
                {
                    "number": n,
                    "head": {"sha": f"{n:040x}"},
                    "base": {"sha": self.bases.get(n, self.base)},
                }
                for n in range(start, end)
            ]
            headers["ETag"] = f'"pulls-{self.base}-{page}"'
            if self.reverse_pulls:
                body.reverse()
            if end <= count:
                headers["Link"] = f'<{request.url.copy_set_param("page", page + 1)}>; rel="next"'
            elif page > 1:
                headers["Link"] = f'<{request.url.copy_set_param("page", page - 1)}>; rel="prev"'
        elif "/contents/" in path:
            ref = request.url.params["ref"]
            assert ref in {self.base, *self.bases.values()}
            status, body = self.policies.get(ref, (self.policy_status, self.policy_body))
        elif path.endswith("/check-runs"):
            head = path.split("/")[-2]
            assert request.url.params["check_name"] == "Extra CODEOWNERS / approval"
            assert request.url.params["app_id"] == "7"
            body = {
                "total_count": int(head in self.managed),
                "check_runs": [{"id": 123}] if head in self.managed else [],
            }
            headers["ETag"] = f'"check-{head}-{int(head in self.managed)}"'
            if self.inject_direct_event:
                assert self.store is not None
                self.store.enqueue_shared_head_trigger(
                    JobRequest(17, "example/project", int(head, 16), "pull_request.opened", head)
                )
                self.inject_direct_event = False
        else:
            raise AssertionError(f"unexpected request: {request.method} {path}")
        if headers.get("ETag") and request.headers.get("if-none-match") == headers["ETag"]:
            status = 304
        else:
            self.remaining -= 1
        headers.update(
            {
                "x-ratelimit-resource": "core",
                "x-ratelimit-limit": str(self.limit),
                "x-ratelimit-remaining": str(self.remaining),
                "x-ratelimit-reset": str(self.reset),
            }
        )
        if status == 304:
            return httpx.Response(status, headers=headers)
        if isinstance(body, str):
            return httpx.Response(status, text=body, headers=headers)
        return httpx.Response(status, json=body, headers=headers)


def store_at(tmp_path: Path) -> QueueStore:
    url = f"sqlite:///{tmp_path / 'discovery.db'}"
    upgrade_database(url)
    store = QueueStore(url)
    store.initialize()
    return store


def reconciler_for(
    provider: DiscoveryProvider, store: QueueStore, private_key: str, owner: str
) -> tuple[Reconciler, GitHubClient]:
    github = GitHubClient(
        7,
        private_key,
        transport=httpx.MockTransport(provider.respond),
        recovery_budget=RecoveryApiBudget(store),
    )
    settings = Settings(
        _env_file=None, environment="test", worker_enabled=False, reconcile_enabled=False
    )
    return Reconciler(settings, github, store, owner), github


async def scan(reconciler: Reconciler, stop: asyncio.Event | None = None) -> ReconciliationOutcome:
    result = await reconciler.reconcile_once(stop)
    assert result is not None
    return result


@pytest.mark.asyncio
async def test_large_unenrolled_installation_revalidates_without_refilling_queue(
    tmp_path: Path, private_key: str
) -> None:
    provider = DiscoveryProvider(count=2500)
    store = store_at(tmp_path)
    clients: list[GitHubClient] = []
    try:
        for owner in ("replica-one", "replica-two"):
            reconciler, github = reconciler_for(provider, store, private_key, owner)
            clients.append(github)
            for cycle in range(2):
                before = provider.remaining
                result = await scan(reconciler)
                assert result.complete and result.queued == 0
                assert store.pending_count() == 0
                # Each cold replica fetches pages and check absence once.
                # A warm scan still contacts GitHub for every head/page, but
                # only its one absent-policy read consumes primary quota.
                assert before - provider.remaining == (2527 if cycle == 0 else 1)
            assert store.release_service_lease("open-pr-reconciler", owner)
        assert (
            provider.requests["/repos/example/project/contents/.github/extra-codeowners.toml"] == 4
        )
        assert sum(v for k, v in provider.requests.items() if k.endswith("/check-runs")) == 10000
        with store.session() as session:
            budget = session.get(InstallationApiBudget, 17)
            assert budget is not None and budget.remaining == provider.remaining
    finally:
        for github in clients:
            await github.close()
        store.close()


@pytest.mark.asyncio
async def test_cold_replicas_resume_inside_repository_across_quota_windows(
    tmp_path: Path, private_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    monkeypatch.setattr("extra_codeowners.api_budget.utcnow", lambda: now)
    monkeypatch.setattr("extra_codeowners.database.utcnow", lambda: now)
    provider = DiscoveryProvider(count=140)
    provider.limit = 60
    provider.empty_tail_repository = True
    provider.reverse_pulls = True
    store = store_at(tmp_path)
    previous_number = 0
    try:
        for cycle in range(8):
            owner = f"cold-replica-{cycle}"
            provider.remaining = provider.limit
            provider.reset = int((now + timedelta(hours=1)).timestamp())
            reconciler, github = reconciler_for(provider, store, private_key, owner)
            try:
                result = await scan(reconciler)
            finally:
                await github.close()
            assert store.release_service_lease("open-pr-reconciler", owner)
            assert result.queued == 0 and store.pending_count() == 0
            budget = RecoveryApiBudget(store)
            if result.complete:
                assert cycle > 0
                assert budget.repository_cursor(17) == "example/zempty"
                assert budget.pull_cursor(17) == ("", 0)
                break
            assert result.deferred
            repository, number = budget.pull_cursor(17)
            assert repository == "example/project"
            assert number > previous_number
            previous_number = number
            now += timedelta(hours=1, seconds=1)
        else:
            pytest.fail("cold scans repeated a prefix instead of finishing the repository")
        checks = {
            path: count for path, count in provider.requests.items() if path.endswith("/check-runs")
        }
        assert len(checks) == 140
        assert set(checks.values()) == {1}
        assert provider.requests["/repos/example/zempty/pulls"] == 1
    finally:
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["removed", "archived", "suspended"])
async def test_ineligible_partial_repository_clears_progress_before_access_returns(
    tmp_path: Path, private_key: str, change: str
) -> None:
    provider = DiscoveryProvider()
    store = store_at(tmp_path)
    owner = "worker"
    assert store.acquire_service_lease("open-pr-reconciler", owner, 600)
    budget = RecoveryApiBudget(store)
    budget.advance_pull(17, "example/project", 3, owner)
    provider.repository_visible = change != "removed"
    provider.repository_archived = change == "archived"
    provider.installation_suspended = change == "suspended"
    reconciler, github = reconciler_for(provider, store, private_key, owner)
    try:
        assert (await scan(reconciler)).complete
        assert budget.pull_cursor(17) == ("", 0)
    finally:
        await github.close()
    provider.repository_visible = True
    provider.repository_archived = False
    provider.installation_suspended = False
    # A fresh client prevents this fixture's deliberately fixed ETag from
    # masking the membership change. Production GitHub changes that validator.
    reconciler, github = reconciler_for(provider, store, private_key, owner)
    try:
        assert (await scan(reconciler)).complete
        assert sum(v for k, v in provider.requests.items() if k.endswith("/check-runs")) == 3
    finally:
        await github.close()
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 403, 503])
async def test_policy_appearing_or_unreadable_is_not_skipped(
    tmp_path: Path, private_key: str, status: int
) -> None:
    provider = DiscoveryProvider()
    store = store_at(tmp_path)
    reconciler, github = reconciler_for(provider, store, private_key, "worker")
    try:
        assert (await scan(reconciler)).queued == 0
        provider.base = "c" * 40
        provider.policy_status = status
        # Even malformed or disabled policy needs ordinary evaluation.
        provider.policy_body = "enabled = false"
        result = await scan(reconciler)
        assert result.complete and result.queued == 3
    finally:
        await github.close()
        store.close()


@pytest.mark.asyncio
async def test_removed_policy_cannot_hide_existing_managed_check(
    tmp_path: Path, private_key: str
) -> None:
    provider = DiscoveryProvider()
    store = store_at(tmp_path)
    reconciler, github = reconciler_for(provider, store, private_key, "worker")
    try:
        assert (await scan(reconciler)).queued == 0
        provider.managed.add(f"{1:040x}")
        result = await scan(reconciler)
        assert result.complete and result.queued == 1
        invalidation = store.claim_shared_head_invalidation("head-worker", 60)
        assert invalidation is not None and invalidation.head_sha == f"{1:040x}"
    finally:
        await github.close()
        store.close()


@pytest.mark.asyncio
async def test_skip_does_not_remove_a_direct_event_accepted_during_discovery(
    tmp_path: Path, private_key: str
) -> None:
    provider = DiscoveryProvider(count=1)
    store = store_at(tmp_path)
    provider.store = store
    provider.inject_direct_event = True
    reconciler, github = reconciler_for(provider, store, private_key, "worker")
    try:
        assert (await scan(reconciler)).queued == 0
        # One evaluation and its separate exact-head invalidation remain.
        assert store.pending_count() == 2
        invalidation = store.claim_shared_head_invalidation("head-worker", 60)
        assert invalidation is not None and invalidation.work_class == "interactive"
    finally:
        await github.close()
        store.close()


@pytest.mark.asyncio
async def test_policy_is_read_per_distinct_pr_base_not_default_branch(
    tmp_path: Path, private_key: str
) -> None:
    provider = DiscoveryProvider(count=4)
    provider.bases = {3: "c" * 40, 4: "c" * 40}
    provider.policies["c" * 40] = (200, "invalid TOML still needs evaluation")
    store = store_at(tmp_path)
    reconciler, github = reconciler_for(provider, store, private_key, "worker")
    try:
        result = await scan(reconciler)
        assert result.complete and result.queued == 2
        assert (
            provider.requests["/repos/example/project/contents/.github/extra-codeowners.toml"] == 2
        )
        assert sum(v for k, v in provider.requests.items() if k.endswith("/check-runs")) == 2
    finally:
        await github.close()
        store.close()


@pytest.mark.asyncio
async def test_stop_during_policy_read_does_not_queue_or_report_complete(
    tmp_path: Path, private_key: str
) -> None:
    provider = DiscoveryProvider()
    store = store_at(tmp_path)
    reconciler, github = reconciler_for(provider, store, private_key, "worker")
    stop = asyncio.Event()
    original = provider.respond

    def respond(request: httpx.Request) -> httpx.Response:
        if "/contents/" in request.url.path:
            stop.set()
        return original(request)

    await github.close()
    github = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    reconciler.github = github
    try:
        result = await scan(reconciler, stop)
        assert result.stopped and not result.complete and result.queued == 0
        assert not any(k.endswith("/check-runs") for k in provider.requests)
    finally:
        await github.close()
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [{}, [], {"total_count": False, "check_runs": []}, {"total_count": 0, "check_runs": None}],
)
async def test_check_absence_requires_a_valid_response(private_key: str, payload: Any) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "test-token",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
            )
        return httpx.Response(200, json=payload)

    github = GitHubClient(7, private_key, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(GitHubError):
            await github.has_reconciliation_check(17, "example/project", "a" * 40, "approval")
    finally:
        await github.close()
