import hashlib
import hmac
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

import extra_codeowners.app as app_module
from extra_codeowners.database import QueueStore
from extra_codeowners.manifest import ManifestService
from extra_codeowners.migrations import upgrade_database
from extra_codeowners.settings import Settings

HEAD = "a" * 40


class StubGitHub:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.fail_next_check = False
        self.head_sha = HEAD

    async def close(self) -> None:
        pass

    async def list_installations(self) -> list[dict[str, Any]]:
        return []

    async def get_pull(self, installation_id: int, repository: str, number: int) -> dict[str, Any]:
        return {
            "number": number,
            "state": "open",
            "html_url": f"https://github.com/{repository}/pull/{number}",
            "head": {"sha": self.head_sha},
            "base": {"sha": "base123", "ref": "main"},
            "labels": [],
        }

    async def get_file_text(
        self,
        installation_id: int,
        repository: str,
        path: str,
        *,
        ref: str | None = None,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        return "schema_version = 1\nenabled = false\n"

    async def upsert_check_run(self, *args: Any, **values: Any) -> int:
        if self.fail_next_check:
            self.fail_next_check = False
            raise RuntimeError("temporary GitHub failure")
        self.checks.append(values)
        return 99

    async def has_check_run(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
    ) -> bool:
        return bool(self.checks)

    async def existing_check_run_id(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
    ) -> int | None:
        return 99 if self.checks else None

    async def reset_check_run(
        self,
        installation_id: int,
        repository: str,
        check_run_id: int,
        check_name: str,
        **values: Any,
    ) -> None:
        if self.fail_next_check:
            self.fail_next_check = False
            raise RuntimeError("temporary GitHub failure")
        self.checks.append({"status": "in_progress", **values})


def configured_settings() -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        github_app_id=123,
        github_private_key="not-used-by-injected-client",
        github_webhook_secret="webhook-secret",
        worker_enabled=False,
        reconcile_enabled=False,
    )


def migrated_store(database_url: str) -> QueueStore:
    upgrade_database(database_url)
    store = QueueStore(database_url)
    store.initialize()
    return store


def webhook_headers(body: bytes, delivery: str = "delivery-1") -> dict[str, str]:
    digest = hmac.new(b"webhook-secret", body, hashlib.sha256).hexdigest()
    return {
        "X-Hub-Signature-256": f"sha256={digest}",
        "X-GitHub-Delivery": delivery,
        "X-GitHub-Event": "pull_request",
        "Content-Type": "application/json",
    }


def test_health_and_signed_webhook_ingestion(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    github = StubGitHub()
    app = app_module.create_app(configured_settings(), github=github, store=store)  # type: ignore[arg-type]
    payload: dict[str, Any] = {
        "action": "opened",
        "installation": {"id": 10},
        "repository": {"full_name": "example/project"},
        "number": 7,
        "pull_request": {"number": 7, "state": "open", "head": {"sha": HEAD}},
    }
    body = json.dumps(payload).encode()

    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").json()["status"] == "ready"
        first = client.post("/webhooks/github", content=body, headers=webhook_headers(body))
        duplicate = client.post("/webhooks/github", content=body, headers=webhook_headers(body))

    assert first.status_code == 202
    assert first.json() == {"accepted": True, "queued": True}
    assert duplicate.json() == {"accepted": False, "queued": False}
    assert store.pending_count() == 2
    assert [check["status"] for check in github.checks] == ["in_progress"]


def test_new_direct_delivery_enters_fast_invalidation_without_a_second_database_read(
    tmp_path: Path,
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'accepted-fast-path.db'}")
    github = StubGitHub()
    app = app_module.create_app(configured_settings(), github=github, store=store)  # type: ignore[arg-type]
    payload: dict[str, Any] = {
        "action": "opened",
        "installation": {"id": 10},
        "repository": {"full_name": "example/project"},
        "number": 7,
        "pull_request": {"number": 7, "state": "open", "head": {"sha": HEAD}},
    }
    body = json.dumps(payload).encode()

    def unexpected_delivery_read(delivery_id: str) -> bool:
        raise AssertionError(f"accepted delivery {delivery_id} was read again")

    store.delivery_needs_invalidation = unexpected_delivery_read  # type: ignore[method-assign]

    with TestClient(app) as client:
        response = client.post("/webhooks/github", content=body, headers=webhook_headers(body))

    assert response.status_code == 202
    assert response.json() == {"accepted": True, "queued": True}
    assert [check["status"] for check in github.checks] == ["in_progress"]


def test_webhook_fast_path_failure_is_durable_and_replayable(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    github = StubGitHub()
    github.fail_next_check = True
    app = app_module.create_app(configured_settings(), github=github, store=store)  # type: ignore[arg-type]
    body = json.dumps(
        {
            "action": "submitted",
            "installation": {"id": 10},
            "repository": {"full_name": "example/project"},
            "pull_request": {
                "number": 7,
                "state": "open",
                "head": {"sha": HEAD},
            },
            "review": {"state": "approved"},
        }
    ).encode()
    headers = webhook_headers(body, "delivery-retry")
    headers["X-GitHub-Event"] = "pull_request_review"

    with TestClient(app) as client:
        failed = client.post("/webhooks/github", content=body, headers=headers)
        replay = client.post("/webhooks/github", content=body, headers=headers)

    assert failed.status_code == 202
    assert failed.json() == {"accepted": True, "queued": True}
    assert replay.status_code == 202
    assert replay.json() == {"accepted": False, "queued": True}
    assert store.delivery_needs_invalidation("delivery-retry") is False
    assert store.pending_count() == 2
    assert [check["status"] for check in github.checks] == ["in_progress"]


def test_stale_duplicate_reports_separately_queued_live_head(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'stale-duplicate.db'}")
    github = StubGitHub()
    github.fail_next_check = True
    app = app_module.create_app(configured_settings(), github=github, store=store)  # type: ignore[arg-type]
    body = json.dumps(
        {
            "action": "synchronize",
            "installation": {"id": 10},
            "repository": {"full_name": "example/project"},
            "pull_request": {
                "number": 7,
                "state": "open",
                "head": {"sha": HEAD},
            },
        }
    ).encode()
    headers = webhook_headers(body, "stale-duplicate")

    with TestClient(app) as client:
        failed = client.post("/webhooks/github", content=body, headers=headers)
        accepted_head = store.claim_shared_head_invalidation("head-worker", 60)
        assert accepted_head is not None
        assert store.complete_shared_head_invalidation(accepted_head)
        assert store.delivery_needs_invalidation("stale-duplicate") is True
        github.head_sha = "b" * 40
        replay = client.post("/webhooks/github", content=body, headers=headers)

    assert failed.json() == {"accepted": True, "queued": True}
    assert replay.json() == {"accepted": False, "queued": True}
    assert store.shared_head_generation(10, "example/project", HEAD) == 1
    assert store.shared_head_generation(10, "example/project", "b" * 40) == 1
    claimed = store.claim("observer", 60)
    assert claimed is not None
    assert claimed.head_sha_hint == "b" * 40
    assert claimed.shared_head_generation == 1
    assert store.pending_shared_head_invalidation_count() == 1


def test_liveness_fails_when_enabled_worker_task_has_died(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    runtime = configured_settings().model_copy(
        update={"worker_enabled": True, "worker_poll_seconds": 0.05}
    )
    app = app_module.create_app(runtime, github=StubGitHub(), store=store)  # type: ignore[arg-type]

    class DeadTask:
        @staticmethod
        def done() -> bool:
            return True

    with TestClient(app) as client:
        app.state.worker_task = DeadTask()
        response = client.get("/health/live")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_alive",
        "worker": False,
        "reconciler": True,
    }


def test_liveness_fails_when_enabled_reconciler_task_has_died(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    runtime = configured_settings().model_copy(update={"reconcile_enabled": True})
    app = app_module.create_app(runtime, github=StubGitHub(), store=store)  # type: ignore[arg-type]

    class DeadTask:
        @staticmethod
        def done() -> bool:
            return True

    with TestClient(app) as client:
        app.state.reconciler_task = DeadTask()
        response = client.get("/health/live")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_alive",
        "worker": True,
        "reconciler": False,
    }


def test_org_config_repository_webhook_is_acknowledged_but_not_queued(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    app = app_module.create_app(configured_settings(), github=StubGitHub(), store=store)  # type: ignore[arg-type]
    payload: dict[str, Any] = {
        "action": "opened",
        "installation": {"id": 10},
        "repository": {"full_name": "example/.github"},
        "number": 7,
        "pull_request": {"number": 7, "state": "open", "head": {"sha": HEAD}},
    }
    body = json.dumps(payload).encode()

    with TestClient(app) as client:
        response = client.post("/webhooks/github", content=body, headers=webhook_headers(body))

    assert response.json() == {"accepted": True, "queued": False}
    assert store.pending_count() == 0


def test_authority_webhook_is_durably_queued_without_pr_fast_path(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-app.db'}")
    github = StubGitHub()
    app = app_module.create_app(configured_settings(), github=github, store=store)  # type: ignore[arg-type]
    payload: dict[str, Any] = {
        "ref": "refs/heads/main",
        "forced": False,
        "installation": {"id": 10},
        "repository": {"full_name": "Example/Project", "default_branch": "main"},
        "commits": [{"added": [], "modified": ["README.md"], "removed": []}],
        "distinct_size": 1,
    }
    body = json.dumps(payload).encode()
    headers = webhook_headers(body, "authority-delivery")
    headers["X-GitHub-Event"] = "push"

    with TestClient(app) as client:
        response = client.post("/webhooks/github", content=body, headers=headers)

    assert response.status_code == 202
    assert response.json() == {"accepted": True, "queued": True}
    authority = store.claim_authority("observer", 60)
    assert authority is not None
    assert authority.repository_full_name == "example/project"
    assert authority.base_ref == "main"
    assert github.checks == []


def test_authority_guard_failure_returns_retryable_service_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'authority-failure.db'}")
    monkeypatch.setattr(store, "acquire_authority_guard", lambda *args, **kwargs: None)
    app = app_module.create_app(configured_settings(), github=StubGitHub(), store=store)  # type: ignore[arg-type]
    payload: dict[str, Any] = {
        "action": "member_removed",
        "installation": {"id": 10},
        "organization": {"login": "example"},
    }
    body = json.dumps(payload).encode()
    headers = webhook_headers(body, "authority-failure")
    headers["X-GitHub-Event"] = "organization"

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/webhooks/github", content=body, headers=headers)

    assert response.status_code == 503
    assert "redeliver" in response.json()["detail"]
    assert store.pending_count() == 0


def test_invalid_signature_returns_unauthorized(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    app = app_module.create_app(configured_settings(), github=StubGitHub(), store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        response = client.post(
            "/webhooks/github",
            content=b"{}",
            headers={
                "X-Hub-Signature-256": "sha256=" + "0" * 64,
                "X-GitHub-Delivery": "delivery-1",
                "X-GitHub-Event": "ping",
            },
        )

    assert response.status_code == 401


def test_streamed_webhook_is_bounded_without_content_length(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(app_module, "MAX_WEBHOOK_BYTES", 4)
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    app = app_module.create_app(configured_settings(), github=StubGitHub(), store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        response = client.post(
            "/webhooks/github",
            content=(chunk for chunk in (b"123", b"45")),
            headers={
                "X-Hub-Signature-256": "sha256=" + "0" * 64,
                "X-GitHub-Delivery": "delivery-1",
                "X-GitHub-Event": "ping",
            },
        )

    assert response.status_code == 413


def test_setup_routes_are_hidden_when_disabled(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    app = app_module.create_app(configured_settings(), github=StubGitHub(), store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        assert client.get("/setup").status_code == 404
        assert client.get("/setup/complete").status_code == 404


def test_setup_manifest_flow_is_no_store_and_escapes_credentials(
    tmp_path: Path, monkeypatch: Any
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    settings = Settings(
        _env_file=None,
        environment="test",
        github_app_id=123,
        github_private_key="not-used-by-injected-client",
        github_webhook_secret="webhook-secret",
        worker_enabled=False,
        reconcile_enabled=False,
        setup_enabled=True,
        setup_state_secret="setup-state-secret-at-least-32-bytes-long",
        public_url="https://extra-codeowners.example.com",
    )
    monkeypatch.setattr(
        ManifestService,
        "exchange",
        AsyncMock(return_value={"id": 1, "pem": "<private>", "webhook_secret": "secret"}),
    )
    app = app_module.create_app(settings, github=StubGitHub(), store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        setup = client.get("/setup?organization=example")
        callback = client.get("/setup/callback?code=code&state=state")
        complete = client.get("/setup/complete")

    assert setup.status_code == 200
    assert setup.headers["cache-control"].startswith("no-store")
    assert "organizations/example/settings/apps/new" in setup.text
    assert callback.status_code == 200
    assert "&lt;private&gt;" in callback.text
    assert complete.status_code == 200


def test_readiness_fails_without_github_credentials(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'app.db'}")
    settings = Settings(
        _env_file=None,
        environment="test",
        worker_enabled=False,
        reconcile_enabled=False,
    )
    app = app_module.create_app(settings, github=StubGitHub(), store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["github_credentials"] is False
