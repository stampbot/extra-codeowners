import asyncio
import hashlib
import hmac
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import extra_codeowners.app as app_module
from extra_codeowners import __version__
from extra_codeowners.build_identity import BuildIdentity
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

    async def verify_app_identity(
        self,
        *,
        stop: asyncio.Event | None = None,
    ) -> None:
        del stop

    async def list_installations(
        self,
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        del stop
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


class SequencedIdentityGitHub(StubGitHub):
    def __init__(
        self,
        outcomes: list[Exception | None],
        *,
        fallback: Exception | None = None,
    ) -> None:
        super().__init__()
        self.identity_outcomes = outcomes
        self.identity_fallback = fallback
        self.identity_attempts = 0

    async def verify_app_identity(
        self,
        *,
        stop: asyncio.Event | None = None,
    ) -> None:
        del stop
        self.identity_attempts += 1
        index = self.identity_attempts - 1
        outcome = (
            self.identity_outcomes[index]
            if index < len(self.identity_outcomes)
            else self.identity_fallback
        )
        if outcome is not None:
            raise outcome


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


@pytest.mark.asyncio
async def test_lifespan_closes_an_owned_store_when_initialization_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instances: list[Any] = []

    class FailingStore:
        def __init__(self, database_url: str) -> None:
            del database_url
            self.closed = False
            self.engine = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))
            instances.append(self)

        def initialize(self) -> None:
            raise RuntimeError("database initialization failed")

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(app_module, "QueueStore", FailingStore)
    app = app_module.create_app(configured_settings(), github=StubGitHub())  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="database initialization failed"):
        async with app.router.lifespan_context(app):
            raise AssertionError("lifespan yielded after failed initialization")

    assert len(instances) == 1
    assert instances[0].closed is True


@pytest.mark.asyncio
async def test_lifespan_startup_failure_stops_tasks_and_closes_owned_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup: list[str] = []
    stores: list[Any] = []
    github_clients: list[Any] = []
    manifests: list[Any] = []

    class OwnedStore:
        def __init__(self, database_url: str) -> None:
            del database_url
            self.engine = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))
            stores.append(self)

        def initialize(self) -> None:
            pass

        def close(self) -> None:
            cleanup.append("store")

    class OwnedGitHub:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs
            github_clients.append(self)

        async def verify_app_identity(
            self,
            *,
            stop: asyncio.Event | None = None,
        ) -> None:
            del stop

        async def close(self) -> None:
            cleanup.append("github")

    class OwnedManifest:
        def __init__(self, settings: Settings) -> None:
            del settings
            manifests.append(self)

        async def close(self) -> None:
            cleanup.append("manifest")

    class FailingEvaluationService:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs
            raise RuntimeError("evaluation service startup failed")

    monkeypatch.setattr(app_module, "QueueStore", OwnedStore)
    monkeypatch.setattr(app_module, "GitHubClient", OwnedGitHub)
    monkeypatch.setattr(app_module, "ManifestService", OwnedManifest)
    monkeypatch.setattr(app_module, "EvaluationService", FailingEvaluationService)
    settings = Settings(
        _env_file=None,
        environment="test",
        github_app_id=123,
        github_private_key="private-key",
        github_webhook_secret="webhook-secret",
        worker_enabled=False,
        reconcile_enabled=False,
        setup_enabled=True,
        setup_state_secret="setup-state-secret-at-least-32-bytes-long",
        public_url="https://extra-codeowners.example.com",
    )
    app = app_module.create_app(settings)

    with pytest.raises(RuntimeError, match="evaluation service startup failed"):
        async with app.router.lifespan_context(app):
            raise AssertionError("lifespan yielded after failed startup")

    assert len(stores) == len(github_clients) == len(manifests) == 1
    assert app.state.stop.is_set()
    assert app.state.github_identity_task.done()
    assert cleanup == ["manifest", "github", "store"]


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
        index = client.get("/")
        live = client.get("/health/live")
        ready = client.get("/health/ready")
        metrics = client.get("/metrics")
        first = client.post("/webhooks/github", content=body, headers=webhook_headers(body))
        duplicate = client.post("/webhooks/github", content=body, headers=webhook_headers(body))

    assert index.status_code == 200
    assert index.headers["cache-control"] == "no-store, max-age=0"
    assert live.status_code == 200
    assert live.headers["cache-control"] == "no-store, max-age=0"
    assert live.json() == {
        "status": "alive",
        "worker_enabled": False,
        "reconciler_enabled": False,
        "worker": True,
        "reconciler": True,
    }
    assert ready.status_code == 200
    assert ready.headers["cache-control"] == "no-store, max-age=0"
    assert ready.json() == {
        "status": "ready",
        "github_credentials": True,
        "database": True,
        "worker_enabled": False,
        "reconciler_enabled": False,
        "worker": True,
        "reconciler": True,
    }
    assert metrics.status_code == 200
    assert metrics.headers["cache-control"] == "no-store, max-age=0"
    assert first.status_code == 202
    assert first.json() == {"accepted": True, "queued": True}
    assert duplicate.json() == {"accepted": False, "queued": False}
    assert store.pending_count() == 2
    assert [check["status"] for check in github.checks] == ["in_progress"]


def test_health_openapi_publishes_success_and_failure_response_contracts() -> None:
    schema = app_module.create_app(configured_settings()).openapi()
    cases = {
        "/health/live": (
            "LivenessResponse",
            {
                "status",
                "worker_enabled",
                "reconciler_enabled",
                "worker",
                "reconciler",
            },
        ),
        "/health/ready": (
            "ReadinessResponse",
            {
                "status",
                "github_credentials",
                "database",
                "worker_enabled",
                "reconciler_enabled",
                "worker",
                "reconciler",
            },
        ),
    }

    for path, (model_name, fields) in cases.items():
        responses = schema["paths"][path]["get"]["responses"]
        expected_reference = f"#/components/schemas/{model_name}"
        for status_code in ("200", "503"):
            assert responses[status_code]["content"]["application/json"]["schema"] == {
                "$ref": expected_reference
            }
        model = schema["components"]["schemas"][model_name]
        properties = model["properties"]
        assert set(properties) == fields
        assert all(definition.get("description") for definition in properties.values())
        assert set(model["required"]) == fields
        assert model["additionalProperties"] is False


def test_runtime_identity_binds_effective_service_and_baked_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build_identity = BuildIdentity(
        source_revision=HEAD,
        selection_record_sha256="b" * 64,
        wheel_filename="extra_codeowners-0.1.0-py3-none-any.whl",
        wheel_sha256="c" * 64,
        sdist_filename="extra_codeowners-0.1.0.tar.gz",
        sdist_sha256="d" * 64,
    )
    monkeypatch.setattr(app_module, "load_build_identity", lambda: build_identity)
    store = migrated_store(f"sqlite:///{tmp_path / 'runtime-identity.db'}")
    runtime = configured_settings().model_copy(
        update={
            "database_url": "postgresql+psycopg://ignored.example/ignored",
            "check_name": "Beta approval",
            "policy_path": ".github/beta-policy.toml",
            "org_config_repository": "shared-policy",
        }
    )
    app = app_module.create_app(runtime, github=StubGitHub(), store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        response = client.get("/api/runtime-identity")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.json() == {
        "schema_version": 1,
        "environment": "test",
        "github_api_url": "https://api.github.com/",
        "github_app_id": 123,
        "database_backend": "sqlite",
        "check_name": "Beta approval",
        "policy_path": ".github/beta-policy.toml",
        "organization_policy_repository_name": "shared-policy",
        "application_version": __version__,
        "build_revision": HEAD,
    }


def test_runtime_identity_reports_missing_container_build_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "load_build_identity", lambda: None)
    store = migrated_store(f"sqlite:///{tmp_path / 'source-installation.db'}")
    app = app_module.create_app(
        configured_settings(),
        github=StubGitHub(),  # type: ignore[arg-type]
        store=store,
    )

    with TestClient(app) as client:
        response = client.get("/api/runtime-identity")

    assert response.status_code == 200
    assert response.json()["build_revision"] is None


def test_runtime_identity_openapi_contract_is_explicit() -> None:
    schema = app_module.create_app(configured_settings()).openapi()
    response = schema["paths"]["/api/runtime-identity"]["get"]["responses"]["200"]
    assert response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/RuntimeIdentityResponse"
    }
    model = schema["components"]["schemas"]["RuntimeIdentityResponse"]
    fields = {
        "schema_version",
        "environment",
        "github_api_url",
        "github_app_id",
        "database_backend",
        "check_name",
        "policy_path",
        "organization_policy_repository_name",
        "application_version",
        "build_revision",
    }
    assert set(model["properties"]) == fields
    assert all(definition.get("description") for definition in model["properties"].values())
    assert set(model["required"]) == fields - {"schema_version"}
    assert model["additionalProperties"] is False


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
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.json() == {
        "status": "not_alive",
        "worker_enabled": True,
        "reconciler_enabled": False,
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
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.json() == {
        "status": "not_alive",
        "worker_enabled": False,
        "reconciler_enabled": True,
        "worker": True,
        "reconciler": False,
    }


def test_readiness_reports_enabled_background_tasks(tmp_path: Path) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'enabled-task-health.db'}")
    runtime = configured_settings().model_copy(
        update={
            "worker_enabled": True,
            "worker_poll_seconds": 0.05,
            "reconcile_enabled": True,
        }
    )
    app = app_module.create_app(runtime, github=StubGitHub(), store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "github_credentials": True,
        "database": True,
        "worker_enabled": True,
        "reconciler_enabled": True,
        "worker": True,
        "reconciler": True,
    }


def test_readiness_fails_closed_when_the_initial_app_identity_probe_fails(
    tmp_path: Path,
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'identity-unavailable.db'}")
    github = SequencedIdentityGitHub(
        [RuntimeError("GitHub is unavailable")],
        fallback=RuntimeError("GitHub is unavailable"),
    )
    app = app_module.create_app(
        configured_settings(),
        github=github,  # type: ignore[arg-type]
        store=store,
    )

    with TestClient(app) as client:
        ready = client.get("/health/ready")
        live = client.get("/health/live")

    assert ready.status_code == 503
    assert ready.headers["cache-control"] == "no-store, max-age=0"
    assert ready.json()["github_credentials"] is False
    assert live.status_code == 200
    assert live.headers["cache-control"] == "no-store, max-age=0"


def test_readiness_recovers_after_a_background_app_identity_probe(
    tmp_path: Path,
) -> None:
    class ControlledRecoveryGitHub(StubGitHub):
        def __init__(self) -> None:
            super().__init__()
            self.identity_attempts = 0
            self.second_attempt_started = threading.Event()
            self.allow_second_attempt = threading.Event()

        async def verify_app_identity(
            self,
            *,
            stop: asyncio.Event | None = None,
        ) -> None:
            del stop
            self.identity_attempts += 1
            if self.identity_attempts == 1:
                raise RuntimeError("temporary failure")
            if self.identity_attempts == 2:
                self.second_attempt_started.set()
                await asyncio.to_thread(self.allow_second_attempt.wait)

    store = migrated_store(f"sqlite:///{tmp_path / 'identity-recovers.db'}")
    github = ControlledRecoveryGitHub()
    runtime = configured_settings().model_copy(
        update={
            "github_identity_probe_interval_seconds": 0.02,
            "github_identity_freshness_seconds": 0.2,
        }
    )
    app = app_module.create_app(runtime, github=github, store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        try:
            assert github.second_attempt_started.wait(timeout=1)
            assert client.get("/health/ready").status_code == 503
            github.allow_second_attempt.set()
            deadline = time.monotonic() + 1
            response = client.get("/health/ready")
            while response.status_code != 200 and time.monotonic() < deadline:
                time.sleep(0.01)
                response = client.get("/health/ready")
        finally:
            github.allow_second_attempt.set()

    assert github.identity_attempts >= 2
    assert response.status_code == 200
    assert response.json()["github_credentials"] is True


def test_readiness_expires_a_stale_app_identity_proof_without_failing_liveness(
    tmp_path: Path,
) -> None:
    class RevokedIdentityGitHub(SequencedIdentityGitHub):
        def __init__(self) -> None:
            super().__init__([None], fallback=RuntimeError("credentials revoked"))
            self.revoked_attempt_finished = threading.Event()

        async def verify_app_identity(
            self,
            *,
            stop: asyncio.Event | None = None,
        ) -> None:
            try:
                await super().verify_app_identity(stop=stop)
            finally:
                if self.identity_attempts >= 2:
                    self.revoked_attempt_finished.set()

    store = migrated_store(f"sqlite:///{tmp_path / 'identity-stale.db'}")
    github = RevokedIdentityGitHub()
    runtime = configured_settings().model_copy(
        update={
            "github_identity_probe_interval_seconds": 0.02,
            "github_identity_freshness_seconds": 10,
        }
    )
    app = app_module.create_app(runtime, github=github, store=store)  # type: ignore[arg-type]

    with TestClient(app) as client:
        assert client.get("/health/ready").status_code == 200
        assert github.revoked_attempt_finished.wait(timeout=1)
        assert client.get("/health/ready").status_code == 200
        identity_probe = app.state.github_identity_probe
        identity_probe._last_success_monotonic = (
            time.monotonic() - runtime.github_identity_freshness_seconds - 1
        )
        ready = client.get("/health/ready")
        live = client.get("/health/live")

    assert github.identity_attempts >= 2
    assert ready.status_code == 503
    assert ready.headers["cache-control"] == "no-store, max-age=0"
    assert ready.json()["github_credentials"] is False
    assert live.status_code == 200


@pytest.mark.asyncio
async def test_lifespan_shutdown_stops_reconciliation_before_the_next_api_call(
    tmp_path: Path,
) -> None:
    class StoppingGitHub(StubGitHub):
        def __init__(self) -> None:
            super().__init__()
            self.installation_scan_started = asyncio.Event()
            self.repository_calls = 0

        async def list_installations(
            self,
            *,
            stop: asyncio.Event | None = None,
        ) -> list[dict[str, Any]]:
            assert stop is not None
            self.installation_scan_started.set()
            await stop.wait()
            return [{"id": 2, "suspended_at": None}]

        async def list_installation_repositories(
            self,
            installation_id: int,
            *,
            stop: asyncio.Event | None = None,
        ) -> list[dict[str, Any]]:
            del installation_id, stop
            self.repository_calls += 1
            return []

    store = migrated_store(f"sqlite:///{tmp_path / 'reconciliation-shutdown.db'}")
    github = StoppingGitHub()
    runtime = configured_settings().model_copy(update={"reconcile_enabled": True})
    app = app_module.create_app(runtime, github=github, store=store)  # type: ignore[arg-type]

    async def exercise_lifespan() -> None:
        async with app.router.lifespan_context(app):
            await asyncio.wait_for(github.installation_scan_started.wait(), timeout=0.5)

    await asyncio.wait_for(exercise_lifespan(), timeout=1)

    assert github.repository_calls == 0
    assert store.pending_count() == 0


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
    )
    app = app_module.create_app(settings, store=store)

    with TestClient(app) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.headers["cache-control"] == "no-store, max-age=0"
    assert live.json() == {
        "status": "alive",
        "worker_enabled": True,
        "reconciler_enabled": True,
        "worker": True,
        "reconciler": True,
    }
    assert ready.status_code == 503
    assert ready.headers["cache-control"] == "no-store, max-age=0"
    assert ready.json() == {
        "status": "not_ready",
        "github_credentials": False,
        "database": True,
        "worker_enabled": True,
        "reconciler_enabled": True,
        "worker": False,
        "reconciler": False,
    }


def test_authenticated_client_does_not_replace_missing_webhook_credentials(
    tmp_path: Path,
) -> None:
    store = migrated_store(f"sqlite:///{tmp_path / 'missing-webhook-credentials.db'}")
    settings = Settings(
        _env_file=None,
        environment="test",
        worker_enabled=False,
        reconcile_enabled=False,
    )
    app = app_module.create_app(
        settings,
        github=StubGitHub(),  # type: ignore[arg-type]
        store=store,
    )

    with TestClient(app) as client:
        ready = client.get("/health/ready")

    assert ready.status_code == 503
    assert ready.json()["github_credentials"] is False
