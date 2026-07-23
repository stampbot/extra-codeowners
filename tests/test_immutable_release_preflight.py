from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn, cast

import pytest
import yaml  # type: ignore[import-untyped]


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


preflight = load_script("immutable_release_preflight")

REPOSITORY_ID = 1_299_090_885
REPOSITORY = "stampbot/extra-codeowners"
WORKFLOW_PATH = ".github/workflows/release.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/tags/v0.1.0"
WORKFLOW_SHA = "a" * 40
RUN_ID = 998_877
RUN_ATTEMPT = 2
TOKEN = "test-token-never-print"
REQUEST_ID = "A1B2:3C4D:5E6F:7890"


def expected_identity(**changes: Any) -> Any:
    values = {
        "repository_id": REPOSITORY_ID,
        "repository": REPOSITORY,
        "workflow_path": WORKFLOW_PATH,
        "workflow_ref": WORKFLOW_REF,
        "workflow_sha": WORKFLOW_SHA,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
    }
    values.update(changes)
    return preflight.ExpectedIdentity(**values)


def record_value(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "api": {"version": preflight.API_VERSION},
        "immutable_releases": {
            "enabled": True,
            "enforced_by_owner": True,
        },
        "media_type": preflight.RECORD_MEDIA_TYPE,
        "repository": {
            "id": REPOSITORY_ID,
            "name": REPOSITORY,
        },
        "run": {
            "attempt": RUN_ATTEMPT,
            "id": RUN_ID,
        },
        "schema_version": preflight.SCHEMA_VERSION,
        "workflow": {
            "path": WORKFLOW_PATH,
            "ref": WORKFLOW_REF,
            "sha": WORKFLOW_SHA,
        },
    }
    value.update(changes)
    return value


def write_record(path: Path, value: object | None = None, *, raw: bytes | None = None) -> str:
    content = raw if raw is not None else preflight.canonical_json(value or record_value())
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


class FakeAPI:
    def __init__(self, *, enabled: bool = True, enforced_by_owner: bool = True) -> None:
        self.identities = [
            preflight.RepositoryIdentity(REPOSITORY_ID, REPOSITORY),
            preflight.RepositoryIdentity(REPOSITORY_ID, REPOSITORY),
        ]
        self.policy = preflight.ImmutableReleasePolicy(enabled, enforced_by_owner)
        self.events: list[str] = []

    def repository_identity(self) -> Any:
        self.events.append("repository")
        if self.identities:
            return self.identities.pop(0)
        return preflight.RepositoryIdentity(REPOSITORY_ID, REPOSITORY)

    def immutable_release_policy(self) -> Any:
        self.events.append("policy")
        return self.policy


def json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class FakeResponse:
    def __init__(
        self,
        status: int,
        value: object | None = None,
        *,
        raw: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        declared_length: int | str | None = None,
        read_error: BaseException | None = None,
    ) -> None:
        self.status = status
        self.body = raw if raw is not None else json_bytes(value)
        self.offset = 0
        self.closed = False
        self.read_error = read_error
        default_headers = {
            "Content-Length": str(len(self.body)),
            "Content-Type": "application/json; charset=utf-8",
            "X-GitHub-Request-Id": REQUEST_ID,
        }
        if headers:
            default_headers.update(headers)
        if declared_length is not None:
            default_headers["Content-Length"] = str(declared_length)
        self.headers = default_headers

    def getheader(self, name: str) -> str | None:
        lowered = name.lower()
        return next(
            (value for key, value in self.headers.items() if key.lower() == lowered),
            None,
        )

    def read(self, amount: int | None = None) -> bytes:
        if self.read_error is not None:
            raise self.read_error
        if amount is None:
            amount = len(self.body) - self.offset
        chunk = self.body[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


@dataclasses.dataclass(frozen=True)
class RequestRecord:
    host: str
    timeout: float
    method: str
    path: str
    body: bytes
    headers: Mapping[str, str]


class FakeTransport:
    def __init__(self, outcomes: Iterable[FakeResponse | BaseException]) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[RequestRecord] = []
        self.connections = 0
        self.closed_connections = 0

    def connection(self, host: str, *, timeout: float) -> Any:
        assert self.outcomes, "preflight adapter made an unplanned request"
        outcome = self.outcomes.pop(0)
        self.connections += 1
        owner = self

        class Connection:
            def request(
                self,
                method: str,
                path: str,
                body: bytes | None = None,
                headers: Mapping[str, str] | None = None,
            ) -> None:
                if isinstance(outcome, BaseException):
                    raise outcome
                owner.requests.append(
                    RequestRecord(
                        host=host,
                        timeout=timeout,
                        method=method,
                        path=path,
                        body=body or b"",
                        headers=dict(headers or {}),
                    )
                )

            def getresponse(self) -> FakeResponse:
                assert not isinstance(outcome, BaseException)
                return outcome

            def close(self) -> None:
                owner.closed_connections += 1

        return Connection()


@pytest.fixture
def install_transport(monkeypatch: pytest.MonkeyPatch) -> Any:
    def install(*outcomes: FakeResponse | BaseException) -> FakeTransport:
        transport = FakeTransport(outcomes)
        monkeypatch.setattr(preflight.http.client, "HTTPSConnection", transport.connection)
        return transport

    return install


@pytest.fixture
def api() -> Any:
    return preflight.GitHubImmutableReleasePreflightAPI(
        token=TOKEN,
        repository=REPOSITORY,
    )


def assert_common_headers(request: RequestRecord) -> None:
    assert request.headers == {
        "Accept": "application/vnd.github+json",
        "Accept-Encoding": "identity",
        "Authorization": f"Bearer {TOKEN}",
        "User-Agent": preflight.USER_AGENT,
        "X-GitHub-Api-Version": preflight.API_VERSION,
    }


def test_live_adapter_capture_binds_repository_around_policy_read(
    api: Any, install_transport: Any, tmp_path: Path
) -> None:
    transport = install_transport(
        FakeResponse(200, {"id": REPOSITORY_ID, "full_name": REPOSITORY}),
        FakeResponse(200, {"enabled": True, "enforced_by_owner": True}),
        FakeResponse(200, {"id": REPOSITORY_ID, "full_name": REPOSITORY}),
    )
    output = tmp_path / "immutable-release-preflight.json"

    digest = preflight.capture_record(
        api,
        output,
        expected=expected_identity(),
        require_owner_enforcement=True,
    )

    assert digest == hashlib.sha256(output.read_bytes()).hexdigest()
    assert output.read_bytes() == preflight.canonical_json(record_value())
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert [(item.method, item.path, item.body) for item in transport.requests] == [
        ("GET", "/repos/stampbot/extra-codeowners", b""),
        ("GET", "/repos/stampbot/extra-codeowners/immutable-releases", b""),
        ("GET", "/repos/stampbot/extra-codeowners", b""),
    ]
    assert transport.connections == transport.closed_connections == 3
    for request in transport.requests:
        assert request.host == "api.github.com"
        assert request.timeout == 30.0
        assert_common_headers(request)


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"token": ""}, "token"),
        ({"token": "bad token"}, "token"),
        ({"token": "é"}, "token"),
        ({"token": "x" * 4097}, "token"),
        ({"repository": "missing-owner"}, "repository"),
        ({"repository": "./repo"}, "repository"),
        ({"repository": "owner/.."}, "repository"),
        ({"timeout": True}, "timeout"),
        ({"timeout": 0}, "timeout"),
        ({"timeout": 121}, "timeout"),
        ({"timeout": 10**1000}, "timeout"),
        ({"timeout": -(10**1000)}, "timeout"),
    ],
)
def test_adapter_constructor_rejects_unbounded_inputs(
    arguments: dict[str, Any], message: str
) -> None:
    values = {"token": TOKEN, "repository": REPOSITORY, "timeout": 30.0}
    values.update(arguments)

    with pytest.raises(preflight.PreflightError, match=message):
        preflight.GitHubImmutableReleasePreflightAPI(**values)


def test_adapter_repr_never_contains_token(api: Any) -> None:
    representation = repr(api)

    assert TOKEN not in representation
    assert REPOSITORY in representation


def test_adapter_converts_timeout_exactly_once() -> None:
    conversions: list[None] = []

    class OneShotTimeout(float):
        def __float__(self) -> float:
            conversions.append(None)
            if len(conversions) > 1:
                raise AssertionError("timeout was converted more than once")
            return super().__float__()

    adapter = preflight.GitHubImmutableReleasePreflightAPI(
        token=TOKEN,
        repository=REPOSITORY,
        timeout=OneShotTimeout(12.5),
    )

    assert "timeout=12.5" in repr(adapter)
    assert len(conversions) == 1


@pytest.mark.parametrize(
    "response",
    [
        {"id": REPOSITORY_ID, "full_name": "stampbot/replacement"},
        {"id": 0, "full_name": REPOSITORY},
        {"id": True, "full_name": REPOSITORY},
        {"id": str(REPOSITORY_ID), "full_name": REPOSITORY},
    ],
)
def test_repository_substitution_or_invalid_identity_fails_closed(
    api: Any, install_transport: Any, response: dict[str, Any]
) -> None:
    install_transport(FakeResponse(200, response))

    with pytest.raises(preflight.PreflightError):
        api.repository_identity()


@pytest.mark.parametrize(
    "response",
    [
        {"enabled": False, "enforced_by_owner": False},
        {"enabled": False, "enforced_by_owner": True},
        {"enabled": 1, "enforced_by_owner": True},
        {"enabled": True, "enforced_by_owner": 1},
        {"enabled": True},
        {"enabled": True, "enforced_by_owner": True, "future": False},
    ],
)
def test_policy_response_must_be_exact_and_positive(
    api: Any, install_transport: Any, response: dict[str, Any]
) -> None:
    install_transport(FakeResponse(200, response))

    with pytest.raises(preflight.PreflightError):
        api.immutable_release_policy()


def test_repository_level_enablement_is_a_valid_explicit_policy(
    api: Any, install_transport: Any
) -> None:
    install_transport(FakeResponse(200, {"enabled": True, "enforced_by_owner": False}))

    assert api.immutable_release_policy() == preflight.ImmutableReleasePolicy(True, False)


@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 403, 404, 409, 500, 503])
def test_adapter_never_follows_or_accepts_error_responses(
    api: Any, install_transport: Any, status: int
) -> None:
    transport = install_transport(
        FakeResponse(status, {"message": TOKEN}, headers={"Location": "https://example.com/"})
    )

    with pytest.raises(preflight.PreflightError) as captured:
        api.immutable_release_policy()

    assert TOKEN not in str(captured.value)
    assert transport.connections == transport.closed_connections == 1
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(200, raw=b'{"enabled":true,"enabled":true,"enforced_by_owner":true}'),
        FakeResponse(200, raw=b'{"enabled":1.0,"enforced_by_owner":true}'),
        FakeResponse(200, raw=b'{"enabled":NaN,"enforced_by_owner":true}'),
        FakeResponse(
            200,
            raw='{"enabled":true,"enforced_by_owner":true}'.encode("utf-16"),
        ),
        FakeResponse(200, raw=b"not json"),
        FakeResponse(200, []),
        FakeResponse(200, {}, headers={"Content-Type": "text/plain"}),
        FakeResponse(200, {}, headers={"Content-Encoding": "gzip"}),
        FakeResponse(200, {}, declared_length="invalid"),
        FakeResponse(200, {}, declared_length=999),
        FakeResponse(200, {}, read_error=OSError(TOKEN)),
    ],
)
def test_malformed_success_response_fails_without_leaking_body(
    api: Any, install_transport: Any, response: FakeResponse
) -> None:
    install_transport(response)

    with pytest.raises(preflight.PreflightError) as captured:
        api.immutable_release_policy()

    assert TOKEN not in str(captured.value)


def test_oversized_success_response_fails_before_policy_use(
    api: Any, install_transport: Any
) -> None:
    body = b"{" + b" " * preflight.MAX_RESPONSE_BYTES + b"}"
    install_transport(FakeResponse(200, raw=body))

    with pytest.raises(preflight.PreflightError, match="invalid success response"):
        api.immutable_release_policy()


def test_excessive_response_depth_fails_as_a_bounded_preflight_error(
    api: Any, install_transport: Any
) -> None:
    value: object = True
    for _ in range(preflight.MAX_JSON_DEPTH + 1):
        value = [value]
    install_transport(FakeResponse(200, value))

    with pytest.raises(preflight.PreflightError, match="invalid success response"):
        api.immutable_release_policy()


def test_transport_failure_is_bounded_and_scrubbed(api: Any, install_transport: Any) -> None:
    install_transport(OSError(TOKEN))

    with pytest.raises(preflight.PreflightError) as captured:
        api.repository_identity()

    assert TOKEN not in str(captured.value)
    assert "GET /repos/stampbot/extra-codeowners" in str(captured.value)


def test_transport_cancellation_closes_connection_and_propagates(
    api: Any, install_transport: Any
) -> None:
    class SimulatedCancellation(BaseException):
        pass

    transport = install_transport(SimulatedCancellation())

    with pytest.raises(SimulatedCancellation):
        api.repository_identity()

    assert transport.connections == transport.closed_connections == 1


def test_capture_orders_reads_and_writes_only_after_final_identity(tmp_path: Path) -> None:
    api = FakeAPI()
    output = tmp_path / "record.json"

    preflight.capture_record(
        api,
        output,
        expected=expected_identity(),
        require_owner_enforcement=True,
    )

    assert api.events == ["repository", "policy", "repository"]
    assert output.exists()


@pytest.mark.parametrize("which", ["first", "second"])
def test_capture_rejects_repository_identity_drift_before_writing(
    tmp_path: Path, which: str
) -> None:
    api = FakeAPI()
    replacement = preflight.RepositoryIdentity(REPOSITORY_ID + 1, "stampbot/replacement")
    if which == "first":
        api.identities[0] = replacement
    else:
        api.identities[1] = replacement
    output = tmp_path / "record.json"

    with pytest.raises(preflight.PreflightError, match="repository identity"):
        preflight.capture_record(
            api,
            output,
            expected=expected_identity(),
            require_owner_enforcement=True,
        )

    assert not output.exists()
    if which == "first":
        assert api.events == ["repository"]
    else:
        assert api.events == ["repository", "policy", "repository"]


@pytest.mark.parametrize(
    "identity",
    [
        preflight.RepositoryIdentity(True, REPOSITORY),
        preflight.RepositoryIdentity(REPOSITORY_ID, 123),
        {"id": REPOSITORY_ID, "name": REPOSITORY},
    ],
)
def test_capture_rejects_ambiguous_protocol_repository_identity(
    tmp_path: Path, identity: object
) -> None:
    api = FakeAPI()
    api.identities[0] = identity

    with pytest.raises(preflight.PreflightError):
        preflight.capture_record(
            api,
            tmp_path / "record.json",
            expected=expected_identity(),
            require_owner_enforcement=True,
        )


def test_capture_rejects_ambiguous_protocol_policy(tmp_path: Path) -> None:
    api = FakeAPI()
    api.policy = {"enabled": True, "enforced_by_owner": True}

    with pytest.raises(preflight.PreflightError, match="ambiguous"):
        preflight.capture_record(
            api,
            tmp_path / "record.json",
            expected=expected_identity(),
            require_owner_enforcement=True,
        )


def test_capture_parameterizes_owner_enforcement_without_weakening_enablement(
    tmp_path: Path,
) -> None:
    output = tmp_path / "record.json"
    api = FakeAPI(enforced_by_owner=False)

    preflight.capture_record(
        api,
        output,
        expected=expected_identity(),
        require_owner_enforcement=False,
    )

    observed = json.loads(output.read_bytes())
    assert observed["immutable_releases"] == {
        "enabled": True,
        "enforced_by_owner": False,
    }


@pytest.mark.parametrize(
    ("enabled", "enforced", "required", "message"),
    [
        (False, False, False, "not enabled"),
        (False, True, True, "not enabled"),
        (True, False, True, "not enforced"),
    ],
)
def test_capture_rejects_policy_that_does_not_meet_explicit_requirement(
    tmp_path: Path,
    enabled: bool,
    enforced: bool,
    required: bool,
    message: str,
) -> None:
    output = tmp_path / "record.json"

    with pytest.raises(preflight.PreflightError, match=message):
        preflight.capture_record(
            FakeAPI(enabled=enabled, enforced_by_owner=enforced),
            output,
            expected=expected_identity(),
            require_owner_enforcement=required,
        )

    assert not output.exists()


@pytest.mark.parametrize("required", [0, 1, None, "true"])
def test_policy_requirement_must_be_an_actual_boolean(tmp_path: Path, required: object) -> None:
    with pytest.raises(preflight.PreflightError, match="must be a boolean"):
        preflight.capture_record(
            FakeAPI(),
            tmp_path / "record.json",
            expected=expected_identity(),
            require_owner_enforcement=required,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"repository_id": True},
        {"repository_id": 0},
        {"repository": "stampbot"},
        {"repository": "./repo"},
        {"workflow_path": "release.yml"},
        {"workflow_ref": f"{REPOSITORY}/{WORKFLOW_PATH}@refs/tags/../main"},
        {"workflow_ref": f"stampbot/other/{WORKFLOW_PATH}@refs/tags/v0.1.0"},
        {"workflow_sha": "A" * 40},
        {"workflow_sha": "a" * 39},
        {"run_id": 0},
        {"run_attempt": True},
    ],
)
def test_capture_rejects_invalid_trusted_identity_before_api_access(
    tmp_path: Path, changes: dict[str, Any]
) -> None:
    api = FakeAPI()

    with pytest.raises(preflight.PreflightError):
        preflight.capture_record(
            api,
            tmp_path / "record.json",
            expected=expected_identity(**changes),
            require_owner_enforcement=True,
        )

    assert api.events == []


def test_capture_refuses_to_replace_an_existing_record(tmp_path: Path) -> None:
    output = tmp_path / "record.json"
    output.write_bytes(b"keep-me")

    with pytest.raises(preflight.PreflightError, match="exclusively"):
        preflight.capture_record(
            FakeAPI(),
            output,
            expected=expected_identity(),
            require_owner_enforcement=True,
        )

    assert output.read_bytes() == b"keep-me"


def test_capture_removes_a_partial_output_after_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "record.json"
    real_write = preflight.os.write
    calls = 0

    def fail_second_write(descriptor: int, content: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return int(real_write(descriptor, content[:1]))
        return 0

    monkeypatch.setattr(preflight.os, "write", fail_second_write)

    with pytest.raises(preflight.PreflightError, match="complete"):
        preflight.capture_record(
            FakeAPI(),
            output,
            expected=expected_identity(),
            require_owner_enforcement=True,
        )

    assert not output.exists()


@pytest.mark.parametrize("operation", ["write", "fstat"])
def test_capture_normalizes_post_open_os_errors_and_removes_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    output = tmp_path / "record.json"

    def fail_with_os_error(*_args: object) -> Any:
        raise OSError(f"simulated {operation} failure")

    monkeypatch.setattr(preflight.os, operation, fail_with_os_error)

    with pytest.raises(preflight.PreflightError, match="cannot write or inspect") as exc_info:
        preflight.capture_record(
            FakeAPI(),
            output,
            expected=expected_identity(),
            require_owner_enforcement=True,
        )

    assert isinstance(exc_info.value.__cause__, OSError)
    assert not output.exists()


@pytest.mark.parametrize("operation", ["write", "fstat"])
def test_capture_preserves_post_open_base_exceptions_and_removes_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    output = tmp_path / "record.json"

    class SimulatedCancellation(BaseException):
        pass

    def cancel(*_args: object) -> Any:
        raise SimulatedCancellation

    monkeypatch.setattr(preflight.os, operation, cancel)

    with pytest.raises(SimulatedCancellation):
        preflight.capture_record(
            FakeAPI(),
            output,
            expected=expected_identity(),
            require_owner_enforcement=True,
        )

    assert not output.exists()


def test_capture_forces_exact_private_mode_under_restrictive_umask(tmp_path: Path) -> None:
    output = tmp_path / "record.json"
    previous_umask = os.umask(0o777)
    try:
        digest = preflight.capture_record(
            FakeAPI(),
            output,
            expected=expected_identity(),
            require_owner_enforcement=True,
        )
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert hashlib.sha256(output.read_bytes()).hexdigest() == digest


def test_capture_rejects_output_when_private_mode_cannot_be_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "record.json"
    monkeypatch.setattr(preflight.os, "fchmod", lambda *_args: None)
    previous_umask = os.umask(0o777)
    try:
        with pytest.raises(preflight.PreflightError, match="unsafe file metadata"):
            preflight.capture_record(
                FakeAPI(),
                output,
                expected=expected_identity(),
                require_owner_enforcement=True,
            )
    finally:
        os.umask(previous_umask)

    assert not output.exists()


def test_verify_record_accepts_exact_raw_artifact(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    digest = write_record(path)

    result = preflight.verify_record(
        path,
        expected=expected_identity(),
        capture_sha256=digest,
        record_artifact_sha256=digest,
        require_owner_enforcement=True,
    )

    assert result == preflight.PreflightRecord(
        repository_id=REPOSITORY_ID,
        repository=REPOSITORY,
        workflow_path=WORKFLOW_PATH,
        workflow_ref=WORKFLOW_REF,
        workflow_sha=WORKFLOW_SHA,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        api_version=preflight.API_VERSION,
        enabled=True,
        enforced_by_owner=True,
        sha256=digest,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"repository_id": REPOSITORY_ID + 1},
        {
            "repository": "stampbot/other",
            "workflow_ref": ("stampbot/other/.github/workflows/release.yml@refs/tags/v0.1.0"),
        },
        {
            "workflow_path": ".github/workflows/other.yml",
            "workflow_ref": (f"{REPOSITORY}/.github/workflows/other.yml@refs/tags/v0.1.0"),
        },
        {"workflow_ref": f"{REPOSITORY}/{WORKFLOW_PATH}@refs/tags/v0.2.0"},
        {"workflow_sha": "b" * 40},
        {"run_id": RUN_ID + 1},
        {"run_attempt": RUN_ATTEMPT + 1},
    ],
)
def test_verify_rejects_record_bound_to_different_trusted_context(
    tmp_path: Path, changes: dict[str, Any]
) -> None:
    path = tmp_path / "record.json"
    digest = write_record(path)

    with pytest.raises(preflight.PreflightError, match="trusted workflow context"):
        preflight.verify_record(
            path,
            expected=expected_identity(**changes),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "sha256:" + "a" * 64, True])
def test_verify_rejects_invalid_provider_digest(tmp_path: Path, digest: object) -> None:
    path = tmp_path / "record.json"
    capture_digest = write_record(path)

    with pytest.raises(preflight.PreflightError, match="artifact SHA-256 is invalid"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=capture_digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "sha256:" + "a" * 64, True])
def test_verify_rejects_invalid_capture_digest(tmp_path: Path, digest: object) -> None:
    path = tmp_path / "record.json"
    provider_digest = write_record(path)

    with pytest.raises(preflight.PreflightError, match="captured preflight SHA-256 is invalid"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=provider_digest,
            require_owner_enforcement=True,
        )


def test_verify_rejects_provider_digest_mismatch_before_json_use(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    capture_digest = write_record(path, raw=b"not json\n")

    with pytest.raises(preflight.PreflightError, match="provider artifact"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=capture_digest,
            record_artifact_sha256="0" * 64,
            require_owner_enforcement=True,
        )


def test_verify_rejects_valid_record_replaced_between_capture_and_upload(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    capture_digest = preflight.capture_record(
        FakeAPI(),
        path,
        expected=expected_identity(),
        require_owner_enforcement=True,
    )
    replacement = preflight.canonical_json(
        record_value(immutable_releases={"enabled": True, "enforced_by_owner": False})
    )
    path.write_bytes(replacement)
    provider_digest = hashlib.sha256(replacement).hexdigest()

    with pytest.raises(preflight.PreflightError, match="provider artifact"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=capture_digest,
            record_artifact_sha256=provider_digest,
            require_owner_enforcement=False,
        )


def test_verify_rejects_valid_download_replaced_after_upload(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    capture_digest = preflight.capture_record(
        FakeAPI(),
        path,
        expected=expected_identity(),
        require_owner_enforcement=True,
    )
    replacement = preflight.canonical_json(
        record_value(immutable_releases={"enabled": True, "enforced_by_owner": False})
    )
    path.write_bytes(replacement)

    with pytest.raises(preflight.PreflightError, match="downloaded bytes"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=capture_digest,
            record_artifact_sha256=capture_digest,
            require_owner_enforcement=False,
        )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"api":{},"api":{}}\n',
        b'{"floating":1.0}\n',
        b'{"non_finite":NaN}\n',
        b"not json\n",
        b"{}\n",
    ],
)
def test_verify_rejects_malformed_or_duplicate_json(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "record.json"
    digest = write_record(path, raw=raw)

    with pytest.raises(preflight.PreflightError):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )


def test_verify_rejects_noncanonical_json(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    raw = json.dumps(record_value(), indent=2).encode() + b"\n"
    digest = write_record(path, raw=raw)

    with pytest.raises(preflight.PreflightError, match="not canonically encoded"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("media_type", "application/json"),
        ("api", {"version": "latest"}),
        ("api", {"version": preflight.API_VERSION, "extra": True}),
        ("repository", {"id": REPOSITORY_ID, "name": "stampbot/other"}),
        ("run", {"id": RUN_ID, "attempt": True}),
        (
            "workflow",
            {"path": WORKFLOW_PATH, "ref": WORKFLOW_REF, "sha": "A" * 40},
        ),
        ("immutable_releases", {"enabled": 1, "enforced_by_owner": True}),
        ("immutable_releases", {"enabled": True}),
    ],
)
def test_verify_rejects_invalid_record_fields(tmp_path: Path, field: str, value: object) -> None:
    path = tmp_path / "record.json"
    content = record_value()
    content[field] = value
    digest = write_record(path, content)

    with pytest.raises(preflight.PreflightError):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )


@pytest.mark.parametrize(
    ("policy", "required", "message"),
    [
        ({"enabled": False, "enforced_by_owner": False}, False, "not enabled"),
        ({"enabled": True, "enforced_by_owner": False}, True, "not enforced"),
    ],
)
def test_verify_reapplies_policy_from_independent_requirement(
    tmp_path: Path, policy: dict[str, bool], required: bool, message: str
) -> None:
    path = tmp_path / "record.json"
    content = record_value(immutable_releases=policy)
    digest = write_record(path, content)

    with pytest.raises(preflight.PreflightError, match=message):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=required,
        )


def test_verify_accepts_repository_level_policy_only_when_explicit(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    content = record_value(immutable_releases={"enabled": True, "enforced_by_owner": False})
    digest = write_record(path, content)

    result = preflight.verify_record(
        path,
        expected=expected_identity(),
        capture_sha256=digest,
        record_artifact_sha256=digest,
        require_owner_enforcement=False,
    )

    assert result.enabled is True
    assert result.enforced_by_owner is False


def test_verify_rejects_symlink_hardlink_directory_empty_and_oversized_inputs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    digest = write_record(source)
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(source)
    hardlink = tmp_path / "hardlink.json"
    os.link(source, hardlink)
    directory = tmp_path / "directory"
    directory.mkdir()
    empty = tmp_path / "empty.json"
    empty.touch()
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (preflight.MAX_RECORD_BYTES + 1))

    for path in (source, symlink, hardlink, directory, empty, oversized):
        with pytest.raises(preflight.PreflightError):
            preflight.verify_record(
                path,
                expected=expected_identity(),
                capture_sha256=digest,
                record_artifact_sha256=digest,
                require_owner_enforcement=True,
            )


def test_verifier_rejects_fifo_without_waiting_for_a_writer(tmp_path: Path) -> None:
    fifo = tmp_path / "record.fifo"
    os.mkfifo(fifo)

    with pytest.raises(preflight.PreflightError, match="unsafe file metadata"):
        preflight.verify_record(
            fifo,
            expected=expected_identity(),
            capture_sha256="0" * 64,
            record_artifact_sha256="0" * 64,
            require_owner_enforcement=True,
        )


def test_verifier_rejects_metadata_mutation_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "record.json"
    digest = write_record(path)
    real_fstat = preflight.os.fstat
    calls = 0

    def mutate_before_second_fstat(descriptor: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == 2:
            metadata = real_fstat(descriptor)
            os.utime(
                path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
            )
        return cast(os.stat_result, real_fstat(descriptor))

    monkeypatch.setattr(preflight.os, "fstat", mutate_before_second_fstat)

    with pytest.raises(preflight.PreflightError, match="changed while it was read"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )


def test_verifier_rejects_path_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "record.json"
    raw = preflight.canonical_json(record_value())
    digest = write_record(path, raw=raw)
    displaced = tmp_path / "displaced-record.json"
    real_stat = preflight.os.stat
    replaced = False

    def replace_before_path_stat(candidate: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal replaced
        if not replaced and os.fspath(candidate) == os.fspath(path):
            replaced = True
            os.rename(path, displaced)
            path.write_bytes(raw)
        return cast(os.stat_result, real_stat(candidate, *args, **kwargs))

    monkeypatch.setattr(preflight.os, "stat", replace_before_path_stat)

    with pytest.raises(preflight.PreflightError, match="path changed while it was read"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )

    assert replaced is True
    assert displaced.read_bytes() == raw


def test_verifier_fails_when_the_record_descriptor_cannot_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "record.json"
    digest = write_record(path)
    real_close = preflight.os.close

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        raise OSError("simulated close failure")

    monkeypatch.setattr(preflight.os, "close", close_then_fail)

    with pytest.raises(preflight.PreflightError, match="cannot close"):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )


def test_verifier_preserves_validation_failure_when_close_also_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "empty.json"
    path.touch()
    digest = hashlib.sha256(b"").hexdigest()
    real_close = preflight.os.close

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        raise OSError("simulated close failure")

    monkeypatch.setattr(preflight.os, "close", close_then_fail)

    with pytest.raises(preflight.PreflightError, match="unsafe file metadata") as exc_info:
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )

    assert "cannot close" not in str(exc_info.value)


def test_verifier_preserves_cancellation_when_close_also_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "record.json"
    digest = write_record(path)
    real_close = preflight.os.close

    class SimulatedCancellation(BaseException):
        pass

    def cancel_fstat(_descriptor: int) -> NoReturn:
        raise SimulatedCancellation

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        raise OSError("simulated close failure")

    monkeypatch.setattr(preflight.os, "fstat", cancel_fstat)
    monkeypatch.setattr(preflight.os, "close", close_then_fail)

    with pytest.raises(SimulatedCancellation):
        preflight.verify_record(
            path,
            expected=expected_identity(),
            capture_sha256=digest,
            record_artifact_sha256=digest,
            require_owner_enforcement=True,
        )


def test_production_surface_has_no_mutation_cli_or_ambient_token_access() -> None:
    source = (
        Path(__file__).parents[1] / ".github" / "scripts" / "immutable_release_preflight.py"
    ).read_text(encoding="utf-8")

    assert 'connection.request("GET"' in source
    for forbidden in (
        'connection.request("POST"',
        'connection.request("PUT"',
        'connection.request("PATCH"',
        'connection.request("DELETE"',
        "argparse",
        "os.environ",
        "os.getenv",
    ):
        assert forbidden not in source

    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
    runtime_parts = re.split(r"\nFROM [^\n]+ AS runtime\n", dockerfile, maxsplit=1)
    assert len(runtime_parts) == 2
    test_stage, runtime_stage = runtime_parts
    assert ".github/scripts/immutable_release_preflight.py" in test_stage
    assert ".github/scripts/immutable_release_preflight.py" not in runtime_stage


def _workflow_string_leaves(
    value: object, location: tuple[object, ...] = ()
) -> list[tuple[tuple[object, ...], str]]:
    if isinstance(value, Mapping):
        leaves: list[tuple[tuple[object, ...], str]] = []
        for key, child in value.items():
            if isinstance(key, str):
                leaves.append(((*location, "<key>", key), key))
            leaves.extend(_workflow_string_leaves(child, (*location, key)))
        return leaves
    if isinstance(value, list):
        leaves = []
        for index, child in enumerate(value):
            leaves.extend(_workflow_string_leaves(child, (*location, index)))
        return leaves
    if isinstance(value, str):
        return [(location, value)]
    return []


def test_workflows_only_type_check_the_preflight_module() -> None:
    script = ".github/scripts/immutable_release_preflight.py"
    expected_commands = {
        ("ci.yml", "lint", "Type check"): (
            "uv",
            "run",
            "mypy",
            "extra_codeowners",
            "tests",
            ".github/scripts/build_python_artifacts.py",
            ".github/scripts/build_python_distribution_spine.py",
            ".github/scripts/build_release_spine.py",
            ".github/scripts/container_evidence.py",
            ".github/scripts/github_release_api.py",
            script,
            ".github/scripts/python_distribution_spine.py",
            ".github/scripts/release_asset_assembler.py",
            ".github/scripts/release_controller.py",
            ".github/scripts/release_spine.py",
            ".github/scripts/release_readiness.py",
        ),
        ("release.yml", "quality", "Verify Python source"): (
            "uv",
            "run",
            "mypy",
            "extra_codeowners",
            "tests",
            ".github/scripts/build_python_artifacts.py",
            ".github/scripts/build_python_distribution_spine.py",
            ".github/scripts/build_release_spine.py",
            ".github/scripts/container_evidence.py",
            ".github/scripts/github_release_api.py",
            script,
            ".github/scripts/python_distribution_spine.py",
            ".github/scripts/release_asset_assembler.py",
            ".github/scripts/release_controller.py",
            ".github/scripts/release_spine.py",
            ".github/scripts/release_readiness.py",
        ),
    }
    forbidden_markers = (
        "capture_record",
        "verify_record",
        "GitHubImmutableReleasePreflightAPI",
        "import immutable_release_preflight",
        "from immutable_release_preflight",
    )
    observed: set[tuple[str, str, str]] = set()

    workflow_root = Path(__file__).parents[1] / ".github" / "workflows"
    for path in sorted(workflow_root.glob("*.y*ml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(document, Mapping), f"{path}: workflow must be a mapping"
        jobs = document.get("jobs")
        assert isinstance(jobs, Mapping), f"{path}: jobs must be a mapping"

        allowed_locations: dict[tuple[object, ...], tuple[str, str, str]] = {}
        for job_name, job in jobs.items():
            assert isinstance(job_name, str)
            assert isinstance(job, Mapping)
            steps = job.get("steps", [])
            assert isinstance(steps, list)
            for index, step in enumerate(steps):
                assert isinstance(step, Mapping)
                step_name = step.get("name")
                run = step.get("run")
                if not isinstance(step_name, str) or not isinstance(run, str):
                    continue
                key = (path.name, job_name, step_name)
                if key in expected_commands:
                    allowed_locations[("jobs", job_name, "steps", index, "run")] = key

        for location, value in _workflow_string_leaves(document):
            assert not any(marker in value for marker in forbidden_markers), (
                f"{path}:{location} activates or imports the preflight module"
            )
            if "immutable_release_preflight" not in value:
                continue
            assert location in allowed_locations, (
                f"{path}:{location} references the preflight module outside the allowlist"
            )
            key = allowed_locations[location]
            logical_run = re.sub(r"\\\n[ \t]*", " ", value)
            commands = [command.strip() for command in logical_run.splitlines() if command.strip()]
            matching_commands = [command for command in commands if script in command]
            assert len(matching_commands) == 1
            assert tuple(shlex.split(matching_commands[0])) == expected_commands[key]
            observed.add(key)

    assert observed == set(expected_commands)
