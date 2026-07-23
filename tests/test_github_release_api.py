from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest


def load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


controller = load_script("release_controller")
adapter = load_script("github_release_api")

REPOSITORY = "stampbot/extra-codeowners"
TOKEN = "test-token-never-print"
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
REQUEST_ID = "A1B2:3C4D:5E6F:7890"


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
    ) -> None:
        self.status = status
        self.body = raw if raw is not None else json_bytes(value)
        self.offset = 0
        self.closed = False
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
        if amount is None:
            amount = len(self.body) - self.offset
        chunk = self.body[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class RequestRecord:
    def __init__(
        self,
        *,
        host: str,
        timeout: float,
        method: str,
        path: str,
        body: bytes,
        headers: Mapping[str, str],
    ) -> None:
        self.host = host
        self.timeout = timeout
        self.method = method
        self.path = path
        self.body = body
        self.headers = dict(headers)


class FakeTransport:
    def __init__(self, outcomes: Iterable[FakeResponse | BaseException]) -> None:
        self.outcomes = list(outcomes)
        self.connections = 0
        self.requests: list[RequestRecord] = []
        self.closed_connections = 0

    def connection(self, host: str, *, timeout: float) -> Any:
        assert self.outcomes, "adapter made an unplanned request"
        outcome = self.outcomes.pop(0)
        self.connections += 1
        owner = self

        class Connection:
            def request(
                self,
                method: str,
                path: str,
                body: bytes | Iterable[bytes] | None = None,
                headers: Mapping[str, str] | None = None,
            ) -> None:
                if isinstance(outcome, BaseException):
                    raise outcome
                if body is None:
                    sent = b""
                elif isinstance(body, bytes):
                    sent = body
                else:
                    sent = b"".join(body)
                owner.requests.append(
                    RequestRecord(
                        host=host,
                        timeout=timeout,
                        method=method,
                        path=path,
                        body=sent,
                        headers=headers or {},
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
        monkeypatch.setattr(adapter.http.client, "HTTPSConnection", transport.connection)
        return transport

    return install


@pytest.fixture
def api() -> Any:
    return adapter.GitHubReleaseAPI(token=TOKEN, repository=REPOSITORY)


def plan() -> Any:
    return controller.ReleasePlan(
        repository_id=12345,
        repository=REPOSITORY,
        tag="v0.1.0",
        target_commit=COMMIT,
        workflow_path=".github/workflows/release.yml",
        workflow_sha="c" * 40,
        run_id=998877,
        assets=(
            controller.Asset("app.whl", "python/app.whl", 5, hashlib.sha256(b"wheel").hexdigest()),
        ),
        manifest_sha256="d" * 64,
    )


def release_response(
    release_plan: Any, *, release_id: int = 77, draft: bool, immutable: bool
) -> dict[str, Any]:
    return {
        "body": release_plan.marker,
        "draft": draft,
        "id": release_id,
        "immutable": immutable,
        "name": release_plan.tag,
        "prerelease": False,
        "tag_name": release_plan.tag,
        "target_commitish": release_plan.target_commit,
        "upload_url": (
            f"https://uploads.github.com/repos/{release_plan.repository}/releases/"
            f"{release_id}/assets{{?name,label}}"
        ),
    }


def assert_common_headers(record: RequestRecord) -> None:
    assert record.headers["Accept"] == "application/vnd.github+json"
    assert record.headers["Accept-Encoding"] == "identity"
    assert record.headers["Authorization"] == f"Bearer {TOKEN}"
    assert record.headers["User-Agent"] == "extra-codeowners-release-controller/1"
    assert record.headers["X-GitHub-Api-Version"] == "2026-03-10"


def test_repository_query_binds_id_to_exact_trusted_full_name(
    api: Any, install_transport: Any
) -> None:
    transport = install_transport(FakeResponse(200, {"id": 12345, "full_name": REPOSITORY}))

    assert api.repository_id() == 12345

    assert transport.connections == transport.closed_connections == 1
    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert (request.host, request.method, request.path, request.body) == (
        "api.github.com",
        "GET",
        "/repos/stampbot/extra-codeowners",
        b"",
    )
    assert_common_headers(request)


@pytest.mark.parametrize(
    "response",
    [
        {"id": 12345, "full_name": "stampbot/renamed"},
        {"id": True, "full_name": REPOSITORY},
        {"id": 0, "full_name": REPOSITORY},
    ],
)
def test_repository_identity_mismatch_fails_closed(
    api: Any, install_transport: Any, response: dict[str, Any]
) -> None:
    install_transport(FakeResponse(200, response))

    with pytest.raises(controller.ControllerError):
        api.repository_id()


def test_lightweight_tag_resolves_only_the_exact_reference(
    api: Any, install_transport: Any
) -> None:
    transport = install_transport(
        FakeResponse(
            200,
            {
                "ref": "refs/tags/v0.1.0",
                "object": {"sha": COMMIT, "type": "commit"},
            },
        )
    )

    assert api.resolve_tag("v0.1.0") == COMMIT
    assert [(item.method, item.path) for item in transport.requests] == [
        ("GET", "/repos/stampbot/extra-codeowners/git/ref/tags/v0.1.0")
    ]


def test_one_annotated_tag_resolves_directly_to_a_commit(api: Any, install_transport: Any) -> None:
    transport = install_transport(
        FakeResponse(
            200,
            {
                "ref": "refs/tags/v0.1.0",
                "object": {"sha": TAG_OBJECT, "type": "tag"},
            },
        ),
        FakeResponse(
            200,
            {
                "sha": TAG_OBJECT,
                "tag": "v0.1.0",
                "object": {"sha": COMMIT, "type": "commit"},
            },
        ),
    )

    assert api.resolve_tag("v0.1.0") == COMMIT
    assert [(item.host, item.path) for item in transport.requests] == [
        ("api.github.com", "/repos/stampbot/extra-codeowners/git/ref/tags/v0.1.0"),
        ("api.github.com", f"/repos/stampbot/extra-codeowners/git/tags/{TAG_OBJECT}"),
    ]


@pytest.mark.parametrize(
    "first,second",
    [
        (
            {"ref": "refs/tags/v0.1.1", "object": {"sha": COMMIT, "type": "commit"}},
            None,
        ),
        (
            {"ref": "refs/tags/v0.1.0", "object": {"sha": COMMIT, "type": "tree"}},
            None,
        ),
        (
            {"ref": "refs/tags/v0.1.0", "object": {"sha": TAG_OBJECT, "type": "tag"}},
            {
                "sha": TAG_OBJECT,
                "tag": "v0.1.0",
                "object": {"sha": "e" * 40, "type": "tag"},
            },
        ),
        (
            {"ref": "refs/tags/v0.1.0", "object": {"sha": TAG_OBJECT, "type": "tag"}},
            {
                "sha": "e" * 40,
                "tag": "v0.1.0",
                "object": {"sha": COMMIT, "type": "commit"},
            },
        ),
    ],
    ids=["different-ref", "tree", "tag-chain", "annotated-object-substitution"],
)
def test_tag_resolution_rejects_substitution_and_tag_chains(
    api: Any,
    install_transport: Any,
    first: dict[str, Any],
    second: dict[str, Any] | None,
) -> None:
    outcomes = [FakeResponse(200, first)]
    if second is not None:
        outcomes.append(FakeResponse(200, second))
    install_transport(*outcomes)

    with pytest.raises(controller.ControllerError):
        api.resolve_tag("v0.1.0")


def test_release_and_asset_reads_use_exact_bounded_queries(
    api: Any, install_transport: Any
) -> None:
    releases = [{"id": 7}, {"id": 8}]
    release = {"id": 7}
    assets = [{"id": 70}, {"id": 71}]
    transport = install_transport(
        FakeResponse(200, releases),
        FakeResponse(200, release),
        FakeResponse(200, assets),
    )

    assert api.list_releases(2, 100) == releases
    assert api.get_release(7) == release
    assert api.list_assets(7, 3, 50) == assets

    assert [(item.method, item.path) for item in transport.requests] == [
        ("GET", "/repos/stampbot/extra-codeowners/releases?per_page=100&page=2"),
        ("GET", "/repos/stampbot/extra-codeowners/releases/7"),
        (
            "GET",
            "/repos/stampbot/extra-codeowners/releases/7/assets?per_page=50&page=3",
        ),
    ]


def test_get_release_rejects_a_substituted_release_id(api: Any, install_transport: Any) -> None:
    transport = install_transport(FakeResponse(200, {"id": 8}))

    with pytest.raises(controller.ControllerError, match="failed closed"):
        api.get_release(7)

    assert [(item.method, item.path) for item in transport.requests] == [
        ("GET", "/repos/stampbot/extra-codeowners/releases/7")
    ]


@pytest.mark.parametrize(("page", "per_page"), [(0, 100), (11, 100), (1, 0), (1, 101), (True, 1)])
def test_pagination_bounds_stop_before_network(
    api: Any, install_transport: Any, page: Any, per_page: Any
) -> None:
    transport = install_transport()

    with pytest.raises(controller.ControllerError):
        api.list_releases(page, per_page)

    assert transport.connections == 0


def test_create_draft_sends_the_exact_reviewed_body(api: Any, install_transport: Any) -> None:
    release_plan = plan()
    response = release_response(release_plan, draft=True, immutable=False)
    transport = install_transport(FakeResponse(201, response))

    assert api.create_draft(release_plan) == response

    request = transport.requests[0]
    assert (request.host, request.method, request.path) == (
        "api.github.com",
        "POST",
        "/repos/stampbot/extra-codeowners/releases",
    )
    assert json.loads(request.body) == {
        "body": release_plan.marker,
        "draft": True,
        "generate_release_notes": False,
        "make_latest": "false",
        "name": "v0.1.0",
        "prerelease": False,
        "tag_name": "v0.1.0",
        "target_commitish": COMMIT,
    }
    assert request.body == json_bytes(json.loads(request.body))
    assert request.headers["Content-Length"] == str(len(request.body))
    assert request.headers["Content-Type"] == "application/json"
    assert_common_headers(request)


def test_publish_disables_the_latest_release_side_effect(api: Any, install_transport: Any) -> None:
    response = release_response(plan(), draft=False, immutable=True)
    transport = install_transport(FakeResponse(200, response))

    assert api.publish_release(77) == response

    request = transport.requests[0]
    assert (request.host, request.method, request.path, request.body) == (
        "api.github.com",
        "PATCH",
        "/repos/stampbot/extra-codeowners/releases/77",
        b'{"draft":false,"make_latest":"false"}',
    )
    assert request.headers["Content-Length"] == str(len(request.body))
    assert request.headers["Content-Type"] == "application/json"


def test_upload_streams_exact_chunks_without_path_seek_or_descriptor_ownership(
    tmp_path: Path,
    api: Any,
    install_transport: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"a" * adapter.READ_CHUNK_BYTES + b"final"
    path = tmp_path / "artifact-name.whl"
    path.write_bytes(content)
    descriptor = os.open(path, os.O_RDONLY)
    os.lseek(descriptor, 2, os.SEEK_SET)
    positions: list[tuple[int, int]] = []
    actual_pread = os.pread

    def capture_pread(fd: int, amount: int, offset: int) -> bytes:
        positions.append((amount, offset))
        return actual_pread(fd, amount, offset)

    monkeypatch.setattr(adapter.os, "pread", capture_pread)
    monkeypatch.setattr(
        adapter.os,
        "open",
        lambda *_args, **_kwargs: pytest.fail("adapter reopened an asset path"),
    )
    asset = controller.Asset(
        "artifact-name.whl",
        "artifact-name.whl",
        len(content),
        hashlib.sha256(content).hexdigest(),
    )
    verified = controller.VerifiedAsset(asset, descriptor, ())
    response = {
        "content_type": "application/octet-stream",
        "id": 91,
        "label": None,
        "name": asset.name,
        "size": asset.size,
        "state": "uploaded",
        "digest": f"sha256:{asset.sha256}",
    }
    transport = install_transport(FakeResponse(201, response))

    try:
        assert (
            api.upload_asset(
                77,
                "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets"
                "{?name,label}",
                verified,
            )
            == response
        )
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 2
        os.fstat(descriptor)
    finally:
        os.close(descriptor)

    request = transport.requests[0]
    assert (request.host, request.method) == ("uploads.github.com", "POST")
    assert request.path == (
        "/repos/stampbot/extra-codeowners/releases/77/assets?name=artifact-name.whl"
    )
    assert request.body == content
    assert request.headers["Content-Length"] == str(len(content))
    assert request.headers["Content-Type"] == "application/octet-stream"
    assert "Transfer-Encoding" not in request.headers
    assert positions == [
        (adapter.READ_CHUNK_BYTES, 0),
        (5, adapter.READ_CHUNK_BYTES),
        (1, len(content)),
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets{?name,label}",
        "https://evil.example/repos/stampbot/extra-codeowners/releases/77/assets{?name,label}",
        "https://uploads.github.com/repos/stampbot/other/releases/77/assets{?name,label}",
        "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/78/assets"
        + "{?name,label}",
        "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets",
        "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets"
        + "{?name,label}&name=second",
    ],
)
def test_upload_accepts_only_the_exact_trusted_template(
    tmp_path: Path, api: Any, install_transport: Any, url: str
) -> None:
    source = tmp_path / "app.whl"
    source.write_bytes(b"wheel")
    descriptor = os.open(source, os.O_RDONLY)
    verified = controller.VerifiedAsset(plan().assets[0], descriptor, ())
    transport = install_transport()
    try:
        with pytest.raises(controller.ControllerError, match="upload URL"):
            api.upload_asset(77, url, verified)
    finally:
        os.close(descriptor)
    assert transport.connections == 0


def test_upload_rejects_a_name_github_would_normalize(
    tmp_path: Path, api: Any, install_transport: Any
) -> None:
    source = tmp_path / "artifact."
    source.write_bytes(b"asset")
    descriptor = os.open(source, os.O_RDONLY)
    asset = controller.Asset("artifact.", "artifact.", 5, hashlib.sha256(b"asset").hexdigest())
    verified = controller.VerifiedAsset(asset, descriptor, ())
    transport = install_transport()
    try:
        with pytest.raises(controller.ControllerError, match="asset name"):
            api.upload_asset(
                77,
                "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/"
                "assets{?name,label}",
                verified,
            )
    finally:
        os.close(descriptor)

    assert transport.connections == 0


@pytest.mark.parametrize(
    ("method", "invoke", "status"),
    [
        ("POST", lambda api, release_plan: api.create_draft(release_plan), 101),
        ("POST", lambda api, release_plan: api.create_draft(release_plan), 102),
        ("POST", lambda api, release_plan: api.create_draft(release_plan), 103),
        ("POST", lambda api, release_plan: api.create_draft(release_plan), 408),
        ("POST", lambda api, release_plan: api.create_draft(release_plan), 500),
        ("PATCH", lambda api, _release_plan: api.publish_release(77), 503),
    ],
)
def test_mutation_informational_timeout_and_server_responses_are_ambiguous(
    api: Any,
    install_transport: Any,
    method: str,
    invoke: Any,
    status: int,
) -> None:
    transport = install_transport(
        FakeResponse(
            status, raw=b"secret server diagnostics", headers={"Content-Type": "text/plain"}
        )
    )

    with pytest.raises(controller.AmbiguousMutationError) as caught:
        invoke(api, plan())

    assert transport.connections == 1
    assert len(transport.requests) == 1
    assert transport.requests[0].method == method
    assert "secret server diagnostics" not in str(caught.value)
    assert f"status={status}" in str(caught.value)


@pytest.mark.parametrize("status", [200, 202, 204, 206])
def test_unexpected_success_status_for_mutation_is_ambiguous(
    api: Any, install_transport: Any, status: int
) -> None:
    transport = install_transport(FakeResponse(status, {"id": 77}))

    with pytest.raises(controller.AmbiguousMutationError) as caught:
        api.create_draft(plan())

    assert f"status={status}" in str(caught.value)
    assert transport.connections == len(transport.requests) == 1


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 429])
def test_definite_mutation_client_errors_are_not_ambiguous(
    api: Any, install_transport: Any, status: int
) -> None:
    transport = install_transport(FakeResponse(status, {"message": TOKEN}))

    with pytest.raises(controller.ControllerError) as caught:
        api.create_draft(plan())

    assert not isinstance(caught.value, controller.AmbiguousMutationError)
    assert TOKEN not in str(caught.value)
    assert transport.connections == len(transport.requests) == 1


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_never_followed_or_retried(
    api: Any, install_transport: Any, status: int
) -> None:
    transport = install_transport(
        FakeResponse(
            status,
            {"message": "redirect"},
            headers={"Location": "https://evil.example/collect"},
        )
    )

    with pytest.raises(controller.ControllerError) as caught:
        api.create_draft(plan())

    assert not isinstance(caught.value, controller.AmbiguousMutationError)
    assert transport.connections == len(transport.requests) == 1
    assert transport.requests[0].host == "api.github.com"


@pytest.mark.parametrize(
    "outcome",
    [TimeoutError("lost"), OSError("lost"), adapter.http.client.RemoteDisconnected("lost")],
)
def test_transport_loss_after_mutation_start_is_ambiguous_and_not_retried(
    api: Any, install_transport: Any, outcome: BaseException
) -> None:
    transport = install_transport(outcome)

    with pytest.raises(controller.AmbiguousMutationError) as caught:
        api.publish_release(77)

    assert transport.connections == 1
    assert transport.closed_connections == 1
    assert transport.requests == []
    assert "lost" not in str(caught.value)


def test_read_transport_or_server_failure_is_not_mutation_ambiguity(
    api: Any, install_transport: Any
) -> None:
    transport = install_transport(FakeResponse(502, {"message": "bad gateway"}))

    with pytest.raises(controller.ControllerError) as caught:
        api.get_release(77)

    assert not isinstance(caught.value, controller.AmbiguousMutationError)
    assert transport.connections == len(transport.requests) == 1


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(201, raw=b'{"id":'),
        FakeResponse(201, {"id": 77}, declared_length=999),
        FakeResponse(201, raw=b'[{"id":77}]'),
        FakeResponse(201, {}),
        FakeResponse(201, {"id": 77}, headers={"Content-Encoding": "gzip"}),
        FakeResponse(201, {"id": 77}, headers={"Content-Type": "text/plain"}),
    ],
    ids=[
        "invalid-json",
        "truncated",
        "wrong-root",
        "invalid-object",
        "content-encoding",
        "media-type",
    ],
)
def test_invalid_successful_mutation_response_is_ambiguous(
    api: Any, install_transport: Any, response: FakeResponse
) -> None:
    install_transport(response)

    with pytest.raises(controller.AmbiguousMutationError):
        api.create_draft(plan())


def test_invalid_successful_publish_response_is_ambiguous(api: Any, install_transport: Any) -> None:
    install_transport(FakeResponse(200, {"id": 77, "draft": False}))

    with pytest.raises(controller.AmbiguousMutationError):
        api.publish_release(77)


def test_mismatched_successful_upload_response_is_ambiguous(
    tmp_path: Path, api: Any, install_transport: Any
) -> None:
    source = tmp_path / "app.whl"
    source.write_bytes(b"wheel")
    descriptor = os.open(source, os.O_RDONLY)
    verified = controller.VerifiedAsset(plan().assets[0], descriptor, ())
    install_transport(
        FakeResponse(
            201,
            {
                "digest": "sha256:" + "0" * 64,
                "id": 90,
                "name": "app.whl",
                "size": 5,
                "state": "uploaded",
            },
        )
    )
    try:
        with pytest.raises(controller.AmbiguousMutationError):
            api.upload_asset(
                77,
                "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets"
                "{?name,label}",
                verified,
            )
    finally:
        os.close(descriptor)


def test_successful_upload_response_missing_required_label_is_ambiguous(
    tmp_path: Path, api: Any, install_transport: Any
) -> None:
    source = tmp_path / "app.whl"
    source.write_bytes(b"wheel")
    descriptor = os.open(source, os.O_RDONLY)
    asset = plan().assets[0]
    verified = controller.VerifiedAsset(asset, descriptor, ())
    install_transport(
        FakeResponse(
            201,
            {
                "content_type": "application/octet-stream",
                "digest": f"sha256:{asset.sha256}",
                "id": 90,
                "name": asset.name,
                "size": asset.size,
                "state": "uploaded",
            },
        )
    )
    try:
        with pytest.raises(controller.AmbiguousMutationError):
            api.upload_asset(
                77,
                "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets"
                "{?name,label}",
                verified,
            )
    finally:
        os.close(descriptor)


def test_upload_read_failure_after_request_start_is_ambiguous(
    tmp_path: Path,
    api: Any,
    install_transport: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "app.whl"
    source.write_bytes(b"wheel")
    descriptor = os.open(source, os.O_RDONLY)
    verified = controller.VerifiedAsset(plan().assets[0], descriptor, ())
    transport = install_transport(FakeResponse(201, {"id": 90}))
    monkeypatch.setattr(
        adapter.os,
        "pread",
        lambda *_args: (_ for _ in ()).throw(OSError("contains-sensitive-path")),
    )

    try:
        with pytest.raises(controller.AmbiguousMutationError) as caught:
            api.upload_asset(
                77,
                "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets"
                "{?name,label}",
                verified,
            )
    finally:
        os.close(descriptor)

    assert transport.connections == 1
    assert transport.requests == []
    assert "contains-sensitive-path" not in str(caught.value)


def test_upload_502_is_ambiguous_and_never_retried_or_deleted(
    tmp_path: Path, api: Any, install_transport: Any
) -> None:
    source = tmp_path / "app.whl"
    source.write_bytes(b"wheel")
    descriptor = os.open(source, os.O_RDONLY)
    verified = controller.VerifiedAsset(plan().assets[0], descriptor, ())
    transport = install_transport(FakeResponse(502, {"message": "starter asset may remain"}))
    try:
        with pytest.raises(controller.AmbiguousMutationError):
            api.upload_asset(
                77,
                "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets"
                "{?name,label}",
                verified,
            )
    finally:
        os.close(descriptor)

    assert [(item.method, item.host) for item in transport.requests] == [
        ("POST", "uploads.github.com")
    ]


def test_controller_reconciles_create_upload_and_publish_502_without_retry(
    tmp_path: Path, install_transport: Any
) -> None:
    content = b"wheel"
    asset_path = tmp_path / "python" / "app.whl"
    asset_path.parent.mkdir()
    asset_path.write_bytes(content)
    manifest = {
        "assets": [
            {
                "name": "app.whl",
                "path": "python/app.whl",
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        ],
        "repository": REPOSITORY,
        "repository_id": 12345,
        "run_id": 998877,
        "schema_version": 1,
        "tag": "v0.1.0",
        "target_commit": COMMIT,
        "workflow_path": ".github/workflows/release.yml",
        "workflow_sha": "c" * 40,
    }
    manifest_sha256 = hashlib.sha256(controller.canonical_json(manifest)).hexdigest()
    release_plan = controller.validate_manifest(manifest, manifest_sha256)
    expected = controller.ExpectedIdentity(
        repository_id=release_plan.repository_id,
        repository=release_plan.repository,
        tag=release_plan.tag,
        target_commit=release_plan.target_commit,
        workflow_path=release_plan.workflow_path,
        workflow_sha=release_plan.workflow_sha,
        run_id=release_plan.run_id,
        manifest_sha256=release_plan.manifest_sha256,
    )
    draft = {
        "body": release_plan.marker,
        "draft": True,
        "id": 77,
        "immutable": False,
        "name": release_plan.tag,
        "prerelease": False,
        "tag_name": release_plan.tag,
        "target_commitish": release_plan.target_commit,
        "upload_url": (
            "https://uploads.github.com/repos/stampbot/extra-codeowners/releases/77/assets"
            "{?name,label}"
        ),
    }
    immutable = {**draft, "draft": False, "immutable": True}
    remote_asset = {
        "content_type": "application/octet-stream",
        "digest": f"sha256:{release_plan.assets[0].sha256}",
        "id": 91,
        "label": None,
        "name": "app.whl",
        "size": len(content),
        "state": "uploaded",
    }
    tag = {
        "ref": "refs/tags/v0.1.0",
        "object": {"sha": COMMIT, "type": "commit"},
    }
    transport = install_transport(
        FakeResponse(200, {"full_name": REPOSITORY, "id": 12345}),
        FakeResponse(200, tag),
        FakeResponse(200, []),
        FakeResponse(200, {"full_name": REPOSITORY, "id": 12345}),
        FakeResponse(502, {"message": "draft response lost"}),
        FakeResponse(200, {"full_name": REPOSITORY, "id": 12345}),
        FakeResponse(200, [draft]),
        FakeResponse(200, []),
        FakeResponse(200, {"full_name": REPOSITORY, "id": 12345}),
        FakeResponse(502, {"message": "starter asset may remain"}),
        FakeResponse(200, {"full_name": REPOSITORY, "id": 12345}),
        FakeResponse(200, [remote_asset]),
        FakeResponse(200, draft),
        FakeResponse(200, [remote_asset]),
        FakeResponse(200, tag),
        FakeResponse(200, {"full_name": REPOSITORY, "id": 12345}),
        FakeResponse(502, {"message": "publish response lost"}),
        FakeResponse(200, {"full_name": REPOSITORY, "id": 12345}),
        FakeResponse(200, immutable),
        FakeResponse(200, [remote_asset]),
        FakeResponse(200, tag),
    )
    release_api = adapter.GitHubReleaseAPI(token=TOKEN, repository=REPOSITORY)

    result = controller.reconcile_release(
        release_api,
        release_plan,
        tmp_path,
        expected=expected,
    )

    assert result == controller.ReleaseResult(77, "v0.1.0", True, resumed=True)
    mutations = [request for request in transport.requests if request.method in {"POST", "PATCH"}]
    assert [(request.host, request.method, request.path) for request in mutations] == [
        ("api.github.com", "POST", "/repos/stampbot/extra-codeowners/releases"),
        (
            "uploads.github.com",
            "POST",
            "/repos/stampbot/extra-codeowners/releases/77/assets?name=app.whl",
        ),
        ("api.github.com", "PATCH", "/repos/stampbot/extra-codeowners/releases/77"),
    ]
    assert all(request.method != "DELETE" for request in transport.requests)
    assert [(request.method, request.path) for request in transport.requests] == [
        ("GET", "/repos/stampbot/extra-codeowners"),
        ("GET", "/repos/stampbot/extra-codeowners/git/ref/tags/v0.1.0"),
        ("GET", "/repos/stampbot/extra-codeowners/releases?per_page=100&page=1"),
        ("GET", "/repos/stampbot/extra-codeowners"),
        ("POST", "/repos/stampbot/extra-codeowners/releases"),
        ("GET", "/repos/stampbot/extra-codeowners"),
        ("GET", "/repos/stampbot/extra-codeowners/releases?per_page=100&page=1"),
        ("GET", "/repos/stampbot/extra-codeowners/releases/77/assets?per_page=100&page=1"),
        ("GET", "/repos/stampbot/extra-codeowners"),
        ("POST", "/repos/stampbot/extra-codeowners/releases/77/assets?name=app.whl"),
        ("GET", "/repos/stampbot/extra-codeowners"),
        ("GET", "/repos/stampbot/extra-codeowners/releases/77/assets?per_page=100&page=1"),
        ("GET", "/repos/stampbot/extra-codeowners/releases/77"),
        ("GET", "/repos/stampbot/extra-codeowners/releases/77/assets?per_page=100&page=1"),
        ("GET", "/repos/stampbot/extra-codeowners/git/ref/tags/v0.1.0"),
        ("GET", "/repos/stampbot/extra-codeowners"),
        ("PATCH", "/repos/stampbot/extra-codeowners/releases/77"),
        ("GET", "/repos/stampbot/extra-codeowners"),
        ("GET", "/repos/stampbot/extra-codeowners/releases/77"),
        ("GET", "/repos/stampbot/extra-codeowners/releases/77/assets?per_page=100&page=1"),
        ("GET", "/repos/stampbot/extra-codeowners/git/ref/tags/v0.1.0"),
    ]
    assert transport.connections == transport.closed_connections == 21


@pytest.mark.parametrize(
    "raw",
    [
        b'{"id":77,"id":77}',
        b'{"id":77,"extra":1.5}',
        b'{"id":77,"extra":NaN}',
        b'{"id":77,"extra":9223372036854775808}',
        b"\xff",
    ],
    ids=["duplicate", "float", "nan", "integer", "utf8"],
)
def test_strict_json_fail_closed(api: Any, install_transport: Any, raw: bytes) -> None:
    install_transport(FakeResponse(200, raw=raw))

    with pytest.raises(controller.ControllerError):
        api.get_release(77)


@pytest.mark.parametrize("length", ["01", "not-a-number"])
def test_invalid_content_length_fails_an_otherwise_valid_response(
    api: Any, install_transport: Any, length: str
) -> None:
    install_transport(FakeResponse(200, raw=b'{"id":77}', headers={"Content-Length": length}))

    with pytest.raises(controller.ControllerError):
        api.get_release(77)


@pytest.mark.parametrize(
    ("setting", "bound", "raw"),
    [
        ("MAX_JSON_DEPTH", 3, b'{"id":77,"extra":[[[0]]]}'),
        ("MAX_JSON_ITEMS", 3, b'{"id":77,"extra":[]}'),
        ("MAX_RESPONSE_BYTES", 16, b'{"id":77,"padding":"123456"}'),
    ],
    ids=["depth", "items", "bytes"],
)
def test_json_depth_item_and_byte_bounds_fail_closed_independently(
    api: Any,
    install_transport: Any,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    bound: int,
    raw: bytes,
) -> None:
    monkeypatch.setattr(adapter, setting, bound)
    transport = install_transport(FakeResponse(200, raw=raw))

    with pytest.raises(controller.ControllerError):
        api.get_release(77)

    assert transport.connections == 1


def test_errors_repr_and_logs_never_expose_token_or_response_body(
    api: Any, install_transport: Any, caplog: pytest.LogCaptureFixture
) -> None:
    secret_body = f"server echoed Authorization: Bearer {TOKEN}"
    transport = install_transport(
        FakeResponse(
            500,
            raw=secret_body.encode(),
            headers={
                "Content-Type": "text/plain",
                "X-GitHub-Request-Id": "x" * (adapter.MAX_REQUEST_ID_BYTES + 1),
            },
        )
    )

    with pytest.raises(controller.AmbiguousMutationError) as caught:
        api.create_draft(plan())

    combined = str(caught.value) + repr(caught.value) + caplog.text + repr(api)
    assert TOKEN not in combined
    assert secret_body not in combined
    assert "request_id=unavailable" in str(caught.value)
    assert "repository='stampbot/extra-codeowners'" in repr(api)
    assert transport.connections == 1


@pytest.mark.parametrize(
    "token",
    ["", " token", "token ", "token\rheader", "token\nheader", "t\x00oken", "é", "x" * 4097],
)
def test_constructor_rejects_empty_unbounded_or_header_injection_tokens(token: str) -> None:
    with pytest.raises(controller.ControllerError) as caught:
        adapter.GitHubReleaseAPI(token=token, repository=REPOSITORY)

    assert repr(token) not in str(caught.value)


@pytest.mark.parametrize(
    "repository",
    [
        "../repository",
        "owner/..",
        "./repository",
        "owner/.",
        "owner/" + "r" * 101,
        "o" * 101 + "/repository",
    ],
)
def test_constructor_rejects_unsafe_or_unbounded_repository_components(
    repository: str,
) -> None:
    with pytest.raises(controller.ControllerError, match="repository name"):
        adapter.GitHubReleaseAPI(token=TOKEN, repository=repository)


def test_adapter_surface_has_no_delete_update_ref_cli_or_environment_lookup() -> None:
    public_methods = {
        name
        for name, value in vars(adapter.GitHubReleaseAPI).items()
        if callable(value) and not name.startswith("_")
    }
    source = Path(".github/scripts/github_release_api.py").read_text(encoding="utf-8")

    assert public_methods == {
        "create_draft",
        "get_release",
        "list_assets",
        "list_releases",
        "publish_release",
        "repository_id",
        "resolve_tag",
        "upload_asset",
    }
    for forbidden in (
        '"DELETE"',
        "delete_release",
        "delete_asset",
        "update_asset",
        "update_ref",
        "delete_ref",
        "os.environ",
        "os.getenv",
        "argparse",
        "def main(",
        "urlopen",
    ):
        assert forbidden not in source


def test_adapter_and_controller_remain_unwired_from_every_workflow() -> None:
    adapter_path = ".github/scripts/github_release_api.py"
    controller_path = ".github/scripts/release_controller.py"
    workflows = sorted(Path(".github/workflows").glob("*.y*ml"))
    assert workflows
    for workflow in workflows:
        executable_source = workflow.read_text(encoding="utf-8")
        assert f"python {adapter_path}" not in executable_source
        assert f"uv run python {adapter_path}" not in executable_source
        assert "import github_release_api" not in executable_source
        assert "from github_release_api" not in executable_source
        assert f"python {controller_path}" not in executable_source
        assert f"uv run {controller_path}" not in executable_source


def test_adapter_is_in_every_strict_typecheck_and_test_container() -> None:
    path = ".github/scripts/github_release_api.py"
    ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    mise = Path("mise.toml").read_text(encoding="utf-8")
    dockerignore = Path(".dockerignore").read_text(encoding="utf-8")
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    for checked_scope in (ci, release, mise):
        assert path in checked_scope
    assert f"!{path}" in dockerignore
    assert path in dockerfile


def test_no_workflow_imports_adapter_or_grants_new_publication_authority() -> None:
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    jobs = release.split("\n  publication-block:\n", 1)[1]

    assert "python .github/scripts/github_release_api.py" not in release
    assert "import github_release_api" not in release
    assert "from github_release_api" not in release
    assert "release_controller.py" in release  # type-check scope only
    assert "permissions: {}" in jobs.split("\n  python:\n", 1)[0]
    for job_name in ("python", "image", "chart", "release"):
        match = re.search(
            rf"(?ms)^  {job_name}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            release,
        )
        assert match is not None
        body = match.group("body")
        assert "      - publication-block\n" in body


def test_protocol_conformance_is_structural(api: Any) -> None:
    protocol = cast(type[Any], controller.ReleaseAPI)
    methods = {
        name
        for name, value in vars(protocol).items()
        if callable(value) and not name.startswith("_")
    }
    assert all(callable(getattr(api, name)) for name in methods)
