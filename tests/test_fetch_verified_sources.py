"""Hostile-network tests for the verified-source fetch boundary."""

from __future__ import annotations

import datetime
import hashlib
import http.client
import importlib.util
import json
import os
import socket
import ssl
import stat
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
STORE_SCRIPT = ROOT / ".github" / "scripts" / "verified_source_store.py"
FETCH_SCRIPT = ROOT / ".github" / "scripts" / "fetch_verified_sources.py"
PUBLIC_IP = "93.184.216.34"
SOURCE_REVISION = "1" * 40
POLICY_SHA256 = "2" * 64
UV_LOCK_SHA256 = "3" * 64


def load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


source_store: Any = load_script(STORE_SCRIPT, "verified_source_store")
fetcher: Any = load_script(FETCH_SCRIPT, "fetch_verified_sources_for_test")


@dataclass(frozen=True)
class RequestSpec:
    identifier: str
    content: bytes
    url: str = "https://downloads.example.test/source.bin"
    algorithm: str = "sha256"
    expected_size: bool = True
    max_bytes: int | None = None
    allowed_hosts: tuple[str, ...] = ("downloads.example.test",)


def request_record(spec: RequestSpec) -> dict[str, Any]:
    return {
        "id": spec.identifier,
        "url": spec.url,
        "allowed_hosts": list(spec.allowed_hosts),
        "algorithm": spec.algorithm,
        "digest": hashlib.new(spec.algorithm, spec.content).hexdigest(),
        "expected_size": len(spec.content) if spec.expected_size else None,
        "max_bytes": spec.max_bytes or max(1, len(spec.content) + 64),
        "consumers": [f"platform:linux/amd64:{spec.identifier}"],
    }


def plan_record(specs: tuple[RequestSpec, ...]) -> dict[str, Any]:
    return {
        "schema_version": source_store.SCHEMA_VERSION,
        "media_type": source_store.PLAN_MEDIA_TYPE,
        "kind": "direct",
        "evidence_schema_version": source_store.SUPPORTED_EVIDENCE_SCHEMA_VERSION,
        "source_revision": SOURCE_REVISION,
        "policy_sha256": POLICY_SHA256,
        "uv_lock_sha256": UV_LOCK_SHA256,
        "requests": [
            request_record(spec) for spec in sorted(specs, key=lambda item: item.identifier)
        ],
    }


def write_plan(tmp_path: Path, specs: tuple[RequestSpec, ...]) -> Path:
    path = tmp_path / "plan.json"
    path.write_bytes(source_store.canonical_json(plan_record(specs)))
    return path


def plan_binding(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "expected_plan_sha256": hashlib.sha256(content).hexdigest(),
        "expected_plan_size": len(content),
    }


def manifest_admission_bound(path: Path) -> int:
    content = path.read_bytes()
    plan = source_store.validate_source_plan(
        source_store.strict_json_bytes(
            content,
            "test source plan",
            maximum=source_store.MAX_PLAN_BYTES,
        )
    )
    return cast(
        int,
        fetcher.ManifestMetadataBudget(
            plan,
            limit=source_store.MAX_STORE_BYTES * 8,
        ).admission_upper_bound,
    )


class FakeResponse:
    def __init__(
        self,
        status: int,
        body: bytes = b"",
        *,
        headers: list[tuple[str, str]] | None = None,
        fail_after: int | None = None,
        read_error: BaseException | None = None,
        read_limit: int | None = None,
        after_read: Any = None,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = [("Content-Length", str(len(body)))] if headers is None else headers
        self.fail_after = fail_after
        self.read_error = read_error
        self.read_limit = read_limit
        self.after_read = after_read
        self.offset = 0
        self.closed = False

    def read(self, amount: int) -> bytes:
        if self.fail_after is not None and self.offset >= self.fail_after:
            raise self.read_error or ConnectionResetError(
                "simulated transport failure with secret details"
            )
        end = min(len(self.body), self.offset + amount)
        if self.read_limit is not None:
            end = min(end, self.offset + self.read_limit)
        if self.fail_after is not None:
            end = min(end, self.fail_after)
        chunk = self.body[self.offset : end]
        self.offset = end
        if self.after_read is not None:
            self.after_read()
        return chunk

    def getheader(self, name: str, default: str | None = None) -> str | None:
        values = [value for key, value in self.headers if key.lower() == name.lower()]
        return values[0] if values else default

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self.headers)

    def close(self) -> None:
        self.closed = True


@dataclass(frozen=True)
class PeerResponse:
    response: FakeResponse
    selected_ip: str = PUBLIC_IP
    peer_ip: str = PUBLIC_IP


class FakeNetwork:
    def __init__(
        self,
        outcomes: Sequence[FakeResponse | PeerResponse | BaseException],
    ) -> None:
        self.outcomes = list(outcomes)
        self.resolver_calls: list[str] = []
        self.open_calls: list[tuple[str, str, dict[str, str]]] = []
        self.connection_closes = 0

    def resolve(self, hostname: str) -> tuple[Any, ...]:
        self.resolver_calls.append(hostname)
        return (
            fetcher.ResolvedAddress(
                family=socket.AF_INET,
                socktype=socket.SOCK_STREAM,
                protocol=socket.IPPROTO_TCP,
                sockaddr=(PUBLIC_IP, 443),
                ip=PUBLIC_IP,
            ),
        )

    def open(
        self,
        url: str,
        address: Any,
        headers: Mapping[str, str],
    ) -> Any:
        self.open_calls.append((url, address.ip, dict(headers)))
        if not self.outcomes:
            raise AssertionError("fake network exhausted")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        selected = outcome if isinstance(outcome, PeerResponse) else PeerResponse(outcome)
        return fetcher.OpenedResponse(
            response=selected.response,
            selected_ip=selected.selected_ip,
            peer_ip=selected.peer_ip,
            close_connection=self._close_connection,
        )

    def _close_connection(self) -> None:
        self.connection_closes += 1


@dataclass
class FakeClock:
    value: float = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, amount: float) -> None:
        self.value += amount


def read_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_bytes()))


def write_local_tls_chain(tmp_path: Path, hostname: str) -> tuple[Path, Path, Path]:
    """Create a short-lived test CA and one server certificate for hostname."""

    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "extra-codeowners test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = tmp_path / "test-ca.pem"
    certificate_path = tmp_path / "server.pem"
    key_path = tmp_path / "server-key.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(server_certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, certificate_path, key_path


def run_fetch(
    tmp_path: Path,
    plan_path: Path,
    network: FakeNetwork,
    *,
    name: str = "store",
    sleeper: Any = lambda _delay: None,
    clock: Any = fetcher.time.monotonic,
) -> tuple[Path, Path, dict[str, Any]]:
    output = tmp_path / name
    journal = tmp_path / f"{name}.journal.json"
    result = fetcher.fetch_source_plan(
        plan_path,
        output,
        journal,
        **plan_binding(plan_path),
        resolver=network.resolve,
        opener=network.open,
        sleeper=sleeper,
        clock=clock,
    )
    return output, journal, result


def assert_private_tree(root: Path) -> None:
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    for path in root.rglob("*"):
        expected = 0o700 if path.is_dir() else 0o600
        assert stat.S_IMODE(path.stat().st_mode) == expected


def test_attempt_deadline_fits_the_largest_object_and_outer_timeout() -> None:
    transfer_seconds = source_store.MAX_OBJECT_BYTES / fetcher.MINIMUM_TRANSFER_BYTES_PER_SECOND
    retry_delays = sum(1 << (attempt - 1) for attempt in range(1, source_store.MAX_ATTEMPTS))
    outer_timeout_seconds = 30 * 60

    assert transfer_seconds == 256
    assert fetcher.ATTEMPT_TIMEOUT_SECONDS == 300
    assert fetcher.ATTEMPT_TIMEOUT_SECONDS - transfer_seconds == 44
    assert (
        fetcher.ATTEMPT_TIMEOUT_SECONDS + fetcher.CONNECT_TIMEOUT_SECONDS
    ) * source_store.MAX_ATTEMPTS + retry_delays < outer_timeout_seconds


def test_fetches_verifies_and_atomically_publishes_a_private_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"verified source bytes"
    secret = "must-not-enter-the-journal"
    spec = RequestSpec(
        "source:demo",
        content,
        url=f"https://downloads.example.test/source.bin?token={secret}",
    )
    plan_path = write_plan(tmp_path, (spec,))
    response = FakeResponse(200, content)
    network = FakeNetwork([response])
    verifier_calls: list[dict[str, Any]] = []
    real_verifier = source_store.verify_source_store

    def record_verifier(root: Path, **kwargs: Any) -> dict[str, Any]:
        verifier_calls.append(kwargs)
        return cast(dict[str, Any], real_verifier(root, **kwargs))

    monkeypatch.setattr(fetcher.verified_source_store, "verify_source_store", record_verifier)
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "socks5://attacker.invalid:1080")

    output, journal_path, result = run_fetch(tmp_path, plan_path, network)

    plan_bytes = plan_path.read_bytes()
    assert result == real_verifier(output, **plan_binding(plan_path))
    assert verifier_calls == [
        {
            "expected_plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "expected_plan_size": len(plan_bytes),
        },
        {
            "expected_plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "expected_plan_size": len(plan_bytes),
        },
    ]
    assert result["request_count"] == 1
    digest = hashlib.sha256(content).hexdigest()
    assert (output / "objects" / "sha256" / digest).read_bytes() == content
    assert_private_tree(output)
    assert response.closed
    assert network.connection_closes == 1
    assert network.resolver_calls == ["downloads.example.test"]
    assert len(network.open_calls) == 1
    sent_headers = network.open_calls[0][2]
    assert sent_headers == {
        "Accept": "application/octet-stream",
        "Accept-Encoding": "identity",
        "Connection": "close",
        "User-Agent": fetcher.USER_AGENT,
    }
    assert all(
        forbidden not in key.lower()
        for key in sent_headers
        for forbidden in ("authorization", "cookie", "proxy")
    )

    journal_bytes = journal_path.read_bytes()
    journal = read_json(journal_path)
    assert journal_bytes == source_store.canonical_json(journal)
    assert journal["status"] == "succeeded"
    assert journal["error"] is None
    assert secret.encode() not in journal_bytes
    attempt = journal["requests"][0]["attempts"][0]
    assert attempt["redirect_origins"] == ["https://downloads.example.test/"]
    assert attempt["hops"][0]["resolved_addresses"] == [PUBLIC_IP]
    assert attempt["hops"][0]["peer_address"] == PUBLIC_IP
    assert not list(tmp_path.glob(".source-fetch-*"))
    assert not list(tmp_path.glob(".verified-source-store-*"))


def test_sha256_and_sha512_requests_deduplicate_the_cas_object(tmp_path: Path) -> None:
    content = b"same bytes under two trusted digest algorithms"
    specs = (
        RequestSpec("source:a-sha256", content),
        RequestSpec(
            "source:b-sha512",
            content,
            url="https://mirror.example.test/source.bin",
            algorithm="sha512",
            expected_size=False,
            allowed_hosts=("mirror.example.test",),
        ),
    )
    plan_path = write_plan(tmp_path, specs)
    network = FakeNetwork([FakeResponse(200, content), FakeResponse(200, content)])

    output, _journal, result = run_fetch(tmp_path, plan_path, network)

    manifest = read_json(output / source_store.STORE_FILENAME)
    assert result["request_count"] == 2
    assert result["object_count"] == 1
    assert len(manifest["objects"]) == 1
    assert [item["algorithm"] for item in manifest["results"]] == ["sha256", "sha512"]
    assert len(list((output / "objects" / "sha256").iterdir())) == 1


def test_rejects_noncanonical_plan_without_network_or_partial_output(tmp_path: Path) -> None:
    spec = RequestSpec("source:demo", b"content")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan_record((spec,)), indent=2))
    network = FakeNetwork([])
    output = tmp_path / "store"
    journal = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="invalid-source-plan"):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert not output.exists()
    assert not journal.exists()
    assert network.resolver_calls == []


@pytest.mark.parametrize("binding_field", ["expected_plan_sha256", "expected_plan_size"])
def test_rejects_untrusted_plan_binding_before_network_or_output(
    tmp_path: Path,
    binding_field: str,
) -> None:
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", b"content"),))
    binding = plan_binding(plan_path)
    binding[binding_field] = (
        "0" * 64
        if binding_field == "expected_plan_sha256"
        else cast(int, binding["expected_plan_size"]) + 1
    )
    network = FakeNetwork([])
    output = tmp_path / "store"
    journal = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="source-plan-binding-mismatch"):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal,
            **binding,
            resolver=network.resolve,
            opener=network.open,
        )

    assert network.resolver_calls == []
    assert not output.exists()
    assert not journal.exists()


def test_rejects_a_manifest_unrepresentable_plan_before_network_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path = write_plan(
        tmp_path,
        (RequestSpec("source:demo", b"content"),),
    )
    monkeypatch.setattr(
        source_store,
        "MAX_STORE_BYTES",
        manifest_admission_bound(plan_path) - 1,
    )
    network = FakeNetwork([])
    output = tmp_path / "store"
    journal = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="source-store-manifest-admission-limit"):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert network.resolver_calls == []
    assert network.open_calls == []
    assert not output.exists()
    assert not journal.exists()


def test_refuses_an_existing_output_before_network_access(tmp_path: Path) -> None:
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", b"content"),))
    output = tmp_path / "store"
    output.mkdir()
    sentinel = output / "owned-by-another-process"
    sentinel.write_text("untouched")
    network = FakeNetwork([])

    with pytest.raises(fetcher.FetchError, match="output-already-exists"):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            tmp_path / "journal.json",
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert sentinel.read_text() == "untouched"
    assert network.resolver_calls == []


@pytest.mark.parametrize(
    "reason",
    [
        "dns-non-public-address",
        "dns-scoped-address",
        "dns-answer-count",
    ],
)
def test_dns_policy_failures_are_terminal_and_audited(
    tmp_path: Path,
    reason: str,
) -> None:
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", b"content"),))
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"

    def reject_dns(_hostname: str) -> tuple[Any, ...]:
        raise fetcher.FetchError(reason)

    with pytest.raises(fetcher.FetchError, match=reason):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=reject_dns,
            opener=FakeNetwork([]).open,
        )

    assert not output.exists()
    journal = read_json(journal_path)
    assert journal["status"] == "failed"
    assert journal["error"] == reason
    attempts = journal["requests"][0]["attempts"]
    assert len(attempts) == 1
    assert attempts[0]["outcome"] == "terminal_failure"
    assert attempts[0]["hops"][0]["origin"] == "https://downloads.example.test/"


def test_real_resolver_rejects_private_mixed_and_scoped_answer_sets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_IP, 443))
    private = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("127.0.0.1", 443),
    )
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [record, private])
    with pytest.raises(fetcher.FetchError, match="dns-non-public-address"):
        fetcher._resolve_public_addresses("downloads.example.test")

    multicast = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("224.0.0.1", 443),
    )
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [multicast])
    with pytest.raises(fetcher.FetchError, match="dns-non-public-address"):
        fetcher._resolve_public_addresses("downloads.example.test")

    scoped = (
        socket.AF_INET6,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("2606:4700:4700::1111", 443, 0, 2),
    )
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [scoped])
    with pytest.raises(fetcher.FetchError, match="dns-scoped-address"):
        fetcher._resolve_public_addresses("downloads.example.test")


def test_real_resolver_distinguishes_permanent_dns_failure_from_retryable_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def permanent(*_args: Any, **_kwargs: Any) -> Any:
        raise socket.gaierror(socket.EAI_NONAME, "secret resolver detail")

    monkeypatch.setattr(socket, "getaddrinfo", permanent)
    with pytest.raises(fetcher.FetchError, match="dns-resolution-failure"):
        fetcher._resolve_public_addresses("downloads.example.test")

    def transient(*_args: Any, **_kwargs: Any) -> Any:
        raise socket.gaierror(socket.EAI_AGAIN, "secret resolver detail")

    monkeypatch.setattr(socket, "getaddrinfo", transient)
    with pytest.raises(fetcher.FetchError, match="dns-transport-failure"):
        fetcher._resolve_public_addresses("downloads.example.test")


def test_peer_mismatch_is_terminal_and_records_attempted_address(tmp_path: Path) -> None:
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", b"content"),))
    response = FakeResponse(200, b"content")
    network = FakeNetwork([PeerResponse(response, selected_ip=PUBLIC_IP, peer_ip="8.8.8.8")])
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="peer-address-mismatch"):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert not output.exists()
    assert response.closed
    hop = read_json(journal_path)["requests"][0]["attempts"][0]["hops"][0]
    assert hop["resolved_addresses"] == [PUBLIC_IP]
    assert hop["attempted_addresses"] == [PUBLIC_IP]
    assert hop["selected_address"] == PUBLIC_IP
    assert hop["peer_address"] == "8.8.8.8"


def test_tls_context_ignores_ambient_key_logging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keylog = tmp_path / "tls-secrets.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    for variable in fetcher.TLS_TRUST_OVERRIDE_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    address = fetcher.ResolvedAddress(
        family=socket.AF_INET,
        socktype=socket.SOCK_STREAM,
        protocol=socket.IPPROTO_TCP,
        sockaddr=(PUBLIC_IP, 443),
        ip=PUBLIC_IP,
    )

    connection = fetcher._PinnedHTTPSConnection("downloads.example.test", address)
    try:
        assert connection._ssl_context.keylog_filename is None
        assert connection._ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert connection._ssl_context.check_hostname is True
        assert connection._ssl_context.minimum_version >= ssl.TLSVersion.TLSv1_2
        assert not keylog.exists()
    finally:
        connection.close()


@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_tls_context_rejects_ambient_trust_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
) -> None:
    monkeypatch.setenv(variable, str(tmp_path / "untrusted"))
    other = (set(fetcher.TLS_TRUST_OVERRIDE_VARIABLES) - {variable}).pop()
    monkeypatch.delenv(other, raising=False)
    address = fetcher.ResolvedAddress(
        family=socket.AF_INET,
        socktype=socket.SOCK_STREAM,
        protocol=socket.IPPROTO_TCP,
        sockaddr=(PUBLIC_IP, 443),
        ip=PUBLIC_IP,
    )

    with pytest.raises(fetcher.FetchError, match="ambient-tls-trust-override"):
        fetcher._PinnedHTTPSConnection("downloads.example.test", address)


def test_concrete_pinned_opener_authenticates_local_tls_and_sends_sni(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostname = "downloads.example.test"
    content = b"locally authenticated source bytes"
    ca_path, certificate_path, key_path = write_local_tls_chain(tmp_path, hostname)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    port = cast(tuple[str, int], listener.getsockname())[1]

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(certificate_path, key_path)
    observed_sni: list[str | None] = []
    observed_requests: list[bytes] = []
    server_errors: list[Exception] = []
    server_context.set_servername_callback(
        lambda _socket, server_name, _context: observed_sni.append(server_name)
    )

    def serve_once() -> None:
        try:
            raw, _peer = listener.accept()
            with raw:
                raw.settimeout(3)
                with server_context.wrap_socket(raw, server_side=True) as secured:
                    request = b""
                    while b"\r\n\r\n" not in request and len(request) < 64 * 1024:
                        chunk = secured.recv(4096)
                        if not chunk:
                            break
                        request += chunk
                    observed_requests.append(request)
                    secured.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(content)}\r\n".encode("ascii")
                        + b"Content-Type: application/octet-stream\r\n"
                        + b"Connection: close\r\n\r\n"
                        + content
                    )
        except Exception as exc:
            server_errors.append(exc)

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()

    monkeypatch.setattr(
        fetcher.ssl,
        "get_default_verify_paths",
        lambda: SimpleNamespace(cafile=str(ca_path), capath=None),
    )
    for variable in fetcher.TLS_TRUST_OVERRIDE_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    address = fetcher.ResolvedAddress(
        family=socket.AF_INET,
        socktype=socket.SOCK_STREAM,
        protocol=socket.IPPROTO_TCP,
        sockaddr=("127.0.0.1", port),
        ip="127.0.0.1",
    )

    opened = None
    try:
        opened = fetcher._open_pinned_response(
            f"https://{hostname}/signed/path?token=local-test",
            address,
            {
                "Accept": "application/octet-stream",
                "Connection": "close",
            },
        )
        assert opened.response.status == 200
        assert opened.response.read(len(content) + 1) == content
        assert opened.selected_ip == "127.0.0.1"
        assert opened.peer_ip == "127.0.0.1"
    finally:
        if opened is not None:
            opened.close()
        thread.join(timeout=4)
        listener.close()

    assert not thread.is_alive()
    assert server_errors == []
    assert observed_sni == [hostname]
    assert len(observed_requests) == 1
    assert observed_requests[0].startswith(b"GET /signed/path?token=local-test HTTP/1.1\r\n")
    assert f"\r\nHost: {hostname}\r\n".encode() in observed_requests[0]


@pytest.mark.parametrize(
    "failure",
    [
        ssl.SSLError("certificate verification failed: secret"),
        OSError("unexpected local network failure: secret"),
    ],
)
def test_tls_and_unclassified_network_failures_are_terminal(
    tmp_path: Path,
    failure: BaseException,
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))
    network = FakeNetwork([failure, FakeResponse(200, content)])
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"
    delays: list[float] = []

    with pytest.raises(fetcher.FetchError):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
            sleeper=delays.append,
        )

    assert not output.exists()
    assert len(network.open_calls) == 1
    assert delays == []
    journal = read_json(journal_path)
    attempt = journal["requests"][0]["attempts"][0]
    assert attempt["outcome"] == "terminal_failure"
    expected = "tls-failure" if isinstance(failure, ssl.SSLError) else "network-io-failure"
    assert journal["error"] == expected
    assert b"secret" not in journal_path.read_bytes()


def test_tls_record_failure_during_body_stream_is_terminal(tmp_path: Path) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))
    network = FakeNetwork(
        [
            FakeResponse(
                200,
                content,
                fail_after=0,
                read_error=ssl.SSLError("bad TLS record with secret details"),
            ),
            FakeResponse(200, content),
        ]
    )
    journal_path = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="tls-failure"):
        fetcher.fetch_source_plan(
            plan_path,
            tmp_path / "store",
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert len(network.open_calls) == 1
    assert read_json(journal_path)["requests"][0]["attempts"][0]["outcome"] == ("terminal_failure")
    assert b"secret" not in journal_path.read_bytes()


def test_follows_only_allowlisted_https_redirects_and_redacts_the_journal(
    tmp_path: Path,
) -> None:
    content = b"redirected content"
    first_secret = "first-secret"
    second_secret = "second-secret"
    spec = RequestSpec(
        "source:redirect",
        content,
        url=f"https://downloads.example.test/start?token={first_secret}",
        allowed_hosts=("downloads.example.test", "mirror.example.test"),
    )
    plan_path = write_plan(tmp_path, (spec,))
    network = FakeNetwork(
        [
            FakeResponse(
                302,
                headers=[
                    (
                        "Location",
                        f"https://mirror.example.test/final?token={second_secret}",
                    )
                ],
            ),
            FakeResponse(200, content),
        ]
    )

    output, journal_path, _result = run_fetch(tmp_path, plan_path, network)

    manifest_path = output / source_store.STORE_FILENAME
    manifest_bytes = manifest_path.read_bytes()
    manifest = read_json(manifest_path)
    result = manifest["results"][0]
    assert result["request_origin"] == "https://downloads.example.test/"
    assert result["redirect_origins"] == [
        "https://downloads.example.test/",
        "https://mirror.example.test/",
    ]
    assert result["attempts"][-1]["redirect_origins"] == [
        "https://downloads.example.test/",
        "https://mirror.example.test/",
    ]
    journal_bytes = journal_path.read_bytes()
    plan_bytes = (output / source_store.PLAN_FILENAME).read_bytes()
    assert first_secret.encode() not in manifest_bytes
    assert second_secret.encode() not in manifest_bytes
    assert first_secret.encode() not in journal_bytes
    assert second_secret.encode() not in journal_bytes
    assert first_secret.encode() in plan_bytes
    assert second_secret.encode() not in plan_bytes
    attempt = read_json(journal_path)["requests"][0]["attempts"][0]
    assert attempt["redirect_origins"] == [
        "https://downloads.example.test/",
        "https://mirror.example.test/",
    ]
    assert attempt["hops"][0]["origin"] == "https://downloads.example.test/"
    assert attempt["hops"][0]["redirect_origin"] == "https://mirror.example.test/"
    assert attempt["hops"][1]["origin"] == "https://mirror.example.test/"
    assert attempt["hops"][1]["redirect_origin"] is None
    assert network.resolver_calls == [
        "downloads.example.test",
        "mirror.example.test",
    ]


def test_manifest_budget_stops_before_an_unrepresentable_redirect_hop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:redirect", content),))
    monkeypatch.setattr(
        source_store,
        "MAX_STORE_BYTES",
        manifest_admission_bound(plan_path),
    )
    network = FakeNetwork(
        [
            FakeResponse(302, headers=[("Location", "/redirected")]),
            FakeResponse(200, content),
        ]
    )
    journal_path = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="source-store-manifest-runtime-limit"):
        fetcher.fetch_source_plan(
            plan_path,
            tmp_path / "store",
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert network.resolver_calls == ["downloads.example.test"]
    assert len(network.open_calls) == 1
    assert read_json(journal_path)["error"] == "source-store-manifest-runtime-limit"
    assert not (tmp_path / "store").exists()


@pytest.mark.parametrize(
    "location",
    [
        "http://downloads.example.test/insecure",
        "https://evil.example.test/not-allowlisted",
        "https://downloads.example.test/start",
        "https://downloads.example.test:444/wrong-port",
        "https://user:password@downloads.example.test/credentials",
        "https://[::1",
        "//[bad",
    ],
)
def test_rejects_unsafe_redirects_without_publishing(
    tmp_path: Path,
    location: str,
) -> None:
    spec = RequestSpec(
        "source:redirect",
        b"content",
        url="https://downloads.example.test/start",
    )
    plan_path = write_plan(tmp_path, (spec,))
    network = FakeNetwork([FakeResponse(302, headers=[("Location", location)])])
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert not output.exists()
    attempt = read_json(journal_path)["requests"][0]["attempts"][0]
    assert attempt["outcome"] == "terminal_failure"
    assert len(attempt["hops"]) == 1


def test_rejects_more_than_five_redirects(tmp_path: Path) -> None:
    spec = RequestSpec(
        "source:redirect",
        b"content",
        url="https://downloads.example.test/0",
    )
    plan_path = write_plan(tmp_path, (spec,))
    redirects = [FakeResponse(302, headers=[("Location", f"/{index}")]) for index in range(1, 7)]
    network = FakeNetwork(redirects)
    journal_path = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="redirect-limit-or-loop"):
        fetcher.fetch_source_plan(
            plan_path,
            tmp_path / "store",
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    attempt = read_json(journal_path)["requests"][0]["attempts"][0]
    assert len(attempt["hops"]) == 6
    assert len(network.open_calls) == 6


def test_retries_http_and_partial_body_transport_then_freezes_evidence(
    tmp_path: Path,
) -> None:
    content = b"eventually complete content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:retry", content),))
    delays: list[float] = []
    network = FakeNetwork(
        [
            FakeResponse(503, headers=[("Retry-After", "0")]),
            FakeResponse(200, content, fail_after=5),
            FakeResponse(200, content),
        ]
    )

    output, journal_path, _result = run_fetch(
        tmp_path,
        plan_path,
        network,
        sleeper=delays.append,
    )

    assert delays == [0.0, 2.0]
    manifest = read_json(output / source_store.STORE_FILENAME)
    attempts = manifest["results"][0]["attempts"]
    assert [attempt["outcome"] for attempt in attempts] == [
        "retryable_http",
        "retryable_transport",
        "success",
    ]
    assert [attempt["retry_delay_seconds"] for attempt in attempts] == [0, 2, None]
    assert attempts[1]["received_size"] == 5
    assert attempts[1]["sha256"] == hashlib.sha256(content[:5]).hexdigest()
    journal_attempts = read_json(journal_path)["requests"][0]["attempts"]
    assert len(journal_attempts) == 3
    assert journal_attempts[1]["hops"][0]["http_status"] == 200


def test_manifest_budget_stops_before_an_unrepresentable_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:retry", content),))
    monkeypatch.setattr(
        source_store,
        "MAX_STORE_BYTES",
        manifest_admission_bound(plan_path),
    )
    network = FakeNetwork([FakeResponse(503), FakeResponse(200, content)])
    delays: list[float] = []
    journal_path = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="source-store-manifest-runtime-limit"):
        fetcher.fetch_source_plan(
            plan_path,
            tmp_path / "store",
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
            sleeper=delays.append,
        )

    assert network.resolver_calls == ["downloads.example.test"]
    assert len(network.open_calls) == 1
    assert delays == []
    journal = read_json(journal_path)
    assert journal["error"] == "source-store-manifest-runtime-limit"
    assert len(journal["requests"][0]["attempts"]) == 1
    assert not (tmp_path / "store").exists()


def test_ignores_an_overlong_retry_after_without_losing_retry_bounds(
    tmp_path: Path,
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:retry-after", content),))
    delays: list[float] = []
    network = FakeNetwork(
        [
            FakeResponse(503, headers=[("Retry-After", "9" * 5_000)]),
            FakeResponse(200, content),
        ]
    )

    output, journal_path, _result = run_fetch(
        tmp_path,
        plan_path,
        network,
        sleeper=delays.append,
    )

    assert delays == [1.0]
    attempts = read_json(output / source_store.STORE_FILENAME)["results"][0]["attempts"]
    assert [attempt["outcome"] for attempt in attempts] == ["retryable_http", "success"]
    assert read_json(journal_path)["status"] == "succeeded"


def test_incomplete_read_partial_bytes_are_charged_and_frozen(tmp_path: Path) -> None:
    content = b"eventually complete content"
    partial = content[:6]
    plan_path = write_plan(tmp_path, (RequestSpec("source:retry", content),))
    network = FakeNetwork(
        [
            FakeResponse(
                200,
                content,
                fail_after=0,
                read_error=http.client.IncompleteRead(partial, len(content) - len(partial)),
            ),
            FakeResponse(200, content),
        ]
    )

    output, _journal, _result = run_fetch(tmp_path, plan_path, network)

    attempt = read_json(output / source_store.STORE_FILENAME)["results"][0]["attempts"][0]
    assert attempt["outcome"] == "retryable_transport"
    assert attempt["received_size"] == len(partial)
    assert attempt["sha256"] == hashlib.sha256(partial).hexdigest()


def test_slow_drip_attempt_hits_monotonic_deadline_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"slow-drip-content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:slow", content),))
    clock = FakeClock()
    delays: list[float] = []
    network = FakeNetwork(
        [
            FakeResponse(
                200,
                content,
                read_limit=1,
                after_read=lambda: clock.advance(1),
            ),
            FakeResponse(200, content),
        ]
    )
    monkeypatch.setattr(fetcher, "ATTEMPT_TIMEOUT_SECONDS", 3.0)

    output, journal_path, _result = run_fetch(
        tmp_path,
        plan_path,
        network,
        sleeper=delays.append,
        clock=clock,
    )

    attempts = read_json(output / source_store.STORE_FILENAME)["results"][0]["attempts"]
    assert [attempt["outcome"] for attempt in attempts] == [
        "retryable_transport",
        "success",
    ]
    assert attempts[0]["received_size"] == 3
    assert attempts[0]["sha256"] == hashlib.sha256(content[:3]).hexdigest()
    assert attempts[0]["retry_delay_seconds"] == 1
    assert delays == [1.0]
    journal_attempt = read_json(journal_path)["requests"][0]["attempts"][0]
    assert journal_attempt["reason"] == "attempt-deadline-exceeded"


def test_transport_attempts_are_bounded_and_exhaustion_never_publishes(
    tmp_path: Path,
) -> None:
    plan_path = write_plan(tmp_path, (RequestSpec("source:retry", b"content"),))
    network = FakeNetwork([ConnectionResetError("secret endpoint") for _ in range(4)])
    delays: list[float] = []
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"

    with pytest.raises(fetcher.FetchError, match="connection-transport-failure-exhausted"):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
            sleeper=delays.append,
        )

    assert not output.exists()
    assert delays == [1.0, 2.0, 4.0]
    journal = read_json(journal_path)
    assert journal["status"] == "failed"
    assert journal["error"] == "connection-transport-failure-exhausted"
    attempts = journal["requests"][0]["attempts"]
    assert len(attempts) == 4
    assert [attempt["number"] for attempt in attempts] == [1, 2, 3, 4]
    assert attempts[-1]["outcome"] == "attempts_exhausted"
    assert attempts[-1]["retry_delay_seconds"] is None
    assert b"secret endpoint" not in journal_path.read_bytes()


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (
            FakeResponse(
                200,
                b"short",
                headers=[("Content-Length", "10")],
            ),
            "content-length-mismatch",
        ),
        (
            FakeResponse(
                200,
                b"content",
                headers=[("Content-Encoding", "gzip")],
            ),
            "encoded-response",
        ),
        (
            FakeResponse(
                200,
                b"content",
                headers=[
                    ("Content-Length", "7"),
                    ("Transfer-Encoding", "chunked"),
                ],
            ),
            "invalid-response-framing",
        ),
        (
            FakeResponse(
                200,
                b"content",
                headers=[("Content-Length", "9" * 5_000)],
            ),
            "invalid-content-length",
        ),
        (FakeResponse(200, b"wrong!!"), "expected-digest-mismatch"),
    ],
)
def test_response_framing_size_and_digest_fail_closed(
    tmp_path: Path,
    response: FakeResponse,
    reason: str,
) -> None:
    expected = b"content"
    plan_path = write_plan(
        tmp_path,
        (RequestSpec("source:demo", expected, expected_size=False),),
    )
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"
    network = FakeNetwork([response])

    with pytest.raises(fetcher.FetchError, match=reason):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert not output.exists()
    journal = read_json(journal_path)
    assert journal["error"] == reason
    assert journal["requests"][0]["attempts"][0]["outcome"] == "terminal_failure"
    assert not list(tmp_path.glob(".verified-source-store-*"))


def test_terminal_stream_failure_unlinks_its_private_temporary_file(
    tmp_path: Path,
) -> None:
    object_directory = tmp_path / "objects"
    object_directory.mkdir(mode=0o700)
    descriptor = os.open(object_directory, os.O_RDONLY | os.O_DIRECTORY)
    request = cast(
        Any,
        source_store.validate_source_plan(
            plan_record((RequestSpec("source:demo", b"expected", expected_size=False),))
        )["requests"][0],
    )
    try:
        with pytest.raises(fetcher.FetchError, match="expected-digest-mismatch"):
            fetcher._stream_response(
                FakeResponse(200, b"wrong"),
                request=request,
                directory=descriptor,
                budget=fetcher.TransferBudget(),
                deadline=60.0,
                clock=FakeClock(),
            )
        assert list(object_directory.iterdir()) == []
    finally:
        os.close(descriptor)


def test_declared_body_cannot_cross_aggregate_transfer_budget(tmp_path: Path) -> None:
    content = b"five"
    object_directory = tmp_path / "objects"
    object_directory.mkdir(mode=0o700)
    descriptor = os.open(object_directory, os.O_RDONLY | os.O_DIRECTORY)
    request = cast(
        Any,
        source_store.validate_source_plan(
            plan_record((RequestSpec("source:demo", content, expected_size=False),))
        )["requests"][0],
    )
    response = FakeResponse(200, content)
    try:
        with pytest.raises(fetcher.FetchError, match="aggregate-transfer-limit"):
            fetcher._stream_response(
                response,
                request=request,
                directory=descriptor,
                budget=fetcher.TransferBudget(limit=len(content) - 1),
                deadline=60.0,
                clock=FakeClock(),
            )
        assert response.offset == 0
        assert list(object_directory.iterdir()) == []
    finally:
        os.close(descriptor)


def test_publication_race_does_not_replace_the_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))
    network = FakeNetwork([FakeResponse(200, content)])
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"

    def lose_race(parent: int, _source: str, destination: str) -> None:
        os.mkdir(destination, dir_fd=parent)
        descriptor = os.open(
            destination,
            os.O_RDONLY | os.O_DIRECTORY,
            dir_fd=parent,
        )
        try:
            os.mkdir("winner", dir_fd=descriptor)
        finally:
            os.close(descriptor)
        raise fetcher.FetchError("output-publication-race")

    monkeypatch.setattr(fetcher, "_rename_noreplace", lose_race)

    with pytest.raises(fetcher.FetchError, match="output-publication-race"):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert (output / "winner").is_dir()
    assert list(output.iterdir()) == [output / "winner"]
    journal = read_json(journal_path)
    assert journal["status"] == "failed"
    assert journal["error"] == "output-publication-race"
    assert not list(tmp_path.glob(".verified-source-store-*"))


def test_rejects_a_store_mutated_between_staging_verification_and_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"content that must still match after publication"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"
    real_verifier = source_store.verify_source_store
    verifier_calls = 0
    network = FakeNetwork([FakeResponse(200, content)])

    def mutate_after_staging_check(root: Path, **kwargs: Any) -> dict[str, Any]:
        nonlocal verifier_calls
        verifier_calls += 1
        result = cast(dict[str, Any], real_verifier(root, **kwargs))
        if verifier_calls == 1:
            object_path = next((Path(root) / "objects" / "sha256").iterdir())
            object_path.write_bytes(b"x" * object_path.stat().st_size)
        return result

    monkeypatch.setattr(
        fetcher.verified_source_store,
        "verify_source_store",
        mutate_after_staging_check,
    )

    with pytest.raises(
        fetcher.FetchError,
        match="published-store-verification-failure",
    ):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    assert verifier_calls == 2
    assert output.is_dir()
    assert read_json(journal_path)["status"] == "failed"
    with pytest.raises(source_store.SourceStoreError, match="wrong SHA-256"):
        real_verifier(output, **plan_binding(plan_path))


def test_rejects_a_persistently_replaced_output_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"
    detached_parent = tmp_path.with_name(f"{tmp_path.name}-detached")
    real_rename = fetcher._rename_noreplace
    network = FakeNetwork([FakeResponse(200, content)])

    def replace_parent(parent: int, source: str, destination: str) -> None:
        os.rename(tmp_path, detached_parent)
        tmp_path.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        (output / "attacker-marker").write_bytes(b"not the verified store")
        real_rename(parent, source, destination)

    monkeypatch.setattr(fetcher, "_rename_noreplace", replace_parent)

    try:
        with pytest.raises(fetcher.FetchError, match="output-parent-changed"):
            fetcher.fetch_source_plan(
                plan_path,
                output,
                journal_path,
                **plan_binding(plan_path),
                resolver=network.resolve,
                opener=network.open,
            )

        assert (output / "attacker-marker").read_bytes() == b"not the verified store"
        assert (detached_parent / "store" / source_store.PLAN_FILENAME).is_file()
        assert read_json(journal_path)["status"] == "failed"
    finally:
        if detached_parent.exists():
            if (output / "attacker-marker").exists():
                (output / "attacker-marker").unlink()
            if output.exists():
                output.rmdir()
            if journal_path.exists():
                journal_path.unlink()
            tmp_path.rmdir()
            os.rename(detached_parent, tmp_path)


def test_fetcher_documents_mutable_path_and_outer_timeout_boundaries() -> None:
    module_documentation = fetcher.__doc__
    function_documentation = fetcher.fetch_source_plan.__doc__

    assert module_documentation is not None
    assert function_documentation is not None
    for documentation in (module_documentation, function_documentation):
        assert "private" in documentation
        assert "process-level timeout" in documentation
        assert "point-in-time" in documentation
        assert "read-only" in documentation


def test_staging_cleanup_never_deletes_a_replacement_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))
    output = tmp_path / "store"
    journal_path = tmp_path / "journal.json"
    network = FakeNetwork([FakeResponse(200, content)])

    def replace_staging(parent: int, source: str, _destination: str) -> None:
        os.rename(
            source,
            "detached-original",
            src_dir_fd=parent,
            dst_dir_fd=parent,
        )
        os.mkdir(source, 0o700, dir_fd=parent)
        replacement = os.open(
            source,
            os.O_RDONLY | os.O_DIRECTORY,
            dir_fd=parent,
        )
        try:
            marker = os.open(
                "replacement-marker",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=replacement,
            )
            os.close(marker)
        finally:
            os.close(replacement)
        raise fetcher.FetchError("output-publication-race")

    monkeypatch.setattr(fetcher, "_rename_noreplace", replace_staging)

    with pytest.raises(fetcher.FetchError, match="output-publication-race"):
        fetcher.fetch_source_plan(
            plan_path,
            output,
            journal_path,
            **plan_binding(plan_path),
            resolver=network.resolve,
            opener=network.open,
        )

    replacements = list(tmp_path.glob(".verified-source-store-*"))
    assert len(replacements) == 1
    assert (replacements[0] / "replacement-marker").is_file()
    assert (tmp_path / "detached-original" / source_store.PLAN_FILENAME).is_file()
    assert not output.exists()


def test_staging_cleanup_leaves_fanout_beyond_its_entry_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_path = tmp_path / "parent"
    staging_path = parent_path / "staging"
    staging_path.mkdir(parents=True)
    budget = 7
    entry_count = budget + 11
    for number in range(entry_count):
        (staging_path / f"entry-{number:02d}").write_bytes(b"retain safely")
    monkeypatch.setattr(fetcher, "MAX_CLEANUP_ENTRIES", budget)

    parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY)
    staging = os.open("staging", os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
    try:
        fetcher._remove_staging(parent, "staging", staging)
    finally:
        os.close(staging)
        os.close(parent)

    remaining = list(staging_path.iterdir())
    assert len(remaining) == entry_count - budget
    assert all(path.read_bytes() == b"retain safely" for path in remaining)


def test_staging_cleanup_shares_one_entry_budget_across_recursive_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_path = tmp_path / "parent"
    branch_path = parent_path / "staging" / "branch"
    branch_path.mkdir(parents=True)
    budget = 6
    child_count = budget + 13
    for number in range(child_count):
        (branch_path / f"child-{number:02d}").write_bytes(b"retain safely")
    monkeypatch.setattr(fetcher, "MAX_CLEANUP_ENTRIES", budget)

    parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY)
    staging = os.open("staging", os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
    try:
        fetcher._remove_staging(parent, "staging", staging)
    finally:
        os.close(staging)
        os.close(parent)

    remaining = list(branch_path.iterdir())
    assert len(remaining) == child_count - (budget - 1)
    assert all(path.read_bytes() == b"retain safely" for path in remaining)


def test_post_commit_parent_sync_failure_returns_success_with_visible_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))

    def fail_sync(_parent: int) -> None:
        raise fetcher.FetchError("output-directory-fsync-failure")

    monkeypatch.setattr(fetcher, "_sync_published_parent", fail_sync)
    output, journal_path, result = run_fetch(
        tmp_path,
        plan_path,
        FakeNetwork([FakeResponse(200, content)]),
    )

    assert result == source_store.verify_source_store(output, **plan_binding(plan_path))
    journal = read_json(journal_path)
    assert journal["status"] == "published-with-warning"
    assert journal["error"] == "output-directory-fsync-failure"
    assert "published-with-warning:output-directory-fsync-failure" in capsys.readouterr().err


def test_post_commit_journal_failure_returns_success_and_leaves_publishing_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    content = b"content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))
    real_finish = fetcher.FetchJournal.finish

    def fail_final_journal(journal: Any, status: str, error: str | None) -> None:
        if status == "succeeded":
            raise fetcher.FetchError("journal-publication-failure")
        real_finish(journal, status, error)

    monkeypatch.setattr(fetcher.FetchJournal, "finish", fail_final_journal)
    output, journal_path, result = run_fetch(
        tmp_path,
        plan_path,
        FakeNetwork([FakeResponse(200, content)]),
    )

    assert result == source_store.verify_source_store(output, **plan_binding(plan_path))
    journal = read_json(journal_path)
    assert journal["status"] == "publishing"
    assert journal["error"] is None
    assert "published-with-warning:journal-finalization-failure" in capsys.readouterr().err


def test_same_plan_and_responses_produce_identical_store_manifests(tmp_path: Path) -> None:
    content = b"deterministic content"
    plan_path = write_plan(tmp_path, (RequestSpec("source:demo", content),))

    first, first_journal, _first_result = run_fetch(
        tmp_path,
        plan_path,
        FakeNetwork([FakeResponse(200, content)]),
        name="first",
    )
    second, second_journal, _second_result = run_fetch(
        tmp_path,
        plan_path,
        FakeNetwork([FakeResponse(200, content)]),
        name="second",
    )

    assert (first / source_store.STORE_FILENAME).read_bytes() == (
        second / source_store.STORE_FILENAME
    ).read_bytes()
    assert first_journal.read_bytes() == second_journal.read_bytes()
