#!/usr/bin/env python3
"""Fetch one canonical source plan into an atomically named verified store.

Run this process in a private workspace whose output parent and ancestors cannot
be renamed by another process. Directory descriptors prevent link traversal, but
they cannot make a same-user writable pathname stable. The caller must also set a
process-level timeout because the operating system's name resolver is not
cancellable from Python.

The returned verification summary is a point-in-time observation. A later
consumer must bind the plan to its own trusted digest and verify object bytes as
part of the read that consumes them, or first put the store behind a trusted
read-only boundary.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import http.client
import ipaddress
import os
import re
import secrets
import socket
import ssl
import stat
import sys
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verified_source_store  # noqa: E402

USER_AGENT = "curl/8.0 extra-codeowners-source-fetcher/1"
CONNECT_TIMEOUT_SECONDS = 60.0
MINIMUM_TRANSFER_BYTES_PER_SECOND = 512 * 1024
# Five minutes transfers the largest admitted object at 512 KiB/s and leaves
# 44 seconds for DNS, connection setup, TLS, and redirects.
ATTEMPT_TIMEOUT_SECONDS = 5 * 60.0
READ_CHUNK_BYTES = 64 * 1024
MAX_DNS_ADDRESSES = 32
MAX_TOTAL_TRANSFER_BYTES = verified_source_store.MAX_TOTAL_OBJECT_BYTES
JOURNAL_KIND = "extra-codeowners/source-fetch-journal"
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
RETRYABLE_HTTP_STATUSES = frozenset({408, 429, *range(500, 600)})
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_DECIMAL_DIGITS = 20
RENAME_NOREPLACE = 1
TLS_TRUST_OVERRIDE_VARIABLES = ("SSL_CERT_FILE", "SSL_CERT_DIR")
MAX_CLEANUP_DEPTH = 8
MAX_CLEANUP_ENTRIES = verified_source_store.MAX_OBJECTS * 2 + 32
RETRYABLE_SOCKET_ERRNOS = frozenset(
    {
        errno.ECONNABORTED,
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
        errno.ENETUNREACH,
        errno.EPIPE,
        errno.ETIMEDOUT,
    }
)
RETRYABLE_DNS_ERRORS = frozenset(
    value
    for value in (
        getattr(socket, "EAI_AGAIN", None),
        getattr(socket, "EAI_SYSTEM", None),
    )
    if value is not None
)


class FetchError(RuntimeError):
    """A sanitized, fail-closed source acquisition error."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _TerminalAttemptError(FetchError):
    """One request failed in a way that must not be retried."""

    def __init__(
        self,
        reason: str,
        attempt_result: AttemptResult | None = None,
    ) -> None:
        super().__init__(reason)
        self.attempt_result = attempt_result


class _BodyTransportError(FetchError):
    """A response body failed after zero or more bytes were received."""

    def __init__(self, attempt_result: AttemptResult) -> None:
        super().__init__("body-transport-failure")
        self.attempt_result = attempt_result


class Response(Protocol):
    status: int

    def read(self, amount: int) -> bytes:
        raise NotImplementedError

    def getheader(self, name: str, default: str | None = None) -> str | None:
        raise NotImplementedError

    def getheaders(self) -> list[tuple[str, str]]:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


@dataclass(frozen=True)
class ResolvedAddress:
    """One normalized public TCP address returned for a plan hostname."""

    family: int
    socktype: int
    protocol: int
    sockaddr: tuple[Any, ...]
    ip: str


@dataclass
class OpenedResponse:
    """One response plus the connection identity and close operation."""

    response: Response
    selected_ip: str
    peer_ip: str
    close_connection: Callable[[], None]

    def close(self) -> None:
        with contextlib.suppress(OSError, http.client.HTTPException):
            self.response.close()
        with contextlib.suppress(OSError, http.client.HTTPException):
            self.close_connection()


@dataclass
class TransferBudget:
    """Charge every received body byte, including discarded retry bodies."""

    limit: int = MAX_TOTAL_TRANSFER_BYTES
    received: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or self.received + amount > self.limit:
            raise _TerminalAttemptError("aggregate-transfer-limit")
        self.received += amount


@dataclass
class _CleanupBudget:
    """Bound entries inspected across one recursive staging cleanup."""

    remaining: int

    def charge_entry(self) -> None:
        if self.remaining <= 0:
            raise AssertionError("cleanup entry budget exhausted")
        self.remaining -= 1


@dataclass
class HopAudit:
    """Network facts retained only in the external operational journal."""

    url: str
    resolved_addresses: list[str] = field(default_factory=list)
    attempted_addresses: list[str] = field(default_factory=list)
    selected_address: str | None = None
    peer_address: str | None = None
    http_status: int | None = None
    redirect_url: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "origin": _audit_origin(self.url),
            "resolved_addresses": self.resolved_addresses,
            "attempted_addresses": self.attempted_addresses,
            "selected_address": self.selected_address,
            "peer_address": self.peer_address,
            "http_status": self.http_status,
            "redirect_origin": (
                None if self.redirect_url is None else _audit_origin(self.redirect_url)
            ),
        }


@dataclass
class AttemptResult:
    """Internal result for one bounded request attempt."""

    outcome: str
    http_status: int | None
    redirect_chain: list[str]
    received_size: int | None
    sha256: str | None
    retry_delay_seconds: int | None
    hops: list[HopAudit]
    reason: str | None = None
    temporary_name: str | None = None

    def store_projection(self, number: int) -> verified_source_store.FetchAttempt:
        if self.outcome not in {"retryable_transport", "retryable_http", "success"}:
            raise FetchError("invalid-attempt-projection")
        return {
            "number": number,
            "outcome": self.outcome,
            "http_status": self.http_status,
            "redirect_origins": _audit_origins(self.redirect_chain),
            "received_size": self.received_size,
            "sha256": self.sha256,
            "retry_delay_seconds": self.retry_delay_seconds,
        }

    def journal_projection(self, number: int) -> dict[str, Any]:
        return {
            "number": number,
            "outcome": self.outcome,
            "reason": self.reason,
            "http_status": self.http_status,
            "redirect_origins": [_audit_origin(url) for url in self.redirect_chain],
            "received_size": self.received_size,
            "sha256": self.sha256,
            "retry_delay_seconds": self.retry_delay_seconds,
            "hops": [hop.as_json() for hop in self.hops],
        }


Resolver = Callable[[str], tuple[ResolvedAddress, ...]]
ResponseOpener = Callable[[str, ResolvedAddress, Mapping[str, str]], OpenedResponse]
Sleeper = Callable[[float], None]
Clock = Callable[[], float]


_MAXIMUM_OBJECT_SHA256 = "f" * 64


def _canonical_item_size(value: object) -> int:
    """Return one canonical JSON item's size without the document line feed."""

    return len(verified_source_store.canonical_json(value)) - 1


def _projected_success_result(
    request: verified_source_store.SourcePlanRequest,
    completed_attempts: Sequence[verified_source_store.FetchAttempt],
    *,
    success_number: int,
    success_chain: Sequence[str],
) -> verified_source_store.StoreRequest:
    """Build a size-conservative result for one eventual successful request."""

    maximum_size = request["expected_size"]
    if maximum_size is None:
        maximum_size = request["max_bytes"]
    chain = list(success_chain)
    success: verified_source_store.FetchAttempt = {
        "number": success_number,
        "outcome": "success",
        "http_status": 200,
        "redirect_origins": _audit_origins(chain),
        "received_size": maximum_size,
        "sha256": _MAXIMUM_OBJECT_SHA256,
        "retry_delay_seconds": None,
    }
    return {
        "id": request["id"],
        "request_origin": _audit_origin(request["url"]),
        "algorithm": request["algorithm"],
        "digest": request["digest"],
        "expected_size": request["expected_size"],
        "max_bytes": request["max_bytes"],
        "object_sha256": _MAXIMUM_OBJECT_SHA256,
        "size": maximum_size,
        "path": f"objects/sha256/{_MAXIMUM_OBJECT_SHA256}",
        "redirect_origins": _audit_origins(chain),
        "attempts": [*completed_attempts, success],
    }


class ManifestMetadataBudget:
    """Bound the final manifest before and throughout source acquisition."""

    def __init__(
        self,
        plan: verified_source_store.SourcePlan,
        *,
        limit: int,
    ) -> None:
        self._limit = limit
        self._baseline_result_sizes: dict[str, int] = {}
        self._committed_result_deltas: dict[str, int] = {}

        empty_manifest: verified_source_store.SourceStore = {
            "schema_version": verified_source_store.SCHEMA_VERSION,
            "media_type": verified_source_store.STORE_MEDIA_TYPE,
            "kind": plan["kind"],
            "plan_sha256": hashlib.sha256(verified_source_store.canonical_json(plan)).hexdigest(),
            "plan_size": len(verified_source_store.canonical_json(plan)),
            "objects": [],
            "results": [],
        }
        maximum_object: verified_source_store.StoreObject = {
            "algorithm": "sha256",
            "digest": _MAXIMUM_OBJECT_SHA256,
            "size": verified_source_store.MAX_OBJECT_BYTES,
            "path": f"objects/sha256/{_MAXIMUM_OBJECT_SHA256}",
        }
        object_count = len(plan["requests"])
        object_items_size = object_count * _canonical_item_size(maximum_object)
        object_separators = max(0, object_count - 1)

        for request in plan["requests"]:
            baseline = _projected_success_result(
                request,
                (),
                success_number=1,
                success_chain=(request["url"],),
            )
            self._baseline_result_sizes[request["id"]] = _canonical_item_size(baseline)
        result_items_size = sum(self._baseline_result_sizes.values())
        result_separators = max(0, len(self._baseline_result_sizes) - 1)

        self._admission_upper_bound = (
            len(verified_source_store.canonical_json(empty_manifest))
            + object_items_size
            + object_separators
            + result_items_size
            + result_separators
        )
        if self._admission_upper_bound > self._limit:
            raise FetchError("source-store-manifest-admission-limit")

    @property
    def admission_upper_bound(self) -> int:
        """Return the conservative one-success-per-request admission size."""

        return self._admission_upper_bound

    def _require_projected_result(self, request_id: str, projected_size: int) -> None:
        if request_id in self._committed_result_deltas:
            raise FetchError("source-store-manifest-budget-state")
        baseline = self._baseline_result_sizes.get(request_id)
        if baseline is None:
            raise FetchError("source-store-manifest-budget-state")
        projected_upper_bound = (
            self._admission_upper_bound
            + sum(self._committed_result_deltas.values())
            + projected_size
            - baseline
        )
        if projected_upper_bound > self._limit:
            raise FetchError("source-store-manifest-runtime-limit")

    def ensure_success_projection(
        self,
        request: verified_source_store.SourcePlanRequest,
        completed_attempts: Sequence[verified_source_store.FetchAttempt],
        *,
        success_number: int,
        success_chain: Sequence[str],
    ) -> None:
        """Reserve enough metadata for success before another network operation."""

        projected = _projected_success_result(
            request,
            completed_attempts,
            success_number=success_number,
            success_chain=success_chain,
        )
        self._require_projected_result(request["id"], _canonical_item_size(projected))

    def commit_result(self, result: verified_source_store.StoreRequest) -> None:
        """Commit one exact result's metadata before fetching another request."""

        identifier = result["id"]
        baseline = self._baseline_result_sizes.get(identifier)
        if baseline is None or identifier in self._committed_result_deltas:
            raise FetchError("source-store-manifest-budget-state")
        actual_size = _canonical_item_size(result)
        self._require_projected_result(identifier, actual_size)
        self._committed_result_deltas[identifier] = actual_size - baseline

    def require_complete(self, manifest_bytes: bytes) -> None:
        """Check the final exact encoding and the conservative accounting invariant."""

        if len(self._committed_result_deltas) != len(self._baseline_result_sizes):
            raise FetchError("source-store-manifest-budget-state")
        upper_bound = self._admission_upper_bound + sum(self._committed_result_deltas.values())
        if len(manifest_bytes) > upper_bound:
            raise FetchError("source-store-manifest-budget-underestimate")
        if len(manifest_bytes) > self._limit:
            raise FetchError("source-store-manifest-limit")


def _audit_origin(url: str) -> str:
    """Return one canonical origin without credentials, path, query, or fragment."""

    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (UnicodeError, ValueError):
        return "invalid-url"
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        return "invalid-url"
    return f"https://{hostname.lower()}/"


def _audit_origins(urls: Sequence[str]) -> list[str]:
    """Convert a validated redirect chain into its persisted audit form."""

    origins = [_audit_origin(url) for url in urls]
    if "invalid-url" in origins:
        raise FetchError("invalid-redirect-audit-url")
    return origins


def _is_retryable_transport_error(error: BaseException) -> bool:
    """Recognize only connection availability failures, never TLS failures."""

    if isinstance(error, ssl.SSLError):
        return False
    if isinstance(
        error,
        (
            TimeoutError,
            ConnectionError,
            http.client.IncompleteRead,
            http.client.RemoteDisconnected,
        ),
    ):
        return True
    return isinstance(error, OSError) and error.errno in RETRYABLE_SOCKET_ERRNOS


def _terminal_network_reason(error: BaseException) -> str:
    if isinstance(error, ssl.SSLError):
        return "tls-failure"
    if isinstance(error, http.client.HTTPException):
        return "http-protocol-failure"
    return "network-io-failure"


def _audit_ip(value: str) -> str | None:
    try:
        _address, canonical = _canonical_ip(value)
    except FetchError:
        return None
    return canonical


def _deadline_exceeded(clock: Clock, deadline: float) -> bool:
    return clock() >= deadline


def _safe_read_file(path: Path, *, maximum: int, source: str) -> bytes:
    """Read one stable single-link regular file through one no-follow descriptor."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow or not hasattr(os, "pread"):
        raise FetchError("no-follow-file-reads-unavailable")
    flags = os.O_RDONLY | os.O_NONBLOCK | nofollow | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        before_path = os.stat(path, follow_symlinks=False)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
    except OSError:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise FetchError(f"cannot-open-{source}") from None
    try:
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= maximum
            or (
                before_path.st_dev,
                before_path.st_ino,
                before_path.st_mode,
                before_path.st_nlink,
                before_path.st_uid,
                before_path.st_gid,
                before_path.st_size,
                before_path.st_mtime_ns,
                before_path.st_ctime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
        ):
            raise FetchError(f"unsafe-{source}")
        chunks: list[bytes] = []
        position = 0
        while position < before.st_size:
            chunk = os.pread(descriptor, min(READ_CHUNK_BYTES, before.st_size - position), position)
            if not chunk:
                raise FetchError(f"changed-{source}")
            chunks.append(chunk)
            position += len(chunk)
        if os.pread(descriptor, 1, position):
            raise FetchError(f"oversized-{source}")
        after = os.fstat(descriptor)
        after_path = os.stat(path, follow_symlinks=False)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or identity != (
            after_path.st_dev,
            after_path.st_ino,
            after_path.st_mode,
            after_path.st_nlink,
            after_path.st_uid,
            after_path.st_gid,
            after_path.st_size,
            after_path.st_mtime_ns,
            after_path.st_ctime_ns,
        ):
            raise FetchError(f"changed-{source}")
        return b"".join(chunks)
    except OSError:
        raise FetchError(f"cannot-read-{source}") from None
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _canonical_ip(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, str]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise FetchError("dns-invalid-address") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        mapped = address.ipv4_mapped
        return mapped, str(mapped)
    return address, address.compressed


def _resolve_public_addresses(hostname: str) -> tuple[ResolvedAddress, ...]:
    """Resolve once, rejecting the whole answer set if any address is non-public."""

    try:
        records = socket.getaddrinfo(
            hostname,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        if exc.errno not in RETRYABLE_DNS_ERRORS:
            raise FetchError("dns-resolution-failure") from None
        raise FetchError("dns-transport-failure") from None
    except OSError:
        raise FetchError("dns-transport-failure") from None
    if not records or len(records) > MAX_DNS_ADDRESSES:
        raise FetchError("dns-answer-count")

    unique: dict[tuple[int, str], ResolvedAddress] = {}
    for family, socktype, protocol, _canonical_name, raw_sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            raise FetchError("dns-unsupported-family")
        sockaddr = cast(tuple[Any, ...], raw_sockaddr)
        if family == socket.AF_INET6 and len(sockaddr) >= 4 and int(sockaddr[3]) != 0:
            raise FetchError("dns-scoped-address")
        address, canonical = _canonical_ip(str(sockaddr[0]))
        if not address.is_global or address.is_multicast:
            raise FetchError("dns-non-public-address")
        unique[(family, canonical)] = ResolvedAddress(
            family=family,
            socktype=socktype,
            protocol=protocol,
            sockaddr=sockaddr,
            ip=canonical,
        )
    if not unique or len(unique) > MAX_DNS_ADDRESSES:
        raise FetchError("dns-answer-count")
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                ipaddress.ip_address(item.ip).version,
                ipaddress.ip_address(item.ip).packed,
            ),
        )
    )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to one numeric address while authenticating the plan hostname."""

    def __init__(self, hostname: str, address: ResolvedAddress) -> None:
        if any(os.environ.get(name) for name in TLS_TRUST_OVERRIDE_VARIABLES):
            raise FetchError("ambient-tls-trust-override")
        default_paths = ssl.get_default_verify_paths()
        cafile = cast(str | None, default_paths.cafile)
        capath = cast(str | None, default_paths.capath)
        if cafile is None and capath is None:
            raise FetchError("system-tls-trust-unavailable")
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(
                cafile=cafile,
                capath=capath,
            )
        except (OSError, ssl.SSLError):
            raise FetchError("system-tls-trust-unavailable") from None
        if cast(str | None, context.keylog_filename) is not None:
            raise FetchError("tls-key-logging-enabled")
        super().__init__(
            hostname,
            port=443,
            timeout=CONNECT_TIMEOUT_SECONDS,
            context=context,
        )
        self._address = address
        self._ssl_context = context
        self.selected_ip = address.ip
        self.peer_ip = ""

    def connect(self) -> None:
        raw = socket.socket(
            self._address.family,
            self._address.socktype,
            self._address.protocol,
        )
        try:
            raw.settimeout(cast(float, self.timeout))
            raw.connect(self._address.sockaddr)
            _peer, peer = _canonical_ip(str(raw.getpeername()[0]))
            if peer != self._address.ip:
                raise FetchError("peer-address-mismatch")
            wrapped = self._ssl_context.wrap_socket(raw, server_hostname=self.host)
            _tls_peer, tls_peer = _canonical_ip(str(wrapped.getpeername()[0]))
            if tls_peer != self._address.ip:
                wrapped.close()
                raise FetchError("peer-address-mismatch")
            self.peer_ip = tls_peer
            self.sock = wrapped
        except BaseException:
            with contextlib.suppress(OSError):
                raw.close()
            raise


def _request_target(url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(url)
    hostname = parsed.hostname
    if hostname is None:
        raise _TerminalAttemptError("invalid-redirect-url")
    target = parsed.path
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return hostname, target


def _open_pinned_response(
    url: str,
    address: ResolvedAddress,
    headers: Mapping[str, str],
) -> OpenedResponse:
    """Open one direct HTTP/1.1 request without consulting proxy environment state."""

    hostname, target = _request_target(url)
    connection = _PinnedHTTPSConnection(hostname, address)
    try:
        connection.request("GET", target, headers=dict(headers))
        response = cast(Response, connection.getresponse())
    except BaseException:
        with contextlib.suppress(OSError, http.client.HTTPException):
            connection.close()
        raise
    return OpenedResponse(
        response=response,
        selected_ip=connection.selected_ip,
        peer_ip=connection.peer_ip,
        close_connection=connection.close,
    )


def _header_values(response: Response, name: str) -> list[str]:
    return [value for key, value in response.getheaders() if key.lower() == name.lower()]


def _validated_url(url: str, allowed_hosts: set[str]) -> tuple[str, str]:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (UnicodeError, ValueError):
        raise _TerminalAttemptError("invalid-redirect-url") from None
    if (
        not url
        or len(url.encode("ascii", errors="ignore")) != len(url)
        or len(url) > verified_source_store.MAX_URL_BYTES
        or not url.startswith("https://")
        or "\\" in url
        or "#" in url
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url)
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.hostname is None
        or parsed.hostname != parsed.hostname.lower()
        or parsed.hostname not in allowed_hosts
        or not parsed.path.startswith("/")
    ):
        raise _TerminalAttemptError("invalid-redirect-url")
    authority = parsed.hostname if port is None else f"{parsed.hostname}:443"
    if parsed.netloc != authority:
        raise _TerminalAttemptError("invalid-redirect-url")
    return url, parsed.hostname


def _response_headers(
    response: Response,
    *,
    request: verified_source_store.SourcePlanRequest,
) -> int | None:
    lengths = _header_values(response, "Content-Length")
    transfers = _header_values(response, "Transfer-Encoding")
    encodings = _header_values(response, "Content-Encoding")
    ranges = _header_values(response, "Content-Range")
    if len(lengths) > 1 or len(transfers) > 1 or len(encodings) > 1 or ranges:
        raise _TerminalAttemptError("invalid-response-framing")
    if transfers and transfers[0].strip().lower() != "chunked":
        raise _TerminalAttemptError("invalid-response-framing")
    if transfers and lengths:
        raise _TerminalAttemptError("invalid-response-framing")
    if encodings and encodings[0].strip().lower() != "identity":
        raise _TerminalAttemptError("encoded-response")
    if not lengths:
        return None
    raw = lengths[0].strip()
    if len(raw) > MAX_DECIMAL_DIGITS or DECIMAL.fullmatch(raw) is None:
        raise _TerminalAttemptError("invalid-content-length")
    length = int(raw)
    if length > request["max_bytes"]:
        raise _TerminalAttemptError("request-byte-limit")
    if request["expected_size"] is not None and length != request["expected_size"]:
        raise _TerminalAttemptError("expected-size-mismatch")
    return length


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        try:
            written = os.write(descriptor, remaining)
        except OSError:
            raise FetchError("local-write-failure") from None
        if written <= 0:
            raise FetchError("local-write-failure")
        remaining = remaining[written:]


def _create_temporary_file(directory: int) -> tuple[int, str]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise FetchError("no-follow-file-creation-unavailable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0)
    for _ in range(32):
        name = f".source-fetch-{os.getpid()}-{secrets.token_hex(8)}"
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory)
            os.fchmod(descriptor, 0o600)
            return descriptor, name
        except FileExistsError:
            continue
        except OSError:
            raise FetchError("local-file-creation-failure") from None
    raise FetchError("local-file-name-exhaustion")


def _stream_response(
    response: Response,
    *,
    request: verified_source_store.SourcePlanRequest,
    directory: int,
    budget: TransferBudget,
    deadline: float,
    clock: Clock,
) -> tuple[str, int, str]:
    declared_length = _response_headers(response, request=request)
    if declared_length is not None and budget.received + declared_length > budget.limit:
        raise _TerminalAttemptError("aggregate-transfer-limit")
    descriptor, temporary_name = _create_temporary_file(directory)
    expected = hashlib.new(request["algorithm"])
    cas = hashlib.sha256()
    received = 0
    retain_temporary = False

    def retryable_body_error(reason: str) -> _BodyTransportError:
        partial = cas.hexdigest() if received else None
        return _BodyTransportError(
            AttemptResult(
                outcome="retryable_transport",
                http_status=None,
                redirect_chain=[],
                received_size=received if received else None,
                sha256=partial,
                retry_delay_seconds=None,
                hops=[],
                reason=reason,
            )
        )

    try:
        while True:
            if _deadline_exceeded(clock, deadline):
                raise retryable_body_error("attempt-deadline-exceeded")
            try:
                chunk = response.read(
                    min(
                        READ_CHUNK_BYTES,
                        request["max_bytes"] - received + 1,
                        budget.limit - budget.received + 1,
                    )
                )
            except (OSError, http.client.HTTPException) as exc:
                if isinstance(exc, http.client.IncompleteRead) and exc.partial:
                    partial_chunk = exc.partial
                    if not isinstance(partial_chunk, bytes):
                        raise _TerminalAttemptError("invalid-response-body") from None
                    if received + len(partial_chunk) > request["max_bytes"]:
                        raise _TerminalAttemptError("request-byte-limit") from None
                    budget.charge(len(partial_chunk))
                    received += len(partial_chunk)
                    expected.update(partial_chunk)
                    cas.update(partial_chunk)
                    _write_all(descriptor, partial_chunk)
                if not _is_retryable_transport_error(exc):
                    raise _TerminalAttemptError(
                        _terminal_network_reason(exc),
                        AttemptResult(
                            outcome="terminal_failure",
                            http_status=200,
                            redirect_chain=[],
                            received_size=received,
                            sha256=cas.hexdigest(),
                            retry_delay_seconds=None,
                            hops=[],
                            reason=_terminal_network_reason(exc),
                        ),
                    ) from None
                raise retryable_body_error("body-transport-failure") from None
            if not isinstance(chunk, bytes):
                raise _TerminalAttemptError("invalid-response-body")
            if chunk:
                if received + len(chunk) > request["max_bytes"]:
                    raise _TerminalAttemptError("request-byte-limit")
                budget.charge(len(chunk))
                received += len(chunk)
                expected.update(chunk)
                cas.update(chunk)
                _write_all(descriptor, chunk)
            if _deadline_exceeded(clock, deadline):
                raise retryable_body_error("attempt-deadline-exceeded")
            if not chunk:
                break
        if declared_length is not None and received != declared_length:
            raise _TerminalAttemptError("content-length-mismatch")
        if request["expected_size"] is not None and received != request["expected_size"]:
            raise _TerminalAttemptError("expected-size-mismatch")
        if expected.hexdigest() != request["digest"]:
            raise _TerminalAttemptError("expected-digest-mismatch")
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != received
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise FetchError("local-file-identity-failure")
        retain_temporary = True
        return temporary_name, received, cas.hexdigest()
    except _TerminalAttemptError as exc:
        if exc.attempt_result is None:
            exc.attempt_result = AttemptResult(
                outcome="terminal_failure",
                http_status=200,
                redirect_chain=[],
                received_size=received,
                sha256=cas.hexdigest(),
                retry_delay_seconds=None,
                hops=[],
                reason=exc.reason,
            )
        raise
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        if not retain_temporary:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory)


def _retry_after(response: Response, fallback: int) -> int:
    values = _header_values(response, "Retry-After")
    if len(values) == 1:
        raw = values[0].strip()
        if len(raw) <= MAX_DECIMAL_DIGITS and DECIMAL.fullmatch(raw) is not None:
            value = int(raw)
            if 0 <= value <= verified_source_store.MAX_RETRY_DELAY_SECONDS:
                return value
    return fallback


def _attempt_request(
    request: verified_source_store.SourcePlanRequest,
    *,
    number: int,
    completed_attempts: Sequence[verified_source_store.FetchAttempt],
    directory: int,
    budget: TransferBudget,
    manifest_budget: ManifestMetadataBudget,
    resolver: Resolver,
    opener: ResponseOpener,
    clock: Clock,
) -> AttemptResult:
    deadline = clock() + ATTEMPT_TIMEOUT_SECONDS
    allowed_hosts = set(request["allowed_hosts"])
    current, _host = _validated_url(request["url"], allowed_hosts)
    chain = [current]
    hops: list[HopAudit] = []
    headers = {
        "Accept": "application/octet-stream",
        "Accept-Encoding": "identity",
        "Connection": "close",
        "User-Agent": USER_AGENT,
    }
    manifest_budget.ensure_success_projection(
        request,
        completed_attempts,
        success_number=number,
        success_chain=chain,
    )
    while True:
        _validated, hostname = _validated_url(current, allowed_hosts)
        hop = HopAudit(url=current)
        hops.append(hop)
        if _deadline_exceeded(clock, deadline):
            return AttemptResult(
                outcome="retryable_transport",
                http_status=None,
                redirect_chain=chain,
                received_size=None,
                sha256=None,
                retry_delay_seconds=1 << (number - 1),
                hops=hops,
                reason="attempt-deadline-exceeded",
            )
        try:
            addresses = resolver(hostname)
        except FetchError as exc:
            if exc.reason == "dns-transport-failure":
                return AttemptResult(
                    outcome="retryable_transport",
                    http_status=None,
                    redirect_chain=chain,
                    received_size=None,
                    sha256=None,
                    retry_delay_seconds=1 << (number - 1),
                    hops=hops,
                    reason=exc.reason,
                )
            raise _TerminalAttemptError(
                exc.reason,
                AttemptResult(
                    outcome="terminal_failure",
                    http_status=None,
                    redirect_chain=chain,
                    received_size=None,
                    sha256=None,
                    retry_delay_seconds=None,
                    hops=hops,
                    reason=exc.reason,
                ),
            ) from None
        hop.resolved_addresses = [address.ip for address in addresses]
        if _deadline_exceeded(clock, deadline):
            return AttemptResult(
                outcome="retryable_transport",
                http_status=None,
                redirect_chain=chain,
                received_size=None,
                sha256=None,
                retry_delay_seconds=1 << (number - 1),
                hops=hops,
                reason="attempt-deadline-exceeded",
            )
        if not addresses:
            return AttemptResult(
                outcome="retryable_transport",
                http_status=None,
                redirect_chain=chain,
                received_size=None,
                sha256=None,
                retry_delay_seconds=1 << (number - 1),
                hops=hops,
                reason="dns-empty-answer",
            )

        opened: OpenedResponse | None = None
        for address in addresses:
            if _deadline_exceeded(clock, deadline):
                break
            hop.attempted_addresses.append(address.ip)
            try:
                opened_candidate = opener(current, address, headers)
            except FetchError as exc:
                raise _TerminalAttemptError(
                    exc.reason,
                    AttemptResult(
                        outcome="terminal_failure",
                        http_status=None,
                        redirect_chain=chain,
                        received_size=None,
                        sha256=None,
                        retry_delay_seconds=None,
                        hops=hops,
                        reason=exc.reason,
                    ),
                ) from None
            except (OSError, http.client.HTTPException) as exc:
                if _is_retryable_transport_error(exc):
                    continue
                reason = _terminal_network_reason(exc)
                raise _TerminalAttemptError(
                    reason,
                    AttemptResult(
                        outcome="terminal_failure",
                        http_status=None,
                        redirect_chain=chain,
                        received_size=None,
                        sha256=None,
                        retry_delay_seconds=None,
                        hops=hops,
                        reason=reason,
                    ),
                ) from None
            hop.selected_address = _audit_ip(opened_candidate.selected_ip)
            hop.peer_address = _audit_ip(opened_candidate.peer_ip)
            if (
                opened_candidate.selected_ip != address.ip
                or opened_candidate.peer_ip != address.ip
                or opened_candidate.selected_ip not in hop.resolved_addresses
            ):
                opened_candidate.close()
                raise _TerminalAttemptError(
                    "peer-address-mismatch",
                    AttemptResult(
                        outcome="terminal_failure",
                        http_status=None,
                        redirect_chain=chain,
                        received_size=None,
                        sha256=None,
                        retry_delay_seconds=None,
                        hops=hops,
                        reason="peer-address-mismatch",
                    ),
                )
            if _deadline_exceeded(clock, deadline):
                opened_candidate.close()
                break
            opened = opened_candidate
            break
        if opened is None:
            reason = (
                "attempt-deadline-exceeded"
                if _deadline_exceeded(clock, deadline)
                else "connection-transport-failure"
            )
            return AttemptResult(
                outcome="retryable_transport",
                http_status=None,
                redirect_chain=chain,
                received_size=None,
                sha256=None,
                retry_delay_seconds=1 << (number - 1),
                hops=hops,
                reason=reason,
            )

        try:
            response = opened.response
            status = response.status
            if not isinstance(status, int) or isinstance(status, bool):
                raise _TerminalAttemptError("invalid-http-status")
            hop.http_status = status
            if status in REDIRECT_STATUSES:
                locations = _header_values(response, "Location")
                if len(locations) != 1 or not locations[0]:
                    raise _TerminalAttemptError("invalid-redirect-location")
                try:
                    redirect_target = urllib.parse.urljoin(current, locations[0])
                except (UnicodeError, ValueError):
                    raise _TerminalAttemptError("invalid-redirect-url") from None
                redirect_target, _candidate_host = _validated_url(
                    redirect_target,
                    allowed_hosts,
                )
                if redirect_target in chain or len(chain) > verified_source_store.MAX_REDIRECTS:
                    raise _TerminalAttemptError("redirect-limit-or-loop")
                hop.redirect_url = redirect_target
                prospective_chain = [*chain, redirect_target]
                manifest_budget.ensure_success_projection(
                    request,
                    completed_attempts,
                    success_number=number,
                    success_chain=prospective_chain,
                )
                chain = prospective_chain
                current = redirect_target
                continue
            if status in RETRYABLE_HTTP_STATUSES:
                return AttemptResult(
                    outcome="retryable_http",
                    http_status=status,
                    redirect_chain=chain,
                    received_size=None,
                    sha256=None,
                    retry_delay_seconds=_retry_after(response, 1 << (number - 1)),
                    hops=hops,
                    reason="retryable-http-status",
                )
            if status != 200:
                raise _TerminalAttemptError("terminal-http-status")
            try:
                temporary_name, received, sha256 = _stream_response(
                    response,
                    request=request,
                    directory=directory,
                    budget=budget,
                    deadline=deadline,
                    clock=clock,
                )
            except _BodyTransportError as exc:
                partial = exc.attempt_result
                partial.redirect_chain = chain
                partial.hops = hops
                partial.retry_delay_seconds = 1 << (number - 1)
                return partial
            except _TerminalAttemptError as exc:
                terminal_result = exc.attempt_result
                if terminal_result is None:
                    terminal_result = AttemptResult(
                        outcome="terminal_failure",
                        http_status=hop.http_status,
                        redirect_chain=chain,
                        received_size=None,
                        sha256=None,
                        retry_delay_seconds=None,
                        hops=hops,
                        reason=exc.reason,
                    )
                    exc.attempt_result = terminal_result
                else:
                    terminal_result.redirect_chain = chain
                    terminal_result.hops = hops
                    terminal_result.http_status = hop.http_status
                raise
            return AttemptResult(
                outcome="success",
                http_status=200,
                redirect_chain=chain,
                received_size=received,
                sha256=sha256,
                retry_delay_seconds=None,
                hops=hops,
                temporary_name=temporary_name,
            )
        except _TerminalAttemptError as exc:
            if exc.attempt_result is None:
                exc.attempt_result = AttemptResult(
                    outcome="terminal_failure",
                    http_status=hop.http_status,
                    redirect_chain=chain,
                    received_size=None,
                    sha256=None,
                    retry_delay_seconds=None,
                    hops=hops,
                    reason=exc.reason,
                )
            raise
        except (OSError, http.client.HTTPException) as exc:
            reason = _terminal_network_reason(exc)
            if _is_retryable_transport_error(exc):
                return AttemptResult(
                    outcome="retryable_transport",
                    http_status=None,
                    redirect_chain=chain,
                    received_size=None,
                    sha256=None,
                    retry_delay_seconds=1 << (number - 1),
                    hops=hops,
                    reason="response-transport-failure",
                )
            raise _TerminalAttemptError(
                reason,
                AttemptResult(
                    outcome="terminal_failure",
                    http_status=hop.http_status,
                    redirect_chain=chain,
                    received_size=None,
                    sha256=None,
                    retry_delay_seconds=None,
                    hops=hops,
                    reason=reason,
                ),
            ) from None
        finally:
            opened.close()


def _open_directory(path: Path, source: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise FetchError("no-follow-directory-support-unavailable")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        raise FetchError(f"cannot-open-{source}") from None
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise FetchError(f"unsafe-{source}")
        return descriptor
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise


def _open_directory_at(parent: int, name: str, source: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
    except OSError:
        raise FetchError(f"cannot-open-{source}") from None
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise FetchError(f"unsafe-{source}")
        return descriptor
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise


def _write_file_at(directory: int, name: str, content: bytes) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    except OSError:
        raise FetchError("local-file-creation-failure") from None
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, content)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(content)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise FetchError("local-file-identity-failure")
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _require_absent(parent: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise FetchError("cannot-inspect-output") from None
    raise FetchError("output-already-exists")


def _create_staging(parent: int) -> tuple[str, int]:
    for _ in range(32):
        name = f".verified-source-store-{os.getpid()}-{secrets.token_hex(8)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            continue
        except OSError:
            raise FetchError("cannot-create-staging-root") from None
        descriptor = -1
        try:
            descriptor = _open_directory_at(parent, name, "staging-root")
            os.fchmod(descriptor, 0o700)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
                raise FetchError("unsafe-staging-root")
            return name, descriptor
        except BaseException:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            with contextlib.suppress(OSError):
                os.rmdir(name, dir_fd=parent)
            raise
    raise FetchError("staging-name-exhaustion")


def _rename_noreplace(parent: int, source: str, destination: str) -> None:
    if sys.platform != "linux":
        raise FetchError("atomic-publication-requires-linux")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError):
        raise FetchError("atomic-publication-unavailable") from None
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent,
        os.fsencode(source),
        parent,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FetchError("output-publication-race")
    if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise FetchError("atomic-publication-unavailable")
    raise FetchError("output-publication-failure")


def _sync_published_parent(parent: int) -> None:
    try:
        os.fsync(parent)
    except OSError:
        raise FetchError("output-directory-fsync-failure") from None


def _post_commit_warning(reasons: Sequence[str]) -> None:
    """Report faults after the atomic rename without turning success into failure."""

    if not reasons:
        return
    message = ",".join(sorted(set(reasons)))
    with contextlib.suppress(OSError, ValueError):
        sys.stderr.write(f"verified source fetch warning: published-with-warning:{message}\n")


def _atomic_replace(path: Path, content: bytes) -> None:
    if len(content) > MAX_JOURNAL_BYTES:
        raise FetchError("journal-byte-limit")
    parent = _open_directory(path.parent, "journal-parent")
    temporary = ""
    descriptor = -1
    try:
        descriptor, temporary = _create_temporary_file(parent)
        _write_all(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.replace(
                temporary,
                path.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
            )
        except OSError:
            raise FetchError("journal-publication-failure") from None
        temporary = ""
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if temporary:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=parent)
        with contextlib.suppress(OSError):
            os.close(parent)


class FetchJournal:
    """Atomically persist bounded operational facts after every attempt."""

    def __init__(
        self,
        path: Path,
        plan: verified_source_store.SourcePlan,
        plan_bytes: bytes,
    ) -> None:
        self.path = path
        self.value: dict[str, Any] = {
            "schema_version": 1,
            "kind": JOURNAL_KIND,
            "status": "running",
            "error": None,
            "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "plan_size": len(plan_bytes),
            "requests": [{"id": request["id"], "attempts": []} for request in plan["requests"]],
        }
        self._indices = {request["id"]: index for index, request in enumerate(plan["requests"])}
        self.write()

    def append(self, request_id: str, attempt: dict[str, Any]) -> None:
        index = self._indices[request_id]
        requests = cast(list[dict[str, Any]], self.value["requests"])
        attempts = cast(list[dict[str, Any]], requests[index]["attempts"])
        attempts.append(attempt)
        self.write()

    def finish(self, status: str, error: str | None) -> None:
        self.value["status"] = status
        self.value["error"] = error
        self.write()

    def write(self) -> None:
        _atomic_replace(self.path, verified_source_store.canonical_json(self.value))


def _promote_object(
    directory: int,
    temporary_name: str,
    digest: str,
    size: int,
    objects: dict[str, verified_source_store.StoreObject],
) -> None:
    previous = objects.get(digest)
    if previous is not None:
        if previous["size"] != size:
            raise FetchError("cas-digest-size-conflict")
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except OSError:
            raise FetchError("temporary-object-cleanup-failure") from None
        return
    try:
        os.rename(
            temporary_name,
            digest,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
    except OSError:
        raise FetchError("object-publication-failure") from None
    objects[digest] = {
        "algorithm": "sha256",
        "digest": digest,
        "size": size,
        "path": f"objects/sha256/{digest}",
    }


def _fetch_one(
    request: verified_source_store.SourcePlanRequest,
    *,
    directory: int,
    budget: TransferBudget,
    manifest_budget: ManifestMetadataBudget,
    journal: FetchJournal,
    objects: dict[str, verified_source_store.StoreObject],
    resolver: Resolver,
    opener: ResponseOpener,
    sleeper: Sleeper,
    clock: Clock,
) -> verified_source_store.StoreRequest:
    stored_attempts: list[verified_source_store.FetchAttempt] = []
    for number in range(1, verified_source_store.MAX_ATTEMPTS + 1):
        try:
            result = _attempt_request(
                request,
                number=number,
                completed_attempts=stored_attempts,
                directory=directory,
                budget=budget,
                manifest_budget=manifest_budget,
                resolver=resolver,
                opener=opener,
                clock=clock,
            )
        except _TerminalAttemptError as exc:
            terminal = exc.attempt_result or AttemptResult(
                outcome="terminal_failure",
                http_status=None,
                redirect_chain=[request["url"]],
                received_size=None,
                sha256=None,
                retry_delay_seconds=None,
                hops=[],
                reason=exc.reason,
            )
            journal.append(request["id"], terminal.journal_projection(number))
            raise FetchError(exc.reason) from None

        if result.outcome == "success":
            if (
                result.temporary_name is None
                or result.received_size is None
                or result.sha256 is None
            ):
                raise FetchError("invalid-success-state")
            success_attempt = result.store_projection(number)
            store_result: verified_source_store.StoreRequest = {
                "id": request["id"],
                "request_origin": _audit_origin(request["url"]),
                "algorithm": request["algorithm"],
                "digest": request["digest"],
                "expected_size": request["expected_size"],
                "max_bytes": request["max_bytes"],
                "object_sha256": result.sha256,
                "size": result.received_size,
                "path": f"objects/sha256/{result.sha256}",
                "redirect_origins": _audit_origins(result.redirect_chain),
                "attempts": [*stored_attempts, success_attempt],
            }
            manifest_budget.commit_result(store_result)
            _promote_object(
                directory,
                result.temporary_name,
                result.sha256,
                result.received_size,
                objects,
            )
            result.temporary_name = None
            stored_attempts.append(success_attempt)
            journal.append(request["id"], result.journal_projection(number))
            return store_result

        if number == verified_source_store.MAX_ATTEMPTS:
            result.outcome = "attempts_exhausted"
            result.retry_delay_seconds = None
            result.reason = f"{result.reason or 'retryable-failure'}-exhausted"
            journal.append(request["id"], result.journal_projection(number))
            raise FetchError(result.reason) from None

        stored_attempts.append(result.store_projection(number))
        journal.append(request["id"], result.journal_projection(number))
        manifest_budget.ensure_success_projection(
            request,
            stored_attempts,
            success_number=number + 1,
            success_chain=(request["url"],),
        )
        delay = result.retry_delay_seconds
        if delay is None:
            raise FetchError("invalid-retry-delay")
        sleeper(float(delay))
    raise FetchError("attempt-loop-exhausted")


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_mode, left.st_uid, left.st_gid) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_uid,
        right.st_gid,
    )


def _require_retained_directory(parent: int, name: str, directory: int) -> None:
    try:
        retained = os.fstat(directory)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        raise FetchError("staging-root-changed") from None
    if not stat.S_ISDIR(current.st_mode) or not _same_file(retained, current):
        raise FetchError("staging-root-changed")


def _require_output_parent_unchanged(path: Path, directory: int) -> None:
    """Reject a persistent rename or replacement of the requested output parent."""

    try:
        retained = os.fstat(directory)
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        raise FetchError("output-parent-changed") from None
    if not stat.S_ISDIR(current.st_mode) or not _same_file(retained, current):
        raise FetchError("output-parent-changed")


def _remove_directory_contents(
    directory: int,
    *,
    depth: int = 0,
    budget: _CleanupBudget | None = None,
) -> None:
    """Remove a globally bounded set of entries without following links."""

    if budget is None:
        budget = _CleanupBudget(MAX_CLEANUP_ENTRIES)
    if depth > MAX_CLEANUP_DEPTH or budget.remaining <= 0:
        return
    try:
        with os.scandir(directory) as entries:
            while budget.remaining > 0:
                try:
                    entry = next(entries)
                except StopIteration:
                    break
                budget.charge_entry()
                name = entry.name
                if name in {"", ".", ".."}:
                    continue
                try:
                    metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    with contextlib.suppress(OSError):
                        os.unlink(name, dir_fd=directory)
                    continue

                child = -1
                try:
                    child = _open_directory_at(directory, name, "staging-cleanup-directory")
                    retained = os.fstat(child)
                    if not _same_file(metadata, retained):
                        continue
                    _remove_directory_contents(
                        child,
                        depth=depth + 1,
                        budget=budget,
                    )
                    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if _same_file(retained, current):
                        os.rmdir(name, dir_fd=directory)
                except (FetchError, OSError):
                    continue
                finally:
                    if child >= 0:
                        with contextlib.suppress(OSError):
                            os.close(child)
    except (OSError, TypeError):
        return


def _remove_staging(parent: int, name: str, directory: int) -> None:
    """Clean only the staging inode retained from creation, never a replacement."""

    try:
        retained = os.fstat(directory)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        return
    if not stat.S_ISDIR(current.st_mode) or not _same_file(retained, current):
        return
    _remove_directory_contents(directory)
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISDIR(current.st_mode) and _same_file(retained, current):
            os.rmdir(name, dir_fd=parent)
    except OSError:
        return


def fetch_source_plan(
    plan_path: Path,
    output_root: Path,
    journal_path: Path,
    *,
    expected_plan_sha256: str,
    expected_plan_size: int,
    resolver: Resolver = _resolve_public_addresses,
    opener: ResponseOpener = _open_pinned_response,
    sleeper: Sleeper = time.sleep,
    clock: Clock = time.monotonic,
) -> verified_source_store.VerificationResult:
    """Fetch, verify, and publish a point-in-time source-store observation.

    The output parent and its ancestors must be private and stable for the whole
    call. A post-publication integrity or parent-identity failure is fatal even
    though the no-replace rename may already have committed the directory.
    Durability and final journal-write faults after a successful final verification
    are warnings because the verified output is already visible.

    The caller must impose a process-level timeout. The result cannot authorize a
    later read from writable storage; the consumer must verify bytes while reading
    them or use a trusted read-only boundary.
    """

    if (
        not isinstance(expected_plan_sha256, str)
        or LOWER_SHA256.fullmatch(expected_plan_sha256) is None
        or not isinstance(expected_plan_size, int)
        or isinstance(expected_plan_size, bool)
        or not 1 <= expected_plan_size <= verified_source_store.MAX_PLAN_BYTES
    ):
        raise FetchError("invalid-expected-plan-binding")

    plan_path = Path(plan_path).absolute()
    output_root = Path(output_root).absolute()
    journal_path = Path(journal_path).absolute()
    if sys.platform != "linux":
        raise FetchError("atomic-publication-requires-linux")
    if (
        output_root.name in {"", ".", ".."}
        or journal_path.name in {"", ".", ".."}
        or journal_path in (plan_path, output_root)
        or output_root in journal_path.parents
    ):
        raise FetchError("unsafe-output-path")

    plan_bytes = _safe_read_file(
        plan_path,
        maximum=verified_source_store.MAX_PLAN_BYTES,
        source="source-plan",
    )
    if (
        len(plan_bytes) != expected_plan_size
        or hashlib.sha256(plan_bytes).hexdigest() != expected_plan_sha256
    ):
        raise FetchError("source-plan-binding-mismatch")
    try:
        plan = verified_source_store.validate_source_plan(
            verified_source_store.strict_json_bytes(
                plan_bytes,
                "source plan",
                maximum=verified_source_store.MAX_PLAN_BYTES,
            )
        )
    except verified_source_store.SourceStoreError:
        raise FetchError("invalid-source-plan") from None

    manifest_budget = ManifestMetadataBudget(
        plan,
        limit=verified_source_store.MAX_STORE_BYTES,
    )
    parent = -1
    staging_name = ""
    staging_descriptor = -1
    objects_descriptor = -1
    digest_descriptor = -1
    published = False
    journal: FetchJournal | None = None
    try:
        parent = _open_directory(output_root.parent, "output-parent")
        _require_output_parent_unchanged(output_root.parent, parent)
        _require_absent(parent, output_root.name)
        staging_name, staging_descriptor = _create_staging(parent)
        staging_path = Path("/proc/self/fd") / str(parent) / staging_name
        os.mkdir("objects", 0o700, dir_fd=staging_descriptor)
        objects_descriptor = _open_directory_at(
            staging_descriptor,
            "objects",
            "objects-directory",
        )
        os.fchmod(objects_descriptor, 0o700)
        os.mkdir("sha256", 0o700, dir_fd=objects_descriptor)
        digest_descriptor = _open_directory_at(
            objects_descriptor,
            "sha256",
            "sha256-directory",
        )
        os.fchmod(digest_descriptor, 0o700)
        _write_file_at(staging_descriptor, verified_source_store.PLAN_FILENAME, plan_bytes)

        journal = FetchJournal(journal_path, plan, plan_bytes)
        budget = TransferBudget()
        objects: dict[str, verified_source_store.StoreObject] = {}
        results = [
            _fetch_one(
                request,
                directory=digest_descriptor,
                budget=budget,
                manifest_budget=manifest_budget,
                journal=journal,
                objects=objects,
                resolver=resolver,
                opener=opener,
                sleeper=sleeper,
                clock=clock,
            )
            for request in plan["requests"]
        ]

        manifest: verified_source_store.SourceStore = {
            "schema_version": verified_source_store.SCHEMA_VERSION,
            "media_type": verified_source_store.STORE_MEDIA_TYPE,
            "kind": plan["kind"],
            "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "plan_size": len(plan_bytes),
            "objects": [objects[digest] for digest in sorted(objects)],
            "results": results,
        }
        manifest_bytes = verified_source_store.canonical_json(manifest)
        manifest_budget.require_complete(manifest_bytes)
        _write_file_at(
            staging_descriptor,
            verified_source_store.STORE_FILENAME,
            manifest_bytes,
        )
        os.fsync(digest_descriptor)
        os.fsync(objects_descriptor)
        os.fsync(staging_descriptor)
        try:
            verified_source_store.verify_source_store(
                staging_path,
                expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
                expected_plan_size=len(plan_bytes),
            )
        except verified_source_store.SourceStoreError:
            raise FetchError("staged-store-verification-failure") from None

        _require_retained_directory(parent, staging_name, staging_descriptor)
        _require_output_parent_unchanged(output_root.parent, parent)
        journal.finish("publishing", None)
        _require_retained_directory(parent, staging_name, staging_descriptor)
        _require_output_parent_unchanged(output_root.parent, parent)
        _require_absent(parent, output_root.name)
        published = True
        try:
            _rename_noreplace(parent, staging_name, output_root.name)
        except BaseException:
            published = False
            raise
        staging_name = ""
        _require_output_parent_unchanged(output_root.parent, parent)
        published_path = Path("/proc/self/fd") / str(parent) / output_root.name
        try:
            verification = verified_source_store.verify_source_store(
                published_path,
                expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
                expected_plan_size=len(plan_bytes),
            )
        except verified_source_store.SourceStoreError:
            raise FetchError("published-store-verification-failure") from None
        _require_output_parent_unchanged(output_root.parent, parent)
        warnings: list[str] = []
        try:
            _sync_published_parent(parent)
        except FetchError as exc:
            warnings.append(exc.reason)
        final_status = "succeeded" if not warnings else "published-with-warning"
        final_error = None if not warnings else ",".join(warnings)
        try:
            journal.finish(final_status, final_error)
        except (FetchError, OSError):
            warnings.append("journal-finalization-failure")
        _post_commit_warning(warnings)
        return verification
    except (FetchError, OSError) as exc:
        reason = exc.reason if isinstance(exc, FetchError) else "local-io-failure"
        if journal is not None:
            with contextlib.suppress(FetchError, OSError):
                journal.finish("failed", reason)
        if isinstance(exc, OSError):
            raise FetchError(reason) from None
        raise
    finally:
        if digest_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(digest_descriptor)
        if objects_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(objects_descriptor)
        try:
            if staging_name and not published and staging_descriptor >= 0 and parent >= 0:
                _remove_staging(parent, staging_name, staging_descriptor)
        finally:
            if staging_descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(staging_descriptor)
            if parent >= 0:
                with contextlib.suppress(OSError):
                    os.close(parent)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--expected-plan-size", required=True, type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        result = fetch_source_plan(
            cast(Path, arguments.plan),
            cast(Path, arguments.output),
            cast(Path, arguments.journal),
            expected_plan_sha256=cast(str, arguments.expected_plan_sha256),
            expected_plan_size=cast(int, arguments.expected_plan_size),
        )
    except (FetchError, verified_source_store.SourceStoreError) as exc:
        reason = exc.reason if isinstance(exc, FetchError) else "verification-failure"
        sys.stderr.write(f"verified source fetch: {reason}\n")
        return 1
    sys.stdout.buffer.write(verified_source_store.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
