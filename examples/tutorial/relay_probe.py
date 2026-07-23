"""Verify that an HTTPS relay preserves webhook bytes and their HMAC."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, cast

MAX_BODY_BYTES = 1024 * 1024
SIGNATURE_HEADER = "X-Hub-Signature-256"


def _signature(secret: bytes, body: bytes) -> str:
    return f"sha256={hmac.new(secret, body, hashlib.sha256).hexdigest()}"


class ProbeServer(HTTPServer):
    """One-request server with fixed expected evidence."""

    expected_body: bytes
    expected_signature: str
    succeeded: bool = False


class ProbeHandler(BaseHTTPRequestHandler):
    """Compare the forwarded request with the locally recorded evidence."""

    server: ProbeServer

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_error(411, "a valid Content-Length is required")
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(413, "probe body is outside the accepted bound")
            return

        body = self.rfile.read(length)
        supplied_signature = self.headers.get(SIGNATURE_HEADER, "")
        body_matches = hmac.compare_digest(body, self.server.expected_body)
        signature_matches = hmac.compare_digest(
            supplied_signature,
            self.server.expected_signature,
        )
        if not body_matches or not signature_matches:
            self.send_error(400, "relay changed the body or signature")
            return

        self.server.succeeded = True
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format: str, *args: Any) -> None:
        """Keep the probe output limited to its pass or fail signal."""


def receive(args: argparse.Namespace) -> int:
    body = args.payload_file.read_bytes()
    secret = args.secret_file.read_bytes()
    server = ProbeServer((args.host, args.port), ProbeHandler)
    server.expected_body = body
    server.expected_signature = _signature(secret, body)
    server.timeout = args.timeout
    sys.stdout.write(f"waiting for one relay request on http://{args.host}:{args.port}\n")
    server.handle_request()
    server.server_close()
    if not server.succeeded:
        sys.stderr.write("relay probe failed or timed out\n")
        return 1
    sys.stdout.write("relay preserved the exact body and HMAC\n")
    return 0


def send(args: argparse.Namespace) -> int:
    body = args.payload_file.read_bytes()
    secret = args.secret_file.read_bytes()
    parsed_url = urllib.parse.urlsplit(args.url)
    local_http = parsed_url.scheme == "http" and parsed_url.hostname in {
        "127.0.0.1",
        "::1",
        "localhost",
    }
    if parsed_url.scheme != "https" and not local_http:
        sys.stderr.write("relay URL must use HTTPS, except for a loopback test\n")
        return 1
    if parsed_url.username or parsed_url.password or parsed_url.fragment:
        sys.stderr.write("relay URL must not contain credentials or a fragment\n")
        return 1

    request = urllib.request.Request(  # noqa: S310 -- scheme validated above
        args.url,
        data=body,
        headers={
            "Content-Type": "application/json",
            SIGNATURE_HEADER: _signature(secret, body),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 -- scheme validated above
            request,
            timeout=args.timeout,
        ) as response:
            status = response.status
    except urllib.error.URLError as error:
        sys.stderr.write(f"relay request failed: {error}\n")
        return 1
    if status != 204:
        sys.stderr.write(f"relay returned unexpected HTTP {status}\n")
        return 1
    sys.stdout.write("relay returned HTTP 204\n")
    return 0


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)

    receiver = subcommands.add_parser("receive")
    receiver.add_argument("--secret-file", type=Path, required=True)
    receiver.add_argument("--payload-file", type=Path, required=True)
    receiver.add_argument("--host", default="127.0.0.1")
    receiver.add_argument("--port", type=int, default=8000)
    receiver.add_argument("--timeout", type=float, default=300)
    receiver.set_defaults(run=receive)

    sender = subcommands.add_parser("send")
    sender.add_argument("--secret-file", type=Path, required=True)
    sender.add_argument("--payload-file", type=Path, required=True)
    sender.add_argument("--url", required=True)
    sender.add_argument("--timeout", type=float, default=30)
    sender.set_defaults(run=send)

    return command


def main() -> int:
    args = parser().parse_args()
    run = cast(Callable[[argparse.Namespace], int], args.run)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
