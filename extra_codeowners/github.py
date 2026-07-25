"""Least-privilege asynchronous GitHub REST and GraphQL API client."""

from __future__ import annotations

import asyncio
import json as json_module
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Final, Literal, NoReturn
from urllib.parse import parse_qsl, quote, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from extra_codeowners.dco import (
    MAX_COMMIT_MESSAGE_BYTES,
    MAX_PULL_COMMITS,
    CommitEvidence,
    PullCommit,
    PullCommitComparison,
    PullRequestSnapshot,
    RepositoryIdentity,
)

MAX_PULL_FILES: Final = 3000
MAX_PULL_REVIEWS: Final = 1000
MAX_DCO_COMMIT_LIST_RESPONSE_BYTES: Final = 256 * 1024
MAX_DCO_COMMIT_DETAIL_RESPONSE_BYTES: Final = 8 * 1024 * 1024
MAX_DCO_AGGREGATE_MESSAGE_BYTES: Final = 16 * 1024 * 1024
MAX_DCO_DETAIL_CONCURRENCY: Final = 2
MAX_JSON_RESPONSE_DEPTH: Final = 64
MAX_CONFIG_BYTES: Final = 1_000_000
MAX_CODEOWNERS_BYTES: Final = 3 * 1024 * 1024

_REPOSITORY_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_LINK_PARAMETER_RE = re.compile(
    r""";\s*([!#$%&'*+\-.^_`|~0-9A-Za-z]+)\s*=\s*"""
    r"""(?:"((?:\\.|[^"\\])*)"|([^;,\s]+))\s*"""
)

_DCO_PULL_COMMITS_QUERY: Final = """\
query DcoPullCommits(
  $owner: String!
  $name: String!
  $number: Int!
  $cursor: String
) {
  repository(owner: $owner, name: $name) {
    databaseId
    nameWithOwner
    pullRequest(number: $number) {
      number
      state
      baseRefName
      baseRefOid
      baseRepository { databaseId nameWithOwner }
      headRefName
      headRefOid
      headRepository { databaseId nameWithOwner }
      commits(first: 100, after: $cursor) {
        totalCount
        nodes { id commit { oid } }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

_DCO_COMMIT_QUERY: Final = """\
query DcoCommit($id: ID!) {
  node(id: $id) {
    __typename
    ... on PullRequestCommit {
      id
      pullRequest {
        number
        state
        baseRefName
        baseRefOid
        baseRepository { databaseId nameWithOwner }
        headRefName
        headRefOid
        headRepository { databaseId nameWithOwner }
        repository { databaseId nameWithOwner }
      }
      commit {
        oid
        parents(first: 65) {
          totalCount
          nodes { oid }
          pageInfo { hasNextPage endCursor }
        }
        message
        author { name email user { login databaseId } }
        committer { name email }
        signature {
          isValid
          state
          verifiedAt
          wasSignedByGitHub
          signer { login databaseId }
        }
      }
    }
  }
}
"""


def _dco_repository_path(repository: str) -> str:
    """Validate an exact repository name before using it in a DCO REST path."""
    if (
        not isinstance(repository, str)
        or not repository.isascii()
        or len(repository) > 512
        or not _REPOSITORY_FULL_NAME_RE.fullmatch(repository)
        or any(component in {".", ".."} for component in repository.split("/"))
    ):
        raise ValueError("repository must be a GitHub-safe ASCII owner/repository name")
    return repository


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object while rejecting ambiguous duplicate names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    """Reject non-standard numeric constants accepted by Python's JSON parser."""
    raise ValueError(f"JSON response contains the non-standard constant {value}")


def _validate_json_nesting(value: str) -> None:
    """Enforce a parser-independent bound on JSON container nesting."""
    depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_RESPONSE_DEPTH:
                raise ValueError("JSON response exceeds the nesting-depth limit")
        elif character in "]}":
            depth = max(0, depth - 1)


class GitHubError(RuntimeError):
    """Base class for GitHub API failures."""


class GitHubOperationStoppedError(GitHubError):
    """The caller requested a stop between GitHub API operations."""


class GitHubAPIError(GitHubError):
    """A non-success GitHub API response."""

    def __init__(self, status_code: int, method: str, path: str, message: str) -> None:
        super().__init__(f"GitHub API {method} {path} returned {status_code}: {message}")
        self.status_code = status_code
        self.method = method
        self.path = path


class GitHubRateLimitError(GitHubAPIError):
    """GitHub asked the caller to wait before retrying."""

    def __init__(
        self,
        status_code: int,
        method: str,
        path: str,
        message: str,
        retry_after_seconds: int,
    ) -> None:
        super().__init__(status_code, method, path, message)
        self.retry_after_seconds = retry_after_seconds


class PullRequestTooLargeError(GitHubError):
    """A pull request exceeds a supported API completeness bound."""


@dataclass(frozen=True, slots=True)
class InstallationToken:
    """Cached installation token and conservative expiry."""

    value: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _BoundedJsonResponse:
    """Parsed JSON plus the bounded retry metadata needed after HTTP 200."""

    payload: Any
    status_code: int
    retry_after: str | None
    rate_limit_remaining: str | None
    rate_limit_reset: str | None


class GitHubClient:
    """GitHub App and installation API client.

    The caller supplies only an App ID and PEM key. Installation tokens are
    cached in memory and never logged or persisted.
    """

    def __init__(
        self,
        app_id: int,
        private_key: str,
        *,
        api_url: str = "https://api.github.com",
        api_version: str = "2026-03-10",
        timeout_seconds: float = 20,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.app_id = app_id
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a finite positive number")
        self._request_deadline_seconds = timeout_seconds
        try:
            loaded_key = serialization.load_pem_private_key(private_key.encode(), password=None)
        except (TypeError, ValueError) as error:
            msg = "GitHub App private key is not a valid unencrypted PEM private key"
            raise ValueError(msg) from error
        if not isinstance(loaded_key, RSAPrivateKey):
            msg = "GitHub App private key must be an RSA private key"
            raise ValueError(msg)
        self._private_key = loaded_key
        self._tokens: dict[int, InstallationToken] = {}
        self._token_locks: dict[int, asyncio.Lock] = {}
        self._http = httpx.AsyncClient(
            base_url=api_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "extra-codeowners",
                "X-GitHub-Api-Version": api_version,
            },
        )

    async def close(self) -> None:
        """Close pooled HTTP connections."""
        await self._http.aclose()

    def _app_jwt(self) -> str:
        now = datetime.now(UTC)
        payload = {
            "iat": int((now - timedelta(seconds=60)).timestamp()),
            "exp": int((now + timedelta(minutes=9)).timestamp()),
            "iss": str(self.app_id),
        }
        return str(jwt.encode(payload, self._private_key, algorithm="RS256"))

    async def verify_app_identity(
        self,
        *,
        stop: asyncio.Event | None = None,
    ) -> None:
        """Verify that these credentials authenticate as the configured App ID."""
        response = await self._request(
            "GET",
            "/app",
            app_authenticated=True,
            stop=stop,
        )
        authenticated_app_id = response.get("id")
        if (
            isinstance(authenticated_app_id, bool)
            or not isinstance(authenticated_app_id, int)
            or authenticated_app_id != self.app_id
        ):
            raise GitHubError(
                "authenticated GitHub App identity does not match the configured App ID"
            )

    async def _installation_token(
        self,
        installation_id: int,
        *,
        stop: asyncio.Event | None = None,
    ) -> str:
        self._raise_if_stopped(stop)
        cached = self._tokens.get(installation_id)
        now = datetime.now(UTC)
        if cached is not None and cached.expires_at > now + timedelta(minutes=5):
            return cached.value

        lock = self._token_locks.setdefault(installation_id, asyncio.Lock())
        async with lock:
            self._raise_if_stopped(stop)
            cached = self._tokens.get(installation_id)
            if cached is not None and cached.expires_at > now + timedelta(minutes=5):
                return cached.value
            response = await self._request(
                "POST",
                f"/app/installations/{installation_id}/access_tokens",
                app_authenticated=True,
                json={
                    "permissions": {
                        "checks": "write",
                        "contents": "read",
                        "members": "read",
                        "pull_requests": "read",
                    }
                },
                stop=stop,
            )
            self._raise_if_stopped(stop)
            token = response.get("token")
            expires_at = response.get("expires_at")
            if not isinstance(token, str) or not isinstance(expires_at, str):
                msg = "installation-token response omitted token or expiry"
                raise GitHubError(msg)
            parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            self._tokens[installation_id] = InstallationToken(token, parsed_expiry)
            return token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        installation_id: int | None = None,
        app_authenticated: bool = False,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        allow_not_found: bool = False,
        stop: asyncio.Event | None = None,
    ) -> dict[str, Any]:
        if app_authenticated == (installation_id is not None):
            msg = "request must use exactly one authentication mode"
            raise ValueError(msg)
        response = await self._authenticated_response(
            method,
            path,
            installation_id=installation_id,
            app_authenticated=app_authenticated,
            params=params,
            json=json,
            headers=headers,
            stop=stop,
        )
        if allow_not_found and response.status_code == 404:
            return {}
        if response.is_success:
            if response.status_code == 204 or not response.content:
                return {}
            value = response.json()
            if not isinstance(value, dict):
                msg = f"expected object response from {method} {path}"
                raise GitHubError(msg)
            return value
        self._raise_api_error(response, method, path)
        raise AssertionError("unreachable")  # pragma: no cover

    async def _authenticated_response(
        self,
        method: str,
        path: str,
        *,
        installation_id: int | None = None,
        app_authenticated: bool = False,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        stop: asyncio.Event | None = None,
    ) -> httpx.Response:
        """Send an authenticated request, refreshing a rejected installation token once."""
        attempts = 1 if app_authenticated else 2
        for attempt in range(attempts):
            self._raise_if_stopped(stop)
            if app_authenticated:
                token = self._app_jwt()
            else:
                assert installation_id is not None
                token = await self._installation_token(installation_id, stop=stop)
            self._raise_if_stopped(stop)
            try:
                async with asyncio.timeout(self._request_deadline_seconds):
                    response = await self._http.request(
                        method,
                        path,
                        params=params,
                        json=json,
                        headers={**(headers or {}), "Authorization": f"Bearer {token}"},
                    )
            except TimeoutError as error:
                if stop is not None and stop.is_set():
                    raise GitHubOperationStoppedError(
                        "GitHub operation stopped during a request"
                    ) from error
                raise GitHubError("GitHub API request exceeded its wall-clock deadline") from error
            except httpx.TimeoutException as error:
                if stop is not None and stop.is_set():
                    raise GitHubOperationStoppedError(
                        "GitHub operation stopped during a request"
                    ) from error
                raise
            self._raise_if_stopped(stop)
            if response.status_code != 401 or app_authenticated or attempt > 0:
                return response
            assert installation_id is not None
            cached = self._tokens.get(installation_id)
            if cached is not None and cached.value == token:
                self._tokens.pop(installation_id, None)
        raise AssertionError("unreachable")  # pragma: no cover

    async def _authenticated_streaming_response(
        self,
        method: str,
        path: str,
        installation_id: int,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Return an open streamed response, refreshing a rejected token once.

        The caller owns the returned response and must close it. A rejected
        response is closed before its cached token is evicted and retried.
        """
        for attempt in range(2):
            token = await self._installation_token(installation_id)
            request = self._http.build_request(
                method,
                path,
                params=params,
                json=json,
                headers={**(headers or {}), "Authorization": f"Bearer {token}"},
            )
            response = await self._http.send(request, stream=True)
            if response.status_code != 401 or attempt > 0:
                return response
            await response.aclose()
            cached = self._tokens.get(installation_id)
            if cached is not None and cached.value == token:
                self._tokens.pop(installation_id, None)
        raise AssertionError("unreachable")  # pragma: no cover

    @staticmethod
    async def _bounded_error_response(response: httpx.Response, max_bytes: int) -> httpx.Response:
        """Read a bounded error prefix into a response safe for error parsing."""
        limit = max(0, min(max_bytes, 1000))
        content = bytearray()
        if limit:
            async for chunk in response.aiter_bytes(chunk_size=min(limit, 64 * 1024)):
                remaining = limit - len(content)
                content.extend(chunk[:remaining])
                if len(content) == limit:
                    break
        # aiter_bytes() has already decoded transfer/content encodings. Do not
        # make the synthetic response decode the bounded prefix a second time.
        headers = [
            (name, value)
            for name, value in response.headers.multi_items()
            if name.lower() not in {"content-encoding", "content-length", "transfer-encoding"}
        ]
        return httpx.Response(
            response.status_code,
            headers=headers,
            content=bytes(content),
            request=response.request,
        )

    @staticmethod
    def _response_message(response: httpx.Response) -> str:
        message = response.text[:1000]
        try:
            body = response.json()
            if isinstance(body, dict) and isinstance(body.get("message"), str):
                message = body["message"][:1000]
        except ValueError:
            return message
        return message

    @staticmethod
    def _bounded_retry_delay(
        retry_after: str | None,
        rate_limit_reset: str | None,
    ) -> int:
        """Normalize provider retry metadata to the service's safe delay range."""
        delay: float | None = None
        if retry_after is not None:
            try:
                delay = float(retry_after)
            except ValueError:
                try:
                    parsed = parsedate_to_datetime(retry_after)
                    delay = (parsed - datetime.now(UTC)).total_seconds()
                except (TypeError, ValueError, OverflowError):
                    delay = None
        if delay is None and rate_limit_reset is not None:
            try:
                delay = float(rate_limit_reset) - datetime.now(UTC).timestamp()
            except ValueError:
                delay = None
        if delay is not None and not math.isfinite(delay):
            delay = None
        return max(1, min(math.ceil(delay if delay is not None else 60), 86_400))

    @classmethod
    def _retry_delay(cls, response: httpx.Response, message: str) -> int | None:
        retry_after = response.headers.get("retry-after")
        remaining = response.headers.get("x-ratelimit-remaining")
        is_limited = response.status_code == 429 or (
            response.status_code == 403
            and (retry_after is not None or remaining == "0" or "rate limit" in message.lower())
        )
        if not is_limited:
            return None
        return cls._bounded_retry_delay(
            retry_after,
            response.headers.get("x-ratelimit-reset"),
        )

    @classmethod
    def _raise_api_error(cls, response: httpx.Response, method: str, path: str) -> NoReturn:
        message = cls._response_message(response)
        retry_after = cls._retry_delay(response, message)
        if retry_after is not None:
            raise GitHubRateLimitError(
                response.status_code,
                method,
                path,
                message,
                retry_after,
            )
        raise GitHubAPIError(response.status_code, method, path, message)

    async def _get_list(
        self,
        path: str,
        installation_id: int,
        *,
        params: dict[str, Any] | None = None,
        max_items: int | None = None,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        query = {**(params or {}), "per_page": 100}
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            self._raise_if_stopped(stop)
            query["page"] = page
            response = await self._authenticated_response(
                "GET",
                path,
                installation_id=installation_id,
                params=query,
                stop=stop,
            )
            self._raise_if_stopped(stop)
            if not response.is_success:
                self._raise_api_error(response, "GET", path)
            page_items = response.json()
            if not isinstance(page_items, list):
                msg = f"expected list response from GET {path}"
                raise GitHubError(msg)
            for item in page_items:
                if not isinstance(item, dict):
                    msg = f"expected object items from GET {path}"
                    raise GitHubError(msg)
                items.append(item)
                if max_items is not None and len(items) > max_items:
                    msg = f"GET {path} exceeded the supported {max_items}-item limit"
                    raise PullRequestTooLargeError(msg)
            if not self._response_has_next_page(response, page, len(page_items)):
                break
            page += 1
        return items

    @staticmethod
    def _raise_if_stopped(stop: asyncio.Event | None) -> None:
        if stop is not None and stop.is_set():
            raise GitHubOperationStoppedError("GitHub operation stopped between requests")

    @staticmethod
    def _split_link_header(value: str) -> list[str]:
        """Split a Link field without treating URL or quoted commas as separators."""
        parts: list[str] = []
        start = 0
        in_url = False
        in_quote = False
        escaped = False
        for index, character in enumerate(value):
            if in_quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_quote = False
                continue
            if character == '"':
                in_quote = True
            elif character == "<":
                if in_url:
                    raise GitHubError("GitHub pagination Link header is malformed")
                in_url = True
            elif character == ">":
                if not in_url:
                    raise GitHubError("GitHub pagination Link header is malformed")
                in_url = False
            elif character == "," and not in_url:
                part = value[start:index].strip()
                if not part:
                    raise GitHubError("GitHub pagination Link header is malformed")
                parts.append(part)
                start = index + 1
        if in_url or in_quote or escaped:
            raise GitHubError("GitHub pagination Link header is malformed")
        part = value[start:].strip()
        if not part:
            raise GitHubError("GitHub pagination Link header is malformed")
        parts.append(part)
        return parts

    @classmethod
    def _next_link_target(
        cls,
        response: httpx.Response,
    ) -> str | None | Literal[False]:
        """Return the unique next target, False for a terminal Link, or None if absent."""
        values = response.headers.get_list("link")
        if not values:
            return None
        entries = cls._split_link_header(",".join(values))
        next_target: str | None = None
        for entry in entries:
            match = re.match(r"^\s*<([^<>]+)>\s*", entry)
            if match is None:
                raise GitHubError("GitHub pagination Link header is malformed")
            target = match.group(1)
            position = match.end()
            parameters: dict[str, str] = {}
            while position < len(entry):
                parameter = _LINK_PARAMETER_RE.match(entry, position)
                if parameter is None:
                    raise GitHubError("GitHub pagination Link header is malformed")
                name = parameter.group(1).casefold()
                if name in parameters:
                    raise GitHubError("GitHub pagination Link header repeats a parameter")
                quoted_value = parameter.group(2)
                value = (
                    re.sub(r"\\(.)", r"\1", quoted_value)
                    if quoted_value is not None
                    else parameter.group(3)
                )
                parameters[name] = value
                position = parameter.end()
            relations = parameters.get("rel", "").casefold().split()
            if "next" not in relations:
                continue
            if next_target is not None:
                raise GitHubError("GitHub pagination Link header has multiple next links")
            next_target = target
        return next_target if next_target is not None else False

    @classmethod
    def _response_has_next_page(
        cls,
        response: httpx.Response,
        current_page: int,
        page_item_count: int,
        *,
        full_page_fallback: bool = True,
    ) -> bool:
        """Validate pagination metadata and decide whether another page exists."""
        target = cls._next_link_target(response)
        if target is None:
            return full_page_fallback and page_item_count == 100
        if target is False:
            return False

        try:
            next_url = urlsplit(target)
            request_url = urlsplit(str(response.request.url))
            next_scheme = next_url.scheme.casefold()
            request_scheme = request_url.scheme.casefold()
            next_port = next_url.port
            request_port = request_url.port
            if next_port is None:
                next_port = {"http": 80, "https": 443}.get(next_scheme)
            if request_port is None:
                request_port = {"http": 80, "https": 443}.get(request_scheme)
        except ValueError as error:
            raise GitHubError("GitHub pagination next link is invalid") from error
        if (
            not next_url.scheme
            or not next_url.netloc
            or next_url.username is not None
            or next_url.password is not None
            or next_url.fragment
            or next_scheme != request_scheme
            or next_url.hostname is None
            or request_url.hostname is None
            or next_url.hostname.casefold() != request_url.hostname.casefold()
            or next_port != request_port
            or next_url.path != request_url.path
        ):
            raise GitHubError("GitHub pagination next link does not match the request endpoint")
        next_query = parse_qsl(next_url.query, keep_blank_values=True)
        request_query = parse_qsl(request_url.query, keep_blank_values=True)
        page_values = [value for name, value in next_query if name == "page"]
        request_page_values = [value for name, value in request_query if name == "page"]
        expected_page = current_page + 1
        if (
            len(page_values) != 1
            or not page_values[0].isascii()
            or not page_values[0].isdecimal()
            or int(page_values[0]) != expected_page
        ):
            raise GitHubError("GitHub pagination next link has an invalid page number")
        if (
            len(request_page_values) != 1
            or not request_page_values[0].isascii()
            or not request_page_values[0].isdecimal()
            or int(request_page_values[0]) != current_page
        ):
            raise GitHubError("GitHub pagination request has an invalid page number")
        next_non_page = sorted((name, value) for name, value in next_query if name != "page")
        request_non_page = sorted((name, value) for name, value in request_query if name != "page")
        if next_non_page != request_non_page:
            raise GitHubError("GitHub pagination next link changes the request query")
        return True

    async def _bounded_json_request(
        self,
        method: str,
        path: str,
        installation_id: int,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        max_bytes: int,
    ) -> _BoundedJsonResponse:
        """Read and parse one size-limited JSON response."""
        response = await self._authenticated_streaming_response(
            method,
            path,
            installation_id,
            params=params,
            json=json,
        )
        try:
            if not response.is_success:
                error_response = await self._bounded_error_response(response, 1000)
                self._raise_api_error(error_response, method, path)

            content_length = response.headers.get("content-length")
            normalized_length = content_length.strip() if content_length is not None else ""
            declared_length = (
                int(normalized_length)
                if normalized_length.isascii() and normalized_length.isdecimal()
                else None
            )
            if declared_length is not None and declared_length > max_bytes:
                raise GitHubError(f"{method} {path} exceeds the {max_bytes}-byte response limit")

            content = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=min(max_bytes, 64 * 1024)):
                if len(chunk) > max_bytes - len(content):
                    raise GitHubError(
                        f"{method} {path} exceeds the {max_bytes}-byte response limit"
                    )
                content.extend(chunk)
            try:
                decoded = bytes(content).decode("utf-8")
                if decoded.startswith("\ufeff"):
                    raise ValueError("JSON response must not contain a UTF-8 BOM")
                _validate_json_nesting(decoded)
                payload = json_module.loads(
                    decoded,
                    object_pairs_hook=_unique_json_object,
                    parse_constant=_reject_json_constant,
                )
            except (UnicodeDecodeError, RecursionError, ValueError) as error:
                raise GitHubError(f"expected JSON response from {method} {path}") from error
            return _BoundedJsonResponse(
                payload=payload,
                status_code=response.status_code,
                retry_after=response.headers.get("retry-after"),
                rate_limit_remaining=response.headers.get("x-ratelimit-remaining"),
                rate_limit_reset=response.headers.get("x-ratelimit-reset"),
            )
        finally:
            await response.aclose()

    async def _get_bounded_json(
        self,
        path: str,
        installation_id: int,
        *,
        params: dict[str, Any] | None = None,
        max_bytes: int,
    ) -> Any:
        """Read and parse one size-limited GET response."""
        response = await self._bounded_json_request(
            "GET",
            path,
            installation_id,
            params=params,
            max_bytes=max_bytes,
        )
        return response.payload

    async def get_pull(self, installation_id: int, repository: str, number: int) -> dict[str, Any]:
        """Fetch current pull request metadata."""
        return await self._request(
            "GET", f"/repos/{repository}/pulls/{number}", installation_id=installation_id
        )

    async def get_pull_files(
        self, installation_id: int, repository: str, number: int
    ) -> list[dict[str, Any]]:
        """Fetch every visible changed file, failing at GitHub's 3,000-file cap."""
        items = await self._get_list(
            f"/repos/{repository}/pulls/{number}/files",
            installation_id,
            max_items=MAX_PULL_FILES,
        )
        if len(items) >= MAX_PULL_FILES:
            # GitHub truncates at 3,000, so exactly 3,000 cannot prove completeness.
            msg = f"pull request has at least GitHub's {MAX_PULL_FILES:,}-file API limit"
            raise PullRequestTooLargeError(msg)
        return items

    async def get_reviews(
        self, installation_id: int, repository: str, number: int
    ) -> list[dict[str, Any]]:
        """Fetch all submitted pull request reviews."""
        return await self._get_list(
            f"/repos/{repository}/pulls/{number}/reviews",
            installation_id,
            max_items=MAX_PULL_REVIEWS,
        )

    async def _graphql(
        self,
        installation_id: int,
        *,
        query: str,
        variables: dict[str, Any],
        operation: str,
        max_bytes: int,
    ) -> dict[str, Any]:
        """Run one bounded GraphQL query and reject partial/error responses."""
        response = await self._bounded_json_request(
            "POST",
            "/graphql",
            installation_id,
            json={"query": query, "variables": variables},
            max_bytes=max_bytes,
        )
        payload = response.payload
        if not isinstance(payload, dict):
            raise GitHubError(f"GraphQL {operation} returned a non-object response")
        errors = payload.get("errors")
        if errors is not None and (not isinstance(errors, list) or errors):
            if self._graphql_errors_are_rate_limited(
                errors,
                retry_after=response.retry_after,
                rate_limit_remaining=response.rate_limit_remaining,
            ):
                retry_delay = self._bounded_retry_delay(
                    response.retry_after,
                    response.rate_limit_reset,
                )
                raise GitHubRateLimitError(
                    response.status_code,
                    "POST",
                    "/graphql",
                    f"GraphQL {operation} was rate limited",
                    retry_delay,
                )
            raise GitHubError(f"GraphQL {operation} returned errors")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise GitHubError(f"GraphQL {operation} omitted its data object")
        return data

    @staticmethod
    def _graphql_errors_are_rate_limited(
        errors: Any,
        *,
        retry_after: str | None,
        rate_limit_remaining: str | None,
    ) -> bool:
        """Recognize GitHub's HTTP-200 primary and secondary limit responses."""
        if retry_after is not None or rate_limit_remaining == "0":
            return True
        if not isinstance(errors, list):
            return False
        for error in errors:
            if not isinstance(error, dict):
                continue
            error_type = error.get("type")
            if isinstance(error_type, str) and error_type.casefold() == "rate_limited":
                return True
            extensions = error.get("extensions")
            if isinstance(extensions, dict):
                code = extensions.get("code")
                if isinstance(code, str) and code.casefold() == "rate_limited":
                    return True
            message = error.get("message")
            if isinstance(message, str) and "rate limit" in message.casefold():
                return True
        return False

    @staticmethod
    def _graphql_repository(value: Any, field: str) -> RepositoryIdentity:
        if not isinstance(value, dict):
            raise GitHubError(f"GraphQL {field} must be an object")
        repository_id = value.get("databaseId")
        full_name = value.get("nameWithOwner")
        if type(repository_id) is not int or not isinstance(full_name, str):
            raise GitHubError(f"GraphQL {field} has an invalid identity")
        try:
            return RepositoryIdentity(
                id=repository_id,
                full_name=full_name,
            )
        except ValueError as error:
            raise GitHubError(f"GraphQL {field} has an invalid identity") from error

    @classmethod
    def _validate_graphql_pull_identity(
        cls,
        value: Any,
        pull: PullRequestSnapshot,
        *,
        repository: Any,
    ) -> dict[str, Any]:
        """Bind a selected GraphQL pull object to the exact REST snapshot."""
        if not isinstance(value, dict):
            raise GitHubError("GraphQL pull request must be an object")
        if cls._graphql_repository(repository, "repository") != pull.repository:
            raise GitHubError("GraphQL repository identity changed during DCO collection")
        allowed_states = {"OPEN"} if pull.state == "open" else {"CLOSED", "MERGED"}
        base_repository = cls._graphql_repository(value.get("baseRepository"), "base repository")
        head_repository = cls._graphql_repository(value.get("headRepository"), "head repository")
        if (
            type(value.get("number")) is not int
            or value.get("number") != pull.number
            or value.get("state") not in allowed_states
            or value.get("baseRefName") != pull.base_ref
            or value.get("baseRefOid") != pull.base_sha
            or base_repository != pull.base_repository
            or value.get("headRefName") != pull.head_ref
            or value.get("headRefOid") != pull.head_sha
            or head_repository != pull.head_repository
        ):
            raise GitHubError("GraphQL pull request identity changed during DCO collection")
        return value

    async def compare_pull_commits(
        self,
        installation_id: int,
        pull: PullRequestSnapshot,
    ) -> PullCommitComparison:
        """List only commit OIDs, binding every page to the exact pull snapshot."""
        expected_count = pull.commit_count
        if expected_count > MAX_PULL_COMMITS:
            msg = f"pull request exceeds the supported {MAX_PULL_COMMITS}-commit limit"
            raise PullRequestTooLargeError(msg)

        repository_path = _dco_repository_path(pull.repository.full_name)
        owner, name = repository_path.split("/", maxsplit=1)
        items: list[PullCommit] = []
        seen_shas: set[str] = set()
        seen_node_ids: set[str] = set()
        seen_cursors: set[str] = set()
        cursor: str | None = None

        while True:
            data = await self._graphql(
                installation_id,
                query=_DCO_PULL_COMMITS_QUERY,
                variables={
                    "owner": owner,
                    "name": name,
                    "number": pull.number,
                    "cursor": cursor,
                },
                operation="DCO pull commit list",
                max_bytes=MAX_DCO_COMMIT_LIST_RESPONSE_BYTES,
            )
            repository = data.get("repository")
            if not isinstance(repository, dict):
                raise GitHubError("GraphQL DCO pull commit list omitted its repository")
            pull_payload = self._validate_graphql_pull_identity(
                repository.get("pullRequest"),
                pull,
                repository=repository,
            )
            commits = pull_payload.get("commits")
            if not isinstance(commits, dict):
                raise GitHubError("GraphQL pull request omitted its commit connection")
            total_count = commits.get("totalCount")
            if type(total_count) is not int or total_count < 1:
                raise GitHubError("GraphQL pull commit count is invalid")
            if total_count > MAX_PULL_COMMITS:
                msg = f"pull request exceeds the supported {MAX_PULL_COMMITS}-commit limit"
                raise PullRequestTooLargeError(msg)
            if total_count != expected_count:
                raise GitHubError("GraphQL pull commit count does not match the snapshot")

            nodes = commits.get("nodes")
            page_info = commits.get("pageInfo")
            if not isinstance(nodes, list) or not isinstance(page_info, dict):
                raise GitHubError("GraphQL pull commit page is malformed")
            remaining = expected_count - len(items)
            expected_page_items = min(100, remaining)
            if len(nodes) != expected_page_items:
                raise GitHubError("GraphQL pull commit page is incomplete")
            for node in nodes:
                if not isinstance(node, dict):
                    raise GitHubError("GraphQL pull commit page contains a null node")
                try:
                    item = PullCommit.from_graphql(node)
                except ValueError as error:
                    raise GitHubError("GraphQL pull commit node is invalid") from error
                if item.sha in seen_shas or item.node_id in seen_node_ids:
                    raise GitHubError("GraphQL pull commit page repeated a commit")
                seen_shas.add(item.sha)
                seen_node_ids.add(item.node_id)
                items.append(item)

            has_next_page = page_info.get("hasNextPage")
            end_cursor = page_info.get("endCursor")
            if type(has_next_page) is not bool:
                raise GitHubError("GraphQL pull commit page has invalid pagination metadata")
            expected_next_page = len(items) < expected_count
            if has_next_page != expected_next_page:
                raise GitHubError("GraphQL pull commit pagination disagrees with its count")
            cursor_bytes = 0
            if end_cursor is not None:
                if not isinstance(end_cursor, str):
                    raise GitHubError("GraphQL pull commit cursor is invalid")
                try:
                    cursor_bytes = len(end_cursor.encode("utf-8"))
                except UnicodeEncodeError as error:
                    raise GitHubError("GraphQL pull commit cursor is invalid") from error
                if cursor_bytes > 4096:
                    raise GitHubError("GraphQL pull commit cursor is invalid")
            if not has_next_page:
                break
            if not isinstance(end_cursor, str) or not end_cursor or end_cursor in seen_cursors:
                raise GitHubError("GraphQL pull commit cursor is invalid")
            seen_cursors.add(end_cursor)
            cursor = end_cursor

        if len(items) != expected_count:
            raise GitHubError("GraphQL pull commit list is incomplete")
        if items[-1].sha != pull.head_sha:
            raise GitHubError("GraphQL pull commit list did not end at the snapshot head")
        return PullCommitComparison(
            repository=pull.repository,
            pull_number=pull.number,
            base_sha=pull.base_sha,
            head_sha=pull.head_sha,
            base_commit_sha=pull.base_sha,
            total_commits=expected_count,
            ahead_by=expected_count,
            commits=tuple(items),
        )

    async def _get_pull_commit_evidence(
        self,
        installation_id: int,
        pull: PullRequestSnapshot,
        item: PullCommit,
    ) -> tuple[CommitEvidence, int]:
        data = await self._graphql(
            installation_id,
            query=_DCO_COMMIT_QUERY,
            variables={"id": item.node_id},
            operation="DCO commit detail",
            max_bytes=MAX_DCO_COMMIT_DETAIL_RESPONSE_BYTES,
        )
        node = data.get("node")
        if not isinstance(node, dict) or node.get("__typename") != "PullRequestCommit":
            raise GitHubError("GraphQL DCO commit detail returned the wrong node type")
        if node.get("id") != item.node_id:
            raise GitHubError("GraphQL DCO commit detail returned the wrong node")
        pull_payload = node.get("pullRequest")
        if not isinstance(pull_payload, dict):
            raise GitHubError("GraphQL DCO commit detail omitted its pull request")
        self._validate_graphql_pull_identity(
            pull_payload,
            pull,
            repository=pull_payload.get("repository"),
        )
        commit = node.get("commit")
        if not isinstance(commit, dict) or commit.get("oid") != item.sha:
            raise GitHubError("GraphQL DCO commit detail returned the wrong commit")
        message = commit.get("message")
        if not isinstance(message, str):
            raise GitHubError("GraphQL DCO commit detail omitted its message")
        try:
            message_bytes = len(message.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise GitHubError("GraphQL DCO commit message is not valid Unicode") from error
        if message_bytes > MAX_COMMIT_MESSAGE_BYTES:
            raise GitHubError(f"commit message exceeds the {MAX_COMMIT_MESSAGE_BYTES}-byte limit")
        try:
            evidence = CommitEvidence.from_graphql(commit)
        except ValueError as error:
            raise GitHubError("GraphQL DCO commit detail is invalid") from error
        return evidence, message_bytes

    async def get_pull_commit_evidence(
        self,
        installation_id: int,
        pull: PullRequestSnapshot,
    ) -> tuple[PullCommitComparison, tuple[CommitEvidence, ...]]:
        """Collect bounded DCO commit evidence with at most two detail requests in flight."""
        comparison = await self.compare_pull_commits(installation_id, pull)
        evidence: list[CommitEvidence] = []
        message_bytes = 0
        for offset in range(0, len(comparison.commits), MAX_DCO_DETAIL_CONCURRENCY):
            batch = comparison.commits[offset : offset + MAX_DCO_DETAIL_CONCURRENCY]
            tasks = [
                asyncio.create_task(self._get_pull_commit_evidence(installation_id, pull, item))
                for item in batch
            ]
            try:
                results = await asyncio.gather(*tasks)
            except BaseException:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            for item_evidence, item_message_bytes in results:
                message_bytes += item_message_bytes
                if message_bytes > MAX_DCO_AGGREGATE_MESSAGE_BYTES:
                    raise GitHubError(
                        "pull-request commit messages exceed the aggregate DCO evidence limit"
                    )
                evidence.append(item_evidence)
        return comparison, tuple(evidence)

    async def get_codeowners_errors(
        self, installation_id: int, repository: str, ref: str
    ) -> list[dict[str, Any]]:
        """Ask GitHub to validate CODEOWNERS at the exact base revision."""
        result = await self._request(
            "GET",
            f"/repos/{repository}/codeowners/errors",
            installation_id=installation_id,
            params={"ref": ref},
        )
        errors = result.get("errors")
        if not isinstance(errors, list):
            msg = "CODEOWNERS errors response omitted its errors list"
            raise GitHubError(msg)
        if any(not isinstance(item, dict) for item in errors):
            msg = "CODEOWNERS errors response contained a malformed error"
            raise GitHubError(msg)
        return errors

    async def get_file_text(
        self,
        installation_id: int,
        repository: str,
        path: str,
        *,
        ref: str | None = None,
        max_bytes: int = MAX_CONFIG_BYTES,
    ) -> str | None:
        """Read bounded raw UTF-8 repository content, returning ``None`` for 404."""
        params = {"ref": ref} if ref is not None else None
        encoded_path = quote(path, safe="/")
        endpoint = f"/repos/{repository}/contents/{encoded_path}"
        response = await self._authenticated_streaming_response(
            "GET",
            endpoint,
            installation_id,
            params=params,
            headers={
                "Accept": "application/vnd.github.raw+json",
            },
        )
        try:
            if response.status_code == 404:
                return None
            if not response.is_success:
                error_response = await self._bounded_error_response(response, max_bytes)
                self._raise_api_error(error_response, "GET", endpoint)

            content_length = response.headers.get("content-length")
            normalized_length = content_length.strip() if content_length is not None else ""
            declared_length = (
                int(normalized_length)
                if normalized_length.isascii() and normalized_length.isdecimal()
                else None
            )
            if declared_length is not None and declared_length > max_bytes:
                msg = f"{repository}:{path} exceeds the {max_bytes}-byte file limit"
                raise GitHubError(msg)

            content = bytearray()
            chunk_size = max(1, min(max_bytes, 64 * 1024))
            async for chunk in response.aiter_bytes(chunk_size=chunk_size):
                if len(chunk) > max_bytes - len(content):
                    msg = f"{repository}:{path} exceeds the {max_bytes}-byte file limit"
                    raise GitHubError(msg)
                content.extend(chunk)
            try:
                return content.decode("utf-8")
            except UnicodeDecodeError as error:
                msg = f"{repository}:{path} is not valid UTF-8"
                raise GitHubError(msg) from error
        finally:
            await response.aclose()

    async def team_member(
        self,
        installation_id: int,
        organization: str,
        team_slug: str,
        username: str,
    ) -> bool:
        """Return whether a user is an active member of an organization team."""
        result = await self._request(
            "GET",
            f"/orgs/{organization}/teams/{team_slug}/memberships/{username}",
            installation_id=installation_id,
            allow_not_found=True,
        )
        return result.get("state") == "active"

    async def user_can_own_repository(
        self,
        installation_id: int,
        repository: str,
        username: str,
    ) -> bool:
        """Return whether a direct CODEOWNER candidate currently has write access."""
        result = await self._request(
            "GET",
            f"/repos/{repository}/collaborators/{username}/permission",
            installation_id=installation_id,
            allow_not_found=True,
        )
        return result.get("permission") in {"write", "maintain", "admin"}

    async def team_can_own_repository(
        self,
        installation_id: int,
        organization: str,
        team_slug: str,
        repository: str,
    ) -> bool:
        """Return whether a visible team explicitly grants write access."""
        team = await self._request(
            "GET",
            f"/orgs/{organization}/teams/{team_slug}",
            installation_id=installation_id,
            allow_not_found=True,
        )
        if team.get("privacy") != "closed":
            return False
        repository_metadata = await self._request(
            "GET",
            f"/orgs/{organization}/teams/{team_slug}/repos/{repository}",
            installation_id=installation_id,
            headers={"Accept": "application/vnd.github.v3.repository+json"},
            allow_not_found=True,
        )
        permissions = repository_metadata.get("permissions")
        if not isinstance(permissions, dict):
            return False
        return any(permissions.get(level) is True for level in ("push", "maintain", "admin"))

    async def get_app(self, installation_id: int, slug: str) -> dict[str, Any]:
        """Fetch independently observed public identity metadata for an allowed App."""
        return await self._request(
            "GET",
            f"/apps/{slug}",
            installation_id=installation_id,
        )

    async def _latest_check_run_id(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
    ) -> int | None:
        existing = await self._request(
            "GET",
            f"/repos/{repository}/commits/{head_sha}/check-runs",
            installation_id=installation_id,
            params={
                "check_name": check_name,
                "filter": "latest",
                "app_id": self.app_id,
                "per_page": 100,
            },
        )
        runs = existing.get("check_runs", [])
        if not isinstance(runs, list):
            msg = "check-runs response omitted its list"
            raise GitHubError(msg)
        for run in runs:
            if not isinstance(run, dict) or run.get("name") != check_name:
                continue
            app = run.get("app")
            if isinstance(app, dict) and app.get("id") == self.app_id:
                candidate = run.get("id")
                if isinstance(candidate, int):
                    return candidate
        return None

    async def has_check_run(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
    ) -> bool:
        """Return whether this App already manages the named check on a commit."""
        return (
            await self._latest_check_run_id(
                installation_id,
                repository,
                head_sha,
                check_name,
            )
            is not None
        )

    async def existing_check_run_id(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
    ) -> int | None:
        """Return this App's latest exact check ID without creating one."""
        return await self._latest_check_run_id(
            installation_id,
            repository,
            head_sha,
            check_name,
        )

    async def reset_check_run(
        self,
        installation_id: int,
        repository: str,
        check_run_id: int,
        check_name: str,
        *,
        title: str,
        summary: str,
        text: str = "",
        details_url: str | None = None,
        external_id: str | None = None,
    ) -> None:
        """PATCH one known App check to blocking state without a POST fallback."""
        payload: dict[str, Any] = {
            "name": check_name,
            "status": "in_progress",
            "started_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "output": {
                "title": title[:255],
                "summary": summary[:65535],
                "text": text[:65535],
            },
        }
        if details_url is not None:
            payload["details_url"] = details_url
        if external_id is not None:
            payload["external_id"] = external_id[:255]
        result = await self._request(
            "PATCH",
            f"/repos/{repository}/check-runs/{check_run_id}",
            installation_id=installation_id,
            json=payload,
        )
        candidate = result.get("id")
        if not isinstance(candidate, int) or isinstance(candidate, bool):
            raise GitHubError("check-run response omitted its integer ID")
        if candidate != check_run_id:
            raise GitHubError("check-run response changed the requested check ID")

    async def upsert_check_run(
        self,
        installation_id: int,
        repository: str,
        head_sha: str,
        check_name: str,
        *,
        status: str = "completed",
        conclusion: str | None = None,
        title: str,
        summary: str,
        text: str = "",
        details_url: str | None = None,
        external_id: str | None = None,
    ) -> int:
        """Create or update this App's latest named check on a commit."""
        if status not in {"queued", "in_progress", "completed"}:
            raise ValueError("unsupported check-run status")
        if status == "completed" and conclusion is None:
            raise ValueError("completed check runs require a conclusion")
        if status != "completed" and conclusion is not None:
            raise ValueError("non-completed check runs cannot have a conclusion")
        check_id = await self._latest_check_run_id(
            installation_id,
            repository,
            head_sha,
            check_name,
        )

        payload: dict[str, Any] = {
            "name": check_name,
            "status": status,
            "output": {"title": title[:255], "summary": summary[:65535], "text": text[:65535]},
        }
        if status == "completed":
            payload["conclusion"] = conclusion
            payload["completed_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        elif status == "in_progress":
            payload["started_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        if details_url is not None:
            payload["details_url"] = details_url
        if external_id is not None:
            payload["external_id"] = external_id[:255]
        if check_id is None:
            payload["head_sha"] = head_sha
            result = await self._request(
                "POST",
                f"/repos/{repository}/check-runs",
                installation_id=installation_id,
                json=payload,
            )
        else:
            payload.pop("name")
            result = await self._request(
                "PATCH",
                f"/repos/{repository}/check-runs/{check_id}",
                installation_id=installation_id,
                json=payload,
            )
        result_id = result.get("id")
        if not isinstance(result_id, int):
            msg = "check-run response omitted its integer ID"
            raise GitHubError(msg)
        return result_id

    async def list_installations(
        self,
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        """List every installation visible to the App JWT."""
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            self._raise_if_stopped(stop)
            response = await self._authenticated_response(
                "GET",
                "/app/installations",
                app_authenticated=True,
                params={"per_page": 100, "page": page},
                stop=stop,
            )
            self._raise_if_stopped(stop)
            if not response.is_success:
                self._raise_api_error(response, "GET", "/app/installations")
            values = response.json()
            if not isinstance(values, list):
                msg = "expected list response from GET /app/installations"
                raise GitHubError(msg)
            for item in values:
                if not isinstance(item, dict):
                    msg = "expected object items from GET /app/installations"
                    raise GitHubError(msg)
                items.append(item)
            if not self._response_has_next_page(response, page, len(values)):
                return items
            page += 1

    async def list_installation_repositories(
        self,
        installation_id: int,
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        """List repositories granted to one installation."""
        result: list[dict[str, Any]] = []
        expected_total: int | None = None
        page = 1
        while True:
            self._raise_if_stopped(stop)
            response = await self._authenticated_response(
                "GET",
                "/installation/repositories",
                installation_id=installation_id,
                params={"per_page": 100, "page": page},
                stop=stop,
            )
            self._raise_if_stopped(stop)
            if not response.is_success:
                self._raise_api_error(response, "GET", "/installation/repositories")
            payload = response.json()
            if not isinstance(payload, dict):
                msg = "expected object response from GET /installation/repositories"
                raise GitHubError(msg)
            total_count = payload.get("total_count")
            if isinstance(total_count, bool) or not isinstance(total_count, int) or total_count < 0:
                msg = "installation repositories response omitted a nonnegative integer total_count"
                raise GitHubError(msg)
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                msg = "installation repositories response changed total_count between pages"
                raise GitHubError(msg)
            repositories = payload.get("repositories")
            if not isinstance(repositories, list):
                msg = "installation repositories response omitted repositories"
                raise GitHubError(msg)
            for item in repositories:
                if not isinstance(item, dict):
                    msg = "expected object items from GET /installation/repositories"
                    raise GitHubError(msg)
                result.append(item)
            if len(result) > expected_total:
                msg = "installation repositories response exceeded total_count"
                raise GitHubError(msg)
            has_next = self._response_has_next_page(
                response,
                page,
                len(repositories),
                full_page_fallback=len(result) < expected_total,
            )
            if has_next and len(result) >= expected_total:
                msg = "installation repositories response has a next page after total_count"
                raise GitHubError(msg)
            if not has_next:
                if len(result) != expected_total:
                    msg = "installation repositories response ended before total_count"
                    raise GitHubError(msg)
                return result
            page += 1

    async def list_open_pulls(
        self,
        installation_id: int,
        repository: str,
        *,
        stop: asyncio.Event | None = None,
    ) -> list[dict[str, Any]]:
        """List open pull requests for reconciliation."""
        return await self._get_list(
            f"/repos/{repository}/pulls",
            installation_id,
            params={"state": "open", "sort": "updated", "direction": "desc"},
            stop=stop,
        )

    async def list_commit_pulls(
        self, installation_id: int, repository: str, head_sha: str
    ) -> list[dict[str, Any]]:
        """List pull requests associated with a commit for shared-head detection."""
        return await self._get_list(
            f"/repos/{repository}/commits/{head_sha}/pulls",
            installation_id,
            max_items=100,
        )
