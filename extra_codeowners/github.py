"""Least-privilege asynchronous GitHub REST API client."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Final, NoReturn
from urllib.parse import quote

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

MAX_PULL_FILES: Final = 3000
MAX_PULL_REVIEWS: Final = 1000
MAX_CONFIG_BYTES: Final = 1_000_000
MAX_CODEOWNERS_BYTES: Final = 3 * 1024 * 1024


class GitHubError(RuntimeError):
    """Base class for GitHub API failures."""


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
    """A pull request exceeds GitHub's files API visibility limit."""


@dataclass(frozen=True, slots=True)
class InstallationToken:
    """Cached installation token and conservative expiry."""

    value: str
    expires_at: datetime


class GitHubClient:
    """GitHub App and installation REST API client.

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

    async def _installation_token(self, installation_id: int) -> str:
        cached = self._tokens.get(installation_id)
        now = datetime.now(UTC)
        if cached is not None and cached.expires_at > now + timedelta(minutes=5):
            return cached.value

        lock = self._token_locks.setdefault(installation_id, asyncio.Lock())
        async with lock:
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
            )
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
    ) -> httpx.Response:
        """Send an authenticated request, refreshing a rejected installation token once."""
        attempts = 1 if app_authenticated else 2
        for attempt in range(attempts):
            if app_authenticated:
                token = self._app_jwt()
            else:
                assert installation_id is not None
                token = await self._installation_token(installation_id)
            response = await self._http.request(
                method,
                path,
                params=params,
                json=json,
                headers={**(headers or {}), "Authorization": f"Bearer {token}"},
            )
            if response.status_code != 401 or app_authenticated or attempt > 0:
                return response
            assert installation_id is not None
            cached = self._tokens.get(installation_id)
            if cached is not None and cached.value == token:
                self._tokens.pop(installation_id, None)
        raise AssertionError("unreachable")  # pragma: no cover

    async def _authenticated_streaming_response(
        self,
        path: str,
        installation_id: int,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Return an open streamed response, refreshing a rejected token once.

        The caller owns the returned response and must close it. A rejected
        response is closed before its cached token is evicted and retried.
        """
        for attempt in range(2):
            token = await self._installation_token(installation_id)
            request = self._http.build_request(
                "GET",
                path,
                params=params,
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
    def _retry_delay(response: httpx.Response, message: str) -> int | None:
        retry_after = response.headers.get("retry-after")
        remaining = response.headers.get("x-ratelimit-remaining")
        is_limited = response.status_code == 429 or (
            response.status_code == 403
            and (retry_after is not None or remaining == "0" or "rate limit" in message.lower())
        )
        if not is_limited:
            return None

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
        if delay is None:
            reset = response.headers.get("x-ratelimit-reset")
            if reset is not None:
                try:
                    delay = float(reset) - datetime.now(UTC).timestamp()
                except ValueError:
                    delay = None
        if delay is not None and not math.isfinite(delay):
            delay = None
        return max(1, min(math.ceil(delay if delay is not None else 60), 86_400))

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
    ) -> list[dict[str, Any]]:
        query = {**(params or {}), "per_page": 100}
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            query["page"] = page
            response = await self._authenticated_response(
                "GET",
                path,
                installation_id=installation_id,
                params=query,
            )
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
            if len(page_items) < 100:
                break
            page += 1
        return items

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

    async def list_installations(self) -> list[dict[str, Any]]:
        """List every installation visible to the App JWT."""
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            response = await self._authenticated_response(
                "GET",
                "/app/installations",
                app_authenticated=True,
                params={"per_page": 100, "page": page},
            )
            if not response.is_success:
                self._raise_api_error(response, "GET", "/app/installations")
            values = response.json()
            if not isinstance(values, list):
                msg = "expected list response from GET /app/installations"
                raise GitHubError(msg)
            items.extend(item for item in values if isinstance(item, dict))
            if len(values) < 100:
                return items
            page += 1

    async def list_installation_repositories(self, installation_id: int) -> list[dict[str, Any]]:
        """List repositories granted to one installation."""
        result: list[dict[str, Any]] = []
        page = 1
        while True:
            response = await self._request(
                "GET",
                "/installation/repositories",
                installation_id=installation_id,
                params={"per_page": 100, "page": page},
            )
            repositories = response.get("repositories")
            if not isinstance(repositories, list):
                msg = "installation repositories response omitted repositories"
                raise GitHubError(msg)
            result.extend(item for item in repositories if isinstance(item, dict))
            if len(repositories) < 100:
                return result
            page += 1

    async def list_open_pulls(self, installation_id: int, repository: str) -> list[dict[str, Any]]:
        """List open pull requests for reconciliation."""
        return await self._get_list(
            f"/repos/{repository}/pulls",
            installation_id,
            params={"state": "open", "sort": "updated", "direction": "desc"},
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
