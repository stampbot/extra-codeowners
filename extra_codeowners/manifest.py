"""GitHub App Manifest registration flow."""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
import jwt

from extra_codeowners.settings import Settings


class ManifestError(RuntimeError):
    """The App Manifest setup handshake failed validation or conversion."""


class ManifestService:
    """Build and exchange GitHub App Manifests.

    Setup is deployment-controlled and disabled by default. Conversion returns
    credentials once, directly to the operator over a no-store response.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.setup_enabled:
            msg = "App Manifest setup is disabled"
            raise ManifestError(msg)
        if settings.public_url is None or settings.setup_state_secret is None:
            msg = "setup requires public_url and setup_state_secret"
            raise ManifestError(msg)
        self.settings = settings
        self._state_secret = settings.setup_state_secret.get_secret_value()
        self._http = httpx.AsyncClient(
            base_url=str(settings.github_api_url).rstrip("/"),
            timeout=20,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "extra-codeowners",
                "X-GitHub-Api-Version": settings.github_api_version,
            },
            transport=transport,
        )

    async def close(self) -> None:
        """Close pooled HTTP connections."""
        await self._http.aclose()

    def issue_state(self) -> str:
        """Issue a short-lived state token bound to this setup flow."""
        now = datetime.now(UTC)
        return str(
            jwt.encode(
                {
                    "iat": int(now.timestamp()),
                    "exp": int(
                        (now + timedelta(seconds=self.settings.setup_state_ttl_seconds)).timestamp()
                    ),
                    "aud": "extra-codeowners-app-manifest",
                },
                self._state_secret,
                algorithm="HS256",
            )
        )

    def validate_state(self, state: str) -> None:
        """Validate setup state signature, expiry, and audience."""
        try:
            jwt.decode(
                state,
                self._state_secret,
                algorithms=["HS256"],
                audience="extra-codeowners-app-manifest",
                options={"require": ["iat", "exp", "aud"]},
            )
        except jwt.PyJWTError as error:
            msg = "invalid or expired App Manifest setup state"
            raise ManifestError(msg) from error

    def manifest(self) -> dict[str, Any]:
        """Return the least-privilege GitHub App Manifest."""
        base = str(self.settings.public_url).rstrip("/")
        return {
            "name": "Extra CODEOWNERS",
            "url": "https://github.com/stampbot/extra-codeowners",
            "description": (
                "Require human CODEOWNER approval or a narrowly delegated GitHub App approval."
            ),
            "public": False,
            "redirect_url": f"{base}/setup/callback",
            "setup_url": f"{base}/setup/complete",
            "setup_on_update": True,
            "request_oauth_on_install": False,
            "hook_attributes": {"url": f"{base}/webhooks/github", "active": True},
            "default_permissions": {
                "checks": "write",
                "contents": "read",
                "members": "read",
                "metadata": "read",
                "pull_requests": "read",
                # GitHub requires this installation permission before an App
                # can be selected as an expected source in organization
                # rulesets. Runtime tokens are downscoped and cannot write
                # commit statuses; this service publishes Check Runs only.
                "statuses": "write",
            },
            "default_events": [
                "check_run",
                "installation_target",
                "label",
                "member",
                "membership",
                "organization",
                "push",
                "pull_request",
                "pull_request_review",
                "repository",
                "team",
                "team_add",
            ],
        }

    def registration_page(self, organization: str | None = None) -> str:
        """Return an auto-submitting manifest form for user or organization ownership."""
        state = self.issue_state()
        if organization:
            action_path = f"organizations/{quote(organization, safe='')}/settings/apps/new"
        else:
            action_path = "settings/apps/new"
        action = f"https://github.com/{action_path}?state={quote(state, safe='')}"
        manifest_json = json.dumps(self.manifest(), separators=(",", ":"))
        return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Create Extra CODEOWNERS GitHub App</title></head>
<body>
<main>
  <h1>Create Extra CODEOWNERS</h1>
  <p>Review the requested permissions on GitHub before creating the App.</p>
  <form method="post" action="{html.escape(action, quote=True)}">
    <input type="hidden" name="manifest" value="{html.escape(manifest_json, quote=True)}">
    <button type="submit">Continue to GitHub</button>
  </form>
</main>
</body>
</html>"""

    async def exchange(self, code: str, state: str) -> dict[str, Any]:
        """Exchange GitHub's single-use code for newly created App credentials."""
        self.validate_state(state)
        response = await self._http.post(f"/app-manifests/{quote(code, safe='')}/conversions")
        if not response.is_success:
            msg = f"GitHub rejected App Manifest conversion with HTTP {response.status_code}"
            raise ManifestError(msg)
        value = response.json()
        if not isinstance(value, dict):
            msg = "GitHub returned a malformed App Manifest conversion"
            raise ManifestError(msg)
        required = ("id", "pem", "webhook_secret")
        if any(not value.get(field) for field in required):
            msg = "GitHub App Manifest conversion omitted required credentials"
            raise ManifestError(msg)
        return value

    @staticmethod
    def credentials_page(credentials: dict[str, Any]) -> str:
        """Render the one-time credential result without embedding executable markup."""
        safe_json = html.escape(json.dumps(credentials, indent=2, sort_keys=True))
        return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Store Extra CODEOWNERS credentials</title></head>
<body>
<main>
  <h1>Store the GitHub App credentials now</h1>
  <p>This service does not retain this response. Put the values in your secret manager,
  then close this page. Never commit them to a repository.</p>
  <pre aria-label="New GitHub App credentials">{safe_json}</pre>
</main>
</body>
</html>"""
