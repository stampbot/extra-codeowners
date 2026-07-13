import httpx
import pytest

from extra_codeowners.manifest import ManifestError, ManifestService
from extra_codeowners.settings import Settings


def setup_settings() -> Settings:
    return Settings(
        _env_file=None,
        setup_enabled=True,
        setup_state_secret="state-secret-with-enough-entropy-for-tests",
        public_url="https://extra-codeowners.example.com",
    )


def test_manifest_requests_only_required_permissions_and_events() -> None:
    service = ManifestService(setup_settings())

    manifest = service.manifest()

    assert manifest["default_permissions"] == {
        "checks": "write",
        "contents": "read",
        "members": "read",
        "metadata": "read",
        "pull_requests": "read",
        "statuses": "write",
    }
    assert manifest["hook_attributes"]["url"] == (
        "https://extra-codeowners.example.com/webhooks/github"
    )
    assert set(manifest["default_events"]) == {
        "check_run",
        "installation_target",
        "label",
        "member",
        "membership",
        "organization",
        "pull_request",
        "pull_request_review",
        "push",
        "repository",
        "team",
        "team_add",
    }
    # GitHub delivers installation and repository-selection lifecycle events
    # to every App and explicitly forbids manual subscription to them.
    assert "installation" not in manifest["default_events"]
    assert "installation_repositories" not in manifest["default_events"]
    assert "issues" not in manifest["default_permissions"]


def test_organization_registration_page_targets_organization_settings() -> None:
    service = ManifestService(setup_settings())

    page = service.registration_page("example-org")

    assert "https://github.com/organizations/example-org/settings/apps/new?state=" in page
    assert 'name="manifest"' in page
    assert "webhook_secret" not in page


def test_personal_registration_page_targets_personal_settings() -> None:
    service = ManifestService(setup_settings())

    page = service.registration_page()

    assert "https://github.com/settings/apps/new?state=" in page


def test_state_rejects_tampering() -> None:
    service = ManifestService(setup_settings())
    state = service.issue_state()

    service.validate_state(state)
    with pytest.raises(ManifestError, match="invalid or expired"):
        service.validate_state(state + "x")


@pytest.mark.asyncio
async def test_exchange_validates_state_and_returns_one_time_credentials() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            201,
            json={"id": 123, "pem": "PRIVATE KEY", "webhook_secret": "SECRET"},
        )

    service = ManifestService(setup_settings(), transport=httpx.MockTransport(handler))
    state = service.issue_state()

    credentials = await service.exchange("one-use-code", state)
    await service.close()

    assert credentials["id"] == 123
    assert captured[0].url.path == "/app-manifests/one-use-code/conversions"


@pytest.mark.asyncio
async def test_exchange_rejects_github_errors_and_incomplete_credentials() -> None:
    responses = iter(
        [
            httpx.Response(422, json={"message": "expired"}),
            httpx.Response(201, json={"id": 123}),
        ]
    )
    service = ManifestService(
        setup_settings(), transport=httpx.MockTransport(lambda request: next(responses))
    )
    state = service.issue_state()

    with pytest.raises(ManifestError, match="HTTP 422"):
        await service.exchange("expired", state)
    with pytest.raises(ManifestError, match="omitted required credentials"):
        await service.exchange("incomplete", state)
    await service.close()


def test_manifest_service_rejects_disabled_setup() -> None:
    with pytest.raises(ManifestError, match="disabled"):
        ManifestService(Settings(_env_file=None))


def test_credentials_page_escapes_untrusted_values() -> None:
    page = ManifestService.credentials_page(
        {"id": 1, "pem": "</pre><script>alert(1)</script>", "webhook_secret": "secret"}
    )

    assert "<script>" not in page
    assert "&lt;/pre&gt;" in page
