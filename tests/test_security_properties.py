"""Bounded generative tests for security-sensitive, untrusted inputs."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import string
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from extra_codeowners.codeowners import CodeownersParseError, parse_codeowners
from extra_codeowners.database import JobRequest
from extra_codeowners.evaluator import evaluate
from extra_codeowners.github import (
    GitHubClient,
    InstallationToken,
    PullRequestTooLargeError,
)
from extra_codeowners.models import (
    ChangedFile,
    ChangedFileStatus,
    EvaluationConclusion,
    EvaluationInput,
    OrganizationPolicy,
    RepositoryPolicy,
)
from extra_codeowners.policy import compile_policy
from extra_codeowners.webhooks import (
    PULL_REQUEST_ACTIONS,
    VerifiedWebhook,
    WebhookError,
    evaluation_job,
    verify_webhook,
)

EXCLUDED_CATEGORIES: tuple[Literal["Cs"], ...] = ("Cs",)
SAFE_TEXT = st.text(
    alphabet=st.characters(exclude_categories=EXCLUDED_CATEGORIES),
    max_size=16_384,
)
SAFE_TOKEN = st.text(alphabet=string.ascii_lowercase + string.digits, min_size=1, max_size=16)
SAFE_FILENAME = st.builds(lambda stem: f"{stem}.txt", SAFE_TOKEN)
DISTINCT_FILENAMES = st.builds(
    lambda stem: (f"{stem}-old.txt", f"{stem}-new.txt"),
    SAFE_TOKEN,
)


def _signature(body: bytes) -> str:
    return "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()


@pytest.mark.property
@given(body=st.binary(max_size=65_536))
@example(body=b'{"action":"opened"}')
def test_invalid_webhook_signatures_always_fail_closed(body: bytes) -> None:
    with pytest.raises(WebhookError, match="signature mismatch"):
        verify_webhook(
            body,
            signature="sha256=not-a-valid-digest",
            delivery_id="synthetic-delivery",
            event="pull_request",
            secret="secret",
        )


JSON_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(alphabet=st.characters(exclude_categories=EXCLUDED_CATEGORIES), max_size=256),
)


@pytest.mark.property
@given(value=st.one_of(JSON_SCALAR, st.lists(JSON_SCALAR, max_size=32)))
@example(value=[])
def test_authenticated_non_object_webhooks_fail_closed(value: object) -> None:
    body = json.dumps(value).encode()
    with pytest.raises(WebhookError, match="root must be an object"):
        verify_webhook(
            body,
            signature=_signature(body),
            delivery_id="synthetic-delivery",
            event="pull_request",
            secret="secret",
        )


@pytest.mark.property
@given(
    action=st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**63), max_value=2**63 - 1),
        st.lists(JSON_SCALAR, max_size=8),
    )
)
def test_authenticated_non_string_actions_fail_closed(action: object) -> None:
    body = json.dumps({"action": action}).encode()
    with pytest.raises(WebhookError, match="action must be a string"):
        verify_webhook(
            body,
            signature=_signature(body),
            delivery_id="synthetic-delivery",
            event="pull_request",
            secret="secret",
        )


@pytest.mark.property
@given(
    action=st.sampled_from(sorted(PULL_REQUEST_ACTIONS)),
    installation_id=st.integers(min_value=1, max_value=2**31 - 1),
    pull_number=st.integers(min_value=1, max_value=2**31 - 1),
)
def test_supported_pull_request_events_map_to_exact_job(
    action: str,
    installation_id: int,
    pull_number: int,
) -> None:
    webhook = VerifiedWebhook(
        delivery_id="synthetic-delivery",
        event="pull_request",
        action=action,
        payload={
            "action": action,
            "installation": {"id": installation_id},
            "repository": {"full_name": "Example/Project"},
            "pull_request": {
                "number": pull_number,
                "state": "closed" if action == "closed" else "open",
                "head": {"sha": "a" * 40},
            },
        },
    )

    job = evaluation_job(webhook)

    assert isinstance(job, JobRequest)
    assert job.installation_id == installation_id
    assert job.repository_full_name == "example/project"
    assert job.pull_number == pull_number
    assert job.reason == f"pull_request.{action}"
    assert job.head_sha_hint == "a" * 40


@pytest.mark.property
@given(event_suffix=SAFE_TOKEN, action=SAFE_TOKEN)
def test_unknown_webhook_events_never_enqueue_work(event_suffix: str, action: str) -> None:
    webhook = VerifiedWebhook(
        delivery_id="synthetic-delivery",
        event=f"synthetic-{event_suffix}",
        action=action,
        payload={"action": action},
    )

    assert evaluation_job(webhook) is None


@pytest.mark.property
@given(content=SAFE_TEXT, path=SAFE_FILENAME)
@example(content="!private/** @example/security\n", path="private/key.txt")
def test_codeowners_parser_has_only_explicit_success_or_failure(
    content: str,
    path: str,
) -> None:
    try:
        document = parse_codeowners(content)
    except CodeownersParseError as error:
        assert error.issues
        assert all(issue.code and issue.message for issue in error.issues)
        return

    owners = document.owners_for(path)
    assert isinstance(owners, tuple)
    assert all(owner.startswith("@") and owner == owner.lower() for owner in owners)


@pytest.mark.property
@given(
    invalid=st.sampled_from(("!private/**", "docs/[ab].md", "docs\\private.md")),
    owner=SAFE_TOKEN,
)
def test_unsupported_codeowners_patterns_never_become_rules(invalid: str, owner: str) -> None:
    with pytest.raises(CodeownersParseError) as caught:
        parse_codeowners(f"{invalid} @{owner}\n")

    assert caught.value.issues[0].code == "invalid_pattern"


@pytest.mark.property
@given(path=SAFE_FILENAME, fallback=SAFE_TOKEN, selected=SAFE_TOKEN)
def test_codeowners_last_literal_rule_wins(path: str, fallback: str, selected: str) -> None:
    document = parse_codeowners(f"* @{fallback}\n/{path} @{selected}\n")

    assert document.owners_for(path) == (f"@{selected}",)
    assert document.owners_for("unrelated.txt") == (f"@{fallback}",)


@pytest.mark.property
@given(path=SAFE_FILENAME, required_label=SAFE_TOKEN)
def test_valid_toml_policy_composition_only_narrows_delegation(
    path: str,
    required_label: str,
) -> None:
    organization = OrganizationPolicy.from_toml(
        """
        schema_version = 1

        [apps.automation]
        slug = "automation"
        app_id = 1001
        bot_user_id = 2001
        """
    )
    repository = RepositoryPolicy.from_toml(
        f"""
        schema_version = 1
        enabled = true

        [[delegations]]
        app = "automation"
        paths = ["/{path}"]
        for_owners = ["@example/platform"]
        required_labels = ["{required_label}"]
        """
    )
    compiled = compile_policy(organization, repository)
    owners = frozenset({"@example/platform"})

    without_label = compiled.delegation_decisions(path, owners, frozenset())
    with_label = compiled.delegation_decisions(path, owners, frozenset({required_label}))

    assert len(without_label) == len(with_label) == 1
    assert without_label[0].eligible is False
    assert with_label[0].eligible is True


@pytest.mark.property
@given(extra_patterns=st.integers(min_value=1, max_value=10))
def test_repository_toml_pattern_limit_fails_closed(extra_patterns: int) -> None:
    pattern_count = 1000 + extra_patterns
    delegations: list[str] = []
    for offset in range(0, pattern_count, 100):
        paths = [
            f'"/generated/{index}.txt"' for index in range(offset, min(offset + 100, pattern_count))
        ]
        delegations.append(
            "\n".join(
                (
                    "[[delegations]]",
                    'app = "automation"',
                    f"paths = [{', '.join(paths)}]",
                    'for_owners = ["@example/platform"]',
                )
            )
        )
    content = "schema_version = 1\nenabled = true\n\n" + "\n\n".join(delegations)

    with pytest.raises(ValueError, match="1,000 delegation patterns"):
        RepositoryPolicy.from_toml(content)


@pytest.mark.property
@given(paths=DISTINCT_FILENAMES)
def test_rename_evaluation_keeps_old_and_new_owner_requirements(paths: tuple[str, str]) -> None:
    old_path, new_path = paths
    result = evaluate(
        EvaluationInput(
            head_sha="synthetic-head",
            codeowners_text=(f"/{old_path} @example/legacy\n/{new_path} @example/current\n"),
            changed_files=(
                ChangedFile(
                    path=new_path,
                    previous_path=old_path,
                    status=ChangedFileStatus.RENAMED,
                ),
            ),
            organization_policy=OrganizationPolicy(),
            repository_policy=RepositoryPolicy(enabled=True),
        )
    )

    assert result.conclusion is EvaluationConclusion.FAILURE
    requirements = {requirement.owners: requirement.paths for requirement in result.requirements}
    assert requirements[("@example/legacy",)] == (old_path,)
    assert requirements[("@example/current",)] == (new_path,)


@pytest.mark.property
@given(full_pages=st.integers(min_value=0, max_value=1), tail=st.lists(SAFE_TOKEN, max_size=20))
def test_github_pagination_stops_only_after_a_short_page(
    private_key: str,
    full_pages: int,
    tail: list[str],
) -> None:
    requested_pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        requested_pages.append(page)
        if page <= full_pages:
            return httpx.Response(200, json=[{"value": index} for index in range(100)])
        return httpx.Response(200, json=[{"value": value} for value in tail])

    async def exercise() -> list[dict[str, Any]]:
        client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
        client._tokens[2] = InstallationToken(
            "synthetic-token",
            datetime.now(UTC) + timedelta(hours=1),
        )
        try:
            return await client._get_list("/synthetic", 2)
        finally:
            await client.close()

    items = asyncio.run(exercise())

    assert len(items) == full_pages * 100 + len(tail)
    assert requested_pages == list(range(1, full_pages + 2))


@pytest.mark.property
@given(max_items=st.integers(0, 150))
def test_github_pagination_fails_closed_above_caller_limit(
    private_key: str,
    max_items: int,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        if page == 1:
            page_size = 100 if max_items >= 100 else max_items + 1
            return httpx.Response(200, json=[{"value": index} for index in range(page_size)])
        if page == 2:
            tail_size = max_items - 100 + 1
            return httpx.Response(200, json=[{"value": index} for index in range(tail_size)])
        raise AssertionError(f"unexpected page {page}")

    async def exercise() -> None:
        client = GitHubClient(1, private_key, transport=httpx.MockTransport(handler))
        client._tokens[2] = InstallationToken(
            "synthetic-token",
            datetime.now(UTC) + timedelta(hours=1),
        )
        try:
            with pytest.raises(PullRequestTooLargeError):
                await client._get_list(
                    "/synthetic",
                    2,
                    max_items=max_items,
                )
        finally:
            await client.close()

    asyncio.run(exercise())


@pytest.mark.property
@given(
    message=st.text(
        alphabet=st.characters(exclude_categories=EXCLUDED_CATEGORIES),
        max_size=4000,
    )
)
def test_structured_github_errors_are_bounded(message: str) -> None:
    response = httpx.Response(500, json={"message": message})

    assert GitHubClient._response_message(response) == message[:1000]


@pytest.mark.property
@given(
    retry_after=st.text(
        alphabet=string.ascii_letters + string.digits + " .,:;+-/",
        max_size=64,
    )
)
def test_rate_limit_retry_delay_is_always_bounded(retry_after: str) -> None:
    response = httpx.Response(429, headers={"retry-after": retry_after})

    delay = GitHubClient._retry_delay(response, "rate limit")

    assert delay is not None
    assert 1 <= delay <= 86_400
