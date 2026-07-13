"""Tests for strict configuration and evaluation models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from extra_codeowners.models import (
    ActorKind,
    ChangedFile,
    ChangedFileStatus,
    Delegation,
    EvaluationConclusion,
    EvaluationMessage,
    EvaluationResult,
    OrganizationPolicy,
    OwnerSetResult,
    PathEvidence,
    PullRequestReview,
    RepositoryPolicy,
    ReviewActor,
    ReviewState,
)


def test_org_policy_parses_apps_and_guardrails_from_toml() -> None:
    policy = OrganizationPolicy.from_toml(
        """
        schema_version = 1

        [apps.example_automation]
        slug = "stampbot"
        app_id = 2909932
        bot_user_id = 262871904

        [guardrails]
        non_delegable_paths = ["/secrets/**"]
        """
    )

    assert policy.apps["example_automation"].app_id == 2909932
    assert policy.guardrails.non_delegable_paths == ("/secrets/**",)


def test_policy_rejects_unknown_fields_and_duplicate_app_identity() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        OrganizationPolicy.model_validate({"schema_version": 1, "typo": True})

    with pytest.raises(ValidationError, match="duplicate GitHub App id"):
        OrganizationPolicy.model_validate(
            {
                "apps": {
                    "one": {"slug": "one", "app_id": 1, "bot_user_id": 10},
                    "two": {"slug": "two", "app_id": 1, "bot_user_id": 20},
                }
            }
        )

    with pytest.raises(ValidationError):
        OrganizationPolicy.model_validate(
            {"apps": {"bot": {"slug": "bot", "app_id": True, "bot_user_id": "2"}}}
        )


def test_repository_policy_is_explicit_opt_in_and_parses_delegation() -> None:
    assert RepositoryPolicy().enabled is False

    policy = RepositoryPolicy.from_toml(
        """
        schema_version = 1
        enabled = true

        [[delegations]]
        app = "StampBot"
        paths = ["**/*.lock"]
        for_owners = ["@Example/Infrastructure"]
        required_labels = ["Automated"]
        forbidden_labels = ["Needs Human"]
        """
    )

    delegation = policy.delegations[0]
    assert delegation.app == "stampbot"
    assert delegation.for_owners == ("@example/infrastructure",)
    assert delegation.required_labels == frozenset({"automated"})
    assert delegation.forbidden_labels == frozenset({"needs human"})

    with pytest.raises(ValidationError):
        RepositoryPolicy.model_validate({"enabled": "true"})


def test_committed_toml_requires_explicit_schema_version() -> None:
    with pytest.raises(ValueError, match="organization policy requires schema_version"):
        OrganizationPolicy.from_toml("[apps]\n")
    with pytest.raises(ValueError, match="repository policy requires schema_version"):
        RepositoryPolicy.from_toml("enabled = true\n")
    with pytest.raises(ValueError, match="explicit enabled"):
        RepositoryPolicy.from_toml("schema_version = 1\n")
    with pytest.raises(ValidationError, match="integer 1"):
        RepositoryPolicy.from_toml("schema_version = true\nenabled = false\n")
    with pytest.raises(ValidationError, match="integer 1"):
        OrganizationPolicy.from_toml("schema_version = 1.0\n")


@pytest.mark.parametrize("owners", [[], ["*", "@example/infra"], ["owner@example.com"]])
def test_delegation_requires_explicit_valid_owner_scope(owners: list[str]) -> None:
    with pytest.raises(ValidationError):
        Delegation(app="stampbot", paths=("**",), for_owners=owners)


def test_delegation_rejects_conflicting_label_conditions() -> None:
    with pytest.raises(ValidationError, match="both required and forbidden"):
        Delegation(
            app="stampbot",
            paths=("**",),
            for_owners=("*",),
            required_labels=frozenset({"automated"}),
            forbidden_labels=frozenset({"AUTOMATED"}),
        )


def test_rename_requires_a_distinct_previous_path() -> None:
    with pytest.raises(ValidationError, match="require previous_path"):
        ChangedFile(path="new/name.py", status=ChangedFileStatus.RENAMED)

    changed = ChangedFile(
        path="new/name.py",
        previous_path="old/name.py",
        status=ChangedFileStatus.RENAMED,
    )
    assert changed.previous_path == "old/name.py"


def test_changed_file_path_is_not_silently_whitespace_normalized() -> None:
    with pytest.raises(ValidationError, match="whitespace are unsupported"):
        ChangedFile(path=" docs/file.txt ")


def test_check_output_cannot_be_structurally_forged_by_repository_evidence() -> None:
    result = EvaluationResult(
        conclusion=EvaluationConclusion.FAILURE,
        summary="real summary\n### Forged summary",
        errors=(
            EvaluationMessage(
                code="bad`</code><h1>",
                message="real error\n- forged result",
            ),
        ),
        requirements=(
            OwnerSetResult(
                owners=("@owner</code><h1>",),
                paths=("safe",),
                satisfied=False,
                explanation="real explanation\n### Forged requirement",
                path_evidence=(
                    PathEvidence(
                        path="unsafe`\n### Forged path",
                        non_delegable=False,
                        explanation="real evidence\n> forged quote",
                    ),
                ),
            ),
        ),
        unowned_paths=("unowned\u202e\n### Forged unowned",),
    )

    output = result.check_output()

    assert "\n### Forged" not in output
    assert "</code><h1>" not in output
    assert "&lt;/code&gt;&lt;h1&gt;" in output
    assert r"\n###" in output
    assert "&lt;U+202E&gt;" in output


def test_application_review_requires_complete_identity_and_aware_time() -> None:
    with pytest.raises(ValidationError, match="require app_id and app_slug"):
        ReviewActor(kind=ActorKind.APPLICATION, login="bot[bot]", user_id=1)

    actor = ReviewActor(
        kind=ActorKind.APPLICATION,
        login="StampBot[bot]",
        user_id=262871904,
        app_id=2909932,
        app_slug="StampBot",
    )
    review = PullRequestReview(
        review_id=1,
        actor=actor,
        state=ReviewState.APPROVED,
        commit_sha="ABC",
        submitted_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert review.actor.login == "stampbot[bot]"
    assert review.commit_sha == "abc"

    with pytest.raises(ValidationError, match="timezone"):
        PullRequestReview(
            review_id=2,
            actor=actor,
            state=ReviewState.APPROVED,
            commit_sha="abc",
            submitted_at=datetime.min,  # noqa: DTZ901 - deliberately invalid evidence
        )
