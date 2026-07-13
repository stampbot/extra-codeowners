"""End-to-end unit tests for the network-free approval evaluator."""

from datetime import UTC, datetime, timedelta

from extra_codeowners.evaluator import evaluate, latest_opinionated_reviews
from extra_codeowners.models import (
    ActorKind,
    ChangedFile,
    ChangedFileStatus,
    Delegation,
    EnrolledApplication,
    EvaluationConclusion,
    EvaluationInput,
    EvaluationOptions,
    Guardrails,
    OrganizationPolicy,
    PullRequestReview,
    RepositoryPolicy,
    ReviewActor,
    ReviewState,
)

HEAD_SHA = "a" * 40
OLD_SHA = "b" * 40
NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def organization(*, guardrails: tuple[str, ...] = ()) -> OrganizationPolicy:
    return OrganizationPolicy(
        apps={
            "stampbot": EnrolledApplication(
                slug="stampbot",
                app_id=2909932,
                bot_user_id=262871904,
            ),
            "other-bot": EnrolledApplication(
                slug="other-bot",
                app_id=42,
                bot_user_id=43,
            ),
        },
        guardrails=Guardrails(non_delegable_paths=guardrails),
    )


def repository(*delegations: Delegation, enabled: bool = True) -> RepositoryPolicy:
    return RepositoryPolicy(enabled=enabled, delegations=delegations)


def delegation(
    *,
    app: str = "stampbot",
    paths: tuple[str, ...] = ("**",),
    owners: tuple[str, ...] = ("*",),
    required_labels: tuple[str, ...] = (),
    forbidden_labels: tuple[str, ...] = (),
) -> Delegation:
    return Delegation(
        app=app,
        paths=paths,
        for_owners=owners,
        required_labels=frozenset(required_labels),
        forbidden_labels=frozenset(forbidden_labels),
    )


def app_review(
    *,
    review_id: int = 1,
    state: ReviewState = ReviewState.APPROVED,
    sha: str = HEAD_SHA,
    submitted_at: datetime = NOW,
    app_id: int = 2909932,
    app_slug: str = "stampbot",
    bot_user_id: int = 262871904,
    login: str | None = None,
) -> PullRequestReview:
    return PullRequestReview(
        review_id=review_id,
        actor=ReviewActor(
            kind=ActorKind.APPLICATION,
            login=login or f"{app_slug}[bot]",
            user_id=bot_user_id,
            app_id=app_id,
            app_slug=app_slug,
        ),
        state=state,
        commit_sha=sha,
        submitted_at=submitted_at,
    )


def human_review(
    *,
    review_id: int = 10,
    login: str = "alice",
    owner_aliases: tuple[str, ...] = (),
    state: ReviewState = ReviewState.APPROVED,
    sha: str = HEAD_SHA,
    submitted_at: datetime = NOW,
) -> PullRequestReview:
    return PullRequestReview(
        review_id=review_id,
        actor=ReviewActor(
            kind=ActorKind.HUMAN,
            login=login,
            user_id=review_id + 100,
            owner_aliases=frozenset(owner_aliases),
        ),
        state=state,
        commit_sha=sha,
        submitted_at=submitted_at,
    )


def evaluation(
    *,
    codeowners: str = "* @example/infra\n",
    files: tuple[ChangedFile, ...] = (ChangedFile(path="deps/lock.json"),),
    reviews: tuple[PullRequestReview, ...] = (),
    repo: RepositoryPolicy | None = None,
    org: OrganizationPolicy | None = None,
    labels: tuple[str, ...] = (),
    options: EvaluationOptions | None = None,
) -> EvaluationInput:
    return EvaluationInput(
        head_sha=HEAD_SHA,
        codeowners_text=codeowners,
        changed_files=files,
        reviews=reviews,
        labels=frozenset(labels),
        organization_policy=org or organization(),
        repository_policy=repo or repository(delegation()),
        options=options or EvaluationOptions(),
    )


def test_current_enrolled_app_approval_satisfies_delegated_owner_set() -> None:
    result = evaluate(evaluation(reviews=(app_review(),)))

    assert result.conclusion is EvaluationConclusion.SUCCESS
    assert result.requirements[0].satisfied_by == ("app:stampbot",)
    assert result.requirements[0].path_evidence[0].approved_apps == ("stampbot",)
    assert "✅" in result.check_output()


def test_all_three_application_identity_fields_must_match_enrollment() -> None:
    result = evaluate(evaluation(reviews=(app_review(app_id=999),)))

    assert result.conclusion is EvaluationConclusion.FAILURE
    assert result.requirements[0].satisfied is False
    assert {warning.code for warning in result.warnings} == {"untrusted_application_review_ignored"}

    login_mismatch = evaluate(evaluation(reviews=(app_review(login="impostor[bot]"),)))
    assert login_mismatch.conclusion is EvaluationConclusion.FAILURE


def test_latest_opinionated_review_wins_but_later_comment_does_not_supersede() -> None:
    approved = app_review(review_id=1, submitted_at=NOW)
    comment = app_review(
        review_id=2,
        state=ReviewState.COMMENTED,
        submitted_at=NOW + timedelta(minutes=1),
    )
    rejected = app_review(
        review_id=3,
        state=ReviewState.CHANGES_REQUESTED,
        submitted_at=NOW + timedelta(minutes=2),
    )

    assert latest_opinionated_reviews((approved, comment)) == (approved,)
    result = evaluate(evaluation(reviews=(approved, comment, rejected)))
    assert result.conclusion is EvaluationConclusion.FAILURE


def test_exact_head_freshness_is_default_and_can_be_explicitly_disabled() -> None:
    stale = app_review(sha=OLD_SHA)
    strict_result = evaluate(evaluation(reviews=(stale,)))
    relaxed_result = evaluate(
        evaluation(
            reviews=(stale,),
            options=EvaluationOptions(exact_head_reviews=False),
        )
    )

    assert strict_result.conclusion is EvaluationConclusion.FAILURE
    assert strict_result.warnings[0].code == "stale_approval_ignored"
    assert relaxed_result.conclusion is EvaluationConclusion.SUCCESS


def test_human_team_member_satisfies_non_delegable_workflow_path() -> None:
    data = evaluation(
        files=(ChangedFile(path=".github/workflows/release.yml"),),
        reviews=(human_review(owner_aliases=("@example/infra",)), app_review()),
    )
    result = evaluate(data)

    assert result.conclusion is EvaluationConclusion.SUCCESS
    assert result.requirements[0].satisfied_by == ("human:@alice",)
    assert result.requirements[0].path_evidence[0].non_delegable is True


def test_application_cannot_approve_builtin_non_delegable_path() -> None:
    result = evaluate(
        evaluation(
            files=(ChangedFile(path=".github/extra-codeowners.toml"),),
            reviews=(app_review(),),
        )
    )

    assert result.conclusion is EvaluationConclusion.FAILURE
    evidence = result.requirements[0].path_evidence[0]
    assert evidence.non_delegable is True
    assert "security-sensitive" in evidence.explanation


def test_insecure_escape_removes_builtin_but_not_organization_guardrails() -> None:
    insecure = EvaluationOptions(allow_insecure_changes=True)
    built_in_result = evaluate(
        evaluation(
            files=(ChangedFile(path=".github/workflows/release.yml"),),
            reviews=(app_review(),),
            options=insecure,
        )
    )
    org_result = evaluate(
        evaluation(
            files=(ChangedFile(path="secrets/production.txt"),),
            reviews=(app_review(),),
            org=organization(guardrails=("/secrets/**",)),
            options=insecure,
        )
    )

    assert built_in_result.conclusion is EvaluationConclusion.SUCCESS
    assert built_in_result.warnings[0].code == "insecure_changes_enabled"
    assert "### Warnings" in built_in_result.check_output()
    assert org_result.conclusion is EvaluationConclusion.FAILURE


def test_mixed_delegated_and_uncovered_paths_require_a_human() -> None:
    repo = repository(delegation(paths=("/deps/**",), owners=("@example/infra",)))
    result = evaluate(
        evaluation(
            files=(ChangedFile(path="deps/lock.json"), ChangedFile(path="src/main.py")),
            reviews=(app_review(),),
            repo=repo,
        )
    )

    assert result.conclusion is EvaluationConclusion.FAILURE
    evidence = {item.path: item for item in result.requirements[0].path_evidence}
    assert evidence["deps/lock.json"].approved_apps == ("stampbot",)
    assert evidence["src/main.py"].eligible_apps == ()


def test_every_distinct_owner_set_must_be_satisfied() -> None:
    codeowners = "/infra/** @example/infra\n/security/** @example/security\n"
    repo = repository(delegation(paths=("/infra/**",), owners=("@example/infra",)))
    result = evaluate(
        evaluation(
            codeowners=codeowners,
            files=(ChangedFile(path="infra/main.tf"), ChangedFile(path="security/policy.rego")),
            reviews=(app_review(),),
            repo=repo,
        )
    )

    assert result.conclusion is EvaluationConclusion.FAILURE
    assert len(result.requirements) == 2
    assert sum(requirement.satisfied for requirement in result.requirements) == 1


def test_rename_evaluates_both_old_and_new_ownership() -> None:
    result = evaluate(
        evaluation(
            codeowners="/old/** @example/legacy\n/new/** @example/infra\n",
            files=(
                ChangedFile(
                    path="new/name.py",
                    previous_path="old/name.py",
                    status=ChangedFileStatus.RENAMED,
                ),
            ),
            reviews=(app_review(),),
            repo=repository(delegation(paths=("/new/**",), owners=("@example/infra",))),
        )
    )

    assert result.conclusion is EvaluationConclusion.FAILURE
    assert {requirement.owners for requirement in result.requirements} == {
        ("@example/legacy",),
        ("@example/infra",),
    }


def test_labels_only_restrict_app_eligibility_and_do_not_block_human() -> None:
    repo = repository(
        delegation(
            required_labels=("automated",),
            forbidden_labels=("needs-human",),
        )
    )
    app_result = evaluate(evaluation(reviews=(app_review(),), repo=repo))
    human_result = evaluate(
        evaluation(
            reviews=(human_review(owner_aliases=("@example/infra",)),),
            repo=repo,
        )
    )

    assert app_result.conclusion is EvaluationConclusion.FAILURE
    assert "label conditions" in app_result.requirements[0].path_evidence[0].explanation
    assert human_result.conclusion is EvaluationConclusion.SUCCESS


def test_unowned_files_are_github_compatible_and_require_no_approval() -> None:
    result = evaluate(
        evaluation(
            codeowners="/src/** @example/infra\n",
            files=(ChangedFile(path="README.md"),),
            reviews=(),
        )
    )

    assert result.conclusion is EvaluationConclusion.SUCCESS
    assert result.requirements == ()
    assert result.unowned_paths == ("README.md",)


def test_invalid_codeowners_fails_closed() -> None:
    result = evaluate(evaluation(codeowners="/src/** security@example.com\n"))

    assert result.conclusion is EvaluationConclusion.FAILURE
    assert result.errors[0].code == "email_owner_unsupported"
    assert result.requirements == ()


def test_unenrolled_delegation_fails_closed() -> None:
    result = evaluate(
        evaluation(
            repo=repository(delegation(app="missing-bot")),
        )
    )
    assert result.conclusion is EvaluationConclusion.FAILURE
    assert result.errors[0].code == "unenrolled_application"


def test_disabled_repository_fails_without_evaluating_codeowners() -> None:
    result = evaluate(
        evaluation(
            codeowners="this is invalid",
            repo=RepositoryPolicy(),
        )
    )
    assert result.conclusion is EvaluationConclusion.FAILURE
    assert result.errors[0].code == "repository_policy_disabled"
    assert "disabled" in result.summary
