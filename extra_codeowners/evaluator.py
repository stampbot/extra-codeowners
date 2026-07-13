"""Pure evaluation of human-or-application CODEOWNER approval evidence."""

from __future__ import annotations

from collections.abc import Iterable

from extra_codeowners.codeowners import CodeownersParseError, parse_codeowners
from extra_codeowners.models import (
    ActorKind,
    EvaluationConclusion,
    EvaluationInput,
    EvaluationMessage,
    EvaluationResult,
    OwnerSetResult,
    PathEvidence,
    PullRequestReview,
    ReviewState,
)
from extra_codeowners.policy import PolicyCompilationError, compile_policy

_OPINIONATED_STATES = {
    ReviewState.APPROVED,
    ReviewState.CHANGES_REQUESTED,
    ReviewState.DISMISSED,
}


def latest_opinionated_reviews(
    reviews: Iterable[PullRequestReview],
) -> tuple[PullRequestReview, ...]:
    """Return each actor's latest approval, rejection, or dismissal.

    Comments do not supersede an approval. Dismissed reviews do, ensuring an
    older approval cannot become effective again after GitHub dismisses it.
    """

    latest: dict[tuple[ActorKind, int], PullRequestReview] = {}
    for review in reviews:
        if review.state not in _OPINIONATED_STATES:
            continue
        actor_key = (review.actor.kind, review.actor.user_id)
        previous = latest.get(actor_key)
        ordering = (review.submitted_at, review.review_id)
        if previous is None or ordering > (previous.submitted_at, previous.review_id):
            latest[actor_key] = review
    return tuple(
        sorted(latest.values(), key=lambda review: (review.submitted_at, review.review_id))
    )


def _evaluation_paths(data: EvaluationInput) -> tuple[str, ...]:
    paths: list[str] = []
    for changed_file in data.changed_files:
        if changed_file.previous_path is not None:
            paths.append(changed_file.previous_path)
        paths.append(changed_file.path)
    return tuple(dict.fromkeys(paths))


def _current_approvals(
    data: EvaluationInput,
) -> tuple[tuple[PullRequestReview, ...], tuple[EvaluationMessage, ...]]:
    approvals: list[PullRequestReview] = []
    warnings: list[EvaluationMessage] = []
    for review in latest_opinionated_reviews(data.reviews):
        if review.state is not ReviewState.APPROVED:
            continue
        if data.options.exact_head_reviews and review.commit_sha != data.head_sha:
            warnings.append(
                EvaluationMessage(
                    code="stale_approval_ignored",
                    message=(
                        f"approval {review.review_id} from @{review.actor.login} does not target "
                        "the current pull request head"
                    ),
                )
            )
            continue
        approvals.append(review)
    return tuple(approvals), tuple(warnings)


def _recognized_app_approvals(
    data: EvaluationInput,
    approvals: Iterable[PullRequestReview],
) -> tuple[frozenset[str], tuple[EvaluationMessage, ...]]:
    approved: set[str] = set()
    warnings: list[EvaluationMessage] = []
    for review in approvals:
        actor = review.actor
        if actor.kind is not ActorKind.APPLICATION:
            continue
        alias = next(
            (
                app_alias
                for app_alias, enrolled in data.organization_policy.apps.items()
                if enrolled.app_id == actor.app_id
                and enrolled.slug == actor.app_slug
                and enrolled.bot_user_id == actor.user_id
                and actor.login == f"{enrolled.slug}[bot]"
            ),
            None,
        )
        if alias is None:
            warnings.append(
                EvaluationMessage(
                    code="untrusted_application_review_ignored",
                    message=(
                        f"approval {review.review_id} from @{actor.login} did not match an "
                        "organization-enrolled app_id, slug, bot login, and bot_user_id"
                    ),
                )
            )
            continue
        approved.add(alias)
    return frozenset(approved), tuple(warnings)


def _human_approvals_by_owner(
    approvals: Iterable[PullRequestReview],
) -> tuple[tuple[PullRequestReview, frozenset[str]], ...]:
    resolved: list[tuple[PullRequestReview, frozenset[str]]] = []
    for review in approvals:
        if review.actor.kind is not ActorKind.HUMAN:
            continue
        identities = set(review.actor.owner_aliases)
        if review.actor.direct_owner_eligible:
            identities.add(f"@{review.actor.login.lower()}")
        resolved.append((review, frozenset(identities)))
    return tuple(resolved)


def _error_result(
    messages: tuple[EvaluationMessage, ...],
    *,
    warnings: tuple[EvaluationMessage, ...] = (),
) -> EvaluationResult:
    return EvaluationResult(
        conclusion=EvaluationConclusion.FAILURE,
        summary="Extra CODEOWNERS could not evaluate safely; approval is denied.",
        errors=messages,
        warnings=warnings,
    )


def evaluate(data: EvaluationInput) -> EvaluationResult:
    """Evaluate one pull request using only supplied, already-fetched evidence."""

    if not data.repository_policy.enabled:
        return EvaluationResult(
            conclusion=EvaluationConclusion.FAILURE,
            summary="Repository policy is missing or disabled; approval is denied.",
            errors=(
                EvaluationMessage(
                    code="repository_policy_disabled",
                    message=(
                        "repository policy is missing or enabled=false; remove the required "
                        "check from the ruleset before disabling Extra CODEOWNERS"
                    ),
                ),
            ),
        )

    try:
        document = parse_codeowners(data.codeowners_text)
    except CodeownersParseError as error:
        return _error_result(
            tuple(
                EvaluationMessage(code=issue.code, message=issue.render()) for issue in error.issues
            )
        )

    try:
        policy = compile_policy(
            data.organization_policy,
            data.repository_policy,
            data.options,
        )
    except PolicyCompilationError as error:
        return _error_result(
            tuple(
                EvaluationMessage(code=issue.code, message=issue.message) for issue in error.issues
            )
        )

    warnings: list[EvaluationMessage] = []
    if data.options.allow_insecure_changes:
        warnings.append(
            EvaluationMessage(
                code="insecure_changes_enabled",
                message=(
                    "the runtime allow-insecure-changes escape hatch disabled built-in "
                    "non-delegable paths; organization-added paths remain enforced"
                ),
            )
        )

    approvals, approval_warnings = _current_approvals(data)
    warnings.extend(approval_warnings)
    approved_apps, app_warnings = _recognized_app_approvals(data, approvals)
    warnings.extend(app_warnings)
    human_approvals = _human_approvals_by_owner(approvals)

    owner_paths: dict[tuple[str, ...], list[str]] = {}
    unowned_paths: list[str] = []
    for path in _evaluation_paths(data):
        owners = tuple(sorted(document.owners_for(path)))
        if not owners:
            unowned_paths.append(path)
            continue
        paths = owner_paths.setdefault(owners, [])
        if path not in paths:
            paths.append(path)

    requirements: list[OwnerSetResult] = []
    for owners, paths in owner_paths.items():
        owner_set = frozenset(owners)
        satisfying_humans = [
            review for review, identities in human_approvals if identities & owner_set
        ]
        if satisfying_humans:
            actors = tuple(f"human:@{review.actor.login}" for review in satisfying_humans)
            requirements.append(
                OwnerSetResult(
                    owners=owners,
                    paths=tuple(paths),
                    satisfied=True,
                    satisfied_by=actors,
                    explanation=(
                        "approved by human CODEOWNER "
                        + ", ".join(f"@{review.actor.login}" for review in satisfying_humans)
                    ),
                    path_evidence=tuple(
                        PathEvidence(
                            path=path,
                            non_delegable=policy.is_non_delegable(path),
                            explanation="covered by the human CODEOWNER approval",
                        )
                        for path in paths
                    ),
                )
            )
            continue

        path_evidence: list[PathEvidence] = []
        approving_apps: set[str] = set()
        all_paths_satisfied = True
        for path in paths:
            if policy.is_non_delegable(path):
                all_paths_satisfied = False
                path_evidence.append(
                    PathEvidence(
                        path=path,
                        non_delegable=True,
                        explanation=(
                            "application delegation is disabled for this security-sensitive path"
                        ),
                    )
                )
                continue

            decisions = policy.delegation_decisions(path, owner_set, data.labels)
            eligible_apps = tuple(decision.app_alias for decision in decisions if decision.eligible)
            path_approvals = tuple(sorted(set(eligible_apps) & approved_apps))
            if path_approvals:
                approving_apps.update(path_approvals)
                explanation = "covered by approved application " + ", ".join(path_approvals)
            else:
                all_paths_satisfied = False
                if eligible_apps:
                    explanation = "eligible application approval is missing: " + ", ".join(
                        eligible_apps
                    )
                elif decisions:
                    blocked = "; ".join(
                        f"{decision.app_alias}: {', '.join(decision.reasons)}"
                        for decision in decisions
                    )
                    explanation = "delegation label conditions were not met: " + blocked
                else:
                    explanation = "no application delegation covers this path and owner set"
            path_evidence.append(
                PathEvidence(
                    path=path,
                    non_delegable=False,
                    eligible_apps=eligible_apps,
                    approved_apps=path_approvals,
                    explanation=explanation,
                )
            )

        if all_paths_satisfied:
            aliases = tuple(sorted(approving_apps))
            requirements.append(
                OwnerSetResult(
                    owners=owners,
                    paths=tuple(paths),
                    satisfied=True,
                    satisfied_by=tuple(f"app:{alias}" for alias in aliases),
                    explanation="all paths are covered by approved application delegation",
                    path_evidence=tuple(path_evidence),
                )
            )
        else:
            requirements.append(
                OwnerSetResult(
                    owners=owners,
                    paths=tuple(paths),
                    satisfied=False,
                    explanation=(
                        "requires an approval from a listed human CODEOWNER or an eligible "
                        "application for every path"
                    ),
                    path_evidence=tuple(path_evidence),
                )
            )

    failed = sum(not requirement.satisfied for requirement in requirements)
    if failed:
        conclusion = EvaluationConclusion.FAILURE
        summary = (
            f"{failed} of {len(requirements)} distinct CODEOWNER requirements are unsatisfied."
        )
    elif requirements:
        conclusion = EvaluationConclusion.SUCCESS
        summary = f"All {len(requirements)} distinct CODEOWNER requirements are satisfied."
    else:
        conclusion = EvaluationConclusion.SUCCESS
        summary = "No changed path has a CODEOWNER requirement."

    return EvaluationResult(
        conclusion=conclusion,
        summary=summary,
        requirements=tuple(requirements),
        warnings=tuple(warnings),
        unowned_paths=tuple(unowned_paths),
    )
