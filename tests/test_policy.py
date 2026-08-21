"""Tests for combining organization and repository policy."""

import pytest

from extra_codeowners.models import (
    Delegation,
    EnrolledApplication,
    EvaluationOptions,
    Guardrails,
    OrganizationPolicy,
    RepositoryPolicy,
)
from extra_codeowners.policy import PolicyCompilationError, compile_policy


def organization(*, guardrails: tuple[str, ...] = ()) -> OrganizationPolicy:
    return OrganizationPolicy(
        apps={
            "stampbot": EnrolledApplication(
                slug="stampbot",
                app_id=2909932,
                bot_user_id=262871904,
            )
        },
        guardrails=Guardrails(non_delegable_paths=guardrails),
    )


def repository(
    *, allow_delegation_for_policy_file: bool = False, **delegation_overrides: object
) -> RepositoryPolicy:
    values: dict[str, object] = {
        "app": "stampbot",
        "paths": ("**",),
        "for_owners": ("*",),
    }
    values.update(delegation_overrides)
    return RepositoryPolicy(
        enabled=True,
        allow_delegation_for_policy_file=allow_delegation_for_policy_file,
        delegations=(Delegation.model_validate(values),),
    )


def test_builtin_and_org_guardrails_are_non_delegable() -> None:
    compiled = compile_policy(
        organization(guardrails=("/secrets/**",)),
        repository(),
    )

    assert compiled.is_non_delegable("CODEOWNERS")
    assert compiled.is_non_delegable(".github/CODEOWNERS")
    assert compiled.is_non_delegable("docs/CODEOWNERS")
    assert compiled.is_non_delegable(".github/extra-codeowners.toml")
    assert compiled.is_non_delegable(".github/workflows/test.yml")
    assert compiled.is_non_delegable("secrets/production.txt")
    assert not compiled.is_non_delegable("src/main.py")


def test_insecure_escape_removes_only_builtin_guardrails() -> None:
    compiled = compile_policy(
        organization(guardrails=("/secrets/**",)),
        repository(),
        EvaluationOptions(allow_insecure_changes=True),
    )

    assert not compiled.is_non_delegable(".github/workflows/test.yml")
    assert compiled.is_non_delegable("secrets/production.txt")


def test_configured_repository_policy_path_is_non_delegable() -> None:
    compiled = compile_policy(
        organization(),
        repository(),
        EvaluationOptions(repository_policy_path="config/extra-codeowners.toml"),
    )

    assert compiled.is_non_delegable("config/extra-codeowners.toml")
    assert not compiled.is_non_delegable(".github/extra-codeowners.toml")


def test_policy_file_delegation_opt_in_leaves_other_builtins_and_org_guardrails_intact() -> None:
    repository_policy = repository(allow_delegation_for_policy_file=True)
    delegated = compile_policy(organization(), repository_policy)
    organization_guarded = compile_policy(
        organization(guardrails=("/.github/extra-codeowners.toml",)), repository_policy
    )

    assert not delegated.is_non_delegable(".github/extra-codeowners.toml")
    assert delegated.is_non_delegable(".github/workflows/test.yml")
    assert delegated.is_non_delegable("CODEOWNERS")
    assert organization_guarded.is_non_delegable(".github/extra-codeowners.toml")


def test_unenrolled_application_fails_policy_compilation() -> None:
    repo = RepositoryPolicy(
        enabled=True,
        delegations=(Delegation(app="other-bot", paths=("**",), for_owners=("*",)),),
    )
    with pytest.raises(PolicyCompilationError) as caught:
        compile_policy(organization(), repo)
    assert caught.value.issues[0].code == "unenrolled_application"


def test_label_conditions_only_narrow_delegation() -> None:
    compiled = compile_policy(
        organization(),
        repository(required_labels=("automated",), forbidden_labels=("needs-human",)),
    )
    owners = frozenset({"@example/infra"})

    missing = compiled.delegation_decisions("deps/lock.json", owners, frozenset())
    assert not missing[0].eligible
    assert "missing required labels" in missing[0].reasons[0]

    eligible = compiled.delegation_decisions("deps/lock.json", owners, frozenset({"automated"}))
    assert eligible[0].eligible

    forbidden = compiled.delegation_decisions(
        "deps/lock.json", owners, frozenset({"automated", "needs-human"})
    )
    assert not forbidden[0].eligible
    assert "forbidden labels present" in forbidden[0].reasons[0]


def test_named_owner_scope_matches_one_codeowners_alternative() -> None:
    compiled = compile_policy(
        organization(),
        repository(for_owners=("@example/infra",)),
    )
    decisions = compiled.delegation_decisions(
        "src/main.py",
        frozenset({"@example/infra", "@example/security"}),
        frozenset(),
    )
    assert decisions[0].eligible


def test_invalid_delegation_pattern_fails_closed() -> None:
    compiled_repo = repository(paths=("[ab].py",))
    with pytest.raises(PolicyCompilationError) as caught:
        compile_policy(organization(), compiled_repo)
    assert caught.value.issues[0].code == "invalid_delegation_pattern"
