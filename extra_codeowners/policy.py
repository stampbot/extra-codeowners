"""Compilation and path-level decisions for Extra CODEOWNERS policy."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from extra_codeowners.codeowners import compile_pattern, validate_pattern
from extra_codeowners.models import (
    Delegation,
    EnrolledApplication,
    EvaluationOptions,
    OrganizationPolicy,
    RepositoryPolicy,
    normalize_repository_path,
)

# These paths define or execute the approval boundary. Application delegation
# is disabled for them unless an operator explicitly enables the process-level
# insecure escape hatch. Organization-added paths are never removed by it.
BUILTIN_NON_DELEGABLE_PATHS: tuple[str, ...] = (
    "/CODEOWNERS",
    "/.github/CODEOWNERS",
    "/docs/CODEOWNERS",
    "/stampbot.toml",
    "/.github/workflows/**",
    "/.github/actions/**",
)


@dataclass(frozen=True, slots=True)
class PolicyIssue:
    """A policy compilation problem with a stable machine code."""

    code: str
    message: str


class PolicyCompilationError(ValueError):
    """Raised when repository and organization policy cannot be combined."""

    def __init__(self, issues: tuple[PolicyIssue, ...]) -> None:
        self.issues = issues
        super().__init__("; ".join(issue.message for issue in issues))


@dataclass(frozen=True, slots=True)
class DelegationDecision:
    """Eligibility of one delegation after path, owner, and label checks."""

    app_alias: str
    eligible: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompiledDelegation:
    """A validated repository delegation and its enrolled application."""

    rule: Delegation
    application: EnrolledApplication
    _path_patterns: tuple[re.Pattern[str], ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_path_patterns",
            tuple(compile_pattern(pattern) for pattern in self.rule.paths),
        )

    def applies_to_path_and_owners(self, path: str, owners: frozenset[str]) -> bool:
        """Return whether the static path and owner selectors apply."""

        normalized_path = normalize_repository_path(path)
        path_matches = any(pattern.fullmatch(normalized_path) for pattern in self._path_patterns)
        owner_matches = "*" in self.rule.for_owners or bool(owners & set(self.rule.for_owners))
        return path_matches and owner_matches

    def decide(
        self,
        path: str,
        owners: frozenset[str],
        labels: frozenset[str],
    ) -> DelegationDecision | None:
        """Evaluate labels for an otherwise matching path/owner delegation."""

        if not self.applies_to_path_and_owners(path, owners):
            return None
        reasons: list[str] = []
        missing = self.rule.required_labels - labels
        forbidden = self.rule.forbidden_labels & labels
        if missing:
            reasons.append(f"missing required labels: {', '.join(sorted(missing))}")
        if forbidden:
            reasons.append(f"forbidden labels present: {', '.join(sorted(forbidden))}")
        return DelegationDecision(
            app_alias=self.rule.app,
            eligible=not reasons,
            reasons=tuple(reasons),
        )


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Organization and repository policy validated as one trust boundary."""

    repository: RepositoryPolicy
    organization: OrganizationPolicy
    delegations: tuple[CompiledDelegation, ...]
    non_delegable_patterns: tuple[str, ...]
    _non_delegable_patterns: tuple[re.Pattern[str], ...] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_non_delegable_patterns",
            tuple(compile_pattern(pattern) for pattern in self.non_delegable_patterns),
        )

    def is_non_delegable(self, path: str) -> bool:
        """Return whether application approvals are forbidden for ``path``."""

        normalized_path = normalize_repository_path(path)
        return any(pattern.fullmatch(normalized_path) for pattern in self._non_delegable_patterns)

    def delegation_decisions(
        self,
        path: str,
        owners: frozenset[str],
        labels: frozenset[str],
    ) -> tuple[DelegationDecision, ...]:
        """Return all relevant delegation decisions, coalesced by app alias."""

        decisions = [
            decision
            for delegation in self.delegations
            if (decision := delegation.decide(path, owners, labels)) is not None
        ]
        by_app: dict[str, list[DelegationDecision]] = {}
        for decision in decisions:
            by_app.setdefault(decision.app_alias, []).append(decision)

        coalesced: list[DelegationDecision] = []
        for alias, app_decisions in sorted(by_app.items()):
            if any(decision.eligible for decision in app_decisions):
                coalesced.append(DelegationDecision(alias, True, ()))
                continue
            reasons = tuple(
                dict.fromkeys(reason for decision in app_decisions for reason in decision.reasons)
            )
            coalesced.append(DelegationDecision(alias, False, reasons))
        return tuple(coalesced)


def compile_policy(
    organization: OrganizationPolicy,
    repository: RepositoryPolicy,
    options: EvaluationOptions | None = None,
) -> CompiledPolicy:
    """Validate cross-file references and construct effective safety policy."""

    runtime = options or EvaluationOptions()
    issues: list[PolicyIssue] = []

    builtins = (
        ()
        if runtime.allow_insecure_changes
        else (*BUILTIN_NON_DELEGABLE_PATHS, f"/{runtime.repository_policy_path}")
    )
    non_delegable_patterns = builtins + organization.guardrails.non_delegable_paths
    for pattern in non_delegable_patterns:
        try:
            validate_pattern(pattern)
        except ValueError as error:
            issues.append(
                PolicyIssue(
                    code="invalid_non_delegable_pattern",
                    message=f"invalid non-delegable path {pattern!r}: {error}",
                )
            )

    compiled_delegations: list[CompiledDelegation] = []
    for index, delegation in enumerate(repository.delegations, start=1):
        application = organization.apps.get(delegation.app)
        if application is None:
            issues.append(
                PolicyIssue(
                    code="unenrolled_application",
                    message=(
                        f"delegation {index} references application alias "
                        f"{delegation.app!r}, which organization policy has not enrolled"
                    ),
                )
            )
            continue
        invalid = False
        for pattern in delegation.paths:
            try:
                validate_pattern(pattern)
            except ValueError as error:
                issues.append(
                    PolicyIssue(
                        code="invalid_delegation_pattern",
                        message=f"delegation {index} has invalid path {pattern!r}: {error}",
                    )
                )
                invalid = True
        if not invalid:
            compiled_delegations.append(CompiledDelegation(delegation, application))

    if issues:
        raise PolicyCompilationError(tuple(issues))
    return CompiledPolicy(
        repository=repository,
        organization=organization,
        delegations=tuple(compiled_delegations),
        non_delegable_patterns=non_delegable_patterns,
    )
