"""Tests for the dormant, side-effect-free DCO evidence contract."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

import pytest
from pydantic import ValidationError

from extra_codeowners.dco import (
    MAX_COMMIT_MESSAGE_BYTES,
    MAX_COMMIT_PARENTS,
    MAX_PULL_COMMITS,
    MAX_VERIFICATION_TEXT_BYTES,
    CommitEvidence,
    CommitVerification,
    DcoCommitOutcome,
    DcoCommitResult,
    DcoEvaluationResult,
    DcoEvidenceInput,
    DcoFailure,
    GitCommitIdentity,
    GitHubActor,
    PullCommit,
    PullCommitComparison,
    PullRequestSnapshot,
    RepositoryIdentity,
    evaluate_dco,
)


def sha(number: int) -> str:
    return f"{number:040x}"


REPOSITORY = RepositoryIdentity(id=100, full_name="Example/Project")
BASE_SHA = sha(10_000)


def rebuild[Model](model: Model, **changes: object) -> Model:
    values = model.model_dump(mode="python")  # type: ignore[attr-defined]
    values.update(changes)
    return type(model).model_validate(values)  # type: ignore[no-any-return,attr-defined]


def pull_snapshot(
    *,
    count: int = 1,
    head_sha: str = sha(1),
    head_repository: RepositoryIdentity = REPOSITORY,
    author: GitHubActor | None = None,
    head_ref: str = "feature/dco",
    state: Literal["open", "closed"] = "open",
) -> PullRequestSnapshot:
    return PullRequestSnapshot(
        number=7,
        state=state,
        repository=REPOSITORY,
        base_repository=REPOSITORY,
        base_ref="main",
        base_sha=BASE_SHA,
        head_repository=head_repository,
        head_ref=head_ref,
        head_sha=head_sha,
        author=author or GitHubActor(login="contributor", id=200, type="User"),
        commit_count=count,
    )


def signed_commit(
    commit_sha: str,
    parents: tuple[str, ...],
    *,
    name: str = "Test Contributor",
    email: str = "contributor@example.com",
    message: str | None = None,
    github_author: GitHubActor | None = None,
    github_committer: GitHubActor | None = None,
    verification: CommitVerification | None = None,
) -> CommitEvidence:
    return CommitEvidence(
        sha=commit_sha,
        parents=parents,
        author=GitCommitIdentity(name=name, email=email),
        committer=GitCommitIdentity(name=name, email=email),
        message=message or f"test: change\n\nSigned-off-by: {name} <{email}>\n",
        github_author=github_author,
        github_committer=github_committer,
        verification=verification
        or CommitVerification(
            verified=False,
            reason="unsigned",
            signature=None,
            payload=None,
            verified_at=None,
        ),
    )


def comparison_for(
    pull: PullRequestSnapshot,
    commits: tuple[PullCommit, ...],
    *,
    base_commit_sha: str | None = None,
    total_commits: int | None = None,
    ahead_by: int | None = None,
) -> PullCommitComparison:
    count = len(commits)
    return PullCommitComparison(
        repository=pull.repository,
        pull_number=pull.number,
        base_sha=pull.base_sha,
        head_sha=pull.head_sha,
        base_commit_sha=base_commit_sha or pull.base_sha,
        total_commits=count if total_commits is None else total_commits,
        ahead_by=count if ahead_by is None else ahead_by,
        commits=commits,
    )


def linear_evidence(count: int) -> DcoEvidenceInput:
    commits: list[CommitEvidence] = []
    parent = BASE_SHA
    for index in range(1, count + 1):
        commit_sha = sha(index)
        commits.append(signed_commit(commit_sha, (parent,)))
        parent = commit_sha
    pull = pull_snapshot(count=count, head_sha=commits[-1].sha)
    return DcoEvidenceInput(
        event=pull,
        before=pull,
        after=pull,
        comparison=comparison_for(
            pull,
            tuple(PullCommit(sha=commit.sha) for commit in commits),
        ),
        commits=tuple(commits),
    )


@pytest.mark.parametrize("count", (1, 101, MAX_PULL_COMMITS))
def test_accepts_complete_bounded_linear_histories(count: int) -> None:
    result = evaluate_dco(linear_evidence(count))

    assert result.passed is True
    assert result.repository == REPOSITORY
    assert result.pull_number == 7
    assert result.base_sha == BASE_SHA
    assert result.head_sha == sha(count)
    assert result.failure is None
    assert len(result.commits) == count
    assert {item.outcome for item in result.commits} == {DcoCommitOutcome.AUTHOR_SIGNOFF}


def test_rejects_commit_counts_over_githubs_pull_commit_limit() -> None:
    with pytest.raises(ValidationError, match="less than or equal to 250"):
        pull_snapshot(count=MAX_PULL_COMMITS + 1)

    evidence = linear_evidence(MAX_PULL_COMMITS)
    with pytest.raises(ValidationError, match="at most 250 items"):
        rebuild(
            evidence.comparison,
            commits=(*evidence.comparison.commits, PullCommit(sha=sha(999))),
        )


@pytest.mark.parametrize("field", ("comparison", "commits"))
def test_rejects_missing_or_truncated_commit_evidence(field: str) -> None:
    evidence = linear_evidence(2)
    if field == "comparison":
        changed = rebuild(
            evidence,
            comparison=rebuild(
                evidence.comparison,
                commits=evidence.comparison.commits[:-1],
            ),
        )
    else:
        changed = rebuild(evidence, commits=evidence.commits[:-1])
    result = evaluate_dco(changed)

    assert result.passed is False
    assert result.failure is DcoFailure.COMMIT_COUNT_MISMATCH


def test_rejects_duplicate_commits_before_evaluating_signoffs() -> None:
    evidence = linear_evidence(3)
    duplicate = rebuild(
        evidence.comparison.commits[1],
        sha=evidence.comparison.commits[0].sha,
    )
    result = evaluate_dco(
        rebuild(
            evidence,
            comparison=rebuild(
                evidence.comparison,
                commits=(
                    evidence.comparison.commits[0],
                    duplicate,
                    evidence.comparison.commits[2],
                ),
            ),
        )
    )

    assert result.passed is False
    assert result.failure is DcoFailure.DUPLICATE_COMMIT
    assert result.commits == ()


def test_rejects_reordered_commit_list_and_details() -> None:
    evidence = linear_evidence(3)
    reordered_list = (
        evidence.comparison.commits[1],
        evidence.comparison.commits[0],
        evidence.comparison.commits[2],
    )
    reordered_details = (evidence.commits[1], evidence.commits[0], evidence.commits[2])

    result = evaluate_dco(
        rebuild(
            evidence,
            comparison=rebuild(evidence.comparison, commits=reordered_list),
            commits=reordered_details,
        )
    )

    assert result.passed is False
    assert result.failure is DcoFailure.COMMIT_ORDER_MISMATCH


def test_rejects_details_that_do_not_align_with_list_order() -> None:
    evidence = linear_evidence(2)
    result = evaluate_dco(rebuild(evidence, commits=tuple(reversed(evidence.commits))))

    assert result.failure is DcoFailure.COMMIT_ORDER_MISMATCH


def test_rejects_a_list_whose_last_sha_is_not_the_exact_head() -> None:
    evidence = linear_evidence(2)
    result = evaluate_dco(
        rebuild(
            evidence,
            comparison=rebuild(
                evidence.comparison,
                commits=(evidence.comparison.commits[0], PullCommit(sha=sha(999))),
            ),
        )
    )

    assert result.passed is False
    assert result.failure is DcoFailure.HEAD_MISMATCH


def test_rejects_commits_not_reachable_from_the_exact_head() -> None:
    first = signed_commit(sha(1), (BASE_SHA,))
    disconnected = signed_commit(sha(2), (BASE_SHA,))
    pull = pull_snapshot(count=2, head_sha=disconnected.sha)
    evidence = DcoEvidenceInput(
        event=pull,
        before=pull,
        after=pull,
        comparison=comparison_for(
            pull,
            (PullCommit(sha=first.sha), PullCommit(sha=disconnected.sha)),
        ),
        commits=(first, disconnected),
    )

    assert evaluate_dco(evidence).failure is DcoFailure.COMMIT_ORDER_MISMATCH


def test_accepts_merge_commit_topology_without_requiring_a_linear_history() -> None:
    left = signed_commit(sha(1), (BASE_SHA,))
    right = signed_commit(sha(2), (BASE_SHA,))
    merge = signed_commit(sha(3), (left.sha, right.sha))
    pull = pull_snapshot(count=3, head_sha=merge.sha)
    evidence = DcoEvidenceInput(
        event=pull,
        before=pull,
        after=pull,
        comparison=comparison_for(
            pull,
            tuple(PullCommit(sha=item.sha) for item in (left, right, merge)),
        ),
        commits=(left, right, merge),
    )

    assert evaluate_dco(evidence).passed is True


@pytest.mark.parametrize(
    "head_repository",
    (
        REPOSITORY,
        RepositoryIdentity(id=101, full_name="fork-owner/project"),
    ),
    ids=("same-repository", "fork"),
)
def test_ordinary_signoffs_work_for_same_repository_and_fork_heads(
    head_repository: RepositoryIdentity,
) -> None:
    evidence = linear_evidence(1)
    pull = rebuild(evidence.event, head_repository=head_repository)
    evidence = rebuild(evidence, event=pull, before=pull, after=pull)

    assert evaluate_dco(evidence).passed is True


def test_accepts_a_stacked_pull_request_relative_to_its_current_base() -> None:
    stacked_base = sha(500)
    child = signed_commit(sha(501), (stacked_base,))
    pull = rebuild(
        pull_snapshot(head_sha=child.sha),
        base_ref="feature/parent",
        base_sha=stacked_base,
    )
    evidence = DcoEvidenceInput(
        event=pull,
        before=pull,
        after=pull,
        comparison=comparison_for(pull, (PullCommit(sha=child.sha),)),
        commits=(child,),
    )

    assert evaluate_dco(evidence).passed is True


@pytest.mark.parametrize(
    ("snapshot", "failure"),
    (
        (rebuild(pull_snapshot(), state="closed"), DcoFailure.PULL_REQUEST_NOT_OPEN),
        (
            rebuild(pull_snapshot(), head_ref="feature/force-pushed"),
            DcoFailure.PULL_REQUEST_CHANGED,
        ),
        (
            rebuild(pull_snapshot(), base_sha=sha(999)),
            DcoFailure.PULL_REQUEST_CHANGED,
        ),
    ),
    ids=("closed", "head-ref-race", "base-race"),
)
def test_fails_closed_on_state_and_revision_races(
    snapshot: PullRequestSnapshot,
    failure: DcoFailure,
) -> None:
    evidence = linear_evidence(1)
    if failure is DcoFailure.PULL_REQUEST_NOT_OPEN:
        raced = rebuild(evidence, event=snapshot, before=snapshot, after=snapshot)
    else:
        raced = rebuild(evidence, after=snapshot)

    assert evaluate_dco(raced).failure is failure


def test_a_changed_commit_count_between_observations_fails_as_a_race() -> None:
    evidence = linear_evidence(2)
    before = rebuild(evidence.before, commit_count=1)

    assert evaluate_dco(rebuild(evidence, before=before)).failure is DcoFailure.PULL_REQUEST_CHANGED


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("repository", RepositoryIdentity(id=101, full_name="other/project")),
        ("pull_number", 8),
        ("base_sha", sha(998)),
        ("head_sha", sha(999)),
        ("base_commit_sha", sha(998)),
    ),
)
def test_comparison_must_be_bound_to_the_exact_pull_snapshot(
    field: str,
    value: object,
) -> None:
    evidence = linear_evidence(1)
    comparison = rebuild(evidence.comparison, **{field: value})
    result = evaluate_dco(rebuild(evidence, comparison=comparison))

    assert result.failure is DcoFailure.COMPARISON_MISMATCH
    assert result.repository == REPOSITORY
    assert result.pull_number == 7
    assert result.base_sha == BASE_SHA
    assert result.head_sha == evidence.event.head_sha


def test_exact_compare_binding_closes_same_head_same_count_retarget_aba_for_merge_graphs() -> None:
    left = signed_commit(sha(1), (BASE_SHA,))
    right = signed_commit(sha(2), (BASE_SHA,))
    merge = signed_commit(sha(3), (left.sha, right.sha))
    pull = pull_snapshot(count=3, head_sha=merge.sha)
    current = comparison_for(
        pull,
        tuple(PullCommit(sha=item.sha) for item in (left, right, merge)),
    )
    retargeted_base = sha(900)
    comparison_collected_during_retarget = rebuild(
        current,
        base_sha=retargeted_base,
        base_commit_sha=retargeted_base,
    )
    evidence = DcoEvidenceInput(
        event=pull,
        before=pull,
        after=pull,
        comparison=comparison_collected_during_retarget,
        commits=(left, right, merge),
    )

    assert comparison_collected_during_retarget.head_sha == pull.head_sha
    assert comparison_collected_during_retarget.total_commits == pull.commit_count
    assert evaluate_dco(evidence).failure is DcoFailure.COMPARISON_MISMATCH


@pytest.mark.parametrize("field", ("total_commits", "ahead_by"))
def test_compare_metadata_count_must_match_the_snapshot(field: str) -> None:
    evidence = linear_evidence(2)
    comparison = rebuild(evidence.comparison, **{field: 1})

    assert evaluate_dco(rebuild(evidence, comparison=comparison)).failure is (
        DcoFailure.COMMIT_COUNT_MISMATCH
    )


@pytest.mark.parametrize(
    ("message", "passes"),
    (
        ("subject\nSigned-off-by: Test Contributor <contributor@example.com>", True),
        ("SIGNED-OFF-BY: test contributor <CONTRIBUTOR@EXAMPLE.COM>", True),
        ("subject Signed-off-by: Test Contributor <contributor@example.com>", False),
        ("Signed-off-by: Test Contributor <contributor@example.com> ", False),
        (" Signed-off-by: Test Contributor <contributor@example.com>", False),
        ("Signed-off-by: Other <contributor@example.com>", False),
        ("Signed-off-by: Test Contributor <other@example.com>", False),
        ("Signed-off-by: Test Contributor <contributor@example.com>\r", False),
        (
            "Signed-off-by: Test Contributor <contributor@example.com>\u2028forged",
            False,
        ),
    ),
)
def test_author_signoff_requires_one_case_insensitive_whole_message_line(
    message: str,
    passes: bool,
) -> None:
    evidence = linear_evidence(1)
    commit = rebuild(evidence.commits[0], message=message)
    result = evaluate_dco(rebuild(evidence, commits=(commit,)))

    assert result.passed is passes
    assert result.commits[0].outcome is (
        DcoCommitOutcome.AUTHOR_SIGNOFF if passes else DcoCommitOutcome.MISSING_SIGNOFF
    )


@pytest.mark.parametrize(
    ("name", "email"),
    (
        ("Zoë Δ", "zoë@example.com"),
        ("$(touch never-runs)", "`id`@example.com"),
        ("**Markdown** [link](https://example.com)", "$USER@example.com"),
    ),
)
def test_unicode_markdown_and_shell_like_identity_text_is_compared_as_data(
    name: str,
    email: str,
) -> None:
    evidence = linear_evidence(1)
    commit = signed_commit(evidence.event.head_sha, (BASE_SHA,), name=name, email=email)

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).passed is True


@pytest.mark.parametrize(
    ("name", "email", "trailer_identity"),
    (
        (
            "Test Contributor",
            "contributor@example.com",
            "TEST CONTRIBUTOR <CONTRIBUTOR@EXAMPLE.COM>",
        ),
        ("Zoë", "zoë@example.com", "ZOË <ZOË@EXAMPLE.COM>"),
        ("ΟΣ", "sigma@example.com", "ος <SIGMA@EXAMPLE.COM>"),
        ("İpek", "ipek@example.com", "i\u0307PEK <IPEK@EXAMPLE.COM>"),
        ("Straße", "straße@example.com", "STRASSE <STRASSE@EXAMPLE.COM>"),
    ),
    ids=("ascii", "accented-latin", "final-sigma", "dotted-i", "sharp-s"),
)
def test_author_signoff_uses_deterministic_unicode_casefold(
    name: str,
    email: str,
    trailer_identity: str,
) -> None:
    evidence = linear_evidence(1)
    commit = signed_commit(
        evidence.event.head_sha,
        (BASE_SHA,),
        name=name,
        email=email,
        message=f"SIGNED-OFF-BY: {trailer_identity}",
    )

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).passed is True


def test_author_signoff_does_not_apply_unicode_normalization() -> None:
    evidence = linear_evidence(1)
    commit = signed_commit(
        evidence.event.head_sha,
        (BASE_SHA,),
        name="José",
        email="jose@example.com",
        message="Signed-off-by: Jose\u0301 <JOSE@EXAMPLE.COM>",
    )

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).failure is DcoFailure.MISSING_SIGNOFF


def test_control_characters_cannot_turn_a_nonmatching_line_into_a_signoff() -> None:
    evidence = linear_evidence(1)
    message = "\x1b[2KSigned-off-by: Test Contributor <contributor@example.com>"
    result = evaluate_dco(
        rebuild(evidence, commits=(rebuild(evidence.commits[0], message=message),))
    )

    assert result.failure is DcoFailure.MISSING_SIGNOFF


@pytest.mark.parametrize(
    ("model", "changes", "match"),
    (
        (GitCommitIdentity, {"name": "bad\nname", "email": "a@example.com"}, "control"),
        (GitCommitIdentity, {"name": "bad<name", "email": "a@example.com"}, "must not"),
        (GitHubActor, {"login": "bad login", "id": 1, "type": "User"}, "whitespace"),
        (PullCommit, {"sha": "A" * 40}, "lowercase"),
        (RepositoryIdentity, {"id": 1, "full_name": "owner//repo"}, "owner/repository"),
        (RepositoryIdentity, {"id": 1, "full_name": "owner/repo?query"}, "owner/repository"),
        (RepositoryIdentity, {"id": 1, "full_name": "owner/repo#fragment"}, "owner/repository"),
        (RepositoryIdentity, {"id": 1, "full_name": "owner/repo%2fother"}, "owner/repository"),
        (RepositoryIdentity, {"id": 1, "full_name": "ownér/repo"}, "owner/repository"),
        (RepositoryIdentity, {"id": 1, "full_name": "\ud800/repo"}, "valid Unicode"),
        (RepositoryIdentity, {"id": 1, "full_name": "owner\\repo"}, "owner/repository"),
        (RepositoryIdentity, {"id": 1, "full_name": "owner/."}, "owner/repository"),
    ),
)
def test_strict_models_reject_malformed_untrusted_fields(
    model: type[Any], changes: dict[str, object], match: str
) -> None:
    with pytest.raises(ValidationError, match=match):
        model(**changes)


def test_models_reject_unknown_fields_and_mutation() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PullCommit.model_validate({"sha": sha(1), "message": "hidden"})

    item = PullCommit(sha=sha(1))
    with pytest.raises(ValidationError, match="frozen"):
        item.sha = sha(2)  # type: ignore[misc]


def test_repository_name_case_remains_exact_race_evidence() -> None:
    evidence = linear_evidence(1)
    lowercase = RepositoryIdentity(id=REPOSITORY.id, full_name=REPOSITORY.full_name.lower())
    after = rebuild(
        evidence.after,
        repository=lowercase,
        base_repository=lowercase,
        head_repository=lowercase,
    )

    assert evaluate_dco(rebuild(evidence, after=after)).failure is DcoFailure.PULL_REQUEST_CHANGED


def test_commit_evidence_applies_message_parent_and_verification_bounds() -> None:
    evidence = linear_evidence(1)
    values = evidence.commits[0].model_dump(mode="python")

    with pytest.raises(ValidationError, match="message exceeds"):
        CommitEvidence.model_validate(
            {**values, "message": "é" * (MAX_COMMIT_MESSAGE_BYTES // 2 + 1)}
        )
    with pytest.raises(ValidationError, match="at most 64 items"):
        CommitEvidence.model_validate(
            {
                **values,
                "parents": tuple(sha(index + 100) for index in range(MAX_COMMIT_PARENTS + 1)),
            }
        )
    with pytest.raises(ValidationError, match="parents must be unique"):
        CommitEvidence.model_validate({**values, "parents": (BASE_SHA, BASE_SHA)})
    with pytest.raises(ValidationError, match="parent SHA"):
        CommitEvidence.model_validate({**values, "parents": ("not-a-sha",)})
    with pytest.raises(ValidationError, match="must not contain NUL"):
        CommitEvidence.model_validate({**values, "message": "bad\0message"})

    verification = values["verification"]
    with pytest.raises(ValidationError, match="verification text exceeds"):
        CommitEvidence.model_validate(
            {
                **values,
                "verification": {
                    **verification,
                    "signature": "x" * (MAX_VERIFICATION_TEXT_BYTES + 1),
                },
            }
        )


def github_pull_payload(pull: PullRequestSnapshot) -> dict[str, Any]:
    return {
        "number": pull.number,
        "state": pull.state,
        "commits": pull.commit_count,
        "user": pull.author.model_dump(mode="python") | {"ignored": "provider field"},
        "base": {
            "ref": pull.base_ref,
            "sha": pull.base_sha,
            "repo": pull.base_repository.model_dump(mode="python") | {"private": False},
        },
        "head": {
            "ref": pull.head_ref,
            "sha": pull.head_sha,
            "repo": pull.head_repository.model_dump(mode="python") | {"private": False},
        },
        "title": "ignored provider field",
    }


def github_commit_payload(commit: CommitEvidence) -> dict[str, Any]:
    return {
        "sha": commit.sha,
        "parents": [{"sha": parent, "url": "ignored"} for parent in commit.parents],
        "author": (
            None
            if commit.github_author is None
            else commit.github_author.model_dump(mode="python") | {"node_id": "ignored"}
        ),
        "committer": (
            None
            if commit.github_committer is None
            else commit.github_committer.model_dump(mode="python") | {"node_id": "ignored"}
        ),
        "commit": {
            "author": commit.author.model_dump(mode="python") | {"date": "ignored"},
            "committer": commit.committer.model_dump(mode="python") | {"date": "ignored"},
            "message": commit.message,
            "verification": commit.verification.model_dump(mode="python") | {"extra": "ignored"},
            "tree": {"sha": sha(888)},
        },
        "files": [{"filename": "ignored"}],
    }


def test_github_payload_factories_copy_only_strict_consumed_fields() -> None:
    evidence = linear_evidence(1)
    pull = PullRequestSnapshot.from_github(
        github_pull_payload(evidence.event), repository=REPOSITORY
    )
    listed = PullCommit.from_github({"sha": evidence.event.head_sha, "ignored": True})
    commit = CommitEvidence.from_github(github_commit_payload(evidence.commits[0]))

    assert pull == evidence.event
    assert listed == evidence.comparison.commits[0]
    assert commit == evidence.commits[0]


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.pop("base"),
        lambda payload: payload.__setitem__("head", None),
        lambda payload: payload["user"].pop("id"),
        lambda payload: payload["base"].__setitem__("repo", None),
    ),
    ids=("missing-base", "null-head", "missing-actor-id", "null-base-repository"),
)
def test_pull_payload_factory_fails_closed_on_missing_or_malformed_shapes(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    payload = github_pull_payload(linear_evidence(1).event)
    mutate(payload)

    with pytest.raises((ValueError, ValidationError)):
        PullRequestSnapshot.from_github(payload, repository=REPOSITORY)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.pop("commit"),
        lambda payload: payload.__setitem__("parents", {}),
        lambda payload: payload["parents"].__setitem__(0, "bad"),
        lambda payload: payload["commit"].pop("verification"),
        lambda payload: payload["commit"].__setitem__("author", None),
        lambda payload: payload["commit"]["committer"].pop("email"),
        lambda payload: payload.__setitem__("author", {"login": "missing fields"}),
    ),
    ids=(
        "missing-commit",
        "parents-not-list",
        "parent-not-object",
        "missing-verification",
        "null-author",
        "missing-committer-email",
        "malformed-github-actor",
    ),
)
def test_commit_payload_factory_fails_closed_on_missing_or_malformed_shapes(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    payload = github_commit_payload(linear_evidence(1).commits[0])
    mutate(payload)

    with pytest.raises((ValueError, ValidationError)):
        CommitEvidence.from_github(payload)


def official_dependabot_evidence() -> DcoEvidenceInput:
    author = GitHubActor(login="dependabot[bot]", id=49_699_333, type="Bot")
    committer = GitHubActor(login="web-flow", id=19_864_447, type="User")
    commit = signed_commit(
        sha(1),
        (BASE_SHA,),
        name="dependabot[bot]",
        email="49699333+dependabot[bot]@users.noreply.github.com",
        message=(
            "build(deps): bump a dependency\n\nSigned-off-by: dependabot[bot] <support@github.com>"
        ),
        github_author=author,
        github_committer=committer,
        verification=CommitVerification(
            verified=True,
            reason="valid",
            signature="signed",
            payload="payload",
            verified_at="2026-07-22T00:00:00Z",
        ),
    )
    commit = rebuild(
        commit,
        committer=GitCommitIdentity(name="GitHub", email="noreply@github.com"),
    )
    pull = pull_snapshot(
        head_sha=commit.sha,
        author=author,
        head_ref="dependabot/pip/example-1.2.3",
    )
    return DcoEvidenceInput(
        event=pull,
        before=pull,
        after=pull,
        comparison=comparison_for(pull, (PullCommit(sha=commit.sha),)),
        commits=(commit,),
    )


def test_accepts_only_the_provenance_constrained_dependabot_fallback() -> None:
    result = evaluate_dco(official_dependabot_evidence())

    assert result.passed is True
    assert result.commits[0].outcome is DcoCommitOutcome.OFFICIAL_DEPENDABOT


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("login", "dependabot-copy[bot]"),
        ("id", 49_699_334),
        ("type", "User"),
    ),
)
def test_dependabot_pull_author_predicates_are_independent(field: str, value: object) -> None:
    evidence = official_dependabot_evidence()
    author = rebuild(evidence.event.author, **{field: value})
    pull = rebuild(evidence.event, author=author)
    result = evaluate_dco(rebuild(evidence, event=pull, before=pull, after=pull))

    assert result.failure is DcoFailure.MISSING_SIGNOFF


def test_dependabot_head_must_be_in_the_base_repository() -> None:
    evidence = official_dependabot_evidence()
    fork = RepositoryIdentity(id=101, full_name="fork/project")
    pull = rebuild(evidence.event, head_repository=fork)

    assert evaluate_dco(rebuild(evidence, event=pull, before=pull, after=pull)).failure is (
        DcoFailure.MISSING_SIGNOFF
    )


def test_contradictory_base_repository_identity_is_rejected_before_evaluation() -> None:
    values = official_dependabot_evidence().event.model_dump(mode="python")
    values["base_repository"] = {"id": 101, "full_name": "other/project"}

    with pytest.raises(ValidationError, match="base repository"):
        PullRequestSnapshot.model_validate(values)


def test_dependabot_branch_prefix_and_single_commit_predicates_are_required() -> None:
    evidence = official_dependabot_evidence()
    wrong_ref = rebuild(evidence.event, head_ref="renovate/dependency")
    result = evaluate_dco(rebuild(evidence, event=wrong_ref, before=wrong_ref, after=wrong_ref))
    assert result.failure is DcoFailure.MISSING_SIGNOFF

    second = signed_commit(sha(2), (evidence.event.head_sha,), message="no signoff")
    two_commit_pull = rebuild(evidence.event, commit_count=2, head_sha=second.sha)
    two_commits = rebuild(
        evidence,
        event=two_commit_pull,
        before=two_commit_pull,
        after=two_commit_pull,
        comparison=comparison_for(
            two_commit_pull,
            (evidence.comparison.commits[0], PullCommit(sha=second.sha)),
        ),
        commits=(evidence.commits[0], second),
    )
    assert evaluate_dco(two_commits).failure is DcoFailure.MISSING_SIGNOFF


@pytest.mark.parametrize(
    ("component", "field", "value"),
    (
        ("github_author", "login", "dependabot-copy[bot]"),
        ("github_author", "id", 49_699_334),
        ("github_author", "type", "User"),
        ("github_committer", "login", "github-actions[bot]"),
        ("github_committer", "id", 19_864_448),
        ("github_committer", "type", "Bot"),
        ("author", "name", "Dependabot"),
        ("author", "email", "other@github.com"),
        ("committer", "name", "github"),
        ("committer", "email", "web-flow@users.noreply.github.com"),
        ("verification", "verified", False),
        ("verification", "reason", "unknown_signature_type"),
        ("verification", "signature", ""),
        ("verification", "payload", ""),
        ("verification", "verified_at", ""),
    ),
)
def test_every_dependabot_commit_identity_predicate_is_required(
    component: str,
    field: str,
    value: object,
) -> None:
    evidence = official_dependabot_evidence()
    commit = evidence.commits[0]
    nested = getattr(commit, component)
    assert nested is not None
    changed = rebuild(nested, **{field: value})
    commit = rebuild(commit, **{component: changed})

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).failure is DcoFailure.MISSING_SIGNOFF


@pytest.mark.parametrize(
    "change",
    (
        {"parents": (sha(999),)},
        {"parents": (BASE_SHA, sha(999))},
        {"message": ("build(deps): bump\n\nsigned-off-by: dependabot[bot] <support@github.com>")},
    ),
    ids=("wrong-parent", "multiple-parents", "signoff-case"),
)
def test_dependabot_parent_and_canonical_signoff_predicates_are_required(
    change: dict[str, object],
) -> None:
    evidence = official_dependabot_evidence()
    commit = rebuild(evidence.commits[0], **change)

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).failure is DcoFailure.MISSING_SIGNOFF


def test_dependabot_commit_must_be_the_exact_head() -> None:
    evidence = official_dependabot_evidence()
    changed_list = (PullCommit(sha=sha(999)),)

    result = evaluate_dco(
        rebuild(
            evidence,
            comparison=rebuild(evidence.comparison, commits=changed_list),
        )
    )

    assert result.failure is DcoFailure.HEAD_MISMATCH


def test_an_official_dependabot_commit_can_still_use_the_ordinary_author_route() -> None:
    evidence = official_dependabot_evidence()
    commit = rebuild(
        evidence.commits[0],
        message=(
            "build(deps): bump\n\n"
            "Signed-off-by: dependabot[bot] "
            "<49699333+dependabot[bot]@users.noreply.github.com>"
        ),
        verification=rebuild(evidence.commits[0].verification, verified=False),
    )

    result = evaluate_dco(rebuild(evidence, commits=(commit,)))

    assert result.passed is True
    assert result.commits[0].outcome is DcoCommitOutcome.AUTHOR_SIGNOFF


def test_result_model_rejects_contradictory_pass_and_failure_states() -> None:
    with pytest.raises(ValidationError, match="passing result cannot have"):
        DcoEvaluationResult(
            passed=True,
            repository=REPOSITORY,
            pull_number=7,
            base_sha=BASE_SHA,
            head_sha=sha(1),
            failure=DcoFailure.MISSING_SIGNOFF,
            commits=(),
        )
    with pytest.raises(ValidationError, match="passing result cannot contain"):
        DcoEvaluationResult(
            passed=True,
            repository=REPOSITORY,
            pull_number=7,
            base_sha=BASE_SHA,
            head_sha=sha(1),
            failure=None,
            commits=(
                DcoCommitResult(
                    sha=sha(1),
                    outcome=DcoCommitOutcome.MISSING_SIGNOFF,
                ),
            ),
        )
