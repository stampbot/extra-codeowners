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
    CommitEvidence,
    CommitVerification,
    DcoCommitOutcome,
    DcoCommitResult,
    DcoEvaluationResult,
    DcoEvidenceInput,
    DcoFailure,
    GitCommitIdentity,
    GitHubActor,
    GitHubUserIdentity,
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


def _message_predicates(message: str, *, name: str, email: str) -> tuple[bool, bool]:
    lines = message.split("\n")
    author_signoff = f"Signed-off-by: {name} <{email}>".casefold()
    return (
        any(line.casefold() == author_signoff for line in lines),
        "Signed-off-by: dependabot[bot] <support@github.com>" in lines,
    )


def signed_commit(
    commit_sha: str,
    parents: tuple[str, ...],
    *,
    name: str = "Test Contributor",
    email: str = "contributor@example.com",
    message: str | None = None,
    github_author: GitHubUserIdentity | None = None,
    verification: CommitVerification | None = None,
    committer_name: str | None = None,
    committer_email: str | None = None,
) -> CommitEvidence:
    raw_message = (
        message if message is not None else f"test: change\n\nSigned-off-by: {name} <{email}>\n"
    )
    author_signoff_present, dependabot_signoff_present = _message_predicates(
        raw_message,
        name=name,
        email=email,
    )
    return CommitEvidence(
        sha=commit_sha,
        parents=parents,
        author=GitCommitIdentity(name=name, email=email),
        committer=GitCommitIdentity(
            name=committer_name or name,
            email=committer_email or email,
        ),
        author_signoff_present=author_signoff_present,
        dependabot_signoff_present=dependabot_signoff_present,
        github_author=github_author,
        verification=verification,
    )


def listed(commit: CommitEvidence | str, *, suffix: str = "") -> PullCommit:
    commit_sha = commit.sha if isinstance(commit, CommitEvidence) else commit
    return PullCommit(sha=commit_sha, node_id=f"PRC_{commit_sha}{suffix}")


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


def evidence_for_commit(
    commit: CommitEvidence,
    *,
    pull: PullRequestSnapshot | None = None,
) -> DcoEvidenceInput:
    current = pull or pull_snapshot(head_sha=commit.sha)
    return DcoEvidenceInput(
        event=current,
        before=current,
        after=current,
        comparison=comparison_for(current, (listed(commit),)),
        commits=(commit,),
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
        comparison=comparison_for(pull, tuple(listed(commit) for commit in commits)),
        commits=tuple(commits),
    )


def graphql_user(identity: GitHubUserIdentity) -> dict[str, object]:
    return {
        "login": identity.login,
        "databaseId": identity.id,
        "providerField": "ignored",
    }


def graphql_signature(verification: CommitVerification) -> dict[str, object]:
    return {
        "__typename": "GpgSignature",
        "isValid": verification.is_valid,
        "state": verification.state,
        "verifiedAt": verification.verified_at,
        "wasSignedByGitHub": verification.was_signed_by_github,
        "signer": (None if verification.signer is None else graphql_user(verification.signer)),
    }


def graphql_commit_payload(
    *,
    commit_sha: str = sha(1),
    parents: tuple[str, ...] = (BASE_SHA,),
    name: str = "Test Contributor",
    email: str = "contributor@example.com",
    committer_name: str | None = None,
    committer_email: str | None = None,
    message: str | None = None,
    github_author: GitHubUserIdentity | None = None,
    verification: CommitVerification | None = None,
) -> dict[str, Any]:
    return {
        "oid": commit_sha,
        "parents": {
            "totalCount": len(parents),
            "nodes": [{"oid": parent, "ignored": True} for parent in parents],
            "pageInfo": {"hasNextPage": False, "endCursor": None},
        },
        "message": (
            message if message is not None else f"test: change\n\nSigned-off-by: {name} <{email}>\n"
        ),
        "author": {
            "name": name,
            "email": email,
            "user": None if github_author is None else graphql_user(github_author),
            "date": "ignored",
        },
        "committer": {
            "name": committer_name or name,
            "email": committer_email or email,
            "user": {"login": "ignored-committer", "databaseId": 999},
            "date": "ignored",
        },
        "signature": None if verification is None else graphql_signature(verification),
        "tree": {"oid": sha(999)},
    }


def parsed_commit(**changes: Any) -> CommitEvidence:
    return CommitEvidence.from_graphql(graphql_commit_payload(**changes))


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
            commits=(*evidence.comparison.commits, listed(sha(999))),
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
                commits=(evidence.comparison.commits[0], listed(sha(999))),
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
        comparison=comparison_for(pull, (listed(first), listed(disconnected))),
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
            tuple(listed(item) for item in (left, right, merge)),
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
        comparison=comparison_for(pull, (listed(child),)),
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
        tuple(listed(item) for item in (left, right, merge)),
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
    commit = parsed_commit(message=message)
    result = evaluate_dco(evidence_for_commit(commit))

    assert commit.author_signoff_present is passes
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
    commit = parsed_commit(name=name, email=email)

    assert evaluate_dco(evidence_for_commit(commit)).passed is True


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
def test_author_signoff_parser_uses_unicode_casefold_parity(
    name: str,
    email: str,
    trailer_identity: str,
) -> None:
    commit = parsed_commit(
        name=name,
        email=email,
        message=f"SIGNED-OFF-BY: {trailer_identity}",
    )

    assert commit.author_signoff_present is True
    assert evaluate_dco(evidence_for_commit(commit)).passed is True


def test_author_signoff_parser_does_not_apply_unicode_normalization() -> None:
    commit = parsed_commit(
        name="José",
        email="jose@example.com",
        message="Signed-off-by: Jose\u0301 <JOSE@EXAMPLE.COM>",
    )

    assert commit.author_signoff_present is False
    assert evaluate_dco(evidence_for_commit(commit)).failure is DcoFailure.MISSING_SIGNOFF


def test_control_characters_cannot_turn_a_nonmatching_line_into_a_signoff() -> None:
    commit = parsed_commit(
        message="\x1b[2KSigned-off-by: Test Contributor <contributor@example.com>"
    )

    assert commit.author_signoff_present is False
    assert evaluate_dco(evidence_for_commit(commit)).failure is DcoFailure.MISSING_SIGNOFF


@pytest.mark.parametrize(
    ("model", "changes", "match"),
    (
        (GitCommitIdentity, {"name": "bad\nname", "email": "a@example.com"}, "control"),
        (GitCommitIdentity, {"name": "bad<name", "email": "a@example.com"}, "must not"),
        (GitHubActor, {"login": "bad login", "id": 1, "type": "User"}, "whitespace"),
        (GitHubUserIdentity, {"login": "bad login", "id": 1}, "whitespace"),
        (PullCommit, {"sha": "A" * 40, "node_id": "PRC_1"}, "lowercase"),
        (PullCommit, {"sha": sha(1), "node_id": "bad id"}, "whitespace"),
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


def test_projected_boolean_fields_remain_strict() -> None:
    commit_values = parsed_commit().model_dump(mode="python")
    verification_values = CommitVerification(
        is_valid=True,
        state="VALID",
        verified_at="2026-07-22T00:00:00Z",
        was_signed_by_github=True,
        signer=None,
    ).model_dump(mode="python")

    with pytest.raises(ValidationError, match="valid boolean"):
        CommitEvidence.model_validate({**commit_values, "author_signoff_present": 1})
    with pytest.raises(ValidationError, match="valid boolean"):
        CommitEvidence.model_validate({**commit_values, "dependabot_signoff_present": "true"})
    with pytest.raises(ValidationError, match="valid boolean"):
        CommitVerification.model_validate({**verification_values, "is_valid": 1})
    with pytest.raises(ValidationError, match="valid boolean"):
        CommitVerification.model_validate({**verification_values, "was_signed_by_github": "true"})


def test_models_reject_unknown_fields_and_mutation() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PullCommit.model_validate({"sha": sha(1), "node_id": "PRC_1", "message": "hidden"})

    item = listed(sha(1))
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


def test_payload_factories_copy_only_strict_consumed_fields() -> None:
    evidence = linear_evidence(1)
    pull = PullRequestSnapshot.from_github(
        github_pull_payload(evidence.event), repository=REPOSITORY
    )
    pull_commit = PullCommit.from_graphql(
        {
            "id": evidence.comparison.commits[0].node_id,
            "commit": {"oid": evidence.event.head_sha, "message": "ignored"},
            "ignored": True,
        }
    )
    commit = CommitEvidence.from_graphql(graphql_commit_payload())

    assert pull == evidence.event
    assert pull_commit == evidence.comparison.commits[0]
    assert commit == parsed_commit()


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
        lambda payload: payload.pop("id"),
        lambda payload: payload.__setitem__("commit", None),
        lambda payload: payload["commit"].pop("oid"),
    ),
    ids=("missing-node-id", "null-commit", "missing-oid"),
)
def test_pull_commit_graphql_factory_fails_closed(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    payload: dict[str, Any] = {"id": "PRC_1", "commit": {"oid": sha(1)}}
    mutate(payload)

    with pytest.raises((ValueError, ValidationError)):
        PullCommit.from_graphql(payload)


def test_graphql_commit_parser_projects_large_text_without_retaining_raw_blobs() -> None:
    trailer = "Signed-off-by: Test Contributor <contributor@example.com>"
    prefix_bytes = MAX_COMMIT_MESSAGE_BYTES - len(trailer.encode()) - 1
    message = f"{'m' * prefix_bytes}\n{trailer}"
    verification = CommitVerification(
        is_valid=True,
        state="VALID",
        verified_at="2026-07-22T00:00:00Z",
        was_signed_by_github=True,
        signer=GitHubUserIdentity(login="web-flow", id=19_864_447),
    )
    payload = graphql_commit_payload(message=message, verification=verification)
    raw_signature = "s" * 500_000
    raw_signed_payload = "p" * 500_000
    payload["signature"].update({"signature": raw_signature, "payload": raw_signed_payload})

    commit = CommitEvidence.from_graphql(payload)
    projected_json = commit.model_dump_json()

    assert commit.author_signoff_present is True
    assert commit.verification == verification
    assert "message" not in type(commit).model_fields
    assert "github_committer" not in type(commit).model_fields
    assert "signature" not in type(commit.verification).model_fields
    assert "payload" not in type(commit.verification).model_fields
    assert "m" * 100 not in projected_json
    assert "s" * 100 not in projected_json
    assert "p" * 100 not in projected_json
    assert len(projected_json) < 2_000


@pytest.mark.parametrize(
    ("message", "match"),
    (
        ("é" * (MAX_COMMIT_MESSAGE_BYTES // 2 + 1), "message exceeds"),
        ("bad\0message", "must not contain NUL"),
        (123, "must be text"),
    ),
    ids=("utf8-byte-limit", "nul", "not-text"),
)
def test_graphql_commit_parser_rejects_malformed_or_oversized_messages(
    message: object,
    match: str,
) -> None:
    payload = graphql_commit_payload()
    payload["message"] = message

    with pytest.raises(ValueError, match=match):
        CommitEvidence.from_graphql(payload)


@pytest.mark.parametrize("count", (0, MAX_COMMIT_PARENTS))
def test_graphql_commit_parser_accepts_complete_bounded_parent_pages(count: int) -> None:
    parents = tuple(sha(20_000 + index) for index in range(count))

    assert parsed_commit(parents=parents).parents == parents


@pytest.mark.parametrize(
    ("change", "match"),
    (
        ({"totalCount": MAX_COMMIT_PARENTS + 1}, "count exceeds"),
        ({"totalCount": -1}, "count exceeds"),
        ({"totalCount": True}, "count exceeds"),
        ({"pageInfo": {"hasNextPage": True}}, "list exceeds"),
        ({"pageInfo": {"hasNextPage": 0}}, "list exceeds"),
        ({"nodes": []}, "complete list"),
        ({"nodes": "not-a-list"}, "complete list"),
    ),
    ids=(
        "over-limit",
        "negative-count",
        "boolean-count",
        "next-page",
        "non-boolean-page-flag",
        "count-mismatch",
        "nodes-not-list",
    ),
)
def test_graphql_commit_parser_rejects_incomplete_or_unbounded_parent_pages(
    change: dict[str, object],
    match: str,
) -> None:
    payload = graphql_commit_payload()
    payload["parents"].update(change)

    with pytest.raises(ValueError, match=match):
        CommitEvidence.from_graphql(payload)


@pytest.mark.parametrize(
    ("parents", "match"),
    (
        ((BASE_SHA, BASE_SHA), "parents must be unique"),
        (("not-a-sha",), "parent SHA"),
    ),
)
def test_graphql_commit_parser_rejects_invalid_projected_parents(
    parents: tuple[str, ...],
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        parsed_commit(parents=parents)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.pop("oid"),
        lambda payload: payload.__setitem__("author", None),
        lambda payload: payload["author"].pop("email"),
        lambda payload: payload.__setitem__("committer", None),
        lambda payload: payload["parents"].pop("pageInfo"),
        lambda payload: payload["parents"]["nodes"].__setitem__(0, "bad"),
        lambda payload: payload.__setitem__("signature", "bad"),
        lambda payload: payload["author"].__setitem__("user", {"login": "missing-id"}),
    ),
    ids=(
        "missing-oid",
        "null-author",
        "missing-author-email",
        "null-committer",
        "missing-parent-page-info",
        "parent-not-object",
        "signature-not-object",
        "malformed-github-author",
    ),
)
def test_commit_graphql_factory_fails_closed_on_missing_or_malformed_shapes(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    payload = graphql_commit_payload()
    mutate(payload)

    with pytest.raises((ValueError, ValidationError)):
        CommitEvidence.from_graphql(payload)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.pop("isValid"),
        lambda payload: payload.pop("state"),
        lambda payload: payload.pop("wasSignedByGitHub"),
        lambda payload: payload.__setitem__("isValid", 1),
        lambda payload: payload.__setitem__("wasSignedByGitHub", "true"),
        lambda payload: payload.__setitem__("signer", {"login": "missing-id"}),
    ),
    ids=(
        "missing-validity",
        "missing-state",
        "missing-github-signature-flag",
        "non-boolean-validity",
        "non-boolean-github-signature-flag",
        "malformed-signer",
    ),
)
def test_signature_graphql_factory_fails_closed_on_malformed_predicates(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    verification = CommitVerification(
        is_valid=True,
        state="VALID",
        verified_at="2026-07-22T00:00:00Z",
        was_signed_by_github=True,
        signer=GitHubUserIdentity(login="web-flow", id=19_864_447),
    )
    payload = graphql_signature(verification)
    mutate(payload)

    with pytest.raises((ValueError, ValidationError)):
        CommitVerification.from_graphql(payload)


def official_dependabot_evidence() -> DcoEvidenceInput:
    pull_author = GitHubActor(login="dependabot[bot]", id=49_699_333, type="Bot")
    commit_author = GitHubUserIdentity(login="dependabot[bot]", id=49_699_333)
    verification = CommitVerification(
        is_valid=True,
        state="VALID",
        verified_at="2026-07-22T00:00:00Z",
        was_signed_by_github=True,
        signer=GitHubUserIdentity(login="web-flow", id=19_864_447),
    )
    commit = parsed_commit(
        commit_sha=sha(1),
        parents=(BASE_SHA,),
        name="dependabot[bot]",
        email="49699333+dependabot[bot]@users.noreply.github.com",
        committer_name="GitHub",
        committer_email="noreply@github.com",
        message=(
            "build(deps): bump a dependency\n\nSigned-off-by: dependabot[bot] <support@github.com>"
        ),
        github_author=commit_author,
        verification=verification,
    )
    pull = pull_snapshot(
        head_sha=commit.sha,
        author=pull_author,
        head_ref="dependabot/pip/example-1.2.3",
    )
    return evidence_for_commit(commit, pull=pull)


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
            (evidence.comparison.commits[0], listed(second)),
        ),
        commits=(evidence.commits[0], second),
    )
    assert evaluate_dco(two_commits).failure is DcoFailure.MISSING_SIGNOFF


@pytest.mark.parametrize(
    ("component", "field", "value"),
    (
        ("github_author", "login", "dependabot-copy[bot]"),
        ("github_author", "id", 49_699_334),
        ("author", "name", "Dependabot"),
        ("author", "email", "other@github.com"),
        ("committer", "name", "github"),
        ("committer", "email", "web-flow@users.noreply.github.com"),
        ("verification", "is_valid", False),
        ("verification", "state", "INVALID"),
        ("verification", "verified_at", None),
        ("verification", "verified_at", ""),
        ("verification", "was_signed_by_github", False),
        ("signer", "login", "github-actions[bot]"),
        ("signer", "id", 19_864_448),
    ),
    ids=(
        "github-author-login",
        "github-author-id",
        "raw-author-name",
        "raw-author-email",
        "raw-committer-name",
        "raw-committer-email",
        "signature-validity",
        "signature-state",
        "missing-verification-time",
        "empty-verification-time",
        "github-created-signature",
        "signer-login",
        "signer-id",
    ),
)
def test_every_dependabot_commit_identity_predicate_is_required(
    component: str,
    field: str,
    value: object,
) -> None:
    evidence = official_dependabot_evidence()
    commit = evidence.commits[0]
    if component == "signer":
        verification = commit.verification
        assert verification is not None
        assert verification.signer is not None
        signer = rebuild(verification.signer, **{field: value})
        changed = rebuild(verification, signer=signer)
        commit = rebuild(commit, verification=changed)
    else:
        nested = getattr(commit, component)
        assert nested is not None
        changed = rebuild(nested, **{field: value})
        commit = rebuild(commit, **{component: changed})

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).failure is DcoFailure.MISSING_SIGNOFF


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("github_author", None),
        ("verification", None),
        ("dependabot_signoff_present", False),
    ),
    ids=("missing-github-author", "missing-signature", "missing-canonical-trailer"),
)
def test_optional_and_projected_dependabot_predicates_are_required(
    field: str,
    value: object,
) -> None:
    evidence = official_dependabot_evidence()
    commit = rebuild(evidence.commits[0], **{field: value})

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).failure is DcoFailure.MISSING_SIGNOFF


def test_dependabot_signature_requires_a_github_signer_identity() -> None:
    evidence = official_dependabot_evidence()
    verification = evidence.commits[0].verification
    assert verification is not None
    commit = rebuild(evidence.commits[0], verification=rebuild(verification, signer=None))

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).failure is DcoFailure.MISSING_SIGNOFF


@pytest.mark.parametrize(
    "parents",
    (
        (sha(999),),
        (BASE_SHA, sha(999)),
        (),
    ),
    ids=("wrong-parent", "multiple-parents", "missing-parent"),
)
def test_dependabot_parent_must_be_exactly_the_current_base(
    parents: tuple[str, ...],
) -> None:
    evidence = official_dependabot_evidence()
    commit = rebuild(evidence.commits[0], parents=parents)

    assert evaluate_dco(rebuild(evidence, commits=(commit,))).failure is DcoFailure.MISSING_SIGNOFF


def test_dependabot_signoff_projection_is_exact_case_and_whole_line() -> None:
    evidence = official_dependabot_evidence()
    original = evidence.commits[0]
    commit = parsed_commit(
        commit_sha=original.sha,
        parents=original.parents,
        name=original.author.name,
        email=original.author.email,
        committer_name=original.committer.name,
        committer_email=original.committer.email,
        github_author=original.github_author,
        verification=original.verification,
        message="signed-off-by: dependabot[bot] <support@github.com>",
    )

    assert commit.dependabot_signoff_present is False
    assert evaluate_dco(rebuild(evidence, commits=(commit,))).failure is DcoFailure.MISSING_SIGNOFF


def test_dependabot_commit_must_be_the_exact_head() -> None:
    evidence = official_dependabot_evidence()
    wrong_detail = rebuild(evidence.commits[0], sha=sha(999))

    result = evaluate_dco(rebuild(evidence, commits=(wrong_detail,)))

    assert result.passed is False
    assert result.failure is DcoFailure.COMMIT_ORDER_MISMATCH


def test_an_official_dependabot_commit_can_still_use_the_ordinary_author_route() -> None:
    evidence = official_dependabot_evidence()
    verification = evidence.commits[0].verification
    assert verification is not None
    commit = rebuild(
        evidence.commits[0],
        author_signoff_present=True,
        verification=rebuild(verification, is_valid=False),
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
