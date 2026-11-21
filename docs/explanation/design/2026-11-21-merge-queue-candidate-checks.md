# Design: Check the commit in the merge queue

GitHub can show two pull requests the same passing Check Run when they
share a head commit. The App can revoke that check after it hears about
the second PR, but it can't make webhook delivery atomic with merging. A
check on GitHub's queue candidate could close that particular gap.

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-21 |
| Status | Proposed; not implemented |
| Owner | Maintainers |
| Scope | A first proof with one queue entry and an isolated GitHub App |
| Related | [Shared-commit blocker][shared-head], [merge-queue work][queue-work], [November 20 provider test][provider-test] |

## What we know

In the playground fixture, GitHub required a named check from the expected
App. A pass on the PR head let it enter the queue. The synthetic commit
still waited for its own result. A failure on that candidate removed the
PR from the queue without merging it.

The live GraphQL queue entry identified both the PR and the synthetic
head. The entry's base and head were null before GitHub finished building
the candidate. GitHub assigned a different entry ID and candidate
commit when we requeued the same PR, even though the queue ref name
stayed the same. That's one observation, not a guarantee against reuse.

We wrote those checks by hand. They don't establish the contents of a
`merge_group` delivery, prove that a candidate contains only the expected
PR, or show that the policy evaluator can publish to one safely.

## Boundaries

- [XCO-001](../threat-model.md#invariants): missing or contradictory
  evidence must block, including a queue read that is incomplete.
- [XCO-002 and XCO-007](../threat-model.md#invariants): identify the PR head
  whose reviews were evaluated and the separate candidate that receives
  the Check Run. A pass on one target must not authorize the other.
- [XCO-008 through XCO-010](../threat-model.md#invariants): don't bypass
  the current generation, authority or publication guards. An uncertain
  write isn't a confirmed decision.
- [XCO-011](../threat-model.md#invariants): capture field names and
  observations for the test receipt. Don't publish raw private payloads.

Queue support must not change the ordinary PR author, review, or App
delegation rules. Keep native review in place on repositories that need
it. The test App doesn't need to approve reviews, merge PRs, or change the
operating App registration.

## Options

Keep revoking the PR-head check as soon as events arrive. This improves the
existing shadow check, but no amount of retrying can prove GitHub blocked a
merge while the event was still missing.

Require a separate check on GitHub's synthetic merge candidate. The
one-entry test supports this direction. It adds an API and webhook
dependency, and we still need to prove which reviews and policy apply.

Keep native enforcement as the only production gate. This is safe within
its current scope, but a delegated App review still can't replace the
human code-owner approval the project was designed to complement.

## Proposed first proof

Use a separate App installed only on the disposable repository. Give it
read access to **Merge queues**, subscribe to `merge_group`, and grant
**Checks: write**. Add only the other read permissions the evaluation
needs. GitHub documents the [event and its permission][merge-group-event].
The test must capture a real App delivery; a workflow event or a synthetic
request isn't evidence about the installation delivery.

Start with a mandatory queue, no bypass actors, one build and merge slot,
and the setting that requires each entry to pass. Verify these settings
and the expected check source independently in the fixture. Limit the
first test to a queue snapshot with exactly one entry. One build slot
alone doesn't establish that a candidate represents one PR.

The following order keeps the evaluation tied to what GitHub may merge:

1. Verify the webhook signature and bind the installation and repository.
   Store the candidate commit and base from the event in durable work.
   Don't use a PR number parsed from the queue ref as proof of membership.
2. Resolve the candidate ref and read the current [queue entry][queue-entry].
   Require an unambiguous match on repository, base and candidate commit.
   Record the queue entry ID and its associated open PR and head. Null queue
   commits get a bounded retry. Missing, contradictory or truncated reads
   don't authorize a check.
3. Read the policy from the candidate's verified target-branch base. Read
   fresh reviews for the PR head and verify that the candidate preserves
   the change the PR was reviewed for. Candidate equivalence is an open
   proof obligation: if GitHub can't supply enough evidence, stop.
4. Recheck the entry, refs, PR and relevant generations at publication.
   Bind the result to the candidate and the App. If the candidate moved,
   discard the old work rather than copying its result to the new commit.

The PR-head result may still be needed to enter the queue. It doesn't
prove that the candidate is approved. Test both stages, including the
rules that make the queue mandatory, before proposing a supported mode.

## What would rule this out

Test the initial candidate and a rebuild after a requeue or base change.
Prove GitHub waits when the current candidate delivery is withheld or its
identity can't be resolved. Prove it accepts a correctly evaluated,
approved candidate in the disposable fixture. Record what GitHub does
when the evidence changes before and after publication. Do not claim that
review withdrawal and merging are atomic; a result can still go stale
after the final read.

If the App can't identify the candidate's contents or GitHub reuses a
prior result for a different decision, stop before any production rollout.
The [shared-commit issue][shared-head] remains the release gate.

[shared-head]: https://github.com/stampbot/extra-codeowners/issues/1
[queue-work]: https://github.com/stampbot/extra-codeowners/issues/4
[provider-test]: https://github.com/stampbot/extra-codeowners/issues/4#issuecomment-7029566017
[merge-group-event]: https://docs.github.com/en/webhooks/webhook-events-and-payloads#merge_group
[queue-entry]: https://docs.github.com/en/graphql/reference/pulls#mergequeueentry
