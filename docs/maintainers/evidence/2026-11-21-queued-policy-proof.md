# November 21, 2026: policy evaluation on a queue candidate

GitHub merged a benign change into a disposable branch after a local
operator probe evaluated its PR and posted a passing check on the
bound candidate. The resulting branch tip was the candidate commit.
The deployed service didn't evaluate the candidate or publish that
check.

## Test conditions

The probes ran from 22:58 to 23:19 UTC on November 21, 2026, in the
same private fixture as the [delivery test](2026-11-21-merge-group-delivery.md).
The shared App's deployed receiver ran [alpha.95][alpha95]. The local
probe used the evaluator from [alpha.97][alpha97], source
`a1f728a19b7e1a068a2bfb957a03d1d17febdfda`, and the read-only candidate
verifier from [PR #316][verifier].

Each temporary target branch required a one-entry queue and the same
fixture check from the shared App, with no bypass actors. The check name
was distinct from the deployed App's advisory check. A passing control
on the PR head allowed queue entry; GitHub still waited for the candidate's
own result. The operator used short-lived read tokens for the fixture
and its organization policy, and separate fixture-only tokens for check
writes.

## Observations

- **Author policy.** The queued PR passed when its target branch opted
  in to author-as-code-owner. The evaluator failed a second read with
  that option disabled in memory and no approval. This was a
  counterfactual, not a change to the branch's policy.
- **App review withdrawal.** A separate branch allowed one delegated
  path but did not allow author ownership. Stampbot approved the PR
  head, and the evaluator passed. Dismissing that exact review made the
  evaluator fail. GitHub kept the same candidate waiting; we published
  no result and closed the PR. Stampbot needed the test branch to be
  the disposable repository's default while it read its config. We
  restored the original default before queueing the PR.
- **Candidate check and merge.** The operator evaluated a new,
  author-owned PR, rechecked its candidate and the fixture's rules,
  then published a pass on the candidate from the required App. GitHub
  merged the PR, and the new target tip had both the candidate's SHA
  and the evaluated PR head's tree. The original default branch did
  not advance.
- **Older base.** After the successful merge moved the temporary
  target, GitHub still queued a different PR based on the earlier tip.
  The new candidate's parent was the current target tip and its tree
  differed from the PR head. The verifier refused that case, so the
  probe didn't post a candidate result.
- **Shared head.** Two open PRs had the same head SHA. Their distinct
  target branches also pointed to the same base SHA. GitHub created
  different candidate SHAs and held both for checks. Each App delivery
  matched its own queue entry; the verifier rejected it against the
  other queue. Neither PR merged.

We revoked the temporary tokens, closed the unmerged PRs, and removed
the temporary branches and rulesets. The original branch and rule
remained in place.

## Limits

The checks came from an operator probe, not a durable merge-group worker.
These observations don't establish safe publication after delivery loss,
review changes during a write, or queue and base movement outside the
tested cases. The shared-head probe had one entry per target; it did
not test two entries in one queue. The verifier accepts only one entry
and requires both commits to be direct children of the verified base.
A normal PR can fall outside that case, as the older-base probe showed.

[Issue #4][queue-work] tracks the remaining implementation and tests.
Retain native code-owner enforcement on production repositories.

[alpha95]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.95
[alpha97]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.97
[verifier]: https://github.com/stampbot/extra-codeowners/pull/316
[queue-work]: https://github.com/stampbot/extra-codeowners/issues/4
