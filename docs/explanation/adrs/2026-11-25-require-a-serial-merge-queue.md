# ADR: Require a one-at-a-time merge queue for enforcement

| Field | Value |
| --- | --- |
| Date | 2026-11-25 |
| Status | Accepted |
| Owner | Maintainers |
| Scope | The supported GitHub.com configuration for replacing native code-owner review in 1.0 |
| Related | [Release gate #347][release-gate], [queue design][proposal], [required-check ADR][check-adr] |

## Why the PR-head check isn't enough

Extra CODEOWNERS decides whether one pull request satisfies its owners.
GitHub attaches the Check Run to a commit. Two PRs can share that commit, so
a passing check can appear on a different PR before the App gets a chance
to reassess it. Faster delivery would make that window smaller. It wouldn't
make a pass belong to one PR.

## Decision

For 1.0, replace native code-owner review only when a GitHub.com repository
requires a one-at-a-time merge queue and the Extra CODEOWNERS check from the
installed App. GitHub builds one candidate at a time and squash merges one
PR per merge. Every candidate must pass. The queue can hold other PRs, but
each needs its own candidate and its own policy evaluation when it gets
to the front. Leave the ordinary review count and other protections in place.

Candidate checks are opt-in for one repository per service deployment.
Outside this setup, leave native code-owner review enabled and use Extra
CODEOWNERS as an advisory check. In particular, GitHub.com doesn't offer a
merge queue for personal repositories or private repositories on Team plans.

## Evidence and limits

In the [delivery-loss test][delivery-loss], GitHub didn't reuse the PR-head
pass. It waited for the candidate: an undelivered result timed out, and an
ineligible candidate failed. In the [follow-on test][waiting], GitHub gave a
waiting PR a distinct candidate only after the first candidate failed. The
first check didn't satisfy the second. A separate [approved control][merged]
merged the candidate the App evaluated, with GitHub's one-review requirement
still active. The [native-review handback][handback] blocked queue admission
for a non-owner without a native code-owner review despite a passing App
check and a qualifying ordinary approval.

The App can withdraw a confirmed pass after it learns that an approval is
no longer valid. It can't revoke one atomically with GitHub's merge. A lost
initial delivery, missing candidate CI check, or unavailable GitHub read can
hold up the queue. Operators must be able to restore native review before
they remove the App's access.

## Alternatives

Requiring only the PR-head check would work on more repositories, but
would leave the shared-commit gap open. Parallel builds or grouped merges
would increase queue throughput, but a candidate that combines several
PRs needs a proof for every included change. The current worker doesn't
make that claim. [Issue #4][queue-work] tracks broader queue support.

[release-gate]: https://github.com/stampbot/extra-codeowners/issues/347
[queue-work]: https://github.com/stampbot/extra-codeowners/issues/4
[proposal]: ../design/2026-11-21-merge-queue-candidate-checks.md
[check-adr]: 2026-07-13-app-approvals-through-a-required-check.md
[delivery-loss]: ../../maintainers/evidence/2026-11-23-candidate-checks-during-delivery-loss.md
[waiting]: ../../maintainers/evidence/2026-11-23-worker-with-queued-follower.md
[merged]: ../../maintainers/evidence/2026-11-23-approved-candidate-merged.md
[handback]: ../../maintainers/evidence/2026-11-23-native-review-restored-with-queue.md
