# Independent review count in the merge queue: November 23, 2026

GitHub refused to queue a pull request with a passing Extra CODEOWNERS check
and no approving reviews. Stampbot then approved the same PR head, and GitHub
admitted it to the queue. The candidate didn't merge because a separate
required check never ran on that commit.

We ran two probes from 14:22 to 14:29 UTC in the private disposable repository
used for the [earlier queue test](2026-11-23-candidate-checks-during-delivery-loss.md).
The deployed App ran [alpha.111][alpha] from
`2bc0e98f60286c30e76b7bcc260faeb39eed31f0`. Its experimental queue worker was
off. Neither PR merged, and no production review rule changed.

## GitHub still required an approving review

The temporary target let an author satisfy Extra CODEOWNERS for a path the
author owned. GitHub required its merge queue, one ordinary approving review,
and a passing check from the installed Extra CODEOWNERS App. GitHub's native
code-owner review was off for this branch. The queue built one candidate at a
time, merged one PR at a time, required checks to pass, and had no bypass
actors. We also required a separate fixture check and set it on the PR head
only.

Both head checks passed. GitHub still reported `REVIEW_REQUIRED`. Its queue
API refused the request because an approving review from a reviewer with
write access was missing. We asked Stampbot to approve without changing the
head. GitHub recorded the App's review on that commit, reported `APPROVED`,
and accepted the next queue request.

The candidate had a different commit and waited in `AWAITING_CHECKS`. We
confirmed that the fixture check was absent from it and closed the PR without
merging. The target didn't move.

## Review dismissal on an ordinary PR

On a separate branch with author approval disabled, Stampbot approved a
delegated path. Extra CODEOWNERS reported success on the PR head. After we
dismissed the review, the App changed the same Check Run to failure. We
didn't enqueue that PR.

We restored the disposable repository's original default branch, closed both
PRs, and removed the branches and rule created for the probes. Its default
branch tip and original rule were unchanged.

## Limits

This shows that a passing PR check doesn't replace GitHub's numeric review
rule and that a real Stampbot review satisfied that rule in this fixture. It
doesn't show that the worker revalidates a passing candidate after a review
is dismissed. It also doesn't establish support for queues with more than
one built candidate. [Issue #347][release-gate] tracks the release boundary.

[alpha]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.111
[release-gate]: https://github.com/stampbot/extra-codeowners/issues/347
