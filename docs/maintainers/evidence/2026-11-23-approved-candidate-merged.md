# An approved candidate merged under both rules: November 23, 2026

GitHub merged the commit that Extra CODEOWNERS evaluated. The branch
required the installed App's candidate check and one ordinary approving
review. A real Stampbot review satisfied the review count. After the merge,
the worker retired the timer and left the candidate's Check Run passing.

## Setup

We ran the signed [alpha.115 image][alpha] from
`60668c354707e00f166460142ddf8327676b45bb` in an isolated Kubernetes Job
with a fresh SQLite database. The private fixture used a temporary target
branch with squash merging, one build slot, one PR per merge, and passing
checks for every entry. No actor could bypass the rule. GitHub's native
code-owner review was off on that branch; its one-review requirement stayed on.

We disabled author approval for the fixture. Stampbot approved the PR head
for a change to one delegated path. GitHub reported the ordinary review
requirement as satisfied. A separate fixture check held the candidate until
we had read back the worker's result. Only the real candidate webhook was
replayed to the isolated receiver.

## What happened

On November 23, from 15:15 to 15:18 UTC:

- The worker passed the candidate and kept the same Check Run green through
  a timer recheck. At 15:17:11 the separate required check was still absent.
- We checked the review decision and effective rules again, then passed the
  fixture check on that candidate. We didn't call a merge endpoint or change
  the branch rules to complete the merge.
- At 15:17:52 GitHub merged the evaluated candidate into the temporary
  target. The new target tip and the reported merge commit matched the
  candidate the worker checked.
- At 15:18:01 the worker's timer no longer tracked the merged candidate.
  The same Check Run still read back as a completed success.

We revoked the scoped tokens and removed the Job, branches, and ruleset
created for this test. The original default branch and rule were unchanged.

## Limits

This is a positive control for the serial queue and ordinary review rule
together. The [review-count probe](2026-11-23-independent-review-count.md)
separately verified that a green PR check without an approving review
didn't let a PR enter the queue. This run doesn't establish a supported
production configuration or eliminate the window between review dismissal
and merge. [Issue #347][release-gate] tracks that decision.

[alpha]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.115
[release-gate]: https://github.com/stampbot/extra-codeowners/issues/347
