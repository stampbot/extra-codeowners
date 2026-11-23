# The worker checked a candidate with another PR waiting: November 23, 2026

An unbuilt PR behind the front of a serial queue didn't stop Extra CODEOWNERS
from evaluating the front candidate. After that candidate lost its approval,
GitHub removed it and built a new candidate for the second PR. The second
candidate didn't inherit either required check.

## Setup

We used the signed [alpha.115 image][alpha] from
`60668c354707e00f166460142ddf8327676b45bb` in a fresh isolated Kubernetes Job.
The test used the same serial queue rules, SQLite database setup, and separate
required check as the [missed-dismissal probe](2026-11-23-missed-review-dismissal.md).
The private fixture had two synthetic PRs. Stampbot approved the first; no one
approved the second.

## What GitHub and the worker returned

From 15:02 to 15:05 UTC:

- Before the initial delivery replay, GitHub showed the first candidate in
  `AWAITING_CHECKS`. The second PR was `QUEUED` with neither a base nor a
  candidate commit in its queue entry. We replayed only the delivery for
  the first candidate.
- The worker passed the first candidate and kept that Check Run passing
  through a timer recheck. GitHub still showed the second PR waiting
  without a candidate.
- We requested dismissal of the Stampbot review at 15:03:58. The worker
  didn't receive the dismissal event. At 15:04:22 it read back failure
  on the same Check Run. GitHub recorded removal for `failed_checks`
  at 15:04:51.
- GitHub built a distinct commit for the second candidate and waited for
  checks. Neither the expected App's check nor the separate hold was
  present on that commit. We didn't replay the second candidate's delivery.

Neither PR merged, and the target didn't move. We revoked the scoped tokens,
removed the Job, closed both PRs, and removed the branches and ruleset
created for the test. The original default branch and its rule were unchanged.

## Limits

This tested two entries with one built candidate at a time. It didn't test
groups that contain more than one PR, approval of the second candidate, or
review dismissal while GitHub is already merging. The separate required
check kept both candidates from merging throughout. The
[merge-queue proposal][queue-design] explains why the worker checks how many
candidates GitHub can build, not just how many PRs are waiting.

[alpha]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.115
[queue-design]: ../../explanation/design/2026-11-21-merge-queue-candidate-checks.md
