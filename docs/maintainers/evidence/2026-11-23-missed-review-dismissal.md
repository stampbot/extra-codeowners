# A queued candidate lost its approval: November 23, 2026

Extra CODEOWNERS kept a passing candidate check green while its approval
was valid. After the Stampbot review was dismissed, the worker changed the
same Check Run to failure without receiving the dismissal webhook. GitHub
removed the candidate from the queue. The pull request didn't merge.

## Setup

We ran the signed [alpha.115 image][alpha] from
`60668c354707e00f166460142ddf8327676b45bb` in an isolated Kubernetes Job
with a fresh SQLite database. The test used a private disposable GitHub.com
repository. The shared App service and its database stayed online and
didn't run the candidate worker.

The target branch required squash merging, one build slot, one PR per
merge, and passing checks for every entry. No actor could bypass the rule.
The rule required a check from the installed App and a separate fixture
check. We passed the fixture check on the PR head only, so the candidate
could not merge.

Stampbot approved a change to one delegated path. Author approval was
disabled. We replayed GitHub's real `merge_group.checks_requested` payload
to the isolated receiver, with a local signature for its temporary webhook
secret. We didn't replay any review or cancellation delivery to that worker.
The worker read live reviews and queue state from GitHub.

## What happened

On November 23, from 14:54 to 14:57 UTC:

- At 14:55:02 the receiver accepted and stored the candidate delivery.
  The worker reported success on the candidate's commit.
- By 14:55:42 the worker had completed a timer recheck. The recorded Check
  Run was still passing and the separate required check was still absent.
- We requested dismissal of the Stampbot review at 14:55:44. GitHub
  confirmed the dismissal. At 14:56:11 the worker read back failure on the
  same Check Run, commit, and App identity.
- At 14:56:39 GitHub recorded removal from the queue with reason
  `failed_checks`. The target branch didn't move.

We revoked the scoped test tokens, removed the Job, closed the unmerged
PR, and removed the temporary branches and ruleset. The original default
branch and its rule were unchanged.

## Limits

The timer was set to 20 seconds. The elapsed time from the dismissal
request to the failed check was about 28 seconds in this run. That isn't
a latency guarantee. A separate check held the candidate throughout, so
this test doesn't make review dismissal atomic with merging.

This run covered one candidate and an isolated worker. It didn't exercise
direct callback delivery to the shared service, replica coordination on
PostgreSQL, or multiple entries waiting on the same branch.
[Issue #4][queue-work] tracks the queue tests; [issue #347][release-gate]
tracks the production support decision.

[alpha]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.115
[queue-work]: https://github.com/stampbot/extra-codeowners/issues/4
[release-gate]: https://github.com/stampbot/extra-codeowners/issues/347
