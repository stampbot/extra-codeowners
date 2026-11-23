# November 22, 2026: A behind-base PR in the merge queue

A pull request with two commits passed the policy probe even though its branch
was behind the target. GitHub preserved independent edits to the same file.
The candidate's whole tree differed from the PR head, but its changes relative
to the target were covered by the review on that head.

## What we tested

The policy probe ran from 17:11 to 17:16 UTC in the disposable GitHub repository
from the [November 21 test](2026-11-21-queued-policy-proof.md). It used the same
one-entry queue. The local evaluator came from commit
`4a890d04e4b7cef23a379cc695d847aeaf43aedb`; the revised read-only verifier was
recorded in [PR #318](https://github.com/stampbot/extra-codeowners/pull/318).
The deployed App did not evaluate the candidate.

The PR changed two lines of an owned file across two commits. The target
changed another line in the same file and added a separate file. Stampbot
approved the PR head. A fixture check on that head let the PR enter the queue.

## What we observed

- GitHub combined the independent edits. The target-only file did not appear
  in the candidate's changes relative to the target.
- The diff from the PR's merge base to its head and the diff from the target
  to the candidate touched the same owned path. The probe checked that the PR
  file list covered that path. The evaluator read policy at the candidate's
  base and passed.
- In a local control, changing the recorded approval to the first PR commit
  made evaluation fail. The control did not change the actual review.
- GitHub reused the queue ref after dequeue and requeue. The verifier rejected
  the first delivery when it checked the ref against the replacement.
- The replacement passed with the live review. Dismissing that review made
  the local result fail while GitHub still showed the same candidate waiting.
  The probe did not publish a candidate result and the PR did not merge.

The default branch and both branch tips were unchanged. The operator closed the
PR, emptied the queue, and revoked the probe tokens.

## Separate control: a check on a superseded candidate

From 17:19 to 17:22 UTC, the operator queued another fixture PR, then dequeued
and requeued it. GitHub reused the queue ref with a different commit. The
required App posted a passing check on the old candidate only.

The new candidate had no required check and waited throughout the 45-second
observation. The operator closed the PR without merging and removed the
temporary branches. GitHub did not apply the old candidate's result to the new
commit during that observation.

## What this doesn't prove

The first probe read live evidence and evaluated it locally. The second posted
a manual control check. Neither tested publication by the deployed worker,
recovery from a missed event, or revocation after the worker publishes success.
The tests do not cover groups with multiple PRs or make review withdrawal
atomic with merge.

The earlier verifier used full-tree equality and one commit as fixture
shortcuts. This follow-up tested a different way to prove path coverage for one
verified candidate. [Issue #4][queue-work] tracks the remaining queue work.

[queue-work]: https://github.com/stampbot/extra-codeowners/issues/4
