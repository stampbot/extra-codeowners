# November 22, 2026: a behind-base PR in the merge queue

A PR with two commits passed a local policy evaluation on a live queue
candidate even though its branch was behind the target. The candidate's
whole tree differed from the PR head. Its changes relative to the
target were covered by the PR's approval.

## What we tested

The test ran from 17:11 to 17:16 UTC on November 22, 2026. The disposable
repository used the shared App and the same one-entry queue setup as the
[previous probe](2026-11-21-queued-policy-proof.md).
The local probe used the evaluator from source revision
`4a890d04e4b7cef23a379cc695d847aeaf43aedb` and the revised read-only
candidate verifier. The deployed App didn't evaluate the merge group.

The PR changed two lines of an owned file across two commits. The target
advanced independently: it edited another line in the same file and
added a separate file. Stampbot approved the PR head. A fixture check
on that head let the PR enter the queue.

## What we observed

- GitHub combined the non-conflicting edits to the owned file. The
  target-only file was unchanged relative to the candidate's base.
- The PR's merge-base-to-head diff and the candidate's target-to-candidate
  diff both touched only the owned file. The local probe checked that
  GitHub's PR file evidence fed the same paths to the evaluator. The
  evaluator read policy at the candidate's base and passed.
- In a local control, changing only the approval's recorded commit
  to the first PR commit made the evaluator fail. This did not change
  the real review.
- After dequeue and requeue, GitHub reused the ref name. The verifier
  rejected the original delivery when checked against the replacement
  candidate.
- The replacement passed with the live approval. Dismissing that review
  made it fail while GitHub still showed the same candidate waiting.
  No candidate check was written and the PR didn't merge.

The default branch and both branch tips were unchanged after the probe.
The PR closed, the queue emptied, and the probe tokens were revoked.

## What this doesn't prove

This was a read-only evaluation of a candidate, not a worker rollout.
It doesn't prove automatic publication, recovery after a missed event,
or revocation of an already-published success. It doesn't establish
atomic review withdrawal or cover candidates that contain several PRs.

The earlier test's full-tree equality and single-commit restrictions
were shortcuts for that fixture, not requirements for the App. A
candidate still needs a verified link to its PR and complete evidence
for the paths it changes. [Issue #4][queue-work] tracks that work.

[queue-work]: https://github.com/stampbot/extra-codeowners/issues/4
