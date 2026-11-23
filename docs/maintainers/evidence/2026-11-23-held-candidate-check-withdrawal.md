# November 23, 2026: GitHub removed a held candidate after its check failed

GitHub let the expected App change a passing candidate Check Run to failure.
The merge queue removed the candidate even though a separate required check
was still missing. The pull request did not merge.

## Setup

We used a temporary target branch and a synthetic PR in a private GitHub.com
fixture. Its rules required squash merging, one build slot, one PR per merge,
and `ALLGREEN`, with no bypass actors. The rules named the tested App as the
source of one required check. A second required check held the candidate.
We passed both checks on the PR head to let it enter the queue.

We ran a manual probe from the [alpha.111][alpha] image at
`2bc0e98f60286c30e76b7bcc260faeb39eed31f0`. The candidate worker was disabled.
The probe used App tokens restricted to the fixture repository and revoked
each after use. It never passed the independent check on the candidate.

## What GitHub returned

All times below are UTC on November 23:

- At 13:51:51, the probe read back the App's success on the candidate commit.
  GitHub still reported `AWAITING_CHECKS` on the same queue entry.
- At 13:51:52, the probe read back `failure` on the same Check Run ID, commit,
  and App after updating it through the Checks API.
- At 13:52:19, GitHub's pull-request timeline recorded removal from the queue
  with reason `failed_checks`. The target branch had not moved.

We closed the unmerged PR and removed the temporary branches and ruleset.
The default branch and its ruleset were unchanged.

## Limits

This test shows that the App can revoke a passing Check Run while another
check holds the candidate. The time between the update and removal isn't a
revocation guarantee: the separate check kept the merge blocked throughout.
The test didn't dismiss a review, exercise webhook delivery, or verify how
the deployed worker reacts when a review change never arrives.
[Issue #4](https://github.com/stampbot/extra-codeowners/issues/4) tracks those
worker tests.

[alpha]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.111
