# November 21, 2026: merge-group delivery and candidate identity

GitHub delivered `merge_group.checks_requested` to the shared Extra
CODEOWNERS App for two attempts to queue the same pull request. GitHub
waited for a result on each candidate even though the PR head already
had a passing check from that App. The deployed receiver accepted the
events but didn't schedule work.

## Test conditions

The observation ran from 22:48 to 22:51 UTC on November 21, 2026, in a
private disposable repository. The receiver ran
[alpha.95][release], source `9c373e49c1670d5c557067e22318f4b4bd135ebc`.
Its deployed image digest matched the release.

The playground installation had **Merge queues: read**, **Checks:
write**, and the `merge_group` subscription. The base branch required
the queue and a fixture check from that App, with no bypass actors.
GitHub was configured to build and merge one entry at a time and to
require each entry to pass. We checked that each queue read contained
exactly one entry. The tokens used to inspect the live queue and refs
were read-only and limited to the fixture repository.

## What GitHub showed

- GitHub delivered one `checks_requested` event for each attempt. Each
  included `installation`, `repository`, and `merge_group`. The group
  contained `base_ref`, `base_sha`, `head_ref`, `head_sha`, and
  `head_commit`. It did not include a pull-request object.
- The App's GraphQL read identified the queued PR, its current head,
  and the candidate. The candidate SHA matched the webhook and a
  separate read of the queue ref. In both attempts, the PR head and
  candidate each had the target tip as their only parent and had the
  same Git tree. That verifies content equivalence in this fixture.
- The second attempt kept the base, PR head, and queue ref name. It
  received a different queue-entry ID and candidate SHA.
- Each candidate remained `AWAITING_CHECKS` with no Check Run by the
  required name. We closed the PR both times without writing a result
  on the candidate. GitHub removed the entries and sent `destroyed`
  with the same group fields and a top-level `reason`.

All four deliveries from these two attempts returned HTTP 202 with
`accepted: true` and `queued: false`. The receiver had authenticated the
requests, but it didn't run policy evaluation.

At 22:55 UTC, a third attempt exercised the read-only candidate verifier.
It bound the live delivery to the current entry and the same tree. When
given the second attempt's real delivery against those fresh reads, it
rejected it even though GitHub reused the ref name. Neither use of the
verifier ran policy or wrote a Check Run.

The queue ended empty, the test PR was closed, and the base branch didn't
move. We revoked the probe tokens.

## What this doesn't prove

This was a one-PR test against an unchanged base. It doesn't establish
content equivalence for a moving base or multiple PRs, or guarantee
GitHub never reuses a candidate SHA. It also doesn't show that an
automatic evaluator can check current reviews and publish the right
result, or that review withdrawal is atomic with merging.
[Issue #4][queue-work] tracks those next steps. Keep native code-owner
enforcement on production repositories.

[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.95
[queue-work]: https://github.com/stampbot/extra-codeowners/issues/4
