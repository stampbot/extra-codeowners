# ADR: Keep valid results while reassessing a base update

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-12 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Scope | Repository base-push rechecks of a confirmed PR head. Other authority events, direct PR events and publication fences keep their revoke-first behavior. |
| Supersedes | The timer-only restriction in [the scheduled-recheck decision](2026-10-11-keep-results-on-scheduled-rechecks.md); its retry and failure protections still apply. |
| Implementation | [Issue #296](https://github.com/stampbot/extra-codeowners/issues/296) |
| Revisit when | GitHub offers PR-scoped checks or a stronger way to establish that a base update invalidated an approval. |

## Business driver

An unrelated merge to the target branch turned approved PRs red until their
background evaluations caught up. Their final decisions hadn't changed.
Every reset also sent check webhooks to observers. The timer-only fix didn't
cover this path because base pushes used revoke-first authority fan-out.

## Constraints

- A base update still needs a fresh assessment. It can change the effective
  diff, CODEOWNERS or policy without changing the PR's head. A push payload
  or filename list cannot prove that approval remains valid.
- Only a confirmed completion for the current head qualifies for retention.
  New heads, uncertain work and stronger triggers must still block first.
- Relevant authority discovery must finish before a completed result can be
  published (XCO-009). The shared-head and publication guards stay in place.

## Decision

**Y statement:** We will queue a preserving recheck for a base push affecting
a confirmed PR head, because the push requests a new assessment rather than
proving that approval was withdrawn, so an unchanged assessment leaves the
published check alone.

The repository authority job still lists affected PRs and remains a publication
fence until discovery finishes. A confirmed head gets `base_branch_recheck`
work bound to its current shared-head generation. It does not advance that
generation or reset the check. The worker fetches fresh policy, changed paths,
reviews and ownership evidence, then writes only a changed result or output.

A later base refresh supersedes the queued observation without extending its
original recheck deadline. It preserves stronger queued work, and coalescing
authority jobs cannot turn a label or membership event into a base recheck.
An old, failed or reclaimed recheck becomes revoke-first work instead.

A first attempt can retain its result through a short deferral. Failure,
worker loss or a retry beyond one recheck interval ends that eligibility.
Authority deferrals now use the same limit because base discovery need not
have reset the check. Another base advancement during a preserving evaluation
requests a fresh assessment without publishing the older evidence. A head,
base-ref or label change still takes the blocking path.

## Consequences

An old success can remain visible while a base update is queued, discovered
and assessed. If new ownership or policy makes it invalid, the completed
assessment replaces it with failure. This is an intentional consistency
trade-off, not a promise that every old approval stays valid after a push.

The retry limit controls when an attempted recheck becomes revoke-first work;
it is not a wall-clock recovery guarantee. Queue backlog, provider outages
and lost webhooks still affect convergence. Operators must retain the documented
shadow-mode restriction until the separate production contracts are proven.

There is no schema migration. Older workers treat the new reason as ordinary
work and can still reset checks during a rolling deployment. Rolling back
restores base-push flapping, not a different approval policy.

## Alternatives considered

### Ignore base updates that changed unrelated filenames

This avoids work, but a base update can affect the merge base and applicable
ownership. Fetch current evidence instead of treating a payload as approval.

### Reset before every base assessment

This is conservative, but reports a changed decision before finding one.
It causes the observed false alarms and merge interruptions.

### Retain every published result on every trigger

Review dismissals and other authority changes carry evidence that may revoke
approval. They still block first. This decision applies only to confirmed-head
base refreshes and the existing timer recheck.
