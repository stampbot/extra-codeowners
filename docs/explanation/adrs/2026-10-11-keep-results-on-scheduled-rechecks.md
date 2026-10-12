# ADR: Keep the published result on a scheduled recheck

## Record

| Field | Value |
| --- | --- |
| Date | 2026-10-11 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Danny Sauer |
| Scope | How the reconciler's timer-driven rechecks of an unchanged head write the check. It doesn't change how webhooks, authority changes, or missed head changes revoke a result. |
| Related | [Store webhook work before acknowledging it](2026-07-13-store-webhook-work-first.md), [architecture: reconciler](../architecture.md#reconciler), [threat model](../threat-model.md#invariants) |
| Implementation | Fixes [issue #243](https://github.com/stampbot/extra-codeowners/issues/243) |
| Revisit when | GitHub offers a way to update a Check Run without sending webhooks, or a scheduled recheck needs to write something other than its result. |

## Business driver

The reconciler re-evaluates every open pull request once its recheck interval
passes, so it can repair a review, label, or policy event whose webhook never
arrived. Each recheck used the same path as a real trigger: it reset the check
to failure, evaluated, and published the result again. A quiet, approved pull
request showed a red check about every 30 minutes, as
[issue #243](https://github.com/stampbot/extra-codeowners/issues/243)
recorded. Every reset notified watchers, could block a merge while the check
was required, and woke automation subscribed to check events, which then
reacted to a failure that meant nothing.

## Constraints

- A trigger that might change the result, or that we can't vouch for, must
  still block the check before evaluation. That covers webhooks, authority
  fan-out, a head change the reconciler found, and a completion it can't
  confirm.
- A stale success must not stay visible much longer than it already could
  between rechecks, including while GitHub is failing requests or rate
  limiting.
- The shared-head and generation fences that order check writes stay
  authoritative.

## Decision

**Y statement:** We will keep the published result while a timer-only recheck
evaluates, and write the check only if the new result differs, because a
recheck that carries no new evidence shouldn't change what the check says, so
quiet pull requests stop flapping and stop sending check webhooks.

The decision has these boundaries:

- Only a recheck of a head whose last evaluation completed and was confirmed
  qualifies. It binds to the head's current shared-head generation instead of
  advancing it.
- A trigger that lands on the queued row replaces it and blocks first as
  usual.
- A scheduled recheck keeps the result only while it can replace it promptly
  ([XCO-016](../threat-model.md#invariants)). A failed attempt or a lost
  worker blocks the check before the retry. So does a rate-limit or budget
  deferral that would land more than one recheck interval after the recheck
  was queued. A deferral for pending authority fan-out or a pending exact-head
  invalidation doesn't, because a reset is already on its way.
- The skip compares the existing check's status, conclusion, external ID,
  title, summary, text, and details URL. Any difference writes the new result.

## Consequences

- A review dismissal, label removal, or policy change whose webhook was missed
  now flips the check straight from the old result to the new one. The old
  result stays visible for the evaluation's duration on top of the recheck
  interval it was already visible for.
- A missed reopen or base-branch retarget on an unchanged head looks like
  "only time passed" to the reconciler, so it has the same window as a missed
  review dismissal.
- GitHub's check-run responses don't include actions. An identical older check
  written without the **Re-evaluate** action keeps that gap until its result
  changes.
- An error reading the existing check before the final write still resets the
  check, because the worker can't tell what GitHub shows.

## Alternatives considered

### Keep the current approach

Resetting before every evaluation is uniform and never shows an old result
while the worker reads new evidence. On a quiet pull request it produces a
failure and a recovery every recheck interval, which is the noise this record
removes.

### Show the check as in progress instead of failed

Issue #243 suggested reporting an in-progress status during the recheck. The
client can't do that on an existing check: GitHub can keep a completed
conclusion when a PATCH asks only for an in-progress status, so the client
writes an explicit `failure` to make the block reliable. An in-progress state
would still change the check and send webhooks every interval.

### Lengthen the recheck interval

A longer `EXTRA_CODEOWNERS_RECONCILE_RECHECK_SECONDS` makes the flap rarer
without removing it, and it lengthens the window in which the reconciler can
repair a missed webhook.
