# ADR: Retry due installations without replaying healthy scans

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-11 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Scope | Reconciliation polling deadlines and cycle accounting. Approval policy, durable admission and worker lanes remain unchanged. |
| Related | [Reconciler](../architecture.md#reconciler), [metric and trace reference](../../reference/http-api.md#get-metrics) |
| Implementation | [Issue #203](https://github.com/stampbot/extra-codeowners/issues/203) |
| Revisit when | Repeated leader churn makes cold revalidation too costly, or deadlines must survive leadership changes for an agreed recovery objective. |

## Business driver

A live budget deferral supplied a 60-second retry delay, but the loop waited
the full 300-second interval after the attempt finished. Shortening that global
interval would also replay healthy installations early. Slow scans can consume
the deferred delay before the loop gets back to waiting.

## Constraints

- Authenticated current GitHub evidence remains necessary (XCO-001 and XCO-014).
- The shared service lease, API budget, provider backpressure and durable
  repository/pull cursors retain their existing authority.
- An early retry cannot count as full reconciliation merely because its due
  subset succeeded. Operational fields keep fixed names and bounded labels
  (XCO-011).
- Periodic scope discovery continues even when every known installation has a
  distant retry deadline. No installation-access or shared quota change is
  needed to make progress.

## Decision

**Y statement:** We will keep per-installation monotonic deadlines and unfinished
cycle membership in the elected process, because recovery already has durable
safety controls, so one installation can resume on time without replaying
healthy scans or adding another persistent coordination mechanism.

Every attempt validates the complete current App installation list. Successful
installation scans wait the configured interval from completion. Deferred scans
use their reported delay; ordinary failures use the configured interval. The
next loop wait is the earlier of a due deadline and the configured interval,
with a one-second floor when a deadline has already passed.

A cycle needs a completed scan for every current active installation. Successful
coverage can accumulate across attempts by the same leader. Additions join that
cycle; validated removals and suspensions leave it. A later failure puts an
installation back in the pending set. Idle attempts do not advance the success
counter or timestamp. Summary request counts and durations still describe one
attempt, not a whole cycle or simultaneous snapshot.

Loss of election, shutdown or an unhandled attempt failure discards this state.
A cold successor revalidates from scratch while retaining shared cursor progress
and quota controls. These hints neither authorize a result nor suppress direct
webhook work. They require no schema migration.

## Consequences

- Known retry delays survive time spent scanning later installations. Healthy
  installations keep their normal cadence during another installation's retry.
- Cold leadership can repeat a healthy scan earlier than the old leader would
  have. Durable quota admission still applies to every physical request.
- A complete cycle can span multiple attempt traces. It is not proof that all
  queued work completed or that missed-event latency is acceptable.
- Live performance and checkpoint-continuation evidence remain separate work.
  Passing scheduler tests does not finish that validation gate.

## Alternatives considered

### Shorten the global interval

This retries every installation, spending more requests on healthy scopes and
ignoring different deferral deadlines. It also restarts the delay after a slow
attempt unless the deadline is tracked separately.

### Persist every deadline and cycle marker

This avoids cold replay, but adds schema, fencing and rollout requirements for
advisory state. The durable lease, budgets and cursors already preserve safety
and progress. Reconsider persistent scheduling if measured leadership churn
makes the extra revalidation material.

### Count a successful due subset as full reconciliation

That would clear the stale-reconciliation signal while another active
installation remained uncovered. Keep a separate cycle completion condition.
