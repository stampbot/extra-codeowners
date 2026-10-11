# ADR: Store webhook work before acknowledging it

## Record

| Field | Value |
| --- | --- |
| Date | 2026-07-13 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Danny Sauer |
| Scope | How the service accepts GitHub webhooks and where it keeps work, generations, and audit records. It doesn't cover the policy evaluator's rules. |
| Related | [Architecture](../architecture.md), [explicit database migrations](2026-07-15-explicit-schema-migrations.md) |
| Implementation | [Bootstrap commit `2d18a53`](https://github.com/stampbot/extra-codeowners/commit/2d18a539bc23efd2c6633c2a33808592cb40683d) |
| Revisit when | A second state-store backend is designed, as proposed in [issue #124](https://github.com/stampbot/extra-codeowners/issues/124). |

## Business driver

GitHub gives a webhook delivery about ten seconds and
[doesn't redeliver a failed one automatically](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries).
A review dismissal or a new push that the service drops can leave an old
success in place, and that success lets a pull request merge.

## Constraints

- A delivery the service acknowledges must eventually be processed, even if
  the process dies right after responding.
- Several service instances must share deduplication, leases, retry state,
  and generation counters so that an older worker can't overwrite newer
  evidence.
- The response must stay inside GitHub's delivery deadline.

## Decision

**Y statement:** We will record each relevant delivery, its pull-request work,
and its exact-head revocation in one PostgreSQL transaction before returning
`202`, because GitHub won't resend a delivery we lose, so an acknowledged event
always has durable work behind it.

The decision has these boundaries:

- Ingress verifies the HMAC signature over the raw body before it parses
  anything that can affect authorization.
- After the transaction commits, a bounded fast path may try to reset the check
  to a blocking result. It's best effort; the durable worker stays
  authoritative.
- Production requires PostgreSQL through the `postgresql+psycopg` driver.
  SQLite is for local development only.
- When ingress can't take the authority publication guard in time, it returns
  `503` without accepting the event, so the operator knows to redeliver it.

## Consequences

- Operators run PostgreSQL, back it up, and treat it as private repository
  metadata, because audit rows name repositories, paths, and owners.
- Every schema change becomes a release concern; see the
  [migration decision](2026-07-15-explicit-schema-migrations.md).
- A database outage blocks new acceptance. The check fails closed instead of
  succeeding on partial evidence.

## Alternatives considered

### Evaluate inside the webhook request

Process the event synchronously and respond when the check is published. That
needs no queue, but GitHub API calls can't reliably finish inside the delivery
deadline, and a crash mid-request would lose the event with nothing to retry.

### Keep work in process memory

An in-memory queue is simple and fast. It loses work on every restart or
rollout, and separate replicas can't share generation counters, so a stale
worker could publish over newer evidence.
