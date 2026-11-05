# ADR: Link bounded request traces to a reconciliation summary

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-05 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Scope | Reconciliation trace layout and sampling. Approval, queue authority, API budgets and worker trace layout are unchanged. |
| Related | [Design comparison](../design/2026-11-02-bounded-reconciliation-traces.md), [size evidence](../../maintainers/evidence/2026-11-05-trace-size-investigation.md) |
| Implementation | [Issue #259](https://github.com/stampbot/extra-codeowners/issues/259) |
| Revisit when | A new instrumentation source can add unbounded spans, events or metadata to a request trace, or the tracing backend cannot search links or the scan correlation attribute. |

## Business driver

A successful large scan outgrew the tracing backend's per-trace limit. The
backend rejected data for that exact trace near completion, and a later fetch
returned thousands of request spans without the scan root. Operators could
confirm completion from logs and metrics, but not inspect a complete trace.

## Constraints

- Diagnostics preserve the private-metadata opt-in and fixed metric labels
  (XCO-011).
- Traces are not authorization evidence (XCO-001 and XCO-014), queue state or
  permission to reuse a published result (XCO-016 and XCO-017).
- Request deadlines, quota accounting, cancellation and scan scheduling stay
  unchanged. Shared backend limits are outside this change's scope.

## Decision

**Y statement:** We will keep one small scan-summary trace and link an
independent trace for each logical GitHub request to it, because a scan can
contain arbitrarily many requests, so operators retain request detail without
putting it all under one trace-size limit.

The summary contains the final outcome, fixed counters and aggregate request
phases. Nested token requests get their own linked roots, but their phases
are excluded from the summary: the outer request already counts that work as
authentication. Phase sums can still overlap across concurrent operations.

Each detail root links to the locally created scan span and carries its opaque
trace ID as a searchable attribute. It follows that scan's sampling decision,
including an unsampled decision; it is not independently ratio-sampled and
does not invent a parent span. External trace headers cannot select this
context. Worker and webhook relationships remain as before.

The application emits no unbounded list of request IDs on the summary and
deliberately omits no sampled request span. Reconciliation paths and private
exception fields are capped at 2,048 characters each, with a clipping count on
the affected span. New instrumentation must preserve these bounds.

## Consequences

- Every source-owned reconciliation trace has a fixed shape, regardless of
  the number of repositories, pages or requests. A request's existing bounded
  retries stay inside its request span.
- Total data still grows with work. The measured linked layout uses about
  17% more OTLP bytes than the growing layout; it also creates more trace
  records. Sampling controls total volume, not the size of a sampled scan.
- Operators search from the summary to linked request roots rather than
  opening one waterfall. The summary's detail count helps detect incomplete
  search or retention; it does not prove delivery to the backend.
- Export failures, receiver outages, retention and backend-wide limits can
  still lose data. Completion logs and metrics remain necessary. A process
  killed before the summary ends cannot export a final outcome.

## Alternatives considered

### Keep one growing trace

The measured backend rejects it near completion. Lower sampling reduces the
number of such traces, not their size. Raising shared limits postpones the
same problem and changes other services' operating conditions.

### Group detail by repository or fixed-size chunks

A repository can itself be large, so it still needs a second bound. Fixed
chunks can reduce trace count, but introduce rollover state and a sampling
policy without improving the request-level diagnosis this service needs.
One logical request is already a bounded unit.

### Keep only an aggregate

A root-only prototype is small, but omits every individual request. It cannot
show which request retried, failed or spent time in quota admission. Keep the
aggregate for navigation and retain request detail in linked roots instead.
