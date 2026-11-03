# Design: Keep long reconciliation traces complete and bounded

> A full reconciliation can outgrow one trace. Compare ways to keep its
> completion record and useful phase attribution without changing approval
> behavior or shared backend limits. No replacement layout is selected yet.

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-02 |
| Status | In review |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Related | [Issue #259](https://github.com/stampbot/extra-codeowners/issues/259), [performance gate #203](https://github.com/stampbot/extra-codeowners/issues/203), [November evidence](../../maintainers/evidence/2026-11-02-reconciliation-and-alpha67.md#trace-completeness) |

## Problem

The current reconciler opens one root span for a whole scan and nests its
GitHub operations beneath it. The measured 38-minute successful scan retained
6,228 child spans but no root on two later fetches. Completion logs and metrics
confirmed the scan succeeded; the fetched trace could not explain the complete
run.

The observed backend had a five-million-byte trace limit and size-related
discard metrics. That is a lead, not proof of the missing span's cause. We
must distinguish backend rejection from export loss, query truncation and
delayed availability before choosing a fix.

## Goals and non-goals

Keep a queryable completion/outcome record and useful request-phase timing
for large scans at sample ratio `1`. Bound any detail the application retains
or emits, and make deliberate omission visible rather than presenting a
partial trace as complete.

This work does not change approval policy, queue authority, API budgets or
scan scheduling. It does not raise shared Tempo limits, change other services,
or establish a new latency objective. Issue #203 keeps its separate live gates.

## Requirements in scope

- [XCO-001](../threat-model.md#invariants): incomplete evidence never yields
  success. Incomplete telemetry cannot repair or replace authorization evidence.
- [XCO-011](../threat-model.md#invariants): credentials and raw private payloads
  stay out of diagnostic output. Correlation must preserve the existing
  private-metadata opt-in and fixed metric labels.
- [XCO-014](../architecture.md#design-rules): GitHub remains the source of
  authorization evidence. Instrumentation cannot replace a required read.
- [XCO-016](../threat-model.md#invariants) and
  [XCO-017](../architecture.md#design-rules): tracing must not change when a
  scheduled recheck preserves or blocks a published result.

## Constraints

The [durable-work decision](../adrs/2026-07-13-store-webhook-work-first.md)
keeps accepted work and cross-replica coordination in the database. Trace
relationships are diagnostic only, never a new queue or source of authority.
The [discovery decision](../adrs/2026-11-02-bounded-discovery-optimizations.md)
keeps request deadlines, quota admission and cancellation intact.

Fixed request phases already exist as span attributes and metric histograms;
more child spans are not needed to represent each phase. Existing webhook-to-
worker links show that separate roots can retain a useful causal relationship,
but don't prove a suitable bound for a long scan.

## Options

### Keep one trace for the entire scan

No relationship or query changes are needed. The privacy and authority
boundaries stay intact, but span count still grows with the workload. Sampling
fewer scans reduces total traffic, not the size of an individual sampled scan.
This does not answer the measured completeness problem.

### Keep a small scan summary and link bounded detail traces

Record completion and aggregate phases in a small scan trace. Put request
detail in separately bounded chunks linked to that scan. A repository boundary
may be useful for navigation, but a large repository still needs a size or
span-count bound; splitting by repository alone is insufficient.

This can retain request-level explanation without one growing trace. It needs
tests for chunk rollover, relationship semantics, cancellation and the queries
operators use to find each chunk. Any work identifiers remain subject to
XCO-011; no repository-valued metric label is needed.

### Emit a bounded aggregate instead of every request span

Retain one small completion trace with fixed operation/phase aggregates and
an explicit count of omitted detail. This gives a simpler hard bound and
preserves the same privacy and authority constraints, but loses individual
request relationships unless a separate, bounded detail mechanism is added.
We need to test whether it answers the incidents operators actually investigate.

## Comparison

The difference is diagnostic detail, not approval authority:

| Option | Bounds an individual scan's trace | Per-request explanation | Main unknown |
| --- | --- | --- | --- |
| One growing trace | No | Present only while retained | Which stage lost the measured root? |
| Summary plus bounded linked detail | Yes, if every chunk has an enforced bound | Retained within the chosen detail budget | Chunk policy and usable backend navigation |
| Bounded aggregate | Yes, if aggregate keys are fixed | Mostly omitted | Whether aggregates are sufficient for diagnosis |

## Recommendation

Investigate bounded linked detail first because the existing request phases
already distinguish HTTP work from quota and permit waits. That is a candidate,
not an accepted decision. Compare it with an aggregate-only prototype before
committing to a layout; the evidence doesn't yet establish the simplest option
that preserves useful diagnosis.

## Open questions

- Where did the root disappear? Correlate exporter results, backend discard
  evidence and complete query responses for a controlled large trace.
- What bounds each emitted unit? Measure encoded size and span count at sample
  ratio `1`, including long metadata values and a repository with many pages.
- How do operators reach linked detail? Exercise the actual backend queries
  and document a route from completion to each retained chunk.
- What happens on errors or shutdown? Tests must show a bounded final summary,
  honest omission accounting and unchanged queue/deadline behavior.

Maintainers decide the layout after those checks. Any durable choice gets its
own ADR, and the current architecture, runbook and metric reference change
with the implementation.

## Outcome

Open. No prototype or replacement layout is implemented by this document.
The investigation and implementation checklist remain in issue #259 rather
than being copied here.
