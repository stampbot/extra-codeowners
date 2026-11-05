# Design: Keep long reconciliation traces complete and bounded

> A full reconciliation can outgrow one trace. Compare ways to keep its
> completion record and useful phase attribution without changing approval
> behavior or shared backend limits. The selected layout keeps a small summary
> and links one independent trace per logical GitHub request.

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-02 |
| Status | Decided |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Related | [Issue #259](https://github.com/stampbot/extra-codeowners/issues/259), [performance gate #203](https://github.com/stampbot/extra-codeowners/issues/203), [November evidence](../../maintainers/evidence/2026-11-02-reconciliation-and-alpha67.md#trace-completeness) |
| Decision | [Linked reconciliation traces](../adrs/2026-11-05-linked-reconciliation-traces.md) |

## Problem

The current reconciler opens one root span for a whole scan and nests its
GitHub operations beneath it. The measured 38-minute successful scan retained
6,228 child spans but no root on two later fetches. Completion logs and metrics
confirmed the scan succeeded; the fetched trace could not explain the complete
run.

The initial backend observation had a five-million-byte trace limit and
size-related discard metrics, but no trace-specific loss record. The
[November 5 investigation](../../maintainers/evidence/2026-11-05-trace-size-investigation.md)
later tied size rejection and compaction discards to a newly measured scan's
exact trace. A successful fetch well after completion still lacked the root.

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

Record completion and aggregate phases in a small scan trace. Put each
logical GitHub operation in its own linked root, including nested token
operations. This avoids chunk rollover and the unbounded size of a repository
with many pages. Each request keeps its existing retry bound.

This retains request-level explanation without one growing trace. Linked
roots follow the locally created scan's sampling decision. A searchable
opaque scan trace ID supports navigation without repository-valued metric
labels. Private text has a fixed per-field cap and a visible clipping count.

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
| Summary plus bounded linked detail | Yes, one fixed-shape root per logical request | Every sampled request retained | More trace records and about 17% more encoded bytes |
| Bounded aggregate | Yes, if aggregate keys are fixed | Mostly omitted | Whether aggregates are sufficient for diagnosis |

## Recommendation

Use a small summary and one linked trace per request. The 10,000-request
comparison exceeded five million bytes as one trace; the linked version
retained every request with no individual trace above 1,185 bytes. Selecting
only its 600-byte summary was smaller, but lost all individual request detail.
The linked layout is the simplest tested option that retains that detail.

The live backend accepts the correlation-attribute query. Actual full-scan
retention and navigation still need deployment evidence; passing the offline
comparison is not proof that an exporter or receiver can never drop data.

## Questions and findings

- **Where was data lost?** Trace-specific backend warnings confirm size
  rejection and later compaction discards. They do not exclude additional
  exporter loss; telemetry completeness still needs cross-checking.
- **What bounds a unit?** One fixed-shape root per logical request, bounded
  private text and no retained request list on the summary. Tests include
  10,000 requests and very long multi-byte private text.
- **How do operators navigate?** Each request links to the summary and carries
  its opaque trace ID as an attribute. The live backend accepts that search;
  counting an actual scan's returned details remains a rollout check.
- **What about failure or shutdown?** Tests cover error outcomes, propagated
  cancellation and context cleanup. Abrupt process loss or export failure can
  still prevent a final summary from arriving.

The live checks remain in issue #259. They validate the rollout rather than
selecting a different approval or queue policy.

## Outcome

Selected the summary-plus-linked-request layout, recorded in the
[November 5 decision](../adrs/2026-11-05-linked-reconciliation-traces.md).
The architecture, operations guide and HTTP/trace reference change with the
implementation; the investigation and live checklist remain in issue #259.

- 2026-11-02: Opened the comparison after a successful scan's root was missing.
- 2026-11-05: Confirmed backend size rejection for a new measured trace;
  compared growing, linked and summary-only encodings and selected linked
  request roots. No shared receiver limits changed.
