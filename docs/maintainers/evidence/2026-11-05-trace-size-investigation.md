# Reconciliation trace-size investigation: November 5, 2026

The backend rejected data for a successful scan's exact trace after it crossed
the five-million-byte limit. A bounded linked layout retains every request in
the offline comparison. Live validation of that replacement is separate; this
receipt does not declare the performance gate complete.

## Live scope and method

The read-only investigation ran on November 5, 2026 UTC against alpha.67,
source `02f064ea82a23bf6b791d87ccc0145a08eabb759`, with two ready replicas on
separate nodes and shared PostgreSQL state. No deployment, backend setting,
installation selection or queue/budget override was changed for this capture.

The scan's completion log at 04:27:42 reported success and 78 queued PRs. The
elected replica's last-success gauge agreed. A trace fetch at 04:56:36 returned
6,228 spans but no `reconciliation.run` root. Converting its retained resource
batches back to OTLP protobuf measured 4,642,252 bytes. That is the retained
subset, not the amount the service tried to export or the backend's internal
size accounting.

A bounded Loki query for this exact trace found:

- `TRACE_TOO_LARGE` warnings at 04:27:21, 04:27:31, 04:27:41 and 04:27:51,
  with `max=5000000` and reported totals above the limit.
- Compaction warnings for the same trace at 04:29:19, 04:39:19 and 04:39:50,
  reporting discarded spans. Those counts overlap processing stages and
  must not be added as a unique-loss total.
- A successful HTTP 200 trace query at 04:56:36, well after completion and
  those discards.

This ties size rejection to the measured trace, not just a fleet-wide discard
counter. It rules out query timeout or merely waiting a few more seconds as
the explanation for that fetch. It does not prove that no additional exporter
loss occurred. Raw logs, trace IDs and infrastructure identities remain in the
maintainer's private evidence records.

## Offline layout comparison

The prototype used the locked OpenTelemetry SDK, an in-memory exporter,
fictional fixed operational attributes and 10,000 logical request spans at
sample ratio `1`. It encoded the result as OTLP protobuf without sending it
to a receiver. The source is the implementation accompanying
`tests/test_reconciliation_tracing.py`, based on main revision
`4aa5f4d6069bab4ef711e2b4b80d7c0365a2a953`.

| Layout | Spans | Traces | Combined OTLP bytes | Largest trace |
| --- | --- | --- | --- | --- |
| One growing trace | 10,001 | 1 | 7,290,450 | 7,290,450 bytes |
| Summary plus one linked root per request | 10,001 | 10,001 | 8,540,604 | 1,185 bytes |
| Summary only | 1 | 1 | 600 | 600 bytes; all 10,000 request details omitted |

The summary-only measurement selects the linked prototype's summary. It is
not a separate production mode. The linked layout preserves every request,
costing about 17% more encoded bytes overall. Individual trace sizes include
the resource envelope; the combined encoding shares that envelope.

Additional tests cover nested token timing, all-or-none scan sampling,
concurrent scans, errors, cancellation, private-text clipping and unchanged
worker parent relationships. The long-text case uses multi-byte characters
and verifies an individual trace remains below 64 KiB. This is a bound for
the source-owned instrumentation, not arbitrary external instrumentation or
operator-supplied resource attributes.

The live Tempo 2.9 search endpoint accepted the documented span-attribute
correlation query over a five-minute range. It returned no matches for a
fictional ID, as expected before the replacement was deployed. Finding and
counting a real scan's linked detail remains a rollout check.

## Cleanup and limits

The experiment creates no GitHub fixtures or backend resources. The local
exporter keeps its spans only for the test process; private captures remain
access-controlled. No shared cache or cluster resource was removed.

These results support the [linked-trace decision](../../explanation/adrs/2026-11-05-linked-reconciliation-traces.md).
They do not establish live full-scan completeness, a latency percentile, two
quiet successful cycles or missed-webhook recovery. Those gates remain in
[issue #259](https://github.com/stampbot/extra-codeowners/issues/259) and
[issue #203](https://github.com/stampbot/extra-codeowners/issues/203).
