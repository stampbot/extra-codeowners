# Discovery validator expiry: November 6, 2026

Two more alpha.69 scans completed successfully, but each still took about
33–34 minutes. A controlled regression also found avoidable quota use when
a scan revisits discovery entries after one idle hour. This receipt records
the observations before deploying the retention change. It does not complete
[issue #203][performance].

## Live observations

The deployed release was [v0.1.0-alpha.69][release], source
`31820d7e207f18846f1d0260c270e22c78047db7`. Read-only checks at
19:39 UTC found two Ready replicas on distinct nodes, shared PostgreSQL,
zero restarts and the same pod identities retained in the November 5 receipt.
Argo reported Synced/Healthy. No installation selection, quota, queue or
deployment setting was changed for this observation.

A bounded three-hour log query found these outcomes. Times are UTC on
November 6, 2026. Partial attempts remain partial, even when a later attempt
finishes their durable work.

| Completion | Outcome | PRs queued | Observation |
| --- | --- | ---: | --- |
| 16:45:16 | Success | 77 | Completion log retained; detailed verification below covers the later successes. |
| 17:04:45 | Partial | 66 | Recovery-budget deferral, no failed installation or lost lease. |
| 17:43:30 | Success | 77 | Summary and all 6,400 linked request traces retained. |
| 18:04:47 | Partial | 77 | Recovery-budget deferral, no failed installation or lost lease. |
| 18:42:51 | Success | 77 | Summary and all 6,401 linked request traces retained. |
| 19:05:17 | Partial | 66 | Recovery-budget deferral, no failed installation or lost lease. |

The two detailed successes lasted 2,025.85 and 1,983.17 seconds. Their
summaries report no deferral or failed installation, with 6,399 and 6,400
outer requests. Both backend searches completed and returned the expected
number of unique linked traces. Three details from each had the expected
parentless root and scan link. Each capture used five read-only queries.

Their HTTP phase totals were 1,754.13 and 1,750.06 seconds; permit wait was
about 0.023 seconds each. Phase sums are not wall-clock percentages. This
supports investigating repeated HTTP work rather than assuming permit
contention. It does not establish a latency percentile or service objective.

The elected process had recorded 15,390 compact-cache expirations and 8,463
page-cache expirations by the 19:39 snapshot, with no reported byte or entry
eviction. These are cumulative process counters, not per-scan attribution.
They motivated a controlled expiry test; they do not prove expiry caused
each partial outcome.

This is a retrospective review of an unchanged pod epoch, not a prospective
observation proving that every installed repository was idle. No controlled
fixture change was made during the review. Queued work is not evidence that
every evaluation had completed at the scan's completion timestamp.

## Controlled expiry regression

The regression uses the real HTTP adapter and durable queue with fictional
GitHub responses. It scans 25 unenrolled PRs, advances only the two discovery
caches' monotonic clock, then scans again. API quota time and headers are not
advanced. Every scan must still request the PR listing and all 25 check
listings; the provider's authenticated `304` responses save primary quota,
not physical requests.

With the one-hour idle lifetime, revisits after 3,601 and 7,199 seconds each
cost 29 primary-quota units instead of one. Both assertions failed before
the change. After extending the lifetime to two idle hours, those cases
pass and cost one unit, the uncached absent-policy read. At 7,200 seconds
the entries expire and the scan again costs 29 units. All three cases pass.
The 19 cache unit tests also pass.

The two-hour bound lets a validator survive one hour of quota waiting plus
a long scan. It is a storage choice, not a freshness guarantee. The combined
32 MiB byte cap and entry limits remain unchanged, and every reuse still
needs authenticated HTTP revalidation. Dropping a replica's cache remains
safe. No extra concurrency, quota refund or write retry is introduced.

## Limits and remaining validation

These observations do not prove that the retention change speeds up a live
scan. It does not remove the HTTP round trips, and it has not yet been
deployed in this receipt's window. A successful resumed attempt does not
prove that every repository was freshly visited during that attempt.

The isolated missed-webhook experiment and controlled live multipage
checkpoint across a quota reset remain open in [issue #203][performance].
An ordinary reset observation is not a substitute for an interrupted
multipage fixture. No receiver outage, webhook redelivery or artificial
quota reset was performed here. Raw infrastructure and trace identities
are retained privately.

[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.69
