# Alpha.82 cadence and scan cost: November 11, 2026

Alpha.82 is deployed and the approval probe passed. Later attempts reported
one skipped installation, and their next-wake hints matched the observed
start times. Two reconciliation cohorts completed, but request cost remains
high. Faster retries alone have not solved recovery latency.

The observations below are from November 11, 2026 UTC. Private repository,
trace, pod and node identities remain in maintainer captures. A cohort means
the installations tracked for one reconciliation cycle; it can take several
attempts to finish. The trace duration and request count describe one attempt,
not necessarily the whole cohort.

## Release and deployment

[PR #289][cadence] added advisory per-installation deadlines. Durable leases,
API budgets and cursors remain authoritative. Each elected attempt still
authenticates and validates the complete installation list before selecting
due work. Losing the election discards the process-local deadlines.

[Alpha.82][release], source
`df46713b0bcd6c8a47bdb93f4860508cec0a9ab0`, passed independent verification
of all 38 immutable release assets, totaling 776,462,075 bytes. Sizes and
SHA-256 values matched. Signatures, workflow provenance, notices, source
bundles and VEX bindings verified. Registry image children matched the
published native digests, and the chart matched the release package bytes.

The image index is
`sha256:5e9dbaa68d67d28d91a2a00312c9c5af3a64a0a13bd41df299807b3b41df3422`.

The app-only [Argo deployment PR][deployment] changed the chart version and
image digest. CI and both reviews passed before its authorized admin merge
at 03:58:40. Ordinary GitOps reconciliation deployed it; no forced refresh,
sync, shared credential change or direct cluster mutation was used.

Independent checks at 04:04:36 found two Ready replicas on distinct ARM
nodes, zero restarts, the expected source revision and PostgreSQL/App identity,
and a healthy disruption budget with minimum availability 1. These are
point-in-time observations, not proof of uninterrupted availability.

Local broad testing recorded 2,696 passes, one skip and 34 failures in the
provenance shell harness. That harness resolved the host's asdf Python shim;
all 39 provenance tests passed with the test environment first on `PATH`.
The original broad run was not a zero-failure result. The hosted full Python
matrix, both architecture builds and the remaining required CI passed.

A later broad local run against source
`8bf2cdef2b48c0bfb115baf6930b87c823fe11d7`, with the corrected `PATH`, passed
2,685 tests with 53 skips and 48 deselections. It excluded integration-marked
tests and reached 88.61% coverage. That is a separate test scope, not a rerun
of every PostgreSQL integration case.

## Approval probe

Between 04:06:03 and 04:06:28, the retained delegated-path fixture lost its
required label and received a fresh final failure. Restoring the label
produced a fresh success. API-observed intervals were 12.59 and 12.52 seconds,
using three-second polling. They include observation delay and are not
latency percentiles.

The original label and head were verified afterward. This probe did not
capture a review-list baseline, so it does not establish unchanged reviews.
No installation selection, queue, quota or deployment setting changed.

## Quiet reconciliation

The operator made no controlled fixture changes between 04:06:28 and the
end of the two cohorts below. That does not mean the installation's other
repositories had no traffic. Both cohorts fall wholly inside the retained
runtime observation window.

| Attempt | Outcome | Seconds | Outer requests | Linked details retained | Installations skipped |
| --- | --- | ---: | ---: | ---: | ---: |
| 04:13:00–04:42:14 | Cohort complete | 1,753.91 | 6,434 | 6,434 of 6,434 | 0 |
| 04:47:11–04:52:05 | Partial, budget deferred | 293.48 | 976 | 976 of 976 | 1 |
| 04:52:06–04:52:09 | Partial | 3.10 | 7 | 7 of 7 | 1 |
| 04:53:05–05:21:41 | Cohort complete | 1,716.72 | 6,428 | 6,429 of 6,429 | 1 |

The second cohort spans the last three rows: 7,411 outer requests over
roughly 34.5 minutes, including the intervening waits. Its final successful
attempt alone is not the cohort's total cost. The extra detail in that
attempt is not an extra outer request. No row reports a failed installation,
lost lease or stop signal.

The deferred attempt reported a one-second next-wake hint. The next attempt
began about one second later and reported one skipped installation. That
small attempt returned a 56-second hint; the following attempt began about
56 seconds later. A next-wake hint is the earliest due scope, not necessarily
the deferred installation's own deadline. The skip count alone doesn't
identify which scope was due. These observations exercise the new cadence,
not a full scan completed in three seconds.

The first completed cohort queued 78 PRs. The second queued 11 in its final
attempt. Those are enqueue counts, not proof that every evaluation completed
within the scan or that every repository was visited afresh in each attempt.

## Request cost

The first attempt's complete selected-attribute capture contains:

| GitHub operation | Requests |
| --- | ---: |
| List checks | 2,657 |
| List open PRs | 1,795 |
| Resolve repository ref | 981 |
| Read policy content | 981 |
| List installation repositories | 19 |
| List App installations | 1 |

Only three requests returned 304. Policy reads included 973 expected 404s
and eight 200s; a missing policy is not by itself an evaluation error.
HTTP phase totals were about 1,609 seconds, admission 45.53 seconds,
accounting 58.07 seconds and permit wait 0.012 seconds. These sums are not
wall-clock percentages or a count of charged API quota.

The second successful attempt's complete capture adds an important limit to
the cache strategy. Of its conditional requests, 920 returned 304 before a
token request at 04:58:11; one returned 200. After that token request, all
4,522 conditional requests returned 200. No token or raw ETag was collected.
This is temporal correlation, not a comparison proving every body unchanged.
It is consistent with the [upstream-confirmed behavior][token-etags] that
installation-token changes also change ETags. Retaining validators longer
doesn't make them valid across those token changes.

A separate 71-sample window bracketed both cohorts, from 04:11:56 through
05:22:01. The larger cache instance held at most about 5.68 MiB of pages
and 1.31 MiB of compact entries, below its 24 MiB and 8 MiB limits. No
eviction or expiry counter appeared. There were 49 page-size rejections
across both pods. These are whole-pod observations, not traffic attributed
exclusively to the scans. They don't support increasing cache capacity as
the first fix for this run.

Source inspection identified another candidate for repeat work: each resumed
attempt rotates the repository list after its saved cursor and then includes
the earlier prefix again. A deferred cohort can therefore revisit repositories
already processed before it finishes. The 7,411-request cohort is consistent
with extra work, but this capture does not attribute every additional request
to that code path or compare identical repository populations.

A separate deterministic reproduction used a fresh migrated SQLite database
and fake GitHub methods, with no live API or database access. Its three
fictional repositories were A, B and C. The first attempt completed A, then
deferred at B with A saved as the repository cursor. The continuation visited
B, C, then A again before completing the cohort. Both attempts freshly listed
the installation and its repositories. This confirms prefix replay in that
case; it does not establish the proportion of live cost caused by replay.

[Issue #203][performance] retains that investigation and the separate live
checkpoint proof. A follow-up must distinguish continuation of an active
sweep from a new scan without missing new or renamed repositories, weakening
membership validation, or starving direct events. Serial installation work
can also delay another installation that becomes due during a long attempt.
No recovery deadline, acceptable-latency guarantee or request-cost improvement
is inferred here. The [production warning][status] remains in place.

[cadence]: https://github.com/stampbot/extra-codeowners/pull/289
[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.82
[deployment]: https://github.com/neverendingsupport/argo-apps/pull/2655
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[status]: ../../reference/project-status.md
[token-etags]: https://github.com/github/docs/issues/34689#issuecomment-2383522447
