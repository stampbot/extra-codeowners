# Checkpoint continuation and alpha.92 performance

Alpha.92 resumed a saved authority checkpoint after its stored accounting
deadline and completed all 140 expected review denials. A direct label probe
also passed while background work was pending. Two quiet reconciliation cohorts
have complete request, log, and counter accounting. These observations complete
the performance and checkpoint validation tracked in [issue #203][issue-203].

These results do not establish production readiness. The
[project status](../../reference/project-status.md) retains the separate
provider/lifecycle and distribution-review gates.

## Environment and changes

The observations below span November 12–13, 2026 UTC.

The tested release was
[v0.1.0-alpha.92](https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.92),
runtime version `0.1.0a92`, source
[`09f80e3d3448c74a60c2516f3688179f8a6d0fc2`](https://github.com/stampbot/extra-codeowners/commit/09f80e3d3448c74a60c2516f3688179f8a6d0fc2).
Independent verification passed for the 42-asset immutable release, including
the artifact signatures and attestations. Both native image children and the
registry chart bytes matched the verified release. This is not approval of
complete corresponding-source coverage.

The service ran with shared PostgreSQL and two Ready replicas on distinct
ARM64 nodes. Retained runtime and metric samples matched the verified image
and pod identities, with zero restarts. Readiness observations are sampled,
not a continuous availability guarantee.

The release includes bounded concurrent discovery and durable continuations
from [#298](https://github.com/stampbot/extra-codeowners/pull/298), cooperative
reconciler lease cleanup from
[#299](https://github.com/stampbot/extra-codeowners/pull/299), and repository
scoping for unambiguous `team.added_to_repository` events from
[#301](https://github.com/stampbot/extra-codeowners/pull/301). Shared policy
repositories, uncertain context, and other team or membership actions still
invalidate the whole installation. The separate
[base-refresh receipt](2026-11-12-base-refresh-stability.md) covers unchanged
base updates and policy withdrawal.

No quota, queue, database state, installation selection, or shared deployment
setting was edited to obtain a result. Fixture mutations were limited to
existing disposable PRs, a comment-only policy change, and the retained label
probe. No new repository was created.

## Quiet reconciliation

A cohort starts after the previous cycle completes and includes every elected
attempt through the next completion. Operator quiet means no controlled
fixture writes; it doesn't mean other installed repositories were inactive.

The first operator-quiet cohort ran on November 12 from 21:13:25.212522 to
21:36:52.605137 UTC. It took **1,407.39 seconds** across five elected attempts:
four partials followed by success. Their active durations totaled 1,110.39
seconds; the wall time also includes scheduled waits.

Every elected attempt contributes to these totals, not just the final success:

| Attempt | Outcome | Duration, seconds | Outer request roots | Retrieved / expected detail roots |
| --- | --- | ---: | ---: | ---: |
| 1 | Partial | 5.26 | 7 | 7 / 7 |
| 2 | Partial | 323.66 | 1,961 | 1,961 / 1,961 |
| 3 | Partial | 322.23 | 1,900 | 1,902 / 1,902 |
| 4 | Partial | 323.24 | 1,839 | 1,839 / 1,839 |
| 5 | Success, cycle complete | 136.00 | 848 | 848 / 848 |
| Total | Four partials, one success | 1,110.39 | 6,555 | 6,557 / 6,557 |

The two extra details are nested token requests. Canceled reads without an
observed response status remain included; one had HTTP time, so those reads
are not all classified as unsent. These are logical request-root counts, not
physical HTTP-attempt totals or proof of quota charges. Concurrent phase
durations are not wall-clock percentages.

Metric deltas agree with all elected completions in the scrape bracket. That
bracket also contains a neighboring cohort's success, which is listed
separately in the retained proof and excluded from this cohort's costs.
Completion logs also matched every elected attempt between the previous
cycle's success and this one, including the first attempt. This checks for a
missing prefix before the first retrieved trace.

The first attempt visited a healthy installation before the large installation
was next due. Its wait is included, rather than counting only the busy part.

These observations are not a like-for-like percentage comparison with an older
release.

### Later quiet cohort: November 13

The second complete quiet cohort ran from 00:08:57.295779 to
00:29:17.245570 UTC. It took **1,219.95 seconds**, including scheduled waits,
across three partial attempts and one success. The attempts' active durations
totaled 921.95 seconds.

The same accounting includes every elected attempt:

| Attempt | Outcome | Duration, seconds | Outer request roots | Retrieved / expected detail roots |
| --- | --- | ---: | ---: | ---: |
| 1 | Partial | 3.62 | 7 | 7 / 7 |
| 2 | Partial | 332.14 | 2,156 | 2,156 / 2,156 |
| 3 | Partial | 321.08 | 2,224 | 2,224 / 2,224 |
| 4 | Success, cycle complete | 265.11 | 2,127 | 2,127 / 2,127 |
| Total | Three partials, one success | 921.95 | 6,514 | 6,514 / 6,514 |

All 6,514 expected detail roots were retrieved, including a canceled read with
HTTP time but no response status. Completion logs matched all four attempts.
The counter baseline preceded the previous cycle's completion, so an omitted
first attempt could not be hidden by a later scrape boundary.

Counter deltas include the preceding cycle's success and the next cohort's
first partial. Both are identified separately and excluded from the selected
cohort's request costs. After accounting for them, the counters match the
three partials and one success. Continuations reported 474 and 1,093
active-sweep skips. Neither selected cohort reported a failed installation,
lost lease, or stop signal.

The final rollout check at 00:34:40 UTC was Synced/Healthy with two Ready
replicas, the same pod identities, zero restarts, and a healthy PDB. It does
not turn these individual timings into a recovery-latency guarantee.

### Incomplete candidate excluded

An intervening candidate had a logged budget-deferred completion missing from
Tempo at the subsequent lookup. The shared collector reported permanent failures
at 21:53:52.733 and 21:54:02.733 UTC, dropping batches of 3,644 and 3,786 spans
after Tempo rejected messages above 4 MiB. Distributor logs confirm the size
errors. Those mixed batches do not identify every affected trace, so their
timing alone does not prove which batch contained a particular missing span.

App export counters reported success. That records the immediate export
result, not retention through the whole telemetry pipeline. The finding was
recorded in the infrastructure investigation; no collector or Tempo setting
was changed. That candidate is incomplete cost evidence and is not counted
as a passing quiet cohort.

The query investigation found a separate retrieval error: Tempo 2.9 strips
leading zeroes from trace IDs in link-scope searches. The app's full 32-digit
string attribute was correct. All seven affected detail traces were retrieved
after using the backend's link-ID format, and their raw links matched the
summary. The [operator queries](../../how-to/operate.md#follow-a-reconciliation-scan)
and [trace reference](../../reference/http-api.md#reconciliation-trace-fields)
now distinguish ID formatting, query limits, and actual export/drop evidence.

## Checkpoint across an accounting deadline

The paced trial reused 140 existing PRs with distinct heads. Each first had a
fresh missing-review denial. The controller recorded its windows, source
bindings, and the ten PR numbers to track before any fixture writes. It allowed
only bounded same-head periodic work during preparation; that did not relax
the selected-prefix proof.

The following observations are from November 12, 2026 UTC:

| Observation | Time | Evidence |
| --- | --- | --- |
| Policy change requested | 22:32:26.646633 | Comment-only change; parsed policy unchanged |
| Prefix selected | 22:33:48.443108 | Cursor 40; predeclared PRs 1–10 had settled invalidations and saved job identities |
| Stored accounting deadline | 23:08:33 | Background work had paused at the recovery reserve |
| First qualifying provider request began | 23:08:38.298546 | Later accepted installation response, with valid core-quota headers |
| Retained post-deadline checkpoint | 23:08:40.822163 | Same authority generation and all ten selected job identities |
| Page 2 observed | By 23:10:59.310577 | Cursor 100, with the same authority job |
| Final evaluations complete | 23:16:46.984718 | All 140 fresh denials; no fixture authority or evaluation jobs left |

The strict proof passed. Cursor progress was monotonic, and the ten selected
jobs and their settled head generations remained unchanged while the authority
job existed. This proves the predeclared sub-prefix, not identity preservation
for every pending job.

A separate trace check found **595 qualifying accepted installation responses**
after the deadline, tied to the matching authority trace, release, and pod
identities. They had HTTP 200 or 304, valid core-quota headers, and a later
provider deadline. This is evidence across a stored accounting deadline, not
zero-quota exhaustion, a cold restart, or a globally synchronized GitHub reset.

Earlier incomplete or interrupted trials remain separate and unpassed. This
trial does not reclassify their evidence.

## Direct-event response during recovery

The retained probe removed and restored only its existing `bot-ok` label.
Background authority and evaluation work was pending before and after the
probe. Its head and managed Check Run identity stayed unchanged.

Three-second API polling produced these observation bounds:

| Result | From label API request, seconds |
| --- | ---: |
| First blocking result after removal | 4.86 |
| Final missing-review denial | 11.88 |
| Final restored success | 11.82 |

The corresponding worker traces took 4.70 and 5.76 seconds and matched
alpha.92's verified pod identities. Final observations followed the
`webhook_accepted` logs by 6.91 and 7.00 seconds. The first blocking API
observation preceded that log by 0.11 seconds: acceptance is logged after the
fast path, not at request receipt or the HTTP 202 instant. No negative ingress
latency is inferred.

These are polling-bounded observations, not a continuous UI measurement,
latency guarantee, or atomic merge-safety proof.

## Cleanup and retained evidence

Cleanup completed at 23:21:33.854857 UTC. All 140 PRs were closed unmerged and
the original policy was restored. A read-only check at 23:22:05.997210 found no
fixture jobs, authority work, or pending head invalidations. Seven sampled
closed checks retained completed failure results, with none skipped. This is
not a continuous observation of closure or proof that no in-flight evaluation
wrote during closure.

The label probe restored its original label and success. Raw traces, metric
samples, API observations, controller records, and proofs remain in the
maintainer's private captures. No private repository, infrastructure identity,
or payload is reproduced here.

[issue-203]: https://github.com/stampbot/extra-codeowners/issues/203
