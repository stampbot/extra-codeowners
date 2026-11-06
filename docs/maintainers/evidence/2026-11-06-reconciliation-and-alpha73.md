# Reconciliation and alpha.73: November 6, 2026

Alpha.73 passed independent artifact verification, automatic rollout and a
guarded approval-withdrawal/restoration test. Before rollout, two more
alpha.69 reconciliation attempts completed successfully with all expected
linked traces retained. The isolated recovery tests in [issue #203][performance]
remain open.

All times below are UTC on November 6, 2026. Private infrastructure, fixture,
delivery and trace identities remain in the maintainer's retained captures.

## Reconciliation before rollout

The tested [alpha.69][previous-release] source was
`31820d7e207f18846f1d0260c270e22c78047db7`, running two replicas on distinct
nodes with shared PostgreSQL. Forty retained samples span 19:39:06.969924
through 20:47:17.694276. Pod identities, images and nodes stayed unchanged,
both replicas were Ready with zero restarts, and no counter reset was
observed. The elected replica's success count rose from 12 to 14; the other
replica recorded no elected outcome.

The completed attempts had these results:

| Completion | Seconds | PRs queued | Outer requests | Linked traces retained |
| --- | ---: | ---: | ---: | ---: |
| 19:44:56 | 2,078.93 | 78 | 6,404 | 6,405 / 6,405 |
| 20:45:17 | 2,071.29 | 78 | 6,403 | 6,404 / 6,404 |

Both final summaries report success without deferral or a failed
installation. Completion logs, counters and last-success timestamps agree.
Backend searches completed, and three fetched details from each attempt
had the expected parentless root and scan link. The first capture used five
read-only queries. The second large detail query failed; a new capture
searched twelve smaller time windows and verified the complete unique count
in sixteen read-only queries. A failed query is not evidence of data loss.

Their HTTP phase totals were 1,846.42 and 1,806.59 seconds; permit wait was
about 0.023 seconds each. Phase sums are not wall-clock percentages. These
runs still spend most of their measured request time in HTTP work; they
do not establish acceptable latency for every installation.

A separate attempt ended partial at 20:05:46, queuing 78 PRs with a recovery
deferral and no failed installation, lost lease or stop signal. It remains
partial. Read-only database samples captured actual quota windows advancing
and queued work draining without a manual budget or queue change. That is
not a controlled interrupted multipage experiment.

No controlled fixture change, receiver outage, redelivery, access-selection
change or deployment occurred during the stated observation. Other
repositories could still generate work. The first successful attempt began
before the initial metric sample, so this is not two complete cycles observed
prospectively from their starts. A resumed attempt can reuse durable progress;
success does not prove fresh visits to every repository within that attempt,
or completion of every queued evaluation.

## Alpha.73 verification and rollout

[Alpha.73][release] contains [PR #272][retention], source
`95dfd13f5ce26962c73c8bcf9d78d911178f67c5`. Discovery validators now survive two
idle hours within the existing storage limits. Every reuse still requires
authenticated HTTP revalidation. The [expiry regression receipt][expiry]
records the pre-deployment diagnosis, not a live performance improvement.

All required PR checks and code/security reviews passed, followed by a
successful main/release run. Independent verification matched all 38 asset
hashes, verified signatures and source-bound provenance, and checked the
retained source, notice and OpenVEX evidence. Both native image digests match
the multiarch index and signed inventories. The registry chart tag/digest
and package bytes match the signed release. These technical checks do not
establish the distribution approval tracked by [issue #18][sources].

GitOps changed only the chart version and image digest. Its repository
comparison error recovered without a forced refresh or sync. At 20:58:47,
the application was Synced/Healthy with two Ready ARM64 replicas on distinct
nodes, zero restarts, and the verified image and source. Both reported the
expected App/check/policy identity and PostgreSQL backend. The disruption
budget required one healthy pod and reported two.

## Guarded approval probe

The retained disposable fixture had one eligible current-head App review and
no human review. Removing its existing delegation label produced a blocking
failure and final denial. Restoring the label returned success. The label is
restored and the pull-request head is unchanged. No review, policy, repository
rule, installation selection or quota setting changed.

These intervals have different origins and endpoints:

| Action | Label API start to final `completed_at` | Delivery receipt to invalidation confirmation | Delivery receipt to worker completion log |
| --- | ---: | ---: | ---: |
| Remove label | 9.35 s | 2.77 s | 8.37 s |
| Restore label | 11.01 s | 2.57 s | 9.01 s |

Delivery receipt and invalidation confirmation come from durable records.
Worker logs correlate each completed evaluation with that delivery. The
first API-observed explicit failure arrived 4.93 seconds after the removal
request, or 2.51 seconds after durable receipt. These are individual
observations, not latency percentiles.

The App supplies `completed_at` before sending its Check Run write; GitHub
returned it at whole-second precision in this probe. It is not an independent measurement
of when GitHub displayed or enforced that result. Poll observations and
confirmed write/completion records provide different bounds. This test did
not attempt a merge or prove the shared-head contract in [issue #1][provider].

Both evaluation traces were retrieved on alpha.73. They lasted 5.89 and
6.73 seconds, with 17 and 18 outer operations, no recorded request errors or
retries, and negligible permit waiting. The queue-age histogram reported
about 6.02 and 6.87 seconds: a queue handoff had reset its origin. Those
values are not the original delivery-to-completion intervals above.

## Remaining validation

No fresh isolated missed-webhook experiment or controlled live multipage
checkpoint across a quota reset was performed. The normal label test does
not prove either one. Nor do these pre-rollout alpha.69 scans measure the
warm full-scan performance of alpha.73. [Issue #203][performance] remains open.

[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[previous-release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.69
[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.73
[retention]: https://github.com/stampbot/extra-codeowners/pull/272
[expiry]: 2026-11-06-discovery-retention.md
[sources]: https://github.com/stampbot/extra-codeowners/issues/18
[provider]: https://github.com/stampbot/extra-codeowners/issues/1
