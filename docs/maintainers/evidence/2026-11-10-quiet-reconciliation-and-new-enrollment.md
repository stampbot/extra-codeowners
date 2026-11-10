# Quiet reconciliation and new enrollment: November 10, 2026

Two reconciliation attempts completed during a stable observation window,
with every expected linked request trace retrieved. A later test recovered
a newly added, valid repository policy after its push webhook failed.
Recovery took about 28 minutes. These observations establish eventual
discovery in the tested cases, not a recovery deadline or atomic revocation.

All times below are UTC on November 10, 2026. The App used two replicas on
distinct Kubernetes nodes and shared PostgreSQL. Raw fixture identities,
delivery records, infrastructure metadata and traces remain in private
maintainer captures.

## Quiet observation on alpha.73

The tested release was [alpha.73][alpha73], source
`95dfd13f5ce26962c73c8bcf9d78d911178f67c5`. No controlled fixture change or
deployment occurred during the observation. The installation's existing
repositories remained accessible; other users' activity was not disabled.

The combined record contains 149 metric samples from 07:13:32.653 through
09:29:59.210. Both pod identities and their image stayed unchanged, with
zero restarts and no counter reset. The largest sampling gap was 75.42 seconds.

Two successful attempts began and ended inside that window:

| Completion | Duration | PRs queued | Linked traces retrieved |
| --- | --- | --- | --- |
| 08:23:59.876 | 2,006.86 seconds | 78 | 6,420 of 6,420 |
| 09:24:14.011 | 1,991.73 seconds | 78 | 6,379 of 6,379 |

Their summary spans and metric outcomes agree. Neither recorded a failed
installation or a budget deferral. The linked details were collected with
bounded, partitioned Tempo queries rather than one oversized trace request.

The same metric window contains another success that began before capture
and two partial outcomes. Those do not become additional wholly observed
successes. Both partials have complete linked-detail captures, but remain
partial scans.

HTTP phase totals were 1,872.67 and 1,859.77 seconds for the two fully
observed successes. Quota admission contributed 44.11 and 43.15 seconds;
quota accounting contributed 49.58 and 49.07 seconds. Request-permit waits
totaled about 0.012 seconds each. These are sums of recorded phases, not
percentages of wall-clock duration. Request volume and HTTP latency remain
more promising investigation targets than permit contention.

A successful attempt can continue from a retained cursor. It does not prove
that every repository received a fresh visit in that attempt, nor that all
queued evaluations finished. These timings do not establish acceptable
latency or a service-level objective.

## Alpha.77 deployment and delivered-event probe

[Alpha.77][alpha77], source
`26142d027853a63dd57a59fda12df431164ba698`, passed independent verification
of all 38 release assets. That included metadata hashes, signatures,
provenance, source bundles, notices and VEX. The registry's platform children
and chart bytes matched the release records. This is artifact verification,
not the distribution approval tracked in [issue #18][sources].

The chart and image update followed the existing GitOps path. Argo reported
a brief repository-comparison error, then recovered during ordinary
reconciliation without a forced sync or refresh. At 09:34:18, the deployment
was Synced and Healthy: two Ready replicas on distinct nodes, zero restarts,
the expected source revision, shared PostgreSQL and the existing disruption
budget. No installation selection, quota or queue setting changed.

On an existing disposable delegated-path PR, removing its required label
produced the final missing-approval failure after an API-observed interval
of 11.85 seconds. Restoring the label produced success after 12.10 seconds.
The head stayed unchanged and the label was restored. Three-second polling
and the API request's timing bound these observations; the App-supplied
completion timestamps are not independent UI or merge-gate measurements.

The two retrieved evaluation traces lasted 6.39 and 4.97 seconds, with 19
and 17 outer GitHub operations. Neither recorded a request error or retry.

## New enrollment after a missed push

A fresh private test repository had one open PR, ordinary human CODEOWNERS,
no repository policy and no managed check. Its initial unenrolled evaluation
had finished. Relevant authority work and evaluation jobs were empty before
the test.

The App's own policy parser validated the intended configuration before the
interruption: schema version 1, enrollment enabled, author ownership disabled
and no App delegations. Adding that policy should require a human review;
the PR deliberately had none.

Using the approved interruption method, the controller briefly changed only
the webhook URL to an unused path on the same HTTPS origin. An independent
watchdog could restore it. GitHub recorded a `404` for the intended push,
with the matching commit and destination. The controller then verified the
original URL, content type and TLS-verification setting. The webhook secret,
deployment and installation access were unchanged.

The recovery record has these distinct endpoints:

| Observation | Time |
| --- | --- |
| Policy write confirmed | 10:36:25.717 |
| Original webhook configuration verified restored | 10:36:29.816 |
| Initial periodic enqueue | 11:04:05.698 |
| Denial worker started | 11:04:11.795 |
| Denial worker completed | 11:04:15.347 |
| Final-denial API query began | 11:04:28.228 |
| Response, final state and unchanged-fixture checks recorded | 11:04:57.040 |

The enqueue identifies `periodic_reconciliation` and recovery work. The
durable audit identifies `scheduled_recheck` with no delivery ID, no
evaluation error and a nonempty human-ownership requirement. The missed
delivery remained unaccepted. Bounded database and log captures found no
accepted fixture, organization-policy or installation-wide event that could
explain this recovery.

There was no redelivery, manual kick, review, label change or PR-head change.
The observer polled about every 20 seconds. Its query-start and post-response
record bound the observation at roughly 28 minutes after policy confirmation;
neither is the exact instant GitHub displayed the result.

The worker trace lasted 3.55 seconds with 13 outer GitHub operations and no
recorded request error or retry. Enqueue to worker completion was 9.65 seconds.
Most delay preceded queue insertion. The configured 300-second reconciliation
interval and 900-second minimum recheck age are not recovery deadlines.

An earlier attempt used a policy fixture that accidentally omitted
`schema_version`. Periodic discovery also recovered that missed push, but its
denial was `invalid_policy`, not missing review. That attempt's captures are
retained with a correction; it is not counted as the valid-policy result above.

## Limits and retained state

The original webhook configuration is restored, and this enrollment test's
watchdog and observer have exited. The disposable PR remains open with the
expected failure at the end of this observation. Test repositories are
retained for the maintainer rather than deleted.

The separate controlled multipage/reset experiment is not established by
this receipt. Neither is missed-review recovery, installation access loss,
shared-head merge safety or a maximum discovery delay. [Issue #203][performance]
still holds the remaining performance and recovery work. Keep the production
warning in [project status][status].

[alpha73]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.73
[alpha77]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.77
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[sources]: https://github.com/stampbot/extra-codeowners/issues/18
[status]: ../../reference/project-status.md
