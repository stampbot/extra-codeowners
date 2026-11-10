# Alpha.79 rollout and budget boundaries: November 10, 2026

Alpha.79 deployed successfully and passed the approval-withdrawal/restoration
probe. All 140 PRs in each completed fan-out test eventually received the
expected missing-review failure. The timed cases did not establish a saved
authority prefix on both sides of a reset deadline. That criterion remains
unproven.

All times below are UTC on November 10, 2026. The
[artifact and component receipt][artifacts] records independent verification
of [alpha.79][release], source
`52ae0f48980a357191dda43718d364559508727a`. Private repository, delivery,
trace, pod and node identities remain in maintainer captures.

## GitOps rollout and approval probe

The [deployment PR][deployment] changed only the chart version and image
digest. It passed CI and both reviews before the authorized admin merge
at 11:53:12. No shared credential, installation selection, database setting
or other application changed.

The first retained Argo comparison at 11:53:38 reported `repository not found`
while resolving source 1 of 3. Existing replicas remained Ready. Ordinary
reconciliation recovered by 11:56:51; Argo was Synced, Healthy and Succeeded
at 11:57:55. No forced refresh, sync or direct cluster mutation was used.
The occurrence is recorded in the existing [Argo follow-up][argo-lookup].

Independent checks at 11:58:03 matched the release's image, source revision
and package version on two Ready replicas on different nodes. Both reported
zero restarts, retained the expected PostgreSQL/App identity and had a
healthy disruption budget with minimum availability 1.

Karpenter evicted one new pod as underutilized at 11:59:04. A replacement
served the same verified release before the approval probe. Another
independent identity and health check at 12:00:45 confirmed two Ready
replicas on distinct nodes. The probe's trace checks used its actual pod
identities, not the earlier rollout snapshot. These are point-in-time health
observations, not a claim that pod identities never changed or that every
instant of availability was measured.

On the retained disposable delegated-path PR, removing the required label
produced the final denial after an API-observed interval of 12.23 seconds.
Restoring it produced success after 12.25 seconds. The label was restored
and the head stayed unchanged. Three-second polling bounds these observations;
the App-supplied completion timestamps are a different timing basis.

The retrieved worker traces lasted 5.56 and 5.53 seconds, with 18 and 17
outer GitHub operations. Neither recorded a request error or retry.

## Multipage fan-out tests

A private fixture held 140 open PRs with distinct heads, human CODEOWNERS,
no reviews and no App delegations. Its valid repository policy disabled
author ownership, so a missing-human-review failure was the expected result.
The App listed 100 records on the first authority page and 40 on the second.

Each test changed only a comment in the base branch's policy after the initial
enrollment. The direct-event variants also added one temporary label to PR 1
after its authority fence was observed. The label had no approval meaning;
it exercised the existing priority for an authority fence blocking a direct
PR event. No quota value, queue row or deployment setting was edited.

The completed cases had these different scopes:

| Case | Observed result |
| --- | --- |
| Alpha.77 calibration | Both pages completed; all 140 valid missing-review denials were observed after 483.67 seconds. |
| Alpha.77 timed recovery-only case | Reserve held the empty checkpoint until the stored deadline passed. All 140 denials followed; this was not a completed-prefix continuation test. |
| Alpha.77 timed direct-event case | The first observed `cursor=100`, `next_page=2` checkpoint was at 11:46:31.185, essentially at the 11:46:31 deadline. All 140 denials were observed after 490.95 seconds. There was no robust pre-deadline checkpoint observation. |
| Alpha.79 timed direct-event case | The stored deadline passed at 12:25:23; the first page checkpoint was observed at 12:25:58.628. All 140 denials were observed at 12:34:00, 663.68 seconds after the policy write was confirmed. No pre-deadline checkpoint was established. |

The durations end when the observer saw every expected audit, not at an
independently measured merge-gate transition. They are not controlled version
comparisons. The observers checked unchanged heads, empty evaluation errors,
nonempty ownership requirements and drained fixture work before recording
completion.

The final alpha.79 case's bounded worker-log capture matched 140 completed
attempts and no failed attempt. The two slowest retrieved attempt traces
lasted 6.67 and 6.50 seconds, with no recorded request errors or retries.
That describes execution after a worker claimed the job, not its total queue
or authority-fence wait.

The planned proof required a nonempty saved authority prefix at least five
seconds before the stored deadline and after a fresh provider observation
beyond it. None of the timed cases met that criterion. Pending evaluation
jobs are durable work, but they are not a saved authority cursor; substituting
one for the other would overstate the result.

These tests establish completed multipage fan-out in the observed conditions.
They do not establish cold-worker checkpoint recovery, actual zero-quota
recovery or a maximum discovery delay. Local controlled-clock regressions
cover additional continuation cases, but are not substituted for this missing
live proof.

## Quota evidence and one partial reconciliation

The authority traces contain different future reset values within one attempt.
The shared budget deliberately retains its accounting deadline and lower
balance until that deadline expires. [GitHub documents regional variation in
quota responses][github-quota]; a stored-deadline transition is not proof of
one globally synchronized provider window.

On alpha.79, bounded request-trace captures observed `accepted`,
`missing_resource` and `stale_reset` classifications. The latest-response
classification agreed with `github.quota.core_headers_valid` in the returned
spans. App-authentication responses explained some missing-resource
observations; they must not all be attributed to an installation-core failure.
These captures are samples, not a census of every request or proof of why an
older release paused.

A reconciliation attempt ended partial at 12:25:26 after 1,107.81 seconds,
with 67 PRs queued. It reported `probe_pending`, no failed installation,
no lost lease and no stop signal. Its summary and all 3,431 expected linked
request traces were retrieved. HTTP phase totals were 1,032.86 seconds,
quota admission 24.50 seconds, accounting 27.48 seconds and permit waits
about 0.007 seconds. Phase sums are not wall-clock percentages.

This attempt overlapped fixture traffic and did not complete the scan. It
is neither a quiet successful cycle nor evidence that the reserve was
exhausted. The [operation-cost receipt][costs] provides the earlier complete
request breakdown. [Issue #203][performance] retains the performance and
continuation work; the [production warning][status] remains unchanged.

## Cleanup

The temporary label was removed after each direct-event test, with a fresh
missing-review denial observed afterward. Mutation controllers and webhook
restoration watchdogs have exited. The original webhook configuration remains
restored. A separate read-only metric observation continues after these tests;
it is not included as a completed quiet-cycle result here.

All 142 PRs created in the three private fixtures were closed without merging;
their heads were unchanged and the repositories were left for the maintainer.
Afterward, bounded database captures matched all 142 closure deliveries and
their completed invalidations, with no fixture evaluation job remaining.
Seven sampled checks retained their IDs, heads and completed failure results,
not `skipped`. Six matched the early baseline including its completion time;
the seventh had a newer completion time that still preceded its close request.
This is a sampled result-retention check, not an assertion that all background
authority work on the installation had drained.

[artifacts]: 2026-11-10-policy-withdrawal-and-component-audit.md
[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.79
[deployment]: https://github.com/neverendingsupport/argo-apps/pull/2653
[argo-lookup]: https://github.com/neverendingsupport/argo-apps/issues/2029#issuecomment-6766851391
[costs]: 2026-11-10-reconciliation-operation-costs.md
[github-quota]: https://github.com/github/docs/blob/main/content/rest/using-the-rest-api/rate-limits-for-the-rest-api.md#checking-the-status-of-your-rate-limit
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[status]: ../../reference/project-status.md
