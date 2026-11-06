# Missed policy webhook: November 6, 2026

Periodic reconciliation found a policy change whose push webhook was not
accepted. The first API-observed final denial arrived about
27 minutes after the policy write was confirmed. That proves recovery in
this case, not prompt revocation or a maximum recovery time.

The tested runtime was [alpha.73][release], source
`95dfd13f5ce26962c73c8bcf9d78d911178f67c5`, with two replicas on distinct nodes
and shared PostgreSQL. The [earlier receipt][earlier] records its artifact
verification and normal delivered-event probe. All times below are UTC on
November 6, 2026. Private fixture, delivery, trace and infrastructure identities
remain in retained maintainer captures.

## Method

The existing disposable PR had one eligible App approval, no human review and
its required delegation label. Its head, reviews and labels stayed unchanged.
The only policy change added another required label that the PR did not have.
This changed the base branch's policy, not the PR's files.

With the operator's approval, the test briefly changed the App's webhook URL
to an unused path on the same HTTPS origin. A separate watchdog could restore
the URL if the controller stopped. GitHub recorded a `404` for the policy
push; the delivery's commit and URL matched the intended test. Its generated
check-suite event also failed. A bounded inspection retained the pre-test
delivery boundary and found no other failed delivery in that interval.

The controller verified the original URL, content type and TLS-verification
setting after about five seconds. It did not change the webhook secret.
Independent reads confirmed restoration. Workers and reconciliation continued
running; no replica count, installation selection, quota, queue or shared
deployment setting changed.

The test then left the policy in place without redelivering either missed
event, commenting on the PR, requesting a check rerun or manually invoking
reconciliation. Read-only database samples and bounded log queries followed
the recovery. After the denial, the controller restored the original policy
and waited for a successful check.

## Observed recovery

The retained observations have these distinct endpoints:

| Observation | Time |
| --- | --- |
| Last confirmed evaluation before the change | 22:04:53.903 |
| Policy write confirmed | 22:13:41.177 |
| Original webhook configuration verified restored | 22:13:44.907 |
| Initial periodic enqueue recorded | 22:40:05.011 |
| Denial evaluation completed in the worker log | 22:40:18.152 |
| Final denial observed through the GitHub API | 22:40:34.715 |
| Original policy verified restored | 22:40:40.827 |
| Successful check observed through the GitHub API | 22:40:52.283 |

The initial enqueue log names `periodic_reconciliation` and recovery work.
The durable failure audit names `scheduled_recheck` with no delivery ID.
Before restoration, the missed GUID had no acceptance record, and the
database contained no accepted fixture, organization-policy or
installation-wide event in the observed scope. This establishes the initial
recovery source rather than inferring it from a later shared-head handoff.

Policy confirmation to the first observed final denial took 1,613.54 seconds;
enqueue to worker completion took 13.14 seconds. The controller polled checks
about every 20 seconds, so its observation is not the instant the result became
visible. The App-supplied Check Run `completed_at` is not independent evidence
of display or merge-gate timing either.

The denial worker began 9.61 seconds after enqueue. Its retrieved evaluation
trace lasted 3.54 seconds and contained 14 outer operations; the restoration
evaluation lasted 5.70 seconds with 18. Neither recorded a request error or
retry. Most of this run's recovery delay preceded queue insertion, not the
evaluation itself.

The deployment used a 300-second reconciliation interval and a 900-second
minimum recheck age. The fixture had already been visited before the policy
change. The scan had to reach it again; neither setting promised a recovery
deadline. The [architecture description][reconciler] explains those limits.

## Cleanup and limits

The original policy bytes, head, reviews and labels were verified after the
test. The check returned to success. Independent configuration reads confirmed
the original webhook URL; both replicas remained Ready on distinct nodes with
zero restarts and the verified alpha.73 image. No new test repository was
created, and no observer or watchdog remains active.

This tests a missed policy restriction on an already managed PR. It does not
prove discovery of a newly enrolled repository, missed-review recovery,
authority loss, shared-head merge behavior or atomic revocation. The old
success remained visible while recovery waited. Keep the production warning
in [project status][status]; this is not a fail-closed merge proof.

A separate alpha.73 scan completed at 21:38:23 with 77 PRs queued in
1,847.02 seconds. Its summary reports 6,403 expected request traces, but the
partitioned capture retrieved only 6,373. An independent attribute-only search
returned the same count with all backend search jobs complete. The telemetry
is incomplete; no cause is established. Another attempt at 22:06:49 was
partial after 1,405.50 seconds, with 12 PRs queued and recovery deferred. Neither
observation is a complete quiet-performance validation.

The controlled live multipage checkpoint across a quota reset also remains
unperformed. [Issue #203][performance] stays open.

[release]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.73
[earlier]: 2026-11-06-reconciliation-and-alpha73.md
[reconciler]: ../../explanation/architecture.md#reconciler
[status]: ../../reference/project-status.md
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
