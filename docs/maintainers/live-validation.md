# Live validation results

These are observations from GitHub.com and the deployed App, not guarantees
about future webhook timing. The open release gates are tracked in
[the first supported release milestone][milestone]. Keep Extra CODEOWNERS
non-required during evaluation; retain native code-owner enforcement for
production-sensitive repositories.

New runs have their own dated [evidence receipts](evidence/index.md). The
[November 2 reconciliation and alpha.67 receipt](evidence/2026-11-02-reconciliation-and-alpha67.md)
records the completed observation windows, release verification and restored
label probe. The older sections below retain their original observations;
later evidence does not silently turn them into tests of a newer release.

## Diagnostics and approval probe: November 2, 2026

Alpha.65 runs on two Kubernetes nodes with shared PostgreSQL state. The
diagnostics from [PR #253][diagnostics] are deployed through
[Argo PR #2626][diagnostics-deployment]. Release signatures and source-bound
provenance verified against the exact main commit. Inventory, notice, source
and OpenVEX verification passed too; those checks do not establish the
distribution approval tracked in [issue #18][sources].

On a retained delegated-path PR, removing its required label produced an
explicit blocking failure after about 8.5 seconds and the final
missing-approval failure after about 13.5 seconds. Restoring the label
produced success after about 11.5 seconds. These intervals start when the API
request began and end at GitHub's whole-second completion timestamp. They
are individual observations, not latency percentiles. The label is restored
and the PR head is unchanged.

Both evaluation traces were retrieved from Tempo. They last about 8.00 and
7.74 seconds, with 17 and 18 outer GitHub operations. Every operation records
zero retries and no error. Semaphore wait is negligible in those traces;
HTTP reads and writes dominate. This does not explain the older 32.5-second
withdrawal or establish acceptable reconciliation performance.

The first elected scan in the subsequent observation ended partial at
16:57:41 UTC. A GitHub HTTP 500 while listing checks failed one installation;
the outcome reports neither a quota deferral nor a lost lease. Its trace lasts
1,783 seconds and contains 4,615 outer GitHub operations. Their phase totals
include 1,490 seconds in HTTP and 201 seconds in quota admission/accounting,
with only 0.017 seconds waiting for the request semaphore. Nested token requests
are excluded from these operation totals to avoid double-counting.

The new retention counters also recorded page-cache byte evictions, proving
storage pressure rather than inferring it from a full byte gauge. Reducing
that pressure may improve reuse, but a cached response still needs a GitHub
request. It will not remove the cost of thousands of serial validations.

No installation selection, queue, quota or deployment setting was changed to
obtain these measurements; no webhook was redelivered. The quiet window has
no further controlled fixture changes, not a guarantee that every repository
in the installation is idle. These results do not complete the two-success
quiet-cycle gate, isolate missed-webhook recovery, or test a multipage
checkpoint across a quota reset. See the [dated evidence][november-evidence]
and the [performance gate][performance].

## Deployed approval checks: September 14, 2026

The App ran `v0.1.0-alpha.45` on two Kubernetes nodes with PostgreSQL state.
Tests used a disposable organization with an all-repositories installation.
The installation's existing repository workload and provider backoff were
left in place.

| Test | Observed result |
| --- | --- |
| Human approves a bot-authored PR outside bot-delegated paths | Failure changed to success in 11 seconds. |
| Human dismisses that approval | Success changed to failure in 3 seconds. |
| Human approves again | Failure changed to success in 10 seconds. |
| Close the approved PR without merging | The successful result and completion timestamp were unchanged when checked 30 seconds later. |
| Eligible author with author-as-owner enabled | The check passed. |
| Non-delegated changed path without eligible approval | The check failed. |
| Stampbot approves a delegated path while recovery is preserving its API reserve | The check passed 13 seconds after the approval request. |
| Remove the required delegation label, then restore it | The check failed after 4 seconds and passed 9 seconds after the label was restored. |

These timings run from the recorded API action or review timestamp to GitHub's
completed check timestamp. They are individual observations, not latency
percentiles or a service-level objective. The Stampbot interval includes the
time Stampbot took to submit its review.

The same run exposed a slow first check: one newly opened PR waited about
3 minutes 52 seconds for a final result. Database inspection showed its
repository authority refresh was still pending while API quota was available.
[PR #212][priority] prioritizes those refreshes when a direct PR event is
waiting. The alpha.48 observations below include that fix; the table above
predates it.

See [issue #1's dated evidence][live-evidence] for the human-review sequence.
The missed opening webhook also recovered without redelivery, but repository
fan-out visited the PR during recovery. That observation does not isolate the
periodic reconciliation path or establish acceptable recovery latency.

## Authority refresh and native handback: September 14, 2026

With `v0.1.0-alpha.48`, a PR opened after a repository rename reached its first
final result in 64 seconds. Part of that wait was existing provider backoff;
the result arrived 29 seconds after quota became available. Stampbot approval
then passed in 31 seconds, including Stampbot's review submission.

Broad authority work still exhausted the test installation's quota later in
the run. Prioritizing direct events helps while capacity is available, but
does not create capacity once GitHub has denied further requests. The
[performance gate][performance] remains open.

The native-enforcement handback passed on a separate, bot-authored PR. Native
code-owner review was active with no bypass actors before the Extra CODEOWNERS
requirement was removed. After dismissing the human approval, GitHub reported
`BLOCKED` and `REVIEW_REQUIRED`. A merge request for that exact head returned
HTTP 405, citing the missing code-owner review. The PR remained open under
native enforcement.

This verifies the handback on that fixture, not installation suspension,
uninstall, or repository-selection removal. An earlier PR authored by its
sole code owner was not a useful negative control: GitHub still reported it
approved with Stampbot's review. The bot-authored PR kept author ownership
out of the negative control. See the [dated handback evidence][handback].

## Scoped repository addition: September 14, 2026

With `v0.1.0-alpha.51`, a newly created repository's first PR reached a final
missing-approval result in 8 seconds. Stampbot approval then passed in
12 seconds, including its review submission. Both service replicas were
healthy on separate nodes.

The installation-wide authority generation did not change, and no authority
jobs remained after the test. The earlier stuck addition job for the old
repository name also cleared. No queue reset, rename, or webhook redelivery
was used for this test.

The lifecycle collector retained an automatic repository-addition delivery
with HTTP 202. Its bounded listing was incomplete, so it does not establish
an exhaustive delivery history. These are positive observations of one
addition, not proof of every lifecycle transition. See the
[dated addition evidence][addition].

## GitHub's check contract

The schema-3 provider fixture completed its automated observations on
September 14. Expected App sources worked in repository and organization
rulesets, and an App-authored approving review satisfied GitHub's ordinary
numeric review requirement.

An explicit completed failure blocked merging. Moving a previous successful
check back to `in_progress` did not reliably do so in the earlier September 12
run; the App now publishes an explicit blocking failure while reevaluating.

The shared-head result remains unsafe: opening or retargeting another PR to
an already-successful commit can inherit that success before the new event
is invalidated. The fixture recorded `github_contract_fail_closed: false`.
Completing the fixture does not turn that result into a pass. See
[issue #1][contract] and the [threat model][threat-model].

## Work still needed

The performance gate remains open. These results do not establish quiet
recovery or complete coverage of repository lifecycle transitions and App
access loss. The
[remaining work](../reference/project-status.md#remaining-work) list tracks
those gates, along with the distribution source work in
[issue #18][sources], which passing approval tests doesn't close.

When you add results here, record delivery payload contracts separately from
service behavior: an event in GitHub's delivery log doesn't prove the service
processed it.

[milestone]: https://github.com/stampbot/extra-codeowners/milestone/1
[priority]: https://github.com/stampbot/extra-codeowners/pull/212
[live-evidence]: https://github.com/stampbot/extra-codeowners/issues/1#issuecomment-5671232698
[contract]: https://github.com/stampbot/extra-codeowners/issues/1
[threat-model]: ../explanation/threat-model.md
[sources]: https://github.com/stampbot/extra-codeowners/issues/18
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[handback]: https://github.com/stampbot/extra-codeowners/issues/1#issuecomment-5672325273
[addition]: https://github.com/stampbot/extra-codeowners/issues/203#issuecomment-5672497697
[diagnostics]: https://github.com/stampbot/extra-codeowners/pull/253
[diagnostics-deployment]: https://github.com/neverendingsupport/argo-apps/pull/2626
[november-evidence]: https://github.com/stampbot/extra-codeowners/issues/203#issuecomment-6583054451
