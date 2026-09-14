# Live validation results

These are observations from GitHub.com and the deployed App, not guarantees
about future webhook timing. The open release gates are tracked in
[the first supported release milestone][milestone]. Keep Extra CODEOWNERS
non-required during evaluation; retain native code-owner enforcement for
production-sensitive repositories.

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

Before a supported release, finish the large-installation performance and
reconciliation measurements, then exercise repository lifecycle and App
access-loss transitions with the native-enforcement handback in place.
Record delivery payload contracts separately from service behavior: an event
in GitHub's delivery log does not prove the service processed it.

The distribution source and notice work in [issue #18][sources] is a separate
release gate. Passing approval tests or verifying signed source bundles does
not close it.

[milestone]: https://github.com/stampbot/extra-codeowners/milestone/1
[priority]: https://github.com/stampbot/extra-codeowners/pull/212
[live-evidence]: https://github.com/stampbot/extra-codeowners/issues/1#issuecomment-5671232698
[contract]: https://github.com/stampbot/extra-codeowners/issues/1
[threat-model]: ../explanation/threat-model.md
[sources]: https://github.com/stampbot/extra-codeowners/issues/18
[performance]: https://github.com/stampbot/extra-codeowners/issues/203
[handback]: https://github.com/stampbot/extra-codeowners/issues/1#issuecomment-5672325273
