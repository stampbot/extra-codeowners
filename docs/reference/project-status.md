# Project status

Last verified: 2026-07-23.

Extra CODEOWNERS is pre-release. The source can publish a check in a disposable
development environment, but there is no supported production enforcement or
deployable release.

## Availability

| Surface | Status |
| --- | --- |
| Source checkout for development and evaluation | Available |
| App Manifest registration flow | Implemented for development testing |
| Production code-owner enforcement | Not supported; the live GitHub contract remains open in [issue #1][issue-1] |
| Supported GitHub release | Not available |
| Supported container image | Not available |
| Packaged Helm chart | Not available; a chart exists in source only |
| Public GitHub Container Registry (GHCR) package | A pre-compliance preview is public, but it is unsupported |
| Hosted service | Not available |
| `extra-codeowners-action` Marketplace Action | Not available |

Anonymous registry inspection on 2026-07-23 confirmed that the public
`ghcr.io/stampbot/extra-codeowners:main` tag still resolves. That image
predates the current release controls. Its native dependency inventory and
corresponding-source closure are incomplete under [issue #18][issue-18], so it
is not approved distribution evidence. Don't deploy, mirror, or redistribute
it. [Issue #30][issue-30] tracks its complete inventory and final disposition.

## What you can evaluate from source

The repository contains:

- the GitHub App service and policy evaluator
- an App Manifest registration flow
- SQLite support for local development and PostgreSQL support for a future
  deployment
- a Helm chart in source form
- unit, integration, property, workflow, and container tests
- CI-built container candidates and review evidence.

Use these parts to review the policy model or run a disposable live test. They
don't add up to a supported release.

## Production enforcement blocker

GitHub attaches a Check Run to a commit. Extra CODEOWNERS evaluates evidence
for one pull request: its base, changed paths, labels, and reviews. If two open
pull requests use the same head commit, a successful result from the first can
appear on the second before Extra CODEOWNERS receives and processes the event
that should revoke it.

The service now records durable exact-head invalidation, resets an existing
managed check to `in_progress`, reevaluates every current pull request GitHub
reports for that commit, and uses generation guards to stop older workers from
publishing over newer evidence. Those controls reduce the window after event
acceptance. They can't protect the time before GitHub delivers the event.

There is another provider boundary: GitHub's commit-to-pull-requests endpoint
doesn't mark its response as complete. If GitHub omits a pull request, the
service can't discover it from that response.

[Issue #1][issue-1] tracks the remaining live tests, including:

- required-check behavior while a completed Check Run returns to
  `in_progress`
- shared-head opening and retargeting under delayed or lost delivery
- expected-source selection in repository and organization rulesets
- whether a third-party App approval satisfies GitHub's ordinary numeric
  approval count
- installation lifecycle, repository transfer, and access-loss behavior.

No dated live execution has been recorded. Until the issue closes, keep
GitHub's native **Require review from Code Owners** rule on production
repositories.

## Distribution blockers

Tagged publication is disabled. Six issues define the first supported release
boundary:

| Issue | Required outcome |
| --- | --- |
| [#1][issue-1] | Prove the live Check Run, App-review, and authority-loss contracts. |
| [#18][issue-18] | Complete notices and corresponding-source evidence. |
| [#25][issue-25] | Publish the first release as an immutable GitHub release. |
| [#28][issue-28] | Separate archive parsing from publication authority and finish the recipient verification contract. |
| [#30][issue-30] | Inventory and decide the disposition of the public preview package. |
| [#32][issue-32] | Retain and bind the selected Python build proof. |

CI records substantial Python and container evidence. That work exposes what
is still missing; it doesn't approve an artifact for distribution.

## Hardening code that is not active yet

The source includes a bounded Developer Certificate of Origin (DCO) evaluator
and read-only GitHub methods. The evaluator binds its decision to a repository,
pull request, and exact base and head commits, but no independent service or
workflow calls it. The checked-in DCO workflow can still change in the same
pull request it evaluates. The [DCO evidence contract](dco-evidence.md) records
the boundary, and [issue #40][issue-40] tracks independent execution and
publication.

The source also contains parts of a future privileged release path:

- an offline [release controller](immutable-release-controller.md)
- a [GitHub release API adapter](github-release-api-adapter.md)
- a read-only [immutable-release preflight](immutable-release-preflight.md)
- a [blocked release candidate assembler](release-asset-candidate-format.md).

No workflow connects the controller, adapter, and preflight or gives that path
a privileged token. The workflow places the candidate assembler downstream of
the failing publication block, so it skips that job. The assembler's record
forbids publication when the script is exercised independently. These are
reviewable contracts, not a working release process.

## Planned distributions

The self-hosted GitHub App is the first planned distribution. A packaged
Marketplace Action and a hosted service are separate roadmap items. Neither
has an availability date.

Follow the linked issues for current evidence and decisions. Update this page
whenever an availability or safety claim changes.

[issue-1]: https://github.com/stampbot/extra-codeowners/issues/1
[issue-18]: https://github.com/stampbot/extra-codeowners/issues/18
[issue-25]: https://github.com/stampbot/extra-codeowners/issues/25
[issue-28]: https://github.com/stampbot/extra-codeowners/issues/28
[issue-30]: https://github.com/stampbot/extra-codeowners/issues/30
[issue-32]: https://github.com/stampbot/extra-codeowners/issues/32
[issue-40]: https://github.com/stampbot/extra-codeowners/issues/40
