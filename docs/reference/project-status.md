# Project status

Last verified: 2026-07-28.

Extra CODEOWNERS is ready for source review and disposable testing. It is not
ready to enforce production merges, and it has no supported release artifact.

## What is available

Use a source checkout to evaluate the project today:

| Surface | Status |
| --- | --- |
| Source checkout | Available for development and evaluation |
| App Manifest registration | Implemented for development testing |
| Evaluation-beta preflight | Available from source; checks prerequisites but does not run the beta |
| Production code-owner enforcement | Not supported; live GitHub contracts remain open in [issue #1][issue-1] |
| Supported GitHub release | Not available |
| Supported container image | Not available |
| Packaged Helm chart | Not available; a chart exists in source only |
| Public GitHub Container Registry (GHCR) package | A pre-compliance preview is public, but it is unsupported |
| Native dependency wheelhouse | Signed build and publication path implemented; application images consume its immutable contract |
| Container evidence verifier | Schema-9 content verification and immutable GitHub release authentication are implemented in source; they are not connected, and workflow and OCI authentication remain blocked |
| Hosted service | Not available |
| `extra-codeowners-action` Marketplace Action | Not available |

The source contains the GitHub App, policy evaluator, App Manifest flow, local
SQLite support, PostgreSQL support for future deployments, a Helm chart, and
the test and evidence pipelines. You can use those pieces to study the policy
model or run a disposable live test. They don't add up to a release.

Anonymous registry inspection on 2026-07-23 confirmed that
`ghcr.io/stampbot/extra-codeowners:main` still resolves. That image predates
the current release controls. Its exact component and source evidence is
incomplete under [issue #18][issue-18], so it is not an approved distribution.
Don't deploy, mirror, or redistribute it. [Issue #30][issue-30] tracks its
inventory and final disposition.

## Why production enforcement is blocked {#production-enforcement-blocker}

GitHub attaches a Check Run to a commit, but Extra CODEOWNERS evaluates one
pull request: its base, changed paths, labels, and reviews. Two open pull
requests can share a head commit. In that case, a successful result from the
first pull request can appear on the second before Extra CODEOWNERS receives
the event that should revoke it.

The service now resets its managed check to `in_progress`, asks GitHub for
every current pull request using that commit, and reevaluates each one.
Generation guards stop an older worker from overwriting newer evidence. Those
controls start only after GitHub delivers an event.

GitHub's commit-to-pull-requests endpoint creates a second limit: the response
doesn't say whether the list is complete. The service can't revoke a check for
a pull request GitHub omitted.

[Issue #1][issue-1] owns the remaining provider tests:

- required-check behavior when a completed Check Run returns to `in_progress`
- shared-head opening and retargeting with delayed or lost webhooks
- expected-source selection in repository and organization rulesets
- the way third-party App reviews interact with the ordinary approval count
- installation lifecycle, repository transfer, and access loss.

No dated live execution has proved the whole contract. Keep GitHub's native
**Require review from Code Owners** rule on production repositories until
issue #1 closes.

## Why distribution is blocked {#distribution-blockers}

Tagged publication is disabled. These issues define the first supported
release boundary:

| Issue | Required outcome |
| --- | --- |
| [#1][issue-1] | Prove the live Check Run, App-review, and authority-loss contracts |
| [#18][issue-18] | Complete notices and corresponding-source evidence |
| [#25][issue-25] | Publish the first release as an immutable GitHub release |
| [#28][issue-28] | Separate archive parsing from publication authority and finish recipient verification |
| [#30][issue-30] | Inventory the public preview and decide its disposition |
| [#32][issue-32] | Retain and bind the selected Python build proof |

CI produces detailed Python and container evidence. That evidence tells a
reviewer exactly what is missing; it does not approve an artifact for
distribution.

## Inactive hardening work

The source includes a bounded Developer Certificate of Origin (DCO) evaluator.
It binds a decision to one repository, pull request, and exact base and head
commit. No independent service or workflow calls it yet, so a pull request can
still modify the workflow that checks that same pull request. Read the
[DCO evidence contract](dco-evidence.md) for the implemented boundary.
[Issue #40][issue-40] tracks independent execution.

There are also parts of a future privileged release path:

- a bounded schema-9
  [container evidence verifier](container-evidence-release-contract.md#current-content-verifier)
- a read-only
  [authenticated GitHub release verifier](authenticated-github-release-record.md)
- a GitHub-read-only
  [authenticated asset acquirer](authenticated-release-asset-acquisition.md)
- an offline [release controller](immutable-release-controller.md)
- a [GitHub release API adapter](github-release-api-adapter.md)
- a read-only [immutable-release preflight](immutable-release-preflight.md)
- a [blocked release candidate assembler](release-asset-candidate-format.md).

No workflow gives that path publication authority. The candidate assembler is
downstream of an intentional failure and is skipped in normal release runs. If
someone invokes it independently, its record still forbids publication.
These are reviewable contracts, not a working release process.

## Planned distributions

The self-hosted GitHub App comes first. A packaged Marketplace Action and a
hosted service are separate roadmap items, with no availability date.

Follow the linked issues for current evidence and decisions. This page should
change whenever an availability or safety claim changes.

[issue-1]: https://github.com/stampbot/extra-codeowners/issues/1
[issue-18]: https://github.com/stampbot/extra-codeowners/issues/18
[issue-25]: https://github.com/stampbot/extra-codeowners/issues/25
[issue-28]: https://github.com/stampbot/extra-codeowners/issues/28
[issue-30]: https://github.com/stampbot/extra-codeowners/issues/30
[issue-32]: https://github.com/stampbot/extra-codeowners/issues/32
[issue-40]: https://github.com/stampbot/extra-codeowners/issues/40
