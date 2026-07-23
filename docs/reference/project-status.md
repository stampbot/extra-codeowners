# Project status

Last verified: 2026-07-23.

Extra CODEOWNERS is under active development. You can run the source as a
self-hosted GitHub App in a disposable environment, but the project does not
yet support production enforcement or public distribution.

## Available now

The repository contains:

- the GitHub App service and policy evaluator
- an App Manifest registration flow
- SQLite support for local development and PostgreSQL support for deployment
- a Helm chart in source form
- unit, integration, property, workflow, and container tests
- CI-built container candidates and review evidence.

The source is useful for evaluation and development. It is not a supported
release.

## DCO hardening status

The source also contains a bounded, side-effect-free DCO evaluator and the
read-only GitHub client methods it needs. The evaluator uses an exact
base-to-head comparison and returns a decision bound to the repository, pull
request, base SHA, and head SHA.

This path is dormant: no service or workflow calls it, and it cannot publish a
required check. The checked-in DCO workflow remains active, so a pull request
can still change the checker that evaluates that same pull request.

The [DCO evidence contract](dco-evidence.md) records the new validation layer
and the work that must surround it. [Issue #40][issue-40] tracks independent
execution, publication guards, and live repository-rule testing.

## Not available yet

The project does not currently publish or operate:

- a supported GitHub release
- a supported public container image
- a packaged Helm chart
- a hosted Extra CODEOWNERS service
- the planned `extra-codeowners-action` Marketplace Action.

An older public GHCR preview may still be discoverable. It is incomplete and
unsupported; do not deploy, mirror, or redistribute it. The disposition is
tracked in [issue #30](https://github.com/stampbot/extra-codeowners/issues/30).

## Production enforcement blocker

GitHub attaches Check Runs to commits. Extra CODEOWNERS evaluates evidence that
belongs to one pull request: its base, changed paths, labels, and reviews.

The service refuses to publish success when it can already see another open
pull request with the same head. It cannot stop a second pull request from
appearing after success, so that new pull request may briefly inherit the old
result. The stale result remains until the service processes a related event or
its periodic reconciler inserts work for the new pull request.

Once the service accepts a direct trigger, it records a durable revocation for
the payload's exact head. That work survives the original pull request closing
or moving to another head. Its worker resets an existing managed check, then
revalidates and queues every current open pull request on that commit.

Evaluation cannot publish until the captured generation is current and its
exact-head revocation has finished. The same generation guard prevents an
older fast-path handler or expired lease owner from resetting a newer result.
This closes the cross-worker race after acceptance; it cannot protect the
period before GitHub delivers the event.

The worker fetches current state for every pull request returned by GitHub's
commit-to-pulls endpoint. That endpoint has no completeness marker. If GitHub
omits a pull request, Extra CODEOWNERS cannot discover it from that response.

[Issue #1](https://github.com/stampbot/extra-codeowners/issues/1) tracks the
live contract tests and design work. Until it closes, keep GitHub's native
**Require review from Code Owners** rule on production repositories.

## Distribution blockers

Tagged publication is structurally disabled. These issues describe the work
that must finish before the first supported release:

- [#18: complete notices and corresponding-source evidence](https://github.com/stampbot/extra-codeowners/issues/18)
- [#28: separate archive parsing from publication authority](https://github.com/stampbot/extra-codeowners/issues/28)
- [#32: retain and bind the selected Python build proof](https://github.com/stampbot/extra-codeowners/issues/32)
- [#25: publish the first release as an immutable GitHub release](https://github.com/stampbot/extra-codeowners/issues/25).

CI already records substantial container and Python evidence. That work makes
the remaining gaps visible; it does not approve the current artifacts for
distribution.

## Roadmap distributions

The self-hosted GitHub App is the first planned distribution. A packaged
Marketplace Action and a hosted service are separate roadmap items. Neither
has an availability date.

Follow the linked issues for current evidence and decisions. This page should
change whenever one of these availability or safety claims changes.

[issue-40]: https://github.com/stampbot/extra-codeowners/issues/40
