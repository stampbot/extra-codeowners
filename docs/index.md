# Extra CODEOWNERS documentation

GitHub's code-owner rule answers a useful but narrow question: did a person or
team named in `CODEOWNERS` approve this change? Extra CODEOWNERS keeps that
human ownership model and adds one carefully bounded alternative. An
organization can let an enrolled GitHub App approve particular paths, while a
human code owner can still approve everything they own.

The service evaluates each owned path in a pull request and publishes its
decision as a GitHub Check Run. A repository can require that check in place of
GitHub's native code-owner-review rule. Its ordinary approval count and every
other required check stay in force.

The repository contains an implemented self-hosted GitHub App, a reusable
evaluator, an App Manifest setup flow, and a Helm chart. CI builds and scans
container candidates. The `main` publication job has been removed, and tagged
publication is disabled pending three issues:
[source completeness #18](https://github.com/stampbot/extra-codeowners/issues/18)
covers native-wheel and embedded-SBOM component/source expansion;
[privilege separation #28](https://github.com/stampbot/extra-codeowners/issues/28)
isolates publication authority; and
[build proof #32](https://github.com/stampbot/extra-codeowners/issues/32)
retains the selected application proof in release evidence and connects it to
the future isolated publication path.
An [older public GHCR preview](https://github.com/stampbot/extra-codeowners/issues/30)
may still be discoverable; it is unsupported, incomplete, and must not be
deployed or mirrored.
There is no supported release or hosted installation yet.

CI already normalizes CPython as a top-level runtime component. It binds that
record to exact per-platform identity files and retains the pinned build recipe,
source archive, and source-carried license evidence. This closes the CPython
part of issue #18, but the image is not yet source-complete or approved for
distribution.

> **Production blocker:** GitHub attaches Check Runs to commits, but Extra
> CODEOWNERS evaluates evidence for one pull request. A newly opened or
> retargeted pull request can briefly inherit an earlier result for the same
> commit. Don't replace native production enforcement until the
> [eventual-consistency contract](reference/checks.md#eventual-consistency) has
> been resolved and tested against live GitHub behavior.

## Choose your task

If you are deciding whether the model fits your repository:

- Read [how Extra CODEOWNERS differs from native CODEOWNERS](explanation/native-codeowners.md).
- Follow the reasoning in the [architecture](explanation/architecture.md) and
  [threat model](explanation/threat-model.md).
- Check the [GitHub permissions](reference/github-permissions.md) before you
  install an App build.

If you want to run the current implementation:

- Follow the [development installation tutorial](tutorials/development-installation.md).
- [Register a development App with the setup URL](how-to/register-app.md).
- [Configure an organization and repository](how-to/configure.md).
- [Prepare repository rules](how-to/prepare-repository-rules.md).

If you operate a deployment:

- Use the [deployment guide](how-to/deploy.md).
- Keep the [operations and recovery guide](how-to/operate.md) close at hand.
- Review the [container evidence policy](reference/container-evidence-policy.md)
  and [future release contract](reference/container-evidence-release-contract.md).
  No tagged evidence assets exist while
  [source-completeness issue #18](https://github.com/stampbot/extra-codeowners/issues/18),
  [privilege-separation issue #28](https://github.com/stampbot/extra-codeowners/issues/28),
  and [build-proof issue #32](https://github.com/stampbot/extra-codeowners/issues/32)
  keep release publication denied.
- Consult the [checks](reference/checks.md),
  [configuration](reference/configuration.md), and
  [HTTP API](reference/http-api.md) references when you need exact behavior.

## Where trust lives

`CODEOWNERS` still says which humans own a path. Organization policy enrolls a
trusted application by immutable identity, and repository policy delegates a
limited set of paths to it. The evaluator reads policy from the pull request's
exact base commit and accepts approvals only for its current head. It checks
both names of a renamed file and fails closed when evidence is missing,
truncated, stale, or contradictory.

Some files can grant or expand an application's authority. Built-in rules keep
an application from substituting for a human on those sensitive paths. An
operator can disable that protection with the deployment-wide insecure-changes
escape hatch, but doing so is a deliberate change to the trust boundary, not a
convenience setting.

## What comes next

The GitHub App is the first distribution. A packaged Marketplace Action and a
hosted service are separate roadmap items; neither exists yet. The Helm chart
and App Manifest code are available now, but the project has not published a
supported release.

## Project help

Use the repository's
[support policy](https://github.com/stampbot/extra-codeowners/blob/main/SUPPORT.md)
for questions and operational incidents. Report security issues through the
[private security policy](https://github.com/stampbot/extra-codeowners/security/policy),
never through a public issue or discussion. Contributions follow the
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md).
