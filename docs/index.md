# Extra CODEOWNERS documentation

Extra CODEOWNERS publishes a GitHub check that accepts either a human
CODEOWNER approval or an approval from a specifically enrolled GitHub App.
People and teams stay in `CODEOWNERS`; App authority lives in separate policy.

!!! warning "Development and test use only"

    Extra CODEOWNERS is not ready to replace GitHub's native code-owner rule on
    a production repository. Read the
    [current project status](reference/project-status.md) before you install or
    test it.

## Start here

If this is your first visit, read the
[native CODEOWNERS comparison](explanation/native-codeowners.md). It explains
what the extra check replaces, what stays with GitHub, and why App delegation
uses a separate policy file.

Then choose the task that matches what you're doing.

### Run the first check

The [first-check tutorial](tutorials/development-installation.md) starts with a
clean checkout and a disposable GitHub organization. It uses a human approval
so you can prove the checker works before you introduce another App.

### Register and configure the App

- [Register an App with the setup URL](how-to/register-app.md)
- [Configure organization and repository policy](how-to/configure.md)
- [Prepare repository rules in a disposable repository](how-to/prepare-repository-rules.md)
- [Run the live GitHub contract fixture](how-to/run-live-github-contract.md)

### Understand a check result

Use [Troubleshoot a check](how-to/troubleshoot-check.md) when you are looking at
a failed, pending, or missing check on a pull request. It starts with the text
GitHub shows and tells you when an operator needs to get involved.

The [checks reference](reference/checks.md) contains the complete evaluation
contract.

### Operate a development deployment

There is no supported image or chart release yet. The deployment, upgrade, and
operations guides describe the contract implemented by the current source:

- [Prepare a future deployment](how-to/deploy.md)
- [Upgrade, back up, and restore](how-to/upgrade.md)
- [Operate and recover](how-to/operate.md)

These pages are useful for evaluation and design review. They are not a
production-readiness claim.

## Reference

Use the reference pages for exact fields, limits, permissions, routes, and
failure behavior:

- [configuration](reference/configuration.md)
- [checks and evaluation](reference/checks.md)
- [command line](reference/cli.md)
- [GitHub permissions and events](reference/github-permissions.md)
- [HTTP API](reference/http-api.md)
- [project status](reference/project-status.md).

## Understand the design

The [architecture](explanation/architecture.md) follows a webhook from
authenticated ingress to a Check Run. The
[threat model](explanation/threat-model.md) explains who holds authority and
where fail-closed behavior still depends on GitHub delivery.

The other explanation pages cover database migrations, property tests, and the
runtime base image.

## Maintainer and release engineering

Supply-chain evidence, release candidates, DCO hardening, and publication
controls are project-maintainer work. They have their own
[maintainer documentation index](maintainers/index.md) so they don't interrupt
the setup and policy paths above.

## Get help or contribute

Use the repository's [support policy](https://github.com/stampbot/extra-codeowners/blob/main/SUPPORT.md)
for questions and operational incidents. Report vulnerabilities through the
[private security policy](https://github.com/stampbot/extra-codeowners/security/policy),
not through a public issue. The
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md)
explains local checks, commit sign-off, and pull-request expectations.
