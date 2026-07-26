# Extra CODEOWNERS

[![CI](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml)
[![Property testing](https://github.com/stampbot/extra-codeowners/actions/workflows/property-tests.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/property-tests.yml)
[![Coverage report](https://github.com/stampbot/extra-codeowners/actions/workflows/coverage-pages.yml/badge.svg)](https://stampbot.github.io/extra-codeowners/)
[![CodeQL](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/stampbot/extra-codeowners/badge)](https://scorecard.dev/viewer/?uri=github.com/stampbot/extra-codeowners)
[![Documentation](https://readthedocs.org/projects/extra-codeowners/badge/?version=latest)](https://extra-codeowners.readthedocs.io/)
[![Python 3.12–3.14](https://img.shields.io/badge/python-3.12%E2%80%933.14-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Extra CODEOWNERS is a self-hosted GitHub App for teams that trust automation
to approve routine pull requests. It publishes a required check that accepts
either a human CODEOWNER approval or an approval from an explicitly enrolled
GitHub App.

People and teams stay in GitHub's standard `CODEOWNERS` file. A separate
policy says which Apps may cover which owners and paths.

> [!WARNING]
> Extra CODEOWNERS is pre-release software. Don't use it to enforce production
> merges yet. The public container preview is also unsupported; don't deploy,
> mirror, or redistribute it. The [project status](docs/reference/project-status.md)
> lists the remaining enforcement and release blockers.

## Why this exists

GitHub's **Require review from Code Owners** rule understands people and
teams. It doesn't let a GitHub App stand in for them.

That becomes awkward when an App such as
[Stampbot](https://github.com/dannysauer/stampbot) already knows that a pull
request is routine. Stampbot can approve a policy-compliant `uv.lock` update,
for example, but GitHub still waits for a human code owner.

Extra CODEOWNERS replaces that one decision with a check:

```text
appropriate human CODEOWNER approval
                  OR
enrolled App approval + matching delegation
                  │
                  ▼
       Extra CODEOWNERS / approval
```

A normal pull request still needs its human owners. An App approval qualifies
only when all of these are true:

- the organization enrolled that exact App identity
- the repository opted in
- the delegation covers the changed path and effective CODEOWNER
- any required labels are present
- the approval applies to the current pull-request head
- no organization or built-in guardrail makes the path human-only

A pull request that mixes delegated and undelegated files still needs human
coverage for the undelegated files.

## What stays in GitHub

Keep your ordinary pull-request rules: minimum approval count, stale-review
handling, signed commits, and unrelated required checks. Extra CODEOWNERS is
intended to replace only **Require review from Code Owners**.

The App doesn't submit reviews, merge pull requests, grant another App access,
or edit `CODEOWNERS`. It reads GitHub evidence and publishes one Check Run.

This composition still needs live provider testing before production use.
Check Runs belong to commits, while labels, changed paths, and reviews belong
to pull requests. [Issue #1](https://github.com/stampbot/extra-codeowners/issues/1)
tracks the shared-commit edge cases and other GitHub contracts that must be
proven.

## How delegation is split

Extra CODEOWNERS deliberately requires two policy scopes.

| Source | Decides |
| --- | --- |
| `CODEOWNERS` | Which people or teams own each path |
| Organization policy | Which Apps are trusted at all, plus paths no App may cover |
| Repository policy | Which enrolled App may cover which owner and path in this repository |

The repository policy can narrow organization policy, but it can't enroll an
App or weaken an organization guardrail.

Here is the smallest useful repository policy:

```toml
schema_version = 1
enabled = true

[[delegations]]
app = "example-automation"
paths = ["/uv.lock"]
for_owners = ["@example-org/platform"]
required_labels = ["automation-approved"]
```

The `app` value refers to an immutable identity enrolled by the organization.
The names above are examples; use the validated files under
[`examples/policy/`](examples/policy/) as your starting point. The
[configuration guide](docs/how-to/configure.md) covers both scopes, path
matching, labels, built-in protected files, and the insecure escape hatch.

## Evaluate the source

There is no production install command yet. You can inspect the code and run
the local suite from a clean checkout with Bash, Git, and
[`mise`](https://mise.jdx.dev/) installed:

```bash
git clone https://github.com/stampbot/extra-codeowners.git
cd extra-codeowners
mise trust
mise install
mise run bootstrap
mise run test
```

Read `mise.toml` before `mise trust`; that command records a local trust
decision. A successful run ends with the test suite passing. It doesn't
register a GitHub App or prove the live GitHub contracts.

To publish a check in a disposable organization, follow the
[first-check tutorial](docs/tutorials/development-installation.md). Keep
GitHub's native code-owner rule enabled anywhere that matters.

## Documentation

These are the shortest routes into the manual:

| I want to… | Read |
| --- | --- |
| Find out what works today | [Project status](docs/reference/project-status.md) |
| Decide whether the trust model fits | [Native CODEOWNERS comparison](docs/explanation/native-codeowners.md) and [threat model](docs/explanation/threat-model.md) |
| Run a disposable live test | [First-check tutorial](docs/tutorials/development-installation.md) |
| Enroll an App and delegate paths | [Configuration guide](docs/how-to/configure.md) |
| Diagnose a check | [Troubleshooting guide](docs/how-to/troubleshoot-check.md) |
| Review deployment and operations | [Deployment guide](docs/how-to/deploy.md) and [operations guide](docs/how-to/operate.md) |
| Contribute | [Contributor guide](CONTRIBUTING.md) |

The full manual is on
[Read the Docs](https://extra-codeowners.readthedocs.io/).

## Project policy

Use the [support policy](SUPPORT.md) for questions and operational incidents.
Report vulnerabilities privately under the [security policy](SECURITY.md).
The project also publishes its [governance](GOVERNANCE.md),
[changelog](CHANGELOG.md), and
[maintainer documentation](docs/maintainers/index.md).

Extra CODEOWNERS is licensed under the [Apache License 2.0](LICENSE).
