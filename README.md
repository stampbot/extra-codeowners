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
GitHub App. A repository may also opt in to treating its eligible pull-request
author as human CODEOWNER evidence for that check.

People and teams stay in GitHub's standard `CODEOWNERS` file. A separate
policy says which Apps may cover which owners and paths.

> [!WARNING]
> Extra CODEOWNERS is pre-release software. Alpha images and charts are for
> non-required, shadow-mode testing only. Don't use them to enforce production
> merges. The older `:main` preview predates the current release pipeline;
> don't deploy, mirror, or redistribute it. The
> [project status](docs/reference/project-status.md) separates what is usable
> today from what still blocks a supported release.

## Why this exists

GitHub's **Require review from Code Owners** rule understands people and
teams. It doesn't let a GitHub App stand in for them.

That becomes awkward when an App such as
[Stampbot](https://github.com/dannysauer/stampbot) already knows that a pull
request is routine. Stampbot can approve a policy-compliant `uv.lock` update,
for example, but GitHub still waits for a human code owner.

Extra CODEOWNERS replaces that one decision with a check. It evaluates each
distinct effective owner set separately:

```text
appropriate human CODEOWNER approval
                  OR
opt-in: eligible pull-request author
                  OR
enrolled App approval + matching delegation
                  │
                  ▼
       Extra CODEOWNERS / approval
```

Every owner set represented by an owned path must pass. One pull request may
use a human approval for one owner set and an App approval for another. An App
approval qualifies only when all of these are true:

- the organization enrolled that exact App identity
- the repository opted in
- the delegation covers the changed path and effective CODEOWNER
- any required labels are present
- the approval applies to the current pull-request head
- no organization or built-in guardrail makes the path human-only

A pull request that mixes delegated and undelegated owned paths still needs
human coverage for each undelegated owner set. A path with no effective
`CODEOWNERS` match creates no code-owner requirement, although the repository's
ordinary approval count and other rules still apply.

## What stays in GitHub

Keep your ordinary pull-request rules: minimum approval count, stale-review
handling, signed commits, and unrelated required checks. Extra CODEOWNERS is
intended to replace only **Require review from Code Owners**.

GitHub's public contract doesn't say whether a third-party App review counts
toward the ordinary approval minimum. Test that combination in a disposable
repository before you rely on it. A nonzero minimum may still require a human
even when the Extra CODEOWNERS check succeeds; the
[native CODEOWNERS comparison](docs/explanation/native-codeowners.md#what-changes-in-repository-rules)
explains the open contract and links to the live probe.

The App doesn't submit reviews, merge pull requests, grant another App access,
or edit `CODEOWNERS`. It reads GitHub evidence and publishes one Check Run.

### Read the check as a policy result, not a review

Extra CODEOWNERS appears in GitHub's checks area, while GitHub's ordinary
approval count appears in the review area. Keep a normal minimum-review rule
when you need one; a successful Extra CODEOWNERS check is not itself a GitHub
review. Review the check's expected source and its explanatory output with the
same care as a required review rule, especially while contributors are learning
the different UI.

The check is asynchronous. When an approval is dismissed or changed, a prior
success remains visible until GitHub delivers the event and the App resets and
re-evaluates the check. That is normally short, but it cannot be made zero by a
third-party App. Reconciliation repairs missed deliveries; it is not an
instantaneous revocation mechanism. Keep GitHub's native code-owner rule for a
boundary that cannot tolerate that stale-success window.

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

The `app` value is an alias from the organization policy's `[apps.<alias>]`
table. That organization entry binds the alias to the App's immutable numeric
ID, public slug, and bot-user ID. The names above are examples; use the
validated files under [`examples/policy/`](examples/policy/) as your starting
point. The [configuration guide](docs/how-to/configure.md) covers both scopes,
path matching, labels, built-in protected files, and the insecure escape hatch.

## Run the project locally

You can inspect the code and run the local suite from a clean checkout with
Bash, Git, and
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

To publish a check in a test repository, follow the
[first-check tutorial](docs/tutorials/development-installation.md). Keep
GitHub's native code-owner rule enabled anywhere that matters. If you want to
deploy an alpha image and chart, use the
[shadow-mode deployment guide](docs/how-to/deploy.md) and pin the image by
digest.

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
| Understand CI and releases | [Architecture](docs/explanation/architecture.md#ci-and-release-path) and [maintainer guide](docs/maintainers/index.md) |
| Contribute | [Contributor guide](CONTRIBUTING.md) |

The full manual is on
[Read the Docs](https://extra-codeowners.readthedocs.io/).

## Project policy

Use the [support policy](SUPPORT.md) for questions and operational incidents.
Report vulnerabilities privately under the [security policy](SECURITY.md).
The container includes OpenSSL. The security policy records known CVEs that do
not affect this service and links to the current VEX.
The project also publishes its [governance](GOVERNANCE.md),
[changelog](CHANGELOG.md), and
[maintainer documentation](docs/maintainers/index.md).

Extra CODEOWNERS is licensed under the [Apache License 2.0](LICENSE).
