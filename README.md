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
to approve routine pull requests. It posts a check that can count an enrolled
App's approval for a lockfile and still report that an application change needs
a human code owner. If the repository opts in, the author can cover paths they
already own.

People and teams stay in GitHub's standard `CODEOWNERS` file. A separate
policy says which Apps may cover which owners and paths.

> [!WARNING]
> Extra CODEOWNERS is pre-release software. Alpha images and charts are for
> shadow mode and disposable tests. Don't use them to enforce production
> merges. Legacy preview images — `:main` and its `sha-*` and `sha256-*`
> companion tags — are unsupported and unsafe for deployment. They predate the
> immutable release pipeline and lack the complete release and
> corresponding-source evidence required for a supported artifact. Don't
> deploy, mirror, or redistribute them. This is not a claim of a known
> vulnerability. The
> [project status](docs/reference/project-status.md) separates what is usable
> today from what still blocks a supported release.

## Why this exists

GitHub's **Require review from Code Owners** rule understands people and
teams. It doesn't let a GitHub App stand in for them.

That becomes awkward when an App such as
[Stampbot](https://github.com/dannysauer/stampbot) already knows that a pull
request is routine. Stampbot can approve a policy-compliant `uv.lock` update,
for example, but GitHub still waits for a human code owner.

Extra CODEOWNERS evaluates that one decision. It checks each distinct set of
owners separately:

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
handling, signed commits, and unrelated required checks. Keep **Require review
from Code Owners** while trying an alpha. The [1.0 enforcement setup](docs/how-to/test-merge-queue.md)
requires GitHub's one-at-a-time merge queue. Without that queue, keep native
review on and use Extra CODEOWNERS as advice.

GitHub's public contract doesn't say whether a third-party App review counts
toward the ordinary approval minimum. It counted in a disposable repository,
but test your own rules before relying on that behavior. The
[native CODEOWNERS comparison](docs/explanation/native-codeowners.md#what-changes-in-repository-rules)
explains how the review count and the check differ.

The App doesn't submit reviews, merge pull requests, grant another App access,
or edit `CODEOWNERS`. It reads GitHub evidence and publishes Check Runs.

### Read the check as a policy result, not a review

Extra CODEOWNERS appears in GitHub's checks area, while GitHub's ordinary
approval count appears in the review area. Keep a normal minimum-review rule
when you need one; a successful Extra CODEOWNERS check is not itself a GitHub
review. Review the check's expected source and its explanatory output with the
same care as a required review rule, especially while contributors are learning
the different UI.

When someone dismisses an approval, GitHub can still show the old pass until
the App learns about the change and resets the check. Reconciliation can repair
a missed event, but it can't make dismissal and merging happen together.

GitHub attaches checks to commits, not pull requests. If two PRs share a head
commit, both can show the same pass even when their policies or approvals
differ. In a [live queue test](docs/maintainers/evidence/2026-11-23-candidate-checks-during-delivery-loss.md),
GitHub waited for a separate check on the commit it would merge. Waiting PRs
each need their own result when they reach the front. A pass on the PR head
alone can't enforce that distinction.

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
Bash, Git, and [`mise`](https://mise.jdx.dev/) installed:

```bash
git clone https://github.com/stampbot/extra-codeowners.git
cd extra-codeowners
```

Read `mise.toml` before running `mise trust`; that command records a local
trust decision.

```bash
mise trust
mise install
mise run bootstrap
mise run test
```

A successful run ends with the test suite passing. It doesn't register a
GitHub App or prove the live GitHub contracts.

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
| Inspect release notice evidence | [Recipient notice bundles](docs/reference/recipient-notices.md) |
| Understand CI and releases | [Architecture](docs/explanation/architecture.md#ci-and-release-path) and [maintainer guide](docs/maintainers/index.md) |
| Understand why it's built this way | [Decision records](docs/explanation/adrs/index.md) |
| See what's left before a supported release | [Remaining work](docs/reference/project-status.md#remaining-work) |
| Contribute | [Contributor guide](CONTRIBUTING.md) |

The full manual is on
[Read the Docs](https://extra-codeowners.readthedocs.io/).

## Project policy

Use the [support policy](SUPPORT.md) for questions and operational incidents.
Report vulnerabilities privately under the [security policy](SECURITY.md).
The security policy links the current VEX and explains its reviewed package
claims and remaining native-library coverage gaps.
The project also publishes its [governance](GOVERNANCE.md),
[changelog](CHANGELOG.md), and
[maintainer documentation](docs/maintainers/index.md).

Extra CODEOWNERS is licensed under the [Apache License 2.0](LICENSE).
