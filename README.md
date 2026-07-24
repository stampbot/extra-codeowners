# Extra CODEOWNERS

[![CI](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml)
[![Property testing](https://github.com/stampbot/extra-codeowners/actions/workflows/property-tests.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/property-tests.yml)
[![Coverage report](https://github.com/stampbot/extra-codeowners/actions/workflows/coverage-pages.yml/badge.svg)](https://stampbot.github.io/extra-codeowners/)
[![CodeQL](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/stampbot/extra-codeowners/badge)](https://scorecard.dev/viewer/?uri=github.com/stampbot/extra-codeowners)
[![Documentation](https://readthedocs.org/projects/extra-codeowners/badge/?version=latest)](https://extra-codeowners.readthedocs.io/)
[![Python 3.12–3.14](https://img.shields.io/badge/python-3.12%E2%80%933.14-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Extra CODEOWNERS is a self-hosted GitHub App that lets a required check accept
either a human CODEOWNER approval or a narrowly delegated approval from another
GitHub App. People and teams stay in the standard `CODEOWNERS` file. App
identity and delegated authority live in separate policy.

> [!WARNING]
> Extra CODEOWNERS is pre-release software. Don't use it to enforce production
> merges yet. A public GitHub Container Registry (GHCR) preview exists, but it
> predates the current release controls and is not a supported deployable
> artifact. Don't deploy, mirror, or redistribute it. The
> [project status](docs/reference/project-status.md) records the enforcement
> and distribution blockers.

## The routine pull request that still needs a person

Suppose a platform team owns `uv.lock`.
[Stampbot](https://github.com/dannysauer/stampbot)'s repository policy allows
a routine dependency update, so Stampbot approves the current pull-request
head. GitHub's native code-owner rule still waits for a person: GitHub
documents `CODEOWNERS` entries for users and teams, not GitHub App bot
accounts.

Extra CODEOWNERS fills that gap with a required check:

```text
Human CODEOWNER approves the current head
                         \
                          -> Extra CODEOWNERS / approval succeeds
                         /
Enrolled App approves the current head
and policy covers its path and owner
```

For a regular pull request, the appropriate human approval satisfies the
check. For the delegated `uv.lock` update, the evaluator is designed to accept
Stampbot's approval. Local tests cover that decision, but the project has not
recorded a dated live GitHub run of the App-review and required-check contract.
A pull request that touches both delegated and undelegated code still needs
every effective owner set covered.

The check doesn't submit reviews, grant repository access, merge pull requests,
or replace any other repository rule. Keep the ordinary approval count,
stale-review behavior, signed-commit rules, and unrelated required checks.
GitHub's public contract does not say whether a third-party App review counts
toward the ordinary numeric approval rule; the project still needs a dated live
test for that behavior.

## Authority has two policy scopes

Your normal `CODEOWNERS` file continues to assign people and teams:

```text
/uv.lock @example-org/platform
```

The policy values below are deliberately fake.

Organization policy then enrolls the App by immutable identity and adds paths
where no enrolled App may stand in for a person:

```toml
schema_version = 1

[apps.example-automation]
slug = "example-automation"
app_id = 123456
bot_user_id = 234567

[guardrails]
non_delegable_paths = ["/infrastructure/production/**"]
```

Repository policy opts in one repository and grants a smaller alternative:

```toml
schema_version = 1
enabled = true

[[delegations]]
app = "example-automation"
paths = ["/uv.lock"]
for_owners = ["@example-org/platform"]
required_labels = ["dependencies"]
```

The organization scope answers “which App may ever qualify?” and “which paths
never accept App substitution?” The repository scope answers “which paths and
owners may this App cover here?” A repository can't enroll a new App or weaken
an organization guardrail.

The complete validated example is under
[`examples/policy/`](examples/policy/). The
[configuration guide](docs/how-to/configure.md) explains labels, path
patterns, built-in non-delegable files, and the process-wide insecure escape
hatch.

## What changes in GitHub

Extra CODEOWNERS is meant to replace one switch: **Require review from Code
Owners**. In a disposable test repository, keep the rest of the pull-request
rule and require `Extra CODEOWNERS / approval` from the Extra CODEOWNERS App as
the expected source.

That composition is not ready for production. GitHub Check Runs belong to
commits, while code-owner evidence belongs to a pull request. A second pull
request can briefly inherit a successful result attached to the same commit
before webhook processing revokes it.
[Issue #1](https://github.com/stampbot/extra-codeowners/issues/1) tracks the
live provider tests and the remaining safety work.

Read [why this uses a separate check](docs/explanation/native-codeowners.md)
before changing repository rules. Then follow the
[disposable-repository procedure](docs/how-to/prepare-repository-rules.md),
which includes rollback steps.

## Evaluate the source

There is intentionally no production install command yet. To inspect the code
and run its local test suite, use Bash from a clean checkout with Git and
[`mise`](https://mise.jdx.dev/) installed:

```bash
git clone https://github.com/stampbot/extra-codeowners.git
cd extra-codeowners
mise trust
mise install
mise run bootstrap
mise run test
```

Review `mise.toml` before `mise trust`. The commands record a local trust
decision, install pinned tools, and create `.venv/`; a successful run ends with
the test suite passing. They do not register a GitHub App or prove the live
GitHub contracts.

To publish a real check in a disposable organization, follow the
[first-check tutorial](docs/tutorials/development-installation.md). Keep native
code-owner enforcement on anywhere that matters.

## Find the right documentation

| If you want to… | Start here |
| --- | --- |
| Decide whether the trust model fits | [Native CODEOWNERS comparison](docs/explanation/native-codeowners.md) and [threat model](docs/explanation/threat-model.md) |
| See what is usable today | [Project status](docs/reference/project-status.md) |
| Run one check in a disposable organization | [First-check tutorial](docs/tutorials/development-installation.md) |
| Verify the non-required beta boundary | [Evaluation beta preflight](docs/how-to/preflight-evaluation-beta.md) |
| Register the App through its setup URL | [App registration guide](docs/how-to/register-app.md) |
| Enroll an App and delegate paths | [Configuration guide](docs/how-to/configure.md) |
| Diagnose a failed, pending, or missing check | [Check troubleshooting guide](docs/how-to/troubleshoot-check.md) |
| Review the service and security design | [Architecture](docs/explanation/architecture.md) and [checks reference](docs/reference/checks.md) |
| Evaluate future deployment and operations | [Deployment guide](docs/how-to/deploy.md) and [operations guide](docs/how-to/operate.md) |
| Contribute code or docs | [Contributor guide](CONTRIBUTING.md) |

The complete documentation is published on
[Read the Docs](https://extra-codeowners.readthedocs.io/).

## Community and project policy

- Ask for help under the [support policy](SUPPORT.md).
- Report vulnerabilities privately under the [security policy](SECURITY.md).
- Read the [governance](GOVERNANCE.md), [changelog](CHANGELOG.md), and
  [maintainer documentation](docs/maintainers/index.md).
- Extra CODEOWNERS is licensed under the [Apache License 2.0](LICENSE).
