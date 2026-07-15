# Extra CODEOWNERS

[![CI](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml)
[![Property testing](https://github.com/stampbot/extra-codeowners/actions/workflows/property-tests.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/property-tests.yml)
[![Coverage report](https://github.com/stampbot/extra-codeowners/actions/workflows/coverage-pages.yml/badge.svg)](https://stampbot.github.io/extra-codeowners/)
[![CodeQL](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/stampbot/extra-codeowners/badge)](https://scorecard.dev/viewer/?uri=github.com/stampbot/extra-codeowners)
[![Documentation](https://readthedocs.org/projects/extra-codeowners/badge/?version=latest)](https://extra-codeowners.readthedocs.io/)
[![Python 3.12–3.14](https://img.shields.io/badge/python-3.12%E2%80%933.14-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Routine automation can know that a pull request is safe while GitHub's code-owner rule still waits for a person. Extra CODEOWNERS adds a separate required check so a human or an enrolled GitHub App can satisfy ownership for specific files.

[Stampbot](https://github.com/dannysauer/stampbot) is the first integration. A repository might let it approve a routine lockfile update, for example, while a human still has to approve application code.

> [!IMPORTANT]
> The self-hosted App and its documentation are available, and the repository
> includes Helm chart source. The `main` publication job has been removed, and
> tagged publication is blocked. [Source-completeness issue #18](https://github.com/stampbot/extra-codeowners/issues/18)
> covers CPython normalization, native-wheel and embedded-SBOM expansion, and
> historical Python `RECORD` replay.
> [Hash-pinned build isolation](https://github.com/stampbot/extra-codeowners/issues/32)
> and
> [publication privilege separation](https://github.com/stampbot/extra-codeowners/issues/28)
> also remain open. An [older public GHCR preview](https://github.com/stampbot/extra-codeowners/issues/30)
> may still be discoverable; it is unsupported, incomplete, and must not be
> deployed or mirrored. There is no hosted service or Marketplace Action. The
> [commit-scoped check limitation](#the-current-production-blocker) must also be
> resolved before this check can replace GitHub's code-owner rule on production
> repositories.

GitHub doesn't accept an App's bot account as a valid owner in `CODEOWNERS`. Keep the standard file for people and teams. Extra CODEOWNERS reads it alongside a separate policy for applications, then publishes `Extra CODEOWNERS / approval`.

## Why use it?

Extra CODEOWNERS fits a repository when:

- human ownership is already expressed in the standard `CODEOWNERS` file
- an installed application has a narrow, auditable reason to approve some paths
- application authority must be limited by path, owner group, and optional labels
- repository rules must continue to require the ordinary numeric review count and other checks

The checker does not approve pull requests or grant write access. It evaluates reviews that already exist and publishes one check result.

Trust has two gates. Organization policy enrolls an application by its App ID, bot user ID, and slug. Each repository then opts in and delegates paths to one of those enrolled applications. Organization policy alone never opts in a repository.

## Repository rules

While the [commit-scoped check limitation](#the-current-production-blocker) remains open, keep GitHub's native code-owner rule on production repositories. Test the following composition only in a disposable repository.

In that repository, keep the ordinary approval count and any stale-review or latest-push rules you use. Disable only **Require review from Code Owners**, then require `Extra CODEOWNERS / approval` from the Extra CODEOWNERS App as the expected source.

> [!WARNING]
> Restore GitHub's native code-owner rule before you suspend or uninstall the App, or remove a repository from its installation. Remove the Extra CODEOWNERS required check from every affected repository as well. Once the App loses access, it may be unable to revoke an earlier success.

The repository rules now require:

```text
ordinary required approvals
AND (human code-owner approval OR an eligible application approval for every owned path)
AND all other required checks
```

## The current production blocker

GitHub stores a Check Run on a commit. Extra CODEOWNERS makes its decision from pull-request evidence such as the base branch, labels, changed paths, and reviews.

The service refuses success when it can already see two open pull requests with the same head commit. It cannot stop a second pull request from appearing after a success was published. That pull request can inherit the old result until GitHub delivers its event and the service moves the check back to `in_progress`.

This gap is [tracked as a release blocker](https://github.com/stampbot/extra-codeowners/issues/1). Keep GitHub's native code-owner rule on production repositories until the live contract test and design work close it.

## Files that applications cannot approve

By default, an application cannot satisfy ownership for:

- any supported `CODEOWNERS` file
- the repository's Extra CODEOWNERS policy
- `/stampbot.toml`
- workflows under `.github/workflows/`
- local actions under `.github/actions/`

These files can still mention or invoke applications. "Cannot approve" describes the review path, not the file contents.

`EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` removes this built-in list for every installation served by the process. It emits a warning and a metric. Organization guardrails still apply. Read the [threat model](docs/explanation/threat-model.md#insecure-changes-escape-hatch) before you enable it.

## Run it locally

Install Git and [mise](https://mise.jdx.dev/) on a POSIX-compatible system. From the repository root, run:

```bash
mise trust
mise install
mise run bootstrap
mise exec -- uv run python -m extra_codeowners database migrate
mise exec -- uv run python -m extra_codeowners serve
```

The development server listens on `127.0.0.1:8000`. In another terminal, verify it is alive:

```bash
curl --fail-with-body http://127.0.0.1:8000/health/live
```

This starts the service for local inspection. GitHub processing also needs a configured App and a public HTTPS URL. The App configuration includes its ID, private key, and webhook secret. The [development installation tutorial](docs/tutorials/development-installation.md) walks through that setup.

Run the local quality gate with:

```bash
mise run check
```

The tutorial also covers the PostgreSQL-backed coverage suite.

Start runtime configuration from [`.env.example`](.env.example). Keep real credentials out of Git.

## Documentation

- [Start with a development installation](docs/tutorials/development-installation.md)
- [Register an App with the setup URL](docs/how-to/register-app.md)
- [Configure organizations and repositories](docs/how-to/configure.md)
- [Prepare repository rules](docs/how-to/prepare-repository-rules.md)
- [Run the live GitHub contract fixture](docs/how-to/run-live-github-contract.md)
- [Deploy the service](docs/how-to/deploy.md)
- [Operate and recover the service](docs/how-to/operate.md)
- [Review CI container evidence](docs/how-to/review-container-evidence.md)
- [Container evidence policy reference](docs/reference/container-evidence-policy.md)
- [Understand the future release evidence contract](docs/reference/container-evidence-release-contract.md)
- [Configuration reference](docs/reference/configuration.md)
- [Checks and evaluation reference](docs/reference/checks.md)
- [Command-line reference](docs/reference/cli.md)
- [GitHub permissions and events](docs/reference/github-permissions.md)
- [HTTP API reference](docs/reference/http-api.md)
- [Architecture](docs/explanation/architecture.md)
- [Threat model](docs/explanation/threat-model.md)
- [Container distribution evidence design](docs/explanation/container-distribution-evidence.md)
- [Property testing of untrusted inputs](docs/explanation/property-testing.md)
- [Helm chart](charts/extra-codeowners/README.md) (source only; no released OCI chart yet)
- [Support](SUPPORT.md) and [security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md), [governance](GOVERNANCE.md), and the [code of conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md) and [license](LICENSE)

## Project shape

This repository contains the GitHub App, its policy evaluator, and the Helm chart source. Python imports are not a stable public API before 1.0.

A separate `extra-codeowners-action` distribution is [planned](https://github.com/stampbot/extra-codeowners/issues/2) for repositories that cannot run an App service. It does not exist yet.
