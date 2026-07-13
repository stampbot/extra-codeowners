# Extra CODEOWNERS

[![CI](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/ci.yml)
[![Coverage report](https://github.com/stampbot/extra-codeowners/actions/workflows/coverage-pages.yml/badge.svg)](https://stampbot.github.io/extra-codeowners/)
[![CodeQL](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml/badge.svg)](https://github.com/stampbot/extra-codeowners/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/stampbot/extra-codeowners/badge)](https://scorecard.dev/viewer/?uri=github.com/stampbot/extra-codeowners)
[![Documentation](https://readthedocs.org/projects/extra-codeowners/badge/?version=latest)](https://extra-codeowners.readthedocs.io/)
[![Python 3.12–3.14](https://img.shields.io/badge/python-3.12%E2%80%933.14-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Extra CODEOWNERS is a GitHub App that lets a trusted application satisfy code-owner policy for explicitly delegated files. It is intended for repositories where automation such as [Stampbot](https://github.com/dannysauer/stampbot) can approve routine, constrained changes while ordinary changes still require a human code owner.

> [!IMPORTANT]
> Extra CODEOWNERS is in early development. There is no supported hosted service, release, or Marketplace Action yet. The documentation describes the security contract being implemented; interfaces may change before the first release.

GitHub's native **Require review from Code Owners** rule does not treat an application account as a valid entry in `CODEOWNERS`. Extra CODEOWNERS leaves the standard file unchanged, evaluates human reviews and separately configured application delegations, then publishes the `Extra CODEOWNERS / approval` check.

## Why use it?

Use Extra CODEOWNERS when all of these are true:

- human ownership is already expressed in the standard `CODEOWNERS` file;
- an installed application has a narrow, auditable reason to approve some paths;
- application authority must be limited by path, owner group, and optionally labels; and
- repository rules must continue to require the ordinary numeric review count and other checks.

Extra CODEOWNERS does not grant an application write access, approve a pull request, or change `CODEOWNERS` syntax. It only evaluates existing reviews and publishes a check result.

Enrollment is explicit at both levels: organization policy defines which applications may ever be trusted, and each target repository must add its own enabled policy before Extra CODEOWNERS begins publishing checks. Organization configuration alone does not enroll every repository.

## Repository rules

Keep the ordinary minimum approval count and any desired stale-review or latest-push rules. Disable only GitHub's native **Require review from Code Owners** rule, then require `Extra CODEOWNERS / approval` from the Extra CODEOWNERS App as an expected source.

> [!WARNING]
> Before removing a target or organization-policy repository from the App, suspending an installation, or uninstalling the App, restore GitHub's native code-owner requirement and remove Extra CODEOWNERS as a required expected-source check from every affected target. Removing the policy repository triggers conservative fencing for targets that remain accessible, but after target access is gone the App cannot revoke an earlier success. This project does not assume GitHub invalidates it.

This produces the intended conjunction:

```text
ordinary required approvals
AND (human code-owner approval OR an eligible application approval for every owned path)
AND all other required checks
```

> [!CAUTION]
> GitHub Check Runs are commit-scoped, but code-owner evidence is pull-request-scoped. Extra CODEOWNERS refuses success when it sees the same head on multiple open pull requests. A new or retargeted pull request created after success can nevertheless inherit that commit's result until GitHub delivers the new event and the service moves the check back to `in_progress`. This preview limitation is not equivalent to native code-owner enforcement and must not protect production merges.

Application delegation is disabled by default for `CODEOWNERS`, the effective repository-policy path (`.github/extra-codeowners.toml` under default settings), Stampbot's root `/stampbot.toml`, GitHub Actions workflows, and repository-local actions under `.github/actions/`. The deployment-wide `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` escape hatch removes only those built-in protections and emits a prominent warning. It does not create a delegation or bypass any organization-defined restriction. See the [threat model](docs/explanation/threat-model.md#insecure-changes-escape-hatch) before enabling it.

## Local development

From the repository root on a POSIX-compatible system:

```bash
mise install
uv sync --all-groups
uv run python -m extra_codeowners serve
```

The development server listens on `127.0.0.1:8000`. In another terminal, verify it is alive:

```bash
curl --fail-with-body http://127.0.0.1:8000/health/live
```

This starts the service for local inspection. Functional GitHub processing also requires an App ID, private key, webhook secret, and public HTTPS URL. Follow the [development installation tutorial](docs/tutorials/development-installation.md) for that setup. Run the fast local quality gate with `mise run check`; the tutorial also shows the PostgreSQL-backed coverage task.

Use the checked-in [`.env.example`](.env.example) as the safe starting point for local runtime configuration; keep real credentials out of Git.

## Documentation

- [Start with a development installation](docs/tutorials/development-installation.md)
- [Register an App with the setup URL](docs/how-to/register-app.md)
- [Configure organizations and repositories](docs/how-to/configure.md)
- [Prepare repository rules](docs/how-to/prepare-repository-rules.md)
- [Deploy the service](docs/how-to/deploy.md)
- [Operate and recover the service](docs/how-to/operate.md)
- [Configuration reference](docs/reference/configuration.md)
- [Checks and evaluation reference](docs/reference/checks.md)
- [Command-line reference](docs/reference/cli.md)
- [GitHub permissions and events](docs/reference/github-permissions.md)
- [HTTP API reference](docs/reference/http-api.md)
- [Architecture](docs/explanation/architecture.md)
- [Threat model](docs/explanation/threat-model.md)
- [Helm chart](charts/extra-codeowners/README.md) (preview source; not published)
- [Support](SUPPORT.md), [security reporting](SECURITY.md), [contributing](CONTRIBUTING.md), [governance](GOVERNANCE.md), [code of conduct](CODE_OF_CONDUCT.md), [changelog](CHANGELOG.md), and [license](LICENSE)

## Project shape

This repository contains the GitHub App, the shared policy evaluator intended to support future distributions, and the initial Helm chart source. Python imports are not a stable public API before 1.0. A separate `extra-codeowners-action` repository is on the roadmap for users who need a workflow-based deployment backed by a prebuilt, signed container. The Action does not exist yet and is not required by the App design.
