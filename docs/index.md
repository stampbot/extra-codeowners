# Extra CODEOWNERS documentation

Your dependency automation already knows when a pull request is routine.
[Stampbot](https://github.com/dannysauer/stampbot) may approve a trusted
`uv.lock` update after its own rules pass, but GitHub's native code-owner
setting still expects a person or team from `CODEOWNERS`.

Extra CODEOWNERS publishes an alternative required check. It accepts a
current-head approval from an appropriate human, or a current-head approval
from an enrolled GitHub App when policy delegates that path and owner to the
App. A regular pull request still goes to its human owners. The evaluator
implements both paths, but the project has not recorded a dated live GitHub run
of the App-review and required-check contract.

!!! warning "Pre-release: evaluate only in a disposable environment"

    Extra CODEOWNERS is not ready to enforce production merges. A public GitHub
    Container Registry (GHCR) preview exists, but it predates the current
    release controls and is not a supported deployable artifact. Don't deploy,
    mirror, or redistribute it. Read the
    [current project status](reference/project-status.md) before you register
    or test the App.

## Understand the boundary first

The existing `CODEOWNERS` file keeps its people and teams. Extra CODEOWNERS
adds two policy scopes:

- Organization policy enrolls Apps by immutable identity and names paths where
  App substitution is never accepted.
- Repository policy opts in one repository and delegates narrower paths,
  owner sets, and optional label restrictions.

The repository can't enroll a new App or weaken an organization guardrail.
The [native CODEOWNERS comparison](explanation/native-codeowners.md) walks
through the complete decision and the GitHub rule it is meant to replace. The
[threat model](explanation/threat-model.md) covers the trust and failure
boundaries.

## Choose your route

### Repository administrator evaluating the idea

Start with these pages, in order:

1. [Compare native CODEOWNERS with the extra check](explanation/native-codeowners.md).
2. [Check what is implemented and what is still blocked](reference/project-status.md).
3. [Run the first check in a disposable organization](tutorials/development-installation.md).
4. [Preflight the non-required evaluation beta](how-to/preflight-evaluation-beta.md).
5. [Exercise the replacement repository rule and its rollback](how-to/prepare-repository-rules.md).

The live GitHub contracts are not all proven. Keep GitHub's native **Require
review from Code Owners** rule on production repositories.

### Policy administrator

Use the [configuration guide](how-to/configure.md) to enroll an App, delegate
low-risk paths, and test the human-only boundary. The
[configuration reference](reference/configuration.md) lists every field,
default, limit, and failure mode.

### Developer testing the App

The [first-check tutorial](tutorials/development-installation.md) starts with a
clean checkout and ends with a real Check Run on a disposable pull request. It
uses a human approval first, so you can isolate the checker from the approving
App.

If you already have a development service:

- [register a GitHub App with the setup URL](how-to/register-app.md)
- [configure both policy scopes](how-to/configure.md)
- [run the live GitHub contract fixture](how-to/run-live-github-contract.md).

### Operator reviewing a future deployment

There is no supported image, chart package, or production deployment today.
The current source still defines useful contracts for review:

- [prepare a future deployment](how-to/deploy.md)
- [upgrade, back up, and restore](how-to/upgrade.md)
- [operate and recover](how-to/operate.md)
- [review the architecture](explanation/architecture.md).

These pages describe the source and the intended operating boundary. They
aren't a release or production-readiness claim.

### Maintainer or contributor

The [maintainer index](maintainers/index.md) collects release evidence,
supply-chain controls, dependency review, and live-contract work. For local
development and pull-request requirements, use the repository's
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md).

## Look up exact behavior

Use reference pages when you need the contract rather than a walkthrough:

- [checks and evaluation](reference/checks.md)
- [configuration](reference/configuration.md)
- [command line](reference/cli.md)
- [GitHub permissions and webhook events](reference/github-permissions.md)
- [HTTP API](reference/http-api.md)
- [project status](reference/project-status.md).

For a failed, pending, or missing Check Run, start with
[Troubleshoot a check](how-to/troubleshoot-check.md). It follows the text shown
in GitHub and tells you when an operator needs to intervene.

## Get help

Use the repository's
[support policy](https://github.com/stampbot/extra-codeowners/blob/main/SUPPORT.md)
for questions and operational incidents. Report vulnerabilities through the
[private security policy](https://github.com/stampbot/extra-codeowners/security/policy),
not through a public issue.
