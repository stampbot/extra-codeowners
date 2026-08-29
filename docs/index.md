# Extra CODEOWNERS

Extra CODEOWNERS lets a repository accept either a human CODEOWNER approval or
an approval from a trusted GitHub App for selected pull-request paths. It is
built for teams whose automation, such as
[Stampbot](https://github.com/dannysauer/stampbot), already has its own policy
for approving routine work.

GitHub's normal `CODEOWNERS` file still names people and teams. Extra
CODEOWNERS adds a required check and a separate delegation policy for Apps.
Regular pull requests keep going to their human owners.

!!! warning "Use a disposable environment"

    Extra CODEOWNERS is pre-release software. An alpha artifact is for
    non-required, shadow-mode testing, not production enforcement or supported
    distribution. Legacy preview images — `:main` and its `sha-*` and
    `sha256-*` companion tags — are unsupported and unsafe for deployment.
    Don't deploy, mirror, or redistribute them. Read the
    [project status](reference/project-status.md) before testing the App.

## Start with the decision

Before you register anything, make sure this is the rule you want. Extra
CODEOWNERS evaluates each distinct effective owner set separately. For each
owner set, the `Extra CODEOWNERS / approval` check accepts either:

- an appropriate human CODEOWNER approves the current head
- an enrolled App approves the current head and its delegation matches the
  changed paths and owners.

Every owner set must pass. A pull request may use human evidence for one set
and App evidence for another. Paths with no effective `CODEOWNERS` match create
no code-owner requirement.

The check is meant to replace GitHub's **Require review from Code Owners**
switch. It doesn't replace your minimum approval count, stale-review setting,
signed-commit policy, or other required checks.

GitHub doesn't publicly promise that a third-party App review counts toward
the ordinary approval minimum. A nonzero minimum may therefore keep a pull
request blocked after the Extra CODEOWNERS check succeeds. Test that combination
in a disposable repository before relying on it.

Read the [native CODEOWNERS comparison](explanation/native-codeowners.md) for
the full decision model. The [threat model](explanation/threat-model.md)
explains what the App trusts and where it fails closed.

## Try one check

Choose one setup path. The
[first-check tutorial](tutorials/development-installation.md) manually creates
the checker App, starts from a clean checkout, and ends with a real Check Run in
a disposable organization. It uses a human approval first, which separates App
setup problems from delegation problems.

If you prefer GitHub's App Manifest flow, use the
[App Manifest registration guide](how-to/register-app.md) instead of the tutorial's
manual registration steps.

After the first check works, continue with the pieces you need:

1. [Enroll an approving App and delegate paths](how-to/configure.md).
2. [Run the live GitHub contract fixture](how-to/run-live-github-contract.md).
3. [Exercise the replacement rule and its rollback](how-to/prepare-repository-rules.md).

Keep GitHub's native code-owner rule enabled on production repositories. The
[project status](reference/project-status.md) names the live contracts that
are still open.

## Configure policy

Policy administrators work with two files:

- organization policy enrolls Apps by immutable identity and sets guardrails
- repository policy opts in and grants narrower path-and-owner delegations

A repository can narrow organization policy, but it can't enroll a new App or
weaken an organization guardrail. Start with the
[configuration guide](how-to/configure.md), then use the
[configuration reference](reference/configuration.md) for field types,
defaults, limits, and validation errors.

## Diagnose and operate

If a Check Run is missing, pending, or failed, start with
[Troubleshoot a check](how-to/troubleshoot-check.md). It follows the text
shown in GitHub and says when an operator needs to step in.

The repository also contains deployment and operations guides:

- [deploy an alpha in shadow mode](how-to/deploy.md)
- [upgrade, back up, and restore](how-to/upgrade.md)
- [operate and recover](how-to/operate.md)
- [review the architecture](explanation/architecture.md).

Alpha images and chart packages are available for shadow-mode testing. They
aren't a production-readiness claim, and there is no hosted deployment.

## Look up exact behavior

Reference pages describe the current contract:

- [project status](reference/project-status.md)
- [checks and evaluation](reference/checks.md)
- [configuration](reference/configuration.md)
- [command line](reference/cli.md)
- [GitHub permissions and webhook events](reference/github-permissions.md)
- [HTTP API](reference/http-api.md).

Maintainers and contributors should start at the
[maintainer index](maintainers/index.md). It collects release evidence,
supply-chain controls, dependency review, and live-contract procedures. The
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md)
covers local development and pull-request requirements.

## Get help

Use the repository's
[support policy](https://github.com/stampbot/extra-codeowners/blob/main/SUPPORT.md)
for questions and operational incidents. Report vulnerabilities through the
[private security policy](https://github.com/stampbot/extra-codeowners/security/policy),
not through a public issue.
