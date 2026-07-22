# Extra CODEOWNERS documentation

Extra CODEOWNERS lets a human code owner or a specifically enrolled GitHub App
satisfy ownership for selected files. Human ownership stays in the standard
`CODEOWNERS` file. App identity and delegated paths live in separate policy.

The service evaluates the current pull request and publishes one GitHub Check
Run. It does not submit reviews or grant applications new repository access.

!!! warning "Development and test use only"

    Extra CODEOWNERS is not ready to replace GitHub's native code-owner rule on
    a production repository. A Check Run belongs to a commit, while the
    evidence used here belongs to one pull request. Read the
    [current project status](reference/project-status.md) before installing or
    testing the App.

## Start with your task

### Evaluate the idea

Read [the native CODEOWNERS comparison](explanation/native-codeowners.md) for
the problem and intended repository-rule composition. Then use the
[threat model](explanation/threat-model.md) to decide whether the trust split
fits your repository.

The short version is:

1. `CODEOWNERS` names people and teams.
2. Organization policy enrolls an App by immutable GitHub identity.
3. Repository policy delegates paths, owners, and optional label conditions.
4. An existing human or eligible App approval can satisfy each owner set.

### Build a development installation

Follow the [development installation tutorial](tutorials/development-installation.md).
It starts the service, connects a disposable GitHub App, and exercises one
delegated pull request.

When you already have a running development service, use the focused guides:

- [Register an App with the setup URL](how-to/register-app.md)
- [Configure organization and repository policy](how-to/configure.md)
- [Prepare repository rules in a disposable repository](how-to/prepare-repository-rules.md)
- [Run the live GitHub contract fixture](how-to/run-live-github-contract.md).

### Plan a future deployment

There is no supported image or chart release yet. If you are planning an
evaluation, start with the [future-deployment guide](how-to/deploy.md) to see
what is implemented and what remains blocked. The
[operations and recovery guide](how-to/operate.md) and
[upgrade guide](how-to/upgrade.md) document the contracts a future deployment
must satisfy; they are not a production-readiness claim.

### Look up exact behavior

Use the reference pages when you need a field, limit, permission, route, or
failure state:

- [configuration](reference/configuration.md)
- [checks and evaluation](reference/checks.md)
- [command line](reference/cli.md)
- [GitHub permissions and events](reference/github-permissions.md)
- [HTTP API](reference/http-api.md)
- [project status](reference/project-status.md).

The container-evidence pages document review and release work that remains
blocked. They describe evidence and safety requirements; they do not mark the
current candidates as distributable.

### Understand the design

The [architecture](explanation/architecture.md) follows a webhook from receipt
through durable work and reconciliation. The other explanation pages cover
the choices behind database migrations, property tests, the runtime base, and
container evidence.

## Get help or contribute

Use the repository's [support policy](https://github.com/stampbot/extra-codeowners/blob/main/SUPPORT.md)
for questions and operational incidents. Report vulnerabilities through the
[private security policy](https://github.com/stampbot/extra-codeowners/security/policy),
not through a public issue. The
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md)
explains local checks, commit sign-off, and pull-request expectations.
