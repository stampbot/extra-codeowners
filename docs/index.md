# Extra CODEOWNERS documentation

Extra CODEOWNERS evaluates whether each owned path in a pull request has been approved by either an appropriate human code owner or an explicitly delegated GitHub App. It publishes the result as a GitHub Check Run so repositories can replace only GitHub's native code-owner-review rule while retaining ordinary review counts and other protections.

> **Project status:** early development. No production release or hosted installation is available. Pages that describe an unshipped interface say so explicitly.

**Production blocker:** GitHub Check Runs are commit-scoped while this policy is pull-request-scoped. See [eventual consistency](reference/checks.md#eventual-consistency).

## Choose your task

If you are evaluating the project:

- Read [how Extra CODEOWNERS differs from native CODEOWNERS](explanation/native-codeowners.md).
- Review the [architecture](explanation/architecture.md) and [threat model](explanation/threat-model.md).
- Check the [GitHub permissions](reference/github-permissions.md) before installing an App build.

If you are trying the development version:

- Follow the [development installation tutorial](tutorials/development-installation.md).
- [Register a development App with the setup URL](how-to/register-app.md).
- [Configure an organization and repository](how-to/configure.md).
- [Prepare repository rules](how-to/prepare-repository-rules.md).

If you operate a deployment:

- Use the [deployment guide](how-to/deploy.md).
- Use the [operations and recovery guide](how-to/operate.md).
- Consult the [checks](reference/checks.md), [configuration](reference/configuration.md), and [HTTP API](reference/http-api.md) references.

## Security boundary in one paragraph

`CODEOWNERS` remains the source of human ownership. Organization policy enrolls trusted applications by immutable identifiers; repository policy delegates paths to those applications. The evaluator reads pull-request policy from the exact base commit, accepts approvals only for the current head commit, evaluates both names of a renamed file, and fails closed when required evidence is incomplete. For sensitive paths that `CODEOWNERS` assigns to humans, built-in non-delegable rules prevent application substitution unless the operator deliberately enables the deployment-wide insecure-changes escape hatch.

## Roadmap boundaries

The GitHub App is the first deliverable. The repository includes preview Helm chart and App Manifest setup code, but neither has a supported published release. A separately packaged Marketplace Action and public hosted service remain roadmap distribution options.

## Project help

Use the repository's [support policy](https://github.com/stampbot/extra-codeowners/blob/main/SUPPORT.md) for questions and operational incidents. Report security issues through the [private security policy](https://github.com/stampbot/extra-codeowners/security/policy), never through a public issue or discussion. Contributions follow the [contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md).
