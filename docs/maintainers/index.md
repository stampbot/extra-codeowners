# Maintainer and release engineering

These pages support people who maintain Extra CODEOWNERS itself. They describe
CI evidence, release candidates, dependency review, and publication controls.
You don't need them to configure a repository or understand a pull-request
check.

There is no supported release today. The release pages describe controls that
must pass before one can exist; they do not approve current CI artifacts for
distribution.

## Release readiness

- [Current project status](../reference/project-status.md)
- [Prepare a future deployment](../how-to/deploy.md)
- [Container distribution evidence](../explanation/container-distribution-evidence.md)
- [Container evidence policy](../reference/container-evidence-policy.md)
- [Container evidence release contract](../reference/container-evidence-release-contract.md)
- [Runtime base image decision](../explanation/runtime-base.md)

## Review and incident procedures

- [Review pull-request container evidence](../how-to/review-container-evidence.md)
- [Respond to a dependency audit](../how-to/respond-to-dependency-audit.md)
- [Review stacked pull requests](../how-to/review-stacked-pull-requests.md)
- [Update the tutorial webhook relay](update-tutorial-relay.md)

## Publication and contributor controls

- [Raw OCI release-spine format](../reference/release-spine-format.md)
- [Raw Python distribution spine](../reference/python-distribution-spine-format.md)
- [GitHub release API adapter](../reference/github-release-api-adapter.md)
- [Immutable-release preflight](../reference/immutable-release-preflight.md)
- [Immutable release controller contract](../reference/immutable-release-controller.md)
- [DCO evidence contract](../reference/dco-evidence.md)
