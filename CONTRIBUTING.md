# Contributing to Extra CODEOWNERS

Extra CODEOWNERS is pre-1.0 security-sensitive infrastructure. Small,
well-tested changes are easier to review than broad changes that mix behavior,
refactoring, and documentation.

## Before you begin

- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- Search existing issues and pull requests before proposing duplicate work.
- Use a private vulnerability report instead of an issue for security findings;
  see [SECURITY.md](SECURITY.md).
- Open an issue before investing in a large feature or compatibility change.

## Prepare a development environment

You need Git, [mise](https://mise.jdx.dev/), and a POSIX-compatible shell. From
the repository root:

```shell
mise trust
mise install
mise run bootstrap
```

The last command installs dependencies exactly as recorded in `uv.lock`. A
successful run exits with status 0 and creates `.venv/`.

## Make and verify a change

Add tests for behavior changes, including failure and authorization boundaries.
Then run:

```shell
mise run format
mise run check
```

`mise run check` runs Python linting and type checking, tests, strict
documentation builds, workflow linting, and Helm linting. Its test task does not
enforce coverage, and PostgreSQL-specific integration tests are skipped unless
`TEST_POSTGRES_URL` points to a disposable test database. Run
`mise run test:coverage` with that variable set to execute the complete database
suite and enforce the project coverage threshold; follow the
[development installation tutorial][database-tests] for a safe setup. Never
point it at a production or shared database.
Docker is also needed to reproduce the container build performed in continuous
integration (CI):

```shell
docker build --tag extra-codeowners:dev .
```

Do not paste real GitHub payloads, credentials, organization identifiers, or
private repository content into tests. Use clearly fictional fixtures.

## Sign off commits

This project uses the [Developer Certificate of Origin][dco], not a contributor
license agreement. Sign off every commit:

```shell
git commit --signoff
```

The sign-off records that you have the right to submit the contribution under
the project's license. It is separate from cryptographic commit signing.

## Open a pull request

Open the pull request ready for review and complete its checklist. Explain the
security and operational effects, add or update documentation, and call out any
compatibility change. Maintainers may ask for commits to be reorganized before
merge so that the history remains reviewable.

All required checks and reviews must pass. Application approvals cannot replace
human CODEOWNER review for changes to `CODEOWNERS`, Extra CODEOWNERS policy, or
GitHub Actions workflows or repository-local actions under `.github/actions/`
unless an operator has explicitly enabled the documented insecure override.

## Review priorities

Reviewers consider these properties in order:

1. authorization and fail-closed behavior;
2. correctness under retries, stale events, and concurrent updates;
3. test evidence and operational recoverability;
4. compatibility and configuration migration; and
5. maintainability and documentation.

[dco]: https://developercertificate.org/
[database-tests]: docs/tutorials/development-installation.md#7-run-the-project-checks
