# Contributing to Extra CODEOWNERS

Extra CODEOWNERS participates in pull-request authorization. Keep changes small enough for a reviewer to follow, and don't mix new behavior with an unrelated refactor.

## Before you begin

- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- Search existing issues and pull requests before proposing duplicate work.
- Use a private vulnerability report for security findings. See [SECURITY.md](SECURITY.md).
- Open an issue before investing in a large feature or compatibility change.

## Prepare a development environment

You need Git, [mise](https://mise.jdx.dev/), and a POSIX-compatible shell. Run these commands from the repository root:

```shell
mise trust
mise install
mise run bootstrap
```

The last command installs dependencies exactly as recorded in `uv.lock`. It exits with status 0 and creates `.venv/`.

## Make and verify a change

Add tests for behavior changes. Cover failure paths and authorization boundaries, then run:

```shell
mise run format
mise run check
```

`mise run check` runs:

- Python linting and type checking
- the locally available tests
- the strict documentation build
- workflow and YAML linting
- Helm linting and rendering

It does not enforce coverage. PostgreSQL tests are skipped unless `TEST_POSTGRES_URL` points to a disposable test database.

Set that variable and run `mise run test:coverage` for the complete suite and coverage gate. The [development installation tutorial][database-tests] shows a safe setup.

The normal suite runs the bounded development property-test profile. Run
`mise run test:property` to match the larger pull-request profile. See the
[property-testing design](docs/explanation/property-testing.md) before adding a
generator or regression seed; generated inputs and CI reports must remain free
of real payloads and credentials.

> [!WARNING]
> Never point `TEST_POSTGRES_URL` at a production or shared database. The test suite drops and recreates project tables.

Docker is required to build the Dockerfile locally:

```shell
docker build --tag extra-codeowners:dev .
```

The live GitHub contract fixture is destructive and opt-in. It is not part of
`mise run check`. Use only the disposable organization procedure in the
[live-contract guide](docs/how-to/run-live-github-contract.md); ordinary tests
must never need GitHub credentials.

Do not paste real GitHub payloads, credentials, organization identifiers, or
private repository content into tests. Use clearly fictional fixtures.

Database schema changes require an explicit Alembic revision, fresh-install
and previous-revision upgrade tests, PostgreSQL concurrency or interruption
coverage where relevant, and a versioned entry in
[`docs/reference/upgrade-notes.md`](docs/reference/upgrade-notes.md). Normal
application startup must remain migration-free.
Every Alembic head change is a restore boundary: document and test the backup
restore path rather than claiming an additive migration permits an old-image
rollback.

## Sign off commits

This project uses the [Developer Certificate of Origin][dco], not a contributor license agreement. Sign off every commit:

```shell
git commit --signoff
```

The sign-off says you have the right to submit the contribution under the project's license. It is separate from cryptographic commit signing.

The only alternate identity accepted by CI is GitHub's canonical
`dependabot[bot] <support@github.com>` trailer on an official, same-repository
Dependabot update. CI verifies the bot account, branch and repository identity,
single-commit history, parent and head SHAs, author and committer identities,
and GitHub signature before accepting that trailer. This narrow exception is
DCO handling only; it does not approve or authorize the dependency change.

## Open a pull request

Open the pull request ready for review and complete its checklist. Explain the security and operational effects. Update the documentation and call out compatibility changes.

Maintainers may ask you to reorganize commits when that makes the history easier to review.

All required checks and reviews must pass. By default, application approvals cannot replace human CODEOWNER review for:

- `CODEOWNERS`
- Extra CODEOWNERS policy
- GitHub Actions workflows
- local actions under `.github/actions/`

The documented insecure override removes that built-in restriction for operators who explicitly accept the risk.

## Review priorities

Reviewers consider these properties in order:

1. authorization and fail-closed behavior
2. correctness under retries, stale events, and concurrent updates
3. test evidence and operational recoverability
4. compatibility and configuration migration
5. maintainability and documentation

[dco]: https://developercertificate.org/
[database-tests]: docs/tutorials/development-installation.md#7-run-the-project-checks
