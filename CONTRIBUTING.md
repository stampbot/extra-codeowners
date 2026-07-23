# Contributing to Extra CODEOWNERS

Extra CODEOWNERS participates in pull-request authorization. Keep each change
small enough to review, and leave unrelated refactoring for another pull
request.

## Before you begin

- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- Search existing issues and pull requests before proposing duplicate work.
- Use a private vulnerability report for security findings. See
  [SECURITY.md](SECURITY.md).
- Open an issue before investing in a large feature or compatibility change.

## Prepare a development environment

You need Git, [mise](https://mise.jdx.dev/), and a POSIX-compatible shell.
Review the checked-out revision and `mise.toml` before trusting it:

```shell
git status --short
git log -1 --oneline --show-signature
less mise.toml
```

`mise trust` permits repository configuration and tasks to execute locally.
Once the files match the revision you intended to run, continue from the
repository root:

```shell
mise trust
mise install
mise run bootstrap
```

The last command installs the dependencies recorded in `uv.lock` and creates
`.venv/`.

## Make and verify a change

Add tests for behavior changes. Cover failure paths and authorization
boundaries, then run:

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

It does not enforce coverage. PostgreSQL tests are skipped unless
`TEST_POSTGRES_URL` points to a disposable test database.

Set that variable and run `mise run test:coverage` for the complete suite and
coverage gate. The database name must end in `_test`; the test runner rejects
other names before it changes the schema.

The normal suite runs the bounded development property-test profile. Run
`mise run test:property` to match the larger pull-request profile. See the
[property-testing design](docs/explanation/property-testing.md) before adding a
generator or regression seed; generated inputs and CI reports must remain free
of real payloads and credentials.

> [!WARNING]
> Never point `TEST_POSTGRES_URL` at a production or shared database. The test
> suite drops and recreates project tables.

The Dockerfile intentionally rejects an ad hoc `docker build .`. It installs
only the exact application wheel selected by the cross-architecture Python
proof, passed as a read-only `verified-python` build context with three digest
arguments. Pull-request CI is the maintained way to create that proof and test
both image platforms. Follow the
[container-evidence review guide](docs/how-to/review-container-evidence.md) if
your change affects the image or its evidence; do not substitute a locally
built wheel and treat the result as equivalent release evidence.

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

This project uses the [Developer Certificate of Origin][dco], not a
contributor license agreement. Sign off every commit:

```shell
git commit --signoff
```

The sign-off says you have the right to submit the contribution under the
project's license. It is separate from cryptographic commit signing.

The only alternate identity accepted by CI is GitHub's canonical
`dependabot[bot] <support@github.com>` trailer on an official, same-repository
Dependabot update. CI verifies the bot account, branch and repository identity,
single-commit history, parent and head SHAs, author and committer identities,
and GitHub signature before accepting that trailer. This narrow exception is
DCO handling only; it does not approve or authorize the dependency change.

## Open a pull request

Open the pull request ready for review and complete its checklist. Explain the
security and operational effects. Update the documentation and call out
compatibility changes.

Maintainers may ask you to reorganize commits when that makes the history
easier to review.

Stacked pull requests receive the DCO, CodeQL, dependency-review, and
workflow-security checks even when they target another feature branch. Merge
the stack from the bottom. After a parent is squash-merged or rebase-merged,
rebase each child onto the new `main` while dropping the original parent commit
range. Either merge method can give those changes new commit IDs.

Retarget the child, push rewritten history with `--force-with-lease`, and wait
for required checks on that exact SHA. Follow the
[stacked pull-request review procedure](docs/how-to/review-stacked-pull-requests.md).
Moving only the base branch does not synchronize the child, and a green check
on an unchanged head can still describe the previous base.

All required checks must pass. This repository currently has one human
maintainer, so `main` does not require a pull-request approval or native
CODEOWNER review. It does require the configured test, security,
documentation, and packaging checks, along with conversation resolution and
linear history. `CODEOWNERS` records ownership, but GitHub does not enforce it
as a review gate here today. Issue
[#34](https://github.com/stampbot/extra-codeowners/issues/34) tracks the plan to
dogfood Extra CODEOWNERS with Stampbot.

When Extra CODEOWNERS evaluates a repository, its default protected-path list
rejects App substitution for `CODEOWNERS`, Extra CODEOWNERS policy,
`/stampbot.toml`, GitHub Actions workflows, and local actions under
`.github/actions/`. That restriction does not create a review requirement by
itself; repository rules and effective CODEOWNERS ownership still decide which
reviews are required. The insecure override removes the built-in list for
operators who explicitly accept that change in authority.

## Review priorities

Reviewers consider these properties in order:

1. authorization and fail-closed behavior
2. correctness under retries, stale events, and concurrent updates
3. test evidence and operational recoverability
4. compatibility and configuration migration
5. maintainability and documentation

[dco]: https://developercertificate.org/
