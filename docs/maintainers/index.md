# Maintainer and release engineering

Extra CODEOWNERS releases from `main` after CI succeeds. Maintainers review and
merge the change; they don't prepare a release pull request, edit a version
file, or create the normal release tag.

## Pull-request checks

The `CI` workflow consolidates these build and test checks behind `Required`:

- Python formatting, linting, typing, workflow linting, and YAML linting
- the test suite on Python 3.12, 3.13, and 3.14, including PostgreSQL and
  backup/restore coverage on 3.12
- wheel and source-archive build plus a clean wheel installation
- strict MkDocs build and Markdown linting
- Helm lint, render, schema, security, and Kubernetes validation
- native `amd64` and `arm64` container builds, smoke tests, and vulnerability
  scans.

The final `Required` job fails unless every group succeeds. Keep that stable
name in repository rules; matrix details can change without another branch
protection edit. Keep DCO, CodeQL, dependency review, the larger property-test
profile, and workflow-security checks as independent required controls. A
pull-request update cancels its stale run. Runs on `main` use `queue: max`, so a
later push cannot discard an earlier run.

Run the local subset with:

```bash
mise run check
```

That command exits zero when its checks pass. PostgreSQL and native
cross-architecture behavior still need CI; the
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md)
explains how to run the complete database suite locally.

## Automatic releases

On a push to `main`, the `Release` job invokes the reusable release workflow
after `Required` succeeds. The planner reads Git tags for that exact commit,
then refuses malformed versions, divergent release history, multiple tags on
one commit, and version collisions.

Confirm that GitHub's **Immutable releases** repository setting is enabled
before the next merge. The workflow's `GITHUB_TOKEN` cannot read that setting
in advance. Instead, the publisher stages a draft release after the other
artifacts are ready, uploads the assets, publishes the release, and requires
GitHub to report it as immutable. Only then does `Release complete` succeed.

While the latest release is an alpha, the planner increments its numeric alpha
suffix. If the latest release is stable, commits since that tag select a
semantic version bump:

- `BREAKING CHANGE`, `BREAKING-CHANGE`, or a conventional `!` bumps major
- `feat` bumps minor
- any other merged change bumps patch.

The planner does not promote an alpha line to its first stable release. Until
[issue #144](https://github.com/stampbot/extra-codeowners/issues/144) defines a
reviewed promotion rule, each newly published release continues the alpha line.

GitHub may start queued runs out of commit order. When a descendant run
publishes first, an older untagged run succeeds only after it proves that the
descendant tag is on `main` and the release is complete and immutable. It then
skips its own build and publication. This coalesces closely spaced merges into
one release instead of failing the older run or publishing versions out of
order.

That one calculated version feeds every artifact. The planner renders its
matching PEP 440 form for Hatch, the container receives the semantic version as
a build argument, and `helm package` overrides the chart's development
metadata. The checked-in chart stays at `0.0.0-dev`.

Release jobs build the Python wheel, source distribution, Helm chart, and native
images in parallel. The publisher then creates the immutable tag, assembles one
multi-platform image, signs and attests the artifacts, pushes the OCI chart,
and stages the GitHub release. It uploads the assets and publishes that release
last. The release includes the Python artifacts; it does not publish them to
PyPI.

Before allocating another version, the workflow requires the preceding release
to be published and immutable. It accepts `v0.1.0-alpha.7` as the sole
historical exception because that public release predates this policy. No later
mutable release can advance the version chain.

If publication stops halfway through, rerun the failed jobs in the original CI
run. GitHub keeps that run on its original commit. A tag already on that commit
is reused, and a completed GitHub release switches the workflow into
verification mode. It verifies the required assets, both image architectures,
and the exact image and chart digests. Conflicting state stops the retry.

If the postcondition reports a mutable release, first enable immutable releases
and query that release again. If GitHub still reports it as mutable, delete only
that incomplete GitHub release. Keep its tag, image, and chart, then rerun the
failed jobs in the original CI run so the workflow can verify and reuse them.

The retry is complete only when its `Release complete` job succeeds. Don't
dispatch a fresh CI run for a newer commit as a substitute, and don't move or
delete a tag to clear failed verification.

The scheduled `Cold container build` workflow builds both architectures with
BuildKit caching disabled. Treat its failure as evidence that the normal cache
hid a missing or mutable input.

## Maintainer procedures

- [Review current project status](../reference/project-status.md)
- [Review the runtime base decision](../explanation/runtime-base.md)
- [Respond to a dependency audit](../how-to/respond-to-dependency-audit.md)
- [Review stacked pull requests](../how-to/review-stacked-pull-requests.md)
- [Run the live GitHub contract](../how-to/run-live-github-contract.md)
- [Read live GitHub evidence reports](../reference/live-github-evidence-reports.md)
- [Update the tutorial webhook relay](update-tutorial-relay.md)
- [Review the DCO evidence contract](../reference/dco-evidence.md)
