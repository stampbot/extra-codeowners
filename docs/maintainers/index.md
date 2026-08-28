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

Release-channel changes are explicit, append-only Git history. An ordinary
merge follows the latest release: an alpha increments its numeric suffix, while
a stable release applies conventional-commit rules to the commits since its
tag. To change that behavior, include one standard Git trailer in the commit
that lands on `main`:

```text
Release-Channel: alpha
```

or:

```text
Release-Channel: stable
```

The planner replays those transitions in commit order. `alpha` starts the next
semantic version as `.alpha.1`; `stable` promotes the current alpha base
without another conventional bump. A repeated, malformed, or duplicated
trailer fails the release rather than changing state implicitly. See the
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md#choose-a-release-channel)
for the merge-message procedure.

While the release channel is stable, commits since that tag select a semantic
version bump:

- `BREAKING CHANGE`, `BREAKING-CHANGE`, or a conventional `!` bumps major
- `feat` bumps minor
- any other merged change bumps patch.

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

Each image build exports its exact native filesystem without starting the
container and writes a raw per-platform distribution inventory. The published
release carries `distribution-inventory-amd64.json` and
`distribution-inventory-arm64.json` with their Sigstore bundles. Each inventory
is attested, signed, and bound to its matching child-image digest. It records
available package and license material for review; it is not itself a notice
package or a decision that source or notice duties have been met. It also
records the Debian distribution derived from the image's hashed
canonical `/usr/lib/os-release` file.

### Update a VEX claim

The reviewed source statement lives under `security/vex/`. Use Vexcalibur as an
analysis aid when a vulnerability needs review, then check the affected package
URLs and impact statement in the pull request. The statement is a security
conclusion, not a way to hide a scanner result.

The publisher copies the reviewed bytes only when every product URL matches the
signed native inventories. Debian URLs must identify the released architecture
and distribution; an `upstream` qualifier, when present, must match the
installed package's source. Unknown qualifiers stop the release. This check
runs before the workflow creates an immutable tag or a versioned image
reference. The publisher then signs that release asset and attaches an OpenVEX
attestation to the final multi-platform image digest. If a package update or a
change in reachable behavior invalidates a conclusion, update or remove the
source statement and release the correction. Never try to rewrite a published
VEX asset.

Before allocating another version, the workflow requires the preceding release
to be published and immutable. It accepts `v0.1.0-alpha.7` as the sole
historical exception because that public release predates this policy. No later
mutable release can advance the version chain.

If publication stops halfway through, rerun the failed jobs in the original CI
run. GitHub keeps that run on its original commit. A tag already on that commit
is reused, and a completed GitHub release switches the workflow into
verification mode. It verifies the required assets, both image architectures,
and the exact image and chart digests. It then verifies GitHub provenance and
Sigstore evidence against the release workflow and original commit, including
the raw inventory's platform-digest binding and the OpenVEX statement's image
binding. Conflicting, missing, or ambiguous evidence stops the retry.

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
