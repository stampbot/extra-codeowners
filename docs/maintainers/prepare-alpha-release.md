# Prepare an alpha release

Use this procedure when the change set is ready and you need a new alpha
version. It prepares a normal pull request. It does not create a tag or publish
an image, chart, or GitHub release.

The release version has one source: `pyproject.toml`. The release workflow
derives the published chart version, chart app version, and default image tag
from the signed tag. The container evidence binds the first-party wheel to the
same source revision, so an application version bump does not rewrite the
third-party dependency policy.

## Check the planned change

From the repository root, start with a clean checkout and Git plus `mise`
available. Pick the next SemVer alpha version, then run the dry run:

```shell
mise run release:prepare-alpha --dry-run 0.1.0-alpha.5
```

The command prints the changes it would make to `pyproject.toml`, `uv.lock`,
and `CHANGELOG.md`. It does not modify the checkout. If the target is not newer
than the current project version, or the changelog already has that release,
the command stops.

## Prepare the pull request

Run the same command without `--dry-run`:

```shell
mise run release:prepare-alpha 0.1.0-alpha.5
git diff --check
git diff -- pyproject.toml uv.lock CHANGELOG.md
```

The command updates the PEP 440 project version, refreshes the lock file, and
moves the current Unreleased notes under the alpha heading. It then checks the
lock file and runs the source-plan and toolchain test modules. Review that
small diff, commit it, and open the pull request for review.

If a focused check fails, don't create the release PR yet. The command has
already made the three tracked changes, so leave them in place, fix the failure,
and rerun the named check. Once it passes, inspect the same diff and continue.

## Publish after the pull request merges

After the release-preparation pull request lands on `main`, create and push a
signed `vMAJOR.MINOR.PATCH-alpha.N` tag on that merged commit. The tag-triggered
workflow validates that tag against `pyproject.toml`, builds the artifacts, and
packages the chart with the tag's version. Nothing in the preparation command
can publish on its own.
