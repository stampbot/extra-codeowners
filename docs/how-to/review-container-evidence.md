# Review container evidence for a release

This maintainer procedure updates the reviewed component policy and explicitly
approves recipient delivery. A green collector is not that approval.

## Prerequisites

You need a clean review branch, Docker with amd64 and arm64 support, Python
3.14, and the tools required by the repository's ordinary CI. You also need
authority to approve changes under `.compliance/`. Do not perform this review
in the same pull request that unexpectedly introduced the dependency or base
change unless an independent reviewer can evaluate both.

## 1. Inspect CI's raw inventories

Each container matrix job uploads
`container-distribution-evidence-ARCHITECTURE`. The upload runs even when the
reviewed-policy comparison fails. Download both artifacts from the pull request
workflow and compare their `components-*.json` files with the matching entries
under `.platforms` in `.compliance/container-policy.json`.

For every difference, identify:

- why the component, version, declared license, architecture, or source commit
  changed
- whether it remains in the effective filesystem or only a lower layer
- the exact Python sdist or Alpine aports commit and distfile checksums
- the applicable notice and source-delivery obligations
- whether the base image digest and Docker Official Python recipe changed.

The raw pull-request artifact uses the local image configuration digest as its
subject because CI has not published a manifest. Release evidence does not use
that exception: its subject must match a repository digest recorded for the
exact pulled platform manifest.

Do not copy a new observed expression into `license_resolutions` without
checking the exact source. Blank, non-SPDX, and compound expressions require a
written rationale. `LicenseRef-Public-Domain` is intentionally backed by
source-carried upstream notices rather than a fabricated standard text.

## 2. Update the reviewed policy

Edit `.compliance/container-policy.json`. Keep amd64 and arm64 baselines
separate. A newly observed component needs an exact `license_resolutions`
entry. A new standard SPDX identifier needs a text URL pinned to the committed
SPDX license-list-data revision and the file's SHA-256.

For a changed Alpine origin commit, fetch only that recipe subtree from the
commit recorded in `/lib/apk/db/installed`, record the archive SHA-256 under
`alpine_recipe_archives`, and inspect its literal `sha512sums` block. The
collector retrieves non-local filenames from Alpine's versioned distfiles
mirror and fails on a checksum mismatch. It never sources or executes the
`APKBUILD`.

For a Python package, use the exact sdist URL, size, and SHA-256 from `uv.lock`.
If the installed distribution is wheel-only, add an immutable upstream source
archive under `python_sources` and explain the source relationship during
review. A mutable repository branch is not acceptable.

When the base image changes, update `base_image` and
`base_image_index_digest` together. The collector requires the Dockerfile's
builder and final runtime stages to use that exact reviewed reference.

Run the focused checks from the repository root:

```bash
uv run pytest tests/test_container_evidence.py --no-cov
uv run ruff check .github/scripts/container_evidence.py \
  .github/scripts/release_readiness.py \
  tests/test_container_evidence.py
uv run mkdocs build --strict
```

Then run the complete `mise run check` gate and let both hosted container jobs
build their archives. Download the successful artifacts and follow the
[recipient verification procedure](verify-container-evidence.md) against each
archive.

## 3. Approve or reject recipient delivery

Keep `distribution_approval.approved` set to `false` while evidence is under
review. The tagged-release workflow passes
`--require-distribution-approval`, so it fails before semantic image tags,
signatures, chart publication, or a GitHub release when approval is absent.

After reviewing both platform archives and the recipient procedure, an
authorized maintainer may set:

```json
{
  "approved": true,
  "approved_by": "GITHUB_LOGIN",
  "approved_on": "YYYY-MM-DD",
  "rationale": "REVIEWED_DELIVERY_DECISION"
}
```

Replace every uppercase placeholder. The approver and rationale belong in the
reviewed commit; do not inject them from CI. Qualified legal review remains a
separate requirement before a paid hosted distribution, and its policy field
does not become true merely because an open-source release is approved.

## 4. Confirm release readiness

The release workflow fetches the exact milestone number committed in
`.release-readiness.json` with read-only issue permission and verifies its
expected title. It requires that milestone to be open with zero open issues and
records its open and closed counts, repository, commit, and workflow run in the
GitHub Actions summary. The repository also restricts
creation, update, and deletion of `v*` tags through GitHub ruleset
[`18967285`](https://github.com/stampbot/extra-codeowners/rules/18967285).

The workflow cannot prevent an authorized bypass user from pushing a Git tag.
It prevents publication jobs from proceeding when the milestone is not ready.
Before pushing a tag, confirm the milestone, ruleset, project version, and
release policy still describe the intended release.

If any evidence step fails after the candidate image is pushed, do not retag
that candidate manually. Correct the reviewed source or policy and rerun the
workflow from a new reviewed commit.
