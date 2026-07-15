# Review container evidence

Use this maintainer procedure to review the two container evidence artifacts
produced by pull-request CI and update the fail-closed component policy. A green
collector is not legal approval or permission to publish a release.

Tagged publication remains structurally disabled by security issue
[`#28`](https://github.com/stampbot/extra-codeowners/issues/28). The current CI
artifacts are unsigned review inputs, not release assets.

## Prerequisites

You need a clean review branch, Docker with amd64 and arm64 support, Python
3.14, and the repository's ordinary development tools. You also need authority
to approve `.compliance/` changes. Ask an independent reviewer to evaluate an
unexpected dependency or base-image change instead of approving the new input
and its policy baseline alone.

## 1. Inspect both CI artifacts

Each container matrix job uploads
`container-distribution-evidence-ARCHITECTURE`. The upload step runs after a
failed collection so partial diagnostics are not lost. Its missing-file mode is
only a warning; the preceding collection step is required and still fails the
job.

Download both artifacts from the pull-request workflow. Compare
`components-ARCHITECTURE.json` with the matching object under `platforms` in
`.compliance/container-policy.json`. For every difference, establish:

- why the component, version, declared license, architecture, metadata hash,
  effective state, or source commit changed
- whether the bytes remain effective or only in a distributed lower layer
- the exact Python source distribution or Alpine aports commit and checksums
- the applicable notices and source-delivery obligations
- whether the base index, platform manifest, configuration, or initial layer
  diff IDs changed.

The CI artifact's subject is a local image configuration digest. That exception
is explicit because a pull-request candidate has no registry manifest. A future
release archive must instead bind to one exact published platform manifest.

## 2. Review source provenance

Inspect `MANIFEST.json`. Every network source record has both `url`, the
requested URL, and `urls`, the complete ordered request and redirect chain.
Every entry must be credential-free HTTPS. Investigate a new host, redirect,
or chain length even when the final bytes still match their hash.

For a changed Alpine origin:

1. confirm `/lib/apk/db/installed` names the exact 40-character aports commit
2. fetch only that origin's recipe subtree and record its SHA-256 under
   `alpine_recipe_archives`
3. inspect the recipe without sourcing or executing it
4. confirm each local source is a regular file whose SHA-512 matches
   `sha512sums`
5. confirm every other checksum filename is available from the pinned Alpine
   distfiles release and matches its SHA-512.

The default parser requires exact, ordered coverage between one literal
`source` block and one literal `sha512sums` block. Do not add a recipe exception
merely to make a parser failure disappear. An exception must be keyed by the
exact origin and commit, explain the upstream construction, and grant only
`allow_dynamic_sources` or an exact safe link path, type, and target. A changed
recipe archive hash requires reviewing the exception again.

For Python, use the exact URL, size, and SHA-256 from `uv.lock`. A wheel-only or
lower-layer component needs an immutable upstream archive under
`python_sources` and an explanation of its relationship to the installed
artifact. Do not use a mutable branch URL.

When Docker Official Python changes, review these values together:

- `base_image` and `base_image_index_digest`
- both records under `base_image_platforms`, including manifest, configuration,
  and ordered layer diff IDs
- the commit- and hash-pinned Official Python recipe
- the recipe's literal CPython version and SHA-256 against `cpython_source`
- the builder and final runtime `FROM` lines in `Dockerfile`.

## 3. Review license resolutions

Do not copy a new observed expression into `license_resolutions` without
reading the exact source. Blank, non-SPDX, compound, and `LicenseRef-*`
expressions require deliberate review.

A `LicenseRef-*` entry must cover exactly the components that use it, include a
nonempty rationale, and pin one retained source notice path and SHA-256 for each
component. The current public-domain evidence is intentionally exact:

- `alpine:tzdata@2026b-r0` uses
  `licenses/from-source/alpine-tzdata/061340856888-LICENSE`, SHA-256
  `0613408568889f5739e5ae252b722a2659c02002839ad970a63dc5e9174b27cf`
- `alpine:xz-libs@5.8.3-r0` uses
  `licenses/from-source/alpine-xz/616a3ad264ce-COPYING`, SHA-256
  `616a3ad264ce29b8f1cb97e53037b139d406899ca8d1f799651e17bfa09830b8`.

An unrelated `COPYING` file does not satisfy either pin. A new standard SPDX
identifier needs a text URL pinned to a committed SPDX license-list-data
revision and the exact file SHA-256.

## 4. Run the verification gates

From the repository root, run:

```bash
uv run pytest tests/test_container_evidence.py --no-cov
uv run ruff check .github/scripts/container_evidence.py \
  .github/scripts/release_readiness.py \
  tests/test_container_evidence.py
uv run mypy .github/scripts/container_evidence.py \
  .github/scripts/release_readiness.py \
  tests/test_container_evidence.py
uv run mkdocs build --strict
```

Then run `mise run check` and require both hosted container jobs to complete.
Inspect a freshly generated archive rather than reusing an artifact from an
older policy commit.

## 5. Record approval without unlocking publication

Keep `distribution_approval.approved` set to `false` while evidence or a
delivery mechanism is under review. A future release implementation must
require explicit values for `approved_by`, `approved_on`, and `rationale` before
publication.

The current release workflow has an unconditional failure linked to issue
`#28`. Changing the approval value cannot bypass it. Qualified legal review is
a separate requirement before a paid hosted distribution; neither collector
success nor open-source delivery completes that review automatically.

The workflow also checks the committed release-readiness milestone and records
its counts and run context. That check and the repository's `v*` tag ruleset do
not replace the privilege-separation work. Do not push or manually retag a
release candidate until issue `#28` is resolved, the future recipient contract
is implemented, and the project announces a supported release.
