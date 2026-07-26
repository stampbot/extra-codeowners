# Update the native wheelhouse

Use this procedure when a native dependency, CPython patch release, Alpine
base, or build tool changes. Work from the repository root on a native amd64
or arm64 machine with Docker Buildx and the repository's `mise` tools
installed.

The local build downloads checksum-bound source archives and the crates named
by `Cargo.lock`. It doesn't need GitHub credentials. Don't put registry,
package-index, or source-host credentials in Docker build arguments.

## Review the new inputs

Start with the upstream release, not the existing wheel.

For every changed source:

1. Identify the release tag and commit.
2. Verify the tag or commit with a trusted upstream signing key when one is
   available.
3. Record what you actually verified in `signature_review`. Use an unsigned
   value when upstream didn't sign that object.
4. Download the exact archive and record its URL, filename, top-level
   directory, byte count, and SHA-256.

The following commands use a temporary archive. Set `SOURCE_URL` to the exact
HTTPS URL you plan to add to the input contract.

```bash
SOURCE_URL='https://example.com/project/archive.tar.gz'
SOURCE_ARCHIVE="$(mktemp)"
curl --proto '=https' --tlsv1.2 \
  --fail --show-error --silent --location \
  --retry 3 --retry-all-errors \
  --output "$SOURCE_ARCHIVE" \
  "$SOURCE_URL"
sha256sum "$SOURCE_ARCHIVE"
stat --format='%s bytes' "$SOURCE_ARCHIVE"
tar --list --gzip --file "$SOURCE_ARCHIVE" | sed -n '1,5p'
```

The commands print the values you need; they don't modify the repository.
Delete the temporary archive after you have recorded and reviewed those
values.

`signature_review` is evidence from this maintainer review. The build checks
the archive hash, but it does not verify upstream signatures.

## Update the input contract and Dockerfile

Edit
[`containers/native-wheelhouse/inputs.json`][inputs] first. Keep every array
sorted and update all fields affected by the release:

- the base image reference and digest
- the complete Alpine package closure in `builder_packages`, plus the
  architecture-specific entries in `builder_platform_packages`
- Python version and ABI
- source URL, size, SHA-256, root directory, tag, commit, and signature review
- expected wheel version, native payload count, and shared libraries
- Cargo registry package count
- `SOURCE_DATE_EPOCH` only when the input review deliberately selects a new
  stable timestamp; record the reason in the pull request

The two package arrays form the complete installed Alpine inventory, not just
the packages named by a maintainer. Keep common packages in
`builder_packages`; keep only genuine platform differences in
`builder_platform_packages`. The current base has one such difference: its
`.python-rundeps` virtual package. The assembler rejects a package that is
missing, extra, or at another version.

Then mirror the source URLs, checksums, base digest, and common Alpine closure
in [`containers/native-wheelhouse/Dockerfile`][dockerfile]. The
platform-specific virtual package comes from the pinned base and stays in
`inputs.json`; the final installed-package check still requires it. Tests
require the common Dockerfile list and the input contract to agree exactly.

Keep the package-install instruction before the copies of `inputs.json`, the
builder script, and the source archives. That order lets a source-only update
reuse the completed compiler layer instead of reinstalling the toolchain.

Setuptools is the only source with a release transformation. If its bootstrap
layout changes, update the exact removed-file inventory and hashes. Don't
broaden the removal to a wildcard or delete an uninspected directory.

## Run the fast checks

From the repository root:

```bash
uv run ruff format --check \
  .github/scripts/native_wheelhouse.py \
  tests/test_native_wheelhouse.py
uv run ruff check \
  .github/scripts/native_wheelhouse.py \
  tests/test_native_wheelhouse.py
uv run mypy \
  .github/scripts/native_wheelhouse.py \
  tests/test_native_wheelhouse.py
uv run pytest --no-cov tests/test_native_wheelhouse.py
uv run yamllint .github/workflows/native-wheelhouse.yml
actionlint .github/workflows/native-wheelhouse.yml
```

Success ends with the wheelhouse tests passing and no linter failures.

## Build one native platform locally

Use a fresh output directory so files from an older build cannot survive the
export.

```bash
case "$(uname -m)" in
  x86_64) WHEELHOUSE_PLATFORM='linux/amd64' ;;
  aarch64 | arm64) WHEELHOUSE_PLATFORM='linux/arm64' ;;
  *)
    echo "Unsupported native architecture: $(uname -m)" >&2
    exit 2
    ;;
esac
WHEELHOUSE_OUTPUT="$(mktemp --directory)"
docker buildx build \
  --file containers/native-wheelhouse/Dockerfile \
  --target wheelhouse \
  --platform "$WHEELHOUSE_PLATFORM" \
  --build-arg "SOURCE_REVISION=$(git rev-parse HEAD)" \
  --output "type=local,dest=${WHEELHOUSE_OUTPUT}" \
  .
jq -e '
  .kind == "extra-codeowners/native-wheelhouse"
  and .reproducible_builds == 2
  and (.wheels | length == 4)
' "${WHEELHOUSE_OUTPUT}/wheelhouse/manifest.json"
jq -r '
  .builder.alpine_packages[]
  | "\(.name)=\(.version)"
' "${WHEELHOUSE_OUTPUT}/wheelhouse/manifest.json"
find "${WHEELHOUSE_OUTPUT}/wheelhouse" \
  -maxdepth 1 -type f -printf '%f\n' | sort
```

The first `jq` command exits successfully only when the assembler recorded two
matching builds and four wheels. Review the package list printed by the second
command against the platform closure in `inputs.json`; don't accept additions
or version changes merely because `apk` resolved them. The final command
should list seven files: the four wheels plus `inputs.json`,
`cargo-inputs.json`, and `manifest.json`. Remove the temporary output
directory after you finish inspecting it.

The first run can take several minutes because it installs the compiler
toolchain and fetches the Cargo closure. Buildx reuses those layers while the
reviewed inputs stay unchanged. Inspect local cache use with `docker buildx du`
before removing anything; don't prune unrelated builders or images.

## Let both native CI jobs run

Open the pull request ready for review. The workflow builds on native amd64 and
arm64 runners, then runs the exported-artifact verifier with the wheelhouse
mounted read-only.

Review these items before merging:

- both architecture jobs passed
- the source and toolchain changes in `inputs.json` are intentional
- both manifests contain exactly their reviewed Alpine platform closure
- signature-review claims match the evidence you checked
- wheel filenames, `WHEEL` compatibility metadata, native payload counts, and
  shared libraries match the expected platform; inspect every reported ELF
  payload, including versioned libraries and executables
- the Setuptools wheel still matches its published digest, or the pull request
  explains why a reviewed release changed it
- no build stage gained network access

A pull-request artifact is unsigned and short-lived. Don't use it as an
application build dependency.

## Record the published digest

After the change reaches `main`, the trusted publication job verifies both
transported artifacts again. It publishes and signs one multi-platform digest,
then writes that digest to the workflow summary.

Set `DIGEST` to that value and verify the keyless signature:

```bash
IMAGE='ghcr.io/stampbot/extra-codeowners-native-wheelhouse'
DIGEST='sha256:REPLACE_WITH_64_HEX_CHARACTERS'
cosign verify \
  --certificate-identity \
    'https://github.com/stampbot/extra-codeowners/.github/workflows/native-wheelhouse.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${IMAGE}@${DIGEST}"
```

The command must report a valid signature for the workflow identity above.
Keep the full `IMAGE@DIGEST` value in the pull request that updates the
application build. Never pin `latest`.

If publication fails after creating the `sha-$GITHUB_SHA` tag, rerun the same
workflow. You may rerun failed jobs or all jobs. The publication job selects
the newest unexpired amd64 and arm64 uploads from that workflow run by
immutable artifact ID, so a failed-jobs-only rerun can reuse successful build
jobs from an earlier attempt.

The retry keeps the commit tag immutable and reuses its digest only after
checking the workflow signature, revision labels, platform index, and exact
wheelhouse bytes against the selected producer artifacts. Don't delete or
move the commit tag to force a retry.

If a published wheelhouse is wrong, leave its digest in place. Fix the inputs,
publish a new digest, and revert any consuming application to its last known
good digest while the replacement builds.

[dockerfile]: https://github.com/stampbot/extra-codeowners/blob/main/containers/native-wheelhouse/Dockerfile
[inputs]: https://github.com/stampbot/extra-codeowners/blob/main/containers/native-wheelhouse/inputs.json
