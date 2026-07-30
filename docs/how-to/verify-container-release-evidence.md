# Verify container release evidence

Use this procedure to exercise five non-publishing boundaries against a future
release candidate. The commands authenticate GitHub's immutable release, check
the successful tagged workflow and its exact source, acquire the release
assets, bind one selected file to that workflow's SLSA provenance, and inspect
one evidence archive. None of these steps authorizes publication or deployment.

!!! danger "There is no supported container release yet"
    Current pull-request artifacts use CI-only names and local image
    configuration subjects. Distribution approval is also false. The
    recipient verifier rejects those artifacts by design.

!!! warning "The complete producer path is unfinished"
    The Actions provenance command checks one selected file; the project has
    not frozen which files must pass it. Local file provenance does not verify
    a Cosign blob signature or authenticate an OCI platform, signature, or
    registry attestation. The remaining policy and OCI checks are tracked in
    [issue #28](https://github.com/stampbot/extra-codeowners/issues/28). Do not
    deploy, mirror, or redistribute an image from these partial results.

## Prepare an isolated verifier

Run these commands on Linux from a previously reviewed checkout. Don't use code
from the candidate you are inspecting. The commands need Python 3.12 or newer;
the content verifier uses no third-party Python packages.

Keep the reviewed checkout read-only. Run the networked release commands with
only a GitHub read token. Then remove that token and disable network access
before you run the archive parser as a dedicated unprivileged user. Give the
parser a volume with at least 2 GiB free and a filesystem quota.

The repository pins GitHub CLI 2.96.0 in `mise.toml`. Do not substitute GitHub
CLI 2.92.0 or older:
[GHSA-8xvp-7hj6-mcj9][gh-cli-advisory] affects attestation and release
verification and can expose the CLI token.

Before you remove write access from the checkout, install its reviewed tools
from that directory:

```bash
cd -- /opt/extra-codeowners-verifier
mise install
mise exec -- gh version
```

The version command must report GitHub CLI 2.96.0.

Obtain the canonical release-controller manifest and its SHA-256 through an
independent trusted path. The project does not produce that final manifest
yet. Using a manifest and digest copied from the release under test does not
establish the expected asset policy.

GitHub CLI 2.96.0 requires an authenticated session even when the release is
public. Set `GH_TOKEN` to the least-privileged token that can read the target
repository. For a private repository, limit it to that repository with
**Actions: read**, **Contents: read**, and **Attestations: read**. Don't put the
token in a command argument.

The acquisition command creates a flat, mode-`0700` asset directory beneath
the private authentication workspace. Each file uses its GitHub release asset
name and mode `0600`.

Obtain the following values through an independently authenticated release
path:

- the exact semantic version
- `linux/amd64` or `linux/arm64`
- the selected platform manifest digest
- the 40-character source revision
- the source commit's committer timestamp.

The current project does not yet provide that authenticated path. Do not copy
these values out of the untrusted predicate and pass them back as trusted
arguments.

## Authenticate and acquire the GitHub release

Use Bash from the reviewed checkout. `RELEASE_MANIFEST` is the canonical
controller manifest obtained through the trusted handoff.

```bash
set -euo pipefail
umask 077

VERIFIER_CHECKOUT='/opt/extra-codeowners-verifier'
RELEASE_MANIFEST='/mnt/trusted-release/release-manifest.json'
RELEASE_MANIFEST_SHA256='REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS'
AUTH_WORK="${HOME}/extra-codeowners-release-authentication"
AUTH_CACHE="${AUTH_WORK}/cache"
AUTH_SUMMARY="${AUTH_WORK}/authenticated-github-release.json"
AUTH_SUMMARY_TMP="${AUTH_SUMMARY}.tmp"
WORKFLOW_SUMMARY="${AUTH_WORK}/authenticated-release-workflow.json"
WORKFLOW_SUMMARY_TMP="${WORKFLOW_SUMMARY}.tmp"
ASSET_ROOT="${AUTH_WORK}/assets"
ACQUISITION_SUMMARY="${AUTH_WORK}/asset-acquisition.json"
ACQUISITION_SUMMARY_TMP="${ACQUISITION_SUMMARY}.tmp"
PROVENANCE_SUMMARY="${AUTH_WORK}/authenticated-actions-provenance.json"
PROVENANCE_SUMMARY_TMP="${PROVENANCE_SUMMARY}.tmp"
PROVENANCE_ASSET_NAME='REPLACE_WITH_ONE_ATTESTED_ASSET_NAME'

test ! -e "$AUTH_WORK"
mkdir -m 0700 -- "$AUTH_WORK"
mkdir -m 0700 -- "$AUTH_CACHE"
test ! -e "$AUTH_SUMMARY"
test ! -e "$WORKFLOW_SUMMARY"
test ! -e "$ASSET_ROOT"
test ! -e "$ACQUISITION_SUMMARY"
test ! -e "$PROVENANCE_SUMMARY"
trap 'rm -f -- "$AUTH_SUMMARY_TMP" "$WORKFLOW_SUMMARY_TMP" "$ACQUISITION_SUMMARY_TMP" "$PROVENANCE_SUMMARY_TMP"; unset GH_TOKEN GITHUB_TOKEN' EXIT

cd -- "$VERIFIER_CHECKOUT"
XDG_CACHE_HOME="$AUTH_CACHE" \
  mise exec -- python -I -B .github/scripts/verify_github_release.py \
  --manifest "$RELEASE_MANIFEST" \
  --manifest-sha256 "$RELEASE_MANIFEST_SHA256" \
  > "$AUTH_SUMMARY_TMP"

mv -- "$AUTH_SUMMARY_TMP" "$AUTH_SUMMARY"
AUTH_SUMMARY_SHA256="$(sha256sum -- "$AUTH_SUMMARY" | cut -d ' ' -f 1)"

XDG_CACHE_HOME="$AUTH_CACHE" \
  mise exec -- python -I -B .github/scripts/verify_release_workflow.py \
  --manifest "$RELEASE_MANIFEST" \
  --manifest-sha256 "$RELEASE_MANIFEST_SHA256" \
  --authenticated-release-record "$AUTH_SUMMARY" \
  --authenticated-release-record-sha256 "$AUTH_SUMMARY_SHA256" \
  > "$WORKFLOW_SUMMARY_TMP"

mv -- "$WORKFLOW_SUMMARY_TMP" "$WORKFLOW_SUMMARY"
WORKFLOW_SUMMARY_SHA256="$(sha256sum -- "$WORKFLOW_SUMMARY" | cut -d ' ' -f 1)"

XDG_CACHE_HOME="$AUTH_CACHE" \
  mise exec -- python -I -B .github/scripts/acquire_github_release_assets.py \
  --manifest "$RELEASE_MANIFEST" \
  --manifest-sha256 "$RELEASE_MANIFEST_SHA256" \
  --authenticated-release-record "$AUTH_SUMMARY" \
  --authenticated-release-record-sha256 "$AUTH_SUMMARY_SHA256" \
  --output-dir "$ASSET_ROOT" \
  > "$ACQUISITION_SUMMARY_TMP"

mv -- "$ACQUISITION_SUMMARY_TMP" "$ACQUISITION_SUMMARY"
ACQUISITION_SUMMARY_SHA256="$(sha256sum -- "$ACQUISITION_SUMMARY" | cut -d ' ' -f 1)"

XDG_CACHE_HOME="$AUTH_CACHE" \
  mise exec -- python -I -B .github/scripts/verify_actions_build_provenance.py \
  --manifest "$RELEASE_MANIFEST" \
  --manifest-sha256 "$RELEASE_MANIFEST_SHA256" \
  --authenticated-workflow-record "$WORKFLOW_SUMMARY" \
  --authenticated-workflow-record-sha256 "$WORKFLOW_SUMMARY_SHA256" \
  --acquisition-record "$ACQUISITION_SUMMARY" \
  --acquisition-record-sha256 "$ACQUISITION_SUMMARY_SHA256" \
  --asset-root "$ASSET_ROOT" \
  --asset-name "$PROVENANCE_ASSET_NAME" \
  > "$PROVENANCE_SUMMARY_TMP"

mv -- "$PROVENANCE_SUMMARY_TMP" "$PROVENANCE_SUMMARY"
unset GH_TOKEN GITHUB_TOKEN
trap - EXIT
```

Exit status `0` means GitHub reports the exact repository ID, tag target,
immutable release, and remote asset set from the reviewed manifest. It also
means GitHub CLI cryptographically verified the release attestation and the
verifier matched its statement to that same tag and asset set.

The workflow command also confirmed that GitHub reports the manifest's run as
a successful tag-triggered run at the target commit. It read the workflow file
at that immutable commit and recorded the file's Git blob SHA-1 and independent
SHA-256. This establishes the run and workflow-file identity; it does not prove
that the workflow produced any listed asset.

The acquisition command then rechecked the release identity, downloaded every
asset by database ID, and matched each local file's size and SHA-256 before it
exposed `ASSET_ROOT`.

The provenance command finally required the selected file in a
GitHub-verified SLSA statement signed by the exact tagged workflow, source
commit, run ID, and run attempt. Choose an asset that the release workflow
passes to `actions/attest-build-provenance`; the current workflow attests its
wheel, source distribution, and chart package. The final release policy has
not decided which of those files are mandatory. Run the command once for each
file your reviewed test policy selects, using a separate output record.

The private cache keeps Sigstore trust metadata managed through The Update
Framework (TUF) separate from other `gh` commands. A stale or invalid cache
makes verification fail; don't bypass that failure by supplying an unreviewed
trust root.

Read the
[authenticated GitHub release
record](../reference/authenticated-github-release-record.md),
[authenticated release workflow
record](../reference/authenticated-release-workflow-record.md), and
[asset acquisition record](../reference/authenticated-release-asset-acquisition.md),
and [authenticated Actions provenance
record](../reference/authenticated-actions-build-provenance.md)
for the output fields, permissions, limits, and non-claims.

The example removes `GH_TOKEN` and `GITHUB_TOKEN` before it exits. The
remaining blob-signature, OCI, final asset-policy, and trusted-handoff checks
do not exist yet. Stop here unless you already have the other trusted identity
values from a separately reviewed test fixture.

## Verify the archive content

Set the independently verified values in your shell. `INPUT` is the read-only
directory containing the candidate files. `VERIFIER_CHECKOUT` is the reviewed
source checkout, not the candidate's checkout. This command uses a separate
private work directory so you can exercise the content verifier without
pretending that an incomplete authentication run succeeded.

```bash
set -euo pipefail
umask 077

VERIFIER_CHECKOUT='/opt/extra-codeowners-verifier'
INPUT="${HOME}/extra-codeowners-release-authentication/assets"
WORK="${HOME}/extra-codeowners-verification"
VERSION='0.1.0'
PLATFORM='linux/amd64'
PLATFORM_DIGEST='sha256:REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS'
SOURCE_REVISION='REPLACE_WITH_40_LOWERCASE_HEX_CHARACTERS'
SOURCE_DATE_EPOCH='REPLACE_WITH_COMMITTER_UNIX_TIMESTAMP'

test ! -e "$WORK"
test -z "${GH_TOKEN:-}"
test -z "${GITHUB_TOKEN:-}"
mkdir -m 0700 -- "$WORK"

ARCHITECTURE="${PLATFORM#linux/}"
ARCHIVE="${INPUT}/extra-codeowners-${VERSION}-linux-${ARCHITECTURE}-evidence.tar.gz"
CHECKSUM="${ARCHIVE}.sha256"
PREDICATE="${INPUT}/evidence-predicate-${ARCHITECTURE}.json"
OUTPUT="${WORK}/verified-${VERSION}-${ARCHITECTURE}"
SUMMARY="${WORK}/verification-summary.json"
SUMMARY_TMP="${SUMMARY}.tmp"

test ! -e "$OUTPUT"
test ! -e "$SUMMARY"
trap 'rm -f -- "$SUMMARY_TMP"' EXIT

python3 -I -B "$VERIFIER_CHECKOUT/.github/scripts/recipient_evidence.py" \
  --archive "$ARCHIVE" \
  --checksum "$CHECKSUM" \
  --predicate "$PREDICATE" \
  --output "$OUTPUT" \
  --version "$VERSION" \
  --platform "$PLATFORM" \
  --subject-digest "$PLATFORM_DIGEST" \
  --source-revision "$SOURCE_REVISION" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  > "$SUMMARY_TMP"

mv -- "$SUMMARY_TMP" "$SUMMARY"
trap - EXIT
```

The placeholders are intentional: the missing authenticated release path is
still tracked in
[#28](https://github.com/stampbot/extra-codeowners/issues/28). Stop if you
cannot obtain every value independently.

## Check the content result

Exit status `0` means the verifier consumed the complete gzip and tar streams,
validated the schema-9 relationships described in the release contract, and
materialized the files. The JSON summary records the archive, predicate,
manifest, and policy hashes alongside the trusted identity values.

Keep these items together while you review the candidate:

- the original archive, sidecar, and predicate
- the `verification-summary.json` in the private work directory
- the materialized output directory
- the authenticated records from which you obtained the command arguments.

Any nonzero exit is a hard failure. The verifier removes an incomplete output
directory when the filesystem permits safe cleanup. Treat any leftover after a
filesystem or cleanup failure as hostile. Do not retry with a generic archive
tool, weaken a limit, or copy identity values from the rejected evidence.

After the review, remove the materialized directory unless your audit policy
requires it. Preserve the original authenticated assets and verification
summary according to that policy.

Read the
[container evidence release contract](../reference/container-evidence-release-contract.md)
for the exact envelope, resource limits, and remaining authentication work.

[gh-cli-advisory]: https://github.com/cli/cli/security/advisories/GHSA-8xvp-7hj6-mcj9
