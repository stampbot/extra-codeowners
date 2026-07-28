# Verify a container evidence archive

Use this procedure to exercise the schema-9 content verifier against a future
release candidate. A successful run proves that one archive is structurally
complete and internally consistent with the identity values you supplied.

!!! danger "There is no supported container release yet"
    Current pull-request artifacts use CI-only names and local image
    configuration subjects. Distribution approval is also false. The
    recipient verifier rejects those artifacts by design.

!!! warning "Content verification is not producer authentication"
    This command does not verify GitHub release immutability, a Sigstore
    identity, a transparency-log entry, or an OCI attestation. Until the
    release workflow and this guide include those steps, do not use the result
    to deploy, mirror, or redistribute an image.

## Prepare an isolated verifier

Run the verifier on Linux in a no-secret environment. It needs Python 3.12 or
newer and no third-party Python packages. Use a previously reviewed checkout;
do not run the verifier from the untrusted candidate you are inspecting.
Run it as a dedicated unprivileged user on a volume with at least 2 GiB free
and a filesystem quota. Disable network access before parsing. Keep the
reviewed verifier checkout read-only.

Put these files in a read-only input directory:

- `extra-codeowners-VERSION-linux-ARCHITECTURE-evidence.tar.gz`
- its `.sha256` sidecar
- the platform's canonical evidence predicate.

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

## Run the verifier

Set the independently verified values in your shell. `INPUT` is the read-only
directory containing the candidate files. `VERIFIER_CHECKOUT` is the reviewed
source checkout, not the candidate's checkout. The example creates a fresh
private work directory so a failed command cannot leave a plausible summary:

```bash
set -euo pipefail
umask 077

VERIFIER_CHECKOUT='/opt/extra-codeowners-verifier'
INPUT='/mnt/extra-codeowners-release'
WORK="${HOME}/extra-codeowners-verification"
VERSION='0.1.0'
PLATFORM='linux/amd64'
PLATFORM_DIGEST='sha256:REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS'
SOURCE_REVISION='REPLACE_WITH_40_LOWERCASE_HEX_CHARACTERS'
SOURCE_DATE_EPOCH='REPLACE_WITH_COMMITTER_UNIX_TIMESTAMP'

test ! -e "$WORK"
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

## Check the result

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
