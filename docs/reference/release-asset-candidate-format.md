# Blocked release asset candidate

The tagged workflow now contains a job that can assemble one exact set of
current candidate files. It still cannot publish them. The assembler runs only
after the unconditional `publication-block` job, so GitHub skips it while
supported distribution is disabled.

This boundary exists to exercise the Python proof handoff without pretending
that the container evidence or final release policy is complete. Maintainers
changing `.github/workflows/release.yml`,
`.github/scripts/release_asset_assembler.py`, or the future asset policy should
use this page as the contract.

## Current boundary

```text
Current tagged workflow:

publication-block fails
          |
          +--> Python, image, and chart producer jobs are skipped
          |
          +--> repository-read-only candidate job is skipped

Future isolated test path:

raw five-file Python spine ----+
signed Python run artifact ----+
image metadata run artifact ---+--> repository-read-only candidate job
signed chart run artifact -----+                 |
                                                  v
                                15-file candidate plus blocked record
                                 |
                                 +--> rejected by immutable release controller
```

The `release-asset-candidate` job has **Contents: read** and no package,
attestation, OpenID Connect (OIDC), administration, or release-write authority.
It can write its runner workspace and Actions artifact storage. It does not
call the GitHub release adapter or controller, and the existing release job
does not download its output.

The job is configured to upload a seven-day Actions artifact named
`blocked-release-asset-candidate`. Today the failed block prevents that
artifact from being created. Seven-day retention would help inspect a future
workflow test, but it would not be durable release storage.

!!! danger "Do not bypass the publication block to test this job"
    The same block also stops the existing Python signing, image publication,
    chart publication, and GitHub release jobs. Making it succeed would enable
    those privileged paths before the candidate runs. Issue #28 must first
    split out unprivileged producers that a hosted candidate test can depend on
    safely.

## The 15-file scope

The candidate inventory contains exactly the files the current blocked jobs
would provide, plus the three records required by issue
[#32](https://github.com/stampbot/extra-codeowners/issues/32):

| Group | Exact files | Count |
| --- | --- | ---: |
| Python proof | `python-build-record-amd64.json`, `python-build-record-arm64.json`, `python-selection-record.json` | 3 |
| Python distributions | One `extra_codeowners-VERSION-py3-none-any.whl`, one `extra_codeowners-VERSION.tar.gz`, and one Sigstore bundle for each | 4 |
| Image metadata | `amd64` and `arm64` SPDX files and bundles, plus one versioned OpenVEX file and bundle | 6 |
| Helm chart | One versioned chart archive and its Sigstore bundle | 2 |

Every name is derived literally from the validated `MAJOR.MINOR.PATCH` version
or committed as a fixed basename. The assembler does not accept a wildcard,
recursive search, case variant, alias, or caller-selected filename.

This is a complete inventory only for the
`current-dormant-release-inputs-v1` scope. It is not the complete asset set for
a supported release.

## Why this is not the old 26-asset plan

The design note in issue
[#25](https://github.com/stampbot/extra-codeowners/issues/25) counted 24
payloads implied by an earlier issue #18 layout, then added
`release-manifest.json` and `SHA256SUMS` for 26 release assets.

That count is no longer a final policy:

- it predates the three Python records now required as individual retained
  assets
- the current 15-file candidate contains the 12 files already named by the
  blocked release jobs plus those three records
- it deliberately omits the unresolved container evidence and
  corresponding-source deliverables from
  [issue #18](https://github.com/stampbot/extra-codeowners/issues/18)
- it does not create `release-manifest.json` or `SHA256SUMS`.

Adding the three records to the old 26-file design would produce at least 29
assets if every old assumption remained valid. Do not turn that arithmetic
into a new expected count. Schema 7 evidence delivery and the recipient
verification contract are not frozen yet, so issues #18, #25, and #28 must set
the actual final policy together.

## Candidate record

The assembler writes `release-asset-candidate.json`, not the controller's
`release-manifest.json`. Its media type is:

```text
application/vnd.stampbot.release-asset-candidate.v1+json
```

The record is canonical ASCII JSON: sorted keys, compact separators, escaped
non-ASCII characters, and one final line feed. Duplicate keys, floats,
non-finite values, alternate encodings, unknown fields, and booleans used as
integers are rejected. The file is limited to 256 KiB.

The top-level object contains exactly:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1`. |
| `media_type` | The candidate media type above. |
| `identity` | Repository ID and name, run ID, semantic tag and version, source commit, and the exact `.github/workflows/release.yml` path and commit. |
| `candidate` | The fixed non-publication state described below. |
| `assets` | Fifteen unique records sorted by basename. |

Each asset record has exactly `name`, `path`, `size`, and `sha256`. `path` must
equal the flat basename. Files are nonempty, no larger than 2 GiB each, and no
larger than 16 GiB in aggregate.

The `candidate` object is intentionally incompatible with a publication
manifest:

| Field | Required value |
| --- | --- |
| `asset_count` | `15` |
| `asset_policy` | `current-dormant-release-inputs-v1` |
| `asset_scope` | `current-dormant-release-inputs` |
| `blocking_issues` | `[1, 18, 25, 28, 30, 32]` |
| `controller_manifest` | `false` |
| `final_asset_policy_frozen` | `false` |
| `non_python_payload_semantics_verified` | `false` |
| `publication_allowed` | `false` |
| `source_completeness` | `false` |

Those issue numbers are the six open issues in the **First supported release**
milestone at the commit that introduced this format. The release-readiness
milestone remains the authoritative live gate.

Changing any false value to true, removing a blocker, changing the media type,
or reshaping the record makes it invalid. The immutable release controller also
rejects the record because it is not a controller manifest.

## Python proof handling

The assembler consumes the existing raw Python spine and canonical spine record
by immutable artifact ID and provider digest. It supplies repository, run,
workflow, source, selected-artifact, wheel, and selection-record identity from
trusted workflow values.

The other three inputs use fixed, same-run artifact names produced by jobs that
the candidate job depends on. Their downloads require provider digest
verification, and the assembler enforces each complete file set. Actions'
single-upload artifact namespace makes a conflicting earlier upload fail the
expected producer job, which in turn skips the candidate job.

The candidate record binds every retained file by name, size, and SHA-256. It
does not retain the upstream Actions artifact IDs or provider digests,
including those for the raw pair. The final release chain still needs that
provenance.

After the spine materializer exposes its exact five-file directory, the
assembler runs the existing `verify_selection` implementation again. That
verification parses and validates the wheel, source distribution, both native
build records, and selection record in a job with repository-read permission.
The job uses a normal networked runner; it is not the offline parser sandbox
required by issue #28.

The separately signed Python run artifact must contain exactly the wheel,
source distribution, and their two Sigstore bundles. Its wheel and source
distribution must be byte-for-byte identical to the files materialized from the
raw spine. The candidate retains the materialized copies and the two bundle
files.

There is no second Python proof format. The three JSON files in the candidate
are the original bytes from the existing spine.

## Filesystem handling

Every input directory must be flat and match its expected name set exactly.
Each input must be a nonempty, assembler-owned, single-link regular file.
Symlinks, hard links, special files, missing files, extra files, case changes,
and duplicate candidate basenames fail before the output becomes visible.

The assembler retains no-follow file descriptors while it hashes and copies
each file. It checks device, inode, type, link count, ownership, size,
modification time, and change time before and after each read. Destination
files are created exclusively with mode `0600` below a mode-`0700` staging
directory.

The candidate record is written canonically, read back through the strict
parser, and checked against every staged file. The assembler flushes files and
directories, then exposes the complete directory with Linux
`renameat2(RENAME_NOREPLACE)`. It never replaces an existing output.

The caller must provide a new absolute child below an assembler-owned
mode-`0700` parent. After any failure, discard that whole parent before
retrying.

## What this tranche does not verify

The assembler retains the exact bytes of the Sigstore bundles, SPDX documents,
OpenVEX document, and Helm chart. It does not parse their semantics, verify
their signatures, inspect the chart archive, or prove that their subjects and
workflow identities agree. The explicit
`non_python_payload_semantics_verified: false` field records that gap.

It also does not:

- consume schema 7 container evidence or prove `source_completeness: true`
- create the recipient evidence archives required by issue #18
- create checksums or a final release manifest
- run archive parsing in the offline, rootless sandbox required by issue #28
- run the immutable-release preflight
- call the release controller or GitHub API adapter
- grant release, package, registry, signing, tagging, or attestation authority.

The next release-assembler tranche must consume only complete schema 7
evidence, freeze the final asset policy, and satisfy the recipient verification
contract. Only then should a separate reviewed transformation create the
controller manifest accepted by issue #25's privileged publisher.

## Local checks

The assembler depends on Linux's no-replace rename operation. From a reviewed
checkout, install the pinned toolchain and locked dependencies, then run its
focused checks:

```bash
mise trust
mise install
mise run bootstrap
mise exec -- uv run python .github/scripts/release_asset_assembler.py --help
mise exec -- uv run pytest tests/test_release_asset_assembler.py --no-cov
```

The final two commands exit with status zero on success. The test suite includes
one complete five-file Python proof and a self-consistent raw transport whose
arm64 build record has the wrong machine.

The full command intentionally requires both raw artifact digests and all
trusted Python-spine identity arguments. Use the committed workflow as the
argument map; do not copy authority-bearing values from either input record.
