# Raw Python distribution spine

The Python distribution spine carries five already-built files across a CI
trust boundary without asking the receiving job to unpack an archive. It is an
internal transport format, not a package format and not a public release
artifact.

Use this page when changing the Python proof workflow, the release workflow, or
either spine script. Application operators do not need to configure the spine.

## Current status

The reusable `Python distribution proof` workflow builds and verifies the
spine. Its read-only consumer also materializes the five files, so a manual
workflow dispatch exercises the complete transport.

The tagged release workflow contains a privileged Python job that would consume
the same raw artifacts, attest the wheel and source distribution, and sign both
files. That job still depends directly on the failing `publication-block` job
tracked in [issue #28](https://github.com/stampbot/extra-codeowners/issues/28).
This code therefore defines and tests the handoff without enabling publication.

Another blocked job would consume the raw pair independently, revalidate the
five materialized files, and place all three original JSON records in a
[15-file candidate inventory](release-asset-candidate-format.md). That
inventory says `publication_allowed: false` and is not a release-controller
manifest.

The existing selected-distribution ZIP remains in place for the read-only
container scan. Removing that older path is separate work.

```text
native amd64 and arm64 builds
               |
               v
      unprivileged selection
               |
               v
   raw spine and canonical record
          |
          +--> read-only verifier and materializer
          |
          +--> attest and sign wheel and sdist
          |    (blocked by publication-block)
          |
          +--> build non-publishable candidate inventory
               (blocked by publication-block)
```

## Transport artifacts

The producer uploads two files directly with `archive: false`:

| Artifact | Media type | Contents |
| --- | --- | --- |
| `extra-codeowners-python-SOURCE_SHA-artifact-SELECTED_ID-attempt-PRODUCER_ATTEMPT.bin` | `application/vnd.stampbot.python-distribution-spine.v1+octet-stream` | The five selected files concatenated in a fixed order. |
| `extra-codeowners-python-SOURCE_SHA-artifact-SELECTED_ID-attempt-PRODUCER_ATTEMPT.spine.json` | `application/vnd.stampbot.python-distribution-spine.v1+json` | Canonical identity, byte ranges, sizes, and digests. |

Consumers download both files by immutable artifact ID with
`skip-decompress: true`. The provider digest from each pinned upload step must
match the downloaded bytes. A mutable artifact name, pattern, repository, or
run lookup is not part of this handoff.

Raw filenames include the selected artifact ID and the producer's run attempt.
The consumer uses that exported attempt rather than its own attempt, so rerunning
only a failed consumer still addresses the producer's original files. Direct
artifacts are never overwritten.

## Trusted identity

The record is untrusted input. A consumer supplies every authority-bearing
value separately:

| Value | Trusted source |
| --- | --- |
| Repository ID and name | GitHub workflow context |
| Source revision and run ID | Calling workflow context |
| Producer run attempt | Raw-producer output written from its `GITHUB_RUN_ATTEMPT` |
| Reusable workflow ref and commit | Verified raw-consumer outputs derived from `job.workflow_ref` and `job.workflow_sha` |
| Selected artifact ID and provider SHA-256 | Pinned selection upload step |
| Wheel and selection-record SHA-256 | Validated selection outputs |
| Spine and record provider SHA-256 | Pinned direct-upload steps |

The verifier rejects a record unless every value matches. Passing values copied
from the record would remove this trust boundary.

GitHub gives a reusable workflow its caller's `github` context. The current
job's `job.workflow_ref` and `job.workflow_sha` identify the reusable workflow
itself. The workflow uses those job values when available and falls back to the
corresponding `github` values. See the [GitHub Actions contexts
reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context).

The workflow ref must name the same repository and workflow path recorded by
the caller. Cross-repository proof workflows are not supported.

## Canonical record

The record is ASCII JSON with:

- keys sorted at every object level
- compact separators
- non-ASCII characters escaped
- exactly one trailing line feed.

Duplicate keys, floats, non-finite numbers, unknown fields, and alternate JSON
encodings are invalid. The parser accepts at most 1,024 JSON values at a maximum
depth of 8.

The top-level object contains exactly these fields:

| Field | Requirement |
| --- | --- |
| `schema_version` | Integer `1`; booleans are invalid |
| `media_type` | `application/vnd.stampbot.python-distribution-spine.v1+json` |
| `repository` | Exact trusted `id` and `name` |
| `run` | Exact trusted `id` and producer `attempt` |
| `source` | Exact 40-character lowercase `revision` |
| `workflow` | Exact `.github/workflows/` `path`, full `ref`, and 40-character lowercase `sha` |
| `selected_artifact` | Immutable `id` and provider `sha256` for the selected five-file ZIP |
| `selection` | Trusted `wheel_sha256` and selection `record_sha256` |
| `spine` | Exact `filename`, media type, byte `size`, and `sha256` |
| `files` | Five contiguous file-range records |

Run and artifact IDs are positive decimal strings no larger than `2^63 - 1`.
SHA-256 values are 64 lowercase hexadecimal characters. Workflow refs are
limited to safe branch, tag, and pull-request refs.

## File ranges

Each file record contains exactly `filename`, `kind`, `offset`, `sha256`, and
`size`. The ranges begin at byte zero, cover the spine completely, and permit no
gap, overlap, alias, prefix, or trailing byte.

The order is fixed:

1. `python-build-record-amd64.json` as `build-record-amd64`
2. `python-build-record-arm64.json` as `build-record-arm64`
3. `python-selection-record.json` as `selection-record`
4. the selected `PROJECT-VERSION.tar.gz` as `sdist`
5. the selected `PROJECT-VERSION-py3-none-any.whl` as `wheel`.

The wheel and source-distribution filenames must carry the same literal project
and version identity. This boundary compares that identity exactly; it does not
normalize package names or versions. Every file digest must be distinct. The
wheel and selection-record range digests must also match their trusted workflow
outputs.

| Bound | Maximum |
| --- | ---: |
| Canonical record | 128 KiB |
| Each build or selection record | 4 MiB |
| Wheel | 64 MiB |
| Source distribution | 64 MiB |
| Complete spine | 140 MiB |
| One verification read | 1 MiB |

## Selection projection

The verifier parses only the bounded selection record. It does not open the
wheel or source-distribution archive.

The selection record must bind:

- the source revision and selected `amd64` architecture
- distinct amd64 and arm64 build-record digests
- each build-record filename and expected machine name
- the wheel and source-distribution filenames, sizes, and SHA-256 values.

Those values must match the already verified spine ranges. No ZIP, tar, gzip,
network, subprocess, or build-backend parser exists in the consumer.

The unprivileged producer has a different role. It downloads the selected ZIP
by immutable ID, runs the existing selection verifier, and then packs the five
known files into the spine.

## Materialization contract

`materialize` accepts a record, a spine, all trusted identity values, and a new
output directory. The output path must be absolute and contain no `..`
component. Its parent must already exist, be owned by the current user, and
grant no permissions to group or other users. The output itself must not exist.

Before reading either artifact, the materializer walks every directory from `/`
to the output parent. Each component is opened relative to the retained parent
descriptor with `O_DIRECTORY | O_NOFOLLOW`. An ancestor is trusted only when
its owner is UID 0 or the current effective UID. Group- or other-writable
ancestors are rejected, with one Linux exception: a sticky directory owned by
root may lead to a child owned by root or the current user. That exception is
what permits the usual `/tmp/CURRENT_USER_DIRECTORY/...` path without allowing
another UID to replace the current user's child.

Some user namespaces display an unmapped owner of `/` as Linux overflow UID
65534. The materializer treats that value as root-equivalent only when `/`
grants no write permission to group or other users and a bounded read of
`/proc/self/uid_map` proves all three conditions below:

- namespace UID 0 is unmapped
- UID 65534 is also unmapped
- the current effective UID is mapped and is not 65534.

Materialization rejects effective UID 65534 before it trusts any root owner.
Outside this namespace exception, it also rejects 65534 as root authority. The
map proves that no process in the namespace owns that identity. Host root and
any authority outside the user namespace remain part of the root trust boundary.

The operation proceeds as follows:

1. Retain the verified descriptor chain from `/` to the private parent. Open the
   record and spine without following their final path components.
2. Verify the provider digests, complete spine digest, all five ranges, and the
   selection projection.
3. Create a hidden staging directory with mode `0700`.
4. Rehash each range, then create its staged file with no-follow and exclusive
   flags. Each file is mode `0600` and is flushed before use.
5. Recheck the open spine and its path after all five files have been written.
6. Recheck every retained ancestry descriptor and path entry, including owner
   and mode, then confirm that the destination remains absent.
7. Publish with Linux `renameat2(RENAME_NOREPLACE)`. The operation fails closed
   when that syscall or flag is unavailable, and it never replaces a destination
   that appears after the preceding check.
8. Recheck the complete ancestry again and require the destination entry to have
   the staged directory's exact device, inode, mode, and owner.

Until step 7, the requested output path does not exist. On a handled failure, the
materializer uses its retained descriptors and tries to remove the staged files.
Cleanup is best effort: an I/O error, interruption, or process termination can
prevent it. A failure after the rename can therefore leave the requested path in
place, although the materializer never publishes it before all five files have
passed verification.

Use a disposable private parent for every call. If the command returns nonzero,
do not consume anything below that parent. Remove the whole parent before you
retry.

A successful output contains exactly the two native build records, the
selection record, the source distribution, and the wheel.

If another process creates even an empty destination before the no-replace
rename, that competing directory remains untouched and materialization fails.
If an ancestor changes before or immediately after publication, the retained
descriptors expose the mismatch. The materializer then attempts cleanup through
the original parent descriptor.

These checks exclude path replacement by unrelated UIDs. A process running as
the same effective UID, root, or the host-side authority behind an unmapped user
namespace is inside the trust boundary. Those identities must not modify the
materialization ancestry concurrently.

## File identity checks

Record and spine inputs must be single-link regular files. The scripts compare
each opened descriptor with its path and recheck device, inode, mode, link
count, ownership, size, modification time, and change time. Symlinks and hard
links are rejected. Every output-ancestry component is also a retained,
descriptor-relative no-follow open; a symlink anywhere in that chain is
invalid.

`VerifiedSpine.file_chunks(FILENAME)` rereads one recorded range into immutable
chunks of at most 1 MiB and returns nothing until the complete digest matches.
One call can retain up to 64 MiB plus Python object overhead. The materializer
consumes those chunks while the verified spine descriptor remains open and does
not expose its final directory until the verification context exits cleanly.

## Commands

Run the help commands from the repository root with Python 3.12 or newer. They
read local files, need no credentials, and make no changes:

```bash
python .github/scripts/build_python_distribution_spine.py --help
python .github/scripts/python_distribution_spine.py verify --help
python .github/scripts/python_distribution_spine.py materialize --help
```

The materialization example requires Linux with `renameat2` support and uses
Bash. Set `RECORD_PATH` and `SPINE_PATH` to the directly downloaded raw
artifacts. Set the other uppercase variables from the trusted-identity table
above; do not copy them from the record.

Create a private parent before calling `materialize`:

```bash
MATERIALIZATION_PARENT="$(mktemp -d)"
chmod 0700 "$MATERIALIZATION_PARENT"
OUTPUT="$MATERIALIZATION_PARENT/files"
```

`mktemp -d` normally creates an owner-private directory below root-owned sticky
`/tmp`, which satisfies the ancestry rule. The workflows create an equivalent
mode-`0700` child below `RUNNER_TEMP`; a self-hosted runner must keep the
ancestors of `RUNNER_TEMP` within the ownership and write-permission rules above.

Call the materializer with both artifact paths, both provider digests, and every
trusted identity:

```bash
python .github/scripts/python_distribution_spine.py materialize \
  --record "$RECORD_PATH" \
  --spine "$SPINE_PATH" \
  --output "$OUTPUT" \
  --record-artifact-sha256 "$RECORD_ARTIFACT_SHA256" \
  --spine-artifact-sha256 "$SPINE_ARTIFACT_SHA256" \
  --repository-id "$REPOSITORY_ID" \
  --repository-name "$REPOSITORY_NAME" \
  --run-id "$RUN_ID" \
  --run-attempt "$PRODUCER_RUN_ATTEMPT" \
  --source-revision "$SOURCE_REVISION" \
  --workflow-path .github/workflows/python-distribution.yml \
  --workflow-ref "$WORKFLOW_REF" \
  --workflow-sha "$WORKFLOW_SHA" \
  --selected-artifact-id "$SELECTED_ARTIFACT_ID" \
  --selected-artifact-sha256 "$SELECTED_ARTIFACT_SHA256" \
  --wheel-sha256 "$WHEEL_SHA256" \
  --selection-record-sha256 "$SELECTION_RECORD_SHA256"
```

A successful command creates `$OUTPUT` with mode `0700` and five mode-`0600`
files. After a nonzero result, do not read `$OUTPUT`, even if the path exists;
discard `$MATERIALIZATION_PARENT` instead.

## What verification does not prove

A valid spine proves that five byte sequences match the supplied workflow
identity and selection evidence. It does not prove that:

- either distribution is safe to install
- archive members are well formed
- the source is free of malicious code
- the files were published or retained permanently
- the caller has release authority.

The blocked Python job is configured to attest and sign only the materialized
wheel and source distribution. It also uploads the three JSON records to a
separate run-scoped artifact. The blocked candidate assembler does not trust
that ZIP: it consumes the raw spine by immutable ID, revalidates the five-file
set, and retains each original record directly.

Local integration tests show that the candidate keeps all three records from a
complete five-file proof and rejects an arm64 record with the wrong machine.
The candidate has not run in the hosted workflow, and a seven-day Actions
artifact would not be durable evidence. Issue #32 therefore remains open.

The candidate does not choose a future public release asset set. Its record is
structurally incompatible with the release controller, and the GitHub release
job does not consume it.

The raw producer retains its direct artifacts for five days. The blocked
privileged job is configured for seven-day run artifacts if it is eventually
enabled. Neither retention period is archival storage.

## Rerun limitation in the older handoff

The native amd64 and arm64 artifacts still use the current workflow attempt in
their names. If selection fails after both native jobs succeed, rerun all jobs.
A failed-jobs-only rerun would search for native artifacts named with the new
attempt even though the successful jobs used the previous one. The direct raw
spine handoff does not have this limitation.
