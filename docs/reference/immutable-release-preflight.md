# Immutable-release preflight contract

Extra CODEOWNERS can capture a read-only record that proves GitHub reported
immutable releases enabled for one repository. The record is bound to the
repository and the workflow run that requested it. A later job can verify the
record without receiving the token that queried GitHub.

The implementation lives in
`.github/scripts/immutable_release_preflight.py`. No workflow invokes it, and
it has no command-line interface. Nothing in the repository currently mints or
passes its token, changes a repository setting, or makes release publication
reachable.

This contract is one prerequisite for the
[immutable release controller](immutable-release-controller.md). It does not
replace the unfinished release evidence, publication, and recipient checks
tracked by issues
[#18](https://github.com/stampbot/extra-codeowners/issues/18),
[#25](https://github.com/stampbot/extra-codeowners/issues/25),
[#28](https://github.com/stampbot/extra-codeowners/issues/28), and
[#32](https://github.com/stampbot/extra-codeowners/issues/32).

## Permission boundary

`GitHubImmutableReleasePreflightAPI` requires a token and an exact
`OWNER/REPOSITORY` name as constructor arguments. It never reads credentials
from the process environment. Tokens must be printable ASCII without
whitespace or control characters and may contain at most 4,096 bytes. Each
repository-name component may contain at most 100 characters and cannot be `.`
or `..`.

The token needs the **Administration: read** repository permission, and it must
be scoped to the one repository named by trusted workflow context. A classic
personal access token, or any credential that can read Administration settings
for several repositories, is outside this contract.

GitHub documents the permission on the
[immutable-releases repository endpoint](https://docs.github.com/en/rest/repos/repos?apiVersion=2026-03-10#check-if-immutable-releases-are-enabled-for-a-repository).
The publication token described by the
[release API adapter](github-release-api-adapter.md) needs the
**Contents: write** repository permission instead. Keep the tokens in separate
jobs so the code that can publish a release cannot also make its own preflight
evidence.

The adapter makes only these requests:

| Method | Path | Accepted response |
| --- | --- | --- |
| `GET` | `/repos/OWNER/REPOSITORY` | A JSON object whose `id` is a positive integer and whose `full_name` exactly matches trusted routing. |
| `GET` | `/repos/OWNER/REPOSITORY/immutable-releases` | A JSON object containing exactly the Boolean fields `enabled` and `enforced_by_owner`. `enabled` must be `true`. |

Every request goes directly to `api.github.com` with REST API version
`2026-03-10`. The adapter does not follow redirects or retry failures. It
rejects a `200` response with `enabled: false` and also rejects `404`, which
GitHub may use when the setting is disabled or unavailable to the caller.

The configured timeout applies to socket operations, not the whole request.
DNS resolution or a peer that keeps making progress can run longer. A future
job must add its own finite timeout around capture.

## Repository binding

GitHub's settings route names a repository by `OWNER/REPOSITORY`, but the
stable security identity is the numeric repository ID. `capture_record()`
uses this order:

1. Read the repository and require its ID and name to match trusted workflow
   values.
2. Read the immutable-release setting.
3. Read the repository again and require the same ID and name.
4. Write the record only after all three reads pass.

The repeated read detects a rename or replacement during the request
sequence. It cannot make the name-based GitHub routes atomic. Restricting the
installation token to the expected repository ID is the control for that
remaining race.

## Owner-enforcement policy

Both capture and verification require an explicit
`require_owner_enforcement` Boolean. When it is `true`, GitHub must report
`enforced_by_owner: true`. When it is `false`, a repository-level setting is
accepted, but `enabled` must still be `true`.

The requirement comes from trusted workflow policy, not from the record. A
record captured under repository-level enforcement cannot tell its consumer
to accept that weaker policy.

Owner enforcement is the safer release policy because a repository
administrator cannot disable it independently. An organization owner can
still change the policy after preflight, and repository-level enforcement has
an even wider race. GitHub does not offer an atomic setting check and release
publication operation.

## Canonical record

The preflight record uses media type
`application/vnd.stampbot.immutable-release-preflight.v1+json`. Its one
accepted encoding sorts object keys, uses compact separators, escapes
non-ASCII characters, and ends with one line feed. Duplicate keys,
floating-point and non-finite numbers, alternate encodings, unknown fields,
and noncanonical whitespace are invalid.

The top-level object has exactly these fields:

| Field | Requirement |
| --- | --- |
| `schema_version` | Integer `1`. |
| `media_type` | Exact preflight media type. |
| `api` | Object containing only `version`, exactly `2026-03-10`. |
| `repository` | Exact positive numeric `id` and `OWNER/REPOSITORY` `name`. |
| `workflow` | Exact workflow `path`, full `ref`, and lowercase 40-character `sha`. |
| `run` | Positive numeric workflow `id` and `attempt`. |
| `immutable_releases` | Boolean `enabled` and `enforced_by_owner` values returned by GitHub. |

Repository and run integers may not exceed `2^63 - 1`; a Boolean never counts
as an integer. The workflow path must name a YAML file under
`.github/workflows/`. Its ref must bind the same repository and path to a safe
branch, tag, or pull-request ref.

The encoded record may not exceed 64 KiB. Its JSON depth is limited to 8 and
its JSON item count is limited to 4,096.

## Program interface

The module exposes these interfaces for a future workflow wrapper:

| Interface | Contract |
| --- | --- |
| `ExpectedIdentity` | Holds the independently trusted repository, workflow, and run fields. |
| `GitHubImmutableReleasePreflightAPI(token=, repository=, timeout=)` | Implements the two read-only GitHub operations. The default socket-operation timeout is 30 seconds; accepted values are greater than zero and at most 120 seconds. |
| `capture_record(api, output, expected=, require_owner_enforcement=)` | Performs both repository reads and the setting read, writes one new record, and returns the raw bytes' lowercase SHA-256. It never replaces an existing path. |
| `verify_record(path, expected=, capture_sha256=, record_artifact_sha256=, require_owner_enforcement=)` | Verifies the capture digest, provider artifact digest, downloaded bytes, record identity, and policy. It returns a frozen `PreflightRecord`. |
| `PreflightError` | Reports validation, transport, expected file-system, identity, and policy failures. Error text excludes tokens and response bodies. |

The caller must create the output's parent directory in trusted runner storage
before capture. `capture_record()` creates only the final file; it does not
create or validate parent directories. It uses exclusive-create semantics,
calls `os.fchmod()` with mode `0600`, and then requires the file's mode to be
exactly `0600`.
This produces the same private mode even under a restrictive umask.

An `OSError` while changing the mode, writing, or inspecting the open file is
reported as `PreflightError`. Before raising it, the cleanup path attempts to
close the descriptor and remove the partial file. A cleanup failure does not
hide the original error. Cancellation and other `BaseException` subclasses use
the same cleanup path, then propagate unchanged.

## Artifact handoff

A future capture job must expose the following values as direct job outputs.
The publication job must depend on a successful capture job; an `always()` path
must not turn a failed or cancelled capture into acceptable evidence.

| Job output | Source and consumer check |
| --- | --- |
| Capture SHA-256 | The exact value returned by `capture_record()`. Preserve it before upload and do not recompute it from the upload input. |
| Artifact ID | The upload step's immutable artifact ID. Download by this ID, not by a reusable artifact name. |
| Provider artifact SHA-256 | The digest returned by the same upload step. Do not read it from the record or a companion file. |
| Repository ID and name | The trusted values used for capture. The consumer compares them with its own repository context. |
| Workflow path, ref, and SHA | The workflow identity used for capture. The consumer derives its own `ExpectedIdentity` and requires an exact match. |
| Run ID and attempt | The run that captured and uploaded the record. Both must equal the publication job's current run and attempt. |

The reviewed raw-file transport uses `actions/upload-artifact@v7.0.1` with
`archive: false` and `actions/download-artifact@v8.0.1` with `artifact-ids` and
`skip-decompress: true`. Workflows pin both actions by full commit ID. These
settings preserve the record bytes without wrapping them in a ZIP archive. The
consumer must reject a missing, empty, malformed, or duplicate output before it
calls the verifier.

`verify_record()` requires two digests. `capture_sha256` is the independently
preserved return value from capture; `record_artifact_sha256` is the provider's
upload digest. Each must contain exactly 64 lowercase hexadecimal characters
without a `sha256:` prefix. The verifier applies these checks in order:

1. Require the capture and provider digests to be equal.
2. Hash the raw downloaded bytes and require that digest to equal both inputs.
3. Parse the canonical record and compare every identity field with its own
   `ExpectedIdentity`.
4. Reapply the consumer's owner-enforcement requirement.

The first comparison detects replacement between capture and upload. The
raw-byte comparisons detect replacement after upload or during download. A
provider digest by itself cannot prove that the uploaded bytes are the ones
written by `capture_record()`.

The run attempt in both the job output and record must equal the current
publication attempt. A failed-job-only rerun cannot reuse a positive preflight
from an earlier attempt because the setting may have changed. Rerun the
preflight job whenever publication is rerun.

The verifier accepts one nonempty, single-link regular file no larger than 64
KiB. It opens the file with no-follow and nonblocking flags, reads it once, and
requires its device, inode, mode, link count, owner, size, modification time,
and change time to remain stable. Symlinks, hard links, directories, FIFOs,
truncated files, trailing bytes, and path replacement fail closed.

## HTTP response limits

Successful GitHub responses must be uncompressed UTF-8 `application/json`.
Each response is limited to 256 KiB, 8 JSON levels, and 4,096 values. The
adapter rejects duplicate keys, floating-point or non-finite values, integers
outside the signed 63-bit range, malformed content lengths, and a returned body
whose size does not match its declared content length. The adapter closes each
connection after one response and never reuses it, so surplus bytes on the wire
cannot affect a later request.

Transport errors include only the method, bounded path, status, and a bounded
GitHub request ID. They don't include the Authorization header, response body,
or underlying exception text.

## Publication remains blocked

This module does not:

- mint, configure, or receive a token from any current workflow
- upload the record as a GitHub Actions artifact
- pass its artifact ID or either digest to another job
- call the release controller or release API adapter
- enable immutable releases at the repository or organization level
- create, upload, publish, edit, or delete a release, asset, or tag
- prove that the setting remains enabled until publication.

Before workflow integration, test the read-only adapter against a disposable
repository with a short-lived token restricted to that repository. The live
test must cover both organization-enforced and repository-level settings,
disabled responses, repository renames, real response framing, cancellation,
and the minimum GitHub App permission. Publication stays blocked until that
test and the remaining release gates pass.
