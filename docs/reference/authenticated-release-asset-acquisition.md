# Authenticated release asset acquisition

`.github/scripts/acquire_github_release_assets.py` downloads the exact files
named by an authenticated GitHub release record. It treats every file as opaque
bytes. No workflow calls this command, and Extra CODEOWNERS does not have a
supported release yet.

The command writes the files to a new private directory and emits one
deterministic JSON record. It cannot publish, sign, attest, delete, or modify a
GitHub release.

## Trust inputs

The command requires two records and two separately supplied digests:

| Input | Required binding |
| --- | --- |
| Release-controller manifest | Its independently trusted SHA-256 |
| Authenticated GitHub release record | The SHA-256 carried from the read-only release-verification step |

The manifest sets the repository, tag, commit, and complete asset policy. The
authenticated release record proves that GitHub reported an immutable release
with that identity and asset set. The acquirer requires both records to be
canonical, bounded, single-link regular files.

Don't copy either digest from an untrusted release asset. A future workflow must
carry them across reviewed handoffs.

The separate
[release workflow verifier](authenticated-release-workflow-record.md) checks
the run and exact workflow file named by the same manifest. The acquirer does
not consume that record because a matching run alone does not prove which
assets it produced. After both commands succeed, the
[Actions provenance verifier](authenticated-actions-build-provenance.md) can
bind one acquired asset to the exact tagged run.

## Command

The command accepts these options:

| Option | Required | Default | Contract |
| --- | --- | --- | --- |
| `--manifest PATH` | yes | none | Canonical schema-1 release-controller manifest. |
| `--manifest-sha256 HEX` | yes | none | Independently trusted lowercase SHA-256 of the manifest. |
| `--authenticated-release-record PATH` | yes | none | Canonical schema-1 authenticated GitHub release record. |
| `--authenticated-release-record-sha256 HEX` | yes | none | Lowercase SHA-256 carried from the release-verification handoff. |
| `--output-dir PATH` | yes | none | New directory that will contain the acquired files. Its parent must already exist. |
| `--gh PATH` | no | `gh` | GitHub CLI executable. It must resolve to an executable regular file. |
| `--timeout-seconds NUMBER` | no | `120` | Per-command timeout greater than `0` and no greater than `300` seconds. |

The command requires Linux because it uses `renameat2(RENAME_NOREPLACE)` to
promote the completed directory without replacing an existing path.

Run it in a workspace that no untrusted process can modify as the same user.
Retained descriptors and no-follow file access stop path replacement, but they
cannot isolate two hostile processes that share one operating-system identity.

The repository pins GitHub CLI 2.96.0. The command refuses versions older than
2.93.0 before it makes an authenticated request.

## Credentials

Asset acquisition needs **Contents: read** for the target repository. It does
not need Attestations, OpenID Connect, package, workflow, or write permission.

If one job runs the release verifier and acquirer, its token also needs
**Attestations: read** for the earlier `gh release verify` call. Remove the
token before any archive parser runs.

The acquirer uses the same reduced child-process environment as the release
verifier. It passes the selected token as `GH_TOKEN`, never as an argument, and
does not forward Actions OpenID Connect variables or unrelated secrets.

## Acquisition sequence

The command performs these checks in order:

1. Bind the controller manifest to its trusted SHA-256.
2. Bind the authenticated release record to its supplied SHA-256, then require
   its exact schema and manifest identity.
3. Require GitHub CLI 2.93.0 or newer.
4. Read the repository, tag, immutable release by database ID, and complete
   release-asset inventory.
5. Create a random mode-`0700` staging directory beside the requested output.
6. Download each asset through its release-asset database ID. The command
   streams the response through a bounded pipe into one create-once mode-`0600`
   file and checks its size and SHA-256.
7. Read the repository, tag, release, and asset inventory again. Any change
   fails the run.
8. Rehash every retained file descriptor. Require a flat directory containing
   exactly the expected release asset names, and require each path to name the
   same inode that received the download.
9. Synchronize the directory and atomically rename it to `--output-dir` without
   replacement.
10. Emit the acquisition record.

GitHub release assets have a flat namespace, so each local path equals the
asset `name`. The controller manifest's `path` identifies the publisher's
original local file and does not become part of the acquired layout.

## Output record

Success writes one canonical JSON object followed by a newline. The record has
exactly these top-level fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Exactly `1`. |
| `kind` | string | Exactly `extra-codeowners/acquired-github-release-assets`. |
| `publication_allowed` | boolean | Always `false`. |
| `controller_manifest` | object | Exact trusted manifest `sha256`. |
| `authenticated_release` | object | Authenticated-record `sha256` and verified release-attestation payload `sha256`. |
| `github_cli` | object | Enforced `minimum_version` and observed `version`. |
| `repository` | object | Repository `id`, exact `name`, and immutable `owner_id`. |
| `tag` | object | Tag `name`, target commit, and attested tag-reference object. |
| `release` | object | Release `id`, canonical `url`, and literal `immutable: true`. |
| `assets` | array | Name-sorted `github_asset_id`, `name`, flat `path`, `sha256`, and `size` records. |

The record contains no timestamp or absolute local path. Repeating acquisition
against unchanged GitHub state and the same inputs produces the same JSON.

## Resource limits and failure behavior

The command inherits the controller's asset bounds:

| Resource | Limit |
| --- | --- |
| Assets | 64 |
| One asset | 2 GiB |
| All assets | 16 GiB |
| One GitHub CLI command | 120 seconds by default; configurable to at most 300 seconds |
| GitHub CLI standard error | 64 KiB |
| Manifest or authenticated release record | 256 KiB each |

The output directory must not exist. A race that creates it before promotion
fails rather than replacing it.

Any short body, extra body byte, digest mismatch, API change, local path
replacement, hard link, special file, or unexpected directory entry is a hard
failure. The command removes its bounded staging tree when it can do so safely.
Treat a leftover staging directory after a filesystem failure as hostile.

If the final parent-directory `fsync` fails after the atomic rename, the command
prints a warning. The bytes and names have passed verification, but their
survival across an immediate host crash is uncertain.

## Non-claims

This command does not:

- rerun or replace the authenticated GitHub release verifier
- expose or record GitHub CLI's temporary asset-download redirect
- authenticate the release workflow; use the separate workflow verifier
- prove which workflow produced a release asset
- verify an Actions build-provenance attestation; use the separate Actions
  provenance verifier
- select or verify an Open Container Initiative (OCI) index or platform
- verify image signatures, software bills of materials, provenance, or
  evidence attestations
- parse a gzip, tar, wheel, source distribution, chart, or container layer
- call the schema-9 content verifier
- publish, sign, attest, repair, delete, or resume a release.

Issue [#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
remaining asset policy, redirect audit, blob signatures, OCI verification, and
offline-parser handoffs.
