# Authenticated Actions build provenance

`.github/scripts/verify_actions_build_provenance.py` proves that one acquired
release asset appears in a GitHub-verified SLSA provenance statement from the
exact tagged workflow run that the release manifest names.

The command is read-only. It emits a deterministic JSON record with
`publication_allowed: false`. No release workflow calls it.

## Where this fits

The verifier joins two facts that the preceding commands establish separately:

```text
reviewed manifest ──┬── authenticated workflow record
                    └── acquisition record + private asset directory
                                      │
                                      ▼
                     authenticated Actions provenance
```

The workflow record fixes the repository, workflow source, run ID, and run
attempt. The acquisition record fixes the release asset's GitHub ID, name,
size, and SHA-256. Both records must name the same authenticated release and
repository owner.

Supply each record's SHA-256 through the handoff from the command that produced
it. A digest copied from the candidate release is not a trust anchor.

## Command

| Option | Required | Default | Contract |
| --- | --- | --- | --- |
| `--manifest PATH` | yes | none | Canonical schema-1 release-controller manifest. |
| `--manifest-sha256 HEX` | yes | none | Independently trusted lowercase SHA-256 of the manifest. |
| `--authenticated-workflow-record PATH` | yes | none | Canonical schema-1 authenticated release workflow record. |
| `--authenticated-workflow-record-sha256 HEX` | yes | none | SHA-256 carried from workflow verification. |
| `--acquisition-record PATH` | yes | none | Canonical schema-1 release asset acquisition record. |
| `--acquisition-record-sha256 HEX` | yes | none | SHA-256 carried from asset acquisition. |
| `--asset-root PATH` | yes | none | Absolute path to the private directory created by the acquirer. |
| `--asset-name NAME` | yes | none | One exact asset name from the manifest and acquisition record. |
| `--gh PATH` | no | `gh` | GitHub CLI executable; it must resolve to an executable regular file. |
| `--timeout-seconds NUMBER` | no | `120` | Per-command timeout greater than `0` and no greater than `300` seconds. |

Run the command from a previously reviewed checkout, not from the tag being
verified. Extra CODEOWNERS pins GitHub CLI 2.96.0 and refuses versions older
than 2.93.0 because of
[GHSA-8xvp-7hj6-mcj9](https://github.com/cli/cli/security/advisories/GHSA-8xvp-7hj6-mcj9).

The asset root must belong to the current user and have mode `0700`. It must
contain the manifest's exact flat inventory; each file must be a single-link
regular file owned by the current user with mode `0600` and the expected size.
Run the verifier under an operating-system identity that no untrusted process
shares.

## Credentials

GitHub CLI must have an authenticated session. For a private repository, the
token needs **Attestations: read** and **Contents: read** on that repository.
The command does not need Actions, OpenID Connect, package, or write
permission.

The selected token is passed to the child process as `GH_TOKEN`, never as an
argument. The reduced environment omits unrelated secrets, proxy variables,
Actions runtime tokens, and Actions OpenID Connect variables.

## Checks

The verifier:

1. Binds the manifest and both input records to their separately supplied
   SHA-256 values.
2. Requires the records' exact schemas, asset inventories, repository IDs,
   owner ID, tag, commit, workflow, run ID, and run attempt.
3. Hashes the selected private file through a retained no-follow descriptor.
4. Runs `gh attestation verify` with the exact certificate identity, GitHub
   OpenID Connect issuer, tagged source ref, source commit, signer commit,
   GitHub-hosted runner requirement, SHA-256 algorithm, and SLSA provenance
   predicate type.
5. Decodes the verified DSSE payload and requires it to equal the statement
   returned by GitHub CLI.
6. Matches the certificate, SLSA workflow build definition, repository IDs,
   source dependency, builder, and invocation URI to the manifest and workflow
   record.
7. Requires the selected asset name and SHA-256 exactly once in the statement.
   A statement may cover other unique, safely named subjects.
8. Selects exactly one attestation from the authenticated run attempt. Valid
   attestations from older attempts do not satisfy the check.
9. Rehashes the retained file and rechecks its path and root directory after
   GitHub CLI exits.

The command uses `--cert-identity`, not GitHub CLI's workflow-name filter. In
the pinned client, that workflow filter is a prefix match and is not suitable
for this exact-identity boundary.

## Output record

Success writes one canonical JSON object followed by a newline:

| Field | Meaning |
| --- | --- |
| `schema_version` | Exactly `1`. |
| `kind` | Exactly `extra-codeowners/authenticated-actions-build-provenance`. |
| `publication_allowed` | Always `false`. |
| `controller_manifest` | Trusted manifest `sha256`. |
| `authenticated_release` | Authenticated release record `sha256` shared by both inputs. |
| `authenticated_workflow` | Input workflow record `sha256`. |
| `acquired_assets` | Input acquisition record `sha256`. |
| `repository`, `tag`, `workflow` | Exact source and producer identity used for verification. |
| `asset` | Selected GitHub asset ID, name, flat path, SHA-256, and size. |
| `github_cli` | Enforced minimum and observed client versions. |
| `attestation` | Media and predicate types, DSSE statement-payload SHA-256, subject count, and verified timestamp count. |

The record has no clock-derived field. Unchanged inputs, GitHub state, run
attempt, artifact bytes, and client version produce the same JSON.

## Limits and failure behavior

| Resource | Limit |
| --- | --- |
| Input manifest or record | 256 KiB each |
| Manifest assets or statement subjects | 64 |
| Attestations fetched and parsed | 30 |
| Decoded DSSE statement | 1 MiB |
| GitHub CLI JSON output | 8 MiB |
| GitHub CLI standard error | 64 KiB |
| One GitHub CLI command | 120 seconds by default; configurable to at most 300 seconds |

Duplicate JSON keys, floating-point values, malformed base64, unexpected
fields, ambiguous attestations, identity drift, hard links, symlinks, special
files, permission drift, digest mismatches, and selected-file or root-path
changes are hard failures. The command writes no partial success record.

## Non-claims

This verifier checks one selected file. It does not decide which release assets
must carry Actions provenance, and it does not:

- verify a Cosign blob signature or its bundle; use the separate
  [blob-signature verifier](authenticated-blob-signature.md)
- verify an Open Container Initiative (OCI) index, platform, signature, or
  registry attestation; the separate [OCI index
  command](authenticated-oci-index.md) authenticates the signed root, and the
  [platform selector](selected-oci-platforms.md) checks its descriptor policy
- authenticate distribution of the controller manifest or its trusted digest
- parse a chart, wheel, source distribution, archive, SBOM, or evidence
  predicate
- call the schema-9 content verifier
- prevent a later workflow rerun
- publish, sign, attest, dispatch, cancel, rerun, repair, or delete anything.

Issue [#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
remaining asset-policy, OCI, and trusted-handoff work.
