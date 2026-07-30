# Authenticated release workflow record

`.github/scripts/verify_release_workflow.py` checks the completed GitHub Actions
run named by a reviewed release-controller manifest. It also reads and hashes
the exact workflow file at the tagged commit. No workflow calls this command,
and Extra CODEOWNERS does not have a supported release yet.

The command is read-only. Success emits one deterministic JSON record with
`publication_allowed: false`.

## Trust inputs

The command requires two canonical records and two separately supplied
digests:

| Input | Required binding |
| --- | --- |
| Release-controller manifest | Its independently trusted SHA-256 |
| Authenticated GitHub release record | The SHA-256 carried from release verification |

The [release-controller manifest](immutable-release-controller.md) fixes the
repository, tag, target commit, workflow path, workflow revision, and run ID.
The [authenticated GitHub release
record](authenticated-github-release-record.md) binds that manifest to the
repository owner, immutable release, and asset inventory that GitHub reported.

The manifest digest remains the root trust input. Don't copy it from the
release under test. The authenticated release record digest binds the next
step to the record that the preceding verifier actually produced.

## Command

The command accepts these options:

| Option | Required | Default | Contract |
| --- | --- | --- | --- |
| `--manifest PATH` | yes | none | Canonical schema-1 release-controller manifest. |
| `--manifest-sha256 HEX` | yes | none | Independently trusted lowercase SHA-256 of the manifest. |
| `--authenticated-release-record PATH` | yes | none | Canonical schema-1 authenticated GitHub release record. |
| `--authenticated-release-record-sha256 HEX` | yes | none | Lowercase SHA-256 carried from release verification. |
| `--gh PATH` | no | `gh` | GitHub CLI executable. It must resolve to an executable regular file. |
| `--timeout-seconds NUMBER` | no | `120` | Per-command timeout greater than `0` and no greater than `300` seconds. |

The repository pins GitHub CLI 2.96.0. The verifier refuses versions older
than 2.93.0 before it sends an authenticated request because earlier versions
are affected by
[GHSA-8xvp-7hj6-mcj9](https://github.com/cli/cli/security/advisories/GHSA-8xvp-7hj6-mcj9).

Run the command from a previously reviewed, read-only checkout. Don't run the
copy from the tag you are trying to verify.

## Credentials and permissions

The verifier makes two GitHub REST reads:

- [Get a workflow run][workflow-run-api]
- [Get repository content][contents-api].

For a private repository, use a fine-grained token limited to that repository
with **Actions: read** and **Contents: read**. If one token also runs the
preceding release verifier, it needs **Attestations: read**.

A GitHub Actions job that runs both verifiers needs:

```yaml
permissions:
  actions: read
  attestations: read
  contents: read
```

The command does not need `id-token`, package, or write permission. It uses the
same reduced child-process environment as the release verifier: the selected
token is passed as `GH_TOKEN`, never as an argument, and unrelated secrets,
proxy variables, Actions runtime tokens, and Actions OpenID Connect variables
are not forwarded.

## Verification sequence

The command performs these checks in order:

1. Bind the controller manifest to its independently supplied SHA-256.
2. Bind the authenticated release record to its supplied SHA-256, then require
   its exact schema, repository, tag, release, asset, and manifest identity.
3. Require the manifest's workflow revision to equal its tagged target commit.
4. Require GitHub CLI 2.93.0 or newer.
5. Read the workflow run by repository and run ID.
6. Require a successful, completed `push` run whose tag, head commit, workflow
   path, repository IDs, owner ID, and canonical run URL match the two input
   records.
7. Read the workflow file from the exact target commit. Require the expected
   path, filename, file type, base64 encoding, byte size, and Git blob SHA-1.
   Compute an independent SHA-256 over the decoded bytes.
8. Read the workflow run and file again. Any change to the checked fields fails
   the command.

The file read uses the 40-character commit revision, not the repository's
default branch. A later edit to `main` therefore cannot change which workflow
bytes the record names.

GitHub can rerun an existing workflow. The record captures the current
`run_attempt`, and the double read catches an attempt change during this
command. A later rerun can produce a different valid record, so preserve the
record used by the rest of a release review.

## Output record

Success writes one canonical JSON object followed by a newline. The record has
exactly these top-level fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Exactly `1`. |
| `kind` | string | Exactly `extra-codeowners/authenticated-release-workflow`. |
| `publication_allowed` | boolean | Always `false`. |
| `controller_manifest` | object | Exact trusted manifest `sha256`. |
| `authenticated_release` | object | SHA-256 of the input authenticated release record. |
| `github_cli` | object | Enforced `minimum_version` and observed `version`. |
| `repository` | object | Repository `id`, exact `name`, and immutable `owner_id`. |
| `tag` | object | Tag `name` and exact 40-character `target_commit`. |
| `workflow` | object | Checked run identity and exact workflow-file identity. |

The `workflow` object contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `event` | string | Exactly `push`. |
| `id` | integer | GitHub's workflow definition ID. |
| `path` | string | Exact manifest workflow path. |
| `ref` | string | Exact `refs/tags/TAG` reference constructed from the manifest tag. |
| `run_id` | integer | Exact manifest run ID. |
| `run_attempt` | integer | Attempt reported by both workflow-run reads. |
| `sha` | string | Workflow revision, equal to the tagged target commit. |
| `url` | string | Canonical GitHub Actions run URL. |
| `file` | object | Decoded `size`, Git `git_blob_sha1`, and independent `sha256` of the workflow bytes. |

The record contains no timestamp. Repeating verification against the same run
attempt, GitHub state, inputs, and client version produces the same JSON.

## Resource limits and failure behavior

| Resource | Limit |
| --- | --- |
| One GitHub CLI command | 120 seconds by default; configurable to at most 300 seconds |
| GitHub CLI JSON output | 8 MiB |
| GitHub CLI standard error | 64 KiB |
| Workflow file | 1 MiB decoded |
| Manifest or authenticated release record | 256 KiB each |

The inherited process runner uses a fixed argument vector and no shell. It
starts each command in a new process group, closes standard input, enforces
output bounds, and terminates the group after a timeout or output-limit
failure.

JSON parsing rejects duplicate keys, floating-point values, non-finite
numbers, invalid UTF-8, excessive nesting, and excessive structure. Workflow
content must use GitHub's bounded canonical base64 representation. The command
emits no record until both final reads pass. Any nonzero exit is a hard
failure.

## Non-claims

This command does not:

- prove that the checked workflow produced a release asset
- verify an Actions build-provenance attestation or its signer
- verify a Sigstore signature, software bill of materials (SBOM), provenance,
  or evidence attestation for an asset or OCI digest
- download or parse a release asset
- authenticate a trusted distribution path for the controller manifest
- make a workflow rerun impossible after verification
- publish, sign, attest, repair, delete, dispatch, cancel, or rerun anything.

Issue [#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
remaining per-asset provenance, signer, OCI, and privileged handoff work.

[contents-api]: https://docs.github.com/en/rest/repos/contents#get-repository-content
[workflow-run-api]: https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run
