# Authenticated GitHub release record

`.github/scripts/verify_github_release.py` authenticates one published,
immutable GitHub release against a reviewed release-controller manifest. It is
a read-only verifier. No workflow calls it, and Extra CODEOWNERS does not have
a supported release yet.

The verifier emits one deterministic JSON record after every check succeeds.
It writes nothing to GitHub and never receives release, package, signing, or
OpenID Connect authority.

A separate
[asset acquisition command](authenticated-release-asset-acquisition.md)
consumes this record and binds downloaded local bytes to the authenticated
inventory. The
[release workflow verifier](authenticated-release-workflow-record.md) consumes
the same record and checks the run and exact workflow file named by the
manifest. Both commands are unwired from workflows.

## Trust input

The command requires two inputs:

- a canonical schema-1
  [release-controller manifest](immutable-release-controller.md)
- the independently trusted SHA-256 of those exact manifest bytes.

The digest is the trust input. Supplying a manifest and a digest obtained from
the same unverified release does not establish an independent asset policy.
The future release pipeline must carry the reviewed manifest digest across the
unprivileged verification handoff.

The manifest fixes the repository ID and name, semantic tag, target commit,
workflow metadata, run ID, and complete asset inventory. This verifier
authenticates the repository, tag, release, and assets. The separate workflow
verifier authenticates the manifest's workflow metadata against live GitHub
state.

## Command

The command accepts these options:

| Option | Required | Default | Contract |
| --- | --- | --- | --- |
| `--manifest PATH` | yes | none | Canonical schema-1 release-controller manifest. The loader requires one bounded, single-link regular file and no-follow file access. |
| `--manifest-sha256 HEX` | yes | none | Independently trusted lowercase SHA-256 of the manifest, expressed as 64 hexadecimal characters. |
| `--gh PATH` | no | `gh` | GitHub CLI executable. It must resolve to an executable regular file. |
| `--timeout-seconds NUMBER` | no | `120` | Per-command timeout greater than `0` and no greater than `300` seconds. |

The verifier requires GitHub CLI 2.93.0 or newer. The repository pins 2.96.0
in `mise.toml`, and the verifier's strict JSON contract is tested against that
version.

Versions through 2.92.0 are affected by
[GHSA-8xvp-7hj6-mcj9][gh-cli-advisory]. The verifier runs `gh version` without
token environment variables and stops before any authenticated command when
the executable is affected.

## Credentials and permissions

GitHub's REST API can serve public attestation records without authentication.
GitHub CLI 2.96.0 still requires an authenticated session for
`gh release verify`. It may use an existing login or a token from `GH_TOKEN` or
`GITHUB_TOKEN`. When both variables are set, they must contain the same value.
The verifier passes the selected value to the child process as `GH_TOKEN`; it
does not put the token in an argument or error message.

For a private repository, use a fine-grained token limited to that repository
with these read-only repository permissions:

- **Contents: read**, for repository, tag, release, and asset records
- **Attestations: read**, for the release attestation.

A GitHub Actions job needs the equivalent permissions:

```yaml
permissions:
  attestations: read
  contents: read
```

The job does not need `id-token`, package, workflow, or write permission.
GitHub documents the
[repository attestation permission][attestation-permission] and the
[release and Git-data permissions][token-permissions].

## Child-process environment

The verifier builds a small environment for every GitHub CLI process. It keeps
the selected authentication, configuration, and cache paths, certificate
paths, `HOME`, and `PATH`. It sets a fixed GitHub host, disables pagers and
update notices, and uses the C locale. Set `XDG_CACHE_HOME` to a private
directory for an isolated cache of Sigstore trust metadata managed through The
Update Framework (TUF).

It does not forward unrelated secrets, proxy configuration, Actions runtime
tokens, or Actions OpenID Connect variables. A command failure reports the
exit status without copying GitHub CLI diagnostics into the verifier's error
message.

The version probe receives no `GH_TOKEN` or `GITHUB_TOKEN`. If `gh` uses a
credential store under `HOME`, that store remains available to the
executable, but `gh version` performs no authenticated operation.

## Verification sequence

The verifier performs these read-only checks in order:

1. Require GitHub CLI 2.93.0 or newer.
2. Read the repository record and require the exact repository and owner IDs.
3. Resolve the semantic tag. One lightweight tag or one annotated tag that
   points directly to a commit is accepted. Preserve both the tag reference
   object and the peeled commit.
4. Read the release by tag and require the controller marker, exact target
   commit, published state, and `immutable: true`.
5. Read one 100-item asset page. The controller allows at most 64 assets, so a
   full page is already an invalid unexpected set. Every expected asset must
   have its exact name, size, GitHub server SHA-256, content type, state, API
   URL, and download URL.
6. Run `gh release verify TAG --repo REPOSITORY --format json`.
7. Parse the verified Sigstore bundle and require its Dead Simple Signing
   Envelope (DSSE) statement to name the exact tag reference object and
   complete asset digest set. For a lightweight tag, that object is the target
   commit; for an annotated tag, it is the annotated-tag object. The GitHub
   release v0.2 predicate must contain the same owner ID, repository and
   package IDs, release database ID, repository name, tag, and package URL.
8. Require the Sigstore verification result to contain the same statement, a
   verified signature and identity, and at least one verified timestamp.
9. Read the repository, tag, release, and assets again. Any change fails the
   run.

GitHub CLI 2.96.0 filters the API response to attestations initiated by
GitHub, fetches the selected bundle, and then serializes a new in-memory
attestation. That object no longer carries the API `bundle_url` or `initiator`
fields. The verifier requires both serialized fields to be empty and instead
cross-checks the cryptographically verified result against the bundle
statement.

## Output record

Success writes one canonical JSON object followed by a newline. The record has
exactly these top-level fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Exactly `1`. |
| `kind` | string | Exactly `extra-codeowners/authenticated-github-release`. |
| `controller_manifest` | object | Exact trusted manifest `sha256`. |
| `github_cli` | object | Enforced `minimum_version` and observed `version`. |
| `repository` | object | Immutable repository `id`, exact `name`, and immutable `owner_id`. |
| `tag` | object | Semantic tag `name`, exact 40-character `target_commit`, and the `attestation_subject_sha1` tag-reference object verified by GitHub CLI. |
| `release` | object | Release `id`, canonical `url`, literal `immutable: true`, exact `attestation_predicate_type`, and SHA-256 of the verified DSSE payload. |
| `assets` | array | Manifest-sorted asset `name`, `sha256`, and `size` records. |

The output contains no timestamp. Repeating the verification against unchanged
GitHub state and the same client version produces the same record.

## Resource limits and failure behavior

The command enforces these process and parser limits:

| Resource | Limit |
| --- | --- |
| One GitHub CLI command | 120 seconds by default; configurable to at most 300 seconds |
| Version output | 4 KiB |
| JSON standard output | 8 MiB |
| Standard error | 64 KiB |
| Decoded release-attestation statement | 1 MiB |
| Parsed JSON nesting | 32 levels |
| Parsed JSON values and object keys | 200,000 |
| Controller assets | 64, inherited from the controller manifest |

The process runner uses a fixed argument vector and no shell. It starts each
command in a new process group, closes standard input, and terminates the group
after a timeout or output-limit failure. JSON parsing rejects duplicate keys,
floating-point values, non-finite numbers, invalid UTF-8, excessive nesting,
and excessive structure.

The command emits no success record until the final reread passes. Any nonzero
exit is a hard failure.

## Non-claims

This verifier does not:

- download a release asset or compare local bytes with the authenticated
  digest
- authenticate the release workflow; use the separate workflow verifier
- prove that the checked workflow produced an asset
- verify an Actions build-provenance attestation
- verify an Open Container Initiative (OCI) index, platform manifest,
  signature, software bill of materials (SBOM), provenance, or evidence
  attestation
- run the schema-9 content verifier
- accept a draft or mutable release
- publish, repair, delete, or resume a release.

Issue [#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
missing per-asset provenance, signer, and OCI authentication steps. Issue
[#25](https://github.com/stampbot/extra-codeowners/issues/25) tracks the
draft-first publication path and repository immutability.

[attestation-permission]: https://docs.github.com/en/rest/repos/attestations
[gh-cli-advisory]: https://github.com/cli/cli/security/advisories/GHSA-8xvp-7hj6-mcj9
[token-permissions]: https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens
