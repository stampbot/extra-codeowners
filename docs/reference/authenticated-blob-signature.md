# Authenticated blob-signature record

`verify_blob_signature.py` verifies one downloaded release asset and its
`ASSET.sigstore.json` companion. It joins the signature to the immutable
release, the exact tagged workflow run, and the local bytes acquired earlier.

The command is read-only with respect to GitHub and the release. Cosign may
update its private trust cache.

## What success establishes

Exit status `0` establishes all of these facts:

- the controller manifest, authenticated workflow record, and acquisition
  record agree on the repository, owner, tag, target commit, and immutable
  release
- the selected asset and its derived `.sigstore.json` filename occur exactly
  once in the authenticated release inventory
- both local files still match their authenticated names, sizes, SHA-256
  values, owners, modes, paths, and retained filesystem identities
- patched Cosign verifies the blob signature, Fulcio chain, signed certificate
  timestamp, and Rekor inclusion material against the public Sigstore trust
  root
- the certificate names the exact tag-scoped release workflow, target commit,
  GitHub-hosted runner, repository and owner IDs, `push` trigger, and
  authenticated run attempt
- the bundle's message digest and canonical Rekor `hashedrekord` body name the
  selected asset bytes, signature, and certificate.

The command then writes one canonical JSON record to standard output. A
successful record always contains `publication_allowed: false`.

## Command

Run the verifier from a reviewed checkout with Python 3.12 or newer and the
locked project dependencies installed:

```text
python -I -B .github/scripts/verify_blob_signature.py \
  --manifest PATH \
  --manifest-sha256 HEX64 \
  --authenticated-workflow-record PATH \
  --authenticated-workflow-record-sha256 HEX64 \
  --acquisition-record PATH \
  --acquisition-record-sha256 HEX64 \
  --asset-root ABSOLUTE_PATH \
  --asset-name RELEASE_ASSET_NAME \
  --cosign-home ABSOLUTE_PATH \
  [--cosign EXECUTABLE] \
  [--timeout-seconds SECONDS]
```

The options have these meanings:

| Option | Required | Default | Contract |
| --- | --- | --- | --- |
| `--manifest` | yes | none | Canonical release-controller manifest obtained through an independent trusted path. |
| `--manifest-sha256` | yes | none | Independently trusted lowercase SHA-256 of the manifest. |
| `--authenticated-workflow-record` | yes | none | Canonical output from `verify_release_workflow.py`. |
| `--authenticated-workflow-record-sha256` | yes | none | Lowercase SHA-256 calculated after the workflow record was stored. |
| `--acquisition-record` | yes | none | Canonical output from `acquire_github_release_assets.py`. |
| `--acquisition-record-sha256` | yes | none | Lowercase SHA-256 calculated after the acquisition record was stored. |
| `--asset-root` | yes | none | Absolute mode-`0700` directory created by the acquisition command. |
| `--asset-name` | yes | none | Exact release filename of the blob to verify. The verifier derives `ASSET_NAME.sigstore.json`; callers cannot substitute another bundle. |
| `--cosign-home` | yes | none | Existing absolute mode-`0700` directory owned by the verifier user. Cosign uses it as `HOME` for its trust cache. |
| `--cosign` | no | `cosign` | Cosign executable. |
| `--timeout-seconds` | no | `180` | Per-command timeout. Values must be greater than `0` and no more than `600`. |

The repository pins Cosign 3.0.6. The verifier accepts patched Cosign releases
from 3.0.6 through the end of major version 3. A major-version change requires
a review because the bundle and command contracts may change.

## Cosign invocation

The verifier calls `cosign verify-blob` with literal values derived from the
authenticated records:

- `--certificate-identity` for
  `https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/TAG`
- `--certificate-oidc-issuer` for GitHub Actions
- exact workflow trigger, repository, tag ref, and commit claims
- `--max-workers 1`
- the exact companion bundle and selected local file.

It does not use regular-expression identity flags, custom trust roots, or
Cosign's `--insecure-ignore-sct` and `--insecure-ignore-tlog` flags. It accepts
only Cosign's exact `Verified OK` success response.

The child process receives a small environment allowlist. GitHub tokens,
Actions runtime credentials, OpenID Connect request variables, and
`SIGSTORE_*` overrides are withheld. `HOME` and `XDG_CACHE_HOME` point beneath
`--cosign-home`. TLS certificate paths and HTTPS proxy settings may pass
through when the operator supplied them.

An empty cache normally requires network access so Cosign can obtain current
Sigstore trust metadata through The Update Framework (TUF). Keep the cache
private. Don't work around an update failure with an unreviewed trust root or
an insecure flag.

## Accepted bundle

The parser accepts the v0.3 Sigstore message-signature bundle emitted by
Cosign 3:

- media type `application/vnd.dev.sigstore.bundle.v0.3+json`
- one `messageSignature` with a `SHA2_256` digest equal to the selected asset
- one DER X.509 certificate
- exactly one Rekor `hashedrekord` v0.0.1 entry with an inclusion promise and
  proof
- zero or one timestamp-verification object containing one to eight RFC 3161
  timestamps.

The verifier independently decodes the certificate's provider-neutral Fulcio
extensions. It requires the build signer, source, repository and owner IDs,
tag ref, workflow revision, GitHub-hosted runner, trigger, public visibility,
token subject, and run-attempt URL to agree with the authenticated workflow.
A certificate carrying a deployment environment is rejected because the
release job doesn't use one.

The canonical Rekor body must repeat the same asset SHA-256, message signature,
and PEM encoding of the certificate. Its integrated time must fall within the
certificate's validity interval. Cosign remains responsible for the
cryptographic signature, trust chain, signed certificate timestamp, and
transparency proof.

## Output

The top-level object contains exactly these sections:

| Field | Meaning |
| --- | --- |
| `schema_version` | Record schema. Currently `1`. |
| `kind` | `extra-codeowners/authenticated-blob-signature`. |
| `publication_allowed` | Always `false`. |
| `controller_manifest.sha256` | Trusted controller-manifest SHA-256. |
| `authenticated_release.sha256` | Hash-bound authenticated-release record shared by the input records. |
| `authenticated_workflow.sha256` | Exact authenticated-workflow record consumed by this command. |
| `acquired_assets.sha256` | Exact acquisition record consumed by this command. |
| `repository` | Repository name plus immutable repository and owner IDs. |
| `tag` | Semantic tag and peeled target commit. |
| `workflow` | Workflow path, ref, revision, definition ID, run ID, attempt, URL, source-file SHA-256, and signer identity. |
| `asset` | Selected asset name, local path, size, SHA-256, and GitHub asset ID. |
| `signature_bundle` | Companion asset identity plus the bundle media type, certificate and signature hashes, Rekor log identity and indices, integrated time, proof tree size, and timestamp counts. |
| `cosign` | Accepted version range and actual client version. |

The record contains hashes and public identities, not a certificate, raw
signature, token, or trust cache.

## Resource and filesystem limits

- the bundle is at most 4 MiB
- strict JSON rejects duplicate keys, floats, non-finite values, excessive
  depth, and more than 40,000 parsed items
- decoded certificates are at most 32 KiB
- signatures are at most 16 KiB
- Rekor bodies, checkpoints, and timestamps are bounded
- the inclusion proof contains at most 128 hashes
- Cosign output, diagnostics, execution time, and worker count are bounded
- the asset directory must be an absolute, verifier-owned mode-`0700`
  directory with the complete manifest inventory
- every asset must be a verifier-owned, single-link, mode-`0600` regular file.

The verifier retains file and directory descriptors while Cosign runs. It
rehashes both files and rechecks their paths afterward. A replacement, link,
permission change, truncation, growth, or directory swap still present at the
final check fails the command.

Run the verifier in a workspace that no untrusted process can modify as the
same operating-system user. Retained descriptors and final path checks do not
isolate two hostile processes that share one user identity.

## Failure behavior

Any mismatch produces exit status `1`, a short diagnostic on standard error,
and no JSON record. Cosign's raw diagnostics are bounded but not copied into
the record or relayed to standard error.

Treat failure as an authentication failure. Don't retry with a different
bundle, weaker identity, broader version range, custom trust root, or insecure
Cosign flag.

## What this record does not establish

This verifier checks one selected blob and its companion bundle. It does not:

- decide which release assets must be signed
- prove Actions build provenance; use the separate provenance verifier
- authenticate the controller manifest's trusted handoff
- select or authenticate an OCI index or platform
- verify OCI signatures, Software Bill of Materials (SBOM), provenance,
  OpenVEX, or evidence attestations in the registry
- inspect the signed blob's internal content
- authorize signing, tagging, release mutation, deployment, or publication.

No release workflow calls this command. Issue
[#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
remaining release-verification and publication boundaries.

## Upstream contracts

- [Sigstore bundle format](https://docs.sigstore.dev/about/bundle/)
- [Cosign 3.0.6 `verify-blob` reference](https://github.com/sigstore/cosign/blob/v3.0.6/doc/cosign_verify-blob.md)
- [Fulcio certificate extension directory](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
- [Cosign transparency-entry verification advisory](https://github.com/sigstore/cosign/security/advisories/GHSA-whqx-f9j3-ch6m)
