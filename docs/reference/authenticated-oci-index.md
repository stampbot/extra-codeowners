# Authenticated OCI index

`acquire_oci_index.py` downloads one digest-addressed image index from GitHub
Container Registry (GHCR). It also keeps the one Cosign signature made by the
authenticated release run.

The command does not choose a platform. It gives the next verifier the exact
root index bytes and signature bundle without granting publication authority.

## Trust inputs

The command needs three values from outside the registry:

| Input | Required binding |
| --- | --- |
| Release-controller manifest | Its independently trusted SHA-256 |
| Authenticated release-workflow record | The SHA-256 calculated when that record was stored |
| OCI index digest | An independently trusted lowercase `sha256:` digest |

The manifest fixes the repository, release tag, target commit, workflow path,
workflow revision, and run ID. The
[authenticated workflow record](authenticated-release-workflow-record.md)
adds the owner ID, workflow definition ID, run attempt, run URL, and exact
workflow-file hash.

The index digest remains a separate trust input. Don't copy it from the GHCR
response or the signature bundle and pass it back as `--index-digest`. That
would prove only that the supplied digest has a valid signature, not that it
names the image selected for the release.

## Command

Run the command on Linux from a reviewed checkout with the locked project
dependencies and Cosign installed:

```text
python -I -B .github/scripts/acquire_oci_index.py \
  --manifest PATH \
  --manifest-sha256 HEX64 \
  --authenticated-workflow-record PATH \
  --authenticated-workflow-record-sha256 HEX64 \
  --index-digest sha256:HEX64 \
  --output-dir PATH \
  --cosign-home ABSOLUTE_PATH \
  [--cosign EXECUTABLE] \
  [--registry-timeout-seconds SECONDS] \
  [--cosign-timeout-seconds SECONDS]
```

The options have these meanings:

| Option | Required | Default | Contract |
| --- | --- | --- | --- |
| `--manifest` | yes | none | Canonical release-controller manifest obtained through an independent trusted path. |
| `--manifest-sha256` | yes | none | Independently trusted lowercase SHA-256 of the manifest. |
| `--authenticated-workflow-record` | yes | none | Canonical output from `verify_release_workflow.py`. |
| `--authenticated-workflow-record-sha256` | yes | none | Lowercase SHA-256 calculated after the workflow record was stored. |
| `--index-digest` | yes | none | Independently trusted lowercase `sha256:` digest of the root OCI index. |
| `--output-dir` | yes | none | New private directory for `index.json` and `signature.sigstore.json`. The command refuses to replace an existing path. |
| `--cosign-home` | yes | none | Existing absolute mode-`0700` directory owned by the verifier user. Cosign uses it for its trust cache. |
| `--cosign` | no | `cosign` | Cosign executable. |
| `--registry-timeout-seconds` | no | `30` | Timeout for each GHCR request. Values must be greater than `0` and no more than `120`. |
| `--cosign-timeout-seconds` | no | `180` | Timeout for each Cosign command. Values must be greater than `0` and no more than `600`. |

The repository pins Cosign 3.0.6. The verifier accepts patched releases from
3.0.6 through the end of major version 3.

## Registry access

The command supports the project's public GHCR repository at
`ghcr.io/OWNER/REPOSITORY`. It derives `OWNER/REPOSITORY` from the manifest and
requires lowercase names.

The GHCR client requests an anonymous pull token, then fetches the manifest by
the exact digest. It requires:

- HTTPS requests to `ghcr.io`
- the OCI index response media type
  `application/vnd.oci.image.index.v1+json`
- an identity content encoding
- a bounded `Content-Length`
- a `Docker-Content-Digest` equal to the requested digest
- response bytes whose SHA-256 equals that same digest.

The client refuses redirects. It never sends a bearer token to another host,
and a successful record therefore has an empty `registry.redirects` array.
Private packages and registries other than GHCR are not supported by this
command.

Cosign receives no Docker configuration, registry token, GitHub token, Actions
credential, or OpenID Connect request variable from the verifier. The selected
public package must be readable anonymously.

## Signature verification

Cosign downloads the bundles attached to the exact
`ghcr.io/OWNER/REPOSITORY@sha256:DIGEST` reference. The parser accepts at most
32 newline-delimited v0.3 Sigstore bundles in 16 MiB of output.

Other predicate types and signatures from earlier workflow attempts may be
present. The verifier keeps exactly one bundle that has:

- payload type `application/vnd.in-toto+json`
- statement type `https://in-toto.io/Statement/v1`
- predicate type `https://sigstore.dev/cosign/sign/v1`
- one subject whose SHA-256 equals the trusted index digest
- one Dead Simple Signing Envelope (DSSE) signature
- a Fulcio certificate for the exact repository, tag-scoped workflow, source
  commit, owner and repository IDs, GitHub-hosted runner, `push` trigger, and
  authenticated run attempt
- one Rekor `dsse` v0.0.1 entry bound to the envelope, payload, signature, and
  certificate.

Two matching current-run signatures are an integrity failure. A later
workflow attempt needs a new authenticated workflow record.

The command writes the selected bundle to a private staging directory. It then
runs `cosign verify-blob-attestation` against that local file, the exact digest,
and literal certificate claims. This matters: Cosign verifies the same bundle
bytes that the Python parser inspected, not a second registry response.

Cosign checks the signature, Fulcio chain, signed certificate timestamp, and
Rekor inclusion material against the public Sigstore trust root. The Python
parser separately checks the certificate extensions, in-toto statement,
canonical Rekor body, inclusion bounds, and integrated time.

## Retained files

The command atomically creates a mode-`0700` output directory with two
mode-`0600` files:

| File | Contents |
| --- | --- |
| `index.json` | Exact raw OCI index response whose SHA-256 equals `--index-digest`. |
| `signature.sigstore.json` | Exact current-run bundle selected from Cosign's download. |

Both files are created once. The verifier retains descriptors, rechecks bytes
and filesystem identities after Cosign exits, verifies the complete two-file
inventory, and uses a no-replace rename to expose the final directory.

Run the command in a workspace that no untrusted process can modify as the
same operating-system user. File descriptors and final path checks do not
isolate hostile processes that share that identity.

## Output record

Success writes one canonical JSON object followed by a newline. Its top-level
fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Record schema. Currently `1`. |
| `kind` | `extra-codeowners/authenticated-oci-index`. |
| `publication_allowed` | Always `false`. |
| `controller_manifest.sha256` | Trusted controller-manifest SHA-256. |
| `authenticated_workflow.sha256` | Exact authenticated-workflow record consumed by the command. |
| `repository` | Repository name plus immutable repository and owner IDs. |
| `tag` | Semantic tag and peeled target commit. |
| `workflow` | Workflow path, ref, revision, definition ID, run ID, attempt, URL, source-file SHA-256, and signer identity. |
| `image` | Exact GHCR repository, digest-addressed reference, and retained index identity. |
| `registry` | Fixed host, token and manifest URLs, and the empty redirect list. |
| `signature_bundle` | Retained bundle identity, DSSE hashes, certificate hash, Rekor identity and indices, integrated time, proof tree size, and timestamp counts. |
| `cosign` | Accepted version range and actual client version. |

The index section records the root descriptor count for audit work. It does
not validate descriptor media types, platforms, annotations, or relationships.

## Resource and failure behavior

- the OCI index is at most 4 MiB and contains at most 128 descriptor objects
- the token response is at most 64 KiB
- Cosign may return at most 16 MiB and 32 bundles
- each bundle is at most 4 MiB
- strict JSON rejects duplicate keys, floats, non-finite values, excessive
  depth, and more than 40,000 parsed items
- certificates, signatures, Rekor bodies, proofs, and timestamps inherit the
  bounds from the blob-signature verifier
- Cosign output, diagnostics, execution time, and worker count are bounded.

Any mismatch produces exit status `1`, a short diagnostic on standard error,
and no JSON record. The command removes its private staging directory when
safe cleanup remains possible. It never replaces an existing output path.

Treat failure as an authentication failure. Don't retry with a tag instead of
a digest, a broader signer identity, a custom trust root, registry credentials,
or an insecure Cosign flag.

## What this record does not establish

This command authenticates one root index and one current-run signature. It
does not:

- authenticate the trusted handoff for the manifest or index digest
- require a final set of index descriptors
- select or authenticate the `linux/amd64` or `linux/arm64` manifest
- fetch an image configuration or layer
- verify BuildKit provenance, Software Bill of Materials (SBOM), OpenVEX, or
  evidence attestations
- decide which GitHub release assets are mandatory
- inspect an archive
- authorize signing, semantic tagging, release mutation, deployment, mirroring,
  or publication.

No workflow calls this command. Issue
[#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
remaining platform, attestation, recipient, and privileged publication work.

## Upstream contracts

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [Cosign 3.0.6 `download signature` reference](https://github.com/sigstore/cosign/blob/v3.0.6/doc/cosign_download_signature.md)
- [Cosign 3.0.6 `verify-blob-attestation` reference](https://github.com/sigstore/cosign/blob/v3.0.6/doc/cosign_verify-blob-attestation.md)
- [Sigstore bundle format](https://docs.sigstore.dev/about/bundle/)
- [Fulcio certificate extension directory](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
