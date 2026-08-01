# Selected OCI platforms

`select_oci_platforms.py` applies the Extra CODEOWNERS release policy to one
already authenticated Open Container Initiative (OCI) root index. It selects
the two runnable image manifests and the BuildKit attestation manifest linked
to each one.

The command is offline. It does not fetch a manifest, call Cosign, inspect an
attestation, or authorize publication.

## Trust inputs

The command requires both inputs from
[`acquire_oci_index.py`](authenticated-oci-index.md):

| Input | Requirement |
| --- | --- |
| Authenticated-index record | Canonical `extra-codeowners/authenticated-oci-index` schema `1` record. |
| Record SHA-256 | Independently retained lowercase SHA-256 of that exact record. |
| Authenticated-index directory | Absolute path to the private directory containing the exact `index.json` and `signature.sigstore.json` files named by the record. |

The record SHA-256 is the trust handoff. Supplying a record and a digest
calculated from that same untrusted copy does not authenticate it.

The upstream index command requires an independently trusted root digest. This
selector does not establish where that digest came from.

## Command

Run the command on Linux from the reviewed verifier checkout. It needs Python
3.12 or newer and the locked project environment, but it needs no credential
or network access.

```bash
set -euo pipefail
umask 077

VERIFIER_CHECKOUT='/opt/extra-codeowners-verifier'
AUTH_WORK="${HOME}/extra-codeowners-release-authentication"
OCI_ROOT="${AUTH_WORK}/oci-index"
OCI_SUMMARY="${AUTH_WORK}/authenticated-oci-index.json"
OCI_SUMMARY_SHA256="$(sha256sum -- "$OCI_SUMMARY" | cut -d ' ' -f 1)"
PLATFORM_SUMMARY="${AUTH_WORK}/selected-oci-platforms.json"
PLATFORM_SUMMARY_TMP="${PLATFORM_SUMMARY}.tmp"

test ! -e "$PLATFORM_SUMMARY"
trap 'rm -f -- "$PLATFORM_SUMMARY_TMP"' EXIT

cd -- "$VERIFIER_CHECKOUT"
mise exec -- python -I -B .github/scripts/select_oci_platforms.py \
  --authenticated-index-record "$OCI_SUMMARY" \
  --authenticated-index-record-sha256 "$OCI_SUMMARY_SHA256" \
  --authenticated-index-directory "$OCI_ROOT" \
  > "$PLATFORM_SUMMARY_TMP"

mv -- "$PLATFORM_SUMMARY_TMP" "$PLATFORM_SUMMARY"
trap - EXIT
```

Exit status `0` and one canonical JSON line in `PLATFORM_SUMMARY` indicate
success. The command does not modify `OCI_ROOT`.

## Arguments

| Argument | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--authenticated-index-record` | yes | none | Canonical authenticated-index record. |
| `--authenticated-index-record-sha256` | yes | none | Independently trusted lowercase SHA-256 of the record bytes. |
| `--authenticated-index-directory` | yes | none | Absolute path to the retained private index directory. |

The command has no network, credential, timeout, trust-root, or output-directory
option.

## Accepted root index

The root must use schema version `2` and media type
`application/vnd.oci.image.index.v1+json`. It must contain exactly four
descriptors in this order:

| Position | Platform | Purpose |
| --- | --- | --- |
| `0` | `linux/amd64` | Runnable amd64 image manifest. |
| `1` | `linux/arm64` | Runnable arm64 image manifest. |
| `2` | `unknown/unknown` | BuildKit attestation manifest for position `0`. |
| `3` | `unknown/unknown` | BuildKit attestation manifest for position `1`. |

Every descriptor must contain only `mediaType`, `digest`, `size`, and
`platform`, except the two attestation descriptors, which must also contain
`annotations`. The media type is always
`application/vnd.oci.image.manifest.v1+json`. Digests are unique lowercase
SHA-256 values, and sizes are positive values no greater than 4 MiB.

The two runnable platform objects contain only `os` and `architecture`. The
selector rejects variants, features, alternate operating systems, additional
architectures, nested indexes, Docker media types, and reordered descriptors.

Each attestation descriptor has exactly these annotations:

| Annotation | Required value |
| --- | --- |
| `vnd.docker.reference.type` | `attestation-manifest` |
| `vnd.docker.reference.digest` | Digest of the corresponding runnable image manifest. |

BuildKit uses `unknown/unknown` so a runtime does not mistake an attestation
manifest for a runnable image. These two descriptors are required release
metadata, not extra supported platforms.

This policy matches the repository's tagged release workflow:

- Buildx `v0.35.0`
- BuildKit `v0.30.0`
- `platforms: linux/amd64,linux/arm64`
- `provenance: mode=max`
- `sbom: true`.

A change to those producer settings must update this contract, its adversarial
fixtures, and the recipient procedure in the same reviewed change.

## Local file checks

Before parsing the index, the selector validates the complete authenticated
record and its internal identity relationships. It then opens one absolute,
owned mode-`0700` directory without following a symbolic link.

The directory must contain exactly:

| File | Local requirement |
| --- | --- |
| `index.json` | Owned, single-link, mode `0600`, exact size and SHA-256 from the record. |
| `signature.sigstore.json` | Owned, single-link, mode `0600`, exact size and SHA-256 from the record. |

The selector keeps both file descriptors open while it parses `index.json`.
Before returning, it rehashes both descriptors, reopens both names without
following links, checks the complete directory inventory again, and verifies
that the directory path still names the opened directory.

Run the command under an operating-system identity that no untrusted process
shares. Descriptor checks do not isolate two hostile processes running as the
same user.

## Output record

Success writes one canonical JSON object followed by a newline. Its top-level
fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Record schema. Currently `1`. |
| `kind` | `extra-codeowners/selected-oci-platforms`. |
| `publication_allowed` | Always `false`. |
| `authenticated_oci_index.sha256` | Exact trusted input-record SHA-256. |
| `controller_manifest.sha256` | Controller-manifest SHA-256 carried by the authenticated record. |
| `repository` | Repository name plus immutable repository and owner IDs. |
| `tag` | Semantic tag and peeled target commit. |
| `workflow` | Authenticated workflow path, ref, revision, run, attempt, signer identity, and source-file SHA-256. |
| `image` | Root image identity, retained input files, and the selected descriptors. |

`image.platforms` contains exact `linux/amd64` and `linux/arm64` keys. Each
value has an `image_manifest` and `attestation_manifest` object with:

| Field | Meaning |
| --- | --- |
| `position` | Zero-based descriptor position in the authenticated root index. |
| `media_type` | Exact OCI image-manifest media type. |
| `digest` | Lowercase digest-addressed child-manifest identity. |
| `size` | Expected raw child-manifest size in bytes. |

The output contains no fetched child bytes and no claims about their contents.

## Resource and failure behavior

- the authenticated record inherits the release manifest's record-size and
  strict-JSON limits
- `index.json` is at most 4 MiB
- the root contains exactly four descriptors
- each child descriptor is at most 4 MiB
- strict JSON rejects duplicate keys, floating-point and non-finite values,
  excessive depth, and excessive structure
- all input files and directory entries are read through bounded,
  no-follow descriptors.

Any mismatch produces exit status `1`, a short diagnostic on standard error,
and no JSON record. Treat failure as a release-authentication failure. Do not
drop an unexpected descriptor, infer a platform from descriptor order alone,
or relabel `unknown/unknown` metadata as a runnable image.

## What this record does not establish

This command establishes the exact descriptor policy within a signed,
digest-addressed root index. It does not:

- establish the trusted handoff for the controller manifest, workflow record,
  or root index digest
- fetch or hash either runnable image manifest
- fetch either BuildKit attestation manifest
- validate an image configuration, layer descriptor, or layer
- inspect Software Bill of Materials (SBOM) or provenance statements stored by
  BuildKit
- discover or verify GitHub artifact attestations, Cosign attestations,
  OpenVEX, or evidence attestations stored through the registry referrers API
- choose the final GitHub release asset set
- invoke the schema-9 content verifier
- authorize signing, semantic tagging, release mutation, deployment, mirroring,
  or publication.

No workflow calls this command. Issue
[#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the child
manifest, registry-attestation, recipient-integration, and publication work.

## Upstream contracts

- [OCI image index specification
  v1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md)
- [OCI descriptor specification
  v1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)
- [Docker BuildKit attestation storage](https://docs.docker.com/build/metadata/attestations/attestation-storage/)
