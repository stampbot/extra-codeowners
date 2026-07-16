# Container evidence release contract

This reference defines the evidence that a future supported Extra CODEOWNERS
container release must publish. It is a minimum contract, not a complete wire
format or procedure: there is no supported container release today, and no
current release assets satisfy it. Issue #28 must specify and implement the
exact canonical JSON encoding, gzip and tar envelope and member order,
`MANIFEST.json` and source-record schemas, Sigstore issuer and transparency-log
requirements, and SBOM and provenance predicate contracts before publication.

Issue [#18](https://github.com/stampbot/extra-codeowners/issues/18) must close
two remaining source-completeness gaps before an inventory may report complete:

- normalize the CPython runtime into the top-level component and notice
  inventory
- expand native wheel payloads and embedded software bills of materials
  (SBOMs) into component, notice, and corresponding-source records.

The current collector already replays wheel `RECORD` ownership for ineffective
historical Python installs whose bytes remain in distributed lower layers. A
future release inventory must retain that `python_record_installations` evidence
and its effective-only `python_record_ownership` projection; source closure must
not remove or weaken the attribution gate.

Issue [#28](https://github.com/stampbot/extra-codeowners/issues/28) must then
provide privilege-separated collection and publication. That issue will also
add a shipped, adversarially tested verifier and a runnable recipient how-to.
Issue [#32](https://github.com/stampbot/extra-codeowners/issues/32) must provide
a hash-pinned isolated build environment and bind the exact application wheel
to the installed runtime. Until all three issues are closed and a supported
release is announced, missing assets are expected. Do not substitute
pull-request CI artifacts or the unsupported historical `main` image.

## Trust statements

Evidence is platform-specific. Evidence for `linux/amd64` says nothing about
the bytes in `linux/arm64`, and the reverse is also true. For each supported
platform, all of these identities must agree:

1. the platform manifest digest selected from the versioned OCI index
2. the subject of the signed evidence predicate and its OCI attestation
3. the subject recorded in the evidence archive manifest
4. the platform named by the component and all-layer inventories
5. the SHA-256 and filename of the release evidence archive.

A signature proves who produced particular bytes. It does not establish that
the component analysis is complete, that upstream metadata is accurate, or
that a distribution satisfies legal obligations.

## Required assets

A supported version must provide these assets for each supported architecture:

- `extra-codeowners-VERSION-linux-ARCHITECTURE-evidence.tar.gz`
- the archive's GNU-style `.sha256` file
- a keyless Sigstore bundle for the exact archive
- a small evidence predicate bound to the platform manifest digest
- the same predicate as a signed OCI attestation on that platform digest.

The OCI index must have exactly one `linux/amd64` and one `linux/arm64`
manifest. Each platform manifest must have its own signed SPDX SBOM and
evidence attestation. The multi-platform index must have separate provenance
and a signature.

For selected version `VERSION`, the release workflow identity used for every
keyless signature and attestation must be exactly
`https://github.com/stampbot/extra-codeowners/.github/workflows/release.yml@refs/tags/v${VERSION}`,
with `${VERSION}` replaced by the already validated selected version. A
verifier must construct that one literal identity. It must not use a regular
expression that accepts every semantic-version tag, another branch,
repository, or workflow.

## Evidence predicate

The canonical JSON predicate has exactly these fields:

| Field | Type | Requirement |
| --- | --- | --- |
| `schema_version` | integer | Exactly `1`. |
| `media_type` | string | Exactly `application/vnd.stampbot.container-evidence.v1+tar+gzip`. |
| `platform` | string | `linux/amd64` or `linux/arm64`; it must match the selected manifest. |
| `subject_digest` | string | Lowercase `sha256:` digest of the published platform manifest, never a local image configuration digest. |
| `artifact` | object | Exactly `filename` and `sha256`. |
| `artifact.filename` | string | Exact release-asset filename for this platform. |
| `artifact.sha256` | string | Lowercase SHA-256 of the raw archive bytes. |
| `release_url` | string | Immutable GitHub release URL for the selected version tag. |

A workflow rerun may reproduce the same canonical predicate. A recipient may
deduplicate byte-identical, independently verified predicates. Two distinct
valid predicates for one platform digest are an integrity failure.

## Archive envelope

The archive is a deterministic gzip-compressed POSIX tar. Every retained
member is a regular file with:

- a normalized relative POSIX path
- no duplicate path
- mode `0644`
- numeric UID and GID `0`
- owner and group name `root`
- the source commit's committer timestamp as whole Unix seconds, exactly the
  value produced by `git show -s --format=%ct SOURCE_REVISION`
- an uncompressed size no greater than 64 MiB.

Links, devices, FIFOs, sparse files, unknown member types, absolute or
traversing paths, control characters, unsupported PAX fields, negative sizes,
and partial archive iteration are invalid. The archive is limited to 100,000
retained files and 1 GiB of retained and compressed output. A conforming
verifier must enforce its own bounded compressed input, expansion, path,
member-count, PAX/GNU extension, JSON-size, and JSON-depth limits before
creating output.

Generic `tar` extraction and ordinary iteration with Python's `tarfile` module
are not conforming verification procedures. Some malformed extension headers
can terminate iteration without a complete-member signal. The verifier added
by issue #28 must reject malformed headers, premature termination, and archive
trailing-data cases in its test corpus and must create output with no-follow,
exclusive-create semantics.

## Required archive records

The archive must contain at least these entry points:

| Path | Contract |
| --- | --- |
| `MANIFEST.json` | Canonical archive identity, platform subject, reviewed policy digest, complete source status, and every retained source and license record. |
| `SHA256SUMS` | SHA-256 for every other retained member, with exact one-to-one path coverage. |
| `THIRD_PARTY_NOTICES.md` | Human-readable observed and reviewed license expressions for every effective and lower-layer component. |
| `inventory/components.json` | Exact normalized component, package-record, native-payload, SBOM, wheel-identity, historical RECORD-installation, effective RECORD-ownership, and source-completeness inventory. |
| `inventory/all-layer-files.json` | Every regular, directory, non-regular, and whiteout occurrence in every distributed layer, including security metadata; regular and directory records also carry effective state. |
| `policy/container-policy.json` | The exact reviewed policy used to accept the candidate. |
| `licenses/standard/` | Hash-pinned standard license texts required by reviewed expressions. |
| `licenses/from-source/` | Hash-pinned notices retained from exact source archives. |
| `sources/application/` | Exact tracked Extra CODEOWNERS source blobs and Git modes at the image revision. |
| `sources/base/` | Commit-pinned Docker Official Python recipe, CPython source, and required license evidence. |
| `sources/python/` | Locked top-level Python sources plus corresponding sources for every expanded native or SBOM component. |
| `sources/alpine/` | Commit-pinned recipe subtrees and every local or downloaded source named by their verified checksums. |

`MANIFEST.json` and `inventory/components.json` must both report
`source_completeness.complete: true`. Their reason text and the complete source
set must demonstrate closure of both remaining #18 gaps while retaining
historical RECORD replay. Merely removing the
current `false` value is not sufficient.

## Collection and publication boundary

No job that parses a contributor-controlled image or archive may hold package
write, signing, attestation, GitHub release, or OpenID Connect authority. The
required sequence is:

```text
unprivileged pinned fetch
  -> rootless offline discovery parse
  -> unprivileged checksum-addressed distfile fetch
  -> rootless offline final parse and deterministic bundle
  -> digest and policy validation
  -> short-lived isolated signing and publication
```

Rootless parse phases must have no network, no secrets, no Docker socket, an
immutable input, read-only mounts where practical, and explicit memory, CPU,
process, file-count, and disk quotas. The privileged phase accepts only
bounded, schema-validated, digest-addressed outputs from that boundary.

## Retention and mirror behavior

Recipients should preserve the original signed archive, signature bundle,
predicate, release URL, subject platform digest, and release-workflow identity
together. A mirror must retain the original filename and hashes and must not
replace the upstream signature with only a mirror-local signature.

The current pull-request evidence artifacts expire after five days. They are
unsigned review inputs for maintainers and are outside this recipient
contract. If they expire, rerun CI for the exact source revision; do not use an
artifact produced for another commit.

See [container distribution evidence](../explanation/container-distribution-evidence.md)
for design rationale and
[review container evidence](../how-to/review-container-evidence.md) for the
current maintainer-only CI procedure.
