# Container evidence release contract

This reference defines the minimum evidence contract for a future supported
Extra CODEOWNERS container release. It is an acceptance boundary, not a current
asset list or a runnable verification procedure.

The [raw OCI release spine](release-spine-format.md) now freezes one internal
transport: a canonical record and an opaque byte-range file for exactly two
platforms. CI proves that transport with a synthetic fixture. The spine is not
a release asset, a recipient evidence archive, or permission to publish.

!!! danger "No current release satisfies this contract"
    Extra CODEOWNERS does not publish a supported container release today. Do
    not substitute pull-request artifacts, manual-run artifacts, or the old
    unsupported `main` image.

Issue [#28](https://github.com/stampbot/extra-codeowners/issues/28) must still
freeze the complete wire format: canonical JSON, the gzip and tar envelope and
member order, `MANIFEST.json` and source-record schemas, Sigstore issuer and
transparency-log requirements, and the SBOM and provenance predicate
contracts.

Three open security gates separate today's CI evidence from this release
contract:

| Issue | Work still required |
| --- | --- |
| [#18](https://github.com/stampbot/extra-codeowners/issues/18) | Complete notice and corresponding-source records for the four native-wheel owners that remain after Greenlet, MarkupSafe, and SQLAlchemy. |
| [#28](https://github.com/stampbot/extra-codeowners/issues/28) | Separate unprivileged collection from publication authority, freeze the wire format, and ship an adversarially tested recipient verifier and how-to. |
| [#32](https://github.com/stampbot/extra-codeowners/issues/32) | Retain the reproducible Python proof in release evidence and pass it to the isolated publication jobs, which must bind the exact selected wheel to the installed runtime. |

The raw spine includes an adversarially tested transport verifier. It does not
finish [#28](https://github.com/stampbot/extra-codeowners/issues/28), which
still requires a separate recipient verifier and a runnable how-to for the
final release assets.

The collector has completed the CPython identity and source portion of #18 and
the Greenlet, MarkupSafe, and SQLAlchemy native-owner portions on both
platforms. It retains the exact locked platform wheel for every native-payload
or embedded-SBOM owner and a separately addressed copy of each raw SBOM. For
Greenlet, it also binds the owner sdist, the complete five-file native set,
each embedded component, the exact Alpine GCC recipe and distfile, and
reviewed source notices. These exact sets prove co-membership in the wheel.
The SBOM has no component-to-file map, so the evidence does not assign an
individual native file to the owner source or a nested component.

MarkupSafe adds one exact native payload and explicit empty SBOM and component
sets. SQLAlchemy adds five exact native payloads and the same explicit empty
sets. Each record binds the exact owner sdist as source evidence, not proof
that every binary byte came from that archive. Four owners remain; their raw
records make the gap inspectable but do not close it.

The collector also replays wheel `RECORD` ownership for historical Python
installations whose bytes remain in lower layers. A release inventory must keep
that `wheel_installations` evidence and its effective-only
`python_record_ownership` projection. Completing source closure must not weaken
file attribution.

CI, manual runs, and the tagged candidate scan share one reusable build-proof
workflow, and each caller builds its proof within its own run. Missing release
assets remain expected until all three issues close and the project announces a
supported release.

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
| `schema_version` | integer | Exactly `6`. |
| `media_type` | string | Exactly `application/vnd.stampbot.container-evidence.v6+tar+gzip`. |
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
- an uncompressed size no greater than 64 MiB, except a member below
  `sources/native-components/`, which may be no greater than 128 MiB.

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
| `inventory/components.json` | Exact normalized component inventory, including the CPython runtime and its identity files, package records, structured native payloads, structured SBOMs, raw wheel identities, historical wheel installations, effective RECORD ownership, and source-completeness status. |
| `inventory/all-layer-files.json` | Every regular, directory, non-regular, and whiteout occurrence in every distributed layer, including security metadata; regular and directory records also carry effective state. |
| `inventory/native-component-coverage.json` | Derived per-owner ledger containing the exact resolved evidence sets and every remaining unresolved native payload and embedded-SBOM component projection. |
| `policy/container-policy.json` | The exact reviewed policy used to accept the candidate. |
| `artifacts/application/` | The exact selected wheel, sdist, both native build records, and cross-architecture selection record; every file is hash-bound by `MANIFEST.json`. |
| `artifacts/native-wheels/` | One exact locked platform wheel for every owner in the union of `native_payloads` and `embedded_sboms`, plus separately retained raw embedded-SBOM bytes. `MANIFEST.json` binds each owner, platform, requested URL and redirect chain, path, size, and SHA-256. |
| `licenses/standard/` | Hash-pinned standard license texts required by reviewed expressions. |
| `licenses/from-source/` | Hash-pinned notices retained from exact source archives. |
| `sources/application/` | Exact tracked Extra CODEOWNERS source blobs and Git modes at the image revision. |
| `sources/base/` | Commit-pinned Docker Official Python recipe, exact recipe-selected CPython source archive, and required license evidence. |
| `sources/python/` | Locked and reviewed-fallback top-level Python sources. |
| `sources/alpine/` | Commit-pinned recipe subtrees and every local or downloaded source named by their verified checksums. |
| `sources/native-components/` | Commit-pinned builder recipe and exact recipe-selected source for resolved components nested inside wheels. |

### Current native-wheel manifest records

Until issue #28 freezes the recipient schema, this is the exact schema-v6
collector format for `MANIFEST.json.native_wheel_artifacts`. It is an inspection
reference, not a promise that the unfinished release wire format will remain
unchanged.

Each wheel record has exactly these fields:

| Field | Requirement |
| --- | --- |
| `owner` | Canonical `python:NAME@VERSION` owner derived from the inventory. |
| `platform` | Exact inventory platform. |
| `url` | Requested lock-file URL. |
| `urls` | Ordered requested URL and redirect chain; every URL is credential-free HTTPS. |
| `filename` | Basename selected from the lock-file URL. |
| `path` | `artifacts/native-wheels/NAME/VERSION/FILENAME`. |
| `size`, `sha256` | Size and lowercase SHA-256 of the retained wheel bytes. |
| `build`, `tags` | Exact WHEEL build value and sorted tag list used for selection. |
| `generated_files` | Sorted records for reviewed installer-generated launchers. |
| `embedded_sboms` | Sorted records for separately retained raw SBOM bytes. |

Each `generated_files` item has exactly `name`, `kind`, `module`, `callable`,
`source_path`, `launcher_interpreter`, and `installed_occurrence`. The
occurrence has exactly `effective`, `layer`, `path`, `sha256`, `size`, `mode`,
`uid`, and `gid`.

Each `embedded_sboms` item has exactly `owner`, `platform`, `url`, `urls`,
`archive_path`, `installed_occurrence`, `path`, `size`, and `sha256`. Its `path`
is
`artifacts/native-wheels/NAME/VERSION/embedded-sboms/ARCHIVE_PATH`, and its
occurrence uses the same exact field set described above. `SHA256SUMS` binds the
wheel, raw SBOM, and manifest bytes independently of these records.

### Current native-component coverage records

`inventory/native-component-coverage.json` and
`MANIFEST.json.native_component_coverage` contain the same canonical object:

| Field | Requirement |
| --- | --- |
| `schema_version` | Exactly `6`. |
| `platform` | Exact inventory platform. |
| `complete` | Derived boolean; `true` only when no native/SBOM owner remains unresolved. |
| `resolved_owners` | Sorted exact owner records copied from the reviewed coverage policy after inventory and lock binding. |
| `unresolved_owners` | Sorted observed owners with native path/hash pairs and embedded-SBOM path/hash/component projections. |

Each resolved owner binds one exact wheel, one exact owner sdist, one complete
owner-level native payload set, every embedded SBOM, and the canonical union of
the components represented by those SBOMs. The native, SBOM, and component
sets must all be present. `native_payloads` and `sboms` may each be empty, but
not both. `components` may be empty and must equal the canonical union of all
`sboms[].components`. Every payload record has an exact path and digest. Its
platform-independent role is derived from
that path by removing the reviewed `site-packages` prefix and normalizing the
platform ABI or auditwheel filename hash. A role cannot be reassigned to
another payload, and both platforms must use the same derived role set. Each
SBOM component binds its exact CycloneDX identity, reviewed license expression,
and source ID.

These records prove exact co-membership in the wheel. The auditwheel SBOM does
not provide a relationship from a component to a file path, hash, or SONAME.
The schema therefore does not attribute any individual payload to the owner
source or to a nested component.

The current per-platform ledger resolves `python:greenlet@3.5.3`,
`python:markupsafe@3.0.3`, and `python:sqlalchemy@2.0.51`, leaving four owners
unresolved. MarkupSafe's record has one native role and explicit empty SBOM and
component sets. Its exact sdist is retained at
`sources/python/markupsafe/3.0.3/markupsafe-3.0.3.tar.gz`. The source members
`LICENSE.txt` and `docs/license.rst` are retained as
`licenses/from-source/python-markupsafe-3.0.3/489a8e110850-LICENSE.txt` and
`licenses/from-source/python-markupsafe-3.0.3/6fc7e80b75b5-license.rst`.
SQLAlchemy's record has five native roles and the same explicit empty sets. Its
exact sdist is retained at
`sources/python/sqlalchemy/2.0.51/sqlalchemy-2.0.51.tar.gz`. Its source notices
are retained at these exact paths:

- `licenses/from-source/python-sqlalchemy-2.0.51/4a0179c4ef9f-copyright.rst`
- `licenses/from-source/python-sqlalchemy-2.0.51/dc1db0b5d174-AUTHORS`
- `licenses/from-source/python-sqlalchemy-2.0.51/e38dfb2d3115-copyright.html`
- `licenses/from-source/python-sqlalchemy-2.0.51/e862bb5b904f-LICENSE`

Greenlet's nested `libgcc` and `libstdc++` records point to the exact Alpine GCC
14.2.0-r6 builder source retained under
`sources/native-components/gcc/14.2.0-r6/`. The shared source-carried notices
are retained under `licenses/from-source/native-gcc-14.2.0-r6/` and attributed
to both nested component package URLs in `license_records`.

A supported release requires `MANIFEST.json` and `inventory/components.json`
to report `source_completeness.complete: true` and the coverage ledger to report
`complete: true` with an empty `unresolved_owners` array. The complete source set
must retain CPython identity/source evidence and historical RECORD replay.
Merely changing either current `false` value is not sufficient.

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

The raw spine can carry OCI objects across the unprivileged-to-privileged
boundary, but it does not complete the boundary by itself. The root OCI index
digest must come from the pinned build action, outside the spine record. A
future publisher must consume only the bounded object snapshot returned from
the descriptor retained by successful spine verification. The verifier hashes
the entire snapshot before exposing it and never rereads the source for that
snapshot. A publisher must not reopen a verified path or finalize a manifest,
tag, release, or other reference until the verification context exits
successfully.

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
