# Container evidence release contract

This reference defines the minimum evidence contract for a future supported
Extra CODEOWNERS container release. It is an acceptance boundary, not a current
asset list or a runnable verification procedure.

The [raw OCI release spine](release-spine-format.md) now freezes one internal
transport: a canonical record and an opaque byte-range file for exactly two
platforms. CI uses pinned Buildx and BuildKit versions to export a real
candidate to a local OCI directory, then verifies the two raw artifacts in a
separate read-only job. The spine is not a release asset, a recipient evidence
archive, or permission to publish.

The [raw Python-distribution
spine](python-distribution-spine-format.md) similarly carries the selected
five-file application proof without archive parsing. The reusable workflow
verifies and materializes that pair in a read-only job. The tagged workflow
also defines a privileged consumer that would retain the three selection
records and attest and sign the distributions, but the publication blocker
keeps it unreachable. A separate blocked candidate assembler would revalidate
the raw pair and inventory those three records, but its
[candidate record](release-asset-candidate-format.md) states that source
completeness and publication are false. The GitHub release job does not consume
either output.

!!! danger "No current release satisfies this contract"
    Extra CODEOWNERS does not publish a supported container release today. Do
    not substitute pull-request artifacts, manual-run artifacts, or the old
    unsupported `main` image.

Issue [#28](https://github.com/stampbot/extra-codeowners/issues/28) still owns
the complete release wire format. The repository has a bounded verifier for
the schema-9 predicate, gzip and tar envelope, `MANIFEST.json`, checksums, and
retained files. A separate read-only verifier authenticates an immutable
GitHub release and its exact asset set. Another command downloads those assets
and binds their local bytes to that authenticated inventory. A third verifier
checks GitHub's successful tag-triggered run and hashes the exact workflow file
at the tagged commit. A fourth downloads one digest-addressed GHCR root index
and locally verifies the current run's exact Cosign signature bundle. None of
these commands runs in a workflow. A fifth offline command applies the exact
four-descriptor release policy and selects both runnable platforms and their
linked BuildKit attestation manifests. The remaining work must bind the trusted
index digest, fetch and authenticate the selected child manifests, and finish
the OCI SBOM, provenance, OpenVEX, and evidence attestation contracts.

CI now gives image and source parsing separate rootless, networkless
boundaries. A Docker-only process exports the local candidate without opening
its archive. The export record binds the archive hash and size to the image
configuration, subject, and platform before a separate parser inventories the
layers. CI also fetches direct and Alpine sources once into verified stores,
reuses those stores for both architectures, and assembles the final bundle
offline.

That is substantial #28 groundwork, not a supported release path. The tagged
workflow does not yet transport and attest the image-export handoff, run the
complete recipient procedure against exact candidate assets, or grant isolated
signing and publication authority. The workflow verifier authenticates one
successful run and its workflow bytes, but no current verifier binds those
facts to an asset producer.

Three open security gates separate today's CI evidence from this release
contract:

| Issue | Work still required |
| --- | --- |
| [#18](https://github.com/stampbot/extra-codeowners/issues/18) | Deliver the complete notices and corresponding-source evidence against the exact platform digests, and document how recipients obtain it. |
| [#28](https://github.com/stampbot/extra-codeowners/issues/28) | Carry the isolated CI handoffs into the tagged candidate pipeline, bind the trusted index digest, authenticate both platform manifests and their attestations, connect the content verifier, and finish the signing and publication path. |
| [#32](https://github.com/stampbot/extra-codeowners/issues/32) | Bind the retained Python selection records and exact wheel digest into the complete release evidence, then bind the installed runtime to that same wheel. |

The raw spine includes an adversarially tested transport verifier. The
schema-9 evidence archive now has a separate content verifier. Neither one
finishes [#28](https://github.com/stampbot/extra-codeowners/issues/28): the
release workflow still has to authenticate the final assets and exercise the
complete recipient procedure before publication.

The collector has completed CPython identity and source accounting and closes
all seven observed native owners on both platforms. It retains the exact
platform wheel for every native-payload or embedded-SBOM owner and a separately
addressed copy of each raw SBOM. For Greenlet, it also binds the owner sdist,
the complete five-file native set, each embedded component, the exact Alpine
GCC recipe and distfile, and reviewed source notices. These exact sets prove
co-membership in the wheel. The SBOM has no component-to-file map, so the
evidence does not assign an individual native file to the owner source or a
nested component.

Cryptography adds exact archives, checksums, manifests, licenses, and notices
for 32 crates.io components. Its record also retains the sdist's local Rust
subtree and the official checksummed OpenSSL 4.0.1 release. The arm64
`NotpineForGHA` observation remains literal. A relationship links it to
Greenlet's reviewed Alpine GCC evidence because the `libgcc` payload bytes
match exactly.

Pydantic Core adds exact archives, manifests, checksums, licenses, and notices
for all 87 crates.io components in its SBOM. The retained sdist supplies its
root Cargo package and exact lockfile, including 16 registry packages that the
SBOM does not claim as components. The extension payload cites the complete
reviewed observation set.

MarkupSafe adds one exact native payload, no SBOM observations, and an owner
payload disposition. SQLAlchemy adds five exact native payloads with the same
review shape. Each record binds the exact owner sdist as source evidence, not
proof that every binary byte came from that archive. The Cryptography record
also does not claim wheel reproducibility or build provenance.

The signed wheelhouse records CFFI's `libffi.so.8`, Psycopg C's `libpq.so.5`,
and Pydantic Core's `libgcc_s.so.1` dependencies. Schema 9 binds each SONAME to
an exact effective runtime path, resolved regular-file path, APK package and
version, and APK checksum. It rejects search-path overrides, absolute or chained
links, cross-directory targets, and cross-package substitutions.

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

The root index also contains exactly two BuildKit attestation-manifest
descriptors. Each one uses platform `unknown/unknown` and links to one runnable
manifest through `vnd.docker.reference.digest`. These are required metadata
descriptors, not supported runtime platforms.

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
| `schema_version` | integer | Exactly `9`. |
| `media_type` | string | Exactly `application/vnd.stampbot.container-evidence.v9+tar+gzip`. |
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

The archive is one deterministic gzip member containing a POSIX pax tar. Its
gzip header has no optional fields, timestamp `0`, maximum-compression marker
`2`, and operating-system byte `255`. The verifier requires the exact CRC-32
and input-size trailer and rejects concatenated members or any trailing byte.

Tar members are sorted by their UTF-8 path bytes. A path longer than the
100-byte name field, or containing non-ASCII text, uses one canonical
path-only pax header immediately before the file. Short ASCII paths do not use
pax. The stream ends with two zero blocks and only the zero padding needed to
reach the next 10,240-byte tar record boundary.

Every retained member is a regular file with:

- a normalized relative POSIX path
- no duplicate path
- mode `0644`
- numeric UID and GID `0`
- owner and group name `root`
- the source commit's committer timestamp as whole Unix seconds, exactly the
  value produced by `git show -s --format=%ct SOURCE_REVISION`
- an uncompressed size no greater than 64 MiB, except a member below
  `sources/native-components/` or an Alpine distfile at
  `sources/alpine/ORIGIN/COMMIT/distfiles/FILENAME`, which may be no greater
  than 128 MiB.

Links, devices, FIFOs, sparse files, unknown member types, absolute or
traversing paths, control characters, unsupported PAX fields, negative sizes,
and partial archive iteration are invalid.

The recipient verifier enforces these resource limits. Envelope and path
limits apply before file creation, JSON limits apply before decoding, and the
semantic limits apply during SPDX parsing and filesystem replay:

| Input | Limit |
| --- | --- |
| Compressed archive | 1 GiB |
| Expanded tar stream | 2 GiB |
| Retained member bytes | 1 GiB |
| Retained files | 100,000 |
| One path | 4,096 UTF-8 bytes and 32 components |
| All path bytes | 32 MiB |
| All parent-path components | 500,000, including repeated components |
| One pax record | 1 MiB |
| All pax records | 16 MiB |
| One JSON document | 64 MiB |
| All parsed archive JSON | 64 MiB |
| JSON nesting | 64 levels |
| One JSON structure | 250,000 values and object keys |
| All parsed archive JSON structures | 300,000 values and object keys |
| One SPDX expression | 1,024 tokens and 64 levels of parentheses |
| One TOML document | 64 structural levels and 250,000 values |
| Replayed filesystem state | 200,000 paths |
| Filesystem replay state scans | 10,000,000 path inspections |

The JSON preflight reads the byte grammar and counts nesting and structure
before `json.loads` can allocate the object graph. UTF-8 decoding, duplicate-key
checks, integer-only parsing, canonical encoding, and a second bounded walk
follow that preflight. The verifier reads these documents one at a time and
charges both bytes and structure to one archive-wide budget before it loads the
next object graph.

Generic `tar` extraction and ordinary iteration with Python's `tarfile` module
are not conforming verification procedures. Some malformed extension headers
can terminate iteration without a complete-member signal. The repository's
recipient verifier parses the raw block stream, rejects malformed headers,
premature termination, and trailing data, and creates files with no-follow,
exclusive-create semantics.

## Current content verifier

`.github/scripts/recipient_evidence.py` accepts trusted release identity values
and three untrusted files: the evidence archive, its checksum sidecar, and its
predicate. It requires Linux-style no-follow descriptor support and writes
only to a new output directory with permissions no broader than `0700`.
Materialized files are no broader than mode `0600`. On failure, it removes the
incomplete output when it can prove that the original directory still occupies
the output path. It refuses to delete a replacement.

The verifier checks:

- one stable, bounded regular file for each input
- the exact schema-9 predicate, archive filename, release URL, platform
  manifest digest, and archive SHA-256
- the required single-member gzip framing and canonical raw tar structure
  described above
- safe, unique, case-folding-distinct paths and exact member metadata
- complete one-to-one `SHA256SUMS` coverage
- canonical JSON, shared release identity across the manifest and inventories,
  and exact native-component coverage agreement between the manifest,
  inventory, and policy
- the complete all-layer schema: sequential layer identities, every regular,
  directory, link, special-file, and whiteout occurrence, per-layer counts,
  security metadata, and cumulative limits; the verifier replays the layer
  operations to derive each regular file's and directory's effective state
- all six selected-platform filesystem baselines reconstructed from that same
  replay and occurrence history: APK database and world files, reviewed system
  files and links, directory effects, and removals
- every component-evidence collection, including APK databases and shared
  libraries, wheel identities and historical installations, effective RECORD
  ownership, native payloads, and embedded SBOMs; each occurrence must match
  the all-layer inventory and the selected policy coverage
- every schema-9 policy field and nested record, including the selected
  platform's exact component inventory, license resolutions and text pins,
  custom-license evidence, native-component review references, Cargo closure,
  and retained source pins; every reviewed license expression must use the
  bounded canonical SPDX 2.3 grammar, and every standard license or exception
  identifier must exist in license-list-data version `3dfd9aa` at revision
  `421fbabbe80c94c58c12316af1bc6a2dca2362bc`
- explicit distribution approval and a closed source-completeness assertion;
  URL-fetched sources are manifest-bound, while derived subtree manifests and
  Cargo lockfiles are bound by their reviewed policy records; retained
  lockfile bytes are reparsed and reconciled with every reviewed registry
  checksum, lock-only package, and local Cargo package
- the five application artifacts at their canonical flat paths, the
  deterministic application source tar and project identity, installed
  application package bytes, the source tar's exact match to the retained
  application license, the application launcher's exact active-installation
  bytes, every other retained license, and every native-wheel artifact binding
- installer-generated launchers down to their exact RECORD occurrence and
  deterministic launcher bytes; each native artifact's build and tag fields
  must also match its unique historical WHEEL installation
- the complete deterministic `THIRD_PARTY_NOTICES.md` reconstructed from the
  validated inventory, license policy, native review records, omissions, and
  SBOM anomaly ledger
- the exact native-wheelhouse consumer contract, the store's embedded copy of
  that contract, both platform inventories, and the selected platform's
  retained files.

The command emits a canonical JSON summary only after it has consumed the
complete gzip and tar streams, rechecked the stable archive descriptor, and
confirmed that the materialized directory still occupies its original path.

This is an unsigned-content verifier. It does **not** select a platform from an
OCI index, call the separate GitHub release verifier, validate a Sigstore
bundle or transparency-log entry, or verify OCI SBOM, provenance, or evidence
attestations. Those steps must supply the trusted command arguments and
authenticate the exact files before a recipient relies on the summary. The
tagged workflow does not perform those steps yet. In particular, the
application source tar must name the trusted revision, match the expected
project version, and reproduce the installed package bytes. That is an
internal content binding, not proof that GitHub served the named commit.

## Current GitHub release verifier

`.github/scripts/verify_github_release.py` accepts a canonical release-controller
manifest and its independently trusted SHA-256. It requires GitHub CLI 2.93.0
or newer before any authenticated operation. The repository pins 2.96.0 in
`mise.toml`.

The verifier reads the live repository, tag, immutable release, and exact
asset set. It then runs `gh release verify`, checks the GitHub release
v0.2 predicate and every attested asset digest, and requires the Sigstore
verification result to contain the same DSSE statement. A final reread catches
state changes during the run.

Success emits a small canonical
[authenticated GitHub release record](authenticated-github-release-record.md).
The command does not download assets, authenticate the release workflow,
select an OCI platform, or call the schema-9 content verifier. No workflow
invokes it.

Versions through 2.92.0 are affected by
[GHSA-8xvp-7hj6-mcj9](https://github.com/cli/cli/security/advisories/GHSA-8xvp-7hj6-mcj9),
which can expose a CLI token while verification commands fetch trust material.
The verifier checks the client version without token environment variables and
stops before the first GitHub API request when the executable is affected.

## Current release workflow verifier

`.github/scripts/verify_release_workflow.py` accepts the trusted controller
manifest plus a hash-bound authenticated GitHub release record. It requires the
manifest's workflow revision to equal the tagged target commit. It then checks
GitHub's live workflow-run record for the exact repository, owner, run ID,
successful `push` event, semantic tag, target commit, and workflow path.

The command reads the workflow file at that immutable commit, checks its Git
blob identity and size, and records an independent SHA-256. It rereads the run
and file before emitting an
[authenticated release workflow
record](authenticated-release-workflow-record.md) with
`publication_allowed: false`.

This authenticates the reported run and exact workflow source. It does not
prove that the run produced a particular release asset, verify an Actions
build-provenance statement, or authenticate a Sigstore signer by itself. The
separate per-asset verifier described below consumes its record. No workflow
invokes either command.

## Current release asset acquirer

`.github/scripts/acquire_github_release_assets.py` accepts the same trusted
manifest plus a hash-bound authenticated release record. It rechecks the live
repository, tag, release ID, and asset set. It then downloads each asset by
database ID into a create-once private file, enforces the manifest's byte
limit, and checks the exact size and SHA-256.

After a final GitHub reread, the command rehashes every retained descriptor and
atomically exposes one flat directory. Its
[acquisition record](authenticated-release-asset-acquisition.md) names every
local file and states `publication_allowed: false`.

The acquirer treats asset contents as opaque bytes. It does not consume the
workflow record, select an OCI platform, verify OCI signatures or attestations,
or call the schema-9 content verifier. No workflow invokes it. GitHub CLI also
does not expose the temporary asset-download redirect to this command, so
issue #28's redirect-audit criterion remains open.

## Current Actions build-provenance verifier

`.github/scripts/verify_actions_build_provenance.py` accepts the trusted
manifest, a hash-bound workflow record, a hash-bound acquisition record, and
one selected file from the acquirer's private directory. It requires both
records to name the same authenticated release and owner.

The command runs GitHub CLI with the exact certificate identity, OpenID Connect
issuer, tagged source ref, source and signer commit, GitHub-hosted runner, and
SLSA provenance predicate. It independently decodes the verified DSSE payload,
matches the certificate and SLSA workflow build definition to the authenticated
run attempt, and requires the selected name and SHA-256 exactly once. It then
rehashes the retained local file.

Success emits an [authenticated Actions provenance
record](authenticated-actions-build-provenance.md) with
`publication_allowed: false`. The command verifies one file; it does not decide
which assets require provenance or authenticate an OCI index, platform,
signature, or registry attestation. No workflow invokes it.

## Current blob-signature verifier

`.github/scripts/verify_blob_signature.py` accepts the trusted manifest, the
same workflow and acquisition records, one selected file, and that file's
exact `.sigstore.json` companion. Both release assets must appear exactly once
in the authenticated inventory and remain unchanged in the acquirer's private
directory.

The command uses a patched Cosign 3 release to verify the keyless signature,
Fulcio chain and signed certificate timestamp, and Rekor inclusion material.
It also parses the bounded v0.3 message-signature bundle itself. The
independent checks bind the message digest, certificate, canonical Rekor body,
tagged workflow identity, repository and owner IDs, source revision, and run
attempt to the authenticated records.

Success emits an [authenticated blob-signature
record](authenticated-blob-signature.md) with
`publication_allowed: false`. The command verifies one file; it does not decide
which assets must be signed or authenticate an OCI platform. The separate
index command described below handles only the signed root index. No workflow
invokes either command.

## Current OCI index acquirer

`.github/scripts/acquire_oci_index.py` accepts the trusted manifest, a
hash-bound workflow record, and an independently trusted root index digest. It
fetches that exact index from the project's public GHCR repository and checks
the response media type, length, digest header, and bytes. The client refuses
redirects and uses only an anonymous pull token.

Cosign downloads the bundles attached to the digest-addressed image. The
command ignores other predicate types and prior workflow attempts, then
requires exactly one image-signature bundle from the authenticated attempt. It
checks the DSSE statement, Fulcio extensions, canonical Rekor body, inclusion
bounds, and integrated time before Cosign verifies that same local bundle
against the public Sigstore trust root.

Success atomically retains `index.json` and `signature.sigstore.json` in a
private directory. It also emits an [authenticated OCI index
record](authenticated-oci-index.md) with `publication_allowed: false`.

This command doesn't establish where the trusted index digest came from. It
also doesn't choose a platform, validate the index descriptors, fetch an image
configuration or layer, or verify any registry attestation. No workflow invokes
it.

## Current OCI platform selector

`.github/scripts/select_oci_platforms.py` consumes the authenticated-index
record, an independently retained hash of that record, and the private
two-file index directory. It revalidates the complete record and local file
identities, then parses `index.json` without network access.

The selector requires this exact order:

1. `linux/amd64` image manifest
2. `linux/arm64` image manifest
3. `unknown/unknown` BuildKit attestation manifest linked to amd64
4. `unknown/unknown` BuildKit attestation manifest linked to arm64.

It rejects extra fields, descriptors, platforms, annotations, media types,
variants, links, reordered entries, duplicate digests, and oversized child
manifests. Success emits a [selected OCI platforms
record](selected-oci-platforms.md) with `publication_allowed: false`.

The selected digests are authenticated children of the signed root. The
command does not fetch those child manifests, validate their configuration or
layers, or inspect the BuildKit attestations. No workflow invokes it.

## Required archive records

The archive must contain at least these entry points:

| Path | Contract |
| --- | --- |
| `MANIFEST.json` | Canonical archive identity, platform subject, reviewed policy digest, complete source status, and every retained source and license record. |
| `SHA256SUMS` | SHA-256 for every other retained member, with exact one-to-one path coverage. |
| `THIRD_PARTY_NOTICES.md` | Human-readable observed and reviewed license expressions for every effective and lower-layer component. |
| `inventory/components.json` | Exact normalized component inventory, including the CPython runtime and its identity files, package records, APK-owned shared libraries, structured native payloads, structured SBOMs, raw wheel identities, historical wheel installations, and effective RECORD ownership. |
| `inventory/all-layer-files.json` | Every regular, directory, non-regular, and whiteout occurrence in every distributed layer, including security metadata; regular and directory records also carry effective state, and the APK-owned shared-library projection is bound back to these occurrences. |
| `inventory/native-component-coverage.json` | Derived per-owner ledger containing full closed and open review records, reviewed SBOM anomalies, and the exact remaining owner count and names. |
| `policy/container-policy.json` | The exact reviewed policy used to accept the candidate. |
| `policy/native-wheelhouse-consumer.json` | The exact reviewed consumer contract whose digest is bound by policy, source plans, and image labels. |
| `artifacts/application/` | The exact selected wheel, sdist, both native build records, and cross-architecture selection record; every file is hash-bound by `MANIFEST.json`. |
| `artifacts/native-wheelhouse/` | The verified consumer-store record and selected platform files retained from the signed wheelhouse image. |
| `artifacts/native-wheels/` | One exact platform wheel for every owner in the union of `native_payloads` and `embedded_sboms`, plus separately retained raw embedded-SBOM bytes. Lock wheels retain the requested URL and credential-safe redirect origins. Wheelhouse wheels retain their provider and source identity without inventing a download URL. `MANIFEST.json` binds every path, size, and SHA-256. |
| `licenses/standard/` | Hash-pinned standard license texts required by reviewed expressions. |
| `licenses/from-source/` | Hash-pinned notices retained from exact source archives. |
| `sources/application/` | Exact tracked Extra CODEOWNERS source blobs and Git modes at the image revision. |
| `sources/base/` | Commit-pinned Docker Official Python recipe, exact recipe-selected CPython source archive, and required license evidence. |
| `sources/python/` | Locked and reviewed-fallback top-level Python sources. |
| `sources/alpine/` | Commit-pinned recipe subtrees and every local or downloaded source named by their verified checksums. |
| `sources/native-components/` | Hash-addressed native-source artifacts or verified subtree manifests for directly reviewed components nested inside wheels. An owner-sdist source reuses the exact archive under `sources/python/`. |
| `sources/cargo-locks/` | Exact `Cargo.lock` bytes verified from retained owner sdists for owners with crates.io reviews. The policy binds the original member path, digest, size, reviewed source IDs, and complete lock-only registry remainder. The recipient reparses these bytes and reconciles registry checksums and local packages before accepting them. |

### Current native-wheel manifest records

Until issue #28 freezes the recipient schema, this is the exact schema-v9
collector format for `MANIFEST.json.native_wheel_artifacts`. It is an inspection
reference, not a promise that the unfinished release wire format will remain
unchanged.

Each wheel record has common identity fields plus one provider-specific source:

| Field | Requirement |
| --- | --- |
| `owner` | Canonical `python:NAME@VERSION` owner derived from the inventory. |
| `platform` | Exact inventory platform. |
| `url` | Requested lock-file URL; absent for a wheelhouse wheel. |
| `provider` and `source` | Exactly `native-wheelhouse` and its contract source name; absent for a lock wheel. |
| `urls` | For a lock wheel, the exact requested URL followed by the canonical HTTPS origin of each redirect destination. Redirected paths and queries are not persisted. Empty for a wheelhouse wheel. |
| `filename` | Basename selected from the lock-file URL or signed wheelhouse manifest. |
| `path` | `artifacts/native-wheels/NAME/VERSION/FILENAME`. |
| `size`, `sha256` | Size and lowercase SHA-256 of the retained wheel bytes. |
| `build`, `tags` | Exact WHEEL build value and sorted tag list used for selection. The recipient requires both to match the unique validated historical installation. |
| `generated_files` | Sorted records for reviewed installer-generated launchers. |
| `embedded_sboms` | Sorted records for separately retained raw SBOM bytes. |

Each `generated_files` item has exactly `name`, `kind`, `module`, `callable`,
`source_path`, `launcher_interpreter`, and `installed_occurrence`. The
occurrence has exactly `effective`, `layer`, `path`, `sha256`, `size`, `mode`,
`uid`, and `gid`.

Each `embedded_sboms` item uses the same lock URL or wheelhouse provider/source
union and also has `owner`, `platform`, `urls`, `archive_path`,
`installed_occurrence`, `path`, `size`, and `sha256`. Its `path` is
`artifacts/native-wheels/NAME/VERSION/embedded-sboms/ARCHIVE_PATH`, and its
occurrence uses the same exact field set described above. `SHA256SUMS` binds the
wheel, raw SBOM, and manifest bytes independently of these records.

### Current native-component coverage records

`inventory/native-component-coverage.json` and
`MANIFEST.json.native_component_coverage` contain the same canonical object:

| Field | Requirement |
| --- | --- |
| `schema_version` | Exactly `9`. |
| `platform` | Exact inventory platform. |
| `complete` | Derived boolean; true only when every observed native/SBOM owner has a closed review. |
| `resolved_owners` | Sorted, full policy records whose review state is `closed`. |
| `unresolved_owners` | Sorted, full policy records whose review state is `open`. |
| `observed_sbom_anomalies` | Sorted anomaly-review records copied from accepted SBOM metadata-root echoes. |
| `remaining_owner_count` | Number of open owner records. |
| `remaining_owner_names` | Sorted owner names derived from the open records. |

Schema 9 keeps each CycloneDX occurrence distinct. A nonempty `bom-ref` is the
document-local identity; PURL is the fallback only when `bom-ref` is empty.
Repeated PURLs are allowed only when every occurrence has a unique, nonempty
`bom-ref`.

An accepted auditwheel metadata-root echo appears in both the observation and
`observed_sbom_anomalies`. It must be canonically identical to the metadata
component and have an explicit `metadata-root-echo` review. Cryptography and
Greenlet each have one such reviewed anomaly on each platform.

Closed records hold direct component reviews, source IDs, reviewed license
expressions, payload dispositions, and any narrowly validated cross-owner
relationship. Such a relationship binds byte-identical payloads and requires
both named payload dispositions to cite the corresponding observations. Open
records retain those same fields plus structured `known_omissions`; they are
not reduced to path/hash summaries.

All seven current owner records are closed. The resulting ledger has
`complete: true`, `remaining_owner_count: 0`, and empty `unresolved_owners` and
`remaining_owner_names` arrays. This closes the current source-accounting
ledger. It does not approve distribution or finish the recipient-facing release
path.

Native sources use a four-way tagged union: commit-pinned Alpine aports
sources, canonical crates.io archives, canonical subtrees of the locked owner
sdist, and upstream releases bound by a strict checksum document. Their bundle
directory is the first 20 hexadecimal characters of SHA-256 over the source ID:

- kind-specific artifacts or subtree manifests:
  `sources/native-components/SOURCE_DIGEST_PREFIX/`
- source notices: `licenses/from-source/native-SOURCE_DIGEST_PREFIX/`.

For `owner-sdist-subpath`, the exact locked archive remains under
`sources/python/`; the native-source directory retains the verified subtree
manifest.

Any owner with a crates.io component review must also carry a non-null
`cargo_lock` record. Collection extracts the exact named lockfile from the
retained owner sdist and checks the complete registry package set. Reviewed
crate entries must match their source archive checksums; every other crates.io
entry must appear in the sorted `non_sbom_packages` remainder. Foreign
registries, missing or duplicate packages, checksum drift, and unexplained
local packages fail collection. The verified bytes are retained below
`sources/cargo-locks/`.

The raw component inventory does not carry a `source_completeness` assertion.
`MANIFEST.json.source_completeness` is derived from the coverage ledger. A
supported release requires that manifest value and ledger `complete` to be
`true`, with no open owner records, a zero remaining count, and an empty
remaining-name list. CPython identity/source evidence and historical RECORD
replay must also remain intact. Editing a boolean cannot satisfy these gates.

## Collection and publication boundary

No job that parses a contributor-controlled image or archive may hold package
write, signing, attestation, GitHub release, or OpenID Connect authority.

CI currently implements this source and bundle path:

```text
trusted direct-source plan
  -> unprivileged direct-source fetch
  -> rootless offline Alpine distfile plan
  -> unprivileged Alpine distfile fetch
  -> verified stores reused by both architecture jobs
  -> rootless offline final parse and deterministic bundle
```

The two stores are uploaded once and downloaded by immutable artifact ID. Each
bundle consumer binds them to trusted plan digests and sizes; there is no
network fallback. Each source plan retains its exact requested URL. Persisted
redirect destinations are reduced to canonical HTTPS origins, so a redirected
path, signed query, or credential does not enter the store or evidence
manifest.

The rootless parser runs without network access, secrets, a Docker socket,
Linux capabilities, or privilege escalation. It uses a read-only image and
inputs, bounded `tmpfs` scratch, work, and output mounts, and explicit memory,
CPU, process, file-descriptor, byte, and inode limits.

Issue #28 still needs to carry the image-export handoff and these parser
boundaries into the tagged candidate path. It must run the content verifier
against the exact candidate assets, authenticate those assets, and add a
short-lived isolated signing and publication path. That privileged phase may
accept only bounded, schema-validated, digest-addressed outputs from the
parser.

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
