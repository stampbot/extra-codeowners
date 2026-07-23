# Container distribution evidence

This directory holds the reviewed allowlist for Extra CODEOWNERS container
evidence. It isn't runtime configuration. If a package, source archive, license,
base layer, native payload, or embedded software bill of materials (SBOM)
changes, the policy must change with it.

The current policy schema is `7`. Evidence predicates use
`application/vnd.stampbot.container-evidence.v7+tar+gzip`. The collector
rejects schema 6 and every other version; there is no compatibility reader or
automatic migration.

## What schema 7 records

The collector inventories every distributed image layer, including bytes that
a later whiteout hides. It binds CPython to the installed runtime, the pinned
Docker Official Python recipe, the exact source archive, and its license. For
each Python wheel with native code or an embedded SBOM, it also retains the
locked wheel, native payloads, and raw SBOM bytes.

Schema 7 keeps observation separate from review:

- An SBOM observation preserves the document path and digest plus each exact
  component occurrence: type, name, version, package URL (PURL), `bom-ref`,
  hashes, and declared licenses.
- A review cites an occurrence by SBOM path, observation digest, PURL, and
  `bom-ref` when one exists. The review then names the source and the project's
  reviewed license expression.
- A payload disposition says whether a native file belongs to the wheel owner,
  corresponds to reviewed SBOM occurrences, or remains part of a known
  omission.
- A known omission records the affected observations and payload roles, the
  missing evidence, and the exact reason the owner remains open.

Each `known-omission` metadata root or payload disposition must point to the
exact omission that lists its observation or role. A reference listed under a
different omission does not satisfy that claim.

`bom-ref` is the occurrence identity when it is present. A PURL is only the
fallback when `bom-ref` is empty. This matters for the Psycopg wheel: its SBOM
contains four distinct `krb5` occurrences and two distinct `libldap`
occurrences with repeated PURLs. Schema 7 keeps all six because their
`bom-ref` values are unique. It rejects repeated PURLs when any occurrence
lacks a unique, nonempty `bom-ref`.

Some auditwheel documents repeat their metadata root as a canonically identical
top-level component, including the same `bom-ref`. The collector accepts only
that narrow upstream anomaly. The policy must classify the root and carry a
`metadata-root-echo` review with a reason. The coverage ledger reports the
reviewed anomaly; it never silently removes it.

The only cross-owner relationship is
`same-component-by-payload-equivalence`. It requires byte-identical payloads,
matching component identity, a directly reviewed target in a closed owner, and
source and target payload dispositions that cite the exact observations being
related.

## Current closure

Every observed native-wheel owner has a policy record on both architectures.
The record is either `closed` or `open`; an unconfigured owner fails
verification instead of becoming an inferred gap.

| Owner | State | Evidence still missing |
| --- | --- | --- |
| `python:cffi@2.1.0` | Open | `missing-native-sbom` |
| `python:cryptography@48.0.1` | Open | `unresolved-rust-and-openssl-sources` |
| `python:greenlet@3.5.3` | Closed | None |
| `python:markupsafe@3.0.3` | Closed | None |
| `python:psycopg-binary@3.3.4` | Open | `missing-libpq-sbom`, `unreviewed-bundled-library-sources` |
| `python:pydantic-core@2.46.4` | Open | `missing-libgcc-sbom`, `unreviewed-cargo-sources` |
| `python:sqlalchemy@2.0.51` | Closed | None |

Greenlet's reviewed components use the commit-pinned Alpine GCC recipe and
source archive. MarkupSafe and SQLAlchemy have no embedded SBOM, so their
closed records contain empty SBOM and component-review arrays. Their native
payloads are still exact.

The policy can describe four immutable native-source forms: an Alpine aports
recipe and distfiles, a crates.io archive, a verified subtree of the owner's
source distribution, or an upstream archive accompanied by a pinned checksum
document. The bundle retains the exact reviewed notices for every used source.

`inventory/native-component-coverage.json` derives the result from policy and
the observed image. Closed records appear in `resolved_owners`; open records
appear in `unresolved_owners` with their full evidence and omissions.
`source_completeness` is derived in `MANIFEST.json`; it is not trusted as an
input from `inventory/components.json`.

Four owners remain open, so `source_completeness.complete` is `false`.
`distribution_approval.approved` also remains `false`. The ledger records
progress. It does not grant permission to distribute the image.

## Raw OCI release spine

CI also checks the [raw OCI release-spine format](../docs/reference/release-spine-format.md).
That check is an internal transport proof, not compliance evidence. It builds a
real two-platform candidate with pinned BuildKit, then packs its reachable OCI
objects into two unarchived workflow artifacts.

The spine holds opaque OCI object bytes and a canonical range record. It neither
inspects layers nor proves component, notice, source, SBOM, signature,
attestation, or publication completeness. A future release consumer must get
the root index digest directly from the pinned build action, outside the spine
record. It must also consume only the authenticated chunks that the verifier
copied from its open file descriptor, without reopening the path.

## Release guardrails

Collector success is neither a legal determination nor publication authority.
The repository has no `main` publication job, and tagged publication remains
blocked by:

- [source completeness #18](https://github.com/stampbot/extra-codeowners/issues/18)
- [publication privilege separation #28](https://github.com/stampbot/extra-codeowners/issues/28)
- [selected build-proof handoff #32](https://github.com/stampbot/extra-codeowners/issues/32)

An [older GHCR preview](https://github.com/stampbot/extra-codeowners/issues/30)
is unsupported and incomplete. Do not deploy or mirror it. Pull-request CI
artifacts are short-lived, unsigned review inputs rather than release assets.

Follow [Review container evidence](../docs/how-to/review-container-evidence.md)
to inspect both platform artifacts and the policy that accepted them.
