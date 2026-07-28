# Container distribution evidence

This directory holds the reviewed policy for Extra CODEOWNERS container
evidence. It is not application configuration. A change to a package, source
archive, license, base layer, native payload, or embedded software bill of
materials (SBOM) must come with a matching policy review.

The current policy uses schema `9`. Evidence predicates use
`application/vnd.stampbot.container-evidence.v9+tar+gzip`. The collector
rejects every other schema version; there is no compatibility reader or
automatic migration.

## What the collector proves

The collector inventories every image layer, including files that a later OCI
whiteout hides. It binds the installed CPython runtime to the pinned Docker
Official Python recipe, source archive, and license. For each Python wheel with
native code or an embedded SBOM, it retains the selected wheel, installed
payloads, raw SBOM bytes, and the wheel's historical `RECORD` ownership.

Schema 9 keeps observation and review separate:

- An SBOM observation preserves the document path and digest plus every exact
  component occurrence.
- A review cites an occurrence, then names its immutable source and reviewed
  license expression.
- A payload disposition says whether a native file belongs to the wheel owner,
  maps to reviewed SBOM occurrences, or remains a known omission.
- A known omission names the affected observations or payload roles and the
  evidence still missing.

When `bom-ref` is present, it identifies the occurrence within that document.
The package URL (PURL) is the fallback only when `bom-ref` is empty. Repeated
PURLs need unique, nonempty `bom-ref` values.

Some auditwheel SBOMs repeat their metadata root as an identical top-level
component. The parser accepts only that narrow case. Policy must record a
`metadata-root-echo` review, and the coverage ledger reports the anomaly rather
than hiding it.

The only cross-owner relationship is
`same-component-by-payload-equivalence`. It requires byte-identical payloads,
matching component identities, and a directly reviewed target in a closed
owner. Relationships cannot chain.

Rust reviews also carry the exact `Cargo.lock` from the retained owner source
distribution. Bundle generation reparses the lock and rejects missing
packages, foreign registries, or checksum drift.

## APK runtime-library binding

Schema 9 closes the gap between a wheel's recorded ELF dependency and the file
that the final image would load.

The collector parses Alpine's `F`, `R`, and `Z` ownership records. For every
package-owned shared library under `/lib` or `/usr/lib`, it records the package,
APK SHA-1, and effective layer occurrence. A regular file must match APK's
checksum over its bytes. A symbolic link must match APK's checksum over its
target text. Missing, replaced, duplicated, malformed, or checksum-drifted
records fail collection.

Wheelhouse policy then binds each ELF shared-library name to a runtime path and
one final regular file:

| Owner | ELF name | Runtime path | Final file | Alpine package |
| --- | --- | --- | --- | --- |
| `python:cffi@2.1.0` | `libffi.so.8` | `usr/lib/libffi.so.8` | `usr/lib/libffi.so.8.2.0` | `libffi@3.5.2-r1` |
| `python:psycopg-c@3.3.4` | `libpq.so.5` | `usr/lib/libpq.so.5` | `usr/lib/libpq.so.5.18` | `libpq@18.4-r0` |
| `python:pydantic-core@2.46.4` | `libgcc_s.so.1` | `usr/lib/libgcc_s.so.1` | same path | `libgcc@15.2.0-r5` |

Only the default Alpine loader directories are accepted. When the runtime path
is a link, it must point directly to the final file in the same directory and
both paths must belong to the same package. Native wheel inspection also
rejects ELF `RPATH` and `RUNPATH`, so a wheel cannot redirect lookup to an
unreviewed directory.

## Native-owner closure

Every observed native-wheel owner now has a closed policy record on both
architectures.

| Owner | State |
| --- | --- |
| `python:cffi@2.1.0` | Closed |
| `python:cryptography@48.0.1` | Closed |
| `python:greenlet@3.5.3` | Closed |
| `python:markupsafe@3.0.3` | Closed |
| `python:psycopg-c@3.3.4` | Closed |
| `python:pydantic-core@2.46.4` | Closed |
| `python:sqlalchemy@2.0.51` | Closed |

Cryptography binds its registry components to exact crates.io archives,
manifests, checksums, licenses, and notices. Its retained source distribution
supplies the local Rust workspace and lockfile. The policy also pins the
official OpenSSL release and its checksum document.

Greenlet uses the commit-pinned Alpine GCC recipe and source archive. A narrow
payload-equivalence relationship lets Cryptography reuse Greenlet's reviewed
`libgcc` evidence where the bundled bytes match. MarkupSafe and SQLAlchemy have
no embedded SBOMs, but their native payload sets remain exact.

The signed wheelhouse supplies reviewed builds for CFFI, Psycopg C, and
Pydantic Core. The bindings above connect their recorded ELF dependencies to
the final APK-owned runtime files.

`inventory/native-component-coverage.json` derives the result from policy and
the observed image. All seven records appear in `resolved_owners`;
`unresolved_owners` is empty. `MANIFEST.json` therefore records
`source_completeness.complete: true`.

That is source-evidence closure for the current candidate. It is not permission
to distribute the image.

## What still blocks a supported release

`distribution_approval.approved` remains `false`, and the workflow has no
reachable publication job. Collector success is neither a legal conclusion nor
publication authority.

The remaining release work is tracked in:

- [issue #18](https://github.com/stampbot/extra-codeowners/issues/18), which
  covers recipient delivery of notices and corresponding source bound to each
  platform digest
- [issue #28](https://github.com/stampbot/extra-codeowners/issues/28), which
  covers the bounded recipient format and isolated signing and publication
  path
- [issue #32](https://github.com/stampbot/extra-codeowners/issues/32), which
  covers retaining the selected Python build proof in release evidence.

An [older GHCR preview](https://github.com/stampbot/extra-codeowners/issues/30)
is unsupported and incomplete. Do not deploy or mirror it. Pull-request CI
artifacts are short-lived, unsigned review inputs rather than release assets.

## Raw OCI release spine

CI also checks the
[raw OCI release-spine format](../docs/reference/release-spine-format.md). The
spine is an internal transport proof. It holds opaque OCI objects and a
canonical range record, but it does not inspect layers or prove notice, source,
signature, attestation, or publication completeness.

Follow [Review container evidence](../docs/how-to/review-container-evidence.md)
to inspect both platform artifacts and the policy that accepted them.
