# Container distribution evidence

This directory holds the reviewed policy for Extra CODEOWNERS container
evidence. It is an allowlist, not runtime configuration. A change to a package,
source archive, license, base layer, native payload, or embedded SBOM must be
matched by an intentional policy update.

The current policy schema is `6`. Evidence predicates use
`application/vnd.stampbot.container-evidence.v6+tar+gzip`. The collector
rejects older schemas, unknown fields, and records that no longer match the
image.

## What the evidence covers

The collector inventories every distributed image layer, including bytes hidden
by a later whiteout. It binds CPython to its installed runtime files, the pinned
Docker Official Python recipe, the exact source archive, and the source-carried
license. It also retains the exact locked wheel and raw embedded SBOM for every
Python package that owns native code or an SBOM.

Schema 6 closes one wheel owner at a time. Greenlet, MarkupSafe, and SQLAlchemy
are resolved on both supported architectures.

The Greenlet record:

- binds the exact platform wheel and Greenlet sdist from `uv.lock`
- records all five native files as one exact path-and-digest set, with each
  cross-platform role derived from its installed path
- binds the retained auditwheel SBOM and its exact component, source, and
  reviewed-license set
- requires each nested package URL to keep one identity, source, and reviewed
  license across every resolved owner and SBOM
- pins Alpine's `gcc` recipe at commit
  `fbf60319be3bbaf6dd32ef55cc6fb7189e05c266`
- verifies the recipe-selected GCC 14.2.0 source archive and retains its
  reviewed `COPYING3` and `COPYING.RUNTIME` files.

The MarkupSafe record binds the exact platform wheel, the 80,313-byte sdist from
`uv.lock`, and the wheel's one `_speedups` extension. It also records explicit
empty SBOM and embedded-component sets. An empty set is evidence that the
reviewed wheel contains no such surface; omitting the field is a schema error.

The SQLAlchemy record binds the exact platform wheel, the 9,912,201-byte sdist,
and all five `cyextension` payloads. The wheels contain no embedded SBOM or
separately packaged native library, so the SBOM and component sets are empty.
Each extension names only the platform musl runtime as a dynamic dependency.
The source archive carries the project's Cython sources and no bundled
third-party native code.

These records prove exact co-membership in each reviewed wheel. They do not
prove how an individual binary was built. Greenlet's SBOM does not relate a
component to a file path, hash, or SONAME, so the policy does not assign a file
to the Greenlet sdist, `libgcc`, or `libstdc++`. MarkupSafe and SQLAlchemy have
no embedded SBOM. Their exact sdists do not prove how the compiled extensions
were built or explain every binary byte.

`inventory/native-component-coverage.json` records that result and lists every
owner still open. Four native-wheel owners remain unresolved, so
`source_completeness.complete` and `distribution_approval.approved` both remain
`false`. The ledger is evidence of incremental progress; it is not permission
to distribute the image.

## Raw OCI release spine

CI also checks the [raw OCI release-spine format](../docs/reference/release-spine-format.md).
That check is an internal transport proof, not compliance evidence. It generates
a two-platform fixture and carries it in two unarchived workflow artifacts.

The spine holds opaque OCI object bytes and a canonical range record. It neither
inspects layers nor proves component, notice, source, SBOM, signature,
attestation, or publication completeness. A future release consumer must get
the root index digest directly from the pinned build action, outside the spine
record. It must also consume only the authenticated chunks that the verifier
copied from its open file descriptor, without reopening the path.

## Release guardrails

Collector success is not a legal determination and does not enable
publication. The repository has no `main` publication job, and tagged release
publication remains blocked by:

- [source completeness #18](https://github.com/stampbot/extra-codeowners/issues/18)
- [publication privilege separation #28](https://github.com/stampbot/extra-codeowners/issues/28)
- [selected build-proof handoff #32](https://github.com/stampbot/extra-codeowners/issues/32).

An [older GHCR preview](https://github.com/stampbot/extra-codeowners/issues/30)
is unsupported and incomplete. Do not deploy or mirror it. Pull-request CI
artifacts are short-lived, unsigned review inputs, not release assets.

Follow [Review container evidence](../docs/how-to/review-container-evidence.md)
to inspect both platform artifacts and the policy that accepted them.
