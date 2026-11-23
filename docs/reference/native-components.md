# Wheel-native component catalogs

An image SBOM can list a Python wheel without identifying the C libraries
inside it. Releases containing this feature add two companion catalogs:

- `native-components-amd64.cdx.json`
- `native-components-arm64.cdx.json`

Each is a CycloneDX 1.5 document for the reviewed C-library components in the
Cryptography and Psycopg wheels. It supplements the image SBOM; it is not a
complete image inventory or Rust dependency catalog.

## What the catalog records

Components identify their parent wheel and version. Native components also
carry the reviewed source archive's path, URL and SHA-256, and the hash of the
wheel SBOM used as evidence. Custom Psycopg libraries carry their matching
native-file paths, sizes and hashes. A source archive hash is never presented
as the hash of a compiled library.
Archive paths are relative to the matching `python-source-ARCHITECTURE.tar.gz`
bundle in the same release.

The collector combines two kinds of evidence:

- Cryptography's OpenSSL declaration and Psycopg's RPM-origin library
  declarations come from the exact retained wheel SBOMs. Repeated declarations
  of one RPM package become one catalog component.
- Psycopg's custom OpenSSL, libpq, and OpenLDAP, and its amd64 libxcrypt build,
  come from reviewed source recipes bound to installed files in the signed
  inventory. Auditwheel's SBOM does not declare those libraries. The
  [libxcrypt recipe entry](source-archives.md#the-amd64-psycopg-libxcrypt-build)
  also points to the pinned builder image and install script.

The wheel's own license does not describe every library it bundles. Native
entries therefore say `license-review: unresolved` rather than inheriting
Cryptography's or Psycopg's license. This is an explicit review gap, not a
license exemption. The original declarations and available license texts remain
in the [recipient notice bundle](recipient-notices.md).

Metadata binds the catalog to the architecture, exact platform child digest,
raw inventory, verified notice manifest and release lockfile. The signed
inventory's `python.native_component_catalog` field names the required asset.
Its signature and build attestation accompany the JSON file. The release
verifier rejects missing catalogs, changed bytes or evidence from another
platform. Older inventories without that field remain verifiable without
claiming that a catalog was published.

### Selected upstream notices

The metadata property `extra-codeowners:source-notice-evidence` tells you
where the catalog points: `1` covers standalone upstream tarballs; `2` also
covers upstream tarballs inside source RPMs. The files stay in the Python
source bundle, not the runtime notice bundle.

For OpenSSL, the selection is the archive's top-level `LICENSE.txt`. For
libpq, it is PostgreSQL's top-level `COPYRIGHT`. OpenLDAP supplies top-level
`COPYRIGHT` and `LICENSE`; libxcrypt supplies `COPYING.LIB` and `LICENSING`.
Each selected component has a
`extra-codeowners:source-notice-files` property containing JSON records with
the inner archive path, byte size and SHA-256. Its existing `source-archive`
property identifies the enclosing tarball in `python-source-ARCHITECTURE.tar.gz`.

For standalone tarballs, the verifier checks the complete Python source
bundle against the inventory, lockfile and recipes before reading the files.
It rejects missing, duplicate, linked, sparse or oversized notices. It reads
compressed archives without extracting or executing them, with limits of
512 MiB expanded bytes, 50,000 members and 1 MiB per notice file.

For an RPM-origin component in a version 2 catalog, `source-archive`
identifies the source RPM. Each notice record also has a `member` field:
open that tarball within the RPM, then find the file at `path` and compare its
size and SHA-256. The release verifier checks each enclosing RPM against the
notice receipt in the release checkout; it does not unpack the RPM. The
catalog records the receipt's SHA-256 as
`extra-codeowners:rpm-notice-receipt-sha256`.

When a new wheel changes a source RPM, release generation stops until
`tools/release_rpm_notice_evidence.json` covers the new archive. Review the
RPM recipe for the reported library, then record the exact member paths,
sizes and hashes from the new source archive. Keep the RPM and notice
checks separate from the decision about binary redistribution.

These files give reviewers a place to start. They don't map every copyright
holder to compiled code or establish that the bundles contain all required
source. Catalogs without the metadata property make no notice-selection claim.

### License texts from the standalone sources

Catalogs with `extra-codeowners:source-license-evidence` set to `1` also
carry selected top-level license texts. Each affected component records an
SPDX identifier and the exact text as base64 in the CycloneDX
`evidence.licenses` field. For amd64 libxcrypt this is `COPYING.LIB`;
`LICENSING` in the same archive describes per-file terms. The matching file
paths and SHA-256 hashes are in `extra-codeowners:source-notice-files`.

The verifier checks the source archive and the selected file against reviewed
hashes. If an archive changes, update the selection in
`tools/release_native_notices.py` after checking the new license text. An
older catalog without this marker still verifies without the embedded text.

These are license texts from the source archives. They don't assign a license
to a compiled library or to its parent wheel. RPM-origin components still
have notice references without an embedded license assertion.

### RPM binary attribution

When `extra-codeowners:rpm-binary-evidence` is `1`, the catalog
ties each RPM entry in the Psycopg wheel's SBOM to a shipped library. The
binding records the library's original path and SHA-256 in the vendor RPM
and its size and SHA-256 in the wheel. The verifier checks the original path
against the SBOM, the renamed file against the signed inventory, and the
wheel against the lockfile.

The `binary-rpm-*` properties identify the vendor binary RPM. They record
its declared license and the hashes of any files it marks as license texts.
Those hashes match selected notices in the retained source RPM. An empty
license-files object means the vendor did not mark any files, not that the
library has no notice obligations. The vendor's declaration is not a license
conclusion for the compiled library.

Generation uses `tools/release_rpm_binary_evidence.json` and stops if the
bindings no longer match. To update the receipt for a different wheel,
verify the vendor RPM signatures, compare the original ELF code and
read-only data against the wheel, and confirm the license file hashes in
the source notice receipt. Verify older catalogs with their own release
checkout; they don't gain attribution from a later receipt.

### OpenSSL in Cryptography

When `extra-codeowners:static-wheel-evidence` is `1`, Cryptography's
OpenSSL record identifies the extension that contains the compiled code.
`native-files` gives the extension's path relative to the installed wheel,
size, and SHA-256. `wheel-filename` and `wheel-sha256` identify the
wheel in the lockfile. `native-linkage: static` describes the reviewed
extension; it does not mean that the whole wheel links statically.

The verifier checks those values against the signed inventory and lockfile.
It also checks the OpenSSL source archive and wheel SBOM already bound
to that component. It does not run tools on the binary again. If the wheel
changes, inspect the extension from the new locked wheel before updating
`tools/release_crypto_static_evidence.json`. The catalog still records a
source license, not a license conclusion for the compiled extension.

## Verify a catalog

Check out the release tag and download these assets from that same release:

- `digest-amd64.txt`
- `distribution-inventory-amd64.json`
- `recipient-notices-amd64.tar.gz`
- `native-components-amd64.cdx.json`
- `python-source-amd64.tar.gz` for catalogs with source notice evidence

Use Bash and Python 3.12 or newer. This command reads local files, makes no network
request, and does not start the application:

```bash
python -I -S -B tools/release_native_components.py verify \
  --architecture amd64 \
  --platform-digest "$(<digest-amd64.txt)" \
  --inventory distribution-inventory-amd64.json \
  --lock uv.lock \
  --notices recipient-notices-amd64.tar.gz \
  --python-sources python-source-amd64.tar.gz \
  --catalog native-components-amd64.cdx.json
```

It succeeds silently with exit status zero. For arm64, replace `amd64` in the
arguments and filenames. The tool reconstructs the catalog from verified
notice material and the checked-out source recipes, then compares the bytes.
Use the release's own checkout: an unrelated lockfile or a later source recipe
is not equivalent evidence.

This comparison does not authenticate a downloaded file. The
[release provenance procedure](source-archives.md#verify-a-cpython-source-bundle)
shows how to verify a release asset's adjacent Sigstore bundle and GitHub
attestation. Apply that procedure to the catalog as well as its input assets,
using the same release revision and workflow identity.

For an older catalog without `extra-codeowners:source-notice-evidence`, omit
`--python-sources`; the verifier reconstructs the original catalog without
adding a later notice claim. New catalog generation requires that argument.
Generation runs after source collection, and publication verifies the notice
references again before allocating immutable release state. Missing or changed
source evidence fails the release rather than publishing a catalog without it.

## Coverage limits

The catalog exposes components that the top-level image SBOM missed. It does
not merge them into the existing required image-vulnerability scan. The
[published-release rescan](../how-to/rescan-published-image.md) retains a
separate, unfiltered native report for review; a green workflow is not a
clean native-vulnerability assessment. A scanner
may interpret RPM origins, generic package URLs and backported versions
differently; consuming this catalog is not proof that it matched every
component to the right advisory data.

Source recipes pin declared versions and retained archives, not the exact
inputs used by the original wheel builder. The catalog does not establish
complete corresponding source, complete attribution, or whether a vulnerability
is reachable. It adds no VEX exclusion and changes no package version. The separate
[runtime security review](https://github.com/stampbot/extra-codeowners/blob/main/security/vex/runtime-review.md)
records the selected native OpenSSL assessments and unresolved candidates.
The [alpha.107 receipt](../maintainers/evidence/2026-11-23-alpha107-source-and-notices.md)
records what the published catalogs and archives cover. The
[Psycopg wheel update](https://github.com/stampbot/extra-codeowners/issues/341)
and [recurring scans](https://github.com/stampbot/extra-codeowners/issues/22)
track separate security work.
