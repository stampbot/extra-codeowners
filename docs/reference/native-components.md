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
- Psycopg's custom OpenSSL, libpq and OpenLDAP identities come from reviewed
  source recipes bound to native files in the signed inventory. Auditwheel's
  SBOM does not declare those custom libraries.

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

Catalogs with metadata property `extra-codeowners:source-notice-evidence` set
to `1` also identify selected notice files inside the retained upstream
sources. These references supplement the runtime notice bundle; they don't
add files to it.

For OpenSSL, the selection is the archive's top-level `LICENSE.txt`. For
libpq, it is PostgreSQL's top-level `COPYRIGHT`. OpenLDAP supplies top-level
`COPYRIGHT` and `LICENSE`. Each selected component has a
`extra-codeowners:source-notice-files` property containing JSON records with
the inner archive path, byte size and SHA-256. Its existing `source-archive`
property identifies the enclosing tarball in `python-source-ARCHITECTURE.tar.gz`.

The verifier checks the complete Python source bundle against the inventory,
lockfile and source recipes before reading these files. It rejects missing,
duplicate, linked, sparse or oversized selected notices. It reads compressed
archives without extracting or executing them, with limits of 512 MiB expanded
bytes, 50,000 members and 1 MiB per notice file.

These are selected upstream texts, not a complete map of copyright holders to
compiled code. RPM-origin component notices remain unselected, and every
native component's license review remains unresolved. A matching notice hash
does not approve binary redistribution or establish corresponding-source
adequacy. Older catalogs omit these properties and make no notice-selection
claim.

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
complete corresponding source, complete attribution, license approval, or
whether a vulnerability is reachable. The catalog itself adds no VEX exclusion
and changes no package version. The separate
[runtime security review](https://github.com/stampbot/extra-codeowners/blob/main/security/vex/runtime-review.md)
records the selected native OpenSSL assessments and unresolved candidates.
Native vulnerability triage and distribution review remain
in [issue #18](https://github.com/stampbot/extra-codeowners/issues/18).
