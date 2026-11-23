# Recipient notice bundles

Starting with the first release that contains this feature, each released Linux
platform has a companion recipient notice bundle:

- `recipient-notices-amd64.tar.gz`
- `recipient-notices-arm64.tar.gz`

Choose the bundle that matches the image's platform child digest, not merely
the multi-platform image tag. `digest-amd64.txt` and `digest-arm64.txt` in the
same GitHub release identify those child digests.

The bundle preserves notice material found in the exact runtime filesystem. It
is signed, carries a GitHub build attestation, and is bound to the matching
raw distribution inventory. It is evidence about a released image; it is not a
legal conclusion and not a corresponding-source offer.

## Contents

`NOTICE-MANIFEST.json` is the machine-readable index. It identifies the
platform, its child digest, the SHA-256 of the matching
`distribution-inventory-<architecture>.json`, and every preserved file. The
archive includes available:

- Debian package copyright files and shared license files, preserving safe
  shared-license symlinks as symlinks;
- Python license files. The collector includes declared `License-File` paths,
  files under a distribution's `licenses/` directory, and direct legacy files
  named like `LICENSE`, `LICENCE`, `COPYING`, `COPYRIGHT`, or `NOTICE`. It does
  not assume other direct `.dist-info` files are notice material;
- Python `METADATA` files and embedded wheel SBOMs, with their original bytes
  and inventory hashes;
- the CPython runtime license; and
- Extra CODEOWNERS' Apache-2.0 license.

New images also include `notices/cpython/source.json`. It records the CPython
version, source archive URL, and SHA-256 declared by the pinned official Python
base image. The build checks that the declared version matches its interpreter.
The raw inventory records this metadata and the matching runtime license with
their file hashes, so both are covered by the signed notice bundle.

Older inventories omit the `cpython` record and remain verifiable. The new
metadata identifies the expected upstream source; it does not contain the
source archive or prove that rebuilding it reproduces the image's interpreter.
Releases containing the [CPython source delivery workflow](source-archives.md)
also publish that archive in a separate signed bundle.

When package metadata declares a Python license file that is absent from the
image, or whose entry is a filesystem link, the manifest records it under
`unresolved_notice_evidence`. The bundle does not follow Python package links;
the raw inventory retains their link record for review. That makes the gap
reviewable without silently turning a missing or indirect file into evidence.

`NOTICE-README.txt` repeats the platform identity and the evidence boundary
inside the archive so the context remains with a copied bundle.

Schema 3 bundles retain Python metadata and embedded SBOMs alongside licenses.
They let a recipient inspect the wheel publisher's component, version, license,
and source declarations without extracting the container. An SBOM declaration
is not proof that every listed build dependency is shipped, or that every
shipped component is listed. Linked SBOMs are recorded as unresolved evidence,
not followed. Their presence, link kind, and target must still match the
exported filesystem before a bundle is produced. Schema 2 bundles did not preserve these files; use the verifier
from the matching release tag when checking an older bundle.

[Rust source bundles](source-archives.md#rust-dependencies-in-python-wheels)
add checksum-verified crate archives for Cargo components reported by those
SBOMs. Their manifests connect the wheel's declarations to the retained sources;
they do not replace the notice bundle or the remaining native-library review.

The separate [wheel-native catalogs](native-components.md) make reviewed
Cryptography and Psycopg C-library identities available as CycloneDX documents.
They bind the wheel declarations and source recipes to the same platform
evidence. Unknown library licenses remain explicitly unresolved; the parent
wheel's license is not silently applied to its bundled libraries.
Catalogs with source notice evidence also point to selected upstream notices
inside the separately delivered Python source bundles. Version 2 adds
references inside Psycopg's retained source RPMs.
Those files are not added to the runtime notice bundle. See the
[selected upstream notice contract](native-components.md#selected-upstream-notices)
for the paths, hashes and remaining attribution limits.

## Verify a bundle

Check out the release tag, then download the matching inventory and notice
bundle from that release. The release tag identifies the source revision used
to build the artifact. This verifier uses only the Python standard library and
does not start the container.

```bash
python -I -S -B tools/release_notices.py verify \
  --architecture amd64 \
  --platform-digest "$(<digest-amd64.txt)" \
  --inventory distribution-inventory-amd64.json \
  --bundle recipient-notices-amd64.tar.gz
```

The command rejects a bundle whose manifest, file hashes, links, inventory hash,
or platform identity differs from the supplied inventory and digest. For
cryptographic verification, also verify the release asset's GitHub attestation
and its adjacent `.sigstore.json` bundle. Maintainers do that automatically
when the release workflow retries or verifies an existing release.

## Third-party inventory baseline

Container CI and the release build both compare the collected third-party
inventory with the baseline for that architecture. The check covers Debian
packages and their notice files, CPython source and license evidence,
and installed Python distributions, native files and embedded SBOMs. It
ignores the image digest and first-party distribution metadata in the
comparison, so a new Extra CODEOWNERS version doesn't require a new baseline.

The initial baselines record the inventory of the verified
[alpha.95 release](https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.95).
A matching baseline is a check for changes, not a license review or
permission to distribute. The [contributor guide][review-changes] explains
how to review a difference and propose an update.

## What this does not establish

The bundle is intentionally narrow. It does not establish that every notice
obligation is complete, that a package's declared license is correct, or that a
retained source artifact is the complete corresponding source for a component.
It does not make alpha releases supported for production use.

The raw inventory records installed Debian package identities and Python
metadata so you can check those questions against the exact image.
[Issue #18][issue-18] tracks missing notice attribution and the remaining
work to deliver corresponding source.

[issue-18]: https://github.com/stampbot/extra-codeowners/issues/18
[review-changes]: https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md#review-changes-to-container-components
