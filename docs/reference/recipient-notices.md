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
- the CPython runtime license; and
- Extra CODEOWNERS' Apache-2.0 license.

When package metadata declares a Python license file that is absent from the
image, the manifest records it under `unresolved_notice_evidence`. That makes
the gap reviewable; it does not silently turn the missing file into evidence.

`NOTICE-README.txt` repeats the platform identity and the evidence boundary
inside the archive so the context remains with a copied bundle.

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

## What this does not establish

The bundle is intentionally narrow. It does not establish that every notice
obligation is complete, that a package's declared license is correct, or that a
retained source artifact is the complete corresponding source for a component.
It does not make alpha releases supported for production use.

The raw inventory records installed Debian package identities and Python
metadata so those questions can be reviewed against the exact image. The
project still needs an approved, reviewed corresponding-source delivery
mechanism and maintainer approval of the distribution process. Those remaining
decisions are tracked in [issue #18][issue-18].

[issue-18]: https://github.com/stampbot/extra-codeowners/issues/18
