# Source archives

Starting with alpha.40, releases include
`cpython-source-amd64.tar.gz` and `cpython-source-arm64.tar.gz`. Each bundle
contains the upstream CPython source archive identified by that platform's
image metadata. The release retains the bytes, not just a download link.

Releases containing the Debian source workflow also include `debian-source.tar`,
shared by both platforms. These bundles retain version-matched upstream source
and build recipes. They do not prove the exact inputs used by upstream binary
builders, and the project does not rebuild dependencies to make that claim.

This is not yet the complete container source. Libraries inside Python wheels
and other missing notice material remain under
[issue #18](https://github.com/stampbot/extra-codeowners/issues/18).
The bundles do not establish distribution approval.

## CPython contents and identity

Each bundle has two regular files:

- `Python-<version>.tar.xz`, unchanged from the upstream download.
- `manifest.json`, recording the source URL, SHA-256, size, and CPython version.
  It also records the image's platform child digest and the SHA-256 of its
  `distribution-inventory-<architecture>.json` release asset.

The version and expected checksum come from the pinned Docker Official Python
image, not a second version file in this project. Collection checks the
download against that checksum before writing a bundle. The source archive is
never extracted or executed by the collector or verifier.

The signed inventory's `cpython.source_bundle` field names the required asset.
Release verification fails if that asset or its signature is missing. Older
inventories without this field remain verifiable; successful verification of
an old release does not mean it delivered source.

## Verify a CPython source bundle

Use Bash with Python 3.12 or newer, GitHub CLI, and Cosign installed. Start from
a trusted checkout of the release tag. The commands below read files and
contact GitHub and Sigstore; they do not start the application. GitHub CLI
must be authenticated for attestation verification.

Download these assets from the same GitHub release into the checkout root:

- `digest-amd64.txt`
- `distribution-inventory-amd64.json` and its `.sigstore.json` file
- `cpython-source-amd64.tar.gz` and its `.sigstore.json` file

For arm64, replace `amd64` in the filenames and commands. The digest file
identifies the platform child, not the multi-platform index. Confirm it
matches the platform you intend to use before continuing.

```bash
set -euo pipefail
for artifact in distribution-inventory-amd64.json cpython-source-amd64.tar.gz; do
  gh attestation verify "$artifact" \
    --repo stampbot/extra-codeowners \
    --signer-workflow stampbot/extra-codeowners/.github/workflows/release.yml \
    --source-digest "$(git rev-parse HEAD)" \
    --source-ref refs/heads/main
  cosign verify-blob "$artifact" \
    --bundle "$artifact.sigstore.json" \
    --certificate-identity https://github.com/stampbot/extra-codeowners/.github/workflows/release.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-sha "$(git rev-parse HEAD)"
done

python -I -S -B tools/release_sources.py verify \
  --architecture amd64 \
  --platform-digest "$(<digest-amd64.txt)" \
  --inventory distribution-inventory-amd64.json \
  --bundle cpython-source-amd64.tar.gz
```

GitHub CLI and Cosign report successful verification. The Python command
succeeds silently with exit status zero. Stop if any command fails; a valid
archive checksum alone does not authenticate its publisher.

The verifier rejects altered source bytes, a changed inventory, missing or
duplicate members, links, and unexpected archive entries. Downloads and
verification have a 64 MiB source limit; the outer bundle may be at most
65 MiB before or after decompression. These limits apply to the retained
compressed source archive, not to extracting it yourself.

For license texts already present in the runtime, use the separate
[recipient notice bundle](recipient-notices.md).

## Debian contents and identity

`debian-source.tar` contains the source packages named by the installed Debian
package metadata on both platforms. A source package used by both images appears
once. The collector uses an explicit source version when the binary package
records one, so an epoch or a binary-only rebuild suffix does not silently select
a different source release.

The archive contains `manifest.json` and a directory for each package under
`sources/<package>/<URL-encoded-source-version>/`. Each directory holds the
Debian `.dsc` descriptor and every source file listed in its `Checksums-Sha256`
field. That includes the Debian patches and build recipes, whether they are in
a separate Debian archive or part of a native source package. Files inside these
source archives are not extracted or executed during collection or verification.

The manifest records each file's name, size, SHA-256, and Debian Snapshot
locator. Its `images` object binds both platform digests and the hashes of both
distribution inventories. Each inventory's `debian.source_bundle` field names
the required release asset. A missing bundle or signature fails release
verification when either signed inventory requires it.

Collection obtains descriptors over HTTPS from [Debian Snapshot][snapshot].
Source archive bytes must match the descriptor's SHA-256 and size. Snapshot's
SHA-1 addresses locate files; they are not a substitute for authenticating the
release. The original descriptor signatures remain in the bundle, but this
collector does not verify them against Debian developer keyrings.

This bundle covers installed Debian packages, not libraries supplied by a Python
wheel merely because they have the same name. For example, Debian's OpenSSL
source does not stand in for Psycopg's bundled OpenSSL source.

## Verify the Debian bundle

Use the same Bash, Python, GitHub CLI, and Cosign prerequisites as above, from a
trusted checkout of the release tag. Download `debian-source.tar` and its
`.sigstore.json` file, both distribution inventories and their signatures, and
both `digest-<architecture>.txt` files from that release into the checkout root.

Run the attestation and signature verification loop above with these three
artifact names: `distribution-inventory-amd64.json`,
`distribution-inventory-arm64.json`, and `debian-source.tar`. Then check the
contents against both inventories:

```bash
python -I -S -B tools/release_debian_sources.py verify \
  --inventory-amd64 distribution-inventory-amd64.json \
  --inventory-arm64 distribution-inventory-arm64.json \
  --digest-amd64 "$(<digest-amd64.txt)" \
  --digest-arm64 "$(<digest-arm64.txt)" \
  --bundle debian-source.tar
```

Success is silent with exit status zero. The verifier requires every source
package identified by either inventory and every archive named by its descriptor.
It rejects wrong versions, altered bytes, links, duplicate paths, and extra or
missing files. Verification does not extract anything.

The bundle is limited to 512 MiB, each source file to 256 MiB, and each metadata
document to 2 MiB. The current collector supports Debian 13 and at most 256
source packages, with fewer than 32 source archives per descriptor. Other base
distributions need an explicit collector update; a failed lookup never counts
as a complete source bundle.

[snapshot]: https://snapshot.debian.org/

## Python source distributions

Releases containing the Python source collector include
`python-source-amd64.tar.gz` and `python-source-arm64.tar.gz`. Each holds the
upstream sdists listed in `uv.lock` for the distributions installed on that
platform. Package names and versions must match; downloads must match the
lock's SHA-256 and size. The collector never extracts or runs them.

`manifest.json` binds the bundle to the platform digest, inventory hash, and
lock hash. It lists each archive under `sources/<package>/`. The application's
own sdist is delivered separately in the same release. Packages without a
locked sdist appear in `unresolved_sources` unless a reviewed, exact-version
source recipe is available. An unresolved entry is a missing source-delivery
item, not an exemption. These archives do not supply every native library
embedded in a wheel.

For `psycopg-binary` 3.3.4, the bundle includes the upstream repository archive
at commit `83f110367cdd249cc0a352e2246ecea9e878e5a0`, the commit referenced by
the signed 3.3.4 tag. The manifest records the tag object, archive checksum,
size, and paths to the upstream wheel and libpq build recipes. Downloads use
the commit-specific GitHub archive URL and must match the reviewed bytes;
the collector neither follows redirects nor runs those recipes.

That archive supplies Psycopg's wrapper source and recipes, not the source of
every bundled libpq, OpenSSL, OpenLDAP, or operating-system library. Their
source and notice evidence remains part of [issue #18][source-work]. A later
Psycopg version does not silently reuse the 3.3.4 recipe: it remains unresolved
until its source identity is reviewed.

The inventory's `python.source_bundle` field requires the bundle and its
signature during release verification. Older inventories without the field do
not imply source delivery. From a trusted checkout of the release tag, download
the bundle, its signature, the matching inventory and signature, and the platform
digest file. Verify the signatures and attestations using the loop above with
`distribution-inventory-amd64.json` and `python-source-amd64.tar.gz`, then run:

```bash
python -I -S -B tools/release_python_sources.py verify \
  --architecture amd64 \
  --platform-digest "$(<digest-amd64.txt)" \
  --inventory distribution-inventory-amd64.json \
  --lock uv.lock \
  --bundle python-source-amd64.tar.gz
```

Use the lock from that release tag, not today's main branch. Verification
succeeds silently with exit status zero. It rejects changed identities, hashes,
sizes, duplicate or unexpected archive members, and filesystem links. Each
sdist is limited to 64 MiB; the bundle is limited to 256 MiB before and after
decompression. No dependency is rebuilt to produce this evidence.

[source-work]: https://github.com/stampbot/extra-codeowners/issues/18
