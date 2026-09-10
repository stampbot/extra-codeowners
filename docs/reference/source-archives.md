# Source archives

Releases containing the CPython source delivery workflow include
`cpython-source-amd64.tar.gz` and `cpython-source-arm64.tar.gz`. Each bundle
contains the upstream CPython source archive identified by that platform's
image metadata. The release retains the bytes, not just a download link.

This is CPython source, not the complete container source. Debian packages and
libraries bundled inside Python wheels still need source and notice review
under [issue #18](https://github.com/stampbot/extra-codeowners/issues/18).
These bundles do not establish distribution approval or reproducible builds.

## Contents and identity

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

## Verify a source bundle

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
