# Verify container distribution evidence

Use this procedure to identify the notices and exact source evidence for a
released Extra CODEOWNERS container. Complete it separately for every platform
you deploy. An amd64 archive is not evidence for an arm64 manifest.

No supported release exists yet. These commands apply after a release page
contains the files described below.

## Prerequisites

You need a POSIX-compatible shell, GitHub CLI, Cosign, Docker Buildx, `jq`,
`sha256sum`, and GNU tar. Authenticate GitHub CLI for public-repository access.
Choose the semantic version and architecture before you begin:

```bash
export VERSION='REPLACE_WITH_VERSION'
export ARCHITECTURE='amd64'
export IMAGE='ghcr.io/stampbot/extra-codeowners'
```

Replace `REPLACE_WITH_VERSION` with a release such as `0.1.0`. Set
`ARCHITECTURE` to `amd64` or `arm64`. Run the remaining commands from a new,
empty working directory; extraction writes files below it.

## 1. Download one platform's evidence

```bash
mkdir "extra-codeowners-${VERSION}-evidence"
cd "extra-codeowners-${VERSION}-evidence"
gh release download "v${VERSION}" \
  --repo stampbot/extra-codeowners \
  --pattern "extra-codeowners-${VERSION}-linux-${ARCHITECTURE}-evidence.tar.gz*" \
  --pattern "evidence-predicate-${ARCHITECTURE}.json"
```

The download must contain the evidence archive, its `.sha256` file, its
`.sigstore.json` signature bundle, and the small digest-binding predicate.
Stop if any file is absent.

## 2. Verify the archive before extracting it

```bash
archive="extra-codeowners-${VERSION}-linux-${ARCHITECTURE}-evidence.tar.gz"
sha256sum --check "${archive}.sha256"
gh attestation verify "$archive" --repo stampbot/extra-codeowners
cosign verify-blob \
  --bundle "${archive}.sigstore.json" \
  --certificate-identity-regexp='^https://github\.com/stampbot/extra-codeowners/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  "$archive"
```

All three commands must succeed. They check the recorded digest, GitHub build
provenance, and keyless workflow signature. They do not decide whether the
archive's licensing analysis is legally sufficient.

## 3. Match the evidence to the image platform

Resolve the versioned image index and select exactly one manifest for your
architecture:

```bash
platform_digest="$(
  docker buildx imagetools inspect "${IMAGE}:${VERSION}" --raw \
    | jq -er --arg architecture "$ARCHITECTURE" '
        [.manifests[]
         | select(.platform.os == "linux" and .platform.architecture == $architecture)]
        | if length == 1 then .[0].digest
          else error("expected exactly one platform manifest") end
      '
)"
jq -e --arg digest "$platform_digest" \
  '.subject_digest == $digest' \
  "evidence-predicate-${ARCHITECTURE}.json"
```

The final `jq` command must print `true`. The predicate is also attached as a
signed OCI attestation to that platform digest. Verify its workflow identity,
extract the one signed predicate, and compare it with the downloaded copy:

```bash
evidence_type='https://github.com/stampbot/extra-codeowners/attestations/container-evidence/v1'
cosign verify-attestation \
  --type "$evidence_type" \
  --certificate-identity-regexp='^https://github\.com/stampbot/extra-codeowners/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  "${IMAGE}@${platform_digest}" > verified-attestations.json
jq -es --arg type "$evidence_type" '
  map(.payload | @base64d | fromjson)
  | map(select(.predicateType == $type))
  | if length == 1 then .[0].predicate
    else error("expected exactly one verified evidence predicate") end
' verified-attestations.json > attested-predicate.json
jq --sort-keys . "evidence-predicate-${ARCHITECTURE}.json" > downloaded-predicate.json
jq --sort-keys . attested-predicate.json > signed-predicate.json
cmp downloaded-predicate.json signed-predicate.json
archive_sha="$(sha256sum "$archive" | awk '{print $1}')"
jq -e \
  --arg digest "$platform_digest" \
  --arg filename "$archive" \
  --arg sha256 "$archive_sha" \
  '.subject_digest == $digest
   and .artifact.filename == $filename
   and .artifact.sha256 == $sha256' \
  attested-predicate.json
```

The last `jq` command must print `true`. Stop if the registry digest, signed
predicate, downloaded predicate, filename, or archive hash differs, even when
the other signatures are valid.

## 4. Inspect notices and source

List the archive before extracting it, then extract without restoring archive
ownership or permissions:

```bash
tar --list --gzip --file "$archive"
mkdir unpacked
tar --extract --gzip --file "$archive" \
  --directory unpacked \
  --no-same-owner \
  --no-same-permissions
cd unpacked
sha256sum --check SHA256SUMS
```

Use these entry points:

- `THIRD_PARTY_NOTICES.md` lists every observed component, whether it remains
  in the effective filesystem, and the reviewed license expression.
- `MANIFEST.json` binds the archive to the platform digest and records every
  retained source URL, hash, and path.
- `inventory/components.json` is the normalized package and license inventory.
- `inventory/all-layer-files.json` records every regular file occurrence in
  every distributed layer, including content later hidden by a whiteout.
- `licenses/standard/` contains hash-pinned standard license texts.
- `licenses/from-source/` contains notices copied from exact source archives.
- `sources/alpine/` contains commit-pinned recipe subtrees and every
  checksum-verified distfile those recipes name.
- `sources/python/` contains locked Python source distributions, including
  separately reviewed sources for wheel-only runtime packages.
- `sources/base/` contains the exact Docker Official Python recipe and CPython
  source archive.
- `sources/application/` contains the Extra CODEOWNERS Git source archive.

Preserve the original signed archive. If an internal artifact repository
mirrors it, retain its filename, SHA-256, signature bundle, release URL, and
subject platform digest together.

## Troubleshooting

If `gh release download` finds no file, confirm that you selected an actual
released version and supported architecture. If a signature identity differs,
do not weaken the identity regular expression; inspect the release workflow and
repository security history. If the OCI attestation is absent but the release
archive exists, report a release-integrity defect rather than treating the
GitHub asset as registry evidence.

See [how the evidence is produced](../explanation/container-distribution-evidence.md)
for the trust boundary and residual risks.
