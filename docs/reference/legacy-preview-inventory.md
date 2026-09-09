# Retained legacy images

The old `main` and `sha-*` images remain public for historical reference. They
are unsupported and unsafe for deployment. Don't deploy, mirror, or
redistribute them. This warning is not a claim of a known vulnerability.

The [2026-09-09 inventory][inventory] records their package-version IDs and
digests, including objects that no longer have tags. It supports the retention
decision in [issue #30][issue-30] and the historical scanning work in
[issue #22][issue-22]. It doesn't change either image contents or support status.

## What was found

The read-only audit enumerated 542 active package versions in six GitHub API
pages. It fetched every manifest and verified its SHA-256 against the package
version's digest. The package listing was unchanged when checked again after
collection, at 2026-09-09 05:06:55 UTC. Verification of the legacy attachments
followed; the JSON records both timestamps.

Nine legacy image indexes connect to 81 package versions through index-child
and OCI-subject references. Of those versions, 63 have no tags. The 18 tagged
versions carry 19 tags because `main` and `sha-929dd66` identify the same index.
The other 461 package versions are outside this legacy inventory; exclusion is
not a statement that they are supported or verified releases.

Each legacy image has these retained objects:

| Object | Count per image | Evidence |
| --- | --- | --- |
| Image index | 1 | Exact root digest and package-version ID |
| Linux image manifest | 2 | One each for `amd64` and `arm64`, with config and layer descriptors |
| BuildKit attestation manifest | 2 | Platform SBOM and provenance statement descriptors |
| Sigstore bundle manifest | 2 | Index signature and index build provenance |
| Referrer fallback index | 2 | Current tagged index and an earlier untagged index |

All nine indexes passed Cosign 3.1.2 verification with the exact certificate
identity `https://github.com/stampbot/extra-codeowners/.github/workflows/ci.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`. Certificate, claim,
and transparency-log verification remained enabled. The recorded claims cover
both the index signature and its build provenance.

The audit also downloaded and hashed the small config and attestation blobs.
It recorded the subjects of 18 platform SBOMs, 18 platform provenance
statements, nine index provenance statements, and nine index signatures.
The signed root indexes bind the BuildKit attestation manifests; those platform
statements weren't independently verified as separately signed artifacts.
No filesystem layers were downloaded, and no container was run.

### Referrer discovery

GHCR returned HTTP 404 from the OCI referrers endpoint for all 81 legacy
objects. That is not evidence that attachments are absent. The audit found
them through the complete package-version listing, OCI `subject` references,
index children, and `sha256-*` fallback tags.

The JSON preserves the exact raw legacy manifests, so their digests can be
checked offline. It also lists every package version seen during collection,
including versions outside the legacy set. Config blobs and layer blobs
don't have separate package-version IDs; their descriptors identify them by
digest and size.

## Use the inventory

From a source checkout, with `jq` installed, list the retained image indexes:

```bash
jq -r '.legacy_images[] | [.package_version_id, .digest, (.tags | join(","))] | @tsv' \
  security/legacy-preview-inventory-2026-09-09.json
```

The command prints nine rows. For scanner inputs, list the 18 platform digests:

```bash
jq -r '.image as $image | .legacy_images[].platforms[] | [$image + "@" + .digest, .architecture] | @tsv' \
  security/legacy-preview-inventory-2026-09-09.json
```

These are historical scan targets, not deployment recommendations. The current
[release rescan workflow](../how-to/rescan-published-image.md) does not accept
them: it requires immutable release assets that these previews don't have.
Issue #22 tracks scanning them separately without treating missing evidence as
a successful verification or applying a newer release's VEX statement to an
older image.

## What remains missing

The previews have signature, SBOM, and provenance evidence. They don't have the
immutable GitHub release binding or signed per-platform distribution
inventories and recipient notice bundles used by the current release process.
Complete corresponding-source delivery and approval of the distribution
mechanism remain open in [issue #18][issue-18]. A valid signature doesn't settle
those questions.

This inventory is a dated observation, not a new release attestation or a
vulnerability scan. GHCR's package page is shared by old and current images;
the repository's warnings distinguish legacy objects by their tags and the
digests recorded here. Nothing was deleted, retagged, or republished.

[inventory]: https://github.com/stampbot/extra-codeowners/blob/main/security/legacy-preview-inventory-2026-09-09.json
[issue-18]: https://github.com/stampbot/extra-codeowners/issues/18
[issue-22]: https://github.com/stampbot/extra-codeowners/issues/22
[issue-30]: https://github.com/stampbot/extra-codeowners/issues/30
