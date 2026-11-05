# ADR: Reuse authenticated, version-matched Debian sources

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-05 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Scope | Debian source collection during release. Runtime dependencies, image inputs and the application authorization model are unchanged. |
| Related | [Release-from-main decision](2026-08-17-release-from-main-ci.md), [source archive contract](../../reference/source-archives.md#reusing-retained-debian-sources) |
| Implementation | [Issue #264](https://github.com/stampbot/extra-codeowners/issues/264) |
| Revisit when | The official signing workflow or trust policy changes, or source reuse needs to combine partial package sets. |

## Business driver

The November 5 release failed twice because Debian Snapshot's metadata API
returned HTTP 504. The archive cache restored successfully, but the collector
still needed fresh metadata for every package. The previous immutable release
already carried the exact version-matched sources, so a routine application
change was blocked by an upstream service it did not need to consult again.

## Constraints

- Every new release still carries its required source bytes, bound to both
  new image inventories and signed by the current release workflow.
- Reuse must authenticate the previous evidence before treating it as a
  source. A cache hit or matching filename is insufficient.
- Source versions, hashes, size limits, archive checks and retained descriptor
  signatures must not be weakened. No old release code or upstream source
  archive is executed or extracted.
- This changes neither dependency versions nor the existing disclaimer:
  version-matched recipes do not prove an upstream binary's exact build inputs.

## Decision

**Y statement:** We will rebind an authenticated prior Debian source bundle
when its complete source identity set matches the new images, because those
bytes are already retained and verified, so routine releases can keep source
delivery intact during an upstream metadata outage.

The previous release must be completed and immutable. Both inventories and
the source bundle require verified official release-workflow provenance,
constrained to the resolved tag commit and main ref, with self-hosted signers
rejected. The old bundle is fully verified before reuse. Its source files and
package records remain unchanged; only the image/inventory binding changes,
and the result must pass verification against the new inventories.

No compatible evidence or a changed source identity selects ordinary source
collection. Invalid evidence or failed authentication is a release failure,
not permission to skip a check. The workflow selects evidence automatically;
maintainers do not synchronize a second source-version file.

## Consequences

- Routine releases depend on GitHub's retained artifacts and verification
  services, which the release process already needs, but not on Snapshot
  metadata availability when every source identity matches.
- A first release, changed base or changed source version can still need
  Snapshot. An upstream outage cannot justify inventing source evidence.
- Reuse downloads a bundle and verifies its content again. It avoids rebuilding
  dependencies, but does not remove transfer or hashing costs.
- Old evidence is read only as data. A later collector continues to apply its
  current structural checks before producing a newly signed bundle.

## Alternatives considered

### Keep requesting Snapshot metadata on every release

Even a warm archive cache still depends on that API. The observed outage
blocked two publication attempts without any dependency change.

### Cache unsigned resolver metadata

This would make a new cache record part of the source trust boundary. The
project already has immutable, authenticated bundles with versioned identities;
use those instead of introducing a separate authority.

### Skip source delivery or rebuild dependencies during an outage

Skipping the bundle weakens the release contract. Rebuilding is unnecessary
for version-matched source delivery and introduces different build inputs
without solving upstream source availability.
