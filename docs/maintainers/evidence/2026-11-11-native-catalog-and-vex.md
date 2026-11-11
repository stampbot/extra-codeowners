# Native catalogs and VEX: November 11, 2026

The release now publishes signed catalogs for reviewed C libraries inside
the Cryptography and Psycopg wheels. A separate native scan found advisories
that the image scan had not exposed. The VEX review excludes only the cases
whose affected paths or platform requirements were assessed; it leaves the
other candidates visible.

All observations below are from November 11, 2026 UTC. This is technical
artifact and vulnerability evidence, not approval of the distribution
mechanism or a claim that the native libraries are vulnerability-free.

## Catalog publication and independent verification

[PR #290][catalog-pr] added the two companion CycloneDX 1.5 catalogs,
first published in [alpha.83][alpha83], source
`58eb82d13b3f0af950f299894b6194fed7b685c5`. Independent verification
passed at 04:41:07 for all 42 immutable release assets, totaling 776,527,748
bytes. Sizes, SHA-256 values, signatures, provenance and component/source
bindings verified. Registry image children matched the native digest assets;
the registry chart matched the release package bytes.

All seven delivered source bundles bind to those platform digests and raw
inventory hashes: two CPython, two Python, two Rust and one Debian bundle.
The Debian manifest covers both platforms, so a separate saved-manifest
recheck confirmed eight platform bindings. This follows the full archive,
signature and provenance verification; the later manifest check is not a
fresh authentication of source downloads already removed. It establishes
bindings for delivered artifacts, not complete source coverage or adequacy.

Each catalog includes its two parent wheels, reviewed custom C libraries and
the RPM-origin components declared by the retained wheel SBOMs. There are
12 entries on amd64 and 14 on arm64. Source hashes identify retained source
archives, not compiled binaries. The [catalog reference][catalog] describes
the input bindings and missing coverage.

These tooling changes were not deployed during the alpha.82 runtime
observation. A comparison of the two independently verified releases found
the same 33 amd64 and 34 arm64 native-file records, and the same four embedded
SBOMs per platform. That comparison does not turn alpha.83's catalogs into
official alpha.82 release assets.

## Raw native findings

The trusted-main [rescan][raw-rescan] verified alpha.83's release evidence and
scanned both catalogs with Grype 0.118.0. It generated CPEs for matching leads,
ran offline against the same database as the image scan, and applied neither
VEX nor severity/fix filters to the native reports.

Both reports contain 82 OpenSSL product/CVE pairs:

| Native copy | Matches | Critical | High | Medium | Low |
| --- | ---: | ---: | ---: | ---: | ---: |
| Psycopg OpenSSL 3.5.4 | 57 | 5 | 27 | 19 | 6 |
| Cryptography OpenSSL 4.0.1 | 25 | 2 | 13 | 6 | 4 |

The union contains 59 CVEs. These are scanner severities, not an assessment
of this service's exposure. There were no ignored matches in either raw
native report. No match was reported for libpq, OpenLDAP or an RPM-origin
entry. That absence doesn't establish correct matching or unaffected status.

The database was built at `2026-11-10T06:21:20Z`, version `v6.1.10`, with
SHA-256
`f536af5882d8e03ad3e3ea5b32b3fc1965d55321ddab67ad7a5d7aeec3725190`.
Later disclosures are not established to be covered. The image policy
passed while its raw report still retained 189 matches; a green image gate
is not a clean native assessment.

## Scoped VEX review

[PR #292][identity-pr] rejects unsupported aliases, hashes, nested products
and other extra matching fields in this project's OpenVEX profile. A
statement can't validate one PURL and quietly add another consumer identity.
[PR #293][vex-pr] binds generic native products to reviewed source identities
common to both platform inventories, using the release lock and existing
SBOM/native-file checks.

Vexcalibur 1.1.1 formatted the local findings offline. Four assessments cover
five product/CVE pairs as `not_affected`: two CMS cases, one CMP-client case
on both OpenSSL versions, and a 32-bit-only case on OpenSSL 3.5.4. The
[runtime review][review] records the CVEs, source reasoning and limits.
The other 55 statements cover 77 pairs as `under_investigation`.

The static check used both locked Psycopg 3.3.4 wheels, verified by size and
SHA-256. All 17 amd64 and 18 arm64 native payloads matched the signed
inventories and were ELF64 with the expected machine types. No inspected
payload imported CMS or CMP symbols. Libpq did import TLS and certificate
APIs. Symbol absence supports the source review; it is not proof of every
possible runtime path, and ARM64 was not executed.

The release validator accepted the new statements against both independently
verified alpha.82 and alpha.83 inventory pairs. Six unsigned derived controls
changed a wheel version, embedded SBOM hash or native-file hash, once per
architecture; every changed input was rejected. Those controls test metadata
validation, not signatures or scanner matching.

No Dockerfile, base-image digest, package version or dependency lock changed.
The libraries remain present and unpatched. In particular,
`sslmode=require` does not make certificate processing unreachable.

## Published VEX and consumer comparison

[Alpha.86][alpha86], source
`8bf2cdef2b48c0bfb115baf6930b87c823fe11d7`, published the new statements.
Its main CI completed successfully without a manual retry. Independent
verification passed at 06:13:49 for all 42 immutable assets, totaling
776,604,064 bytes. Signatures, provenance, source/catalog/VEX bindings,
image children and registry chart bytes all verified.

The image index is
`sha256:89d58a29567dce4d41510790042bd33604ab8790972feabee2bdc6fdf28dbc91`.
This tooling-only release was not deployed over the alpha.82 live test.

The [alpha.86 rescan][vex-rescan] passed on both architectures. Each pair of
raw and VEX-applied reports used the same database described above. Each raw
report retained 82 matches; applying the verified release VEX left 77 matches
and moved exactly the five assessed pairs into `ignoredMatches`. Every moved
match names the `not_affected` VEX rule. The raw matches partition exactly
into those two groups, with no extra or missing pair.

This also checked Cryptography's qualified catalog PURL against the statement's
unqualified native identity: its assessed CMP pair matched on both platforms.
The TLS/certificate candidates stayed in the visible set.

Neither report applies a fix-availability or severity filter. Grype adds its
standard `fixed` and `not_affected` status rules when a VEX document is loaded;
the comparison retained the original built-in kernel rules and found no
other rule addition. Its [filtering documentation][grype-vex] describes that
consumer behavior. No project ignore or native severity gate was added.
Passing proves the observed statement matching, not complete native coverage
or the reachability of the remaining candidates.

## Source and notice limits

An archive audit checked source hashes for 22 native records across the two
platforms. It retained available RPM headers, license declarations, spec
lines and upstream notice candidates. A source package's license label is
not necessarily the license of every binary built from it: e2fsprogs, for
example, has MIT-licensed libraries alongside its broader GPL declaration.
The audit therefore did not copy a source-package label onto every component.

The catalogs keep native license review explicitly unresolved. Corresponding
source adequacy, complete notices, native/RPM advisory context and maintainer
distribution approval remain in [issue #18][sources]. Large local source
downloads were removed after verification and the notice audit; small signed
manifests and receipts remain in private maintainer records. No image ran
during these artifact checks.

[catalog-pr]: https://github.com/stampbot/extra-codeowners/pull/290
[alpha83]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.83
[catalog]: ../../reference/native-components.md
[raw-rescan]: https://github.com/stampbot/extra-codeowners/actions/runs/42961876543
[identity-pr]: https://github.com/stampbot/extra-codeowners/pull/292
[vex-pr]: https://github.com/stampbot/extra-codeowners/pull/293
[review]: https://github.com/stampbot/extra-codeowners/blob/8bf2cdef2b48c0bfb115baf6930b87c823fe11d7/security/vex/runtime-review.md
[sources]: https://github.com/stampbot/extra-codeowners/issues/18
[alpha86]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.86
[vex-rescan]: https://github.com/stampbot/extra-codeowners/actions/runs/42969936145
[grype-vex]: https://oss.anchore.com/docs/guides/vulnerability/filter-results/#use-vex-documents
