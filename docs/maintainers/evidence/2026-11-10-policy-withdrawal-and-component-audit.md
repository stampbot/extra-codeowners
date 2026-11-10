# Policy withdrawal and component audit: November 10, 2026

Delivered policy changes revoked a successful check in the disposable
repository. Separate artifact checks verified alpha.79 and found no ELF
payload present only in an earlier image layer. Neither result establishes
production readiness: wheel-native component coverage and the provider
contract remain incomplete.

All observations below are from November 10, 2026 UTC. Raw repository,
delivery, trace and infrastructure identifiers remain in private maintainer
captures. The [earlier receipt][earlier] records the quiet scans and the
isolated missed-enrollment test; these later tests don't change those results.

## Delivered policy changes on alpha.77

The App ran [alpha.77][alpha77], source
`26142d027853a63dd57a59fda12df431164ba698`, with two replicas and shared
PostgreSQL. The disposable PR's head, labels and reviews stayed unchanged.
Its human author was its direct CODEOWNER. It had no review and no App
delegation.

Between 11:25 and 11:28, the controller changed only the base branch's
repository policy. It established a fresh success before each withdrawal
case. The observed results were:

| Policy change | Result |
| --- | --- |
| Enable author ownership | Success, with no evaluation error |
| Set `enabled = false` | Failure with `repository_policy_disabled` |
| Restore author ownership, then delete policy | Success, then failure with `repository_policy_disabled` |
| Restore author ownership, then write malformed policy | Success, then failure with `invalid_policy` |
| Restore author ownership, then write a 1,000,001-byte policy | Success, then an explicit blocking failure while work remained pending |
| Restore the original valid policy with author ownership disabled | Missing-review failure, with no evaluation error |

The final disabled, removed and malformed-policy results were checked against
durable audits evaluated after their respective writes. For oversized
content, the retained worker log reports that the policy exceeded the
1,000,000-byte limit. The API showed the blocking reevaluation failure and
the database retained a pending retry. This is not a completed diagnostic
result for oversized input, nor a test of every possible provider-read error.

The original policy bytes were restored. The final missing-review failure
was observed, the head and empty labels/reviews were rechecked, and the
controller exited. No webhook URL, installation access, quota, queue or
deployment setting changed during these tests.

## Alpha.79 artifact verification and fresh rescan

[Alpha.79][alpha79], source
`52ae0f48980a357191dda43718d364559508727a`, passed independent verification
of all 38 immutable release assets, totaling 776,442,855 bytes. Recorded
sizes and SHA-256 values matched. Signatures, workflow provenance, notices,
source bundles and VEX bindings verified. The published platform digests
matched the image index, and the registry chart matched the release package
byte-for-byte.

The image index is
`sha256:9339722e28b66771496e3a6ab16ea9cd0deabfc2d2bdfd3a1a858f526c5e6c01`.
The chart manifest is
`sha256:47d9893cdd4570b0555dbe51a8a3f903277ade96ae0d10f3aded9b6411e2c1d1`.
The two native child digests are recorded in that release's `digest-amd64.txt`
and `digest-arm64.txt`.

A [manual rescan][rescan] of those published digests passed on both
architectures with Grype 0.118.0 and its database built at 06:21:20 UTC.
Each raw report retains 189 matches, including 63 High findings. Passing
means the existing fixable-High/Critical policy passed with the signed VEX
statement; it does not mean the image has no findings. The four High matches
with available fixes concern APT and zlib and have existing scoped VEX
assessments. Other findings remain visible rather than being declared
unaffected by implication.

The current [rescan workflow][rescan-guide] covers the newest published alpha
or stable release daily, plus explicitly selected eligible releases. It does
not yet cover every retained digest. That wider scope remains in
[issue #22][rescans].

No Dockerfile, base-image digest or runtime dependency version changed during
these assessments. New exclusions were limited to the two zlib gzip-writer
paths reviewed in [PR #280][zlib]; they were not blanket package exclusions.

## Native payloads in earlier layers

The layer audit read all ten compressed filesystem layers for each native
alpha.79 image, without extracting paths or starting the images. Every blob's
SHA-256 and size matched its manifest. Every uncompressed tar matched the
image config's corresponding `rootfs.diff_ids` entry.

Each architecture contained 778 distinct ELF path/hash pairs across the
entire layer history. All 778 remained in the reconstructed final filesystem;
none appeared only in a replaced or hidden earlier-layer file. The final
path/hash sets also matched the independent alpha.75 native-file audit
retained earlier in the run. The base and wheel dependencies were unchanged.

This establishes the earlier-layer ELF result for these digests. It does not
assess every non-ELF payload or complete the license and source review.

## Native component catalog gap

A separate comparison used alpha.78's published BuildKit SPDX package lists,
signed wheel inventories and retained wheel SBOMs. Both platform lists name
Debian OpenSSL `3.5.7-1~deb13u3`; ARM also names the wheel's vendor RPM,
`openssl-libs` `1.1.1k-15.el8_6`.

Neither list separately names Cryptography's OpenSSL `4.0.1` or Psycopg's
custom OpenSSL `3.5.4`, libpq `18.0` and OpenLDAP `2.6.9` components. Those
identities were checked while adding version-matched sources. Retaining
their SBOMs and source archives did not automatically add them to the
top-level scanner catalog.

The release-day vulnerability reports had no matches for the candidate native
library names. A match list is not a complete scanner catalog, and no match
is not evidence that a component is unaffected. A Debian-package VEX statement
also cannot establish the status of a different OpenSSL copy inside a wheel.

[Issue #18][sources] retains the component, notice and source review, including
this catalog gap. Artifact verification and the layer audit do not provide
maintainer distribution approval or a legal conclusion. The production
warning in [project status][status] remains in place.

[earlier]: 2026-11-10-quiet-reconciliation-and-new-enrollment.md
[alpha77]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.77
[alpha79]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.79
[rescan]: https://github.com/stampbot/extra-codeowners/actions/runs/42805455780
[rescan-guide]: ../../how-to/rescan-published-image.md
[rescans]: https://github.com/stampbot/extra-codeowners/issues/22
[zlib]: https://github.com/stampbot/extra-codeowners/pull/280
[sources]: https://github.com/stampbot/extra-codeowners/issues/18
[status]: ../../reference/project-status.md
