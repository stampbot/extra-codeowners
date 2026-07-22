# Container distribution evidence

This directory contains the reviewed input to the container evidence collector.
`container-policy.json` is deliberately fail-closed: a package version, declared
license, Alpine origin commit, Python source archive, base image, or license-text
change requires a reviewed policy update.

The policy and generated JSON records use schema version `4`. Evidence
predicates use media type
`application/vnd.stampbot.container-evidence.v4+tar+gzip`; earlier or unknown
versions fail closed.

Raw layer headers remain in the generated all-layer inventory. Filesystem
policy stores canonical directory effects and removals, not a Docker
exporter's incidental tar encoding. Regenerate that projection with the
reviewed helper; do not copy raw directory or whiteout arrays into policy.

Do not describe a passing collector as a legal-compliance determination. The
collector records the package metadata, embedded wheel SBOM files, native
payload paths, retained sources, and reviewed policy it observed. It normalizes
CPython into the top-level component inventory and binds that record to exact
version-header, interpreter-link, interpreter, and shared-library identities.
The bundle also retains the pinned Docker Official Python recipe, exact CPython
source archive, and source-carried `LICENSE` bytes. The source and image
`patchlevel.h` digests must agree. For each wheel that owns a native payload or
embedded SBOM, the bundle retains the exact locked platform wheel and a separate
copy of every raw SBOM. It still does not expand the components inside those
files into complete notice and corresponding-source coverage. The inventory
and manifest therefore keep source completeness `false` for that remaining
work.

Do not set `distribution_approval.approved` to `true` while that status remains
false. Normal inventory verification does not treat that policy field as a
publication control. The optional approval-required gate rejects approval
while component and corresponding-source completeness issue
[`#18`](https://github.com/stampbot/extra-codeowners/issues/18) remains open,
and the field cannot enable publication. The `main` publication job has been
removed. Tagged-release publication is
independently and structurally disabled pending privilege-separation issue
[`#28`](https://github.com/stampbot/extra-codeowners/issues/28). The
[handoff of the selected Python proof](https://github.com/stampbot/extra-codeowners/issues/32)
must also reach release and ad-hoc consumers before supported distribution. An
[older public GHCR preview](https://github.com/stampbot/extra-codeowners/issues/30)
is unsupported and incomplete; do not deploy or mirror it. Pull-request CI
artifacts are unsigned, untrusted review inputs, not release assets.

The CI [raw OCI release-spine check](../docs/reference/release-spine-format.md)
is another internal proof, not compliance evidence. It verifies a generated
two-platform fixture carried as two unarchived workflow artifacts. The spine
contains opaque OCI object bytes and a canonical range record; it does not
inspect layer contents or establish component, notice, source, SBOM,
signature, attestation, or publication completeness. A future release consumer
must take the root index digest from the pinned build action outside the record
and must stream from the verifier's already-open file descriptor.

Run the documented workflow in
[`docs/how-to/review-container-evidence.md`](../docs/how-to/review-container-evidence.md)
to inspect this evidence.
