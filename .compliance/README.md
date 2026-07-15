# Container distribution evidence

This directory contains the reviewed input to the container evidence collector.
`container-policy.json` is deliberately fail-closed: a package version, declared
license, Alpine origin commit, Python source archive, base image, or license-text
change requires a reviewed policy update.

Raw layer headers remain in the generated all-layer inventory. Filesystem
policy stores canonical directory effects and removals, not a Docker
exporter's incidental tar encoding. Regenerate that projection with the
reviewed helper; do not copy raw directory or whiteout arrays into policy.

Do not describe a passing collector as a legal-compliance determination. The
collector records the package metadata, embedded wheel SBOM files, native
payload paths, retained sources, and reviewed policy it observed. It does not
yet normalize CPython into the top-level inventory, expand native wheel and
embedded-SBOM components into complete notice and corresponding-source
coverage, or replay `RECORD` ownership for ineffective historical Python
installs. The inventory and manifest therefore mark source completeness
`false`.

Do not set `distribution_approval.approved` to `true` while that status remains
false. Normal inventory verification does not treat that policy field as a
publication control. The optional approval-required gate rejects approval
while component and corresponding-source completeness issue
[`#18`](https://github.com/stampbot/extra-codeowners/issues/18) remains open,
and the field cannot enable publication. The `main` publication job has been
removed. Tagged-release publication is
independently and structurally disabled pending privilege-separation issue
[`#28`](https://github.com/stampbot/extra-codeowners/issues/28). An
[exact, hash-pinned Python build boundary](https://github.com/stampbot/extra-codeowners/issues/32)
is also required before supported distribution. An
[older public GHCR preview](https://github.com/stampbot/extra-codeowners/issues/30)
is unsupported and incomplete; do not deploy or mirror it. Pull-request CI
artifacts are unsigned, untrusted review inputs, not release assets.

Run the documented workflow in
[`docs/how-to/review-container-evidence.md`](../docs/how-to/review-container-evidence.md)
to inspect or update this evidence.
