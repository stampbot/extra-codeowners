# Security policy

Extra CODEOWNERS participates in pull-request authorization. A false success,
credential leak, or check attached to the wrong repository or commit is a
security issue.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Use GitHub's
[private vulnerability reporting form][report]. Include:

- the release, container digest, or exact commit SHA
- the deployment mode and relevant configuration, with secrets removed
- the smallest reproduction or proof of concept you can safely provide
- the impact you observed
- any temporary mitigation you have tested.

Never include credentials, complete webhook payloads from a private repository,
private repository contents, or unsanitized organization identifiers.

If the private form is unavailable, contact maintainer
[Danny Sauer](https://github.com/dannysauer) through a direct method listed on
his GitHub profile. Keep the first message brief and free of sensitive
attachments so the maintainer can arrange a safer exchange.

Maintainers will acknowledge and investigate reports when they are available,
then coordinate disclosure with the reporter. This volunteer project does not
promise a response or remediation time.

## Supported versions

There is no supported stable release yet. Alpha GitHub releases, images, and
charts are for non-required shadow-mode testing. Builds from pull requests are
not releases. Legacy preview images — `:main` and its `sha-*` and `sha256-*`
companion tags — are unsupported and unsafe for deployment. They are not
approved distribution evidence, but this warning does not assert a known
vulnerability. The
[project status](docs/reference/project-status.md) records the remaining
production and distribution work.

After the first stable release, and until a longer support policy is published,
only the latest minor line will receive security fixes.

## What to report

Send a private report when a flaw involves:

- confusion between an enrolled GitHub App and its bot account
- policy or `CODEOWNERS` evaluation that can fail open
- webhook signature verification, replay, or delivery deduplication
- installation tokens, private keys, webhook secrets, or setup credentials
- a check written to the wrong repository, pull request, or commit
- path matching, renames, owner sets, labels, or stale reviews that bypass
  required approval
- repository transfer, App suspension, or missed-event behavior that can leave
  a false success
- container, Helm, release, source, software bill of materials, signature, or
  provenance integrity
- resource exhaustion that prevents required checks from converging.

The [threat model](docs/explanation/threat-model.md) describes the expected
controls and known residual risks. A behavior already listed there may still be
worth reporting if you found a new way to exploit it or a control does not work
as documented.

## Operator responsibilities

Operators own the deployment boundary. In particular:

- grant only the documented GitHub App permissions
- keep private keys and webhook secrets in a managed secret store
- restrict administrative, database, and metrics access
- monitor failed deliveries, queue convergence, and readiness
- restore native human code-owner enforcement before suspending the App or
  removing repository access
- pin deployed images by digest
- apply updates and rehearse credential rotation and database recovery.

The [deployment guide](docs/how-to/deploy.md) and
[operations guide](docs/how-to/operate.md) cover those procedures. An alpha
operator also accepts that interfaces and database compatibility may change
before 1.0.

## Known non-exploitable vulnerabilities

The current container includes Debian OpenSSL packages with known CVEs. We
reviewed the affected code paths, and they do not affect Extra CODEOWNERS. The
[OpenVEX statement](security/vex/openssl-3.5.6.openvex.json) names the exact
package versions, architectures, Debian distribution, and CVEs. It remains
valid until we upgrade those packages or enable a relevant protocol or API.

This is a project security statement. CI consumes the same file when it scans
the image. The raw report retains every scanner finding, and a package-version
change stops the VEX from matching.

Before it creates an immutable tag or a versioned image reference, the
workflow checks every product URL against signed `amd64` and `arm64`
inventories. Those inventories include the Debian distribution derived from
the image's hashed canonical `/usr/lib/os-release` file. The workflow then
publishes the reviewed bytes as `extra-codeowners-VERSION.openvex.json`, signs
the file, and attaches a keyless OpenVEX attestation to the exact
multi-platform image digest. The release process records the reviewed
conclusion; it does not make a new vulnerability decision.

If a package version or reachable behavior changes, update or remove the source
statement before the next release. Do not replace a VEX asset on an existing
release. GitHub releases are immutable, so a later release is the correction.

## Container policy

The runtime dependency graph is locked in `uv.lock`. The Docker build installs
published wheels with `--no-build`; a missing wheel stops the build instead of
silently compiling native code with an ambient toolchain. The build backend and
its transitive dependencies are another locked group and do not enter the
runtime image.

CI builds the container independently on native `amd64` and `arm64` runners.
Each job runs the image as a nonroot user with no network, no capabilities, and
a read-only root filesystem. The smoke test checks the architecture, glibc,
binary PostgreSQL driver, installed version, source revision, file ownership,
database migration, and health endpoints. A scheduled workflow repeats both
builds without BuildKit cache.

Each container job runs two vulnerability scans:

1. A nonblocking scan records the scanner's raw High and Critical inventory as
   a CI artifact.
2. A blocking scan rejects every High or Critical finding for which the
   scanner reports an available fix.

The raw report keeps unfixed findings visible. The blocking policy makes an
available fix actionable without pretending that an unfixed finding is safe.

Scanner results can lag disclosures, so
[issue #22](https://github.com/stampbot/extra-codeowners/issues/22) tracks
recurring scans of published digests.

The [runtime base decision](docs/explanation/runtime-base.md) explains why the
image uses pinned Debian slim and what that choice leaves exposed.

## Release policy

On a push to `main`, the `Release` job invokes the reusable release workflow
only after `Required` succeeds. It keeps the original commit throughout the
build and derives the next semantic version from reachable tags. It
refuses malformed, ambiguous, divergent, or nonmonotonic release history.

The release builds a Python wheel and source distribution, the Helm chart, and
native images in parallel. Native image jobs receive only package-write
permission and push by digest. The publisher checks the reviewed VEX statement
after every build succeeds. It creates the immutable Git tag only when that
check passes, then joins the native digests into one versioned image and
verifies that the result contains only `linux/amd64` and `linux/arm64`.

Release images carry BuildKit provenance and software bills of materials. The
publisher adds a GitHub provenance attestation and a keyless Sigstore signature
for the multi-platform image. It also attests and signs the Python wheel,
source distribution, Helm chart, and the raw `amd64` and `arm64` container
inventories. The publisher validates the reviewed OpenVEX statement against
those inventories, signs it as a release asset, and attaches it to the
multi-platform image digest. It then signs the OCI chart. Each inventory names
its child-image digest. It stages a draft GitHub release, uploads the assets,
and publishes it. The run succeeds only after GitHub reports that release as
published and immutable. That release is the completion record. Python
artifacts remain GitHub release assets; they are not uploaded to PyPI.

Repository administrators must enable GitHub's **Immutable releases** setting.
The workflow's `GITHUB_TOKEN` cannot read that setting before publication, so
the workflow enforces it as a postcondition on the release object. Before
building the next version, it also requires the preceding release to be
complete and immutable. The public `v0.1.0-alpha.7` release is the only
grandfathered predecessor; it predates this contract.

Rerun a failed release job only in its original CI run. A retry may reuse a tag
when it resolves to that same commit. When it detects a completed GitHub
release, it verifies the required assets, image platforms and digests, and
chart archive and digest instead of republishing them. It then verifies GitHub
provenance for the image, wheel, source distribution, chart, and raw container
inventories. It checks that each inventory names the released platform digest,
then validates the release OpenVEX file against those inventories and its OCI
attestation against that multi-platform digest. It also checks the Sigstore
bundles for the release files and keyless signatures for the image and OCI
chart. Every proof must name this repository's release workflow and the
original commit. Missing, invalid, or ambiguous evidence stops the retry; it
never edits a published immutable release.

Actions are pinned to full commit SHAs. The publishing job receives
`contents`, `packages`, `id-token`, and `attestations` write access; ordinary CI
keeps repository contents read-only. Tag rules must permit GitHub Actions to
create a release tag while preventing later update or deletion.

These controls provide traceable release artifacts, not exhaustive legal or
supply-chain proof. BuildKit metadata and package licenses do not prove that
every notice or corresponding-source obligation has been met. Alpha releases
remain unsupported while that work and the live GitHub authorization contract
are open.

[report]: https://github.com/stampbot/extra-codeowners/security/advisories/new
