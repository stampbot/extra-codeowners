# Security policy

Extra CODEOWNERS takes part in pull-request authorization. Treat any flaw that could approve the wrong change or expose GitHub credentials as a security issue.

## Supported versions

There is no tagged release today. After the first release and until the project publishes a stable compatibility policy, only the latest minor version will receive security fixes. Builds from `main` are not supported deployments.

## Container vulnerability policy

CI builds and scans separate `linux/amd64` and `linux/arm64` candidates. The release image job cannot run until both scans finish.

CI saves a raw JSON inventory without applying VEX, including findings with no upstream fix. Narrowly reviewed OpenVEX dispositions are then applied to the blocking scan, and any remaining High or Critical finding blocks the candidate when the scanner knows of a fix. This keeps unresolved risk visible without pretending that an unavailable or inapplicable patch can be applied.

The `main` container publication job has been removed, and tagged publication
is currently disabled. Source-completeness issue #18 covers two gaps: CPython
is not normalized into the top-level component and notice inventory; installed
native-wheel and embedded-SBOM contents are not expanded into complete
component, notice, and corresponding-source records. The collector separately
replays historical wheel `RECORD` ownership across every distributed layer.

Pull-request CI now builds a hash-pinned PEP 517 proof on both native
architectures and installs the exact selected application wheel. Build-proof
issue [`#32`](https://github.com/stampbot/extra-codeowners/issues/32) remains
open because the release and ad-hoc build paths do not yet consume that selected
proof. A successful candidate scan does not close that supply-chain gap.

The release workflow unconditionally
fails after validating its readiness milestone and before any job with image,
chart, Python package, signing, attestation, or GitHub release authority can
run. Security issue
[`#28`](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
required privilege-separated container-evidence pipeline. Changing the
component policy's approval value does not remove this structural block.

The repository's `v*` tag ruleset restricts tag changes to an explicit
maintainer bypass identity. The tag workflow also queries the configured release
milestone number with read-only issue permission, verifies its expected title,
and stops when any issue remains open. It records the milestone counts and
release context in the workflow summary.
This workflow gate cannot prevent an authorized user from pushing a Git tag; it
prevents that unready tag from publishing release artifacts through the
workflow.

A future supported release must publish a signed SPDX SBOM for each supported
architecture. Each SBOM attestation must name its platform digest, while the
multi-platform index receives separate provenance and a signature. Evidence
from one architecture must never be presented for the other.

That release must also publish a deterministic notice and source-evidence
archive for each platform digest. The required archive contains effective and
all-layer inventories, commit-pinned Alpine recipes, checksum-verified
distfiles, locked Python source, license texts, and a human-readable notice. It
must close both remaining #18 gaps, including expanding every embedded wheel
SBOM and native payload into exact component, notice, and corresponding-source
coverage, or use wheels rebuilt against separately inventoried system packages.
It must also consume the hash-pinned, cross-architecture application proof
required by issue #32 and bind the installed application to that exact wheel.
Publication requires reviewed component policy and explicit maintainer
distribution approval after the collector is split into rootless, network-free
parsing and separately privileged fetch and publication phases. The current CI
archives are unsigned review inputs and are not substitutes. This evidence is
not a legal-compliance determination. See the
[container distribution evidence design](docs/explanation/container-distribution-evidence.md).

A Vulnerability Exploitability eXchange (VEX) exception must name one vulnerability and the exact package version. It must also explain why the vulnerable code cannot run in this application. VEX dispositions are honored by the blocking scan even when another, unsupported release line contains a fix, so review them like any other security-sensitive change.

Source statements live in [`.openvex.json`](.openvex.json). No release VEX asset
exists today. A future release must bind each release VEX document to the image
digest, attach it as an OCI attestation, sign it, and include it with the
release artifacts. If a usable fix exists, upgrade instead of adding a VEX
statement.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's [private vulnerability reporting form][report]. Include:

- the affected version or container digest
- the deployment mode and relevant configuration, with secrets removed
- reproduction steps or a proof of concept
- the security impact you observed
- any suggested mitigation

If the private form is unavailable, use a non-public contact method from a maintainer's GitHub profile. Do not put credentials or private repository content in the first message.

Maintainers will acknowledge the report when they are available. They will investigate and coordinate disclosure with the reporter. This volunteer project does not promise response or remediation times.

## Security-sensitive areas

Send a private report when a flaw involves:

- approval identity confusion between a GitHub App and its bot account
- policy or `CODEOWNERS` evaluation that fails open
- webhook signature verification, replay, or delivery deduplication
- installation-token, private-key, or webhook-secret disclosure
- check results applied to the wrong repository, pull request, or commit SHA
- path matching, rename, or owner-set behavior that bypasses required review
- container, Helm chart, or release provenance
- denial of service that prevents required checks from converging

## Operator responsibilities

Operators must keep GitHub App permissions narrow. They must protect the App private key and webhook secret. Restrict administrative access and update the application and chart. Monitor failed webhook deliveries.

The [deployment guide](docs/how-to/deploy.md) and [operations guide](docs/how-to/operate.md) cover permissions, credential rotation, and recovery.

[report]: https://github.com/stampbot/extra-codeowners/security/advisories/new
