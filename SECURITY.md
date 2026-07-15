# Security policy

Extra CODEOWNERS takes part in pull-request authorization. Treat any flaw that could approve the wrong change or expose GitHub credentials as a security issue.

## Supported versions

There is no tagged release today. After the first release and until the project publishes a stable compatibility policy, only the latest minor version will receive security fixes. Builds from `main` are not supported deployments.

## Container vulnerability policy

CI builds and scans separate `linux/amd64` and `linux/arm64` candidates. The release image job cannot run until both scans finish.

CI saves a raw JSON inventory without applying VEX, including findings with no upstream fix. Narrowly reviewed OpenVEX dispositions are then applied to the blocking scan, and any remaining High or Critical finding blocks the candidate when the scanner knows of a fix. This keeps unresolved risk visible without pretending that an unavailable or inapplicable patch can be applied.

For a tagged release, the image job first pushes a candidate tag named for the full commit. It scans each published platform digest, then signs and attests the verified index and its software bills of materials (SBOMs). Semantic-version tags are added last.

If an exact-artifact scan, signature, attestation, or metadata upload fails, the workflow does not create a release-version tag.

The repository's `v*` tag ruleset restricts tag changes to an explicit
maintainer bypass identity. The tag workflow also queries the configured release
milestone number with read-only issue permission, verifies its expected title,
and stops when any issue remains open. It records the milestone counts and
release context in the workflow summary.
This workflow gate cannot prevent an authorized user from pushing a Git tag; it
prevents that unready tag from publishing release artifacts through the
workflow.

Each release publishes a signed SPDX SBOM for each supported architecture. An SBOM attestation names its platform digest. The multi-platform index gets a separate provenance attestation and signature, so one architecture's package list is never presented as evidence for the other.

Each release must also publish a deterministic notice and source-evidence
archive for each platform digest. The archive includes effective and all-layer
inventories, commit-pinned Alpine recipes, checksum-verified distfiles, locked
Python source, license texts, and a human-readable notice file. A reviewed
component policy and explicit maintainer distribution approval gate the release.
This evidence is not a legal-compliance determination. See the
[container distribution evidence design](docs/explanation/container-distribution-evidence.md).

A Vulnerability Exploitability eXchange (VEX) exception must name one vulnerability and the exact package version. It must also explain why the vulnerable code cannot run in this application. VEX dispositions are honored by the blocking scan even when another, unsupported release line contains a fix, so review them like any other security-sensitive change.

Source statements live in [`.openvex.json`](.openvex.json). Release VEX documents are bound to the image digest, attached as OCI attestations, signed, and included with the release artifacts. If a usable fix exists, upgrade instead of adding a VEX statement.

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
