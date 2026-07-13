# Security policy

Extra CODEOWNERS participates in pull-request authorization, so reports that
could allow an unauthorized approval or expose GitHub credentials are treated
as security-sensitive.

## Supported versions

The project is pre-1.0. Until a stable compatibility policy is published, only
the latest released minor version receives security fixes. Deployments built
from an unreleased branch are not supported.

## Container vulnerability policy

CI independently builds and scans candidates for both `linux/amd64` and
`linux/arm64` before a release image job may upload its commit-specific
candidate. A candidate is blocked by any High or Critical finding for which the
scanner reports an available fix. CI also saves a non-blocking JSON inventory
of all findings, including vulnerabilities for which the upstream distributor
has not published a fix. This distinction keeps unresolved risk visible without
making releases impossible when no remediation exists.

For a tagged release, the image job first pushes only a full-commit candidate
tag, then scans each published platform manifest digest. It signs and attests
the verified index and platform SBOMs before adding semantic-version tags. A
failed exact-artifact scan, signature, attestation, or metadata upload therefore
does not create a release-version image tag.

Each release publishes separate signed SPDX SBOMs for `linux/amd64` and
`linux/arm64`. Each SBOM attestation names its platform manifest digest; the
multi-platform index receives its own provenance attestation and signature.
This avoids presenting one architecture's package inventory as if it covered
both images.

VEX exceptions must identify one vulnerability and the exact affected package
version, explain why the vulnerable code cannot execute in this application,
and pass review like any other security-sensitive change. Source-controlled
statements live in [`.openvex.json`](.openvex.json). Release VEX documents are
bound to the published image digest, attached as OCI attestations, signed, and
included with the release artifacts. A VEX statement is not a substitute for
upgrading when a usable fix exists.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's
[private vulnerability reporting form][report] for the `stampbot/extra-codeowners`
repository. Include:

- the affected version or container digest;
- the deployment mode and relevant configuration, with secrets removed;
- reproduction steps or a proof of concept;
- the security impact you observed; and
- any suggested mitigation.

If private vulnerability reporting is unavailable, contact a repository
maintainer through a non-public contact method listed on their GitHub profile.
Do not include credentials or private repository content in the first message.

Maintainers will acknowledge receipt when available, investigate, and coordinate
disclosure with the reporter. Response and remediation times depend on severity
and maintainer availability; this volunteer project does not promise a service
level agreement.

## Security-sensitive areas

Reports are especially useful when they involve:

- approval identity confusion between a GitHub App and its bot account;
- policy or `CODEOWNERS` evaluation that fails open;
- webhook signature verification, replay, or delivery deduplication;
- installation-token, private-key, or webhook-secret disclosure;
- check results applied to the wrong repository, pull request, or commit SHA;
- path matching, rename, or owner-set behavior that bypasses required review;
- container, Helm chart, or release provenance; or
- denial of service that prevents required checks from converging.

## Operator responsibilities

Operators must use least-privilege GitHub App permissions, protect App private
keys and webhook secrets, restrict administrative access, keep the application
and chart current, and monitor failed webhook deliveries. See the deployment
and operations documentation for the current permission and rotation procedures.

[report]: https://github.com/stampbot/extra-codeowners/security/advisories/new
