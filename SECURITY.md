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

There is no supported release yet. Builds from `main`, pull-request artifacts,
and the older public GHCR preview are development evidence, not supported
deployments. The [project status](docs/reference/project-status.md) tracks the
release blockers.

After the first release, and until a stable support policy is published, only
the latest minor line will receive security fixes.

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
- container, Helm, release, source, SBOM, signature, or provenance integrity
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
- apply updates and rehearse credential rotation and database recovery.

The [deployment guide](docs/how-to/deploy.md) and
[operations guide](docs/how-to/operate.md) cover those procedures. The absence
of a supported release means operators evaluating the source also own the build
and distribution risk.

## Container and release policy

The repository treats container evidence as a security boundary, not as a
release approval.

CI builds separate `linux/amd64` and `linux/arm64` candidates. It retains a raw
vulnerability inventory before applying narrowly reviewed OpenVEX statements.
Any remaining High or Critical finding blocks the candidate when the scanner
knows of a fix. Findings without an available or applicable fix remain visible
in the raw inventory.

Current evidence normalizes CPython as a top-level runtime component. It binds
that record to the interpreter's exact identity files and retains the pinned
build recipe, source archive, and source-carried license. It also replays
historical wheel `RECORD` ownership across distributed layers. This is not yet
complete corresponding-source evidence: native wheel payloads and embedded
SBOMs still need exact component, notice, and source coverage under
[#18](https://github.com/stampbot/extra-codeowners/issues/18).

The application package follows a separate build proof:

1. Native `amd64` and `arm64` jobs each create two clean, hash-pinned PEP 517
   distributions.
2. CI selects byte-identical results and retains the source, wheel, and
   selection-record digests.
3. Container jobs download that proof by immutable artifact ID, verify it, and
   install the selected wheel without consulting the ambient source tree.

CI, manual proof runs, and the tagged read-only scan use this same reusable
workflow. [#32](https://github.com/stampbot/extra-codeowners/issues/32) remains
open because retained release evidence and future publication do not yet
consume the selected proof.

Tagged publication is structurally disabled. The release workflow may run
read-only source checks, Python proof, milestone validation, and candidate
scans. A separate job then fails unconditionally, and every job with image,
chart, Python-package, signing, attestation, or GitHub-release authority depends
directly on that blocker. Changing a policy approval field cannot bypass it.

[#28](https://github.com/stampbot/extra-codeowners/issues/28) tracks the
privilege-separated evidence and publication design. The `v*` tag ruleset also
restricts tag changes to an explicit maintainer bypass identity, while the
workflow verifies the configured milestone title and refuses publication when
issues remain open. Those controls govern the workflow; they cannot prevent an
authorized maintainer from creating a Git tag.

A future supported release must include, for each platform digest:

- a signed SPDX SBOM and platform-specific SBOM attestation
- separate provenance and a signature for the multi-platform index
- deterministic notices and corresponding-source evidence
- the exact retained application build proof
- reviewed component policy and explicit distribution approval.

Evidence from one architecture must never be presented for another. Current CI
archives are unsigned review inputs and are not substitutes for released
evidence or legal review. The
[container distribution evidence design](docs/explanation/container-distribution-evidence.md)
documents the detailed contract.

## OpenVEX exceptions

Each VEX statement must identify one vulnerability and the exact package
version, then explain why the affected code cannot run in Extra CODEOWNERS.
Review that claim as security-sensitive code. If a usable fix exists, upgrade
instead of adding an exception.

Source statements live in [`.openvex.json`](.openvex.json). No release VEX
asset exists today. A future release must bind VEX to the exact image digest,
attach it as an OCI attestation, sign it, and publish it with the release
artifacts.

[report]: https://github.com/stampbot/extra-codeowners/security/advisories/new
