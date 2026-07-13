# Project governance

Extra CODEOWNERS is maintained as a small, security-sensitive open-source
project. This document describes how decisions and maintainer access work while
the project is pre-1.0.

## Roles

**Contributors** submit issues, documentation, code, reviews, and operational
feedback. A contribution does not require or imply commit access.

**Maintainers** review and merge changes, triage security reports, publish
releases, and administer project infrastructure. Current maintainers are the
users and teams listed in `.github/CODEOWNERS` and granted repository maintainer
access by the `stampbot` organization.

## Decisions

Routine decisions are made in issues and pull requests by maintainer consensus.
The reviewing maintainer records material trade-offs in the pull request or an
architecture decision record. Security fixes may be developed privately until
coordinated disclosure is safe.

When consensus cannot be reached, maintainers prefer the option that preserves
fail-closed authorization behavior, compatibility, and reversibility. A
maintainer with a direct conflict of interest should disclose it and avoid being
the sole decision maker.

## Changes and releases

All normal changes use pull requests and required checks. Direct pushes to the
default branch are reserved for repository recovery. Releases are created from
`vMAJOR.MINOR.PATCH` tags that point to commits on `main`; the release workflow
signs and attests the resulting artifacts. Releases follow semantic versioning
where practical. Before 1.0, minor releases may contain documented breaking
changes.

Maintainers may remove a release that contains a known credential, malicious
artifact, or critical authorization flaw. Published package versions are not
reused.

## Becoming or leaving a maintainer

An existing maintainer may nominate a contributor who has demonstrated sound
security judgment, sustained participation, respectful reviews, and reliable
follow-through. Existing maintainers approve access by consensus and grant only
the permissions needed for the role.

Maintainers who become inactive may be moved to emeritus status and have write,
release, and secret access removed. Access is also removed promptly after a
maintainer resigns or when account security is in doubt. Reinstatement follows
the same review as a new grant.

## Policy updates

Governance changes require a pull request, public rationale, and approval from
at least two maintainers when the project has two or more active maintainers.
