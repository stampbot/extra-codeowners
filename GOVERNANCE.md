# Project governance

Extra CODEOWNERS is a small open-source project that participates in pull-request authorization. This document explains how maintainers make decisions and grant access before 1.0.

## Roles

Contributors submit issues, documentation, code, reviews, and operational feedback. Contributing does not grant commit access.

Maintainers review and merge changes. They triage security reports and publish releases. They also administer project infrastructure. Current maintainers must appear in `.github/CODEOWNERS` and hold maintainer access from the `stampbot` organization.

## Decisions

Maintainers make routine decisions by consensus in issues and pull requests. Record a material trade-off in the pull request or an architecture decision record. Security fixes may stay private until coordinated disclosure is safe.

When maintainers cannot reach consensus, they prefer the option that preserves fail-closed authorization behavior, compatibility, and reversibility. A maintainer with a direct conflict of interest should disclose it and avoid being the sole decision maker.

## Changes and releases

Normal changes use pull requests and required checks. Direct pushes to `main` are reserved for repository recovery.

A release starts from a `vMAJOR.MINOR.PATCH` tag on `main`. The release workflow signs and attests its artifacts. The project follows semantic versioning where practical, but a minor release may contain a documented breaking change before 1.0.

Maintainers may remove a release that contains a known credential, malicious
artifact, or critical authorization flaw. Published package versions are not
reused.

## Becoming or leaving a maintainer

An existing maintainer may nominate a contributor who has demonstrated sound security judgment, sustained participation, respectful reviews, and reliable follow-through. Existing maintainers approve access by consensus and grant only the permissions needed for the role.

Maintainers who become inactive may be moved to emeritus status and have write, release, and secret access removed. Access is also removed promptly after a maintainer resigns or when account security is in doubt. Reinstatement follows the same review as a new grant.

## Policy updates

A governance change requires a pull request and a public rationale. Once the project has two active maintainers, it also requires approval from at least two maintainers.
