# Project governance

Extra CODEOWNERS participates in pull-request authorization. This document
explains who may make project decisions, merge changes, and grant access before
1.0.

## Roles

Contributors submit issues, documentation, code, reviews, and operational
feedback. Contributing does not grant commit access.

Maintainers review and merge changes, triage security reports, publish
releases, and administer project infrastructure. Every current maintainer must
appear in `.github/CODEOWNERS` and have maintainer access through the
`stampbot` organization.

Danny Sauer is the only active maintainer today. The repository therefore does
not require a second human approval or native CODEOWNER review. Its protected
branch still requires automated checks, resolved review conversations, and
linear history. The current operating policy is tracked in
[#34](https://github.com/stampbot/extra-codeowners/issues/34).

## Decisions

While the project has one maintainer, Danny makes routine decisions in public
issues and pull requests and records material trade-offs there or in an
architecture decision record. Security fixes may stay private until
coordinated disclosure is safe.

With two or more maintainers, routine decisions use consensus. If maintainers
disagree, they prefer the option that keeps authorization fail closed and is
easiest to reverse. A maintainer with a direct conflict of interest should
disclose it and ask another maintainer or an appropriate outside reviewer to
weigh in. When no independent maintainer exists, record that limitation instead
of implying that an independent review occurred.

## Changes and releases

Normal changes use pull requests and required checks. Direct pushes to `main`
are reserved for repository recovery.

A future release will start from a `vMAJOR.MINOR.PATCH` tag on `main`. The
release workflow contains the intended signing and attestation jobs, but an
unconditional publication blocker currently keeps them unreachable. Once that
block is removed through the reviewed release process, published artifacts
will be signed and attested. The project follows semantic versioning where
practical, but a minor release may contain a documented breaking change before
1.0.

A credential, malicious artifact, or critical authorization flaw in a release
is a security incident. Revoke or remove the affected artifact wherever the
platform permits it, publish an advisory, and issue a corrected version.
Immutable releases may be impossible to delete; never reuse their package
version or tag.

## Becoming or leaving a maintainer

An existing maintainer may nominate a contributor who has demonstrated sound
security judgment, sustained participation, respectful reviews, and reliable
follow-through. While there is one maintainer, the nomination and reasons stay
public unless they contain private security or personal information. With two
or more maintainers, maintainers approve access by consensus. Grant only the
permissions needed for the role.

Maintainers who become inactive may be moved to emeritus status and have
write, release, and secret access removed. Remove access promptly after a
maintainer resigns or when account security is in doubt. Reinstatement follows
the same process as a new grant.

## Policy updates

A governance change requires a pull request and a public rationale. Once the
project has two active maintainers, the record must show agreement from at
least two of them.
