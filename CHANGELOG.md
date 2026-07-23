# Changelog

This file records notable changes to Extra CODEOWNERS.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before `1.0.0`, release notes may describe incompatible interface changes.

## [Unreleased]

### Added

- GitHub App service with signed webhook ingestion and Check Runs.
- Health endpoints, Prometheus metrics, and an optional App Manifest setup flow.
- Strict models for `CODEOWNERS`, organization policy, and repository policy.
- Human-or-application evaluation against exact pull-request revisions.
- Organization enrollment by App identity.
- Repository delegation by path, CODEOWNER, and label.
- Built-in and organization-defined non-delegable paths.
- Database-backed webhook delivery deduplication.
- Evaluation queues that retain the latest generation for a pull request.
- Authority fan-out queues with bounded backoff and indefinite retries.
- Audit evidence tied to the delivery and evaluation that produced it.
- Invalidation for base-branch, policy, label, membership, team, organization, installation, and repository lifecycle changes.
- Scheduled reconciliation of open pull requests.
- Explicit repository opt-in that stays silent when no policy or managed check exists.
- A bounded webhook fast path that moves an existing success back to `in_progress`.
- Durable worker recovery when fast invalidation fails.
- Generation guards before and after check publication.
- Configurable webhook-delivery retention.
- Installation authority epochs that permanently fence older queued work.
- Installation-wide fencing when the organization-policy repository is removed, or when repository-removal evidence is missing or malformed.
- A documented handoff for ordinary repository removal after the App loses access.
- Broad authority work scheduled ahead of base-specific work.
- Repository-wide work that replaces older base-specific rows.
- Conservative repository-wide collapse after 100 distinct base-ref rows.
- Reactivation of terminal rows left by older builds.
- Explicit Alembic migrations with bounded PostgreSQL advisory locking.
- A fail-closed startup schema check with no implicit ORM table creation.
- A Helm pre-install and pre-upgrade migration Job.
- Migration-only Helm Secret, environment, volume, mount, and ServiceAccount inputs that exclude runtime GitHub credentials.
- Versioned database compatibility, backup, restore, and rollback guidance.
- Evaluation and authority failures that remain pending until recovery.
- Failure when multiple open pull requests already share a head commit.
- Hostname-verified PostgreSQL TLS for non-local production databases.
- HTTPS and secret-strength checks for App Manifest setup.
- Reproducible uv and mise development tasks.
- A reusable, manually runnable Python distribution proof shared by CI and the
  read-only tagged candidate scan.
- An offline-tested immutable-release controller core with exact draft
  ownership, retained asset descriptors, response-loss reconciliation, and no
  deletion or replacement authority.
- A non-root container, Helm chart source, and supply-chain workflows.
- Schema-v6 container evidence that binds CPython runtime/source identities,
  retains every exact locked native wheel and raw embedded SBOM, and closes
  Greenlet with an exact wheel, owner sdist, five-file native set, and embedded
  SBOM component/source/license set. The evidence proves exact co-membership in
  the wheel; the SBOM provides no component-to-file map, so the policy makes no
  individual payload attribution. Roles are deterministic platform-neutral
  projections of the installed paths, so they cannot be reassigned while
  comparing the native set across platforms. Global package-URL semantics
  reject conflicting nested identity, source, or license records.
- Closed-world native-owner records for MarkupSafe and SQLAlchemy. MarkupSafe
  binds its exact wheels, 80,313-byte sdist, single native role, and explicit
  empty SBOM and component sets. SQLAlchemy binds its exact wheels,
  9,912,201-byte sdist, five native roles, and the same explicit empty sets.
  These records do not claim the sdists explain every binary byte or prove
  reproducible builds. The other four native-wheel owners and overall source
  completeness remain explicitly unresolved.
- Diátaxis documentation, a threat model, operating guides, and Read the Docs configuration.
- Bounded pull-request and scheduled property tests for untrusted parsing and policy inputs.

### Changed

- GitHub API error messages are capped at 1,000 characters, and non-finite rate-limit hints use the bounded default delay.
- Shell lint CI verifies the pinned official ShellCheck release archive instead of depending on an anonymous Docker Hub pull.

[Unreleased]: https://github.com/stampbot/extra-codeowners/commits/main
