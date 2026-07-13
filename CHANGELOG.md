# Changelog

All notable changes to Extra CODEOWNERS will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before `1.0.0`, incompatible interfaces may change with release notes.

## [Unreleased]

### Added

- GitHub App service with signed webhook ingestion, Check Runs, health endpoints, Prometheus metrics, and an optional App Manifest setup flow.
- Strict CODEOWNERS and Extra CODEOWNERS policy models with human-or-application evaluation on exact pull-request revisions.
- Organization App enrollment, repository path and owner delegation, label restrictions, and non-delegable security paths.
- Database-backed delivery deduplication, latest-generation evaluation and authority fan-out queues, indefinite retries with bounded delay, audit evidence, direct base, policy, label, membership, team, organization, installation, target-repository and policy-repository lifecycle invalidation, and scheduled open-pull-request reconciliation.
- Opt-in, no-noise repository enrollment and a bounded webhook-triggered fast path for revoking managed successes, backed by durable worker evaluation and replay-safe invalidation recovery.
- Blocking `in_progress` checks with pre- and post-publication generation guards, plus configurable webhook-delivery retention.
- Enqueue-time installation authority epochs that permanently fence work queued before an accepted broad authority or repository-identity change.
- Conservative installation-wide fencing when the organization-policy repository is removed from App selection or repository-removal evidence is malformed; well-formed ordinary-target removals remain an access-loss handoff.
- Broad-first authority scheduling, repository-wide preemption of base-specific pushes, and conservative repository-wide collapse after 100 distinct base-ref rows.
- Automatic reactivation of terminal rows created by pre-release builds; current evaluation and authority failures remain pending and retry indefinitely so revocation work is never abandoned.
- Publication-time fail-closed handling when one head commit is already shared by multiple open pull requests.
- Production startup validation requiring hostname-verified `sslmode=verify-full` for non-local PostgreSQL, plus hardened HTTPS App Manifest setup requirements.
- Reproducible uv and mise development environment, non-root container, preview Helm chart, and initial CI and supply-chain workflows.
- Diataxis documentation, security model, operating guidance, and ReadTheDocs configuration.

[Unreleased]: https://github.com/stampbot/extra-codeowners/commits/main
