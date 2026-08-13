# Changelog

This file records notable changes to Extra CODEOWNERS.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before `1.0.0`, release notes may describe incompatible interface changes.

## [Unreleased]

## [0.1.0-alpha.7] - 2026-08-13

### Fixed

- Alternate authority fan-out and ordinary evaluation after exact-head
  invalidation. A retrying repository fan-out can no longer hold up unrelated
  pull-request decisions.
- Retry interrupted Alpine package retrieval during container builds without
  changing the pinned packages or accepting an unbounded retry.

## [0.1.0-alpha.6] - 2026-08-13

### Added

- A **Re-evaluate** action on completed Extra CODEOWNERS checks. It fetches
  current review and policy evidence again without requiring an empty commit.

### Fixed

- Validate a delegated App through its configured immutable GitHub bot account.
  GitHub does not let an installation token look up a different App directly.

## [0.1.0-alpha.5] - 2026-08-11

### Fixed

- Fetch enrolled App identity without an installation token. GitHub rejects
  that token for a different App.
- Cache successful public App identity lookups for one hour to avoid consuming
  the unauthenticated GitHub API quota during every evaluation.
- Bind the application's changing installed `RECORD` file to the selected wheel
  instead of a stale static container-policy baseline.

### Changed

- Alpha release preparation now updates the project version, lock file, and
  changelog with one checked command. Published chart metadata and its default
  image tag come from the signed release tag.
- Container evidence binds first-party wheel metadata to the selected wheel and
  source revision, so an application version bump does not rewrite the
  third-party dependency policy.

## [0.1.0-alpha.4] - 2026-08-10

### Added

- A Helm `deploymentAnnotations` value for workload-level integrations such as
  Stakater Reloader.

## [0.1.0-alpha.3] - 2026-08-08

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
- Repository-and-commit epochs that fence Check Run publication across pull
  requests sharing a head commit.
- Durable exact-head invalidation with leased retries, strict associated
  pull-request revalidation, and publication blocked until the accepted
  generation's reset finishes.
- Shielded blocking resets when a completed Check Run write has an uncertain
  outcome, post-publication database verification fails, or the evaluation
  task is cancelled.
- Atomic shared-head fencing when reconciliation inserts genuinely missing
  work for a known head.
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
- A bounded raw Python-distribution spine and canonical record, verified through
  direct `archive: false` artifacts without archive parsing in the consumer,
  plus atomic five-file materialization for the manually runnable proof and the
  still-blocked privileged release job. Materialization retains and rechecks a
  no-follow ancestry chain and publishes with Linux no-replace rename semantics.
- A dormant release-candidate assembler with repository-read permission. It
  revalidates the raw Python proof, retains its three original records in an
  exact 15-file review inventory, and writes a record that the release
  controller cannot accept. The hosted job remains behind the unconditional
  publication block.
- A bounded raw OCI release-spine builder and standalone verifier, with a
  real two-platform BuildKit directory export, a rerun-safe two-file
  `archive: false` CI transport proof, immutable pre-exposure object
  verification, and no publication authority.
- A standard-library schema-9 recipient content verifier. It parses the
  required single-member gzip framing and pax-tar envelope without generic
  archive extraction. Before writing output, it bounds path use and the
  per-document and aggregate JSON workload, then applies no-follow file
  handling. It checks every checksum, all-layer occurrence, component-evidence
  collection, reviewed policy and license decision, source pin, deterministic
  notice, application source and artifact path, native-wheel launcher,
  native-wheelhouse store record, and selected artifact binding. It derives
  effective files and every filesystem baseline by replaying the layer
  operations, parses reviewed license decisions as bounded canonical SPDX 2.3
  expressions against a frozen SPDX identifier list, reparses retained Cargo
  lockfiles, binds application and native-wheel launcher metadata to validated
  installations, and requires the application source archive to carry the
  same license bytes retained for recipients. TOML inputs now have explicit
  structural bounds and fail closed on parser recursion.
  Signature, attestation, and immutable-release authentication remain blocked
  release work.
- An offline-tested immutable-release controller core with exact draft
  ownership, retained asset descriptors, response-loss reconciliation, and no
  deletion or replacement authority.
- A standard-library GitHub release API adapter with fixed routing, bounded
  responses, descriptor-based uploads, and no workflow or token wiring.
- A read-only immutable-release preflight contract that binds GitHub's setting
  to one repository and workflow run without sharing publication authority.
- A non-root container, Helm chart source, and supply-chain workflows.
- A dedicated amd64 and arm64 native-wheelhouse workflow that builds CFFI,
  Psycopg C, Pydantic Core, and Setuptools twice from pinned inputs and a
  complete platform-specific Alpine package closure. It rejects
  non-reproducible output, contradictory wheel compatibility metadata, and
  unreviewed ELF payloads regardless of filename. It then publishes only the
  verified files in a signed, provenance-attested scratch image. The
  immutable commit digest can be reused after a partially successful
  publication only when its signature, revision, platforms, and payloads match
  a fresh build. Failed-jobs-only reruns select each successful platform upload
  by immutable artifact ID instead of assuming both producers ran in the
  current attempt. Each platform now carries deterministic SPDX 2.3 generated
  from the exact verified wheel manifest. Its package records bind wheel
  filenames, SHA-256 checksums, Python package URLs, declared licenses, and
  reviewed source records. Publication reverifies those bytes, attests them to
  their platform manifests, and uploads separately signed copies instead of
  relying on an empty scratch-image scan.
- Schema-v9 container evidence for native wheelhouse runtime dependencies. The
  application image consumes the signed wheelhouse by immutable digest and
  binds each recorded ELF shared-library name to exact effective APK-owned
  runtime and resolved files, package version, APK checksum, and all-layer
  occurrence. The evidence rejects ELF search-path overrides, unsafe or
  chained links, cross-package substitutions, and checksum drift. The current
  CFFI, Psycopg C, and Pydantic Core owner records are closed, making the
  derived native source-accounting ledger complete while distribution approval
  remains false.
- A Docker-only, bounded image exporter and a separate rootless, networkless
  layer parser. Their create-once handoff binds the saved archive to its exact
  hash, size, configuration digest, subject, and platform; only two bounded
  inventory JSON files cross back to the host.
- Schema-v7 container evidence with a lossless review ledger that separates
  observed artifact facts, reviewed source mappings, and closure. It preserves
  document-local and repeated SBOM occurrence identity, component hashes and
  licenses, metadata-root decisions, payload dispositions, and explicit
  omissions. It also binds CPython runtime and source identities and retains
  every exact locked native wheel and raw embedded SBOM. Earlier schema
  revisions are rejected instead of migrated lossily. Greenlet is closed with
  an exact wheel, owner sdist, five-file native set, and embedded SBOM
  component, source, and license set. The evidence proves exact co-membership
  in the wheel; the SBOM provides no component-to-file map, so the policy makes
  no individual payload attribution. Roles are deterministic platform-neutral
  projections of the installed paths, so they cannot be reassigned while
  comparing the native set across platforms. Global package-URL semantics
  reject conflicting nested identity, source, or license records.
- Closed-world native-owner records for MarkupSafe and SQLAlchemy. MarkupSafe
  binds its exact wheels, 80,313-byte sdist, single native role, and explicit
  empty SBOM and component sets. SQLAlchemy binds its exact wheels,
  9,912,201-byte sdist, five native roles, and the same explicit empty sets.
  These records do not claim the sdists explain every binary byte or prove
  reproducible builds.
- A closed Cryptography 48.0.1 native-owner record that binds all 32 crates.io
  components to exact archives, manifests, checksums, licenses, and notices.
  It also retains the sdist's local Rust subtree, pins its Cargo workspace and
  package manifests, and retains the official checksummed OpenSSL 4.0.1
  release. Local and upstream reviews must match their source paths, identities,
  PURLs, hashes, and reviewed license expressions. Crate notice policy must
  exactly cover every license or notice file in each archive. The arm64
  `NotpineForGHA` observation remains literal and shares Greenlet's closed
  Alpine GCC evidence only through exact `libgcc` payload equivalence. This
  record does not claim wheel reproducibility or build provenance.
- Pydantic Core source retention for all 87 crates.io components in its SBOM,
  including exact archives, manifests, checksums, licenses, and notices. The
  retained sdist supplies the root Cargo package and exact lockfile with 16
  additional registry entries. Local path dependencies are traced from the
  selected package or workspace even when the upstream SBOM omits them, and
  every reachable local package must agree with the reviewed manifests and
  lockfile. Library-target verification binds `_pydantic_core` and `src/lib.rs`
  to the pinned manifest before the extension payload can cite those
  observations. Build-directory prefixes remain opaque rather than being
  mistaken for Python project names.
- Diátaxis documentation, a threat model, operating guides, and Read the Docs configuration.
- Bounded pull-request and scheduled property tests for untrusted parsing and policy inputs.
- Machine-readable live GitHub evidence completeness that distinguishes false,
  not-run, missing, and invalid observations, plus a bounded lifecycle-delivery
  collector that uses GitHub's cursor links and retains payload shape without
  payload values.
- A fail-closed prerequisite preflight and sanitized local report for the
  disposable, non-required evaluation beta.
- A first-check tutorial that proves human CODEOWNER evaluation before App delegation.
- A pull-request check troubleshooting guide and CI-validated policy examples.
- A byte-for-byte HMAC probe for reviewing tutorial webhook-relay updates.

### Changed

- Public documentation now starts with repository setup and check results; release
  engineering has a separate maintainer section.
- Native CODEOWNERS guidance no longer claims undocumented GitHub App bot
  behavior, and diagrams render without browser-side JavaScript.
- The first-check tutorial now uses a checksum-pinned webhook relay on supported
  Linux and macOS platforms, with an explicit maintainer update procedure.
- Known-head evaluation and authority fan-out writes now create their
  exact-head invalidation fence in the same transaction, so pruning cannot
  orphan a queued generation.
- A duplicate webhook reports `queued: true` when its pending fast-path retry
  discovers and queues a newer live head.
- Reconciliation now validates GitHub pagination links, repository result
  counts, and duplicate discovery identities. An interrupted graceful shutdown
  no longer reports a complete scan.
- GitHub API error messages are capped at 1,000 characters, and non-finite rate-limit hints use the bounded default delay.
- Shell lint CI verifies the pinned official ShellCheck release archive instead of depending on an anonymous Docker Hub pull.
- Production PostgreSQL connections can use `sslmode=require` when the deployment has no CA verification path. `sslmode=verify-full` remains available for deployments that do.

### Security

- Updated `cryptography` to 50.0.0 and refreshed the reviewed native source and wheel evidence for both supported container architectures.

[Unreleased]: https://github.com/stampbot/extra-codeowners/commits/main
