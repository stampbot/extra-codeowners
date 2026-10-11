# Project status

Legacy registry inventory verified: 2026-09-09. Other status last verified:
2026-10-11.

Extra CODEOWNERS is ready for source review and non-required shadow-mode
testing. It is not ready to replace GitHub's native code-owner enforcement on
production repositories.

## Available surfaces

| Surface | Status |
| --- | --- |
| Source checkout | Available for development and evaluation |
| GitHub App Manifest registration | Implemented |
| Policy evaluation and Check Run | Implemented; production provider contracts remain open in [issue #1][issue-1] |
| GitHub release | Published automatically by successful `main` CI; an interrupted run may leave a draft until that run is retried |
| Container image | Signed, attested, multi-platform alpha image in GitHub Container Registry (GHCR) |
| Helm chart | Signed alpha OCI chart in GHCR |
| Python wheel and source distribution | Signed and attested GitHub release assets; not published to the Python Package Index (PyPI) |
| Production code-owner enforcement | Not supported |
| Hosted service | Not available |
| `extra-codeowners-action` Marketplace Action | Not available |

Current alpha releases are complete enough to run the App in shadow mode. Pin
the image by digest, use the chart from the same version, and leave the check
non-required. The [deployment guide](../how-to/deploy.md) covers that path.

Legacy preview images — `ghcr.io/stampbot/extra-codeowners:main` and its
`sha-*` and `sha256-*` companion tags — are unsupported and unsafe for
deployment. They predate the immutable release pipeline. Their signatures and
provenance verify, but they lack the complete release and corresponding-source
evidence required for a supported artifact. Don't deploy, mirror, or
redistribute them. This is not a claim of a known vulnerability. The
[legacy inventory](legacy-preview-inventory.md) records all 81 retained objects;
[issue #30][issue-30] holds the retention decision.

## Release behavior

A push to `main` must pass the required CI jobs before `Release` invokes the
reusable release workflow. It derives the next semantic version from
reachable Git tags, then builds the Python wheel, source distribution, Helm
chart, and native `amd64` and `arm64` images from that exact commit.

Branch concurrency uses `queue: max`, so a later `main` push cannot discard an
earlier run. GitHub may start queued runs out of commit order. If a descendant
run publishes first, the older run proves that the descendant release is on
`main`, complete, and immutable, then finishes without publishing duplicate
artifacts. One release may therefore contain more than one closely spaced
merge.

The two image jobs push content-addressed native images. The publisher validates
the reviewed OpenVEX statement against both raw inventories before it creates a
versioned image or immutable tag. It then joins the native images into one
multi-platform image and signs and attests the released artifacts. It publishes
the OCI chart and stages a draft GitHub release. The VEX release asset carries
a keyless attestation for that multi-platform digest. The job uploads the
release assets, publishes the release, and succeeds only when GitHub reports it
as immutable. That published immutable release is the completion record.
Rerunning the failed job in the original CI run keeps the same commit, reuses
matching immutable state, and refuses a collision.

Release-channel trailers provide an audited, portable promotion control:
`Release-Channel: alpha` starts the next semantic version as an alpha and
`Release-Channel: stable` promotes the current alpha base. Without a trailer,
an alpha increments its numeric suffix and stable releases use conventional
commits to select major, minor, or patch bumps. There is no release pull
request or manually maintained version file. See the
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md#choose-a-release-channel)
for the exact merge-message procedure.

These controls describe what the workflow publishes. They do not make an alpha
a supported production release. Starting with the first release containing the
notice-bundle workflow, it also publishes signed, attested per-platform
[recipient notice bundles](recipient-notices.md). Releases containing the
source delivery workflows also retain [source archives](source-archives.md)
for CPython and installed Debian packages.
[Issue #18][issue-18] still
tracks complete corresponding-source delivery and approval of the distribution
mechanism, and
[issue #74][issue-74] tracks clean-client verification of a published release.

### Raw container inventory

Each new release includes `distribution-inventory-amd64.json` and
`distribution-inventory-arm64.json`, plus a Sigstore bundle for each file. The
collector exports the exact native image filesystem without starting the
container. It records:

- installed Debian package status and available Debian copyright and
  shared-license entries
- the Debian distribution derived from the image's hashed canonical
  `/usr/lib/os-release` file
- Python distribution metadata and license-file entries
- embedded JSON SBOMs and native Python extension files.

For images containing CPython source metadata, the inventory also identifies
the interpreter version, the source URL and SHA-256 declared by the pinned
base image, and the matching runtime license. The notice bundle preserves the
metadata and license. Source-archive delivery and full build-recipe evidence
remain part of issue #18.

Regular files are hashed. Filesystem links are recorded as links rather than
followed.

The inventory names the exact platform digest from `digest-amd64.txt` or
`digest-arm64.txt`. The release workflow attests and signs each inventory, then
checks that binding again when it verifies an existing release.

When a reviewed OpenVEX statement is present, the publisher accepts it only if
its product URLs match the pair of signed inventories, including the Debian
distribution for Debian package URLs. The resulting release asset is signed and
attached to the multi-platform image digest. It records the reviewed conclusion
for that image; it does not replace the raw scanner report.

This is raw review evidence. The release workflow uses it to construct and
verify the accompanying [recipient notice bundle](recipient-notices.md), while
keeping missing declared license files visible. Neither artifact decides
whether package metadata, bundled material, or source availability satisfies a
redistribution obligation. Corresponding-source delivery and approval remain
part of [issue #18][issue-18].

## Production enforcement blocker {#production-enforcement-blocker}

GitHub attaches a Check Run to a commit, but Extra CODEOWNERS evaluates one
pull request: its base, changed paths, labels, and reviews. Two open pull
requests can share a head commit. A success from the first pull request can
therefore appear on the second before Extra CODEOWNERS receives the event that
should revoke it.

The service resets its managed check to a blocking failure, asks GitHub for every
current pull request using that commit, and reevaluates each one. Generation
guards stop an older worker from overwriting newer evidence. Those controls
start only after GitHub delivers an event.

GitHub's commit-to-pull-requests endpoint has another limit: its response does
not say whether the list is complete. The service cannot revoke a check for a
pull request GitHub omitted.

[Issue #1][issue-1] owns the remaining live tests:

- repeated validation of the explicit failure reset used during reevaluation
- shared-head opening and retargeting with delayed or lost webhooks
- installation lifecycle, repository transfer, and access loss.

Live tests have confirmed that an expected App source works in both
repository and organization rulesets, that an App review can satisfy the
ordinary approval count, and that the explicit failure reset blocks a merge.
The service resets to an explicit failure because a status-only `in_progress`
reset didn't reliably block one. The reusable fixture writes a versioned report
so an older observation isn't mistaken for a test of current behavior. The
[live validation results](../maintainers/live-validation.md) record each run's
date and release.

Keep GitHub's native **Require review from Code Owners** rule on production
repositories until that contract is proven.

## Other open hardening work

The repository contains a bounded Developer Certificate of Origin (DCO)
evaluator. It binds a decision to one repository, pull request, and exact base
and head commit. No independent service or workflow calls it yet, so a pull
request can still modify the workflow that checks that pull request. Read the
[DCO evidence contract](dco-evidence.md) for the implemented boundary.
[Issue #40][issue-40] tracks independent execution.

The release pipeline produces BuildKit software bills of materials, raw
container inventories, provenance, signatures, attestations, and vulnerability
reports. None of those artifacts alone proves every open-source redistribution
duty. The project also needs recurring scans of already-published digests
because a clean release-day scan cannot see tomorrow's disclosure; [issue #22][issue-22]
tracks that work.

## Planned distributions

The self-hosted GitHub App comes first. A packaged Marketplace Action and a
hosted service are separate roadmap items, with no availability date.

## Remaining work {#remaining-work}

This is the one list of open work. Other pages describe current limits and
link here instead of keeping their own lists. Each item links to the issue that
holds its evidence and decisions.

### Gates for the first supported release

The [First supported release][milestone] milestone holds the gates that must
close before the project is presented as production-ready:

- [Issue #1][issue-1]: prove live check invalidation, shared-head behavior,
  and installation access loss. This is the
  [production enforcement blocker](#production-enforcement-blocker).
- [Issue #203][issue-203]: bound GitHub API use for large installations whose
  repositories are mostly unenrolled, and measure quiet reconciliation and
  missed-webhook recovery.
- [Issue #18][issue-18]: complete corresponding-source delivery and approval of
  the distribution mechanism.

### Known defects

- [Issue #243][issue-243]: the check briefly reports failure about every 30
  minutes on an unchanged, approved pull request, then returns to success.
- [Issue #241][issue-241]: when Argo CD resumes a drained release, the
  PodDisruptionBudget should be ordered after the Deployment.

### Hardening and verification

- [Issue #40][issue-40]: run DCO evaluation where a pull request can't modify
  its own checker.
- [Issue #22][issue-22]: rescan published image digests for newly disclosed
  vulnerabilities.
- [Issue #74][issue-74]: verify the first immutable release from a clean
  client.
- [Issue #24][issue-24]: harden the `stampbot` organization's identity and
  new-repository defaults.
- [Issue #10][issue-10]: enroll in the OpenSSF Best Practices program.
- Two requirements have no test that names them: XCO-004 in the
  [threat model](../explanation/threat-model.md#invariants) and XCO-015 in the
  [architecture design rules](../explanation/architecture.md#design-rules).

### Evaluation and adoption

- [Issue #76][issue-76]: run a disposable, non-required evaluation beta.
- [Issue #34][issue-34]: require the check on this repository, with Stampbot
  as the approving App.

### Roadmap

- [Issue #4][issue-4]: support merge queues and `merge_group` reevaluation.
- [Issue #2][issue-2]: publish the `extra-codeowners-action` Marketplace
  Action.
- [Issue #5][issue-5]: design the hosted service's security and operating
  model.
- [Issue #3][issue-3]: add a supported Google Cloud reference deployment.
- [Issue #124][issue-124]: support Redis as a second state-store backend.
- [Issue #7][issue-7]: design the App icon and project identity.

Update this page whenever an availability or safety claim changes, or an issue
on this list opens or closes.

[milestone]: https://github.com/stampbot/extra-codeowners/milestone/1
[issue-1]: https://github.com/stampbot/extra-codeowners/issues/1
[issue-2]: https://github.com/stampbot/extra-codeowners/issues/2
[issue-3]: https://github.com/stampbot/extra-codeowners/issues/3
[issue-4]: https://github.com/stampbot/extra-codeowners/issues/4
[issue-5]: https://github.com/stampbot/extra-codeowners/issues/5
[issue-7]: https://github.com/stampbot/extra-codeowners/issues/7
[issue-10]: https://github.com/stampbot/extra-codeowners/issues/10
[issue-18]: https://github.com/stampbot/extra-codeowners/issues/18
[issue-22]: https://github.com/stampbot/extra-codeowners/issues/22
[issue-24]: https://github.com/stampbot/extra-codeowners/issues/24
[issue-30]: https://github.com/stampbot/extra-codeowners/issues/30
[issue-34]: https://github.com/stampbot/extra-codeowners/issues/34
[issue-40]: https://github.com/stampbot/extra-codeowners/issues/40
[issue-74]: https://github.com/stampbot/extra-codeowners/issues/74
[issue-76]: https://github.com/stampbot/extra-codeowners/issues/76
[issue-124]: https://github.com/stampbot/extra-codeowners/issues/124
[issue-203]: https://github.com/stampbot/extra-codeowners/issues/203
[issue-241]: https://github.com/stampbot/extra-codeowners/issues/241
[issue-243]: https://github.com/stampbot/extra-codeowners/issues/243
