# Project status

Last verified: 2026-08-24.

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

The old `ghcr.io/stampbot/extra-codeowners:main` preview predates the current
pipeline. Don't deploy, mirror, or redistribute it. [Issue #30][issue-30]
tracks its final disposition.

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

The two image jobs push content-addressed native images. The publisher joins
them into one versioned multi-platform image, signs and attests the released
artifacts, publishes the OCI chart, and stages a draft GitHub release. It
uploads the release assets, publishes the release, and succeeds only when
GitHub reports it as immutable. That published immutable release is the
completion record. Rerunning the failed job in the original CI run keeps the
same commit, reuses matching immutable state, and refuses a collision.

Release-channel trailers provide an audited, portable promotion control:
`Release-Channel: alpha` starts the next semantic version as an alpha and
`Release-Channel: stable` promotes the current alpha base. Without a trailer,
an alpha increments its numeric suffix and stable releases use conventional
commits to select major, minor, or patch bumps. There is no release pull
request or manually maintained version file. See the
[contributor guide](https://github.com/stampbot/extra-codeowners/blob/main/CONTRIBUTING.md#choose-a-release-channel)
for the exact merge-message procedure.

These controls describe what the workflow publishes. They do not make an alpha
a supported production release. [Issue #18][issue-18] still tracks complete
notices and corresponding-source delivery, and
[issue #74][issue-74] tracks clean-client verification of a published release.

### Raw container inventory

Each new release includes `distribution-inventory-amd64.json` and
`distribution-inventory-arm64.json`, plus a Sigstore bundle for each file. The
collector exports the exact native image filesystem without starting the
container. It records:

- installed Debian package status and available Debian copyright and
  shared-license entries
- Python distribution metadata and license-file entries
- embedded JSON SBOMs and native Python extension files.

Regular files are hashed. Filesystem links are recorded as links rather than
followed.

The inventory names the exact platform digest from `digest-amd64.txt` or
`digest-arm64.txt`. The release workflow attests and signs each inventory, then
checks that binding again when it verifies an existing release.

This is raw review evidence, not a notice bundle or a corresponding-source
offer. It deliberately reports missing declared license files and does not
decide whether a package's metadata, bundled material, or source availability
satisfies a redistribution obligation. The recipient-facing notice and source
delivery decision remains part of [issue #18][issue-18].

## Production enforcement blocker {#production-enforcement-blocker}

GitHub attaches a Check Run to a commit, but Extra CODEOWNERS evaluates one
pull request: its base, changed paths, labels, and reviews. Two open pull
requests can share a head commit. A success from the first pull request can
therefore appear on the second before Extra CODEOWNERS receives the event that
should revoke it.

The service resets its managed check to `in_progress`, asks GitHub for every
current pull request using that commit, and reevaluates each one. Generation
guards stop an older worker from overwriting newer evidence. Those controls
start only after GitHub delivers an event.

GitHub's commit-to-pull-requests endpoint has another limit: its response does
not say whether the list is complete. The service cannot revoke a check for a
pull request GitHub omitted.

[Issue #1][issue-1] owns the remaining live tests:

- required-check behavior when a completed Check Run returns to `in_progress`
- shared-head opening and retargeting with delayed or lost webhooks
- expected-source selection in repository and organization rulesets
- interaction between a third-party App review and the ordinary approval count
- installation lifecycle, repository transfer, and access loss.

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

Follow the linked issues for current evidence and decisions. Update this page
whenever an availability or safety claim changes.

[issue-1]: https://github.com/stampbot/extra-codeowners/issues/1
[issue-18]: https://github.com/stampbot/extra-codeowners/issues/18
[issue-22]: https://github.com/stampbot/extra-codeowners/issues/22
[issue-30]: https://github.com/stampbot/extra-codeowners/issues/30
[issue-40]: https://github.com/stampbot/extra-codeowners/issues/40
[issue-74]: https://github.com/stampbot/extra-codeowners/issues/74
