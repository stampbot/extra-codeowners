# Rescan a published image

Use **Rescan published release** to check an existing image against a fresh
vulnerability database. It scans the published `amd64` and `arm64` digests;
it doesn't rebuild the image, change a tag, or publish new evidence as though
it came from the original build.

## Start a scan

The workflow is scheduled daily at 08:43 UTC. It selects the most recently
published release, including alphas. GitHub can delay scheduled runs, so use a
manual run when you need a result now.

With repository Actions write access and an authenticated GitHub CLI, run it
from `main` (other branches are skipped):

```bash
gh workflow run rescan-release.yml --repo stampbot/extra-codeowners
gh run list --repo stampbot/extra-codeowners --workflow rescan-release.yml --limit 5
```

Select a specific tag with `-f tag=v0.1.0-alpha.32`, replacing the example with
the release you want. Manual selection is limited to the latest 100 release
records returned by GitHub. The release must be immutable and carry the signed
inventories, recipient notice bundles, and VEX evidence required by the current
verifier. Older releases without that evidence fail verification, not pass
the scan. Moving `main` and commit-SHA image tags aren't accepted.

Find the run in **Actions → Rescan published release**. Both architecture jobs
must succeed. Before scanning, each job verifies the release evidence against
its original release commit and checks that the inventory digests belong to the
published multi-platform image.

## Read the result

Each job retains an unfiltered Grype JSON report for 14 days as
`rescan-TAG-ARCHITECTURE`. The report includes the scanner and vulnerability
database metadata. Download it from the run's artifacts section, including
when the later vulnerability check fails.

The blocking check uses that job's same database, the release's signed VEX
statement, and the current repository's `.grype.yaml` exceptions. It fails for
remaining high or critical findings with an available fix. The unfiltered
report does not apply those exceptions or omit findings without fixes.

Releases with signed [wheel-native component catalogs](../reference/native-components.md)
also produce `rescan-native-TAG-ARCHITECTURE` artifacts, retained for 14 days.
These reports scan the delivered catalog with the same database, without
network access, VEX exclusions or severity filtering. They can expose bundled
C libraries missing from the image report. Older releases without a declared
catalog skip this step; a required catalog that is missing fails release
verification first.

The native scan generates missing CPE identifiers for advisory matching. These
are heuristic identities, not new facts about the binary. As
[Grype's matching guide](https://oss.anchore.com/docs/guides/vulnerability/ecosystems/)
explains, CPE matches can be wrong or incomplete. RPM-origin entries also need
the correct distribution advisory context, which this mixed catalog does not
provide. An entry with no match has not been established to be unaffected.

Native findings need separate advisory and reachability review. They do not
yet participate in the blocking image severity check, so a green workflow
does not mean the native report has no findings. A native scanner error does
fail the job. See [issue #18](https://github.com/stampbot/extra-codeowners/issues/18)
for the remaining native-library triage and distribution review.

A failed signature or inventory check means the image was **not scanned**.
An interrupted database download or scanner error also needs investigation;
neither is a clean vulnerability result. Check the failed step before deciding
what to fix. Failures use normal GitHub Actions notifications; the workflow
doesn't open issues or notify a separate incident channel.

For a confirmed finding, update the affected dependency or base-image digest
and release the correction. If it doesn't affect the app, review and document
that conclusion through the normal VEX process. Don't rewrite an old release's
VEX asset or move its image tag.

## Coverage limits

The daily job covers one release, not every retained image or every supported
release line. Manual runs can check other eligible tags. Historical images
without the required evidence need separate handling under
[issue #22](https://github.com/stampbot/extra-codeowners/issues/22).

The scanner container is pinned by digest and updated by Renovate. It runs
without GitHub credentials or a Docker socket. The checkout and downloaded
release evidence are mounted read-only. Its database cache is job-local;
the image inventory downloads the current database. The blocking check and
native catalog scan reuse it without updating it.
