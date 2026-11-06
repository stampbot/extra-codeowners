# Validation evidence

These dated receipts record what a particular run established. They are not
the current architecture, a rollout plan or proof that every release gate
passed. The [project status](../../reference/project-status.md) describes
support and remaining work; [live validation](../live-validation.md) retains
the older results and links newer receipts.

## Receipts

- [November 2, 2026: reconciliation and alpha.67](2026-11-02-reconciliation-and-alpha67.md)
- [November 5, 2026: trace-size investigation](2026-11-05-trace-size-investigation.md)
- [November 5, 2026: Debian source outage and reuse](2026-11-05-debian-source-reuse.md)
- [November 5, 2026: alpha.69 release and approval validation](2026-11-05-alpha69-release-and-approval.md)
- [November 5, 2026: alpha.69 successful reconciliation](2026-11-05-alpha69-successful-reconciliation.md)
- [November 6, 2026: discovery validator expiry](2026-11-06-discovery-retention.md)
- [November 6, 2026: reconciliation and alpha.73 rollout](2026-11-06-reconciliation-and-alpha73.md)
- [November 6, 2026: missed policy webhook recovery](2026-11-06-missed-policy-webhook.md)

## Add a receipt

Name each file `YYYY-MM-DD-short-claim.md`, using the observation date. Include
the tested version and source revision, environment, UTC window, method,
results, source evidence, cleanup and limits. Name a requirement ID only when
the receipt actually tests that obligation; a timing observation doesn't prove
an entire authorization invariant.

Once published, a receipt stays unchanged. Add a dated follow-up for a new
run or correction, and update this index or the living page that cites it.
Older evidence remains available. The same rule applies to historical results
already published in the live-validation page.

Inspect evidence before publishing. Keep raw private traces, payloads,
credentials, repository metadata and infrastructure identifiers in the
maintainer's access-controlled records. A public receipt should contain the
sanitized observations needed to assess its claim, not the raw capture.
