# Database upgrade notes

This page is the versioned application/schema compatibility ledger. Read every
entry between the running and target versions before migration. A release that
changes database schema must update this page in the same pull request.

## 0.1.0

| Field | Contract |
| --- | --- |
| Database head | `0002_retry_dead_jobs` |
| Supported source releases | None; this is the first supported schema baseline |
| Previous application compatible after migration | Not applicable |
| Target application compatible before migration | No; startup requires the exact head |
| In-place database downgrade | Not supported |
| Backup required | Yes, for every pre-release schema adoption and before deployment |

The baseline creates the queue, webhook-delivery, authority epoch, lease, audit,
and compatibility tables. The second revision changes any pre-release
`evaluation_jobs` or `authority_jobs` row in terminal `dead` state back to
`pending`, resets its attempts and error, and clears its lease. Current GitHub
and policy evidence is fetched before that work can publish a check.

There is no supported application release before `0.1.0`. A database produced
by a pre-release build has no Alembic revision. The explicit
`--adopt-pre-alembic-schema` path accepts only the exact documented table shape
and compatibility marker after the operator has verified a backup. Modified,
partial, or unversioned schemas require a separately reviewed recovery plan.
