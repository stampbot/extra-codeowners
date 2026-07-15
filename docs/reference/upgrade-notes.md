# Database upgrade notes

This page is the versioned application/schema restore ledger. Read every entry
between the running and target versions before migration. A release that
changes the Alembic head must update this page in the same pull request.

## 0.1.0

| Field | Contract |
| --- | --- |
| Database head | `0002_retry_dead_jobs` |
| Head change | Yes; establishes the first supported head |
| Supported source releases | None; this is the first supported schema baseline |
| Target application compatible before migration | No; startup requires the exact head |
| In-place database downgrade | Not supported |
| Rollback after head change | Restore the verified pre-migration backup; an old image rejects this head |
| Backup required | Yes, before deployment and before every pre-release schema adoption |

The baseline creates the queue, webhook-delivery, authority epoch, lease, audit,
and compatibility tables. The second revision changes any pre-release
`evaluation_jobs` or `authority_jobs` row in terminal `dead` state back to
`pending`, resets its attempts and error, and clears its lease. Current GitHub
and policy evidence is fetched before that work can publish a check.

There is no supported application release before `0.1.0`. A database produced
by a pre-release build has no Alembic revision. The explicit
`--adopt-pre-alembic-schema` path is available only in the 0.1.0 artifact. It
accepts only the immutable 0001 table, column, index, constraint, and
compatibility-marker contract after the operator has verified a backup. Column
defaults, owned sequences, identity/computed behavior, PostgreSQL timestamp
time-zone mode, and index predicates/options are part of that contract.
Modified, partial, provenance-ambiguous, or other unversioned schemas require a
separately reviewed recovery plan.
