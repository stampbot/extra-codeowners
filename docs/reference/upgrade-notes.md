# Database upgrade notes

This page records the application and database compatibility contract planned
for each release. No supported release exists yet. When releases begin, read
every entry after the version you run, through the version you plan to deploy.
Any release that changes the Alembic head must update this ledger in the same
pull request.

## 0.1.0

**Status:** Unreleased.

The planned first release will establish this compatibility contract:

| Field | Contract |
| --- | --- |
| Database head | `0002_retry_dead_jobs` |
| Head change | Yes; this release is planned to establish the first supported head. |
| Supported source releases | None; this is planned as the first supported schema baseline. |
| Target application compatible before migration | No; startup requires the exact head. |
| In-place database downgrade | Not supported. |
| Rollback after head change | Restore the verified pre-migration backup. An older image rejects this head. |
| Backup required | Yes, before deployment and before every pre-release schema adoption. |

Revision `0001_initial_schema` creates the queue, webhook-delivery, authority-epoch, lease, audit, and compatibility tables. Revision `0002_retry_dead_jobs` reactivates any pre-release `evaluation_jobs` or `authority_jobs` row in the terminal `dead` state. It changes the row to `pending`, resets the attempt count and error, clears the lease, and makes the row immediately available. Before any reactivated work can publish a check, the worker fetches current GitHub and policy evidence.

No supported application release predates the planned `0.1.0`. Databases
created by pre-release builds have no Alembic revision, so the current `0.1.0`
source provides the one-time `--adopt-pre-alembic-schema` path. Adoption
succeeds only when the unversioned database matches immutable revision
`0001_initial_schema` exactly and the operator has verified a backup.

That comparison covers tables, columns, types, lengths, nullability, primary keys, named indexes and unique constraints, the compatibility marker, column defaults, owned sequences, identity and computed behavior, PostgreSQL timestamp time-zone mode, and index predicates and options. It also rejects unexpected tables, indexes, foreign keys, and check constraints. A partial, modified, or provenance-ambiguous schema needs a separately reviewed recovery plan.
