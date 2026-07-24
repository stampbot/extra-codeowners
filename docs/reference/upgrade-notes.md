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
| Database head | `0003_shared_head_epochs` |
| Head change | Yes; this release is planned to establish the first supported head. |
| Supported source releases | None; this is planned as the first supported schema baseline. |
| Target application compatible before migration | No; startup requires the exact head. |
| Required process state | Stop webhook ingress and every older worker before applying `0003_shared_head_epochs`. Suspend GitOps reconciliation and remove the HPA before scaling a Kubernetes Deployment to zero. |
| In-place database downgrade | Not supported. |
| Rollback after head change | Restore the verified pre-migration backup. An older image rejects this head. |
| Backup required | Yes, before deployment and before every pre-release schema adoption. |

Revision `0001_initial_schema` creates the queue, webhook-delivery,
authority-epoch, lease, audit, and compatibility tables. Revision
`0002_retry_dead_jobs` reactivates any pre-release `evaluation_jobs` or
`authority_jobs` row in the terminal `dead` state. It changes the row to
`pending`, resets the attempt count and error, clears the lease, and makes the
row immediately available. Before any reactivated work can publish a check,
the worker fetches current GitHub and policy evidence.

Revision `0003_shared_head_epochs` adds a durable generation for each
installation, repository, and head commit. The same row records the newest
generation whose exact-head invalidation finished, plus retry and lease state.
An evaluation may publish only when its captured generation is current and
invalidated.

The revision also records the generation on each evaluation job and stores the
pull-request identity and exact generation token with each direct webhook
delivery. Carried jobs with a known head are grouped by installation,
repository, and head. Each group receives generation `1` with invalidation
pending, and its jobs receive token `1`.

Carried jobs without a head receive token `0`. Their first authoritative
pull-request read advances or creates a pending exact-head generation and binds
the job to it in the same transaction. A superseded or lost claim rolls back
the tentative generation. Existing delivery rows have no token and keep their
pre-migration deduplication semantics. The revision changes the application
compatibility marker from `1` to `2`.

An already-running process does not revalidate the Alembic head before every
claim. Stop every older ingress, worker, and reconciler before this revision
runs. Start only the target artifact after `database check` reports
`0003_shared_head_epochs` and validates that artifact's
`required-release-contract`. Readiness removes an old process from webhook
traffic after migration, but it does not cancel work that process already
claimed. For Kubernetes, a zero-replica Deployment is not proof of a drain
while an HPA or GitOps controller can recreate pods. Keep autoscaling disabled
for the migration update, wait out both worker and reconciler leases, and
verify the target pod and database contract. Apply the reviewed final
autoscaling state in a separate update before resuming GitOps; an HPA should
exist only when those values enable it.

No supported application release predates the planned `0.1.0`. Databases
created by pre-release builds have no Alembic revision, so the current `0.1.0`
source provides the one-time `--adopt-pre-alembic-schema` path. Adoption
succeeds only when the unversioned database matches immutable revision
`0001_initial_schema` exactly and the operator has verified a backup.

That comparison covers tables, columns, types, lengths, nullability, primary
keys, named indexes and unique constraints, the compatibility marker, column
defaults, owned sequences, identity and computed behavior, PostgreSQL
timestamp time-zone mode, and index predicates and options. It also rejects
unexpected tables, indexes, foreign keys, and check constraints. A partial,
modified, or provenance-ambiguous schema needs a separately reviewed recovery
plan.
