# ADR: Apply schema changes only through an explicit migrator

## Record

| Field | Value |
| --- | --- |
| Date | 2026-07-15 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Danny Sauer |
| Scope | How the database schema changes and how a running service checks it. It doesn't cover backup tooling or retention. |
| Related | [Why database migrations are explicit](../database-migrations.md), [upgrade procedure](../../how-to/upgrade.md) |
| Implementation | [PR #17](https://github.com/stampbot/extra-codeowners/pull/17), [issue #6](https://github.com/stampbot/extra-codeowners/issues/6) |

## Business driver

The database holds pending revocations, generations, leases, and audit
evidence that the authorization path depends on. A database with the wrong
schema can still answer a health query while missing state the service needs,
and the first symptom could be a check that succeeds when it shouldn't.

## Constraints

- Webhook replicas shouldn't need schema-changing database privileges.
- Replicas from two application versions must not race to change the schema
  during a rollout.
- A failed migration must be visible before traffic moves.

## Decision

**Y statement:** We will change the schema only through an explicit Alembic
migration command, run as its own Helm Job, and have every service process
refuse to start unless the database matches its one expected head and release
contract, because a silently wrong schema can turn into a wrong authorization
result, so operators see exactly one bounded change before traffic moves.

The decision has these boundaries:

- Normal startup never creates or alters tables.
- Each application artifact accepts exactly one Alembic head. Every head change
  is a restore boundary, even for an additive change.
- Alembic downgrades aren't an operator interface. Rollback across a head
  change means restoring the backup taken before the migration.
- The migration Job gets its own Secret, environment, and ServiceAccount, and
  doesn't inherit the runtime App credentials.

## Consequences

- Every schema-changing pull request needs a revision, fresh-install and
  upgrade tests, and an entry in the
  [database upgrade notes](../../reference/upgrade-notes.md).
- Rolling back an image after a head change takes a database restore, not just
  an older image.
- A deployment can give the runtime role no schema privileges at all.

## Alternatives considered

### Keep the current approach

Before this decision, the service created tables from ORM metadata at
startup. That works for a first install, but it can't change an existing
schema safely, needs schema privileges in every replica, and lets replicas from
different versions race during a rollout.

### Migrate automatically at startup

Run Alembic from each process before it serves traffic. This removes a
deployment step, but it keeps schema privileges in every replica, invites
concurrent migrations during rollouts, and hides a half-finished migration
behind repeated pod restarts.
