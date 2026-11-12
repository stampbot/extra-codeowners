# ADR: Scope repository access grants to their repository

## Record

| Field | Value |
| --- | --- |
| Date | 2026-11-12 |
| Status | Accepted |
| Owner | Maintainers |
| Author | Extra CODEOWNERS contributors |
| Scope | Routing `team.added_to_repository`; not approval evaluation or other team actions. |
| Implementation | [Issue #300](https://github.com/stampbot/extra-codeowners/issues/300) |
| Revisit when | GitHub changes the event contract or another repository-scoped action is reviewed. |

## Business driver

The parser treated every `team` action as installation-wide. One repository
access grant could therefore create authority work for every accessible
repository. On a large installation, that spends quota and delays unrelated
work before evaluation begins.

## Constraints

An authentic event can still have incomplete or conflicting metadata. Choosing
the wrong repository would leave the affected checks outside the retry queue.
The configured organization-policy repository remains a shared input.

## Decision

**Y statement:** We will route an unambiguous repository access grant to its
repository, because that event changes access there, while keeping the existing
installation-wide fallback whenever the signed scope cannot be established.

[GitHub's contract](https://docs.github.com/en/webhooks/webhook-events-and-payloads#team)
describes `team.added_to_repository` as a repository access grant and includes
an optional repository object. Only this action receives the optimization.

The repository, organization and team must have positive integer identities,
not booleans. The repository owner must match the organization by ID and login;
its canonical full name must match that owner and repository name. Optional
installation-account metadata must agree too. The configured shared-policy
repository, missing fields and conflicting identities retain global work.
Other team actions, membership events and organization events remain global,
even when they contain a repository object.

The result is still durable authority work, not approval evidence. Workers
authenticate current installation membership, enforce publication fences and
evaluate current inputs through the existing path.

New authority-delivery rows also record the installation and routed repository
in the existing nullable metadata columns. This retains no raw payload. A null
routed repository means global work; legacy rows may also lack the installation
ID, so those rows cannot establish the earlier routing context.

## Consequences

A validated ordinary grant no longer queues unrelated repositories. Ambiguous
events can still be expensive. Previously queued global work is not cancelled
or narrowed. There is no schema, configuration or permission change. Rollback
restores broad routing and can still read the retained metadata.

## Alternatives considered

### Ignore access grants because they do not remove permission

A grant can make an owner eligible and change a failed check's result. Keep
reevaluation for the affected repository.

### Narrow every team action when a repository is present

Other actions can change team identity or membership across repositories. Keep
their existing scope until each contract is reviewed.
