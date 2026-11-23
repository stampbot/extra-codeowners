# Published images migrated and restored schema 0012: November 23, 2026

The published alpha.115 image migrated a restored alpha.114 backup.
Both images rejected the other release's schema. We restored the same
backup into a fresh database, and alpha.114 opened it with the test data
intact.

## Setup

We ran the test from 15:28 to 15:29 UTC on disposable PostgreSQL inside
an isolated container network. The database wasn't exposed on a host
port. The test verified TLS 1.3 with the application's `sslmode=require`
connection setting. It used the verified `amd64` published digests:

- [Alpha.114][old]: `c1afffeb5e59bed16dd8498f8785e6194d1bb9c3`.
- [Alpha.115][new]: `60668c354707e00f166460142ddf8327676b45bb`.

No shared database, webhook, or deployment was involved.

## What we verified

1. The alpha.114 CLI created and verified `0011_merge_group_work`. We added
   a single synthetic webhook-delivery row and took a PostgreSQL backup.
2. We verified the backup's checksum and restored it into a new database.
   Alpha.114 accepted it, and alpha.115 rejected the old schema.
3. The alpha.115 CLI migrated the restored copy to
   `0012_merge_candidate_recheck` and accepted it. The synthetic row was
   still present. Alpha.114 refused to open the migrated database.
4. We verified the same backup's checksum and restored it again, into
   another empty database. Alpha.114 accepted the restored schema. The
   synthetic row was present in both the original and the restored copy.

We removed the test database, network, and temporary backup after the
checks passed.

## Limits

This verifies the shipped migration and restore on a small fixture, not a
production backup or its recovery time. For a live migration, stop old
workers and [verify your own backup before applying the migration][upgrade].
Changing the image alone won't roll back a changed schema.

[old]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.114
[new]: https://github.com/stampbot/extra-codeowners/releases/tag/v0.1.0-alpha.115
[upgrade]: ../../how-to/upgrade.md#4-restore-and-verify-the-backup
