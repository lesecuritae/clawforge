# Backup and restore

The `clawforge-backup` Compose service creates a validated PostgreSQL custom
format dump immediately at startup and every 24 hours thereafter. It keeps
`CLAWFORGE_BACKUP_RETENTION_DAYS` days in the `clawforge-backups` volume. The
backup directory uses mode `0700`; each dump is created privately, validated,
and only then atomically published with mode `0600`. A failed or invalid dump
is removed instead of being exposed as a usable backup.

For an operator-managed backup, run:

```sh
./scripts/backup.sh ./backups
```

Restore a validated dump during a maintenance window with:

```sh
docker compose stop clawforge-api clawforge-worker
./scripts/restore.sh ./backups/clawforge-<timestamp>.dump
docker compose up -d
```

The restore script recreates the database and uses `pg_restore --exit-on-error`.
Keep a copy outside the host and periodically perform a separate restore test.

The complete fresh-database procedure, configuration backup and secret
handling rules are documented in [recovery.md](recovery.md). The backup service
does not copy Docker secrets or token values.

## Verified full restore (2026-10-26)

The dump `clawforge-20261025T005531Z` (custom format, about 25.5 GB) was restored completely, without leaving out any table, into a throw-away PostgreSQL 16 on an internal Docker network with no route to production (dump volume mounted read-only).
Not production evidence of recovery time under load; a drill on one host.

| Item | Result |
| --- | --- |
| `pg_restore -j 2 --exit-on-error` | exit 0 after 27,328 s (7.6 h), empty error output |
| Restored size | 161 GB (production 188 GB: bloat and later growth) |
| Ledger / public tables / indexes / constraints / functions / triggers | 70/66, 87, 230, 388, 20, 7 - each equal to production |
| Invalid indexes / unvalidated constraints | 0 / 0 |
| Rows `incident_relations`, `event_relationships` | 260,607,230 and 259,266,178 (production planner estimates 248 M and 256.6 M, which include rows added after the dump) |
| Rows at or before the dump time | `events` 1,844,098, `audit_events` 1,365,169, `risk_history` 1,241,368, `security_events` 210,190, `incident_candidate_events` 1,341,052 - exactly equal to production |
| Orphans in `incident_relations` (no incident) | 0 |
| `amcheck` `bt_index_check` on both big primary keys | no error |
| Deployed migrator (1.2.9) against the restored database | "current at version 70" |

Limits: exact counts of the two big tables could only be compared with estimates (production changed after the dump); no application traffic was replayed; a restore on the production host's own disk does not fit (188 GB database, about 90 GB free), so the drill used a dedicated ext4 image file on an external disk.

Practical notes from the drill: the external disk is NTFS through FUSE, which ignores `chmod`, so an image file there is readable by every local user - the data copy was deleted after verification. Mount such an image with `noinit_itable` (the FUSE backing does not support `WRITE_ZEROES`; the kernel logged 1,540 harmless "operation not supported" lines during lazy inode-table initialisation, none after the remount, and a read-only `e2fsck -fn` of the unmounted image was clean). A host reboot kills a running restore; it is not resumable, run it as a transient unit and expect to restart it.
