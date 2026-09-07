# Backup and restore

The `clawforge-backup` Compose service creates a validated PostgreSQL custom
format dump immediately at startup and every 24 hours thereafter. It keeps
`CLAWFORGE_BACKUP_RETENTION_DAYS` days in the `clawforge-backups` volume.

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
