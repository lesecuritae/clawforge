# Backup und Recovery

PostgreSQL ist die Source of Truth für Events, Incidents, Providerstatus,
Risk-/Trust-Historie, Audit, Workflows, Approvals und Execution-Metadaten.
Backups werden außerhalb des Repositorys gespeichert und geschützt.

## Regelmäßiges Backup

```sh
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  --format=custom --file=/tmp/clawforge.dump
docker compose cp postgres:/tmp/clawforge.dump ./backup/clawforge-$(date -u +%Y%m%dT%H%M%SZ).dump
```

Backup-Dateien enthalten sensible Betriebsdaten. Zugriff beschränken,
verschlüsseln und nach einer definierten Retention rotieren. Secret-Dateien
werden separat gesichert; Secretwerte gehören nicht in PostgreSQL-Dumps oder
Git.

## Restore

1. Zielumgebung stoppen und eine frische PostgreSQL-Datenbank bereitstellen.
2. Das geprüfte Dump einspielen:

```sh
docker compose cp ./backup/clawforge-<timestamp>.dump postgres:/tmp/restore.dump
docker compose exec -T postgres pg_restore -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" --clean --if-exists /tmp/restore.dump
```

3. `docker compose up -d` starten und `/ready` prüfen.
4. Migrationstand, Incidents, Audit, Providerstatus und MCP-Discovery prüfen.
5. Restore-Ergebnis und Zeitpunkt auditierbar dokumentieren.

`./scripts/test-backup-restore.sh` führt einen isolierten Dump-, Volume-
Entfernungs-, Restore- und Integritätstest aus. Vor Upgrades immer ein Backup
und einen Restore-Nachweis erstellen.

Die englische Referenz ist [backup.md](backup.md).
