# Backup und Recovery

PostgreSQL ist die Source of Truth für Events, Incidents, Providerstatus,
Risk-/Trust-Historie, Audit, Workflows, Approvals und Execution-Metadaten.
Backups werden außerhalb des Repositorys gespeichert und geschützt.

## Regelmäßiges Backup

```sh
./scripts/backup.sh ./backups
```

Das Skript verwendet Verzeichnismodus `0700` und Dateimodus `0600`, prüft das
Dump mit `pg_restore --list` und veröffentlicht es erst danach atomar. Ein
fehlgeschlagenes oder ungültiges temporäres Dump wird entfernt. Backup-Dateien
enthalten sensible Betriebsdaten. Zusätzlich verschlüsseln und nach einer
definierten Retention rotieren. Secret-Dateien werden separat gesichert;
Secretwerte gehören nicht in PostgreSQL-Dumps oder Git.

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
