# Recovery und Restore

Clawforge verwendet PostgreSQL als Source of Truth. Das Backup umfasst die
Datenbank und die deployment-relevante Konfiguration; Secrets werden separat
über Docker Secrets verwaltet und niemals in ein Git- oder Datenbankdump
geschrieben.

## Regelmäßiges Backup

Der Compose-Dienst `clawforge-backup` erstellt standardmäßig täglich ein
komprimiertes PostgreSQL-Dump. `CLAWFORGE_BACKUP_INTERVAL_SECONDS` und
`CLAWFORGE_BACKUP_RETENTION_DAYS` steuern Intervall und Rotation. Dumps werden
privat erzeugt, vor der atomaren Veröffentlichung validiert und im gemounteten
Backup-Volume abgelegt. Sie sollten zusätzlich verschlüsselt an einen
getrennten Speicher repliziert werden.

## Restore auf frischer Datenbank

1. Compose stoppen und eine leere PostgreSQL-Instanz bereitstellen.
2. Das gewünschte Dump mit `scripts/restore.sh` einspielen.
3. API starten. `PostgresStore::connect` prüft Downgrades und führt die
   sqlx-Migrationen idempotent aus.
4. `/ready` muss `current: true` melden und die erwartete Migration (aktuell
   16) ausweisen.
5. API, Worker, Event-/Correlation-Service, Notifier und MCP auf Healthchecks
   prüfen.
6. Einen repräsentativen Incident-, Event-, Provider- und Audit-Read prüfen.

Der reproduzierbare Test ist:

```text
./scripts/test-backup-restore.sh
```

Der Test verwendet eine isolierte Datenbank und hinterlässt keine
Produktionsdaten. Vor jedem Release wird zusätzlich `./scripts/test-postgres.sh`
für Migration, Neustart und Persistenz ausgeführt.

## Konfiguration und Secrets

`.env.example` und `secrets/*.example` dokumentieren nur Namen und Formate;
sie sind keine produktiven Compose-Defaults. `scripts/init-secrets.sh` erzeugt
die privaten Dateien, `scripts/validate-secrets.sh` prüft den Normalbetrieb und
`scripts/validate-secrets.sh --bootstrap` zusätzlich das Einmal-Secret.
Produktive Werte liegen außerhalb der Versionsverwaltung. Bei einer
Wiederherstellung werden sie aus dem Secret-Manager beziehungsweise dem
Deployment-System erneut injiziert. API-Token, Provider-Schlüssel,
MCP-Service-Token und SMTP/Webhook-Geheimnisse werden nicht aus Logs oder
Backups rekonstruiert.
