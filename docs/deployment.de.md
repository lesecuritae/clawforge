# Deployment

Clawforge läuft als API, Worker, Event Backbone, Notifier, Frontend,
PostgreSQL, MCP, Correlation-, Incident-, Executor- und Backup-Services. Der
Analyzer ist hinter dem Profil `analysis` isoliert; Redis ist unter `cache`
optional und nicht für die Korrektheit erforderlich.

## Veröffentliche Release-Images

Die Produktions-Registry ist:

```text
ghcr.io/lesecuritae/clawforge-<service>
```

Veröffentlicht werden `api`, `mcp`, `frontend`, `correlation`, `incidents`,
`worker` und `executor`. Das Release-Tag wird über
`CLAWFORGE_IMAGE_TAG=v1.0.0` oder `1.0.0` gewählt.

```sh
cp .env.example .env
# unveränderliches Release-Tag verwenden
CLAWFORGE_IMAGE_TAG=v1.0.0
docker compose pull
docker compose up -d
```

Für einen lokalen Build: `docker compose build && docker compose up -d`. Die
Images enthalten OCI-Titel, Beschreibung, Version, Revision, Quelle und
Apache-2.0-Lizenz. GitHub Actions veröffentlicht `linux/amd64` und
`linux/arm64`, erzeugt SBOM/Provenance und führt Trivy aus.

## Frische Installation

1. Docker Engine und Compose-Plugin installieren.
2. `.env.example` nach `.env` kopieren und Image-Tag und Ports konfigurieren.
3. Private Secret-Dateien aus `secrets/*.example` anlegen; niemals committen.
4. `docker compose pull && docker compose up -d` ausführen (oder lokal bauen).
5. API mit `/health`, `/ready` und `/version` prüfen.
6. MCP intern unter `http://clawforge-mcp:8090/health` prüfen.

Die API führt sqlx-Migrationen vor dem Listening aus. `/ready` prüft PostgreSQL
und meldet den angewendeten Migrationsstand. Für Updates Volume behalten.

## Upgrade von v0.x

1. PostgreSQL-Backup erstellen und prüfen.
2. `CLAWFORGE_IMAGE_TAG=v1.0.0` setzen.
3. Images laden und Compose neu starten:

```sh
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > backup-before-v1.sql
docker compose pull
docker compose up -d
```

Auf die Bereitschaft warten und Incidents, Audit, Providerstatus, Frontend,
MCP-Health und MCP-Discovery prüfen. PostgreSQL-Volume nicht löschen. Für ein
Rollback die dokumentierte Restore-Prozedur verwenden.

## Backups und Profile

Vor Updates den Ablauf in [backup.de.md](backup.de.md) bzw. [backup.md](backup.md)
verwenden. Der Test `scripts/test-backup-restore.sh` prüft Dump, Volume-Entfernung,
Restore und Integrität in einem echten PostgreSQL-Container.

Optionale Dienste:

```sh
docker compose --profile analysis up -d
docker compose --profile cache up -d
docker compose --profile observability up -d
```

Die englische Referenz ist [deployment.md](deployment.md).
