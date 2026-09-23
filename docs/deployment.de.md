# Deployment

Clawforge läuft als API, Worker, Event Backbone, Notifier, Frontend,
PostgreSQL, Correlation-, Incident-, Executor- und Backup-Services. MCP ist
hinter dem Profil `agent`, der Analyzer hinter `analysis` isoliert; Redis ist
unter `cache` optional und nicht für die Korrektheit erforderlich.

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
./scripts/init-secrets.sh
./scripts/validate-secrets.sh --bootstrap
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
3. `./scripts/init-secrets.sh` ausführen, optionale Provider-Credentials
   ergänzen und mit `./scripts/validate-secrets.sh --bootstrap` prüfen. Private Dateien
   werden nicht versioniert und erhalten Modus `0600`; eingecheckte Beispiele
   sind keine Runtime-Defaults. `init-secrets.sh` erzeugt auch
   `secrets/analyzer_ip_hmac_key`: Bei aktivierter IP-Anonymisierung
   (`CLAWFORGE_ANALYZER_ANONYMIZE_IPS`, Standard) wird damit aus einer rohen
   IP ein stabiles, nicht umkehrbares Pseudonym gebildet, bevor sie
   persistiert wird - statt des früheren festen Platzhalters, in dem jede IP
   zusammenfiel (das zerstörte Korrelation und konnte unabhängige Ereignisse
   fälschlich verschmelzen). Ohne diesen Schlüssel verweigern
   api/worker/correlation/incidents/executor das Persistieren bzw. Anzeigen
   einer IP, statt auf den unsicheren Platzhalter zurückzufallen.
4. `docker compose pull && docker compose up -d` ausführen (oder lokal bauen).
5. Die API vorübergehend mit `compose.bootstrap.yml` neu erzeugen, den
   einmaligen Admin-Bootstrap durchführen, die API danach wieder ausschließlich
   aus `compose.yml` erzeugen und `secrets/admin_bootstrap_token` löschen.
6. API mit `/health`, `/ready` und `/version` prüfen.
7. Für MCP zuerst `mcp_agent_api_token` durch ein ausgestelltes Read-only-
   Agent-API-Token ersetzen und dann
   `docker compose --profile agent up -d clawforge-mcp` starten. Anschließend
   MCP intern unter `http://clawforge-mcp:8090/health` prüfen.

   Der Streamable-HTTP-Transport akzeptiert standardmäßig nur `Host`-Header
   `localhost`/`127.0.0.1`/`::1` (Schutz vor DNS-Rebinding, keine
   Authentifizierung). Ein Client außerhalb des eigenen Netzwerk-Namespace von
   `clawforge-mcp` – der Normalfall, da MCP-Clients wie OpenClaw als eigener
   Prozess oder auf einem eigenen Host laufen – bekommt
   `403 Forbidden: Host header is not allowed`, bis seine anfragende Adresse in
   `CLAWFORGE_MCP_ALLOWED_HOSTS` eingetragen ist. Das erweitert nur die
   Host-Erlaubnisliste; `mcp_auth_token` bleibt die eigentliche Zugriffskontrolle
   und wird weiterhin bei jeder Anfrage verlangt.

   `backend` ist absichtlich `internal: true`, weshalb `docker compose` für
   einen Container darauf keinen Host-Port wirklich veröffentlichen kann (die
   Bindung wird übernommen, aber nie tatsächlich weitergeleitet). `clawforge-mcp`
   bekommt deshalb eine feste Adresse auf `backend`
   (`CLAWFORGE_MCP_BACKEND_IP`, Standard `10.77.77.90`). Ein Client auf
   demselben Docker-Host – der übliche Fall bei OpenClaw – erreicht ihn direkt
   über die Bridge unter `http://10.77.77.90:8090/mcp`; dazu passend
   `CLAWFORGE_MCP_ALLOWED_HOSTS=10.77.77.90:8090` setzen (bereits Standard in
   `.env.example`). `CLAWFORGE_BACKEND_SUBNET` nur ändern, wenn `10.77.77.0/24`
   mit einem anderen Docker-Netz auf dem Host kollidiert.

Der einmalige Dienst `clawforge-migrate` führt sqlx-Migrationen mit dem
Eigentümerkonto aus. Danach provisioniert `clawforge-db-roles` idempotent je
ein minimales Konto für API, Worker, Correlation, Incidents, Executor und
Backup. Erst anschließend starten die Laufzeitdienste; sie können keine DDL
ausführen und verweigern einen veralteten oder neueren Schema-Stand. `/ready`
meldet den angewendeten Migrationsstand. Für Updates das Volume behalten.

## Upgrade von v0.x

1. PostgreSQL-Backup erstellen und prüfen.
2. `CLAWFORGE_IMAGE_TAG=v1.0.0` setzen.
3. Images laden und Compose neu starten:

```sh
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > backup-before-v1.sql
docker compose pull
docker compose up -d
```

Migration und Rollen-Provisionierung müssen erfolgreich beendet sein. Danach
auf die Bereitschaft warten und Incidents, Audit, Providerstatus, Frontend,
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
docker compose --profile agent up -d clawforge-mcp
docker compose --profile sensors up -d clawforge-linux-sensor
```

`sensors` braucht zuerst einen registrierten Sensor mit hinterlegtem
Credential - siehe [sensors.md](sensors.md).

Die englische Referenz ist [deployment.md](deployment.md).
