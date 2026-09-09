# Clawforge Production Betrieb

Clawforge ist eine Rust-/Tokio-Plattform mit Axum API, PostgreSQL, Worker,
Event Backbone, Correlation-/Incident-Services, optionalem Analyzer,
Notifier, MCP-Adapter und React-Konsole. PostgreSQL ist die Source of Truth;
MCP greift ausschließlich über die Agent API v1 zu.

## Produktionsstart

1. `.env.example` kopieren und alle Secret-Dateien außerhalb von Git durch
   hochentropische Werte ersetzen.
2. `docker compose config` prüfen.
3. `docker compose up -d --build` ausführen.
4. `/health` und `/ready` prüfen. `/ready` muss PostgreSQL verbinden und alle
   sqlx-Migrationen als aktuell melden.
5. Admin Bootstrap einmalig durchführen und den Bootstrap-Token danach
   rotieren beziehungsweise entfernen.

Alle Container verwenden einen unprivilegierten Benutzer, Read-only-
Dateisysteme, `cap_drop: ALL`, `no-new-privileges`, begrenzte PID-/tmpfs-
Ressourcen und Compose-Healthchecks. Die interne Backend-Netzwerkzone ist
   nicht von außen erreichbar.

## OpenClaw und MCP

Der interne MCP-Endpunkt ist `http://clawforge-mcp:8090/mcp`. Der MCP-Token
für OpenClaw und das ausgehende Agent-API-Token sind getrennte Docker
Secrets. Der Standardzugang ist minimal read-only:

```text
agent:operations:read
agent:operations:briefing
agent:operations:recommend
agent:context:read
agent:decision:read
agent:incident:read
agent:provider:read
agent:security:read
agent:knowledge:read
agent:workflow:read
```

Für Netzwerk-, Trust-, Event- oder Systemtools müssen die entsprechenden
Scopes zusätzlich explizit vergeben werden. MCP kennt keine Schreibtools,
keine direkte Datenbankverbindung und keine automatische Remediation.
Timeouts und Antwortgrößen sind begrenzt; Fehler werden ohne Upstream-
Secrets oder Rohpayloads zurückgegeben. Die vollständige Abnahme steht in
`docs/openclaw-integration.md` und `docs/mcp-server.md`.

## Betrieb und Beobachtung

- API: `/health`, `/ready`, `/metrics`
- MCP: `/health`, `/metrics` (Upstream-Aufrufe und Fehler)
- PostgreSQL: Compose-Healthcheck und Migrationstatus
- Worker/Event/Correlation/Incident/Notifier: Compose-Healthchecks und
  Runtime-/Prometheus-Metriken

Rate Limits, Tokenablauf, Rotation, Widerruf und Auditierung bleiben aktiv.
Agent- und MCP-Zugriffe werden redigiert auditiert; Credentials erscheinen
nicht in Logs, Reports oder Datenbankfeldern.

## Backup und Restore

Der `clawforge-backup`-Dienst erzeugt täglich validierte PostgreSQL-Dumps und
rotiert sie. Konfigurationsdateien werden getrennt gesichert, Secrets nie in
Git oder in Dumps. Für einen Restore auf einer frischen Datenbank:

```text
./scripts/test-backup-restore.sh
./scripts/test-postgres.sh
```

Danach `/ready`, Migrationstand, API, MCP und die relevanten Read-only-
Endpunkte prüfen. Details stehen in `docs/backup.md` und `docs/recovery.md`.

## Release-Prüfung

```text
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
(cd frontend && npm test && npm run build)
docker compose config
docker compose build
```

Vor dem Push zusätzlich Compose-Neustart, Healthchecks, OpenAPI-Parsing,
MCP-Discovery/Tool-Listing und ein gültiges sowie ein abgewiesenes Token
prüfen.

## Optional Prometheus und Grafana

Für die zentrale Betriebsansicht kann das Observability-Profil gestartet
werden:

```sh
docker compose --profile observability up -d prometheus grafana
```

Die Konfiguration und das Dashboard liegen unter `monitoring/`. Die Dienste
sind standardmäßig nur über Loopback-Ports erreichbar; PostgreSQL bleibt die
Source of Truth und wird nicht durch Grafana oder Prometheus verändert.

## CI/CD und Abhängigkeitsscans

`.github/workflows/ci.yml` führt bei Pushes und Pull Requests Formatprüfung,
Workspace-Tests, Clippy, Frontend-Test/Build, npm Audit, Trivy-Dateiscan,
Compose-Validierung und Docker-Builds aus. `cargo audit` meldet derzeit nur
RUSTSEC-2023-0071 für die optionale, im PostgreSQL-Produktionsbuild nicht
kompilierte `sqlx-mysql`/`rsa`-Kette; RustSec weist dafür weiterhin keine
behobene Version aus. Dieser Restbefund ist in den Release-Unterlagen
festgehalten und wird bei jedem Release erneut geprüft.
