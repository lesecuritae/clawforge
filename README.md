# Clawforge

**Self-hosted Operations Intelligence Platform**

Clawforge verbindet Infrastruktur, Events, Sicherheitsinformationen,
Betriebsdaten und kontrollierte Automatisierung in einer gemeinsamen
Operations-Schicht. Menschen und LLM-Agenten erhalten den gleichen
nachvollziehbaren Kontext über die versionierte Agent API und den read-only
MCP-Server.

Clawforge ist kein autonomer KI-Administrator. Es sammelt und bewertet
Informationen, erklärt Zusammenhänge und stellt kontrollierte Schnittstellen
für Menschen und Agenten bereit. Externe Aktionen sind allowlisted,
policy-geprüft, approvalgebunden und im aktuellen Release weiterhin Dry-Run.

[🇩🇪 Deutsch](README.de.md) · [🇬🇧 English](README.en.md)

![Clawforge Security Platform](assets/branding/rebranding-announcement.png)

## Warum Clawforge?

Moderne Systeme bestehen aus Containern, Servern, Cloud-Diensten,
Repositories, Monitoring, Security-Feeds und Automatisierungen. Informationen
entstehen an vielen Stellen, aber ihre Zusammenhänge fehlen oft. Clawforge
schafft eine zentrale Operations-Intelligence-Ebene: Ereignisse werden
gesammelt, korreliert, als Incidents nachvollziehbar gemacht und mit Risiko,
Trust, Provider-Zustand und Empfehlungen verbunden.

## Gesamtarchitektur

```text
Infrastruktur
      |
Connector Layer
      |
Provider Intelligence
      |
Event Backbone
      |
Correlation Engine
      |
Incident Intelligence
      |
Risk / Trust / Policy Engine
      |
Decision Intelligence
      |
Workflow Governance
      |
Controlled Operations
      |
Agent API v1
      |
MCP Server
      |
LLM Agent
```

- **Connector Layer** verbindet Docker, GitHub und Proxmox mit sicheren,
  normalisierten Projektionen.
- **Provider Intelligence** synchronisiert Threat-, ASN-, BGP- und RPKI-Daten.
- **Event Backbone** speichert strukturierte Ereignisse und verteilt sie an
  Correlation, Incident, Alert und Audit Consumer.
- **Correlation und Incident Intelligence** erkennen zusammengehörige Events,
  bewahren Beziehungen und führen einen auditierten Incident-Lifecycle.
- **Risk, Trust und Policy** bewerten Signale getrennt. Kein einzelner Feed,
  ASN, RPKI-Status oder Connector darf allein blockieren.
- **Decision und Workflow Governance** erzeugen erklärbare Empfehlungen und
  verwalten Freigaben.
- **Controlled Operations** kennt nur registrierte Actions. Der Executor ist
  in v1.0 standardmäßig Dry-Run.
- **Agent API und MCP** liefern redigierten read-only Kontext an OpenClaw und
  andere Agenten.

Die ausführliche Beschreibung steht in [docs/architecture.md](docs/architecture.md).

## Feature-Matrix

| Bereich | Funktionen |
| --- | --- |
| Security Intelligence | Events, Correlation, Incidents, Alerts, Risk- und Trust-Bewertung |
| Operations Intelligence | Context API, Operations Summary, Briefings, Decisions, Historie |
| Automation Governance | Workflows, Actions, Approvals, Execution Queue, Audit |
| Integration | MCP, OpenAPI, Docker, GitHub, Proxmox, OpenClaw |
| Platform | Rust, PostgreSQL/sqlx, Migrationen, Backup/Restore, Prometheus, Dashboard |

## LLM- und MCP-Integration

LLMs erhalten keine direkte Infrastruktur- oder Datenbankkenntnis. Der MCP-
Server ruft ausschließlich die Agent API v1 auf und liefert begrenzte,
redigierte Antworten. Scopes, Timeouts, Response-Limits und Auditierung gelten
für jeden Aufruf.

```text
LLM -> MCP -> Agent Context API -> Events / Incidents / Risiko / Provider
     -> formulierte Erklärung oder Empfehlung
```

Der Ablauf einer später freigegebenen kontrollierten Aktion ist:

```text
LLM -> Decision -> Policy -> Approval -> Execution Queue -> Worker -> Audit
```

MCP bleibt read-only: keine direkten Datenbankzugriffe, keine versteckten
Aktionen und keine Schreibwerkzeuge. Siehe
[docs/llm-integration.md](docs/llm-integration.md) und
[docs/openclaw-integration.md](docs/openclaw-integration.md).

## Schnellstart

```bash
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
curl http://127.0.0.1:8080/version
```

Die Standardinstallation startet API, Worker, PostgreSQL, Frontend,
Event-/Correlation-/Incident-Dienste, MCP, Notifier, Executor und Backup.
Optionale Analyzer-, Redis- und Observability-Profile sind in
[docs/deployment.md](docs/deployment.md) beschrieben. Provider bleiben ohne
explizite Aktivierung und Secrets deaktiviert.

## Sicherheit

- Least Privilege über Rollen und Agent-Scopes
- Audit First für Zugriffe, Statusänderungen, Freigaben und Executions
- keine automatischen Block- oder Remediation-Aktionen aus einem einzelnen Signal
- Human Approval für kritische Abläufe
- Secret Separation über Docker Secrets oder externe Referenzen
- keine Secret-Werte, Rohfeeds oder Rohpayloads in MCP-Antworten
- nicht-root Container, Health Checks, Migration- und Backup-Prüfungen

Das Modell ist in [docs/security-model.md](docs/security-model.md) und der
Security-Prüfung in [docs/security-audit.md](docs/security-audit.md)
dokumentiert.

## Betrieb und Dokumentation

- [Deployment und Updates](docs/deployment.md)
- [Backup und Recovery](docs/backup.md)
- [Provider](docs/providers.md)
- [Agent API v1](docs/agent-api.md)
- [MCP Server](docs/mcp-server.md)
- [Connectoren](docs/connectors.md)
- [Incident Intelligence v0.12](docs/incident-intelligence-v0.12.md)
- [Secret Provider](docs/secret-providers.md)
- [v1.0-Finalpositionierung](docs/final-release.md)

## Entwicklung und Validierung

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm --prefix frontend test
npm --prefix frontend run build
docker compose config
docker compose build
```

Die PostgreSQL-Migrations- und Backup/Restore-Tests liegen unter `scripts/`.

## Lizenz

Apache License 2.0. Clawforge ist ein eigenständiges Rust-Projekt und enthält
keine KorbKlar-, Supermarkt- oder OpenClaw-Runtime-Logik.
