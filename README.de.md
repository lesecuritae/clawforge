# Clawforge

**Selbsthostbare Operations-Intelligence-Plattform**

Clawforge verbindet Infrastruktur, Ereignisse, Sicherheitsinformationen,
Betriebsdaten und kontrollierte Automatisierung in einer nachvollziehbaren
Operations-Schicht. Menschen und LLM-Agenten erhalten denselben bereinigten
Kontext über die versionierte Agent API und den schreibgeschützten MCP-Server.

Clawforge ist kein autonomer KI-Administrator. Die Plattform sammelt und
bewertet Informationen, erklärt Zusammenhänge und stellt kontrollierte
Schnittstellen für Menschen und Agenten bereit. Externe Aktionen sind
allowlisted, durch Policies geprüft, freigabepflichtig und auditiert; in v1.0.0
läuft der Executor standardmäßig nur im Dry-Run.

[English](README.md) · [Deutsch](README.de.md)

![Clawforge Operations Intelligence](assets/branding/rebranding-announcement.png)

## Warum Clawforge?

Moderne Umgebungen verbinden Container, Server, Cloud-Dienste, Repositories,
Monitoring, Security-Feeds und Automatisierungen. Informationen entstehen an
vielen Stellen, aber die Beziehungen zwischen den Signalen bleiben schwer
überschaubar. Clawforge bildet eine gemeinsame Operations-Intelligence-Ebene:
Ereignisse werden gesammelt, korreliert, als nachvollziehbare Incidents
bewahrt und mit Risiko, Trust, Provider-Zustand und Empfehlungen verbunden.

## Architektur

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

- **Connectoren** lesen sichere Projektionen aus Docker, GitHub und Proxmox.
- **Provider Intelligence** normalisiert Threat-, ASN-, BGP- und RPKI-Daten.
- **Event Backbone** speichert strukturierte Ereignisse für Correlation,
  Incidents, Alerts und Audit-Consumer.
- **Correlation und Incident Intelligence** bewahren Beziehungen und einen
  auditierten Incident-Lifecycle.
- **Risk, Trust und Policy** bewerten Signale getrennt. Ein einzelner Feed,
  ASN-, RPKI- oder Connector-Hinweis kann allein nicht blockieren.
- **Decision und Workflow Governance** erzeugen erklärbare Empfehlungen und
  verwalten Freigaben.
- **Controlled Operations** kennt nur registrierte Actions. Der Executor ist
  in v1.0 ein Dry-Run und verändert keine externen Systeme.
- **Agent API und MCP** liefern begrenzten, bereinigten Read-only-Kontext an
  OpenClaw und andere Agenten.

Die ausführliche Architektur steht in
[docs/architecture.de.md](docs/architecture.de.md); die englische Referenz ist
[docs/architecture.md](docs/architecture.md).

## Funktionsmatrix

| Bereich | Funktionen |
| --- | --- |
| Security Intelligence | Events, Correlation, Incidents, Alerts, Risiko- und Trust-Bewertung |
| Operations Intelligence | Context API, Operations Summary, Briefings, Decisions, Historie |
| Automation Governance | Workflows, Actions, Approvals, Execution Queue, Audit |
| Integration | MCP, OpenAPI, Docker, GitHub, Proxmox, OpenClaw |
| Plattform | Rust, PostgreSQL/sqlx, Migrationen, Backup/Restore, Prometheus, Dashboard |

Clawforge verwendet ein erweiterbares Connector Framework und ist kein
technologiespezifischer Administrator. Connectoren liefern normalisierten
Zustand, Health und Capabilities für Containerplattformen, Infrastruktur,
Virtualisierung, Repositories, Cloud-Dienste, Monitoring und externe
Datenquellen. Docker, GitHub und Proxmox sind erste Beispiele.

## LLM- und MCP-Integration

LLMs erhalten keinen direkten Infrastruktur- oder Datenbankzugriff. MCP ruft
nur die Agent API v1 auf und liefert begrenzte, bereinigte Antworten. Scopes,
Timeouts, Antwortlimits und Audit-Einträge gelten für jeden Aufruf.

```text
LLM -> MCP -> Agent Context API -> Events / Incidents / Risiko / Providerstatus
     -> Erklärung oder Empfehlung
```

Eine kontrollierte Aktion folgt diesem Pfad:

```text
LLM -> Decision -> Policy -> Approval -> Execution Queue -> Worker -> Audit
```

MCP bleibt read-only: kein direkter Datenbankzugriff, keine versteckten
Aktionen und keine Schreibwerkzeuge. Siehe
[docs/llm-integration.de.md](docs/llm-integration.de.md) und die englische
Referenz [docs/llm-integration.md](docs/llm-integration.md).

## Installation mit Docker

Voraussetzungen: Docker Engine und das Docker-Compose-Plugin.

```bash
git clone https://github.com/lesecuritae/clawforge.git
cd clawforge
cp .env.example .env
# private Secret-Dateien aus secrets/*.example anlegen
docker compose pull
docker compose up -d
curl http://127.0.0.1:8080/ready
```

Für einen lokalen Build: `docker compose up -d --build`. Veröffentlicht werden
API, MCP, Frontend, Correlation, Incidents, Worker und Executor unter
`ghcr.io/lesecuritae/clawforge-<service>:1.0.0`. Details zu Updates, Backups
und Health Checks stehen in [docs/deployment.de.md](docs/deployment.de.md) und
[docs/deployment.md](docs/deployment.md).

## Sicherheitsgrenzen

- Least Privilege über Rollen und explizite Agent-Scopes.
- Append-only Audit-Einträge für Zugriffe, Zustandsänderungen, Freigaben und
  Executions.
- Kein automatisches Blockieren oder Remediation aus einem Signal oder LLM.
- Kritische Abläufe benötigen eine menschliche Freigabe.
- Secrets werden über Docker Secrets oder externe Referenzen injiziert und nie
  über API, MCP, Logs oder Frontend-Projektionen ausgegeben.
- Nicht-root-Container, Health Checks, Migrationsprüfungen und Backup-Abläufe.

Siehe [docs/security.de.md](docs/security.de.md),
[docs/security.md](docs/security.md) und den
[Security Audit](docs/security-audit.md).

## Dokumentation

- [Architektur](docs/architecture.de.md) · [English](docs/architecture.md)
- [LLM/MCP-Integration](docs/llm-integration.de.md) · [English](docs/llm-integration.md)
- [Deployment und Updates](docs/deployment.de.md) · [English](docs/deployment.md)
- [Sicherheitsmodell](docs/security.de.md) · [English](docs/security.md)
- [Agent API v1](docs/agent-api.md)
- [MCP-Server](docs/mcp-server.md)
- [Provider](docs/providers.md)
- [Connectoren](docs/connectors.md)
- [Backup und Recovery](docs/backup.md)
- [Final Release](docs/final-release.de.md) · [English](docs/final-release.md)

## Validierung

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm --prefix frontend test
npm --prefix frontend run build
docker compose config
docker compose build
```

## Lizenz

Apache License 2.0. Clawforge ist ein eigenständiges Rust-Projekt ohne
KorbKlar-, Supermarkt- oder OpenClaw-Runtime-Code.
