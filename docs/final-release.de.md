# Clawforge v1.0.0 Final Release

## Was ist Clawforge?

Clawforge ist eine selbsthostbare Operations-Intelligence-Plattform. Sie
sammelt strukturierte Infrastruktur- und Security-Events, korreliert sie,
erzeugt nachvollziehbare Incidents, bewertet Risiko und Trust und stellt einen
gemeinsamen Betriebskontext für Menschen und read-only LLM-Agenten bereit.

Clawforge ist kein autonomer KI-Administrator. Die Plattform erklärt, was
passiert ist und warum es relevant ist. Kontrollierte Abläufe nutzen Allowlist,
Policy-Prüfung, explizite Freigaben, Execution Queue und Audit. Der Executor
bleibt in v1.0 standardmäßig Dry-Run.

## Zweck

Infrastrukturinformationen sind über Container, Server, Provider, Repositories,
Monitoring und Security-Feeds verteilt. Clawforge schafft eine bereinigte,
auditable Ebene, die Zusammenhänge sichtbar macht, ohne Agenten versteckten
Zugriff oder uneingeschränkte Befehle zu geben.

## Architektur

```text
Connectors / Providers -> Event Backbone -> Correlation -> Incidents / Alerts
                                      -> Risk / Trust / Policy
                                      -> Decisions -> Workflows -> Controlled Operations
                                      -> Agent API v1 -> MCP -> LLM agents
```

PostgreSQL ist die Source of Truth. Rust-Services verwenden sqlx-Migrationen;
das Frontend ist API-only. MCP verbindet sich nie direkt mit PostgreSQL oder dem
Event Backbone.

## Stabile v1.0-Funktionen

- Event-, Alert-, Correlation-, Incident- und Timeline-Verarbeitung
- Threat-, ASN-, BGP-, RPKI-, Risk- und Trusted-Infrastructure-Kontext
- Erklärbare Decisions, Workflows, Approvals und Audit-Historie
- Read-only Agent API v1 und scoped MCP für OpenClaw
- Docker-, GitHub- und Proxmox-Connector-Grundlagen
- PostgreSQL, Backup/Restore, Health Checks und Metriken
- React/TypeScript Operations Dashboard

## Sicherheitsmodell

Least Privilege, explizite Scopes, append-only Audits, menschliche Freigaben für
kritische Aktionen, Secret Separation, begrenzte Antworten und kein Single-
Feed-Blocking sind Release-Anforderungen. Secretwerte gelangen nie in
Repository, MCP-Antworten, Logs oder PostgreSQL-Metadaten.

## Installation und Betrieb

[deployment.de.md](deployment.de.md) beschreibt Compose-Installation,
veröffentlichte GHCR-Images, Migrationen, Health Checks, Updates und Rollback.
Vor Produktionsupdates [backup.md](backup.md) und [recovery.md](recovery.md)
verwenden. Die LLM-Grenze steht in [llm-integration.de.md](llm-integration.de.md).

## Roadmap nach v1.0

Künftige Releases können geprüfte Connector-Ausführung, erweiterten Knowledge-
und Trend-Kontext sowie signierte Image-Attestierungen ergänzen. Read-only MCP,
Approval-Pflicht, Audit und Secret-Isolation bleiben erhalten.

Die englische Referenz ist [final-release.md](final-release.md).
