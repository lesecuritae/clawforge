# Clawforge API Governance

## Versionierung

Die externe Agent-Fassade wird unter `/api/v1` versioniert. Neue Felder und
neue read-only Ressourcen dürfen innerhalb von v1 ergänzt werden, solange
bestehende Feldnamen, Datentypen, Statuscodes und Scope-Anforderungen
kompatibel bleiben.

## Breaking Changes

Das Entfernen oder Umbenennen eines Feldes, eine geänderte Bedeutung eines
Feldes, strengere Validierung mit vorher gültigen Werten und Änderungen an
Auth- oder Scope-Anforderungen sind Breaking Changes. Sie benötigen eine neue
API-Version oder eine dokumentierte Migrationsfrist.

## Deprecation

Abgekündigte Endpunkte bleiben mindestens eine dokumentierte Übergangsfrist
erreichbar. Die API-Dokumentation nennt Ersatz und Ablaufdatum. Clients sollen
Deprecation-Header tolerieren und die neue Route vor dem Ablauf übernehmen.

## MCP-Kompatibilität

Der MCP-Server ist ein read-only Adapter und verwendet ausschließlich die
Agent API v1. Tool-Namen, Parameter und Antwortformen bleiben stabil. Neue
Tools dürfen bestehende Tools nicht entfernen oder Schreibrechte einführen.
Scopes werden explizit in OpenAPI, `docs/agent-api.md` und
`docs/mcp-server.md` dokumentiert.

## Response- und Sicherheitsvertrag

JSON-Antworten verwenden den gemeinsamen Envelope mit `status`, `data`,
`timestamp`, `pagination` und `errors`. Agenten erhalten nur normalisierte,
bereits bewertete Daten. Secrets, Tokens, Provider-Schlüssel, Rohpayloads,
freie Incident-Notizen und interne Datenbankfelder bleiben ausgeschlossen.

## Migration und Tests

Schemaänderungen werden als aufsteigende sqlx-Migration eingebracht und
müssen auf einer frischen sowie einer bestehenden Datenbank reproduzierbar
sein. Änderungen an der Agent API benötigen OpenAPI-Beispiele,
Authentifizierungs-/Scope-Tests und MCP-Regressionstests. Vor jedem Release
werden `cargo fmt`, Workspace-Tests, Clippy, Frontend-Build, Compose-Konfigu-
ration und die Readiness-Prüfung ausgeführt.
