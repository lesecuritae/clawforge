# Architektur

Clawforge trennt Transport, Sammlung, Intelligence, Bewertung, Policies und
Speicherung. Provider erzeugen normalisierte Indicators und Netzwerkbeobachtungen.
Risk- und Trust-Engine berechnen begrenzte Scores mit Begründungen. Nur die
Policy-Grenze kann eine Bewertung in eine Aktion übersetzen; dafür sind mehrere
bestätigende Signale nötig.

Der Rust-Workspace ist eine eigenständige Neuimplementierung, kein Zeile-für-Zeile-
Port. KorbKlar-Namensräume, Runtime-Code und Supermarktlogik gehören nicht zu
Clawforge.

## Aktueller Stand

Die API verbindet sich mit PostgreSQL, führt sqlx-Migrationen aus und stellt
Health/Readiness, Intelligence-, Netzwerk-, Trust-, Incident-, Alert- und
Prometheus-Endpunkte bereit. Der Worker verwendet Tokio und speichert Provider-
und Netzwerkjobs, Retry/Backoff, Risk-Verbrauch, typisierte Audit-Events und
optionale Redis-Locks. `clawforge-correlation` konsumiert den Event-Stream und
speichert begrenzte Beziehungen und Incident Candidates. `clawforge-incidents`
überführt offene Candidates in einen verwalteten Incident-Lifecycle. Der
MCP-Adapter ist stateless, read-only und verwendet ausschließlich Agent API v1.
Jobs und Provider sind standardmäßig deaktiviert; kein Provider-Event blockiert.

## Funktionsübersicht

### Security Intelligence

- Event Backbone
- Event Correlation
- Incident Management
- Alert Management
- Risk-Bewertung
- Trust-Bewertung

### Operations Intelligence

- Context API
- Operations Summary
- Briefings
- Decision Engine
- Historical Intelligence

### Automation Governance

- Workflow Engine
- Action Registry
- Approval-System
- Execution Queue
- Controlled Operations

### Integration und Connector Framework

Clawforge besitzt ein generisches Connector Framework. Connectoren verbinden
externe Systeme mit der Operations-Intelligence-Plattform, normalisieren Daten,
liefern Health- und Capability-Informationen und geben nur sichere Projektionen
an die Operations-Schicht weiter. Das Framework ist nicht auf einen Hersteller
oder eine Technologie begrenzt. Docker, GitHub und Proxmox sind erste Beispiele;
Containerplattformen, Infrastruktur, Virtualisierung, Repositories, Cloud,
Monitoring, Security-Feeds und weitere Datenquellen können ergänzt werden.

Connectoren speichern keine unnötigen Rohdaten. Actions sind allowlisted und
standardmäßig deaktiviert; Lese- und künftige Ausführungsfähigkeiten bleiben
getrennt.

## Datenfluss

```text
Provider -> Normalizer -> Indicator/Network Store -> Risk + Trust -> Policy -> Response
```

Netzwerkprovider verwenden dieselbe Grenze für ASN-, BGP- und RPKI-Daten. Ihre
normalisierten Datensätze werden in PostgreSQL gespeichert und als bewertbare
Evidenz weitergegeben. Netzwerkprovider führen keine Blockaktionen aus.

Rohfeeds erreichen weder LLMs noch Blockaktionen. Der optionale
`clawforge-analyzer` erhält nur bereinigten Incident-Kontext über eine interne
API und speichert strukturierte Erklärungen. Er kann Risiko, Trust, Policy,
Provider oder Berechtigungen nicht ändern.

## Architekturebenen

```text
Infrastructure Sources
  containers | virtualization | repositories | cloud | monitoring | feeds
                                |
                                v
                         Connector Layer
                                |
                                v
                    Provider Intelligence Layer
                                |
                                v
                         Event Backbone
                                |
                                v
                       Correlation Engine
                                |
                                v
                     Incident Intelligence
                                |
                                v
                    Risk / Trust / Policy Engine
                                |
                                v
                      Decision Intelligence
                                |
                                v
                       Workflow Governance
                                |
                                v
                      Controlled Operations
                                |
                                v
                           Agent API
                                |
                                v
                           MCP Server
                                |
                                v
                           LLM Agent
```

- **Connector Layer** verbindet externe Systeme ohne Bindung an einen
  einzelnen Hersteller.
- **Provider Intelligence** bewertet Zustand, Qualität und Aktualität externer
  Datenquellen.
- **Event Backbone** sammelt Betriebs- und Sicherheitsereignisse.
- **Correlation Engine** erkennt Zusammenhänge zwischen einzelnen Ereignissen.
- **Incident Intelligence** erstellt nachvollziehbare Vorgänge.
- **Risk / Trust / Policy** bewertet Sicherheit, Vertrauen und erlaubte Abläufe.
- **Decision Intelligence** erzeugt erklärbare Empfehlungen.
- **Workflow Governance** verwaltet kontrollierte Abläufe und Freigaben.
- **Controlled Operations** führt nur registrierte, geprüfte und freigegebene
  Pfade aus.

## Event Backbone

Kanonische Events liegen in `events` und werden über `event_consumers` und
`event_delivery` verteilt. Event-Service und Notifier verwenden interne
Service-Tokens, begrenzte Retries und Dead-Letter-Zustände. Payloads werden vor
der Speicherung gefiltert; Consumer können Risk, Trust, Policy oder Provider
nicht ändern.

Die englische Referenz ist [architecture.md](architecture.md).
