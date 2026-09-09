# LLM- und MCP-Integration

Clawforge ist eine Operations-Intelligence-Schicht für Menschen und Agenten.
Ein LLM erhält keinen direkten Infrastrukturzugriff, keine
Datenbankzugangsdaten, keine Rohfeeds und keine Policy-Rechte. Clawforge liefert
begrenzten Kontext; das LLM formuliert daraus Erklärungen und Empfehlungen.

## Read-only-Kontextfluss

```text
Benutzerfrage
    |
    v
OpenClaw / anderer LLM-Agent
    |
    v
Clawforge MCP (read-only, scoped)
    |
    v
Agent API v1 / Context API
    |
    +--> Events, Incidents, Risiko, Trust, Providerstatus
    |
    v
Bereinigter Erklärungskontext
```

Für „Was passiert auf meinem Server?“ kann ein Agent
`get_operations_summary`, `get_agent_context`, `get_decisions` und Incident-
Tools kombinieren. Für „Warum ist dieser Container langsam?“ liefert Clawforge
gespeicherten und bewerteten Kontext; das LLM berechnet keine Scores aus
Rohdaten.

Der Connector-Pfad ist generisch:

```text
LLM -> MCP -> Operations Layer -> Connector Framework -> Infrastrukturquelle
```

Connectoren können Containerplattformen, Infrastruktur, Virtualisierung,
Repositories, Cloud-Dienste, Monitoring oder externe Datenquellen abbilden.
Docker, GitHub und Proxmox sind Beispiele, keine Produktgrenzen. Ein
Connector liefert normalisierten Zustand, Health und Capabilities und gibt
keine unnötigen Rohdaten aus.

## Kontrollierte Abläufe

Eine Anfrage wie „Starte den Container neu“ folgt diesem Weg:

```text
LLM-Anfrage
  -> Decision / Empfehlung
  -> Action-Allowlist
  -> Policy-Prüfung
  -> menschliche Freigabe
  -> Execution Queue
  -> Worker
  -> Audit Event
```

In v1.0 bleibt Connector-Ausführung deaktiviert und der Executor arbeitet mit
`CLAWFORGE_EXECUTOR_DRY_RUN=true`. MCP hat keine Action-, Approval-, Policy-
oder Cancel-Tools. Kein Prompt kann eine Policy umgehen oder Trust vergeben.

## Authentifizierung und Scopes

MCP-Authentifizierung und Upstream-Agent-API-Token sind getrennte Secrets. Sie
werden über Docker-Secret-Dateien oder externe Secret-Referenzen injiziert. Ein
minimales Read-only-Profil kann enthalten:

- `agent:operations:read`
- `agent:context:read`
- `agent:decision:read`
- `agent:incident:read`
- `agent:provider:read`
- `agent:security:read`

Jeder Aufruf ist durch Timeout und Antwortgröße begrenzt, gegen die Scope-
Allowlist geprüft, bereinigt und ohne Tokenwert auditiert.

## Datengrenze

Der optionale Analyzer erhält nur bereinigten Incident-Kontext. Rohfeeds,
Credentials, API-Keys, Datenbankverbindungen und interne Secretwerte werden
entfernt. LLM-Ausgaben sind beratend und können Risk, Trust, Policy, Provider,
Berechtigungen, Incident- oder Workflow-Zustände nicht ändern.

Die englische Referenz ist [llm-integration.md](llm-integration.md).
