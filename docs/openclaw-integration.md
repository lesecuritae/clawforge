# OpenClaw-Integration

Diese Anleitung beschreibt den produktiven, read-only Anschluss von OpenClaw
an den MCP-Adapter. OpenClaw verwendet ausschließlich die versionierte Agent
API v1 über den separaten MCP-Dienst.

## Endpunkt und Geheimnisse

Im Compose-Netz ist der MCP-Endpunkt:

`http://clawforge-mcp:8090/mcp`

Der MCP-HTTP-Zugang und das ausgehende Agent-API-Credential sind getrennte
Secrets. Beide werden über Docker Secrets beziehungsweise die vorhandenen
`*_FILE`-Variablen injiziert. Tokenwerte gehören weder in Git, Logs,
PostgreSQL noch in Reports.

Für ein read-only Agent-Profil werden nur die benötigten Scopes vergeben:

- `agent:operations:read`
- `agent:operations:briefing`
- `agent:context:read`
- `agent:decision:read`
- `agent:incident:read`
- `agent:provider:read`
- `agent:security:read`
- `agent:knowledge:read`
- `agent:incident:replay`
- `agent:history:read`
- `agent:security:briefing`
- `agent:system:graph:read`

`agent:read` kann diese Einzelrechte zusammenfassen, sollte aber nur für ein
bewusst breit lesendes Profil verwendet werden. Für `get_status`,
`list_events`, `get_trust_status` und `get_network_overview` werden zusätzlich
`agent:system:read`, `agent:events:read` beziehungsweise
`agent:network:read` benötigt. Es existieren keine MCP-Schreibwerkzeuge.

## Abnahmetest

1. MCP-Container und API im isolierten Compose-Netz starten.
2. MCP-Token und Agent-Token getrennt rotieren und als Secrets laden.
3. Tool-Liste abrufen und die 23 read-only Tools erkennen.
4. `get_status`, `get_agent_context`, `get_decisions`,
   `get_operations_summary`, `get_daily_operations_briefing`,
   `get_operations_history`, `get_knowledge_context`,
   `get_security_briefing` und `get_system_graph` aufrufen.
5. Incident-Replay sowie Incident-, Security-, Trust-, Network-, Provider- und Event-Tools mit den
   jeweils dokumentierten Scopes prüfen.
6. Fehlender, falscher, abgelaufener und widerrufener Token müssen abgewiesen
   werden; ein fehlender Scope muss `403` beziehungsweise einen MCP-
   Berechtigungsfehler liefern.
7. Upstream-Timeout, `401`, `429` und `5xx` prüfen. Antworten dürfen keine
   Rohpayloads, Secrets, Candidate-IDs oder Korrelationsschlüssel enthalten.
8. `/metrics` auf MCP-Aufruf- und Fehlerzähler prüfen, ohne Tokenwerte zu
   loggen.

Die OpenAPI-Spezifikation unter `docs/openapi.yaml` und
`docs/agent-api.md` bleiben der Vertrag für den Upstream. OpenClaw darf keine
historischen ungeschützten Routen verwenden.

## Live-Abnahme

Die produktive Testverbindung wurde mit einem getrennten MCP-Token und einem
separaten Agent-API-Token geprüft. Die MCP-Discovery liefert alle 21
read-only Tools. Erfolgreich geprüft wurden `get_operations_summary`,
`get_agent_context` und `list_incidents`; die Agent-API-Auditspur enthält
Quelle, Ressource und Zeitpunkt, aber keine Tokenwerte.

Der Operations-Agent ist als read-only Rolle definiert. Er darf den Zustand
bewerten, Incidents erklären und Prüfungen empfehlen. Er darf weder Policies,
Provider, Trust, Benutzerrechte oder Incident-Status ändern noch Blockierungen
oder andere Remediation auslösen.

Tool-Aufrufe werden über MCP-Zähler, OpenClaw-Aufrufmetadaten und die
redigierte Agent-API-Auditspur beobachtbar. Die derzeitigen MCP-Metriken sind
aggregiert; Toolname und Laufzeit stammen aus der OpenClaw-Aufrufspur.

Die kontrollierte Correlation-Abnahme hat drei Events gleicher Quelle zu
einem kritischen Incident mit einer Korrelation und ohne Incident-Duplikate
zusammengeführt. Provider-Ausfalltests benötigen mindestens einen aktivierten
Provider; bei deaktivierter Feed-Synchronisation bleibt der Providerstatus
leer und wird nicht als erfolgreicher Feedtest gewertet.
