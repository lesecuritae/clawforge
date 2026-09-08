# OpenClaw-Integration (Vorbereitung)

Diese Anleitung beschreibt den späteren Anschluss von OpenClaw an den
read-only MCP-Adapter. In dieser Phase wird keine OpenClaw-Konfiguration
geändert und keine produktive Verbindung aktiviert.

## Endpunkt und Geheimnisse

Im Compose-Netz ist der MCP-Endpunkt:

`http://clawforge-mcp:8090/mcp`

Der MCP-HTTP-Zugang und das ausgehende Agent-API-Credential sind getrennte
Secrets. Beide werden über Docker Secrets beziehungsweise die vorhandenen
`*_FILE`-Variablen injiziert. Tokenwerte gehören weder in Git, Logs,
PostgreSQL noch in Reports.

Für ein read-only Agent-Profil werden nur die benötigten Scopes vergeben:

- `agent:operations:read`
- `agent:context:read`
- `agent:decision:read`
- `agent:incident:read`
- `agent:provider:read`
- `agent:security:read`

`agent:read` kann diese Einzelrechte zusammenfassen, sollte aber nur für ein
bewusst breit lesendes Profil verwendet werden. Für `get_status`,
`list_events`, `get_trust_status` und `get_network_overview` werden zusätzlich
`agent:system:read`, `agent:events:read` beziehungsweise
`agent:network:read` benötigt. Es existieren keine MCP-Schreibwerkzeuge.

## Abnahmetest

1. MCP-Container und API im isolierten Compose-Netz starten.
2. MCP-Token und Agent-Token getrennt rotieren und als Secrets laden.
3. Tool-Liste abrufen und die 14 read-only Tools erkennen.
4. `get_status`, `get_agent_context`, `get_decisions` und
   `get_operations_summary` aufrufen.
5. Incident-, Security-, Trust-, Network-, Provider- und Event-Tools mit den
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
