# Clawforge Decision Intelligence v0.6

Die Decision Engine erzeugt aus bereits gespeicherten Incidents, Alerts,
Providerzuständen und Knowledge-Zusammenfassungen nachvollziehbare
Empfehlungen. Sie berechnet keine neue Risk- oder Trust-Policy und führt keine
Systemaktion aus.

## Persistenz

Migration `0020_decisions.sql` legt `decisions`, `rules`, `rule_executions`
und `approvals` an. Entscheidungen enthalten Severity, Kategorie, Quelle,
Grund, Empfehlung, Confidence und Status. Die Approval-Tabelle bildet nur die
spätere Freigabe ab; ein Approval löst in v0.6 keine Aktion aus.

## Rules Engine

Regeln sind deklarative JSON-Bedingungen. Die Engine akzeptiert nur bekannte
Felder wie Mindest-Severity, Quelle und Zeitfenster. Es gibt keine
Script-Ausführung. Ein Treffer wird als Decision-Empfehlung und
`rule_execution` gespeichert; Incident-, Provider- oder Policy-Änderungen
werden nicht automatisch ausgeführt.

## Agent API und MCP

`GET /api/v1/operations/recommendations` liefert offene Empfehlungen.
`GET /api/v1/decisions/history` liefert die Historie. Beide Routen benötigen
`agent:operations:recommend` und sind read-only. Die MCP-Tools
`get_operations_recommendations` und `get_decision_history` verwenden nur
diese Agent-API-Routen.

Antworten enthalten keine Rohpayloads, Secrets oder internen Regelzustände.
`reason`, `recommendation` und `confidence` machen jede Ausgabe prüfbar.
