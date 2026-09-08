# Operations Workflows

Der v0.6-Workflow erweitert die bestehende Kette:

```text
Events → Correlation → Incidents/Alerts → Decision Engine → Empfehlung
```

Der Worker bewertet den gespeicherten Zustand in seinem normalen Polling-Loop.
Offene Empfehlungen werden dedupliziert und bei erneutem Auftreten aktualisiert.
Abgelaufene Entscheidungen werden nach der Aufbewahrungsfrist als `expired`
markiert.

Agents und MCP dürfen Empfehlungen lesen und erklären. Sie dürfen keine
Provider aktivieren, Policies ändern, Trust vergeben oder Approvals auslösen.
Die Operations-Center-Ansicht zeigt aktuelle Empfehlungen und die Historie
über die bestehenden administrativen Read-Routen.

Bei einem Provider-Ausfall lautet die Ausgabe beispielsweise, die Provider-
Historie und Fallback-Konfiguration zu prüfen. Das System aktiviert keinen
Fallback automatisch.
