# Incident Management

Incident Management ist die Betriebsschicht oberhalb der Event Correlation
Layer. `clawforge-correlation` erzeugt weiterhin nur Kandidaten; der separate
`clawforge-incidents`-Dienst übernimmt offene Kandidaten transaktional in
verwaltbare Incidents. Der Event Backbone und die Correlation Rules bleiben
unverändert.

## Lifecycle

Ein neuer Incident startet mit `detected`. Zulässige Statuswerte sind:

`detected` → `investigating` → `confirmed` → `mitigated` → `resolved` → `closed`

Abkürzungen zu `closed` sind aus jedem offenen Status zulässig. `closed` ist
terminal. Alte Eingaben `Open` und `Ignored` werden aus
Kompatibilitätsgründen als `detected` beziehungsweise `closed` interpretiert;
neue Antworten verwenden ausschließlich die kanonischen Kleinschreibungen.

Jeder Statuswechsel speichert den vorherigen Status, den Benutzer, eine
Begründung und den Zeitpunkt in `incident_status_history`. Zusätzlich werden
`detected_at`, `confirmed_at`, `mitigated_at`, `resolved_at` und `closed_at`
am Incident geführt.

## Candidate-Übernahme

Der Incident-Dienst liest `incident_candidates` mit `status='open'` und nutzt
PostgreSQL Row Locks, damit ein Kandidat nur einmal übernommen wird. Dabei
werden Severity, Confidence, Summary, Korrelationsschlüssel und Zeitbereich
übernommen. Der Kandidat erhält anschließend den Status `promoted`.

Kanonische Event-UUIDs werden als `event`-Relationen gespeichert. Die aus der
Correlation Layer stammenden Event-Paarbeziehungen werden als
`event_relationship` erhalten. Ein Korrelationsschlüssel vom Typ
`indicator:<value>` wird zusätzlich mit passenden gespeicherten Indicators
verknüpft. Die ursprünglichen Audit-Event-Verknüpfungen älterer Incidents
bleiben lesbar.

## Datenmodell

Migration `0014_incident_management.sql` ergänzt:

- `incidents.confidence`, `incidents.candidate_id` und Lifecycle-Zeitpunkte,
- `incident_status_history` für eine unveränderliche Status-Timeline,
- `incident_notes` für operator-geführte Untersuchungshinweise,
- `incident_relations` für Events, Event-Beziehungen, Indicators und spätere
  Incident-Verknüpfungen.

Die Relationstabellen enthalten keine Secrets und verändern weder Risk-, Trust-
noch Policy-Bewertungen.

## API

Die bestehenden authentifizierten Incident-Routen bleiben erhalten und liefern
die kanonischen Statuswerte:

- `GET /incidents` — Liste mit Severity, Confidence, Candidate-ID und Event-Anzahl,
- `GET /incidents/{id}` — Incident-Details,
- `GET /incidents/{id}/events` — verbundene Events,
- `GET /incidents/{id}/timeline` — Status-, Notiz- und Relations-Timeline,
- `GET /incidents/{id}/status-history` — Statushistorie,
- `GET /incidents/{id}/notes` — Untersuchungsnotizen,
- `POST /incidents/{id}/notes` — Note für Administratoren und Operatoren,
- `POST /incidents/{id}/status` — Statuswechsel für Administratoren und
  Operatoren; optional mit `reason`.

Viewer dürfen lesen, aber keine Statuswechsel oder Notizen schreiben. Jede
administrative Aktion wird wie bisher auditiert. Agent API und MCP erhalten in
dieser Phase keine neuen Schreibwerkzeuge oder Aktionen.

## Analyse

Die bestehende Analyse-Route bleibt verfügbar. Sie liest nun auch kanonische
Event-Relationen aus dem Incident-Timeline-Modell und bleibt erklärend. Sie
kann weder blockieren noch Trust, Policy, Provider oder Berechtigungen ändern.

Incident Management erzeugt keine Blockierung, ändert keine Policy und vergibt
keinen Trust. Es macht erkannte Korrelationen für Operatoren nachvollziehbar
und bereitet eine spätere Read-only-Auswertung über die vorhandenen API-
Verträge vor.
