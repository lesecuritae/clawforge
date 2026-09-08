# Event Correlation Layer

Die Event Correlation Layer ist eine eigenständige Analyse-Schicht oberhalb
des unveränderten Event Backbones. Sie liest kanonische Events über einen
eigenen Event-Consumer, bewertet zeitlich nahe Beziehungen und speichert
Beziehungen sowie Incident-Kandidaten. Sie verändert keine Backbone-Events,
Policies, Risk- oder Trust-Entscheidungen und löst keine automatische Reaktion
aus.

## Architektur

```text
Event Backbone
      |
      | event_delivery (consumer: correlation)
      v
clawforge-correlation
      |
      +-- Correlation Rules
      +-- Confidence/Severity derivation
      +-- event_relationships
      +-- incident_candidates
```

Der Dienst verwendet PostgreSQL als Quelle der Wahrheit und bestätigt eine
Delivery erst nach erfolgreicher Analyse und Persistenz. Fehlgeschlagene
Analysen bleiben durch das bestehende Delivery-Retry-Modell erneut zustellbar.
Der Default-Zeitraum beträgt 900 Sekunden und kann mit
`CLAWFORGE_CORRELATION_WINDOW_SECONDS` angepasst werden.

## Correlation Rules

Events werden nur korreliert, wenn sie zu den unterstützten Security-Eventtypen
gehören und innerhalb des Zeitfensters liegen:

- gleiche `correlation_id` (typischerweise gemeinsames Ziel oder gemeinsame
  Ressource),
- gemeinsame normalisierte Indikatoren aus `resource`, `target`, `ip`,
  `prefix`, `asn`, `domain`, `url` oder `hash`,
- unterschiedliche Eventtypen bilden eine Event Chain; gleiche Eventtypen
  werden als gemeinsame Indikatorbeziehung gespeichert.

Die Regel liefert einen Confidence-Wert und eine erklärbare Begründung. Die
Kandidaten-Severity ist die höchste Event-Severity; eine Kette aus mindestens
zwei unterschiedlichen Eventtypen hebt `medium` auf `high` an. Diese Ableitung
ist eine Analyseklassifikation und keine Policy- oder Blockentscheidung.

## Datenmodell

Migration `0013_event_correlation.sql` ergänzt:

- `incident_candidates`: Status (`open`, `promoted`, `dismissed`),
  Korrelationsschlüssel, Confidence, Severity, Zeitbereich und Zusammenfassung,
- `incident_candidate_events`: Zuordnung eines Kandidaten zu kanonischen
  Event-UUIDs,
- `event_relationships`: deduplizierte Event-Paarbeziehung mit Regeltyp,
  Confidence und Begründung.

Ein Kandidat wird erst erzeugt, wenn mindestens zwei passende Events gefunden
wurden. Die aktuelle Phase promotet Kandidaten nicht automatisch in `incidents`.
Damit bleiben die vorhandenen Incident-Lifecycle- und Policy-Flows unverändert.

## Betrieb

`clawforge-correlation` läuft als eigener, nicht-rootfähiger Compose-Dienst mit
Read-only-Dateisystem und ausschließlich dem PostgreSQL-Secret. Der Dienst
registriert den Consumer `correlation`, nutzt keine Provider-Credentials und
kommuniziert nicht mit MCP oder der Agent API.

## API-Auswirkungen

In dieser Phase gibt es keine neue öffentliche oder versionierte API-Route.
Die bestehende Event- und Incident-API bleibt unverändert. Kandidaten und
Beziehungen sind zunächst interne Persistenzdaten; eine spätere Read-only-
Ansicht kann darauf aufbauen, ohne die Correlation Rules oder das Event
Backbone zu verändern.

## Tests

Die Rule-Ebene testet Event Chains mit gemeinsamen Indikatoren, gleiche
Correlation IDs, Zeitfenstergrenzen und die Ableitung von Confidence und
Severity. Storage-/Compose-Tests prüfen Migration und Consumer-Persistenz;
bestehende Tests bleiben unverändert ausführbar.
