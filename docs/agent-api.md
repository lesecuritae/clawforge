# Agent API Design

Status: Phase 1 implementiert. Dieses Dokument beschreibt die externe
Read-only-API-Schicht für OpenClaw- und spätere MCP-Anbindungen. Ein MCP-
Server ist weiterhin nicht implementiert.

## Ziele und Grenzen

Die Agent API stellt bereits bewertete Clawforge-Daten lesbar bereit. Ein
Agent darf Systemzustand erklären, Events abfragen, Incidents untersuchen und
Netzwerk- oder Trust-Kontext abrufen. Die API führt keine Bewertung aus und
ändert keine Daten.

Die folgenden Grenzen bleiben unverändert:

- Risk Engine, Policy Engine, Trust Engine und Event Backbone bleiben die
  bestehenden Komponenten.
- Ein Agent kann weder blockieren noch Policies, Provider oder Trust ändern.
- Rohfeeds, Provider-Secrets, interne Service-Tokens und direkte
  PostgreSQL-Zugriffe werden nicht an Agenten weitergegeben.
- Der spätere MCP-Server ruft ausschließlich diese API auf. Er erhält keinen
  eigenen Storage-Zugriff und keine privilegierten internen Endpunkte.

## Bestandsaufnahme

### Event Backbone

Migration `0011_events.sql` trennt das unveränderliche Event (`events`) von
Consumer- und Zustellstatus (`event_consumers`, `event_delivery`). Der
Event-Service, Notifier und Analyzer verwenden interne Service-Tokens und
Retry-/Dead-Letter-Zustellung. `GET /events`, `GET /events/{id}` und
`GET /events/status` sind aktuell nur für Administratoren und Operatoren
zugänglich.

Die Agent API liest ausschließlich kanonische Events und verwendet deren
`event_id`, `event_type`, `source`, `severity`, `timestamp`,
`correlation_id`, `payload` und `metadata`. Zustellstatus und interne
Service-Tokens gehören nicht in die Agent-Antwort.

### Storage Layer

`PostgresStore` kapselt sqlx und die Migrationen. Bereits vorhandene
Read-Modelle liefern Providerstatus, Indicators mit aktueller Risiko-/Trust-
Bewertung, ASN-, BGP-, RPKI- und Trust-Daten sowie Incidents und ihre
zugeordneten Audit-Events.

Es gibt noch kein eigenes Security-Finding-Read-Model und keinen öffentlichen
Risk-History-Endpunkt. Für die Agent API wird deshalb ein stabiler Finding-
View aus Indicator, letzter Bewertung, Incident-Verknüpfungen und zeitlicher
Gültigkeit benötigt. Die zugrunde liegenden Tabellen und Bewertungsfunktionen
werden dabei nicht verändert.

### API-Struktur

Die API verwendet bereits eine gemeinsame JSON-Hülle:

```json
{
  "status": "ok",
  "data": {},
  "timestamp": "2026-09-08T00:00:00Z",
  "pagination": null,
  "errors": []
}
```

Die bestehenden UI-/Administrationsrouten sind jedoch überwiegend
unversioniert. Die historischen Intelligence- und Network-Read-Routen
(`/intelligence/*` und `/network/*`) prüfen heute nicht alle einen Bearer-
Principal. Sie dürfen daher nicht als externe Agentenschnittstelle verwendet
werden. Die neue Fassade muss eigene authentifizierte Handler besitzen und
die vorhandenen Storage-Read-Modelle wiederverwenden.

### Frontend-Datenmodelle

Das Frontend verwendet TypeScript-Typen für Provider, Incidents, Indicators
und ein generisches `NetworkRecord`. Einige Visualisierungsdaten sind noch
lokale Komponenten-Typen. Für Agenten wird ein unabhängiger, dokumentierter
API-Vertrag benötigt; Frontend-Typen werden nicht zur Sicherheits- oder
Versionsgrenze gemacht. Später können daraus generierte TypeScript-Typen
entstehen.

### Authentifizierung

Die bestehende Authentifizierung akzeptiert Bearer-Sessions und API-Tokens.
Passwörter und Tokenwerte werden nicht im Klartext gespeichert; PostgreSQL
erhält Hashes, Präfixe und Ablauf-/Widerrufsdaten. Rollen sind
`Administrator`, `Operator` und `Viewer`.

Für Agenten wird ausschließlich ein dedizierter, ablaufender API-Token mit
expliziten Read-Scopes verwendet. Browser-Sessions, Bootstrap-Tokens und
interne Docker-Service-Tokens sind keine Agent-Credentials.

## Versionierte externe API

Die Fassade ist unter `/api/v1` verschachtelt. Die bisherigen unversionierten
Routen bleiben für die aktuelle Konsole und interne Kompatibilität bestehen;
neue Agentenintegrationen verwenden ausschließlich `/api/v1`.

Alle JSON-Endpunkte verwenden die bestehende Hülle. Listen sind paginiert und
tragen mindestens `page`, `page_size`, `total` und `has_next`. `page_size`
ist auf 100 für Agenten begrenzt; größere Exporte bleiben separate,
rollenbasierte Exportfunktionen. Zeitangaben sind UTC in RFC-3339-Format.

### Vorgeschlagene Ressourcen

| Endpoint | Zweck | Inhalt | Mindest-Scope |
| --- | --- | --- | --- |
| `GET /api/v1/status` | Betriebszustand | API, Worker, PostgreSQL, Migrationen, Event-Consumer, Provider-Zusammenfassung, Versionsstand | `agent:system:read` |
| `GET /api/v1/events` | aktuelle kanonische Events | Typ, Quelle, Severity, Zeit, Korrelation, begründete Zusammenfassung | `agent:events:read` |
| `GET /api/v1/incidents` | Incident-Liste | Status, Severity, Risiko, Summary, Zeit, Event-Anzahl | `agent:incidents:read` |
| `GET /api/v1/security/findings` | Security Findings | Indicator-Finding, Quelle, Confidence, Alter, Ablauf, Risk-/Trust-Werte, Reason | `agent:security:read` |
| `GET /api/v1/security/overview` | Security-Zusammenfassung | Finding-Anzahl, aktive Findings, Severity-Verteilung, höchste gespeicherte Bewertung | `agent:security:read` |
| `GET /api/v1/network/asn` | ASN-Kontext | ASN, Organisation, Provider, Land, Prefixe, Netzwerktyp, Reputation, Alter | `agent:network:read` |
| `GET /api/v1/network/prefixes` | Prefix-Kontext | Prefix, ASN, Netzwerktyp, Zeit und Quelle | `agent:network:read` |
| `GET /api/v1/network/bgp` | Routing-Ereignisse | Prefix, vorherige/neue ASN, Status, Quelle, Zeit, Confidence | `agent:network:read` |
| `GET /api/v1/network/rpki` | ROA-Bewertung | Prefix, ASN, Valid/Invalid/Unknown, Quelle, Zeit, Trust-Hinweis | `agent:network:read` |
| `GET /api/v1/network/trust` | Trusted Infrastructure | Name, Typ, Identifier, Status, Zeit, Confidence und gespeicherter Trust-Wert ohne Registry-Interna | `agent:network:read` |

Die Detailrouten für einzelne Events und Incidents sowie Provider- und
Capabilities-Ressourcen bleiben für Phase 2 vorgesehen.

Die Ressourcen sind ausschließlich `GET`. Es gibt unter `/api/v1` keine
Provider-Aktivierung, manuelle Synchronisation, Trust-Änderung,
Incident-Statusänderung, Policy- oder Blockaktion.

### Filter und Abfragen

Listen unterstützen, soweit fachlich sinnvoll:

- `page`, `page_size`
- `from`, `to`
- `severity`, `source`, `status`
- `event_type` und `correlation_id` für Events
- `asn`, `prefix` und `rpki_status` für Netzwerkdaten
- `confidence_min` und `active` für Findings

Filter werden serverseitig validiert. Ungültige Werte erzeugen einen
strukturierten `400`-Fehler. Agenten erhalten keine ungefilterten Rohpayloads;
die Antwort enthält nur normalisierte und bereits gespeicherte Daten.

### Stabiler Datenvertrag

Die äußere Hülle bleibt für alle Ressourcen gleich. Die fachlichen Felder
werden innerhalb von `data` versioniert; Felder werden nur hinzugefügt und
nicht stillschweigend umgedeutet. Ein unbekannter neuer Wert muss von Clients
als unbekannt behandelt werden können.

Ein Systemstatus enthält Komponentenstatus statt interner Prozessdetails:

```json
{
  "status": "ok",
  "data": {
    "service": "clawforge",
    "version": "0.1.0",
    "status": "ok",
    "migrations": { "current": true, "applied": 13, "expected": 13 },
    "runtime": [],
    "events": { "pending": 0, "failed": 0 },
    "providers": { "total": 0, "enabled": 0 }
  },
  "timestamp": "2026-09-08T00:00:00Z",
  "pagination": null,
  "errors": []
}
```

Ein Finding liefert die bereits gespeicherte Bewertung und ihre Herkunft:

```json
{
  "id": "indicator-123",
  "kind": "ip",
  "subject": "198.51.100.10",
  "source": "ThreatFox",
  "severity": "high",
  "confidence": 90,
  "risk_score": 72,
  "trust_score": 0,
  "reason": "botnet C2 indicator",
  "first_seen": "2026-09-07T23:00:00Z",
  "last_seen": "2026-09-08T00:00:00Z",
  "expires_at": "2026-09-08T12:00:00Z",
  "related_incident_ids": []
}
```

Ein Netzwerkdatensatz enthält stets Quelle, Zeitpunkt, Alter und vorhandene
Bewertung. Die API berechnet dabei keinen neuen Score; sie gibt die vom
bestehenden Network-/Risk-Layer gespeicherten Werte aus.

## Berechtigungsmodell

Die Autorisierung wird an der Fassade zentral geprüft:

1. Bearer-Token aus `Authorization` lesen.
2. Token-Hash gegen die bestehende Credential-Prüfung validieren.
3. Ablauf, Widerruf und Benutzerstatus prüfen.
4. Für jede Ressource den erforderlichen Agent-Scope prüfen.
5. Rate-Limit und maximale Seitengröße anwenden.
6. Einen anonymisierten Audit-Eintrag für Agent-Lesezugriffe erzeugen.

Die geplanten Agent-Scopes sind absichtlich feiner als die bestehenden
UI-Rollen. Ein Operator- oder Administrator-Benutzer kann später einen
separaten Agent-Token mit einer Teilmenge seiner Leserechte ausstellen. Ein
Agent-Token erhält niemals Schreibrechte. Tokenwerte, IPs und Rohpayloads
werden weder geloggt noch in Audit-Details abgelegt.

`401` bedeutet fehlende oder ungültige Credentials, `403` fehlende Scopes,
`404` unbekannte Ressourcen, `429` überschrittenes Limit und `503` nicht
verfügbare PostgreSQL-/Migrationsabhängigkeit. Die bestehenden
`Retry-After`- und `X-RateLimit-*`-Header gelten auch für `/api/v1`.

## OpenAPI-Vertrag

Die OpenAPI-Datei enthält jetzt den `/api/v1`-Bereich und die
`agentBearerAuth`-Sicherheitsdefinition. Die Beschreibung umfasst:

- `bearerAgentToken` als eigenes Security Scheme ausweisen;
- für jede Operation erforderliche Scopes dokumentieren;
- `ApiEnvelope`, `Pagination`, `SystemStatus`, `Event`, `Incident`,
  `Finding`, `TrustStatus`, `AsnRecord`, `PrefixRecord`, `BgpEvent`,
  `RpkiRecord` und `ProviderStatus` als wiederverwendbare Schemas führen;
- Beispiele für leere Listen, Fehler und paginierte Antworten enthalten;
- `401`, `403`, `404`, `429` und `503` mit der bestehenden Fehlerhülle
  beschreiben;
- klar zwischen `/api/v1` (externe read-only Fassade) und `/internal/*`
  (Service-Tokens) trennen.

Ein MCP-Server wird erst gegen diese validierte OpenAPI-Spezifikation gebaut.
Er darf keine nicht dokumentierten Felder voraussetzen.

## Implementierungsreihenfolge und Status

1. **Erledigt:** Read-only Handler unter `/api/v1` mounten. Bestehende
   Handler und Response-Verträge bleiben unverändert.
2. **Erledigt:** Read-Models für Findings, Systemstatus und Prefixe aus den
   vorhandenen Storage-Views ableiten, ohne Bewertungslogik zu verändern.
3. **Erledigt:** Agent-Token-Scopes, Ablauf, Widerruf und Audit-Prüfung
   ergänzen.
4. **Erledigt:** OpenAPI-Schemas, Filter und Fehlercodes dokumentieren.
5. **Erledigt:** Versionierten Trust-Read-Endpunkt mit Registry-Redaktion
   ergänzen.
6. **Offen:** OpenClaw/MCP erst als separaten, read-only Client anbinden.

Die Migration `0012_agent_tokens.sql` legt die dedizierte Credential-Tabelle
für die Fassade an. Sie wird beim normalen Start über den bestehenden
Migration-Runner eingespielt; eine Scope-Migration für bereits ausgestellte
Agent-Tokens ist für diese Phase nicht erforderlich.

## Testplan

### API- und Berechtigungstests

- Jeder `/api/v1`-Endpunkt antwortet ohne Token mit `401`.
- Ein gültiger Agent-Token erhält nur seine erlaubten Ressourcen; fehlende
  Scopes liefern `403`.
- Abgelaufene und widerrufene Tokens bleiben unwirksam.
- Kein Agent-Token kann `POST`, `PUT`, `PATCH` oder `DELETE` unter der Fassade
  ausführen.
- Interne Service-Tokens funktionieren nicht an externen Agent-Routen.

### Daten- und Vertragsprüfungen

- Envelope, Pagination, RFC-3339-Zeit und Fehlercodes entsprechen OpenAPI.
- Leere Datenbanken, große Seiten, ungültige Filter und unbekannte IDs werden
  deterministisch behandelt.
- Findings enthalten nur normalisierte Werte, Reason, Alter und Ablauf; keine
  Secrets, Rohfeeds oder internen Zustellfelder.
- Events bleiben unverändert und werden nur gelesen.
- ASN-, Prefix-, BGP- und RPKI-Antworten enthalten Quelle, Zeitpunkt und
  Bewertung ohne neue Risk- oder Trust-Berechnung.

### Integrations- und Regressionstests

- PostgreSQL-Migrationen und Neustart mit den neuen Read-Modellen.
- Agent-API gegen eine isolierte PostgreSQL-Testdatenbank.
- Rate-Limit-/`Retry-After`-Verhalten für Agenten.
- Keine Regressionen in Event-Delivery, Risk, Policy, Trust, Providern oder
  bestehender UI.
- OpenAPI-Schema-Validierung und ein späterer MCP-Contract-Test gegen
  `/api/v1/capabilities`.

## Abnahmekriterien für die nächste Implementierungsphase

Die nächste Phase ist erst abnahmefähig, wenn die `/api/v1`-Routen unter
Bearer-Authentifizierung laufen, alle Antworten OpenAPI-konform sind,
Agent-Tokens auf Read-Scopes begrenzt sind und die Regressionstests für
Event Backbone, Risk/Policy/Trust, Provider und Frontend erfolgreich sind.
