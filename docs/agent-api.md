# Agent API Design

Status: Agent API v1 und Operations-Erweiterung implementiert. Dieses Dokument
beschreibt die externe Read-only-API-Schicht für OpenClaw- und MCP-Anbindungen.
Der separate MCP-Adapter verwendet diese API als einzige Datenquelle.

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
| `GET /api/v1/agents/status` | Agent-Betriebsstatus | Runtime-Komponenten, letzter erfolgreicher Agent-Zugriff und abgeleiteter Fehlerstatus | `agent:system:read` |
| `GET /api/v1/context` | konsolidierte Lageabfrage | Systemstatus, aktive Incidents, Severity, Risk-Scores, Trust-Status, wichtige Events und Correlation-Zusammenfassungen | `agent:context:read` |
| `GET /api/v1/decisions` | priorisierte read-only Lageeinschätzung | Gesamtstatus, bestehende Risikowerte, Aufmerksamkeitspunkte, empfohlene Prüfungen und Context-Zusammenfassung | `agent:decision:read` |
| `GET /api/v1/providers` | Provider-Health | Quelle, Status, letzter Erfolg/Fehler, Datenalter, Qualität und Indicator-Anzahl ohne Rohfeeds | `agent:provider:read` |
| `GET /api/v1/operations/summary` | Operations-Einstiegspunkt | Status, Risk-Level, aktive Incidents, kritische Events, Provider-Health, Attention Points und Recommended Checks | `agent:operations:read` |
| `GET /api/v1/operations/briefing` | tägliches Lagebild | Aktueller Status, aktive Incidents/Alerts, Ereignisse, Provider-Health, Änderungen und Prüfempfehlungen | `agent:operations:briefing` |
| `GET /api/v1/operations/recommendations` | Decision Engine Empfehlungen | Persistierte, erklärbare Empfehlungen mit Schweregrad, Grund, Empfehlung und Confidence | `agent:operations:recommend` |
| `GET /api/v1/decisions/history` | Decision Historie | Frühere Entscheidungen einschließlich resolved/expired ohne automatische Aktionen | `agent:operations:recommend` |
| `GET /api/v1/workflows` | Workflow-Definitionen | Aktivierte deklarative Schritte und Approval-Anforderungen | `agent:workflow:read` |
| `GET /api/v1/workflows/{id}` | Workflow-Details | Schritte, vorbereitete Runs und redigierte Audit-Historie | `agent:workflow:read` |
| `GET /api/v1/workflow-runs` | Workflow-Historie | Vorbereitete Runs, Status und Decision-Referenzen | `agent:workflow:read` |
| `GET /api/v1/connectors` | Connector Registry | Read-only externe Infrastruktur-Connectoren und Fähigkeiten | `agent:connector:read` |
| `GET /api/v1/connectors/{id}` | Connector-Details | Sanitized Metadaten ohne Credentials | `agent:connector:read` |
| `GET /api/v1/connectors/{id}/health` | Connector Health | Status, letzter Check und Latenz | `agent:connector:read` |
| `GET /api/v1/connectors/{id}/capabilities` | Connector-Fähigkeiten | Allowlisted read-only Fähigkeiten | `agent:connector:read` |
| `GET /api/v1/knowledge` | historische Erkenntnisse | Redigierte Lessons Learned, Incident-Zusammenfassungen und Muster | `agent:knowledge:read` |
| `GET /api/v1/providers/{id}/history` | Provider-Verlauf | Status, Datenalter, Qualität und Synchronisationsverlauf ohne Feed-Inhalte | `agent:provider:read` |
| `GET /api/v1/history` | historische Lagebilder | Operations-Snapshots mit Zeitbereich, Intervall und Trendvergleich | `agent:operations:read` |
| `GET /api/v1/history/summary` | historische Intelligence | Trends, Veränderungen und Auffälligkeiten nach Stunde/Tag/Woche | `agent:history:read` |
| `GET /api/v1/events` | aktuelle kanonische Events | Typ, Quelle, Severity, Zeit, Korrelation, begründete Zusammenfassung | `agent:events:read` |
| `GET /api/v1/incidents` | Incident-Liste | Status, Severity, Confidence, Risiko, Summary, Zeit, Event-Anzahl | `agent:incident:read` |
| `GET /api/v1/incidents/{id}` | Incident-Details | Status, Severity, Confidence, Risiko, Summary und Zeit | `agent:incident:read` |
| `GET /api/v1/incidents/{id}/timeline` | Incident-Timeline | Status- und Relationsereignisse, paginiert und redigiert | `agent:incident:read` |
| `GET /api/v1/incidents/{id}/relations` | Incident-Relationen | Events, Indicators und Incident-Beziehungen ohne Rohpayload | `agent:incident:read` |
| `GET /api/v1/incidents/{id}/replay` | Incident-Replay | gespeicherte Incident-Rekonstruktion und Timeline ohne Rohpayload | `agent:incident:replay` |
| `GET /api/v1/security/findings` | Security Findings | Indicator-Finding, Quelle, Confidence, Alter, Ablauf, Risk-/Trust-Werte, Reason | `agent:security:read` |
| `GET /api/v1/security/overview` | Security-Zusammenfassung | Finding-Anzahl, aktive Findings, Severity-Verteilung, höchste gespeicherte Bewertung | `agent:security:read` |
| `GET /api/v1/security/posture` | Security Posture | Findings, betroffene Komponenten, Severity-Verteilung und historische Richtung | `agent:security:read` |
| `GET /api/v1/security/briefing` | Security Briefing | aktuelle Lage, Incidents, Findings, Provider-Probleme und Unsicherheiten | `agent:security:briefing` |
| `GET /api/v1/network/asn` | ASN-Kontext | ASN, Organisation, Provider, Land, Prefixe, Netzwerktyp, Reputation, Alter | `agent:network:read` |
| `GET /api/v1/network/prefixes` | Prefix-Kontext | Prefix, ASN, Netzwerktyp, Zeit und Quelle | `agent:network:read` |
| `GET /api/v1/network/bgp` | Routing-Ereignisse | Prefix, vorherige/neue ASN, Status, Quelle, Zeit, Confidence | `agent:network:read` |
| `GET /api/v1/network/rpki` | ROA-Bewertung | Prefix, ASN, Valid/Invalid/Unknown, Quelle, Zeit, Trust-Hinweis | `agent:network:read` |
| `GET /api/v1/network/trust` | Trusted Infrastructure | Name, Typ, Identifier, Status, Zeit, Confidence und gespeicherter Trust-Wert ohne Registry-Interna | `agent:network:read` |
| `GET /api/v1/system/graph` | Systemgraph | sichere Service-, Datenbank- und Provider-Abhängigkeiten | `agent:system:graph:read` |

Die Agent-Incident-Detail-, Timeline- und Relationsrouten sind read-only. Für
einzelne Events wird weiterhin nur die normalisierte Event-Liste exportiert;
Provider-Health und Provider-Historie sind bereits Bestandteil dieses
Vertrags. Interne Capabilities-Ressourcen bleiben außerhalb von `/api/v1`.

## Eingefrorener v1-Vertrag

`/api/v1` ist der stabile Vertrag für OpenClaw und externe Agents. Innerhalb
dieser Version sind ausschließlich additive Änderungen erlaubt: neue
optionale Felder, neue Filter und neue read-only Ressourcen dürfen ergänzt
werden. Bestehende Feldnamen, Datentypen, Semantik, Statuscodes und Scope-
Anforderungen werden nicht entfernt oder stillschweigend geändert. Eine
inkompatible Änderung erhält eine neue Fassung unter `/api/v2`; die v1-Routen
bleiben während der dokumentierten Übergangszeit verfügbar.

Alle v1-Routen verwenden Bearer-Agent-Tokens. Die aktuell unterstützten
Scopes sind:

| Scope | Ressourcen |
| --- | --- |
| `agent:system:read` | `/api/v1/status` |
| `agent:events:read` | `/api/v1/events` |
| `agent:incident:read` | `/api/v1/incidents` und Detail-/Timeline-/Relationsrouten |
| `agent:security:read` | `/api/v1/security/findings`, `/security/overview`, `/security/posture` |
| `agent:network:read` | `/api/v1/network/*` einschließlich Trust |
| `agent:context:read` | `/api/v1/context` |
| `agent:decision:read` | `/api/v1/decisions` |
| `agent:provider:read` | `/api/v1/providers` |
| `agent:operations:read` | `/api/v1/operations/summary`, `/api/v1/history` |
| `agent:operations:state` | `/api/v1/operations/state`; Queue, Freigaben, Retry-/Timeout-Zustand sowie Connector- und Provider-Health |
| `agent:operations:briefing` | `/api/v1/operations/briefing` |
| `agent:operations:recommend` | `/api/v1/operations/recommendations`, `/api/v1/decisions/history` |
| `agent:workflow:read` | `/api/v1/workflows`, `/api/v1/workflows/{id}`, `/api/v1/workflow-runs` |
| `agent:workflow:approve` | Für spätere, separat geschützte Freigabeflüsse reserviert; OpenClaw erhält keine Schreibroute |
| `agent:connector:read` | `/api/v1/connectors` und Connector-Detail-, Health- und Capability-Routen; nur Lesedaten |
| `agent:action:read` | `/api/v1/actions` und Action-Details; registrierte Aktionen ohne Ausführung |
| `agent:execution:read` | `/api/v1/executions` und Execution-Details; Status und begrenzte Ergebniszusammenfassung |
| `agent:knowledge:read` | `/api/v1/knowledge` |
| `agent:history:read` | `/api/v1/history/summary` |
| `agent:incident:replay` | `/api/v1/incidents/{id}/replay` |
| `agent:security:briefing` | `/api/v1/security/briefing` |
| `agent:system:graph:read` | `/api/v1/system/graph` |
| `agent:read` | explizit erteiltes read-only Gesamtprofil |

Ein fehlender oder ungültiger Bearer-Token liefert `401`, ein gültiger Token
ohne erforderlichen Scope `403`. Ungültige Query-Parameter liefern `400`, ein
nicht vorhandenes Objekt `404`, temporär nicht verfügbare Daten `503` und ein
überschrittenes API-Limit `429` mit `Retry-After`. Jeder Zugriff wird als
redigiertes Audit-Ereignis erfasst. Erfolgsantworten verwenden weiterhin die
gemeinsame Hülle mit `status`, `data`, `timestamp`, `pagination` und `errors`.

Beispiel für einen Fehler:

```json
{
  "status": "error",
  "data": null,
  "timestamp": "2026-09-08T00:00:00Z",
  "pagination": null,
  "errors": [{ "code": "forbidden", "message": "required agent scope is missing" }]
}
```

Die OpenAPI-Datei (`docs/openapi.yaml`) ist die maschinenlesbare Quelle für
Ressourcen, Security-Schemes, Parameter und Beispiele. CI validiert sie vor
einem Release. MCP ist ein separater read-only Adapter und darf diesen
Vertrag nicht umgehen.

Die Ressourcen sind ausschließlich `GET`. Es gibt unter `/api/v1` keine
Provider-Aktivierung, manuelle Synchronisation, Trust-Änderung,
Incident-Statusänderung, Policy- oder Blockaktion.

## Connector Framework v0.8

## Controlled Operations v0.9

`GET /api/v1/actions` and `GET /api/v1/actions/{id}` expose only registered
action metadata. `GET /api/v1/executions` and `GET /api/v1/executions/{id}`
expose sanitized request state and bounded summaries. Agent tokens have no
write scope. Administrative approval and cancellation are separate protected
routes and every transition is audited; the executor accepts dry-run mode only.

Die Connector-Ressourcen liefern ausschließlich sanitisiertes Registry-,
Health- und Capability-Material. Docker, GitHub und die Proxmox-Foundation
bleiben read-only; Credentials, Secret-Referenzen und Rohdaten werden nicht
ausgegeben. Zugriffe werden auditiert und benötigen `agent:connector:read`.

## Workflow Governance v0.7

Workflows bereiten ausschließlich nachvollziehbare Schritte vor. Erlaubte
Schritttypen sind `notification`, `analysis`, `approval`, `external_check` und
`manual`; Shell-Ausführung und automatische externe Änderungen sind nicht
zulässig. Ein vorbereiteter Run kann auf `waiting_approval` stehen. Eine
Freigabe wird ausschließlich über eine intern geschützte
Administrationsroute protokolliert und setzt den Run zurück auf `pending`; sie
startet keine Ausführung.

Die administrativ geschützte Route `POST /api/v1/workflows/{id}/approve` benötigt eine
Administrator-Session oder einen Administrator-API-Token und einen `run_id`.
Agenten und MCP erhalten nur die oben genannten Read-only-Ressourcen.

### Filter und Abfragen

Listen unterstützen, soweit fachlich sinnvoll:

- `page`, `page_size` für alle Listen und Incident-Unterressourcen
- `from`, `to`
- `severity`, `source`, `status`
- `event_type` und `correlation_id` für Events
- `relation_type` für Incident-Relationen
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
    "migrations": { "current": true, "applied": 16, "expected": 16 },
    "runtime": [],
    "events": { "pending": 0, "failed": 0 },
    "providers": { "total": 0, "enabled": 0 }
  },
  "timestamp": "2026-09-08T00:00:00Z",
  "pagination": null,
  "errors": []
}
```

Die konsolidierte Lageabfrage unter `/api/v1/context` verwendet einen eigenen
Scope und liefert ausschließlich bereits bewertete, normalisierte Ausschnitte:

```json
{
  "data": {
    "system": { "status": "ok", "migrations": {}, "runtime": [] },
    "active_incidents": { "total": 1, "items": [] },
    "open_incident_severity": { "total": 1, "by_severity": { "high": 1 } },
    "risk_scores": { "total": 12, "highest": 82, "average": 31, "top": [] },
    "trust": { "total": 3, "by_status": { "Verified": 2, "Pending": 1 } },
    "important_events": [],
    "correlations": { "active_incidents": [] }
  }
}
```

`agent:context:read` gibt keinen Zugriff auf Rohpayloads, Provider-Secrets,
Trust-Registry-Interna, Candidate-IDs oder Korrelationsschlüssel. Incident- und
Event-IDs erscheinen nur als notwendige Referenzen in den bereits redigierten
Zusammenfassungen. Jeder Abruf erzeugt einen anonymisierten Audit-Eintrag.

Die read-only Decision Layer unter `/api/v1/decisions` aggregiert diesen
Context mit den bereits gespeicherten aktiven Incidents, Risk Scores,
Trust-Statuswerten und Correlation-Confidence-Werten. Sie berechnet keine neue
Risk- oder Trust-Bewertung. `overall_status` und `risk_assessment` spiegeln
vorhandene Bewertungen zusammengefasst wider; `attention_points` priorisieren
redigierte Referenzen und `recommended_checks` sind ausschließlich Hinweise
für weitere Prüfungen. Die API löst keine Aktion aus, ändert keine Policy und
vergibt keinen Trust. Jeder Abruf wird mit dem Scope
`agent:decision:read` auditiert.

Beispiel:

```json
{
  "data": {
    "overall_status": "high",
    "risk_assessment": {
      "highest_risk_score": 82,
      "risk_level": "high",
      "active_incidents": 1,
      "correlation_confidence": { "assessed": 1, "highest": 90, "average": 90, "lowest": 90 }
    },
    "attention_points": [
      { "type": "incident", "priority": "high", "incident_id": "incident-123", "reason": "active incident requires review" }
    ],
    "recommended_checks": [
      { "priority": "high", "check": "incident_timelines", "reason": "review active incident timelines and correlated events" }
    ],
    "context": { "active_incidents": {}, "risk_scores": {}, "trust": {}, "correlations": {} }
  }
}
```

Die Decision-Antwort enthält weder Rohpayloads, Secrets, Candidate-IDs noch
Korrelationsschlüssel. Sie verwendet ausschließlich die bestehenden sicheren
Agent-Views und ist vollständig read-only.

`GET /api/v1/providers` liefert den normalisierten Zustand der registrierten
Provider und internen Intelligence-Worker. `quality_score`, `data_age`,
Datenalter in Sekunden,
Synchronisationsdauer und Indicator-Anzahl stammen aus den bestehenden
Provider-Statusdaten; Feed-Inhalte und Credentials werden nie ausgegeben.

`GET /api/v1/operations/summary` ist ein kompakter Einstiegspunkt für Agents.
Er kombiniert die vorhandenen Incident-, Risk-, Trust-, Event- und
Provider-Views. Die enthaltenen `attention_points` und
`recommended_checks` sind Hinweise für weitere Leseprüfungen. Sie lösen keine
Policy-, Trust-, Provider- oder Blockaktion aus. Beide Endpunkte sind
vollständig read-only und werden pro Abruf auditiert.

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

Ein Agent-Incident enthält nur den stabilen, bereits bewerteten Kontext:

```json
{
  "id": "incident-uuid",
  "status": "investigating",
  "severity": "high",
  "confidence": 88,
  "risk_score": 72,
  "summary": "Correlated threat",
  "event_count": 2,
  "created_at": "2026-09-08T00:00:00Z",
  "updated_at": "2026-09-08T00:05:00Z"
}
```

`correlation_key`, `candidate_id`, Notiztexte, Rohpayloads und interne
Datenbankfelder werden nicht ausgegeben. Timeline- und Relationsantworten
verwenden dieselbe Hülle und Pagination; freie Operator-Notizen werden nur als
`recorded: true` signalisiert.

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
separaten Agent-Token mit einer Teilmenge seiner Leserechte ausstellen. Für
Incidents ist `agent:incident:read` der kanonische Scope. Der frühere
`agent:incidents:read` wird für bereits ausgestellte Tokens aus
Kompatibilitätsgründen weiterhin akzeptiert. Ein
Agent-Token erhält niemals Schreibrechte. Tokenwerte, IPs und Rohpayloads
werden weder geloggt noch in Audit-Details abgelegt.
Die konsolidierte Lageabfrage benötigt ausschließlich `agent:context:read`;
ihre Teilbereiche erweitern keine granularen Resource-Scopes.

`401` bedeutet fehlende oder ungültige Credentials, `403` fehlende Scopes,
`404` unbekannte Ressourcen, `429` überschrittenes Limit und `503` nicht
verfügbare PostgreSQL-/Migrationsabhängigkeit. Die bestehenden
`Retry-After`- und `X-RateLimit-*`-Header gelten auch für `/api/v1`.

## Operations Intelligence v0.5

`GET /api/v1/operations/briefing` ist der kompakte read-only Einstiegspunkt
für Tagesberichte. Er verwendet ausschließlich bereits gespeicherte
Operations Summary-, Incident-, Alert-, Event- und Provider-Daten. Die
Antwort enthält keine Rohpayloads und führt keine neue Risikoberechnung aus.

`GET /api/v1/security/posture` bündelt den aktuellen Risk-Level, aktive
Incident- und Alert-Zahlen, Provider-Zustände, den vorhandenen Policy-Status,
Trust-Zusammenfassung und den gespeicherten Trend.

`GET /api/v1/knowledge` liefert nur freigegebene Zusammenfassungen. Freie
Incident-Notizen, Rohfeeds, Korrelation-Schlüssel und Registry-Interna werden
nicht exportiert. Abgeschlossene oder gelöste Incidents können als
`incident`-Einträge persistiert werden.

`GET /api/v1/providers/{id}/history` zeigt die normalisierte Providerqualität
und Synchronisationsereignisse. Der Verlauf enthält Status, Datenalter,
Indicator-Anzahl, Laufzeit und Fehlertext, aber keine Zugangsdaten oder
Feedinhalte.

## Decision Intelligence v0.6

`GET /api/v1/operations/recommendations` liefert die offenen, persistierten
Empfehlungen der Decision Engine. Jede Empfehlung enthält einen Grund, eine
nachvollziehbare Confidence und eine reine Prüfempfehlung. Der Endpunkt führt
keine Aktion aus und verändert weder Risk-, Trust- noch Policy-Daten.

`GET /api/v1/decisions/history` stellt die gespeicherte Historie einschließlich
`acknowledged`, `dismissed`, `resolved` und `expired` bereit. Beide Endpunkte
verwenden `agent:operations:recommend`; Rohpayloads, Secrets und interne
Regelzustände werden nicht exportiert.

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

Der separate MCP-Adapter ist gegen diese validierte OpenAPI-Spezifikation
gebaut und darf ausschließlich die hier beschriebenen read-only Routen
verwenden.
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
6. **Offen:** Eine produktive OpenClaw-Verbindung muss separat konfiguriert,
   mit einem dedizierten Token versehen und anhand der MCP-Testfälle geprüft
   werden. Der MCP-Adapter selbst bleibt bereits verfügbar.

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

## Production Operations v0.10

`GET /api/v1/operations/state` liefert die read-only Lage der kontrollierten
Operations-Schicht: Warteschlange, offene Freigaben, laufende Executions sowie
Connector- und Provider-Health. Der Zugriff benötigt den Scope
`agent:operations:state`. Retry-, Timeout- und Recovery-Zustände werden nur
angezeigt; MCP erhält weiterhin keine Schreib- oder Ausführungsrechte.
