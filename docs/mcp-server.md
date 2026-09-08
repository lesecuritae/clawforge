# Clawforge MCP Server

Status: Read-only MCP-Adapter implementiert. Der MCP-Dienst ist ein isolierter
Rust-Service. OpenClaw ist noch nicht angebunden.

Dieses Dokument beschreibt einen separaten, read-only MCP-Dienst für
OpenClaw. Die Agent API v1 bleibt die einzige Datenquelle. Der MCP-Dienst
greift weder direkt auf PostgreSQL noch auf den Event Backbone, die Provider,
die Risk Engine, die Policy Engine oder die Trust Engine zu.

## Zielbild

```text
OpenClaw
   |
   | MCP / Streamable HTTP
   v
clawforge-mcp
   |
   | HTTPS/HTTP intern, Agent Bearer Token
   v
clawforge-api /api/v1
   |
   v
PostgreSQL und bestehende Intelligence-Komponenten
```

Der MCP-Dienst ist eine Protokoll- und Authentifizierungsbrücke. Er übersetzt
MCP-Tool-Aufrufe in dokumentierte `GET`-Aufrufe der Agent API und gibt deren
bereits bereinigte Antwort weiter. Er berechnet keine Scores, korreliert keine
neuen Events und führt keine Aktionen aus.

Die Agent API bleibt der einzige Upstream-Vertrag. Insbesondere werden die alten,
unversionierten `/intelligence/*`, `/network/*` und `/internal/*`-Routen nicht
als MCP-Upstream verwendet.

## Bestandsprüfung der Agent API v1

| MCP-Tool | Agent-API-v1-Upstream | Scope | Stand |
| --- | --- | --- | --- |
| `get_status` | `GET /api/v1/status` + Incident-Liste | `agent:system:read` + `agent:incident:read` | direkt nutzbar |
| `get_agent_context` | `GET /api/v1/context` | `agent:context:read` | direkt nutzbar |
| `get_decisions` | `GET /api/v1/decisions` | `agent:decision:read` | direkt nutzbar |
| `get_provider_status` | `GET /api/v1/providers` | `agent:provider:read` | direkt nutzbar |
| `get_operations_summary` | `GET /api/v1/operations/summary` | `agent:operations:read` | direkt nutzbar |
| `list_events` | `GET /api/v1/events` | `agent:events:read` | direkt nutzbar |
| `list_incidents` | `GET /api/v1/incidents` | `agent:incident:read` | direkt nutzbar |
| `get_incident` | `GET /api/v1/incidents/{id}` | `agent:incident:read` | direkt nutzbar |
| `get_incident_timeline` | `GET /api/v1/incidents/{id}/timeline` | `agent:incident:read` | direkt nutzbar |
| `get_incident_relations` | `GET /api/v1/incidents/{id}/relations` | `agent:incident:read` | direkt nutzbar |
| `get_security_overview` | `GET /api/v1/security/overview` + Incident-Liste | `agent:security:read` + `agent:incident:read` | direkt nutzbar |
| `list_security_findings` | `GET /api/v1/security/findings` | `agent:security:read` | direkt nutzbar |
| `get_trust_status` | `GET /api/v1/network/trust` | `agent:network:read` | direkt nutzbar |
| `get_network_overview` | `GET /api/v1/network/asn`, `/prefixes`, `/bgp`, `/rpki` | `agent:network:read` | deterministische Zusammenführung im Adapter |

`get_trust_status` verwendet ausschließlich den versionierten
`/api/v1/network/trust`-Vertrag. Die historische Route `/network/trust` bleibt
für MCP gesperrt.

`get_network_overview` fragt die vier vorhandenen Network-Endpunkte parallel
ab und gibt die Antworten nach Bereichen gruppiert zurück. Diese
Zusammenführung kopiert nur Daten; sie führt keine neue Bewertung oder
Priorisierung ein.

## Tool-Verträge

Alle Tools liefern strukturierte Daten aus der bestehenden
`ApiEnvelope`-Antwort. Der MCP-Server darf Felder nicht erweitern oder aus
Rohdaten ableiten. JSON-Schemas werden aus Rust-Typen mit `schemars` erzeugt
und im Tool-Vertrag versioniert.

### `get_status`

- Eingabe: keine
- Upstream: `/api/v1/status` und `/api/v1/incidents?page_size=100`
- Ausgabe: Serviceversion, Migrationsstatus, Runtime-Komponenten, Eventstatus
- Provider-Zusammenfassung und eine Incident-Übersicht mit Gesamtzahl,
  aktiven Incidents sowie Status-/Severity-Verteilung
- Erfordert `agent:system:read` und `agent:incident:read`
- Keine internen Fehlertexte, Secrets oder Zustellinformationen

### `get_agent_context`

- Eingabe: keine
- Upstream: `/api/v1/context`
- Scope: `agent:context:read`
- Ausgabe: konsolidierter Systemstatus, aktive Incidents, gespeicherte
  Risk-Scores, Trust-Status, wichtige Events und Correlation-Zusammenfassungen
- Die Antwort stammt ausschließlich aus der Agent API v1 und wird vor der
  MCP-Ausgabe zusätzlich redigiert
- Keine Rohpayloads, Secrets, Candidate-IDs oder Korrelationsschlüssel

### `get_decisions`

- Eingabe: keine
- Upstream: `/api/v1/decisions`
- Scope: `agent:decision:read`
- Ausgabe: bestehender Gesamtstatus, Risikoeinschätzung, priorisierte
  Aufmerksamkeitspunkte, empfohlene Prüfungen und die zugehörige
  Context-Zusammenfassung
- Der MCP-Dienst berechnet keine neue Bewertung und löst keine Aktion aus; er
  reicht ausschließlich die read-only Agent-API-Antwort weiter
- Keine Rohpayloads, Secrets, Candidate-IDs oder Korrelationsschlüssel

### `get_provider_status`

- Eingabe: keine
- Upstream: `/api/v1/providers`
- Scope: `agent:provider:read`
- Ausgabe: Provider-Typ und Quelle, Status, letzter Erfolg/Fehler, Datenalter,
  Qualität, Synchronisationsdauer und Indicator-Anzahl
- Feed-Inhalte, Credentials und Rohdaten werden nicht weitergereicht

### `get_operations_summary`

- Eingabe: keine
- Upstream: `/api/v1/operations/summary`
- Scope: `agent:operations:read`
- Ausgabe: Gesamtstatus, Risk-Level, aktive Incidents, kritische Events,
  Provider-Health, Attention Points und Recommended Checks
- Der MCP-Server führt keine Remediation oder Schreiboperation aus und bildet
  keine neue Risk- oder Trust-Bewertung

### `list_events`

- Eingabe: `page`, `page_size` (maximal 100), `event_type`, `source`,
  `severity`, `correlation_id`, `from`, `to`
- Upstream: `/api/v1/events`
- Ausgabe: paginierte, bereinigte Event-Ansichten
- `payload`, `metadata`, Zustellstatus und interne Consumer-Daten bleiben
  ausgeschlossen

### `list_incidents`

- Eingabe: `page`, `page_size`, `status`, `severity`, `from`, `to`
- Upstream: `/api/v1/incidents`
- Ausgabe: Status, Severity, Confidence, Risiko, Summary, Zeit und
  Eventanzahl; die Agent-API redigiert interne Korrelation und Rohdaten

### `get_incident`

- Eingabe: `id` als Incident-UUID
- Upstream: `/api/v1/incidents/{id}`
- Ausgabe: der sichere, bereits bewertete Incident-Kontext ohne Candidate-ID,
  Korrelation, Notizen oder Rohpayload

### `get_incident_timeline`

- Eingabe: `id`, `page`, `page_size`, `status`, `severity`, `from`, `to`
- Upstream: `/api/v1/incidents/{id}/timeline`
- Ausgabe: paginierte Status- und Relationsereignisse; freie Notiztexte werden
  nicht weitergereicht

### `get_incident_relations`

- Eingabe: `id`, `page`, `page_size`, `relation_type`, `severity`, `from`, `to`
- Upstream: `/api/v1/incidents/{id}/relations`
- Ausgabe: normalisierte Event-, Indicator- und Incident-Beziehungen ohne
  Rohpayloads oder interne Datenbankfelder

### `get_security_overview`

- Eingabe: keine
- Upstream: `/api/v1/security/overview` und `/api/v1/incidents?page_size=100`
- Ausgabe: bereits gespeicherte Finding-Anzahlen und Severity-Verteilung sowie
  dieselbe sichere Incident-Übersicht wie `get_status`
- Erfordert `agent:security:read` und `agent:incident:read`
- Der MCP-Dienst berechnet keinen neuen Risk Score

### `list_security_findings`

- Eingabe: `page`, `page_size`, `source`, `severity`, `confidence_min`,
  `active`, `from`, `to`
- Upstream: `/api/v1/security/findings`
- Ausgabe: normalisierte Findings mit Quelle, Confidence, Alter, Ablauf,
  Risk-/Trust-Werten und Begründung

### `get_trust_status`

- Eingabe: optionaler Status- oder Typfilter
- Upstream: `/api/v1/network/trust`
- Ausgabe: Verified-, Pending- und Revoked-Netzwerke ohne Änderungsaktion
- Keine Trust-Vergabe und kein Statuswechsel über MCP

### `get_network_overview`

- Eingabe: optional `asn`, `prefix`, `rpki_status`, `from`, `to`,
  `page_size`
- Upstream: ASN-, Prefix-, BGP- und RPKI-Endpunkte der Agent API v1
- Ausgabe: `{ asn, prefixes, bgp, rpki }` mit Quelle, Zeit, Alter und bereits
  gespeicherter Bewertung
- Bei einem Upstream-Fehler wird kein unvollständiger Erfolg verschleiert;
  der Tool-Aufruf liefert einen strukturierten temporären Fehler

Keines der Tools unterstützt `POST`, `PUT`, `PATCH`, `DELETE`, Provider-
Aktivierung, Policy-Änderungen, Incident-Statusänderungen oder Blockaktionen.

## Produktionsvertrag und OpenClaw-Vorbereitung

Der MCP-Server ist ein stateless read-only Adapter. Alle 14 Tools verwenden
die versionierte Agent API v1 als einzige Datenquelle; es gibt keine direkte
PostgreSQL-, Event-Backbone- oder Worker-Verbindung. Upstream-Aufrufe haben
ein konfigurierbares Timeout (`CLAWFORGE_MCP_UPSTREAM_TIMEOUT_SECONDS`,
Standard 15 Sekunden). Netzwerk-, HTTP- und JSON-Fehler werden in eine
strukturierte, redigierte MCP-Fehlermeldung übersetzt; Upstream-Body,
Credentials und interne Stacktraces werden nicht weitergegeben.

Jedes Tool hat ein explizites Read-Scope. Der MCP-Eingang wird mit einem
separaten MCP-Token geschützt; das ausgehende Agent-API-Token wird nur über
Docker Secret oder Environment-Datei injiziert. Kein Token wird geloggt oder
in PostgreSQL gespeichert. Die zulässigen Scopes und die Zuordnung zu den
Tools sind in der Tabelle oben und in `docs/agent-api.md` eingefroren.

### OpenClaw-Testplan (noch keine produktive Verbindung)

1. MCP-Endpunkt intern auf `http://clawforge-mcp:8090/mcp` auflösen.
2. MCP-Token und Agent-API-Token als getrennte Secrets bereitstellen.
3. Nur `agent:system:read`, `agent:events:read`,
   `agent:incident:read`, `agent:security:read`, `agent:network:read`,
   `agent:context:read`, `agent:decision:read`, `agent:operations:read` und
   `agent:provider:read` erteilen, soweit das Agent-Profil es benötigt.
4. Tools auflisten und für jedes Tool einen erfolgreichen Read-Aufruf prüfen.
5. Fehlender Token, falscher Scope, abgelaufener/widerrufener Token,
   Upstream-Timeout und `401`/`429`/`5xx` testen.
6. Sicherstellen, dass Antworten keine Secrets, Rohpayloads, Candidate-IDs,
   Korrelationsschlüssel oder internen Zustellinformationen enthalten.

OpenClaw-Konfigurationsdateien werden in dieser Phase nicht geändert. Eine
spätere Verbindung muss den MCP-Token rotieren können, ohne das
Agent-API-Credential zu ändern.

## Sprache und SDK

Der MCP-Dienst ist in Rust als eigenes Workspace-Mitglied umgesetzt. Das passt
zu Tokio, Axum, `reqwest`, den vorhandenen Secret-Konventionen und den
bestehenden Build-/Clippy-Prüfungen. Die API bleibt ein eigenständiger Prozess;
es wird keine MCP-Schicht in `api/src/main.rs` eingebaut.

Als SDK wird das offizielle Rust-SDK `rmcp` verwendet. Die aktuelle
Dokumentation führt Server-Tools, Makros, JSON-Schema-Erzeugung und
Streamable-HTTP-Transport als getrennte Features. `rmcp` ist auf die
veröffentlichte Version 3.2.0 gepinnt; der Client-Transport wird zusätzlich
für die Protokolltests verwendet.

Vorgesehene Features:

- `server`
- `macros`
- `schemars`
- `transport-streamable-http-server`
- `client`
- `transport-streamable-http-client-reqwest`
- `reqwest` für den ausgehenden Agent-API-Client

`auth` wird nur aktiviert, wenn der MCP-Dienst selbst den standardisierten
OAuth-HTTP-Fluss übernimmt. Für die erste interne Installation ist ein
separater, kurzlebiger MCP-Zugang über Docker Secret möglich; die
Upstream-Agent-Credentials bleiben davon getrennt.

Referenzen:

- [offizielles Rust-SDK `rmcp`](https://github.com/modelcontextprotocol/rust-sdk)
- [`rmcp` API und Feature-Übersicht](https://docs.rs/rmcp/latest/rmcp/)
- [MCP HTTP Authorization Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)

## Authentifizierungsfluss

Der eingehende OpenClaw-Zugang und das ausgehende Agent-API-Credential sind
zwei verschiedene Geheimnisse:

1. OpenClaw verbindet sich mit dem MCP-Endpunkt und authentifiziert sich mit
   einem MCP-eigenen Credential. Das Credential wird nicht an Clawforge API
   weitergereicht.
2. Der MCP-Dienst prüft das Credential und ordnet dem Aufruf die gleichen
   Scope-Namen wie der Agent API zu. Ein Tool wird vor jedem Upstream-Aufruf
   gegen seinen Mindest-Scope geprüft.
3. Der MCP-Dienst ruft die Agent API mit einem separaten, vom Administrator
   ausgestellten Agent-Token auf. Dieses Token wird nur als Docker Secret in
   den MCP-Container injiziert.
4. Die Agent API validiert Hash, Ablauf, Widerruf und Scope erneut, wendet ihre
   Rate Limits an und erzeugt den bestehenden Audit-Eintrag
   `agent_api_read`.
5. Der MCP-Dienst gibt nur die bereinigte `data`-Antwort und die notwendige
   Pagination bzw. einen strukturierten Fehler an OpenClaw zurück.

Damit bleiben Token-Audience und Berechtigungsgrenzen getrennt. Ein MCP-
Clienttoken kann nicht als Agent-API-Token missbraucht werden. Tokenwerte,
Authorization-Header und sensible Tool-Eingaben werden weder geloggt noch in
MCP-Tool-Ergebnissen gespeichert.

### Transportentscheidung

Für den eigenständigen Container ist Streamable HTTP der primäre Transport.
Der Endpunkt bleibt im internen Docker-Netzwerk; eine externe Veröffentlichung
erfolgt nur über einen TLS-terminierenden Reverse Proxy. Ein optionaler
Stdio-Modus kann später für einen lokal gestarteten OpenClaw-Prozess ergänzt
werden, ist aber kein zweiter Datenpfad.

Bei HTTP-Authorization muss die MCP-Spezifikation beachtet werden: Der Server
benötigt Protected-Resource-Metadata, `WWW-Authenticate` bei `401`,
Audience-Prüfung und Bearer-Token in jedem Request. Dynamic Client
Registration und ein vollständiger OAuth-Authorization-Server sind für die
erste interne Bereitstellung nicht automatisch erforderlich; falls ein
öffentlicher HTTP-Endpunkt entsteht, muss diese Entscheidung erneut geprüft
und dokumentiert werden.

## Docker- und Laufzeitplanung

Implementierte Struktur:

```text
mcp/
  Cargo.toml
  src/main.rs
```

Compose-Service:

```yaml
  clawforge-mcp:
    build:
      context: .
      dockerfile: docker/Dockerfile
    environment:
      CLAWFORGE_AGENT_API_URL: http://clawforge-api:8080
      CLAWFORGE_MCP_BIND: 0.0.0.0:8090
      CLAWFORGE_MCP_AGENT_TOKEN_FILE: /run/secrets/mcp_agent_api_token
      CLAWFORGE_MCP_AUTH_TOKEN_FILE: /run/secrets/mcp_auth_token
    depends_on:
      clawforge-api:
        condition: service_healthy
    secrets:
      - mcp_agent_api_token
      - mcp_auth_token
    networks:
      - backend
```

Der Dienst erhält keine `DATABASE_URL`, keinen PostgreSQL-Port, keine
Provider-Secrets und keinen Zugriff auf den Docker Socket. Er läuft als
non-root, mit Read-only-Dateisystem, `cap_drop: [ALL]`,
`no-new-privileges` und begrenztem `/tmp`. Der Healthcheck prüft nur Prozess
und interne Konfiguration; ein MCP-Tool-Aufruf ist kein Healthcheck.

Das Agent-API-Token wird über die vorhandene Admin-Verwaltung mit den
minimalen Scopes ausgestellt. Für mehrere OpenClaw-Installationen wird ein
separates Upstream-Token je MCP-Instanz verwendet. Secrets werden nicht in
Compose-Dateien, Images, Logs oder PostgreSQL abgelegt.

## Fehler- und Observability-Vertrag

- Upstream `401`: MCP-Credential oder konfigurierte Upstream-Credentials sind
  ungültig; keine Wiederholung ohne Credential-Änderung.
- Upstream `403`: Tool-Scope fehlt; als Berechtigungsfehler zurückgeben.
- Upstream `429`: als temporären MCP-Fehler mit der Statusklasse zurückgeben;
  Wiederholungen bleiben dem Agent-API-Client bzw. dem aufrufenden Agenten
  überlassen.
- Upstream `5xx`, Timeout oder Netzwerkfehler: temporären Tool-Fehler ohne
  interne URL, SQL-Fehler oder Secret-Inhalt zurückgeben.
- `get_network_overview`: ein Teilfehler führt zu einem Fehlerstatus oder
  ausdrücklich markiertem Teilresultat nach einem vorab festgelegten Vertrag;
  ein stillschweigend unvollständiges Netzwerkbild ist nicht zulässig.

MCP-Aufrufe erhalten nur nicht-sensitive Metriken wie Toolname, Ergebnisstatus,
Dauer und Upstream-Statusklasse. Agent-API-Audits bleiben die maßgebliche
fachliche Zugriffsspur.

## Implementierung und Betrieb

1. Das Crate `mcp/` nutzt `rmcp` mit Streamable HTTP und registriert genau die
   zehn read-only Tools.
2. Der Upstream-Client liest getrennte Agent-API- und MCP-Credentials aus
   Docker Secrets, validiert die Agent-API-Envelope und setzt Timeouts.
3. Die Compose-Datei startet `clawforge-mcp` intern auf Port 8090. Der Dienst
   erhält weder Datenbank- noch Provider-Zugangsdaten.
4. `GET /health` ist ein lokaler Prozess-Healthcheck; MCP-Verbindungen laufen
   über `POST /mcp` und benötigen den MCP-Bearer-Token.
5. Scope-Prüfungen werden vor jedem Agent-API-Aufruf ausgeführt. Die Agent API
   validiert das separate Upstream-Token anschließend erneut.
6. OpenClaw-Konfiguration und öffentliche Exponierung sind ausdrücklich nicht
   Bestandteil dieser Phase.

## Tests

- `tools/list` enthält genau die zehn read-only Tools.
- Incident-Tools rufen ausschließlich die vier versionierten Incident-
  Endpunkte der Agent API auf und akzeptieren den kanonischen Scope
  `agent:incident:read` (der alte Plural bleibt kompatibel).
- `get_status` und `get_security_overview` ergänzen nur die aus der Agent API
  gelesene Incident-Übersicht; sie ändern keine Bewertung und speichern keine
  zusätzlichen Daten.
- Jeder Tool-Aufruf verwendet ausschließlich `GET /api/v1`.
- Fehlende und falsche MCP-Credentials werden abgewiesen.
- Fehlende MCP-Scopes werden vor dem Upstream-Aufruf verweigert; Ablauf und
  Widerruf des separaten Agent-Tokens werden durch die Agent API geprüft.
- Eingangs- und Upstream-Token werden nie geloggt oder als Tool-Ergebnis
  ausgegeben.
- Event-`payload`/`metadata`, Provider-Secrets und interne Zustellfelder
  bleiben entfernt.
- Pagination, Filter, leere Daten und große Antworten bleiben begrenzt.
- Upstream-Timeout, `429`, `401`, `403` und `5xx` werden deterministisch
  abgebildet.
- `get_network_overview` testet parallele Abfragen und Teilfehler.
- Docker-Build läuft ohne Datenbank- oder Provider-Secrets im Image.
- Compose-Healthcheck startet erst nach gesunder Agent API.
- Es existieren keine schreibenden MCP-Tools und keine Policy-/Risk-/Trust-
  Änderungen.

## Nicht Bestandteil dieser Phase

- keine Änderung an `api/src/main.rs`
- keine neue Migration
- keine Änderung an Risk, Policy, Trust, Providern oder Event Backbone
- kein direkter Storage-Zugriff des MCP-Dienstes
- kein LLM-, Prompt-, Sampling- oder Blockierungsmechanismus
- keine öffentliche OAuth-Infrastruktur ohne separate Sicherheitsprüfung
