# Security Control Plane: Bestandsanalyse und Zielarchitektur

Status: Phase-1-Architektur, Stand 2026-09-19
Analysierter Stand: `v1.0.0`, Commit `c109824399f4865bc4598de4bd1dbfaf7b4a1d51`

## Ziel und Abgrenzung

Clawforge wird als Sicherheitsschicht über vorhandenen Routern, Firewalls,
Reverse Proxies und Plattformen ausgebaut. Die Plattform sammelt und korreliert
Sicherheitsereignisse, bewertet Risiken, verwaltet Incidents und orchestriert
kontrollierte Gegenmaßnahmen. Sie ersetzt weder Router noch klassische
Netzwerk-Firewalls.

OpenClaw bleibt außerhalb der technischen Vertrauensgrenze. Es darf über die
read-only Agent API und MCP Lagebilder lesen, Analysen formulieren und
Vorschläge erzeugen. Eine LLM-Antwort ist niemals selbst eine Policy-
Entscheidung, Freigabe oder ausführbare Firewall-Regel.

## Aktueller Bestand

Das Repository ist bereits eine Rust-/PostgreSQL-Plattform mit 16 Workspace-
Crates, 28 sqlx-Migrationen, React-Frontend und Docker-Compose-Deployment.

| Bereich | Vorhandene Bausteine | Reife für das Ziel |
| --- | --- | --- |
| Ereignisse | `events`, Consumer, Zustellung, Retry und Dead Letter | Backbone vorhanden; Security-Vertrag und Sensor-Ingress fehlen |
| Korrelation | separater Consumer, Beziehungen und Incident Candidates | vorhanden; nur wenige Infrastruktur-Eventtypen werden korreliert |
| Incidents | eigener Service, Lifecycle, Timeline und Relations | gute Basis; Security-Assessments müssen ergänzt werden |
| Risiko/Policy | `risk`- und `policy`-Crates, Trust-Abzug, Mehrquellenprinzip | Basislogik vorhanden; Regeln sind noch statisch und nicht eventorientiert |
| Threat Intelligence | ThreatFox, URLhaus, MalwareBazaar, Spamhaus sowie ASN/BGP/RPKI | vorhanden; Zusammenführung mit Sensorverhalten fehlt |
| Aktionen | Registry, Requests, Freigaben, Leases, Recovery-Metadaten | Governance-Basis vorhanden; Executor ist absichtlich Dry-Run-only |
| Connectoren | Docker, GitHub und Proxmox als bereinigte Read-Modelle | keine laufenden Security-Sensoren, keine Firewall-Adapter |
| Agenten | Agent API v1 und MCP mit Scopes, Redaction und Audit | bewusst read-only; diese Grenze bleibt erhalten |
| Betrieb | Compose, Secrets, Backup, Prometheus/Grafana, CI | solide Basis; DB-Migrationen werden in CI nicht real ausgeführt |

Die bestehenden Namen `risk`, `policy`, `correlation`, `incidents`, `executor`
und `intelligence` sind fachliche Bausteine der Zielkomponenten. Neue Services
sollen diese Crates wiederverwenden und nicht parallele Bewertungslogik
einführen.

## Heutige Datenflüsse

### Event- und Incident-Fluss

```text
Provider/Worker
    -> PostgresStore::publish_event
    -> events + event_delivery
    -> Events / Notifier / optionaler Analyzer
    -> Correlation (eigener DB-Zugriff und Delivery-Consumer)
    -> event_relationships + incident_candidates
    -> Incidents Service
    -> incidents + relations + timeline + alerts
```

Kanonische Events und Zustellzustand sind getrennt. Payload und Metadata werden
vor der Speicherung bereinigt. Zustellungen werden atomar geclaimed, begrenzt
wiederholt und nach fünf Fehlversuchen als `dead` markiert.
Neu registrierte Consumer erhalten heute keine historischen Deliveries; ein
kontrollierter Replay-Vertrag ist Teil der Zielarchitektur, nicht des Bestands.

### OpenClaw-Fluss

```text
OpenClaw -> MCP (eigener Token) -> Agent API v1 (scoped Token)
          -> redigierte Events / Incidents / Risiko / Decisions
```

MCP besitzt weder Datenbankzugang noch Write-Tools. Diese Eigenschaft ist eine
Sicherheitsinvariante und wird durch den Ausbau nicht aufgeweicht.

### Vorbereiteter Aktionsfluss

```text
Decision -> Action Registry -> Execution Request -> Approval
         -> Lease / Executor -> Dry-run Result -> Audit / Recovery-Metadaten
```

Actions sind allowlisted und standardmäßig deaktiviert. Execute- und
Destructive-Permissions sind deaktiviert. Der Executor bricht den Start ab,
wenn Dry-Run ausgeschaltet wird. Es gibt damit noch keine produktive
Firewall-Aktion.

## Festgestellte Lücken

1. Die Eventtabelle akzeptiert freie Texte für Typ, Quelle und Severity. Es
   existiert kein versionierter Security-Event-Katalog mit typspezifischer
   Validierung.
2. Es gibt keinen authentifizierten Sensor-Ingress. Der vorhandene interne
   Operational-Event-Endpunkt akzeptiert nur `backup_error` und
   `system_health_error`.
3. `is_correlatable` kennt nur Threat-, BGP-, RPKI-, ASN-, Trust- und Provider-
   Ereignisse. Die geplanten Firewall-, Auth-, SSH-, HTTP-, DNS-, Scan- und
   Containerereignisse werden noch nicht verarbeitet.
4. HAProxy-, Linux- und Docker-Sensoren existieren nicht als laufende Adapter.
   Der Docker-Connector normalisiert nur Read-Modelle.
5. Risk und Policy sind Bibliotheken mit statischen Regeln. Es fehlen ein
   persistiertes Assessment-Modell, Regelversionen, Simulation und
   entscheidungsfeste Evidence-Snapshots.
6. nftables, HAProxy und Tailscale besitzen keine ausführbaren Adapter. Ursache,
   Zielzustand, verifizierter Istzustand und konkreter Rollback sind noch nicht
   als gemeinsamer Action Receipt modelliert.
7. Der aktuelle Dashboard-Schwerpunkt ist Operations Intelligence; Live
   Security, aktive Sperren, Ablaufzeiten und Agentenentscheidungen fehlen.
8. Der reale PostgreSQL-Migrationstest ist ignoriert. Worker, Events und
   Executor haben keine eigenen Tests; das Frontend nutzt TypeScript-
   Kompilierung als einzigen Test. Der vollständige Release-Gate läuft nicht in
   CI und seine Wait-Loops besitzen keine Timeouts.
9. Intelligence Events können über einen Legacy-Pfad direkt Incidents erzeugen,
   während der neuere Pfad Event, Correlation Candidate und Incident trennt.
   Beide Wege müssen vor Security Events auf einen kanonischen Pfad
   konsolidiert werden, damit keine doppelten Incidents entstehen.
10. IP-Felder werden mit dem Analyzer-Sanitizer vor der Eventpersistenz
    anonymisiert. Der gleiche Platzhalter kann IP-Korrelation entweder zerstören
    oder unterschiedliche Adressen falsch verbinden. Kanonische, streng
    geschützte Korrelationsdaten und redigierte Read-Projektionen müssen getrennt
    werden; stabile Pseudonyme benötigen einen geheimen HMAC-Schlüssel.
11. Runtime- und Datenbank-Allowlist für Actions sind nicht synchron. Mehrere
    in Migrationen registrierte Actions werden durch die statische Policy-
    Allowlist abgelehnt.
12. API und Storage sind stark monolithisch. Security-Ingress, Events, Policy,
    Execution und Auth sollten vor wachsender Komplexität in interne Module mit
    klaren Verträgen getrennt werden.

## Priorisierte Security-Befunde

Die folgenden Befunde blockieren produktive Security- und Firewall-Aktionen:

| Priorität | Befund | Erforderliche Maßnahme |
| --- | --- | --- |
| hoch | `compose.yml` verwendet bekannte Dateien aus `secrets/*.example` als Defaults | Start ohne echte Secrets verweigern, bekannte Platzhalter ablehnen und Entropie prüfen |
| hoch | frei konfigurierbare Notifier-`secret_ref`- und Webhook-Ziele erlauben Secret-Exfiltration/SSRF | serverseitige Secret-IDs, feste Channel-Bindung, HTTPS-/Host-Allowlist, DNS/IP-/Redirect-Prüfung und Egress-Regeln |
| hoch | Events-, Notifier- und Analyzer-Tokens werden für mehrere interne Operationen gleichwertig akzeptiert | getrennte Dienstidentitäten und Scopes; Consumer serverseitig aus der Identität ableiten; Ack an Eigentümer binden |
| hoch | Approval Policies verlangen bei high/critical zwei Freigaben, der API-Pfad setzt nach einer Freigabe auf `approved` | Transition-Matrix, getrennte Approver, Separation of Duties, Ablaufzeit und gezählte Approval Records erzwingen |
| hoch | Execution-Mutation und Audit werden nicht in einer Transaktion geschrieben | Mutation, Approval, Audit/Outbox atomar und bei Auditfehler fail-closed ausführen |
| hoch | Backenddienste teilen einen voll schreibfähigen DB-Account; Auditzeilen sind änderbar | PostgreSQL-Rollen pro Dienst, minimale Rechte, append-only Audit-Writer und manipulationsnachweisbare/externe Auditkopie |
| mittel | Backups können unverschlüsselt mit zu breiten Dateirechten entstehen | `0700`/`0600`, atomische Dateien, Verschlüsselung und Integritätsprüfung |
| mittel | Proxy-Rate-Limits gruppieren Frontend-Nutzer unter der Proxy-IP | explizite Trusted Proxies und validiertes Forwarded-Parsing |
| mittel | Frontend-Logout entfernt nur den lokalen Token | serverseitigen Logout/Revocation-Endpunkt aufrufen |
| mittel | Frontend ist unnötig zusätzlich mit dem Backend-Netz verbunden | Frontend nur im Frontend-Netz betreiben |
| mittel | Build- und Laufzeitimages sind nur über Tags referenziert | Digests pinnen und Signatur/Provenance im Deployment prüfen |

Positive Grundlagen bleiben bestehen: Loopback-Bindings, internes Backend-
Netz, non-root Container, read-only Filesysteme, entfernte Capabilities,
gehashte Tokens, RBAC/Scopes, CSP, Redaction und der strikt deaktivierte
Produktivmodus des Executors.

### Evidenz und Regression der hohen Findings

| Befund | Fundstelle | Angriffsvoraussetzung/Risiko | Verlangter Regressionstest | Status |
| --- | --- | --- | --- | --- |
| Beispiel-Secrets | `compose.yml`, `secrets/*.example`, `api/src/main.rs` | erreichbare frische Installation; bekannte Credentials übernehmen Bootstrap/interne APIs | fehlende, bekannte, gleiche und zu schwache Secrets verhindern den Start | offen |
| Notifier SSRF/Secret-Exfiltration | `api/src/main.rs`, `storage/src/lib.rs`, `notifier/src/main.rs` | Admin-/API-Missbrauch konfiguriert Secret-Referenz und Angreifer-URL | fremde Secret-ID, private/link-local IP, URL-Userinfo, Redirect und DNS-Rebinding werden abgewiesen | offen |
| ungebundene Service-Tokens | `api/src/main.rs`, `storage/src/lib.rs` | gestohlener Nebenservice-Token claimt oder bestätigt eine fremde Queue | jede Identity darf nur ihren festen Consumer und erlaubte Operationen nutzen | offen |
| Approval nicht erzwungen | `migrations/0025_production_operations.sql`, `api/src/main.rs`, `storage/src/lib.rs` | einzelner/eigener Approver gibt high/critical Action frei | verschiedene Approver, kein Self-Approval, Hash-Bindung, Expiry und Transitionen | offen |
| Mutation/Audit nicht atomar | `storage/src/lib.rs`, `api/src/main.rs` | DB-/Auditfehler hinterlässt ausführbaren, unvollständig auditierten Zustand | injizierter Auditfehler rollt Mutation zurück; Outbox und State committen gemeinsam | offen |
| geteilter DB-Account/veränderbares Audit | `compose.yml`, `migrations/0001_initial.sql` | kompromittierter Dienst ändert Tokens, Policy, Execution oder Audit | Dienstrollen dürfen fremde Tabellen und Audit-UPDATE/DELETE nicht ausführen | offen |

## Zielarchitektur

```text
Internet / interne Clients
           |
Router / Reverse Proxy / bestehende Firewall
           |
HAProxy Sensor | Linux Sensor | Docker Sensor | spätere Sensoren
           |
Security Event Ingress
  AuthN/Z | Schema | Limits | Dedupe | Redaction | Clock checks
           |
Event Backbone (kanonisch, append-oriented, replay-fähig)
           |
+----------+-------------------+-------------------+
|                              |                   |
Security Engine          Threat Intelligence   Audit/Monitoring
Correlation + Risk       Reputation + Historie
|                              |
+-------------- Evidence Snapshot -------------+
                       |
                  Policy Engine
          observe | approval | automatic
                       |
               Action/Approval Queue
                       |
                 Firewall Agent
           dry-run -> execute -> verify
           nftables | HAProxy | Tailscale
                       |
           Action Receipt + Rollback + Audit

Agent API v1 -> MCP -> OpenClaw (read-only Analyse und Empfehlung)
Dashboard    -> API     (rollenbasierte Bedienung und Freigabe)
```

### Security Event Ingress

Der Ingress ist eine interne Schreibschnittstelle und gehört nicht zur
read-only Agent API. Jeder Sensor erhält eine eigene, widerrufbare Identität
mit erlaubten Quellen und Eventtypen. Ein geteilter globaler Sensor-Token ist
nicht ausreichend.

Der Sensor sendet mindestens:

- `sensor_event_id`, `event_type` und `schema_version`
- `observed_at`, `site_id`, `asset_id` und beobachtete Severity
- normalisierte `actor`, `target`, `network` und typspezifische Evidence

Der Server erzeugt `event_id` und `received_at`, leitet `sensor_id`, Site und
erlaubte Source aus Registry und Credential ab und dedupliziert über
`(sensor_id, sensor_event_id, schema_version)`. Ein Sensor darf seine kanonische
Identität oder Site nicht frei behaupten. Nur zu weit in der Zukunft liegende
Zeitstempel werden strikt abgelehnt; verspätete Events innerhalb der Retention
werden als `late` akzeptiert und metrisiert.

Der resultierende kanonische Envelope ergänzt:

- servergenerierte `event_id`, `received_at`, `sensor_id` und Source
- typspezifische, größenbegrenzte `evidence`
- optional `correlation_id` und Trace-Kontext

Die vom Sensor gelieferte Severity ist nicht vertrauenswürdig und besitzt keine
Ausführungsautorität. Security Engine und Policy leiten die wirksame Severity
serverseitig aus validierter Evidence, Provenance und gespeicherten Regeln ab.

Zulässige v1-Typen sind:

```text
firewall.connection  firewall.allow   firewall.block
auth.failed          auth.success     ssh.attack
network.scan         http.anomaly     dns.threat
container.change     system.alert
```

Unbekannte Typen, unzulässige Felder, zu große Batches, ungültige IPs oder zu
weit in der Zukunft liegende Zeitstempel werden abgewiesen und metrisiert.
Verspätete Events innerhalb der Retention werden als `late` angenommen.
Geheimnisse, vollständige Header, Cookies, Passwörter,
Authorization-Werte und ungefilterte Prozessumgebungen dürfen nicht in den Bus.
Batch-Antworten weisen pro Event `accepted` oder `rejected` aus. Die Kombination
aus Sensoridentität, Sensor-Event-ID und Schemaversion darf nie für veränderten
Inhalt wiederverwendet werden. Nonce/Sequenz, sichere Retry-Regeln und Quotas pro
Sensor, Standort und Eventklasse begrenzen Replay und Überlastung.

### Sensor Layer

- Der HAProxy-Sensor liest strukturierte Logs oder einen lokalen Syslog-Stream.
  Er sendet normalisierte Metadaten, keine vollständigen Bodies oder Cookies.
- Der Linux-Sensor liest journald/audit-nahe Quellen mit minimalen
  Leserechten. Er führt keine Shell-Kommandos aus und benötigt kein root.
- Der Docker-Sensor liest den Eventstream über einen eng begrenzten Socket-
  Proxy. Ein ungefilterter Docker-Socket im Sensorcontainer ist nicht zulässig.

Sensoren puffern begrenzt lokal, senden Batches idempotent und melden Lag,
Drops, Parse-Fehler und die letzte erfolgreiche Zustellung. Ein Sensorausfall
darf niemals als unauffällige Lage bewertet werden.

### Security Engine

`clawforge-security-engine` ist die Weiterentwicklung beziehungsweise der
kontrollierte Ersatz des heutigen `clawforge-correlation`-Dienstes. Er ist der
einzige korrelierende Event-Consumer und verwendet die bestehenden Correlation-
und Risk-Crates; es entsteht kein zweiter Incident-Pfad. Ergebnis ist ein
unveränderliches Assessment mit
Score, Confidence, Gründen, Eventreferenzen, Threat-Intel-Stand und
Engine-Version. Deterministische Regeln entscheiden; optionale LLM-Analysen
erklären nur bereits gespeicherten Kontext.

Die erste Regelgruppe umfasst SSH-Bruteforce, horizontale und vertikale Scans,
bekannte Angreifer-IP plus lokales Verhalten, HTTP-Anomalien und wiederholte
Angriffe gegen mehrere Systeme. Fenster, Schwellenwerte und Score-Beiträge sind
versioniert und per Replay testbar.

### Policy Engine

`clawforge-policy-engine` bewertet ausschließlich persistierte Evidence-
Snapshots. Jede Entscheidung enthält Regelversion, Klasse, Begründung,
Confidence, Gültigkeitsdauer und die erlaubte Action.
Der heutige Worker darf nach dieser Migration keine parallelen Policy-
Entscheidungen oder Actions erzeugen.

- `observe`: keine Aktion, aber Incident/Alert und erneute Bewertung.
- `approval`: Action Request bleibt bis zur gültigen Freigabe gesperrt.
- `automatic`: nur eng begrenzte, reversible und zeitlich befristete Aktionen.

Automatische IP-Sperren sind anfänglich nur für exakte `/32`- oder `/128`-
Ziele erlaubt, benötigen mindestens zwei unabhängige Signale, besitzen eine
TTL und dürfen weder Management-Netze noch explizite Allowlists treffen.
Breite Netze, Portschließungen, Dienstabschaltungen und Tailscale-ACL-
Änderungen benötigen eine Freigabe.

Unabhängig bedeutet unterschiedliche Trust- und Provenance-Domänen. Zwei Parser
desselben Logs oder zwei Ableitungen desselben Feeds zählen als ein Signal.
Requester und Approver sind getrennt; mehrere Freigaben stammen von
unterschiedlichen Identitäten. Eine Freigabe bindet einen unveränderlichen Hash
aus Action, Ziel, TTL, Adapter, Policy-/Evidence-Version und gerendertem Diff.
Änderung, Drift, abgelaufene Freigabe oder stale Evidence invalidieren sie.
Transitionen werden in API, Storage und Datenbank erzwungen.

### Firewall Agent

Der Firewall Agent besitzt keine freie Shell-Schnittstelle. Adapter akzeptieren
nur typisierte Commands aus einer Allowlist. Jeder Lauf folgt dem Muster:

```text
preflight -> render -> dry-run/validate -> apply -> read-back verify -> receipt
                                              -> rollback on failure
```

Ein Receipt enthält Ursache, Assessment und Policy, anfordernde Identität,
Freigaben, Zielsystem, vorherigen und gewünschten Zustand, Start/Ende,
Ergebnis, Ablaufzeit und Rollbackstatus. Idempotency Keys verhindern doppelte
Regeln. Ein Watchdog entfernt abgelaufene temporäre Sperren auch dann, wenn die
Control Plane zeitweise nicht erreichbar ist.

Der Agent verwendet eine eigene kurzlebige Identität und zieht nur signierte
oder per mTLS authentifizierte, nonce-/sequenzgebundene Commands für explizit
zugewiesene Zielsysteme. Er besitzt keine allgemeinen Datenbank-Credentials,
keinen Docker-Socket und nur die minimal nötigen OS-/Netzwerkrechte. Adapter
dürfen technisch ausschließlich Clawforge-eigene Chains, Sets oder Maps ändern.
Die nftables-Integration verwendet eine vorprovisionierte Clawforge-Chain und
ein agentverwaltetes Set; freie Änderungen an Basis-Chains sind ausgeschlossen.
Ein lokales Recovery-Journal wird vor `apply` dauerhaft geschrieben. Ein
out-of-band Kill-Switch funktioniert unabhängig von API, Datenbank und Agent.
Native TTL/Fail-safe-Expiry, Rate-, Concurrency- und Mass-block-Budgets gelten
pro Adapter und Ziel. Normalisierte Zielprüfungen schließen Clawforge selbst,
Management-, Break-glass-, Loopback-, Link-local-, Multicast-, DNS-, NTP- und
PKI-Ziele einschließlich IPv4-mapped IPv6 aus. Leader-/Lease-Regeln verhindern
Doppelanwendung in HA-Szenarien.

## Sicherheitsinvarianten

1. Deny by default: unbekannte Events, Regeln, Actions, Adapter und Ziele sind
   nicht erlaubt.
2. Kein einzelnes Signal und keine LLM-Ausgabe darf eine Sperre auslösen.
3. Agent API und MCP bleiben read-only und ohne Infrastruktur-Credentials.
4. Produktive Actions benötigen explizite Aktivierung pro Adapter, Ziel und
   Umgebung; Dry-Run bleibt der Standard.
5. Jede automatische Aktion ist klein, zeitlich begrenzt, idempotent,
   verifizierbar und rückrollbar.
6. Management- und Break-glass-Zugänge sind technisch von automatischen Regeln
   ausgeschlossen.
7. Event, Assessment, Policy Decision, Approval, Action und Resultat bilden
   eine durchgängige Auditkette.
8. Bei unvollständiger Evidence, veralteter Threat Intelligence oder fehlender
   Verifikation wird beobachtet oder eskaliert, nicht automatisch ausgeführt.
9. Dienstidentitäten, Datenbankrollen und ausgehende Netzwerkziele folgen Least
   Privilege; kein kompromittierter Nebenservice darf Policies, Executions oder
   Auditdaten beliebig verändern.

## Offene Architekturentscheidungen

Vor Phase 2 werden ADRs für folgende Punkte benötigt:

- `ADR-SCP-001` Security-Event-Schema, Versionierung und Kompatibilitätsregeln
- `ADR-SCP-002` Sensoridentität: mTLS versus kurzlebige, gehashte Tokens
- `ADR-SCP-003` Mandanten-/Standortmodell und erlaubte Zielbereiche pro Agent
- `ADR-SCP-004` nftables-Ownership und Koexistenz mit Hostverwaltung
- `ADR-SCP-005` HAProxy-Updateweg: Runtime API, Maps oder Config-Reload
- `ADR-SCP-006` Tailscale-Änderungen und Freigabepflicht
- `ADR-SCP-007` TTL, Allowlist, Break-glass und maximaler Blast-Radius
- `ADR-SCP-008` Retention, Partitionierung und Datenschutz

Alle ADRs stehen zunächst auf `proposed`. Das Phase-1-Exit-Gate verlangt den
Status `accepted`; die Entscheidungen werden vor ihrer Umsetzung als eigene
ADR-Dateien versioniert.

## Referenzen im Bestand

- Workspace und Crates: `Cargo.toml`
- Laufzeitdienste, Netze, Secrets und Hardening: `compose.yml`
- Eventtabellen und Zustellung: `migrations/0011_events.sql`
- Actions, Execution, Approval und Recovery: `migrations/0023_actions.sql` bis
  `migrations/0026_platform_hardening.sql`
- Persistenz, Event-Publish und Queues: `storage/src/lib.rs`
- HTTP-, Agent- und interne API: `api/src/main.rs`
- Correlation-Allowlist und Regeln: `correlation/src/lib.rs`
- Risk- und Policy-Basis: `risk/src/lib.rs`, `policy/src/lib.rs`
- Connector-Verträge: `connector/src/lib.rs`
- Dry-Run-Executor: `executor/src/main.rs`
- MCP-Grenze: `mcp/src/main.rs`
- CI und Release-Gates: `.github/workflows/ci.yml`,
  `scripts/test-release-validation.sh`
