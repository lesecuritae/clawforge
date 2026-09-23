# Roadmap zur Security Control Plane

Status: Umsetzungsplan nach Phase-1-Analyse, Stand 2026-09-19

Diese Roadmap baut auf Clawforge v1.0.0 auf. Sie ersetzt die bestehende
v1-Roadmap nicht, sondern konkretisiert den Ausbau nach v1.0. Jede Phase endet
mit Analyse, Plan, Umsetzung, Tests, Security-/Code-Review und einem
eigenständigen Commit. Phase 6 bleibt Dry-Run und Lab. Ein manueller
Produktions-Canary ist frühestens nach Gate 7A zulässig; automatische Aktionen
benötigen weitere getrennte Gates.

## Querschnittliche Definition of Done

Für jede Phase gelten mindestens:

- versionierter Daten- oder API-Vertrag und rückwärtskompatible Migration
- Unit-, Integrations- und Negativtests für Authentifizierung, Grenzen und
  Fehlerpfade
- Redaction, Rate Limits, Audit und Prometheus-Metriken
- Compose-/Deployment-Dokumentation ohne Secrets im Repository
- Threat-Model-Update und Review der Berechtigungen
- getesteter Upgradepfad; bei Datenbankschemata kompatibler Binary-Rollback und
  DB-Restore-Test, bei externen Actions ein eigener Action-Rollbacktest
- keine automatische Aktion aus einem einzelnen Signal oder einer LLM-Ausgabe

## Phase 1: Bestandsanalyse

Status: Analyse dokumentiert; Exit-Gate offen.

Ergebnisse:

- Architektur, Datenflüsse, Grenzen und Lücken sind in
  `security-control-plane-architecture.de.md` beschrieben.
- Auf Commit `c109824` mit Rust `1.98.1` bestehen
  `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings` und
  `cargo test --workspace` mit 86 bestandenen und einem ignorierten
  PostgreSQL-Test. `npm ci`, `npm test`, `npm run build`,
  `npm audit --omit=dev --audit-level=high` sowie Compose mit und ohne
  Observability-Profil bestehen ebenfalls.
- Der reale PostgreSQL-Test bleibt ignoriert; UI-, Worker- und Executor-
  Testabdeckung muss vor produktiver Ausführung geschlossen werden.

Exit-Gate: Architektur und Roadmap reviewed; die offenen ADRs für Eventvertrag,
Sensoridentität und Firewall-Ownership sind als `accepted` versioniert.

### Phase 1a: Sicherheits- und Bestandsbereinigung

Diese Stufe ist ein Stop-Gate vor neuen Ingress-Endpunkten:

1. Beispiel-Secrets aus produktiven Compose-Defaults entfernen und bekannte
   Platzhalter beim Start ablehnen. Interne Tokens müssen voneinander
   verschieden, ausreichend lang und mit restriktiven Dateirechten gespeichert
   sein; Bootstrap-Secrets werden nach Initialisierung entfernt oder rotiert.
2. Notifier-Secrets an registrierte Channels binden und Webhooks gegen SSRF,
   Redirects und unerlaubte Egress-Ziele absichern.
3. interne Tokens auf Dienst, Operation und festen Consumer begrenzen.
4. High-/Critical-Approval mit unterschiedlichen Approvern und gültiger
   Transition-Matrix tatsächlich erzwingen.
5. Execution, Approval und Audit/Outbox atomar schreiben.
6. Datenbankrollen pro Dienst und eine nicht änderbare Audit-Schreibgrenze
   einführen.
7. Legacy-Direktkorrelation auf den Candidate-/Incident-Pfad migrieren und
   Action-Allowlist aus Code und Datenbank konsolidieren.
8. geschützte kanonische IP-Korrelationswerte von redigierten API-/MCP-
   Projektionen trennen und Retention festlegen.
9. PostgreSQL-Integrationstest als CI-Service ausführen; RustSec mit einer
   dokumentierten, engen Ausnahme statt globalem `continue-on-error` blockieren.
10. Backups mit sicheren Rechten, Verschlüsselung und Integritätsprüfung
    erstellen; Trusted-Proxy-Verarbeitung und serverseitigen Logout korrigieren.
11. Frontend aus dem Backend-Netz entfernen und produktive Images per Digest
    mit Signatur-/Provenance-Prüfung pinnen.

Exit-Gate: alle hohen Findings sind behoben und negativ getestet; Upgrade von
v1.0.0, Restart/Persistenz, Downgrade-Guard und Audit-Atomizität bestehen in CI.

## Phase 2: Security Event Layer

Ziel: ein stabiler, abgesicherter Vertrag für Security-Sensoren.

Arbeitspakete:

1. Eigenes Domain-Crate für Eventtypen, Envelope, Severity, Source und
   typspezifische Evidence einführen.
2. Migration für Schema-Version, serverseitige Empfangszeit, Sensoridentität
   und validierte Eventklassen erstellen. Bestehende Events bleiben lesbar.
3. Authentifizierten internen Batch-Ingress mit Quellbindung, Größenlimit,
   Idempotenz, Clock-Skew-Prüfung, Nonce/Sequenz und eindeutiger
   Teilfehlerantwort implementieren. Dedupe Keys sind sensor-scoped und dürfen
   bei gleichem Schlüssel keinen abweichenden Inhalt akzeptieren.
4. Sensor-Registry, gehashte Credentials, Rotation, Widerruf und Audit ergänzen.
5. OpenAPI-/Event-Dokumentation, Test-Fixtures und Contract-Tests hinzufügen.
6. Correlation-Allowlist um die elf Security-Eventtypen erweitern, ohne bereits
   automatische Aktionen auszulösen.
7. autorisierten Backfill/Rebuild mit Checkpoint, Watermark, Late-Arrival-
   Semantik und getrenntem Replay-Namespace einführen. Replay erzeugt weder
   Notifications, Actions noch doppelte Incidents.

Tests: alle Eventtypen, unbekannte Typen/Felder, ungültige IPs und Zeitwerte,
Oversize, Dedupe, Replay, Credential-Isolation, Rotation, Rate Limit, Redaction,
Dead Letter sowie PostgreSQL-Neuinstallation und Upgrade von v1.0.0.

Exit-Gate: Vor Phasenstart werden Last und Fehlerbudget festgelegt. Die
Eventbilanz erfüllt bei Fixture, Retry und Backfill jederzeit
`input = accepted + rejected + explicit_drop`; kein ungültiges oder nicht
autorisiertes Event erreicht das Backbone und Replay hat keine Seiteneffekte.

## Phase 3: Sensor Layer

Ziel: drei minimal privilegierte, beobachtbare Sensoren.

Reihenfolge:

1. Linux-Sensor für SSH-/Auth- und Systemereignisse.
2. HAProxy-Sensor für Request-Metadaten, Fehlercodes, Rate-Limit- und
   Anomaliesignale.
3. Docker-Sensor für Lifecycle, Image-, Port- und Netzänderungen.

Jeder Sensor besitzt Parser-Fixtures, Cursor/Checkpoint, begrenzten Puffer,
Backpressure, Dedupe, Health, Lag- und Drop-Metriken. Docker-Zugriff erfolgt nur
über eine read-only Proxy-Allowlist; Linux benötigt kein root; HAProxy-Payloads
enthalten keine Bodies, Cookies oder Authorization-Header.

Exit-Gate: 24-Stunden-Soak-Test mit vorab festgelegter Burst-Last, Neustart,
Netzunterbrechung und Logrotation; die Eventbilanz ist vollständig,
`explicit_drop` bleibt im genehmigten Budget und es entstehen keine doppelten
Incidents.

## Phase 4: Security Engine

Ziel: reproduzierbare Correlation und Risikobewertung.

Arbeitspakete:

- den heutigen Correlation-Service zu `clawforge-security-engine` migrieren
  oder durch ihn ersetzen; genau ein Service korreliert kanonische Events und
  bestehende Correlation-/Risk-Crates werden wiederverwendet.
- Assessments, Evidence-Referenzen und Engine-/Regelversion persistieren.
- Regeln für SSH-Bruteforce, Scans, Multi-Target-Angriffe, HTTP-Anomalien sowie
  Threat-Intel-plus-Verhalten implementieren.
- minimale Provenance-, Freshness-, Confidence- und Konfliktregeln für alle
  verwendeten Threat-Intel-Signale implementieren; stale/unklare Daten dürfen
  keine automatische Klasse erreichen.
- Incident-Erzeugung und Score-Änderungen idempotent und replay-fähig machen.
- Goldene Angriffsszenarien sowie False-positive-/False-negative-Fixtures
  aufnehmen.

Exit-Gate: gleiche Events und Regelversion erzeugen deterministisch dasselbe
Assessment; Backfill/Replay erzeugt keine Notifications, Actions oder doppelten
Incidents; ein einzelnes Signal erreicht nie eine Block-Entscheidung.

## Phase 5: Policy Engine

Ziel: versionierte Regeln mit explizitem Entscheidungsweg.

Arbeitspakete:

- persistierte Policy-Versionen, Status, Gültigkeit und Simulation ergänzen
- Klassen `observe`, `approval` und `automatic` abbilden
- Evidence Snapshot, Allowlist, Zielbereich, TTL und Blast Radius prüfen
- Zwei-Personen-Freigabe für high/critical gegen vorhandene Approval-
  Infrastruktur durchsetzen
- Freigabe an den unveränderlichen Hash von Action, Ziel, TTL, Adapter,
  gerendertem Diff und Policy-/Evidence-Version binden; Drift invalidiert sie
- Shadow Evaluation und Entscheidungserklärung bereitstellen

Exit-Gate: mindestens zwei Wochen Shadow Mode gegen ein vorab festgelegtes
Goldkorpus und eine genehmigte False-positive-Grenze; Policies können gegen
historische Incidents replayed werden; keine Action wird produktiv ausgeführt.

## Phase 6: Firewall Action Layer

Ziel: sichere Ausführungsplattform, zunächst vollständig im Dry-Run.

Arbeitspakete:

- `clawforge-firewall-agent` mit typisiertem Adaptervertrag erstellen
- Action Receipt, Preflight, Istzustand, Verification, TTL und konkreten
  Rollback persistieren
- Idempotency, Lease, Retry, Timeout und Recovery des vorhandenen Executors
  integrieren
- nftables-Adapter mit exklusiver Clawforge-Tabelle/-Chain implementieren
  und ausschließlich ein vorprovisioniertes Set verwalten lassen
- HAProxy-Adapter für Maps/ACLs und Rate-Limits implementieren
- Tailscale zunächst nur als freigabepflichtigen Adapter vorbereiten

Pflichtgates vor der ersten verändernden Lab-Testaktion:

- PostgreSQL-Migrationstest läuft in CI und ist nicht ignoriert
- Executor besitzt Unit-, Crash-/Restart-, Idempotency- und Rollbacktests
- Action API und Adapter bestehen Fuzz-/Negativtests und Command-Injection-
  Review; es existiert keine freie Shell
- isoliertes Netzwerk-Lab bestätigt, dass Allowlist und Managementzugang nicht
  gesperrt werden können
- Break-glass-Verfahren und manuelles Entfernen aller Clawforge-Regeln sind
  dokumentiert und geprobt
- Failure-Injection deckt Prozess-/Host-/DB-Ausfall zwischen Intent, Apply,
  Receipt und Audit, Lease-Verlust, Reboot, Uhrsprung, konkurrierende Actions,
  abgelaufene TTL, manuelle Drift und fehlgeschlagenes Read-back ab
- vor `apply` existiert immer ein persistierter Intent und ein lokales
  Recovery-Journal
- Desired/Actual State, TTL, Drift, Kill-Switch und vollständige Audit-Lineage
  sind vor einem Produktionspilot über ein geprüftes Admin-Werkzeug sichtbar
- pro Adapter/Ziel gelten getestete Rate-, Concurrency- und Mass-block-Budgets;
  Zielnormalisierung und technische Ausschlusslisten decken IPv4, IPv6, CIDR
  und IPv4-mapped IPv6 ab
- HA-/Leader-/Lease-Tests beweisen, dass dieselbe Action nicht doppelt greift;
  Rollback-p95, Drift-Erkennungszeit und erlaubte verwaiste Regeln (`0`) werden
  vor dem Labtest quantifiziert

Exit-Gate A: Dry-Run rendert und validiert Regeln, verändert aber nichts.
Exit-Gate B: zeitlich befristete Einzel-IP-Sperre nur im Lab, mit Read-back und
erfolgreichem automatischem Rollback. Produktion bleibt deaktiviert.

## Phase 7: HAProxy/nftables Pilot

Ziel: begrenzter Pilot mit messbarer Sicherheit und kleinem Blast Radius.

Vor Phasenstart werden Pilotdauer, Canary-Anzahl, False-positive-Budget,
Rollback-p95, Drift-Erkennungszeit, Lockout-SLO und maximale Blockanzahl
quantifiziert und durch Security Review genehmigt.

- vor Gate 7A existiert eine geprüfte Approval-Oberfläche, die unveränderlichen
  Action-Diff, Evidence und Alter, Ziel/Blast Radius, Istzustand, TTL,
  Rollbackplan und alle Freigaben zeigt
- Gate 7A: manuell freigegebener Produktions-Canary für `/32`/`/128` mit kurzer
  TTL; noch keine automatische Sperre
- Gate 7B: definierte Pilotdauer, eingehaltene Rollback-/Lockout-SLOs und
  formale Security-Freigabe
- Gate 7C: genau eine eng definierte automatische Bruteforce- oder Scanner-
  Regel; nur mit frischer, nachvollziehbarer Provenance und voneinander
  unabhängigen Signalen
- Gate 7D: Erweiterung erst nach erneutem False-positive-, Lockout- und
  Rollback-Review
- Canary-Ziel, Parallelbeobachtung und automatische Deaktivierung bei
  Verification-, Health- oder Telemetriefehlern
- regelmäßiger Abgleich gewünschter, angewandter und abgelaufener Regeln

Veraltete, widersprüchliche oder nicht ausreichend unabhängige Threat-
Intelligence ergibt höchstens `observe` oder `approval`, niemals `automatic`.

## Phase 8: Threat Intelligence

Ziel: die vor Gate 7C verpflichtenden Mindestprüfungen vertiefen und externe
Reputation, lokales Verhalten und Historie nachvollziehbar zusammenführen.

- vorhandene Provider um Freshness, Provenance und Confidence pro Assessment
  ergänzen
- lokale IP-/ASN-/Angriffshistorie als zeitlich abklingendes Signal verwenden
- Konflikte, Ausfälle und veraltete Feeds sichtbar machen
- Datenschutz und Aufbewahrung für Identifikatoren festlegen

Exit-Gate: Offline- oder veraltete Feeds reduzieren Confidence und lösen keine
automatische Eskalation aus; jede Score-Komponente bleibt erklärbar.

## Phase 9: Dashboard

Ziel: operative Sicht und sichere Bedienung.

Ansichten:

- Live Security mit Angriffen, Assessments und Incidents
- Firewall Status mit Desired/Actual State, Sperren, TTL und Drift
- Agentenentscheidungen mit Analyse, Empfehlung, Policy und Resultat
- durchgängige Auditkette vom Event bis zum Rollback

Vor Abschluss werden Component- und Browser-E2E-Tests ergänzt; TypeScript-
Kompilierung allein reicht nicht als Frontend-Test.

Exit-Gate: Operatoren können Entscheidungen nachvollziehen, Freigaben getrennt
erteilen und Rollbacks verfolgen, ohne Rohsecrets oder unbereinigte Payloads zu
sehen.

## Phase 10: OpenClaw Security Integration

Ziel: Analyse und Berichte ohne neue Ausführungsprivilegien.

- bestehende read-only MCP-Grenze beibehalten
- Ressourcen für Assessment, Policy Decision, Action Receipt und Firewall-
  Status ergänzen
- OpenClaw erzeugt Zusammenfassungen, Handlungsvorschläge und Berichte
- Modellrouting ist datenklassifiziert: freie Remote-Modelle nur für
  unkritische bereinigte Aufgaben, lokale Modelle für interne Logs, Spezialisten
  für kritische Architektur, Fehleranalyse und Final Review

Exit-Gate: Scope-, Redaction-, Prompt-Injection- und Exfiltrationstests; OpenClaw
kann weder freigeben noch ausführen und besitzt keine Firewall-Credentials.

## Phase 11: Quarantäne

Ziel: spätere, streng freigabepflichtige Isolation von Containern/VMs.

Reihenfolge: Snapshot vorbereiten, Netzplan validieren, Freigabe einholen,
isolieren, Zustand verifizieren, analysieren, freigeben oder wiederherstellen.
Docker- und Proxmox-Aktionen bleiben getrennte Adapter. Automatische Quarantäne
ist nicht Teil der ersten Implementierung.

Exit-Gate: ausschließlich im Lab nachgewiesener End-to-End-Restore, klare
Dateneigentümerschaft und zwei-Personen-Freigabe.

## Empfohlene erste Pull Requests

1. `deployment-secret-hardening` (umgesetzt): Beispiel-Secrets entkoppeln,
   Placeholder-Erkennung und sichere Backup-Rechte.
2. `internal-identity-hardening` (umgesetzt): Dienst-/Consumer-Bindung und
   Notifier-Egress-Schutz.
3. `approval-audit-integrity` (umgesetzt): Approval-State-Machine, atomare
   Audit-Outbox und PostgreSQL-Integrationstest in CI.
4. `database-least-privilege` (umgesetzt): eigener Migrationsjob, getrennte
   Laufzeitrollen und PostgreSQL-Negativtests für fremde Tabellen und Audit.
5. `incident-correlation-convergence` (umgesetzt): Legacy-Pfad
   (`correlate_incident`) entfernt, Kandidat-/Promotion-Pfad um Solo-
   Kandidaten, Alert-Backfill und Re-Eskalation bereits promoteter
   Kandidaten ergänzt; IP-Korrelation von Read-Redaction getrennt durch ein
   geheimes HMAC-Pseudonym (`CLAWFORGE_ANALYZER_IP_HMAC_KEY`) statt des
   alten, IPs kollabierenden Platzhalters, fail-closed ohne konfigurierten
   Schlüssel.
6. `security-events-domain` (umgesetzt): neues, eigenständiges Crate
   `clawforge-security-events` - elf Eventtypen (Firewall/Auth/SSH je als
   Vorkommnis und Anomalie, HTTP-/DNS-Anomalie, Port-Scan,
   Container-Anomalie/-Escape), geschlossene `Severity`-Skala,
   validierter `SensorEnvelope` (ein flaches JSON-Objekt, intern getaggt
   durch `event_type`) und ein Fixture je Typ; siehe `docs/security-events.md`.
   Bewusst ohne API- oder Datenbankänderung - nichts im Repo hängt bisher
   davon ab.
7. `security-events-storage` (umgesetzt): additive Migration `0031` (
   `security_sensors`, `security_sensor_audit`, `security_events` -
   bestehende `events`/`event_delivery`/`audit_events` unverändert),
   persistente Sensoridentitäten (gehashtes Credential + Prefix, Rotation,
   terminaler Widerruf, Audit-Trail) und Speicherung eines validierten
   `SensorEnvelope` mit `occurred_at`/`received_at` getrennt und
   IP-Pseudonymisierung (`resource` + typisierte Evidence-Felder) vor dem
   Schreiben. Noch keine DB-Rolle erhält Zugriff - das übernimmt der Dienst,
   den `security-events-ingress` einführt. PostgreSQL-Integrationstest in
   `scripts/test-postgres.sh`; siehe `docs/security-events.md`.
8. `security-events-ingress` (umgesetzt): `POST /internal/security-events/batch`
   auf `clawforge-api`, authentifiziert über eine `security_sensors`-
   Credential (SHA-256-Digest-Lookup wie bei `agent_tokens`, nicht die
   festen `InternalIdentity`-Tokens). Größenlimit (100 Items,
   eigenes `DefaultBodyLimit`), Clock-Skew-Prüfung
   (`CLAWFORGE_SECURITY_EVENTS_MAX_FUTURE_SKEW_SECONDS`/
   `..._MAX_PAST_AGE_SECONDS`), Nonce/Sequenz über `dedupe_key` erfüllt,
   Audit-Event pro Batch, Rate-Limit über die bestehende globale
   `rate_limit_middleware`. Eindeutige Teilfehlerantwort: jedes Item wird
   unabhängig verarbeitet und einzeln gemeldet, ein fehlerhaftes Item lässt
   den Rest des Batches nicht scheitern. Dabei eine echte Lücke im Domain-
   Crate gefunden und geschlossen: `#[derive(Deserialize)]` umging die
   Validierung aus `new()` komplett - `SensorEnvelope::validate()` schließt
   das. Fixture-Sender: `api/src/bin/send-security-event-fixtures.rs`.
   Contract-/Negativtests real gegen Postgres in `scripts/test-postgres.sh`.
   Siehe `docs/security-events.md`.

Erst danach beginnen Sensorimplementierungen. So bleibt jede Änderung klein,
reviewbar und rückrollbar.
