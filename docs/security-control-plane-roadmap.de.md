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

1. Linux-Sensor für SSH-/Auth- und Systemereignisse (**dieser Umfang
   erledigt**: `clawforge-linux-sensor` deckt `ssh_login_failure` per
   `journalctl`/`SYSLOG_IDENTIFIER=sshd` **oder** `sshd-session` ab (ein
   Live-Soaktest gegen einen echten OpenSSH-9.8+-Host, Ubuntu 26.04, zeigte,
   dass moderne OpenSSH-Versionen Authentifizierung aus einem
   Pro-Verbindungs-Re-Exec unter `sshd-session` loggen, nicht unter der
   Listener-Identität `sshd` - ein reines `sshd`-Filter sah dort trotz
   echter Fehlanmeldungen nichts) - Cursor/Checkpoint, begrenzter
   Puffer mit Backpressure, Dedupe über den Journal-Cursor als
   `dedupe_key`, Health-/Lag-/Drop-Metriken auf `GET /health`, läuft ohne
   root per `group_add`. PAM/sudo-Auth und breitere System-Ereignisse sind
   bewusst noch nicht abgedeckt, siehe `docs/sensors.md`.).
2. HAProxy-Sensor für Request-Metadaten, Fehlercodes, Rate-Limit- und
   Anomaliesignale (**dieser Umfang erledigt**: `clawforge-haproxy-sensor`
   deckt `http_anomaly` für Fehlerstatus (>=400 sowie -1/keine Antwort) per
   `journalctl`/`SYSLOG_IDENTIFIER=haproxy` ab, gleiche Cursor-/Dedupe-/
   Puffer-/Health-Bauweise wie der Linux-Sensor. Payloads enthalten nie
   Bodies/Cookies/Authorization-Header - nur Client-IP, Methode, Pfad,
   Status werden geparst. Dediziertes Rate-Limit-/Stick-Table-Signal (statt
   nur generischer Fehlerstatus) noch nicht abgedeckt, siehe
   `docs/sensors.md`.).
3. Docker-Sensor für Lifecycle, Image-, Port- und Netzänderungen (**dieser
   Umfang erledigt**: `clawforge-docker-sensor` deckt Container-
   Lifecycle (create/start/die/destroy/restart), Netzwerk-Connect/
   Disconnect und Image-Pull/-Delete über den Docker-Events-Stream ab, als
   neuer, eigenständiger Eventtyp `container_lifecycle_changed` (Migration
   `0032`) statt die Anomalie-Typen zu verbiegen. Kein direkter
   Socket-Zugriff: nur über `docker-socket-proxy`
   (Tecnativa/docker-socket-proxy) mit Allowlist ausschließlich `EVENTS`/
   `PING`/`VERSION`, `POST=0` (kein Schreibzugriff). Port-spezifisches
   Tracking (bräuchte einen zusätzlichen Container-Inspect-Aufruf) noch
   nicht abgedeckt, siehe `docs/sensors.md`.).

Alle drei Sensoren nutzen dasselbe Registrierungs-Tool
(`register-security-sensor`, kein Admin-Endpunkt dafür) und dasselbe
opt-in `sensors`-Compose-Profil. **Damit ist Phase 3 in ihrem hier
umgesetzten Umfang abgeschlossen**; offen bleibt laut Exit-Gate ein
24-Stunden-Soak-Test mit vorab festgelegter Burst-Last, Neustart,
Netzunterbrechung und Logrotation auf einem echten Host - das ist ein
Deployment-Schritt, kein Code-Schritt, und noch nicht durchgeführt.

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
  bestehende Correlation-/Risk-Crates werden wiederverwendet. (**begonnen**:
  `clawforge-security-engine` ist ein neuer, eigenständiger Consumer neben
  `clawforge-correlation` - nicht dessen Ersatz, siehe `docs/security-engine.md`
  für die Begründung -, der dessen bereits idempotente/eskalationssichere
  `persist_correlation`/`incident_candidates`-Pfad wiederverwendet statt
  einen zweiten zu bauen.)
- Assessments, Evidence-Referenzen und Engine-/Regelversion persistieren.
  (**erledigt**: Migration `0033`, `security_assessments`/
  `security_assessment_events`, `dedupe_key` aus rule_id/rule_version/
  resource/bucket_start.)
- Regeln für SSH-Bruteforce, Scans, Multi-Target-Angriffe, HTTP-Anomalien sowie
  Threat-Intel-plus-Verhalten implementieren. (**teilweise**: `ssh_bruteforce`
  und `http_anomaly_burst` als deterministische Zähl-Schwellwert-Regeln,
  `http_scan` als Distinct-Value-Schwellwert-Regel (viele verschiedene Pfade
  statt vieler Treffer - erkennt Scanner-Verhalten, das ein reiner Zähler
  nicht von einem Burst unterscheiden könnte), alle drei über ein festes
  Tumbling-Window, mit echtem Postgres getestet. Echte Multi-Target-Regel
  (eine Quelle gegen mehrere verschiedene Zielhosts) noch nicht sinnvoll
  umsetzbar - aktuell nur ein ueberwachter SSH- und ein ueberwachter
  HTTP-Endpunkt. Threat-Intel-plus-Verhalten **erledigt** (Verknuepfung
  bewusst in Phase 5 "Policy Engine" gebaut, nicht in dieser Crate - siehe
  `docs/policy-engine.md`: Spamhaus-Reputationsabgleich beim Ingest, bevor
  die IP pseudonymisiert wird, nur ein Kategorie-Flag geht weiter; die
  Security-Engine setzt daraus `security_assessments.
  threat_intel_corroborated`, das der Policy-Engine erstmals einen zweiten
  Evidence-Quelle liefert).
- minimale Provenance-, Freshness-, Confidence- und Konfliktregeln für alle
  verwendeten Threat-Intel-Signale implementieren; stale/unklare Daten dürfen
  keine automatische Klasse erreichen. (noch offen)
- Incident-Erzeugung und Score-Änderungen idempotent und replay-fähig machen.
  (**erledigt für die beiden implementierten Regeln**: durch Wiederverwendung
  von `persist_correlation` plus die deterministische Bucket-Zuordnung;
  echter Postgres-Test beweist below-threshold/at-threshold/same-bucket-
  Wiederholung/Replay.)
- Goldene Angriffsszenarien sowie False-positive-/False-negative-Fixtures
  aufnehmen. (noch offen)

Exit-Gate: gleiche Events und Regelversion erzeugen deterministisch dasselbe
Assessment; Backfill/Replay erzeugt keine Notifications, Actions oder doppelten
Incidents; ein einzelnes Signal erreicht nie eine Block-Entscheidung.

## Phase 5: Policy Engine

Ziel: versionierte Regeln mit explizitem Entscheidungsweg.

Arbeitspakete:

- persistierte Policy-Versionen, Status, Gültigkeit und Simulation ergänzen
  (**erledigt**: Migration `0034`, `security_policies` versioniert
  (`UNIQUE (name,version)`), Status `draft`/`active`/`retired`,
  `valid_from`/`valid_until`. "Simulation" = Shadow-Auswertung, siehe unten.)
- Klassen `observe`, `approval` und `automatic` abbilden (**erledigt** als
  Spalte `class` auf `security_policies`; alle drei aktuell seeded mit
  `observe`, da noch keine Action-Ebene existiert, gegen die `approval`/
  `automatic` etwas bedeuten würde.)
- Evidence Snapshot, Allowlist, Zielbereich, TTL und Blast Radius prüfen
  (**teilweise**: Evidence Snapshot + Hash erledigt (`evidence_snapshot`/
  `evidence_hash` auf `security_policy_decisions`). Allowlist/Zielbereich/
  TTL/Blast-Radius-Prüfung noch offen - ergibt erst mit einer echten
  Action-Ebene (Phase 6) Sinn.)
- Zwei-Personen-Freigabe für high/critical gegen vorhandene Approval-
  Infrastruktur durchsetzen (noch offen - braucht Phase 6)
- Freigabe an den unveränderlichen Hash von Action, Ziel, TTL, Adapter,
  gerendertem Diff und Policy-/Evidence-Version binden; Drift invalidiert sie
  (**teilweise**: `evidence_hash` bindet heute Policy-Version + Evidence-
  Snapshot; Action/Ziel/TTL/Adapter/Diff kommen mit Phase 6 dazu.)
- Shadow Evaluation und Entscheidungserklärung bereitstellen (**erledigt**:
  neuer Dienst `clawforge-policy-engine`, wertet
  `clawforge-security-engine`-Assessments gegen aktive Policies aus über
  das bereits vorhandene `clawforge_policy::decide()` - dieselbe Logik, die
  schon "ein einzelnes Signal erreicht nie eine Block-Entscheidung"
  durchsetzt (`evidence_sources>=2` für Block; ein Assessment ohne
  Threat-Intel-Treffer bleibt bei 1 und Block bleibt unerreichbar, ein
  Assessment MIT Treffer bekommt 2 und Block wird erstmals erreichbar -
  siehe `docs/policy-engine.md`). Jede Entscheidung bekommt eine
  Klartext-`rationale`. **Es existiert keine Action-Ebene - "Shadow Mode"
  ist hier eine Eigenschaft der Architektur, nicht nur eine Konfiguration.**)

Exit-Gate: mindestens zwei Wochen Shadow Mode gegen ein vorab festgelegtes
Goldkorpus und eine genehmigte False-positive-Grenze; Policies können gegen
historische Incidents replayed werden (**Replay-Eigenschaft erledigt** - jeder
Poll-Zyklus wertet die letzten N Assessments neu aus, idempotent per
`dedupe_key`, siehe echten Postgres-Test in `policy-engine/src/main.rs`. Die
eigentliche zwei-Wochen-Beobachtung selbst steht noch aus.); keine Action
wird produktiv ausgeführt (**erfüllt per Konstruktion**, siehe oben).

## Phase 6: Firewall Action Layer

Ziel: sichere Ausführungsplattform, zunächst vollständig im Dry-Run.

Arbeitspakete:

- `clawforge-firewall-agent` mit typisiertem Adaptervertrag erstellen
  (**erledigt**: `FirewallAdapter`-Trait mit `preflight`/`render`/`apply`/
  `verify`/`rollback`, alle real implementiert fuer `NftablesAdapter` -
  siehe `docs/firewall-agent.md`. Anbindung an den Executor-Dispatch
  ebenfalls erledigt: `clawforge-executor` claimt `execution_requests`
  ueber `claim_execution_request_for_dispatch`/`complete_execution_dispatch`
  und ruft fuer `nftables.*`-Actions echt `NftablesAdapter::apply` auf,
  `dry_run` weiterhin von `CLAWFORGE_EXECUTOR_DRY_RUN` gesteuert und am
  Aufrufpunkt selbst erneut geprueft, unabhaengig vom Start-Gate.)
- Action Receipt, Preflight, Istzustand, Verification, TTL und konkreten
  Rollback persistieren (**erledigt**: `clawforge-executor` schreibt bei
  jedem `nftables.*`-Dispatch einen vollstaendigen Receipt (Preflight,
  gerenderte Kommandos, Istzustand, Verification-Ergebnis, TTL,
  Rollback-Plan) in `firewall_action_receipts` - Tabelle ist bewusst
  Append-only, `clawforge_executor` hat nur `INSERT`, bewiesen per echtem
  Rollen-Test. Noch offen: kein Admin-Werkzeug liest die Tabelle
  zurueck.)
- Idempotency, Lease, Retry, Timeout und Recovery des vorhandenen Executors
  integrieren (**bereits vorhanden**, unveraendert genutzt: `execution_requests`/
  `execution_leases`/`execution_recovery` mit DB-Trigger-gestuetzten
  Status-Uebergaengen, Ablaufdatum-gebundener Freigabe-Hash - das war schon
  vor dieser Phase gebaut, hier nur wiederverwendet, nicht neu erstellt.)
- nftables-Adapter mit exklusiver Clawforge-Tabelle/-Chain implementieren
  und ausschließlich ein vorprovisioniertes Set verwalten lassen
  (**erledigt, inkl. echtem Apply/Verify/Rollback**: `NftablesAdapter`
  rendert und fuehrt nur `nft add/delete element inet clawforge
  blocklist{,6} {...}` aus - nie eine neue Regel, nur Mitgliedschaft in
  zwei vorab vom Betreiber angelegten, typisierten Sets (IPv4/IPv6
  getrennt, da nftables-Sets typisiert sind). Drei Zieltypen:
  `ThreatIntelIndicator` (rohe, bereits oeffentliche CIDR/IP aus
  `indicators`), `IncidentSource` (pseudonymisierte Resource - render
  loest NIE zur echten IP auf, `apply` darauf schlaegt by construction
  fehl) und `ResolvedIncidentSource` (nur von einem Aufrufer erzeugt, der
  bereits ueber `security_ip_resolutions` aufgeloest hat; `render`
  verweigert diese Variante explizit). IPv4-mapped-IPv6-Normalisierung
  vorhanden. Ein echter Bug (naiver String-Containment-Check statt
  strukturiertem JSON-Parsing bei der Set-Mitgliedschaftspruefung) wurde
  ueber das isolierte Lab gefunden und behoben. Registriert, aber
  deaktiviert (`enabled=FALSE`), wie jede andere Connector-Action seit
  Migration `0027`.)
- HAProxy-Adapter für Maps/ACLs und Rate-Limits implementieren (noch offen)
- Tailscale zunächst nur als freigabepflichtigen Adapter vorbereiten (noch offen)

**Wichtiger Nebenbefund waehrend dieser Phase**: die bestehende
Fail-closed-Pseudonymisierung (Nutzerentscheidung aus Empfehlung 5) macht
"sperre die Quelle von Incident X" grundsaetzlich unmoeglich, da die rohe
IP nirgends mehr auffindbar ist. Nutzerentscheidung dazu (explizit
gefragt): NEUE, eng begrenzte Tabelle `security_ip_resolutions` (Migration
`0036`) - kurze, feste TTL (Default 24h), wird bei JEDEM aufgezeichneten
Security-Event befuellt (nicht nur bei einem Threat-Intel-Treffer, weil
auch eine Kombination aus zwei unabhaengigen VERHALTENS-Regeln - z. B.
`ssh_bruteforce` dann spaeter `http_scan` von derselben Quelle -
korrobieren kann, ganz ohne externen Reputationstreffer; siehe
`docs/policy-engine.md`s zweiten Korrobierungs-Pfad,
`resource_has_other_rule_assessment`). Eine aufgeloeste IP wird nie in
einen Receipt geschrieben, nur just-in-time durch einen echten
Apply-Schritt (existiert noch nicht) genutzt.

Pflichtgates vor der ersten verändernden Lab-Testaktion:

- PostgreSQL-Migrationstest läuft in CI und ist nicht ignoriert (**erfuellt**,
  wie fuer jede Migration in diesem Repo seit Projektbeginn)
- Executor besitzt Unit-, Crash-/Restart-, Idempotency- und Rollbacktests
  (**teilweise** - die bestehende Executor-Infrastruktur hat Idempotency-/
  Freigabe-Tests; `claim_execution_request_for_dispatch`/
  `complete_execution_dispatch` haben eigene Integrationstests gegen
  echtes Postgres, `NftablesAdapter` hat echte apply/verify/rollback-
  Roundtrip-Tests im Lab (u. a. Idempotenz eines doppelten Applies,
  Rollback eines nie applizierten Elements). Gezielte Crash-/Restart-
  Tests, die einen Prozessabbruch *waehrend* eines laufenden Dispatch
  simulieren, existieren noch nicht.)
- Action API und Adapter bestehen Fuzz-/Negativtests und Command-Injection-
  Review; es existiert keine freie Shell (**teilweise**: Negativtests fuer
  `NftablesAdapter` vorhanden (ungueltige CIDR, leere Quelle, Shell-Metazeichen
  als Zieltext, unaufgeloester Pseudonym-Apply), jede Kommandokonstruktion -
  inklusive der jetzt echten apply/verify/rollback-Aufrufe - nutzt
  `tokio::process::Command` mit explizitem Argv statt Shell-String.
  Systematisches Fuzzing noch offen.)
- isoliertes Netzwerk-Lab bestätigt, dass Allowlist und Managementzugang nicht
  gesperrt werden können (**teilweise**: `scripts/test-firewall-lab.sh`
  betreibt einen disposablen Container (NET_ADMIN/NET_RAW, nie
  srv19680 oder ein anderer echter Host) und faehrt dort 8 echte
  `nft`-Roundtrip-Tests (Apply/Verify/Rollback IPv4+IPv6, Dry-Run-
  Isolation, Idempotenz, IPv4-mapped-IPv6). Was das noch nicht abdeckt:
  Selbstsperr-Bestaetigung gegen den echten Management-Zugangspfad
  (SSH/HAProxy-Admin) eines *provisionierten* Hosts - der Container hat
  kein Aequivalent dazu. Das bleibt vor jedem echten Apply gegen einen
  Produktionshost offen und wird bewusst nicht ohne Nutzerbeteiligung
  angegangen.)
- Break-glass-Verfahren und manuelles Entfernen aller Clawforge-Regeln sind
  dokumentiert und geprobt (**erledigt**: `scripts/nftables-clawforge-break-glass.sh`
  entfernt die gesamte exklusive Clawforge-Tabelle in einem atomaren
  `nft delete table`-Aufruf, ohne Abhaengigkeit von Executor/API/Postgres -
  direkt per SSH auf dem betroffenen Host ausfuehrbar. Echt geprobt, nicht
  nur dokumentiert: der Lab-Test `break_glass_removes_every_trace_of_the_
  clawforge_table` blockiert ein echtes Ziel, bestaetigt die Sperre, fuehrt
  das Skript aus, bestaetigt dass die GESAMTE Tabelle weg ist, und
  reprovisioniert danach - im selben isolierten Container wie jeder andere
  echte Lab-Test.)
- Failure-Injection deckt Prozess-/Host-/DB-Ausfall zwischen Intent, Apply,
  Receipt und Audit, Lease-Verlust, Reboot, Uhrsprung, konkurrierende Actions,
  abgelaufene TTL, manuelle Drift und fehlgeschlagenes Read-back ab
- vor `apply` existiert immer ein persistierter Intent und ein lokales
  Recovery-Journal
- Desired/Actual State, TTL, Drift, Kill-Switch und vollständige Audit-Lineage
  sind vor einem Produktionspilot über ein geprüftes Admin-Werkzeug sichtbar
- pro Adapter/Ziel gelten getestete Rate-, Concurrency- und Mass-block-Budgets
  (**teilweise**: `clawforge-executor` verweigert einen echten (nicht
  Dry-Run) `nftables.*`-Apply, sobald `CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW`
  (Standard 20) echte Applies innerhalb von `CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS`
  (Standard 300) bereits erfasst wurden - DB-gestuetzt ueber
  `firewall_action_receipts` selbst, nicht ein In-Prozess-Zaehler, haelt
  also auch ueber einen Prozessneustart und mehrere Executor-Replicas
  hinweg, echt gegen Postgres getestet. Noch offen: ein Concurrency-Limit
  ueber mehrere Replicas hinweg, die DASSELBE Zielsystem bedienen.);
  Zielnormalisierung und technische Ausschlusslisten decken
  IPv4, IPv6, CIDR und IPv4-mapped IPv6 ab (**erledigt fuer die
  Ausschlussliste**: `NftablesAdapter` laedt eine eingebaute Loopback-/
  Link-local-Sicherung plus eine per `CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS`
  konfigurierbare Liste (dort gehoert die eigene Management-/SSH-Quelle
  hinein); `render`/`apply` verweigern jedes Ziel, dessen Netz sich mit
  einem Ausschluss ueberschneidet - in beide Richtungen (ein breites
  Ziel-CIDR, das einen ausgeschlossenen `/32` nur enthaelt, wird genauso
  erkannt). Ein fehlerhafter konfigurierter Eintrag macht die GESAMTE
  Liste fail-closed, nicht nur den einen Eintrag - derselbe Ansatz wie bei
  der Pseudonymisierung. Das ist die konkrete Selbstsperr-Schutzmassnahme,
  die heute existiert, anstelle der Lab-Bestaetigung gegen einen echten
  Management-Zugangspfad, die weiterhin offen ist.)
- HA-/Leader-/Lease-Tests beweisen, dass dieselbe Action nicht doppelt greift
  (**erledigt**: `concurrent_workers_never_claim_the_same_execution_request_twice`
  laesst zwei unabhaengige `PostgresStore`-Verbindungen - stellvertretend fuer
  zwei Executor-Replicas - echt nebenlaeufig per `tokio::join!` um denselben
  einzelnen Request konkurrieren; `FOR UPDATE SKIP LOCKED` garantiert genau
  einen Gewinner. `a_worker_that_dies_after_claiming_is_reclaimed_by_a_
  different_worker` beweist die andere Haelfte: ein Worker, der nach dem
  Claim stirbt (nie `complete_execution_dispatch` aufruft), haelt den
  Request nicht fuer immer fest - die bestehende Lease-Ablauf-Wiedereinsammlung
  in `run_execution_maintenance` gibt ihn frei, ein zweiter Worker uebernimmt
  und schliesst ihn erfolgreich ab. Beide echte Tests gegen Postgres, nicht
  nur behauptet.);
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
