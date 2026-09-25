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
- HAProxy-Adapter für Maps/ACLs und Rate-Limits implementieren
  (**erledigt, beide Haelften**: `HaproxyAdapter` (ACLs) implementiert
  denselben `FirewallAdapter`-Vertrag wie `NftablesAdapter` (gleiche
  Zieltypen), ueber die HAProxy-Runtime-API (`add acl`/`del acl`/`show
  acl` gegen eine exklusiv Clawforge gehoerende ACL-Pattern-Datei - NICHT
  die separate `map`-Mechanik, die per `add map`/`show map` ein echtes
  Key-Value-Objekt ist). Da `haproxy.cfg` anders als eine exklusive
  nftables-Tabelle eine einzige, bereits produktiv genutzte Datei ist,
  kann keiner der beiden Adapter sie exklusiv besitzen - `scripts/haproxy-
  clawforge-provision.sh` legt nur die Pattern-Datei an und gibt die
  Zeilen aus, die ein Betreiber selbst in jedes zu schuetzende Frontend
  eintraegt. **Echter Bug im isolierten Lab gefunden+behoben**: die erste
  ACL-Adapter-Version nutzte faelschlich `add map`/`show map` statt `add
  acl`/`show acl` - eine `acl ... -f`-Referenz wird gar nicht als "map"-
  Objekt registriert, `show map` lieferte daher immer eine leere Liste,
  vom echten `apply`+`verify`-Rundlauf-Test im Lab sofort aufgedeckt
  (nicht vermutet, sondern live am echten Runtime-API-Protokoll
  diagnostiziert). `HaproxyRateLimitAdapter` (Rate-Limits) nutzt eine
  andere Mechanik - ein Stick-Table mit Allzweckzaehler (`gpc0`) statt
  einer Mitgliedschaftsliste, gesetzt/gelesen/geloescht per `set table`/
  `show table`/`clear table`. **Zweiter echter Unterschied im Lab
  gefunden**: anders als `del acl` (Fehler bei fehlendem Eintrag) ist
  `clear table` fuer einen nie gesetzten Key idempotent (kein Fehler) -
  ein erster Testentwurf nahm faelschlich dasselbe Verhalten wie beim
  ACL-Adapter an und scheiterte am echten Runtime-API-Verhalten, was den
  Unterschied aufdeckte. **Dabei zusaetzlich eine echte Sicherheitsluecke
  gefunden+geschlossen**: die Never-block-Ausschlussliste war bisher NUR
  in `NftablesAdapter` verdrahtet - `HaproxyAdapter` rief die Pruefung nie
  auf, der eigene Selbstsperr-Schutz griff fuer HAProxy-Blocks also gar
  nicht. Auf eine gemeinsame freie Funktion refaktoriert, die jetzt alle
  drei Adapter aufrufen (schliesst die Luecke rueckwirkend auch fuer den
  bereits bestehenden ACL-Adapter, nicht nur den neuen). Eigene isolierte
  Labs (`scripts/test-firewall-lab.sh` fuer nftables, `scripts/test-
  haproxy-lab.sh` fuer beide HAProxy-Adapter, keine besonderen
  Capabilities noetig). Registriert ueber Migration `0038`
  (ACL: `haproxy.block_indicator`/`haproxy.block_incident_source`) und
  `0040` (Rate-Limit: `haproxy_ratelimit.block_indicator`/`haproxy_
  ratelimit.block_incident_source`), beide `requires_approval=TRUE,
  enabled=FALSE`. Executor-Dispatch waehlt den passenden Adapter per
  Aktionsname-Praefix (die spezifischere `haproxy_ratelimit`-Praefix-
  Pruefung laeuft VOR der generischen `haproxy`-Pruefung, sonst wuerden
  Rate-Limit-Actions faelschlich zum ACL-Adapter geroutet), alle drei
  HAProxy/nftables-Adapter teilen sich ein Mass-block-Budget.)
- Tailscale zunächst nur als freigabepflichtigen Adapter vorbereiten,
  dann echte Admin-API-Integration (**beide Schritte erledigt**: aus dem
  reinen `render`-Vorbereitungsstand (v1, s.o.) wurde eine echte,
  funktionierende Integration gegen die live Tailscale Admin API gebaut,
  Nutzeranstoss "ja dann mach weiter und du hast meinen tailscale api
  key". Mechanismus: Tailscale-ACLs sind additiv "accept"-only, es gibt
  kein "deny" - Quarantaene taggt ein Geraet (`tag:clawforge-quarantine`,
  konfigurierbar ueber `CLAWFORGE_TAILSCALE_QUARANTINE_TAG`), was es aus
  `autogroup:member` entfernt; wirksam wird das nur, wenn die eigene
  ACL-Policy ihre accept-Regel(n) auf `autogroup:member` statt `*` scopt.
  `apply`/`verify`/`rollback` machen echte HTTP-Calls (OAuth2
  client_credentials, `CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID_FILE`/
  `_SECRET_FILE`, ueber `clawforge_secret::load_optional` - beide
  Credentials optional bei Konstruktion, jede echte Methode schlaegt
  ohne sie sauber fehl), read-modify-write auf `/device/{id}/tags` (der
  Endpunkt ersetzt komplett, daher erst lesen, dann die Quarantaene-Tag
  ergaenzen/entfernen, nie blind ueberschreiben). Executor-Dispatch: eigene
  `dispatch_tailscale()`-Funktion (paralell zu, nicht Teil von,
  `dispatch_multi_adapter()`s `FirewallAdapter`-Fan-out, weil eine
  Tailscale-Geraete-ID eine grundlegend andere Ressourcenform als eine
  IP/CIDR ist), `rollback_expired_target()` verzweigt fuer abgelaufene
  Tailscale-Quarantaenen entsprechend, `is_firewall_action()` deckt das
  Mass-block-Budget auch fuer `tailscale.*` ab.

  **Live-ACL-Policy des echten Tailnets wurde mit Nutzerfreigabe
  angepasst** (kein Code, ein externer Systemzustand): `tagOwners` um
  `tag:clawforge-quarantine` ergaenzt, die einzige accept-Regel von
  `src: ["*"]` auf `src: ["autogroup:member"]` geaendert - ohne das haette
  Tagging keine Wirkung gehabt. Vor diesem Schritt (mehrere Dutzend echte
  Geraete betroffen, darunter kritische selbstgehostete Infrastruktur)
  wurde explizit nachgefragt und Freigabe eingeholt.

  **Echter End-to-End-Test gegen ein reales, vom Nutzer explizit als
  niedrigstes Risiko ausgewaehltes Geraet** deckte eine
  echte Tailscale-Plattform-Eigenschaft auf: `POST /device/{id}/tags`
  lehnt das Entfernen des LETZTEN Tags mit `HTTP 400 "tagged nodes
  cannot be untagged without reauth"` ab - das Geraet blieb dadurch
  zeitweise real quarantaent, bis es manuell (App-Reauth, nicht nur
  Reconnect) erneut authentifiziert wurde. Das ist kein Bug, sondern
  eine bewusste Sicherheitseigenschaft (ein getaggtes Geraet zurueck in
  ein ungetaggtes persoenliches Geraet zu verwandeln verlangt erneuten
  Besitznachweis - analog zu Break-glass, das physischen/Account-Zugriff
  voraussetzt statt eines reinen API-Calls). `rollback()` erkennt diesen
  Fall jetzt VOR dem Aufruf (wenn das Entfernen des Tags die Liste leer
  liesse) und gibt einen klaren, umsetzbaren Fehler statt des rohen
  HTTP-400 zurueck; ist das Quarantaene-Tag bereits nicht mehr gesetzt
  (z.B. weil ein Betreiber es von Hand geloest hat), gibt `rollback()`
  bewusst `Ok(())` zurueck (anders als `NftablesAdapter`s "Rollback von
  nie-Angewandtem schlaegt sauber fehl"-Praezedenzfall), damit der
  TTL-Sweep konvergieren kann statt endlos auf einem bereits geloesten
  Problem zu scheitern. Das reale Geraet wurde am Ende dieser Sitzung
  verifiziert vollstaendig entsperrt (`tags: None`).

  Headscale (selbstgehostete Tailscale-Alternative): das ACL-*Format*
  ist konzeptionell kompatibel, aber dieser Adapter spricht Tailscales
  eigene Cloud-API/-Auth - eine Headscale-Instanz braeuchte einen
  eigenen, separaten Adapter.

  Migration `0037` (Connector + `tailscale.quarantine_device`-Action,
  `requires_approval=TRUE, enabled=FALSE`) unveraendert - die echte
  Integration aendert nichts an Freigabepflicht/Dry-run-Status,
  `CLAWFORGE_EXECUTOR_DRY_RUN` bleibt weiterhin hartkodiert `true`.)
- Multi-Adapter-Dispatch: eine Block-Entscheidung darf nicht nur Dienste
  hinter HAProxy schuetzen, sondern jeden nach aussen gehenden Dienst auf
  dem Host (**erledigt**, Nutzeranstoss: "das jegliche Dienste die nach
  aussen gehen ueberwacht werden koennen und nicht nur HAProxy" - eine neue
  `firewall.*`-Action (statt einer einzelnen `nftables.*`/`haproxy.*`/
  `haproxy_ratelimit.*`) loest ALLE ueber `CLAWFORGE_FIREWALL_ADAPTERS`
  konfigurierten Adapter gleichzeitig aus, `nftables` (host-weiter,
  dienst-unabhaengiger IP-Block) ist dabei IMMER dabei, unabhaengig von der
  Konfiguration - das ist die eigentliche "jeder externe Dienst"-Garantie,
  nicht etwas, das ein Betreiber konfigurieren muss. Jeder Adapter wird
  unabhaengig von einem anderen versucht (Verteidigung in der Tiefe);
  Gesamterfolg haengt nur am PFLICHT-Adapter `nftables`; erfolgreiche
  Adapter bekommen trotzdem einen Receipt, auch wenn ein anderer
  fehlschlug. Ein unbekannter Adaptername in der Konfiguration wird nur
  geloggt und ignoriert (anders als bei der Never-block-Liste - hier ist
  das Auslassen einer optionalen Zusatzschicht kein Selbstsperr-Risiko,
  `nftables` traegt die Kern-Garantie allein). Migration `0041`
  (`firewall.block_indicator`/`firewall.block_incident_source`,
  `requires_approval=TRUE, enabled=FALSE`). Einzeladapter-Actions
  (`nftables.*`/`haproxy.*`/`haproxy_ratelimit.*`) bleiben bestehen und
  funktionieren unveraendert - `firewall.*` ist eine zusaetzliche, breitere
  Option, kein Ersatz.)

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
  Review; es existiert keine freie Shell (**erledigt**: Negativtests fuer
  `NftablesAdapter` vorhanden (ungueltige CIDR, leere Quelle, Shell-Metazeichen
  als Zieltext, unaufgeloester Pseudonym-Apply), jede Kommandokonstruktion -
  inklusive der jetzt echten apply/verify/rollback-Aufrufe - nutzt
  `tokio::process::Command` mit explizitem Argv statt Shell-String.
  **Systematisches Fuzzing jetzt ebenfalls erledigt**: neues `proptest`-
  Dev-Dependency, 8 Property-Tests in `firewall-agent/src/lib.rs`s
  `tests::fuzz`-Modul (je Testlauf mehrere hundert generierte
  Adversarial-Eingaben - Shell-Metazeichen, eingebettete Newlines/
  Null-Bytes, Unicode, Extremlaengen). Zwei Invarianten bewiesen: (1)
  `FirewallTarget::try_from` (die tatsaechliche externe Eingabegrenze -
  `execution_requests.approval_context->>'target'`) und `parse_ip_or_cidr`
  duerfen fuer BELIEBIGE Eingabe nie paniken; (2) sobald ein Wert
  `parse_ip_or_cidr` erfolgreich durchlaeuft, enthaelt `element_reference`s
  neu zusammengesetzte Ausgabe (das, was tatsaechlich als `nft`-Argv-Element
  oder HAProxy-Runtime-API-`key` ankommt) garantiert kein Whitespace, keinen
  Newline, kein Null-Byte und ist immer genau eine Zeile - insbesondere
  fuer die HAProxy-Befehle relevant, deren Protokoll zeilenbasiert ueber
  `UnixStream::write_all` laeuft: ein eingebetteter Newline in `key` haette
  dort einen zweiten, frei waehlbaren Runtime-API-Befehl einschmuggeln
  koennen. Diese Eigenschaft galt vorher nur als Kommentar-Behauptung ("kann
  nie Whitespace/Newline enthalten, weil aus einem typisierten `IpAddr`
  neu formatiert") - jetzt ist sie bewiesen, nicht nur behauptet.)
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
  (**teilweise**: Lease-Verlust/Worker-Tod erledigt -
  `a_worker_that_dies_after_claiming_is_reclaimed_by_a_different_worker`;
  manuelle Drift erledigt - `verify_detects_manual_drift_after_an_out_of_
  band_removal` entfernt ein Element echt per `nft` ausserhalb des
  Adapters und beweist, dass `verify` das erkennt, nicht veraltete
  Zustaende meldet. **Abgelaufene TTL jetzt erledigt**: `clawforge-executor`
  rollt jeden Tick echte Blocks zurueck, deren `expires_at` verstrichen ist
  und die noch keinen spaeteren Rollback-Receipt haben (`firewall_action_
  receipts` bleibt dabei Append-only - ein Rollback ist eine NEUE Zeile,
  kein `UPDATE`). Dabei einen echten, sicherheitsrelevanten Bug gefunden
  und behoben: `apply()`s eigener Receipt (anders als `render()`, das
  `ResolvedIncidentSource` komplett verweigert) baute `rendered_commands`/
  `rollback_commands` bisher aus derselben unredigierten Referenz wie der
  echte Befehl - die rohe aufgeloeste IP waere damit in `firewall_action_
  receipts` persistiert worden, sobald ein Aufrufer je einen `Resolved
  IncidentSource` konstruiert (noch keiner tut das). Gefixt mit einer
  redigierten Receipt-Referenz (`redacted_element_reference`), die real
  ausgefuehrte Befehl bleibt unveraendert real. **Konkurrierende Actions auf
  demselben Ziel jetzt erledigt**: `concurrent_applies_of_the_same_target_
  never_corrupt_or_crash` (nftables) und ihr HAProxy-Gegenstueck lassen
  zwei Applies desselben Ziels echt nebenlaeufig per `tokio::join!` ueber
  zwei unabhaengige Adapter-Instanzen laufen - beweist, dass keiner
  fehlschlaegt/abstuerzt und das Ziel danach sauber genau einmal blockiert
  ist, echt gegen beide Labs getestet, nicht nur sequenziell wie der
  bestehende Idempotenz-Test. Noch offen: Prozess-/Host-/DB-Ausfall
  zwischen den Schritten selbst, Reboot, Uhrsprung, fehlgeschlagenes
  Read-back.)
- vor `apply` existiert immer ein persistierter Intent und ein lokales
  Recovery-Journal
- Desired/Actual State, TTL, Drift, Kill-Switch und vollständige Audit-Lineage
  sind vor einem Produktionspilot über ein geprüftes Admin-Werkzeug sichtbar
  (**erledigt**: `GET /firewall/receipts` (Filter nach Adapter/Ziel) und
  `GET /firewall/expired` (Drift - nutzt exakt dieselbe Abfrage wie der
  TTL-Sweep selbst, kann also nie abweichen) existieren, rollen-gebunden
  wie jede andere Admin-Liste, jedes Feld bereits unbedenklich (nie eine
  rohe IP). **Kill-Switch pro Ziel jetzt ebenfalls erledigt** (Migration
  `0042`): anders als Break-glass (alles-oder-nichts pro Host) zielt er
  auf genau EIN bereits blockiertes Element. `clawforge-api` darf nie
  selbst einen echten Adapter aufrufen - `POST /firewall/kill-switch`
  (nur Administrator/Operator, echte Schreibaktion) zeichnet daher nur die
  Absicht in einer neuen `firewall_kill_switch_requests`-Tabelle auf;
  `clawforge-executor`s `sweep_kill_switch_requests` (derselbe Poll-Tick
  wie der TTL-Sweep) fuehrt den eigentlichen Rollback aus - ueber denselben
  `rollback_target`-Helper, den der TTL-Sweep nutzt (aus dem vormaligen
  `rollback_expired_target` herausgeloest, jetzt parametrisiert statt an
  `ExpiredFirewallTarget` gebunden, damit beide Sweeps nie unterschiedlich
  ausfuehren, nur unterschiedlich AUSLOESEN). Eine Anfrage gilt erst als
  verarbeitet, wenn sowohl der echte Rollback als auch sein Receipt
  persistiert sind - schlaegt eines fehl, bleibt sie offen und wird naechsten
  Tick erneut versucht, gefahrlos dank bewiesener Rollback-Idempotenz.
  `GET /firewall/kill-switch` zeigt sowohl offene als auch bereits
  verarbeitete Anfragen.)
- pro Adapter/Ziel gelten getestete Rate-, Concurrency- und Mass-block-Budgets
  (**erledigt**: `clawforge-executor` verweigert einen echten (nicht
  Dry-Run) Apply, sobald `CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW`
  (Standard 20) echte Applies innerhalb von `CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS`
  (Standard 300) bereits erfasst wurden - DB-gestuetzt ueber
  `firewall_action_receipts` selbst, nicht ein In-Prozess-Zaehler, haelt
  also auch ueber einen Prozessneustart und mehrere Executor-Replicas
  hinweg, echt gegen Postgres getestet. **Concurrency-Limit jetzt ebenfalls
  erledigt** (Migration `0043`): getrennt von diesem RATE-Budget begrenzt
  es, wie viele echte Applies/Rollbacks GLEICHZEITIG gegen denselben
  Adapter laufen duerfen, ueber alle Executor-Replicas hinweg -
  `firewall_inflight_operations` ist eine Reservierungs-Tabelle (Zeile
  existiert nur waehrend die Operation als laufend gilt), `try_begin_
  inflight` reserviert einen Platz und prueft danach den lebenden
  Zaehlerstand (nur Zeilen juenger als `CLAWFORGE_FIREWALL_INFLIGHT_
  STALE_SECONDS`, Standard 120s) gegen `CLAWFORGE_FIREWALL_MAX_CONCURRENT_
  APPLIES_PER_ADAPTER` (Standard 5); bei Ueberschreitung wird die eigene
  Reservierung sofort wieder freigegeben. Das Staleness-Fenster macht das
  selbstheilend - ein zwischen Reservieren und Freigeben abgestuerzter
  Replica hinterlaesst nichts Dauerhaftes, die Zeile veraltet einfach.
  Bewusst insert-then-check statt harte Sperre (wie schon beim RATE-Budget)
  - ein kleines, begrenztes Race wird als Budget-Kosten akzeptiert, keine
  Sicherheitsinvariante wie die Never-block-Liste. `dispatch()`/
  `apply_single_adapter`/`rollback_target` bleiben dabei unveraendert
  DB-frei (direkt unit-testbar ohne Store) - eine neue, reine Funktion
  `adapters_touched_by` spiegelt deren Routing von aussen, `main()`s
  Schleife reserviert/gibt frei rund um den `dispatch()`-Aufruf, die
  beiden Sweeps rund um ihre eigenen `rollback_target`-Aufrufe.);
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
quantifiziert und durch Security Review genehmigt. **Diese Zahlen sind
Richtlinien-Entscheidungen des Betreibers und die Review ein
menschlicher Prozess - beides kann und wird nicht eigenmaechtig
festgelegt/durchgefuehrt.** Begonnen (2026-09-24), Nutzeranstoss "ja
dann mach alles" auf die Rueckfrage nach Phase 7: alles im Dry-Run/Lab
gefahrlos Baubare wurde gebaut (siehe unten und
`docs/haproxy-nftables-pilot.md`); echte Produktions-Aktionen und das
Umschalten von `CLAWFORGE_EXECUTOR_DRY_RUN` bleiben explizit ausgeklammert,
bis der Nutzer dazu separat gefragt wurde und zustimmt.

- vor Gate 7A existiert eine geprüfte Approval-Oberfläche, die unveränderlichen
  Action-Diff, Evidence und Alter, Ziel/Blast Radius, Istzustand, TTL,
  Rollbackplan und alle Freigaben zeigt (**erledigt, Commit siehe unten**:
  `GET /executions/{id}` setzt bestehende Daten (Approvals aus Migration
  `0029`, verknuepfte `security_policy_decisions`/`security_assessments`
  fuer Evidence+Alter) mit einer neuen Faehigkeit zusammen: `render()`
  jedes Adapters ist rein/synchron (keine Adapter-I/O), daher kann
  `action_preview` schon VOR jeder Freigabe live berechnet werden -
  genau die "Action-Diff ... Rollbackplan"-Vorschau, die ein Reviewer
  vor dem Freigeben sehen muss. Nutzt `clawforge_firewall_agent::
  adapter_for_action` - dieselbe Routing-Tabelle, die `clawforge-executor`s
  echter Dispatch nutzt (aus dessen vormals privater `adapter_for`
  herausgeloest), damit die Vorschau nie einen anderen Adapter zeigen
  kann als den, der tatsaechlich liefe. `blast_radius_hint` markiert
  Einzeladress-Ziele (`/32`/`/128`/keine Praefix) als Canary-groesse.)
- Gate 7A: manuell freigegebener Produktions-Canary für `/32`/`/128` mit kurzer
  TTL; noch keine automatische Sperre (**noch offen - ein echter Versuch am
  2026-09-24 gegen srv19680 wurde bewusst abgebrochen**: Zielhost (srv19680),
  Ziel-IP (echte Spamhaus-DROP-Adresse `103.95.56.1/32`), Adapterwahl
  (HAProxy statt nftables - kleinerer Blast-Radius, nur `korbklar_https`),
  TTL (300s) und die Nutzerfreigabe als Security-Review-Ersatz waren
  geklaert; die Session-Umgebung selbst hat den eigentlichen Produktions-
  Schreibzugriff (HAProxy-Config aendern, Executor-Binary fuer Deploy bauen,
  `DRY_RUN` umschalten) konsequent verweigert - "Production Deploy" und
  "Auto-Mode Bypass" liessen sich anders als "Production Reads" nicht per
  `/permissions` freischalten, offenbar bewusst so gebaut, dass ein
  autonomer Hintergrund-Agent das nicht selbst freischalten kann. Fazit:
  der echte Live-Schritt gehoert in eine interaktive Sitzung, in der der
  Betreiber selbst direkt am Rechner sitzt und Prompts live bestaetigt,
  nicht in einen Hintergrund-Agenten. Alles Uebrige (Mechanismus,
  Approval-Oberflaeche) ist fertig; nur die tatsaechliche Ausfuehrung
  steht noch aus.)
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
  ergänzen (**erledigt, Migration `0044`**: `lookup_ip_reputation` prüft
  jetzt ALLE ingestierten Provider statt nur Spamhaus (Nicht-IP-Indikator-
  Typen der anderen Provider matchen die IP/Prefix-Form ohnehin nie, daher
  ungefährlich zu verbreitern); bei mehreren Treffern gewinnt der mit der
  höchsten Confidence (Tie-Break: zuletzt bestätigt). `security_assessments`
  trägt jetzt `threat_intel_source`/`threat_intel_confidence`/
  `threat_intel_indicator_last_seen` (alle-oder-keiner per CHECK-Constraint)
  statt nur eines bool'schen Flags. `clawforge-policy-engine` zählt einen
  Treffer nur noch als echte zweite Evidence-Quelle, wenn er frisch UND
  hinreichend confident ist (`threat_intel_hit_is_corroborating`,
  Standard-Schwellen 7 Tage/Confidence 50, beide per Env konfigurierbar,
  ein `last_seen` aus der Zukunft wird explizit abgelehnt statt als
  unendlich frisch behandelt) - das ist die konkrete Umsetzung des
  Exit-Gates dieser Phase. Siehe `docs/policy-engine.md`s "Freshness,
  provenance and confidence"-Abschnitt.)
- lokale IP-/ASN-/Angriffshistorie als zeitlich abklingendes Signal verwenden
  (**teilweise erledigt - nur der IP/Ressourcen-Teil, nicht ASN**:
  `clawforge-policy-engine`s `evidence_sources_for` bekommt einen DRITTEN,
  unabhaengigen Korrobierungspfad neben Threat-Intel und Cross-Rule -
  `resource_history_score` summiert ueber jede FRUEHERE Assessment
  derselben (pseudonymisierten) Ressource (jede Regel, nicht nur dieselbe)
  ein Exponential-Decay-Gewicht `0.5^(Alter/Halbwertszeit)` (Standard-
  Halbwertszeit 14 Tage, konfigurierbar) - ein frischer Wiederholungsfall
  zaehlt fast voll, einer genau eine Halbwertszeit alt nur noch halb, ohne
  harten Cutoff. Ab `CLAWFORGE_HISTORY_MIN_SCORE` (Standard 0.5) gilt das
  als eigene, unabhaengige Korrobierung - dieselbe Regel, die zweimal
  kurz hintereinander an derselben Ressource ausloest, kann jetzt allein
  dadurch (ohne Threat-Intel-Treffer, ohne andere Regel) `evidence_sources
  =2` erreichen. `exclude_assessment_id` sorgt dafuer, dass eine
  Assessment nie sich selbst als eigene Historie zaehlt. **ASN-Historie
  bewusst NICHT gebaut**: dafuer muesste am Ingest-Zeitpunkt (wo die rohe
  IP noch verfuegbar ist, wie beim Threat-Intel-Reputation-Lookup) eine
  IP-zu-ASN-Ruecksuche gegen `asn_records.prefixes` erfolgen und als
  eigenes Metadata-Flag mitgefuehrt werden - separates, noch nicht
  begonnenes Folgewerk.)
- Konflikte, Ausfälle und veraltete Feeds sichtbar machen (**erledigt**:
  Ausfaelle/Alter waren ueber `provider_status`/`list_provider_views`
  (Admin-Endpoint `/admin/providers`) schon aus einer frueheren Phase
  sichtbar (`state`/`last_error`/`consecutive_failures`/`age_seconds`) -
  neu ist ein expliziter, schwellenwertbasierter `is_stale`-Flag
  (Standard: 3x das eigene `interval_seconds`, konfigurierbar,
  deaktivierte Provider werden nie markiert) statt nur des rohen Alters,
  UND neu die Konflikterkennung selbst: `list_indicator_conflicts`
  (`GET /admin/indicators/conflicts`) findet Werte, die zwei oder mehr
  unabhaengige Provider mit deutlich unterschiedlicher Confidence
  bewerten - reine Sichtbarkeit, unterdrueckt nichts automatisch.
  **Dabei einen echten, vorbestehenden Bug gefunden+behoben**: `EXTRACT
  (EPOCH FROM ...) AS age_seconds` liefert in Postgres `numeric`, nicht
  `float8` - ohne expliziten `::float8`-Cast schlug die Rust-seitige
  `f64`-Dekodierung an sechs Stellen im Code still fehl (`age_seconds`
  war ueberall `None`/verursachte bei `list_alerts` sogar einen
  Panic-Pfad ueber die nicht-tolerante `.get()`-Variante) - unbemerkt,
  weil bisher nichts von einem tatsaechlich befuellten `age_seconds`
  abhing, bis der neue `is_stale`-Test genau das tat und den Bug live
  aufdeckte.)
- Datenschutz und Aufbewahrung für Identifikatoren festlegen (**erledigt**:
  neue `PostgresStore::delete_expired_security_assessments` - eine
  pseudonymisierte `resource` ist zwar keine rohe personenbezogene
  Angabe, aber trotzdem ein Identifikator, der nicht unbegrenzt liegen
  bleiben sollte (dasselbe Prinzip wie die bereits bestehende kurze TTL
  von `security_ip_resolutions` und `indicators.expires_at`). Bewusst eng
  gefasst: loescht NUR Assessments, die NIE zu einem Incident befoerdert
  wurden (`incident_id IS NULL`) und laenger als
  `CLAWFORGE_SECURITY_ASSESSMENT_RETENTION_SECONDS` (Standard 90 Tage -
  laesst `resource_history_score`s eigenem 14-Tage-Halbwertszeit-Signal
  reichlich Spielraum) keine Aktivitaet mehr gesehen haben
  (`last_seen`). Eine Assessment, die an einen echten Incident gebunden
  ist - offen, geschlossen, egal - wird NIE angefasst, unabhaengig vom
  Alter: Incident-Aufbewahrung bleibt die eigene, separat mit dem
  Betreiber abgestimmte Entscheidung (`docs/retention.md`). Zugehoerige
  `security_policy_decisions` werden mitentfernt (keine Kaskade von
  `security_assessments`, also erst die Decisions, dann die Assessment -
  sonst wuerde das Loeschen an der Fremdschluessel-Bindung scheitern);
  `events` selbst werden nie angefasst. In `clawforge-worker`s
  bestehendem Wartungszyklus verdrahtet, direkt neben der schon
  vorhandenen Indikator-Ablauf-Bereinigung.)

Exit-Gate: Offline- oder veraltete Feeds reduzieren Confidence und lösen keine
automatische Eskalation aus; jede Score-Komponente bleibt erklärbar.

## Phase 9: Dashboard

Ziel: operative Sicht und sichere Bedienung.

Ansichten:

- Live Security mit Angriffen, Assessments und Incidents (umgesetzt):
  neue Ansicht auf zwei neuen Endpunkten `GET /admin/security/assessments`
  und `GET /admin/security/events` (vorher rein intern, nur von
  `clawforge-policy-engine` gelesen) plus dem bestehenden `GET /incidents`.
- Firewall Status mit Desired/Actual State, Sperren, TTL und Drift
  (umgesetzt): neue Ansicht auf `/firewall/receipts`, `/firewall/expired`
  und `GET+POST /firewall/kill-switch`; Component-Tests gegen ein
  gemocktes `api`-Modul.
- Agentenentscheidungen mit Analyse, Empfehlung, Policy und Resultat
  (umgesetzt): neue Ansicht auf `GET /admin/security/decisions` (neue
  Storage-Funktion, joint `security_policy_decisions` mit `security_policies`
  und `security_assessments`) - alle vier Felder in einer Tabelle, klar als
  "Shadow only" gekennzeichnet.
- durchgängige Auditkette vom Event bis zum Rollback (umgesetzt): neue
  Ansicht wählt einen Incident und stellt die Kette aus vier unabhängig
  gelesenen Quellen zusammen (Event → Assessment → Decision → Firewall-
  Aktion/Rollback), letzterer Schritt per Wertabgleich über den
  pseudonymisierten `target_fingerprint`, da `firewall_action_receipts`
  keine `incident_id`-Spalte besitzt.

**Damit existieren alle vier geforderten Ansichten.** Component-Tests
(10 Tests über 4 Views) sind vorhanden; Browser-E2E-Tests fehlen noch.

Vor Abschluss werden Component- und Browser-E2E-Tests ergänzt; TypeScript-
Kompilierung allein reicht nicht als Frontend-Test. Component-Test-
Infrastruktur (Vitest + React Testing Library) ist jetzt vorhanden
(`npm test` führt `tsc -b` und `vitest run` aus); Browser-E2E-Tests fehlen
noch, ebenso die übrigen drei Ansichten.

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
