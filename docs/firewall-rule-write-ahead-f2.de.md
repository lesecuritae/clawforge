# F2: dauerhafte Write-ahead-Intents für generische Firewall-Regeln

Siehe `CLAWFORGE_ROADMAP_CONTINUATION.md`, Abschnitt F2. Dieses Inkrement liefert
das **Storage-Fundament**; die Executor-Verdrahtung folgt getrennt.

## Problem

Generische Firewall-Applies (nftables / haproxy / haproxy_ratelimit) persistieren
ihr Receipt heute erst **nach** der Mutation, best effort
(`executor/src/main.rs`, `record_firewall_action_receipt` nach
`apply_single_adapter`). Ein Absturz zwischen `adapter.apply()` und dem
Receipt-INSERT hinterlässt eine reale Mutation **ohne** dauerhaften Nachweis.
Der in Phase 11 (Migration 0054) gehärtete Generations-Controller ist
quarantäne-spezifisch und deckt diesen Pfad nicht ab.

## Lösung (dieses Inkrement)

Dieselbe Write-ahead-Disziplin wie bei Quarantäne, aber über einen **typisierten
Regel-Vertrag** und strikt getrennt von den 0054-Quarantäne-Spalten/Constraints.

### Migration `0055_firewall_rule_write_ahead.sql`

Additiv auf `firewall_action_intents`, unabhängig von 0054:
- Spalten `fw_rule_fingerprint`, `fw_rule_scope` (bindet die konkrete Regel:
  nftables-Set / haproxy-ACL / rate-limit-Table — **nicht** nur eine IP),
  `fw_target_json`, `fw_preflight_state`, `fw_rollback_plan`, `fw_ttl_seconds`
  (60..86400), `fw_expires_at`, `fw_error_summary`.
- CHECK `firewall_rule_intent_snapshot_complete`: greift nur wenn
  `fw_rule_fingerprint IS NOT NULL`, erzwingt Adapter-Whitelist,
  Snapshot-Vollständigkeit und schließt aus, dass eine Zeile zugleich eine
  Quarantäne- (`target_fingerprint`) und eine Regel-Generation ist.
- Unique-Index `firewall_rule_active_generation` über
  `(adapter, fw_rule_scope, fw_rule_fingerprint)` bei Status
  prepared/completed/recovery_required → genau **ein** aktiver Besitzer je Regel.
- Eigener Immutabilitäts-/Transitions-Trigger
  `protect_firewall_rule_intent_snapshot` (ändert die 0054-Objekte nicht).

Die Migration ist rein additiv und konvergiert in **beiden** Fork-Historien
(main-0046 und produktive 0046-Variante); `migration_lineages`-Test auf `latest=55`.

### Storage-Modul `storage/src/firewall_rule_intents.rs`

Spiegelt den Quarantäne-Generations-Fence, **ohne** dessen Dual-Approval (der
Zweck ist Durability der Apply-/Rollback-Lifecycle, kein Freigabe-Gate):
- `prepare_firewall_rule_intent(...)` committet den unveränderlichen Snapshot
  **vor** dem Adapter-Aufruf; schlägt fehl, wenn die Regel bereits von einer
  aktiven Generation besessen wird (Schutz gegen Doppel-Apply).
- `acquire_firewall_rule_guard(id)` hält den Zeilen-Lock über die externe IO
  (`FOR UPDATE SKIP LOCKED`); ein konkurrierender Recovery-Worker überspringt
  eine gesperrte Generation.
- `FirewallRuleGuard::finish(receipt)` schreibt Apply-Receipt + Status=completed
  **atomar**; ein fehlgeschlagenes Receipt lässt die Generation `prepared` und
  besessen. `resolve_rollback` / `recovery_required` / `not_applied` analog.
- Statuslogik identisch zu Quarantäne: prepared/completed/recovery_required
  halten Besitz; nur `not_applied` und `rolled_back` geben ihn frei.

## Tests (real PostgreSQL, Schema 0055)

`storage/tests/firewall_rule_intents.rs`:
- `rule_write_ahead_is_owned_crash_safe_and_atomic`: bereits-besessene Regel
  abgelehnt; Crash vor Mutation (Guard-Drop) lässt `prepared` erhalten; zweiter
  Worker überspringt gesperrte Generation; Receipt-INSERT-Fehler → `prepared`
  bleibt, 0 Receipts; verifizierter Apply → completed (verknüpftes Receipt);
  completed/recovery_required halten Besitz; Stale-Rollback gibt aktuellen
  Besitzer nicht frei; apply+rollback = 2 verknüpfte append-only Receipts.
- `concurrent_prepare_yields_exactly_one_owner`: genau ein paralleler Besitzer.
- `migration_lineages`: 0055 konvergiert in beiden Historien ohne Ledger-Rewrite.

## Offen (nächste Inkremente)

- Executor-Verdrahtung: `apply_single_adapter` prepariert die Generation vor
  `adapter.apply()` und schließt sie atomar ab; unklare Wirkung →
  `recovery_required`. Multi-Adapter-Fan-out je Adapter-Generation.
- Vorhandene Operator-Regeln niemals als eigenen Apply adoptieren oder beim
  Rollback löschen (Adapter-/Executor-Ebene).
- F3: atomare Mass-/Concurrency-Budgets. Kein Live-Gate wird hier geöffnet.
