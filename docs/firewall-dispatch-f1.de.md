# F1: generischen Firewall-Dispatch korrekt abschließen

Stand 2026-10-06; Basis main `2c38b62039470b1951ea1881c171448481882eb0`.
Dieses Paket aktiviert keinen produktiven Vollzug und verändert keine Migration.

## Ergebnis und überprüfbare Regeln

| Situation | Ergebnis | Verhalten |
|---|---|---|
| Echtes Preflight schlägt fehl | Failed | Kein Apply, kein Verify, kein erfundenes Receipt |
| Dry-run ohne erreichbares Preflight | Success als Plan | Receipt markiert preflight_unavailable; keine Live-Verifikation |
| Echtes Apply liefert Fehler | RecoveryRequired | Begrenzte read-only Nachprüfung; keine behauptete Ownership, kein erfundenes Apply-Receipt |
| Apply bekannt, Verify fehlt oder widerspricht | RecoveryRequired | Tatsächliches Receipt einschließlich Beobachtung und Rollbackplan bleibt erhalten |
| Echtes Apply verifiziert | Success | Receipt wird persistiert |
| Pflichtadapter verweigert, anderer Adapter hat real angewendet | RecoveryRequired | Bekannte Teilwirkung erhalten; keine automatische Wiederholung |
| Optionaler Adapter verweigert vor Änderung, Pflichtadapter verifiziert | Success mit degradierter Fehlerzusammenfassung | Keine unbekannte optionale Wirkung |
| Receipt-Schreiben schlägt fehl | Failed im Dry-run; RecoveryRequired bei echter Änderung | Kein Erfolg trotz verlorener Audit-Evidence |

`GenericDispatchOutcome` hält diese Klassifizierung innerhalb des Executors.
`complete_execution_dispatch_for_recovery` speichert den bestehenden Status
`rollback_required`. Die normale Maintenance nimmt diesen Status weder in
Timeout-/Lease-Retry noch in Failed-Requeue auf. Audit speichert den genauen
Status; die bestehende Metrik-Enumeration verwendet dafür `failed`.
Normale erfolgreiche und fehlgeschlagene Abschlüsse behalten ihre Semantik.
Quarantäne-Routing und der native Generationen-Controller bleiben getrennt.

Summaries enthalten keine gerenderten Befehle oder rohen Adapter-Fehlermeldungen.
Zieldaten und tatsächliche Kommandos bleiben im vorhandenen zugriffsbeschränkten
Receipt. Der bisherige CIDR-Test prüft diese Daten dort weiterhin.

## Tatsächliche Prüfung

- `cargo test --workspace`: 298 bestanden; 77 explizite Infrastrukturtests ignoriert.
  Die benötigten PostgreSQL-/Controller-Tests werden separat real ausgeführt.
- `scripts/test-postgres.sh`: 46/46 bestanden, einschließlich restricted-executor
  Recovery-Test und echtem disposable Docker-Controller-Lab; Fixture entfernt.
- Neun neue Fake-Adapter-Regressionen: Preflight, Apply/Readback, Verify,
  Multi-Adapter-Teilwirkung, verlorenes Receipt und Dry-run-Abgrenzung.
- Unabhängiger Review fand die bekannte optionale Teilwirkung bei Pflichtfehler;
  die Korrektur hat einen eigenen Regressionstest.
- `cargo fmt --all -- --check` und Workspace-Clippy mit `-D warnings`: bestanden.

## Grenze: F2 bleibt der nächste Schritt

Dieser Abschluss ist **kein Write-ahead-Protokoll**. Absturz oder Datenbankausfall
zwischen externer Mutation und dauerhafter Speicherung von `rollback_required`
können weiterhin generische Recovery ohne gesicherte Ownership auslösen.
Auch generische TTL-Rücknahmen besitzen noch nicht die native Generationenbindung
von Quarantäne. Ein bloß vorhandener Block beweist nicht, dass Clawforge ihn besitzt.

Deshalb als Nächstes F2: vorhandene native Intents für HAProxy/nftables erweitern,
vor I/O dauerhaft vorbereiten, Ownership und atomare Receipts sichern, Recovery
und TTL gegen fremde/vorhandene Regeln testen. Nicht die angewendete Migration54
umschreiben oder eine zweite Datenbank anlegen. Danach F3: atomare Budgets.
Erst anschließend den bestehenden Pilot 7A→7B→7C→7D prüfen.

Produktive Firewall und Quarantäne bleiben gesperrt. Kein Deployment,
Produktiv-Schemawechsel, automatischer Block oder manueller Hosttest dieses Pakets.
