# Live-readiness audit

Status: **not live-ready.** This document lists what a first live firewall pilot (Phase 7A) needs,
which mechanism covers each point, how it is evidenced, and what remains open. It never opens a
gate. `scripts/live-readiness-check.py` is the read-only checklist; it prints `live_ready: false`
unconditionally, because the last steps are human decisions that no script can supply.

```
python3 -I scripts/live-readiness-check.py [--backup-dir DIR] [--shape-verdict FILE] [--out FILE]
```

Output is JSON: `gates_closed` (must be PASS), `prerequisites` (PASS / FAIL / UNKNOWN), `warnings`,
`outstanding_human_items`. Missing data is UNKNOWN, never PASS. Tests: `scripts/test-live-readiness-check.py`.

## Requirement map

| Requirement | Mechanism | Evidence | State on production (2026-10-23) |
| --- | --- | --- | --- |
| Executor stays dry-run, no live authorization, bridge off, all actions disabled, active policies observe-only, RIPEstat off | env + DB flags, checked as `gates_closed` | checker output | all PASS |
| Safe application of an incident source | policy decision (independent evidence order, reputation required by default) → DB bridge function → approval by risk level → executor | `docs/policy-execution-bridge.md`, PostgreSQL tests with real roles and positive controls | bridge off; simulated requests exist (Go-Away challenges, `simulation_only`) |
| Two independent approvals for high/critical | approval by action risk level; roles are read-only grants | storage tests | no human approval given; cannot be produced by an agent |
| Protective never-block list | `CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS`, fail-closed; executor refuses a productive start without it | kernel-lab test `kernel_lab_never_block_list_protects_real_traffic_and_fails_closed`, executor unit test | **FAIL: not defined.** Candidates below, operator must confirm |
| Pilot limits (TTL ≤ 900 s, ≤ 2 applies / 300 s, concurrency explicit) | env, read at each dispatch | checker | **FAIL: unset / defaults (3600 s, 20, implicit 5).** Setting `CLAWFORGE_FIREWALL_MAX_TTL_SECONDS` or `..._MAX_CONCURRENT_APPLIES_PER_ADAPTER` in `.env` had NO effect: compose did not pass them to the executor (fixed in the repository; the production compose fork needs the same two lines) |
| TTL restore / rollback | write-ahead journal, native nftables element timeout, rollback readback | kernel-lab series (40 cycles apply → block → rollback → restore → native expiry) in a disposable container | proven in the lab; not in production |
| Retention keeps evidence of real requests | migration 0070, `clawforge_delete_expired_security_assessments` | PostgreSQL test with positive/negative controls | in 1.2.8 |
| Component health is truthful | runtime heartbeat every 30 s (api, incidents), policy engine `degraded` on failed cycles | `clawforge_component_up`, storage test | api/incidents showed stale heartbeat before 1.2.8 |
| Feed freshness / failure handling | counting feeds (spamhaus drop/edrop/asn, feodo) must be fresh; failing non-counting feeds warn | checker | counting feeds fresh; threatfox, urlhaus, malwarebazaar fail (need operator AuthKeys) |
| Sensor freshness | sensor `age_seconds ≤ 300` | checker | srv19680 sensors offline since ~22:30Z, cause unknown |
| Observation sufficiency | `scripts/shape-observation-evaluate.py` (24 h, completeness checks, never passes a gate) | verdict file passed to the checker | not before 2026-10-24T12:50Z; a gap from the srv19680 outage yields INSUFFICIENT_DATA |
| Quality gate | behaviour harness | `docs/behavior-validation.md` | RED; 6 FP / 4 FN fixtures are not tuned, no labelled legitimate bursts exist |
| Recent restorable backup | operator backup service | `--backup-dir`; `pg_restore --list` | a completed daily dump exists (2026-10-24 00:55 UTC, ~25.5 GB) and its table of contents lists; **no full restore has been proven**, and the release script's own freshness/size/TOC gate is still evaluated at deploy time |
| Operator audit evidence | execution journal, approval records, receipts | storage tests | nothing live to audit |

## Executed versus merely coded (2026-10-24)

See `docs/live-canary-checkpack.md` for the mechanisms. A test that exists is not a test that ran:

| Evidence | Coded | Executed (where, when) |
| --- | --- | --- |
| Kernel series: 40 apply/block/rollback/restore cycles + 5 native expiries | `kernel_lab_series_...` (ignored, needs NET_ADMIN) | disposable container, 2026-10-24: restore p95 57 ms, expiry overshoot max 231 ms; lab traffic, **not production evidence**; not in CI |
| Never-block against real traffic, fail-closed on a malformed list | `kernel_lab_never_block_...` | same run, passed; not in CI |
| Never-block parser/overlap, both families | unit tests incl. `tailnet_ranges_...` | CI on every PR |
| Evidence retention keeps real-request evidence only | PostgreSQL test | CI (rust job) and local fixture |
| Two-person approval negative paths | `firewall_live_authorization_negative_paths_...` | local fixture 2026-10-24 incl. two mutation controls; CI with the PostgreSQL suite |
| Mirror hook restart equivalent | `mirror_restart_lab.sh` | private namespace 2026-10-24, with a control on the old script; CI only syntax-checks it |
| Real guest/NIC replug on the host | procedure in the check pack | **not performed** |
| Phase 7B window | `phase7b-observe.py` + tests | tool tested; no window run yet |
| Detection quality gate | harness | executed, **red** (6 FP / 4 FN fixtures unchanged, not tuned) |

## Never-block candidates (proposal, not authoritative)

Derived from this VM only: the LAN `192.168.0.0/24` (gateway 192.168.0.1, this VM, the Proxmox host),
Tailscale `100.64.0.0/10`, the resolvers reached through 192.168.0.1. The operator must confirm
these and add the ISP/remote ranges they administer from; nothing here has been applied.

## abuse.ch feeds (ThreatFox, URLhaus, MalwareBazaar): what is wired and what is missing

Checked 2026-10-24 without printing any value. Wiring is complete: the worker container gets
`THREATFOX_AUTH_KEY_FILE`, `URLHAUS_AUTH_KEY_FILE` and `MALWAREBAZAAR_AUTH_KEY_FILE`, mounted from
`secrets/threatfox_auth_key`, `secrets/urlhaus_auth_key` and `secrets/malwarebazaar_auth_key`. The three files exist
but contain **one byte (no key)**; `provider_status` therefore records `provider configuration is missing: ...
cannot be empty` and the worker backs off about an hour between tries. This is a missing credential, not a code
defect, and nothing in the repository can fix it: the key is a free abuse.ch Auth-Key that only the account owner can
create. Nothing is claimed fixed and no key is fabricated.

Operator steps (no restart needed; the file is read on every fetch, so write it in place so the bind-mounted inode is
kept): put the key, one line, mode 0600, into each of the three files, then request a manual provider sync or wait for
the next scheduled attempt, and verify per feed: `provider_status.status = 'ok'` with a fresh `last_success_at`. The
same key is expected to serve all three feeds; verify each, do not assume. These feeds are not "counting"
reputation sources for the enforcement bridge, so the pilot does not depend on them. BGPView and BGPStream stay
disabled as retired.

## Backup risk

The 2026-10-23 cleanup removed the earlier dumps; the service wrote a new complete one at 00:55 UTC on 2026-10-24. A dump ages out of the release gate after 27 h. Retention math: 14 daily dumps of ~23 GiB need ~320 GiB; about 160 GiB are free. Either shorten
retention, compress, or add storage before relying on it. Do not assume a restore works until one is
rehearsed (`docs/backup.md`).

## Guest-reboot validation of the mirror hook (outstanding, not run)

The udev rule re-applies the tc mirror when a tap device reappears. Replaying an `add` event was
verified; a real guest restart was **not** performed (it would interrupt VM100/HA101). In a
maintenance window:

1. Before: `clawforge-ids-mirror status` and `tc filter show dev tap100i0 ingress` — expect `pref 4242`
   mirroring to `tap100i1` (same for `nic0`; `tap101i0` only while HA101 runs).
2. Restart the guest through the Proxmox UI/CLI as usual.
3. After (within ~60 s of the tap returning): the same commands show the filter again; `ids-selftest.sh`
   passes; Suricata `status.json` shows `alive` and no new drops.
4. Rollback if the filter is missing: `clawforge-ids-mirror up`; if that fails, `clawforge-ids-mirror down`
   and the rollback list in `docs/network-ids.md` (sensor is passive; nothing else depends on it).

## Outstanding human decisions

Two independent human approvals; operator-labelled legitimate bursts; formal Phase 7B observation;
confirmed protection values and pilot limits; abuse.ch AuthKeys; srv19680 availability;
maintenance-window reboot validation; backup/restore proof; the final live-authorization decision.
Until all are evidenced, the answer to "live-ready?" is no.
