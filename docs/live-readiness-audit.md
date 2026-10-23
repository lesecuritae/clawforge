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
| Pilot limits (TTL ≤ 900 s, ≤ 2 applies / 300 s, concurrency explicit) | env, read at each dispatch | checker | **FAIL: unset / defaults (3600 s, 20, implicit 5)** |
| TTL restore / rollback | write-ahead journal, native nftables element timeout, rollback readback | kernel-lab series (40 cycles apply → block → rollback → restore → native expiry) in a disposable container | proven in the lab; not in production |
| Retention keeps evidence of real requests | migration 0070, `clawforge_delete_expired_security_assessments` | PostgreSQL test with positive/negative controls | in 1.2.8 |
| Component health is truthful | runtime heartbeat every 30 s (api, incidents), policy engine `degraded` on failed cycles | `clawforge_component_up`, storage test | api/incidents showed stale heartbeat before 1.2.8 |
| Feed freshness / failure handling | counting feeds (spamhaus drop/edrop/asn, feodo) must be fresh; failing non-counting feeds warn | checker | counting feeds fresh; threatfox, urlhaus, malwarebazaar fail (need operator AuthKeys) |
| Sensor freshness | sensor `age_seconds ≤ 300` | checker | srv19680 sensors offline since ~22:30Z, cause unknown |
| Observation sufficiency | `scripts/shape-observation-evaluate.py` (24 h, completeness checks, never passes a gate) | verdict file passed to the checker | not before 2026-10-24T12:50Z; a gap from the srv19680 outage yields INSUFFICIENT_DATA |
| Quality gate | behaviour harness | `docs/behavior-validation.md` | RED; 6 FP / 4 FN fixtures are not tuned, no labelled legitimate bursts exist |
| Recent restorable backup | operator backup service | `--backup-dir` | **UNKNOWN / at risk:** the backup volume currently holds no dump after the user-authorized cleanup; no restore has been proven |
| Operator audit evidence | execution journal, approval records, receipts | storage tests | nothing live to audit |

## Never-block candidates (proposal, not authoritative)

Derived from this VM only: the LAN `192.168.0.0/24` (gateway 192.168.0.1, this VM, the Proxmox host),
Tailscale `100.64.0.0/10`, the resolvers reached through 192.168.0.1. The operator must confirm
these and add the ISP/remote ranges they administer from; nothing here has been applied.

## Backup risk

Retention math: 14 daily dumps of ~23 GiB need ~320 GiB; about 160 GiB are free. Either shorten
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
