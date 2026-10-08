# Phase 7 pilot limits (operator-reviewed)

Status: **reviewed and confirmed by the operator on 2026-10-08.**

These are the quantified, reviewed limits the roadmap requires *before* a
Phase-7 live firewall pilot (step 7A). They are the values the enforcement
code built in P7-1 through P7-4 reads.

**Confirming these limits does not by itself open any gate.** A real pilot
still requires, separately and explicitly:

1. a live authorization (`CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION`, see P7-1),
2. `CLAWFORGE_EXECUTOR_DRY_RUN=false`,
3. the operator actually deploying that authorized build and running it.

Until all three happen, the live/quarantine gate stays closed and every
dispatch is a dry run. The quarantine adapters (docker/proxmox/tailscale) stay
closed independently and are never authorizable through this mechanism.

Every limit below is **env-configurable and read at each dispatch**, so it can
be tuned live without a rebuild or redeploy — the values here are the reviewed
starting point, not a frozen contract.

## Machine-enforced limits (env)

| Limit | Reviewed value | Enforced by |
| --- | --- | --- |
| Authorized action class | `nftables` only | `CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION` `actions=["nftables"]` (P7-1). Not `firewall.*` (fan-out) during 7A. |
| Max block TTL | **900 s** (15 min) | `CLAWFORGE_FIREWALL_MAX_TTL_SECONDS=900` (P7-2): a real apply over this is refused before anything is journaled. |
| Native self-expiry | TTL per element | nftables element `timeout` (P7-4): the kernel expires the block on its own even if the whole stack is dead. |
| Apply rate budget | **2 applies / 300 s** | `CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW=2`, `CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS=300`. |
| Concurrency budget | 5 / adapter (default) | `CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER` (F3); default is already conservative for a 1-target canary. |
| Management never-block | always on | per-adapter never-block exclusion list (loopback/link-local + operator management range); plus the operator's own ISP/Tailscale ranges must be excluded. |

## Observed / operational targets (measured, not hard-enforced)

These are judged against real evidence during 7B, not refused in code. The
rollback-latency numbers come from P7-3 (`firewall_rollback_latency`, surfaced
in the `agent_firewall_status` projection).

| Target | Reviewed value | How it is checked |
| --- | --- | --- |
| Canary count | exactly 1 (`/32` or `/128`) | operator applies exactly one reviewed target in 7A. |
| Max active blocks | 1 | operational during 7A (the rate budget bounds the rate, not the absolute live count). |
| Rollback p95 | **≤ 5 s** | P7-3 rollback-latency p95 over the pilot window. |
| Drift detection | ≤ 1 poll (~10 s) | verify-after-apply + TTL sweep each executor tick. |
| Lockout SLO | **0** management/own-IP blocks; self-unblock ≤ TTL (900 s) | never-block + ISP guard; the native timeout is the hard upper bound. |
| False-positive budget | **0** accepted | with one hand-reviewed target; any FP stops the pilot immediately. |
| Pilot duration (7B) | **48–72 h** | observation + a verified restore before 7C (the first automatic rule). |

## Stop conditions (carry into 7B/7C)

Stale or contradictory threat intelligence, drift, telemetry failure, or a
failed verification must stop new automatic applies. Safe rollback must remain
possible throughout. Two counted evidences are not automatically two
independent sources.

## References

- P7-1 live authorization — `executor/src/live_authorization.rs`
- P7-2 TTL ceiling — `CLAWFORGE_FIREWALL_MAX_TTL_SECONDS`, `executor/src/main.rs`
- P7-3 rollback-latency evidence — `storage::firewall_rollback_latency`, `agent_firewall_status`
- P7-4 native nftables dead-man timeout — `firewall-agent/src/lib.rs`, `scripts/nftables-clawforge-provision.sh`
- Roadmap — `CLAWFORGE_ROADMAP_CONTINUATION.md` §6
