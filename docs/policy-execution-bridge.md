# Policy -> execution bridge (roadmap 7C)

Status: implemented and tested in isolation; **off by default and not enabled
anywhere**. Gate 7B is not passed (see `phase7-pilot-evidence-20261021.md`), so
nothing in this document authorizes an unattended block.

The policy engine used to record shadow decisions only. The bridge lets it turn a
`Block` (or `RateLimit`) decision into exactly one execution request, with every
condition re-derived and re-checked inside the database. The policy-engine role
still has no `INSERT` on `execution_requests`; it can only call two
`SECURITY DEFINER` functions (migration `0060`).

## Modes (`CLAWFORGE_POLICY_BRIDGE_MODE`)

| Mode | Action row required | Request | What can happen |
| --- | --- | --- | --- |
| `off` (default) | any | none | nothing |
| `simulate` | `enabled = FALSE` | `pending`, `simulation_only` | executor can only produce a dry-run receipt |
| `propose` | `enabled` and `requires_approval` | `waiting_approval` | the action's approval policy (critical: two distinct approvers, not the requester, context-hash bound) decides |
| `automatic` | `enabled` and **not** `requires_approval` | `pending` | the executor's own gates still decide (below) |

An unknown mode, or any missing/invalid value for the selected mode, rejects the
entire configuration: the bridge runs disabled and the reason appears in the
policy engine's `runtime_status.last_error`. Shadow decisions are unaffected.

## Configuration (no built-in operating values)

| Variable | Meaning |
| --- | --- |
| `CLAWFORGE_POLICY_BRIDGE_BLOCK_ACTION` | action for `Block`: `nftables.`, `haproxy.` or `firewall.block_incident_source` |
| `CLAWFORGE_POLICY_BRIDGE_RATELIMIT_ACTION` | action for `RateLimit`: `haproxy_ratelimit.block_incident_source` (at least one of the two is required) |
| `..._TTL_SECONDS` | block TTL carried in the request target, 1-86400 (required) |
| `..._MAX_PER_WINDOW`, `..._WINDOW_SECONDS` | request budget enforced in SQL, 1-100 per 60-86400 s (required; also clamped in SQL) |
| `..._MAX_EVIDENCE_AGE_SECONDS` | maximum age of the decision and the assessment, 1-604800 (required) |
| `..._MIN_INTEL_CONFIDENCE` | minimum confidence (1-100, required) of the reputation listing that counts; judged on the current source view (`threat-intel-evidence.md`) |
| `..._REQUIRE_THREAT_INTEL` | default `true`; `false` is refused for `automatic` |
| `..._REQUESTER_ID` | `propose` only: UUID of an enabled **Operator** account (Administrators are refused) |
| `..._RULE_ID` | restrict to one security-engine rule; required for `automatic` |
| `..._AUTOMATIC_ACK` | `automatic` only: must equal `unattended:<rule>:<block action>:<ratelimit action>:<ttl>:<max>/<window>:<age>:<min intel confidence>` - changing any parameter invalidates it |

The compose file passes these through empty; empty counts as unset.

## What the database checks (all modes)

Decision exists, is a shadow decision, matches the action kind (`block` or
`rate_limit`), is corroborated by at least two evidence sources and was updated
within the evidence age. The policy is active and within its validity window; its
class must be at least `approval` for `propose` and `automatic` for `automatic`.
The assessment is pseudonymized, recent and (always for `automatic`, by default
otherwise) threat-intel corroborated. Outside `simulate`, an unexpired single-host
resolution must exist. The approval context is built by `clawforge_policy_bridge_plan`,
hashed by the caller, and `clawforge_enqueue_policy_bridge_request` refuses any
context that differs from its own derivation.

Serialized under an advisory lock: idempotency key per decision and mode (replays
return the same request), no second active request for the same target, and the
per-window budget. `automatic` additionally requires a fresh executor heartbeat
(< 5 min), no `prepared`/`recovery_required` firewall generation and no
`rollback_required` request.

## What stays outside the bridge

Even an `automatic` request only runs if the executor's gates open:
`CLAWFORGE_EXECUTOR_DRY_RUN=false`, a valid live authorization for the action
class, the TTL ceiling, the apply and concurrency budgets, the never-block list
(checked on the resolved address) and the just-in-time address resolution of
migration `0059`. `simulation_only` requests always stay dry runs. Quarantine
actions are not reachable from the bridge.

## Design notes and residual risks

* **Independence.** `threat_intel_required` is the default precisely because behavioural
  "corroboration" is weak: two rules over the same event family, or the overlapping windows
  of one rule, are one observation (see `docs/behavior-validation.md`). The policy engine
  counts a second source only for fresh reputation, a different event family or an earlier
  episode; observation-only rules never corroborate and never reach the bridge.

* **Database-side bounds.** Budget <= 100 per window, window >= 60 s, evidence age
  <= 7 days and TTL <= 1 day hold whatever the caller passes. The executor's own apply
  budgets are an independent backstop, as are the action-row state and the executor
  gates, none of which the policy-engine role can change.
* **The decisions table is writable by the policy-engine role** and cannot be
  re-derived in SQL (`decide()` lives in Rust). The bridge therefore also checks the
  assessment against the policy: same rule, minimum severity met, recent, and (always
  for `automatic`) threat-intel corroborated; the assessment table is written by the
  security-engine role, not the policy engine. A compromised policy-engine role could
  still forge a decision for a genuinely corroborated assessment; `automatic` therefore
  stays behind an operator-flipped action row and the executor gates.
* **Freshness.** `decision_not_reconfirmed` means the engine has not re-evaluated the
  decision within the evidence age (the engine upserts every poll, so a live engine
  keeps it fresh); evidence age itself is the assessment's `last_seen`.
* **One request per decision and mode.** The idempotency key is
  `policy-bridge:<mode>:<decision>`. A continuing attack produces a new assessment
  bucket and therefore a new decision; an expired proposal is not re-proposed by
  itself. This is deliberate (no repeated unattended blocks from one decision).
* **Simulations are separate.** They neither block nor count against live requests.
  A partially applied request (`rollback_required`) keeps its target busy.
* **`automatic` and risk levels.** The seeded incident-source actions are `critical`
  and require approval. Clearing `requires_approval` on such an action is the
  deliberate unattended switch; it also removes the approval requirement for manual
  requests of that action, so it should be done knowingly and reverted when done.
* Concurrent operator changes (disabling the action, retiring the policy, disabling
  the requester) are serialized with the insert via row locks.

## Tests

* `storage/tests/policy_bridge.rs` (PostgreSQL, in `scripts/test-postgres.sh`):
  every refusal reason, the three action-state modes, tamper refusal, duplicate,
  target-active, budget, executor-health and unresolved-generation stops, role
  least privilege, and the chain propose -> two approvals (Rust hash recomputation)
  -> executor claim.
* `scripts/test-incident-source-lab.sh` (not part of CI; needs Docker and network): a
  disposable PostgreSQL plus a container that shares its network namespace and holds
  NET_ADMIN, so a real kernel nftables applies, verifies and rolls back an
  incident-source block (IPv4 and IPv6) with receipts free of the address.
* `policy-engine` unit tests for configuration validation and an end-to-end test
  from assessment to simulated request.

## Rollout sketch (not executed)

1. Apply `0059` and `0060` through `clawforge-migrate` (ledger 58 -> 60, additive),
   after backup and a restore check, with images built from the merged commit.
   Rehearsed 2026-10-21 on a throwaway database holding a read-only schema + ledger
   copy of the running production database: the migrator reported
   `current at version 60` and created the three functions. Production itself was
   only read.
2. `simulate` first: observe requests and dry-run receipts; no action row changes.
3. `propose`: create the Operator requester account (no usable login), enable the
   chosen action row, set the variables. Approvals stay human.
4. `automatic` only after gate 7B is passed and a reviewed live authorization exists.

## Decisions that remain with the operator

* Which first rule, action, TTL, budget and evidence age (the pilot fixture used
  TTL 60 s, one block, one apply per 300 s; that is a lab scope, not a policy).
* The requester account for `propose`.
* Whether telemetry gaps like those in the 48 h observation are acceptable, or the
  window is repeated.
* When, if ever, an action row is switched to unattended operation.
