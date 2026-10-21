# Phase 7 pilot evidence (state 2026-10-21)

Scope: the isolated VPS pilot (not production). This page records what the
pilot actually proved, what the 48-hour observation did and did not show, and
which gates stay closed. It grants no authorization; the live gates in
`docs/phase7-pilot-limits.md` still apply.

## 7A — single canary: passed (isolated VPS)

Third native request `4adc232b-d31f-4ed2-a4c5-5b707ff33de9`, approved by a
real, independent operator account (not by the agent), executor image built
from `aad5e12`:

* real kernel block of `203.0.113.18/32` (documentation address), TTL 60 s;
* baseline packet passed, blocked packet dropped, restored packet passed;
* execution `success`, rule generation `rolled_back`;
* one real (non-dry-run) apply receipt and one rollback receipt, both
  `verification=verified`;
* afterwards: executor stopped, block list empty, test namespace removed.

Two earlier native requests failed on genuine defects and are kept as history
(no approval was reused or fabricated):

| Attempt | Defect | Fix |
| --- | --- | --- |
| 1 | Verifier required a prefix object for `/32`; nft serializes single hosts as a bare address. Generation recovery used the public target decoder on the internal `RecoveryTarget`. | `8b75ee5` |
| 2 | The mass-block budget counted the rollback receipt of attempt 1 as an apply. | `aad5e12` (`receipt_kind = 'apply'`) |

Limits of this evidence: one target, one host, a documentation address. The
reported 75.05 s is the combined block-seen-to-restore-and-journal time, not the
kernel expiry time; the journal receipt landed 1.77 s after the TTL deadline.

## 7B — 48 h read-only observation: window elapsed, gate NOT passed

Source: `observation/report.json` of the pilot state directory
(`status=window_elapsed_requires_review`).

| Fact | Value |
| --- | --- |
| Window | 48.0 h (2026-10-18 18:13 UTC to 2026-10-20 18:13 UTC) |
| Nominal samples | 2880 (window / 60 s) |
| Recorded probe attempts | 2676 (every row of `samples.jsonl`) |
| Successful probes | 2508 |
| Failed probes | 168 (6.3 % of attempts), all `telemetry_unavailable` (SSH) |
| Actual cycle | mean 64.6 s (probe time plus the 60 s sleep); the 204 below nominal is cadence, not a hole |
| Failure shape | 146 separate runs; longest 4 consecutive attempts; largest gap between attempts 92 s; largest gap between successful probes 332.7 s; no gap over 3 intervals |
| Successful probes | all idle: 0 unresolved generations, 0 executable requests, empty block sets, no running executor, API healthy |

Correction (2026-10-21): an earlier version of this page and of the report
summary read "2676 of 2844 successful". That was wrong: `report.json`'s
`sample_count` counts all attempts including the 168 failures. The figures above
are reproduced by `scripts/pilot-observation-evaluate.py` (unit-tested in
`scripts/test-pilot-observation-evaluate.py`), which also lists what was *not*
measured and never passes a gate.

What this does not show:

* False positives were **not measured** (the only block was the documented
  canary address); `classification_false_positives` stays unmeasured.
* Rollback p95 (target <= 5 s) has a single sample, so no percentile exists.
* Lockout and drift SLOs were not stressed; the system was idle.

Per `docs/phase7-pilot-limits.md`, telemetry failure stops new automatic
applies. `automatic_rule_gate_passed` is `false` and stays so: the failure
pattern is consistent with the known flaky management link to the VPS, but that
is an inference, not a measurement. Deciding whether this is acceptable, or
repeating the window with a more tolerant probe or a second path, is an
operator decision.

## 7C — policy to execution bridge: not started

Blocked by the open 7B gate. Findings from reading the current code:

* The policy engine persists shadow decisions only; the sole enqueue path is
  `clawforge_enqueue_goaway_shadow_challenge` (simulation-only challenge).
* Targets travel as `ip-pseudonym:<hash>`. The write side of
  `security_ip_resolutions` (short TTL, default 24 h) always existed, but **no
  code read it**, and the journaled apply path refused a resolved address
  (`render` rejects it by design). A real incident-source block was therefore not
  possible at all. Migration 0059 adds the missing narrow reader (executor role
  only, request must be `starting`, not `simulation_only`, resolution unexpired,
  single host) and the executor now resolves just before a real apply and journals
  a receipt-safe view; see "Incident-source resolution" below.
* An approval-gated request (`waiting_approval`) needs `requested_by_id`
  referencing `admin_users`, `required_approvals >= 1`, an expiry and an
  `approval_context_hash` computed in Rust (migration 0029 trigger plus
  `execution_context_hash`). `status = 'pending'` requests are claimable without
  approval, so an unattended path must be gated by the action's `enabled` flag,
  the executor's live gates and budgets.
* Independent evidence: `evidence_sources` counts rules and threat-intel hits,
  not independent sensors; a bridge must not treat the count as independence.

## Incident-source resolution (migration 0059)

* Reader: `clawforge_resolve_incident_source_for_apply(execution_id)`, executable
  by `clawforge_executor` only; the role still has no `SELECT` on the table.
* Executor: a real apply of an `incident_source` target resolves the request's own
  pseudonym; a missing or expired resolution refuses the apply without touching the
  host. Dry runs never resolve and are previewed through the pure `render`.
* Receipts, previews and the rule fingerprint carry the pseudonym only. The
  restricted recovery snapshot (`fw_target_json`) holds the exact address, as it
  already does for threat-intel indicators, because TTL and crash recovery must
  reconstruct the rollback target; it is an operator-only row, never projected to
  agents.
* Audit: every resolution attempt writes `incident_source_resolved_for_apply` with
  the pseudonym and outcome, never the address.
* Evidence: PostgreSQL role/negative tests (`storage/tests/incident_source_resolution.rs`,
  in `scripts/test-postgres.sh`) and an isolated lab with a real kernel and real
  PostgreSQL (`incident_source_real_apply_resolves_journals_and_rolls_back_lab`, run
  in a container sharing a fixture's network namespace).
