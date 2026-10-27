# Next Phase 7B observation: pre-registered, bounded, honest

The first 48 h window (`phase7-pilot-evidence-20261021.md`) ended `window_elapsed_requires_review`: 2676
attempts, **168 failed** (`telemetry_unavailable`, 146 runs, longest 4, largest gap between successful probes
332.7 s) and every successful probe was an idle-system health check. Those failures stay failures. This page
describes the tool that makes the *next* window judgeable: `scripts/phase7b-observe.py`
(tests: `scripts/test-phase7b-observe.py`). The 24 h attack-shape observer
(`scripts/shape-observation-evaluate.py`) is a different measurement and **never** satisfies 7B.

## What it fixes

| First window | Next window |
| --- | --- |
| Criteria decided after the data | `plan` freezes window, probe and numeric criteria and hashes them; editing the plan afterwards makes every command refuse it |
| A failed probe was one lost minute | up to 3 attempts per cycle with backoff and a per-attempt timeout; **every attempt is a row**, a cycle is ok only if one attempt returned a valid snapshot |
| Sleep of a full interval after each probe (cadence 64.6 s, 204 samples short) | the loop keeps the interval (probe time is subtracted) |
| Idle probes read like evidence | idle probes satisfy only telemetry and idle-invariant criteria; false positives, rollback p95, packet effect, lockout and drift are computed **only** from `measurements.jsonl` |
| Operator labels, lab traffic and guesses mixed | `operator`, `lab_controlled` and `unknown` counters; only `operator` labels count for the false-positive criterion |
| Stop conditions in the operator's head | bounded runtime, stop file, consecutive-failure stop (exit 4), state-violation stop (exit 5: unresolved generation, executable request, active block element, running executor, API unhealthy) |

## Pre-registered criteria (defaults; operator confirms or changes BEFORE the start)

Telemetry (per cycle): availability >= 0.99, longest run of failed cycles <= 3, gap between successful cycles
<= 300 s, window coverage >= 95 % of nominal cycles. Events (real, approved, non-lab canaries only; >= 10):
rollback p95 <= 5 s (nearest rank), receipt after deadline <= 5 s, baseline passed / blocked dropped / restored
passed in each. Lockout: >= 20 protected-address probes, all refused. Drift: >= 3 injected drifts, each detected
<= 10 s. False positives: >= 5 operator-labelled targets, 0 accepted. Values come from
`phase7-pilot-limits.md` where it states them; the sample sizes are proposals that need the operator's yes.

Replaying the first window through these criteria (control, `evaluate` on its real `samples.jsonl`) gives
`CRITERIA_NOT_MET`: availability 0.93722 (< 0.99), longest failure run 4 (> 3), largest gap 332.7 s (> 300 s),
coverage 0.929 (< 0.95), and everything event-based `not_measured`.

## Verdicts

`INSUFFICIENT_EVIDENCE` (window open, anything not measured, or plan not confirmed), `CRITERIA_NOT_MET`, and
`CRITERIA_MET_REQUIRES_OPERATOR_REVIEW`. `gate_passed` is always `false`. A perfect idle window is
`INSUFFICIENT_EVIDENCE`.

## Use (nothing here installs a timer; run it under the existing coordination with Codex)

```
phase7b-observe.py plan --out plan.json --start 2026-10-26T08:00:00Z --hours 48 \
  --probe-argv-json '["ssh","-o","BatchMode=yes","-o","ConnectTimeout=7","-o","ServerAliveInterval=3","-o","ServerAliveCountMax=1",
                      "root@<pilot-host>","python3","/root/clawforge-pilot-20261018/observe.py","snapshot","<existing-request-id>"]' \
  --stop-file ~/.local/state/phase7b/STOP --max-runtime-seconds 180000
# operator edits only operator_confirmed_by / operator_confirmed_at (they are outside the plan hash)
phase7b-observe.py probe --plan plan.json --samples samples.jsonl
phase7b-observe.py evaluate --plan plan.json --samples samples.jsonl --measurements measurements.jsonl --out report.json
```

The probe reuses the remote read-only `observe.py snapshot` already on the pilot VPS; it installs nothing there. Use
the tailnet path as primary. A second transport (public sshd) is deliberately not configured: failed authentications
from an unlisted source would pollute the very SSH signals this system measures.

`measurements.jsonl` record types: `canary` (`lab`, `distinct_human_approvals`, `baseline_ok`, `blocked_dropped`,
`restored_ok`, `rollback_seconds`, `receipt_after_deadline_seconds`), `lockout_probe` (`protected_address`,
`refused`), `drift_injection` (`injected_at`, `detected_at` = the `created_at` of the `firewall_rule_drift_detected` audit event of that generation; an injection without such an event is undetected), `false_positive_review` (`label_source`,
`classification`, `was_blocked`). Lockout probes can be produced without touching a host by the real-parser
validator (`candidate_never_block_list_protects_every_listed_address_and_allows_the_canary`).

## Single-operator deployments

The observation plan defaults to two distinct approvals. Existing registered
plans keep that default and their original hashes; they are never reinterpreted
as single-operator plans. For an explicitly configured single-operator deployment,
the trusted owner may export `SELECT row_to_json(p) FROM clawforge_approval_profile() p`
to a private JSON file and supply `plan --approval-profile-file profile.json`.
The plan pins the mode, designated operator UUID and action allowlist in its hash.
Changing the file afterwards does not change the plan. Confirmation of the plan
remains a separate human step; the command does not supply it.

An eligible single-operator `canary` measurement must additionally contain:

```json
{
  "request_id": "00000000-0000-0000-0001-000000000001",
  "lab": false,
  "distinct_human_approvals": 1,
  "required_approvals": 1,
  "action": "nftables.block_incident_source",
  "approval_context_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "approval_profile": {
    "mode": "single_operator",
    "operator_user_id": "00000000-0000-0000-0000-000000000099"
  },
  "approval_evidence": {
    "execution_id": "00000000-0000-0000-0001-000000000001",
    "approver_id": "00000000-0000-0000-0000-000000000099",
    "approval_mode": "single_operator_confirmation",
    "context_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

The example IDs/hash are synthetic, not an approval. The trusted collector must
copy these fields from the native request context and `execution_approvals` row,
alongside the existing packet/rollback measurements. The action must be in the
pinned allowlist; the native profile marker, request ID, approver ID and both
context hashes must agree. Ordinary approvals, unknown/lab rows, malformed
evidence and quarantines do not count as a single confirmation. Duplicate request
IDs are excluded, so repeating one row cannot fill the sample size in either mode.

The evaluator consumes trusted evidence files; it does not authenticate a human,
read the current production profile, verify signatures, or create an approval.
It never opens a live gate. A profile/action change requires a new registered
observation plan and operator review. False-positive labels, telemetry, packet
effect, rollback, lockout and drift criteria remain unchanged.

## Operator stop conditions

Stop file present; any state violation; more than `max_consecutive_failed_cycles` consecutive failed cycles; a
block that does not expire by its native timeout; a management or own address ever refused-then-applied. After a
stop the window is not resumed silently: the stop row stays in `samples.jsonl` and the evaluation reports it.
