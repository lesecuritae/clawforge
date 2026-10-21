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
| Samples | 2676 successful of 2844 attempted (2880 expected at 60 s) |
| Failed probes | 168 (5.9 %), all `telemetry_unavailable` (SSH) |
| Failure shape | Scattered; most are single missed samples, longest run 5 consecutive minutes, largest gap between any two recorded samples 92 s |
| Successful probes | all idle: 0 unresolved generations, 0 executable requests, empty block sets, no running executor, API healthy |

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

Blocked by the open 7B gate. Findings from reading the current code, to save the
next implementer the investigation:

* The policy engine persists shadow decisions only; the sole enqueue path is
  `clawforge_enqueue_goaway_shadow_challenge` (simulation-only challenge).
* Targets travel as `ip-pseudonym:<hash>`. The executor resolves them to a raw
  IP only at apply time through `security_ip_resolutions` (short TTL, default
  24 h) and never stores the resolved value in a receipt. A Block/RateLimit
  bridge can therefore reuse the existing incident-source actions
  (`nftables.`, `haproxy.`, `haproxy_ratelimit.` and `firewall.block_incident_source`).
* An approval-gated request (`waiting_approval`) needs `requested_by_id`
  referencing `admin_users`, `required_approvals >= 1`, an expiry and an
  `approval_context_hash` (migration 0029 trigger). A service-account requester
  therefore needs a dedicated, reviewed identity. Fully automatic execution
  (status `pending`, zero approvals) is a separate decision that
  `security_policies.class = 'automatic'` is meant to carry.
* Independent evidence: `evidence_sources` counts rules and threat-intel hits,
  not independent sensors; a bridge must not treat the count as independence.

Operator decisions needed before any code: requester identity, which policy
class may enqueue, TTL and budget per rule, which single rule is the first
automatic candidate. Until then nothing in this repository changes execution.
