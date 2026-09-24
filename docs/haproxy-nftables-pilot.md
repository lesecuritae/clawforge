# HAProxy/nftables Pilot

Roadmap phase 7 ("HAProxy/nftables Pilot"). This phase is fundamentally
different in kind from phase 6, not just degree: its later gates require
a real, manually-approved production canary block (`CLAWFORGE_EXECUTOR_DRY_RUN`
would have to become `false`) and a formal, quantified Security Review
(pilot duration, canary count, false-positive budget, rollback-p95,
drift-detection time, lockout SLO, max block count) before the phase
even starts. Neither of those is something this crate/service can do on
its own - they are explicit human decisions and a human review process.
What follows is the engineering prerequisite the roadmap itself asks for
*before* Gate 7A: "vor Gate 7A existiert eine geprueft Approval-
Oberflaeche ...". `CLAWFORGE_EXECUTOR_DRY_RUN` stays hardcoded `true`;
nothing in this phase's current work changes that.

## Approval surface (Gate 7A prerequisite)

The roadmap's own wording: "eine geprueft Approval-Oberflaeche, die
unveraenderlichen Action-Diff, Evidence und Alter, Ziel/Blast Radius,
Istzustand, TTL, Rollbackplan und alle Freigaben zeigt" - an audited
approval surface showing an immutable action diff, evidence and its age,
target/blast radius, current state, TTL, rollback plan, and every
approval.

`GET /executions/{id}` (role-gated `Administrator`/`Operator`/`Viewer`,
same as every other admin list) assembles this from data that mostly
already existed, plus one genuinely new capability:

- **Immutable action diff**: `target` is exactly what
  `approval_context_hash` was computed over (migration `0029`) - so a
  reviewer sees precisely what they are approving, bit for bit, the same
  binding that already makes drift invalidate a stale approval.
- **Evidence and its age**: `LEFT JOIN`ed from `security_policy_decisions`/
  `security_assessments` via `decision_id` (`None` for a request that did
  not originate from the policy engine). `evidence_age_seconds` is
  computed at read time (`NOW() - assessment.created_at`) - the roadmap
  is explicit elsewhere that "veraltete ... Threat-Intelligence" can
  never justify more than `observe`/`approval`, and a reviewer needs the
  actual age to judge that, not just a timestamp to do the arithmetic on
  themselves.
- **Action preview - the new capability**: `render()` on every adapter is
  pure and synchronous (no adapter I/O at all - see
  `docs/firewall-agent.md`'s "Command construction" section), so it is
  always safe to compute *before* a request has been approved or applied.
  `action_preview` calls it live against the request's own `target`,
  returning exactly the `rendered_commands`/`rollback_commands`/
  `ttl_seconds` a real dispatch would produce - the literal "Action-Diff
  ... Rollbackplan" a reviewer needs to see before approving, not a
  description of what already happened. Uses
  `clawforge_firewall_agent::adapter_for_action` - the *exact* routing
  table `clawforge-executor`'s real dispatch uses (moved there from what
  was originally `clawforge-executor`'s own private `adapter_for`,
  specifically so this preview can never show a reviewer a different
  adapter than the one that would actually run). `None`/absent for an
  unrecognized action name or an unparseable target - never fails the
  rest of the detail view.
- **Blast radius**: `blast_radius_hint` flags whether a
  `threat_intel_indicator` target is a single address (`/32`, `/128`, or
  a bare IP with no prefix at all - canary-sized) or wider. Purely a
  hint for a reviewer, computed from the target's own JSON; the adapter's
  own `validate`/never-block checks remain the real gate, at apply time.
- **All approvals**: `execution_approvals` (migration `0029`) was already
  append-only/immutable by DB trigger - `list_execution_approvals` is a
  plain, complete read of who approved and when, in order.

## What Gate 7A itself still needs - not built, and not this crate's to decide

- The quantified numbers themselves (pilot duration, canary count,
  false-positive budget, rollback-p95, drift-detection time, lockout SLO,
  max block count) - policy decisions for an operator, not something to
  default or infer.
- The formal Security Review that approves those numbers - a human
  process.
- Actually flipping `CLAWFORGE_EXECUTOR_DRY_RUN` to `false` and running a
  real `/32`/`/128` canary against a real production host - the "hard to
  reverse / outward-facing" action this session's own discipline
  (confirm-before-acting on anything touching real infrastructure) does
  not proceed on without an explicit, separate go-ahead.

## Gates 7C/7D

Deliberately not started - the roadmap sequences them *after* 7A/7B's
real pilot period succeeds (an automatic bruteforce/scanner rule, then a
renewed review before any further expansion). Building that code now,
before a pilot has even run, would be getting ahead of the roadmap's own
stated order for no reason.
