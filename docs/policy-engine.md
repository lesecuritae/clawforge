# Policy Engine (Shadow Mode)

Roadmap phase 5 ("Policy Engine"). `clawforge-policy-engine` evaluates
`clawforge-security-engine`'s persisted assessments against versioned
policies and records a decision - **it never executes anything**. That is
not a runtime flag defaulting to safe; roadmap phase 6 ("Firewall Action
Layer") does not exist yet, so there is no action layer this service could
call even if it wanted to. Shadow mode is a property of the current
architecture.

## Why reuse `clawforge_policy::decide`, not a new decision function

`decide()` already existed (for a different, unrelated concern - internal
operator action authorization) and already encodes the exact rule the
roadmap's phase 4 exit gate asks for: **a single evidence source can never
reach `Block`** (`evidence_sources >= 2` is required). Every assessment
`clawforge-security-engine` produces today has exactly one evidence source
- the behavioral rule that produced it - so `EVIDENCE_SOURCES = 1` in
`policy-engine/src/main.rs` is not a policy choice this service makes, it
is a fact about what has been correlated so far. `Block` is therefore
structurally unreachable right now, proven by
`a_single_evidence_source_can_never_reach_block` rather than merely
asserted. The moment a second, independent signal exists (see below), that
changes on its own, without this service's logic changing at all.

## What would raise `evidence_sources` above 1 (not built yet)

The `intelligence` crate already ingests Spamhaus DROP/EDROP/ASN-DROP,
RPKI, BGP and ASN change feeds into `indicators`/`asn_records`/
`rpki_records`/`bgp_events` - real threat-intel data, already in this
database. Combining it with a behavioral assessment (an `ssh_bruteforce`
detection *and* the same source being Spamhaus-listed) is exactly the
roadmap's "Threat-Intel-plus-Verhalten" rule shape, and would be the second
evidence source that makes `Block` reachable for the first time.

This is deliberately **not** wired in yet, for two reasons:

1. `clawforge-security-engine`'s assessments only ever hold a pseudonymized
   resource (`ip-pseudonym:<hash>`, via the same fail-closed HMAC scheme
   `events.correlation_id` already uses) - by design, the raw IP a
   Spamhaus DROP-list lookup needs is never available at that point. The
   only place a raw sensor-reported IP still exists server-side is
   *before* `record_security_event` pseudonymizes it - a lookup would have
   to happen there, storing only a category result (e.g.
   "spamhaus_listed: true"), never the IP itself, to keep the existing
   privacy guarantee intact rather than working around it.
2. This deployment currently runs with `CLAWFORGE_ENABLE_FEEDS=false` and
   `CLAWFORGE_ENABLE_NETWORK=false` - the Spamhaus/RPKI/BGP/ASN feeds are
   not actually being polled, so `indicators` etc. are empty right now.
   Enabling them is a separate decision (real network egress from the
   host) that has not been made.

## Schema (migration `0034`)

`security_policies`: versioned (`UNIQUE (name, version)`), `status`
(`draft`/`active`/`retired`), `class` (`observe`/`approval`/`automatic` -
what a decision would require *if* an action layer existed), `rule_id`
(which security-engine rule this evaluates), `min_severity`,
`valid_from`/`valid_until`. Only `active` policies whose validity window
covers "now" are evaluated. Seeded with one `class=observe`, version 1,
`min_severity=medium` policy per rule currently implemented
(`ssh_bruteforce`, `http_anomaly_burst`, `http_scan`) - `observe` even
though nothing executes yet, so a later change that raises a policy to
`approval` or `automatic` is a deliberate, reviewable step, not a default.

`security_policy_decisions`: one row per `(policy_id, policy_version,
assessment_id)` (folded into `dedupe_key`, `UNIQUE`) - replaying the same
assessment through the same policy version always upserts the same row.
Carries the `decision` (`observe`/`challenge`/`rate_limit`/`block`,
`clawforge_policy::Decision`'s own vocabulary), `risk_score`,
`evidence_sources`, `corroborated`, a human-readable `rationale`, an
`evidence_snapshot` (JSON) and `evidence_hash` (sha256 of policy id/version
+ snapshot - the roadmap's "unveränderlicher Hash" binding, today only
covering policy and evidence since there is no action/adapter/diff yet to
extend it with), and `is_shadow` (always `TRUE`).

## Replay

Every poll cycle (`CLAWFORGE_POLICY_ENGINE_POLL_SECONDS`, default 15s)
re-evaluates the most recent assessments
(`CLAWFORGE_POLICY_ENGINE_RECENT_ASSESSMENTS`, default 200), not just new
ones - the upsert-by-`dedupe_key` design means recomputing an unchanged
(policy, assessment) pair is a harmless no-op, and recomputing one whose
assessment grew (its bucket filled further) or whose policy changed
produces an updated decision in place. This is what makes the phase 5 exit
gate "Policies können gegen historische Incidents replayed werden" true by
construction: there is no separate "replay mode", normal operation already
is replay-safe re-evaluation.

## Real-database test coverage

`policy-engine/src/main.rs`'s own `#[ignore]`-gated Postgres test (run via
`scripts/test-postgres.sh`, under the `policy_engine` role) proves, against
a real assessment and the seeded `ssh_bruteforce-default` policy: exactly
one decision is recorded, `is_shadow` is `TRUE`, `decision` is never
`block`, `corroborated` is `false`, and replaying the identical assessment
upserts the same row rather than duplicating it.
