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

## Threat-intel corroboration (what raises `evidence_sources` above 1)

The `intelligence` crate ingests Spamhaus DROP/EDROP/ASN-DROP, RPKI, BGP
and ASN change feeds into `indicators`/`asn_records`/`rpki_records`/
`bgp_events` - real threat-intel data. Combining it with a behavioral
assessment (an `ssh_bruteforce` detection *and* the same source being
Spamhaus-listed) is exactly the roadmap's "Threat-Intel-plus-Verhalten"
rule shape, and is the second evidence source that makes `Block` reachable
for the first time - live, feeds enabled
(`CLAWFORGE_ENABLE_FEEDS=CLAWFORGE_ENABLE_NETWORK=true`, and
`clawforge-worker` given its own dedicated `egress` network to actually
reach them; `backend` stays `internal: true` for every other service).

Two real constraints shaped how this is wired in, both explained in
`PostgresStore::lookup_ip_reputation`'s own doc comment:

1. `clawforge-security-engine`'s assessments only ever hold a pseudonymized
   resource (`ip-pseudonym:<hash>`, the same fail-closed HMAC scheme
   `events.correlation_id` already uses) - by design, the raw IP a
   Spamhaus DROP-list lookup needs is never available at that point. The
   only place a raw sensor-reported IP still exists server-side at all is
   *inside* `record_security_event`, right before it pseudonymizes
   `envelope.resource` - so the lookup happens exactly there, and only a
   category flag (`metadata.threat_intel_hit`/`threat_intel_source` on the
   canonical event, matched via Postgres's `<<=` CIDR-containment operator
   against `indicators` rows with `source LIKE 'spamhaus%'`) crosses into
   anything persisted further - never the IP itself. The lookup fails
   *open* (a lookup error is treated as "no hit", never blocks recording
   the event) - deliberately the opposite of pseudonymization's fail-closed
   design, since a reputation check is an enrichment, not a privacy
   boundary that must never be silently bypassed.
2. `clawforge-security-engine` reads that flag back per bucket
   (`bucket_threat_intel_hit_details`) when it persists an assessment - one
   hit anywhere in the bucket is enough to set
   `security_assessments.threat_intel_corroborated` (migration `0035`),
   not a majority. `clawforge-policy-engine` then computes
   `evidence_sources` as `2` instead of the previous hardcoded `1` whenever
   that flag is set *and* the hit is still fresh/confident enough to trust
   (see "Freshness, provenance and confidence" below -
   `evidence_sources_for`), which is what actually lets
   `clawforge_policy::decide()` reach `Block` for a high-confidence,
   corroborated assessment - proven by a dedicated unit test
   (`threat_intel_corroboration_is_what_makes_block_reachable_at_all`) and
   a real-Postgres one showing a single threat-intel hit in an otherwise
   plain bucket is enough
   (`a_single_threat_intel_hit_in_the_bucket_corroborates_the_whole_assessment`).
   **Still only ever recorded as a shadow decision** - no action layer
   exists to execute a `Block` on.

## Freshness, provenance and confidence (migration `0044`, roadmap phase 8)

`lookup_ip_reputation` originally only checked `indicators.source LIKE
'spamhaus%'` and returned nothing but which feed hit - roadmap phase 8's
"vorhandene Provider um Freshness, Provenance und Confidence ergaenzen"
closed both gaps at once:

- **Every provider, not just Spamhaus.** The query now matches any
  ingested indicator (`threatfox`/`urlhaus`/`feodo_tracker`/
  `malwarebazaar`/every Spamhaus feed) whose `indicator_type` is `Ip` or
  `Prefix` - the non-IP indicator types the other providers also produce
  (hashes, URLs, domains) simply never match this shape, so widening the
  source filter needed no separate exclusion list. When more than one
  indicator matches, the highest-confidence one wins (ties broken by most
  recently confirmed) - deterministic, and a caller is never handed the
  *lesser* of two matching hits.
- **`security_assessments` now carries the actual hit**, not just a
  boolean: `threat_intel_source`, `threat_intel_confidence`,
  `threat_intel_indicator_last_seen` (all-or-nothing together, enforced by
  a `CHECK` constraint). `threat_intel_corroborated` stays exactly what it
  always meant - "some indicator matched at ingest time" - the new columns
  are what make that explainable instead of a bare `true`.
- **A stale or low-confidence hit does not corroborate.** This is the
  literal roadmap phase 8 exit gate: "Offline- oder veraltete ... Feeds
  reduzieren Confidence und loesen keine automatische Eskalation aus."
  `evidence_sources_for` only counts a threat-intel hit toward
  `evidence_sources=2` if `threat_intel_hit_is_corroborating` accepts it -
  `confidence >= CLAWFORGE_THREAT_INTEL_MIN_CONFIDENCE` (default 50) *and*
  `last_seen` no older than `CLAWFORGE_THREAT_INTEL_MAX_STALENESS_SECONDS`
  (default 7 days, and never a *negative* age either - a `last_seen` from
  the future, e.g. from clock skew, is rejected rather than treated as
  infinitely fresh). A stale/low-confidence hit still leaves
  `threat_intel_corroborated=true` on the assessment (it is an honest
  record of what happened at ingest time) but the assessment itself stays
  at `evidence_sources=1` - it can still reach `Block` via cross-rule
  corroboration, just not on the strength of that one external hit alone.
  Both thresholds, and every value they compare, are already visible on
  the persisted assessment or in this service's own env config - "jede
  Score-Komponente bleibt erklaerbar" by construction, not by convention.

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
