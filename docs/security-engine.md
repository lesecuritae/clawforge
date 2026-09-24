# Security Engine

Roadmap phase 4 ("Security Engine"). `clawforge-security-engine` is a new
service that consumes canonical events (`docs/security-events.md`'s sensors
publish onto this bus too, see below) and applies count-threshold detection
rules a pairwise correlator cannot express.

## Why a separate engine, not an extension of `clawforge-correlation`

`clawforge-correlation` answers "are these two events related?" - useful for
threat-intel event chains, but not the shape of "N failed SSH logins from
the same source within five minutes": that is a property of a *set* of
events, not a relationship between a pair. `clawforge-security-engine` runs
as its own named consumer on the same `event_delivery` fan-out
(`claim_event_deliveries("security-engine", ...)`), side by side with
`clawforge-correlation`'s own `"correlation"` consumer - neither sees or
affects the other's delivery rows, and neither's failure or backlog blocks
the other.

It reuses `clawforge-correlation`'s already-idempotent, escalation-aware
`persist_correlation`/`incident_candidates` path for incident creation
rather than building a second one: a rule that fires calls it the same way
`clawforge-correlation` does, inheriting the same replay-safety and
escalation-instead-of-duplication behavior `incident-correlation-convergence`
already gave that path earlier in the roadmap.

## Sensors now publish onto the canonical event bus

`record_security_event` (the security-events-ingress storage layer) now
also calls `publish_event` for every genuinely new security event - never
for a sensor's own at-least-once retry resubmission, which returns early
before reaching this - so `clawforge-security-engine` (and, if ever useful,
`clawforge-correlation`) can see sensor data without querying
`security_events` directly. `correlation_id` is set to the event's already-
pseudonymized `resource` (an IP source is already `ip-pseudonym:<hex>` by
this point - `publish_event`'s own correlation-id sanitizer only touches a
value that still parses as a raw IP address, so this passes through
unchanged, never double-hashed). This is what lets a rule group repeated
events from the same pseudonymous source without ever handling a raw IP
itself.

Sensor event types are deliberately **not** added to
`clawforge_correlation::is_correlatable()`: a single `ssh_login_failure`
must never become a solo incident candidate the way a single
`rpki_invalid` legitimately does (see that function's own doc comment) -
one failed login is not, by itself, a security incident. Gating this in
`clawforge-security-engine`'s own rule set instead keeps that noise out of
`clawforge-correlation` entirely.

## Rules

A rule is a pure count threshold over one canonical `event_type`, keyed by
`correlation_id`, evaluated against a **deterministic tumbling-window
bucket**: `bucket_start = floor(event.occurred_at / window_seconds)`. This
is the core design decision behind the roadmap's exit-gate requirement
"gleiche Events und Regelversion erzeugen deterministisch dasselbe
Assessment": a sliding window ("the N seconds before this event") depends
on exactly when the rule happens to run and is not reproducible across a
replay; a fixed bucket is a pure function of the event's own timestamp, so
the same events always produce the same bucket, the same count, and (via
`dedupe_key = rule_id:rule_version:resource:bucket_start`) the same
assessment row, no matter how many times or in what order they are
(re)processed. The cost is up to one bucket's worth of detection latency at
a boundary; a real attack does not stop after one bucket, so it is still
caught in the very next one.

Currently implemented (`security-engine/src/main.rs`):

- **`ssh_bruteforce`** (v1, `CountThresholdRule`): 5+ `ssh_login_failure`
  events from the same pseudonymous source within 300s.
- **`http_anomaly_burst`** (v1, `CountThresholdRule`): 10+ `http_anomaly`
  events from the same pseudonymous source within 300s.
- **`http_scan`** (v1, `DistinctValueThresholdRule`): 8+ *distinct* `path`
  values across `http_anomaly` events from the same pseudonymous source
  within 300s - not a raw count. A scanner probing eight different
  endpoints once each and a script hammering the same endpoint eight times
  are different behaviors; `http_anomaly_burst` catches the second, this
  catches the first. `evaluate_rule` and `evaluate_scan_rule` share the
  same persistence tail (`persist_assessment_and_incident`) so both kinds
  of rule inherit the same dedupe/replay/incident-reuse behavior from one
  place.

Severity/confidence scale with how far over the threshold the count (or,
for a `DistinctValueThresholdRule`, the distinct-value count) is
(`severity_for_count`/`confidence_for_count`). Not yet implemented, left
for a later increment: a genuine multi-*target* rule (one source hitting
many different destination hosts - not meaningful yet with only one
monitored SSH endpoint and one monitored HTTP endpoint; revisit once more
are), threat-intel provenance/freshness/confidence/conflict rules (the
`intelligence` crate already ingests Spamhaus DROP/EDROP/ASN-DROP, RPKI,
BGP and ASN change feeds - combining those with this engine's own
behavioral assessments into one decision is Phase 5 "Policy Engine"'s job,
not this crate's), and a full golden attack scenario / false-positive /
false-negative fixture suite beyond what each rule's own tests already
cover.

## Persistence

Migration `0033`: `security_assessments` (one row per rule × resource ×
bucket, `UNIQUE (dedupe_key)`) and `security_assessment_events` (evidence
*references* - the canonical event's id, not a copy of its payload).
`security_assessments.incident_id` is a best-effort courtesy link, set via
`get_incident_id_for_candidate` once `persist_correlation`'s returned
candidate has actually been promoted (its return value is
`incident_candidates.id`, never `incidents.id` - `promote_incident_candidates`
always mints a fresh id for the incident row itself); a not-yet-promoted
candidate simply leaves the column `NULL` rather than being retroactively
backfilled the way `alerts.incident_id` is elsewhere.

`clawforge_security_engine` is a new least-privilege database role (see
`scripts/provision-db-roles.sh`): read access to the canonical event bus and
`incidents`, and its own tables - no access to `security_events` itself
(rules operate purely on canonical events) or to any table outside this
scope.

## Real-database test coverage

`security-engine/src/main.rs`'s own `#[ignore]`-gated Postgres test (run via
`scripts/test-postgres.sh`, under the `security_engine` role) proves, end to
end: four events below the threshold of five create nothing; the fifth
creates exactly one assessment and exactly one incident; a sixth event in
the same bucket updates that same assessment in place and does not
duplicate the incident; and replaying the identical sixth event again
leaves every count unchanged - deterministic, not merely idempotent by
accident.
