# Security event catalog

`clawforge-security-events` defines the contract for the Security Event
Layer the roadmap's phase 2 builds toward (`docs/security-control-plane-roadmap.de.md`,
"Empfohlene erste Pull Requests" #6-8): types, validation, and fixtures
(`security-events-domain`), storage (`security-events-storage`, below), and
- not yet built - an authenticated ingress endpoint (`security-events-ingress`).
Nothing writes to storage in production yet: no service holds credentials
for a `security_sensors` row, and no HTTP endpoint calls
`PostgresStore::record_security_event`. That is what `security-events-ingress`
adds.

It is unrelated to `clawforge-events` (the internal consumer of the existing,
free-text event backbone described in `docs/events.md`) and to
`IntelligenceEvent` (`clawforge-intelligence`, the network-intelligence event
shape `record_intelligence_event` persists today). Neither of those changes
here.

## Event types

Eleven event types, matching the categories the architecture note anticipates
(`docs/security-control-plane-architecture.de.md`, "Firewall-, Auth-, SSH-,
HTTP-, DNS-, Scan- und Containerereignisse") - firewall, auth and ssh each
split into a plain occurrence and an anomaly variant, since the evidence
shape and the operational response differ enough to keep separate:

| Event type | Evidence | Meaning |
| --- | --- | --- |
| `firewall_block` | `FirewallBlockEvidence` | a firewall/router rule matched and dropped or rejected traffic |
| `firewall_rule_changed` | `FirewallRuleChangedEvidence` | a firewall/router rule was added, modified or removed |
| `auth_failure` | `AuthFailureEvidence` | a failed authentication attempt against a monitored service |
| `auth_anomaly` | `AuthAnomalyEvidence` | a successful authentication with anomalous characteristics |
| `ssh_login_failure` | `SshLoginFailureEvidence` | a failed SSH authentication attempt |
| `ssh_login_anomaly` | `SshLoginAnomalyEvidence` | a successful SSH login with anomalous characteristics |
| `http_anomaly` | `HttpAnomalyEvidence` | an anomalous or malicious HTTP request pattern (a WAF-style signal) |
| `dns_anomaly` | `DnsAnomalyEvidence` | an anomalous DNS query pattern (tunneling, exfiltration, a DGA indicator) |
| `port_scan_detected` | `PortScanDetectedEvidence` | a port or service scan detected against a monitored host |
| `container_anomaly` | `ContainerAnomalyEvidence` | anomalous container runtime behavior short of a specific escape technique |
| `container_escape_attempt` | `ContainerEscapeAttemptEvidence` | a higher-confidence signal of an attempted container breakout |

`SecurityEventType::ALL` is the canonical list; `as_str()`/`FromStr` use the
lowercase snake_case spelling in the table above, the same convention
`is_correlatable` and the rest of the codebase already use for event type
strings.

## Severity

A closed, ordered scale: `Info < Low < Medium < High < Critical`, serialized
lowercase - the same spelling free-text severities already use elsewhere in
this codebase, so a `Severity` needs no mapping table to fit in.

## Envelope

`SensorEnvelope` is what a sensor submits for one event:

```json
{
  "event_type": "firewall_block",
  "occurred_at": "2024-01-01T00:00:00Z",
  "source": "nftables:homeserver",
  "severity": "medium",
  "resource": "203.0.113.7",
  "dedupe_key": "nftables:homeserver:block:1",
  "rule_id": "drop-inbound-22",
  "source_ip": "203.0.113.7",
  "destination_ip": "198.51.100.10",
  "destination_port": 22,
  "protocol": "tcp",
  "interface": "wan0"
}
```

The wire format is one flat JSON object: `event_type` is an internally
tagged enum discriminant, and the envelope's `evidence` field is
`#[serde(flatten)]`ed, so a type's evidence fields sit directly alongside
`occurred_at`/`source`/`severity`/`resource`/`dedupe_key` rather than nested
under a separate key.

`occurred_at` is the sensor's own clock. A server-assigned receipt time,
schema version and authenticated sensor identity are storage/ingress
concerns layered on top of this envelope, not part of the sensor-facing
contract - see `security-events-storage`/`security-events-ingress` once they
exist. `dedupe_key` is sensor-scoped: `SensorEnvelope::new` only validates
its shape (1..=256 non-blank characters); that a resubmission of an
already-seen key must not accept different content is an ingress-time
invariant that needs persisted state to check, per the roadmap's
`security-events-ingress` item.

`SensorEnvelope::new` is the only constructor and the only place validation
happens: string fields are bounded and rejected if blank after trimming
(`SHORT_FIELD_MAX` = 160 for identifier-like fields such as a rule id, a
username or a container id; `LONG_FIELD_MAX` = 2048 for longer free text such
as an HTTP path or a DNS query name; `RESOURCE_MAX` = 512;
`DEDUPE_KEY_MAX` = 256), and every field named or documented as an IP address
must parse as one. A malformed construction returns `ValidationError` rather
than panicking or silently truncating.

## Fixtures

`security_events::fixtures` provides one realistic, valid `SensorEnvelope`
per event type (`fixtures::all()`, in `SecurityEventType::ALL` order), for
this crate's own tests and for a future ingress endpoint's contract tests and
fixture sender to reuse directly rather than re-inventing example payloads.

## Storage (`security-events-storage`)

Migration `0031_security_events.sql` adds three tables, additive only -
existing `events`/`event_delivery`/`audit_events` are untouched:

- `security_sensors`: a persistent sensor identity (`name`,
  `credential_hash`, `credential_prefix`, `enabled`, `rotated_at`,
  `revoked_at`, `last_seen_at`), the same shape `agent_tokens`/`api_tokens`
  already use elsewhere - storage only ever sees an already-hashed
  credential (argon2, hashed by the caller) and a short, non-secret prefix
  for display, never a credential in the clear. Revocation is terminal: a
  revoked sensor cannot be re-enabled.
- `security_sensor_audit`: one row per `registered`/`credential_rotated`/
  `enabled`/`revoked` action, with an actor and an optional reason.
- `security_events`: one row per accepted `SensorEnvelope`, keyed by a
  server-assigned `id`. `occurred_at` (the sensor's clock) and `received_at`
  (this server's clock, defaulted at insert) are kept distinct so a future
  ingress endpoint's clock-skew check has both to compare. `resource` and
  every IP-shaped evidence field are pseudonymized before the row is ever
  written - the same `CLAWFORGE_ANALYZER_IP_HMAC_KEY` machinery
  `events.correlation_id`/payload already use (`incident-correlation-convergence`),
  applied here as an explicit match over each evidence type's known fields
  rather than the generic key-name heuristic `sanitize_analysis_value` uses
  for free-text JSON, since this evidence is already strongly typed. A
  resubmission of a `(sensor_id, dedupe_key)` pair already stored is
  idempotent only if every reported field (`event_type`, `severity`,
  `occurred_at`, `resource`, `evidence`) is unchanged; a resubmission that
  changes any of them is rejected outright, per the roadmap's
  `security-events-ingress` dedupe requirement.

`PostgresStore` methods: `register_security_sensor`,
`rotate_security_sensor_credential`, `set_security_sensor_enabled`,
`authenticate_security_sensor` (looks up an enabled, non-revoked sensor by
credential hash and bumps `last_seen_at`), `get_security_sensor`,
`list_security_sensors`, `record_security_event`, `get_security_event`,
`list_security_events`.

No new grant was needed for `clawforge-api` (below) to use these tables:
`clawforge_api`'s role already holds `SELECT, INSERT, UPDATE, DELETE ON ALL
TABLES IN SCHEMA public` (`scripts/provision-db-roles.sh` - "the
authenticated administrative boundary", unlike the narrower per-service
roles), which covers any table a migration adds as long as
`clawforge-db-roles` runs after that migration is applied. On a fresh
deployment this happens automatically (`clawforge-db-roles` depends on
`clawforge-migrate` completing first); **upgrading an existing deployment
past migration `0031` requires re-running `clawforge-db-roles` once**, or
`security_sensors`/`security_events` stay inaccessible to `clawforge-api`
until it does. The real-Postgres integration test for the storage layer
itself (`storage/tests/postgres.rs`, `security_events_register_sensor_and_record_event`,
part of `scripts/test-postgres.sh`) uses the owner connection regardless, the
same as `migrations_and_restart_persist`.

## Ingress (`security-events-ingress`)

`POST /internal/security-events/batch` on `clawforge-api`, authenticated by
a `security_sensors` credential (`Authorization: Bearer <raw credential>`,
looked up by its SHA-256 digest via `authenticate_security_sensor` - the
same digest-lookup pattern `agent_tokens`/`api_tokens` already use, not the
fixed per-service tokens `InternalIdentity` checks for `clawforge-api`'s
other internal endpoints, since a sensor is a dynamic, individually
revocable identity rather than a first-party Clawforge service). A sensor is
registered with `PostgresStore::register_security_sensor` directly (no admin
HTTP endpoint for that exists yet - out of scope here); the caller hashes
the raw credential (SHA-256 digest, matching `agent_tokens`) before handing
it to storage, which never sees a credential in the clear.

The request body is a JSON array of envelopes (any shape `SensorEnvelope`
serializes to - `security_events::fixtures` is representative). Each item is
handled independently and reported in its own result, so one bad item never
fails the rest of the batch:

```json
{
  "status": "ok",
  "data": {
    "accepted": 1,
    "rejected": 1,
    "results": [
      {"index": 0, "status": "accepted", "event_id": "..."},
      {"index": 1, "status": "rejected", "error": "occurred_at is 172801 second(s) old, beyond the 86400-second limit"}
    ]
  }
}
```

Per Phase 2's ingress requirements:

- **Auth**: see above; a missing or unrecognized/disabled/revoked
  credential is `401` before any item is looked at.
- **Größenlimit (size limit)**: at most `SECURITY_EVENT_BATCH_MAX_ITEMS`
  (100) items per batch (`400` if exceeded, without processing any item),
  and the route carries its own `DefaultBodyLimit`
  (`SECURITY_EVENT_BATCH_MAX_BODY_BYTES`, 512KB) tighter than axum's global
  2MB default.
- **Idempotenz (idempotency) / dedupe**: `record_security_event`
  (`security-events-storage`) makes a resubmission of an unchanged
  `(sensor_id, dedupe_key)` pair return the same `event_id`; a resubmission
  that changes any reported field is rejected as that item's own error.
- **Clock-Skew-Prüfung**: `occurred_at` must be within
  `CLAWFORGE_SECURITY_EVENTS_MAX_FUTURE_SKEW_SECONDS` (default 300) ahead of
  the server clock and within `CLAWFORGE_SECURITY_EVENTS_MAX_PAST_AGE_SECONDS`
  (default 86400) behind it, checked per item
  (`check_security_event_clock_skew`); a non-positive override falls back to
  the default rather than disabling the check.
- **Nonce/Sequenz**: fulfilled by `dedupe_key` itself (sensor-scoped,
  content-locked as above) rather than a separate sequence field - the
  wire format already shipped in `security-events-domain` was kept as is
  rather than revised for a mechanism `dedupe_key` already provides.
- **Audit**: every batch call writes one `security_event_batch_ingested`
  audit event (`audit_events`, actor = the sensor's name) with the batch's
  accepted/rejected counts.
- **Rate limit**: inherited from `clawforge-api`'s existing global
  `rate_limit_middleware` (a POST route defaults to the "write" class),
  keyed by the bearer token's digest - no bespoke limiter was added for this
  one route.

`SensorEnvelope::validate()` (added alongside this endpoint) matters here
specifically: `#[derive(Deserialize)]` fills `SensorEnvelope`'s `pub` fields
directly from JSON and never runs through the `new()` constructor's checks,
so deserializing a batch item is not enough on its own - the ingress handler
calls `.validate()` immediately after, and a structurally well-formed but
semantically invalid envelope (a blank `source`, an unparseable IP, an
unknown `event_type`) is rejected the same as malformed JSON.

`api/src/bin/send-security-event-fixtures.rs` (`cargo run -p clawforge-api
--bin send-security-event-fixtures`, `CLAWFORGE_SECURITY_EVENTS_URL` and
`CLAWFORGE_SECURITY_EVENTS_SENSOR_CREDENTIAL` env vars) is the roadmap's
"Fixture-Sender": it posts `fixtures::all()` (with `occurred_at` brought to
now, since the fixtures' own fixed timestamp would otherwise fail the
clock-skew check) as one batch against a running ingress endpoint, for
manually verifying a deployment or a sensor integration being built against
it.

Contract and negative tests: `api/src/main.rs`,
`security_events_batch_ingress_contract` (real-Postgres, part of
`scripts/test-postgres.sh`) - missing/unknown bearer token, empty batch,
over-limit batch, one malformed item alongside one valid item in the same
batch, a stale `occurred_at`, and resubmission idempotency, all driven
through `build_router` (the same router `main` serves) via `tower::oneshot`.
`check_security_event_clock_skew` and the
`CLAWFORGE_SECURITY_EVENTS_MAX_*_SECONDS` env parsing also have plain,
storeless unit tests.
