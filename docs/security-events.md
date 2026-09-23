# Security event catalog

`clawforge-security-events` defines the contract for the Security Event
Layer the roadmap's phase 2 builds toward (`docs/security-control-plane-roadmap.de.md`,
"Empfohlene erste Pull Requests" #6-8). This step (`security-events-domain`)
is the domain crate only: types, validation, and fixtures. It makes no API or
database change, and nothing else in the codebase depends on it yet. Wiring a
validated event into storage and an authenticated ingress endpoint is
separate, later work (`security-events-storage`, `security-events-ingress`).

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
