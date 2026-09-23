//! Domain types for the planned Security Event Layer (roadmap phase 2,
//! `security-events-domain`).
//!
//! This crate is deliberately self-contained: no HTTP, no database, no
//! dependency on any other Clawforge crate. It defines the eleven security
//! event types the architecture note anticipates (firewall, auth, ssh, http,
//! dns, scan and container signals - some split into a plain occurrence and
//! an anomaly variant where that distinction is meaningful), a validated
//! sensor envelope that wraps them, and fixtures both this crate's own tests
//! and a future ingress endpoint's contract tests can reuse. Nothing here
//! talks to the existing `events`/`event_delivery` tables or the generic,
//! free-text `IntelligenceEvent` - wiring a validated `SensorEnvelope` into
//! storage and an authenticated ingress endpoint is separate, later work
//! (`security-events-storage`, `security-events-ingress`), on purpose: this
//! step only fixes the contract.

use std::{fmt, net::IpAddr, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Upper bound for a short identifier-like field (a rule id, a username, a
/// container id, an interface name).
pub const SHORT_FIELD_MAX: usize = 160;
/// Upper bound for `SensorEnvelope::resource`.
pub const RESOURCE_MAX: usize = 512;
/// Upper bound for `SensorEnvelope::dedupe_key`.
pub const DEDUPE_KEY_MAX: usize = 256;
/// Upper bound for a longer free-text field (an HTTP path, a change
/// summary, a DNS query name).
pub const LONG_FIELD_MAX: usize = 2048;

/// The eleven security event types the architecture note anticipates.
/// `Display`/`FromStr` round-trip through the same lowercase, snake_case
/// spelling `is_correlatable` and the rest of the codebase already use for
/// event type strings (see `clawforge-correlation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecurityEventType {
    FirewallBlock,
    FirewallRuleChanged,
    AuthFailure,
    AuthAnomaly,
    SshLoginFailure,
    SshLoginAnomaly,
    HttpAnomaly,
    DnsAnomaly,
    PortScanDetected,
    ContainerAnomaly,
    ContainerEscapeAttempt,
}

impl SecurityEventType {
    pub const ALL: [SecurityEventType; 11] = [
        SecurityEventType::FirewallBlock,
        SecurityEventType::FirewallRuleChanged,
        SecurityEventType::AuthFailure,
        SecurityEventType::AuthAnomaly,
        SecurityEventType::SshLoginFailure,
        SecurityEventType::SshLoginAnomaly,
        SecurityEventType::HttpAnomaly,
        SecurityEventType::DnsAnomaly,
        SecurityEventType::PortScanDetected,
        SecurityEventType::ContainerAnomaly,
        SecurityEventType::ContainerEscapeAttempt,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityEventType::FirewallBlock => "firewall_block",
            SecurityEventType::FirewallRuleChanged => "firewall_rule_changed",
            SecurityEventType::AuthFailure => "auth_failure",
            SecurityEventType::AuthAnomaly => "auth_anomaly",
            SecurityEventType::SshLoginFailure => "ssh_login_failure",
            SecurityEventType::SshLoginAnomaly => "ssh_login_anomaly",
            SecurityEventType::HttpAnomaly => "http_anomaly",
            SecurityEventType::DnsAnomaly => "dns_anomaly",
            SecurityEventType::PortScanDetected => "port_scan_detected",
            SecurityEventType::ContainerAnomaly => "container_anomaly",
            SecurityEventType::ContainerEscapeAttempt => "container_escape_attempt",
        }
    }
}

impl fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SecurityEventType {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        SecurityEventType::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or_else(|| ValidationError::UnknownEventType(value.to_string()))
    }
}

/// A closed, ordered severity scale (`Info` < `Low` < `Medium` < `High` <
/// `Critical`), serialized the same lowercase way the rest of the codebase's
/// free-text severity strings already are, so a `Severity` converts to and
/// from existing storage/notification code without a mapping table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("{field} must be 1..={max} non-blank characters")]
    InvalidField { field: &'static str, max: usize },
    #[error("{field} is not a valid IP address")]
    InvalidIp { field: &'static str },
    #[error("unknown security event type: {0}")]
    UnknownEventType(String),
}

fn validate_text(field: &'static str, value: &str, max: usize) -> Result<(), ValidationError> {
    if value.trim().is_empty() || value.chars().count() > max {
        return Err(ValidationError::InvalidField { field, max });
    }
    Ok(())
}

fn validate_optional_text(
    field: &'static str,
    value: &Option<String>,
    max: usize,
) -> Result<(), ValidationError> {
    match value {
        Some(v) => validate_text(field, v, max),
        None => Ok(()),
    }
}

fn validate_ip(field: &'static str, value: &str) -> Result<(), ValidationError> {
    value
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| ValidationError::InvalidIp { field })
}

fn validate_optional_ip(
    field: &'static str,
    value: &Option<String>,
) -> Result<(), ValidationError> {
    match value {
        Some(v) => validate_ip(field, v),
        None => Ok(()),
    }
}

/// A firewall/router rule matched and dropped or rejected traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallBlockEvidence {
    pub rule_id: String,
    pub source_ip: String,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub interface: Option<String>,
}

impl FirewallBlockEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("rule_id", &self.rule_id, SHORT_FIELD_MAX)?;
        validate_ip("source_ip", &self.source_ip)?;
        validate_optional_ip("destination_ip", &self.destination_ip)?;
        validate_text("protocol", &self.protocol, SHORT_FIELD_MAX)?;
        validate_optional_text("interface", &self.interface, SHORT_FIELD_MAX)
    }
}

/// A closed set: a firewall/router rule was added, modified or removed.
/// Distinct from `FirewallBlockEvidence`, which is about matched traffic,
/// not configuration change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleChangeKind {
    Added,
    Modified,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRuleChangedEvidence {
    pub rule_id: String,
    pub actor: String,
    pub change: RuleChangeKind,
    pub summary: String,
}

impl FirewallRuleChangedEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("rule_id", &self.rule_id, SHORT_FIELD_MAX)?;
        validate_text("actor", &self.actor, SHORT_FIELD_MAX)?;
        validate_text("summary", &self.summary, LONG_FIELD_MAX)
    }
}

/// A failed authentication attempt against a monitored service (not SSH -
/// see `SshLoginFailureEvidence` - since SSH's evidence shape and the
/// operational response to it differ enough to keep separate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthFailureEvidence {
    pub username: String,
    pub source_ip: String,
    pub method: String,
    pub attempt_count: u32,
}

impl AuthFailureEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("username", &self.username, SHORT_FIELD_MAX)?;
        validate_ip("source_ip", &self.source_ip)?;
        validate_text("method", &self.method, SHORT_FIELD_MAX)
    }
}

/// A successful authentication with anomalous characteristics (new device,
/// new location, impossible travel, unusual time - `anomaly` names which;
/// left as free text rather than a closed enum since a sensor's set of
/// detectable anomaly kinds is not fixed yet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthAnomalyEvidence {
    pub username: String,
    pub source_ip: String,
    pub anomaly: String,
    pub previous_source_ip: Option<String>,
}

impl AuthAnomalyEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("username", &self.username, SHORT_FIELD_MAX)?;
        validate_ip("source_ip", &self.source_ip)?;
        validate_text("anomaly", &self.anomaly, SHORT_FIELD_MAX)?;
        validate_optional_ip("previous_source_ip", &self.previous_source_ip)
    }
}

/// A failed SSH authentication attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshLoginFailureEvidence {
    pub username: String,
    pub source_ip: String,
    pub attempt_count: u32,
}

impl SshLoginFailureEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("username", &self.username, SHORT_FIELD_MAX)?;
        validate_ip("source_ip", &self.source_ip)
    }
}

/// A successful SSH login with anomalous characteristics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshLoginAnomalyEvidence {
    pub username: String,
    pub source_ip: String,
    pub anomaly: String,
}

impl SshLoginAnomalyEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("username", &self.username, SHORT_FIELD_MAX)?;
        validate_ip("source_ip", &self.source_ip)?;
        validate_text("anomaly", &self.anomaly, SHORT_FIELD_MAX)
    }
}

/// An anomalous or malicious HTTP request pattern (a WAF-style signal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpAnomalyEvidence {
    pub source_ip: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub rule_id: Option<String>,
}

impl HttpAnomalyEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_ip("source_ip", &self.source_ip)?;
        validate_text("method", &self.method, SHORT_FIELD_MAX)?;
        validate_text("path", &self.path, LONG_FIELD_MAX)?;
        validate_optional_text("rule_id", &self.rule_id, SHORT_FIELD_MAX)
    }
}

/// An anomalous DNS query pattern (potential tunneling, exfiltration or a
/// domain-generation-algorithm indicator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnomalyEvidence {
    pub source_ip: String,
    pub query_name: String,
    pub query_type: String,
    pub anomaly: String,
}

impl DnsAnomalyEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_ip("source_ip", &self.source_ip)?;
        validate_text("query_name", &self.query_name, LONG_FIELD_MAX)?;
        validate_text("query_type", &self.query_type, SHORT_FIELD_MAX)?;
        validate_text("anomaly", &self.anomaly, SHORT_FIELD_MAX)
    }
}

/// A port or service scan detected against a monitored host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortScanDetectedEvidence {
    pub source_ip: String,
    pub target_ip: String,
    pub port_count: u32,
    pub window_seconds: u32,
}

impl PortScanDetectedEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_ip("source_ip", &self.source_ip)?;
        validate_ip("target_ip", &self.target_ip)
    }
}

/// Anomalous container runtime behavior (unexpected process, network or
/// filesystem activity) short of a specific escape technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerAnomalyEvidence {
    pub container_id: String,
    pub image: String,
    pub anomaly: String,
}

impl ContainerAnomalyEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("container_id", &self.container_id, SHORT_FIELD_MAX)?;
        validate_text("image", &self.image, LONG_FIELD_MAX)?;
        validate_text("anomaly", &self.anomaly, SHORT_FIELD_MAX)
    }
}

/// A higher-confidence signal of an attempted container breakout, distinct
/// from the broader `ContainerAnomalyEvidence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerEscapeAttemptEvidence {
    pub container_id: String,
    pub image: String,
    pub technique: String,
}

impl ContainerEscapeAttemptEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("container_id", &self.container_id, SHORT_FIELD_MAX)?;
        validate_text("image", &self.image, LONG_FIELD_MAX)?;
        validate_text("technique", &self.technique, SHORT_FIELD_MAX)
    }
}

/// The type-specific evidence for one security event, internally tagged by
/// `event_type` so the wire format is one flat JSON object (see
/// `SensorEnvelope`) rather than a nested nested "evidence" object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum SecurityEventEvidence {
    FirewallBlock(FirewallBlockEvidence),
    FirewallRuleChanged(FirewallRuleChangedEvidence),
    AuthFailure(AuthFailureEvidence),
    AuthAnomaly(AuthAnomalyEvidence),
    SshLoginFailure(SshLoginFailureEvidence),
    SshLoginAnomaly(SshLoginAnomalyEvidence),
    HttpAnomaly(HttpAnomalyEvidence),
    DnsAnomaly(DnsAnomalyEvidence),
    PortScanDetected(PortScanDetectedEvidence),
    ContainerAnomaly(ContainerAnomalyEvidence),
    ContainerEscapeAttempt(ContainerEscapeAttemptEvidence),
}

impl SecurityEventEvidence {
    pub fn event_type(&self) -> SecurityEventType {
        match self {
            SecurityEventEvidence::FirewallBlock(_) => SecurityEventType::FirewallBlock,
            SecurityEventEvidence::FirewallRuleChanged(_) => SecurityEventType::FirewallRuleChanged,
            SecurityEventEvidence::AuthFailure(_) => SecurityEventType::AuthFailure,
            SecurityEventEvidence::AuthAnomaly(_) => SecurityEventType::AuthAnomaly,
            SecurityEventEvidence::SshLoginFailure(_) => SecurityEventType::SshLoginFailure,
            SecurityEventEvidence::SshLoginAnomaly(_) => SecurityEventType::SshLoginAnomaly,
            SecurityEventEvidence::HttpAnomaly(_) => SecurityEventType::HttpAnomaly,
            SecurityEventEvidence::DnsAnomaly(_) => SecurityEventType::DnsAnomaly,
            SecurityEventEvidence::PortScanDetected(_) => SecurityEventType::PortScanDetected,
            SecurityEventEvidence::ContainerAnomaly(_) => SecurityEventType::ContainerAnomaly,
            SecurityEventEvidence::ContainerEscapeAttempt(_) => {
                SecurityEventType::ContainerEscapeAttempt
            }
        }
    }

    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            SecurityEventEvidence::FirewallBlock(evidence) => evidence.validate(),
            SecurityEventEvidence::FirewallRuleChanged(evidence) => evidence.validate(),
            SecurityEventEvidence::AuthFailure(evidence) => evidence.validate(),
            SecurityEventEvidence::AuthAnomaly(evidence) => evidence.validate(),
            SecurityEventEvidence::SshLoginFailure(evidence) => evidence.validate(),
            SecurityEventEvidence::SshLoginAnomaly(evidence) => evidence.validate(),
            SecurityEventEvidence::HttpAnomaly(evidence) => evidence.validate(),
            SecurityEventEvidence::DnsAnomaly(evidence) => evidence.validate(),
            SecurityEventEvidence::PortScanDetected(evidence) => evidence.validate(),
            SecurityEventEvidence::ContainerAnomaly(evidence) => evidence.validate(),
            SecurityEventEvidence::ContainerEscapeAttempt(evidence) => evidence.validate(),
        }
    }
}

/// What a sensor submits for one security event. `occurred_at` is the
/// sensor's own clock; a server-assigned receipt time, schema version and
/// authenticated sensor identity are storage/ingress concerns
/// (`security-events-storage`/`-ingress`) layered on top of this, not part
/// of the sensor-facing contract itself.
///
/// `dedupe_key` is sensor-scoped: it only needs to be unique for a given
/// `source`, and a future ingress endpoint must reject a resubmission of an
/// already-seen key whose content differs, per the roadmap's
/// `security-events-ingress` requirement - this crate only validates the
/// key's shape, not that invariant, which needs persisted state to check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorEnvelope {
    pub occurred_at: DateTime<Utc>,
    pub source: String,
    pub severity: Severity,
    pub resource: String,
    pub dedupe_key: String,
    #[serde(flatten)]
    pub evidence: SecurityEventEvidence,
}

impl SensorEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        occurred_at: DateTime<Utc>,
        source: impl Into<String>,
        severity: Severity,
        resource: impl Into<String>,
        dedupe_key: impl Into<String>,
        evidence: SecurityEventEvidence,
    ) -> Result<Self, ValidationError> {
        let source = source.into();
        let resource = resource.into();
        let dedupe_key = dedupe_key.into();
        validate_text("source", &source, SHORT_FIELD_MAX)?;
        validate_text("resource", &resource, RESOURCE_MAX)?;
        validate_text("dedupe_key", &dedupe_key, DEDUPE_KEY_MAX)?;
        evidence.validate()?;
        Ok(Self {
            occurred_at,
            source,
            severity,
            resource,
            dedupe_key,
            evidence,
        })
    }

    pub fn event_type(&self) -> SecurityEventType {
        self.evidence.event_type()
    }
}

/// One realistic, valid `SensorEnvelope` per event type, for this crate's
/// own tests and reusable as-is by a future ingress endpoint's contract
/// tests and fixture sender (roadmap: "Test-Fixtures" /
/// "ein Fixture-Sender").
pub mod fixtures {
    use super::*;

    fn at(seconds_from_epoch: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds_from_epoch, 0).expect("fixture timestamp is in range")
    }

    pub fn firewall_block() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_000),
            "nftables:homeserver",
            Severity::Medium,
            "203.0.113.7",
            "nftables:homeserver:block:1",
            SecurityEventEvidence::FirewallBlock(FirewallBlockEvidence {
                rule_id: "drop-inbound-22".into(),
                source_ip: "203.0.113.7".into(),
                destination_ip: Some("198.51.100.10".into()),
                destination_port: Some(22),
                protocol: "tcp".into(),
                interface: Some("wan0".into()),
            }),
        )
        .expect("firewall_block fixture is valid")
    }

    pub fn firewall_rule_changed() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_001),
            "haproxy:homeserver",
            Severity::Low,
            "rule:drop-inbound-22",
            "haproxy:homeserver:rule-change:1",
            SecurityEventEvidence::FirewallRuleChanged(FirewallRuleChangedEvidence {
                rule_id: "drop-inbound-22".into(),
                actor: "admin".into(),
                change: RuleChangeKind::Added,
                summary: "added inbound drop rule for tcp/22 from untrusted networks".into(),
            }),
        )
        .expect("firewall_rule_changed fixture is valid")
    }

    pub fn auth_failure() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_002),
            "clawforge-api:homeserver",
            Severity::Medium,
            "user:jdoe",
            "clawforge-api:homeserver:auth-failure:1",
            SecurityEventEvidence::AuthFailure(AuthFailureEvidence {
                username: "jdoe".into(),
                source_ip: "203.0.113.7".into(),
                method: "password".into(),
                attempt_count: 3,
            }),
        )
        .expect("auth_failure fixture is valid")
    }

    pub fn auth_anomaly() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_003),
            "clawforge-api:homeserver",
            Severity::High,
            "user:jdoe",
            "clawforge-api:homeserver:auth-anomaly:1",
            SecurityEventEvidence::AuthAnomaly(AuthAnomalyEvidence {
                username: "jdoe".into(),
                source_ip: "203.0.113.7".into(),
                anomaly: "new_device".into(),
                previous_source_ip: Some("198.51.100.20".into()),
            }),
        )
        .expect("auth_anomaly fixture is valid")
    }

    pub fn ssh_login_failure() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_004),
            "sshd:homeserver",
            Severity::Low,
            "user:root",
            "sshd:homeserver:login-failure:1",
            SecurityEventEvidence::SshLoginFailure(SshLoginFailureEvidence {
                username: "root".into(),
                source_ip: "203.0.113.7".into(),
                attempt_count: 5,
            }),
        )
        .expect("ssh_login_failure fixture is valid")
    }

    pub fn ssh_login_anomaly() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_005),
            "sshd:homeserver",
            Severity::High,
            "user:deploy",
            "sshd:homeserver:login-anomaly:1",
            SecurityEventEvidence::SshLoginAnomaly(SshLoginAnomalyEvidence {
                username: "deploy".into(),
                source_ip: "203.0.113.7".into(),
                anomaly: "unusual_time".into(),
            }),
        )
        .expect("ssh_login_anomaly fixture is valid")
    }

    pub fn http_anomaly() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_006),
            "haproxy:homeserver",
            Severity::Medium,
            "vhost:app.example.internal",
            "haproxy:homeserver:http-anomaly:1",
            SecurityEventEvidence::HttpAnomaly(HttpAnomalyEvidence {
                source_ip: "203.0.113.7".into(),
                method: "POST".into(),
                path: "/api/../../etc/passwd".into(),
                status_code: 403,
                rule_id: Some("path-traversal".into()),
            }),
        )
        .expect("http_anomaly fixture is valid")
    }

    pub fn dns_anomaly() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_007),
            "unbound:homeserver",
            Severity::Medium,
            "host:workstation-1",
            "unbound:homeserver:dns-anomaly:1",
            SecurityEventEvidence::DnsAnomaly(DnsAnomalyEvidence {
                source_ip: "198.51.100.30".into(),
                query_name: "a1b2c3d4e5f6.exfil.example".into(),
                query_type: "TXT".into(),
                anomaly: "high_entropy_subdomain".into(),
            }),
        )
        .expect("dns_anomaly fixture is valid")
    }

    pub fn port_scan_detected() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_008),
            "suricata:homeserver",
            Severity::Medium,
            "host:homeserver",
            "suricata:homeserver:port-scan:1",
            SecurityEventEvidence::PortScanDetected(PortScanDetectedEvidence {
                source_ip: "203.0.113.7".into(),
                target_ip: "198.51.100.10".into(),
                port_count: 42,
                window_seconds: 60,
            }),
        )
        .expect("port_scan_detected fixture is valid")
    }

    pub fn container_anomaly() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_009),
            "docker-connector:homeserver",
            Severity::Medium,
            "container:clawforge-worker",
            "docker-connector:homeserver:container-anomaly:1",
            SecurityEventEvidence::ContainerAnomaly(ContainerAnomalyEvidence {
                container_id: "clawforge-worker".into(),
                image: "ghcr.io/lesecuritae/clawforge-worker:v1.0.0".into(),
                anomaly: "unexpected_outbound_connection".into(),
            }),
        )
        .expect("container_anomaly fixture is valid")
    }

    pub fn container_escape_attempt() -> SensorEnvelope {
        SensorEnvelope::new(
            at(1_700_000_010),
            "docker-connector:homeserver",
            Severity::Critical,
            "container:clawforge-worker",
            "docker-connector:homeserver:escape-attempt:1",
            SecurityEventEvidence::ContainerEscapeAttempt(ContainerEscapeAttemptEvidence {
                container_id: "clawforge-worker".into(),
                image: "ghcr.io/lesecuritae/clawforge-worker:v1.0.0".into(),
                technique: "host_pid_namespace_access".into(),
            }),
        )
        .expect("container_escape_attempt fixture is valid")
    }

    /// One valid envelope per `SecurityEventType::ALL`, in the same order.
    pub fn all() -> Vec<SensorEnvelope> {
        vec![
            firewall_block(),
            firewall_rule_changed(),
            auth_failure(),
            auth_anomaly(),
            ssh_login_failure(),
            ssh_login_anomaly(),
            http_anomaly(),
            dns_anomaly(),
            port_scan_detected(),
            container_anomaly(),
            container_escape_attempt(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_event_type_has_a_fixture_and_round_trips_through_json() {
        let all = fixtures::all();
        assert_eq!(all.len(), SecurityEventType::ALL.len());
        for (envelope, expected_type) in all.iter().zip(SecurityEventType::ALL) {
            assert_eq!(envelope.event_type(), expected_type);
            let json = serde_json::to_string(envelope).expect("fixture serializes");
            let round_tripped: SensorEnvelope =
                serde_json::from_str(&json).expect("fixture round-trips");
            assert_eq!(&round_tripped, envelope);
            // The wire format is one flat object: event_type sits next to
            // the envelope fields, not nested under a separate key.
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(
                value.get("event_type").and_then(serde_json::Value::as_str),
                Some(expected_type.as_str())
            );
            assert!(value.get("evidence").is_none());
        }
    }

    #[test]
    fn event_type_str_round_trips() {
        for event_type in SecurityEventType::ALL {
            assert_eq!(
                event_type.as_str().parse::<SecurityEventType>().unwrap(),
                event_type
            );
        }
    }

    #[test]
    fn unknown_event_type_is_rejected() {
        assert_eq!(
            "not_a_real_event_type".parse::<SecurityEventType>(),
            Err(ValidationError::UnknownEventType(
                "not_a_real_event_type".into()
            ))
        );
        let raw = r#"{"event_type":"not_a_real_event_type","occurred_at":"2024-01-01T00:00:00Z","source":"s","severity":"low","resource":"r","dedupe_key":"d"}"#;
        assert!(serde_json::from_str::<SensorEnvelope>(raw).is_err());
    }

    #[test]
    fn severity_is_ordered_from_info_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn an_invalid_ip_is_rejected() {
        let error = SensorEnvelope::new(
            Utc::now(),
            "sensor:test",
            Severity::Low,
            "resource",
            "dedupe",
            SecurityEventEvidence::FirewallBlock(FirewallBlockEvidence {
                rule_id: "r".into(),
                source_ip: "not-an-ip".into(),
                destination_ip: None,
                destination_port: None,
                protocol: "tcp".into(),
                interface: None,
            }),
        )
        .unwrap_err();
        assert_eq!(error, ValidationError::InvalidIp { field: "source_ip" });
    }

    #[test]
    fn a_blank_field_is_rejected() {
        let error = SensorEnvelope::new(
            Utc::now(),
            "   ",
            Severity::Low,
            "resource",
            "dedupe",
            SecurityEventEvidence::AuthFailure(AuthFailureEvidence {
                username: "user".into(),
                source_ip: "203.0.113.7".into(),
                method: "password".into(),
                attempt_count: 1,
            }),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ValidationError::InvalidField {
                field: "source",
                max: SHORT_FIELD_MAX
            }
        );
    }

    #[test]
    fn an_oversized_field_is_rejected() {
        let error = SensorEnvelope::new(
            Utc::now(),
            "sensor:test",
            Severity::Low,
            "resource",
            "dedupe",
            SecurityEventEvidence::HttpAnomaly(HttpAnomalyEvidence {
                source_ip: "203.0.113.7".into(),
                method: "GET".into(),
                path: "a".repeat(LONG_FIELD_MAX + 1),
                status_code: 200,
                rule_id: None,
            }),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ValidationError::InvalidField {
                field: "path",
                max: LONG_FIELD_MAX
            }
        );
    }

    #[test]
    fn resource_and_dedupe_key_bounds_are_enforced() {
        assert_eq!(
            SensorEnvelope::new(
                Utc::now(),
                "sensor:test",
                Severity::Low,
                "a".repeat(RESOURCE_MAX + 1),
                "dedupe",
                SecurityEventEvidence::SshLoginFailure(SshLoginFailureEvidence {
                    username: "root".into(),
                    source_ip: "203.0.113.7".into(),
                    attempt_count: 1,
                }),
            )
            .unwrap_err(),
            ValidationError::InvalidField {
                field: "resource",
                max: RESOURCE_MAX
            }
        );
        assert_eq!(
            SensorEnvelope::new(
                Utc::now(),
                "sensor:test",
                Severity::Low,
                "resource",
                "a".repeat(DEDUPE_KEY_MAX + 1),
                SecurityEventEvidence::SshLoginFailure(SshLoginFailureEvidence {
                    username: "root".into(),
                    source_ip: "203.0.113.7".into(),
                    attempt_count: 1,
                }),
            )
            .unwrap_err(),
            ValidationError::InvalidField {
                field: "dedupe_key",
                max: DEDUPE_KEY_MAX
            }
        );
    }
}
