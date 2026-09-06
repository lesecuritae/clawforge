//! Domain types for threat, network, routing, and trusted-infrastructure data.
//!
//! This crate deliberately contains no HTTP client or database code. Providers
//! and collectors can be added behind the worker boundary without coupling the
//! risk model to a transport.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IndicatorType {
    Ip,
    Prefix,
    Domain,
    Url,
    Hash,
    Asn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
    pub categories: Vec<String>,
    pub confidence: u8,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub source: String,
    pub interval_seconds: i64,
    pub confidence: u8,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnRecord {
    pub asn: String,
    pub organisation: String,
    pub provider: String,
    pub country: String,
    pub prefixes: Vec<String>,
    pub network_type: String,
    pub reputation: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RpkiStatus {
    Valid,
    Unknown,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BgpStatus {
    Stable,
    Changed,
    Anomalous,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpEvent {
    pub prefix: String,
    pub origin_asn: String,
    pub status: BgpStatus,
    pub rpki_status: RpkiStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub change: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkType {
    Tailscale,
    Netbird,
    Vlan,
    Vpn,
    IpRange,
    Asn,
    Bgp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationStatus {
    Pending,
    Verified,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedNetwork {
    pub id: Uuid,
    pub name: String,
    pub network_type: NetworkType,
    pub identifier: String,
    pub networks: Vec<String>,
    pub node_identities: Vec<String>,
    pub device_tags: Vec<String>,
    pub groups: Vec<String>,
    pub status: VerificationStatus,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

impl TrustedNetwork {
    pub fn is_verified(&self) -> bool {
        self.status == VerificationStatus::Verified
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkObservation {
    pub ip: Option<String>,
    pub asn: Option<String>,
    pub prefix: Option<String>,
    pub identifier: Option<String>,
    pub node_identity: Option<String>,
    pub bgp_status: BgpStatus,
    pub rpki_status: RpkiStatus,
    pub behavior_score: u8,
    pub history_score: u8,
}

impl Default for BgpStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

impl Default for RpkiStatus {
    fn default() -> Self {
        Self::Unknown
    }
}
