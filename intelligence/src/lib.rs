//! Domain types for threat, network, routing, and trusted-infrastructure data.
//!
//! This crate deliberately contains no HTTP client or database code. Providers
//! and collectors can be added behind the worker boundary without coupling the
//! risk model to a transport.

use std::{env, net::IpAddr, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
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

#[derive(Debug, Clone)]
pub struct RawFeed {
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub fetched_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("provider returned HTTP status {0}")]
    HttpStatus(StatusCode),
    #[error("provider response was empty")]
    EmptyResponse,
    #[error("provider response validation failed: {0}")]
    Validation(String),
    #[error("provider configuration is missing: {0}")]
    Configuration(String),
}

#[async_trait]
pub trait IndicatorSink: Send + Sync {
    async fn upsert_indicators(&self, indicators: &[Indicator]) -> Result<usize, ProviderError>;
}

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> Provider;
    async fn fetch(&self) -> Result<RawFeed, ProviderError>;
    fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError>;
    fn normalize(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError>;
    async fn store(
        &self,
        indicators: &[Indicator],
        sink: &dyn IndicatorSink,
    ) -> Result<usize, ProviderError> {
        sink.upsert_indicators(indicators).await
    }
}

#[derive(Clone)]
struct HttpFeedProvider {
    provider: Provider,
    endpoint: String,
    method: Method,
    request_body: Option<serde_json::Value>,
    auth_env: Option<String>,
    client: Client,
}

impl HttpFeedProvider {
    fn new(
        id: &str,
        name: &str,
        source: &str,
        endpoint: &str,
        interval_seconds: i64,
        confidence: u8,
        method: Method,
        request_body: Option<serde_json::Value>,
        auth_env: Option<&str>,
    ) -> Result<Self, ProviderError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("clawforge-intelligence/0.1")
            .build()?;
        Ok(Self {
            provider: Provider {
                id: id.to_string(),
                name: name.to_string(),
                source: source.to_string(),
                interval_seconds,
                confidence,
                enabled: true,
            },
            endpoint: endpoint.to_string(),
            method,
            request_body,
            auth_env: auth_env.map(str::to_string),
            client,
        })
    }

    async fn fetch(&self) -> Result<RawFeed, ProviderError> {
        let mut request = self.client.request(self.method.clone(), &self.endpoint);
        if let Some(body) = &self.request_body {
            request = request.json(body);
        }
        if let Some(variable) = &self.auth_env {
            let key = env::var(variable).map_err(|_| ProviderError::Configuration(variable.clone()))?;
            if key.trim().is_empty() {
                return Err(ProviderError::Configuration(variable.clone()));
            }
            request = request.header("Auth-Key", key);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::HttpStatus(status));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.bytes().await?.to_vec();
        if body.is_empty() {
            return Err(ProviderError::EmptyResponse);
        }
        Ok(RawFeed { body, content_type, fetched_at: Utc::now() })
    }

    fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError> {
        if feed.body.is_empty() {
            return Err(ProviderError::EmptyResponse);
        }
        if feed.body.len() > 50 * 1024 * 1024 {
            return Err(ProviderError::Validation("response exceeds 50 MiB".to_string()));
        }
        Ok(())
    }

    fn normalize(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
        let text = String::from_utf8_lossy(&feed.body);
        let mut indicators = Vec::new();
        for candidate in text.split(|character: char| {
            character.is_whitespace() || matches!(character, ',' | ';' | ':' | '"' | '\'' | '[' | ']' | '{' | '}' | '(' | ')')
        }) {
            let value = candidate.trim_matches(|character: char| matches!(character, '.' | '/' | '\\'));
            if value.is_empty() || value.len() > 2048 {
                continue;
            }
            let indicator_type = if value.parse::<IpAddr>().is_ok() {
                Some(IndicatorType::Ip)
            } else if value.starts_with("http://") || value.starts_with("https://") {
                Some(IndicatorType::Url)
            } else if (value.len() == 32 || value.len() == 40 || value.len() == 64)
                && value.chars().all(|character| character.is_ascii_hexdigit())
            {
                Some(IndicatorType::Hash)
            } else {
                None
            };
            if let Some(indicator_type) = indicator_type {
                indicators.push(Indicator {
                    value: value.to_string(),
                    indicator_type,
                    categories: vec![self.provider.id.clone()],
                    confidence: self.provider.confidence,
                    source: self.provider.id.clone(),
                    first_seen: feed.fetched_at,
                    last_seen: feed.fetched_at,
                    expires_at: feed.fetched_at + chrono::Duration::hours(24),
                    metadata: serde_json::json!({ "content_type": feed.content_type }),
                });
            }
        }
        indicators.sort_by(|left, right| left.value.cmp(&right.value));
        indicators.dedup_by(|left, right| left.value == right.value && left.source == right.source);
        Ok(indicators)
    }
}

macro_rules! define_http_provider {
    ($name:ident, $id:literal, $display:literal, $source:literal, $endpoint:literal, $method:expr, $body:expr, $auth:expr, $interval:expr, $confidence:expr) => {
        pub struct $name(HttpFeedProvider);

        impl $name {
            pub fn new() -> Result<Self, ProviderError> {
                Ok(Self(HttpFeedProvider::new(
                    $id, $display, $source, $endpoint, $interval, $confidence, $method, $body, $auth,
                )?))
            }
        }

        #[async_trait]
        impl ProviderAdapter for $name {
            fn provider(&self) -> Provider { self.0.provider.clone() }
            async fn fetch(&self) -> Result<RawFeed, ProviderError> { self.0.fetch().await }
            fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError> { self.0.validate(feed) }
            fn normalize(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> { self.0.normalize(feed) }
        }
    };
}

define_http_provider!(ThreatFoxProvider, "threatfox", "ThreatFox", "abuse.ch", "https://threatfox-api.abuse.ch/api/v1/", Method::POST, Some(serde_json::json!({"query":"get_ioc","days":1})), Some("THREATFOX_AUTH_KEY"), 900, 90);
define_http_provider!(UrlhausProvider, "urlhaus", "URLhaus", "abuse.ch", "https://urlhaus-api.abuse.ch/v1/urls/recent/", Method::GET, None, None, 900, 85);
define_http_provider!(FeodoProvider, "feodo_tracker", "Feodo Tracker", "abuse.ch", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", Method::GET, None, None, 1800, 85);
define_http_provider!(MalwareBazaarProvider, "malwarebazaar", "MalwareBazaar", "abuse.ch", "https://mb-api.abuse.ch/api/v1/", Method::POST, Some(serde_json::json!({"query":"get_recent","selector":"time"})), Some("MALWAREBAZAAR_AUTH_KEY"), 1800, 95);
define_http_provider!(SpamhausProvider, "spamhaus_drop", "Spamhaus DROP", "Spamhaus", "https://www.spamhaus.org/drop/drop.txt", Method::GET, None, None, 3600, 80);

pub fn phase_one_providers() -> Result<Vec<Box<dyn ProviderAdapter>>, ProviderError> {
    Ok(vec![
        Box::new(ThreatFoxProvider::new()?),
        Box::new(UrlhausProvider::new()?),
        Box::new(FeodoProvider::new()?),
        Box::new(MalwareBazaarProvider::new()?),
        Box::new(SpamhausProvider::new()?),
    ])
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
