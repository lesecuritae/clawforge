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
    #[error("provider rate limited{retry_after}")]
    RateLimited { retry_after: String },
    #[error("provider request timed out")]
    Timeout,
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
    format: FeedFormat,
}

#[derive(Clone, Copy)]
enum FeedFormat { Json, Text }

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
        format: FeedFormat,
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
            format,
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
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() { ProviderError::Timeout } else { ProviderError::Request(error) }
        })?;
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response.headers().get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()).unwrap_or("unknown").to_string();
            return Err(ProviderError::RateLimited { retry_after: format!(" (retry-after {retry_after})") });
        }
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
        if matches!(self.format, FeedFormat::Json) {
            let value: serde_json::Value = serde_json::from_slice(&feed.body)
                .map_err(|error| ProviderError::Validation(format!("invalid JSON: {error}")))?;
            if let Some(status) = value.get("query_status").and_then(serde_json::Value::as_str) {
                if status != "ok" && status != "no_result" && status != "no_results" { return Err(ProviderError::Validation(format!("provider API error: {status}"))); }
            }
            if value.get("error").is_some_and(|error| !error.is_null()) {
                return Err(ProviderError::Validation("provider API returned an error".to_string()));
            }
        } else {
            let text = std::str::from_utf8(&feed.body)
                .map_err(|error| ProviderError::Validation(format!("invalid text encoding: {error}")))?;
            let has_prefix = text.lines().any(|line| {
                let value = line.split('#').next().unwrap_or("").split(';').next().unwrap_or("").trim();
                value.split_whitespace().next().and_then(|candidate| candidate.parse::<ipnet::IpNet>().ok()).is_some()
            });
            if !has_prefix {
                return Err(ProviderError::Validation("text feed contains no network prefixes".to_string()));
            }
        }
        Ok(())
    }

    fn normalize(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
        if matches!(self.format, FeedFormat::Json) {
            return self.normalize_json(feed);
        }
        self.normalize_text(feed)
    }

    fn normalize_json(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
        let value: serde_json::Value = serde_json::from_slice(&feed.body)
            .map_err(|error| ProviderError::Validation(format!("invalid JSON: {error}")))?;
        let mut indicators = Vec::new();
        let rows = value.get("data").and_then(serde_json::Value::as_array)
            .or_else(|| value.get("urls").and_then(serde_json::Value::as_array))
            .or_else(|| value.as_array()).cloned().unwrap_or_default();
        for row in rows {
            let mut candidates: Vec<(String, IndicatorType)> = Vec::new();
            match self.provider.id.as_str() {
                "threatfox" => {
                    if let Some(raw) = row.get("ioc").and_then(serde_json::Value::as_str) {
                        let ioc_type = row.get("ioc_type").and_then(serde_json::Value::as_str).unwrap_or("");
                        let value = if ioc_type == "ip:port" {
                            raw.rsplit_once(':').and_then(|(ip, _)| ip.parse::<IpAddr>().ok().map(|_| ip.to_string())).unwrap_or_else(|| raw.to_string())
                        } else { raw.to_string() };
                        let indicator_type = if ioc_type.starts_with("ip") { IndicatorType::Ip }
                            else if ioc_type.starts_with("domain") { IndicatorType::Domain }
                            else if ioc_type.starts_with("url") { IndicatorType::Url }
                            else { classify(&value).unwrap_or(IndicatorType::Hash) };
                        candidates.push((value, indicator_type));
                    }
                }
                "urlhaus" => if let Some(value) = row.get("url").and_then(serde_json::Value::as_str) { candidates.push((value.to_string(), IndicatorType::Url)); },
                "feodo_tracker" => if let Some(value) = row.get("ip_address").and_then(serde_json::Value::as_str) { candidates.push((value.to_string(), IndicatorType::Ip)); },
                "malwarebazaar" => for key in ["sha256_hash", "sha1_hash", "md5_hash"] {
                    if let Some(value) = row.get(key).and_then(serde_json::Value::as_str) { candidates.push((value.to_string(), IndicatorType::Hash)); }
                },
                _ => {}
            }
            for (value, indicator_type) in candidates {
                let value = value.trim();
                if value.is_empty() || value.len() > 2048 { continue; }
                indicators.push(self.make_indicator(value, indicator_type, feed.fetched_at, feed.content_type.as_deref()));
            }
        }
        deduplicate(indicators)
    }

    fn normalize_text(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
        let text = std::str::from_utf8(&feed.body)
            .map_err(|error| ProviderError::Validation(format!("invalid text encoding: {error}")))?;
        let mut indicators = Vec::new();
        for line in text.lines() {
            let value = line.split('#').next().unwrap_or("").split(';').next().unwrap_or("").trim();
            let value = value.split_whitespace().next().unwrap_or("").trim_matches(|character: char| character == '"' || character == '\'');
            if let Some(indicator_type) = classify(value).or_else(|| value.parse::<ipnet::IpNet>().ok().map(|_| IndicatorType::Prefix)) {
                indicators.push(self.make_indicator(value, indicator_type, feed.fetched_at, feed.content_type.as_deref()));
            }
        }
        deduplicate(indicators)
    }

    fn make_indicator(&self, value: &str, indicator_type: IndicatorType, seen: DateTime<Utc>, content_type: Option<&str>) -> Indicator {
        Indicator { value: value.to_string(), indicator_type, categories: vec![self.provider.id.clone()], confidence: self.provider.confidence, source: self.provider.id.clone(), first_seen: seen, last_seen: seen, expires_at: seen + chrono::Duration::hours(24), metadata: serde_json::json!({ "content_type": content_type, "provider": self.provider.id }) }
    }
}

fn classify(value: &str) -> Option<IndicatorType> {
    if value.parse::<IpAddr>().is_ok() { Some(IndicatorType::Ip) }
    else if value.parse::<ipnet::IpNet>().is_ok() { Some(IndicatorType::Prefix) }
    else if value.starts_with("http://") || value.starts_with("https://") { Some(IndicatorType::Url) }
    else if (value.len() == 32 || value.len() == 40 || value.len() == 64) && value.chars().all(|character| character.is_ascii_hexdigit()) { Some(IndicatorType::Hash) }
    else { None }
}

fn deduplicate(mut indicators: Vec<Indicator>) -> Result<Vec<Indicator>, ProviderError> {
    indicators.sort_by(|left, right| left.value.cmp(&right.value));
    indicators.dedup_by(|left, right| left.value == right.value && left.source == right.source);
    Ok(indicators)
}

macro_rules! define_http_provider {
    ($name:ident, $id:literal, $display:literal, $source:literal, $endpoint:literal, $method:expr, $body:expr, $auth:expr, $interval:expr, $confidence:expr, $format:expr) => {
        pub struct $name(HttpFeedProvider);

        impl $name {
            pub fn new() -> Result<Self, ProviderError> {
                Ok(Self(HttpFeedProvider::new(
                    $id, $display, $source, $endpoint, $interval, $confidence, $method, $body, $auth, $format,
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

define_http_provider!(ThreatFoxProvider, "threatfox", "ThreatFox", "abuse.ch", "https://threatfox-api.abuse.ch/api/v1/", Method::POST, Some(serde_json::json!({"query":"get_ioc","days":1})), Some("THREATFOX_AUTH_KEY"), 900, 90, FeedFormat::Json);
define_http_provider!(UrlhausProvider, "urlhaus", "URLhaus", "abuse.ch", "https://urlhaus-api.abuse.ch/v1/urls/recent/", Method::GET, None, Some("URLHAUS_AUTH_KEY"), 900, 85, FeedFormat::Json);
define_http_provider!(FeodoProvider, "feodo_tracker", "Feodo Tracker", "abuse.ch", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", Method::GET, None, None, 1800, 85, FeedFormat::Json);
define_http_provider!(MalwareBazaarProvider, "malwarebazaar", "MalwareBazaar", "abuse.ch", "https://mb-api.abuse.ch/api/v1/", Method::POST, Some(serde_json::json!({"query":"get_recent","selector":"time"})), Some("MALWAREBAZAAR_AUTH_KEY"), 1800, 95, FeedFormat::Json);
define_http_provider!(SpamhausProvider, "spamhaus_drop", "Spamhaus DROP", "Spamhaus", "https://www.spamhaus.org/drop/drop.txt", Method::GET, None, None, 3600, 80, FeedFormat::Text);

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

#[cfg(test)]
mod provider_tests {
    use super::*;

    fn feed(body: &str) -> RawFeed {
        RawFeed { body: body.as_bytes().to_vec(), content_type: Some("application/json".into()), fetched_at: Utc::now() }
    }

    #[test]
    fn threatfox_json_is_validated_and_normalized_with_deduplication() {
        let provider = ThreatFoxProvider::new().unwrap();
        let raw = feed(r#"{"query_status":"ok","data":[{"ioc":"198.51.100.2:443","ioc_type":"ip:port"},{"ioc":"198.51.100.2:443","ioc_type":"ip:port"},{"ioc":"example.test","ioc_type":"domain"}]}"#);
        provider.validate(&raw).unwrap();
        let values = provider.normalize(&raw).unwrap();
        assert_eq!(values.len(), 2);
        assert!(values.iter().any(|item| item.value == "198.51.100.2"));
        assert!(values.iter().any(|item| item.indicator_type == IndicatorType::Domain));
    }

    #[test]
    fn malformed_json_and_api_errors_are_rejected() {
        let provider = UrlhausProvider::new().unwrap();
        assert!(provider.validate(&feed("not json")).is_err());
        assert!(provider.validate(&feed(r#"{"query_status":"error"}"#)).is_err());
        assert!(provider.validate(&RawFeed { body: Vec::new(), ..feed("") }).is_err());
    }

    #[test]
    fn spamhaus_comments_and_prefixes_are_normalized() {
        let provider = SpamhausProvider::new().unwrap();
        let raw = RawFeed { body: b"203.0.113.0/24 ; comment\n# heading\n2001:db8::/32\n".to_vec(), content_type: Some("text/plain".into()), fetched_at: Utc::now() };
        provider.validate(&raw).unwrap();
        let values = provider.normalize(&raw).unwrap();
        assert_eq!(values.len(), 2);
        assert!(values.iter().all(|item| item.indicator_type == IndicatorType::Prefix));
        assert!(provider.validate(&RawFeed { body: b"<html>rate limited</html>".to_vec(), ..raw }).is_err());
    }

    #[test]
    fn phase_one_provider_shapes_are_normalized() {
        let urlhaus = UrlhausProvider::new().unwrap();
        let values = urlhaus.normalize(&feed(r#"{"query_status":"ok","urls":[{"url":"https://bad.test/payload"}]}"#)).unwrap();
        assert_eq!(values[0].indicator_type, IndicatorType::Url);

        let feodo = FeodoProvider::new().unwrap();
        let values = feodo.normalize(&feed(r#"[{"ip_address":"203.0.113.5","port":443}]"#)).unwrap();
        assert_eq!(values[0].indicator_type, IndicatorType::Ip);

        let malwarebazaar = MalwareBazaarProvider::new().unwrap();
        let values = malwarebazaar.normalize(&feed(r#"{"query_status":"ok","data":[{"sha256_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}"#)).unwrap();
        assert_eq!(values[0].indicator_type, IndicatorType::Hash);
    }

    #[test]
    fn rate_limit_error_is_explicit_and_retryable() {
        let error = ProviderError::RateLimited { retry_after: " (retry-after 30)".into() };
        assert!(error.to_string().contains("rate limited"));
    }
}
