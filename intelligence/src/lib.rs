//! Domain types for threat, network, routing, and trusted-infrastructure data.
//!
//! This crate deliberately contains no HTTP client or database code. Providers
//! and collectors can be added behind the worker boundary without coupling the
//! risk model to a transport.

pub mod ip_context;

use std::{env, net::IpAddr, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clawforge_secret::load_required;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceEvent {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub severity: String,
    pub reason: String,
    pub resource: String,
    pub details: serde_json::Value,
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
    #[error("provider connection failed: {0}")]
    Connection(String),
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
enum FeedFormat {
    Json,
    Text,
    AsnJsonLines,
}

// ASN-DROP ends with a metadata object, not another ASN. Recognize only that
// explicit shape; unknown rows and malformed ASN entries must still fail closed.
fn is_asn_feed_metadata(row: &serde_json::Value) -> bool {
    row.get("asn").is_none()
        && row.get("type").and_then(serde_json::Value::as_str) == Some("metadata")
        && ["timestamp", "size", "records"]
            .iter()
            .all(|key| row.get(*key).and_then(serde_json::Value::as_u64).is_some())
        && ["copyright", "terms"]
            .iter()
            .all(|key| row.get(*key).and_then(serde_json::Value::as_str).is_some())
}

impl HttpFeedProvider {
    #[allow(clippy::too_many_arguments)]
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
            let key = secret_from_env(variable)?;
            if key.trim().is_empty() {
                return Err(ProviderError::Configuration(variable.clone()));
            }
            request = request.header("Auth-Key", key);
        }
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() {
                ProviderError::Timeout
            } else {
                ProviderError::Request(error)
            }
        })?;
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            return Err(ProviderError::RateLimited {
                retry_after: format!(" (retry-after {retry_after})"),
            });
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
        Ok(RawFeed {
            body,
            content_type,
            fetched_at: Utc::now(),
        })
    }

    fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError> {
        if feed.body.is_empty() {
            return Err(ProviderError::EmptyResponse);
        }
        if feed.body.len() > 50 * 1024 * 1024 {
            return Err(ProviderError::Validation(
                "response exceeds 50 MiB".to_string(),
            ));
        }
        if matches!(self.format, FeedFormat::Json) {
            let value: serde_json::Value = serde_json::from_slice(&feed.body)
                .map_err(|error| ProviderError::Validation(format!("invalid JSON: {error}")))?;
            if let Some(status) = value
                .get("query_status")
                .and_then(serde_json::Value::as_str)
            {
                if status != "ok" && status != "no_result" && status != "no_results" {
                    return Err(ProviderError::Validation(format!(
                        "provider API error: {status}"
                    )));
                }
            }
            if value.get("error").is_some_and(|error| !error.is_null()) {
                return Err(ProviderError::Validation(
                    "provider API returned an error".to_string(),
                ));
            }
        } else if !matches!(self.format, FeedFormat::AsnJsonLines) {
            let text = std::str::from_utf8(&feed.body).map_err(|error| {
                ProviderError::Validation(format!("invalid text encoding: {error}"))
            })?;
            let has_expected_value = text.lines().any(|line| {
                let value = line
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim();
                let candidate = value.split_whitespace().next().unwrap_or("");
                candidate.parse::<ipnet::IpNet>().is_ok()
            });
            if !has_expected_value && !text.to_ascii_lowercase().contains("merged into") {
                return Err(ProviderError::Validation(
                    "text feed contains no network prefixes".to_string(),
                ));
            }
        }
        if matches!(self.format, FeedFormat::AsnJsonLines) {
            let text = std::str::from_utf8(&feed.body).map_err(|error| {
                ProviderError::Validation(format!("invalid text encoding: {error}"))
            })?;
            let mut found = false;
            for line in text.lines().filter(|line| !line.trim().is_empty()) {
                let row: serde_json::Value = serde_json::from_str(line).map_err(|error| {
                    ProviderError::Validation(format!("invalid ASN JSON line: {error}"))
                })?;
                if is_asn_feed_metadata(&row) {
                    continue;
                }
                if row.get("asn").and_then(serde_json::Value::as_u64).is_none() {
                    return Err(ProviderError::Validation(
                        "ASN JSON line has no numeric asn".to_string(),
                    ));
                }
                found = true;
            }
            if !found {
                return Err(ProviderError::Validation(
                    "ASN feed contains no records".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn normalize(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
        if matches!(self.format, FeedFormat::Json) {
            return self.normalize_json(feed);
        }
        if matches!(self.format, FeedFormat::AsnJsonLines) {
            return self.normalize_asn_json_lines(feed);
        }
        self.normalize_text(feed)
    }

    fn normalize_asn_json_lines(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
        let text = std::str::from_utf8(&feed.body).map_err(|error| {
            ProviderError::Validation(format!("invalid text encoding: {error}"))
        })?;
        let mut indicators = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let row: serde_json::Value = serde_json::from_str(line).map_err(|error| {
                ProviderError::Validation(format!("invalid ASN JSON line: {error}"))
            })?;
            if is_asn_feed_metadata(&row) {
                continue;
            }
            let Some(asn) = row.get("asn").and_then(serde_json::Value::as_u64) else {
                return Err(ProviderError::Validation(
                    "ASN JSON line has no numeric asn".to_string(),
                ));
            };
            indicators.push(self.make_indicator(
                &format!("AS{asn}"),
                IndicatorType::Asn,
                feed.fetched_at,
                feed.content_type.as_deref(),
            ));
        }
        if indicators.is_empty() {
            return Err(ProviderError::Validation(
                "ASN feed contains no records".to_string(),
            ));
        }
        deduplicate(indicators)
    }

    fn normalize_json(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
        let value: serde_json::Value = serde_json::from_slice(&feed.body)
            .map_err(|error| ProviderError::Validation(format!("invalid JSON: {error}")))?;
        let mut indicators = Vec::new();
        let rows = value
            .get("data")
            .and_then(serde_json::Value::as_array)
            .or_else(|| value.get("urls").and_then(serde_json::Value::as_array))
            .or_else(|| value.as_array())
            .cloned()
            .unwrap_or_default();
        for row in rows {
            let mut candidates: Vec<(String, IndicatorType)> = Vec::new();
            match self.provider.id.as_str() {
                "threatfox" => {
                    if let Some(raw) = row.get("ioc").and_then(serde_json::Value::as_str) {
                        let ioc_type = row
                            .get("ioc_type")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        let value = if ioc_type == "ip:port" {
                            raw.rsplit_once(':')
                                .and_then(|(ip, _)| {
                                    ip.parse::<IpAddr>().ok().map(|_| ip.to_string())
                                })
                                .unwrap_or_else(|| raw.to_string())
                        } else {
                            raw.to_string()
                        };
                        let indicator_type = if ioc_type.starts_with("ip") {
                            IndicatorType::Ip
                        } else if ioc_type.starts_with("domain") {
                            IndicatorType::Domain
                        } else if ioc_type.starts_with("url") {
                            IndicatorType::Url
                        } else {
                            classify(&value).unwrap_or(IndicatorType::Hash)
                        };
                        candidates.push((value, indicator_type));
                    }
                }
                "urlhaus" => {
                    if let Some(value) = row.get("url").and_then(serde_json::Value::as_str) {
                        candidates.push((value.to_string(), IndicatorType::Url));
                    }
                }
                "feodo_tracker" => {
                    if let Some(value) = row.get("ip_address").and_then(serde_json::Value::as_str) {
                        candidates.push((value.to_string(), IndicatorType::Ip));
                    }
                }
                "malwarebazaar" => {
                    for key in ["sha256_hash", "sha1_hash", "md5_hash"] {
                        if let Some(value) = row.get(key).and_then(serde_json::Value::as_str) {
                            candidates.push((value.to_string(), IndicatorType::Hash));
                        }
                    }
                }
                _ => {}
            }
            for (value, indicator_type) in candidates {
                let value = value.trim();
                if value.is_empty() || value.len() > 2048 {
                    continue;
                }
                indicators.push(self.make_indicator(
                    value,
                    indicator_type,
                    feed.fetched_at,
                    feed.content_type.as_deref(),
                ));
            }
        }
        deduplicate(indicators)
    }

    fn normalize_text(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
        let text = std::str::from_utf8(&feed.body).map_err(|error| {
            ProviderError::Validation(format!("invalid text encoding: {error}"))
        })?;
        let mut indicators = Vec::new();
        for line in text.lines() {
            let value = line
                .split('#')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            let value = value
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|character: char| character == '"' || character == '\'');
            if let Some(indicator_type) = classify(value).or_else(|| {
                value
                    .parse::<ipnet::IpNet>()
                    .ok()
                    .map(|_| IndicatorType::Prefix)
            }) {
                indicators.push(self.make_indicator(
                    value,
                    indicator_type,
                    feed.fetched_at,
                    feed.content_type.as_deref(),
                ));
            }
        }
        deduplicate(indicators)
    }

    fn make_indicator(
        &self,
        value: &str,
        indicator_type: IndicatorType,
        seen: DateTime<Utc>,
        content_type: Option<&str>,
    ) -> Indicator {
        Indicator {
            value: value.to_string(),
            indicator_type,
            categories: vec![self.provider.id.clone()],
            confidence: self.provider.confidence,
            source: self.provider.id.clone(),
            first_seen: seen,
            last_seen: seen,
            expires_at: seen + chrono::Duration::hours(24),
            metadata: serde_json::json!({ "content_type": content_type, "provider": self.provider.id }),
        }
    }
}

fn secret_from_env(variable: &str) -> Result<String, ProviderError> {
    let file_variable = format!("{variable}_FILE");
    load_required(&file_variable, variable)
        .map_err(|error| ProviderError::Configuration(format!("{variable}: {error}")))
}

fn classify(value: &str) -> Option<IndicatorType> {
    if value.parse::<IpAddr>().is_ok() {
        Some(IndicatorType::Ip)
    } else if value.parse::<ipnet::IpNet>().is_ok() {
        Some(IndicatorType::Prefix)
    } else if is_asn(value) {
        Some(IndicatorType::Asn)
    } else if value.starts_with("http://") || value.starts_with("https://") {
        Some(IndicatorType::Url)
    } else if (value.len() == 32 || value.len() == 40 || value.len() == 64)
        && value.chars().all(|character| character.is_ascii_hexdigit())
    {
        Some(IndicatorType::Hash)
    } else {
        None
    }
}

fn is_asn(value: &str) -> bool {
    let value = value.trim();
    let Some((prefix, number)) = value.split_at_checked(2) else {
        return false;
    };
    !number.is_empty()
        && prefix.eq_ignore_ascii_case("AS")
        && number.chars().all(|character| character.is_ascii_digit())
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
                    $id,
                    $display,
                    $source,
                    $endpoint,
                    $interval,
                    $confidence,
                    $method,
                    $body,
                    $auth,
                    $format,
                )?))
            }
        }

        #[async_trait]
        impl ProviderAdapter for $name {
            fn provider(&self) -> Provider {
                self.0.provider.clone()
            }
            async fn fetch(&self) -> Result<RawFeed, ProviderError> {
                self.0.fetch().await
            }
            fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError> {
                self.0.validate(feed)
            }
            fn normalize(&self, feed: &RawFeed) -> Result<Vec<Indicator>, ProviderError> {
                self.0.normalize(feed)
            }
        }
    };
}

define_http_provider!(
    ThreatFoxProvider,
    "threatfox",
    "ThreatFox",
    "abuse.ch",
    "https://threatfox-api.abuse.ch/api/v1/",
    Method::POST,
    Some(serde_json::json!({"query":"get_ioc","days":1})),
    Some("THREATFOX_AUTH_KEY"),
    900,
    90,
    FeedFormat::Json
);
define_http_provider!(
    UrlhausProvider,
    "urlhaus",
    "URLhaus",
    "abuse.ch",
    "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    Method::GET,
    None,
    Some("URLHAUS_AUTH_KEY"),
    900,
    85,
    FeedFormat::Json
);
define_http_provider!(
    FeodoProvider,
    "feodo_tracker",
    "Feodo Tracker",
    "abuse.ch",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    Method::GET,
    None,
    None,
    1800,
    85,
    FeedFormat::Json
);
define_http_provider!(
    MalwareBazaarProvider,
    "malwarebazaar",
    "MalwareBazaar",
    "abuse.ch",
    "https://mb-api.abuse.ch/api/v1/",
    Method::POST,
    Some(serde_json::json!({"query":"get_recent","selector":"time"})),
    Some("MALWAREBAZAAR_AUTH_KEY"),
    1800,
    95,
    FeedFormat::Json
);
define_http_provider!(
    SpamhausProvider,
    "spamhaus_drop",
    "Spamhaus DROP",
    "Spamhaus",
    "https://www.spamhaus.org/drop/drop.txt",
    Method::GET,
    None,
    None,
    3600,
    80,
    FeedFormat::Text
);
define_http_provider!(
    SpamhausEdropProvider,
    "spamhaus_edrop",
    "Spamhaus EDROP",
    "Spamhaus",
    "https://www.spamhaus.org/drop/edrop.txt",
    Method::GET,
    None,
    None,
    3600,
    80,
    FeedFormat::Text
);
define_http_provider!(
    SpamhausAsnProvider,
    "spamhaus_asn",
    "Spamhaus ASN-DROP",
    "Spamhaus",
    "https://www.spamhaus.org/drop/asndrop.json",
    Method::GET,
    None,
    None,
    3600,
    80,
    FeedFormat::AsnJsonLines
);

pub fn phase_one_providers() -> Result<Vec<Box<dyn ProviderAdapter>>, ProviderError> {
    Ok(vec![
        Box::new(ThreatFoxProvider::new()?),
        Box::new(UrlhausProvider::new()?),
        Box::new(FeodoProvider::new()?),
        Box::new(MalwareBazaarProvider::new()?),
        Box::new(SpamhausProvider::new()?),
        Box::new(SpamhausEdropProvider::new()?),
        Box::new(SpamhausAsnProvider::new()?),
    ])
}

#[derive(Clone, Copy)]
enum NetworkFormat {
    AsnJson,
    BgpJson,
    RpkiJson,
    HackerTargetAsn,
}

#[derive(Clone)]
struct NetworkHttpProvider {
    provider: Provider,
    endpoint: String,
    format: NetworkFormat,
    fallback_asn: Option<String>,
    client: Client,
}

impl NetworkHttpProvider {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: &str,
        name: &str,
        source: &str,
        endpoint: String,
        interval_seconds: i64,
        confidence: u8,
        format: NetworkFormat,
        fallback_asn: Option<String>,
    ) -> Result<Self, ProviderError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("clawforge-network-intelligence/0.1")
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
            endpoint,
            format,
            fallback_asn,
            client,
        })
    }

    async fn fetch(&self) -> Result<RawFeed, ProviderError> {
        let response = self
            .client
            .get(&self.endpoint)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    ProviderError::Timeout
                } else {
                    ProviderError::Request(error)
                }
            })?;
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            return Err(ProviderError::RateLimited {
                retry_after: format!(" (retry-after {retry_after})"),
            });
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
        Ok(RawFeed {
            body,
            content_type,
            fetched_at: Utc::now(),
        })
    }

    fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError> {
        if feed.body.is_empty() {
            return Err(ProviderError::EmptyResponse);
        }
        if feed.body.len() > 50 * 1024 * 1024 {
            return Err(ProviderError::Validation(
                "network response exceeds 50 MiB".to_string(),
            ));
        }
        if matches!(self.format, NetworkFormat::HackerTargetAsn) {
            std::str::from_utf8(&feed.body).map_err(|error| {
                ProviderError::Validation(format!("invalid text encoding: {error}"))
            })?;
        } else {
            serde_json::from_slice::<serde_json::Value>(&feed.body).map_err(|error| {
                ProviderError::Validation(format!("invalid network JSON: {error}"))
            })?;
        }
        let batch = self.normalize(feed)?;
        if batch.asn_records.is_empty()
            && batch.bgp_events.is_empty()
            && batch.rpki_records.is_empty()
        {
            return Err(ProviderError::Validation(
                "network response contains no records".to_string(),
            ));
        }
        Ok(())
    }

    fn normalize(&self, feed: &RawFeed) -> Result<NetworkBatch, ProviderError> {
        match self.format {
            NetworkFormat::AsnJson => normalize_asn_json(&feed.body, &self.provider),
            NetworkFormat::BgpJson => normalize_bgp_json(
                &feed.body,
                &self.provider,
                feed.fetched_at,
                self.fallback_asn.as_deref(),
            ),
            NetworkFormat::RpkiJson => {
                normalize_rpki_json(&feed.body, &self.provider, feed.fetched_at)
            }
            NetworkFormat::HackerTargetAsn => {
                normalize_hackertarget_asn(&feed.body, &self.provider, feed.fetched_at)
            }
        }
    }
}

fn network_resource(variable: &str, default: &str) -> String {
    env::var(variable)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
        .replace('/', "%2F")
}

fn network_endpoint(variable: &str, template: &str, default: &str) -> String {
    env::var(variable)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            template.replace(
                "{resource}",
                &network_resource("CLAWFORGE_NETWORK_RESOURCE", default),
            )
        })
}

fn json_rows(value: serde_json::Value) -> Vec<serde_json::Value> {
    fn collect(value: serde_json::Value, output: &mut Vec<serde_json::Value>) {
        if let Some(rows) = value.as_array() {
            for row in rows {
                collect(row.clone(), output);
            }
            return;
        }
        if let Some(object) = value.as_object() {
            let is_record = [
                "asn",
                "asn_id",
                "autnum",
                "origin_asn",
                "origin",
                "prefix",
                "network",
                "previous_asn",
                "new_asn",
            ]
            .iter()
            .any(|key| {
                object
                    .get(*key)
                    .is_some_and(|field| field.is_string() || field.is_number())
            }) || (object.contains_key("resource")
                && !object.contains_key("prefixes")
                && !object.contains_key("counts"));
            if is_record {
                output.push(value);
            } else {
                for nested in object.values() {
                    collect(nested.clone(), output);
                }
            }
            return;
        }
        if value.is_string() {
            output.push(value);
        }
    }

    let mut rows = Vec::new();
    collect(value, &mut rows);
    rows
}

fn value_string(row: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        row.get(*key).and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_i64().map(|number| number.to_string()))
        })
    })
}

fn normalize_asn(value: &str) -> Option<String> {
    let value = value.trim();
    let number = value
        .strip_prefix("AS")
        .or_else(|| value.strip_prefix("as"))
        .unwrap_or(value);
    if !number.is_empty() && number.chars().all(|character| character.is_ascii_digit()) {
        Some(format!("AS{number}"))
    } else {
        None
    }
}

fn asn_from_row(row: &serde_json::Value) -> Option<String> {
    [
        "asn",
        "asn_id",
        "autnum",
        "origin_asn",
        "origin",
        "resource",
    ]
    .iter()
    .find_map(|key| value_string(row, &[*key]).and_then(|value| normalize_asn(&value)))
}

fn string_array(row: &serde_json::Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| row.get(*key))
        .map(|value| {
            value
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .or_else(|| value.as_str().map(|item| vec![item.to_string()]))
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

fn normalize_asn_json(body: &[u8], provider: &Provider) -> Result<NetworkBatch, ProviderError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| ProviderError::Validation(format!("invalid ASN JSON: {error}")))?;
    let mut records = Vec::new();
    for row in json_rows(value) {
        let Some(asn) = asn_from_row(&row) else {
            continue;
        };
        records.push(AsnRecord {
            asn,
            name: value_string(
                &row,
                &[
                    "name",
                    "asnName",
                    "holder",
                    "description",
                    "organisation",
                    "org_name",
                ],
            )
            .unwrap_or_else(|| provider.name.clone()),
            organisation: value_string(
                &row,
                &["organisation", "organization", "org_name", "holder"],
            )
            .unwrap_or_default(),
            provider: provider.id.clone(),
            country: value_string(&row, &["country", "country_code", "countryCode"])
                .or_else(|| {
                    row.get("country")
                        .and_then(|country| value_string(country, &["iso", "code"]))
                })
                .unwrap_or_default(),
            registry: value_string(&row, &["registry", "rir", "rir_name"]).unwrap_or_default(),
            prefixes: string_array(&row, &["prefixes", "prefixes_v4", "prefixes_v6"]),
            network_type: value_string(&row, &["network_type", "type", "info_type"])
                .unwrap_or_else(|| "unknown".to_string()),
            reputation: 0,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        });
    }
    records.sort_by(|left, right| left.asn.cmp(&right.asn));
    records.dedup_by(|left, right| left.asn == right.asn);
    Ok(NetworkBatch {
        asn_records: records,
        ..NetworkBatch::default()
    })
}

fn parse_timestamp(value: Option<&serde_json::Value>, fallback: DateTime<Utc>) -> DateTime<Utc> {
    value
        .and_then(|value| value.as_str())
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or(fallback)
}

fn parse_rpki(value: Option<&str>) -> RpkiStatus {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "valid" => RpkiStatus::Valid,
        "invalid" => RpkiStatus::Invalid,
        _ => RpkiStatus::Unknown,
    }
}

fn parse_bgp_status(value: Option<&str>, previous: Option<&str>, new: Option<&str>) -> BgpStatus {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "anomalous" | "hijack" | "hijacking" => BgpStatus::Anomalous,
        "changed" | "change" | "announcement" | "withdrawal" => BgpStatus::Changed,
        "stable" => BgpStatus::Stable,
        _ if previous.is_some() && new.is_some() && previous != new => BgpStatus::Changed,
        _ => BgpStatus::Unknown,
    }
}

fn normalize_bgp_json(
    body: &[u8],
    provider: &Provider,
    fetched_at: DateTime<Utc>,
    fallback_asn: Option<&str>,
) -> Result<NetworkBatch, ProviderError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| ProviderError::Validation(format!("invalid BGP JSON: {error}")))?;
    let mut events = Vec::new();
    for row in json_rows(value) {
        let prefix = row
            .as_str()
            .map(str::to_string)
            .or_else(|| value_string(&row, &["prefix", "prefixes", "network"]));
        let Some(prefix) = prefix else { continue };
        if prefix.parse::<ipnet::IpNet>().is_err() {
            continue;
        }
        let previous_asn = value_string(&row, &["previous_asn", "previous_origin", "old_origin"])
            .and_then(|value| normalize_asn(&value));
        let new_asn = value_string(&row, &["new_asn", "new_origin", "origin_asn", "origin"])
            .and_then(|value| normalize_asn(&value));
        let origin_asn = new_asn
            .clone()
            .or_else(|| previous_asn.clone())
            .or_else(|| fallback_asn.map(str::to_string))
            .unwrap_or_else(|| "AS0".to_string());
        let timestamp =
            parse_timestamp(row.get("timestamp").or_else(|| row.get("time")), fetched_at);
        let status = parse_bgp_status(
            value_string(&row, &["status", "event_type", "type"]).as_deref(),
            previous_asn.as_deref(),
            new_asn.as_deref(),
        );
        events.push(BgpEvent {
            prefix,
            origin_asn,
            previous_asn,
            new_asn,
            timestamp,
            source: provider.id.clone(),
            status,
            rpki_status: parse_rpki(
                value_string(&row, &["rpki_status", "rpki", "rpki_state"]).as_deref(),
            ),
            first_seen: timestamp,
            last_seen: timestamp,
            change: value_string(&row, &["change", "description"]),
        });
    }
    events.sort_by(|left, right| {
        left.prefix
            .cmp(&right.prefix)
            .then(left.timestamp.cmp(&right.timestamp))
    });
    events.dedup_by(|left, right| {
        left.prefix == right.prefix
            && left.previous_asn == right.previous_asn
            && left.new_asn == right.new_asn
            && left.source == right.source
    });
    Ok(NetworkBatch {
        bgp_events: events,
        ..NetworkBatch::default()
    })
}

fn normalize_rpki_json(
    body: &[u8],
    provider: &Provider,
    fetched_at: DateTime<Utc>,
) -> Result<NetworkBatch, ProviderError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| ProviderError::Validation(format!("invalid RPKI JSON: {error}")))?;
    let mut records = Vec::new();
    for row in json_rows(value) {
        let Some(prefix) = value_string(&row, &["prefix", "resource"]) else {
            continue;
        };
        let Some(asn) = asn_from_row(&row) else {
            continue;
        };
        let timestamp = parse_timestamp(
            row.get("timestamp").or_else(|| row.get("validated_at")),
            fetched_at,
        );
        records.push(RpkiRecord {
            prefix,
            asn,
            status: parse_rpki(value_string(&row, &["status", "validation_status"]).as_deref()),
            timestamp,
            source: provider.id.clone(),
        });
    }
    records.sort_by(|left, right| {
        left.prefix
            .cmp(&right.prefix)
            .then(left.asn.cmp(&right.asn))
    });
    records.dedup_by(|left, right| {
        left.prefix == right.prefix && left.asn == right.asn && left.status == right.status
    });
    Ok(NetworkBatch {
        rpki_records: records,
        ..NetworkBatch::default()
    })
}

/// Team Cymru IP-to-ASN mapping, verbose WHOIS answer:
/// ```text
/// AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
/// 15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE - Google LLC, US
/// ```
/// An unannounced address answers `NA` in the AS column and error text has no
/// header at all; both are rejected rather than turned into an empty record.
fn normalize_cymru_whois(
    body: &[u8],
    provider: &Provider,
    fetched_at: DateTime<Utc>,
) -> Result<NetworkBatch, ProviderError> {
    let text = std::str::from_utf8(body)
        .map_err(|error| ProviderError::Validation(format!("invalid Team Cymru text: {error}")))?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let header_ok = lines.next().is_some_and(|line| {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        cells.len() >= 7 && cells[0] == "AS" && cells[1] == "IP" && cells[2] == "BGP Prefix"
    });
    if !header_ok {
        return Err(ProviderError::Validation(
            "Team Cymru answer has no WHOIS header".to_string(),
        ));
    }
    let mut records = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split('|').map(str::trim).collect();
        if fields.len() < 7 {
            return Err(ProviderError::Validation(
                "Team Cymru row has fewer than 7 columns".to_string(),
            ));
        }
        let Some(asn) = normalize_asn(fields[0]) else {
            return Err(ProviderError::Validation(format!(
                "Team Cymru has no ASN for this address ({})",
                fields[0]
            )));
        };
        if fields[2].parse::<ipnet::IpNet>().is_err() {
            return Err(ProviderError::Validation(
                "Team Cymru BGP prefix is not a prefix".to_string(),
            ));
        }
        records.push(AsnRecord {
            asn,
            name: fields[6].to_string(),
            organisation: fields[6].to_string(),
            provider: provider.id.clone(),
            country: fields[3].to_string(),
            registry: fields[4].to_string(),
            prefixes: vec![fields[2].to_string()],
            network_type: "unknown".to_string(),
            reputation: 0,
            first_seen: fetched_at,
            last_seen: fetched_at,
        });
    }
    if records.is_empty() {
        return Err(ProviderError::Validation(
            "Team Cymru answer has no rows".to_string(),
        ));
    }
    Ok(NetworkBatch {
        asn_records: records,
        ..NetworkBatch::default()
    })
}

/// A single unquoted, comma-separated line split respecting `"..."` quoted
/// fields - `hackertarget.com`'s ASlookup response embeds a comma inside
/// its own quoted name field (`"<asn>","<name>, <country>"`), so a naive
/// `split(',')` would wrongly cut that field in two.
fn parse_quoted_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for character in line.chars() {
        match character {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    fields.push(current);
    fields
}

/// `hackertarget.com`'s free ASlookup API - the replacement for the former
/// `bgpview_asn` provider (`api.bgpview.io` stopped resolving entirely,
/// found live: not just the `/asn/{id}` endpoint but the bare `bgpview.io`
/// domain itself has no DNS records at all, an external, unfixable outage,
/// not a Clawforge-side bug). Chosen over other candidates tried live from
/// the actual worker container (not a possibly-filtered local resolver):
/// `ipinfo.io` returned nothing, `bgp.tools`'s REST-looking guesses 404'd
/// (its documented automatable interface is WHOIS, not HTTP JSON, a
/// different `NetworkProvider` shape this crate does not have yet);
/// `hackertarget.com` actually answered, and with more than `bgpview.io`
/// ever gave - the ASN's real announced prefixes, not just its name.
///
/// Response shape (plain text, not JSON - hence `NetworkFormat::CymruText`'s
/// sibling `HackerTargetAsn`, not `AsnJson`):
/// ```text
/// "3333","RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre RIPE NCC, NL"
/// 2001:67c:2e8::/48
/// 193.0.20.0/23
/// ...
/// ```
/// A failed lookup (unknown ASN, or HackerTarget's own free-tier rate limit)
/// answers with plain, unquoted error text instead - the leading `"` is
/// what tells the two apart without needing to pattern-match specific
/// error strings that could change upstream.
fn normalize_hackertarget_asn(
    body: &[u8],
    provider: &Provider,
    fetched_at: DateTime<Utc>,
) -> Result<NetworkBatch, ProviderError> {
    let text = std::str::from_utf8(body).map_err(|error| {
        ProviderError::Validation(format!("invalid HackerTarget text: {error}"))
    })?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let Some(header) = lines.next() else {
        return Ok(NetworkBatch::default());
    };
    if !header.trim_start().starts_with('"') {
        return Err(ProviderError::Validation(format!(
            "HackerTarget ASN lookup failed: {}",
            header.trim()
        )));
    }
    let fields = parse_quoted_csv_line(header);
    let Some(asn) = fields.first().and_then(|value| normalize_asn(value)) else {
        return Ok(NetworkBatch::default());
    };
    let (name, country) = match fields.get(1) {
        Some(value) => match value.rsplit_once(", ") {
            Some((name, country)) => (name.trim().to_string(), country.trim().to_string()),
            None => (value.trim().to_string(), String::new()),
        },
        None => (String::new(), String::new()),
    };
    let prefixes: Vec<String> = lines.map(|line| line.trim().to_string()).collect();
    Ok(NetworkBatch {
        asn_records: vec![AsnRecord {
            asn,
            organisation: name.clone(),
            name,
            provider: provider.id.clone(),
            country,
            registry: String::new(),
            prefixes,
            network_type: "unknown".to_string(),
            reputation: 0,
            first_seen: fetched_at,
            last_seen: fetched_at,
        }],
        ..NetworkBatch::default()
    })
}

macro_rules! define_network_provider {
    ($name:ident, $id:literal, $display:literal, $source:literal, $template:literal, $resource_env:literal, $default:literal, $interval:expr, $confidence:expr, $format:expr) => {
        pub struct $name(NetworkHttpProvider);

        impl $name {
            pub fn new() -> Result<Self, ProviderError> {
                Self::with_resource(&network_resource($resource_env, $default))
            }

            pub fn with_resource(resource: &str) -> Result<Self, ProviderError> {
                let endpoint_override = format!("CLAWFORGE_{}_ENDPOINT", $id.to_ascii_uppercase());
                let endpoint = network_endpoint(&endpoint_override, $template, resource);
                let fallback_asn = normalize_asn(resource);
                Ok(Self(NetworkHttpProvider::new(
                    $id,
                    $display,
                    $source,
                    endpoint,
                    $interval,
                    $confidence,
                    $format,
                    fallback_asn,
                )?))
            }
        }

        #[async_trait]
        impl NetworkProvider for $name {
            fn provider(&self) -> Provider {
                self.0.provider.clone()
            }
            async fn fetch(&self) -> Result<RawFeed, ProviderError> {
                self.0.fetch().await
            }
            fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError> {
                self.0.validate(feed)
            }
            fn normalize(&self, feed: &RawFeed) -> Result<NetworkBatch, ProviderError> {
                self.0.normalize(feed)
            }
        }
    };
}

define_network_provider!(
    RipeStatProvider,
    "ripestat_asn",
    "RIPEstat ASN",
    "RIPE NCC",
    "https://stat.ripe.net/data/as-overview/data.json?resource={resource}",
    "CLAWFORGE_RIPESTAT_RESOURCE",
    "AS3333",
    3600,
    75,
    NetworkFormat::AsnJson
);
define_network_provider!(
    HackerTargetProvider,
    "hackertarget_asn",
    "HackerTarget ASN",
    "HackerTarget",
    "https://api.hackertarget.com/aslookup/?q=AS{resource}",
    "CLAWFORGE_HACKERTARGET_RESOURCE",
    "3333",
    3600,
    70,
    NetworkFormat::HackerTargetAsn
);
define_network_provider!(
    PeeringDbProvider,
    "peeringdb",
    "PeeringDB",
    "PeeringDB",
    "https://www.peeringdb.com/api/net?asn={resource}",
    "CLAWFORGE_PEERINGDB_RESOURCE",
    "3333",
    86400,
    70,
    NetworkFormat::AsnJson
);
define_network_provider!(
    CaidaProvider,
    "caida_as_rank",
    "CAIDA AS Rank",
    "CAIDA",
    "https://api.asrank.caida.org/v2/restful/asns/{resource}",
    "CLAWFORGE_CAIDA_RESOURCE",
    "3333",
    86400,
    65,
    NetworkFormat::AsnJson
);
define_network_provider!(
    RipeRisProvider,
    "ripe_ris",
    "RIPE RIS",
    "RIPE NCC",
    "https://stat.ripe.net/data/ris-prefixes/data.json?resource={resource}&list_prefixes=true",
    "CLAWFORGE_RIPE_RIS_RESOURCE",
    "AS3333",
    1800,
    70,
    NetworkFormat::BgpJson
);
define_network_provider!(
    RouteViewsProvider,
    "routeviews",
    "RouteViews",
    "RouteViews",
    "https://api.routeviews.org/prefix/{resource}",
    "CLAWFORGE_ROUTEVIEWS_RESOURCE",
    "203.0.113.0%2F24",
    1800,
    70,
    NetworkFormat::BgpJson
);
/// RPKI route-origin validation for ONE explicit (origin AS, prefix) pair through
/// the RIPEstat data call `rpki-validation`, which needs both: `resource` is the
/// origin ASN, `prefix` the announced prefix. (The former default sent the prefix
/// as the resource and got HTTP 400.) The pair is a sample; the per-source
/// validation of real traffic lives in the routing-context worker.
pub struct RpkiProvider(NetworkHttpProvider);

impl RpkiProvider {
    pub const DEFAULT_ASN: &'static str = "AS3333";
    pub const DEFAULT_PREFIX: &'static str = "193.0.0.0/21";

    pub fn new() -> Result<Self, ProviderError> {
        let asn = env::var("CLAWFORGE_RPKI_ORIGIN_ASN")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| Self::DEFAULT_ASN.to_string());
        let prefix = env::var("CLAWFORGE_RPKI_PREFIX")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| Self::DEFAULT_PREFIX.to_string());
        Self::with_origin(&asn, &prefix)
    }

    pub fn with_origin(asn: &str, prefix: &str) -> Result<Self, ProviderError> {
        let asn = normalize_asn(asn).ok_or_else(|| {
            ProviderError::Configuration("CLAWFORGE_RPKI_ORIGIN_ASN is not an ASN".to_string())
        })?;
        let net: ipnet::IpNet = prefix.trim().parse().map_err(|_| {
            ProviderError::Configuration("CLAWFORGE_RPKI_PREFIX is not a prefix".to_string())
        })?;
        let endpoint = env::var("CLAWFORGE_RPKI_VALIDATOR_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                format!(
                    "https://stat.ripe.net/data/rpki-validation/data.json?resource={asn}&prefix={}",
                    net.to_string().replace('/', "%2F")
                )
            });
        Ok(Self(NetworkHttpProvider::new(
            "rpki_validator",
            "RPKI Validator",
            "RPKI",
            endpoint,
            3600,
            90,
            NetworkFormat::RpkiJson,
            Some(asn),
        )?))
    }
}

#[async_trait]
impl NetworkProvider for RpkiProvider {
    fn provider(&self) -> Provider {
        self.0.provider.clone()
    }
    async fn fetch(&self) -> Result<RawFeed, ProviderError> {
        self.0.fetch().await
    }
    fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError> {
        self.0.validate(feed)
    }
    fn normalize(&self, feed: &RawFeed) -> Result<NetworkBatch, ProviderError> {
        self.0.normalize(feed)
    }
}

/// Team Cymru IP-to-ASN mapping through the documented WHOIS interface
/// (`whois.cymru.com:43`, verbose query ` -v <ip>`). The former
/// `asn.cymru.com/cgi-bin/asnlookup.pl` URL is an HTML form, not a machine
/// interface (verified live: `text/html`), so the old provider could only ever
/// fail with "no records". One address per run, once a day by default.
pub struct TeamCymruProvider {
    provider: Provider,
    address: std::net::IpAddr,
    server: String,
}

impl TeamCymruProvider {
    pub const DEFAULT_SERVER: &'static str = "whois.cymru.com:43";
    const MAX_ANSWER_BYTES: u64 = 16 * 1024;

    pub fn new() -> Result<Self, ProviderError> {
        let resource = env::var("CLAWFORGE_TEAM_CYMRU_RESOURCE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "8.8.8.8".to_string());
        let mut provider = Self::with_resource(&resource)?;
        if let Some(server) = env::var("CLAWFORGE_TEAM_CYMRU_WHOIS")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            provider.server = server;
        }
        Ok(provider)
    }

    pub fn with_resource(resource: &str) -> Result<Self, ProviderError> {
        let address: std::net::IpAddr = resource.trim().parse().map_err(|_| {
            ProviderError::Configuration(
                "CLAWFORGE_TEAM_CYMRU_RESOURCE must be one IP address".to_string(),
            )
        })?;
        if !is_global_address(&address) {
            return Err(ProviderError::Configuration(
                "CLAWFORGE_TEAM_CYMRU_RESOURCE must be a public address".to_string(),
            ));
        }
        Ok(Self {
            provider: Provider {
                id: "team_cymru".to_string(),
                name: "Team Cymru".to_string(),
                source: "Team Cymru".to_string(),
                interval_seconds: 86400,
                confidence: 65,
                enabled: true,
            },
            address,
            server: Self::DEFAULT_SERVER.to_string(),
        })
    }

    pub fn with_server(mut self, server: &str) -> Self {
        self.server = server.to_string();
        self
    }
}

/// Never send private, loopback, link-local or documentation addresses to a public service.
fn is_global_address(address: &std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(ip) => {
            let o = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || o[0] >= 240)
        }
        std::net::IpAddr::V6(ip) => {
            let s = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

#[async_trait]
impl NetworkProvider for TeamCymruProvider {
    fn provider(&self) -> Provider {
        self.provider.clone()
    }

    async fn fetch(&self) -> Result<RawFeed, ProviderError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let limit = Duration::from_secs(20);
        let exchange = async {
            let mut stream = tokio::net::TcpStream::connect(&self.server)
                .await
                .map_err(|error| ProviderError::Connection(error.kind().to_string()))?;
            stream
                .write_all(format!(" -v {}\r\n", self.address).as_bytes())
                .await
                .map_err(|error| ProviderError::Connection(error.kind().to_string()))?;
            let mut body = Vec::new();
            stream
                .take(Self::MAX_ANSWER_BYTES)
                .read_to_end(&mut body)
                .await
                .map_err(|error| ProviderError::Connection(error.kind().to_string()))?;
            Ok::<_, ProviderError>(body)
        };
        let body = tokio::time::timeout(limit, exchange)
            .await
            .map_err(|_| ProviderError::Timeout)??;
        if body.is_empty() {
            return Err(ProviderError::EmptyResponse);
        }
        Ok(RawFeed {
            body,
            content_type: Some("text/plain".to_string()),
            fetched_at: Utc::now(),
        })
    }

    fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError> {
        normalize_cymru_whois(&feed.body, &self.provider, feed.fetched_at).map(|_| ())
    }

    fn normalize(&self, feed: &RawFeed) -> Result<NetworkBatch, ProviderError> {
        normalize_cymru_whois(&feed.body, &self.provider, feed.fetched_at)
    }
}

pub fn network_providers() -> Result<Vec<Box<dyn NetworkProvider>>, ProviderError> {
    Ok(vec![
        Box::new(RipeStatProvider::new()?),
        Box::new(HackerTargetProvider::new()?),
        Box::new(PeeringDbProvider::new()?),
        Box::new(CaidaProvider::new()?),
        Box::new(TeamCymruProvider::new()?),
        Box::new(RipeRisProvider::new()?),
        Box::new(RouteViewsProvider::new()?),
        Box::new(RpkiProvider::new()?),
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnRecord {
    pub asn: String,
    pub name: String,
    pub organisation: String,
    pub provider: String,
    pub country: String,
    pub registry: String,
    pub prefixes: Vec<String>,
    pub network_type: String,
    pub reputation: u8,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum RpkiStatus {
    Valid,
    #[default]
    Unknown,
    Invalid,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum BgpStatus {
    Stable,
    Changed,
    Anomalous,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpEvent {
    pub prefix: String,
    pub origin_asn: String,
    pub previous_asn: Option<String>,
    pub new_asn: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub status: BgpStatus,
    pub rpki_status: RpkiStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub change: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpkiRecord {
    pub prefix: String,
    pub asn: String,
    pub status: RpkiStatus,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkBatch {
    pub asn_records: Vec<AsnRecord>,
    pub bgp_events: Vec<BgpEvent>,
    pub rpki_records: Vec<RpkiRecord>,
}

#[async_trait]
pub trait NetworkProvider: Send + Sync {
    fn provider(&self) -> Provider;
    async fn fetch(&self) -> Result<RawFeed, ProviderError>;
    fn validate(&self, feed: &RawFeed) -> Result<(), ProviderError>;
    fn normalize(&self, feed: &RawFeed) -> Result<NetworkBatch, ProviderError>;
}

#[async_trait]
pub trait NetworkSink: Send + Sync {
    async fn upsert_asn_records(&self, records: &[AsnRecord]) -> Result<usize, ProviderError>;
    async fn upsert_bgp_events(&self, events: &[BgpEvent]) -> Result<usize, ProviderError>;
    async fn upsert_rpki_records(&self, records: &[RpkiRecord]) -> Result<usize, ProviderError>;
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

#[cfg(test)]
mod provider_tests {
    use super::*;

    fn feed(body: &str) -> RawFeed {
        RawFeed {
            body: body.as_bytes().to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        }
    }

    #[test]
    fn threatfox_json_is_validated_and_normalized_with_deduplication() {
        let provider = ThreatFoxProvider::new().unwrap();
        let raw = feed(
            r#"{"query_status":"ok","data":[{"ioc":"198.51.100.2:443","ioc_type":"ip:port"},{"ioc":"198.51.100.2:443","ioc_type":"ip:port"},{"ioc":"example.test","ioc_type":"domain"}]}"#,
        );
        provider.validate(&raw).unwrap();
        let values = provider.normalize(&raw).unwrap();
        assert_eq!(values.len(), 2);
        assert!(values.iter().any(|item| item.value == "198.51.100.2"));
        assert!(values
            .iter()
            .any(|item| item.indicator_type == IndicatorType::Domain));
    }

    #[test]
    fn malformed_json_and_api_errors_are_rejected() {
        let provider = UrlhausProvider::new().unwrap();
        assert!(provider.validate(&feed("not json")).is_err());
        assert!(provider
            .validate(&feed(r#"{"query_status":"error"}"#))
            .is_err());
        assert!(provider
            .validate(&RawFeed {
                body: Vec::new(),
                ..feed("")
            })
            .is_err());
    }

    #[test]
    fn spamhaus_comments_and_prefixes_are_normalized() {
        let provider = SpamhausProvider::new().unwrap();
        let raw = RawFeed {
            body: b"203.0.113.0/24 ; comment\n# heading\n2001:db8::/32\n".to_vec(),
            content_type: Some("text/plain".into()),
            fetched_at: Utc::now(),
        };
        provider.validate(&raw).unwrap();
        let values = provider.normalize(&raw).unwrap();
        assert_eq!(values.len(), 2);
        assert!(values
            .iter()
            .all(|item| item.indicator_type == IndicatorType::Prefix));
        assert!(provider
            .validate(&RawFeed {
                body: b"<html>rate limited</html>".to_vec(),
                ..raw
            })
            .is_err());
    }

    #[test]
    fn spamhaus_asn_accepts_metadata_but_rejects_unknown_or_invalid_rows() {
        let provider = SpamhausAsnProvider::new().unwrap();
        let metadata = r#"{"type":"metadata","timestamp":1792622642,"size":123,"records":1,"copyright":"(c) The Spamhaus Project","terms":"https://www.spamhaus.org/drop/terms/"}"#;
        let raw = feed(&format!("{{\"asn\":64500}}\n{metadata}\n"));
        provider.validate(&raw).unwrap();
        let values = provider.normalize(&raw).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].value, "AS64500");
        for invalid in [
            metadata.to_string(),
            "{\"asn\":64500}\n{\"unknown\":true}".into(),
            "{\"asn\":64500}\n{\"type\":\"metadata\"}".into(),
            format!("{{\"asn\":\"invalid\"}}\n{metadata}"),
            format!(
                "{{\"asn\":64500}}\n{}",
                metadata.replace("\"type\":", "\"asn\":\"invalid\",\"type\":")
            ),
        ] {
            let raw = feed(&invalid);
            assert!(provider.validate(&raw).is_err(), "accepted {invalid}");
            assert!(provider.normalize(&raw).is_err(), "normalized {invalid}");
        }
    }

    #[test]
    fn caida_nested_asn_envelope_is_not_mistaken_for_a_record() {
        let provider = CaidaProvider::with_resource("3333").unwrap();
        let raw = feed(
            r#"{"data":{"asn":{"asn":"3333","asnName":"RIPE-NCC-AS","country":{"iso":"NL"}}}}"#,
        );
        provider.validate(&raw).unwrap();
        let batch = provider.normalize(&raw).unwrap();
        assert_eq!(batch.asn_records.len(), 1);
        assert_eq!(batch.asn_records[0].asn, "AS3333");
        assert_eq!(batch.asn_records[0].name, "RIPE-NCC-AS");
        assert_eq!(batch.asn_records[0].country, "NL");
    }

    #[test]
    fn spamhaus_edrop_and_asn_feeds_are_validated_and_normalized() {
        let edrop = SpamhausEdropProvider::new().unwrap();
        let raw = RawFeed {
            body: b"198.51.100.0/24 ; comment\n".to_vec(),
            content_type: Some("text/plain".into()),
            fetched_at: Utc::now(),
        };
        edrop.validate(&raw).unwrap();
        assert_eq!(
            edrop.normalize(&raw).unwrap()[0].indicator_type,
            IndicatorType::Prefix
        );
        let merged = RawFeed {
            body:
                b"; This list has been merged into https://www.spamhaus.org/drop/drop.txt\n; EOF\n"
                    .to_vec(),
            content_type: Some("text/plain".into()),
            fetched_at: Utc::now(),
        };
        edrop.validate(&merged).unwrap();
        assert!(edrop.normalize(&merged).unwrap().is_empty());

        let asn = SpamhausAsnProvider::new().unwrap();
        let raw = RawFeed {
            body: br#"{"asn":64500,"asname":"fixture"}
"#
            .to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        };
        asn.validate(&raw).unwrap();
        let values = asn.normalize(&raw).unwrap();
        assert_eq!(values[0].value, "AS64500");
        assert_eq!(values[0].indicator_type, IndicatorType::Asn);
        assert!(asn
            .validate(&RawFeed {
                body: b"not an ASN feed".to_vec(),
                ..raw
            })
            .is_err());
    }

    #[test]
    fn phase_one_provider_shapes_are_normalized() {
        let urlhaus = UrlhausProvider::new().unwrap();
        let values = urlhaus
            .normalize(&feed(
                r#"{"query_status":"ok","urls":[{"url":"https://bad.test/payload"}]}"#,
            ))
            .unwrap();
        assert_eq!(values[0].indicator_type, IndicatorType::Url);

        let feodo = FeodoProvider::new().unwrap();
        let values = feodo
            .normalize(&feed(r#"[{"ip_address":"203.0.113.5","port":443}]"#))
            .unwrap();
        assert_eq!(values[0].indicator_type, IndicatorType::Ip);

        let malwarebazaar = MalwareBazaarProvider::new().unwrap();
        let values = malwarebazaar.normalize(&feed(r#"{"query_status":"ok","data":[{"sha256_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}"#)).unwrap();
        assert_eq!(values[0].indicator_type, IndicatorType::Hash);
    }

    #[test]
    fn release_fixtures_cover_every_phase_one_feed() {
        let fixtures: &[(&str, &[u8], FeedFormat)] = &[
            (
                "threatfox",
                include_bytes!("../fixtures/threatfox.json"),
                FeedFormat::Json,
            ),
            (
                "urlhaus",
                include_bytes!("../fixtures/urlhaus.json"),
                FeedFormat::Json,
            ),
            (
                "feodo",
                include_bytes!("../fixtures/feodo.json"),
                FeedFormat::Json,
            ),
            (
                "malwarebazaar",
                include_bytes!("../fixtures/malwarebazaar.json"),
                FeedFormat::Json,
            ),
            (
                "spamhaus-drop",
                include_bytes!("../fixtures/spamhaus-drop.txt"),
                FeedFormat::Text,
            ),
            (
                "spamhaus-edrop",
                include_bytes!("../fixtures/spamhaus-edrop.txt"),
                FeedFormat::Text,
            ),
            (
                "spamhaus-asn",
                include_bytes!("../fixtures/spamhaus-asn.jsonl"),
                FeedFormat::AsnJsonLines,
            ),
        ];
        for &(name, body, format) in fixtures {
            let raw = RawFeed {
                body: body.to_vec(),
                content_type: Some("fixture".into()),
                fetched_at: Utc::now(),
            };
            let provider = match name {
                "threatfox" => ThreatFoxProvider::new().unwrap().0,
                "urlhaus" => UrlhausProvider::new().unwrap().0,
                "feodo" => FeodoProvider::new().unwrap().0,
                "malwarebazaar" => MalwareBazaarProvider::new().unwrap().0,
                "spamhaus-drop" => SpamhausProvider::new().unwrap().0,
                "spamhaus-edrop" => SpamhausEdropProvider::new().unwrap().0,
                "spamhaus-asn" => SpamhausAsnProvider::new().unwrap().0,
                _ => unreachable!(),
            };
            assert!(matches!(
                (provider.format, format),
                (FeedFormat::Json, FeedFormat::Json)
                    | (FeedFormat::Text, FeedFormat::Text)
                    | (FeedFormat::AsnJsonLines, FeedFormat::AsnJsonLines)
            ));
            provider.validate(&raw).unwrap();
            assert!(
                !provider.normalize(&raw).unwrap().is_empty(),
                "fixture {name} produced no indicators"
            );
        }
    }

    #[test]
    fn network_providers_normalize_asn_bgp_and_rpki_records() {
        let asn = RipeStatProvider::with_resource("AS3333").unwrap();
        let asn_feed = RawFeed {
            body: br#"{"data":{"asn":3333,"holder":"RIPE NCC","country":"NL","rir":"RIPE NCC","prefixes":["193.0.0.0/21"]}}"#.to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        };
        asn.validate(&asn_feed).unwrap();
        let batch = asn.normalize(&asn_feed).unwrap();
        assert_eq!(batch.asn_records[0].asn, "AS3333");
        assert_eq!(batch.asn_records[0].prefixes, vec!["193.0.0.0/21"]);

        let bgp = RipeRisProvider::with_resource("AS3333").unwrap();
        let bgp_feed = RawFeed {
            body: br#"{"events":[{"prefix":"198.51.100.0/24","previous_asn":"AS64501","new_asn":"AS64500","status":"changed","timestamp":"2026-01-01T00:00:00Z"}]}"#.to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        };
        bgp.validate(&bgp_feed).unwrap();
        let batch = bgp.normalize(&bgp_feed).unwrap();
        assert_eq!(batch.bgp_events[0].new_asn.as_deref(), Some("AS64500"));
        assert_eq!(batch.bgp_events[0].status, BgpStatus::Changed);
        let ris_prefixes = RawFeed {
            body: br#"{"data":{"prefixes":{"v4":{"originating":["193.0.22.0/23"]}},"resource":"3333"}}"#.to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        };
        let ris_batch = bgp.normalize(&ris_prefixes).unwrap();
        assert_eq!(ris_batch.bgp_events[0].prefix, "193.0.22.0/23");
        let routeviews = RouteViewsProvider::with_resource("198.51.100.0%2F24").unwrap();
        let routeviews_feed = RawFeed {
            body: br#"[{"prefix":"198.51.100.0/24","origin_asn":64500,"rpki_state":"valid"}]"#
                .to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        };
        routeviews.validate(&routeviews_feed).unwrap();
        let routeviews_batch = routeviews.normalize(&routeviews_feed).unwrap();
        assert_eq!(
            routeviews_batch.bgp_events[0].rpki_status,
            RpkiStatus::Valid
        );

        // Real RIPEstat answer for the pair (AS3333, 193.0.0.0/21), captured 2026-10-22.
        let rpki = RpkiProvider::with_origin("AS3333", "193.0.0.0/21").unwrap();
        let rpki_feed = RawFeed {
            body: br#"{"messages":[],"version":"0.3","data_call_name":"rpki-validation","status":"ok","status_code":200,"data":{"resource":"3333","prefix":"193.0.0.0/21","validating_roas":[{"origin":"3333","prefix":"193.0.0.0/21","validity":"valid","max_length":21}],"status":"valid","validator":"routinator"}}"#
                .to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        };
        rpki.validate(&rpki_feed).unwrap();
        let batch = rpki.normalize(&rpki_feed).unwrap();
        assert_eq!(batch.rpki_records.len(), 1);
        assert_eq!(batch.rpki_records[0].status, RpkiStatus::Valid);
        assert_eq!(batch.rpki_records[0].prefix, "193.0.0.0/21");
        assert_eq!(batch.rpki_records[0].asn, "AS3333");
    }

    #[test]
    fn rpki_endpoint_carries_the_origin_as_resource_and_the_prefix_separately() {
        let provider = RpkiProvider::with_origin("3333", "193.0.0.0/21").unwrap();
        assert_eq!(
            provider.0.endpoint,
            "https://stat.ripe.net/data/rpki-validation/data.json?resource=AS3333&prefix=193.0.0.0%2F21"
        );
        assert!(RpkiProvider::with_origin("not-an-asn", "193.0.0.0/21").is_err());
        assert!(RpkiProvider::with_origin("AS3333", "not-a-prefix").is_err());
        // an invalid answer stays invalid, never coerced to valid
        let invalid = RawFeed {
            body: br#"{"data":{"resource":"64500","prefix":"198.51.100.0/24","validating_roas":[],"status":"invalid"}}"#.to_vec(),
            content_type: None,
            fetched_at: Utc::now(),
        };
        assert_eq!(
            provider.normalize(&invalid).unwrap().rpki_records[0].status,
            RpkiStatus::Invalid
        );
    }

    const CYMRU_ANSWER: &str = "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE - Google LLC, US\n";

    #[test]
    fn team_cymru_whois_answer_is_parsed_and_html_or_unannounced_rows_are_refused() {
        let provider = TeamCymruProvider::with_resource("8.8.8.8").unwrap();
        let feed = |body: &str| RawFeed {
            body: body.as_bytes().to_vec(),
            content_type: Some("text/plain".into()),
            fetched_at: Utc::now(),
        };
        provider.validate(&feed(CYMRU_ANSWER)).unwrap();
        let batch = provider.normalize(&feed(CYMRU_ANSWER)).unwrap();
        assert_eq!(batch.asn_records[0].asn, "AS15169");
        assert_eq!(batch.asn_records[0].prefixes, vec!["8.8.8.0/24"]);
        assert_eq!(batch.asn_records[0].registry, "arin");
        assert_eq!(batch.asn_records[0].country, "US");
        for bad in [
            "<html><body><form>ASN lookup</form></body></html>",
            "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\nNA | 10.0.0.1 | NA | NA | NA | NA | NA\n",
            "Error: no ASN or IP match on line 1.",
            "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n",
        ] {
            assert!(provider.validate(&feed(bad)).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn team_cymru_only_ever_queries_a_public_address() {
        for refused in [
            "10.0.0.1",
            "127.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "203.0.113.5",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "2001:db8::1",
            "AS3333",
            "8.8.8.0/24",
            "",
        ] {
            assert!(
                TeamCymruProvider::with_resource(refused).is_err(),
                "{refused}"
            );
        }
        assert!(TeamCymruProvider::with_resource("8.8.8.8").is_ok());
        assert!(TeamCymruProvider::with_resource("2001:4860:4860::8888").is_ok());
    }

    #[tokio::test]
    async fn team_cymru_fetch_speaks_the_whois_protocol_and_reports_connection_errors() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut query = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read_exact(&mut byte).await.is_ok() {
                query.push(byte[0]);
                if query.ends_with(b"\r\n") {
                    break;
                }
            }
            stream.write_all(CYMRU_ANSWER.as_bytes()).await.unwrap();
            query
        });
        let provider = TeamCymruProvider::with_resource("8.8.8.8")
            .unwrap()
            .with_server(&address);
        let feed = provider.fetch().await.unwrap();
        assert_eq!(server.await.unwrap(), b" -v 8.8.8.8\r\n");
        provider.validate(&feed).unwrap();
        // a closed port is a connection error, not a timeout and not a parse error
        let closed = TeamCymruProvider::with_resource("8.8.8.8")
            .unwrap()
            .with_server("127.0.0.1:1");
        assert!(matches!(
            closed.fetch().await,
            Err(ProviderError::Connection(_))
        ));
    }

    #[test]
    fn network_provider_rejects_empty_or_malformed_records() {
        let provider = RipeStatProvider::with_resource("AS3333").unwrap();
        let empty = RawFeed {
            body: br#"{"data":[]}"#.to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        };
        assert!(provider.validate(&empty).is_err());
        let malformed = RawFeed {
            body: b"not-json".to_vec(),
            ..empty
        };
        assert!(provider.validate(&malformed).is_err());
    }

    #[test]
    fn hackertarget_asn_parses_the_quoted_name_and_prefix_list() {
        let provider = HackerTargetProvider::with_resource("3333").unwrap();
        let feed = RawFeed {
            body: b"\"3333\",\"RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre RIPE NCC, NL\"\n2001:67c:2e8::/48\n193.0.20.0/23\n193.0.0.0/21\n".to_vec(),
            content_type: Some("text/plain".into()),
            fetched_at: Utc::now(),
        };
        provider.validate(&feed).unwrap();
        let batch = provider.normalize(&feed).unwrap();
        assert_eq!(batch.asn_records.len(), 1);
        let record = &batch.asn_records[0];
        assert_eq!(record.asn, "AS3333");
        assert_eq!(
            record.name,
            "RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre RIPE NCC"
        );
        assert_eq!(record.country, "NL");
        assert_eq!(
            record.prefixes,
            vec!["2001:67c:2e8::/48", "193.0.20.0/23", "193.0.0.0/21"]
        );
    }

    #[test]
    fn hackertarget_asn_rejects_an_unquoted_error_response() {
        // HackerTarget answers a bad ASN or its own rate limit with plain,
        // unquoted error text rather than an HTTP error status.
        let provider = HackerTargetProvider::with_resource("3333").unwrap();
        let feed = RawFeed {
            body: b"error check your search parameter".to_vec(),
            content_type: Some("text/plain".into()),
            fetched_at: Utc::now(),
        };
        assert!(provider.validate(&feed).is_err());
    }

    #[test]
    fn rate_limit_error_is_explicit_and_retryable() {
        let error = ProviderError::RateLimited {
            retry_after: " (retry-after 30)".into(),
        };
        assert!(error.to_string().contains("rate limited"));
    }
}
