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
    if let Ok(value) = env::var(variable) {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    let file_variable = format!("{variable}_FILE");
    let path =
        env::var(&file_variable).map_err(|_| ProviderError::Configuration(variable.to_string()))?;
    std::fs::read_to_string(&path)
        .map(|value| value.trim().to_string())
        .map_err(|error| {
            ProviderError::Configuration(format!("{variable}: cannot read secret file: {error}"))
        })
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
    CymruText,
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
        if matches!(self.format, NetworkFormat::CymruText) {
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
            NetworkFormat::CymruText => {
                normalize_cymru_text(&feed.body, &self.provider, feed.fetched_at)
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
            .any(|key| object.contains_key(*key))
                || (object.contains_key("resource")
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

fn normalize_cymru_text(
    body: &[u8],
    provider: &Provider,
    fetched_at: DateTime<Utc>,
) -> Result<NetworkBatch, ProviderError> {
    let text = std::str::from_utf8(body)
        .map_err(|error| ProviderError::Validation(format!("invalid Team Cymru text: {error}")))?;
    let mut records = Vec::new();
    for line in text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<&str> = line.split('|').map(str::trim).collect();
        if fields.len() < 2 {
            continue;
        }
        let Some(asn) = normalize_asn(fields[0]) else {
            continue;
        };
        records.push(AsnRecord {
            asn,
            name: fields
                .get(4)
                .copied()
                .unwrap_or(provider.name.as_str())
                .to_string(),
            organisation: fields.get(4).copied().unwrap_or_default().to_string(),
            provider: provider.id.clone(),
            country: fields.get(1).copied().unwrap_or_default().to_string(),
            registry: fields.get(2).copied().unwrap_or_default().to_string(),
            prefixes: Vec::new(),
            network_type: "unknown".to_string(),
            reputation: 0,
            first_seen: fetched_at,
            last_seen: fetched_at,
        });
    }
    records.dedup_by(|left, right| left.asn == right.asn);
    Ok(NetworkBatch {
        asn_records: records,
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
    BgpViewProvider,
    "bgpview_asn",
    "BGPView ASN",
    "BGPView",
    "https://api.bgpview.io/asn/{resource}",
    "CLAWFORGE_BGPVIEW_RESOURCE",
    "3333",
    3600,
    70,
    NetworkFormat::AsnJson
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
    TeamCymruProvider,
    "team_cymru",
    "Team Cymru",
    "Team Cymru",
    "https://asn.cymru.com/cgi-bin/asnlookup.pl?ip={resource}",
    "CLAWFORGE_TEAM_CYMRU_RESOURCE",
    "8.8.8.8",
    86400,
    65,
    NetworkFormat::CymruText
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
define_network_provider!(
    BgpStreamProvider,
    "bgpstream",
    "BGPStream",
    "BGPStream",
    "https://bgpstream.com/api/v2/events?resource={resource}",
    "CLAWFORGE_BGPSTREAM_RESOURCE",
    "203.0.113.0%2F24",
    900,
    70,
    NetworkFormat::BgpJson
);
define_network_provider!(
    RpkiProvider,
    "rpki_validator",
    "RPKI Validator",
    "RPKI",
    "https://stat.ripe.net/data/rpki-validation/data.json?resource={resource}&prefix={resource}",
    "CLAWFORGE_RPKI_RESOURCE",
    "203.0.113.0%2F24",
    3600,
    90,
    NetworkFormat::RpkiJson
);

pub fn network_providers() -> Result<Vec<Box<dyn NetworkProvider>>, ProviderError> {
    Ok(vec![
        Box::new(RipeStatProvider::new()?),
        Box::new(BgpViewProvider::new()?),
        Box::new(PeeringDbProvider::new()?),
        Box::new(CaidaProvider::new()?),
        Box::new(TeamCymruProvider::new()?),
        Box::new(RipeRisProvider::new()?),
        Box::new(RouteViewsProvider::new()?),
        Box::new(BgpStreamProvider::new()?),
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

        let rpki = RpkiProvider::with_resource("198.51.100.0%2F24").unwrap();
        let rpki_feed = RawFeed {
            body: br#"{"data":{"prefix":"198.51.100.0/24","asn":"AS64500","status":"invalid"}}"#
                .to_vec(),
            content_type: Some("application/json".into()),
            fetched_at: Utc::now(),
        };
        rpki.validate(&rpki_feed).unwrap();
        let batch = rpki.normalize(&rpki_feed).unwrap();
        assert_eq!(batch.rpki_records[0].status, RpkiStatus::Invalid);
    }

    #[test]
    fn network_provider_rejects_empty_or_malformed_records() {
        let provider = BgpViewProvider::with_resource("3333").unwrap();
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
    fn rate_limit_error_is_explicit_and_retryable() {
        let error = ProviderError::RateLimited {
            retry_after: " (retry-after 30)".into(),
        };
        assert!(error.to_string().contains("rate limited"));
    }
}
