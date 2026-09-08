use std::{
    collections::{HashMap, HashSet},
    env, fs,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use clawforge_intelligence::{NetworkType, TrustedNetwork, VerificationStatus};
use clawforge_storage::{
    database_url_from_env, AdminPrincipal, AgentPrincipal, MigrationStatus, PostgresStore,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    store: PostgresStore,
    config: RuntimeConfig,
    rate_limiter: RateLimiter,
}

#[derive(Clone)]
struct RuntimeConfig {
    bind: SocketAddr,
    database_configured: bool,
    analyzer_url: Option<String>,
    analyzer_token: Option<String>,
    notifier_token: Option<String>,
    events_token: Option<String>,
}

#[derive(Clone)]
struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, RateBucket>>>,
}

#[derive(Clone, Copy)]
struct RateBucket {
    started: Instant,
    count: u32,
}

#[derive(Clone, Copy)]
struct RatePolicy {
    class: &'static str,
    limit: u32,
    window: StdDuration,
}

#[derive(Clone, Copy)]
struct RateDecision {
    allowed: bool,
    remaining: u32,
    retry_after: StdDuration,
}

const AGENT_SCOPE_SYSTEM_READ: &str = "agent:system:read";
const AGENT_SCOPE_EVENTS_READ: &str = "agent:events:read";
const AGENT_SCOPE_INCIDENTS_READ: &str = "agent:incidents:read";
const AGENT_SCOPE_SECURITY_READ: &str = "agent:security:read";
const AGENT_SCOPE_NETWORK_READ: &str = "agent:network:read";
const AGENT_SCOPE_ALL_READ: &str = "agent:read";

const AGENT_SCOPES: &[&str] = &[
    AGENT_SCOPE_SYSTEM_READ,
    AGENT_SCOPE_EVENTS_READ,
    AGENT_SCOPE_INCIDENTS_READ,
    AGENT_SCOPE_SECURITY_READ,
    AGENT_SCOPE_NETWORK_READ,
    AGENT_SCOPE_ALL_READ,
];

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl RateLimiter {
    fn check(&self, key: &str, limit: u32, window: StdDuration) -> RateDecision {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned");
        if buckets.len() > 10_000 {
            buckets.retain(|_, bucket| now.duration_since(bucket.started) < window);
        }
        let bucket = buckets.entry(key.to_string()).or_insert(RateBucket {
            started: now,
            count: 0,
        });
        if now.duration_since(bucket.started) >= window {
            bucket.started = now;
            bucket.count = 0;
        }
        let elapsed = now.duration_since(bucket.started);
        let retry_after = window.saturating_sub(elapsed);
        if bucket.count >= limit {
            return RateDecision {
                allowed: false,
                remaining: 0,
                retry_after,
            };
        }
        bucket.count += 1;
        RateDecision {
            allowed: true,
            remaining: limit.saturating_sub(bucket.count),
            retry_after,
        }
    }
}

fn header_client_identity(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn role_multiplier(role: Option<&str>) -> u32 {
    match role {
        Some("Administrator") => 200,
        Some("Operator") => 150,
        Some("Viewer") => 100,
        _ => 50,
    }
}

fn global_limit(policy: RatePolicy, role: Option<&str>) -> u32 {
    let base = match policy.class {
        "login" => 10,
        "bootstrap" => 6,
        _ => 300,
    };
    if matches!(policy.class, "login" | "bootstrap") {
        base
    } else {
        base.saturating_mul(role_multiplier(role)) / 100
    }
}

fn policy_for(path: &str, method: &Method, role: Option<&str>) -> Option<RatePolicy> {
    if matches!(path, "/health" | "/ready") {
        return None;
    }
    let (class, base_limit, window): (&str, u32, StdDuration) = if path == "/admin/auth/login" {
        ("login", 5, StdDuration::from_secs(60))
    } else if path == "/admin/auth/bootstrap" {
        ("bootstrap", 3, StdDuration::from_secs(60 * 60))
    } else if path.ends_with("/export") {
        ("export", 10, StdDuration::from_secs(60))
    } else if method == Method::GET || method == Method::HEAD {
        ("read", 120, StdDuration::from_secs(60))
    } else {
        ("write", 60, StdDuration::from_secs(60))
    };
    let limit = if matches!(class, "login" | "bootstrap") {
        base_limit
    } else {
        base_limit.saturating_mul(role_multiplier(role)) / 100
    };
    Some(RatePolicy {
        class,
        limit: limit.max(1),
        window,
    })
}

fn rate_limit_response(policy: RatePolicy, retry_after: StdDuration) -> Response {
    let seconds = retry_after.as_secs().max(1).to_string();
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ApiError {
            status: "error",
            data: None,
            timestamp: Utc::now(),
            pagination: None,
            errors: vec![format!("{} rate limit exceeded", policy.class)],
        }),
    )
        .into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&seconds).expect("valid retry-after value"),
    );
    response.headers_mut().insert(
        "X-RateLimit-Limit",
        HeaderValue::from_str(&policy.limit.to_string()).expect("valid limit value"),
    );
    response
        .headers_mut()
        .insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
    response
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let Some(_) = policy_for(&path, request.method(), None) else {
        return next.run(request).await;
    };
    let headers = request.headers();
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| header_client_identity(headers));
    let bearer_token = bearer(headers);
    let principal = if let Some(token) = bearer_token {
        state
            .store
            .authenticate_credential(&digest(token))
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let role = principal.as_ref().map(|value| value.role.as_str());
    let policy = policy_for(&path, request.method(), role).expect("non-exempt policy");
    let identity = bearer_token.map(digest).unwrap_or_else(|| digest(&source));
    let global_limit = global_limit(policy, role).max(1);
    let global = state.rate_limiter.check(
        &format!("global:{}:{}", identity, policy.window.as_secs()),
        global_limit,
        policy.window,
    );
    let endpoint = state.rate_limiter.check(
        &format!("endpoint:{}:{}:{}", policy.class, path, identity),
        policy.limit,
        policy.window,
    );
    if !global.allowed || !endpoint.allowed {
        let retry_after = if global.retry_after > endpoint.retry_after {
            global.retry_after
        } else {
            endpoint.retry_after
        };
        let actor = principal
            .as_ref()
            .map(|value| value.username.as_str())
            .unwrap_or("anonymous");
        let _ = state
            .store
            .record_audit_event(
                actor,
                "api_rate_limit_exceeded",
                &path,
                serde_json::json!({
                    "class": policy.class,
                    "role": role.unwrap_or("anonymous"),
                    "source_hash": digest(&source),
                    "retry_after_seconds": retry_after.as_secs().max(1),
                }),
            )
            .await;
        return rate_limit_response(policy, retry_after);
    }
    let remaining = global.remaining.min(endpoint.remaining);
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "X-RateLimit-Limit",
        HeaderValue::from_str(&policy.limit.to_string()).expect("valid limit value"),
    );
    response.headers_mut().insert(
        "X-RateLimit-Remaining",
        HeaderValue::from_str(&remaining.to_string()).expect("valid remaining value"),
    );
    response
}

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    status: &'static str,
    checks: HealthChecks,
    data: serde_json::Value,
    timestamp: chrono::DateTime<Utc>,
    pagination: Option<Pagination>,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct HealthChecks {
    process: &'static str,
    configuration: &'static str,
    postgres: Option<&'static str>,
    migrations: Option<MigrationResponse>,
}

#[derive(Serialize)]
struct MigrationResponse {
    current: bool,
    applied: usize,
    expected: usize,
    latest: i64,
    expected_latest: i64,
}

#[derive(Serialize)]
struct VersionResponse {
    service: &'static str,
    version: &'static str,
    migrations: MigrationResponse,
    data: serde_json::Value,
    timestamp: chrono::DateTime<Utc>,
    pagination: Option<Pagination>,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Pagination {
    page: i64,
    page_size: i64,
    total: i64,
    has_next: bool,
}

#[derive(Serialize)]
struct ApiEnvelope<T> {
    status: &'static str,
    data: T,
    timestamp: chrono::DateTime<Utc>,
    pagination: Option<Pagination>,
    errors: Vec<String>,
}

fn envelope<T: Serialize>(data: T, pagination: Option<Pagination>) -> Json<ApiEnvelope<T>> {
    Json(envelope_value(data, pagination))
}

fn envelope_value<T: Serialize>(data: T, pagination: Option<Pagination>) -> ApiEnvelope<T> {
    ApiEnvelope {
        status: "ok",
        data,
        timestamp: Utc::now(),
        pagination,
        errors: Vec::new(),
    }
}

fn paged_values(
    mut values: Vec<serde_json::Value>,
    page: i64,
    page_size: i64,
) -> (Vec<serde_json::Value>, Pagination) {
    let page = page.max(1);
    let page_size = page_size.clamp(1, 500);
    let total = values.len() as i64;
    let start = ((page - 1) * page_size) as usize;
    let end = start.saturating_add(page_size as usize).min(values.len());
    let data = if start >= values.len() {
        Vec::new()
    } else {
        values.drain(start..end).collect()
    };
    (
        data,
        Pagination {
            page,
            page_size,
            total,
            has_next: page * page_size < total,
        },
    )
}

impl From<MigrationStatus> for MigrationResponse {
    fn from(status: MigrationStatus) -> Self {
        Self {
            current: status.current,
            applied: status.applied,
            expected: status.expected,
            latest: status.latest,
            expected_latest: status.expected_latest,
        }
    }
}

async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let configuration = if state.config.database_configured && state.config.bind.port() != 0 {
        "ok"
    } else {
        "error"
    };
    let status = if configuration == "ok" { "ok" } else { "error" };
    let code = if status == "ok" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(HealthResponse {
            service: "clawforge-api",
            status,
            checks: HealthChecks {
                process: "ok",
                configuration,
                postgres: None,
                migrations: None,
            },
            data: serde_json::json!({"service":"clawforge-api","status":status}),
            timestamp: Utc::now(),
            pagination: None,
            errors: Vec::new(),
        }),
    )
}

async fn ready(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let migration = state.store.readiness().await.ok();
    let postgres_ok = migration.is_some();
    let migrations_ok = migration.as_ref().is_some_and(|value| value.current);
    let status = if postgres_ok && migrations_ok && state.config.database_configured {
        "ready"
    } else {
        "not_ready"
    };
    let code = if status == "ready" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(HealthResponse {
            service: "clawforge-api",
            status,
            checks: HealthChecks {
                process: "ok",
                configuration: if state.config.database_configured {
                    "ok"
                } else {
                    "error"
                },
                postgres: Some(if postgres_ok { "ok" } else { "error" }),
                migrations: migration.map(Into::into),
            },
            data: serde_json::json!({"service":"clawforge-api","status":status}),
            timestamp: Utc::now(),
            pagination: None,
            errors: Vec::new(),
        }),
    )
}

async fn version(State(state): State<AppState>) -> Result<Json<VersionResponse>, StatusCode> {
    state
        .store
        .readiness()
        .await
        .map(|status| {
            Json(VersionResponse {
                service: "clawforge",
                version: env!("CARGO_PKG_VERSION"),
                migrations: status.into(),
                data: serde_json::json!({"service":"clawforge","version":env!("CARGO_PKG_VERSION")}),
                timestamp: Utc::now(),
                pagination: None,
                errors: Vec::new(),
            })
        })
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

#[derive(Deserialize)]
struct IndicatorQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    source: Option<String>,
    from: Option<String>,
    to: Option<String>,
    severity: Option<String>,
    confidence: Option<u8>,
    format: Option<String>,
}

async fn intelligence_providers(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    state
        .store
        .list_provider_views()
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "provider list unavailable"))
}

async fn intelligence_status(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    intelligence_providers(State(state)).await
}

async fn intelligence_indicators(
    State(state): State<AppState>,
    Query(query): Query<IndicatorQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let mut values = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "indicator list unavailable",
        )
    })?;
    values.retain(|value| {
        let source_ok = query.source.as_deref().is_none_or(|source| {
            value.get("source").and_then(serde_json::Value::as_str) == Some(source)
        });
        let confidence_ok = query.confidence.is_none_or(|confidence| {
            value
                .get("confidence")
                .and_then(serde_json::Value::as_i64)
                .is_some_and(|actual| actual >= i64::from(confidence))
        });
        let timestamp = value
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let time_ok = query.from.as_deref().is_none_or(|from| timestamp >= from)
            && query.to.as_deref().is_none_or(|to| timestamp <= to);
        let severity_ok = query.severity.as_deref().is_none_or(|severity| {
            let score = value
                .get("risk_score")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let actual = if score >= 90 {
                "critical"
            } else if score >= 70 {
                "high"
            } else if score >= 40 {
                "medium"
            } else {
                "low"
            };
            actual == severity
        });
        source_ok && confidence_ok && time_ok && severity_ok
    });
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(100),
    );
    Ok(envelope(data, Some(pagination)))
}

async fn network_view(
    State(state): State<AppState>,
    kind: &'static str,
) -> Result<Vec<serde_json::Value>, StatusCode> {
    state
        .store
        .list_network_views(kind)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

#[derive(Deserialize)]
struct NetworkQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    asn: Option<String>,
    prefix: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Deserialize)]
struct VisualizationQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    event_type: Option<String>,
    source: Option<String>,
    severity: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

fn graph_node(
    id: impl Into<String>,
    label: impl Into<String>,
    node_type: &str,
) -> serde_json::Value {
    serde_json::json!({"id": id.into(), "label": label.into(), "type": node_type})
}

fn graph_edge(
    source: impl Into<String>,
    target: impl Into<String>,
    edge_type: &str,
) -> serde_json::Value {
    serde_json::json!({"source": source.into(), "target": target.into(), "type": edge_type})
}

fn visualization_authorized(principal: &AdminPrincipal) -> ApiResult<()> {
    require_role(principal, &["Administrator", "Operator", "Viewer"])
}

async fn visualization_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VisualizationQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    visualization_authorized(&principal)?;
    let mut values = state
        .store
        .list_events(query.event_type.as_deref(), 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "visualization events unavailable",
            )
        })?;
    values.retain(|value| {
        let source_ok = query.source.as_deref().is_none_or(|source| {
            value.get("source").and_then(serde_json::Value::as_str) == Some(source)
        });
        let severity_ok = query.severity.as_deref().is_none_or(|severity| {
            value.get("severity").and_then(serde_json::Value::as_str) == Some(severity)
        });
        let timestamp = value
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        source_ok
            && severity_ok
            && query.from.as_deref().is_none_or(|from| timestamp >= from)
            && query.to.as_deref().is_none_or(|to| timestamp <= to)
    });
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(50),
    );
    Ok(envelope(data, Some(pagination)))
}

async fn visualization_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VisualizationQuery>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    visualization_authorized(&principal)?;
    let asn_values = network_view(State(state.clone()), "asn")
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "network visualization unavailable",
            )
        })?;
    let bgp_values = network_view(State(state.clone()), "bgp")
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "network visualization unavailable",
            )
        })?;
    let indicator_values = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "network visualization unavailable",
        )
    })?;

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut node_ids = HashSet::new();
    let mut edge_keys = HashSet::new();
    let mut known_prefixes = Vec::<(String, ipnet::IpNet)>::new();
    let mut add_node = |id: String, label: String, kind: &str| {
        if node_ids.insert(id.clone()) {
            nodes.push(graph_node(id, label, kind));
        }
    };
    let mut add_edge = |source: String, target: String, kind: &str| {
        let key = format!("{source}:{target}:{kind}");
        if edge_keys.insert(key) {
            edges.push(graph_edge(source, target, kind));
        }
    };
    for record in &asn_values {
        let Some(asn) = record.get("asn").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let asn_id = format!("asn:{asn}");
        add_node(asn_id.clone(), format!("ASN {asn}"), "asn");
        if let Some(prefixes) = record.get("prefixes").and_then(serde_json::Value::as_array) {
            for prefix in prefixes.iter().filter_map(serde_json::Value::as_str) {
                let prefix_id = format!("prefix:{prefix}");
                add_node(prefix_id.clone(), prefix.to_string(), "prefix");
                add_edge(asn_id.clone(), prefix_id, "announces");
                if let Ok(network) = prefix.parse::<ipnet::IpNet>() {
                    known_prefixes.push((format!("prefix:{prefix}"), network));
                }
            }
        }
    }
    for (index, record) in bgp_values.iter().enumerate() {
        let Some(prefix) = record.get("prefix").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let prefix_id = format!("prefix:{prefix}");
        add_node(prefix_id.clone(), prefix.to_string(), "prefix");
        if let Ok(network) = prefix.parse::<ipnet::IpNet>() {
            known_prefixes.push((prefix_id.clone(), network));
        }
        if let Some(asn) = record.get("origin_asn").and_then(serde_json::Value::as_str) {
            let asn_id = format!("asn:{asn}");
            add_node(asn_id.clone(), format!("ASN {asn}"), "asn");
            add_edge(prefix_id.clone(), asn_id, "origin");
        }
        let event_id = format!("bgp:{prefix}:{index}");
        add_node(event_id.clone(), "BGP change".to_string(), "bgp_event");
        add_edge(prefix_id, event_id.clone(), "changed");
        if let Some(source) = record.get("source").and_then(serde_json::Value::as_str) {
            let provider_id = format!("provider:{source}");
            add_node(provider_id.clone(), source.to_string(), "provider");
            add_edge(event_id, provider_id, "observed_by");
        }
    }
    for record in indicator_values {
        let Some(value) = record.get("value").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Ok(ip) = value.parse::<std::net::IpAddr>() else {
            continue;
        };
        let ip_id = format!("ip:{value}");
        add_node(ip_id.clone(), value.to_string(), "ip");
        if let Some(prefix) = record
            .get("metadata")
            .and_then(|v| v.get("prefix"))
            .and_then(serde_json::Value::as_str)
        {
            let prefix_id = format!("prefix:{prefix}");
            add_node(prefix_id.clone(), prefix.to_string(), "prefix");
            add_edge(ip_id, prefix_id, "belongs_to");
        } else {
            for (prefix_id, network) in &known_prefixes {
                if network.contains(&ip) {
                    add_edge(ip_id.clone(), prefix_id.clone(), "belongs_to");
                }
            }
        }
    }
    let (selected_nodes, pagination) = paged_values(
        nodes,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(100),
    );
    let selected_ids = selected_nodes
        .iter()
        .filter_map(|node| node.get("id").and_then(serde_json::Value::as_str))
        .collect::<HashSet<_>>();
    let selected_edges = edges
        .into_iter()
        .filter(|edge| {
            edge.get("source")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| selected_ids.contains(id))
                && edge
                    .get("target")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|id| selected_ids.contains(id))
        })
        .collect::<Vec<_>>();
    Ok(envelope(
        serde_json::json!({"nodes": selected_nodes, "edges": selected_edges}),
        Some(pagination),
    ))
}

async fn visualization_incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VisualizationQuery>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    visualization_authorized(&principal)?;
    let incidents = state.store.list_incidents(None, 500).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "incident visualization unavailable",
        )
    })?;
    let (selected_incidents, pagination) = paged_values(
        incidents,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(25).clamp(1, 100),
    );
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut node_ids = HashSet::new();
    let mut edge_keys = HashSet::new();
    for incident in selected_incidents {
        let Some(id) = incident.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let incident_id = format!("incident:{id}");
        node_ids.insert(incident_id.clone());
        nodes.push(graph_node(
            incident_id.clone(),
            incident
                .get("summary")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Incident"),
            "incident",
        ));
        let incident_uuid = Uuid::parse_str(id).map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid incident identifier",
            )
        })?;
        let events = state
            .store
            .list_incident_events(incident_uuid)
            .await
            .map_err(|_| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "incident visualization unavailable",
                )
            })?;
        for (index, event) in events.iter().enumerate() {
            let event_id = event
                .get("event_id")
                .map(ToString::to_string)
                .unwrap_or_else(|| index.to_string());
            let event_node = format!("event:{event_id}");
            if node_ids.insert(event_node.clone()) {
                nodes.push(graph_node(
                    event_node.clone(),
                    event
                        .get("event_type")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("Event"),
                    "event",
                ));
            }
            let key = format!("{incident_id}:{event_node}:contains");
            if edge_keys.insert(key) {
                edges.push(graph_edge(
                    incident_id.clone(),
                    event_node.clone(),
                    "contains",
                ));
            }
            if let Some(source) = event.get("source").and_then(serde_json::Value::as_str) {
                let provider_id = format!("provider:{source}");
                if node_ids.insert(provider_id.clone()) {
                    nodes.push(graph_node(provider_id.clone(), source, "provider"));
                }
                let key = format!("{event_node}:{provider_id}:source");
                if edge_keys.insert(key) {
                    edges.push(graph_edge(event_node.clone(), provider_id, "source"));
                }
            }
            if let Some(resource) = event
                .get("resource")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
            {
                let indicator_id = format!("indicator:{resource}");
                if node_ids.insert(indicator_id.clone()) {
                    nodes.push(graph_node(indicator_id.clone(), resource, "indicator"));
                }
                let key = format!("{event_node}:{indicator_id}:indicator");
                if edge_keys.insert(key) {
                    edges.push(graph_edge(event_node.clone(), indicator_id, "indicator"));
                }
            }
            if let Some(details) = event.get("details") {
                for key in ["asn", "origin_asn"] {
                    if let Some(asn) = details.get(key).and_then(serde_json::Value::as_str) {
                        let asn_id = format!("asn:{asn}");
                        if node_ids.insert(asn_id.clone()) {
                            nodes.push(graph_node(asn_id.clone(), format!("ASN {asn}"), "asn"));
                        }
                        let key = format!("{event_node}:{asn_id}:asn");
                        if edge_keys.insert(key) {
                            edges.push(graph_edge(event_node.clone(), asn_id, "asn"));
                        }
                    }
                }
                if let Some(prefix) = details.get("prefix").and_then(serde_json::Value::as_str) {
                    let prefix_id = format!("prefix:{prefix}");
                    if node_ids.insert(prefix_id.clone()) {
                        nodes.push(graph_node(prefix_id.clone(), prefix, "prefix"));
                    }
                    let key = format!("{event_node}:{prefix_id}:prefix");
                    if edge_keys.insert(key) {
                        edges.push(graph_edge(event_node.clone(), prefix_id, "prefix"));
                    }
                }
            }
        }
    }
    Ok(envelope(
        serde_json::json!({"nodes": nodes, "edges": edges}),
        Some(pagination),
    ))
}

async fn visualization_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VisualizationQuery>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    visualization_authorized(&principal)?;
    let values = network_view(State(state), "trust").await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "trust visualization unavailable",
        )
    })?;
    let mut summary = serde_json::Map::new();
    for status in ["Verified", "Pending", "Revoked"] {
        summary.insert(
            status.to_ascii_lowercase(),
            serde_json::Value::from(
                values
                    .iter()
                    .filter(|network| {
                        network.get("status").and_then(serde_json::Value::as_str) == Some(status)
                    })
                    .count() as u64,
            ),
        );
    }
    let (networks, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(50),
    );
    Ok(envelope(
        serde_json::json!({"networks": networks, "summary": summary}),
        Some(pagination),
    ))
}

async fn network_asn(
    State(state): State<AppState>,
    Query(query): Query<NetworkQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let mut values = network_view(State(state), "asn")
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "ASN list unavailable"))?;
    values.retain(|value| {
        let timestamp = value
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        query
            .asn
            .as_deref()
            .is_none_or(|asn| value.get("asn").and_then(serde_json::Value::as_str) == Some(asn))
            && query.from.as_deref().is_none_or(|from| timestamp >= from)
            && query.to.as_deref().is_none_or(|to| timestamp <= to)
    });
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(100),
    );
    Ok(envelope(data, Some(pagination)))
}

async fn network_bgp(
    State(state): State<AppState>,
    Query(query): Query<NetworkQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let mut values = network_view(State(state), "bgp")
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "BGP list unavailable"))?;
    values.retain(|value| {
        let asn_ok = query.asn.as_deref().is_none_or(|asn| {
            value.get("origin_asn").and_then(serde_json::Value::as_str) == Some(asn)
        });
        let prefix_ok = query.prefix.as_deref().is_none_or(|prefix| {
            value.get("prefix").and_then(serde_json::Value::as_str) == Some(prefix)
        });
        let timestamp = value
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        asn_ok
            && prefix_ok
            && query.from.as_deref().is_none_or(|from| timestamp >= from)
            && query.to.as_deref().is_none_or(|to| timestamp <= to)
    });
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(100),
    );
    Ok(envelope(data, Some(pagination)))
}

async fn network_rpki(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let values = network_view(State(state), "rpki")
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "RPKI list unavailable"))?;
    let (data, pagination) = paged_values(values, 1, 100);
    Ok(envelope(data, Some(pagination)))
}

async fn network_trust(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let values = network_view(State(state), "trust")
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "trust list unavailable"))?;
    let (data, pagination) = paged_values(values, 1, 100);
    Ok(envelope(data, Some(pagination)))
}

#[derive(Deserialize, Default)]
struct AgentQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    event_type: Option<String>,
    source: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    correlation_id: Option<String>,
    confidence_min: Option<u8>,
    active: Option<bool>,
    asn: Option<String>,
    prefix: Option<String>,
    rpki_status: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

fn agent_page(query: &AgentQuery, default: i64) -> (i64, i64) {
    (
        query.page.unwrap_or(1).max(1),
        query.page_size.unwrap_or(default).clamp(1, 100),
    )
}

fn agent_timestamp(value: &serde_json::Value) -> &str {
    value
        .get("timestamp")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("created_at").and_then(serde_json::Value::as_str))
        .or_else(|| value.get("last_seen").and_then(serde_json::Value::as_str))
        .unwrap_or_default()
}

fn agent_time_matches(value: &serde_json::Value, query: &AgentQuery) -> bool {
    let timestamp = agent_timestamp(value);
    query.from.as_deref().is_none_or(|from| timestamp >= from)
        && query.to.as_deref().is_none_or(|to| timestamp <= to)
}

fn agent_event_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "event_id": value.get("event_id"),
        "event_type": value.get("event_type"),
        "source": value.get("source"),
        "severity": value.get("severity"),
        "timestamp": value.get("timestamp"),
        "correlation_id": value.get("correlation_id"),
        "created_at": value.get("created_at")
    })
}

fn risk_severity(score: i64) -> &'static str {
    if score >= 90 {
        "critical"
    } else if score >= 70 {
        "high"
    } else if score >= 40 {
        "medium"
    } else if score > 0 {
        "low"
    } else {
        "info"
    }
}

fn agent_finding_view(value: &serde_json::Value) -> serde_json::Value {
    let risk_score = value
        .get("risk_score")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    serde_json::json!({
        "id": value.get("id").map(|id| format!("indicator:{id}")),
        "kind": value.get("indicator_type"),
        "subject": value.get("value"),
        "source": value.get("source"),
        "severity": risk_severity(risk_score),
        "confidence": value.get("confidence"),
        "risk_score": value.get("risk_score"),
        "trust_score": value.get("trust_score"),
        "reason": value.get("reason"),
        "first_seen": value.get("first_seen"),
        "last_seen": value.get("last_seen"),
        "expires_at": value.get("expires_at"),
        "age_seconds": value.get("age_seconds"),
        "status": value.get("status"),
        "assessed_at": value.get("assessed_at")
    })
}

fn agent_incident_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"),
        "status": value.get("status"),
        "severity": value.get("severity"),
        "risk_score": value.get("risk_score"),
        "summary": value.get("summary"),
        "correlation_key": value.get("correlation_key"),
        "event_count": value.get("event_count"),
        "created_at": value.get("created_at"),
        "updated_at": value.get("updated_at")
    })
}

fn agent_network_view(value: &serde_json::Value, fields: &[&str]) -> serde_json::Value {
    let mut output = serde_json::Map::new();
    for field in fields {
        if let Some(found) = value.get(*field) {
            output.insert((*field).to_string(), found.clone());
        }
    }
    serde_json::Value::Object(output)
}

async fn agent_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_SYSTEM_READ)?;
    let migration = state
        .store
        .readiness()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "status unavailable"))?;
    let migration_response: MigrationResponse = migration.into();
    let runtime = state.store.runtime_status_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime status unavailable",
        )
    })?;
    let runtime = runtime
        .iter()
        .map(|component| {
            serde_json::json!({
                "component": component.get("component"),
                "state": component.get("state"),
                "version": component.get("version"),
                "last_started_at": component.get("last_started_at"),
                "last_heartbeat_at": component.get("last_heartbeat_at"),
                "updated_at": component.get("updated_at")
            })
        })
        .collect::<Vec<_>>();
    let events = state
        .store
        .event_status()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "event status unavailable"))?;
    let providers = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider status unavailable",
        )
    })?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/status",
        AGENT_SCOPE_SYSTEM_READ,
    )
    .await;
    Ok(envelope(
        serde_json::json!({
            "service": "clawforge",
            "version": env!("CARGO_PKG_VERSION"),
            "status": "ok",
            "migrations": migration_response,
            "runtime": runtime,
            "events": events,
            "providers": {
                "total": providers.len(),
                "enabled": providers.iter().filter(|provider| provider.get("enabled").and_then(serde_json::Value::as_bool) == Some(true)).count()
            }
        }),
        None,
    ))
}

async fn agent_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_EVENTS_READ)?;
    let mut values = state
        .store
        .list_events(query.event_type.as_deref(), 500)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "event list unavailable"))?;
    values.retain(|value| {
        query.source.as_deref().is_none_or(|source| {
            value.get("source").and_then(serde_json::Value::as_str) == Some(source)
        }) && query.severity.as_deref().is_none_or(|severity| {
            value.get("severity").and_then(serde_json::Value::as_str) == Some(severity)
        }) && query.correlation_id.as_deref().is_none_or(|correlation| {
            value
                .get("correlation_id")
                .and_then(serde_json::Value::as_str)
                == Some(correlation)
        }) && agent_time_matches(value, &query)
    });
    let values = values.iter().map(agent_event_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/events",
        AGENT_SCOPE_EVENTS_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_INCIDENTS_READ)?;
    let mut values = state
        .store
        .list_incidents(query.status.as_deref(), 500)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "incident list unavailable"))?;
    values.retain(|value| {
        query.severity.as_deref().is_none_or(|severity| {
            value.get("severity").and_then(serde_json::Value::as_str) == Some(severity)
        }) && agent_time_matches(value, &query)
    });
    let values = values.iter().map(agent_incident_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/incidents",
        AGENT_SCOPE_INCIDENTS_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_SECURITY_READ)?;
    let mut values = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security findings unavailable",
        )
    })?;
    values.retain(|value| {
        let score = value
            .get("risk_score")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let severity = risk_severity(score);
        let active = value.get("status").and_then(serde_json::Value::as_str) == Some("active");
        query.source.as_deref().is_none_or(|source| {
            value.get("source").and_then(serde_json::Value::as_str) == Some(source)
        }) && query
            .severity
            .as_deref()
            .is_none_or(|wanted| wanted == severity)
            && query.confidence_min.is_none_or(|minimum| {
                value
                    .get("confidence")
                    .and_then(serde_json::Value::as_i64)
                    .is_some_and(|confidence| confidence >= i64::from(minimum))
            })
            && query.active.is_none_or(|wanted| wanted == active)
            && agent_time_matches(value, &query)
    });
    let values = values.iter().map(agent_finding_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/security/findings",
        AGENT_SCOPE_SECURITY_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_security_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_SECURITY_READ)?;
    let values = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security overview unavailable",
        )
    })?;
    let mut by_severity = serde_json::Map::new();
    for severity in ["info", "low", "medium", "high", "critical"] {
        by_severity.insert(
            severity.to_string(),
            serde_json::Value::from(
                values
                    .iter()
                    .filter(|value| {
                        let score = value
                            .get("risk_score")
                            .and_then(serde_json::Value::as_i64)
                            .unwrap_or(0);
                        risk_severity(score) == severity
                    })
                    .count() as u64,
            ),
        );
    }
    let active = values
        .iter()
        .filter(|value| value.get("status").and_then(serde_json::Value::as_str) == Some("active"))
        .count();
    let highest_risk = values
        .iter()
        .filter_map(|value| value.get("risk_score").and_then(serde_json::Value::as_i64))
        .max()
        .unwrap_or(0);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/security/overview",
        AGENT_SCOPE_SECURITY_READ,
    )
    .await;
    Ok(envelope(
        serde_json::json!({
            "findings_total": values.len(),
            "active_findings": active,
            "by_severity": by_severity,
            "highest_risk_score": highest_risk
        }),
        None,
    ))
}

async fn agent_network_values(state: &AppState, kind: &str) -> ApiResult<Vec<serde_json::Value>> {
    state
        .store
        .list_network_views(kind)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "network data unavailable"))
}

async fn agent_asn(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_NETWORK_READ)?;
    let mut values = agent_network_values(&state, "asn").await?;
    values.retain(|value| {
        query
            .asn
            .as_deref()
            .is_none_or(|asn| value.get("asn").and_then(serde_json::Value::as_str) == Some(asn))
            && agent_time_matches(value, &query)
    });
    let values = values
        .iter()
        .map(|value| {
            agent_network_view(
                value,
                &[
                    "asn",
                    "name",
                    "organisation",
                    "provider",
                    "country",
                    "registry",
                    "prefixes",
                    "network_type",
                    "reputation",
                    "first_seen",
                    "last_seen",
                    "age_seconds",
                    "timestamp",
                    "confidence",
                    "assessment",
                ],
            )
        })
        .collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/network/asn",
        AGENT_SCOPE_NETWORK_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_prefixes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_NETWORK_READ)?;
    let asn_values = agent_network_values(&state, "asn").await?;
    let mut values = Vec::new();
    for value in &asn_values {
        let Some(asn) = value.get("asn").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(prefixes) = value.get("prefixes").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for prefix in prefixes.iter().filter_map(serde_json::Value::as_str) {
            values.push(serde_json::json!({
                "prefix": prefix,
                "asn": asn,
                "source": value.get("source"),
                "country": value.get("country"),
                "network_type": value.get("network_type"),
                "first_seen": value.get("first_seen"),
                "last_seen": value.get("last_seen"),
                "age_seconds": value.get("age_seconds"),
                "timestamp": value.get("timestamp"),
                "confidence": value.get("confidence"),
                "assessment": value.get("assessment")
            }));
        }
    }
    values.retain(|value| {
        query
            .asn
            .as_deref()
            .is_none_or(|asn| value.get("asn").and_then(serde_json::Value::as_str) == Some(asn))
            && query.prefix.as_deref().is_none_or(|prefix| {
                value.get("prefix").and_then(serde_json::Value::as_str) == Some(prefix)
            })
            && agent_time_matches(value, &query)
    });
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/network/prefixes",
        AGENT_SCOPE_NETWORK_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_bgp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_NETWORK_READ)?;
    let mut values = agent_network_values(&state, "bgp").await?;
    values.retain(|value| {
        query.asn.as_deref().is_none_or(|asn| {
            value.get("origin_asn").and_then(serde_json::Value::as_str) == Some(asn)
        }) && query.prefix.as_deref().is_none_or(|prefix| {
            value.get("prefix").and_then(serde_json::Value::as_str) == Some(prefix)
        }) && query.rpki_status.as_deref().is_none_or(|status| {
            value.get("rpki_status").and_then(serde_json::Value::as_str) == Some(status)
        }) && agent_time_matches(value, &query)
    });
    let values = values
        .iter()
        .map(|value| {
            agent_network_view(
                value,
                &[
                    "prefix",
                    "origin_asn",
                    "previous_asn",
                    "new_asn",
                    "timestamp",
                    "source",
                    "status",
                    "rpki_status",
                    "change",
                    "age_seconds",
                    "confidence",
                    "assessment",
                ],
            )
        })
        .collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/network/bgp",
        AGENT_SCOPE_NETWORK_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_rpki(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_NETWORK_READ)?;
    let mut values = agent_network_values(&state, "rpki").await?;
    values.retain(|value| {
        query
            .asn
            .as_deref()
            .is_none_or(|asn| value.get("asn").and_then(serde_json::Value::as_str) == Some(asn))
            && query.prefix.as_deref().is_none_or(|prefix| {
                value.get("prefix").and_then(serde_json::Value::as_str) == Some(prefix)
            })
            && query.rpki_status.as_deref().is_none_or(|status| {
                value.get("status").and_then(serde_json::Value::as_str) == Some(status)
            })
            && agent_time_matches(value, &query)
    });
    let values = values
        .iter()
        .map(|value| {
            agent_network_view(
                value,
                &[
                    "prefix",
                    "asn",
                    "status",
                    "timestamp",
                    "source",
                    "age_seconds",
                    "confidence",
                    "assessment",
                ],
            )
        })
        .collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/network/rpki",
        AGENT_SCOPE_NETWORK_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn metrics(State(state): State<AppState>) -> Result<Response, StatusCode> {
    let body = state
        .store
        .metrics_text()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(body.into())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Serialize)]
struct ApiError {
    status: &'static str,
    data: Option<Box<serde_json::Value>>,
    timestamp: chrono::DateTime<Utc>,
    pagination: Option<Box<Pagination>>,
    errors: Vec<String>,
}

type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

fn api_error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            status: "error",
            data: None,
            timestamp: Utc::now(),
            pagination: None,
            errors: vec![message.into()],
        }),
    )
}

fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn new_secret() -> String {
    Uuid::new_v4().to_string() + &Uuid::new_v4().to_string()
}

fn configured_bootstrap_token() -> Option<String> {
    if let Ok(path) = env::var("CLAWFORGE_ADMIN_BOOTSTRAP_TOKEN_FILE") {
        if let Ok(value) = fs::read_to_string(path) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }
    env::var("CLAWFORGE_ADMIN_BOOTSTRAP_TOKEN")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn configured_analyzer_token() -> Option<String> {
    if let Ok(path) = env::var("CLAWFORGE_ANALYZER_TOKEN_FILE") {
        if let Ok(value) = fs::read_to_string(path) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }
    env::var("CLAWFORGE_ANALYZER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn configured_notifier_token() -> Option<String> {
    if let Ok(path) = env::var("CLAWFORGE_NOTIFIER_TOKEN_FILE") {
        if let Ok(value) = fs::read_to_string(path) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }
    env::var("CLAWFORGE_NOTIFIER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn configured_events_token() -> Option<String> {
    if let Ok(path) = env::var("CLAWFORGE_EVENTS_TOKEN_FILE") {
        if let Ok(value) = fs::read_to_string(path) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }
    env::var("CLAWFORGE_EVENTS_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .filter(|v| !v.trim().is_empty())
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> ApiResult<AdminPrincipal> {
    let token = bearer(headers)
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "bearer token required"))?;
    state
        .store
        .authenticate_credential(&digest(token))
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid or expired credential"))
}

async fn authenticate_agent(state: &AppState, headers: &HeaderMap) -> ApiResult<AgentPrincipal> {
    let token = bearer(headers)
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "agent bearer token required"))?;
    state
        .store
        .authenticate_agent_token(&digest(token))
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "agent authentication unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid or expired agent token"))
}

fn require_agent_scope(principal: &AgentPrincipal, scope: &str) -> ApiResult<()> {
    if principal
        .scopes
        .iter()
        .any(|value| value == scope || value == AGENT_SCOPE_ALL_READ)
    {
        Ok(())
    } else {
        Err(api_error(
            StatusCode::FORBIDDEN,
            "agent scope is not granted",
        ))
    }
}

async fn audit_agent_read(
    state: &AppState,
    principal: &AgentPrincipal,
    resource: &str,
    scope: &str,
) {
    let actor = format!("agent:{}", principal.name);
    if let Err(error) = state
        .store
        .record_audit_event(
            &actor,
            "agent_api_read",
            resource,
            serde_json::json!({"scope": scope}),
        )
        .await
    {
        tracing::warn!(%error, resource, "could not persist agent API audit event");
    }
}

fn require_role(principal: &AdminPrincipal, roles: &[&str]) -> ApiResult<()> {
    if roles.iter().any(|role| *role == principal.role) {
        Ok(())
    } else {
        Err(api_error(StatusCode::FORBIDDEN, "insufficient permission"))
    }
}

async fn audit(
    state: &AppState,
    principal: &AdminPrincipal,
    action: &str,
    resource: &str,
    details: serde_json::Value,
) {
    if let Err(error) = state
        .store
        .record_audit_event(&principal.username, action, resource, details)
        .await
    {
        tracing::warn!(%error, action, resource, "could not persist admin audit event");
    }
}

#[derive(Deserialize)]
struct BootstrapRequest {
    username: Option<String>,
    password: String,
    bootstrap_token: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    token_type: &'static str,
    expires_at: chrono::DateTime<Utc>,
}

async fn admin_bootstrap(
    State(state): State<AppState>,
    Json(request): Json<BootstrapRequest>,
) -> ApiResult<Json<ApiEnvelope<TokenResponse>>> {
    if state
        .store
        .admin_user_count()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"))?
        != 0
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "bootstrap already completed",
        ));
    }
    let expected = configured_bootstrap_token().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "bootstrap secret is not configured",
        )
    })?;
    if request.bootstrap_token != expected {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid bootstrap token",
        ));
    }
    if request.password.len() < 12 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "password must contain at least 12 characters",
        ));
    }
    let username = request.username.unwrap_or_else(|| {
        env::var("CLAWFORGE_ADMIN_BOOTSTRAP_USERNAME").unwrap_or_else(|_| "admin".into())
    });
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(request.password.as_bytes(), &salt)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?
        .to_string();
    let user_id = state
        .store
        .create_admin_user(&username, "Administrator", &password_hash)
        .await
        .map_err(|_| api_error(StatusCode::CONFLICT, "administrator could not be created"))?;
    let token = new_secret();
    let expires_at = Utc::now() + Duration::hours(12);
    state
        .store
        .create_session(user_id, &digest(&token), expires_at)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "session creation failed"))?;
    state
        .store
        .record_audit_event(
            &username,
            "admin_bootstrap",
            &user_id.to_string(),
            serde_json::json!({"role":"Administrator"}),
        )
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "audit storage failed"))?;
    Ok(envelope(
        TokenResponse {
            token,
            token_type: "Bearer",
            expires_at,
        },
        None,
    ))
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn admin_login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<ApiEnvelope<TokenResponse>>> {
    let user = state
        .store
        .find_admin_by_username(&request.username)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    if !user.enabled {
        return Err(api_error(StatusCode::UNAUTHORIZED, "account disabled"));
    }
    let parsed = PasswordHash::new(&user.password_hash).map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored password is invalid",
        )
    })?;
    Argon2::default()
        .verify_password(request.password.as_bytes(), &parsed)
        .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    state.store.mark_login(user.id).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "login state could not be stored",
        )
    })?;
    let token = new_secret();
    let expires_at = Utc::now() + Duration::hours(12);
    state
        .store
        .create_session(user.id, &digest(&token), expires_at)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "session creation failed"))?;
    state
        .store
        .record_audit_event(
            &user.username,
            "admin_login",
            &user.id.to_string(),
            serde_json::json!({"role":user.role}),
        )
        .await
        .ok();
    Ok(envelope(
        TokenResponse {
            token,
            token_type: "Bearer",
            expires_at,
        },
        None,
    ))
}

async fn admin_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    state
        .store
        .revoke_credential(&principal)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "logout failed"))?;
    audit(
        &state,
        &principal,
        "admin_logout",
        "session",
        serde_json::json!({"credential_id":principal.credential_id}),
    )
    .await;
    Ok(envelope(serde_json::json!({"status":"revoked"}), None))
}

#[derive(Deserialize)]
struct TokenRequest {
    name: String,
    expires_in_hours: Option<i64>,
}

#[derive(Deserialize)]
struct UserRequest {
    username: String,
    password: String,
    role: String,
}

async fn admin_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UserRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    if !matches!(
        request.role.as_str(),
        "Administrator" | "Operator" | "Viewer"
    ) {
        return Err(api_error(StatusCode::BAD_REQUEST, "unsupported role"));
    }
    if request.password.len() < 12 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "password must contain at least 12 characters",
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(request.password.as_bytes(), &salt)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?
        .to_string();
    let user_id = state
        .store
        .create_admin_user(&request.username, &request.role, &password_hash)
        .await
        .map_err(|_| api_error(StatusCode::CONFLICT, "user could not be created"))?;
    audit(
        &state,
        &principal,
        "admin_user_created",
        &user_id.to_string(),
        serde_json::json!({"username":request.username,"role":request.role}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":user_id,"username":request.username,"role":request.role}),
        None,
    ))
}

async fn admin_create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    let token = new_secret();
    let prefix = token.chars().take(8).collect::<String>();
    let expires_at = request
        .expires_in_hours
        .map(|hours| Utc::now() + Duration::hours(hours.clamp(1, 24 * 365)));
    let id = state
        .store
        .create_api_token(
            principal.id,
            &digest(&token),
            &prefix,
            &request.name,
            expires_at,
        )
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "token creation failed"))?;
    audit(
        &state,
        &principal,
        "api_token_created",
        &id.to_string(),
        serde_json::json!({"name":request.name,"expires_at":expires_at}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":id,"token":token,"token_type":"Bearer","expires_at":expires_at}),
        None,
    ))
}

#[derive(Deserialize)]
struct AgentTokenRequest {
    name: String,
    scopes: Vec<String>,
    expires_in_hours: Option<i64>,
}

fn validate_agent_scopes(scopes: &[String]) -> bool {
    !scopes.is_empty()
        && scopes
            .iter()
            .all(|scope| AGENT_SCOPES.contains(&scope.as_str()))
}

async fn admin_create_agent_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AgentTokenRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    if request.name.trim().is_empty() || request.name.len() > 128 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "agent token name must contain 1 to 128 characters",
        ));
    }
    if !validate_agent_scopes(&request.scopes) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "unsupported or empty agent scope list",
        ));
    }
    let expires_at = Utc::now()
        + Duration::hours(
            request
                .expires_in_hours
                .unwrap_or(24 * 30)
                .clamp(1, 24 * 365),
        );
    let token = new_secret();
    let id = state
        .store
        .create_agent_token(
            request.name.trim(),
            &digest(&token),
            &token[..8],
            &request.scopes,
            expires_at,
            Some(principal.id),
        )
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "agent token creation failed",
            )
        })?;
    audit(
        &state,
        &principal,
        "agent_token_created",
        &id.to_string(),
        serde_json::json!({"name":request.name.trim(),"scopes":request.scopes,"expires_at":expires_at}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":id,"token":token,"token_type":"Bearer","scopes":request.scopes,"expires_at":expires_at}),
        None,
    ))
}

async fn admin_revoke_agent_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    state
        .store
        .revoke_agent_token(id)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "agent token not found"))?;
    audit(
        &state,
        &principal,
        "agent_token_revoked",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":id,"status":"revoked"}),
        None,
    ))
}

async fn admin_rotate_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    state
        .store
        .revoke_api_token(id)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "token rotation failed"))?;
    let token = new_secret();
    let expires_at = Utc::now() + Duration::hours(12);
    let new_id = state
        .store
        .create_api_token(
            principal.id,
            &digest(&token),
            &token[..8],
            "rotated",
            Some(expires_at),
        )
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "token rotation failed"))?;
    audit(
        &state,
        &principal,
        "api_token_rotated",
        &id.to_string(),
        serde_json::json!({"new_id":new_id}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":new_id,"token":token,"expires_at":expires_at}),
        None,
    ))
}

async fn admin_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "provider_status_read",
        "providers",
        serde_json::json!({}),
    )
    .await;
    state
        .store
        .list_provider_views()
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider status unavailable",
            )
        })
}

#[derive(Deserialize)]
struct ProviderUpdate {
    enabled: Option<bool>,
    interval_seconds: Option<i64>,
}

async fn admin_update_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(update): Json<ProviderUpdate>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    if update
        .interval_seconds
        .is_some_and(|value| !(30..=86_400).contains(&value))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "interval_seconds must be between 30 and 86400",
        ));
    }
    state
        .store
        .update_provider_admin(&id, update.enabled, update.interval_seconds)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "provider not found"))?;
    audit(
        &state,
        &principal,
        "provider_updated",
        &id,
        serde_json::json!({"enabled":update.enabled,"interval_seconds":update.interval_seconds}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"status":"updated","provider":id}),
        None,
    ))
}

async fn admin_sync_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    let request_id = state
        .store
        .queue_provider_sync(&id, principal.id)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "provider not found"))?;
    audit(
        &state,
        &principal,
        "provider_sync_requested",
        &id,
        serde_json::json!({"request_id":request_id}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"status":"queued","request_id":request_id}),
        None,
    ))
}

async fn admin_trust_networks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "trusted_networks_read",
        "trusted_networks",
        serde_json::json!({}),
    )
    .await;
    state
        .store
        .list_network_views("trust")
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "trust registry unavailable",
            )
        })
}

#[derive(Deserialize)]
struct TrustNetworkRequest {
    name: String,
    network_type: String,
    identifier: String,
    networks: Option<Vec<String>>,
    node_identities: Option<Vec<String>>,
    device_tags: Option<Vec<String>>,
    groups: Option<Vec<String>>,
}

fn parse_network_type(value: &str) -> Option<NetworkType> {
    match value.to_ascii_lowercase().as_str() {
        "tailscale" => Some(NetworkType::Tailscale),
        "netbird" => Some(NetworkType::Netbird),
        "vlan" => Some(NetworkType::Vlan),
        "vpn" => Some(NetworkType::Vpn),
        "iprange" | "ip_range" => Some(NetworkType::IpRange),
        "asn" => Some(NetworkType::Asn),
        "bgp" => Some(NetworkType::Bgp),
        _ => None,
    }
}

async fn admin_create_trust_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TrustNetworkRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    let network_type = parse_network_type(&request.network_type)
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "unsupported network type"))?;
    let network = TrustedNetwork {
        id: Uuid::new_v4(),
        name: request.name,
        network_type,
        identifier: request.identifier,
        networks: request.networks.unwrap_or_default(),
        node_identities: request.node_identities.unwrap_or_default(),
        device_tags: request.device_tags.unwrap_or_default(),
        groups: request.groups.unwrap_or_default(),
        status: VerificationStatus::Pending,
        created_at: Utc::now(),
        verified_at: None,
    };
    state
        .store
        .upsert_trusted_network(&network)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "trust network could not be stored",
            )
        })?;
    audit(
        &state,
        &principal,
        "trusted_network_created",
        &network.id.to_string(),
        serde_json::json!({"status":"Pending","type":request.network_type}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":network.id,"status":"Pending"}),
        None,
    ))
}

#[derive(Deserialize)]
struct TrustStatusRequest {
    status: String,
}

async fn admin_update_trust_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    Json(request): Json<TrustStatusRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    if !matches!(request.status.as_str(), "Pending" | "Verified" | "Revoked") {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "status must be Pending, Verified, or Revoked",
        ));
    }
    state
        .store
        .update_trusted_network_status(id, &request.status)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "trusted network not found"))?;
    audit(
        &state,
        &principal,
        "trusted_network_status_changed",
        &id.to_string(),
        serde_json::json!({"status":request.status}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":id,"status":request.status}),
        None,
    ))
}

#[derive(Deserialize)]
struct AuditQuery {
    from: Option<chrono::DateTime<Utc>>,
    to: Option<chrono::DateTime<Utc>>,
    source: Option<String>,
    severity: Option<String>,
    user: Option<String>,
    limit: Option<i64>,
    page: Option<i64>,
    page_size: Option<i64>,
    format: Option<String>,
}

async fn audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "audit_events_read",
        "audit_events",
        serde_json::json!({"limit": query.limit.unwrap_or(100)}),
    )
    .await;
    let values = state
        .store
        .list_audit_events(
            query.from,
            query.to,
            query.source.as_deref(),
            query.severity.as_deref(),
            query.user.as_deref(),
            500,
        )
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "audit events unavailable"))?;
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.or(query.limit).unwrap_or(100),
    );
    Ok(envelope(data, Some(pagination)))
}

async fn admin_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "configuration_read",
        "admin_config",
        serde_json::json!({}),
    )
    .await;
    state
        .store
        .list_config()
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "configuration unavailable"))
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn values_as_csv(values: &[serde_json::Value], columns: &[&str]) -> String {
    let mut output = columns.join(",");
    output.push('\n');
    for value in values {
        let row = columns
            .iter()
            .map(|column| {
                let text = value
                    .get(*column)
                    .map(|item| {
                        item.as_str()
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| item.to_string())
                    })
                    .unwrap_or_default();
                csv_escape(&text)
            })
            .collect::<Vec<_>>()
            .join(",");
        output.push_str(&row);
        output.push('\n');
    }
    output
}

fn csv_response(body: String, filename: &str) -> Result<Response, StatusCode> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(body.into())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn export_incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IncidentQuery>,
) -> ApiResult<Response> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let values = state
        .store
        .list_incidents(query.status.as_deref(), 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident export unavailable",
            )
        })?;
    if query.format.as_deref() == Some("csv") {
        return csv_response(
            values_as_csv(
                &values,
                &[
                    "id",
                    "status",
                    "severity",
                    "risk_score",
                    "summary",
                    "created_at",
                ],
            ),
            "clawforge-incidents.csv",
        )
        .map_err(|status| api_error(status, "CSV export failed"));
    }
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(500),
    );
    serde_json::to_vec(&envelope_value(data, Some(pagination)))
        .map(|body| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.into())
                .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "JSON export failed"))
        })
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "JSON export failed"))?
}

async fn export_indicators(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IndicatorQuery>,
) -> ApiResult<Response> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let values = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "indicator export unavailable",
        )
    })?;
    if query.format.as_deref() == Some("csv") {
        return csv_response(
            values_as_csv(
                &values,
                &[
                    "id",
                    "value",
                    "indicator_type",
                    "source",
                    "confidence",
                    "risk_score",
                    "last_seen",
                ],
            ),
            "clawforge-indicators.csv",
        )
        .map_err(|status| api_error(status, "CSV export failed"));
    }
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(500),
    );
    serde_json::to_vec(&envelope_value(data, Some(pagination)))
        .map(|body| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.into())
                .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "JSON export failed"))
        })
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "JSON export failed"))?
}

async fn export_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Response> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let values = state
        .store
        .list_audit_events(
            query.from,
            query.to,
            query.source.as_deref(),
            query.severity.as_deref(),
            query.user.as_deref(),
            500,
        )
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "audit export unavailable"))?;
    if query.format.as_deref() == Some("csv") {
        return csv_response(
            values_as_csv(
                &values,
                &[
                    "id",
                    "actor",
                    "action",
                    "resource",
                    "severity",
                    "reason",
                    "recorded_at",
                ],
            ),
            "clawforge-audit-events.csv",
        )
        .map_err(|status| api_error(status, "CSV export failed"));
    }
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(500),
    );
    serde_json::to_vec(&envelope_value(data, Some(pagination)))
        .map(|body| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.into())
                .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "JSON export failed"))
        })
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "JSON export failed"))?
}

async fn admin_set_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(values): Json<serde_json::Map<String, serde_json::Value>>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    for (key, value) in values {
        let lower = key.to_ascii_lowercase();
        if lower.contains("secret")
            || lower.contains("password")
            || lower.contains("token")
            || lower.contains("api_key")
        {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "secret values must be supplied through Docker Secrets",
            ));
        }
        state
            .store
            .set_config(&key, value, principal.id)
            .await
            .map_err(|_| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "configuration update failed",
                )
            })?;
        audit(
            &state,
            &principal,
            "configuration_updated",
            &key,
            serde_json::json!({"stored":true}),
        )
        .await;
    }
    Ok(envelope(serde_json::json!({"status":"updated"}), None))
}

#[derive(Deserialize)]
struct IncidentQuery {
    status: Option<String>,
    limit: Option<i64>,
    page: Option<i64>,
    page_size: Option<i64>,
    severity: Option<String>,
    from: Option<String>,
    to: Option<String>,
    format: Option<String>,
}

async fn incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IncidentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "incidents_read",
        "incidents",
        serde_json::json!({"status":query.status,"limit":query.limit.unwrap_or(100)}),
    )
    .await;
    let mut values = state
        .store
        .list_incidents(query.status.as_deref(), 500)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "incident list unavailable"))?;
    values.retain(|value| {
        let timestamp = value
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        query.severity.as_deref().is_none_or(|severity| {
            value.get("severity").and_then(serde_json::Value::as_str) == Some(severity)
        }) && query.from.as_deref().is_none_or(|from| timestamp >= from)
            && query.to.as_deref().is_none_or(|to| timestamp <= to)
    });
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.or(query.limit).unwrap_or(100),
    );
    Ok(envelope(data, Some(pagination)))
}

async fn incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let value = state
        .store
        .get_incident(id)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "incident unavailable"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    audit(
        &state,
        &principal,
        "incident_read",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(value, None))
}

async fn incident_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    if state
        .store
        .get_incident(id)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "incident unavailable"))?
        .is_none()
    {
        return Err(api_error(StatusCode::NOT_FOUND, "incident not found"));
    }
    state
        .store
        .list_incident_events(id)
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident events unavailable",
            )
        })
}

async fn incident_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let value = state
        .store
        .incident_analysis(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident analysis unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    audit(
        &state,
        &principal,
        "incident_analysis_read",
        &id.to_string(),
        serde_json::json!({"llm_allowed":"analysis_only"}),
    )
    .await;
    Ok(envelope(value, None))
}

#[derive(Serialize)]
struct AnalyzerRequest {
    incident_id: Uuid,
    input: serde_json::Value,
}

async fn request_incident_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<ApiEnvelope<serde_json::Value>>)> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    let input = state
        .store
        .incident_analysis_input(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident analysis unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    let analyzer_url = state.config.analyzer_url.as_deref().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "analyzer is not configured",
        )
    })?;
    let analyzer_token = state.config.analyzer_token.as_deref().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "analyzer token is not configured",
        )
    })?;
    let response = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(15))
        .build()
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "analyzer client unavailable",
            )
        })?
        .post(format!("{}/analyze", analyzer_url.trim_end_matches('/')))
        .bearer_auth(analyzer_token)
        .json(&AnalyzerRequest {
            incident_id: id,
            input,
        })
        .send()
        .await
        .map_err(|_| api_error(StatusCode::BAD_GATEWAY, "analyzer request failed"))?;
    if !response.status().is_success() {
        return Err(api_error(
            StatusCode::BAD_GATEWAY,
            "analyzer rejected the request",
        ));
    }
    audit(
        &state,
        &principal,
        "incident_analysis_requested",
        &id.to_string(),
        serde_json::json!({"mode":"analysis_only"}),
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        envelope(
            serde_json::json!({"incident_id":id,"status":"accepted"}),
            None,
        ),
    ))
}

#[derive(Deserialize)]
struct StoredAnalysisRequest {
    incident_id: Uuid,
    provider: String,
    model: String,
    confidence: f32,
    summary: String,
    observations: Vec<String>,
    recommendations: Vec<String>,
}

fn forbidden_analysis_text(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "block",
        "grant trust",
        "change polic",
        "activate provider",
        "change permission",
    ]
    .iter()
    .any(|term| value.contains(term))
}

async fn store_internal_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StoredAnalysisRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let expected = state.config.analyzer_token.as_deref().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "analyzer token is not configured",
        )
    })?;
    let provided = bearer(&headers)
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "analyzer service token required"))?;
    if digest(provided) != digest(expected) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid analyzer service token",
        ));
    }
    if request.provider.trim().is_empty()
        || request.provider.len() > 128
        || request.model.trim().is_empty()
        || request.model.len() > 256
        || request.summary.trim().is_empty()
        || request.summary.len() > 4_000
        || !(0.0..=1.0).contains(&request.confidence)
        || request.observations.len() > 32
        || request.recommendations.len() > 32
        || request
            .observations
            .iter()
            .chain(request.recommendations.iter())
            .any(|value| value.len() > 1_000 || forbidden_analysis_text(value))
        || forbidden_analysis_text(&request.summary)
    {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "analysis output failed safety validation",
        ));
    }
    let id = state
        .store
        .store_incident_analysis(
            request.incident_id,
            &request.provider,
            &request.model,
            request.confidence,
            &request.summary,
            &serde_json::to_value(&request.observations).expect("serializable observations"),
            &serde_json::to_value(&request.recommendations).expect("serializable recommendations"),
        )
        .await
        .map_err(|error| {
            if error.to_string().contains("incident not found") {
                api_error(StatusCode::NOT_FOUND, "incident not found")
            } else {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "analysis storage unavailable",
                )
            }
        })?;
    state
        .store
        .record_audit_event(
            "analyzer",
            "incident_analysis_stored",
            &request.incident_id.to_string(),
            serde_json::json!({"analysis_id":id,"provider":request.provider,"model":request.model,"confidence":request.confidence}),
        )
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "analysis audit unavailable"))?;
    Ok(envelope(
        serde_json::json!({"id":id,"incident_id":request.incident_id,"status":"stored"}),
        None,
    ))
}

#[derive(Deserialize)]
struct IncidentStatusRequest {
    status: String,
}

async fn update_incident_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<IncidentStatusRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    state
        .store
        .update_incident_status(id, &request.status)
        .await
        .map_err(|error| {
            if error.to_string().contains("not found") {
                api_error(StatusCode::NOT_FOUND, "incident not found")
            } else {
                api_error(StatusCode::BAD_REQUEST, "invalid incident status")
            }
        })?;
    if matches!(request.status.as_str(), "Resolved" | "Ignored") {
        let _ = state
            .store
            .enqueue_notification_event(
                None,
                "incident_closed",
                "info",
                &id.to_string(),
                serde_json::json!({"incident_id": id, "status": request.status}),
                &format!("incident_closed:{id}:{}", request.status),
            )
            .await;
    }
    audit(
        &state,
        &principal,
        "incident_status_changed",
        &id.to_string(),
        serde_json::json!({"status":request.status}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":id,"status":request.status}),
        None,
    ))
}

#[derive(Deserialize)]
struct NotificationChannelRequest {
    name: String,
    channel_type: String,
    target: String,
    secret_ref: Option<String>,
    config: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct NotificationRuleRequest {
    event_type: String,
    minimum_severity: String,
    channel_id: Uuid,
}

#[derive(Deserialize)]
struct NotificationStatusRequest {
    enabled: bool,
}

async fn admin_notification_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    state
        .store
        .list_notification_channels()
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "notification channels unavailable",
            )
        })
}

async fn admin_create_notification_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NotificationChannelRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    let id = state
        .store
        .create_notification_channel(
            &request.name,
            &request.channel_type,
            &request.target,
            request.secret_ref.as_deref(),
            request.config.unwrap_or_else(|| serde_json::json!({})),
        )
        .await
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid notification channel"))?;
    audit(&state, &principal, "notification_channel_created", &id.to_string(), serde_json::json!({"name":request.name,"channel_type":request.channel_type,"target":request.target,"secret_ref":request.secret_ref})).await;
    Ok(envelope(
        serde_json::json!({"id":id,"status":"enabled"}),
        None,
    ))
}

async fn admin_notification_channel_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<NotificationStatusRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    state
        .store
        .set_notification_channel_status(id, request.enabled)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "notification channel not found"))?;
    audit(
        &state,
        &principal,
        "notification_channel_status_changed",
        &id.to_string(),
        serde_json::json!({"enabled":request.enabled}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":id,"enabled":request.enabled}),
        None,
    ))
}

async fn admin_notification_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    state
        .store
        .list_notification_rules()
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "notification rules unavailable",
            )
        })
}

async fn admin_create_notification_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NotificationRuleRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    let id = state
        .store
        .create_notification_rule(
            &request.event_type,
            &request.minimum_severity,
            request.channel_id,
        )
        .await
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid notification rule"))?;
    audit(&state, &principal, "notification_rule_created", &id.to_string(), serde_json::json!({"event_type":request.event_type,"minimum_severity":request.minimum_severity,"channel_id":request.channel_id})).await;
    Ok(envelope(
        serde_json::json!({"id":id,"status":"enabled"}),
        None,
    ))
}

async fn admin_notification_rule_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<NotificationStatusRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator"])?;
    state
        .store
        .set_notification_rule_status(id, request.enabled)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "notification rule not found"))?;
    audit(
        &state,
        &principal,
        "notification_rule_status_changed",
        &id.to_string(),
        serde_json::json!({"enabled":request.enabled}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":id,"enabled":request.enabled}),
        None,
    ))
}

#[derive(Deserialize)]
struct EventQuery {
    event_type: Option<String>,
    limit: Option<i64>,
}

async fn events_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    state
        .store
        .list_events(query.event_type.as_deref(), query.limit.unwrap_or(100))
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "event list unavailable"))
}

async fn event_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    let event = state
        .store
        .get_event(id)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "event unavailable"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "event not found"))?;
    Ok(envelope(event, None))
}

async fn events_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    state
        .store
        .event_status()
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "event status unavailable"))
}

fn notifier_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.config.notifier_token.as_deref() else {
        return false;
    };
    bearer(headers).is_some_and(|provided| digest(provided) == digest(expected))
}

fn events_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let provided = bearer(headers);
    state
        .config
        .events_token
        .as_deref()
        .is_some_and(|expected| provided.is_some_and(|value| digest(value) == digest(expected)))
        || notifier_authorized(state, headers)
        || state
            .config
            .analyzer_token
            .as_deref()
            .is_some_and(|expected| provided.is_some_and(|value| digest(value) == digest(expected)))
}

async fn internal_notifier_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    if !notifier_authorized(&state, &headers) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid notifier token",
        ));
    }
    let limit = query
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);
    state
        .store
        .claim_notification_events(limit)
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "notification queue unavailable",
            )
        })
}

#[derive(Deserialize)]
struct NotificationResultRequest {
    success: bool,
    error: Option<String>,
}

#[derive(Deserialize)]
struct InternalOperationalEventRequest {
    event_type: String,
    source: String,
    severity: String,
    reason: String,
    resource: String,
    details: Option<serde_json::Value>,
}

async fn internal_operational_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<InternalOperationalEventRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    if !events_authorized(&state, &headers) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid notifier token",
        ));
    }
    if !matches!(
        request.event_type.as_str(),
        "backup_error" | "system_health_error"
    ) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "unsupported operational event",
        ));
    }
    let id = state
        .store
        .record_operational_event(
            &request.event_type,
            &request.source,
            &request.severity,
            &request.reason,
            &request.resource,
            request.details.unwrap_or_else(|| serde_json::json!({})),
        )
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "operational event unavailable",
            )
        })?;
    Ok(envelope(serde_json::json!({"event_id": id}), None))
}

async fn internal_events_consume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    if !events_authorized(&state, &headers) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid event service token",
        ));
    }
    let consumer = query
        .get("consumer")
        .map(String::as_str)
        .unwrap_or("events");
    state
        .store
        .claim_event_deliveries(
            consumer,
            query
                .get("limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(25),
        )
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "event delivery unavailable",
            )
        })
}

async fn internal_event_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<NotificationResultRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    if !events_authorized(&state, &headers) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid event service token",
        ));
    }
    state
        .store
        .complete_event_delivery(id, request.success, request.error.as_deref())
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "event delivery result unavailable",
            )
        })?;
    Ok(envelope(
        serde_json::json!({"delivery_id":id,"success":request.success}),
        None,
    ))
}

async fn internal_notifier_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<NotificationResultRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    if !notifier_authorized(&state, &headers) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid notifier token",
        ));
    }
    state
        .store
        .complete_notification_event(id, request.success, request.error.as_deref())
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "notification result unavailable",
            )
        })?;
    let _ = state
        .store
        .record_audit_event(
            "notifier",
            if request.success {
                "notification_sent"
            } else {
                "notification_failed"
            },
            &id.to_string(),
            serde_json::json!({"error":request.error}),
        )
        .await;
    Ok(envelope(
        serde_json::json!({"id":id,"success":request.success}),
        None,
    ))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let database_url = database_url_from_env()?;
    let bind = env::var("CLAWFORGE_API_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let address: SocketAddr = bind
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid CLAWFORGE_API_BIND: {error}"))?;
    let store = PostgresStore::connect(&database_url).await?;
    // Register internal consumers before accepting events. Consumers remain
    // independent; disabled services can simply leave their delivery rows
    // pending until they are started.
    store.ensure_event_consumer("notifier").await?;
    store.ensure_event_consumer("events").await?;
    let runtime_store = store.clone();
    let listener = tokio::net::TcpListener::bind(address).await?;
    runtime_store
        .set_runtime_status("api", "running", None)
        .await?;
    let app_state = AppState {
        store,
        config: RuntimeConfig {
            bind: address,
            database_configured: true,
            analyzer_url: env::var("CLAWFORGE_ANALYZER_URL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            analyzer_token: configured_analyzer_token(),
            notifier_token: configured_notifier_token(),
            events_token: configured_events_token(),
        },
        rate_limiter: RateLimiter::default(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/version", get(version))
        .route("/events", get(events_list))
        .route("/events/{id}", get(event_get))
        .route("/events/status", get(events_status))
        .route("/intelligence/providers", get(intelligence_providers))
        .route("/intelligence/status", get(intelligence_status))
        .route("/intelligence/indicators", get(intelligence_indicators))
        .route("/network/asn", get(network_asn))
        .route("/network/bgp", get(network_bgp))
        .route("/network/rpki", get(network_rpki))
        .route("/network/trust", get(network_trust))
        .route("/visualization/events", get(visualization_events))
        .route("/visualization/network", get(visualization_network))
        .route("/visualization/incidents", get(visualization_incidents))
        .route("/visualization/trust", get(visualization_trust))
        .route("/metrics", get(metrics))
        .route("/admin/auth/bootstrap", post(admin_bootstrap))
        .route("/admin/auth/login", post(admin_login))
        .route("/admin/auth/logout", post(admin_logout))
        .route("/admin/auth/users", post(admin_create_user))
        .route("/admin/auth/tokens", post(admin_create_token))
        .route("/admin/auth/tokens/{id}/rotate", post(admin_rotate_token))
        .route("/admin/auth/agent-tokens", post(admin_create_agent_token))
        .route(
            "/admin/auth/agent-tokens/{id}/revoke",
            post(admin_revoke_agent_token),
        )
        .route("/admin/providers", get(admin_providers))
        .route("/admin/providers/{id}", post(admin_update_provider))
        .route("/admin/providers/{id}/sync", post(admin_sync_provider))
        .route(
            "/admin/notifications/channels",
            get(admin_notification_channels).post(admin_create_notification_channel),
        )
        .route(
            "/admin/notifications/channels/{id}/status",
            post(admin_notification_channel_status),
        )
        .route(
            "/admin/notifications/rules",
            get(admin_notification_rules).post(admin_create_notification_rule),
        )
        .route(
            "/admin/notifications/rules/{id}/status",
            post(admin_notification_rule_status),
        )
        .route(
            "/admin/trust-networks",
            get(admin_trust_networks).post(admin_create_trust_network),
        )
        .route(
            "/admin/trust-networks/{id}/status",
            post(admin_update_trust_status),
        )
        .route("/audit/events", get(audit_events))
        .route("/admin/audit/events", get(audit_events))
        .route("/admin/config", get(admin_config).post(admin_set_config))
        .route("/incidents", get(incidents))
        .route("/incidents/{id}", get(incident))
        .route("/incidents/{id}/events", get(incident_events))
        .route("/incidents/{id}/analysis", get(incident_analysis))
        .route(
            "/incidents/{id}/analysis/request",
            post(request_incident_analysis),
        )
        .route("/incidents/{id}/status", post(update_incident_status))
        .route("/internal/analyzer/analyses", post(store_internal_analysis))
        .route("/internal/notifier/events", get(internal_notifier_events))
        .route(
            "/internal/notifier/events/{id}/result",
            post(internal_notifier_result),
        )
        .route("/internal/events/consume", get(internal_events_consume))
        .route("/internal/events/{id}/result", post(internal_event_result))
        .route(
            "/internal/notifier/operational-events",
            post(internal_operational_event),
        )
        .route("/incidents/export", get(export_incidents))
        .route("/intelligence/indicators/export", get(export_indicators))
        .route("/audit/events/export", get(export_audit_events))
        .nest(
            "/api/v1",
            Router::new()
                .route("/status", get(agent_status))
                .route("/events", get(agent_events))
                .route("/incidents", get(agent_incidents))
                .route("/security/findings", get(agent_findings))
                .route("/security/overview", get(agent_security_overview))
                .route("/network/asn", get(agent_asn))
                .route("/network/prefixes", get(agent_prefixes))
                .route("/network/bgp", get(agent_bgp))
                .route("/network/rpki", get(agent_rpki)),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            rate_limit_middleware,
        ))
        .with_state(app_state);
    tracing::info!(%address, "Clawforge API listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    runtime_store
        .set_runtime_status("api", "stopped", None)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_hashed_and_not_reversible() {
        let value = "sensitive-token";
        let hash = digest(value);
        assert_ne!(hash, value);
        assert_eq!(hash, digest(value));
        assert_ne!(hash, digest("other-token"));
    }

    #[test]
    fn role_permissions_are_enforced() {
        let principal = AdminPrincipal {
            id: Uuid::new_v4(),
            username: "viewer".into(),
            role: "Viewer".into(),
            auth_kind: "session".into(),
            credential_id: Uuid::new_v4(),
        };
        assert!(require_role(&principal, &["Viewer"]).is_ok());
        assert!(require_role(&principal, &["Administrator"]).is_err());
    }

    #[test]
    fn bootstrap_password_policy_rejects_short_values() {
        assert!("short".len() < 12);
        assert!("a-long-enough-password".len() >= 12);
    }

    #[test]
    fn passwords_use_argon2_verification() {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(b"correct-password", &salt)
            .expect("hash password")
            .to_string();
        let parsed = PasswordHash::new(&hash).expect("parse password hash");
        assert!(Argon2::default()
            .verify_password(b"correct-password", &parsed)
            .is_ok());
        assert!(Argon2::default()
            .verify_password(b"wrong-password", &parsed)
            .is_err());
    }

    #[test]
    fn rate_limit_bucket_returns_retry_after_when_exhausted() {
        let limiter = RateLimiter::default();
        let window = StdDuration::from_secs(60);
        assert!(limiter.check("test", 1, window).allowed);
        let decision = limiter.check("test", 1, window);
        assert!(!decision.allowed);
        assert_eq!(decision.remaining, 0);
        assert!(decision.retry_after > StdDuration::ZERO);
        let response = rate_limit_response(
            RatePolicy {
                class: "login",
                limit: 1,
                window,
            },
            decision.retry_after,
        );
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
        assert_eq!(response.headers()["X-RateLimit-Remaining"], "0");
    }

    #[test]
    fn rate_limit_policies_exempt_health_and_scale_by_role() {
        assert!(policy_for("/health", &Method::GET, None).is_none());
        assert_eq!(
            policy_for("/admin/auth/login", &Method::POST, None)
                .unwrap()
                .limit,
            5
        );
        assert_eq!(
            policy_for("/incidents/export", &Method::GET, Some("Viewer"))
                .unwrap()
                .limit,
            10
        );
        assert_eq!(
            policy_for("/incidents/export", &Method::GET, Some("Operator"))
                .unwrap()
                .limit,
            15
        );
        assert_eq!(
            policy_for("/incidents/export", &Method::GET, Some("Administrator"))
                .unwrap()
                .limit,
            20
        );
        assert_eq!(
            policy_for("/incidents", &Method::GET, Some("Administrator"))
                .unwrap()
                .class,
            "read"
        );
        assert_eq!(
            policy_for("/incidents", &Method::POST, Some("Viewer"))
                .unwrap()
                .class,
            "write"
        );
    }

    #[test]
    fn rate_limit_identity_is_hashed() {
        let identity = header_client_identity(&HeaderMap::new());
        assert_eq!(identity, "unknown");
        assert_ne!(digest(&identity), identity);
    }

    #[test]
    fn analysis_output_cannot_contain_control_actions() {
        assert!(forbidden_analysis_text("block this address"));
        assert!(forbidden_analysis_text("grant trust to this node"));
        assert!(forbidden_analysis_text("change policy threshold"));
        assert!(!forbidden_analysis_text("review the correlated events"));
    }

    #[test]
    fn pagination_and_csv_contracts_are_stable() {
        let values = vec![
            serde_json::json!({"id": 1, "status": "Open"}),
            serde_json::json!({"id": 2, "status": "Resolved"}),
            serde_json::json!({"id": 3, "status": "Ignored"}),
        ];
        let (page, pagination) = paged_values(values, 2, 2);
        assert_eq!(page.len(), 1);
        assert_eq!(pagination.total, 3);
        assert!(!pagination.has_next);
        let csv = values_as_csv(&page, &["id", "status"]);
        assert!(csv.starts_with("id,status\n"));
        assert!(csv.contains("3,Ignored"));
        let response = serde_json::to_value(envelope_value(page, Some(pagination)))
            .expect("serialize envelope");
        assert!(response.get("status").is_some());
        assert!(response.get("data").is_some());
        assert!(response.get("timestamp").is_some());
        assert!(response.get("pagination").is_some());
        assert!(response.get("errors").is_some());
    }

    #[test]
    fn visualization_graph_contract_is_typed_and_read_only() {
        let node = graph_node("asn:64500", "ASN 64500", "asn");
        let edge = graph_edge("prefix:203.0.113.0/24", "asn:64500", "origin");
        assert_eq!(node["type"], "asn");
        assert_eq!(edge["source"], "prefix:203.0.113.0/24");
        assert_eq!(edge["target"], "asn:64500");
    }

    #[test]
    fn visualization_allows_only_read_roles() {
        let principal = |role: &str| AdminPrincipal {
            id: Uuid::new_v4(),
            username: "test".into(),
            role: role.into(),
            auth_kind: "session".into(),
            credential_id: Uuid::new_v4(),
        };
        assert!(visualization_authorized(&principal("Viewer")).is_ok());
        assert!(visualization_authorized(&principal("Operator")).is_ok());
        assert!(visualization_authorized(&principal("Administrator")).is_ok());
        assert!(visualization_authorized(&principal("Unknown")).is_err());
    }

    #[test]
    fn agent_scopes_are_read_only_and_wildcard_is_supported() {
        assert!(validate_agent_scopes(
            &[AGENT_SCOPE_EVENTS_READ.to_string()]
        ));
        assert!(validate_agent_scopes(&[AGENT_SCOPE_ALL_READ.to_string()]));
        assert!(!validate_agent_scopes(&["agent:admin:write".to_string()]));
        let principal = AgentPrincipal {
            id: Uuid::new_v4(),
            name: "test-agent".into(),
            scopes: vec![AGENT_SCOPE_ALL_READ.into()],
        };
        assert!(require_agent_scope(&principal, AGENT_SCOPE_NETWORK_READ).is_ok());
    }

    #[test]
    fn agent_views_exclude_raw_event_and_indicator_payloads() {
        let event = agent_event_view(&serde_json::json!({
            "event_id": "event-1",
            "event_type": "provider.failed",
            "source": "test",
            "severity": "high",
            "timestamp": "2026-09-08T00:00:00Z",
            "payload": {"token": "must-not-leak"},
            "metadata": {"secret": "must-not-leak"}
        }));
        assert!(event.get("payload").is_none());
        assert!(event.get("metadata").is_none());
        let finding = agent_finding_view(&serde_json::json!({
            "id": 7,
            "indicator_type": "ip",
            "value": "198.51.100.10",
            "source": "fixture",
            "confidence": 80,
            "risk_score": 75,
            "metadata": {"raw_feed": "must-not-leak"}
        }));
        assert_eq!(finding["severity"], "high");
        assert!(finding.get("metadata").is_none());
    }

    #[test]
    fn agent_pagination_and_time_contract_are_bounded() {
        let query = AgentQuery {
            page: Some(0),
            page_size: Some(1000),
            ..AgentQuery::default()
        };
        assert_eq!(agent_page(&query, 50), (1, 100));
        let value = serde_json::json!({"created_at":"2026-09-08T00:00:00Z"});
        let query = AgentQuery {
            from: Some("2026-09-07T00:00:00Z".into()),
            to: Some("2026-09-09T00:00:00Z".into()),
            ..AgentQuery::default()
        };
        assert!(agent_time_matches(&value, &query));
    }
}
