use std::{
    collections::{HashMap, HashSet},
    env, fs,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration as StdDuration, Instant},
};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use clawforge_intelligence::{NetworkType, TrustedNetwork, VerificationStatus};
use clawforge_policy::authorize_action;
use clawforge_storage::{
    database_url_from_env, AdminPrincipal, AgentPrincipal, AuditEventFilter, MigrationStatus,
    PostgresStore,
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
const AGENT_SCOPE_INCIDENT_READ: &str = "agent:incident:read";
const AGENT_SCOPE_INCIDENTS_READ_LEGACY: &str = "agent:incidents:read";
const AGENT_SCOPE_INCIDENTS_READ: &str = "agent:incidents:read";
const AGENT_SCOPE_CONTEXT_READ: &str = "agent:context:read";
const AGENT_SCOPE_DECISION_READ: &str = "agent:decision:read";
const AGENT_SCOPE_PROVIDER_READ: &str = "agent:provider:read";
const AGENT_SCOPE_OPERATIONS_READ: &str = "agent:operations:read";
const AGENT_SCOPE_OPERATIONS_BRIEFING: &str = "agent:operations:briefing";
const AGENT_SCOPE_OPERATIONS_RECOMMEND: &str = "agent:operations:recommend";
const AGENT_SCOPE_SECURITY_READ: &str = "agent:security:read";
const AGENT_SCOPE_KNOWLEDGE_READ: &str = "agent:knowledge:read";
const AGENT_SCOPE_NETWORK_READ: &str = "agent:network:read";
const AGENT_SCOPE_INCIDENT_REPLAY: &str = "agent:incident:replay";
const AGENT_SCOPE_HISTORY_READ: &str = "agent:history:read";
const AGENT_SCOPE_SECURITY_BRIEFING: &str = "agent:security:briefing";
const AGENT_SCOPE_SYSTEM_GRAPH: &str = "agent:system:graph:read";
const AGENT_SCOPE_WORKFLOW_READ: &str = "agent:workflow:read";
const AGENT_SCOPE_WORKFLOW_APPROVE: &str = "agent:workflow:approve";
const AGENT_SCOPE_CONNECTOR_READ: &str = "agent:connector:read";
const AGENT_SCOPE_ACTION_READ: &str = "agent:action:read";
const AGENT_SCOPE_EXECUTION_READ: &str = "agent:execution:read";
const AGENT_SCOPE_OPERATIONS_STATE: &str = "agent:operations:state";
const AGENT_SCOPE_METRICS_READ: &str = "agent:metrics:read";
const AGENT_SCOPE_ALL_READ: &str = "agent:read";

const AGENT_SCOPES: &[&str] = &[
    AGENT_SCOPE_SYSTEM_READ,
    AGENT_SCOPE_EVENTS_READ,
    AGENT_SCOPE_INCIDENT_READ,
    AGENT_SCOPE_INCIDENTS_READ,
    AGENT_SCOPE_CONTEXT_READ,
    AGENT_SCOPE_DECISION_READ,
    AGENT_SCOPE_PROVIDER_READ,
    AGENT_SCOPE_OPERATIONS_READ,
    AGENT_SCOPE_OPERATIONS_BRIEFING,
    AGENT_SCOPE_OPERATIONS_RECOMMEND,
    AGENT_SCOPE_SECURITY_READ,
    AGENT_SCOPE_KNOWLEDGE_READ,
    AGENT_SCOPE_NETWORK_READ,
    AGENT_SCOPE_INCIDENT_REPLAY,
    AGENT_SCOPE_HISTORY_READ,
    AGENT_SCOPE_SECURITY_BRIEFING,
    AGENT_SCOPE_SYSTEM_GRAPH,
    AGENT_SCOPE_WORKFLOW_READ,
    AGENT_SCOPE_WORKFLOW_APPROVE,
    AGENT_SCOPE_CONNECTOR_READ,
    AGENT_SCOPE_ACTION_READ,
    AGENT_SCOPE_EXECUTION_READ,
    AGENT_SCOPE_OPERATIONS_STATE,
    AGENT_SCOPE_METRICS_READ,
    AGENT_SCOPE_ALL_READ,
];

static API_REQUESTS: AtomicU64 = AtomicU64::new(0);
static API_ERRORS: AtomicU64 = AtomicU64::new(0);
static API_RATE_LIMITED: AtomicU64 = AtomicU64::new(0);
static API_RESPONSE_TIME_US: AtomicU64 = AtomicU64::new(0);
static API_RESPONSE_COUNT: AtomicU64 = AtomicU64::new(0);
static API_AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);

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
        Some("Approver") => 125,
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
    let started = Instant::now();
    API_REQUESTS.fetch_add(1, Ordering::Relaxed);
    let path = request.uri().path().to_string();
    let Some(_) = policy_for(&path, request.method(), None) else {
        let response = next.run(request).await;
        API_RESPONSE_TIME_US.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        API_RESPONSE_COUNT.fetch_add(1, Ordering::Relaxed);
        return response;
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
        API_RATE_LIMITED.fetch_add(1, Ordering::Relaxed);
        API_ERRORS.fetch_add(1, Ordering::Relaxed);
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
        let response = rate_limit_response(policy, retry_after);
        API_RESPONSE_TIME_US.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        API_RESPONSE_COUNT.fetch_add(1, Ordering::Relaxed);
        return response;
    }
    let remaining = global.remaining.min(endpoint.remaining);
    let mut response = next.run(request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        API_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    response.headers_mut().insert(
        "X-RateLimit-Limit",
        HeaderValue::from_str(&policy.limit.to_string()).expect("valid limit value"),
    );
    response.headers_mut().insert(
        "X-RateLimit-Remaining",
        HeaderValue::from_str(&remaining.to_string()).expect("valid remaining value"),
    );
    API_RESPONSE_TIME_US.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
    API_RESPONSE_COUNT.fetch_add(1, Ordering::Relaxed);
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
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "provider_status_read",
        "intelligence/providers",
        serde_json::json!({}),
    )
    .await;
    state
        .store
        .list_provider_views()
        .await
        .map(|data| envelope(data, None))
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "provider list unavailable"))
}

async fn intelligence_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    intelligence_providers(State(state), headers).await
}

async fn intelligence_indicators(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IndicatorQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "intelligence_indicators_read",
        "intelligence/indicators",
        serde_json::json!({}),
    )
    .await;
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
    headers: HeaderMap,
    Query(query): Query<NetworkQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "network_asn_read",
        "network/asn",
        serde_json::json!({}),
    )
    .await;
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
    headers: HeaderMap,
    Query(query): Query<NetworkQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "network_bgp_read",
        "network/bgp",
        serde_json::json!({}),
    )
    .await;
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
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "network_rpki_read",
        "network/rpki",
        serde_json::json!({}),
    )
    .await;
    let values = network_view(State(state), "rpki")
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "RPKI list unavailable"))?;
    let (data, pagination) = paged_values(values, 1, 100);
    Ok(envelope(data, Some(pagination)))
}

async fn network_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    audit(
        &state,
        &principal,
        "network_trust_read",
        "network/trust",
        serde_json::json!({}),
    )
    .await;
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
    relation_type: Option<String>,
    network_type: Option<String>,
    rpki_status: Option<String>,
    from: Option<String>,
    to: Option<String>,
    interval: Option<String>,
    category: Option<String>,
    workflow_id: Option<String>,
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
        "title": value.get("title"),
        "status": value.get("status"),
        "severity": value.get("severity"),
        "source": value.get("source"),
        "confidence": value.get("confidence"),
        "risk_score": value.get("risk_score"),
        "summary": value.get("summary"),
        "event_count": value.get("event_count"),
        "created_at": value.get("created_at"),
        "updated_at": value.get("updated_at")
    })
}

fn require_agent_incident_scope(principal: &AgentPrincipal) -> ApiResult<()> {
    // Keep accepting the plural scope issued by the first Agent API release;
    // new integrations should request the singular, canonical scope.
    require_agent_scope_any(
        principal,
        &[AGENT_SCOPE_INCIDENT_READ, AGENT_SCOPE_INCIDENTS_READ_LEGACY],
    )
}

fn agent_incident_timeline_view(value: &serde_json::Value) -> serde_json::Value {
    let kind = value.get("kind").and_then(serde_json::Value::as_str);
    let data = value.get("data").unwrap_or(&serde_json::Value::Null);
    match kind {
        Some("status") => serde_json::json!({
            "kind": "status",
            "timestamp": value.get("timestamp"),
            "status": data.get("status"),
            "previous_status": data.get("previous_status"),
            "reason": data.get("reason")
        }),
        Some("relation") => serde_json::json!({
            "kind": "relation",
            "timestamp": value.get("timestamp"),
            "relation_type": data.get("relation_type"),
            "event_id": data.get("event_id"),
            "related_event_id": data.get("related_event_id"),
            "related_incident_id": data.get("related_incident_id"),
            "event_type": data.get("event_type"),
            "source": data.get("source"),
            "severity": data.get("severity"),
            "occurred_at": data.get("occurred_at"),
            "correlation_id": data.get("correlation_id"),
            "indicator": data.get("indicator"),
            "confidence": data.get("confidence"),
            "reason": data.get("reason")
        }),
        // Operator note bodies are deliberately not exposed to external
        // agents because they are free-form internal investigation content.
        Some("note") => serde_json::json!({
            "kind": "note",
            "timestamp": value.get("timestamp"),
            "recorded": true
        }),
        Some("timeline") => serde_json::json!({
            "kind": "timeline",
            "timestamp": value.get("timestamp"),
            "action": data.get("action"),
            "recorded": true
        }),
        _ => serde_json::json!({
            "kind": "unknown",
            "timestamp": value.get("timestamp")
        }),
    }
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

fn context_is_active_incident(value: &serde_json::Value) -> bool {
    value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|status| {
            matches!(
                status,
                "open" | "acknowledged" | "detected" | "investigating" | "confirmed" | "mitigated"
            )
        })
}

fn context_incident_data(
    values: &[serde_json::Value],
) -> (
    Vec<serde_json::Value>,
    serde_json::Value,
    Vec<serde_json::Value>,
) {
    let active = values
        .iter()
        .filter(|value| context_is_active_incident(value))
        .map(agent_incident_view)
        .collect::<Vec<_>>();
    let mut by_severity = serde_json::Map::new();
    for value in &active {
        if let Some(severity) = value.get("severity").and_then(serde_json::Value::as_str) {
            let count = by_severity
                .entry(severity.to_string())
                .or_insert_with(|| serde_json::Value::from(0_u64));
            *count = serde_json::Value::from(count.as_u64().unwrap_or(0) + 1);
        }
    }
    let correlations = active
        .iter()
        .take(50)
        .map(|incident| {
            serde_json::json!({
                "incident_id": incident.get("id"),
                "status": incident.get("status"),
                "severity": incident.get("severity"),
                "confidence": incident.get("confidence"),
                "risk_score": incident.get("risk_score"),
                "summary": incident.get("summary"),
                "event_count": incident.get("event_count"),
                "updated_at": incident.get("updated_at")
            })
        })
        .collect::<Vec<_>>();
    (
        active,
        serde_json::json!({
            "total": values.iter().filter(|value| context_is_active_incident(value)).count(),
            "by_severity": by_severity
        }),
        correlations,
    )
}

fn context_risk_data(values: &[serde_json::Value]) -> serde_json::Value {
    let mut by_severity = serde_json::Map::new();
    let mut scores = Vec::new();
    for value in values {
        let Some(score) = value.get("risk_score").and_then(serde_json::Value::as_i64) else {
            continue;
        };
        let severity = risk_severity(score);
        let count = by_severity
            .entry(severity.to_string())
            .or_insert_with(|| serde_json::Value::from(0_u64));
        *count = serde_json::Value::from(count.as_u64().unwrap_or(0) + 1);
        scores.push((score, value));
    }
    scores.sort_by_key(|left| std::cmp::Reverse(left.0));
    let highest = scores.first().map(|(score, _)| *score).unwrap_or(0);
    let assessed = scores.len();
    let average = if scores.is_empty() {
        0
    } else {
        scores.iter().map(|(score, _)| *score).sum::<i64>() / assessed as i64
    };
    let top = scores
        .into_iter()
        .take(20)
        .map(|(score, value)| {
            serde_json::json!({
                "source": value.get("source"),
                "severity": risk_severity(score),
                "risk_score": score,
                "trust_score": value.get("trust_score"),
                "assessed_at": value.get("assessed_at")
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "total": values.len(),
        "assessed": assessed,
        "highest": highest,
        "average": average,
        "by_severity": by_severity,
        "top": top
    })
}

fn context_trust_data(values: &[serde_json::Value]) -> serde_json::Value {
    let mut by_status = serde_json::Map::new();
    for value in values {
        if let Some(status) = value.get("status").and_then(serde_json::Value::as_str) {
            let count = by_status
                .entry(status.to_string())
                .or_insert_with(|| serde_json::Value::from(0_u64));
            *count = serde_json::Value::from(count.as_u64().unwrap_or(0) + 1);
        }
    }
    serde_json::json!({"total": values.len(), "by_status": by_status})
}

fn context_important_events(values: &[serde_json::Value]) -> Vec<serde_json::Value> {
    values
        .iter()
        .filter(|value| {
            matches!(
                value.get("severity").and_then(serde_json::Value::as_str),
                Some("high" | "critical")
            )
        })
        .take(20)
        .map(agent_event_view)
        .collect()
}

fn decision_severity_rank(value: Option<&str>) -> i64 {
    match value.unwrap_or("info") {
        "critical" => 90,
        "high" => 70,
        "medium" => 40,
        "low" => 10,
        _ => 0,
    }
}

fn decision_priority(score: i64, severity: Option<&str>) -> &'static str {
    match score.max(decision_severity_rank(severity)) {
        value if value >= 90 => "critical",
        value if value >= 70 => "high",
        value if value >= 40 => "medium",
        value if value > 0 => "low",
        _ => "info",
    }
}

fn decision_priority_rank(value: Option<&str>) -> i64 {
    decision_severity_rank(value)
}

fn decision_confidence_data(values: &[serde_json::Value]) -> serde_json::Value {
    let mut confidences = values
        .iter()
        .filter(|value| context_is_active_incident(value))
        .filter_map(|value| {
            value
                .get("confidence")
                .and_then(serde_json::Value::as_i64)
                .map(|confidence| confidence.clamp(0, 100))
        })
        .collect::<Vec<_>>();
    confidences.sort_unstable();
    let assessed = confidences.len();
    let average = if assessed == 0 {
        0
    } else {
        confidences.iter().sum::<i64>() / assessed as i64
    };
    serde_json::json!({
        "assessed": assessed,
        "highest": confidences.last().copied().unwrap_or(0),
        "average": average,
        "lowest": confidences.first().copied().unwrap_or(0)
    })
}

fn decision_attention_points(
    incidents: &[serde_json::Value],
    indicators: &[serde_json::Value],
    events: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut points = Vec::new();
    for value in incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
    {
        let risk_score = value
            .get("risk_score")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let severity = value
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| risk_severity(risk_score));
        let incident = agent_incident_view(value);
        points.push(serde_json::json!({
            "type": "incident",
            "priority": decision_priority(risk_score, Some(severity)),
            "incident_id": incident.get("id"),
            "severity": incident.get("severity"),
            "confidence": incident.get("confidence"),
            "risk_score": incident.get("risk_score"),
            "summary": incident.get("summary"),
            "reason": "active incident requires review"
        }));
    }
    for value in indicators.iter().filter(|value| {
        value
            .get("risk_score")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|score| score > 0)
    }) {
        let score = value
            .get("risk_score")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        points.push(serde_json::json!({
            "type": "risk_finding",
            "priority": decision_priority(score, None),
            "source": value.get("source"),
            "severity": risk_severity(score),
            "risk_score": score,
            "confidence": value.get("confidence"),
            "assessed_at": value.get("assessed_at"),
            "reason": value.get("reason")
        }));
    }
    for value in context_important_events(events) {
        let severity = value
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("info");
        points.push(serde_json::json!({
            "type": "event",
            "priority": decision_priority(0, Some(severity)),
            "event_id": value.get("event_id"),
            "event_type": value.get("event_type"),
            "source": value.get("source"),
            "severity": value.get("severity"),
            "timestamp": value.get("timestamp"),
            "reason": "important event requires contextual review"
        }));
    }
    points.sort_by_key(|point| {
        std::cmp::Reverse(decision_priority_rank(
            point.get("priority").and_then(serde_json::Value::as_str),
        ))
    });
    points.truncate(50);
    points
}

fn decision_recommended_checks(
    incidents: &[serde_json::Value],
    indicators: &[serde_json::Value],
    trust: &[serde_json::Value],
    events: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let active_incidents = incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
        .count();
    let highest_risk = indicators
        .iter()
        .filter_map(|value| value.get("risk_score").and_then(serde_json::Value::as_i64))
        .max()
        .unwrap_or(0);
    let mut checks = Vec::new();
    if active_incidents > 0 {
        checks.push(serde_json::json!({
            "priority": "high",
            "check": "incident_timelines",
            "reason": "review active incident timelines and correlated events"
        }));
    }
    if highest_risk >= 70 {
        checks.push(serde_json::json!({
            "priority": "high",
            "check": "risk_findings",
            "reason": "review the highest stored risk findings and their confidence"
        }));
    }
    if trust
        .iter()
        .any(|value| value.get("status").and_then(serde_json::Value::as_str) == Some("Revoked"))
    {
        checks.push(serde_json::json!({
            "priority": "medium",
            "check": "trust_status",
            "reason": "review revoked trusted infrastructure records"
        }));
    }
    if events.iter().any(|value| {
        value
            .get("event_type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|event_type| {
                event_type.to_ascii_lowercase().contains("bgp")
                    || event_type.to_ascii_lowercase().contains("rpki")
            })
    }) {
        checks.push(serde_json::json!({
            "priority": "medium",
            "check": "network_intelligence",
            "reason": "review recent BGP and RPKI context"
        }));
    }
    if checks.is_empty() {
        checks.push(serde_json::json!({
            "priority": "low",
            "check": "system_health",
            "reason": "confirm system and provider health remains current"
        }));
    }
    checks
}

fn decision_risk_assessment(
    incidents: &[serde_json::Value],
    indicators: &[serde_json::Value],
) -> serde_json::Value {
    let highest_risk_score = indicators
        .iter()
        .chain(
            incidents
                .iter()
                .filter(|value| context_is_active_incident(value)),
        )
        .filter_map(|value| value.get("risk_score").and_then(serde_json::Value::as_i64))
        .max()
        .unwrap_or(0);
    let highest_incident_severity = incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
        .max_by_key(|value| {
            decision_severity_rank(value.get("severity").and_then(serde_json::Value::as_str))
        })
        .and_then(|value| value.get("severity"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let incident_score = decision_severity_rank(
        highest_incident_severity
            .as_str()
            .or_else(|| Some(risk_severity(highest_risk_score))),
    );
    let overall_score = highest_risk_score.max(incident_score);
    serde_json::json!({
        "highest_risk_score": highest_risk_score,
        "risk_level": risk_severity(highest_risk_score),
        "overall_status": decision_priority(overall_score, highest_incident_severity.as_str()),
        "active_incidents": incidents.iter().filter(|value| context_is_active_incident(value)).count(),
        "highest_incident_severity": highest_incident_severity,
        "correlation_confidence": decision_confidence_data(incidents)
    })
}

fn agent_provider_view(value: &serde_json::Value) -> serde_json::Value {
    let status = value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if value
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                "unknown".to_string()
            } else {
                "disabled".to_string()
            }
        });
    serde_json::json!({
        "id": value.get("id"),
        "name": value.get("name"),
        "type": value.get("source"),
        "source": value.get("source"),
        "status": status,
        "enabled": value.get("enabled"),
        "last_success": value.get("last_success_at"),
        "last_failure": value.get("last_failure_at"),
        "last_error": value.get("last_error"),
        "data_age": value.get("age_seconds"),
        "data_age_seconds": value.get("age_seconds"),
        "quality_score": value.get("quality_score").or_else(|| value.get("confidence")),
        "indicator_count": value.get("indicator_count"),
        "sync_duration_ms": value.get("sync_duration_ms"),
        "timestamp": value.get("timestamp")
    })
}

fn operations_provider_health(values: &[serde_json::Value]) -> serde_json::Value {
    let healthy = values
        .iter()
        .filter(|value| value.get("status").and_then(serde_json::Value::as_str) == Some("ok"))
        .count();
    let failed = values
        .iter()
        .filter(|value| value.get("status").and_then(serde_json::Value::as_str) == Some("error"))
        .count();
    let enabled = values
        .iter()
        .filter(|value| value.get("enabled").and_then(serde_json::Value::as_bool) == Some(true))
        .count();
    let quality_sum = values
        .iter()
        .filter_map(|value| {
            value
                .get("quality_score")
                .or_else(|| value.get("confidence"))
                .and_then(serde_json::Value::as_i64)
        })
        .sum::<i64>();
    let quality_count = values
        .iter()
        .filter(|value| {
            value
                .get("quality_score")
                .or_else(|| value.get("confidence"))
                .and_then(serde_json::Value::as_i64)
                .is_some()
        })
        .count();
    serde_json::json!({
        "total": values.len(),
        "enabled": enabled,
        "healthy": healthy,
        "failed": failed,
        "average_quality_score": if quality_count == 0 { 0 } else { quality_sum / quality_count as i64 },
        "items": values.iter().map(agent_provider_view).collect::<Vec<_>>()
    })
}

fn operations_summary_data(
    incidents: &[serde_json::Value],
    indicators: &[serde_json::Value],
    trust: &[serde_json::Value],
    events: &[serde_json::Value],
    providers: &[serde_json::Value],
) -> serde_json::Value {
    let risk_assessment = decision_risk_assessment(incidents, indicators);
    let active_incidents = incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
        .count();
    let critical_events = events
        .iter()
        .filter(|value| {
            value.get("severity").and_then(serde_json::Value::as_str) == Some("critical")
        })
        .count();
    let attention_points = decision_attention_points(incidents, indicators, events);
    let recommended_checks = decision_recommended_checks(incidents, indicators, trust, events);
    serde_json::json!({
        "overall_status": risk_assessment.get("overall_status"),
        "risk_level": risk_assessment.get("risk_level"),
        "active_incidents": active_incidents,
        "critical_events": critical_events,
        "provider_health": operations_provider_health(providers),
        "attention_points": attention_points,
        "recommended_checks": recommended_checks,
        "correlation_confidence": risk_assessment.get("correlation_confidence"),
        "trust": context_trust_data(trust)
    })
}

fn trend_rank(value: &str) -> i16 {
    match value {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" | "ok" => 1,
        "degraded" => 2,
        "unavailable" => 5,
        _ => 0,
    }
}

fn trend_direction(current: i64, previous: i64) -> &'static str {
    match current.cmp(&previous) {
        std::cmp::Ordering::Greater => "increasing",
        std::cmp::Ordering::Less => "decreasing",
        std::cmp::Ordering::Equal => "stable",
    }
}

fn operations_trend(
    summary: &serde_json::Value,
    snapshots: &[serde_json::Value],
) -> serde_json::Value {
    let Some(previous) = snapshots.first() else {
        return serde_json::json!({
            "risk_level": {"value": summary.get("risk_level"), "change_direction": "stable", "change_reason": "no historical snapshot available", "confidence": 0},
            "active_incidents": {"value": summary.get("active_incidents"), "change_direction": "stable", "change_reason": "no historical snapshot available", "confidence": 0},
            "alerts": {"value": summary.get("alerts").and_then(|value| value.get("open")).cloned().unwrap_or_default(), "change_direction": "stable", "change_reason": "no historical snapshot available", "confidence": 0},
            "provider_failures": {"value": summary.get("provider_health").and_then(|value| value.get("failed")).cloned().unwrap_or_default(), "change_direction": "stable", "change_reason": "no historical snapshot available", "confidence": 0},
            "overall": {"change_direction": "stable", "change_reason": "no historical snapshot available", "confidence": 0}
        });
    };
    let current_risk = summary
        .get("risk_level")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("info");
    let previous_risk = previous
        .get("risk_level")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("info");
    let current_incidents = summary
        .get("active_incidents")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let previous_incidents = previous
        .get("active_incident_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let current_alerts = summary
        .get("alerts")
        .and_then(|value| value.get("open"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let previous_alerts = previous
        .get("alert_count")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let current_failures = summary
        .get("provider_health")
        .and_then(|value| value.get("failed"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let previous_failures = previous
        .get("provider_health")
        .and_then(|value| value.get("failed"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let risk_delta = trend_rank(current_risk) - trend_rank(previous_risk);
    let overall_direction = if risk_delta > 0
        || current_incidents > previous_incidents
        || current_alerts > previous_alerts
        || current_failures > previous_failures
    {
        "increasing"
    } else if risk_delta < 0
        || current_incidents < previous_incidents
        || current_alerts < previous_alerts
        || current_failures < previous_failures
    {
        "decreasing"
    } else {
        "stable"
    };
    let overall_reason = if current_risk != previous_risk {
        format!("risk level changed from {previous_risk} to {current_risk}")
    } else if current_incidents != previous_incidents {
        format!("active incidents changed from {previous_incidents} to {current_incidents}")
    } else if current_failures != previous_failures {
        format!("provider failures changed from {previous_failures} to {current_failures}")
    } else if current_alerts != previous_alerts {
        format!("open alerts changed from {previous_alerts} to {current_alerts}")
    } else {
        "no material change since the previous snapshot".to_string()
    };
    let confidence = 80;
    serde_json::json!({
        "risk_level": {"value": current_risk, "previous": previous_risk, "change_direction": if risk_delta > 0 { "increasing" } else if risk_delta < 0 { "decreasing" } else { "stable" }, "change_reason": if current_risk == previous_risk { "risk level is unchanged" } else { "risk level changed" }, "confidence": confidence},
        "active_incidents": {"value": current_incidents, "previous": previous_incidents, "change_direction": trend_direction(current_incidents, previous_incidents), "change_reason": "active incident count comparison", "confidence": confidence},
        "alerts": {"value": current_alerts, "previous": previous_alerts, "change_direction": trend_direction(current_alerts, previous_alerts), "change_reason": "open alert count comparison", "confidence": confidence},
        "provider_failures": {"value": current_failures, "previous": previous_failures, "change_direction": trend_direction(current_failures, previous_failures), "change_reason": "provider failure count comparison", "confidence": confidence},
        "overall": {"change_direction": overall_direction, "change_reason": overall_reason, "confidence": confidence}
    })
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

/// Read-only operational health for agent integrations. This intentionally
/// exposes derived component state only; it never returns tokens, raw events,
/// or database fields.
async fn agent_health_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_SYSTEM_READ)?;
    let runtime = state
        .store
        .runtime_status_views()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "agent status unavailable"))?;
    let components = runtime
        .iter()
        .map(|component| {
            serde_json::json!({
                "component": component.get("component"),
                "state": component.get("state"),
                "last_heartbeat_at": component.get("last_heartbeat_at"),
                "updated_at": component.get("updated_at")
            })
        })
        .collect::<Vec<_>>();
    let unhealthy = runtime
        .iter()
        .filter(|component| {
            matches!(
                component.get("state").and_then(serde_json::Value::as_str),
                Some("error" | "stopped")
            )
        })
        .count();
    let agent_access = state.store.agent_access_status().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent access status unavailable",
        )
    })?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/agents/status",
        AGENT_SCOPE_SYSTEM_READ,
    )
    .await;
    Ok(envelope(
        serde_json::json!({
            "status": if unhealthy == 0 { "healthy" } else { "degraded" },
            "components": components,
            "agent": agent_access,
            "runtime_error_status": if unhealthy == 0 { "none" } else { "component_unhealthy" }
        }),
        None,
    ))
}

async fn agent_context(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_CONTEXT_READ)?;

    let migration = state
        .store
        .readiness()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "context unavailable"))?;
    let migration_response: MigrationResponse = migration.into();
    let runtime = state.store.runtime_status_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "context runtime unavailable",
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
    let event_status = state.store.event_status().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "context events unavailable",
        )
    })?;
    let providers = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "context providers unavailable",
        )
    })?;
    let incidents = state.store.list_incidents(None, 500).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "context incidents unavailable",
        )
    })?;
    let (active_incidents, incident_severity, correlations) = context_incident_data(&incidents);
    let indicators = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "context risk data unavailable",
        )
    })?;
    let trust = agent_network_values(&state, "trust").await?;
    let important_events = state.store.list_events(None, 100).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "context event data unavailable",
        )
    })?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/context",
        AGENT_SCOPE_CONTEXT_READ,
    )
    .await;
    Ok(envelope(
        serde_json::json!({
            "system": {
                "service": "clawforge",
                "version": env!("CARGO_PKG_VERSION"),
                "status": "ok",
                "migrations": migration_response,
                "runtime": runtime,
                "events": event_status,
                "providers": {
                    "total": providers.len(),
                    "enabled": providers.iter().filter(|provider| provider.get("enabled").and_then(serde_json::Value::as_bool) == Some(true)).count()
                }
            },
            "active_incidents": {
                "total": active_incidents.len(),
                "items": active_incidents.iter().take(50).collect::<Vec<_>>()
            },
            "open_incident_severity": incident_severity,
            "risk_scores": context_risk_data(&indicators),
            "trust": context_trust_data(&trust),
            "important_events": context_important_events(&important_events),
            "correlations": {
                "active_incidents": correlations
            }
        }),
        None,
    ))
}

async fn agent_decisions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_DECISION_READ)?;

    let migration = state
        .store
        .readiness()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "decision unavailable"))?;
    let migration_response: MigrationResponse = migration.into();
    let runtime = state.store.runtime_status_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "decision runtime unavailable",
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
    let event_status = state.store.event_status().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "decision events unavailable",
        )
    })?;
    let providers = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "decision providers unavailable",
        )
    })?;
    let incidents = state.store.list_incidents(None, 500).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "decision incidents unavailable",
        )
    })?;
    let indicators = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "decision risk data unavailable",
        )
    })?;
    let trust = agent_network_values(&state, "trust").await?;
    let important_events = state.store.list_events(None, 100).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "decision event data unavailable",
        )
    })?;
    let (active_incidents, incident_severity, correlations) = context_incident_data(&incidents);
    let risk_scores = context_risk_data(&indicators);
    let trust_summary = context_trust_data(&trust);
    let safe_events = context_important_events(&important_events);
    let risk_assessment = decision_risk_assessment(&incidents, &indicators);
    let overall_status = risk_assessment
        .get("overall_status")
        .cloned()
        .unwrap_or_else(|| serde_json::Value::from("info"));
    let attention_points = decision_attention_points(&incidents, &indicators, &important_events);
    let recommended_checks =
        decision_recommended_checks(&incidents, &indicators, &trust, &important_events);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/decisions",
        AGENT_SCOPE_DECISION_READ,
    )
    .await;
    Ok(envelope(
        serde_json::json!({
            "overall_status": overall_status,
            "risk_assessment": risk_assessment,
            "attention_points": attention_points,
            "recommended_checks": recommended_checks,
            "context": {
                "system": {
                    "service": "clawforge",
                    "version": env!("CARGO_PKG_VERSION"),
                    "status": "ok",
                    "migrations": migration_response,
                    "runtime": runtime,
                    "events": event_status,
                    "providers": {
                        "total": providers.len(),
                        "enabled": providers.iter().filter(|provider| provider.get("enabled").and_then(serde_json::Value::as_bool) == Some(true)).count()
                    }
                },
                "active_incidents": {
                    "total": active_incidents.len(),
                    "items": active_incidents.iter().take(50).collect::<Vec<_>>()
                },
                "open_incident_severity": incident_severity,
                "risk_scores": risk_scores,
                "trust": trust_summary,
                "important_events": safe_events,
                "correlations": { "active_incidents": correlations }
            }
        }),
        None,
    ))
}

async fn agent_provider_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_PROVIDER_READ)?;
    let mut values = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider status unavailable",
        )
    })?;
    values.retain(|value| {
        query.source.as_deref().is_none_or(|source| {
            value.get("source").and_then(serde_json::Value::as_str) == Some(source)
        }) && query.status.as_deref().is_none_or(|status| {
            value.get("status").and_then(serde_json::Value::as_str) == Some(status)
        })
    });
    let values = values.iter().map(agent_provider_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/providers",
        AGENT_SCOPE_PROVIDER_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn load_operations_summary(state: &AppState) -> ApiResult<serde_json::Value> {
    let migration = state
        .store
        .readiness()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "operations unavailable"))?;
    let migration_response: MigrationResponse = migration.into();
    let runtime = state.store.runtime_status_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations runtime unavailable",
        )
    })?;
    let event_status = state.store.event_status().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations events unavailable",
        )
    })?;
    let providers = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations providers unavailable",
        )
    })?;
    let incidents = state.store.list_incidents(None, 500).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations incidents unavailable",
        )
    })?;
    let indicators = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations risk data unavailable",
        )
    })?;
    let trust = agent_network_values(state, "trust").await?;
    let events = state.store.list_events(None, 100).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations event data unavailable",
        )
    })?;
    let mut summary = operations_summary_data(&incidents, &indicators, &trust, &events, &providers);
    let alert_counts = state.store.alert_counts().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations alerts unavailable",
        )
    })?;
    let provider_health = summary
        .get("provider_health")
        .and_then(|value| value.get("failed"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let runtime_degraded = runtime
        .iter()
        .any(|value| value.get("state").and_then(serde_json::Value::as_str) == Some("error"));
    let system_status = if migration_response.current && !runtime_degraded {
        if provider_health > 0 {
            "degraded"
        } else {
            "ok"
        }
    } else {
        "unavailable"
    };
    let snapshots = state
        .store
        .list_operations_snapshots(None, None, 100)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "operations history unavailable",
            )
        })?;
    let trend = operations_trend(&summary, &snapshots);
    if let Some(object) = summary.as_object_mut() {
        object.insert(
            "system_status".into(),
            serde_json::Value::from(system_status),
        );
        object.insert(
            "system".into(),
            serde_json::json!({
                "status": system_status,
                "migrations": migration_response,
                "runtime": runtime,
                "events": event_status
            }),
        );
        object.insert("alerts".into(), alert_counts);
        object.insert("trend".into(), trend.clone());
        object.insert(
            "change_direction".into(),
            trend
                .get("overall")
                .and_then(|value| value.get("change_direction"))
                .cloned()
                .unwrap_or_else(|| serde_json::Value::from("stable")),
        );
        object.insert(
            "change_reason".into(),
            trend
                .get("overall")
                .and_then(|value| value.get("change_reason"))
                .cloned()
                .unwrap_or_else(|| serde_json::Value::from("no historical snapshot available")),
        );
        object.insert(
            "confidence".into(),
            trend
                .get("overall")
                .and_then(|value| value.get("confidence"))
                .cloned()
                .unwrap_or_else(|| serde_json::Value::from(0)),
        );
    }
    Ok(summary)
}

fn parse_agent_time(value: Option<&str>) -> ApiResult<Option<DateTime<Utc>>> {
    value
        .map(|raw| {
            DateTime::parse_from_rfc3339(raw)
                .map(|parsed| parsed.with_timezone(&Utc))
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid RFC3339 time filter"))
        })
        .transpose()
}

fn parse_agent_uuid(value: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(value)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid incident identifier"))
}

async fn agent_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_OPERATIONS_READ)?;
    let from = parse_agent_time(query.from.as_deref())?;
    let to = parse_agent_time(query.to.as_deref())?;
    let mut values = state
        .store
        .list_operations_snapshots(from, to, 2000)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "operations history unavailable",
            )
        })?;
    if let Some(interval) = query.interval.as_deref() {
        let seconds = match interval {
            "5m" => 300,
            "15m" => 900,
            "hour" | "1h" => 3600,
            "day" | "1d" => 86_400,
            _ => {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "interval must be 5m, 15m, hour, or day",
                ))
            }
        };
        let mut seen = std::collections::HashSet::new();
        values.retain(|value| {
            let timestamp = value
                .get("timestamp")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let bucket = DateTime::parse_from_rfc3339(timestamp)
                .ok()
                .map(|time| time.timestamp() / seconds);
            bucket.is_some_and(|key| seen.insert(key))
        });
    }
    let (page, page_size) = agent_page(&query, 100);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/history",
        AGENT_SCOPE_OPERATIONS_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

fn safe_alert_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"),
        "source": value.get("source"),
        "severity": value.get("severity"),
        "status": value.get("status"),
        "created_at": value.get("created_at"),
        "updated_at": value.get("updated_at"),
        "delivery_status": value.get("delivery_status"),
        "summary": value.get("summary"),
        "confidence": value.get("confidence"),
        "event_count": value.get("event_count"),
        "group_id": value.get("group_id"),
        "root_cause": value.get("root_cause")
    })
}

fn replay_view(
    incident: &serde_json::Value,
    timeline: &[serde_json::Value],
    alerts: &[serde_json::Value],
    providers: &[serde_json::Value],
) -> serde_json::Value {
    let safe_timeline = timeline
        .iter()
        .map(agent_incident_timeline_view)
        .collect::<Vec<_>>();
    let relations = safe_timeline
        .iter()
        .filter(|entry| entry.get("kind").and_then(serde_json::Value::as_str) == Some("relation"))
        .cloned()
        .collect::<Vec<_>>();
    let first_event = relations.first().cloned();
    let indicators = relations
        .iter()
        .filter_map(|entry| entry.get("indicator"))
        .filter(|value| !value.is_null())
        .cloned()
        .collect::<Vec<_>>();
    let source_names = relations
        .iter()
        .filter_map(|entry| entry.get("source").and_then(serde_json::Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let provider_origins = providers
        .iter()
        .filter(|provider| {
            provider
                .get("source")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|source| source_names.contains(source))
        })
        .map(agent_provider_view)
        .collect::<Vec<_>>();
    let incident_id = incident
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let alert_views = alerts
        .iter()
        .filter(|alert| {
            alert.get("incident_id").and_then(serde_json::Value::as_str) == Some(incident_id)
        })
        .map(safe_alert_view)
        .collect::<Vec<_>>();
    let status_changes = safe_timeline
        .iter()
        .filter(|entry| entry.get("kind").and_then(serde_json::Value::as_str) == Some("status"))
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "incident": agent_incident_view(incident),
        "reason": incident.get("summary"),
        "first_event": first_event,
        "events": relations,
        "correlation_chain": safe_timeline.iter().filter(|entry| entry.get("kind").and_then(serde_json::Value::as_str) == Some("relation")).map(|entry| serde_json::json!({"timestamp": entry.get("timestamp"), "relation_type": entry.get("relation_type"), "event_id": entry.get("event_id"), "source": entry.get("source"), "confidence": entry.get("confidence"), "reason": entry.get("reason")})).collect::<Vec<_>>(),
        "indicators": indicators,
        "risk_assessment": {"severity": incident.get("severity"), "risk_score": incident.get("risk_score"), "confidence": incident.get("confidence")},
        "provider_origins": provider_origins,
        "alerts": alert_views,
        "status_changes": status_changes,
        "timeline": safe_timeline
    })
}

async fn agent_incident_replay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_INCIDENT_REPLAY)?;
    let id = parse_agent_uuid(&raw_id)?;
    let incident = state
        .store
        .get_incident(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident replay unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    let timeline = state
        .store
        .incident_timeline(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident replay unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    let alerts = state
        .store
        .list_alerts(None, None, 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident alerts unavailable",
            )
        })?;
    let providers = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "incident providers unavailable",
        )
    })?;
    audit_agent_read(
        &state,
        &principal,
        &format!("/api/v1/incidents/{id}/replay"),
        AGENT_SCOPE_INCIDENT_REPLAY,
    )
    .await;
    Ok(envelope(
        replay_view(&incident, &timeline, &alerts, &providers),
        None,
    ))
}

async fn agent_history_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_HISTORY_READ)?;
    let from = parse_agent_time(query.from.as_deref())?;
    let to = parse_agent_time(query.to.as_deref())?;
    let mut snapshots = state
        .store
        .list_operations_snapshots(from, to, 2000)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "operations history unavailable",
            )
        })?;
    if let Some(interval) = query.interval.as_deref() {
        let seconds = match interval {
            "hour" | "1h" => 3600,
            "day" | "1d" => 86_400,
            "week" | "1w" => 604_800,
            _ => {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "interval must be hour, day, or week",
                ))
            }
        };
        let mut seen = std::collections::HashSet::new();
        snapshots.retain(|value| {
            value
                .get("timestamp")
                .and_then(serde_json::Value::as_str)
                .and_then(|time| DateTime::parse_from_rfc3339(time).ok())
                .map(|time| seen.insert(time.timestamp() / seconds))
                .unwrap_or(false)
        });
    }
    let current = snapshots
        .first()
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let baseline = snapshots
        .last()
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let current_summary = serde_json::json!({"risk_level": current.get("risk_level"), "active_incidents": current.get("active_incident_count"), "alerts": {"open": current.get("alert_count")}, "provider_health": current.get("provider_health")});
    let trends = operations_trend(
        &current_summary,
        if snapshots.len() > 1 {
            &snapshots[1..]
        } else {
            &[]
        },
    );
    let anomalies = [
        "risk_level",
        "active_incidents",
        "alerts",
        "provider_failures",
    ]
    .iter()
    .filter_map(|key| {
        trends.get(*key).filter(|value| {
            value
                .get("change_direction")
                .and_then(serde_json::Value::as_str)
                == Some("increasing")
        })
    })
    .cloned()
    .collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 100);
    let (data, pagination) = paged_values(snapshots, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/history/summary",
        AGENT_SCOPE_HISTORY_READ,
    )
    .await;
    Ok(envelope(
        serde_json::json!({"period": {"from": from, "to": to, "interval": query.interval}, "current": current, "baseline": baseline, "trends": trends, "changes": {"snapshots": data}, "anomalies": anomalies, "snapshots_count": pagination.total}),
        None,
    ))
}

async fn agent_security_briefing(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_SECURITY_BRIEFING)?;
    let incidents = state.store.list_incidents(None, 500).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security briefing unavailable",
        )
    })?;
    let indicators = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security briefing unavailable",
        )
    })?;
    let providers = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security briefing unavailable",
        )
    })?;
    let snapshots = state
        .store
        .list_operations_snapshots(None, None, 2)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "security briefing unavailable",
            )
        })?;
    let active = incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
        .map(agent_incident_view)
        .take(10)
        .collect::<Vec<_>>();
    let findings = indicators
        .iter()
        .filter(|value| value.get("status").and_then(serde_json::Value::as_str) == Some("active"))
        .map(agent_finding_view)
        .take(10)
        .collect::<Vec<_>>();
    let provider_problems = providers
        .iter()
        .filter(|value| {
            matches!(
                value.get("status").and_then(serde_json::Value::as_str),
                Some("error" | "failed" | "degraded")
            )
        })
        .map(agent_provider_view)
        .collect::<Vec<_>>();
    let summary = load_operations_summary(&state).await?;
    let trends = operations_trend(
        &summary,
        if snapshots.len() > 1 {
            &snapshots[1..]
        } else {
            &[]
        },
    );
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/security/briefing",
        AGENT_SCOPE_SECURITY_BRIEFING,
    )
    .await;
    Ok(envelope(
        serde_json::json!({"current_status": summary.get("overall_status"), "risk_level": summary.get("risk_level"), "top_incidents": active, "new_findings": findings, "provider_problems": provider_problems, "changes_since_last_analysis": trends, "uncertainties": if snapshots.is_empty() { vec!["no operations snapshot available"] } else { Vec::<&str>::new() }}),
        None,
    ))
}

async fn agent_system_graph(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_SYSTEM_GRAPH)?;
    let runtime = state
        .store
        .runtime_status_views()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "system graph unavailable"))?;
    let providers = state
        .store
        .list_provider_views()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "system graph unavailable"))?;
    let mut nodes = vec![
        serde_json::json!({"id":"api","type":"service","status":"running"}),
        serde_json::json!({"id":"postgres","type":"database","status":"internal"}),
        serde_json::json!({"id":"mcp","type":"service","status":"read_only"}),
    ];
    nodes.extend(runtime.iter().filter_map(|value| value.get("component").and_then(serde_json::Value::as_str).map(|component| serde_json::json!({"id":component,"type":"service","status":value.get("state")}))));
    nodes.extend(providers.iter().filter_map(|value| value.get("id").and_then(serde_json::Value::as_str).map(|id| serde_json::json!({"id":format!("provider:{id}"),"type":"provider","status":value.get("status")}))));
    let edges = vec![
        serde_json::json!({"from":"api","to":"postgres","relationship":"requires"}),
        serde_json::json!({"from":"mcp","to":"api","relationship":"reads"}),
        serde_json::json!({"from":"worker","to":"postgres","relationship":"requires"}),
    ];
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/system/graph",
        AGENT_SCOPE_SYSTEM_GRAPH,
    )
    .await;
    Ok(envelope(
        serde_json::json!({"nodes": nodes, "edges": edges, "generated_at": Utc::now()}),
        None,
    ))
}

async fn admin_security_briefing(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let summary = load_operations_summary(&state).await?;
    let incidents = state.store.list_incidents(None, 500).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security briefing unavailable",
        )
    })?;
    let providers = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security briefing unavailable",
        )
    })?;
    let active = incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
        .map(agent_incident_view)
        .take(10)
        .collect::<Vec<_>>();
    let provider_problems = providers
        .iter()
        .filter(|value| {
            matches!(
                value.get("status").and_then(serde_json::Value::as_str),
                Some("error" | "failed" | "degraded")
            )
        })
        .map(agent_provider_view)
        .collect::<Vec<_>>();
    audit(
        &state,
        &principal,
        "security_briefing_read",
        "security/briefing",
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"current_status": summary.get("overall_status"), "risk_level": summary.get("risk_level"), "top_incidents": active, "new_findings": [], "provider_problems": provider_problems, "changes_since_last_analysis": summary.get("trend"), "uncertainties": []}),
        None,
    ))
}

async fn admin_system_graph(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let runtime = state
        .store
        .runtime_status_views()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "system graph unavailable"))?;
    let providers = state
        .store
        .list_provider_views()
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "system graph unavailable"))?;
    let mut nodes = vec![
        serde_json::json!({"id":"api","type":"service","status":"running"}),
        serde_json::json!({"id":"postgres","type":"database","status":"internal"}),
        serde_json::json!({"id":"mcp","type":"service","status":"read_only"}),
    ];
    nodes.extend(runtime.iter().filter_map(|value| value.get("component").and_then(serde_json::Value::as_str).map(|component| serde_json::json!({"id":component,"type":"service","status":value.get("state")}))));
    nodes.extend(providers.iter().filter_map(|value| value.get("id").and_then(serde_json::Value::as_str).map(|id| serde_json::json!({"id":format!("provider:{id}"),"type":"provider","status":value.get("status")}))));
    audit(
        &state,
        &principal,
        "system_graph_read",
        "system/graph",
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"nodes": nodes, "edges": [{"from":"api","to":"postgres","relationship":"requires"},{"from":"mcp","to":"api","relationship":"reads"},{"from":"worker","to":"postgres","relationship":"requires"}], "generated_at": Utc::now()}),
        None,
    ))
}

async fn agent_security_posture(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_SECURITY_READ)?;
    let values = state.store.list_indicator_views(1000).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security posture unavailable",
        )
    })?;
    let active = values
        .iter()
        .filter(|value| value.get("status").and_then(serde_json::Value::as_str) == Some("active"))
        .count();
    let highest_risk = values
        .iter()
        .filter_map(|value| value.get("risk_score").and_then(serde_json::Value::as_i64))
        .max()
        .unwrap_or(0);
    let mut by_severity = serde_json::Map::new();
    for severity in ["info", "low", "medium", "high", "critical"] {
        by_severity.insert(
            severity.to_string(),
            serde_json::Value::from(
                values
                    .iter()
                    .filter(|value| {
                        value
                            .get("risk_score")
                            .and_then(serde_json::Value::as_i64)
                            .is_some_and(|score| risk_severity(score) == severity)
                    })
                    .count() as u64,
            ),
        );
    }
    let components = values
        .iter()
        .filter_map(|value| value.get("source").and_then(serde_json::Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let summary = load_operations_summary(&state).await?;
    let incidents = state.store.list_incidents(None, 500).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security posture unavailable",
        )
    })?;
    let providers = state.store.list_provider_views().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security posture unavailable",
        )
    })?;
    let trust = agent_network_values(&state, "trust").await?;
    let trend = summary.get("trend").cloned().unwrap_or_default();
    let active_incidents = incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
        .count();
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/security/posture",
        AGENT_SCOPE_SECURITY_READ,
    )
    .await;
    Ok(envelope(
        serde_json::json!({
            "findings_total": values.len(),
            "active_findings": active,
            "highest_risk_score": highest_risk,
            "risk_level": summary.get("risk_level").cloned().unwrap_or_else(|| serde_json::Value::from(risk_severity(highest_risk))),
            "incident_count": active_incidents,
            "alert_count": summary.get("alerts").and_then(|value| value.get("open")).cloned().unwrap_or_else(|| serde_json::Value::from(0)),
            "provider_status": providers.iter().map(agent_provider_view).collect::<Vec<_>>(),
            "policy_status": {"status": "enforced", "source": "policy_engine"},
            "trust_summary": context_trust_data(&trust),
            "by_severity": by_severity,
            "affected_components": components,
            "trend": trend.get("risk_level").cloned().unwrap_or_default()
        }),
        None,
    ))
}

async fn agent_operations_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_OPERATIONS_READ)?;
    let summary = load_operations_summary(&state).await?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/operations/summary",
        AGENT_SCOPE_OPERATIONS_READ,
    )
    .await;
    Ok(envelope(summary, None))
}

async fn agent_operations_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_OPERATIONS_STATE)?;
    let summary = load_operations_summary(&state).await?;
    let state_view = state.store.operations_state().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations state unavailable",
        )
    })?;
    let mut combined = state_view;
    if let Some(object) = combined.as_object_mut() {
        object.insert(
            "system_state".into(),
            summary
                .get("overall_status")
                .cloned()
                .unwrap_or_else(|| serde_json::json!("unknown")),
        );
        object.insert(
            "risk_level".into(),
            summary
                .get("risk_level")
                .cloned()
                .unwrap_or_else(|| serde_json::json!("unknown")),
        );
        object.insert(
            "active_incidents".into(),
            summary
                .get("active_incidents")
                .cloned()
                .unwrap_or_else(|| serde_json::json!(0)),
        );
        object.insert(
            "recommended_actions".into(),
            summary
                .get("recommended_checks")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
        );
    }
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/operations/state",
        AGENT_SCOPE_OPERATIONS_STATE,
    )
    .await;
    Ok(envelope(combined, None))
}

/// Compact, read-only daily briefing assembled from the existing operations
/// summary and normalized event/provider views. No additional scoring or
/// action is performed here.
async fn agent_operations_briefing(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_OPERATIONS_BRIEFING)?;
    let summary = load_operations_summary(&state).await?;
    let incidents = state.store.list_incidents(None, 500).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations briefing unavailable",
        )
    })?;
    let events = state.store.list_events(None, 100).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations briefing unavailable",
        )
    })?;
    let active_incidents = incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
        .map(agent_incident_view)
        .take(20)
        .collect::<Vec<_>>();
    let active_incident_count = incidents
        .iter()
        .filter(|value| context_is_active_incident(value))
        .count();
    let recent_events = events
        .iter()
        .map(agent_event_view)
        .rev()
        .take(20)
        .collect::<Vec<_>>();
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/operations/briefing",
        AGENT_SCOPE_OPERATIONS_BRIEFING,
    )
    .await;
    Ok(envelope(
        serde_json::json!({
            "timestamp": Utc::now(),
            "overall_status": summary.get("overall_status"),
            "risk_level": summary.get("risk_level"),
            "active_incidents": {"count": active_incident_count, "items": active_incidents},
            "active_alerts": summary.get("alerts"),
            "recent_events": recent_events,
            "provider_health": summary.get("provider_health"),
            "security_changes": summary.get("trend"),
            "attention_points": summary.get("attention_points"),
            "recommended_checks": summary.get("recommended_checks")
        }),
        None,
    ))
}

async fn agent_knowledge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_KNOWLEDGE_READ)?;
    let values = state
        .store
        .list_knowledge_entries(500)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "knowledge unavailable"))?;
    let values = values
        .into_iter()
        .filter(|value| agent_time_matches(value, &query))
        .map(|mut value| {
            if let Some(object) = value.as_object_mut() {
                object.remove("related_incident");
                object.remove("tags");
            }
            value
        })
        .collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/knowledge",
        AGENT_SCOPE_KNOWLEDGE_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_provider_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider_id): Path<String>,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_PROVIDER_READ)?;
    if !valid_provider_identifier(&provider_id) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid provider identifier",
        ));
    }
    let values = state
        .store
        .list_provider_history(&provider_id, 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider history unavailable",
            )
        })?;
    let values = values
        .into_iter()
        .filter(|value| agent_time_matches(value, &query))
        .collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        &format!("/api/v1/providers/{provider_id}/history"),
        AGENT_SCOPE_PROVIDER_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

fn valid_provider_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        })
}

fn agent_decision_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"),
        "created_at": value.get("created_at"),
        "updated_at": value.get("updated_at"),
        "severity": value.get("severity"),
        "category": value.get("category"),
        "source": value.get("source"),
        "title": value.get("title"),
        "description": value.get("description"),
        "reason": value.get("reason"),
        "recommendation": value.get("recommendation"),
        "confidence": value.get("confidence"),
        "status": value.get("status"),
        "related_incident_id": value.get("related_incident_id")
    })
}

fn workflow_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"),
        "name": value.get("name"),
        "description": value.get("description"),
        "category": value.get("category"),
        "enabled": value.get("enabled"),
        "created_at": value.get("created_at"),
        "updated_at": value.get("updated_at"),
        "steps": value.get("steps").and_then(|steps| steps.as_array().map(|items| items.iter().map(|step| serde_json::json!({
            "id": step.get("id"), "name": step.get("name"), "step_order": step.get("step_order"),
            "type": step.get("type"), "required_approval": step.get("required_approval"),
            "created_at": step.get("created_at")
        })).collect::<Vec<_>>()))
    })
}

fn workflow_run_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"), "workflow_id": value.get("workflow_id"),
        "workflow_name": value.get("workflow_name"), "category": value.get("category"),
        "decision_id": value.get("decision_id"), "status": value.get("status"),
        "started_at": value.get("started_at"), "finished_at": value.get("finished_at")
    })
}

fn validate_workflow_query(query: &AgentQuery) -> ApiResult<Option<Uuid>> {
    if let Some(status) = query.status.as_deref() {
        if !matches!(
            status,
            "pending" | "running" | "waiting_approval" | "completed" | "failed" | "cancelled"
        ) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "invalid workflow run status",
            ));
        }
    }
    query
        .workflow_id
        .as_deref()
        .map(|value| {
            Uuid::parse_str(value)
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid workflow id"))
        })
        .transpose()
}

async fn admin_workflows(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let values = state
        .store
        .list_workflows(None, None, 100)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "workflow list unavailable"))?;
    let values = values.iter().map(workflow_view).collect::<Vec<_>>();
    audit(
        &state,
        &principal,
        "workflows_read",
        "workflows",
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(values, None))
}

async fn admin_workflow_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let workflow = state
        .store
        .list_workflows(Some(id), None, 1)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "workflow unavailable"))?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "workflow not found"))?;
    let mut value = workflow_view(&workflow);
    let runs = state
        .store
        .list_workflow_runs(Some(id), None, 100)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "workflow history unavailable",
            )
        })?;
    let audit_log = state
        .store
        .list_workflow_audit(id, 100)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "workflow audit unavailable",
            )
        })?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "runs".into(),
            serde_json::Value::Array(runs.iter().map(workflow_run_view).collect()),
        );
        object.insert("audit".into(), serde_json::Value::Array(audit_log));
    }
    audit(
        &state,
        &principal,
        "workflow_read",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(value, None))
}

async fn admin_workflow_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let workflow_id = validate_workflow_query(&query)?;
    let values = state
        .store
        .list_workflow_runs(workflow_id, query.status.as_deref(), 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "workflow history unavailable",
            )
        })?;
    let values = values.iter().map(workflow_run_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit(
        &state,
        &principal,
        "workflow_runs_read",
        "workflow-runs",
        serde_json::json!({"status":query.status,"workflow_id":workflow_id}),
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

#[derive(Deserialize)]
struct ApproveWorkflowRequest {
    run_id: Uuid,
    comment: Option<String>,
    decision_reason: Option<String>,
}

async fn admin_approve_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workflow_id): Path<Uuid>,
    Json(request): Json<ApproveWorkflowRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Approver"])?;
    if request
        .comment
        .as_deref()
        .is_some_and(|value| value.len() > 10_000)
        || request
            .decision_reason
            .as_deref()
            .is_some_and(|value| value.len() > 10_000)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "approval text is too long",
        ));
    }
    let value = state
        .store
        .approve_workflow_run(
            workflow_id,
            request.run_id,
            principal.id,
            &principal.username,
            request.comment.as_deref(),
            request.decision_reason.as_deref(),
        )
        .await
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("not found") {
                api_error(StatusCode::NOT_FOUND, "workflow run not found")
            } else {
                api_error(StatusCode::CONFLICT, "workflow approval is not available")
            }
        })?;
    audit(
        &state,
        &principal,
        "workflow_approved",
        &workflow_id.to_string(),
        serde_json::json!({"run_id":request.run_id}),
    )
    .await;
    Ok(envelope(value, None))
}

async fn agent_workflows(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_WORKFLOW_READ)?;
    let values = state
        .store
        .list_workflows(None, Some(true), 100)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "workflow list unavailable"))?;
    let values = values.iter().map(workflow_view).collect::<Vec<_>>();
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/workflows",
        AGENT_SCOPE_WORKFLOW_READ,
    )
    .await;
    Ok(envelope(values, None))
}

async fn agent_workflow_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_WORKFLOW_READ)?;
    let workflow = state
        .store
        .list_workflows(Some(id), Some(true), 1)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "workflow unavailable"))?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "workflow not found"))?;
    let mut value = workflow_view(&workflow);
    let runs = state
        .store
        .list_workflow_runs(Some(id), None, 100)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "workflow history unavailable",
            )
        })?;
    let audit_log = state
        .store
        .list_workflow_audit(id, 100)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "workflow audit unavailable",
            )
        })?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "runs".into(),
            serde_json::Value::Array(runs.iter().map(workflow_run_view).collect()),
        );
        object.insert("audit".into(), serde_json::Value::Array(audit_log));
    }
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/workflows/{id}",
        AGENT_SCOPE_WORKFLOW_READ,
    )
    .await;
    Ok(envelope(value, None))
}

async fn agent_workflow_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_WORKFLOW_READ)?;
    let workflow_id = validate_workflow_query(&query)?;
    let values = state
        .store
        .list_workflow_runs(workflow_id, query.status.as_deref(), 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "workflow history unavailable",
            )
        })?;
    let values = values.iter().map(workflow_run_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/workflow-runs",
        AGENT_SCOPE_WORKFLOW_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

fn connector_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"),
        "name": value.get("name"),
        "version": value.get("version"),
        "type": value.get("type"),
        "status": value.get("status"),
        "health": value.get("health"),
        "last_check": value.get("last_check"),
        "health_checked_at": value.get("health_checked_at"),
        "latency_ms": value.get("latency_ms"),
        "description": value.get("description"),
        "read_only": true,
        "capabilities": value.get("capabilities"),
        "permissions": value.get("permissions")
    })
}

fn connector_health_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"),
        "name": value.get("name"),
        "type": value.get("type"),
        "status": value.get("health"),
        "last_check": value.get("health_checked_at").or_else(|| value.get("last_check")),
        "latency_ms": value.get("latency_ms"),
        "read_only": true
    })
}

async fn admin_connectors(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let values = state.store.list_connectors(None).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "connector registry unavailable",
        )
    })?;
    audit(
        &state,
        &principal,
        "connectors_read",
        "connectors",
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(values.iter().map(connector_view).collect(), None))
}

async fn admin_connector_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let value = state
        .store
        .list_connectors(Some(id))
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "connector unavailable"))?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "connector not found"))?;
    audit(
        &state,
        &principal,
        "connector_read",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(connector_view(&value), None))
}

async fn admin_connector_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let value = state
        .store
        .list_connectors(Some(id))
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "connector health unavailable",
            )
        })?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "connector not found"))?;
    audit(
        &state,
        &principal,
        "connector_health_read",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(connector_health_view(&value), None))
}

async fn admin_connector_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    if state
        .store
        .list_connectors(Some(id))
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "connector unavailable"))?
        .is_empty()
    {
        return Err(api_error(StatusCode::NOT_FOUND, "connector not found"));
    }
    let values = state
        .store
        .list_connector_capabilities(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "connector capabilities unavailable",
            )
        })?;
    audit(
        &state,
        &principal,
        "connector_capabilities_read",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(values, None))
}

async fn agent_connectors(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_CONNECTOR_READ)?;
    let values = state.store.list_connectors(None).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "connector registry unavailable",
        )
    })?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/connectors",
        AGENT_SCOPE_CONNECTOR_READ,
    )
    .await;
    Ok(envelope(values.iter().map(connector_view).collect(), None))
}

async fn agent_connector_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_CONNECTOR_READ)?;
    let value = state
        .store
        .list_connectors(Some(id))
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "connector unavailable"))?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "connector not found"))?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/connectors/{id}",
        AGENT_SCOPE_CONNECTOR_READ,
    )
    .await;
    Ok(envelope(connector_view(&value), None))
}

async fn agent_connector_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_CONNECTOR_READ)?;
    let value = state
        .store
        .list_connectors(Some(id))
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "connector health unavailable",
            )
        })?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "connector not found"))?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/connectors/{id}/health",
        AGENT_SCOPE_CONNECTOR_READ,
    )
    .await;
    Ok(envelope(connector_health_view(&value), None))
}

async fn agent_connector_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_CONNECTOR_READ)?;
    if state
        .store
        .list_connectors(Some(id))
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "connector unavailable"))?
        .is_empty()
    {
        return Err(api_error(StatusCode::NOT_FOUND, "connector not found"));
    }
    let values = state
        .store
        .list_connector_capabilities(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "connector capabilities unavailable",
            )
        })?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/connectors/{id}/capabilities",
        AGENT_SCOPE_CONNECTOR_READ,
    )
    .await;
    Ok(envelope(values, None))
}

fn action_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"), "connector_id": value.get("connector_id"), "connector_name": value.get("connector_name"),
        "name": value.get("name"), "type": value.get("type"), "description": value.get("description"),
        "risk_level": value.get("risk_level"), "required_scope": value.get("required_scope"),
        "requires_approval": value.get("requires_approval"), "enabled": value.get("enabled"),
        "created_at": value.get("created_at"), "updated_at": value.get("updated_at")
    })
}

fn execution_view(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": value.get("id"), "action_id": value.get("action_id"), "action_name": value.get("action_name"),
        "workflow_run_id": value.get("workflow_run_id"), "decision_id": value.get("decision_id"),
        "requested_by": value.get("requested_by"), "status": value.get("status"), "risk_level": value.get("risk_level"),
        "requires_approval": value.get("requires_approval"), "created_at": value.get("created_at"),
        "started_at": value.get("started_at"), "finished_at": value.get("finished_at"),
        "result_summary": value.get("result_summary"), "error_summary": value.get("error_summary"),
        "retry_count": value.get("retry_count"), "max_retries": value.get("max_retries"),
        "timeout_seconds": value.get("timeout_seconds"), "next_retry_at": value.get("next_retry_at")
    })
}

async fn admin_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let values = state
        .store
        .list_actions(None, None, 200)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "action registry unavailable",
            )
        })?;
    audit(
        &state,
        &principal,
        "actions_read",
        "actions",
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(values.iter().map(action_view).collect(), None))
}

async fn admin_executions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    validate_execution_status(query.status.as_deref())?;
    let values = state
        .store
        .list_execution_requests(None, query.status.as_deref(), 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "execution history unavailable",
            )
        })?;
    audit(
        &state,
        &principal,
        "executions_read",
        "executions",
        serde_json::json!({"status":query.status}),
    )
    .await;
    let values = values.iter().map(execution_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    Ok(envelope(data, Some(pagination)))
}

async fn agent_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_ACTION_READ)?;
    let values = state
        .store
        .list_actions(None, None, 200)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "action registry unavailable",
            )
        })?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/actions",
        AGENT_SCOPE_ACTION_READ,
    )
    .await;
    Ok(envelope(values.iter().map(action_view).collect(), None))
}

async fn agent_action_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_ACTION_READ)?;
    let value = state
        .store
        .list_actions(Some(id), None, 1)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "action unavailable"))?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "action not found"))?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/actions/{id}",
        AGENT_SCOPE_ACTION_READ,
    )
    .await;
    Ok(envelope(action_view(&value), None))
}

async fn agent_executions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_EXECUTION_READ)?;
    validate_execution_status(query.status.as_deref())?;
    let status = query.status.as_deref();
    let values = state
        .store
        .list_execution_requests(None, status, 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "execution history unavailable",
            )
        })?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/executions",
        AGENT_SCOPE_EXECUTION_READ,
    )
    .await;
    let values = values.iter().map(execution_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    Ok(envelope(data, Some(pagination)))
}

fn validate_execution_status(status: Option<&str>) -> ApiResult<()> {
    if let Some(status) = status {
        if !matches!(
            status,
            "pending"
                | "waiting_approval"
                | "approved"
                | "queued"
                | "starting"
                | "running"
                | "success"
                | "completed"
                | "failed"
                | "timeout"
                | "rollback_required"
                | "cancelled"
        ) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "invalid execution status",
            ));
        }
    }
    Ok(())
}

async fn agent_execution_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_EXECUTION_READ)?;
    let value = state
        .store
        .list_execution_requests(Some(id), None, 1)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "execution unavailable"))?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "execution not found"))?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/executions/{id}",
        AGENT_SCOPE_EXECUTION_READ,
    )
    .await;
    Ok(envelope(execution_view(&value), None))
}

#[derive(Debug, Deserialize)]
struct ExecutionRequestBody {
    action_id: Uuid,
    workflow_run_id: Option<Uuid>,
    decision_id: Option<Uuid>,
    idempotency_key: Option<String>,
}

async fn admin_create_execution(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExecutionRequestBody>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    let action = state
        .store
        .list_actions(Some(body.action_id), None, 1)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "action unavailable"))?
        .into_iter()
        .next()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "action not found"))?;
    let name = action
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    authorize_action(name, &principal.role)
        .map_err(|_| api_error(StatusCode::FORBIDDEN, "action policy denied"))?;
    if action.get("enabled").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(api_error(StatusCode::CONFLICT, "action is disabled"));
    }
    let id = state
        .store
        .create_execution_request(&clawforge_storage::ExecutionRequestInput {
            action_id: body.action_id,
            workflow_run_id: body.workflow_run_id,
            decision_id: body.decision_id,
            requested_by: principal.username.clone(),
            idempotency_key: body.idempotency_key,
        })
        .await
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "execution request rejected"))?;
    audit(
        &state,
        &principal,
        "execution_request_created",
        &id.to_string(),
        serde_json::json!({"action_id":body.action_id}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":id,"status":action.get("requires_approval").and_then(serde_json::Value::as_bool).map(|v| if v {"waiting_approval"} else {"pending"}).unwrap_or("pending")}),
        None,
    ))
}

async fn admin_execution_transition(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    status: &'static str,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    let allowed_roles = if status == "approved" {
        &["Administrator", "Approver"][..]
    } else {
        &["Administrator", "Operator"][..]
    };
    require_role(&principal, allowed_roles)?;
    state
        .store
        .update_execution_status(id, status, &principal.username, None, None)
        .await
        .map_err(|e| {
            if e.to_string().contains("not available") {
                api_error(
                    StatusCode::CONFLICT,
                    "execution state transition unavailable",
                )
            } else {
                api_error(
                    StatusCode::BAD_REQUEST,
                    "execution state transition rejected",
                )
            }
        })?;
    audit(
        &state,
        &principal,
        &format!("execution_request_{status}"),
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(serde_json::json!({"id":id,"status":status}), None))
}

async fn admin_approve_execution(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    admin_execution_transition(State(state), headers, Path(id), "approved").await
}
async fn admin_cancel_execution(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    admin_execution_transition(State(state), headers, Path(id), "cancelled").await
}

fn validate_decision_query(query: &AgentQuery) -> ApiResult<()> {
    if let Some(status) = query.status.as_deref() {
        if !matches!(
            status,
            "open" | "acknowledged" | "dismissed" | "resolved" | "expired"
        ) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "invalid decision status",
            ));
        }
    }
    if let Some(category) = query.category.as_deref() {
        if category.is_empty()
            || category.len() > 128
            || !category
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_' | '.'))
        {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "invalid decision category",
            ));
        }
    }
    Ok(())
}

async fn admin_operations_recommendations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    validate_decision_query(&query)?;
    let values = state
        .store
        .list_decisions(query.status.as_deref(), query.category.as_deref(), 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "recommendations unavailable",
            )
        })?;
    let values = values.iter().map(agent_decision_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit(
        &state,
        &principal,
        "operations_recommendations_read",
        "operations/recommendations",
        serde_json::json!({"category": query.category, "status": query.status}),
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_operations_recommendations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_OPERATIONS_RECOMMEND)?;
    validate_decision_query(&query)?;
    let status = query.status.as_deref().or(Some("open"));
    let values = state
        .store
        .list_decisions(status, query.category.as_deref(), 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "recommendations unavailable",
            )
        })?;
    let values = values.iter().map(agent_decision_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/operations/recommendations",
        AGENT_SCOPE_OPERATIONS_RECOMMEND,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_decision_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_OPERATIONS_RECOMMEND)?;
    validate_decision_query(&query)?;
    let values = state
        .store
        .list_decisions(query.status.as_deref(), query.category.as_deref(), 500)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "decision history unavailable",
            )
        })?;
    let values = values.iter().map(agent_decision_view).collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/decisions/history",
        AGENT_SCOPE_OPERATIONS_RECOMMEND,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn admin_operations_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let summary = load_operations_summary(&state).await?;
    audit(
        &state,
        &principal,
        "operations_summary_read",
        "operations",
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(summary, None))
}

async fn admin_operations_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let summary = load_operations_summary(&state).await?;
    let view = state.store.operations_state().await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operations state unavailable",
        )
    })?;
    audit(
        &state,
        &principal,
        "operations_state_read",
        "operations/state",
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"summary":summary,"state":view}),
        None,
    ))
}

#[derive(Deserialize)]
struct AlertQuery {
    status: Option<String>,
    severity: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
}

async fn admin_alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AlertQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let values = state
        .store
        .list_alerts(query.status.as_deref(), query.severity.as_deref(), 500)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "alerts unavailable"))?;
    audit(
        &state,
        &principal,
        "alerts_read",
        "alerts",
        serde_json::json!({"status": query.status, "severity": query.severity}),
    )
    .await;
    let (data, pagination) = paged_values(
        values,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(100).clamp(1, 100),
    );
    Ok(envelope(data, Some(pagination)))
}

#[derive(Deserialize)]
struct AlertStatusRequest {
    status: String,
    reason: Option<String>,
}

async fn admin_alert_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<AlertStatusRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    if request.reason.as_deref().unwrap_or("").chars().count() > 1000 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "alert reason is too long",
        ));
    }
    state
        .store
        .update_alert_status(
            id,
            request.status.trim(),
            &principal.username,
            request.reason.as_deref().unwrap_or(""),
        )
        .await
        .map_err(|error| {
            if error.to_string().contains("not found") {
                api_error(StatusCode::NOT_FOUND, "alert not found")
            } else {
                api_error(StatusCode::BAD_REQUEST, "invalid alert status")
            }
        })?;
    audit(
        &state,
        &principal,
        "alert_status_changed",
        &id.to_string(),
        serde_json::json!({"status": request.status, "reason": request.reason}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id": id, "status": request.status}),
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
    require_agent_incident_scope(&principal)?;
    let status =
        match query.status.as_deref() {
            Some(value) => Some(canonical_incident_status(value).ok_or_else(|| {
                api_error(StatusCode::BAD_REQUEST, "invalid incident status filter")
            })?),
            None => None,
        };
    let mut values = state
        .store
        .list_incidents(status, 500)
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
        AGENT_SCOPE_INCIDENT_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_incident_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_incident_scope(&principal)?;
    let id = parse_agent_uuid(&raw_id)?;
    let value = state
        .store
        .get_incident(id)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "incident unavailable"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    audit_agent_read(
        &state,
        &principal,
        &format!("/api/v1/incidents/{id}"),
        AGENT_SCOPE_INCIDENT_READ,
    )
    .await;
    Ok(envelope(agent_incident_view(&value), None))
}

async fn agent_incident_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_incident_scope(&principal)?;
    let id = parse_agent_uuid(&raw_id)?;
    let timeline = state
        .store
        .incident_timeline(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident timeline unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    let mut values = timeline
        .iter()
        .filter(|value| {
            query.status.as_deref().is_none_or(|status| {
                value
                    .get("data")
                    .and_then(|data| data.get("status"))
                    .and_then(serde_json::Value::as_str)
                    == Some(status)
            }) && query.severity.as_deref().is_none_or(|severity| {
                value
                    .get("data")
                    .and_then(|data| data.get("severity"))
                    .and_then(serde_json::Value::as_str)
                    == Some(severity)
            }) && agent_time_matches(value, &query)
        })
        .map(agent_incident_timeline_view)
        .collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(std::mem::take(&mut values), page, page_size);
    audit_agent_read(
        &state,
        &principal,
        &format!("/api/v1/incidents/{id}/timeline"),
        AGENT_SCOPE_INCIDENT_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn agent_incident_relations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_incident_scope(&principal)?;
    let id = parse_agent_uuid(&raw_id)?;
    let timeline = state
        .store
        .incident_timeline(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident relations unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    let values = timeline
        .iter()
        .filter(|value| {
            value.get("kind").and_then(serde_json::Value::as_str) == Some("relation")
                && query.relation_type.as_deref().is_none_or(|relation_type| {
                    value
                        .get("data")
                        .and_then(|data| data.get("relation_type"))
                        .and_then(serde_json::Value::as_str)
                        == Some(relation_type)
                })
                && query.severity.as_deref().is_none_or(|severity| {
                    value
                        .get("data")
                        .and_then(|data| data.get("severity"))
                        .and_then(serde_json::Value::as_str)
                        == Some(severity)
                })
                && agent_time_matches(value, &query)
        })
        .map(agent_incident_timeline_view)
        .collect::<Vec<_>>();
    let (page, page_size) = agent_page(&query, 50);
    let (data, pagination) = paged_values(values, page, page_size);
    audit_agent_read(
        &state,
        &principal,
        &format!("/api/v1/incidents/{id}/relations"),
        AGENT_SCOPE_INCIDENT_READ,
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

async fn agent_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_NETWORK_READ)?;
    let mut values = agent_network_values(&state, "trust").await?;
    values.retain(|value| {
        query.status.as_deref().is_none_or(|status| {
            value.get("status").and_then(serde_json::Value::as_str) == Some(status)
        }) && query.network_type.as_deref().is_none_or(|network_type| {
            value.get("type").and_then(serde_json::Value::as_str) == Some(network_type)
        }) && agent_time_matches(value, &query)
    });
    let values = values
        .iter()
        // Trust registry internals (node identities, device tags, groups and
        // raw network lists) stay inside the API/storage boundary.
        .map(|value| {
            agent_network_view(
                value,
                &[
                    "id",
                    "name",
                    "type",
                    "identifier",
                    "source",
                    "status",
                    "created_at",
                    "verified_at",
                    "timestamp",
                    "age_seconds",
                    "confidence",
                    "trust_score",
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
        "/api/v1/network/trust",
        AGENT_SCOPE_NETWORK_READ,
    )
    .await;
    Ok(envelope(data, Some(pagination)))
}

async fn metrics(State(state): State<AppState>) -> Result<Response, StatusCode> {
    let mut body = state.store.metrics_text().await.map_err(|error| {
        tracing::error!(%error, "metrics collection failed");
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    body.push_str(&format!(
        "# TYPE clawforge_api_requests_total counter\nclawforge_api_requests_total {}\n# TYPE clawforge_api_errors_total counter\nclawforge_api_errors_total {}\n# TYPE clawforge_api_rate_limited_total counter\nclawforge_api_rate_limited_total {}\n# TYPE clawforge_api_response_duration_seconds_sum counter\nclawforge_api_response_duration_seconds_sum {:.6}\n# TYPE clawforge_api_response_duration_seconds_count counter\nclawforge_api_response_duration_seconds_count {}\n# TYPE clawforge_api_auth_failures_total counter\nclawforge_api_auth_failures_total {}\n",
        API_REQUESTS.load(Ordering::Relaxed),
        API_ERRORS.load(Ordering::Relaxed),
        API_RATE_LIMITED.load(Ordering::Relaxed),
        API_RESPONSE_TIME_US.load(Ordering::Relaxed) as f64 / 1_000_000.0,
        API_RESPONSE_COUNT.load(Ordering::Relaxed),
        API_AUTH_FAILURES.load(Ordering::Relaxed),
    ));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(body.into())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn agent_metrics(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let principal = authenticate_agent(&state, &headers).await?;
    require_agent_scope(&principal, AGENT_SCOPE_METRICS_READ)?;
    audit_agent_read(
        &state,
        &principal,
        "/api/v1/metrics",
        AGENT_SCOPE_METRICS_READ,
    )
    .await;
    metrics(State(state))
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable"))
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
    let token = bearer(headers).ok_or_else(|| {
        API_AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        api_error(StatusCode::UNAUTHORIZED, "bearer token required")
    })?;
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
        .ok_or_else(|| {
            API_AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
            api_error(StatusCode::UNAUTHORIZED, "invalid or expired credential")
        })
}

async fn authenticate_agent(state: &AppState, headers: &HeaderMap) -> ApiResult<AgentPrincipal> {
    let token = bearer(headers).ok_or_else(|| {
        API_AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        api_error(StatusCode::UNAUTHORIZED, "agent bearer token required")
    })?;
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
        .ok_or_else(|| {
            API_AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
            api_error(StatusCode::UNAUTHORIZED, "invalid or expired agent token")
        })
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

fn require_agent_scope_any(principal: &AgentPrincipal, scopes: &[&str]) -> ApiResult<()> {
    if principal
        .scopes
        .iter()
        .any(|value| value == AGENT_SCOPE_ALL_READ || scopes.iter().any(|scope| value == scope))
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
    if roles.iter().any(|role| *role == principal.role)
        || (principal.role == "Approver" && roles.contains(&"Viewer"))
    {
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
        "Administrator" | "Operator" | "Approver" | "Viewer"
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
    action: Option<String>,
    result: Option<String>,
    scope: Option<String>,
    limit: Option<i64>,
    page: Option<i64>,
    page_size: Option<i64>,
    format: Option<String>,
}

fn audit_scope_matches(value: &serde_json::Value, scope: Option<&str>) -> bool {
    scope.is_none_or(|wanted| {
        value
            .get("details")
            .and_then(|details| details.get("scope"))
            .and_then(serde_json::Value::as_str)
            == Some(wanted)
    })
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
            AuditEventFilter {
                from: query.from,
                to: query.to,
                source: query.source.as_deref(),
                severity: query.severity.as_deref(),
                actor: query.user.as_deref(),
                action: query.action.as_deref(),
                result: query.result.as_deref(),
            },
            500,
        )
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "audit events unavailable"))?;
    let values = values
        .into_iter()
        .filter(|value| audit_scope_matches(value, query.scope.as_deref()))
        .collect::<Vec<_>>();
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
    let status =
        match query.status.as_deref() {
            Some(value) => Some(canonical_incident_status(value).ok_or_else(|| {
                api_error(StatusCode::BAD_REQUEST, "invalid incident status filter")
            })?),
            None => None,
        };
    let values = state.store.list_incidents(status, 500).await.map_err(|_| {
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
            AuditEventFilter {
                from: query.from,
                to: query.to,
                source: query.source.as_deref(),
                severity: query.severity.as_deref(),
                actor: query.user.as_deref(),
                action: query.action.as_deref(),
                result: query.result.as_deref(),
            },
            500,
        )
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "audit export unavailable"))?;
    let values = values
        .into_iter()
        .filter(|value| audit_scope_matches(value, query.scope.as_deref()))
        .collect::<Vec<_>>();
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
    source: Option<String>,
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
    let status =
        match query.status.as_deref() {
            Some(value) => Some(canonical_incident_status(value).ok_or_else(|| {
                api_error(StatusCode::BAD_REQUEST, "invalid incident status filter")
            })?),
            None => None,
        };
    let mut values = state
        .store
        .list_incidents(status, 500)
        .await
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "incident list unavailable"))?;
    values.retain(|value| {
        let timestamp = value
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        query.severity.as_deref().is_none_or(|severity| {
            value.get("severity").and_then(serde_json::Value::as_str) == Some(severity)
        }) && query.source.as_deref().is_none_or(|source| {
            value
                .get("source")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|sources| sources.split(", ").any(|candidate| candidate == source))
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

async fn incident_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<Vec<serde_json::Value>>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator", "Viewer"])?;
    let timeline = state
        .store
        .incident_timeline(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident timeline unavailable",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "incident not found"))?;
    audit(
        &state,
        &principal,
        "incident_timeline_read",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(timeline, None))
}

async fn incident_status_history(
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
    let history = state
        .store
        .list_incident_status_history(id)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident history unavailable",
            )
        })?;
    audit(
        &state,
        &principal,
        "incident_status_history_read",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(history, None))
}

async fn incident_notes(
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
    let notes = state.store.list_incident_notes(id).await.map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "incident notes unavailable",
        )
    })?;
    audit(
        &state,
        &principal,
        "incident_notes_read",
        &id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(envelope(notes, None))
}

#[derive(Deserialize)]
struct IncidentNoteRequest {
    body: String,
}

async fn add_incident_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<IncidentNoteRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    let note_id = state
        .store
        .add_incident_note(id, &principal.username, &request.body)
        .await
        .map_err(|error| {
            if error.to_string().contains("not found") {
                api_error(StatusCode::NOT_FOUND, "incident not found")
            } else {
                api_error(StatusCode::BAD_REQUEST, "invalid incident note")
            }
        })?;
    audit(
        &state,
        &principal,
        "incident_note_added",
        &id.to_string(),
        serde_json::json!({"note_id":note_id}),
    )
    .await;
    Ok(envelope(
        serde_json::json!({"id":note_id,"incident_id":id}),
        None,
    ))
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
    reason: Option<String>,
}

fn canonical_incident_status(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "open" | "detected" => Some("detected"),
        "acknowledged" => Some("acknowledged"),
        "investigating" => Some("investigating"),
        "confirmed" => Some("confirmed"),
        "mitigated" => Some("mitigated"),
        "resolved" => Some("resolved"),
        "ignored" | "closed" => Some("closed"),
        _ => None,
    }
}

async fn update_incident_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<IncidentStatusRequest>,
) -> ApiResult<Json<ApiEnvelope<serde_json::Value>>> {
    let principal = authenticate(&state, &headers).await?;
    require_role(&principal, &["Administrator", "Operator"])?;
    let reason = request.reason.as_deref().unwrap_or("").trim();
    state
        .store
        .transition_incident_status(id, &request.status, &principal.username, reason)
        .await
        .map_err(|error| {
            if error.to_string().contains("not found") {
                api_error(StatusCode::NOT_FOUND, "incident not found")
            } else {
                api_error(StatusCode::BAD_REQUEST, "invalid incident status")
            }
        })?;
    let status = canonical_incident_status(&request.status).unwrap_or(&request.status);
    audit(
        &state,
        &principal,
        "incident_status_changed",
        &id.to_string(),
        serde_json::json!({"status":status,"reason":reason}),
    )
    .await;
    Ok(envelope(serde_json::json!({"id":id,"status":status}), None))
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

/// Replace framework extractor diagnostics with the stable API error contract.
/// Axum's default path/query rejection includes parser details and echoed input
/// values, which are useful for debugging but can disclose implementation
/// details to unauthenticated callers.
async fn sanitize_framework_errors(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() != StatusCode::BAD_REQUEST {
        return response;
    }
    let (parts, body) = response.into_parts();
    let bytes = match to_bytes(body, 64 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid request").into_response();
        }
    };
    let text = String::from_utf8_lossy(&bytes);
    if is_framework_rejection(&text) {
        return api_error(StatusCode::BAD_REQUEST, "invalid request").into_response();
    }
    Response::from_parts(parts, Body::from(bytes))
}

fn is_framework_rejection(message: &str) -> bool {
    message.starts_with("Invalid URL:")
        || message.starts_with("Failed to deserialize")
        || message.starts_with("Failed to parse")
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
        .route("/operations/summary", get(admin_operations_summary))
        .route("/operations/state", get(admin_operations_state))
        .route(
            "/operations/recommendations",
            get(admin_operations_recommendations),
        )
        .route(
            "/operations/decisions/history",
            get(admin_operations_recommendations),
        )
        .route("/workflows", get(admin_workflows))
        .route("/workflows/{id}", get(admin_workflow_detail))
        .route("/workflow-runs", get(admin_workflow_runs))
        .route("/workflows/{id}/approve", post(admin_approve_workflow))
        .route("/connectors", get(admin_connectors))
        .route("/connectors/{id}", get(admin_connector_detail))
        .route("/connectors/{id}/health", get(admin_connector_health))
        .route(
            "/connectors/{id}/capabilities",
            get(admin_connector_capabilities),
        )
        .route("/actions", get(admin_actions))
        .route(
            "/executions",
            get(admin_executions).post(admin_create_execution),
        )
        .route(
            "/admin/executions/{id}/approve",
            post(admin_approve_execution),
        )
        .route(
            "/admin/executions/{id}/cancel",
            post(admin_cancel_execution),
        )
        .route(
            "/api/v1/workflows/{id}/approve",
            post(admin_approve_workflow),
        )
        .route("/security/briefing", get(admin_security_briefing))
        .route("/system/graph", get(admin_system_graph))
        .route("/admin/alerts", get(admin_alerts))
        .route("/admin/alerts/{id}/status", post(admin_alert_status))
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
        .route("/incidents/{id}/timeline", get(incident_timeline))
        .route(
            "/incidents/{id}/status-history",
            get(incident_status_history),
        )
        .route(
            "/incidents/{id}/notes",
            get(incident_notes).post(add_incident_note),
        )
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
                .route("/agents/status", get(agent_health_status))
                .route("/context", get(agent_context))
                .route("/decisions", get(agent_decisions))
                .route("/providers", get(agent_provider_status))
                .route("/providers/{id}/history", get(agent_provider_history))
                .route("/operations/summary", get(agent_operations_summary))
                .route("/operations/state", get(agent_operations_state))
                .route("/operations/briefing", get(agent_operations_briefing))
                .route(
                    "/operations/recommendations",
                    get(agent_operations_recommendations),
                )
                .route("/decisions/history", get(agent_decision_history))
                .route("/workflows", get(agent_workflows))
                .route("/workflows/{id}", get(agent_workflow_detail))
                .route("/workflow-runs", get(agent_workflow_runs))
                .route("/connectors", get(agent_connectors))
                .route("/connectors/{id}", get(agent_connector_detail))
                .route("/connectors/{id}/health", get(agent_connector_health))
                .route(
                    "/connectors/{id}/capabilities",
                    get(agent_connector_capabilities),
                )
                .route("/actions", get(agent_actions))
                .route("/actions/{id}", get(agent_action_detail))
                .route("/executions", get(agent_executions))
                .route("/executions/{id}", get(agent_execution_detail))
                .route("/history", get(agent_history))
                .route("/history/summary", get(agent_history_summary))
                .route("/metrics", get(agent_metrics))
                .route("/knowledge", get(agent_knowledge))
                .route("/events", get(agent_events))
                .route("/incidents", get(agent_incidents))
                .route("/incidents/{id}", get(agent_incident_detail))
                .route("/incidents/{id}/replay", get(agent_incident_replay))
                .route("/incidents/{id}/timeline", get(agent_incident_timeline))
                .route("/incidents/{id}/relations", get(agent_incident_relations))
                .route("/security/findings", get(agent_findings))
                .route("/security/overview", get(agent_security_overview))
                .route("/security/posture", get(agent_security_posture))
                .route("/security/briefing", get(agent_security_briefing))
                .route("/system/graph", get(agent_system_graph))
                .route("/network/asn", get(agent_asn))
                .route("/network/prefixes", get(agent_prefixes))
                .route("/network/bgp", get(agent_bgp))
                .route("/network/rpki", get(agent_rpki))
                .route("/network/trust", get(agent_trust)),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn(sanitize_framework_errors))
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
    fn incident_status_model_and_permissions_are_stable() {
        assert_eq!(canonical_incident_status("detected"), Some("detected"));
        assert_eq!(canonical_incident_status("Open"), Some("detected"));
        assert_eq!(canonical_incident_status("closed"), Some("closed"));
        assert_eq!(canonical_incident_status("invalid"), None);
        let operator = AdminPrincipal {
            id: Uuid::new_v4(),
            username: "operator".into(),
            role: "Operator".into(),
            auth_kind: "session".into(),
            credential_id: Uuid::new_v4(),
        };
        let viewer = AdminPrincipal {
            role: "Viewer".into(),
            ..operator.clone()
        };
        assert!(require_role(&operator, &["Administrator", "Operator"]).is_ok());
        assert!(require_role(&viewer, &["Administrator", "Operator"]).is_err());
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
    fn framework_rejection_messages_are_identified_without_echoing_input() {
        assert!(is_framework_rejection(
            "Invalid URL: Cannot parse `id` with value secret"
        ));
        assert!(is_framework_rejection(
            "Failed to deserialize query string: page: number too large"
        ));
        assert!(!is_framework_rejection("invalid incident identifier"));
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
        assert!(validate_agent_scopes(&[
            AGENT_SCOPE_INCIDENT_READ.to_string()
        ]));
        assert!(validate_agent_scopes(&[
            AGENT_SCOPE_CONTEXT_READ.to_string()
        ]));
        assert!(validate_agent_scopes(&[
            AGENT_SCOPE_DECISION_READ.to_string()
        ]));
        assert!(validate_agent_scopes(&[
            AGENT_SCOPE_PROVIDER_READ.to_string(),
            AGENT_SCOPE_OPERATIONS_READ.to_string()
        ]));
        assert!(validate_agent_scopes(&[
            AGENT_SCOPE_OPERATIONS_BRIEFING.to_string(),
            AGENT_SCOPE_KNOWLEDGE_READ.to_string()
        ]));
        assert!(validate_agent_scopes(&[
            AGENT_SCOPE_OPERATIONS_STATE.to_string(),
            AGENT_SCOPE_EXECUTION_READ.to_string()
        ]));
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
    fn provider_and_operations_views_are_safe_and_action_free() {
        let provider = agent_provider_view(&serde_json::json!({
            "id": "threatfox",
            "name": "ThreatFox",
            "source": "abuse.ch",
            "enabled": true,
            "status": "ok",
            "quality_score": 94,
            "age_seconds": 120,
            "indicator_count": 12,
            "sync_duration_ms": 450,
            "payload": {"api_key": "must-not-leak"},
            "credentials": "must-not-leak"
        }));
        assert_eq!(provider["quality_score"], 94);
        assert_eq!(provider["data_age_seconds"], 120);
        assert!(provider.get("payload").is_none());
        assert!(provider.get("credentials").is_none());

        let summary = operations_summary_data(
            &[serde_json::json!({
                "id": "incident-1", "status": "detected", "severity": "high",
                "risk_score": 82, "confidence": 88, "summary": "review"
            })],
            &[serde_json::json!({"risk_score": 72, "confidence": 90})],
            &[serde_json::json!({"status": "Verified", "trust_score": -20})],
            &[serde_json::json!({"severity": "critical", "event_type": "rpki.invalid"})],
            &[serde_json::json!({
                "id": "threatfox", "name": "ThreatFox", "source": "abuse.ch",
                "enabled": true, "status": "ok", "quality_score": 94
            })],
        );
        assert_eq!(summary["active_incidents"], 1);
        assert_eq!(summary["critical_events"], 1);
        assert_eq!(summary["provider_health"]["healthy"], 1);
        assert!(summary.get("payload").is_none());
        assert!(summary.get("action").is_none());
    }

    #[test]
    fn agent_context_is_aggregated_and_redacted() {
        let incidents = vec![
            serde_json::json!({
                "id": "incident-1",
                "status": "detected",
                "severity": "high",
                "confidence": 90,
                "risk_score": 82,
                "summary": "Correlated event chain",
                "event_count": 3,
                "candidate_id": "candidate-secret",
                "correlation_key": "internal-secret"
            }),
            serde_json::json!({
                "id": "incident-2",
                "status": "closed",
                "severity": "critical",
                "confidence": 99,
                "risk_score": 95,
                "summary": "Closed event chain"
            }),
        ];
        let (active, severity, correlations) = context_incident_data(&incidents);
        assert_eq!(active.len(), 1);
        assert_eq!(severity["total"], 1);
        assert_eq!(severity["by_severity"]["high"], 1);
        assert_eq!(correlations[0]["incident_id"], "incident-1");
        assert!(active[0].get("candidate_id").is_none());
        assert!(correlations[0].get("correlation_key").is_none());

        let risk = context_risk_data(&[
            serde_json::json!({
                "source":"threatfox",
                "risk_score":82,
                "trust_score":-5,
                "assessed_at":"2026-09-08T00:00:00Z",
                "payload":{"secret":"must-not-leak"}
            }),
            serde_json::json!({"source":"urlhaus","risk_score":20}),
        ]);
        assert_eq!(risk["highest"], 82);
        assert_eq!(risk["assessed"], 2);
        assert!(risk.get("payload").is_none());

        let trust = context_trust_data(&[
            serde_json::json!({"status":"Verified","node_identities":["secret"]}),
            serde_json::json!({"status":"Pending"}),
        ]);
        assert_eq!(trust["total"], 2);
        assert_eq!(trust["by_status"]["Verified"], 1);
        assert!(trust.get("node_identities").is_none());

        let events = context_important_events(&[
            serde_json::json!({
                "event_id":"event-1","event_type":"threat","source":"feed",
                "severity":"critical","timestamp":"2026-09-08T00:00:00Z",
                "payload":{"secret":"must-not-leak"}
            }),
            serde_json::json!({"event_id":"event-2","severity":"low"}),
        ]);
        assert_eq!(events.len(), 1);
        assert!(events[0].get("payload").is_none());
    }

    #[test]
    fn agent_decisions_prioritize_safe_context_without_actions_or_raw_data() {
        let incidents = vec![serde_json::json!({
            "id": "incident-1",
            "status": "confirmed",
            "severity": "high",
            "confidence": 88,
            "risk_score": 82,
            "summary": "Correlated threat activity",
            "candidate_id": "internal-candidate",
            "correlation_key": "internal-correlation"
        })];
        let indicators = vec![serde_json::json!({
            "source": "ThreatFox",
            "risk_score": 91,
            "confidence": 95,
            "reason": "botnet C2",
            "payload": {"secret": "must-not-leak"}
        })];
        let trust = vec![serde_json::json!({"status": "Revoked", "node_id": "secret"})];
        let events = vec![serde_json::json!({
            "event_id": "event-1",
            "event_type": "rpki.invalid",
            "source": "network",
            "severity": "critical",
            "timestamp": "2026-09-08T00:00:00Z",
            "payload": {"secret": "must-not-leak"}
        })];

        let assessment = decision_risk_assessment(&incidents, &indicators);
        assert_eq!(assessment["highest_risk_score"], 91);
        assert_eq!(assessment["overall_status"], "critical");
        assert_eq!(assessment["correlation_confidence"]["highest"], 88);

        let attention = decision_attention_points(&incidents, &indicators, &events);
        assert_eq!(attention[0]["priority"], "critical");
        assert!(attention.iter().all(|point| point.get("payload").is_none()));
        assert!(attention
            .iter()
            .all(|point| point.get("candidate_id").is_none()));
        assert!(attention
            .iter()
            .all(|point| point.get("correlation_key").is_none()));

        let checks = decision_recommended_checks(&incidents, &indicators, &trust, &events);
        assert!(checks
            .iter()
            .any(|check| check["check"] == "incident_timelines"));
        assert!(checks.iter().any(|check| check["check"] == "trust_status"));
        assert!(checks
            .iter()
            .any(|check| check["check"] == "network_intelligence"));
        assert!(checks.iter().all(|check| check.get("action").is_none()));
    }

    #[test]
    fn agent_incident_views_are_redacted_and_scope_compatible() {
        let incident = agent_incident_view(&serde_json::json!({
            "id": "incident-1",
            "status": "detected",
            "severity": "high",
            "confidence": 88,
            "risk_score": 72,
            "summary": "Correlated threat",
            "correlation_key": "internal:198.51.100.10",
            "candidate_id": "candidate-1",
            "raw_payload": {"token": "must-not-leak"},
            "event_count": 2,
            "created_at": "2026-09-08T00:00:00Z",
            "updated_at": "2026-09-08T00:01:00Z"
        }));
        assert_eq!(incident["confidence"], 88);
        assert!(incident.get("correlation_key").is_none());
        assert!(incident.get("candidate_id").is_none());
        assert!(incident.get("raw_payload").is_none());

        let timeline = agent_incident_timeline_view(&serde_json::json!({
            "kind": "note",
            "timestamp": "2026-09-08T00:02:00Z",
            "data": {"body": "password=must-not-leak", "author": "operator"}
        }));
        assert_eq!(timeline["recorded"], true);
        assert!(timeline.get("body").is_none());
        assert!(timeline.get("author").is_none());

        let principal = AgentPrincipal {
            id: Uuid::new_v4(),
            name: "incident-agent".into(),
            scopes: vec![AGENT_SCOPE_INCIDENT_READ.into()],
        };
        assert!(require_agent_incident_scope(&principal).is_ok());
        let legacy = AgentPrincipal {
            scopes: vec![AGENT_SCOPE_INCIDENTS_READ_LEGACY.into()],
            ..principal.clone()
        };
        assert!(require_agent_incident_scope(&legacy).is_ok());
        let wrong = AgentPrincipal {
            scopes: vec![AGENT_SCOPE_SECURITY_READ.into()],
            ..principal
        };
        assert!(require_agent_incident_scope(&wrong).is_err());
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
    fn agent_trust_view_excludes_registry_internals() {
        let trust = agent_network_view(
            &serde_json::json!({
                "id": "network-1",
                "name": "Homelab Tailnet",
                "type": "Tailscale",
                "identifier": "tailnet-id",
                "source": "trusted_registry",
                "status": "Verified",
                "networks": ["192.168.10.0/24"],
                "node_identities": ["node-secret"],
                "device_tags": ["tag:prod"],
                "groups": ["admins"],
                "timestamp": "2026-09-08T00:00:00Z",
                "confidence": 100,
                "trust_score": -40
            }),
            &[
                "id",
                "name",
                "type",
                "identifier",
                "source",
                "status",
                "timestamp",
                "confidence",
                "trust_score",
            ],
        );
        assert_eq!(trust["status"], "Verified");
        assert_eq!(trust["trust_score"], -40);
        assert!(trust.get("networks").is_none());
        assert!(trust.get("node_identities").is_none());
        assert!(trust.get("device_tags").is_none());
        assert!(trust.get("groups").is_none());
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

    #[test]
    fn agent_path_identifier_errors_are_generic() {
        let (status, body) =
            parse_agent_uuid("not-a-uuid").expect_err("invalid id must be rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0.errors, vec!["invalid incident identifier"]);
    }

    #[test]
    fn audit_scope_filter_matches_only_explicit_agent_scope() {
        let event = serde_json::json!({"details": {"scope": "agent:operations:briefing"}});
        assert!(audit_scope_matches(&event, None));
        assert!(audit_scope_matches(
            &event,
            Some("agent:operations:briefing")
        ));
        assert!(!audit_scope_matches(&event, Some("agent:knowledge:read")));
        assert!(!audit_scope_matches(
            &serde_json::json!({"details": {}}),
            Some("agent:events:read")
        ));
    }

    #[test]
    fn provider_history_identifiers_are_bounded() {
        assert!(valid_provider_identifier("threatfox"));
        assert!(valid_provider_identifier("asn:ripestat"));
        assert!(!valid_provider_identifier(""));
        assert!(!valid_provider_identifier("provider/history"));
        assert!(!valid_provider_identifier(&"x".repeat(129)));
    }

    #[test]
    fn incident_replay_contains_only_redacted_stored_context() {
        let incident = serde_json::json!({
            "id": "incident-1", "status": "confirmed", "severity": "high",
            "confidence": 80, "risk_score": 75, "summary": "correlated activity",
            "candidate_id": "internal", "correlation_key": "secret-key"
        });
        let timeline = vec![
            serde_json::json!({"kind":"relation","timestamp":"2026-09-08T00:00:00Z","data":{"event_id":"event-1","source":"ThreatFox","severity":"high","indicator":{"type":"ip","value":"198.51.100.10"},"raw_payload":{"secret":"x"}}}),
            serde_json::json!({"kind":"note","timestamp":"2026-09-08T00:01:00Z","data":{"body":"private"}}),
        ];
        let replay = replay_view(&incident, &timeline, &[], &[]);
        let serialized = serde_json::to_string(&replay).unwrap();
        assert!(serialized.contains("198.51.100.10"));
        assert!(!serialized.contains("raw_payload"));
        assert!(!serialized.contains("private"));
        assert!(!serialized.contains("candidate_id"));
        assert!(!serialized.contains("correlation_key"));
    }

    #[test]
    fn decision_views_are_explainable_and_do_not_export_metadata() {
        let value = serde_json::json!({
            "id": Uuid::new_v4(), "severity":"high", "category":"provider_health",
            "source":"decision_engine", "title":"Provider outage", "description":"sync failed",
            "reason":"timeout", "recommendation":"review fallback", "confidence":0.91,
            "status":"open", "metadata":{"provider_id":"secret-internal"}
        });
        let view = agent_decision_view(&value);
        assert_eq!(view["confidence"], 0.91);
        assert!(view.get("metadata").is_none());
        assert!(view["recommendation"].as_str().is_some());
    }

    #[test]
    fn recommendation_scope_is_explicitly_read_only() {
        assert!(validate_agent_scopes(&[
            AGENT_SCOPE_OPERATIONS_RECOMMEND.into()
        ]));
        assert!(!validate_agent_scopes(&["agent:operations:write".into()]));
        let invalid = AgentQuery {
            status: Some("execute".into()),
            ..AgentQuery::default()
        };
        assert!(validate_decision_query(&invalid).is_err());
    }

    #[test]
    fn workflow_views_exclude_configuration_and_metadata() {
        let value = serde_json::json!({
            "id": Uuid::new_v4(), "name": "Security Incident Workflow",
            "description": "approval path", "category": "incident", "enabled": true,
            "metadata": {"secret": "removed"},
            "steps": [{"id": Uuid::new_v4(), "name": "Approve", "step_order": 1,
                "type": "approval", "required_approval": true,
                "configuration": {"token": "removed"}}]
        });
        let view = workflow_view(&value);
        let serialized = serde_json::to_string(&view).unwrap();
        assert!(serialized.contains("Security Incident Workflow"));
        assert!(serialized.contains("required_approval"));
        assert!(!serialized.contains("metadata"));
        assert!(!serialized.contains("configuration"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn workflow_scope_and_filters_are_read_only_and_bounded() {
        assert!(validate_agent_scopes(&[AGENT_SCOPE_WORKFLOW_READ.into()]));
        assert!(validate_agent_scopes(
            &[AGENT_SCOPE_WORKFLOW_APPROVE.into()]
        ));
        assert!(!validate_agent_scopes(&["agent:workflow:execute".into()]));
        let query = AgentQuery {
            workflow_id: Some("not-a-uuid".into()),
            ..AgentQuery::default()
        };
        assert!(validate_workflow_query(&query).is_err());
        let query = AgentQuery {
            status: Some("execute".into()),
            ..AgentQuery::default()
        };
        assert!(validate_workflow_query(&query).is_err());
    }

    #[test]
    fn connector_views_are_read_only_and_redacted() {
        let value = serde_json::json!({
            "id": Uuid::new_v4(), "name": "Docker Connector", "version": "0.8.0",
            "type": "docker", "status": "configured", "health": "unknown",
            "description": "container status", "health_error": "secret socket path",
            "secret_ref": "docker_token", "capabilities": [{"name":"container.list","read_only":true}]
        });
        let view = connector_view(&value);
        let serialized = serde_json::to_string(&view).unwrap();
        assert!(serialized.contains("container.list"));
        assert!(serialized.contains("read_only"));
        assert!(!serialized.contains("secret socket"));
        assert!(!serialized.contains("secret_ref"));
        assert!(validate_agent_scopes(&[AGENT_SCOPE_CONNECTOR_READ.into()]));
    }
}
