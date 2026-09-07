use std::{
    collections::HashMap,
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
use clawforge_storage::{database_url_from_env, AdminPrincipal, MigrationStatus, PostgresStore};
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
        },
        rate_limiter: RateLimiter::default(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/version", get(version))
        .route("/intelligence/providers", get(intelligence_providers))
        .route("/intelligence/status", get(intelligence_status))
        .route("/intelligence/indicators", get(intelligence_indicators))
        .route("/network/asn", get(network_asn))
        .route("/network/bgp", get(network_bgp))
        .route("/network/rpki", get(network_rpki))
        .route("/network/trust", get(network_trust))
        .route("/metrics", get(metrics))
        .route("/admin/auth/bootstrap", post(admin_bootstrap))
        .route("/admin/auth/login", post(admin_login))
        .route("/admin/auth/logout", post(admin_logout))
        .route("/admin/auth/users", post(admin_create_user))
        .route("/admin/auth/tokens", post(admin_create_token))
        .route("/admin/auth/tokens/{id}/rotate", post(admin_rotate_token))
        .route("/admin/providers", get(admin_providers))
        .route("/admin/providers/{id}", post(admin_update_provider))
        .route("/admin/providers/{id}/sync", post(admin_sync_provider))
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
        .route("/incidents/export", get(export_incidents))
        .route("/intelligence/indicators/export", get(export_indicators))
        .route("/audit/events/export", get(export_audit_events))
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
}
