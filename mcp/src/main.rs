use std::{
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use reqwest::{Client, Url};
use rmcp::{
    handler::server::wrapper::{Json, Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ErrorData, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

const SCOPE_SYSTEM: &str = "agent:system:read";
const SCOPE_EVENTS: &str = "agent:events:read";
const SCOPE_INCIDENT: &str = "agent:incident:read";
const SCOPE_INCIDENTS_LEGACY: &str = "agent:incidents:read";
const SCOPE_CONTEXT: &str = "agent:context:read";
const SCOPE_DECISION: &str = "agent:decision:read";
const SCOPE_PROVIDER: &str = "agent:provider:read";
const SCOPE_OPERATIONS: &str = "agent:operations:read";
const SCOPE_SECURITY: &str = "agent:security:read";
const SCOPE_NETWORK: &str = "agent:network:read";
const SCOPE_ALL: &str = "agent:read";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
static MCP_UPSTREAM_REQUESTS: AtomicU64 = AtomicU64::new(0);
static MCP_UPSTREAM_ERRORS: AtomicU64 = AtomicU64::new(0);
static MCP_AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
}

#[derive(Clone)]
struct Config {
    agent_api_url: Url,
    agent_api_token: String,
    mcp_auth_token: String,
    mcp_scopes: HashSet<String>,
    timeout: Duration,
}

#[derive(Clone)]
struct McpServer {
    config: Arc<Config>,
    client: Client,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct EmptyArgs {}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct EventArgs {
    #[schemars(description = "1-based page number")]
    page: Option<i64>,
    #[schemars(description = "Page size, capped at 100")]
    page_size: Option<i64>,
    #[schemars(description = "Filter by normalized event type")]
    event_type: Option<String>,
    #[schemars(description = "Filter by event source")]
    source: Option<String>,
    #[schemars(description = "Filter by severity")]
    severity: Option<String>,
    #[schemars(description = "Filter by correlation reference")]
    correlation_id: Option<String>,
    #[schemars(description = "RFC-3339 start timestamp")]
    from: Option<String>,
    #[schemars(description = "RFC-3339 end timestamp")]
    to: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct IncidentArgs {
    #[schemars(description = "1-based page number")]
    page: Option<i64>,
    #[schemars(description = "Page size, capped at 100")]
    page_size: Option<i64>,
    #[schemars(description = "Incident lifecycle status")]
    status: Option<String>,
    #[schemars(description = "Incident severity")]
    severity: Option<String>,
    #[schemars(description = "RFC-3339 start timestamp")]
    from: Option<String>,
    #[schemars(description = "RFC-3339 end timestamp")]
    to: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct IncidentIdArgs {
    #[schemars(description = "Incident UUID")]
    id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct IncidentTimelineArgs {
    #[schemars(description = "Incident UUID")]
    id: String,
    #[schemars(description = "1-based page number")]
    page: Option<i64>,
    #[schemars(description = "Page size, capped at 100")]
    page_size: Option<i64>,
    #[schemars(description = "Filter timeline status")]
    status: Option<String>,
    #[schemars(description = "Filter timeline severity")]
    severity: Option<String>,
    #[schemars(description = "RFC-3339 start timestamp")]
    from: Option<String>,
    #[schemars(description = "RFC-3339 end timestamp")]
    to: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct IncidentRelationsArgs {
    #[schemars(description = "Incident UUID")]
    id: String,
    #[schemars(description = "1-based page number")]
    page: Option<i64>,
    #[schemars(description = "Page size, capped at 100")]
    page_size: Option<i64>,
    #[schemars(description = "Relation type filter")]
    relation_type: Option<String>,
    #[schemars(description = "Relation severity filter")]
    severity: Option<String>,
    #[schemars(description = "RFC-3339 start timestamp")]
    from: Option<String>,
    #[schemars(description = "RFC-3339 end timestamp")]
    to: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct FindingArgs {
    #[schemars(description = "1-based page number")]
    page: Option<i64>,
    #[schemars(description = "Page size, capped at 100")]
    page_size: Option<i64>,
    #[schemars(description = "Indicator source")]
    source: Option<String>,
    #[schemars(description = "Finding severity")]
    severity: Option<String>,
    #[schemars(description = "Minimum confidence from 0 to 100")]
    confidence_min: Option<u8>,
    #[schemars(description = "Only active findings when true")]
    active: Option<bool>,
    #[schemars(description = "RFC-3339 start timestamp")]
    from: Option<String>,
    #[schemars(description = "RFC-3339 end timestamp")]
    to: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct TrustArgs {
    #[schemars(description = "1-based page number")]
    page: Option<i64>,
    #[schemars(description = "Page size, capped at 100")]
    page_size: Option<i64>,
    #[schemars(description = "Pending, Verified, or Revoked")]
    status: Option<String>,
    #[schemars(description = "Tailscale, NetBird, VLAN, VPN, ASN, or prefix")]
    network_type: Option<String>,
    #[schemars(description = "RFC-3339 start timestamp")]
    from: Option<String>,
    #[schemars(description = "RFC-3339 end timestamp")]
    to: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct NetworkArgs {
    #[schemars(description = "ASN filter")]
    asn: Option<String>,
    #[schemars(description = "CIDR prefix filter")]
    prefix: Option<String>,
    #[schemars(description = "RPKI status filter")]
    rpki_status: Option<String>,
    #[schemars(description = "RFC-3339 start timestamp")]
    from: Option<String>,
    #[schemars(description = "RFC-3339 end timestamp")]
    to: Option<String>,
    #[schemars(description = "Page size, capped at 100")]
    page_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope {
    status: String,
    data: Value,
    timestamp: String,
    pagination: Option<Value>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ToolResponse {
    status: String,
    data: Value,
    timestamp: String,
    pagination: Option<Value>,
    errors: Vec<String>,
}

impl From<ApiEnvelope> for ToolResponse {
    fn from(value: ApiEnvelope) -> Self {
        Self {
            status: value.status,
            data: redact(value.data),
            timestamp: value.timestamp,
            pagination: value.pagination.map(redact),
            errors: value.errors,
        }
    }
}

fn ensure_response_size(response: ToolResponse) -> Result<ToolResponse, ErrorData> {
    let size = serde_json::to_vec(&response)
        .map(|bytes| bytes.len())
        .unwrap_or(MAX_RESPONSE_BYTES + 1);
    if size > MAX_RESPONSE_BYTES {
        MCP_UPSTREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(ErrorData::internal_error(
            "MCP response exceeds the configured size limit",
            Some(json!({"max_bytes": MAX_RESPONSE_BYTES})),
        ));
    }
    Ok(response)
}

impl Config {
    fn from_env() -> Result<Self> {
        let agent_api_url = Url::parse(
            &std::env::var("CLAWFORGE_AGENT_API_URL")
                .unwrap_or_else(|_| "http://clawforge-api:8080".to_string()),
        )
        .context("invalid CLAWFORGE_AGENT_API_URL")?;
        let agent_api_token = read_secret_env(
            "CLAWFORGE_MCP_AGENT_TOKEN_FILE",
            "CLAWFORGE_MCP_AGENT_TOKEN",
        )?;
        let mcp_auth_token =
            read_secret_env("CLAWFORGE_MCP_AUTH_TOKEN_FILE", "CLAWFORGE_MCP_AUTH_TOKEN")?;
        if agent_api_token == mcp_auth_token {
            return Err(anyhow!("MCP and Agent API credentials must be different"));
        }
        let scope_text =
            std::env::var("CLAWFORGE_MCP_SCOPES").unwrap_or_else(|_| SCOPE_ALL.to_string());
        let mcp_scopes = parse_scopes(&scope_text)?;
        let timeout = Duration::from_secs(
            std::env::var("CLAWFORGE_MCP_UPSTREAM_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("invalid CLAWFORGE_MCP_UPSTREAM_TIMEOUT_SECONDS")?,
        );
        if timeout.is_zero() {
            return Err(anyhow!("MCP upstream timeout must be greater than zero"));
        }
        Ok(Self {
            agent_api_url,
            agent_api_token,
            mcp_auth_token,
            mcp_scopes,
            timeout,
        })
    }
}

fn parse_scopes(value: &str) -> Result<HashSet<String>> {
    let scopes: HashSet<String> = value
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect();
    let allowed = [
        SCOPE_SYSTEM,
        SCOPE_EVENTS,
        SCOPE_INCIDENT,
        SCOPE_INCIDENTS_LEGACY,
        SCOPE_CONTEXT,
        SCOPE_DECISION,
        SCOPE_PROVIDER,
        SCOPE_OPERATIONS,
        SCOPE_SECURITY,
        SCOPE_NETWORK,
        SCOPE_ALL,
    ];
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|scope| !allowed.contains(&scope.as_str()))
    {
        return Err(anyhow!("unsupported or empty MCP scope list"));
    }
    Ok(scopes)
}

fn read_secret_env(file_key: &str, value_key: &str) -> Result<String> {
    let value = if let Ok(path) = std::env::var(file_key) {
        std::fs::read_to_string(Path::new(&path))
            .with_context(|| format!("could not read {file_key}"))?
    } else {
        std::env::var(value_key).with_context(|| format!("{file_key} or {value_key} required"))?
    };
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(anyhow!("{file_key} cannot be empty"));
    }
    Ok(value)
}

fn redact(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(redact).collect()),
        Value::Object(mut object) => {
            for key in [
                "payload",
                "metadata",
                "networks",
                "node_identities",
                "device_tags",
                "groups",
                "raw_feed",
                "raw_payload",
                "candidate_id",
                "correlation_key",
                "body",
                "author",
                "token",
                "secret",
                "password",
                "api_key",
                "authorization",
            ] {
                object.remove(key);
            }
            Value::Object(
                object
                    .into_iter()
                    .map(|(key, value)| (key, redact(value)))
                    .collect(),
            )
        }
        other => other,
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.trim().is_empty())
}

async fn mcp_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = bearer(&headers) else {
        MCP_AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        return auth_error("MCP bearer token required");
    };
    if token != state.config.mcp_auth_token {
        MCP_AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        return auth_error("invalid MCP bearer token");
    }
    next.run(request).await
}

fn auth_error(message: &'static str) -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, message).into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(json!({"service":"clawforge-mcp","status":"ok"})),
    )
}

async fn metrics() -> impl IntoResponse {
    (
        StatusCode::OK,
        format!(
            "# TYPE clawforge_mcp_upstream_requests_total counter\nclawforge_mcp_upstream_requests_total {}\n# TYPE clawforge_mcp_upstream_errors_total counter\nclawforge_mcp_upstream_errors_total {}\n# TYPE clawforge_mcp_auth_failures_total counter\nclawforge_mcp_auth_failures_total {}\n",
            MCP_UPSTREAM_REQUESTS.load(Ordering::Relaxed),
            MCP_UPSTREAM_ERRORS.load(Ordering::Relaxed),
            MCP_AUTH_FAILURES.load(Ordering::Relaxed),
        ),
    )
}

impl McpServer {
    fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            client: Client::new(),
            tool_router: Self::tool_router(),
        }
    }

    fn require_scope(&self, scope: &str) -> Result<(), ErrorData> {
        if self.config.mcp_scopes.contains(scope) || self.config.mcp_scopes.contains(SCOPE_ALL) {
            Ok(())
        } else {
            Err(ErrorData::invalid_request(
                "MCP tool scope is not granted",
                Some(json!({"required_scope": scope})),
            ))
        }
    }

    fn require_scopes(&self, scopes: &[&str]) -> Result<(), ErrorData> {
        if self.config.mcp_scopes.contains(SCOPE_ALL)
            || scopes
                .iter()
                .any(|scope| self.config.mcp_scopes.contains(*scope))
        {
            Ok(())
        } else {
            Err(ErrorData::invalid_request(
                "MCP tool scope is not granted",
                Some(json!({"required_scopes": scopes})),
            ))
        }
    }

    fn require_incident_scope(&self) -> Result<(), ErrorData> {
        self.require_scopes(&[SCOPE_INCIDENT, SCOPE_INCIDENTS_LEGACY])
    }

    async fn get(
        &self,
        scope: &str,
        path: &str,
        query: &[(String, String)],
    ) -> Result<ToolResponse, ErrorData> {
        self.require_scope(scope)?;
        self.request(path, query).await
    }

    async fn get_incident(
        &self,
        path: &str,
        query: &[(String, String)],
    ) -> Result<ToolResponse, ErrorData> {
        self.require_incident_scope()?;
        self.request(path, query).await
    }

    async fn request(
        &self,
        path: &str,
        query: &[(String, String)],
    ) -> Result<ToolResponse, ErrorData> {
        let mut url = self.config.agent_api_url.clone();
        let base_path = url.path().trim_end_matches('/').to_string();
        url.set_path(&format!("{base_path}{path}"));
        url.query_pairs_mut().clear().extend_pairs(
            query
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        );
        MCP_UPSTREAM_REQUESTS.fetch_add(1, Ordering::Relaxed);
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.config.agent_api_token)
            .timeout(self.config.timeout)
            .send()
            .await
            .map_err(|_| {
                MCP_UPSTREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
                ErrorData::internal_error("Agent API request failed", None)
            })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| {
            MCP_UPSTREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
            ErrorData::internal_error("Agent API response invalid", None)
        })?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            MCP_UPSTREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
            return Err(ErrorData::internal_error(
                "Agent API response exceeds the MCP size limit",
                Some(json!({"max_bytes": MAX_RESPONSE_BYTES})),
            ));
        }
        let body = serde_json::from_slice::<ApiEnvelope>(&bytes).map_err(|_| {
            MCP_UPSTREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
            ErrorData::internal_error("Agent API response invalid", None)
        })?;
        if !status.is_success() || body.status != "ok" {
            MCP_UPSTREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
            let status_code = status.as_u16();
            return Err(match status {
                StatusCode::UNAUTHORIZED => ErrorData::invalid_request(
                    "Agent API authentication failed",
                    Some(json!({"upstream_status": status_code})),
                ),
                StatusCode::FORBIDDEN => ErrorData::invalid_request(
                    "Agent API scope is not granted",
                    Some(json!({"upstream_status": status_code})),
                ),
                StatusCode::NOT_FOUND => ErrorData::invalid_request(
                    "Agent API resource was not found",
                    Some(json!({"upstream_status": status_code})),
                ),
                _ if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() => {
                    ErrorData::internal_error(
                        "Agent API temporarily unavailable",
                        Some(json!({"upstream_status": status_code})),
                    )
                }
                _ => ErrorData::internal_error(
                    "Agent API request was not successful",
                    Some(json!({"upstream_status": status_code})),
                ),
            });
        }
        let response: ToolResponse = body.into();
        ensure_response_size(response)
    }

    async fn get_incident_context(&self) -> Result<Value, ErrorData> {
        let incidents = self
            .get_incident(
                "/api/v1/incidents",
                &[("page_size".to_string(), "100".to_string())],
            )
            .await?;
        incident_overview(&incidents.data)
    }

    async fn get_network_overview(&self, args: NetworkArgs) -> Result<ToolResponse, ErrorData> {
        self.require_scope(SCOPE_NETWORK)?;
        let mut common: Vec<(String, String)> = Vec::new();
        if let Some(value) = args.asn {
            common.push(("asn".to_string(), value));
        }
        if let Some(value) = args.prefix {
            common.push(("prefix".to_string(), value));
        }
        if let Some(value) = args.rpki_status {
            common.push(("rpki_status".to_string(), value));
        }
        if let Some(value) = args.from {
            common.push(("from".to_string(), value));
        }
        if let Some(value) = args.to {
            common.push(("to".to_string(), value));
        }
        if let Some(value) = args.page_size {
            common.push(("page_size".to_string(), value.clamp(1, 100).to_string()));
        }
        let (asn, prefixes, bgp, rpki) = tokio::join!(
            self.get(SCOPE_NETWORK, "/api/v1/network/asn", &common),
            self.get(SCOPE_NETWORK, "/api/v1/network/prefixes", &common),
            self.get(SCOPE_NETWORK, "/api/v1/network/bgp", &common),
            self.get(SCOPE_NETWORK, "/api/v1/network/rpki", &common),
        );
        if [asn.is_err(), prefixes.is_err(), bgp.is_err(), rpki.is_err()]
            .into_iter()
            .any(|failed| failed)
        {
            return Err(ErrorData::internal_error("Network data unavailable", None));
        }
        let data = json!({
            "asn": redact(asn.expect("checked above").data),
            "prefixes": redact(prefixes.expect("checked above").data),
            "bgp": redact(bgp.expect("checked above").data),
            "rpki": redact(rpki.expect("checked above").data)
        });
        ensure_response_size(ToolResponse {
            status: "ok".to_string(),
            data,
            timestamp: chrono::Utc::now().to_rfc3339(),
            pagination: None,
            errors: Vec::new(),
        })
    }
}

#[tool_router]
impl McpServer {
    #[tool(
        name = "get_status",
        description = "Read-only system, migration, runtime, provider, and incident status; requires agent:system:read and agent:incident:read"
    )]
    async fn get_status(
        &self,
        Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        self.require_scope(SCOPE_SYSTEM)?;
        self.require_incident_scope()?;
        let (status, incidents) = tokio::join!(
            self.get(SCOPE_SYSTEM, "/api/v1/status", &[]),
            self.get_incident_context(),
        );
        let mut response = status?;
        let overview = incidents?;
        if let Some(object) = response.data.as_object_mut() {
            object.insert("incidents".to_string(), overview);
        }
        Ok(Json(response))
    }

    #[tool(
        name = "get_agent_context",
        description = "Read the consolidated, redacted Clawforge context without raw payloads or actions; requires agent:context:read"
    )]
    async fn get_agent_context(
        &self,
        Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        Ok(Json(self.get(SCOPE_CONTEXT, "/api/v1/context", &[]).await?))
    }

    #[tool(
        name = "get_decisions",
        description = "Read existing prioritized operations decisions and recommended checks; no actions are performed; requires agent:decision:read"
    )]
    async fn get_decisions(
        &self,
        Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        Ok(Json(
            self.get(SCOPE_DECISION, "/api/v1/decisions", &[]).await?,
        ))
    }

    #[tool(
        name = "get_provider_status",
        description = "Read normalized provider health, data age, quality, and synchronization status; requires agent:provider:read"
    )]
    async fn get_provider_status(
        &self,
        Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        Ok(Json(
            self.get(SCOPE_PROVIDER, "/api/v1/providers", &[]).await?,
        ))
    }

    #[tool(
        name = "get_operations_summary",
        description = "Read the high-level operations summary, attention points, and checks; no remediation is performed; requires agent:operations:read"
    )]
    async fn get_operations_summary(
        &self,
        Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        Ok(Json(
            self.get(SCOPE_OPERATIONS, "/api/v1/operations/summary", &[])
                .await?,
        ))
    }

    #[tool(
        name = "list_events",
        description = "List paginated normalized events with optional source, severity, type, correlation, and time filters; requires agent:events:read"
    )]
    async fn list_events(
        &self,
        Parameters(args): Parameters<EventArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let query = event_query(&args);
        Ok(Json(
            self.get(SCOPE_EVENTS, "/api/v1/events", &query).await?,
        ))
    }

    #[tool(
        name = "list_incidents",
        description = "List paginated incidents with lifecycle, severity, and time filters; read-only and requires agent:incident:read"
    )]
    async fn list_incidents(
        &self,
        Parameters(args): Parameters<IncidentArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let query = incident_query(&args);
        Ok(Json(self.get_incident("/api/v1/incidents", &query).await?))
    }

    #[tool(
        name = "get_incident",
        description = "Read one redacted incident by UUID; no notes, raw payloads, or status changes; requires agent:incident:read"
    )]
    async fn get_incident_tool(
        &self,
        Parameters(args): Parameters<IncidentIdArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let path = incident_path(&args.id, "")?;
        Ok(Json(self.get_incident(&path, &[]).await?))
    }

    #[tool(
        name = "get_incident_timeline",
        description = "Read a redacted paginated incident timeline by UUID with status, severity, and time filters; requires agent:incident:read"
    )]
    async fn get_incident_timeline(
        &self,
        Parameters(args): Parameters<IncidentTimelineArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let path = incident_path(&args.id, "/timeline")?;
        let query = incident_timeline_query(&args);
        Ok(Json(self.get_incident(&path, &query).await?))
    }

    #[tool(
        name = "get_incident_relations",
        description = "Read normalized paginated incident relations without raw payloads; requires agent:incident:read"
    )]
    async fn get_incident_relations(
        &self,
        Parameters(args): Parameters<IncidentRelationsArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let path = incident_path(&args.id, "/relations")?;
        let query = incident_relations_query(&args);
        Ok(Json(self.get_incident(&path, &query).await?))
    }

    #[tool(
        name = "get_security_overview",
        description = "Read the stored security overview and safe incident context; no new scoring or actions; requires agent:security:read and agent:incident:read"
    )]
    async fn get_security_overview(
        &self,
        Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        self.require_scope(SCOPE_SECURITY)?;
        self.require_incident_scope()?;
        let (security, incidents) = tokio::join!(
            self.get(SCOPE_SECURITY, "/api/v1/security/overview", &[]),
            self.get_incident_context(),
        );
        let mut response = security?;
        if let Some(object) = response.data.as_object_mut() {
            object.insert("incidents".to_string(), incidents?);
        }
        Ok(Json(response))
    }

    #[tool(
        name = "list_security_findings",
        description = "List paginated normalized findings with source, confidence, age, and severity filters; requires agent:security:read"
    )]
    async fn list_security_findings(
        &self,
        Parameters(args): Parameters<FindingArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let query = finding_query(&args);
        Ok(Json(
            self.get(SCOPE_SECURITY, "/api/v1/security/findings", &query)
                .await?,
        ))
    }

    #[tool(
        name = "get_trust_status",
        description = "Read verified, pending, and revoked trusted networks; MCP cannot change trust; requires agent:network:read"
    )]
    async fn get_trust_status(
        &self,
        Parameters(args): Parameters<TrustArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let query = trust_query(&args);
        Ok(Json(
            self.get(SCOPE_NETWORK, "/api/v1/network/trust", &query)
                .await?,
        ))
    }

    #[tool(
        name = "get_network_overview",
        description = "Read grouped ASN, prefix, BGP, and RPKI intelligence with optional filters; no new assessment; requires agent:network:read"
    )]
    async fn get_network_overview_tool(
        &self,
        Parameters(args): Parameters<NetworkArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        Ok(Json(self.get_network_overview(args).await?))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Read-only Clawforge Agent API v1 tools")
    }
}

fn pairs(values: impl IntoIterator<Item = (String, Option<String>)>) -> Vec<(String, String)> {
    values
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .collect()
}

fn event_query(args: &EventArgs) -> Vec<(String, String)> {
    pairs([
        ("page".into(), args.page.map(|v| v.to_string())),
        (
            "page_size".into(),
            args.page_size.map(|v| v.clamp(1, 100).to_string()),
        ),
        ("event_type".into(), args.event_type.clone()),
        ("source".into(), args.source.clone()),
        ("severity".into(), args.severity.clone()),
        ("correlation_id".into(), args.correlation_id.clone()),
        ("from".into(), args.from.clone()),
        ("to".into(), args.to.clone()),
    ])
}

fn incident_query(args: &IncidentArgs) -> Vec<(String, String)> {
    pairs([
        ("page".into(), args.page.map(|v| v.to_string())),
        (
            "page_size".into(),
            args.page_size.map(|v| v.clamp(1, 100).to_string()),
        ),
        ("status".into(), args.status.clone()),
        ("severity".into(), args.severity.clone()),
        ("from".into(), args.from.clone()),
        ("to".into(), args.to.clone()),
    ])
}

fn incident_path(id: &str, suffix: &str) -> Result<String, ErrorData> {
    let id = Uuid::parse_str(id).map_err(|_| {
        ErrorData::invalid_params("incident id must be a UUID", Some(json!({"field": "id"})))
    })?;
    Ok(format!("/api/v1/incidents/{id}{suffix}"))
}

fn incident_timeline_query(args: &IncidentTimelineArgs) -> Vec<(String, String)> {
    pairs([
        ("page".into(), args.page.map(|v| v.to_string())),
        (
            "page_size".into(),
            args.page_size.map(|v| v.clamp(1, 100).to_string()),
        ),
        ("status".into(), args.status.clone()),
        ("severity".into(), args.severity.clone()),
        ("from".into(), args.from.clone()),
        ("to".into(), args.to.clone()),
    ])
}

fn incident_relations_query(args: &IncidentRelationsArgs) -> Vec<(String, String)> {
    pairs([
        ("page".into(), args.page.map(|v| v.to_string())),
        (
            "page_size".into(),
            args.page_size.map(|v| v.clamp(1, 100).to_string()),
        ),
        ("relation_type".into(), args.relation_type.clone()),
        ("severity".into(), args.severity.clone()),
        ("from".into(), args.from.clone()),
        ("to".into(), args.to.clone()),
    ])
}

fn incident_overview(data: &Value) -> Result<Value, ErrorData> {
    let incidents = data
        .as_array()
        .ok_or_else(|| ErrorData::internal_error("Agent API incident response invalid", None))?;
    let mut by_status = serde_json::Map::new();
    let mut by_severity = serde_json::Map::new();
    let mut active_count = 0_u64;
    let mut highest_severity = None;
    let mut highest_rank = 0_u8;
    for incident in incidents {
        if let Some(status) = incident.get("status").and_then(Value::as_str) {
            let count = by_status
                .entry(status.to_string())
                .or_insert_with(|| Value::from(0_u64));
            *count = Value::from(count.as_u64().unwrap_or(0) + 1);
            if !matches!(status, "resolved" | "closed") {
                active_count += 1;
            }
        }
        if let Some(severity) = incident.get("severity").and_then(Value::as_str) {
            let count = by_severity
                .entry(severity.to_string())
                .or_insert_with(|| Value::from(0_u64));
            *count = Value::from(count.as_u64().unwrap_or(0) + 1);
            let rank = match severity {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                _ => 1,
            };
            if rank > highest_rank {
                highest_rank = rank;
                highest_severity = Some(severity);
            }
        }
    }
    Ok(json!({
        "total": incidents.len(),
        "active": active_count,
        "highest_severity": highest_severity,
        "by_status": by_status,
        "by_severity": by_severity
    }))
}

fn finding_query(args: &FindingArgs) -> Vec<(String, String)> {
    pairs([
        ("page".into(), args.page.map(|v| v.to_string())),
        (
            "page_size".into(),
            args.page_size.map(|v| v.clamp(1, 100).to_string()),
        ),
        ("source".into(), args.source.clone()),
        ("severity".into(), args.severity.clone()),
        (
            "confidence_min".into(),
            args.confidence_min.map(|v| v.to_string()),
        ),
        ("active".into(), args.active.map(|v| v.to_string())),
        ("from".into(), args.from.clone()),
        ("to".into(), args.to.clone()),
    ])
}

fn trust_query(args: &TrustArgs) -> Vec<(String, String)> {
    pairs([
        ("page".into(), args.page.map(|v| v.to_string())),
        (
            "page_size".into(),
            args.page_size.map(|v| v.clamp(1, 100).to_string()),
        ),
        ("status".into(), args.status.clone()),
        ("network_type".into(), args.network_type.clone()),
        ("from".into(), args.from.clone()),
        ("to".into(), args.to.clone()),
    ])
}

async fn serve(config: Arc<Config>) -> Result<()> {
    let bind = std::env::var("CLAWFORGE_MCP_BIND").unwrap_or_else(|_| "0.0.0.0:8090".into());
    let address: SocketAddr = bind.parse().context("invalid CLAWFORGE_MCP_BIND")?;
    let app = build_app(config);
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "Clawforge MCP server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM");
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            }
            #[cfg(not(unix))]
            tokio::signal::ctrl_c()
                .await
                .expect("install Ctrl-C handler");
        })
        .await?;
    Ok(())
}

fn build_app(config: Arc<Config>) -> Router {
    let state = AppState {
        config: config.clone(),
    };
    let service_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None);
    let service: StreamableHttpService<McpServer, LocalSessionManager> = StreamableHttpService::new(
        move || Ok(McpServer::new(config.clone())),
        Default::default(),
        service_config,
    );
    let protected = Router::new()
        .fallback_service(service)
        .layer(middleware::from_fn_with_state(state.clone(), mcp_auth));
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .nest("/mcp", protected)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    serve(Arc::new(Config::from_env()?)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(scopes: &[&str]) -> Arc<Config> {
        Arc::new(Config {
            agent_api_url: Url::parse("http://127.0.0.1:1").unwrap(),
            agent_api_token: "agent-secret".into(),
            mcp_auth_token: "mcp-secret".into(),
            mcp_scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
            timeout: Duration::from_millis(50),
        })
    }

    #[test]
    fn scope_policy_denies_missing_permissions() {
        let server = McpServer::new(test_config(&[SCOPE_EVENTS]));
        assert!(server.require_scope(SCOPE_EVENTS).is_ok());
        assert!(server.require_scope(SCOPE_SYSTEM).is_err());
    }

    #[tokio::test]
    async fn tool_call_is_rejected_before_upstream_without_scope() {
        let server = McpServer::new(test_config(&[SCOPE_EVENTS]));
        let result = server.get_status(Parameters(EmptyArgs::default())).await;
        assert!(result.is_err());
        assert!(server
            .get_agent_context(Parameters(EmptyArgs::default()))
            .await
            .is_err());
        assert!(server
            .get_decisions(Parameters(EmptyArgs::default()))
            .await
            .is_err());
        assert!(server
            .get_provider_status(Parameters(EmptyArgs::default()))
            .await
            .is_err());
        assert!(server
            .get_operations_summary(Parameters(EmptyArgs::default()))
            .await
            .is_err());
    }

    #[test]
    fn context_and_decision_scopes_are_independent() {
        let context = McpServer::new(test_config(&[SCOPE_CONTEXT]));
        assert!(context.require_scope(SCOPE_CONTEXT).is_ok());
        assert!(context.require_scope(SCOPE_DECISION).is_err());
        let decision = McpServer::new(test_config(&[SCOPE_DECISION]));
        assert!(decision.require_scope(SCOPE_DECISION).is_ok());
        assert!(decision.require_scope(SCOPE_CONTEXT).is_err());
        let provider = McpServer::new(test_config(&[SCOPE_PROVIDER]));
        assert!(provider.require_scope(SCOPE_PROVIDER).is_ok());
        assert!(provider.require_scope(SCOPE_OPERATIONS).is_err());
        let operations = McpServer::new(test_config(&[SCOPE_OPERATIONS]));
        assert!(operations.require_scope(SCOPE_OPERATIONS).is_ok());
        assert!(operations.require_scope(SCOPE_PROVIDER).is_err());
    }

    #[tokio::test]
    async fn upstream_errors_are_sanitized_for_context_and_decisions() {
        let agent_app = Router::new().fallback(|| async {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(json!({
                    "status": "error",
                    "data": null,
                    "timestamp": "2026-01-01T00:00:00Z",
                    "pagination": null,
                    "errors": ["database secret must not be exposed"]
                })),
            )
        });
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let agent_server = tokio::spawn(async move {
            axum::serve(listener, agent_app).await.unwrap();
        });
        let config = Arc::new(Config {
            agent_api_url: Url::parse(&format!("http://{address}")).unwrap(),
            agent_api_token: "agent-secret".into(),
            mcp_auth_token: "mcp-secret".into(),
            mcp_scopes: [SCOPE_CONTEXT, SCOPE_DECISION]
                .into_iter()
                .map(str::to_string)
                .collect(),
            timeout: Duration::from_secs(2),
        });
        let server = McpServer::new(config);
        let context_error = match server
            .get_agent_context(Parameters(EmptyArgs::default()))
            .await
        {
            Ok(_) => panic!("context request unexpectedly succeeded"),
            Err(error) => error,
        };
        let decision_error = match server.get_decisions(Parameters(EmptyArgs::default())).await {
            Ok(_) => panic!("decision request unexpectedly succeeded"),
            Err(error) => error,
        };
        let serialized = format!("{context_error:?}{decision_error:?}");
        assert!(serialized.contains("temporarily unavailable"));
        assert!(!serialized.contains("database secret"));
        agent_server.abort();
    }

    #[test]
    fn redaction_removes_raw_and_secret_fields() {
        let value = redact(
            json!({"payload":{"token":"secret"},"metadata":{"raw_feed":"x"},"node_identities":["node"],"status":"Verified"}),
        );
        assert_eq!(value, json!({"status":"Verified"}));
    }

    #[test]
    fn tool_responses_are_size_bounded() {
        let response = ToolResponse {
            status: "ok".into(),
            data: json!({"large": "x".repeat(MAX_RESPONSE_BYTES) }),
            timestamp: "2026-01-01T00:00:00Z".into(),
            pagination: None,
            errors: Vec::new(),
        };
        let error = ensure_response_size(response).expect_err("oversized response must fail");
        assert!(format!("{error:?}").contains("size limit"));
    }

    #[test]
    fn all_read_only_tools_are_registered() {
        let server = McpServer::new(test_config(&[SCOPE_ALL]));
        let mut names: Vec<_> = server
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "get_agent_context",
                "get_decisions",
                "get_incident",
                "get_incident_relations",
                "get_incident_timeline",
                "get_network_overview",
                "get_operations_summary",
                "get_provider_status",
                "get_security_overview",
                "get_status",
                "get_trust_status",
                "list_events",
                "list_incidents",
                "list_security_findings",
            ]
        );
    }

    #[tokio::test]
    async fn incident_scope_accepts_canonical_and_legacy_names() {
        let canonical = McpServer::new(test_config(&[SCOPE_INCIDENT]));
        assert!(canonical.require_incident_scope().is_ok());
        let legacy = McpServer::new(test_config(&[SCOPE_INCIDENTS_LEGACY]));
        assert!(legacy.require_incident_scope().is_ok());
        let unrelated = McpServer::new(test_config(&[SCOPE_SECURITY]));
        assert!(unrelated.require_incident_scope().is_err());
        let result = unrelated
            .get_incident_tool(Parameters(IncidentIdArgs {
                id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            }))
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn incident_paths_and_overview_are_bounded() {
        assert!(incident_path("not-a-uuid", "").is_err());
        let overview = incident_overview(&json!([
            {"status":"detected","severity":"high"},
            {"status":"closed","severity":"critical"},
            {"status":"investigating","severity":"low"}
        ]))
        .unwrap();
        assert_eq!(overview["total"], 3);
        assert_eq!(overview["active"], 2);
        assert_eq!(overview["highest_severity"], "critical");
        assert!(incident_overview(&json!({"unexpected":true})).is_err());
    }

    #[tokio::test]
    async fn streamable_http_requires_auth_and_accepts_mcp_initialize() {
        let app = build_app(test_config(&[SCOPE_ALL]));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::new();
        let endpoint = format!("http://{address}/mcp");
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "clawforge-mcp-test", "version": "0.1.0"}
            }
        });
        let unauthorized = client
            .post(&endpoint)
            .json(&initialize)
            .send()
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let invalid = client
            .post(&endpoint)
            .bearer_auth("wrong-mcp-token")
            .json(&initialize)
            .send()
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        let response = client
            .post(&endpoint)
            .bearer_auth("mcp-secret")
            .header("Accept", "application/json, text/event-stream")
            .json(&initialize)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let response_body = response.text().await.unwrap();
        assert!(status.is_success(), "status={status} body={response_body}");
        let body: Value = serde_json::from_str(&response_body).unwrap();
        assert_eq!(body["result"]["serverInfo"]["name"], "rmcp");
        server.abort();
    }

    #[tokio::test]
    async fn rmcp_client_can_connect_with_mcp_token() {
        use rmcp::transport::{
            streamable_http_client::StreamableHttpClientTransportConfig,
            StreamableHttpClientTransport,
        };
        use rmcp::{model::ClientInfo, ServiceExt};

        let app = build_app(test_config(&[SCOPE_ALL]));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(format!("http://{address}/mcp"))
                .auth_header("mcp-secret"),
        );
        let client = ClientInfo::default().serve(transport).await.unwrap();
        let tools = client.list_tools(None).await.unwrap();
        assert_eq!(tools.tools.len(), 14);
        let expected = [
            "get_status",
            "list_events",
            "list_incidents",
            "get_incident",
            "get_incident_timeline",
            "get_incident_relations",
            "get_security_overview",
            "list_security_findings",
            "get_trust_status",
            "get_network_overview",
            "get_agent_context",
            "get_decisions",
            "get_provider_status",
            "get_operations_summary",
        ];
        for name in expected {
            let tool = tools
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("missing MCP tool {name}"));
            assert!(tool
                .description
                .as_deref()
                .is_some_and(|description| !description.trim().is_empty()));
        }
        client.cancel().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn rmcp_client_can_call_incident_tools_and_context() {
        use rmcp::model::{CallToolRequestParams, ClientInfo};
        use rmcp::transport::{
            streamable_http_client::StreamableHttpClientTransportConfig,
            StreamableHttpClientTransport,
        };
        use rmcp::ServiceExt;

        let incident_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let agent_app = Router::new().fallback(move |request: Request<Body>| async move {
            let path = request.uri().path();
            let data = match path {
                "/api/v1/status" => json!({"service":"clawforge","status":"ok"}),
                "/api/v1/context" => json!({
                    "system":{"status":"ok"},
                    "active_incidents":{"total":1},
                    "risk_scores":{"highest":70},
                    "trust":{"total":1},
                    "important_events":[{"payload":{"secret":"removed"}}],
                    "correlations":{"candidate_id":"removed"}
                }),
                "/api/v1/decisions" => json!({
                    "overall_status":"high",
                    "risk_assessment":{"highest_risk_score":70},
                    "attention_points":[{"payload":{"secret":"removed"},"correlation_key":"removed"}],
                    "recommended_checks":[{"check":"incident_timelines"}],
                    "context":{"candidate_id":"removed"}
                }),
                "/api/v1/providers" => json!([
                    {"id":"threatfox","name":"ThreatFox","status":"ok","quality_score":90,"last_error":"none","raw_payload":{"secret":"removed"}}
                ]),
                "/api/v1/operations/summary" => json!({
                    "overall_status":"high",
                    "risk_level":"high",
                    "active_incidents":1,
                    "critical_events":0,
                    "provider_health":{"total":1,"items":[{"raw_payload":{"secret":"removed"}}]},
                    "attention_points":[],
                    "recommended_checks":[]
                }),
                "/api/v1/security/overview" => json!({"findings_total":1,"active_findings":1}),
                "/api/v1/incidents" => json!([
                    {"id":incident_id,"status":"detected","severity":"high","confidence":88,"risk_score":70,"summary":"test incident","raw_payload":{"secret":"removed"}}
                ]),
                path if path == format!("/api/v1/incidents/{incident_id}") => json!({
                    "id":incident_id,"status":"detected","severity":"high","confidence":88,
                    "risk_score":70,"summary":"test incident","raw_payload":{"secret":"removed"}
                }),
                path if path == format!("/api/v1/incidents/{incident_id}/timeline") => json!([
                    {"kind":"status","timestamp":"2026-01-01T00:00:00Z","data":{"status":"detected"}},
                    {"kind":"note","timestamp":"2026-01-01T00:01:00Z","data":{"body":"private"}}
                ]),
                path if path == format!("/api/v1/incidents/{incident_id}/relations") => json!([
                    {"kind":"relation","timestamp":"2026-01-01T00:02:00Z","data":{"relation_type":"event","event_type":"threat.indicator","severity":"high","raw_payload":{"secret":"removed"}}}
                ]),
                _ => json!([]),
            };
            axum::Json(json!({
                "status":"ok",
                "data":data,
                "timestamp":"2026-01-01T00:00:00Z",
                "pagination":null,
                "errors":[]
            }))
        });
        let agent_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let agent_address = agent_listener.local_addr().unwrap();
        let agent_server = tokio::spawn(async move {
            axum::serve(agent_listener, agent_app).await.unwrap();
        });

        let config = Arc::new(Config {
            agent_api_url: Url::parse(&format!("http://{agent_address}")).unwrap(),
            agent_api_token: "agent-secret".into(),
            mcp_auth_token: "mcp-secret".into(),
            mcp_scopes: [SCOPE_ALL.to_string()].into_iter().collect(),
            timeout: Duration::from_secs(2),
        });
        let app = build_app(config);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(format!("http://{address}/mcp"))
                .auth_header("mcp-secret"),
        );
        let client = ClientInfo::default().serve(transport).await.unwrap();

        let mut id_arguments = serde_json::Map::new();
        id_arguments.insert("id".to_string(), json!(incident_id));
        for tool in [
            "list_incidents",
            "get_incident",
            "get_incident_timeline",
            "get_incident_relations",
            "get_agent_context",
            "get_decisions",
            "get_provider_status",
            "get_operations_summary",
            "get_status",
            "get_security_overview",
        ] {
            let params = if tool == "list_incidents" {
                CallToolRequestParams::new(tool)
            } else if matches!(
                tool,
                "get_incident" | "get_incident_timeline" | "get_incident_relations"
            ) {
                CallToolRequestParams::new(tool).with_arguments(id_arguments.clone())
            } else {
                CallToolRequestParams::new(tool)
            };
            let result = client.call_tool(params).await.unwrap();
            assert_ne!(result.is_error, Some(true), "tool={tool}");
            let serialized = serde_json::to_string(&result).unwrap();
            assert!(!serialized.contains("raw_payload"));
            assert!(!serialized.contains("private"));
            assert!(!serialized.contains("candidate_id"));
            assert!(!serialized.contains("correlation_key"));
            assert!(!serialized.contains("payload"));
            if matches!(tool, "get_status" | "get_security_overview") {
                assert!(serialized.contains("\"incidents\""));
            }
            if tool == "get_agent_context" {
                assert!(serialized.contains("\"active_incidents\""));
            }
            if tool == "get_decisions" {
                assert!(serialized.contains("\"overall_status\""));
            }
            if tool == "get_provider_status" {
                assert!(serialized.contains("\"quality_score\""));
            }
            if tool == "get_operations_summary" {
                assert!(serialized.contains("\"provider_health\""));
            }
        }

        client.cancel().await.unwrap();
        server.abort();
        agent_server.abort();
    }
}
