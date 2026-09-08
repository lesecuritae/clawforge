use std::{collections::HashSet, net::SocketAddr, path::Path, sync::Arc, time::Duration};

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

const SCOPE_SYSTEM: &str = "agent:system:read";
const SCOPE_EVENTS: &str = "agent:events:read";
const SCOPE_INCIDENTS: &str = "agent:incidents:read";
const SCOPE_SECURITY: &str = "agent:security:read";
const SCOPE_NETWORK: &str = "agent:network:read";
const SCOPE_ALL: &str = "agent:read";

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
    event_type: Option<String>,
    source: Option<String>,
    severity: Option<String>,
    correlation_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct IncidentArgs {
    page: Option<i64>,
    page_size: Option<i64>,
    status: Option<String>,
    severity: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct FindingArgs {
    page: Option<i64>,
    page_size: Option<i64>,
    source: Option<String>,
    severity: Option<String>,
    confidence_min: Option<u8>,
    active: Option<bool>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct TrustArgs {
    page: Option<i64>,
    page_size: Option<i64>,
    status: Option<String>,
    network_type: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
struct NetworkArgs {
    asn: Option<String>,
    prefix: Option<String>,
    rpki_status: Option<String>,
    from: Option<String>,
    to: Option<String>,
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
        SCOPE_INCIDENTS,
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
        return auth_error("MCP bearer token required");
    };
    if token != state.config.mcp_auth_token {
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

    async fn get(
        &self,
        scope: &str,
        path: &str,
        query: &[(String, String)],
    ) -> Result<ToolResponse, ErrorData> {
        self.require_scope(scope)?;
        let mut url = self.config.agent_api_url.clone();
        let base_path = url.path().trim_end_matches('/').to_string();
        url.set_path(&format!("{base_path}{path}"));
        url.query_pairs_mut().clear().extend_pairs(
            query
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        );
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.config.agent_api_token)
            .timeout(self.config.timeout)
            .send()
            .await
            .map_err(|_| ErrorData::internal_error("Agent API request failed", None))?;
        let status = response.status();
        let body = response
            .json::<ApiEnvelope>()
            .await
            .map_err(|_| ErrorData::internal_error("Agent API response invalid", None))?;
        if !status.is_success() || body.status != "ok" {
            return Err(ErrorData::internal_error(
                "Agent API request was not successful",
                Some(json!({"upstream_status": status.as_u16()})),
            ));
        }
        Ok(body.into())
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
        Ok(ToolResponse {
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
    #[tool(name = "get_status", description = "Read Clawforge system status")]
    async fn get_status(
        &self,
        Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        Ok(Json(self.get(SCOPE_SYSTEM, "/api/v1/status", &[]).await?))
    }

    #[tool(name = "list_events", description = "List normalized Clawforge events")]
    async fn list_events(
        &self,
        Parameters(args): Parameters<EventArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let query = event_query(&args);
        Ok(Json(
            self.get(SCOPE_EVENTS, "/api/v1/events", &query).await?,
        ))
    }

    #[tool(name = "list_incidents", description = "List Clawforge incidents")]
    async fn list_incidents(
        &self,
        Parameters(args): Parameters<IncidentArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        let query = incident_query(&args);
        Ok(Json(
            self.get(SCOPE_INCIDENTS, "/api/v1/incidents", &query)
                .await?,
        ))
    }

    #[tool(
        name = "get_security_overview",
        description = "Read the stored Clawforge security overview"
    )]
    async fn get_security_overview(
        &self,
        Parameters(_args): Parameters<EmptyArgs>,
    ) -> Result<Json<ToolResponse>, ErrorData> {
        Ok(Json(
            self.get(SCOPE_SECURITY, "/api/v1/security/overview", &[])
                .await?,
        ))
    }

    #[tool(
        name = "list_security_findings",
        description = "List normalized Clawforge security findings"
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
        description = "Read verified, pending, and revoked Clawforge trust networks"
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
        description = "Read ASN, prefix, BGP, and RPKI intelligence"
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
    }

    #[test]
    fn redaction_removes_raw_and_secret_fields() {
        let value = redact(
            json!({"payload":{"token":"secret"},"metadata":{"raw_feed":"x"},"node_identities":["node"],"status":"Verified"}),
        );
        assert_eq!(value, json!({"status":"Verified"}));
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
                "get_network_overview",
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
        assert_eq!(tools.tools.len(), 7);
        client.cancel().await.unwrap();
        server.abort();
    }
}
