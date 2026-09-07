use std::{env, fs, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clawforge_analyzer::{
    AnalysisError, AnalysisOutput, AnalysisProvider, AnalysisRequest, MockProvider,
    OpenAiCompatibleProvider,
};
use serde::Serialize;
use serde_json::json;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    token: String,
    core_api_url: String,
    provider: Arc<dyn AnalysisProvider>,
    client: reqwest::Client,
}

#[derive(Serialize)]
struct ErrorResponse {
    status: &'static str,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct AcceptedResponse {
    status: &'static str,
    incident_id: Uuid,
    provider: String,
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.trim().is_empty())
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    bearer(headers).is_some_and(|value| value == token)
}

fn secret(name: &str) -> Result<String> {
    if let Ok(path) = env::var(format!("{name}_FILE")) {
        let value = fs::read_to_string(path).context("read analyzer secret file")?;
        if !value.trim().is_empty() {
            return Ok(value.trim().to_string());
        }
    }
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{name} or {name}_FILE must be configured"))
}

fn build_provider(client: reqwest::Client) -> Result<Arc<dyn AnalysisProvider>> {
    let provider = env::var("CLAWFORGE_ANALYZER_PROVIDER").unwrap_or_else(|_| "mock".into());
    let model = env::var("CLAWFORGE_ANALYZER_MODEL").unwrap_or_else(|_| "offline".into());
    if provider.eq_ignore_ascii_case("mock") {
        return Ok(Arc::new(MockProvider { model }));
    }
    let base_url = env::var("CLAWFORGE_ANALYZER_BASE_URL")
        .context("CLAWFORGE_ANALYZER_BASE_URL is required for non-mock providers")?;
    if base_url.trim().is_empty() {
        anyhow::bail!("CLAWFORGE_ANALYZER_BASE_URL is required for non-mock providers");
    }
    let api_key = secret("CLAWFORGE_ANALYZER_API_KEY").ok();
    Ok(Arc::new(OpenAiCompatibleProvider {
        client,
        base_url,
        api_key,
        model,
        provider,
    }))
}

async fn health() -> impl IntoResponse {
    Json(json!({"status":"ok","service":"clawforge-analyzer","mode":"analysis_only"}))
}

async fn analyze(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AnalysisRequest>,
) -> impl IntoResponse {
    if !authorized(&headers, &state.token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                status: "error",
                errors: vec!["analyzer service token required".into()],
            }),
        )
            .into_response();
    }
    let output = match state.provider.analyze(&request.input).await {
        Ok(output) => output,
        Err(error) => {
            let status = match error {
                AnalysisError::Request(_) | AnalysisError::ProviderHttp { .. } => {
                    StatusCode::BAD_GATEWAY
                }
                AnalysisError::InvalidResponse(_) => StatusCode::UNPROCESSABLE_ENTITY,
            };
            tracing::warn!(incident_id = %request.incident_id, "incident analysis failed");
            return (
                status,
                Json(ErrorResponse {
                    status: "error",
                    errors: vec!["analysis provider failed".into()],
                }),
            )
                .into_response();
        }
    };
    if let Err(error) = persist_output(&state, request.incident_id, &output).await {
        tracing::warn!(incident_id = %request.incident_id, %error, "could not persist incident analysis");
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                status: "error",
                errors: vec!["analysis result could not be stored".into()],
            }),
        )
            .into_response();
    }
    (
        StatusCode::ACCEPTED,
        Json(AcceptedResponse {
            status: "accepted",
            incident_id: request.incident_id,
            provider: output.provider,
        }),
    )
        .into_response()
}

async fn persist_output(
    state: &AppState,
    incident_id: Uuid,
    output: &AnalysisOutput,
) -> Result<()> {
    let response = state
        .client
        .post(format!(
            "{}/internal/analyzer/analyses",
            state.core_api_url.trim_end_matches('/')
        ))
        .bearer_auth(&state.token)
        .json(&json!({
            "incident_id": incident_id,
            "provider": output.provider,
            "model": output.model,
            "confidence": output.confidence,
            "summary": output.summary,
            "observations": output.observations,
            "recommendations": output.recommendations,
        }))
        .send()
        .await
        .context("call core analysis storage endpoint")?;
    if !response.status().is_success() {
        anyhow::bail!("core analysis endpoint returned {}", response.status());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let token = secret("CLAWFORGE_ANALYZER_TOKEN")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(
            env::var("CLAWFORGE_ANALYZER_TIMEOUT_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(30),
        ))
        .build()?;
    let provider = build_provider(client.clone())?;
    let bind = env::var("CLAWFORGE_ANALYZER_BIND").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let address: SocketAddr = bind.parse().context("invalid CLAWFORGE_ANALYZER_BIND")?;
    let state = AppState {
        token,
        core_api_url: env::var("CLAWFORGE_CORE_API_URL")
            .unwrap_or_else(|_| "http://clawforge-api:8080".into()),
        provider,
        client,
    };
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "Clawforge analyzer listening on internal network");
    axum::serve(
        listener,
        Router::new()
            .route("/health", get(health))
            .route("/analyze", post(analyze))
            .with_state(state),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_wrong_token_is_rejected() {
        let headers = HeaderMap::new();
        assert!(!authorized(&headers, "secret"));
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer wrong".parse().unwrap());
        assert!(!authorized(&headers, "secret"));
    }
}
