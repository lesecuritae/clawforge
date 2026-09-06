use std::{env, net::SocketAddr};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use clawforge_storage::{database_url_from_env, MigrationStatus, PostgresStore};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
    store: PostgresStore,
    config: RuntimeConfig,
}

#[derive(Clone)]
struct RuntimeConfig {
    bind: SocketAddr,
    database_configured: bool,
}

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    status: &'static str,
    checks: HealthChecks,
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

impl From<MigrationStatus> for MigrationResponse {
    fn from(status: MigrationStatus) -> Self {
        Self { current: status.current, applied: status.applied, expected: status.expected, latest: status.latest, expected_latest: status.expected_latest }
    }
}

async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let configuration = if state.config.database_configured && state.config.bind.port() != 0 { "ok" } else { "error" };
    let status = if configuration == "ok" { "ok" } else { "error" };
    let code = if status == "ok" { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (code, Json(HealthResponse { service: "clawforge-api", status, checks: HealthChecks { process: "ok", configuration, postgres: None, migrations: None } }))
}

async fn ready(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let migration = state.store.readiness().await.ok();
    let postgres_ok = migration.is_some();
    let migrations_ok = migration.as_ref().is_some_and(|value| value.current);
    let status = if postgres_ok && migrations_ok && state.config.database_configured { "ready" } else { "not_ready" };
    let code = if status == "ready" { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (code, Json(HealthResponse { service: "clawforge-api", status, checks: HealthChecks { process: "ok", configuration: if state.config.database_configured { "ok" } else { "error" }, postgres: Some(if postgres_ok { "ok" } else { "error" }), migrations: migration.map(Into::into) } }))
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
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let database_url = database_url_from_env()?;
    let bind = env::var("CLAWFORGE_API_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let address: SocketAddr = bind.parse().map_err(|error| anyhow::anyhow!("invalid CLAWFORGE_API_BIND: {error}"))?;
    let store = PostgresStore::connect(&database_url).await?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(AppState { store, config: RuntimeConfig { bind: address, database_configured: true } });
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "Clawforge API listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}
