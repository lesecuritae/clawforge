use std::{env, net::SocketAddr};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use clawforge_storage::PostgresStore;
use serde::Serialize;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
    store: PostgresStore,
}

#[derive(Serialize)]
struct ServiceStatus<'a> {
    service: &'a str,
    status: &'a str,
}

async fn health(State(state): State<AppState>) -> Result<Json<ServiceStatus<'static>>, StatusCode> {
    state.store.healthcheck().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(ServiceStatus { service: "clawforge-api", status: "ok" }))
}

async fn ready(State(state): State<AppState>) -> Result<Json<ServiceStatus<'static>>, StatusCode> {
    state.store.healthcheck().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(ServiceStatus { service: "clawforge-api", status: "ready" }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be configured");
    let store = PostgresStore::connect(&database_url).await?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(AppState { store });
    let bind = env::var("CLAWFORGE_API_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let address: SocketAddr = bind.parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "Clawforge API listening");
    axum::serve(listener, app).await?;
    Ok(())
}
