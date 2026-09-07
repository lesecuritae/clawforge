use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::{env, fs, time::Duration};
use tracing::{info, warn};

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Clone)]
struct Config {
    api_url: String,
    token: String,
    poll: Duration,
}

fn configured_token() -> Result<String> {
    if let Ok(path) = env::var("CLAWFORGE_EVENTS_TOKEN_FILE") {
        if let Ok(value) = fs::read_to_string(path) {
            if !value.trim().is_empty() {
                return Ok(value.trim().to_string());
            }
        }
    }
    env::var("CLAWFORGE_EVENTS_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .context("event service token is not configured")
}

async fn poll_once(client: &Client, config: &Config) -> Result<()> {
    let response = client
        .get(format!(
            "{}/internal/events/consume?consumer=events&limit=50",
            config.api_url.trim_end_matches('/')
        ))
        .bearer_auth(&config.token)
        .send()
        .await?
        .error_for_status()?;
    let envelope: Envelope<Vec<Value>> = response.json().await?;
    for event in envelope.data {
        let Some(delivery_id) = event.get("delivery_id").and_then(Value::as_str) else {
            continue;
        };
        info!(
            delivery_id,
            event_type = ?event.get("event_type"),
            event_id = ?event.get("event_id"),
            "event backbone delivery processed"
        );
        client
            .post(format!(
                "{}/internal/events/{}/result",
                config.api_url.trim_end_matches('/'),
                delivery_id
            ))
            .bearer_auth(&config.token)
            .json(&serde_json::json!({"success":true}))
            .send()
            .await?
            .error_for_status()?;
    }
    Ok(())
}

fn config() -> Result<Config> {
    Ok(Config {
        api_url: env::var("CLAWFORGE_CORE_API_URL")
            .unwrap_or_else(|_| "http://clawforge-api:8080".into()),
        token: configured_token()?,
        poll: Duration::from_secs(
            env::var("CLAWFORGE_EVENTS_POLL_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(5),
        ),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let config = config()?;
    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
    info!(api_url = %config.api_url, "Clawforge event backbone started");
    let mut interval = tokio::time::interval(config.poll);
    loop {
        tokio::select! {
            _ = interval.tick() => if let Err(error) = poll_once(&client, &config).await { warn!(%error, "event backbone poll failed"); },
            _ = shutdown_signal() => { info!("Clawforge event backbone shutting down"); break; }
        }
    }
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
