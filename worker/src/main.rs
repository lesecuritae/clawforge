use std::{env, time::Duration};

use clawforge_storage::{database_url_from_env, PostgresStore};
use clawforge_worker::Scheduler;
use tokio::time::{interval, MissedTickBehavior};
use tracing_subscriber::EnvFilter;

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
    let store = PostgresStore::connect(&database_url).await?;
    store.set_runtime_status("worker", "running", None).await?;
    let seconds = env::var("CLAWFORGE_WORKER_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);
    let enabled = env::var("CLAWFORGE_ENABLE_FEEDS")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    let mut scheduler = Scheduler::phase_one(enabled)?;
    let mut ticks = interval(Duration::from_secs(seconds.max(5)));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tracing::info!(
        poll_seconds = seconds,
        providers = scheduler.provider_count(),
        feeds_enabled = enabled,
        network_enabled = env::var("CLAWFORGE_ENABLE_NETWORK")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false),
        "Clawforge worker started"
    );
    loop {
        tokio::select! {
            _ = ticks.tick() => {
                if let Err(error) = store.set_runtime_status("worker", "running", None).await {
                    tracing::warn!(%error, "worker heartbeat persistence failed");
                }
                if let Err(error) = store.healthcheck().await {
                    tracing::error!(%error, "worker database health check failed");
                    let _ = store.set_runtime_status("worker", "error", Some(&error.to_string())).await;
                } else {
                    scheduler.run_due(&store).await;
                    if let Err(error) = store.capture_operations_snapshot().await {
                        tracing::warn!(%error, "operations snapshot persistence failed");
                    }
                }
            }
            _ = shutdown_signal() => {
                tracing::info!("worker shutdown requested");
                let _ = store.set_runtime_status("worker", "stopped", None).await;
                break;
            }
        }
    }
    Ok(())
}
