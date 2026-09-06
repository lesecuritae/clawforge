use std::{env, time::Duration};

use clawforge_storage::PostgresStore;
use tokio::time::{interval, MissedTickBehavior};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be configured");
    let store = PostgresStore::connect(&database_url).await?;
    let seconds = env::var("CLAWFORGE_WORKER_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);
    let mut ticks = interval(Duration::from_secs(seconds.max(5)));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tracing::info!(poll_seconds = seconds, "Clawforge worker started; scheduler is idle until providers are configured");
    loop {
        tokio::select! {
            _ = ticks.tick() => {
                if let Err(error) = store.healthcheck().await {
                    tracing::error!(%error, "worker database health check failed");
                } else {
                    tracing::debug!("worker cycle ready for configured sync jobs");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("worker shutdown requested");
                break;
            }
        }
    }
    Ok(())
}
