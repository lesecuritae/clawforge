use clawforge_storage::{database_url_from_env, PostgresStore};
use std::{env, time::Duration};
use tokio::time::{interval, MissedTickBehavior};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    if env::var("CLAWFORGE_EXECUTOR_DRY_RUN")
        .unwrap_or_else(|_| "true".into())
        .to_lowercase()
        != "true"
    {
        anyhow::bail!(
            "productive execution is disabled; CLAWFORGE_EXECUTOR_DRY_RUN must remain true"
        );
    }
    let store = PostgresStore::connect(&database_url_from_env()?).await?;
    let worker_name = env::var("CLAWFORGE_EXECUTOR_WORKER_NAME")
        .unwrap_or_else(|_| format!("executor-{}", std::process::id()));
    let worker_capacity = env::var("CLAWFORGE_EXECUTOR_WORKER_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(1)
        .clamp(1, 64);
    let worker_id = store
        .register_execution_worker(&worker_name, worker_capacity)
        .await?;
    store
        .set_runtime_status("executor", "running", None)
        .await?;
    let seconds = env::var("CLAWFORGE_EXECUTOR_POLL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10u64)
        .max(2);
    let mut ticks = interval(Duration::from_secs(seconds));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticks.tick() => {
                if let Err(error) = store.set_runtime_status("executor", "running", None).await { tracing::warn!(%error, "executor heartbeat failed"); }
                if let Err(error) = store.heartbeat_execution_worker(worker_id, "healthy", 0, None).await { tracing::warn!(%error, "executor worker heartbeat failed"); }
                if let Err(error) = store.process_one_dry_run_for_worker(Some(worker_id)).await {
                    tracing::warn!(%error, "dry-run request processing failed");
                    let _ = store.heartbeat_execution_worker(worker_id, "degraded", 0, Some(&error.to_string())).await;
                }
            }
            _ = shutdown_signal() => { let _ = store.heartbeat_execution_worker(worker_id, "stopped", 0, None).await; let _ = store.set_runtime_status("executor", "stopped", None).await; break; }
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("signal");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
