use anyhow::Result;
use clawforge_storage::{database_url_from_env, PostgresStore};
use std::{env, time::Duration};
use tracing::{info, warn};

fn poll_interval() -> Duration {
    env::var("CLAWFORGE_INCIDENT_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(5))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let store = PostgresStore::connect_runtime(&database_url_from_env()?).await?;
    store
        .set_runtime_status("incidents", "running", None)
        .await?;
    let poll = poll_interval();
    info!(?poll, "Clawforge incident management started");
    let mut interval = tokio::time::interval(poll);
    // The status follows the loop: it is refreshed while promotion works and reports `error` (once, the
    // transition writes an operational event) while it fails, instead of staying `running` from startup.
    let mut reported_error = false;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                match store.promote_incident_candidates(50).await {
                    Ok(promoted) => {
                        if promoted > 0 {
                            info!(promoted, "incident candidates promoted");
                        }
                        if let Err(error) = store.set_runtime_status("incidents", "running", None).await {
                            warn!(%error, "could not heartbeat incidents runtime status");
                        }
                        reported_error = false;
                    }
                    Err(error) => {
                        warn!(%error, "incident candidate promotion failed");
                        if !reported_error {
                            let detail = error.to_string().chars().take(160).collect::<String>();
                            match store.set_runtime_status("incidents", "error", Some(&detail)).await {
                                Ok(()) => reported_error = true,
                                Err(status_error) => warn!(%status_error, "could not report incidents error state"),
                            }
                        }
                    }
                }
            },
            _ = shutdown_signal() => {
                info!("Clawforge incident management shutting down");
                break;
            }
        }
    }
    store
        .set_runtime_status("incidents", "stopped", None)
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
    use super::poll_interval;
    use std::time::Duration;

    #[test]
    fn default_poll_interval_is_bounded() {
        std::env::remove_var("CLAWFORGE_INCIDENT_POLL_SECONDS");
        assert_eq!(poll_interval(), Duration::from_secs(5));
    }
}
