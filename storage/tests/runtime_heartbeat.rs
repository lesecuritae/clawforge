//! A component that wrote its runtime status only at startup looked down to `clawforge_component_up`
//! two minutes later while its container was healthy (api and incidents in 1.2.7: heartbeat age 9,400 s,
//! metric 0). The heartbeat helper must keep the metric at 1, must not resurrect a stopped component,
//! and a component that stops beating must read 0 again.
use anyhow::Result;
use clawforge_storage::PostgresStore;
use sqlx::PgPool;
use std::time::Duration;

const COMPONENT: &str = "heartbeat-test";

/// The exporter caches for 30 s per store instance: read through a fresh one so each check is live.
async fn component_up(_api: &PostgresStore) -> Result<Option<i64>> {
    let fresh =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_API_DATABASE_URL")?).await?;
    let text = fresh.metrics_text().await?;
    Ok(text
        .lines()
        .find(|l| {
            l.starts_with(&format!(
                "clawforge_component_up{{component=\"{COMPONENT}\"}} "
            ))
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok()))
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn a_heartbeating_component_stays_up_a_silent_one_reads_down_and_stopped_stays_stopped(
) -> Result<()> {
    let owner = PgPool::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
    let api =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_API_DATABASE_URL")?).await?;
    let age = |minutes: i32| {
        let owner = owner.clone();
        async move {
            sqlx::query("UPDATE runtime_status SET updated_at = NOW() - make_interval(mins => $2), last_heartbeat_at = NOW() - make_interval(mins => $2) WHERE component = $1")
                .bind(COMPONENT)
                .bind(minutes)
                .execute(&owner)
                .await
        }
    };

    // control: the old behaviour (status written once) reads down after the 2-minute window
    api.set_runtime_status(COMPONENT, "running", None).await?;
    assert_eq!(component_up(&api).await?, Some(1));
    age(10).await?;
    assert_eq!(
        component_up(&api).await?,
        Some(0),
        "startup-only status goes stale: the defect"
    );

    // the heartbeat brings it back and keeps it there while it runs
    let heartbeat = api.spawn_runtime_heartbeat(COMPONENT, Duration::from_millis(200));
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        component_up(&api).await?,
        Some(1),
        "heartbeat refreshes a stale status"
    );
    age(10).await?;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(component_up(&api).await?, Some(1), "and keeps doing so");

    // shutdown order: abort first, then write stopped - a late tick must not turn it back to running
    heartbeat.abort();
    api.set_runtime_status(COMPONENT, "stopped", None).await?;
    tokio::time::sleep(Duration::from_millis(700)).await;
    let state: String = sqlx::query_scalar("SELECT state FROM runtime_status WHERE component = $1")
        .bind(COMPONENT)
        .fetch_one(&owner)
        .await?;
    assert_eq!(state, "stopped");
    assert_eq!(component_up(&api).await?, Some(0));

    // a component that stops beating reads down again
    api.set_runtime_status(COMPONENT, "running", None).await?;
    let silent = api.spawn_runtime_heartbeat(COMPONENT, Duration::from_millis(200));
    silent.abort();
    age(10).await?;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(component_up(&api).await?, Some(0), "no heartbeat, no up");

    sqlx::query("DELETE FROM runtime_status WHERE component = $1")
        .bind(COMPONENT)
        .execute(&owner)
        .await?;
    Ok(())
}
