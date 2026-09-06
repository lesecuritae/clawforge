use clawforge_storage::PostgresStore;
use clawforge_intelligence::{Indicator, IndicatorType};
use chrono::{Duration, Utc};
use serde_json::json;

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL test container"]
async fn migrations_and_restart_persist() -> anyhow::Result<()> {
    let url = std::env::var("CLAWFORGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))?;
    let store = PostgresStore::connect(&url).await?;
    store.healthcheck().await?;
    assert!(store.migration_version().await?.is_some());
    drop(store);
    let restarted = PostgresStore::connect(&url).await?;
    restarted.healthcheck().await?;
    let now = Utc::now();
    let indicator = Indicator {
        value: "198.51.100.10".into(),
        indicator_type: IndicatorType::Ip,
        categories: vec!["test".into()],
        confidence: 80,
        source: "test".into(),
        first_seen: now,
        last_seen: now,
        expires_at: now + Duration::hours(1),
        metadata: json!({"test": true}),
    };
    let id = restarted.upsert_indicator(&indicator).await?;
    let updated = Indicator { confidence: 90, ..indicator.clone() };
    assert_eq!(restarted.upsert_indicator(&updated).await?, id);
    restarted.record_risk_event(id, &updated, 20, 20, 0, "test indicator").await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM risk_history WHERE indicator_id = $1")
        .bind(id).fetch_one(restarted.pool()).await?;
    assert_eq!(count, 1);
    Ok(())
}
