use clawforge_storage::PostgresStore;
use clawforge_intelligence::{Indicator, IndicatorType, Provider};
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
    let provider = Provider { id: "test-provider".into(), name: "Test Provider".into(), source: "test".into(), interval_seconds: 900, confidence: 80, enabled: true };
    restarted.upsert_provider(&provider).await?;
    let next_run = now + Duration::minutes(15);
    restarted.provider_succeeded(&provider.id, next_run, 1, 42).await?;
    let metrics: (i32, i64) = sqlx::query_as("SELECT indicator_count, sync_duration_ms FROM provider_status WHERE provider_id = $1")
        .bind(&provider.id).fetch_one(restarted.pool()).await?;
    assert_eq!(metrics, (1, 42));
    let expired = Indicator { value: "198.51.100.11".into(), expires_at: now - Duration::minutes(1), ..updated.clone() };
    restarted.upsert_indicator(&expired).await?;
    assert_eq!(restarted.expire_indicators(now).await?, 1);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM risk_history WHERE indicator_id = $1")
        .bind(id).fetch_one(restarted.pool()).await?;
    assert_eq!(count, 1);
    Ok(())
}
