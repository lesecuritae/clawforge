//! Sensor freshness is exported as a metric so a silent remote sensor is visible without
//! shell access to its host.
use anyhow::Result;
use clawforge_storage::PostgresStore;
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn sensor_last_seen_age_is_exported_per_enabled_sensor() -> Result<()> {
    let owner = PgPool::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
    let tag = Uuid::new_v4().simple().to_string();
    let (fresh, stale, never, revoked) = (
        format!("metric-fresh-{tag}"),
        format!("metric-stale-{tag}"),
        format!("metric-never-{tag}"),
        format!("metric-revoked-{tag}"),
    );
    for (name, seen, revoked_at) in [
        (&fresh, Some("5 seconds"), false),
        (&stale, Some("3 hours"), false),
        (&never, None, false),
        (&revoked, Some("5 seconds"), true),
    ] {
        sqlx::query("INSERT INTO security_sensors(id,name,credential_hash,credential_prefix,enabled,last_seen_at,revoked_at) VALUES ($1,$2,$3,$4,NOT $6, CASE WHEN $5::text IS NULL THEN NULL ELSE NOW()-$5::interval END, CASE WHEN $6 THEN NOW() ELSE NULL END)")
            .bind(Uuid::new_v4()).bind(name).bind(format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())).bind(&tag[..8]).bind(seen).bind(revoked_at)
            .execute(&owner).await?;
    }
    let api =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_API_DATABASE_URL")?).await?;
    let text = api.metrics_text().await?;
    let value = |name: &str| -> Option<i64> {
        text.lines()
            .find(|l| {
                l.starts_with(&format!(
                    "clawforge_security_sensor_last_seen_age_seconds{{sensor=\"{name}\"}} "
                ))
            })
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
    };
    assert!(
        value(&fresh).is_some_and(|v| (0..60).contains(&v)),
        "{text}"
    );
    assert!(
        value(&stale).is_some_and(|v| (10_000..11_000).contains(&v)),
        "{text}"
    );
    assert_eq!(
        value(&never),
        Some(2_000_000_000),
        "never reported is not 'fresh'"
    );
    assert_eq!(value(&revoked), None, "revoked sensors are not exported");
    Ok(())
}
