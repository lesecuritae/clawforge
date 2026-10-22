//! Event-delivery claim (migration 0065): oldest ready delivery first, bounded work per
//! poll however deep the backlog, stale in-flight work is reclaimed, concurrent consumers
//! never receive the same delivery, and it all works under the consumer's own role.
use anyhow::Result;
use clawforge_storage::{PostgresStore, CLAIM_READY_DELIVERIES_SQL, CLAIM_STALE_DELIVERIES_SQL};
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use uuid::Uuid;

async fn owner() -> Result<PgPool> {
    Ok(PgPool::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?)
}

async fn consumer_store() -> Result<PostgresStore> {
    // The correlation role may SELECT events and touch only its own delivery bookkeeping.
    PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_CORRELATION_DATABASE_URL")?).await
}

fn consumer_name() -> String {
    format!("claim-test-{}", Uuid::new_v4().simple())
}

/// Insert `count` events with deliveries for `consumer`, `age_step` seconds apart, the oldest
/// first. Returns the delivery ids oldest -> newest.
async fn seed(
    pool: &PgPool,
    consumer: Uuid,
    count: i32,
    status: &str,
    attempts: i32,
    available_in_seconds: i32,
    offset: i32,
) -> Result<Vec<Uuid>> {
    let rows = sqlx::query(
        "WITH e AS (
           INSERT INTO events (event_id,event_type,source,severity,occurred_at,payload,metadata,dedupe_key)
           SELECT gen_random_uuid(),'claim-test','claim-test','low',NOW(),'{}'::jsonb,'{}'::jsonb,
                  'claim-' || gen_random_uuid()::text
             FROM generate_series(1,$1) RETURNING event_id)
         INSERT INTO event_delivery (id,event_id,consumer_id,status,attempts,available_at,created_at)
         SELECT gen_random_uuid(), e.event_id, $2, $3, $4, NOW()+($5*INTERVAL '1 second'),
                NOW()-INTERVAL '1 day' + ($6 + row_number() OVER ()) * INTERVAL '1 second'
           FROM e RETURNING id,created_at",
    )
    .bind(count)
    .bind(consumer)
    .bind(status)
    .bind(attempts)
    .bind(available_in_seconds)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let mut rows: Vec<(chrono::DateTime<chrono::Utc>, Uuid)> = rows
        .iter()
        .map(|r| (r.get("created_at"), r.get("id")))
        .collect();
    rows.sort();
    Ok(rows.into_iter().map(|(_, id)| id).collect())
}

fn ids(claimed: &[serde_json::Value]) -> Vec<Uuid> {
    claimed
        .iter()
        .map(|v| v["delivery_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn claims_the_oldest_ready_deliveries_first_and_skips_everything_else() -> Result<()> {
    let pool = owner().await?;
    let store = consumer_store().await?;
    let name = consumer_name();
    store.claim_event_deliveries(&name, 1).await?; // registers the consumer
    let cid: Uuid = sqlx::query_scalar("SELECT id FROM event_consumers WHERE name=$1")
        .bind(&name)
        .fetch_one(&pool)
        .await?;
    let pending = seed(&pool, cid, 8, "pending", 0, 0, 0).await?;
    let failed_ready = seed(&pool, cid, 1, "failed", 1, -10, 100).await?;
    let failed_later = seed(&pool, cid, 1, "failed", 1, 3600, 200).await?;
    let processed = seed(&pool, cid, 1, "processed", 1, 0, 300).await?;
    let dead = seed(&pool, cid, 1, "dead", 5, -10, 400).await?;
    let exhausted = seed(&pool, cid, 1, "pending", 5, 0, 500).await?;
    let ignored: HashSet<Uuid> = [failed_later, processed, dead, exhausted]
        .into_iter()
        .flatten()
        .collect();
    // created_at of the seeds is row_number seconds; all batches share the same origin,
    // so the expected order is by (row index within batch, batch order). Compare through SQL.
    let expected: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM event_delivery WHERE consumer_id=$1 AND status IN ('pending','failed')
            AND available_at <= NOW() AND attempts < 5 ORDER BY created_at",
    )
    .bind(cid)
    .fetch_all(&pool)
    .await?;
    assert_eq!(expected.len(), pending.len() + failed_ready.len());

    let first = ids(&store.claim_event_deliveries(&name, 4).await?);
    assert_eq!(first, expected[..4], "oldest ready deliveries first");
    let claimed = store.claim_event_deliveries(&name, 100).await?;
    let rest = ids(&claimed);
    assert_eq!(rest, expected[4..], "the rest, still oldest first");
    assert!(
        claimed.iter().all(|v| v["attempts"].as_i64().unwrap() >= 1),
        "attempts reports the new attempt number"
    );
    assert!(rest.iter().all(|id| !ignored.contains(id)));
    assert!(store.claim_event_deliveries(&name, 100).await?.is_empty());
    let states: Vec<String> =
        sqlx::query_scalar("SELECT status FROM event_delivery WHERE id = ANY($1) ORDER BY id")
            .bind(&expected)
            .fetch_all(&pool)
            .await?;
    assert!(states.iter().all(|s| s == "processing"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn a_deep_backlog_cannot_starve_a_stuck_in_flight_delivery() -> Result<()> {
    let pool = owner().await?;
    let store = consumer_store().await?;
    let name = consumer_name();
    store.claim_event_deliveries(&name, 1).await?;
    let cid: Uuid = sqlx::query_scalar("SELECT id FROM event_consumers WHERE name=$1")
        .bind(&name)
        .fetch_one(&pool)
        .await?;
    let backlog = seed(&pool, cid, 300, "pending", 0, 0, 0).await?;
    let stale = seed(&pool, cid, 1, "processing", 1, -10, 1000).await?[0];
    let fresh = seed(&pool, cid, 1, "processing", 1, -10, 2000).await?[0];
    sqlx::query("UPDATE event_delivery SET processing_started_at=NOW()-INTERVAL '11 minutes', created_at=NOW() WHERE id=$1")
        .bind(stale).execute(&pool).await?;
    sqlx::query("UPDATE event_delivery SET processing_started_at=NOW()-INTERVAL '1 minute', created_at=NOW() WHERE id=$1")
        .bind(fresh).execute(&pool).await?;
    let claimed = ids(&store.claim_event_deliveries(&name, 3).await?);
    assert_eq!(claimed.len(), 3);
    assert_eq!(claimed[0..2].len(), 2);
    assert!(
        claimed.contains(&stale),
        "stuck delivery is reclaimed even behind 300 ready rows"
    );
    assert!(
        !claimed.contains(&fresh),
        "a delivery still within its lease is left alone"
    );
    let reclaimed_attempts: i32 =
        sqlx::query_scalar("SELECT attempts FROM event_delivery WHERE id=$1")
            .bind(stale)
            .fetch_one(&pool)
            .await?;
    assert_eq!(reclaimed_attempts, 2);
    // the other two slots went to the oldest ready rows
    let others: HashSet<Uuid> = claimed.into_iter().filter(|id| *id != stale).collect();
    let oldest: HashSet<Uuid> = backlog.iter().take(2).copied().collect();
    assert_eq!(others, oldest);
    Ok(())
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn concurrent_consumers_never_receive_the_same_delivery() -> Result<()> {
    let pool = owner().await?;
    let name = consumer_name();
    let a = consumer_store().await?;
    let b = consumer_store().await?;
    a.claim_event_deliveries(&name, 1).await?;
    let cid: Uuid = sqlx::query_scalar("SELECT id FROM event_consumers WHERE name=$1")
        .bind(&name)
        .fetch_one(&pool)
        .await?;
    let seeded: HashSet<Uuid> = seed(&pool, cid, 400, "pending", 0, 0, 0)
        .await?
        .into_iter()
        .collect();
    let mut seen = Vec::new();
    loop {
        let (x, y) = tokio::join!(
            a.claim_event_deliveries(&name, 50),
            b.claim_event_deliveries(&name, 50)
        );
        let (x, y) = (ids(&x?), ids(&y?));
        if x.is_empty() && y.is_empty() {
            break;
        }
        seen.extend(x);
        seen.extend(y);
    }
    let unique: HashSet<Uuid> = seen.iter().copied().collect();
    assert_eq!(seen.len(), unique.len(), "no delivery was handed out twice");
    assert_eq!(
        unique, seeded,
        "every ready delivery was handed out exactly once"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn the_claim_reads_the_ready_index_in_order_and_does_not_sort_the_backlog() -> Result<()> {
    let pool = owner().await?;
    let store = consumer_store().await?;
    let name = consumer_name();
    store.claim_event_deliveries(&name, 1).await?;
    let cid: Uuid = sqlx::query_scalar("SELECT id FROM event_consumers WHERE name=$1")
        .bind(&name)
        .fetch_one(&pool)
        .await?;
    seed(&pool, cid, 40_000, "pending", 0, 0, 0).await?;
    sqlx::query("ANALYZE event_delivery").execute(&pool).await?;
    for (label, sql) in [
        ("ready", CLAIM_READY_DELIVERIES_SQL),
        ("stale", CLAIM_STALE_DELIVERIES_SQL),
    ] {
        let plan: Vec<String> = sqlx::query_scalar(&format!(
            "EXPLAIN {}",
            sql.replace("$1", &format!("'{cid}'")).replace("$2", "50")
        ))
        .fetch_all(&pool)
        .await?;
        let plan = plan.join("\n");
        assert!(
            !plan.contains("Seq Scan"),
            "{label} claim must not scan the table:\n{plan}"
        );
        if label == "ready" {
            assert!(
                !plan.contains("Sort"),
                "ready claim must not sort the backlog:\n{plan}"
            );
            assert!(
                plan.contains("event_delivery_ready_idx"),
                "ready claim uses the partial index:\n{plan}"
            );
        } else {
            // only the in-flight set (status = 'processing') is ever read and sorted
            assert!(
                plan.contains("status = 'processing'"),
                "stale claim is restricted to in-flight rows:\n{plan}"
            );
        }
    }
    // and the plan is cheap in rows actually read
    let actual: Vec<String> = sqlx::query_scalar(&format!(
        "EXPLAIN (ANALYZE, BUFFERS OFF, TIMING OFF) {}",
        CLAIM_READY_DELIVERIES_SQL
            .replace("$1", &format!("'{cid}'"))
            .replace("$2", "50")
    ))
    .fetch_all(&pool)
    .await?;
    let actual = actual.join("\n");
    assert!(actual.contains("actual rows=50"), "{actual}");
    Ok(())
}
