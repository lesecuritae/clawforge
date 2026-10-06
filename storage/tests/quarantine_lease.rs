//! Generic lease recovery must never replay an owned external quarantine.
use anyhow::Result;
use clawforge_storage::{ExecutionRequestInput, PostgresStore};
use serde_json::json;
use sqlx::{postgres::PgConnectOptions, ConnectOptions, PgPool};
use std::str::FromStr;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires explicit isolated CLAWFORGE_TEST_QUARANTINE_DATABASE_URL with CREATE DATABASE"]
async fn durable_generations_block_claim_reclaim_timeout_and_retry() -> Result<()> {
    let base = std::env::var("CLAWFORGE_TEST_QUARANTINE_DATABASE_URL")?;
    let admin = PgPool::connect(&base).await?;
    let database = format!("quarantine_lease_{}", Uuid::new_v4().simple());
    let url = PgConnectOptions::from_str(&base)?
        .database(&database)
        .to_url_lossy()
        .to_string();
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await?;
    // A spawned task turns assertion panics into JoinError, allowing cleanup
    // even when the regression reproduces. Never touch the base database.
    let result = tokio::spawn(async move { check_owned_generations(&url).await }).await;
    let cleanup = sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&admin)
        .await;
    admin.close().await;
    cleanup?;
    result??;
    Ok(())
}

async fn check_owned_generations(url: &str) -> Result<()> {
    let store = PostgresStore::connect(url).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_requests")
        .fetch_one(store.pool())
        .await?;
    anyhow::ensure!(
        count == 0,
        "lease fixture must be an empty disposable database"
    );
    let action: Uuid = sqlx::query_scalar(
        "UPDATE actions SET enabled=TRUE WHERE name='docker.quarantine_container' RETURNING id",
    )
    .fetch_one(store.pool())
    .await?;
    let worker = Uuid::new_v4();
    sqlx::query("INSERT INTO execution_workers(id,name) VALUES($1,$2)")
        .bind(worker)
        .bind(format!("lease-{worker}"))
        .execute(store.pool())
        .await?;
    let mut owned = Vec::new();
    for intent_status in ["prepared", "completed", "recovery_required"] {
        for request_status in ["running", "failed", "queued"] {
            let nonce = Uuid::new_v4();
            let requester_name = format!("lease-requester-{nonce}");
            let requester = store
                .create_admin_user(&requester_name, "Administrator", "fixture-hash")
                .await?;
            let fp = nonce.simple().to_string().repeat(2);
            let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60});
            let execution = store
                .create_execution_request(&ExecutionRequestInput {
                    action_id: action,
                    workflow_run_id: None,
                    decision_id: None,
                    requested_by: requester_name,
                    requested_by_id: Some(requester),
                    idempotency_key: None,
                    target: Some(target.clone()),
                })
                .await?;
            for index in 0..2 {
                let name = format!("lease-approver-{nonce}-{index}");
                let id = store
                    .create_admin_user(&name, "Approver", "fixture-hash")
                    .await?;
                store
                    .approve_execution_request(execution, id, &name)
                    .await?;
            }
            sqlx::query("UPDATE execution_requests SET status='starting' WHERE id=$1")
                .bind(execution)
                .execute(store.pool())
                .await?;
            let intent = store
                .prepare_quarantine_intent(
                    execution,
                    "docker",
                    &fp,
                    &target,
                    &json!({}),
                    &json!({}),
                    60,
                )
                .await?;
            if intent_status != "prepared" {
                sqlx::query("UPDATE firewall_action_intents SET status=$2 WHERE id=$1")
                    .bind(intent)
                    .bind(intent_status)
                    .execute(store.pool())
                    .await?;
            }
            sqlx::query("UPDATE execution_requests SET status=$2,started_at=NOW()-INTERVAL '10 minutes',next_retry_at=NOW()-INTERVAL '1 minute' WHERE id=$1").bind(execution).bind(request_status).execute(store.pool()).await?;
            sqlx::query("INSERT INTO execution_leases(id,execution_id,worker_id,expires_at) VALUES($1,$2,$3,NOW()-INTERVAL '1 minute')").bind(Uuid::new_v4()).bind(execution).bind(worker).execute(store.pool()).await?;
            owned.push((execution, intent, request_status));
        }
    }
    assert!(store
        .claim_execution_request_for_dispatch(None)
        .await?
        .is_none());
    store.process_one_dry_run_for_worker(None).await?;
    for (id, _, expected) in &owned {
        let actual: (String, i32) =
            sqlx::query_as("SELECT status,retry_count FROM execution_requests WHERE id=$1")
                .bind(id)
                .fetch_one(store.pool())
                .await?;
        assert_eq!(
            actual,
            (expected.to_string(), 0),
            "owned {id} was replayed or timed out"
        );
    }
    // A normal request still follows the pre-existing expired-lease reclaim path.
    let normal_action = Uuid::new_v4();
    sqlx::query("INSERT INTO actions(id,name,type,risk_level,required_scope,requires_approval,enabled) VALUES($1,$2,'connector_action','low','agent:action:read',FALSE,TRUE)").bind(normal_action).bind(format!("lease-normal-{normal_action}")).execute(store.pool()).await?;
    let normal = Uuid::new_v4();
    sqlx::query("INSERT INTO execution_requests(id,action_id,requested_by,status,started_at) VALUES($1,$2,'fixture','pending',NOW())").bind(normal).bind(normal_action).execute(store.pool()).await?;
    sqlx::query("INSERT INTO execution_leases(id,execution_id,worker_id,expires_at) VALUES($1,$2,$3,NOW()-INTERVAL '1 minute')").bind(Uuid::new_v4()).bind(normal).bind(worker).execute(store.pool()).await?;
    sqlx::query("UPDATE execution_requests SET status='starting' WHERE id=$1")
        .bind(normal)
        .execute(store.pool())
        .await?;
    sqlx::query("UPDATE execution_requests SET status='running' WHERE id=$1")
        .bind(normal)
        .execute(store.pool())
        .await?;
    assert_eq!(
        store
            .claim_execution_request_for_dispatch(None)
            .await?
            .unwrap()
            .id,
        normal
    );
    Ok(())
}
