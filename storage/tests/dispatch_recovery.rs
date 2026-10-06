//! Uncertain firewall mutations must remain recoverable and never be replayed.
use anyhow::Result;
use clawforge_storage::PostgresStore;
use sqlx::{postgres::PgConnectOptions, ConnectOptions, PgPool};
use std::{str::FromStr, time::Instant};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires explicit disposable owner and restricted executor database URLs"]
async fn uncertain_dispatch_retains_recovery_and_never_replays() -> Result<()> {
    let base = std::env::var("CLAWFORGE_TEST_DATABASE_URL")?;
    let executor_base = std::env::var("CLAWFORGE_TEST_EXECUTOR_DATABASE_URL")?;
    let admin = PgPool::connect(&base).await?;
    let database = format!("dispatch_recovery_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await?;
    let owner_url = PgConnectOptions::from_str(&base)?
        .database(&database)
        .to_url_lossy()
        .to_string();
    let executor_url = PgConnectOptions::from_str(&executor_base)?
        .database(&database)
        .to_url_lossy()
        .to_string();
    let result =
        tokio::spawn(async move { check_completion(&owner_url, &executor_url).await }).await;
    let cleanup = sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&admin)
        .await;
    admin.close().await;
    cleanup?;
    result??;
    Ok(())
}

async fn check_completion(owner_url: &str, executor_url: &str) -> Result<()> {
    let owner = PostgresStore::connect(owner_url).await?;
    // Use the actual provisioner's executor grants, rather than granting an
    // owner-equivalent role to make a regression pass in an isolated database.
    let provision = include_str!("../../scripts/provision-db-roles.sh");
    let grants = provision
        .split("GRANT SELECT ON TABLE _sqlx_migrations, actions, execution_requests,")
        .nth(1)
        .expect("executor grants start")
        .split("GRANT SELECT ON ALL TABLES IN SCHEMA public TO clawforge_backup;")
        .next()
        .expect("executor grants end");
    sqlx::raw_sql(&format!(
        "GRANT SELECT ON TABLE _sqlx_migrations, actions, execution_requests,{grants}"
    ))
    .execute(owner.pool())
    .await?;
    let executor = PostgresStore::connect_runtime(executor_url).await?;
    let privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolcreatedb FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(executor.pool())
    .await?;
    assert!(
        !privileged,
        "completion must use a restricted executor login"
    );
    let action = Uuid::new_v4();
    sqlx::query("INSERT INTO actions(id,name,type,risk_level,required_scope,requires_approval,enabled) VALUES($1,'dispatch-recovery-fixture','connector_action','low','agent:action:read',FALSE,TRUE)")
        .bind(action).execute(owner.pool()).await?;
    let worker = Uuid::new_v4();
    sqlx::query("INSERT INTO execution_workers(id,name) VALUES($1,'dispatch-recovery-worker')")
        .bind(worker)
        .execute(owner.pool())
        .await?;
    let mut requests = Vec::new();
    for status in ["rollback_required", "success", "failed"] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO execution_requests(id,action_id,requested_by,status,max_retries) VALUES($1,$2,'fixture','pending',3)")
            .bind(id).bind(action).execute(owner.pool()).await?;
        assert_eq!(
            executor
                .claim_execution_request_for_dispatch(Some(worker))
                .await?
                .unwrap()
                .id,
            id
        );
        if status == "rollback_required" {
            executor
                .complete_execution_dispatch_for_recovery(
                    id,
                    Some(worker),
                    Instant::now(),
                    Some("partial mutation; verification mismatch"),
                    Some("recovery required"),
                )
                .await?;
        } else {
            executor
                .complete_execution_dispatch(
                    id,
                    Some(worker),
                    Instant::now(),
                    status == "success",
                    Some("regression result"),
                    if status == "failed" {
                        Some("definite failure")
                    } else {
                        None
                    },
                )
                .await?;
        }
        let row: (String, bool, Option<String>, Option<String>) = sqlx::query_as("SELECT status,finished_at IS NOT NULL,result_summary,error_summary FROM execution_requests WHERE id=$1")
            .bind(id).fetch_one(owner.pool()).await?;
        assert_eq!(row.0, status);
        assert!(row.1);
        assert!(row.2.is_some());
        if status != "success" {
            assert!(row.3.is_some());
        }
        let lease: String =
            sqlx::query_scalar("SELECT status FROM execution_leases WHERE execution_id=$1")
                .bind(id)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(lease, "released");
        let metric: (String, i32) = sqlx::query_as(
            "SELECT status,retry_count FROM execution_metrics WHERE execution_id=$1",
        )
        .bind(id)
        .fetch_one(owner.pool())
        .await?;
        assert_eq!(
            metric,
            (
                if status == "success" {
                    "success"
                } else {
                    "failed"
                }
                .into(),
                i32::from(status != "success")
            )
        );
        let audited: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM audit_events WHERE resource=$1 AND action=$2)",
        )
        .bind(id.to_string())
        .bind(format!("execution_request_{status}"))
        .fetch_one(owner.pool())
        .await?;
        assert!(audited, "exact terminal status must be audited");
        requests.push(id);
    }
    // Make every old lease expired and each task timeout/retry-eligible, then
    // exercise real maintenance through both claim paths. Only definite failed
    // work can be replayed; uncertain work must retain its evidence unchanged.
    sqlx::query("UPDATE execution_leases SET status='active',expires_at=NOW()-INTERVAL '1 minute'")
        .execute(owner.pool())
        .await?;
    sqlx::query("UPDATE execution_requests SET started_at=NOW()-INTERVAL '1 day',next_retry_at=NOW()-INTERVAL '1 minute'")
        .execute(owner.pool()).await?;
    assert_eq!(
        executor
            .claim_execution_request_for_dispatch(Some(worker))
            .await?
            .unwrap()
            .id,
        requests[2]
    );
    executor
        .complete_execution_dispatch(requests[2], Some(worker), Instant::now(), true, None, None)
        .await?;
    assert!(executor
        .claim_execution_request_for_dispatch(Some(worker))
        .await?
        .is_none());
    executor
        .process_one_dry_run_for_worker(Some(worker))
        .await?;
    let recovery: (String, i32, String) = sqlx::query_as(
        "SELECT status,retry_count,error_summary FROM execution_requests WHERE id=$1",
    )
    .bind(requests[0])
    .fetch_one(owner.pool())
    .await?;
    assert_eq!(
        recovery,
        ("rollback_required".into(), 0, "recovery required".into())
    );
    let retries: i32 = sqlx::query_scalar("SELECT retry_count FROM execution_requests WHERE id=$1")
        .bind(requests[2])
        .fetch_one(owner.pool())
        .await?;
    assert_eq!(
        retries, 1,
        "definite failures retain automatic retry semantics"
    );
    let success: String = sqlx::query_scalar("SELECT status FROM execution_requests WHERE id=$1")
        .bind(requests[1])
        .fetch_one(owner.pool())
        .await?;
    assert_eq!(success, "success");
    Ok(())
}
