use clawforge_storage::{ExecutionRequestInput, PostgresStore};
use sqlx::{postgres::PgConnectOptions, ConnectOptions, PgPool};
use std::str::FromStr;

#[tokio::test]
#[ignore = "requires an isolated CLAWFORGE_TEST_DATABASE_URL"]
async fn quarantine_needs_two_distinct_approvers_and_revalidates_policy_at_claim(
) -> anyhow::Result<()> {
    let base = std::env::var("CLAWFORGE_TEST_DATABASE_URL")?;
    let executor_base = std::env::var("CLAWFORGE_TEST_EXECUTOR_DATABASE_URL")?;
    let admin = PgPool::connect(&base).await?;
    let database = format!("quarantine_approval_{}", uuid::Uuid::new_v4().simple());
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
    // Earlier suites intentionally retain immutable request/approval audit rows.
    // A global claim must see only this test's requests, never claim those rows.
    // Spawn catches assertion panics so the disposable DB is also removed on RED.
    let result =
        tokio::spawn(async move { check_approval_invariants(&owner_url, &executor_url).await })
            .await;
    let cleanup = sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&admin)
        .await;
    admin.close().await;
    cleanup?;
    result??;
    Ok(())
}

async fn check_approval_invariants(owner_url: &str, executor_url: &str) -> anyhow::Result<()> {
    let store = PostgresStore::connect(owner_url).await?;
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
    .execute(store.pool())
    .await?;
    let executor = PostgresStore::connect_runtime(executor_url).await?;
    let request_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_requests")
        .fetch_one(store.pool())
        .await?;
    assert_eq!(
        request_count, 0,
        "approval fixture starts with an empty queue"
    );
    let elevated: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolcreatedb OR rolcreaterole FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(executor.pool())
    .await?;
    assert!(
        !elevated,
        "approvals must be checked by the restricted executor"
    );
    for table in [
        "execution_approvals",
        "approval_policies",
        "firewall_action_intents",
    ] {
        let readable: bool =
            sqlx::query_scalar("SELECT has_table_privilege(current_user,$1,'SELECT')")
                .bind(table)
                .fetch_one(executor.pool())
                .await?;
        assert!(readable, "executor must read {table}");
    }
    for (table, privilege) in [
        ("execution_approvals", "INSERT"),
        ("execution_approvals", "UPDATE"),
        ("execution_approvals", "DELETE"),
        ("approval_policies", "UPDATE"),
        ("firewall_action_intents", "DELETE"),
    ] {
        let permitted: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,$1,$2)")
            .bind(table)
            .bind(privilege)
            .fetch_one(executor.pool())
            .await?;
        assert!(!permitted, "executor must not have {privilege} on {table}");
    }
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let requester_name = format!("phase11-requester-{suffix}");
    let one_name = format!("phase11-approver1-{suffix}");
    let two_name = format!("phase11-approver2-{suffix}");
    let requester = store
        .create_admin_user(&requester_name, "Administrator", "argon2-test-hash")
        .await?;
    let one = store
        .create_admin_user(&one_name, "Approver", "argon2-test-hash")
        .await?;
    let two = store
        .create_admin_user(&two_name, "Approver", "argon2-test-hash")
        .await?;
    for action_name in [
        "docker.quarantine_container",
        "proxmox.quarantine_vm",
        "tailscale.quarantine_device",
    ] {
        let action: uuid::Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name=$1")
            .bind(action_name)
            .fetch_one(store.pool())
            .await?;
        let input = ExecutionRequestInput {
            action_id: action,
            workflow_run_id: None,
            decision_id: None,
            requested_by: requester_name.clone(),
            requested_by_id: Some(requester),
            idempotency_key: None,
            target: Some(
                serde_json::json!({"container_id":"0123456789abcdef".repeat(4),"simulation_only":true}),
            ),
        };
        assert!(
            store.create_execution_request(&input).await.is_err(),
            "disabled by default"
        );
        sqlx::query(
            "UPDATE actions SET enabled=TRUE,risk_level='low',requires_approval=FALSE WHERE id=$1",
        )
        .bind(action)
        .execute(store.pool())
        .await?;
        assert!(
            store.create_execution_request(&input).await.is_err(),
            "wrong registration cannot bypass approvals"
        );
        sqlx::query("UPDATE actions SET risk_level='critical',requires_approval=TRUE WHERE id=$1")
            .bind(action)
            .execute(store.pool())
            .await?;
        let id = store.create_execution_request(&input).await?;
        assert!(store
            .approve_execution_request(id, requester, &requester_name)
            .await
            .is_err());
        assert!(executor
            .claim_execution_request_for_dispatch(None)
            .await?
            .is_none());
        let first = store.approve_execution_request(id, one, &one_name).await?;
        assert_eq!(first["status"], "waiting_approval");
        assert_eq!(first["required_approvals"], 2);
        assert!(store
            .approve_execution_request(id, one, &one_name)
            .await
            .is_err());
        assert!(executor
            .claim_execution_request_for_dispatch(None)
            .await?
            .is_none());
        let second = store.approve_execution_request(id, two, &two_name).await?;
        assert_eq!(second["status"], "approved");
        sqlx::query("UPDATE actions SET requires_approval=FALSE WHERE id=$1")
            .bind(action)
            .execute(store.pool())
            .await?;
        assert!(
            executor
                .claim_execution_request_for_dispatch(None)
                .await?
                .is_none(),
            "configuration drift is refused even after approvals"
        );
        sqlx::query("UPDATE actions SET requires_approval=TRUE WHERE id=$1")
            .bind(action)
            .execute(store.pool())
            .await?;
        sqlx::query(
            "UPDATE approval_policies SET required_approvals=3 WHERE risk_level='critical'",
        )
        .execute(store.pool())
        .await?;
        assert!(
            executor
                .claim_execution_request_for_dispatch(None)
                .await?
                .is_none(),
            "a stricter current policy is honored after two approvals"
        );
        sqlx::query(
            "UPDATE approval_policies SET required_approvals=2 WHERE risk_level='critical'",
        )
        .execute(store.pool())
        .await?;
        let claimed = executor
            .claim_execution_request_for_dispatch(None)
            .await?
            .expect("two valid approvals allow a claim");
        assert_eq!(claimed.id, id);
        executor
            .complete_execution_dispatch(
                id,
                None,
                std::time::Instant::now(),
                true,
                Some("test-only simulated dispatch"),
                None,
            )
            .await?;
        if action_name == "docker.quarantine_container" {
            let original_timeout: i32 = sqlx::query_scalar(
                "SELECT approval_timeout FROM approval_policies WHERE risk_level='critical'",
            )
            .fetch_one(store.pool())
            .await?;
            sqlx::query(
                "UPDATE approval_policies SET approval_timeout=60 WHERE risk_level='critical'",
            )
            .execute(store.pool())
            .await?;
            let expired_id = store.create_execution_request(&input).await?;
            store
                .approve_execution_request(expired_id, one, &one_name)
                .await?;
            store
                .approve_execution_request(expired_id, two, &two_name)
                .await?;
            // Real PostgreSQL clock, without modifying the immutable context.
            sqlx::query("SELECT pg_sleep(60.1)")
                .execute(store.pool())
                .await?;
            assert!(
                executor
                    .claim_execution_request_for_dispatch(None)
                    .await?
                    .is_none(),
                "expired approvals are refused at dispatch"
            );
            executor.process_one_dry_run_for_worker(None).await?;
            let expired_status: String =
                sqlx::query_scalar("SELECT status FROM execution_requests WHERE id=$1")
                    .bind(expired_id)
                    .fetch_one(store.pool())
                    .await?;
            assert_eq!(
                expired_status, "approved",
                "dry-run must refuse expired approvals too"
            );
            sqlx::query(
                "UPDATE approval_policies SET approval_timeout=$1 WHERE risk_level='critical'",
            )
            .bind(original_timeout)
            .execute(store.pool())
            .await?;
        }
        // Keep the immutable approval/request audit trail. Cascade deletion is
        // deliberately rejected by the production approval trigger.
        sqlx::query("UPDATE actions SET enabled=FALSE WHERE id=$1")
            .bind(action)
            .execute(store.pool())
            .await?;
    }
    Ok(())
}
