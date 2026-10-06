//! Isolated PostgreSQL regression tests for durable external mutation ownership.
use anyhow::Result;
use clawforge_storage::{FirewallActionReceiptInput, PostgresStore};
use serde_json::{json, Value};
use uuid::Uuid;

async fn store() -> Result<PostgresStore> {
    // No production fallback: this test must be explicitly pointed at a disposable fixture.
    PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_QUARANTINE_DATABASE_URL")?).await
}
async fn execution(store: &PostgresStore, target: &Value) -> Result<(Uuid, String)> {
    execution_for_action(store, target, "docker.quarantine_container").await
}
async fn execution_for_action(
    store: &PostgresStore,
    target: &Value,
    name: &str,
) -> Result<(Uuid, String)> {
    let action = Uuid::new_v4();
    let suffix = Uuid::new_v4();
    let name = name.to_owned();
    let action:Uuid=sqlx::query_scalar("INSERT INTO actions(id,name,type,risk_level,required_scope,requires_approval,enabled) VALUES($1,$2,'connector_action','critical','agent:action:read',TRUE,TRUE) ON CONFLICT(name) DO UPDATE SET risk_level='critical',requires_approval=TRUE,enabled=TRUE RETURNING id")
        .bind(action).bind(&name).fetch_one(store.pool()).await?;
    let requester_name = format!("requester-{suffix}");
    let requester = store
        .create_admin_user(&requester_name, "Administrator", "test-hash")
        .await?;
    let execution = store
        .create_execution_request(&clawforge_storage::ExecutionRequestInput {
            action_id: action,
            workflow_run_id: None,
            decision_id: None,
            requested_by: requester_name,
            requested_by_id: Some(requester),
            idempotency_key: None,
            target: Some(target.clone()),
        })
        .await?;
    for index in [1, 2] {
        let name = format!("approver-{suffix}-{index}");
        let id = store
            .create_admin_user(&name, "Approver", "test-hash")
            .await?;
        store
            .approve_execution_request(execution, id, &name)
            .await?;
    }
    sqlx::query("UPDATE execution_requests SET status='starting' WHERE id=$1")
        .bind(execution)
        .execute(store.pool())
        .await?;
    Ok((execution, name))
}
fn receipt<'a>(
    execution: Uuid,
    action: &'a str,
    fp: &'a str,
    target: Value,
    state: Value,
    plan: Value,
) -> FirewallActionReceiptInput<'a> {
    FirewallActionReceiptInput {
        execution_id: Some(execution),
        adapter: "docker",
        action_name: action,
        preflight_state: state,
        rendered_commands: json!([]),
        observed_state: Some(json!({"isolated":true})),
        verification_result: Some("verified"),
        ttl_seconds: 60,
        rollback_plan: plan,
        is_dry_run: false,
        receipt_kind: "apply",
        target_fingerprint: Some(fp),
        target_json: Some(target),
    }
}

#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0054"]
async fn active_generation_is_exclusive_and_receipt_failure_is_atomic() -> Result<()> {
    let store = store().await?;
    let fp = Uuid::new_v4().simple().to_string().repeat(2);
    let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60});
    let (execution, action) = execution(&store, &target).await?;
    let state = json!({"networks":[{"network_id":"b".repeat(64),"aliases":["api"],"ipv4":"10.254.231.23"}]});
    let plan = json!({"networks":state["networks"]});
    let (first, second) = tokio::join!(
        store.prepare_quarantine_intent(execution, "docker", &fp, &target, &state, &plan, 60),
        store.prepare_quarantine_intent(execution, "docker", &fp, &target, &state, &plan, 60)
    );
    assert_ne!(
        first.is_ok(),
        second.is_ok(),
        "exactly one concurrent owner may prepare"
    );
    let id = first.or(second)?;
    let prepared = store.quarantine_intent(id).await?.unwrap();
    assert_eq!(prepared.status, "prepared");
    assert_eq!(prepared.rollback_plan, plan);
    let mut input = receipt(
        execution,
        &action,
        &fp,
        target.clone(),
        state.clone(),
        plan.clone(),
    );
    input.verification_result = Some("mismatch");
    assert!(store.finish_quarantine_intent(id, &input).await.is_err());
    input.verification_result = Some("verified");
    // Force a real database failure at receipt INSERT, after the generation row is locked.
    sqlx::query("ALTER TABLE firewall_action_receipts ADD CONSTRAINT quarantine_fixture_receipt_rejection CHECK (rendered_commands <> '{\"reject_fixture\":true}'::jsonb)").execute(store.pool()).await?;
    input.rendered_commands = json!({"reject_fixture":true});
    assert!(store.finish_quarantine_intent(id, &input).await.is_err());
    assert_eq!(
        store.quarantine_intent(id).await?.unwrap().status,
        "prepared"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM firewall_action_receipts WHERE intent_id=$1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(count, 0, "failed finish must not publish partial receipt");
    sqlx::query(
        "ALTER TABLE firewall_action_receipts DROP CONSTRAINT quarantine_fixture_receipt_rejection",
    )
    .execute(store.pool())
    .await?;
    input.rendered_commands = json!([]);
    let receipt_id = store.finish_quarantine_intent(id, &input).await?;
    let completed = store.quarantine_intent(id).await?.unwrap();
    assert_eq!(completed.status, "completed");
    assert_eq!(completed.expires_at, prepared.expires_at);
    let linked: Uuid =
        sqlx::query_scalar("SELECT intent_id FROM firewall_action_receipts WHERE id=$1")
            .bind(receipt_id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(linked, id);
    assert!(
        store
            .prepare_quarantine_intent(execution, "docker", &fp, &target, &state, &plan, 60)
            .await
            .is_err(),
        "completed generation owns target until verified rollback"
    );
    store.mark_quarantine_recovery_required(id).await?;
    assert!(store
        .prepare_quarantine_intent(execution, "docker", &fp, &target, &state, &plan, 60)
        .await
        .is_err());
    store.resolve_quarantine_rollback(id).await?;
    let replacement = store
        .prepare_quarantine_intent(execution, "docker", &fp, &target, &state, &plan, 60)
        .await?;
    assert_ne!(replacement, id);
    assert!(
        store.resolve_quarantine_rollback(id).await.is_err(),
        "stale old generation must not release current owner"
    );
    assert_eq!(
        store.quarantine_intent(replacement).await?.unwrap().status,
        "prepared"
    );
    store.mark_quarantine_not_applied(replacement).await?;
    let audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_outbox WHERE resource=$1")
        .bind(id.to_string())
        .fetch_one(store.pool())
        .await?;
    assert_eq!(
        audit, 4,
        "prepare/complete/recovery/rollback each durably audited"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0054"]
async fn expired_prepared_generation_survives_restart_and_is_never_replayed() -> Result<()> {
    let store = store().await?;
    let fp = Uuid::new_v4().simple().to_string().repeat(2);
    let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60});
    let (execution, _action) = execution(&store, &target).await?;
    let id = store
        .prepare_quarantine_intent(
            execution,
            "docker",
            &fp,
            &target,
            &json!({"networks":[]}),
            &json!({"networks":[]}),
            60,
        )
        .await?;
    assert!(
        sqlx::query(
            "UPDATE firewall_action_intents SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1"
        )
        .bind(id)
        .execute(store.pool())
        .await
        .is_err(),
        "expiry snapshot must be immutable"
    );
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    let reopened = crate::store().await?;
    let rows = reopened.unresolved_quarantine_intents().await?;
    let restored = rows
        .iter()
        .find(|row| row.id == id)
        .expect("expired prepared state must remain visible");
    assert_eq!(restored.status, "prepared");
    assert_eq!(restored.target_json, target);
    assert!(
        reopened
            .prepare_quarantine_intent(
                execution,
                "docker",
                &fp,
                &target,
                &json!({}),
                &json!({}),
                60
            )
            .await
            .is_err(),
        "expired prepared intent must retain ownership without replay"
    );
    reopened.mark_quarantine_recovery_required(id).await?;
    let error: Option<String> =
        sqlx::query_scalar("SELECT error_summary FROM firewall_action_intents WHERE id=$1")
            .bind(id)
            .fetch_one(reopened.pool())
            .await?;
    assert_eq!(
        error.as_deref(),
        Some("external quarantine state requires verified recovery")
    );
    reopened.resolve_quarantine_rollback(id).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0054"]
async fn prepare_rejects_stale_approval_and_noncanonical_identity() -> Result<()> {
    let store = store().await?;
    let fp = Uuid::new_v4().simple().to_string().repeat(2);
    let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60});
    let (id, _) = execution(&store, &target).await?;
    // Database rejects rebinding a signed approval or changing the immutable request context.
    assert!(sqlx::query(
        "UPDATE execution_approvals SET context_hash='stale' WHERE execution_id=$1"
    )
    .bind(id)
    .execute(store.pool())
    .await
    .is_err());
    assert!(sqlx::query(
        "UPDATE execution_requests SET approval_context_hash=repeat('0',64) WHERE id=$1"
    )
    .bind(id)
    .execute(store.pool())
    .await
    .is_err());
    sqlx::query("UPDATE execution_requests SET status='running' WHERE id=$1")
        .bind(id)
        .execute(store.pool())
        .await?;
    let prepared = store
        .prepare_quarantine_intent(id, "docker", &fp, &target, &json!({}), &json!({}), 60)
        .await?;
    store.mark_quarantine_not_applied(prepared).await?;
    for invalid in [
        json!({"kind":"docker","container_id":"A".repeat(64),"ttl_seconds":60}),
        json!({"kind":"proxmox","container_id":fp,"ttl_seconds":60}),
        json!({"kind":"docker","container_id":fp,"ttl_seconds":"3600"}),
    ] {
        let (id, _) = execution(&store, &invalid).await?;
        let fp = invalid["container_id"].as_str().unwrap();
        assert!(store
            .prepare_quarantine_intent(id, "docker", fp, &invalid, &json!({}), &json!({}), 60)
            .await
            .is_err());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0054"]
async fn target_ownership_blocks_a_different_execution_until_resolution() -> Result<()> {
    let store = store().await?;
    let fp = Uuid::new_v4().simple().to_string().repeat(2);
    let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60});
    let (old, _) = execution(&store, &target).await?;
    let (new, _) = execution(&store, &target).await?;
    let state = json!({"network":"original"});
    let plan = json!({"restore":"original"});
    let first = store
        .prepare_quarantine_intent(old, "docker", &fp, &target, &state, &plan, 60)
        .await?;
    assert!(store
        .prepare_quarantine_intent(new, "docker", &fp, &target, &state, &plan, 60)
        .await
        .is_err());
    store.mark_quarantine_recovery_required(first).await?;
    assert!(
        store.mark_quarantine_not_applied(first).await.is_err(),
        "ambiguous mutation cannot be declared unapplied"
    );
    store.resolve_quarantine_rollback(first).await?;
    let second = store
        .prepare_quarantine_intent(new, "docker", &fp, &target, &state, &plan, 60)
        .await?;
    assert!(store
        .mark_quarantine_recovery_required(first)
        .await
        .is_err());
    assert!(store.resolve_quarantine_rollback(first).await.is_err());
    assert_eq!(
        store.quarantine_intent(second).await?.unwrap().status,
        "prepared"
    );
    store.mark_quarantine_not_applied(second).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0054"]
async fn generation_guard_serializes_external_recovery_and_survives_drop() -> Result<()> {
    let store = store().await?;
    let fp = Uuid::new_v4().simple().to_string().repeat(2);
    let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60});
    let (execution, action) = execution(&store, &target).await?;
    let state = json!({"original":true});
    let id = store
        .prepare_quarantine_intent(execution, "docker", &fp, &target, &state, &state, 60)
        .await?;
    let first = store.acquire_quarantine_guard(id).await?.unwrap();
    assert_eq!(first.intent().id, id);
    assert!(
        store.acquire_quarantine_guard(id).await?.is_none(),
        "second recovery worker must skip locked generation"
    );
    drop(first); // Crash before mutation: persisted prepared state remains available.
    let first = store.acquire_quarantine_guard(id).await?.unwrap();
    first
        .finish(&receipt(
            execution,
            &action,
            &fp,
            target.clone(),
            state.clone(),
            state.clone(),
        ))
        .await?;
    let guard = store.acquire_quarantine_guard(id).await?.unwrap();
    assert_eq!(guard.intent().status, "completed");
    guard.resolve_rollback().await?;
    assert!(
        sqlx::query("UPDATE firewall_action_intents SET status='prepared' WHERE id=$1")
            .bind(id)
            .execute(store.pool())
            .await
            .is_err(),
        "resolved generations cannot be revived by direct update"
    );
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM firewall_action_receipts WHERE intent_id=$1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(
        receipts, 2,
        "apply and verified rollback are linked append-only receipts"
    );
    let replacement = store
        .prepare_quarantine_intent(execution, "docker", &fp, &target, &state, &state, 60)
        .await?;
    assert!(
        store.acquire_quarantine_guard(id).await?.is_none(),
        "stale resolved generation cannot acquire a mutation fence"
    );
    store
        .acquire_quarantine_guard(replacement)
        .await?
        .unwrap()
        .not_applied()
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0054"]
async fn only_exact_approved_adapter_action_and_target_can_prepare() -> Result<()> {
    let store = store().await?;
    let suffix = Uuid::new_v4().simple().to_string();
    for (adapter, action, fp, target) in [
        (
            "proxmox",
            "proxmox.quarantine_vm",
            format!("pve-{suffix}/101"),
            json!({"kind":"proxmox","node":format!("pve-{suffix}"),"vmid":101,"ttl_seconds":60}),
        ),
        (
            "tailscale",
            "tailscale.quarantine_device",
            format!("device-{suffix}"),
            json!({"kind":"tailscale","device_id":format!("device-{suffix}"),"ttl_seconds":60}),
        ),
    ] {
        let (execution, _) = execution_for_action(&store, &target, action).await?;
        assert!(store
            .prepare_quarantine_intent(
                execution,
                "docker",
                &fp,
                &target,
                &json!({}),
                &json!({}),
                60
            )
            .await
            .is_err());
        assert!(store
            .prepare_quarantine_intent(
                execution,
                adapter,
                "wrong-canonical-fingerprint",
                &target,
                &json!({}),
                &json!({}),
                60
            )
            .await
            .is_err());
        let id = store
            .prepare_quarantine_intent(execution, adapter, &fp, &target, &json!({}), &json!({}), 60)
            .await?;
        store.mark_quarantine_not_applied(id).await?;
    }
    let fp = suffix.repeat(2);
    let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60});
    let (execution, _) =
        execution_for_action(&store, &target, &format!("fixture.quarantine-{suffix}")).await?;
    assert!(store
        .prepare_quarantine_intent(
            execution,
            "docker",
            &fp,
            &target,
            &json!({}),
            &json!({}),
            60
        )
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit quarantine and restricted API/executor PostgreSQL fixtures"]
async fn restricted_roles_preserve_generation_and_bind_kill_switch() -> Result<()> {
    let owner = store().await?;
    let executor =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_EXECUTOR_DATABASE_URL")?)
            .await?;
    let api =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_API_DATABASE_URL")?).await?;
    let fp = Uuid::new_v4().simple().to_string().repeat(2);
    let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60});
    let (execution_id, _) = execution(&owner, &target).await?;
    let id = executor
        .prepare_quarantine_intent(
            execution_id,
            "docker",
            &fp,
            &target,
            &json!({}),
            &json!({}),
            60,
        )
        .await?;
    let mut guard = executor.acquire_quarantine_guard(id).await?.unwrap();
    guard.validate_approval().await?;
    drop(guard);
    for statement in [
        "DELETE FROM firewall_action_intents WHERE id=$1",
        "UPDATE firewall_action_intents SET status='not_applied' WHERE id=$1",
    ] {
        assert!(sqlx::query(statement)
            .bind(id)
            .execute(api.pool())
            .await
            .is_err());
    }
    assert!(sqlx::query(
        "UPDATE actions SET enabled=FALSE WHERE name='docker.quarantine_container'"
    )
    .execute(executor.pool())
    .await
    .is_err());
    let kill = api
        .create_firewall_kill_switch_request(
            "docker",
            &fp,
            &json!({"wrong":"caller restore data"}),
            None,
            "operator",
            None,
        )
        .await?;
    let request = executor
        .pending_firewall_kill_switch_requests()
        .await?
        .into_iter()
        .find(|r| r.request_id == kill)
        .unwrap();
    assert_eq!(request.quarantine_intent_id, Some(id));
    assert_eq!(request.target_json, target);
    // Resolve first generation, then create another: delayed request stays bound to old ID.
    executor.mark_quarantine_not_applied(id).await?;
    let (second_execution, _) =
        execution_for_action(&owner, &target, "docker.quarantine_container").await?;
    let next = executor
        .prepare_quarantine_intent(
            second_execution,
            "docker",
            &fp,
            &target,
            &json!({}),
            &json!({}),
            60,
        )
        .await?;
    assert_ne!(id, next);
    assert!(executor
        .acquire_quarantine_guard(request.quarantine_intent_id.unwrap())
        .await?
        .is_none());
    assert_eq!(
        executor.quarantine_intent(next).await?.unwrap().status,
        "prepared"
    );
    executor.mark_quarantine_not_applied(next).await?;
    assert!(api
        .create_firewall_kill_switch_request("docker", &fp, &target, None, "operator", None)
        .await
        .is_err());
    Ok(())
}
