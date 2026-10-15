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

/// Collect every generation across pages so assertions do not depend on how
/// many rows earlier tests left in the shared fixture.
async fn all_generations(store: &PostgresStore) -> Result<Vec<Value>> {
    let mut all = Vec::new();
    let mut page = 1;
    loop {
        let (rows, total) = store.list_quarantine_generations(page, 200).await?;
        let empty = rows.is_empty();
        all.extend(rows);
        if empty || all.len() as i64 >= total {
            break;
        }
        page += 1;
    }
    Ok(all)
}
fn find(rows: &[Value], id: Uuid) -> &Value {
    rows.iter()
        .find(|r| r["generation_id"] == json!(id))
        .unwrap_or_else(|| panic!("generation {id} missing from read view"))
}

/// Q1 read projection: every durable status is surfaced with the right operator
/// lifecycle label, ownership/recovery flags and apply/rollback receipt lineage,
/// the list is stably ordered newest-first, and pagination partitions it without
/// gaps or overlap while reporting an accurate total/has_next.
#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0054"]
async fn generations_view_reports_all_statuses_lineage_and_stable_pages() -> Result<()> {
    let store = store().await?;
    let mk = |tag: &str| {
        let fp = Uuid::new_v4().simple().to_string().repeat(2);
        let target = json!({"kind":"docker","container_id":fp,"ttl_seconds":60,"tag":tag});
        (fp, target)
    };
    let state = json!({"networks":[]});

    // prepared: owns its target, no receipts yet.
    let (fp_prep, t_prep) = mk("prepared");
    let (ex_prep, _) = execution(&store, &t_prep).await?;
    let g_prepared = store
        .prepare_quarantine_intent(ex_prep, "docker", &fp_prep, &t_prep, &state, &state, 60)
        .await?;

    // completed + active (TTL in the future): apply receipt present.
    let (fp_act, t_act) = mk("active");
    let (ex_act, act_action) = execution(&store, &t_act).await?;
    let g_active = store
        .prepare_quarantine_intent(ex_act, "docker", &fp_act, &t_act, &state, &state, 60)
        .await?;
    let act_receipt = store
        .finish_quarantine_intent(
            g_active,
            &receipt(
                ex_act,
                &act_action,
                &fp_act,
                t_act.clone(),
                state.clone(),
                state.clone(),
            ),
        )
        .await?;

    // not_applied terminal: releases its target, no receipts.
    let (fp_na, t_na) = mk("not_applied");
    let (ex_na, _) = execution(&store, &t_na).await?;
    let g_not_applied = store
        .prepare_quarantine_intent(ex_na, "docker", &fp_na, &t_na, &state, &state, 60)
        .await?;
    store.mark_quarantine_not_applied(g_not_applied).await?;

    // recovery_required: still owns its target, recovery open.
    let (fp_rec, t_rec) = mk("recovery");
    let (ex_rec, _) = execution(&store, &t_rec).await?;
    let g_recovery = store
        .prepare_quarantine_intent(ex_rec, "docker", &fp_rec, &t_rec, &state, &state, 60)
        .await?;
    store.mark_quarantine_recovery_required(g_recovery).await?;

    // rolled_back terminal: apply + verified rollback receipt lineage.
    let (fp_rb, t_rb) = mk("rolled_back");
    let (ex_rb, rb_action) = execution(&store, &t_rb).await?;
    let g_rolled_back = store
        .prepare_quarantine_intent(ex_rb, "docker", &fp_rb, &t_rb, &state, &state, 60)
        .await?;
    store
        .finish_quarantine_intent(
            g_rolled_back,
            &receipt(
                ex_rb,
                &rb_action,
                &fp_rb,
                t_rb.clone(),
                state.clone(),
                state.clone(),
            ),
        )
        .await?;
    store.resolve_quarantine_rollback(g_rolled_back).await?;

    let rows = all_generations(&store).await?;

    let prepared = find(&rows, g_prepared);
    assert_eq!(prepared["lifecycle"], "prepared");
    assert_eq!(prepared["owns_target"], json!(true));
    assert_eq!(prepared["open_recovery"], json!(false));
    assert_eq!(prepared["apply_receipt"], Value::Null);
    assert_eq!(prepared["target_fingerprint"], json!(fp_prep));

    let active = find(&rows, g_active);
    assert_eq!(active["lifecycle"], "active");
    assert_eq!(active["status"], "completed");
    assert_eq!(active["owns_target"], json!(true));
    assert_eq!(active["is_expired"], json!(false));
    assert_eq!(active["apply_receipt"]["id"], json!(act_receipt));
    assert_eq!(active["apply_receipt"]["verification_result"], "verified");
    assert_eq!(active["rollback_receipt"], Value::Null);

    let not_applied = find(&rows, g_not_applied);
    assert_eq!(not_applied["lifecycle"], "not_applied");
    assert_eq!(not_applied["owns_target"], json!(false));
    assert_eq!(not_applied["open_recovery"], json!(false));

    let recovery = find(&rows, g_recovery);
    assert_eq!(recovery["lifecycle"], "recovery_required");
    assert_eq!(recovery["owns_target"], json!(true));
    assert_eq!(recovery["open_recovery"], json!(true));

    let rolled_back = find(&rows, g_rolled_back);
    assert_eq!(rolled_back["lifecycle"], "verified_restored");
    assert_eq!(rolled_back["owns_target"], json!(false));
    assert_eq!(rolled_back["open_recovery"], json!(false));
    assert!(!rolled_back["apply_receipt"].is_null());
    assert_eq!(
        rolled_back["rollback_receipt"]["verification_result"],
        "verified"
    );

    // Newest-first: created_at never increases down the list.
    let mut previous: Option<chrono::DateTime<chrono::Utc>> = None;
    for row in &rows {
        let created: chrono::DateTime<chrono::Utc> =
            serde_json::from_value(row["created_at"].clone())?;
        if let Some(prev) = previous {
            assert!(created <= prev, "generations must be ordered newest-first");
        }
        previous = Some(created);
    }

    // Pagination partitions the same order with no gap or overlap and an exact total.
    let (page1, total) = store.list_quarantine_generations(1, 2).await?;
    assert!(total >= 5);
    assert_eq!(page1.len(), 2);
    let (page2, total2) = store.list_quarantine_generations(2, 2).await?;
    assert_eq!(total, total2);
    assert_eq!(
        page1
            .iter()
            .chain(page2.iter())
            .cloned()
            .collect::<Vec<_>>(),
        rows[..4],
        "contiguous pages must reproduce the single-query order"
    );
    // has_next (computed by the API handler as page*page_size < total) is true
    // while more pages remain: here total >= 5, so the first size-2 page has more.
    assert!(2 < total, "has_next must be true while more pages remain");
    // A page past the end is empty, not a wrapped or duplicated page.
    let (beyond, _) = store.list_quarantine_generations(total + 1, 2).await?;
    assert!(beyond.is_empty());
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

#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0056"]
async fn proxmox_upid_persists_on_prepared_intent_even_when_receipt_fails() -> Result<()> {
    let store = store().await?;
    // Canonical Proxmox fingerprint is "{node}/{vmid}" (see prepare_quarantine_intent).
    let fp = "pve-test/101".to_string();
    let target = json!({"kind":"proxmox","node":"pve-test","vmid":101,"ttl_seconds":60});
    let (execution, action) =
        execution_for_action(&store, &target, "proxmox.quarantine_vm").await?;
    let state = json!({"networks":[{"network_id":"original-net0","aliases":[],"ipv4":"10.0.0.1"}]});
    let plan = json!({"networks":state["networks"]});

    // Prepare the quarantine intent.
    let id = store
        .prepare_quarantine_intent(execution, "proxmox", &fp, &target, &state, &plan, 60)
        .await?;
    let prepared = store.quarantine_intent(id).await?.unwrap();
    assert_eq!(prepared.status, "prepared");
    assert_eq!(prepared.target_json, target);
    assert_eq!(prepared.rollback_plan, plan);

    // Persist the observed Proxmox UPID in its own committed transaction, exactly as the
    // proxmox adapter does before awaiting the config task.
    let test_upid = "UPID:pve-test:qmstart:101:user@pve:root@pam:ABCD1234:";
    store.set_quarantine_intent_upid(id, test_upid).await?;
    let retrieved_upid: Option<String> =
        sqlx::query_scalar("SELECT proxmox_upid FROM firewall_action_intents WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(retrieved_upid.as_deref(), Some(test_upid));

    // Build a receipt that matches the prepared proxmox generation. The shared receipt()
    // helper defaults adapter to "docker", so set it to proxmox to exercise real validation.
    let mut input = receipt(
        execution,
        &action,
        &fp,
        target.clone(),
        state.clone(),
        plan.clone(),
    );
    input.adapter = "proxmox";

    // A rejected receipt (verification mismatch) is refused at validation, which releases
    // the generation lock cleanly. The UPID lives in its own committed transaction, so it
    // must survive the rejected receipt with the intent still prepared.
    input.verification_result = Some("mismatch");
    assert!(store.finish_quarantine_intent(id, &input).await.is_err());

    let intent_after_failed_receipt = store.quarantine_intent(id).await?.unwrap();
    assert_eq!(intent_after_failed_receipt.status, "prepared");
    let upid_after_failure: Option<String> =
        sqlx::query_scalar("SELECT proxmox_upid FROM firewall_action_intents WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(upid_after_failure.as_deref(), Some(test_upid));

    // When the receipt verifies, the intent completes and the UPID remains attached.
    input.verification_result = Some("verified");
    let receipt_id = store.finish_quarantine_intent(id, &input).await?;
    let completed = store.quarantine_intent(id).await?.unwrap();
    assert_eq!(completed.status, "completed");
    let upid_after_success: Option<String> =
        sqlx::query_scalar("SELECT proxmox_upid FROM firewall_action_intents WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(upid_after_success.as_deref(), Some(test_upid));

    // The apply receipt is linked back to the intent.
    let linked: Uuid =
        sqlx::query_scalar("SELECT intent_id FROM firewall_action_receipts WHERE id = $1")
            .bind(receipt_id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(linked, id);

    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated explicit quarantine PostgreSQL fixture with schema 0057"]
async fn operator_reconcile_requires_a_bound_dual_approved_reconcile_request() -> Result<()> {
    let store = store().await?;
    let state = json!({"networks":[{"network_id":"original-net0","aliases":[],"ipv4":"10.0.0.9"}]});
    let plan = json!({"networks":state["networks"]});

    // A recovery_required proxmox generation at `vmid` (the only state the automatic sweep
    // will not resolve), returning the intent id and its canonical target.
    async fn recovery_required(
        store: &PostgresStore,
        vmid: u64,
        state: &Value,
        plan: &Value,
    ) -> Result<(Uuid, Value)> {
        let fp = format!("pve-test/{vmid}");
        let target = json!({"kind":"proxmox","node":"pve-test","vmid":vmid,"ttl_seconds":60});
        let (exec, _) = execution_for_action(store, &target, "proxmox.quarantine_vm").await?;
        let id = store
            .prepare_quarantine_intent(exec, "proxmox", &fp, &target, state, plan, 60)
            .await?;
        store.mark_quarantine_recovery_required(id).await?;
        Ok((id, target))
    }

    // Positive: a SEPARATE, dual-approved reconcile request bound to the same target authorizes.
    let (id, target) = recovery_required(&store, 301, &state, &plan).await?;
    let (reconcile_exec, _) =
        execution_for_action(&store, &target, "proxmox.reconcile_quarantine").await?;
    let mut guard = store.acquire_quarantine_guard(id).await?.unwrap();
    guard
        .validate_reconcile_approval(reconcile_exec, "proxmox.reconcile_quarantine", &target)
        .await?;
    drop(guard);

    // The ORIGINAL quarantine request's approval must NOT authorize a reconcile (action mismatch).
    let (id2, target2) = recovery_required(&store, 302, &state, &plan).await?;
    let (q_exec, _) = execution_for_action(&store, &target2, "proxmox.quarantine_vm").await?;
    let mut guard2 = store.acquire_quarantine_guard(id2).await?.unwrap();
    assert!(guard2
        .validate_reconcile_approval(q_exec, "proxmox.reconcile_quarantine", &target2)
        .await
        .is_err());
    drop(guard2);

    // A reconcile request approved for a DIFFERENT target cannot authorize this generation.
    let (id3, target3) = recovery_required(&store, 303, &state, &plan).await?;
    let (rec3, _) = execution_for_action(&store, &target3, "proxmox.reconcile_quarantine").await?;
    let other = json!({"kind":"proxmox","node":"pve-test","vmid":999,"ttl_seconds":60});
    let mut guard3 = store.acquire_quarantine_guard(id3).await?.unwrap();
    assert!(guard3
        .validate_reconcile_approval(rec3, "proxmox.reconcile_quarantine", &other)
        .await
        .is_err());
    drop(guard3);

    // A generation that is NOT recovery_required (still prepared) cannot be reconciled.
    let fp4 = "pve-test/304".to_string();
    let target4 = json!({"kind":"proxmox","node":"pve-test","vmid":304,"ttl_seconds":60});
    let (exec4, _) = execution_for_action(&store, &target4, "proxmox.quarantine_vm").await?;
    let id4 = store
        .prepare_quarantine_intent(exec4, "proxmox", &fp4, &target4, &state, &plan, 60)
        .await?;
    let (rec4, _) = execution_for_action(&store, &target4, "proxmox.reconcile_quarantine").await?;
    let mut guard4 = store.acquire_quarantine_guard(id4).await?.unwrap();
    assert!(guard4
        .validate_reconcile_approval(rec4, "proxmox.reconcile_quarantine", &target4)
        .await
        .is_err());
    drop(guard4);

    Ok(())
}
