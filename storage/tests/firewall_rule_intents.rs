//! Isolated PostgreSQL regression tests for durable generic-firewall rule
//! ownership (F2). No prepared rule intent is ever blindly replayed.
use anyhow::Result;
use clawforge_storage::{ExecutionRequestInput, FirewallActionReceiptInput, PostgresStore};
use serde_json::{json, Value};
use uuid::Uuid;

async fn store() -> Result<PostgresStore> {
    PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_FIREWALL_RULE_DATABASE_URL")?)
        .await
}

/// A minimal claimed execution for a low-risk firewall action. Rule intents
/// carry no approval gate, so this only needs to exist for the FK.
async fn execution(store: &PostgresStore, action_name: &str) -> Result<Uuid> {
    let suffix = Uuid::new_v4();
    let action: Uuid = sqlx::query_scalar("INSERT INTO actions(id,name,type,risk_level,required_scope,requires_approval,enabled) VALUES($1,$2,'connector_action','low','agent:action:read',FALSE,TRUE) ON CONFLICT(name) DO UPDATE SET enabled=TRUE RETURNING id")
        .bind(Uuid::new_v4()).bind(action_name).fetch_one(store.pool()).await?;
    let requester_name = format!("requester-{suffix}");
    let requester = store
        .create_admin_user(&requester_name, "Administrator", "test-hash")
        .await?;
    let execution = store
        .create_execution_request(&ExecutionRequestInput {
            action_id: action,
            workflow_run_id: None,
            decision_id: None,
            requested_by: requester_name,
            requested_by_id: Some(requester),
            idempotency_key: None,
            target: Some(json!({"cidr": "203.0.113.7/32"})),
        })
        .await?;
    Ok(execution)
}

fn receipt<'a>(
    execution: Uuid,
    adapter: &'a str,
    action_name: &'a str,
    fp: &'a str,
    target: &'a Value,
    state: &'a Value,
    plan: &'a Value,
) -> FirewallActionReceiptInput<'a> {
    FirewallActionReceiptInput {
        execution_id: Some(execution),
        adapter,
        action_name,
        preflight_state: state.clone(),
        rendered_commands: json!([["nft", "add", "element", "..."]]),
        observed_state: Some(json!({"present": true})),
        verification_result: Some("verified"),
        ttl_seconds: 3600,
        rollback_plan: plan.clone(),
        is_dry_run: false,
        receipt_kind: "apply",
        target_fingerprint: Some(fp),
        target_json: Some(target.clone()),
    }
}

#[tokio::test]
#[ignore = "requires an isolated firewall-rule PostgreSQL fixture with schema 0055"]
async fn rule_write_ahead_is_owned_crash_safe_and_atomic() -> Result<()> {
    let store = store().await?;
    let adapter = "nftables";
    let action = "nftables.block_indicator";
    let scope = "clawforge_block_v4";
    let fp = format!("203.0.113.{}/32", Uuid::new_v4().as_u128() % 250 + 1);
    let target = json!({"cidr": fp, "scope": scope});
    let state = json!({"set_present": false});
    let plan = json!({"commands": [["nft", "delete", "element", "..."]]});
    let execution = execution(&store, action).await?;

    let id = store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp, &target, &state, &plan, 3600,
        )
        .await?;
    assert_eq!(
        store.firewall_rule_intent(id).await?.unwrap().status,
        "prepared"
    );

    // An already-owned rule cannot be prepared again until it resolves.
    assert!(
        store
            .prepare_firewall_rule_intent(
                execution, adapter, action, scope, &fp, &target, &state, &plan, 3600
            )
            .await
            .is_err(),
        "an active generation owns the rule"
    );

    // Crash before mutation: the lock releases, the prepared snapshot survives.
    let guard = store.acquire_firewall_rule_guard(id).await?.unwrap();
    assert_eq!(guard.intent().rule_fingerprint, fp);
    assert!(
        store.acquire_firewall_rule_guard(id).await?.is_none(),
        "a second worker must skip the locked generation"
    );
    drop(guard);
    assert_eq!(
        store.firewall_rule_intent(id).await?.unwrap().status,
        "prepared"
    );

    // A receipt that does not match the prepared verified generation is refused.
    let mut input = receipt(execution, adapter, action, &fp, &target, &state, &plan);
    input.verification_result = Some("mismatch");
    assert!(store.finish_firewall_rule_intent(id, &input).await.is_err());

    // Force a real DB failure at receipt INSERT, after the generation is locked.
    input.verification_result = Some("verified");
    sqlx::query("ALTER TABLE firewall_action_receipts ADD CONSTRAINT fw_rule_fixture_reject CHECK (rendered_commands <> '{\"reject\":true}'::jsonb)").execute(store.pool()).await?;
    input.rendered_commands = json!({"reject": true});
    assert!(store.finish_firewall_rule_intent(id, &input).await.is_err());
    assert_eq!(
        store.firewall_rule_intent(id).await?.unwrap().status,
        "prepared",
        "a failed receipt leaves the generation prepared and owned"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM firewall_action_receipts WHERE intent_id=$1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(count, 0, "no partial receipt is published");
    sqlx::query("ALTER TABLE firewall_action_receipts DROP CONSTRAINT fw_rule_fixture_reject")
        .execute(store.pool())
        .await?;

    // A verified apply completes atomically.
    input.rendered_commands = json!([["nft", "add", "element"]]);
    let receipt_id = store.finish_firewall_rule_intent(id, &input).await?;
    assert_eq!(
        store.firewall_rule_intent(id).await?.unwrap().status,
        "completed"
    );
    let linked: Uuid =
        sqlx::query_scalar("SELECT intent_id FROM firewall_action_receipts WHERE id=$1")
            .bind(receipt_id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(linked, id);

    // A completed generation still owns the rule until verified rollback.
    assert!(store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp, &target, &state, &plan, 3600
        )
        .await
        .is_err());
    store.mark_firewall_rule_recovery_required(id).await?;
    assert!(store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp, &target, &state, &plan, 3600
        )
        .await
        .is_err());
    store.resolve_firewall_rule_rollback(id).await?;

    // Only now can the rule be owned by a fresh generation.
    let replacement = store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp, &target, &state, &plan, 3600,
        )
        .await?;
    assert_ne!(replacement, id);
    assert!(
        store.resolve_firewall_rule_rollback(id).await.is_err(),
        "a stale resolved generation must not release the current owner"
    );
    store.mark_firewall_rule_not_applied(replacement).await?;

    // apply + verified rollback are two linked append-only receipts.
    let receipts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM firewall_action_receipts WHERE intent_id=$1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
    assert_eq!(receipts, 2);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated firewall-rule PostgreSQL fixture with schema 0055"]
async fn concurrent_prepare_yields_exactly_one_owner() -> Result<()> {
    let store = store().await?;
    let (adapter, action, scope) = ("haproxy", "haproxy.block_indicator", "clawforge_deny_acl");
    let fp = format!("198.51.100.{}/32", Uuid::new_v4().as_u128() % 250 + 1);
    let target = json!({"cidr": fp});
    let state = json!({});
    let plan = json!({"commands": []});
    let execution = execution(&store, action).await?;
    let (a, b) = tokio::join!(
        store.prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp, &target, &state, &plan, 3600
        ),
        store.prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp, &target, &state, &plan, 3600
        ),
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "exactly one concurrent owner may prepare"
    );
    store.mark_firewall_rule_not_applied(a.or(b)?).await?;
    Ok(())
}

/// The sweep candidate set is prepared + completed-and-expired, and deliberately
/// excludes recovery_required (manual cases must not starve the auto-rollback),
/// unexpired completed generations, and terminal rolled_back ones.
#[tokio::test]
#[ignore = "requires an isolated firewall-rule PostgreSQL fixture with schema 0055"]
async fn recoverable_sweep_set_covers_prepared_and_expired_only() -> Result<()> {
    let store = store().await?;
    let adapter = "nftables";
    let action = "nftables.block_indicator";
    let scope = "clawforge_sweep_v4";
    let execution = execution(&store, action).await?;
    let state = json!({"set_present": false});
    let plan = json!({"commands": [["nft", "delete", "element", "..."]]});
    // Distinct concrete rules so per-rule unique ownership never collides.
    let mk = |n: u32| format!("192.0.2.{n}/32");

    // 1. prepared -> swept.
    let fp_prep = mk(11);
    let t_prep = json!({"cidr": fp_prep, "scope": scope});
    let prepared = store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp_prep, &t_prep, &state, &plan, 3600,
        )
        .await?;

    // 2. completed but unexpired (fw_expires_at = NOW()+3600) -> NOT swept.
    let fp_fresh = mk(12);
    let t_fresh = json!({"cidr": fp_fresh, "scope": scope});
    let fresh = store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp_fresh, &t_fresh, &state, &plan, 3600,
        )
        .await?;
    store
        .finish_firewall_rule_intent(
            fresh,
            &receipt(
                execution, adapter, action, &fp_fresh, &t_fresh, &state, &plan,
            ),
        )
        .await?;

    // 3. completed and expired -> swept. fw_expires_at is immutable under the
    // snapshot trigger, so disable it only to simulate elapsed TTL in the lab.
    let fp_exp = mk(13);
    let t_exp = json!({"cidr": fp_exp, "scope": scope});
    let expired = store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp_exp, &t_exp, &state, &plan, 3600,
        )
        .await?;
    store
        .finish_firewall_rule_intent(
            expired,
            &receipt(execution, adapter, action, &fp_exp, &t_exp, &state, &plan),
        )
        .await?;
    sqlx::query(
        "ALTER TABLE firewall_action_intents DISABLE TRIGGER firewall_rule_intent_snapshot_immutable",
    )
    .execute(store.pool())
    .await?;
    sqlx::query(
        "UPDATE firewall_action_intents SET fw_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
    )
    .bind(expired)
    .execute(store.pool())
    .await?;
    sqlx::query(
        "ALTER TABLE firewall_action_intents ENABLE TRIGGER firewall_rule_intent_snapshot_immutable",
    )
    .execute(store.pool())
    .await?;

    // 4. recovery_required -> NOT swept (manual reconciliation).
    let fp_rec = mk(14);
    let t_rec = json!({"cidr": fp_rec, "scope": scope});
    let rec = store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp_rec, &t_rec, &state, &plan, 3600,
        )
        .await?;
    store.mark_firewall_rule_recovery_required(rec).await?;

    // 5. rolled_back -> NOT swept (terminal).
    let fp_rb = mk(15);
    let t_rb = json!({"cidr": fp_rb, "scope": scope});
    let rb = store
        .prepare_firewall_rule_intent(
            execution, adapter, action, scope, &fp_rb, &t_rb, &state, &plan, 3600,
        )
        .await?;
    store
        .finish_firewall_rule_intent(
            rb,
            &receipt(execution, adapter, action, &fp_rb, &t_rb, &state, &plan),
        )
        .await?;
    store.resolve_firewall_rule_rollback(rb).await?;

    let swept: Vec<Uuid> = store
        .recoverable_firewall_rule_intents()
        .await?
        .into_iter()
        .map(|i| i.id)
        .collect();
    assert!(swept.contains(&prepared), "a prepared generation is swept");
    assert!(
        swept.contains(&expired),
        "a completed-and-expired generation is swept"
    );
    assert!(
        !swept.contains(&fresh),
        "an unexpired completed generation is not swept"
    );
    assert!(
        !swept.contains(&rec),
        "recovery_required must not starve the auto-rollback"
    );
    assert!(
        !swept.contains(&rb),
        "a rolled_back generation is terminal, not swept"
    );
    Ok(())
}
