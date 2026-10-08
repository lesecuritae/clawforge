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
