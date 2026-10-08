use super::*;
use clawforge_firewall_agent::{AdapterError, ApplyResult, FirewallActionReceipt, Preflight};
use std::sync::{Arc, Mutex};

const SENSITIVE: &str = "sensitive-error-marker";
struct FakeAdapter {
    name: &'static str,
    preflight_fails: bool,
    already_blocked: bool,
    apply_fails: bool,
    verification: Option<VerificationResult>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
impl FakeAdapter {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            preflight_fails: false,
            already_blocked: false,
            apply_fails: false,
            verification: Some(VerificationResult::Verified),
            calls: Default::default(),
        }
    }
}
#[async_trait::async_trait]
impl FirewallAdapter for FakeAdapter {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn preflight(&self, _: &FirewallTarget) -> Result<Preflight, AdapterError> {
        self.calls.lock().unwrap().push("preflight");
        if self.preflight_fails {
            Err(AdapterError::Preflight(SENSITIVE.into()))
        } else {
            Ok(Preflight {
                already_blocked: self.already_blocked,
                raw_set_json: "{\"before\":true}".into(),
            })
        }
    }
    fn render(&self, action: &FirewallAction) -> Result<FirewallActionReceipt, AdapterError> {
        Ok(FirewallActionReceipt {
            adapter: self.name,
            rendered_commands: vec![vec!["add".into()]],
            rollback_commands: vec![vec!["remove".into()]],
            is_dry_run: true,
            ttl_seconds: action.ttl_seconds,
            target_fingerprint: "test-target".into(),
        })
    }
    async fn apply(
        &self,
        action: &FirewallAction,
        dry_run: bool,
    ) -> Result<ApplyResult, AdapterError> {
        self.calls.lock().unwrap().push("apply");
        if self.apply_fails {
            return Err(AdapterError::Apply(SENSITIVE.into()));
        }
        let mut receipt = self.render(action)?;
        receipt.is_dry_run = dry_run;
        Ok(ApplyResult {
            receipt,
            observed_state: (!dry_run).then(|| "{\"after\":true}".into()),
        })
    }
    async fn verify(&self, _: &FirewallTarget) -> Result<VerificationResult, AdapterError> {
        self.calls.lock().unwrap().push("verify");
        self.verification
            .clone()
            .ok_or_else(|| AdapterError::Verify(SENSITIVE.into()))
    }
    async fn rollback(&self, _: &FirewallAction) -> Result<(), AdapterError> {
        panic!("dispatch must not improvise a rollback without ownership")
    }
}
fn action() -> FirewallAction {
    parse_firewall_action(Uuid::nil(), &serde_json::json!({"kind":"threat_intel_indicator", "cidr":"203.0.113.7", "source":"test"})).unwrap()
}
fn assert_redacted(outcome: &GenericDispatchOutcome) {
    assert!(!outcome
        .error_summary
        .as_deref()
        .unwrap_or_default()
        .contains(SENSITIVE));
    assert!(!outcome
        .result_summary
        .as_deref()
        .unwrap_or_default()
        .contains(SENSITIVE));
}

#[tokio::test]
async fn real_preflight_failure_never_applies() {
    let mut fake = FakeAdapter::new("nftables");
    fake.preflight_fails = true;
    let outcome = apply_single_adapter(&fake, &action(), false, None).await;
    assert_eq!(outcome.completion, DispatchCompletion::Failed);
    assert_eq!(*fake.calls.lock().unwrap(), vec!["preflight"]);
    assert!(outcome.receipts.is_empty());
    assert_redacted(&outcome);
}
#[tokio::test]
async fn dry_run_can_plan_without_live_preflight_but_never_claims_verification() {
    let mut fake = FakeAdapter::new("nftables");
    fake.preflight_fails = true;
    let outcome = apply_single_adapter(&fake, &action(), true, None).await;
    assert_eq!(outcome.completion, DispatchCompletion::Success);
    assert_eq!(*fake.calls.lock().unwrap(), vec!["preflight", "apply"]);
    assert!(outcome.receipts[0].is_dry_run);
    assert_eq!(outcome.receipts[0].verification_result, None);
    assert_eq!(
        outcome.receipts[0].preflight_state["status"],
        "preflight_unavailable"
    );
    assert_redacted(&outcome);
}
#[tokio::test]
async fn unknown_apply_effect_is_fenced_regardless_of_readback() {
    for verification in [
        Some(VerificationResult::Verified),
        Some(VerificationResult::NotPresent),
        None,
    ] {
        let mut fake = FakeAdapter::new("nftables");
        fake.apply_fails = true;
        fake.verification = verification;
        let outcome = apply_single_adapter(&fake, &action(), false, None).await;
        assert_eq!(outcome.completion, DispatchCompletion::RecoveryRequired);
        assert!(outcome.receipts.is_empty(), "never invent an apply receipt");
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec!["preflight", "apply", "verify"]
        );
        assert_redacted(&outcome);
    }
}
#[tokio::test]
async fn verification_failure_preserves_known_apply_receipt_without_success() {
    for (verification, label) in [
        (Some(VerificationResult::NotPresent), "mismatch"),
        (None, "failed"),
    ] {
        let mut fake = FakeAdapter::new("nftables");
        fake.verification = verification;
        let outcome = apply_single_adapter(&fake, &action(), false, None).await;
        assert_eq!(outcome.completion, DispatchCompletion::RecoveryRequired);
        assert_eq!(outcome.receipts.len(), 1);
        assert_eq!(outcome.receipts[0].verification_result, Some(label));
        assert_eq!(
            outcome.receipts[0].observed_state.as_ref().unwrap()["after"],
            true
        );
        assert_eq!(
            outcome.receipts[0].rollback_plan["commands"][0][0],
            "remove"
        );
        assert!(!outcome.into_legacy().0);
    }
}
#[tokio::test]
async fn verified_real_apply_is_success_and_dry_planning_errors_do_not_verify() {
    let fake = FakeAdapter::new("nftables");
    let outcome = apply_single_adapter(&fake, &action(), false, None).await;
    assert_eq!(outcome.completion, DispatchCompletion::Success);
    assert_eq!(outcome.receipts[0].verification_result, Some("verified"));
    let mut fake = FakeAdapter::new("nftables");
    fake.apply_fails = true;
    let outcome = apply_single_adapter(&fake, &action(), true, None).await;
    assert_eq!(outcome.completion, DispatchCompletion::Failed);
    assert_eq!(*fake.calls.lock().unwrap(), vec!["preflight", "apply"]);
}
#[tokio::test]
async fn optional_uncertain_effect_overrides_mandatory_success() {
    let mut optional = FakeAdapter::new("haproxy");
    optional.apply_fails = true;
    let outcome = dispatch_multi_with_adapters(
        &action(),
        false,
        vec![Box::new(FakeAdapter::new("nftables")), Box::new(optional)],
        None,
    )
    .await;
    assert_eq!(outcome.completion, DispatchCompletion::RecoveryRequired);
    assert_eq!(outcome.receipts.len(), 1);
    assert_redacted(&outcome);
}
#[tokio::test]
async fn safe_optional_refusal_degrades_but_missing_mandatory_fails() {
    let mut optional = FakeAdapter::new("haproxy");
    optional.preflight_fails = true;
    let outcome = dispatch_multi_with_adapters(
        &action(),
        false,
        vec![Box::new(FakeAdapter::new("nftables")), Box::new(optional)],
        None,
    )
    .await;
    assert_eq!(outcome.completion, DispatchCompletion::Success);
    assert!(outcome.error_summary.unwrap().contains("preflight"));
    let outcome = dispatch_multi_with_adapters(&action(), false, vec![], None).await;
    assert_eq!(outcome.completion, DispatchCompletion::Failed);
}
#[tokio::test]
async fn mandatory_failure_retains_optional_real_receipt_and_cannot_auto_retry_partial_apply() {
    let mut mandatory = FakeAdapter::new("nftables");
    mandatory.preflight_fails = true;
    let outcome = dispatch_multi_with_adapters(
        &action(),
        false,
        vec![Box::new(mandatory), Box::new(FakeAdapter::new("haproxy"))],
        None,
    )
    .await;
    assert_eq!(outcome.completion, DispatchCompletion::RecoveryRequired);
    assert_eq!(outcome.receipts.len(), 1);
}

#[tokio::test]
async fn lost_receipt_never_leaves_success_or_retries_a_real_effect() {
    for dry_run in [true, false] {
        let fake = FakeAdapter::new("nftables");
        let mut outcome = apply_single_adapter(&fake, &action(), dry_run, None).await;
        assert_eq!(outcome.completion, DispatchCompletion::Success);
        outcome.receipt_persistence_failed(dry_run);
        assert_eq!(
            outcome.completion,
            if dry_run {
                DispatchCompletion::Failed
            } else {
                DispatchCompletion::RecoveryRequired
            }
        );
        assert_eq!(
            outcome.receipts.len(),
            1,
            "retain available recovery evidence"
        );
        assert!(!outcome.into_legacy().0);
    }
}

#[tokio::test]
#[ignore = "requires an isolated firewall-rule PostgreSQL fixture with schema 0055"]
async fn write_ahead_journal_owns_before_apply_and_resolves_atomically() {
    let store = PostgresStore::connect_runtime(
        &std::env::var("CLAWFORGE_TEST_FIREWALL_RULE_DATABASE_URL").unwrap(),
    )
    .await
    .unwrap();
    // Seed a low-risk firewall execution (FK only; rule intents carry no approval gate).
    let action_name = "nftables.block_indicator";
    let action_id: Uuid = sqlx::query_scalar("INSERT INTO actions(id,name,type,risk_level,required_scope,requires_approval,enabled) VALUES($1,$2,'connector_action','low','agent:action:read',FALSE,TRUE) ON CONFLICT(name) DO UPDATE SET enabled=TRUE RETURNING id")
        .bind(Uuid::new_v4()).bind(action_name).fetch_one(store.pool()).await.unwrap();
    let requester = store
        .create_admin_user(&format!("req-{}", Uuid::new_v4()), "Administrator", "h")
        .await
        .unwrap();
    let execution = store
        .create_execution_request(&clawforge_storage::ExecutionRequestInput {
            action_id,
            workflow_run_id: None,
            decision_id: None,
            requested_by: "req".into(),
            requested_by_id: Some(requester),
            idempotency_key: None,
            target: Some(serde_json::json!({"cidr": "203.0.113.7"})),
        })
        .await
        .unwrap();
    let journal = RuleJournal {
        store: &store,
        execution_id: execution,
        action_name,
    };
    let owned = "SELECT id,status FROM firewall_action_intents WHERE adapter='nftables' AND fw_rule_scope='nftables' AND fw_rule_fingerprint='test-target' AND status IN ('prepared','completed','recovery_required')";

    // Verified real apply: completed generation + one apply receipt, persisted by
    // finish (so no in-memory receipt is returned to the main loop).
    let outcome = apply_single_adapter(
        &FakeAdapter::new("nftables"),
        &action(),
        false,
        Some(&journal),
    )
    .await;
    assert_eq!(outcome.completion, DispatchCompletion::Success);
    assert!(outcome.receipts.is_empty());
    let (gen_id, status): (Uuid, String) =
        sqlx::query_as(owned).fetch_one(store.pool()).await.unwrap();
    assert_eq!(status, "completed");
    let receipts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM firewall_action_receipts WHERE intent_id=$1 AND receipt_kind='apply'",
    )
    .bind(gen_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(receipts, 1);

    // R1: the generation persisted the versioned recovery target (the exact
    // bound identity), not a bare fingerprint, and it reconstructs.
    let persisted: serde_json::Value =
        sqlx::query_scalar("SELECT fw_target_json FROM firewall_action_intents WHERE id=$1")
            .bind(gen_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(
        persisted
            .get("schema_version")
            .and_then(serde_json::Value::as_u64),
        Some(clawforge_firewall_agent::RecoveryTarget::SCHEMA_VERSION),
        "apply persists the versioned recovery target, not a bare fingerprint"
    );
    let recovered = clawforge_firewall_agent::RecoveryTarget::from_json(&persisted)
        .expect("the persisted recovery target reconstructs");
    assert_eq!(
        recovered.target,
        FirewallTarget::ThreatIntelIndicator {
            cidr: "203.0.113.7".into(),
            source: "test".into()
        }
    );

    // The rule is owned: a second real apply refuses before any mutation.
    let blocked = apply_single_adapter(
        &FakeAdapter::new("nftables"),
        &action(),
        false,
        Some(&journal),
    )
    .await;
    assert_eq!(blocked.completion, DispatchCompletion::Failed);

    // After a verified rollback, an uncertain verify leaves a NEW generation
    // recovery_required (owned, never silently retried).
    store.resolve_firewall_rule_rollback(gen_id).await.unwrap();
    let mut drift = FakeAdapter::new("nftables");
    drift.verification = Some(VerificationResult::NotPresent);
    let uncertain = apply_single_adapter(&drift, &action(), false, Some(&journal)).await;
    assert_eq!(uncertain.completion, DispatchCompletion::RecoveryRequired);
    let (_gen3, status3): (Uuid, String) =
        sqlx::query_as(owned).fetch_one(store.pool()).await.unwrap();
    assert_eq!(status3, "recovery_required");
}

// R4: a real journaled apply must refuse to adopt a rule that already exists at
// preflight (operator-owned) - no apply, no generation, no delete-ownership.
#[tokio::test]
#[ignore = "requires an isolated firewall-rule PostgreSQL fixture with schema 0055"]
async fn journaled_apply_refuses_to_adopt_an_already_present_rule() {
    let store = PostgresStore::connect_runtime(
        &std::env::var("CLAWFORGE_TEST_FIREWALL_RULE_DATABASE_URL").unwrap(),
    )
    .await
    .unwrap();
    let action_name = "nftables.block_indicator";
    let action_id: Uuid = sqlx::query_scalar("INSERT INTO actions(id,name,type,risk_level,required_scope,requires_approval,enabled) VALUES($1,$2,'connector_action','low','agent:action:read',FALSE,TRUE) ON CONFLICT(name) DO UPDATE SET enabled=TRUE RETURNING id")
        .bind(Uuid::new_v4()).bind(action_name).fetch_one(store.pool()).await.unwrap();
    let requester = store
        .create_admin_user(&format!("req-{}", Uuid::new_v4()), "Administrator", "h")
        .await
        .unwrap();
    let execution = store
        .create_execution_request(&clawforge_storage::ExecutionRequestInput {
            action_id,
            workflow_run_id: None,
            decision_id: None,
            requested_by: "req".into(),
            requested_by_id: Some(requester),
            idempotency_key: None,
            target: Some(serde_json::json!({"cidr": "203.0.113.7"})),
        })
        .await
        .unwrap();
    let journal = RuleJournal {
        store: &store,
        execution_id: execution,
        action_name,
    };

    let mut fake = FakeAdapter::new("nftables");
    fake.already_blocked = true;
    let outcome = apply_single_adapter(&fake, &action(), false, Some(&journal)).await;
    assert_eq!(outcome.completion, DispatchCompletion::Failed);
    assert!(
        !fake.calls.lock().unwrap().contains(&"apply"),
        "an already-present rule must never be applied"
    );
    let generations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM firewall_action_intents WHERE execution_id=$1 AND fw_rule_fingerprint IS NOT NULL",
    )
    .bind(execution)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        generations, 0,
        "no generation is created when adoption is refused"
    );
}
