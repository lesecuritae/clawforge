use super::*;
use clawforge_firewall_agent::{AdapterError, ApplyResult, FirewallActionReceipt, Preflight};
use std::sync::{Arc, Mutex};

const SENSITIVE: &str = "sensitive-error-marker";
struct FakeAdapter {
    name: &'static str,
    preflight_fails: bool,
    apply_fails: bool,
    verification: Option<VerificationResult>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
impl FakeAdapter {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            preflight_fails: false,
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
                already_blocked: false,
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
    let outcome = apply_single_adapter(&fake, &action(), false).await;
    assert_eq!(outcome.completion, DispatchCompletion::Failed);
    assert_eq!(*fake.calls.lock().unwrap(), vec!["preflight"]);
    assert!(outcome.receipts.is_empty());
    assert_redacted(&outcome);
}
#[tokio::test]
async fn dry_run_can_plan_without_live_preflight_but_never_claims_verification() {
    let mut fake = FakeAdapter::new("nftables");
    fake.preflight_fails = true;
    let outcome = apply_single_adapter(&fake, &action(), true).await;
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
        let outcome = apply_single_adapter(&fake, &action(), false).await;
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
        let outcome = apply_single_adapter(&fake, &action(), false).await;
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
    let outcome = apply_single_adapter(&fake, &action(), false).await;
    assert_eq!(outcome.completion, DispatchCompletion::Success);
    assert_eq!(outcome.receipts[0].verification_result, Some("verified"));
    let mut fake = FakeAdapter::new("nftables");
    fake.apply_fails = true;
    let outcome = apply_single_adapter(&fake, &action(), true).await;
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
    )
    .await;
    assert_eq!(outcome.completion, DispatchCompletion::Success);
    assert!(outcome.error_summary.unwrap().contains("preflight"));
    let outcome = dispatch_multi_with_adapters(&action(), false, vec![]).await;
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
    )
    .await;
    assert_eq!(outcome.completion, DispatchCompletion::RecoveryRequired);
    assert_eq!(outcome.receipts.len(), 1);
}

#[tokio::test]
async fn lost_receipt_never_leaves_success_or_retries_a_real_effect() {
    for dry_run in [true, false] {
        let fake = FakeAdapter::new("nftables");
        let mut outcome = apply_single_adapter(&fake, &action(), dry_run).await;
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
