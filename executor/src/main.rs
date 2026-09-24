//! `clawforge-executor` - claims `execution_requests` and dispatches them.
//!
//! `CLAWFORGE_EXECUTOR_DRY_RUN` must remain `true` (the binary refuses to
//! start otherwise) - the process-level gate. This module's own dispatch
//! logic re-checks the same value at the point it would actually call an
//! adapter's `apply` (see `dry_run_from_env`) as a second, independent
//! check: if some future change ever relaxed the startup gate without
//! this call site being updated too, dispatch would still default to
//! `dry_run: true` rather than silently start applying for real.
//!
//! Any action whose name is not a recognized firewall action (`nftables.`
//! prefix) keeps the exact prior behavior: claimed, marked `running`, then
//! immediately completed with `"dry_run: no external operation executed"`
//! - this module changes nothing about docker/github/proxmox actions.

use clawforge_firewall_agent::{
    FirewallAction, FirewallAdapter, FirewallTarget, NftablesAdapter, VerificationResult,
};
use clawforge_storage::{
    database_url_from_env, ClaimedExecutionRequest, FirewallActionReceiptInput, PostgresStore,
};
use std::{env, time::Duration};
use tokio::time::{interval, MissedTickBehavior};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const DEFAULT_FIREWALL_ACTION_TTL_SECONDS: u32 = 3600;

/// Everything `dispatch()` gathers for a successful `nftables.*` apply, for
/// `main()`'s loop (the only place with a `store`) to persist as an Action
/// Receipt via `record_firewall_action_receipt`. `dispatch()` itself stays
/// DB-free on purpose - its existing unit tests call it directly with no
/// store to hand it.
struct FirewallDispatchReceipt {
    adapter: &'static str,
    preflight_state: serde_json::Value,
    rendered_commands: serde_json::Value,
    observed_state: Option<serde_json::Value>,
    verification_result: Option<&'static str>,
    ttl_seconds: u32,
    rollback_plan: serde_json::Value,
    is_dry_run: bool,
}

/// `nft -j list set`'s own JSON output, kept as structured JSONB where
/// possible rather than an opaque string - falls back to wrapping the raw
/// text if it somehow isn't valid JSON (e.g. an unexpected `nft` version's
/// output), and to an empty object for the "no resolvable address yet"
/// case (`Preflight::raw_set_json` is `""` for an unresolved
/// `IncidentSource` - see that variant's own doc comment).
fn nft_state_json(raw: &str) -> serde_json::Value {
    if raw.is_empty() {
        return serde_json::json!({});
    }
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::json!({"raw": raw}))
}

fn dry_run_from_env() -> bool {
    env::var("CLAWFORGE_EXECUTOR_DRY_RUN")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(true)
}

/// `target` (`{"kind":"threat_intel_indicator",...}` /
/// `{"kind":"incident_source",...}`) plus an optional `ttl_seconds` -
/// carried alongside the target rather than as a `FirewallTarget` field,
/// since TTL is a property of the *action*, not of what it targets.
fn parse_firewall_action(
    request_id: Uuid,
    target: &serde_json::Value,
) -> anyhow::Result<FirewallAction> {
    let firewall_target = FirewallTarget::try_from(target)
        .map_err(|error| anyhow::anyhow!("invalid firewall target: {error}"))?;
    let ttl_seconds = target
        .get("ttl_seconds")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_FIREWALL_ACTION_TTL_SECONDS);
    Ok(FirewallAction {
        target: firewall_target,
        ttl_seconds,
        reason: format!("execution_request {request_id}"),
    })
}

/// Dispatches one claimed request. Returns `(success, result_summary,
/// error_summary, receipt)` for the caller to persist via
/// `complete_execution_dispatch` (always) and `record_firewall_action_receipt`
/// (only when `receipt` is `Some`, i.e. a firewall action actually applied
/// successfully) - never panics, every adapter/parse error becomes a failed
/// completion with a clear `error_summary` instead.
async fn dispatch(
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Option<FirewallDispatchReceipt>,
) {
    if !claimed.action_name.starts_with("nftables.") {
        return (
            true,
            Some("dry_run: no external operation executed".to_string()),
            None,
            None,
        );
    }
    let Some(target) = claimed.target.as_ref() else {
        return (
            false,
            None,
            Some(format!(
                "firewall action {:?} has no target",
                claimed.action_name
            )),
            None,
        );
    };
    let action = match parse_firewall_action(claimed.id, target) {
        Ok(action) => action,
        Err(error) => return (false, None, Some(error.to_string()), None),
    };
    let adapter = NftablesAdapter::new();
    let dry_run = dry_run_from_env();
    // Best-effort: preflight is read-only enrichment for the receipt, not
    // a gate - a preflight failure (e.g. no NET_ADMIN in this environment)
    // is recorded as-is and apply is still attempted, since apply's own
    // success/failure is what actually determines the outcome here.
    let preflight_state = match adapter.preflight(&action.target).await {
        Ok(preflight) => nft_state_json(&preflight.raw_set_json),
        Err(error) => serde_json::json!({"error": error.to_string()}),
    };
    match adapter.apply(&action, dry_run).await {
        Ok(result) => {
            let verification_result = if dry_run {
                None
            } else {
                match adapter.verify(&action.target).await {
                    Ok(VerificationResult::Verified) => Some("verified"),
                    Ok(VerificationResult::NotPresent) => Some("mismatch"),
                    Err(_) => Some("failed"),
                }
            };
            let summary = format!(
                "adapter={} dry_run={} commands={:?}",
                result.receipt.adapter, result.receipt.is_dry_run, result.receipt.rendered_commands
            );
            let receipt = FirewallDispatchReceipt {
                adapter: result.receipt.adapter,
                preflight_state,
                rendered_commands: serde_json::json!(result.receipt.rendered_commands),
                observed_state: result.observed_state.as_deref().map(nft_state_json),
                verification_result,
                ttl_seconds: result.receipt.ttl_seconds,
                rollback_plan: serde_json::json!({"commands": result.receipt.rollback_commands}),
                is_dry_run: result.receipt.is_dry_run,
            };
            (true, Some(summary), None, Some(receipt))
        }
        Err(error) => (false, None, Some(error.to_string()), None),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    if !dry_run_from_env() {
        anyhow::bail!(
            "productive execution is disabled; CLAWFORGE_EXECUTOR_DRY_RUN must remain true"
        );
    }
    let store = PostgresStore::connect_runtime(&database_url_from_env()?).await?;
    let worker_name = env::var("CLAWFORGE_EXECUTOR_WORKER_NAME")
        .unwrap_or_else(|_| format!("executor-{}", std::process::id()));
    let worker_capacity = env::var("CLAWFORGE_EXECUTOR_WORKER_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(1)
        .clamp(1, 64);
    let worker_id = store
        .register_execution_worker(&worker_name, worker_capacity)
        .await?;
    store
        .set_runtime_status("executor", "running", None)
        .await?;
    let seconds = env::var("CLAWFORGE_EXECUTOR_POLL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10u64)
        .max(2);
    let mut ticks = interval(Duration::from_secs(seconds));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticks.tick() => {
                if let Err(error) = store.set_runtime_status("executor", "running", None).await { tracing::warn!(%error, "executor heartbeat failed"); }
                if let Err(error) = store.heartbeat_execution_worker(worker_id, "healthy", 0, None).await { tracing::warn!(%error, "executor worker heartbeat failed"); }
                let started = std::time::Instant::now();
                match store.claim_execution_request_for_dispatch(Some(worker_id)).await {
                    Ok(Some(claimed)) => {
                        let (success, result_summary, error_summary, receipt) = dispatch(&claimed).await;
                        if let Some(receipt) = receipt {
                            if let Err(error) = store
                                .record_firewall_action_receipt(FirewallActionReceiptInput {
                                    execution_id: Some(claimed.id),
                                    adapter: receipt.adapter,
                                    action_name: &claimed.action_name,
                                    preflight_state: receipt.preflight_state,
                                    rendered_commands: receipt.rendered_commands,
                                    observed_state: receipt.observed_state,
                                    verification_result: receipt.verification_result,
                                    ttl_seconds: receipt.ttl_seconds,
                                    rollback_plan: receipt.rollback_plan,
                                    is_dry_run: receipt.is_dry_run,
                                })
                                .await
                            {
                                // Best-effort: a receipt is an audit record of
                                // an already-decided outcome, not a gate on it
                                // - losing one must not turn a completed
                                // dispatch into a failed one.
                                tracing::warn!(%error, execution_id = %claimed.id, "could not persist firewall action receipt");
                            }
                        }
                        if let Err(error) = store
                            .complete_execution_dispatch(
                                claimed.id,
                                Some(worker_id),
                                started,
                                success,
                                result_summary.as_deref(),
                                error_summary.as_deref(),
                            )
                            .await
                        {
                            tracing::warn!(%error, execution_id = %claimed.id, "could not persist dispatch completion");
                            let _ = store.heartbeat_execution_worker(worker_id, "degraded", 0, Some(&error.to_string())).await;
                        } else if !success {
                            tracing::warn!(execution_id = %claimed.id, action = %claimed.action_name, error = ?error_summary, "dispatch failed");
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(%error, "claiming an execution request failed");
                        let _ = store.heartbeat_execution_worker(worker_id, "degraded", 0, Some(&error.to_string())).await;
                    }
                }
            }
            _ = shutdown_signal() => { let _ = store.heartbeat_execution_worker(worker_id, "stopped", 0, None).await; let _ = store.set_runtime_status("executor", "stopped", None).await; break; }
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("signal");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claimed(action_name: &str, target: Option<serde_json::Value>) -> ClaimedExecutionRequest {
        ClaimedExecutionRequest {
            id: Uuid::new_v4(),
            action_name: action_name.to_string(),
            target,
        }
    }

    #[test]
    fn dry_run_from_env_defaults_to_true_when_unset() {
        // SAFETY: single-threaded test process, no other test in this
        // binary reads/writes this specific env var.
        std::env::remove_var("CLAWFORGE_EXECUTOR_DRY_RUN");
        assert!(dry_run_from_env());
    }

    #[tokio::test]
    async fn non_firewall_actions_keep_the_original_dry_run_success_behavior() {
        let request = claimed("docker.restart_container", None);
        let (success, summary, error, receipt) = dispatch(&request).await;
        assert!(success);
        assert_eq!(
            summary.as_deref(),
            Some("dry_run: no external operation executed")
        );
        assert!(error.is_none());
        assert!(
            receipt.is_none(),
            "a non-firewall action must never produce a receipt to persist"
        );
    }

    #[tokio::test]
    async fn a_firewall_action_without_a_target_fails_with_a_clear_error() {
        let request = claimed("nftables.block_indicator", None);
        let (success, _summary, error, receipt) = dispatch(&request).await;
        assert!(!success);
        assert!(error.unwrap().contains("no target"));
        assert!(receipt.is_none());
    }

    #[tokio::test]
    async fn a_firewall_action_with_a_malformed_target_fails_with_a_clear_error() {
        let request = claimed(
            "nftables.block_indicator",
            Some(serde_json::json!({"kind": "not-a-real-kind"})),
        );
        let (success, _summary, error, receipt) = dispatch(&request).await;
        assert!(!success);
        assert!(error.is_some());
        assert!(receipt.is_none());
    }

    #[tokio::test]
    async fn a_valid_firewall_action_dispatches_in_dry_run_by_default() {
        // No CLAWFORGE_EXECUTOR_DRY_RUN set - defaults to true, so this
        // exercises render-only apply, needing no real nft/NET_ADMIN.
        std::env::remove_var("CLAWFORGE_EXECUTOR_DRY_RUN");
        let request = claimed(
            "nftables.block_indicator",
            Some(serde_json::json!({
                "kind": "threat_intel_indicator",
                "cidr": "203.0.113.0/24",
                "source": "spamhaus_drop",
            })),
        );
        let (success, summary, error, receipt) = dispatch(&request).await;
        assert!(success, "dispatch failed: {error:?}");
        let summary = summary.unwrap();
        assert!(summary.contains("dry_run=true"));
        assert!(summary.contains("203.0.113.0/24"));
        let receipt = receipt.expect("a successful firewall apply must produce a receipt");
        assert!(receipt.is_dry_run);
        assert!(
            receipt.verification_result.is_none(),
            "a dry run has nothing to verify"
        );
    }

    #[test]
    fn parse_firewall_action_uses_the_default_ttl_when_absent_and_respects_an_explicit_one() {
        let id = Uuid::new_v4();
        let default_target = serde_json::json!({
            "kind": "threat_intel_indicator",
            "cidr": "203.0.113.7",
            "source": "spamhaus_drop",
        });
        let action = parse_firewall_action(id, &default_target).unwrap();
        assert_eq!(action.ttl_seconds, DEFAULT_FIREWALL_ACTION_TTL_SECONDS);

        let explicit_target = serde_json::json!({
            "kind": "threat_intel_indicator",
            "cidr": "203.0.113.7",
            "source": "spamhaus_drop",
            "ttl_seconds": 120,
        });
        let action = parse_firewall_action(id, &explicit_target).unwrap();
        assert_eq!(action.ttl_seconds, 120);
    }
}
