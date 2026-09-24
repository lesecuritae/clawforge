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
//! or `haproxy.` prefix) keeps the exact prior behavior: claimed, marked
//! `running`, then immediately completed with `"dry_run: no external
//! operation executed"` - this module changes nothing about docker/
//! github/proxmox actions, or `tailscale.*` ones (`TailscaleAdapter` has
//! no `apply` capability to dispatch to at all - see
//! `docs/firewall-agent.md`).

use clawforge_firewall_agent::{
    FirewallAction, FirewallAdapter, FirewallTarget, HaproxyAdapter, NftablesAdapter,
    VerificationResult,
};
use clawforge_storage::{
    database_url_from_env, ClaimedExecutionRequest, FirewallActionReceiptInput, PostgresStore,
};
use std::{env, time::Duration};
use tokio::time::{interval, MissedTickBehavior};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const DEFAULT_FIREWALL_ACTION_TTL_SECONDS: u32 = 3600;
const DEFAULT_FIREWALL_RATE_WINDOW_SECONDS: i64 = 300;
const DEFAULT_FIREWALL_MAX_APPLIES_PER_WINDOW: i64 = 20;

fn firewall_rate_window_seconds() -> i64 {
    env::var("CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_FIREWALL_RATE_WINDOW_SECONDS)
}

fn firewall_max_applies_per_window() -> i64 {
    env::var("CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_FIREWALL_MAX_APPLIES_PER_WINDOW)
}

/// Whether a claimed request needs a mass-block budget check at all - a
/// dry run or a non-firewall action never does, so
/// `firewall_mass_block_budget_exceeded` can skip touching the database
/// entirely for the common case. Pure and separate from that function so
/// it can be unit-tested without a real store to hand it.
fn firewall_budget_applies(action_name: &str, dry_run: bool) -> bool {
    !dry_run && is_firewall_action(action_name)
}

/// Whether `action_name` is one `dispatch()` actually routes to a real
/// adapter - `nftables.*` (`NftablesAdapter`) or `haproxy.*`
/// (`HaproxyAdapter`). `tailscale.*` is deliberately excluded: there is
/// no apply capability to dispatch to at all (see
/// `docs/firewall-agent.md`), so it stays on the same generic dry-run
/// fallback every other non-firewall action already uses.
fn is_firewall_action(action_name: &str) -> bool {
    action_name.starts_with("nftables.") || action_name.starts_with("haproxy.")
}

/// Picks the adapter an `nftables.`/`haproxy.`-prefixed action name (or,
/// for the TTL sweep, an `adapter` column value - `"nftables"`/
/// `"haproxy"`, no trailing dot) routes to. Shared by `dispatch()` and
/// `sweep_expired_firewall_targets()` so the two can never pick a
/// different adapter for the same name.
fn adapter_for(name: &str) -> Option<Box<dyn FirewallAdapter>> {
    if name.starts_with("nftables") {
        Some(Box::new(NftablesAdapter::new()))
    } else if name.starts_with("haproxy") {
        Some(Box::new(HaproxyAdapter::new()))
    } else {
        None
    }
}

/// The mass-block budget: how many *real* (non-dry-run) firewall applies
/// (`nftables.*` or `haproxy.*` - one shared counter across both adapters,
/// not one per adapter) this database has recorded in the trailing rate
/// window - a runaway policy engine or a config mistake must not be able
/// to block hundreds of addresses in a burst. Dry runs and non-firewall
/// actions are never gated (`Ok(None)`) - there is nothing to bound. DB-backed via
/// `recent_real_firewall_apply_count` rather than an in-memory counter, so
/// the budget holds across a process restart and across multiple executor
/// replicas sharing this database - see that method's own doc comment.
/// Concurrency (more than one real apply in flight at once) is not a
/// separate counter here: this loop claims and dispatches one request per
/// tick, sequentially, so within a single process it is already 1 by
/// construction; bounding it across multiple replicas targeting the *same*
/// host is a still-open item (see docs/firewall-agent.md).
async fn firewall_mass_block_budget_exceeded(
    store: &PostgresStore,
    action_name: &str,
    dry_run: bool,
) -> anyhow::Result<Option<String>> {
    if !firewall_budget_applies(action_name, dry_run) {
        return Ok(None);
    }
    let window = firewall_rate_window_seconds();
    let max = firewall_max_applies_per_window();
    let count = store.recent_real_firewall_apply_count(window).await?;
    if count >= max {
        return Ok(Some(format!(
            "mass-block budget exceeded: {count} real applies already recorded in the last \
             {window}s (max {max}, see CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW/\
             CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS)"
        )));
    }
    Ok(None)
}

/// Everything `dispatch()` gathers for a successful firewall apply, for
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
    target_fingerprint: String,
}

/// An adapter's raw preflight/observed-state text (`nft -j list set`'s
/// JSON for `NftablesAdapter`, `show acl`'s plain text for
/// `HaproxyAdapter`), kept as structured JSONB where possible rather than
/// an opaque string - falls back to wrapping the raw text if it isn't
/// valid JSON (always true for HAProxy's plain-text response, and for an
/// unexpected `nft` version's output), and to an empty object for the "no
/// resolvable address yet" case (`Preflight::raw_set_json` is `""` for an
/// unresolved `IncidentSource` - see that variant's own doc comment).
fn adapter_state_json(raw: &str) -> serde_json::Value {
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

/// TTL-driven auto-rollback: rolls back every real (non-dry-run) block
/// whose TTL has passed and that has no later rollback receipt yet (see
/// `PostgresStore::expired_unrolled_back_firewall_targets`'s own query).
/// Called once per poll tick, same cadence as normal dispatch - simple,
/// and expiry is not time-critical enough to need its own faster
/// interval. Never panics; a single target's rollback failure is logged
/// and left for the next tick to retry (no receipt is recorded for it,
/// so the same target is returned again next time) rather than aborting
/// the whole sweep.
async fn sweep_expired_firewall_targets(store: &PostgresStore) {
    let expired = match store.expired_unrolled_back_firewall_targets().await {
        Ok(expired) => expired,
        Err(error) => {
            tracing::warn!(%error, "could not check for expired firewall targets");
            return;
        }
    };
    for target in expired {
        let Some(adapter) = adapter_for(&target.adapter) else {
            tracing::warn!(
                receipt_id = %target.receipt_id,
                adapter = %target.adapter,
                "expired firewall target has an unrecognized adapter - skipping"
            );
            continue;
        };
        let firewall_target = match FirewallTarget::try_from(&target.target_json) {
            Ok(firewall_target) => firewall_target,
            Err(error) => {
                tracing::warn!(
                    %error, receipt_id = %target.receipt_id,
                    "expired firewall target has an unparseable target_json - skipping"
                );
                continue;
            }
        };
        let action = FirewallAction {
            target: firewall_target,
            ttl_seconds: DEFAULT_FIREWALL_ACTION_TTL_SECONDS,
            reason: format!("ttl expired auto-rollback (receipt {})", target.receipt_id),
        };
        if let Err(error) = adapter.rollback(&action).await {
            tracing::warn!(
                %error, receipt_id = %target.receipt_id, adapter = %target.adapter,
                "auto-rollback of an expired firewall target failed - will retry next tick"
            );
            continue;
        }
        tracing::info!(
            receipt_id = %target.receipt_id, adapter = %target.adapter,
            target_fingerprint = %target.target_fingerprint,
            "auto-rolled-back an expired firewall target"
        );
        if let Err(error) = store
            .record_firewall_action_receipt(FirewallActionReceiptInput {
                execution_id: None,
                adapter: &target.adapter,
                action_name: "ttl-expired-auto-rollback",
                preflight_state: serde_json::json!({}),
                rendered_commands: serde_json::json!([]),
                observed_state: None,
                verification_result: None,
                ttl_seconds: DEFAULT_FIREWALL_ACTION_TTL_SECONDS,
                rollback_plan: serde_json::json!({}),
                is_dry_run: false,
                receipt_kind: "rollback",
                target_fingerprint: Some(&target.target_fingerprint),
                target_json: None,
            })
            .await
        {
            // The rollback itself already succeeded against the real
            // adapter, so the target is genuinely no longer blocked - but
            // losing this receipt means the sweep will pick the same
            // (already-gone) target up again next tick and retry a
            // rollback that has nothing left to undo, which
            // `rolling_back_an_element_that_was_never_applied_fails_cleanly`
            // proves fails (not silently succeeds), becoming a recurring
            // warning every tick rather than a security problem, until an
            // operator notices and clears the stuck row by hand.
            tracing::warn!(%error, receipt_id = %target.receipt_id, "could not persist the auto-rollback receipt - this target will be retried (and fail) every tick until fixed by hand");
        }
    }
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
    let Some(adapter) = adapter_for(&claimed.action_name) else {
        return (
            true,
            Some("dry_run: no external operation executed".to_string()),
            None,
            None,
        );
    };
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
    let dry_run = dry_run_from_env();
    // Best-effort: preflight is read-only enrichment for the receipt, not
    // a gate - a preflight failure (e.g. no NET_ADMIN in this environment)
    // is recorded as-is and apply is still attempted, since apply's own
    // success/failure is what actually determines the outcome here.
    let preflight_state = match adapter.preflight(&action.target).await {
        Ok(preflight) => adapter_state_json(&preflight.raw_set_json),
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
                observed_state: result.observed_state.as_deref().map(adapter_state_json),
                verification_result,
                ttl_seconds: result.receipt.ttl_seconds,
                rollback_plan: serde_json::json!({"commands": result.receipt.rollback_commands}),
                is_dry_run: result.receipt.is_dry_run,
                target_fingerprint: result.receipt.target_fingerprint,
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
                sweep_expired_firewall_targets(&store).await;
                let started = std::time::Instant::now();
                match store.claim_execution_request_for_dispatch(Some(worker_id)).await {
                    Ok(Some(claimed)) => {
                        let budget = firewall_mass_block_budget_exceeded(
                            &store,
                            &claimed.action_name,
                            dry_run_from_env(),
                        )
                        .await;
                        let refusal = match budget {
                            Ok(Some(reason)) => Some(reason),
                            Ok(None) => None,
                            Err(error) => {
                                // Fail closed: if the budget itself cannot be
                                // checked, do not apply - complete as failed
                                // rather than proceeding unchecked.
                                tracing::warn!(%error, execution_id = %claimed.id, "could not check the mass-block budget");
                                let _ = store.heartbeat_execution_worker(worker_id, "degraded", 0, Some(&error.to_string())).await;
                                Some(format!("could not check mass-block budget: {error}"))
                            }
                        };
                        let (success, result_summary, error_summary, receipt) =
                            if let Some(reason) = refusal {
                                tracing::warn!(execution_id = %claimed.id, action = %claimed.action_name, reason = %reason, "refusing dispatch");
                                (false, None, Some(reason), None)
                            } else {
                                dispatch(&claimed).await
                            };
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
                                    receipt_kind: "apply",
                                    target_fingerprint: Some(&receipt.target_fingerprint),
                                    target_json: claimed.target.clone(),
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

    #[test]
    fn the_mass_block_budget_only_applies_to_a_real_firewall_apply() {
        assert!(firewall_budget_applies("nftables.block_indicator", false));
        assert!(firewall_budget_applies("haproxy.block_indicator", false));
        assert!(
            !firewall_budget_applies("nftables.block_indicator", true),
            "a dry run has nothing to bound"
        );
        assert!(
            !firewall_budget_applies("docker.restart_container", false),
            "only nftables.*/haproxy.*-prefixed actions are bounded"
        );
        assert!(
            !firewall_budget_applies("tailscale.quarantine_device", false),
            "tailscale.* has no apply capability to bound in the first place"
        );
    }

    #[test]
    fn adapter_for_picks_the_right_adapter_for_both_action_names_and_bare_adapter_column_values() {
        assert!(adapter_for("nftables.block_indicator").is_some());
        assert!(adapter_for("haproxy.block_indicator").is_some());
        // The TTL sweep looks adapters up by the bare `adapter` column
        // value (no trailing dot), not an action name - must resolve the
        // same way.
        assert!(adapter_for("nftables").is_some());
        assert!(adapter_for("haproxy").is_some());
        assert!(adapter_for("tailscale.quarantine_device").is_none());
        assert!(adapter_for("docker.restart_container").is_none());
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

    #[tokio::test]
    async fn a_haproxy_action_dispatches_in_dry_run_and_is_routed_to_the_haproxy_adapter() {
        // Same shape as the nftables dry-run test above, proving
        // dispatch()'s adapter selection actually picks HaproxyAdapter for
        // an `haproxy.`-prefixed action name, not just NftablesAdapter for
        // everything - needs no real HAProxy Runtime API socket since
        // dry_run never touches it.
        std::env::remove_var("CLAWFORGE_EXECUTOR_DRY_RUN");
        let request = claimed(
            "haproxy.block_indicator",
            Some(serde_json::json!({
                "kind": "threat_intel_indicator",
                "cidr": "203.0.113.0/24",
                "source": "spamhaus_drop",
            })),
        );
        let (success, summary, error, receipt) = dispatch(&request).await;
        assert!(success, "dispatch failed: {error:?}");
        let summary = summary.unwrap();
        assert!(summary.contains("adapter=haproxy"));
        assert!(summary.contains("dry_run=true"));
        let receipt = receipt.expect("a successful firewall apply must produce a receipt");
        assert_eq!(receipt.adapter, "haproxy");
        assert!(receipt.is_dry_run);
    }

    #[tokio::test]
    async fn a_tailscale_action_keeps_the_generic_dry_run_fallback() {
        // tailscale.*-prefixed actions are deliberately NOT routed to
        // TailscaleAdapter - it has no apply capability to dispatch to at
        // all (see docs/firewall-agent.md), so dispatch() must treat it
        // exactly like any other non-firewall action.
        let request = claimed("tailscale.quarantine_device", None);
        let (success, summary, error, receipt) = dispatch(&request).await;
        assert!(success);
        assert_eq!(
            summary.as_deref(),
            Some("dry_run: no external operation executed")
        );
        assert!(error.is_none());
        assert!(receipt.is_none());
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
