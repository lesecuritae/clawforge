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
//! Any action whose name is not a recognized firewall action (`nftables.`/
//! `haproxy.`/`haproxy_ratelimit.`/`tailscale.` prefix, one specific
//! adapter each, or `firewall.`, every configured `FirewallAdapter`-based
//! adapter at once - see `dispatch_multi_adapter`) keeps the exact prior
//! behavior: claimed, marked `running`, then immediately completed with
//! `"dry_run: no external operation executed"` - this module changes
//! nothing about docker/github/proxmox actions. `tailscale.*` is
//! dispatched via its own path (`dispatch_tailscale`), not
//! `dispatch_multi_adapter`'s fan-out - `TailscaleAdapter` is not a
//! `FirewallAdapter` (a device ID is a different resource shape from an
//! IP/CIDR - see `TailscaleTarget`'s own doc comment in
//! `clawforge-firewall-agent`).

use clawforge_firewall_agent::{
    FirewallAction, FirewallAdapter, FirewallTarget, HaproxyAdapter, HaproxyRateLimitAdapter,
    NftablesAdapter, TailscaleAction, TailscaleAdapter, TailscaleTarget, VerificationResult,
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
/// A `firewall.*` action (as opposed to `nftables.*`/`haproxy.*`/
/// `haproxy_ratelimit.*`) fans out to every configured adapter - see
/// `dispatch_multi_adapter`'s own doc comment.
const FIREWALL_MULTI_ADAPTER_PREFIX: &str = "firewall.";
/// The one adapter a `firewall.*` action always includes, regardless of
/// `CLAWFORGE_FIREWALL_ADAPTERS` - the host-wide, per-source-IP block that
/// covers *every* service on the host, not just ones fronted by HAProxy.
/// This is what makes a `firewall.*` action's guarantee "any externally-
/// facing service, not just HAProxy" rather than depending on what an
/// operator happened to configure.
const MANDATORY_MULTI_ADAPTER: &str = "nftables";
const DEFAULT_FIREWALL_ADAPTERS: &str = "nftables";

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
/// adapter (or adapters) - `nftables.*`/`haproxy.*`/`haproxy_ratelimit.*`/
/// `tailscale.*` (one specific adapter each) or `firewall.*` (every
/// configured `FirewallAdapter`-based adapter at once - see
/// `dispatch_multi_adapter`; `tailscale.*` is never part of that fan-out,
/// since `TailscaleAdapter` is not a `FirewallAdapter`).
fn is_firewall_action(action_name: &str) -> bool {
    action_name.starts_with("nftables.")
        || action_name.starts_with("haproxy_ratelimit.")
        || action_name.starts_with("haproxy.")
        || action_name.starts_with(FIREWALL_MULTI_ADAPTER_PREFIX)
        || action_name.starts_with(TAILSCALE_ACTION_PREFIX)
}

/// Which adapters a `firewall.*` action fans out to -
/// `CLAWFORGE_FIREWALL_ADAPTERS` (comma-separated, e.g.
/// `"nftables,haproxy"`), defaulting to `nftables` alone so a host with
/// no HAProxy running is never required to configure anything for the
/// host-wide guarantee to work. `nftables` is always included even if an
/// operator's own list omits it - see `MANDATORY_MULTI_ADAPTER`'s own doc
/// comment for why that guarantee cannot be opted out of. An
/// unrecognized name is logged and dropped rather than failing the whole
/// list closed (unlike the never-block exclusion list): omitting one
/// *optional*, best-effort extra layer is not a self-lockout risk the way
/// a silently-dropped exclusion entry would be - `nftables` alone already
/// provides the core guarantee regardless.
fn configured_multi_adapters() -> Vec<String> {
    let raw = env::var("CLAWFORGE_FIREWALL_ADAPTERS")
        .unwrap_or_else(|_| DEFAULT_FIREWALL_ADAPTERS.to_string());
    let mut names: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .filter(|name| {
            let known = matches!(*name, "nftables" | "haproxy" | "haproxy_ratelimit");
            if !known {
                tracing::warn!(
                    adapter = %name,
                    "CLAWFORGE_FIREWALL_ADAPTERS names an unrecognized adapter - ignoring it"
                );
            }
            known
        })
        .map(str::to_string)
        .collect();
    if !names.iter().any(|name| name == MANDATORY_MULTI_ADAPTER) {
        names.insert(0, MANDATORY_MULTI_ADAPTER.to_string());
    }
    names.dedup();
    names
}

/// Picks the adapter an `nftables.`/`haproxy.`/`haproxy_ratelimit.`-prefixed
/// action name (or, for the TTL sweep, an `adapter` column value -
/// `"nftables"`/`"haproxy"`/`"haproxy_ratelimit"`, no trailing dot) routes
/// to. Shared by `dispatch()` and `sweep_expired_firewall_targets()` so
/// the two can never pick a different adapter for the same name.
/// `haproxy_ratelimit` is checked *before* the plain `haproxy` prefix -
/// `"haproxy_ratelimit..."` also starts with `"haproxy"`, so checking the
/// generic prefix first would silently route rate-limit actions to the
/// wrong (ACL) adapter.
fn adapter_for(name: &str) -> Option<Box<dyn FirewallAdapter>> {
    if name.starts_with("nftables") {
        Some(Box::new(NftablesAdapter::new()))
    } else if name.starts_with("haproxy_ratelimit") {
        Some(Box::new(HaproxyRateLimitAdapter::new()))
    } else if name.starts_with("haproxy") {
        Some(Box::new(HaproxyAdapter::new()))
    } else {
        None
    }
}

/// The mass-block budget: how many *real* (non-dry-run) firewall applies
/// (`nftables.*`/`haproxy.*`/`haproxy_ratelimit.*`/`firewall.*` - one
/// shared counter across every adapter, not one per adapter, and a
/// `firewall.*` fan-out's several receipts each count individually) this
/// database has recorded in the trailing rate window - a runaway policy
/// engine or a config mistake must not be able to block hundreds of
/// addresses in a burst. Dry runs and non-firewall actions are never
/// gated (`Ok(None)`) - there is nothing to bound. DB-backed via
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

/// Rolls back one target, dispatching to the right adapter shape for
/// `adapter_name` - `"tailscale"` has its own `target_json` contract
/// (`{"device_id":...}`, not `FirewallTarget`'s `{"kind":...}`) and its
/// own rollback method (not a `FirewallAdapter` implementation - see
/// `TailscaleAdapter`'s own doc comment), so it cannot go through
/// `adapter_for`/`FirewallTarget::try_from` the way the other three do.
/// `TailscaleAdapter::rollback` already treats "tag not present" as
/// idempotent success (not an error) specifically so a sweep calling this
/// can converge once a device has been manually reauth'd - see that
/// method's own doc comment.
///
/// Shared by both `sweep_expired_firewall_targets` (TTL-driven) and
/// `sweep_kill_switch_requests` (operator-triggered, on demand) - the two
/// only differ in *why* a target is being rolled back, never *how*, so
/// `context` (used purely for the adapter's own `reason` field, e.g. an
/// audit log line) is the only thing that varies between call sites.
async fn rollback_target(
    adapter_name: &str,
    target_json: &serde_json::Value,
    context: String,
) -> anyhow::Result<()> {
    if adapter_name == "tailscale" {
        let device_id = target_json
            .get("device_id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("tailscale target_json is missing device_id"))?;
        let action = TailscaleAction {
            target: TailscaleTarget {
                device_id: device_id.to_string(),
            },
            reason: context,
        };
        return TailscaleAdapter::new()
            .rollback(&action)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()));
    }
    let Some(adapter) = adapter_for(adapter_name) else {
        anyhow::bail!("unrecognized adapter {:?}", adapter_name);
    };
    let firewall_target = FirewallTarget::try_from(target_json)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let action = FirewallAction {
        target: firewall_target,
        ttl_seconds: DEFAULT_FIREWALL_ACTION_TTL_SECONDS,
        reason: context,
    };
    adapter
        .rollback(&action)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
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
        let context = format!("ttl expired auto-rollback (receipt {})", target.receipt_id);
        if let Err(error) = rollback_target(&target.adapter, &target.target_json, context).await {
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

/// Kill-switch: rolls back every target an operator has explicitly
/// requested an immediate rollback for, independent of its TTL - the
/// roadmap's "Kill-Switch pro Ziel" gate. `clawforge-api` only ever
/// records the *intent* (`create_firewall_kill_switch_request` - it is
/// never allowed to call a real adapter itself); this sweep, called once
/// per poll tick right alongside `sweep_expired_firewall_targets`, is
/// what actually performs it, using the exact same `rollback_target` path
/// the TTL sweep uses. A request is only marked processed once BOTH the
/// real rollback AND its receipt have been persisted - if either fails,
/// the request stays pending and is retried next tick, which is safe
/// because `rollback_target` is idempotent (see
/// `rolling_back_an_element_that_was_never_applied_fails_cleanly`/
/// `TailscaleAdapter::rollback`'s own "tag not present" case): retrying an
/// already-completed rollback just re-confirms nothing is left to undo.
async fn sweep_kill_switch_requests(store: &PostgresStore) {
    let pending = match store.pending_firewall_kill_switch_requests().await {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(%error, "could not check for pending kill-switch requests");
            return;
        }
    };
    for request in pending {
        let context = format!(
            "kill-switch request {} ({})",
            request.request_id,
            request.reason.as_deref().unwrap_or("no reason given")
        );
        if let Err(error) = rollback_target(&request.adapter, &request.target_json, context).await {
            tracing::warn!(
                %error, request_id = %request.request_id, adapter = %request.adapter,
                "kill-switch rollback failed - will retry next tick"
            );
            continue;
        }
        tracing::info!(
            request_id = %request.request_id, adapter = %request.adapter,
            target_fingerprint = %request.target_fingerprint,
            "kill-switch rolled back a target on demand"
        );
        if let Err(error) = store
            .record_firewall_action_receipt(FirewallActionReceiptInput {
                execution_id: None,
                adapter: &request.adapter,
                action_name: "kill-switch-rollback",
                preflight_state: serde_json::json!({}),
                rendered_commands: serde_json::json!([]),
                observed_state: None,
                verification_result: None,
                ttl_seconds: DEFAULT_FIREWALL_ACTION_TTL_SECONDS,
                rollback_plan: serde_json::json!({}),
                is_dry_run: false,
                receipt_kind: "rollback",
                target_fingerprint: Some(&request.target_fingerprint),
                target_json: None,
            })
            .await
        {
            tracing::warn!(%error, request_id = %request.request_id, "could not persist the kill-switch rollback receipt - this request stays pending and will be retried (and re-succeed harmlessly) next tick");
            continue;
        }
        if let Err(error) = store
            .mark_firewall_kill_switch_request_processed(request.request_id)
            .await
        {
            tracing::warn!(%error, request_id = %request.request_id, "could not mark the kill-switch request processed - it will be retried (and re-succeed harmlessly) next tick");
        }
    }
}

/// Runs preflight (best-effort) + apply + (if a real apply) verify against
/// one adapter, and builds the receipt for it - the single-adapter logic
/// shared by both `dispatch()`'s plain single-adapter path and
/// `dispatch_multi_adapter()`'s fan-out, so the two can never build a
/// receipt differently for the same adapter.
async fn apply_single_adapter(
    adapter: &dyn FirewallAdapter,
    action: &FirewallAction,
    dry_run: bool,
) -> Result<(String, FirewallDispatchReceipt), String> {
    // Best-effort: preflight is read-only enrichment for the receipt, not
    // a gate - a preflight failure (e.g. no NET_ADMIN/no HAProxy socket in
    // this environment) is recorded as-is and apply is still attempted,
    // since apply's own success/failure is what actually determines the
    // outcome here.
    let preflight_state = match adapter.preflight(&action.target).await {
        Ok(preflight) => adapter_state_json(&preflight.raw_set_json),
        Err(error) => serde_json::json!({"error": error.to_string()}),
    };
    let result = adapter
        .apply(action, dry_run)
        .await
        .map_err(|error| error.to_string())?;
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
    Ok((summary, receipt))
}

/// A `firewall.*` action fans out to *every* configured adapter instead of
/// one - see `configured_multi_adapters`'s own doc comment for which ones
/// and why `nftables` is always among them. Every adapter is attempted
/// regardless of another one's failure (defense in depth: a HAProxy-layer
/// block succeeding is still worth having even if the host-wide one
/// somehow failed, and vice versa) - overall `success` is `true` iff the
/// *mandatory* `nftables` adapter succeeded, since that is the "any
/// external service on this host" guarantee a `firewall.*` action exists
/// to make. A receipt is persisted for every adapter that succeeded,
/// regardless of overall success - a real state change happened and must
/// be tracked (audit, TTL) even if a sibling adapter failed.
async fn dispatch_multi_adapter(
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Vec<FirewallDispatchReceipt>,
) {
    let Some(target) = claimed.target.as_ref() else {
        return (
            false,
            None,
            Some(format!(
                "firewall action {:?} has no target",
                claimed.action_name
            )),
            Vec::new(),
        );
    };
    let action = match parse_firewall_action(claimed.id, target) {
        Ok(action) => action,
        Err(error) => return (false, None, Some(error.to_string()), Vec::new()),
    };
    let dry_run = dry_run_from_env();
    let mut receipts = Vec::new();
    let mut summaries = Vec::new();
    let mut mandatory_error = None;
    for name in configured_multi_adapters() {
        // configured_multi_adapters() only ever returns recognized names,
        // so this is always Some - the fallback keeps this loop body
        // total rather than relying on that invariant silently.
        let Some(adapter) = adapter_for(&name) else {
            continue;
        };
        match apply_single_adapter(adapter.as_ref(), &action, dry_run).await {
            Ok((summary, receipt)) => {
                summaries.push(summary);
                receipts.push(receipt);
            }
            Err(error) => {
                if name == MANDATORY_MULTI_ADAPTER {
                    mandatory_error = Some(error.clone());
                }
                summaries.push(format!("{name}: failed: {error}"));
            }
        }
    }
    let combined_summary = Some(summaries.join("; "));
    match mandatory_error {
        Some(error) => (
            false,
            combined_summary,
            Some(format!(
                "mandatory {MANDATORY_MULTI_ADAPTER} adapter failed: {error}"
            )),
            receipts,
        ),
        None => (true, combined_summary, None, receipts),
    }
}

const TAILSCALE_ACTION_PREFIX: &str = "tailscale.";
/// `TailscaleAction` carries no `ttl_seconds` of its own (unlike
/// `FirewallAction`) - used only for the receipt's own bookkeeping field,
/// not for any TTL-sweep auto-rollback (see `dispatch_tailscale`'s own
/// doc comment for why tailscale quarantines are deliberately excluded
/// from that).
const DEFAULT_TAILSCALE_ACTION_TTL_SECONDS: u32 = 3600;

/// Dispatches a `tailscale.*` action - `TailscaleAdapter` is not a
/// `FirewallAdapter` (a device ID is a different resource shape from an
/// IP/CIDR, see `TailscaleTarget`'s own doc comment), so this is its own
/// path rather than going through `apply_single_adapter`/`adapter_for`.
/// Target JSON contract: `{"device_id": "..."}`.
///
/// **Deliberately not part of the TTL sweep's auto-expiry the way
/// nftables/HAProxy targets are**: nothing prevents a tailscale receipt
/// from getting an `expires_at` (the storage layer doesn't distinguish),
/// but `rollback_target` handles it via `TailscaleAdapter::
/// rollback` the same as any other manual rollback - the real constraint
/// is that rollback for a previously-untagged device cannot complete via
/// the API at all (see `TailscaleAdapter::rollback`'s own doc comment),
/// so an unattended sweep retrying it forever produces the exact
/// documented "will fail until fixed by hand" behavior, not a hidden gap.
async fn dispatch_tailscale(
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Vec<FirewallDispatchReceipt>,
) {
    let Some(target) = claimed.target.as_ref() else {
        return (
            false,
            None,
            Some(format!(
                "firewall action {:?} has no target",
                claimed.action_name
            )),
            Vec::new(),
        );
    };
    let device_id = match target.get("device_id").and_then(|value| value.as_str()) {
        Some(device_id) if !device_id.trim().is_empty() => device_id.to_string(),
        _ => {
            return (
                false,
                None,
                Some("tailscale target is missing device_id".to_string()),
                Vec::new(),
            )
        }
    };
    let action = TailscaleAction {
        target: TailscaleTarget {
            device_id: device_id.clone(),
        },
        reason: format!("execution_request {}", claimed.id),
    };
    let adapter = TailscaleAdapter::new();
    let dry_run = dry_run_from_env();
    match adapter.apply(&action, dry_run).await {
        Ok(applied) => {
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
                "adapter=tailscale dry_run={} call={:?}",
                !applied.applied, applied.receipt.described_call
            );
            let receipt = FirewallDispatchReceipt {
                adapter: applied.receipt.adapter,
                preflight_state: serde_json::json!({}),
                rendered_commands: serde_json::json!([applied.receipt.described_call]),
                observed_state: None,
                verification_result,
                ttl_seconds: DEFAULT_TAILSCALE_ACTION_TTL_SECONDS,
                rollback_plan: serde_json::json!({
                    "note": "removes the quarantine tag - may require device-side reauth if \
                             it is the device's only tag, see TailscaleAdapter::rollback"
                }),
                is_dry_run: !applied.applied,
                target_fingerprint: device_id,
            };
            (true, Some(summary), None, vec![receipt])
        }
        Err(error) => (false, None, Some(error.to_string()), Vec::new()),
    }
}

/// Dispatches one claimed request. Returns `(success, result_summary,
/// error_summary, receipts)` for the caller to persist via
/// `complete_execution_dispatch` (always) and `record_firewall_action_receipt`
/// (once per entry in `receipts` - empty for anything that isn't a
/// firewall action, or that failed before any adapter applied) - never
/// panics, every adapter/parse error becomes a failed completion with a
/// clear `error_summary` instead.
async fn dispatch(
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Vec<FirewallDispatchReceipt>,
) {
    if claimed
        .action_name
        .starts_with(FIREWALL_MULTI_ADAPTER_PREFIX)
    {
        return dispatch_multi_adapter(claimed).await;
    }
    if claimed.action_name.starts_with(TAILSCALE_ACTION_PREFIX) {
        return dispatch_tailscale(claimed).await;
    }
    let Some(adapter) = adapter_for(&claimed.action_name) else {
        return (
            true,
            Some("dry_run: no external operation executed".to_string()),
            None,
            Vec::new(),
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
            Vec::new(),
        );
    };
    let action = match parse_firewall_action(claimed.id, target) {
        Ok(action) => action,
        Err(error) => return (false, None, Some(error.to_string()), Vec::new()),
    };
    let dry_run = dry_run_from_env();
    match apply_single_adapter(adapter.as_ref(), &action, dry_run).await {
        Ok((summary, receipt)) => (true, Some(summary), None, vec![receipt]),
        Err(error) => (false, None, Some(error), Vec::new()),
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
                sweep_kill_switch_requests(&store).await;
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
                        let (success, result_summary, error_summary, receipts) =
                            if let Some(reason) = refusal {
                                tracing::warn!(execution_id = %claimed.id, action = %claimed.action_name, reason = %reason, "refusing dispatch");
                                (false, None, Some(reason), Vec::new())
                            } else {
                                dispatch(&claimed).await
                            };
                        // One receipt row per adapter that actually applied -
                        // a firewall.* fan-out (dispatch_multi_adapter) can
                        // produce more than one; every other action produces
                        // at most one. Persisted regardless of overall
                        // `success` - a sibling adapter's real state change
                        // still needs tracking even if another one failed.
                        for receipt in receipts {
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
                                tracing::warn!(%error, execution_id = %claimed.id, adapter = receipt.adapter, "could not persist firewall action receipt");
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
        assert!(firewall_budget_applies(
            "haproxy_ratelimit.block_indicator",
            false
        ));
        assert!(firewall_budget_applies("firewall.block_indicator", false));
        assert!(firewall_budget_applies(
            "tailscale.quarantine_device",
            false
        ));
        assert!(
            !firewall_budget_applies("nftables.block_indicator", true),
            "a dry run has nothing to bound"
        );
        assert!(
            !firewall_budget_applies("docker.restart_container", false),
            "only recognized firewall-action prefixes are bounded"
        );
    }

    #[test]
    fn adapter_for_picks_the_right_adapter_for_both_action_names_and_bare_adapter_column_values() {
        assert_eq!(
            adapter_for("nftables.block_indicator").map(|a| a.name()),
            Some("nftables")
        );
        assert_eq!(
            adapter_for("haproxy.block_indicator").map(|a| a.name()),
            Some("haproxy")
        );
        // "haproxy_ratelimit..." also starts with "haproxy" - must not be
        // misrouted to the plain (ACL) HaproxyAdapter.
        assert_eq!(
            adapter_for("haproxy_ratelimit.block_indicator").map(|a| a.name()),
            Some("haproxy_ratelimit")
        );
        // The TTL sweep looks adapters up by the bare `adapter` column
        // value (no trailing dot), not an action name - must resolve the
        // same way.
        assert_eq!(adapter_for("nftables").map(|a| a.name()), Some("nftables"));
        assert_eq!(adapter_for("haproxy").map(|a| a.name()), Some("haproxy"));
        assert_eq!(
            adapter_for("haproxy_ratelimit").map(|a| a.name()),
            Some("haproxy_ratelimit")
        );
        assert!(adapter_for("tailscale.quarantine_device").is_none());
        assert!(adapter_for("docker.restart_container").is_none());
    }

    #[tokio::test]
    async fn non_firewall_actions_keep_the_original_dry_run_success_behavior() {
        let request = claimed("docker.restart_container", None);
        let (success, summary, error, receipts) = dispatch(&request).await;
        assert!(success);
        assert_eq!(
            summary.as_deref(),
            Some("dry_run: no external operation executed")
        );
        assert!(error.is_none());
        assert!(
            receipts.is_empty(),
            "a non-firewall action must never produce a receipt to persist"
        );
    }

    #[tokio::test]
    async fn a_firewall_action_without_a_target_fails_with_a_clear_error() {
        let request = claimed("nftables.block_indicator", None);
        let (success, _summary, error, receipts) = dispatch(&request).await;
        assert!(!success);
        assert!(error.unwrap().contains("no target"));
        assert!(receipts.is_empty());
    }

    #[tokio::test]
    async fn a_firewall_action_with_a_malformed_target_fails_with_a_clear_error() {
        let request = claimed(
            "nftables.block_indicator",
            Some(serde_json::json!({"kind": "not-a-real-kind"})),
        );
        let (success, _summary, error, receipts) = dispatch(&request).await;
        assert!(!success);
        assert!(error.is_some());
        assert!(receipts.is_empty());
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
        let (success, summary, error, receipts) = dispatch(&request).await;
        assert!(success, "dispatch failed: {error:?}");
        let summary = summary.unwrap();
        assert!(summary.contains("dry_run=true"));
        assert!(summary.contains("203.0.113.0/24"));
        assert_eq!(
            receipts.len(),
            1,
            "a single-adapter action produces exactly one receipt"
        );
        let receipt = &receipts[0];
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
        let (success, summary, error, receipts) = dispatch(&request).await;
        assert!(success, "dispatch failed: {error:?}");
        let summary = summary.unwrap();
        assert!(summary.contains("adapter=haproxy"));
        assert!(summary.contains("dry_run=true"));
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].adapter, "haproxy");
        assert!(receipts[0].is_dry_run);
    }

    #[tokio::test]
    async fn a_haproxy_ratelimit_action_dispatches_in_dry_run_and_is_routed_to_the_ratelimit_adapter(
    ) {
        // "haproxy_ratelimit..." also starts with "haproxy" - proves
        // dispatch() does not misroute it to the plain ACL HaproxyAdapter.
        std::env::remove_var("CLAWFORGE_EXECUTOR_DRY_RUN");
        let request = claimed(
            "haproxy_ratelimit.block_indicator",
            Some(serde_json::json!({
                "kind": "threat_intel_indicator",
                "cidr": "203.0.113.0/24",
                "source": "spamhaus_drop",
            })),
        );
        let (success, summary, error, receipts) = dispatch(&request).await;
        assert!(success, "dispatch failed: {error:?}");
        let summary = summary.unwrap();
        assert!(summary.contains("adapter=haproxy_ratelimit"));
        assert!(summary.contains("dry_run=true"));
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].adapter, "haproxy_ratelimit");
        assert!(receipts[0].is_dry_run);
    }

    #[tokio::test]
    async fn a_tailscale_action_without_a_target_fails_with_a_clear_error() {
        let request = claimed("tailscale.quarantine_device", None);
        let (success, _summary, error, receipts) = dispatch(&request).await;
        assert!(!success);
        assert!(error.unwrap().contains("no target"));
        assert!(receipts.is_empty());
    }

    #[tokio::test]
    async fn a_tailscale_action_with_a_malformed_target_fails_with_a_clear_error() {
        let request = claimed(
            "tailscale.quarantine_device",
            Some(serde_json::json!({"not_device_id": "whatever"})),
        );
        let (success, _summary, error, receipts) = dispatch(&request).await;
        assert!(!success);
        assert!(error.unwrap().contains("device_id"));
        assert!(receipts.is_empty());
    }

    #[tokio::test]
    async fn a_tailscale_action_dispatches_in_dry_run_and_is_routed_to_the_tailscale_adapter() {
        // dry_run never touches the real Tailscale API - needs no
        // credentials configured, mirroring the other adapters' own
        // dry-run tests.
        std::env::remove_var("CLAWFORGE_EXECUTOR_DRY_RUN");
        let request = claimed(
            "tailscale.quarantine_device",
            Some(serde_json::json!({"device_id": "n123456CNTRL"})),
        );
        let (success, summary, error, receipts) = dispatch(&request).await;
        assert!(success, "dispatch failed: {error:?}");
        let summary = summary.unwrap();
        assert!(summary.contains("adapter=tailscale"));
        assert!(summary.contains("dry_run=true"));
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].adapter, "tailscale");
        assert!(receipts[0].is_dry_run);
        assert!(receipts[0].verification_result.is_none());
    }

    /// All three `CLAWFORGE_FIREWALL_ADAPTERS` scenarios in one test,
    /// sequentially - not three separate `#[tokio::test]` functions,
    /// because they need three different values of the *same* env var and
    /// cargo test's default parallel execution would otherwise race them
    /// against each other (unlike a plain set/unset check, three specific
    /// values genuinely need to not interleave).
    #[tokio::test]
    async fn firewall_action_fan_out_honors_configured_multi_adapters() {
        std::env::remove_var("CLAWFORGE_EXECUTOR_DRY_RUN");
        let request = || {
            claimed(
                "firewall.block_indicator",
                Some(serde_json::json!({
                    "kind": "threat_intel_indicator",
                    "cidr": "203.0.113.0/24",
                    "source": "spamhaus_drop",
                })),
            )
        };

        // No CLAWFORGE_FIREWALL_ADAPTERS set - defaults to nftables alone.
        std::env::remove_var("CLAWFORGE_FIREWALL_ADAPTERS");
        let (success, summary, error, receipts) = dispatch(&request()).await;
        assert!(success, "dispatch failed: {error:?}");
        assert_eq!(
            receipts.len(),
            1,
            "with no CLAWFORGE_FIREWALL_ADAPTERS set, only the mandatory nftables adapter runs"
        );
        assert_eq!(receipts[0].adapter, "nftables");
        assert!(summary.unwrap().contains("adapter=nftables"));

        // All three configured explicitly.
        std::env::set_var(
            "CLAWFORGE_FIREWALL_ADAPTERS",
            "nftables,haproxy,haproxy_ratelimit",
        );
        let (success, _summary, error, receipts) = dispatch(&request()).await;
        assert!(success, "dispatch failed: {error:?}");
        let mut adapters: Vec<&str> = receipts.iter().map(|r| r.adapter).collect();
        adapters.sort_unstable();
        assert_eq!(adapters, ["haproxy", "haproxy_ratelimit", "nftables"]);

        // nftables must always run even when an operator's own list omits
        // it - the host-wide "any external service" guarantee cannot be
        // configured away.
        std::env::set_var("CLAWFORGE_FIREWALL_ADAPTERS", "haproxy");
        let (success, _summary, error, receipts) = dispatch(&request()).await;
        assert!(success, "dispatch failed: {error:?}");
        assert!(
            receipts.iter().any(|r| r.adapter == "nftables"),
            "nftables must always run, even when an operator's own list omits it: {:?}",
            receipts.iter().map(|r| r.adapter).collect::<Vec<_>>()
        );

        // An unrecognized name is dropped, not fatal - nftables (the core
        // guarantee) still runs regardless.
        std::env::set_var("CLAWFORGE_FIREWALL_ADAPTERS", "not-a-real-adapter");
        let (success, _summary, error, receipts) = dispatch(&request()).await;
        assert!(success, "dispatch failed: {error:?}");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].adapter, "nftables");

        std::env::remove_var("CLAWFORGE_FIREWALL_ADAPTERS");
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
