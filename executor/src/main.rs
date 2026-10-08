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
//! adapter at once - see `dispatch_multi_with_adapters`) keeps the exact prior
//! behavior: claimed, marked `running`, then immediately completed with
//! `"dry_run: no external operation executed"` - this module changes
//! nothing about docker/github/proxmox actions. `tailscale.*` is
//! dispatched via its own path (`dispatch_tailscale`), not
//! `dispatch_multi_with_adapters`'s fan-out - `TailscaleAdapter` is not a
//! `FirewallAdapter` (a device ID is a different resource shape from an
//! IP/CIDR - see `TailscaleTarget`'s own doc comment in
//! `clawforge-firewall-agent`).

mod live_authorization;
mod quarantine_gate;
mod quarantine_runtime;

use clawforge_firewall_agent::docker::{DockerAdapter, NetworkAttachment};
use clawforge_firewall_agent::proxmox::ProxmoxAdapter;
use clawforge_firewall_agent::quarantine::QuarantineTarget;
use clawforge_firewall_agent::{
    FirewallAction, FirewallAdapter, FirewallTarget, RecoveryTarget, TailscaleAction,
    TailscaleAdapter, TailscaleTarget, VerificationResult,
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
/// The concurrency budget: at most this many real apply/rollback calls
/// may be simultaneously "in flight" (reserved, not yet released) against
/// one adapter at once, across every executor replica sharing this
/// database - see `try_begin_inflight`'s own doc comment.
const DEFAULT_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER: i64 = 5;
/// How long a reservation keeps counting toward the concurrency budget
/// before it is treated as stale (and therefore ignored) - long enough to
/// cover any real apply/rollback call this codebase makes (all of them
/// are single local syscalls or a handful of HTTP/socket round trips, not
/// long-running operations), short enough that a crashed replica's leaked
/// reservation self-heals reasonably quickly rather than needing a
/// separate cleanup job.
const DEFAULT_FIREWALL_INFLIGHT_STALE_SECONDS: i64 = 120;
/// A `firewall.*` action (as opposed to `nftables.*`/`haproxy.*`/
/// `haproxy_ratelimit.*`) fans out to every configured adapter - see
/// `dispatch_multi_with_adapters`'s own doc comment.
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

fn firewall_max_concurrent_applies_per_adapter() -> i64 {
    env::var("CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER)
}

fn firewall_inflight_stale_seconds() -> i64 {
    env::var("CLAWFORGE_FIREWALL_INFLIGHT_STALE_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_FIREWALL_INFLIGHT_STALE_SECONDS)
}

/// P7-2: the hard ceiling on a *real* firewall apply's TTL. A block that
/// cannot self-expire within a bounded window is the core self-lockout risk,
/// so this is a pre-apply gate, not advice. Defaults to the default action TTL
/// (a conservative draft value, not an operator approval - the reviewed pilot
/// ceiling is set via the env var below once P7-5's limits are signed off).
const DEFAULT_FIREWALL_MAX_TTL_SECONDS: u32 = DEFAULT_FIREWALL_ACTION_TTL_SECONDS;

fn firewall_max_ttl_seconds() -> u32 {
    env::var("CLAWFORGE_FIREWALL_MAX_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_FIREWALL_MAX_TTL_SECONDS)
}

/// Pure core of the TTL-ceiling gate (no env), split out so it is testable
/// without mutating process env. A dry-run is never gated (nothing persists or
/// mutates); a real apply whose TTL exceeds `max_ttl_seconds` yields a refusal
/// reason so a block always self-expires within a bounded window.
fn ttl_over_live_ceiling(ttl_seconds: u32, max_ttl_seconds: u32, dry_run: bool) -> Option<String> {
    if dry_run || ttl_seconds <= max_ttl_seconds {
        return None;
    }
    Some(format!(
        "firewall action TTL {ttl_seconds}s exceeds the live ceiling {max_ttl_seconds}s \
         (CLAWFORGE_FIREWALL_MAX_TTL_SECONDS); refused so a real block always self-expires \
         within a bounded window"
    ))
}

fn firewall_ttl_over_live_ceiling(ttl_seconds: u32, dry_run: bool) -> Option<String> {
    ttl_over_live_ceiling(ttl_seconds, firewall_max_ttl_seconds(), dry_run)
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
/// `goaway.*`/`tailscale.*` (one specific adapter each) or `firewall.*` (every
/// configured `FirewallAdapter`-based adapter at once - see
/// `dispatch_multi_with_adapters`; `tailscale.*` is never part of that fan-out,
/// since `TailscaleAdapter` is not a `FirewallAdapter`).
fn is_firewall_action(action_name: &str) -> bool {
    action_name.starts_with("nftables.")
        || action_name.starts_with("haproxy_ratelimit.")
        || action_name.starts_with("haproxy.")
        || action_name.starts_with("goaway.")
        || action_name.starts_with(FIREWALL_MULTI_ADAPTER_PREFIX)
        || action_name == TAILSCALE_ACTION_PREFIX
        || action_name == PROXMOX_QUARANTINE_ACTION
        || action_name == DOCKER_QUARANTINE_ACTION
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

/// Which adapter(s) `action_name` will actually touch if dispatched for
/// real - the concurrency budget's own "which counter(s) does this
/// reserve a slot in" key(s). Mirrors `dispatch()`'s own routing (a
/// single-adapter prefix routes to one adapter; `firewall.*` fans out to
/// every `configured_multi_adapters()` adapter) as a separate, pure,
/// DB-free function rather than threading a `store` into `dispatch()`/
/// `apply_single_adapter` themselves (which stay DB-free on purpose, see
/// `dispatch()`'s own doc comment) - `main()`'s loop calls this *before*
/// calling `dispatch()`, reserves a slot in each returned adapter's
/// counter, calls `dispatch()`, then releases them, wrapping the call
/// from outside instead of threading concurrency-tracking through it.
fn adapters_touched_by(action_name: &str) -> Vec<String> {
    if action_name.starts_with(FIREWALL_MULTI_ADAPTER_PREFIX) {
        return configured_multi_adapters();
    }
    if action_name == TAILSCALE_ACTION_PREFIX {
        return vec!["tailscale".to_string()];
    }
    if action_name == PROXMOX_QUARANTINE_ACTION {
        return vec!["proxmox".to_string()];
    }
    if action_name == DOCKER_QUARANTINE_ACTION {
        return vec!["docker".to_string()];
    }
    if action_name.starts_with("haproxy_ratelimit.") {
        return vec!["haproxy_ratelimit".to_string()];
    }
    if action_name.starts_with("haproxy.") {
        return vec!["haproxy".to_string()];
    }
    if action_name.starts_with("goaway.") {
        return vec!["goaway".to_string()];
    }
    if action_name.starts_with("nftables.") {
        return vec!["nftables".to_string()];
    }
    Vec::new()
}

/// Picks the adapter an `nftables.`/`haproxy.`/`haproxy_ratelimit.`-prefixed
/// action name (or, for the TTL sweep, an `adapter` column value -
/// `"nftables"`/`"haproxy"`/`"haproxy_ratelimit"`, no trailing dot) routes
/// to. A thin alias for `clawforge_firewall_agent::adapter_for_action` -
/// moved there (from what used to be this function's own body) so
/// `clawforge-api`'s pre-approval action preview can share the exact same
/// routing table rather than risk a second copy drifting from it; kept as
/// a local `adapter_for` alias so every existing call site here (and its
/// own unit tests) needs no changes.
fn adapter_for(name: &str) -> Option<Box<dyn FirewallAdapter>> {
    clawforge_firewall_agent::adapter_for_action(name)
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
/// Bounds *how often* real applies happen over time; `try_begin_inflight`
/// (below) is the separate, per-adapter budget for how many may be
/// *simultaneously* in flight - the two are independent and both apply.
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

/// The concurrency budget: reserves one "in flight" slot for a real
/// apply/rollback against `adapter`, refusing (and immediately releasing
/// its own reservation again) if that would push the count over
/// `CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER` - bounding how
/// many real operations may run *simultaneously* against the same
/// adapter's shared resource (the HAProxy Runtime API socket, the local
/// nftables/netlink interface, the Tailscale Admin API) across every
/// executor replica sharing this database, distinct from the mass-block
/// budget's *rate-over-time* bound above. Returns the reservation id to
/// release via `store.end_firewall_inflight_operation` once the real work
/// is done - `Ok(None)` means "refused, nothing to release".
///
/// F3: a HARD concurrency bound. Delegates to the storage-side atomic
/// reservation (`try_reserve_firewall_inflight`), which serializes the
/// count-and-insert per adapter with a transaction-scoped advisory lock, so the
/// configured limit can never be exceeded even when several executor replicas
/// reserve at the same instant - closing the previously-accepted insert-then-
/// check race (two replicas both passing the check and briefly pushing the live
/// count one over the limit). `Ok(None)` means "refused, nothing to release".
async fn try_begin_inflight(store: &PostgresStore, adapter: &str) -> Result<Option<Uuid>, String> {
    let max = firewall_max_concurrent_applies_per_adapter();
    let stale = firewall_inflight_stale_seconds();
    store
        .try_reserve_firewall_inflight(adapter, max, stale, None)
        .await
        .map_err(|error| error.to_string())
}

/// Everything `dispatch()` gathers for a known firewall apply, for
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

/// Shadow requests carry an immutable marker inside approval_context.target.
/// Even if a future release opens the global live gate, a queued shadow
/// request can never turn into a real action after a restart or long lease.
fn request_requires_dry_run(target: Option<&serde_json::Value>) -> bool {
    target
        .and_then(|value| value.get("simulation_only"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn dispatch_dry_run(claimed: &ClaimedExecutionRequest) -> bool {
    // Read the authorization from env at the decision point, mirroring
    // `dry_run_from_env`, so this is the independent second check the module
    // doc describes. A present-but-invalid authorization (`Err`) is discarded
    // to `None` here and so forces dry-run (fail-closed); `main`'s startup gate
    // separately refuses to launch at all on that same `Err`.
    let auth = live_authorization::LiveAuthorization::from_env()
        .ok()
        .flatten();
    resolve_dry_run(
        dry_run_from_env(),
        request_requires_dry_run(claimed.target.as_ref()),
        auth.as_ref(),
        &claimed.action_name,
    )
}

/// Pure core of the live dry-run decision (no env, no I/O), separated so the
/// gate is unit-testable without mutating process-wide env vars. Forces
/// dry-run unless live mode is on, the request is not `simulation_only`, and an
/// authorization explicitly allows this action's class. `auth == None` covers
/// both "no authorization" and "invalid authorization" - both fail closed.
fn resolve_dry_run(
    env_dry_run: bool,
    simulation_only: bool,
    auth: Option<&live_authorization::LiveAuthorization>,
    action_name: &str,
) -> bool {
    if env_dry_run || simulation_only {
        return true;
    }
    // Live mode: dry-run unless an authorization explicitly allows this class.
    !matches!(auth, Some(auth) if auth.allows_action(action_name))
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
    if adapter_name == "proxmox" {
        let node = target_json
            .get("node")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("proxmox target_json is missing node"))?;
        let vmid = target_json
            .get("vmid")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("proxmox target_json is missing vmid"))?;
        let vmid = u32::try_from(vmid).map_err(|_| anyhow::anyhow!("proxmox vmid out of range"))?;
        let target = QuarantineTarget::Proxmox {
            node: node.to_string(),
            vmid,
        };
        return ProxmoxAdapter::new()
            .rollback(
                &target,
                target_json
                    .get("original_net0")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("original Proxmox NIC snapshot missing"))?,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()));
    }
    if adapter_name == "docker" {
        let container_id = target_json
            .get("container_id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("docker target_json is missing container_id"))?;
        let networks: Vec<NetworkAttachment> = serde_json::from_value(target_json.get("networks").cloned().ok_or_else(|| anyhow::anyhow!("Docker rollback snapshot is missing"))?)
            .map_err(|_| anyhow::anyhow!("Docker rollback snapshot is invalid or legacy names-only; operator recovery required"))?;
        let target = QuarantineTarget::Docker {
            container_id: container_id.to_string(),
        };
        return DockerAdapter::new()
            .rollback(&target, &networks)
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
        // Older receipts have no immutable generation ownership. Reconnecting by
        // target alone could undo a later operation; require operator review.
        if matches!(target.adapter.as_str(), "docker" | "proxmox" | "tailscale") {
            tracing::warn!(receipt_id=%target.receipt_id, "legacy quarantine expiry lacks generation ownership; manual reconciliation required");
            continue;
        }
        let inflight_id = match try_begin_inflight(store, &target.adapter).await {
            Ok(Some(id)) => id,
            Ok(None) => {
                tracing::warn!(
                    receipt_id = %target.receipt_id, adapter = %target.adapter,
                    "concurrency budget exceeded - will retry this expired target next tick"
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, receipt_id = %target.receipt_id, adapter = %target.adapter, "could not check the concurrency budget - will retry next tick");
                continue;
            }
        };
        let context = format!("ttl expired auto-rollback (receipt {})", target.receipt_id);
        let result = rollback_target(&target.adapter, &target.target_json, context).await;
        let _ = store.end_firewall_inflight_operation(inflight_id).await;
        if let Err(error) = result {
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

/// Reconcile a single durable firewall *rule* generation (F2, migration 0055).
/// Mirrors `quarantine_runtime::recover` for ordinary rules: a `prepared`
/// generation may have crashed after a real adapter mutation, so it is never
/// blindly replayed - ownership is retained as `recovery_required`. A
/// `completed` generation past its TTL is rolled back through the adapter and
/// resolved only on verified adapter success; any failure keeps exclusive
/// ownership for manual reconciliation. The row lock is held across the remote
/// rollback, so a competing sweep skips a busy generation.
async fn recover_firewall_rule_generation(
    store: &PostgresStore,
    intent_id: Uuid,
) -> quarantine_runtime::RecoveryOutcome {
    use quarantine_runtime::RecoveryOutcome;
    let guard = match store.acquire_firewall_rule_guard(intent_id).await {
        Ok(Some(guard)) => guard,
        // The row is either terminal (resolved) or locked by a competing worker.
        // Distinguish them: a terminal generation is Resolved, so an operator
        // kill-switch for an already-rolled-back target completes instead of
        // retrying forever; a locked one is Busy and retried next tick.
        Ok(None) => {
            return match store.firewall_rule_intent(intent_id).await {
                Ok(Some(intent))
                    if matches!(intent.status.as_str(), "rolled_back" | "not_applied") =>
                {
                    RecoveryOutcome::Resolved
                }
                _ => RecoveryOutcome::Busy,
            };
        }
        Err(error) => {
            tracing::warn!(%error, intent_id=%intent_id, "could not acquire firewall rule generation guard");
            return RecoveryOutcome::Busy;
        }
    };
    if guard.intent().status == "prepared" {
        // R3: a prepared generation whose owning execution still holds a live
        // worker lease is an IN-FLIGHT apply (the apply worker does not hold the
        // generation row lock across its external IO), not a crash - never steal
        // it; let the owner finish. Only a generation whose owner's lease is gone
        // or expired is genuinely orphaned and retained for recovery.
        match store
            .execution_has_active_lease(guard.intent().execution_id)
            .await
        {
            Ok(true) => return RecoveryOutcome::Busy,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, intent_id=%intent_id, "could not check owner lease; leaving the generation untouched this tick");
                return RecoveryOutcome::Busy;
            }
        }
        if let Err(error) = guard.recovery_required().await {
            tracing::warn!(%error, intent_id=%intent_id, "could not retain prepared firewall rule generation for recovery");
        }
        return RecoveryOutcome::ManualReview;
    }
    // Only completed-and-expired generations reach here (the sweep query excludes
    // the rest). Roll the concrete rule back and resolve only on real success.
    let adapter = guard.intent().adapter.clone();
    let target_json = guard.intent().target_json.clone();
    let inflight_id = match try_begin_inflight(store, &adapter).await {
        Ok(Some(inflight)) => inflight,
        // Concurrency budget full: leave the generation owned, retry next tick.
        Ok(None) => return RecoveryOutcome::Busy,
        Err(error) => {
            tracing::warn!(%error, intent_id=%intent_id, adapter=%adapter, "could not check concurrency budget for rule rollback");
            return RecoveryOutcome::Busy;
        }
    };
    let result = rollback_target(
        &adapter,
        &target_json,
        format!("firewall rule generation {intent_id} ttl rollback"),
    )
    .await;
    let _ = store.end_firewall_inflight_operation(inflight_id).await;
    if let Err(error) = result {
        tracing::warn!(%error, intent_id=%intent_id, adapter=%adapter, "firewall rule generation rollback failed; ownership retained");
        if let Err(error) = guard.recovery_required().await {
            tracing::warn!(%error, intent_id=%intent_id, "could not retain firewall rule generation for recovery");
        }
        return RecoveryOutcome::ManualReview;
    }
    if let Err(error) = guard.resolve_rollback().await {
        tracing::warn!(%error, intent_id=%intent_id, "rule rollback succeeded but resolution could not be recorded; retained for next tick");
        return RecoveryOutcome::ManualReview;
    }
    RecoveryOutcome::Restored
}

/// TTL/recovery sweep for durable firewall rule generations, run once per poll
/// tick alongside `quarantine_runtime::sweep` and `sweep_expired_firewall_targets`.
/// Consumes `recoverable_firewall_rule_intents` (prepared + completed-and-expired);
/// a durable `recovery_required` is deliberately not retried every tick.
async fn sweep_firewall_rule_generations(store: &PostgresStore) {
    let intents = match store.recoverable_firewall_rule_intents().await {
        Ok(intents) => intents,
        Err(error) => {
            tracing::warn!(%error, "firewall rule generation recovery lookup failed");
            return;
        }
    };
    for intent in intents {
        if intent.status == "recovery_required" {
            continue;
        }
        match recover_firewall_rule_generation(store, intent.id).await {
            quarantine_runtime::RecoveryOutcome::Restored => {
                tracing::info!(intent_id=%intent.id, adapter=%intent.adapter, "expired firewall rule generation rolled back and resolved")
            }
            quarantine_runtime::RecoveryOutcome::ManualReview => {
                tracing::warn!(intent_id=%intent.id, "firewall rule generation completion unknown; ownership retained for manual reconciliation")
            }
            _ => {}
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
        if let Some(intent_id) = request.quarantine_intent_id {
            match quarantine_runtime::recover(store, intent_id).await {
                Ok(
                    quarantine_runtime::RecoveryOutcome::Restored
                    | quarantine_runtime::RecoveryOutcome::Resolved,
                ) => {
                    if store
                        .mark_firewall_kill_switch_request_processed(request.request_id)
                        .await
                        .is_err()
                    {
                        tracing::warn!(request_id=%request.request_id, "generation kill-switch result could not be persisted; safe retry pending");
                    }
                }
                Ok(_) => {}
                Err(_) => {
                    tracing::warn!(request_id=%request.request_id, "generation kill-switch recovery failed; request remains pending")
                }
            }
            continue;
        }
        // Never use target-only legacy rollback for an unbound quarantine request.
        // A delayed legacy request could otherwise undo a newer generation.
        if matches!(request.adapter.as_str(), "docker" | "proxmox" | "tailscale") {
            tracing::warn!(request_id=%request.request_id, "unbound quarantine kill-switch requires operator reconciliation");
            continue;
        }
        // R4: if a journaled rule generation currently owns this target, route
        // the kill-switch through that generation - its own rollback plan and
        // atomic resolution - rather than a silent target-only rollback that
        // would bypass ownership (and could otherwise undo a newer generation).
        // Only a target with no active generation falls through to the legacy
        // target-only path below.
        match store
            .active_firewall_rule_generation_for(&request.adapter, &request.target_fingerprint)
            .await
        {
            Ok(Some(intent_id)) => {
                match recover_firewall_rule_generation(store, intent_id).await {
                    quarantine_runtime::RecoveryOutcome::Restored
                    | quarantine_runtime::RecoveryOutcome::Resolved => {
                        if store
                            .mark_firewall_kill_switch_request_processed(request.request_id)
                            .await
                            .is_err()
                        {
                            tracing::warn!(request_id=%request.request_id, "rule-generation kill-switch result could not be persisted; safe retry pending");
                        }
                    }
                    _ => {
                        tracing::warn!(request_id=%request.request_id, intent_id=%intent_id, "rule-generation kill-switch could not complete; request remains pending")
                    }
                }
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, request_id=%request.request_id, "could not check for an owning rule generation; will retry next tick");
                continue;
            }
        }
        let inflight_id = match try_begin_inflight(store, &request.adapter).await {
            Ok(Some(id)) => id,
            Ok(None) => {
                tracing::warn!(
                    request_id = %request.request_id, adapter = %request.adapter,
                    "concurrency budget exceeded - will retry this kill-switch request next tick"
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, request_id = %request.request_id, adapter = %request.adapter, "could not check the concurrency budget - will retry next tick");
                continue;
            }
        };
        let context = format!(
            "kill-switch request {} ({})",
            request.request_id,
            request.reason.as_deref().unwrap_or("no reason given")
        );
        let result = rollback_target(&request.adapter, &request.target_json, context).await;
        let _ = store.end_firewall_inflight_operation(inflight_id).await;
        if let Err(error) = result {
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
/// `dispatch_multi_with_adapters()`'s fan-out, so the two can never build a
/// receipt differently for the same adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispatchCompletion {
    Success,
    Failed,
    RecoveryRequired,
}

/// The actual durable effect of a dispatch, distinct from `receipts`: a journaled
/// apply persists its receipt inside `finish`, so a verified-and-owned outcome
/// returns an *empty* receipt vector - which must never be read as "no mutation
/// happened". R5: carry the effect (and the owning generation) explicitly so the
/// multi-adapter fan-out and the caller can tell an owned generation apart from a
/// genuine no-op, and never retry an owned-but-uncertain apply as a plain failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirewallEffect {
    /// Nothing was applied: a refusal, a preflight failure, or a dry-run plan.
    NoMutation,
    /// A real journaled apply was verified and is owned by this generation.
    VerifiedOwned(Uuid),
    /// A real journaled apply whose effect is uncertain; the generation retains
    /// ownership for recovery and must not be retried as a plain failure.
    UncertainOwned(Uuid),
    /// A store-free / non-journaled dispatch (dry-run or unit test): any effect
    /// is reflected by `receipts`, not by a durable generation.
    NonJournaled,
}

impl FirewallEffect {
    /// A durable generation is owned (verified or uncertain), so the request
    /// must not be re-dispatched even if no in-memory receipt was returned.
    fn is_owned(self) -> bool {
        matches!(self, Self::VerifiedOwned(_) | Self::UncertainOwned(_))
    }
}

struct GenericDispatchOutcome {
    completion: DispatchCompletion,
    effect: FirewallEffect,
    result_summary: Option<String>,
    error_summary: Option<String>,
    receipts: Vec<FirewallDispatchReceipt>,
}

impl GenericDispatchOutcome {
    fn failed(reason: &str) -> Self {
        Self {
            completion: DispatchCompletion::Failed,
            effect: FirewallEffect::NoMutation,
            result_summary: None,
            error_summary: Some(reason.into()),
            receipts: Vec::new(),
        }
    }

    fn receipt_persistence_failed(&mut self, dry_run: bool) {
        self.completion = if dry_run {
            DispatchCompletion::Failed
        } else {
            DispatchCompletion::RecoveryRequired
        };
        self.error_summary =
            Some("firewall receipt persistence failed; reconciliation required".into());
    }

    fn into_legacy(
        self,
    ) -> (
        bool,
        Option<String>,
        Option<String>,
        Vec<FirewallDispatchReceipt>,
    ) {
        (
            self.completion == DispatchCompletion::Success,
            self.result_summary,
            self.error_summary,
            self.receipts,
        )
    }

    fn from_legacy(
        value: (
            bool,
            Option<String>,
            Option<String>,
            Vec<FirewallDispatchReceipt>,
        ),
    ) -> Self {
        Self {
            completion: if value.0 {
                DispatchCompletion::Success
            } else {
                DispatchCompletion::Failed
            },
            effect: FirewallEffect::NonJournaled,
            result_summary: value.1,
            error_summary: value.2,
            receipts: value.3,
        }
    }
}

/// Durable write-ahead journal for a real generic firewall rule apply (F2).
/// Binds one generation to `(adapter, scope, rule_fingerprint)` in
/// `firewall_action_intents` before the mutation and resolves it after, so a
/// crash between a real `apply()` and its receipt leaves a durably owned,
/// visible generation that is reconciled, never blindly replayed. The scope is
/// the adapter name today (one ruleset per adapter); a per-set scope is a later
/// refinement. Only used for a real (non-dry-run) apply; dry-run never journals.
struct RuleJournal<'a> {
    store: &'a PostgresStore,
    execution_id: Uuid,
    action_name: &'a str,
}

/// A failed real apply may have mutated remote state. It must never be
/// converted into a retryable failure or a fabricated successful receipt.
/// With a `journal` (a real apply), ownership is committed before the mutation
/// and resolved atomically after; the receipt is then persisted by `finish`, so
/// the returned `receipts` is empty. Without one (dry-run, or store-free unit
/// tests), the F1 behavior is unchanged and the in-memory receipt is returned.
async fn apply_single_adapter(
    adapter: &dyn FirewallAdapter,
    action: &FirewallAction,
    dry_run: bool,
    journal: Option<&RuleJournal<'_>>,
) -> GenericDispatchOutcome {
    let (preflight_state, already_blocked) = match adapter.preflight(&action.target).await {
        Ok(preflight) => (
            adapter_state_json(&preflight.raw_set_json),
            preflight.already_blocked,
        ),
        Err(_) if !dry_run => {
            return GenericDispatchOutcome::failed("adapter preflight failed; apply refused")
        }
        Err(_) => (
            serde_json::json!({"status": "preflight_unavailable", "mode": "dry_run"}),
            false,
        ),
    };
    // Write-ahead: commit the immutable rule snapshot BEFORE the real apply.
    let prepared = match (dry_run, journal) {
        (false, Some(journal)) => {
            // R4: the rule is already present at preflight. We do not own it via
            // an active generation (otherwise `prepare_firewall_rule_intent`
            // below would refuse), so it is pre-existing - typically an
            // operator-owned rule. Never adopt it: applying would claim
            // delete-ownership of a rule we did not create, and a later TTL
            // rollback would then remove the operator's own rule. Refuse without
            // mutating or taking ownership. (A rule added by a racing operator
            // *after* this preflight is not caught here; closing that needs a
            // clawforge-exclusive ruleset - a documented remaining boundary.)
            if already_blocked {
                return GenericDispatchOutcome::failed(
                    "rule already present at preflight; refusing to adopt pre-existing (possibly operator-owned) state - no apply, no ownership",
                );
            }
            let rendered = match adapter.render(action) {
                Ok(rendered) => rendered,
                Err(_) => {
                    return GenericDispatchOutcome::failed("adapter render failed; apply refused")
                }
            };
            let fingerprint = rendered.target_fingerprint.clone();
            // R1: persist the internal versioned recovery target (the exact
            // identity bound at apply time) rather than a bare fingerprint, so
            // TTL/crash recovery can reconstruct the real rollback target. The
            // raw address stays in this access-restricted intent row, never in
            // an agent projection.
            let target_json = RecoveryTarget::new(adapter.name(), action.target.clone()).to_json();
            let rollback_plan = serde_json::json!({"commands": rendered.rollback_commands});
            match journal
                .store
                .prepare_firewall_rule_intent(
                    journal.execution_id,
                    adapter.name(),
                    journal.action_name,
                    &adapter.rule_scope(&action.target),
                    &fingerprint,
                    &target_json,
                    &preflight_state,
                    &rollback_plan,
                    rendered.ttl_seconds,
                )
                .await
            {
                Ok(id) => Some((
                    id,
                    fingerprint,
                    target_json,
                    rollback_plan,
                    rendered.ttl_seconds,
                )),
                Err(_) => return GenericDispatchOutcome::failed(
                    "firewall rule already owned by an active generation; reconcile before reapply",
                ),
            }
        }
        _ => None,
    };
    let result = match adapter.apply(action, dry_run).await {
        Ok(result) => result,
        Err(_) if dry_run => {
            return GenericDispatchOutcome::failed("adapter dry-run planning failed")
        }
        Err(_) => {
            let effect = if let (Some((id, ..)), Some(journal)) = (&prepared, journal) {
                let _ = journal
                    .store
                    .mark_firewall_rule_recovery_required(*id)
                    .await;
                FirewallEffect::UncertainOwned(*id)
            } else {
                FirewallEffect::NonJournaled
            };
            let presence = match adapter.verify(&action.target).await {
                Ok(VerificationResult::Verified) => "present",
                Ok(VerificationResult::NotPresent) => "absent",
                Err(_) => "unknown",
            };
            return GenericDispatchOutcome {
                completion: DispatchCompletion::RecoveryRequired,
                effect,
                result_summary: Some(format!("adapter={} apply outcome uncertain; observed_presence={presence}", adapter.name())),
                error_summary: Some("real apply failed; manual reconciliation required; presence does not prove ownership".into()),
                receipts: Vec::new(),
            };
        }
    };
    let verification_result = if dry_run {
        None
    } else {
        Some(match adapter.verify(&action.target).await {
            Ok(VerificationResult::Verified) => "verified",
            Ok(VerificationResult::NotPresent) => "mismatch",
            Err(_) => "failed",
        })
    };
    // Journaled real path: atomic finish on verified, recovery otherwise. The
    // receipt is written by `finish`, so no in-memory receipt is returned.
    if let (Some((id, fingerprint, target_json, rollback_plan, ttl)), Some(journal)) =
        (&prepared, journal)
    {
        if verification_result == Some("verified") {
            let input = FirewallActionReceiptInput {
                execution_id: Some(journal.execution_id),
                adapter: result.receipt.adapter,
                action_name: journal.action_name,
                preflight_state: preflight_state.clone(),
                rendered_commands: serde_json::json!(result.receipt.rendered_commands),
                observed_state: result.observed_state.as_deref().map(adapter_state_json),
                verification_result: Some("verified"),
                ttl_seconds: *ttl,
                rollback_plan: rollback_plan.clone(),
                is_dry_run: false,
                receipt_kind: "apply",
                target_fingerprint: Some(fingerprint),
                target_json: Some(target_json.clone()),
            };
            return match journal.store.finish_firewall_rule_intent(*id, &input).await {
                Ok(_) => GenericDispatchOutcome {
                    completion: DispatchCompletion::Success,
                    effect: FirewallEffect::VerifiedOwned(*id),
                    result_summary: Some(format!(
                        "adapter={} dry_run=false verification=verified journaled",
                        adapter.name()
                    )),
                    error_summary: None,
                    receipts: Vec::new(),
                },
                Err(_) => {
                    let _ = journal
                        .store
                        .mark_firewall_rule_recovery_required(*id)
                        .await;
                    GenericDispatchOutcome {
                        completion: DispatchCompletion::RecoveryRequired,
                        effect: FirewallEffect::UncertainOwned(*id),
                        result_summary: Some(format!(
                            "adapter={} applied but receipt persistence failed",
                            adapter.name()
                        )),
                        error_summary: Some(
                            "firewall receipt persistence failed; reconciliation required".into(),
                        ),
                        receipts: Vec::new(),
                    }
                }
            };
        }
        let _ = journal
            .store
            .mark_firewall_rule_recovery_required(*id)
            .await;
        return GenericDispatchOutcome {
            completion: DispatchCompletion::RecoveryRequired,
            effect: FirewallEffect::UncertainOwned(*id),
            result_summary: Some(format!(
                "adapter={} verification={}",
                adapter.name(),
                verification_result.unwrap_or("not_attempted")
            )),
            error_summary: Some(
                "real apply could not be verified; manual reconciliation required".into(),
            ),
            receipts: Vec::new(),
        };
    }
    // Non-journaled path (dry-run, or store-free unit tests): F1 behavior.
    let completion = if dry_run || verification_result == Some("verified") {
        DispatchCompletion::Success
    } else {
        DispatchCompletion::RecoveryRequired
    };
    let summary = format!(
        "adapter={} dry_run={} verification={}",
        adapter.name(),
        dry_run,
        verification_result.unwrap_or("not_attempted")
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
    GenericDispatchOutcome {
        completion,
        effect: FirewallEffect::NonJournaled,
        result_summary: Some(summary),
        error_summary: (completion == DispatchCompletion::RecoveryRequired)
            .then(|| "real apply could not be verified; manual reconciliation required".into()),
        receipts: vec![receipt],
    }
}

/// Retain all known receipts, and fence any uncertain real effect even
/// when it belongs to an optional adapter. Safe optional refusals degrade
/// the summary without negating a verified mandatory adapter.
async fn dispatch_multi_with_adapters(
    action: &FirewallAction,
    dry_run: bool,
    adapters: Vec<Box<dyn FirewallAdapter>>,
    journal: Option<&RuleJournal<'_>>,
) -> GenericDispatchOutcome {
    let mut outcome = GenericDispatchOutcome::failed("mandatory nftables adapter missing");
    let mut mandatory_seen = false;
    let mut mandatory_success = false;
    let mut uncertain = false;
    // Track whether any adapter owns a durable generation. A journaled verified
    // apply returns an EMPTY receipt vector (its receipt is persisted inside
    // `finish`), so the receipt-based check below cannot see it - without this an
    // owned optional adapter whose mandatory peer failed would be reported as a
    // plain Failed and the request retried, colliding with the owned generation.
    let mut aggregate_effect = FirewallEffect::NoMutation;
    let mut summaries = Vec::new();
    let mut errors = Vec::new();
    for adapter in adapters {
        let name = adapter.name();
        let result = apply_single_adapter(adapter.as_ref(), action, dry_run, journal).await;
        if name == MANDATORY_MULTI_ADAPTER {
            mandatory_seen = true;
            mandatory_success = result.completion == DispatchCompletion::Success;
        }
        uncertain |= result.completion == DispatchCompletion::RecoveryRequired;
        // Prefer an uncertain generation; otherwise record the first owned one.
        match (aggregate_effect, result.effect) {
            (_, effect @ FirewallEffect::UncertainOwned(_)) => aggregate_effect = effect,
            (
                FirewallEffect::NoMutation | FirewallEffect::NonJournaled,
                effect @ FirewallEffect::VerifiedOwned(_),
            ) => aggregate_effect = effect,
            _ => {}
        }
        if let Some(summary) = result.result_summary {
            summaries.push(summary);
        }
        if let Some(error) = result.error_summary {
            errors.push(format!("{name}: {error}"));
        }
        outcome.receipts.extend(result.receipts);
    }
    outcome.effect = aggregate_effect;
    outcome.completion = if uncertain {
        DispatchCompletion::RecoveryRequired
    } else if mandatory_seen && mandatory_success {
        DispatchCompletion::Success
    } else if !dry_run
        && (outcome.receipts.iter().any(|receipt| !receipt.is_dry_run)
            || aggregate_effect.is_owned())
    {
        DispatchCompletion::RecoveryRequired
    } else {
        DispatchCompletion::Failed
    };
    if !mandatory_seen {
        errors.push("mandatory nftables adapter missing".into());
    }
    outcome.result_summary = Some(summaries.join("; "));
    outcome.error_summary = (!errors.is_empty()).then(|| errors.join("; "));
    outcome
}

async fn try_dispatch_generic(
    store: Option<&PostgresStore>,
    claimed: &ClaimedExecutionRequest,
) -> Option<GenericDispatchOutcome> {
    let multi = claimed
        .action_name
        .starts_with(FIREWALL_MULTI_ADAPTER_PREFIX);
    let single = if multi {
        None
    } else {
        adapter_for(&claimed.action_name)
    };
    if !multi && single.is_none() {
        return None;
    }
    let Some(target) = claimed.target.as_ref() else {
        return Some(GenericDispatchOutcome::failed(
            "firewall action has no target",
        ));
    };
    let action = match parse_firewall_action(claimed.id, target) {
        Ok(action) => action,
        Err(_) => {
            return Some(GenericDispatchOutcome::failed(
                "invalid firewall action target",
            ))
        }
    };
    let dry_run = dispatch_dry_run(claimed);
    // P7-2: refuse a real apply whose TTL exceeds the live ceiling before
    // anything is journaled or applied - a bounded self-expiry is the core
    // guard against a block that outlives its intent and locks someone out.
    // Central here so both the single-adapter and `firewall.*` fan-out paths
    // are covered by one gate; dry-runs are never affected.
    if let Some(reason) = firewall_ttl_over_live_ceiling(action.ttl_seconds, dry_run) {
        return Some(GenericDispatchOutcome::failed(&reason));
    }
    // Durable write-ahead ownership for real applies (F2). Dry-run never
    // journals; store-free callers (unit tests) pass None and get F1 behavior.
    let journal = store.map(|store| RuleJournal {
        store,
        execution_id: claimed.id,
        action_name: &claimed.action_name,
    });
    Some(if multi {
        let adapters = configured_multi_adapters()
            .iter()
            .filter_map(|name| adapter_for(name))
            .collect();
        dispatch_multi_with_adapters(&action, dry_run, adapters, journal.as_ref()).await
    } else {
        apply_single_adapter(single.unwrap().as_ref(), &action, dry_run, journal.as_ref()).await
    })
}

const TAILSCALE_ACTION_PREFIX: &str = "tailscale.quarantine_device";
const PROXMOX_QUARANTINE_ACTION: &str = "proxmox.quarantine_vm";
// Specific to quarantine: `docker.restart_container` and other docker.* actions
// are deliberately NOT firewall actions and must keep their non-firewall no-op.
const DOCKER_QUARANTINE_ACTION: &str = "docker.quarantine_container";
/// Validate operator context and enforce the hard live gate before legacy
/// dry-run quarantine adapters are called. Native live mutations also require
/// the generation journal and remain disabled in quarantine_runtime.
fn checked_quarantine_context(
    claimed: &ClaimedExecutionRequest,
) -> anyhow::Result<quarantine_gate::QuarantineContext> {
    let target = claimed
        .target
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("quarantine action has no target"))?;
    let dry_run = dispatch_dry_run(claimed);
    let context = quarantine_gate::validate_context(&claimed.action_name, target, dry_run)?;
    quarantine_gate::ensure_live_dispatch_disabled(dry_run)?;
    // Metadata is checked context, not a proof of a reachable management path.
    if !dry_run && (context.preflight.is_none() || !context.ready_for_live) {
        anyhow::bail!("quarantine live readiness has not been proven");
    }
    Ok(context)
}

async fn dispatch_tailscale(
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Vec<FirewallDispatchReceipt>,
) {
    let context = match checked_quarantine_context(claimed) {
        Ok(context) => context,
        Err(error) => return (false, None, Some(error.to_string()), Vec::new()),
    };
    let quarantine_gate::QuarantineIdentity::Tailscale { device_id } = context.target else {
        return (
            false,
            None,
            Some("incorrect Tailscale target kind".into()),
            Vec::new(),
        );
    };
    let action = TailscaleAction {
        target: TailscaleTarget {
            device_id: device_id.clone(),
        },
        reason: format!("execution_request {}", claimed.id),
    };
    let adapter = TailscaleAdapter::new();
    let dry_run = dispatch_dry_run(claimed);
    // Read-only quarantine preflight, recorded on the receipt. Best-effort: a
    // transient Admin-API read (or missing credentials) must never block the
    // dispatch, which is itself still dry-run-gated.
    let preflight_state = match adapter.preflight(&action.target).await {
        Ok(pf) => serde_json::json!({
            "already_quarantined": pf.already_quarantined,
            "current_tags": pf.current_tags,
            "rollback_requires_reauth": pf.rollback_requires_reauth,
            "protected": pf.protected,
        }),
        Err(error) => {
            tracing::warn!(%error, "tailscale quarantine preflight read failed; recording empty preflight");
            serde_json::json!({})
        }
    };
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
                preflight_state,
                rendered_commands: serde_json::json!([applied.receipt.described_call]),
                observed_state: None,
                verification_result,
                ttl_seconds: context.ttl_seconds,
                rollback_plan: serde_json::json!({
                    "note": "removes the quarantine tag - may require device-side reauth if \
                             it is the device's only tag, see TailscaleAdapter::rollback"
                }),
                is_dry_run: !applied.applied,
                target_fingerprint: device_id,
            };
            let success = dry_run || verification_result == Some("verified");
            (
                success,
                Some(summary),
                (!success).then(|| "quarantine verification failed; recovery required".to_string()),
                vec![receipt],
            )
        }
        Err(error) => (false, None, Some(error.to_string()), Vec::new()),
    }
}

/// Dispatches a `proxmox.*` VM quarantine. Target JSON is `{"node": "<node>",
/// "vmid": <positive int>}`. Mirrors `dispatch_tailscale`: a read-only preflight
/// is recorded on the receipt, the apply is dry-run-gated, and a protected VM
/// (never-quarantine list) is refused by the adapter itself.
async fn dispatch_proxmox(
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Vec<FirewallDispatchReceipt>,
) {
    let context = match checked_quarantine_context(claimed) {
        Ok(context) => context,
        Err(error) => return (false, None, Some(error.to_string()), Vec::new()),
    };
    let quarantine_gate::QuarantineIdentity::Proxmox { node, vmid } = context.target else {
        return (
            false,
            None,
            Some("incorrect Proxmox target kind".into()),
            Vec::new(),
        );
    };
    let qtarget = QuarantineTarget::Proxmox {
        node: node.clone(),
        vmid,
    };
    let adapter = ProxmoxAdapter::new();
    let dry_run = dispatch_dry_run(claimed);
    // Read-only preflight on the receipt; best-effort so a transient API read
    // never blocks the (dry-run-gated) dispatch.
    let preflight_state = match adapter.preflight(&qtarget).await {
        Ok(pf) => serde_json::json!({
            "node": pf.node,
            "vmid": pf.vmid,
            "net0": pf.net0,
            "currently_quarantined": pf.currently_quarantined,
            "protected": pf.protected,
        }),
        Err(error) => {
            tracing::warn!(%error, "proxmox quarantine preflight read failed; recording empty preflight");
            serde_json::json!({})
        }
    };
    match adapter.apply(&qtarget, dry_run).await {
        Ok(applied) => {
            let verification_result = if dry_run {
                None
            } else {
                match adapter.verify(&qtarget).await {
                    Ok(VerificationResult::Verified) => Some("verified"),
                    Ok(VerificationResult::NotPresent) => Some("mismatch"),
                    Err(_) => Some("failed"),
                }
            };
            let receipt = FirewallDispatchReceipt {
                adapter: "proxmox",
                preflight_state,
                rendered_commands: serde_json::json!([applied.summary]),
                observed_state: None,
                verification_result,
                ttl_seconds: context.ttl_seconds,
                rollback_plan: serde_json::json!({
                    "note": "restore the exact original net0 using the current config digest",
                    "original_net0": applied.original_net0
                }),
                is_dry_run: dry_run,
                target_fingerprint: format!("{node}/{vmid}"),
            };
            (
                dry_run || verification_result == Some("verified"),
                Some(format!(
                    "adapter=proxmox dry_run={dry_run} target={node}/{vmid}"
                )),
                (verification_result.is_some_and(|v| v != "verified"))
                    .then(|| "quarantine verification failed; recovery required".to_string()),
                vec![receipt],
            )
        }
        Err(error) => (false, None, Some(error.to_string()), Vec::new()),
    }
}

/// Dispatches a `docker.*` container quarantine. Target JSON is
/// `{"container_id": "<id>"}`. The disconnected networks are recorded on the
/// receipt so a rollback can reconnect them; a protected container is refused
/// by the adapter's never-quarantine guard.
async fn dispatch_docker(
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Vec<FirewallDispatchReceipt>,
) {
    let context = match checked_quarantine_context(claimed) {
        Ok(context) => context,
        Err(error) => return (false, None, Some(error.to_string()), Vec::new()),
    };
    let quarantine_gate::QuarantineIdentity::Docker { container_id } = context.target else {
        return (
            false,
            None,
            Some("incorrect Docker target kind".into()),
            Vec::new(),
        );
    };
    let qtarget = QuarantineTarget::Docker {
        container_id: container_id.clone(),
    };
    let adapter = DockerAdapter::new();
    let dry_run = dispatch_dry_run(claimed);
    let preflight_state = match adapter.preflight(&qtarget).await {
        Ok(pf) => serde_json::json!({
            "container_id": pf.container_id,
            "networks": pf.networks,
            "currently_quarantined": pf.currently_quarantined,
            "protected": pf.protected,
        }),
        Err(error) => {
            tracing::warn!(%error, "docker quarantine preflight read failed; recording empty preflight");
            serde_json::json!({})
        }
    };
    match adapter.apply(&qtarget, dry_run).await {
        Ok(networks) => {
            let verification_result = if dry_run {
                None
            } else {
                match adapter.verify(&qtarget).await {
                    Ok(VerificationResult::Verified) => Some("verified"),
                    Ok(VerificationResult::NotPresent) => Some("mismatch"),
                    Err(_) => Some("failed"),
                }
            };
            let count = networks.len();
            let commands: Vec<String> = networks
                .iter()
                .map(|network| {
                    format!(
                        "docker network disconnect {} {container_id}",
                        network.network_id
                    )
                })
                .collect();
            let receipt = FirewallDispatchReceipt {
                adapter: "docker",
                preflight_state,
                rendered_commands: serde_json::json!(commands),
                observed_state: Some(
                    serde_json::json!({ "disconnected_networks": networks.clone() }),
                ),
                verification_result,
                ttl_seconds: context.ttl_seconds,
                rollback_plan: serde_json::json!({
                    "note": "reconnect the container to disconnected_networks - see DockerAdapter::rollback",
                    "networks": networks,
                }),
                is_dry_run: dry_run,
                target_fingerprint: container_id.clone(),
            };
            (
                dry_run || verification_result == Some("verified"),
                Some(format!(
                    "adapter=docker dry_run={dry_run} container={container_id} networks={count}"
                )),
                (verification_result.is_some_and(|v| v != "verified"))
                    .then(|| "quarantine verification failed; recovery required".to_string()),
                vec![receipt],
            )
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
    store: Option<&PostgresStore>,
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Vec<FirewallDispatchReceipt>,
) {
    if let Some(outcome) = try_dispatch_generic(store, claimed).await {
        return outcome.into_legacy();
    }
    if claimed.action_name == TAILSCALE_ACTION_PREFIX {
        return dispatch_tailscale(claimed).await;
    }
    if claimed.action_name == PROXMOX_QUARANTINE_ACTION {
        return dispatch_proxmox(claimed).await;
    }
    if claimed.action_name == DOCKER_QUARANTINE_ACTION {
        return dispatch_docker(claimed).await;
    }
    (
        true,
        Some("dry_run: no external operation executed".to_string()),
        None,
        Vec::new(),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // P7-1: `from_env` returns `Err` for a *present but invalid* authorization;
    // propagating it here refuses startup rather than silently ignoring a
    // malformed approval (fail-closed and loud), whether or not DRY_RUN is set.
    let live_authorization = live_authorization::LiveAuthorization::from_env()?;
    if !dry_run_from_env() && live_authorization.is_none() {
        anyhow::bail!(
            "productive execution requires an explicit live authorization \
             (CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION); with none set, \
             CLAWFORGE_EXECUTOR_DRY_RUN must remain true"
        );
    }
    if let Some(auth) = &live_authorization {
        tracing::warn!(
            authorization_id = %auth.authorization_id,
            approved_by = %auth.approved_by,
            authorized_classes = ?auth.actions,
            dry_run = dry_run_from_env(),
            "live execution authorization loaded; only the listed firewall action \
             classes may apply for real - quarantine stays closed and simulation_only \
             still forces dry-run"
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
                quarantine_runtime::sweep(&store).await;
                sweep_expired_firewall_targets(&store).await;
                sweep_kill_switch_requests(&store).await;
                sweep_firewall_rule_generations(&store).await;
                let started = std::time::Instant::now();
                match store.claim_execution_request_for_dispatch(Some(worker_id)).await {
                    Ok(Some(claimed)) => {
                        let budget = firewall_mass_block_budget_exceeded(
                            &store,
                            &claimed.action_name,
                            dispatch_dry_run(&claimed),
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
                        // Concurrency budget: reserve a slot in every
                        // adapter this action would touch *before*
                        // dispatching for real, so two replicas racing to
                        // claim different requests against the same
                        // adapter cannot both proceed unbounded. Only
                        // relevant for a real (non-dry-run) firewall
                        // action that the mass-block budget has not
                        // already refused - see `firewall_budget_applies`.
                        let mut inflight_ids = Vec::new();
                        let mut concurrency_refusal = None;
                        if refusal.is_none()
                            && firewall_budget_applies(&claimed.action_name, dispatch_dry_run(&claimed))
                        {
                            for adapter in adapters_touched_by(&claimed.action_name) {
                                match try_begin_inflight(&store, &adapter).await {
                                    Ok(Some(id)) => inflight_ids.push(id),
                                    Ok(None) => {
                                        concurrency_refusal = Some(format!(
                                            "concurrency budget exceeded for adapter {adapter:?} \
                                             (see CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER)"
                                        ));
                                        break;
                                    }
                                    Err(error) => {
                                        tracing::warn!(%error, execution_id = %claimed.id, %adapter, "could not check the concurrency budget");
                                        concurrency_refusal =
                                            Some(format!("could not check concurrency budget: {error}"));
                                        break;
                                    }
                                }
                            }
                        }
                        let refusal = refusal.or(concurrency_refusal);
                        let mut outcome =
                            if let Some(reason) = refusal {
                                tracing::warn!(execution_id = %claimed.id, action = %claimed.action_name, reason = %reason, "refusing dispatch");
                                GenericDispatchOutcome::failed(&reason)
                            } else if let Some(outcome) = try_dispatch_generic(Some(&store), &claimed).await {
                                outcome
                            } else {
                                GenericDispatchOutcome::from_legacy(quarantine_runtime::dispatch(&store, &claimed).await)
                            };
                        // Release every reserved slot regardless of how
                        // dispatch turned out - a partial reservation
                        // (concurrency_refusal broke out of the loop
                        // early) only ever holds the ones it actually
                        // acquired, so this is correct for that case too.
                        for id in inflight_ids {
                            let _ = store.end_firewall_inflight_operation(id).await;
                        }
                        // One receipt row per adapter that actually applied -
                        // a firewall.* fan-out (dispatch_multi_adapter) can
                        // produce more than one; every other action produces
                        // at most one. Persisted regardless of overall
                        // `success` - a sibling adapter's real state change
                        // still needs tracking even if another one failed.
                        for receipt in std::mem::take(&mut outcome.receipts) {
                            // The TTL sweep rolls back from the receipt's target_json. Docker
                            // needs the disconnected networks (which are not in the action
                            // target) to reconnect, so fold them in from the rollback plan.
                            let target_json = if receipt.adapter == "docker" {
                                let mut target =
                                    claimed.target.clone().unwrap_or_else(|| serde_json::json!({}));
                                if let (Some(object), Some(networks)) =
                                    (target.as_object_mut(), receipt.rollback_plan.get("networks"))
                                {
                                    object.insert("networks".to_string(), networks.clone());
                                }
                                Some(target)
                            } else if receipt.adapter == "proxmox" {
                                let mut target=claimed.target.clone().unwrap_or_else(|| serde_json::json!({}));
                                if let (Some(object),Some(original))=(target.as_object_mut(),receipt.rollback_plan.get("original_net0")) { object.insert("original_net0".into(),original.clone()); }
                                Some(target)
                            } else {
                                claimed.target.clone()
                            };
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
                                    target_json,
                                })
                                .await
                            {
                                outcome.receipt_persistence_failed(dispatch_dry_run(&claimed));
                                tracing::warn!(execution_id = %claimed.id, adapter = receipt.adapter, "could not persist firewall action receipt");
                                let _ = error;
                            }
                        }
                        let success = outcome.completion == DispatchCompletion::Success;
                        let completion = if outcome.completion == DispatchCompletion::RecoveryRequired {
                            store.complete_execution_dispatch_for_recovery(claimed.id, Some(worker_id), started,
                                outcome.result_summary.as_deref(), outcome.error_summary.as_deref()).await
                        } else {
                            store.complete_execution_dispatch(claimed.id, Some(worker_id), started, success,
                                outcome.result_summary.as_deref(), outcome.error_summary.as_deref()).await
                        };
                        if let Err(error) = completion
                        {
                            tracing::warn!(%error, execution_id = %claimed.id, "could not persist dispatch completion");
                            let _ = store.heartbeat_execution_worker(worker_id, "degraded", 0, Some(&error.to_string())).await;
                        } else if !success {
                            tracing::warn!(execution_id = %claimed.id, action = %claimed.action_name, error = ?outcome.error_summary, "dispatch failed");
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

    /// `CLAWFORGE_FIREWALL_ADAPTERS` is mutated by exactly two tests
    /// (`adapters_touched_by_matches_dispatchs_own_routing` and
    /// `firewall_action_fan_out_honors_configured_multi_adapters`).
    /// `cargo test`'s default parallel execution runs both in the same
    /// process on different threads, so without serializing them a
    /// `set_var` from one can be observed by a read in the other between
    /// its own set/assert/remove steps - a real, previously-unguarded
    /// race (an earlier version of one test wrongly assumed a "single-
    /// threaded test process"). Every access to that env var in this
    /// module must hold this lock for the whole set-assert-remove span.
    /// A `tokio::sync::Mutex`, not `std::sync::Mutex`: the async test below
    /// holds the guard across several `.await` points, which clippy
    /// (correctly) rejects for a std mutex.
    static FIREWALL_ADAPTERS_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    fn resolve_dry_run_is_fail_closed_without_a_live_authorization() {
        // Live mode on, not simulation_only, but no authorization at all -
        // must still force dry-run. This is the invariant `main`'s startup gate
        // depends on (DRY_RUN=false is only allowed with an authorization).
        assert!(resolve_dry_run(
            false,
            false,
            None,
            "nftables.block_indicator"
        ));
        // The env default (DRY_RUN unset -> true) always forces dry-run too.
        assert!(resolve_dry_run(
            true,
            false,
            None,
            "nftables.block_indicator"
        ));
    }

    #[test]
    fn resolve_dry_run_applies_only_authorized_classes_in_live_mode() {
        let auth = live_authorization::LiveAuthorization::parse(
            r#"{"version":1,"authorization_id":"pilot-7a","approved_by":"ops","actions":["nftables"]}"#,
        )
        .unwrap();
        // Authorized class, live mode, not simulation_only -> real apply.
        assert!(!resolve_dry_run(
            false,
            false,
            Some(&auth),
            "nftables.block_indicator"
        ));
        // A different, unauthorized class stays dry-run.
        assert!(resolve_dry_run(
            false,
            false,
            Some(&auth),
            "haproxy.block_indicator"
        ));
        // A quarantine action can never be authorized, even in live mode.
        assert!(resolve_dry_run(
            false,
            false,
            Some(&auth),
            PROXMOX_QUARANTINE_ACTION
        ));
    }

    #[test]
    fn resolve_dry_run_simulation_only_and_env_gate_override_a_live_authorization() {
        let auth = live_authorization::LiveAuthorization::parse(
            r#"{"version":1,"authorization_id":"pilot-7a","approved_by":"ops","actions":["nftables"]}"#,
        )
        .unwrap();
        // simulation_only forces dry-run even for an authorized class.
        assert!(resolve_dry_run(
            false,
            true,
            Some(&auth),
            "nftables.block_indicator"
        ));
        // The global env gate (DRY_RUN=true) forces dry-run even with an
        // authorization present.
        assert!(resolve_dry_run(
            true,
            false,
            Some(&auth),
            "nftables.block_indicator"
        ));
    }

    #[test]
    fn shadow_request_remains_dry_run_independent_of_global_gate() {
        let shadow = serde_json::json!({"simulation_only": true});
        assert!(request_requires_dry_run(Some(&shadow)));
        let ordinary = serde_json::json!({"simulation_only": false});
        assert!(!request_requires_dry_run(Some(&ordinary)));
        assert!(!request_requires_dry_run(None));
    }

    #[test]
    fn the_mass_block_budget_only_applies_to_a_real_firewall_apply() {
        assert!(firewall_budget_applies("nftables.block_indicator", false));
        assert!(firewall_budget_applies("haproxy.block_indicator", false));
        assert!(firewall_budget_applies("goaway.challenge_indicator", false));
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
    fn ttl_ceiling_never_gates_a_dry_run() {
        // A dry-run persists and mutates nothing, so even an absurd TTL is fine.
        assert!(ttl_over_live_ceiling(u32::MAX, 3600, true).is_none());
    }

    #[test]
    fn ttl_ceiling_allows_a_real_apply_within_the_limit() {
        assert!(ttl_over_live_ceiling(3600, 3600, false).is_none());
        assert!(ttl_over_live_ceiling(900, 3600, false).is_none());
        assert!(ttl_over_live_ceiling(1, 3600, false).is_none());
    }

    #[test]
    fn ttl_ceiling_refuses_a_real_apply_over_the_limit() {
        let reason = ttl_over_live_ceiling(7200, 3600, false).expect("over the ceiling");
        assert!(reason.contains("exceeds the live ceiling"));
        assert!(reason.contains("7200"));
        assert!(reason.contains("3600"));
    }

    #[test]
    fn firewall_max_ttl_seconds_reads_env_or_falls_back_to_the_default() {
        // One test owns this process-wide var so two env-touching tests never
        // race under the default parallel runner.
        std::env::set_var("CLAWFORGE_FIREWALL_MAX_TTL_SECONDS", "900");
        assert_eq!(firewall_max_ttl_seconds(), 900);
        // A zero/invalid value falls back to the safe default rather than
        // disabling the ceiling.
        std::env::set_var("CLAWFORGE_FIREWALL_MAX_TTL_SECONDS", "0");
        assert_eq!(firewall_max_ttl_seconds(), DEFAULT_FIREWALL_MAX_TTL_SECONDS);
        std::env::set_var("CLAWFORGE_FIREWALL_MAX_TTL_SECONDS", "not-a-number");
        assert_eq!(firewall_max_ttl_seconds(), DEFAULT_FIREWALL_MAX_TTL_SECONDS);
        std::env::remove_var("CLAWFORGE_FIREWALL_MAX_TTL_SECONDS");
        assert_eq!(firewall_max_ttl_seconds(), DEFAULT_FIREWALL_MAX_TTL_SECONDS);
    }

    #[tokio::test]
    async fn unrelated_proxmox_and_similar_docker_actions_never_quarantine() {
        for action in [
            "proxmox.restart_vm",
            "proxmox.snapshot_vm",
            "docker.quarantine_container_extra",
        ] {
            assert!(adapters_touched_by(action).is_empty());
            let result = dispatch(None, &claimed(action, None)).await;
            assert!(result.0);
            assert!(result.3.is_empty());
        }
        assert_eq!(
            adapters_touched_by("proxmox.quarantine_vm"),
            vec!["proxmox"]
        );
        assert_eq!(
            adapters_touched_by("docker.quarantine_container"),
            vec!["docker"]
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
        assert_eq!(
            adapter_for("goaway.challenge_indicator").map(|a| a.name()),
            Some("goaway")
        );
        // The TTL sweep looks adapters up by the bare `adapter` column
        // value (no trailing dot), not an action name - must resolve the
        // same way.
        assert_eq!(adapter_for("nftables").map(|a| a.name()), Some("nftables"));
        assert_eq!(adapter_for("haproxy").map(|a| a.name()), Some("haproxy"));
        assert_eq!(adapter_for("goaway").map(|a| a.name()), Some("goaway"));
        assert_eq!(
            adapter_for("haproxy_ratelimit").map(|a| a.name()),
            Some("haproxy_ratelimit")
        );
        assert!(adapter_for("tailscale.quarantine_device").is_none());
        assert!(adapter_for("docker.restart_container").is_none());
    }

    #[test]
    fn adapters_touched_by_matches_dispatchs_own_routing() {
        assert_eq!(
            adapters_touched_by("nftables.block_indicator"),
            vec!["nftables"]
        );
        assert_eq!(
            adapters_touched_by("haproxy.block_indicator"),
            vec!["haproxy"]
        );
        assert_eq!(
            adapters_touched_by("goaway.challenge_indicator"),
            vec!["goaway"]
        );
        // Same ordering trap as `adapter_for` - must not be misrouted to
        // the plain "haproxy" domain.
        assert_eq!(
            adapters_touched_by("haproxy_ratelimit.block_indicator"),
            vec!["haproxy_ratelimit"]
        );
        assert_eq!(
            adapters_touched_by("tailscale.quarantine_device"),
            vec!["tailscale"]
        );
        assert!(
            adapters_touched_by("docker.restart_container").is_empty(),
            "a non-firewall action touches no adapter's concurrency budget"
        );
        // firewall.* must reserve a slot in every configured adapter,
        // nftables always among them (mirrors configured_multi_adapters).
        let _env_guard = FIREWALL_ADAPTERS_ENV_LOCK.blocking_lock();
        std::env::remove_var("CLAWFORGE_FIREWALL_ADAPTERS");
        assert_eq!(
            adapters_touched_by("firewall.block_indicator"),
            vec!["nftables"]
        );
        std::env::set_var("CLAWFORGE_FIREWALL_ADAPTERS", "haproxy");
        let touched = adapters_touched_by("firewall.block_indicator");
        assert!(touched.contains(&"nftables".to_string()));
        assert!(touched.contains(&"haproxy".to_string()));
        std::env::remove_var("CLAWFORGE_FIREWALL_ADAPTERS");
    }

    #[tokio::test]
    async fn non_firewall_actions_keep_the_original_dry_run_success_behavior() {
        let request = claimed("docker.restart_container", None);
        let (success, summary, error, receipts) = dispatch(None, &request).await;
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
        let (success, _summary, error, receipts) = dispatch(None, &request).await;
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
        let (success, _summary, error, receipts) = dispatch(None, &request).await;
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
        let (success, summary, error, receipts) = dispatch(None, &request).await;
        assert!(success, "dispatch failed: {error:?}");
        let summary = summary.unwrap();
        assert!(summary.contains("dry_run=true"));
        // Targets remain in the restricted receipt, not the summary.
        assert!(receipts[0]
            .rendered_commands
            .to_string()
            .contains("203.0.113.0/24"));
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
    async fn a_goaway_shadow_challenge_produces_a_ttl_and_rollback_receipt() {
        let request = claimed(
            "goaway.challenge_incident_source",
            Some(serde_json::json!({
                "kind": "incident_source",
                "pseudonym": "ip-pseudonym:shadow-test",
                "ttl_seconds": 300,
                "simulation_only": true,
            })),
        );
        let (success, summary, error, receipts) = dispatch(None, &request).await;
        assert!(success, "dispatch failed: {error:?}");
        assert!(summary.unwrap().contains("dry_run=true"));
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        assert_eq!(receipt.adapter, "goaway");
        assert!(receipt.is_dry_run);
        assert_eq!(receipt.ttl_seconds, 300);
        assert!(receipt.verification_result.is_none());
        assert!(receipt
            .rollback_plan
            .to_string()
            .contains("yaml-prefix-remove"));
        assert!(receipt
            .rendered_commands
            .to_string()
            .contains("<resolved-at-apply-time:ip-pseudonym:shadow-test>"));
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
        let (success, summary, error, receipts) = dispatch(None, &request).await;
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
        let (success, summary, error, receipts) = dispatch(None, &request).await;
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
        let (success, _summary, error, receipts) = dispatch(None, &request).await;
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
        let (success, _summary, error, receipts) = dispatch(None, &request).await;
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
        let (success, summary, error, receipts) = dispatch(None, &request).await;
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
    /// values genuinely need to not interleave). Also holds
    /// `FIREWALL_ADAPTERS_ENV_LOCK` for its whole span - the other test
    /// that touches this same env var races it otherwise, see that lock's
    /// own doc comment.
    #[tokio::test]
    async fn firewall_action_fan_out_honors_configured_multi_adapters() {
        let _env_guard = FIREWALL_ADAPTERS_ENV_LOCK.lock().await;
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
        let (success, summary, error, receipts) = dispatch(None, &request()).await;
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
        let (success, _summary, error, receipts) = dispatch(None, &request()).await;
        assert!(success, "dispatch failed: {error:?}");
        let mut adapters: Vec<&str> = receipts.iter().map(|r| r.adapter).collect();
        adapters.sort_unstable();
        assert_eq!(adapters, ["haproxy", "haproxy_ratelimit", "nftables"]);

        // nftables must always run even when an operator's own list omits
        // it - the host-wide "any external service" guarantee cannot be
        // configured away.
        std::env::set_var("CLAWFORGE_FIREWALL_ADAPTERS", "haproxy");
        let (success, _summary, error, receipts) = dispatch(None, &request()).await;
        assert!(success, "dispatch failed: {error:?}");
        assert!(
            receipts.iter().any(|r| r.adapter == "nftables"),
            "nftables must always run, even when an operator's own list omits it: {:?}",
            receipts.iter().map(|r| r.adapter).collect::<Vec<_>>()
        );

        // An unrecognized name is dropped, not fatal - nftables (the core
        // guarantee) still runs regardless.
        std::env::set_var("CLAWFORGE_FIREWALL_ADAPTERS", "not-a-real-adapter");
        let (success, _summary, error, receipts) = dispatch(None, &request()).await;
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

    /// F2 TTL/recovery sweep safety: a durable firewall rule generation whose
    /// completion is uncertain is never blindly replayed. A `prepared`
    /// generation (it may have crashed after a real adapter mutation) is
    /// retained as `recovery_required`, and the sweep does not retry that
    /// durable state. Isolated schema-0055 PostgreSQL fixture; no real firewall.
    #[tokio::test]
    #[ignore = "requires an isolated firewall-rule PostgreSQL fixture with schema 0055"]
    async fn firewall_rule_recovery_retains_ownership_without_blind_replay() -> anyhow::Result<()> {
        let store = PostgresStore::connect_runtime(&std::env::var(
            "CLAWFORGE_TEST_FIREWALL_RULE_DATABASE_URL",
        )?)
        .await?;
        let adapter = "nftables";
        let action = "nftables.block_indicator";
        let scope = "clawforge_recover_v4";
        let fp = format!("203.0.113.{}/32", Uuid::new_v4().as_u128() % 250 + 1);
        let target = serde_json::json!({"cidr": fp, "scope": scope});
        let state = serde_json::json!({"set_present": false});
        let plan = serde_json::json!({"commands": [["nft", "delete", "element", "..."]]});

        // Minimal execution request: rule intents carry no approval gate, the FK
        // just needs to exist.
        let action_id: Uuid = sqlx::query_scalar("INSERT INTO actions(id,name,type,risk_level,required_scope,requires_approval,enabled) VALUES($1,$2,'connector_action','low','agent:action:read',FALSE,TRUE) ON CONFLICT(name) DO UPDATE SET enabled=TRUE RETURNING id")
            .bind(Uuid::new_v4()).bind(action).fetch_one(store.pool()).await?;
        let requester_name = format!("rule-recover-{}", Uuid::new_v4());
        let requester = store
            .create_admin_user(&requester_name, "Administrator", "test-hash")
            .await?;
        let execution = store
            .create_execution_request(&clawforge_storage::ExecutionRequestInput {
                action_id,
                workflow_run_id: None,
                decision_id: None,
                requested_by: requester_name,
                requested_by_id: Some(requester),
                idempotency_key: None,
                target: Some(target.clone()),
            })
            .await?;

        // A prepared generation that may have crashed after a real mutation must
        // be retained for recovery, never auto-applied or auto-resolved.
        let id = store
            .prepare_firewall_rule_intent(
                execution, adapter, action, scope, &fp, &target, &state, &plan, 3600,
            )
            .await?;
        // R3: while the owning execution holds a LIVE lease, the prepared
        // generation is an in-flight apply - the sweep must skip it (Busy),
        // never steal it into recovery_required.
        let worker = Uuid::new_v4();
        sqlx::query("INSERT INTO execution_workers(id,name) VALUES($1,$2)")
            .bind(worker)
            .bind(format!("recover-worker-{worker}"))
            .execute(store.pool())
            .await?;
        sqlx::query("INSERT INTO execution_leases(id,execution_id,worker_id,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '2 minutes')")
            .bind(Uuid::new_v4())
            .bind(execution)
            .bind(worker)
            .execute(store.pool())
            .await?;
        assert!(matches!(
            recover_firewall_rule_generation(&store, id).await,
            quarantine_runtime::RecoveryOutcome::Busy
        ));
        assert_eq!(
            store.firewall_rule_intent(id).await?.unwrap().status,
            "prepared",
            "an in-flight prepared generation (live owner lease) must not be stolen"
        );

        // Owner lease gone/expired -> the generation is genuinely orphaned and is
        // retained for recovery, never blindly replayed.
        sqlx::query("UPDATE execution_leases SET status='expired' WHERE execution_id=$1")
            .bind(execution)
            .execute(store.pool())
            .await?;
        let outcome = recover_firewall_rule_generation(&store, id).await;
        assert!(matches!(
            outcome,
            quarantine_runtime::RecoveryOutcome::ManualReview
        ));
        assert_eq!(
            store.firewall_rule_intent(id).await?.unwrap().status,
            "recovery_required",
            "an orphaned prepared generation is retained, never blindly replayed"
        );

        // The sweep deliberately does not retry a durable recovery_required.
        sweep_firewall_rule_generations(&store).await;
        assert_eq!(
            store.firewall_rule_intent(id).await?.unwrap().status,
            "recovery_required",
            "recovery_required is not retried by the sweep"
        );
        Ok(())
    }
}

#[cfg(test)]
mod dispatch_tests;
