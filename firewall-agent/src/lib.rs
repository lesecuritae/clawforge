//! `clawforge-firewall-agent` (roadmap phase 6, "Firewall Action Layer").
//! Typed adapter contract, plus a real `NftablesAdapter`: preflight,
//! render, apply, verify, rollback.
//!
//! ## `dry_run` is explicit, never a default
//!
//! [`FirewallAdapter::apply`] takes `dry_run: bool` as a required
//! argument - there is no `apply(action)` shorthand that could apply for
//! real by omission. Passing `dry_run: true` behaves exactly like
//! [`FirewallAdapter::render`] and executes nothing. This crate can now
//! genuinely change a host's firewall state (see "What changed" below),
//! so the discipline that used to be "no code path exists" moves one
//! layer up: every call site must say which mode it means, in the open.
//! `clawforge-executor`'s own `CLAWFORGE_EXECUTOR_DRY_RUN` (hardcoded
//! `true`, refuses to start otherwise) is the second, independent gate
//! at the process level - this crate does not relax that on its own.
//!
//! ## One exclusive table, two pre-provisioned sets - never a free-form rule
//!
//! The roadmap is specific: "exklusive Clawforge-Tabelle/-Chain ...
//! ausschließlich ein vorprovisioniertes Set verwalten". This adapter
//! never renders `nft add rule` or `nft add table`/`add set` at all - an
//! operator provisions the table, the two typed sets (`blocklist` for
//! IPv4, `blocklist6` for IPv6 - nftables sets are typed, one cannot hold
//! both) and exactly one rule referencing each, ahead of time, out of
//! band (`scripts/nftables-clawforge-provision.sh` documents and performs
//! this once). This adapter only ever adds or removes *elements* of those
//! sets. A bug here can at most toggle membership of one address in one
//! set; it cannot inject a new rule, touch another table, or affect
//! anything the operator did not already provision by hand.
//!
//! ## Command construction, not string interpolation
//!
//! Every `nft` invocation - `preflight`'s read-only inspection included -
//! is built as an explicit `Vec<String>` of arguments passed to
//! `tokio::process::Command`, never a shell string, so there is no shell
//! to inject into in the first place. [`FirewallTarget::validate`] rejects
//! a malformed target before it is ever used to build a command, as
//! defense in depth on top of that.
//!
//! ## Address normalization
//!
//! An IPv4-mapped IPv6 address (`::ffff:203.0.113.7` - the same shape
//! `clawforge-haproxy-sensor` had to learn to parse this session, for an
//! unrelated reason: HAProxy logs a dual-stack bind's IPv4 clients this
//! way) is normalized to plain IPv4 before it is ever used to pick a set
//! or build a command - nftables' `ipv4_addr`-typed set cannot hold an
//! IPv6-syntax value, and treating the same address inconsistently across
//! calls would silently miss it in one direction or the other.
//!
//! ## Three target kinds, three risk shapes
//!
//! - [`FirewallTarget::ThreatIntelIndicator`] - a raw CIDR/IP that is
//!   already public threat-intel data (`indicators.value`) - never
//!   pseudonymized in the first place, safe to render as-is.
//! - [`FirewallTarget::IncidentSource`] - a pseudonymized resource
//!   (`ip-pseudonym:<hash>`). `render` **never** resolves it to a raw IP;
//!   `apply`ing it directly fails (the placeholder is not valid `nft`
//!   syntax) - safe by construction, not just convention.
//! - [`FirewallTarget::ResolvedIncidentSource`] - only ever constructed by
//!   a caller that already resolved a pseudonym via
//!   `security_ip_resolutions`, and only ever passed to
//!   `apply`/`verify`/`rollback`, never to `render`: `render` returns
//!   `Err` for this variant rather than silently rendering a raw IP into
//!   a receipt that might be persisted. The receipt for an incident-source
//!   action is always built from the *unresolved* `IncidentSource` first;
//!   resolution happens only immediately before a real `apply` call, in
//!   the caller, and the resolved value is never logged or stored beyond
//!   that call.
//!
//! ## Never-block exclusion list
//!
//! `NftablesAdapter::new` loads a built-in safety net (loopback,
//! link-local) plus whatever `CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS`
//! configures (an operator's own management/SSH source range belongs
//! there). `render` and `apply` both refuse - before building or running
//! anything - a target whose network overlaps any excluded network in
//! either direction (a broad target CIDR that merely *contains* an
//! excluded `/32`, not just the reverse). A malformed configured entry
//! fails the *entire* list closed rather than silently dropping just that
//! entry - see `never_block_list_from_env`'s own doc comment. This is the
//! concrete guardrail against self-lockout that exists today, in place of
//! the isolated network lab's own self-lockout confirmation, which needs
//! a real provisioned host's management path to mean anything (see
//! `docs/firewall-agent.md`).
//!
//! ## What changed from the preflight/render-only increment
//!
//! `apply`, `verify`, and `rollback` now exist and can genuinely mutate a
//! host's nftables state when called with `dry_run: false` against a
//! table that has been provisioned. Tested against a real `nft` binary in
//! a disposable, isolated container (`scripts/test-firewall-lab.sh`) -
//! never against any of this deployment's real hosts.
//! `clawforge-executor` now dispatches a claimed `execution_request`
//! through this crate for real (see `docs/firewall-agent.md`'s "Executor
//! dispatch wiring"), gated by a DB-backed mass-block budget
//! (`docs/firewall-agent.md`'s "Mass-block budget") and proven safe under
//! concurrent HA workers (see `storage/tests/postgres.rs`'s
//! `concurrent_workers_never_claim_the_same_execution_request_twice` and
//! `a_worker_that_dies_after_claiming_is_reclaimed_by_a_different_worker`).
//! A break-glass drill (`break_glass_removes_every_trace_of_the_clawforge_table`),
//! manual-drift detection (`verify_detects_manual_drift_after_an_out_of_band_removal`),
//! TTL-driven auto-rollback, a kill-switch per target, and both a
//! DB-backed mass-block rate budget and a per-adapter concurrency budget
//! (both bounding multiple `clawforge-executor` replicas sharing this
//! database, not just one process) also exist now - see
//! `docs/firewall-agent.md`'s "Kill-switch per target" and "Concurrency
//! budget per adapter" sections. Property-based fuzz tests
//! (`proptest_never_panics_on_arbitrary_input` and friends, below) prove
//! the "no shell to inject into" claim above holds for adversarial input,
//! not just the hand-picked negative-test cases. Still open: the
//! roadmap's remaining mandatory gates beyond what this crate's own tests
//! cover - see `docs/firewall-agent.md`'s own remaining list.

use async_trait::async_trait;
use std::net::IpAddr;

/// Clawforge's own, exclusive nftables table and the two typed sets
/// (nftables sets are typed - one set cannot hold both IPv4 and IPv6
/// elements) - see the module doc comment for why this adapter never
/// renders anything outside them.
pub const NFTABLES_FAMILY: &str = "inet";
pub const NFTABLES_TABLE: &str = "clawforge";
pub const NFTABLES_BLOCKLIST_SET_V4: &str = "blocklist";
pub const NFTABLES_BLOCKLIST_SET_V6: &str = "blocklist6";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdapterError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("preflight failed: {0}")]
    Preflight(String),
    #[error("apply failed: {0}")]
    Apply(String),
    #[error("verify failed: {0}")]
    Verify(String),
    #[error("rollback failed: {0}")]
    Rollback(String),
}

/// What a firewall action would apply to. See the module doc comment for
/// why three variants, not one generic "IP or CIDR" shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallTarget {
    /// A raw CIDR or single IP from a threat-intel indicator
    /// (`indicators.value`) - already public data, safe to render as-is.
    ThreatIntelIndicator { cidr: String, source: String },
    /// A pseudonymized resource (`ip-pseudonym:<hash>`) from a corroborated
    /// incident. `render` never resolves this to a raw address, and
    /// `apply`ing it directly fails.
    IncidentSource { pseudonym: String },
    /// A pseudonym already resolved to a raw IP by the caller (via
    /// `security_ip_resolutions`) - for `apply`/`verify`/`rollback` only.
    /// `render` refuses this variant; see the module doc comment.
    ResolvedIncidentSource { raw_ip: String, pseudonym: String },
}

/// The JSON contract for `execution_requests.approval_context->>'target'`
/// (`ExecutionRequestInput::target`/`ClaimedExecutionRequest::target`) -
/// `{"kind":"threat_intel_indicator","cidr":"...","source":"..."}` or
/// `{"kind":"incident_source","pseudonym":"ip-pseudonym:..."}`. Never
/// produces a `ResolvedIncidentSource` - nothing external ever supplies an
/// already-resolved raw IP; only a caller that already holds one from
/// `security_ip_resolutions` constructs that variant directly, at the last
/// possible moment before a real `apply` call.
impl TryFrom<&serde_json::Value> for FirewallTarget {
    type Error = AdapterError;

    fn try_from(value: &serde_json::Value) -> Result<Self, Self::Error> {
        let kind = value.get("kind").and_then(|v| v.as_str()).ok_or_else(|| {
            AdapterError::InvalidTarget("target is missing its \"kind\" field".into())
        })?;
        match kind {
            "threat_intel_indicator" => {
                let cidr = value
                    .get("cidr")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AdapterError::InvalidTarget("target.cidr is missing".into()))?
                    .to_string();
                let source = value
                    .get("source")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AdapterError::InvalidTarget("target.source is missing".into()))?
                    .to_string();
                let target = FirewallTarget::ThreatIntelIndicator { cidr, source };
                target.validate()?;
                Ok(target)
            }
            "incident_source" => {
                let pseudonym = value
                    .get("pseudonym")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AdapterError::InvalidTarget("target.pseudonym is missing".into())
                    })?
                    .to_string();
                let target = FirewallTarget::IncidentSource { pseudonym };
                target.validate()?;
                Ok(target)
            }
            other => Err(AdapterError::InvalidTarget(format!(
                "unknown target kind {other:?}"
            ))),
        }
    }
}

impl FirewallTarget {
    /// Validates the target is well-formed *before* it is ever used to
    /// build a command - defense in depth on top of `tokio::process::
    /// Command`'s argv-array construction already ruling out shell
    /// injection by design.
    fn validate(&self) -> Result<(), AdapterError> {
        match self {
            FirewallTarget::ThreatIntelIndicator { cidr, source } => {
                if source.trim().is_empty() {
                    return Err(AdapterError::InvalidTarget(
                        "threat-intel indicator source must not be empty".into(),
                    ));
                }
                parse_ip_or_cidr(cidr).ok_or_else(|| {
                    AdapterError::InvalidTarget(format!("{cidr:?} is not a valid IP or CIDR"))
                })?;
                Ok(())
            }
            FirewallTarget::IncidentSource { pseudonym } => validate_pseudonym(pseudonym),
            FirewallTarget::ResolvedIncidentSource { raw_ip, pseudonym } => {
                validate_pseudonym(pseudonym)?;
                parse_ip_or_cidr(raw_ip).ok_or_else(|| {
                    AdapterError::InvalidTarget(format!("{raw_ip:?} is not a valid IP"))
                })?;
                Ok(())
            }
        }
    }

    /// Which typed set (`blocklist`/`blocklist6`) this target belongs in -
    /// `None` for `IncidentSource`, which has no address to pick one with
    /// yet.
    fn set_name(&self) -> Result<Option<&'static str>, AdapterError> {
        let addr = match self {
            FirewallTarget::ThreatIntelIndicator { cidr, .. } => {
                parse_ip_or_cidr(cidr).map(|(addr, _)| addr)
            }
            FirewallTarget::ResolvedIncidentSource { raw_ip, .. } => {
                parse_ip_or_cidr(raw_ip).map(|(addr, _)| addr)
            }
            FirewallTarget::IncidentSource { .. } => return Ok(None),
        };
        let addr = addr.ok_or_else(|| AdapterError::InvalidTarget("no address".into()))?;
        Ok(Some(match normalize_address(addr) {
            IpAddr::V4(_) => NFTABLES_BLOCKLIST_SET_V4,
            IpAddr::V6(_) => NFTABLES_BLOCKLIST_SET_V6,
        }))
    }
}

fn validate_pseudonym(pseudonym: &str) -> Result<(), AdapterError> {
    if !pseudonym.starts_with("ip-pseudonym:") || pseudonym.len() <= "ip-pseudonym:".len() {
        return Err(AdapterError::InvalidTarget(format!(
            "{pseudonym:?} is not a recognized pseudonymized resource"
        )));
    }
    Ok(())
}

/// An IPv4-mapped IPv6 address (`::ffff:203.0.113.7`) normalizes to plain
/// IPv4 - see the module doc comment for why (nftables' `ipv4_addr`-typed
/// set cannot hold an IPv6-syntax value, and this address must be treated
/// identically no matter which syntax a caller happened to use for it).
/// Every other address passes through unchanged.
fn normalize_address(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => addr,
        },
    }
}

/// A plain IP (`1.2.3.4`) or CIDR (`1.2.3.4/24`) - the two shapes
/// `indicators.value` actually holds. Accepts nothing else - no
/// hostnames, no ranges. The returned address is already normalized
/// (see `normalize_address`).
fn parse_ip_or_cidr(value: &str) -> Option<(IpAddr, Option<u8>)> {
    match value.split_once('/') {
        Some((addr, prefix)) => {
            let addr: IpAddr = normalize_address(addr.parse().ok()?);
            let prefix: u8 = prefix.parse().ok()?;
            let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > max_prefix {
                return None;
            }
            Some((addr, Some(prefix)))
        }
        None => {
            let addr: IpAddr = normalize_address(value.parse().ok()?);
            Some((addr, None))
        }
    }
}

/// The normalized `(address, prefix length)` a resolvable target refers
/// to - `Err` for `IncidentSource`, which has none yet. Shared by
/// `element_reference` (the `nft` command syntax) and
/// `set_contains_target` (structural JSON comparison), so the two can
/// never drift into checking a different address than the one a command
/// was built for.
fn target_address(target: &FirewallTarget) -> Result<(IpAddr, Option<u8>), AdapterError> {
    match target {
        FirewallTarget::ThreatIntelIndicator { cidr, .. } => parse_ip_or_cidr(cidr)
            .ok_or_else(|| AdapterError::InvalidTarget(format!("{cidr:?} invalid"))),
        FirewallTarget::ResolvedIncidentSource { raw_ip, .. } => parse_ip_or_cidr(raw_ip)
            .ok_or_else(|| AdapterError::InvalidTarget(format!("{raw_ip:?} invalid"))),
        FirewallTarget::IncidentSource { .. } => Err(AdapterError::InvalidTarget(
            "an unresolved IncidentSource has no address".into(),
        )),
    }
}

/// Renders a target to its normalized `nft` element syntax - the literal,
/// normalized CIDR/IP for a resolvable target, or the unresolved
/// placeholder for `IncidentSource`. Never called with
/// `ResolvedIncidentSource` from `render` (see that function's own guard);
/// `apply`/`verify`/`rollback` use it for every variant that has an
/// address.
fn element_reference(target: &FirewallTarget) -> Result<String, AdapterError> {
    if let FirewallTarget::IncidentSource { pseudonym } = target {
        return Ok(format!("<resolved-at-apply-time:{pseudonym}>"));
    }
    let (addr, prefix) = target_address(target)?;
    Ok(match prefix {
        Some(p) => format!("{addr}/{p}"),
        None => addr.to_string(),
    })
}

/// The safe-to-**persist** reference for a receipt - unlike
/// `element_reference` (used to build the real command that actually
/// runs), this never returns a raw IP for `ResolvedIncidentSource`, only
/// its pseudonym's placeholder, the same shape `element_reference` itself
/// already uses for an unresolved `IncidentSource`.
///
/// A resolved raw IP must reach the real `nft`/HAProxy command
/// (`element_reference`) - it must never reach anything that might be
/// persisted (`rendered_commands`/`rollback_commands`/
/// `target_fingerprint` in a `FirewallActionReceipt`), which is exactly
/// the property `render`'s own outright refusal of `ResolvedIncidentSource`
/// already protects. `render` can simply refuse the variant outright
/// because it never needs to build a real command; `apply` cannot refuse
/// it (that would make a resolved incident source entirely unappliable)
/// but still must not let the receipt it returns carry the raw IP - this
/// is what makes both possible at once. Found and fixed the same session
/// `record_firewall_action_receipt` started persisting every `apply`
/// receipt (not just `render`'s): before that, `apply`'s own receipt was
/// never written anywhere a raw IP leaking into it would matter.
fn redacted_element_reference(target: &FirewallTarget) -> Result<String, AdapterError> {
    if let FirewallTarget::ResolvedIncidentSource { pseudonym, .. } = target {
        return Ok(format!("<resolved-at-apply-time:{pseudonym}>"));
    }
    element_reference(target)
}

/// Rejects an unresolved `IncidentSource` - shared guard for any adapter's
/// `apply`/`verify`/`rollback` that (unlike `NftablesAdapter`, which gets
/// this for free from `set_name`'s own `Ok(None)` case) has no per-family
/// set-selection step to piggyback the check on. Called *before*
/// `element_reference`, whose `<resolved-at-apply-time:...>` placeholder
/// is only ever safe to use inside a rendered receipt, never as a live
/// command argument.
fn require_resolved_target(target: &FirewallTarget) -> Result<(), AdapterError> {
    if matches!(target, FirewallTarget::IncidentSource { .. }) {
        return Err(AdapterError::InvalidTarget(
            "an unresolved IncidentSource cannot be applied - resolve it to a \
             ResolvedIncidentSource first"
                .into(),
        ));
    }
    Ok(())
}

/// Whether `addr`/`prefix` is an element of the set `nft -j list set`
/// described in `raw_set_json` - parsed structurally, **not** by string
/// search. `nft`'s own JSON splits a prefixed element into separate
/// `{"prefix":{"addr":...,"len":...}}` fields rather than the combined
/// `addr/len` text form this crate renders commands with, so a naive
/// `raw_set_json.contains("addr/len")` never matches a CIDR element at
/// all (it happens to work for a bare, prefix-less IP, whose JSON form
/// *is* just the plain address string - which is exactly how the bug this
/// replaces stayed hidden until a real IPv6/48 round-trip test caught it
/// live in `scripts/test-firewall-lab.sh`, not a synthetic string check).
fn set_contains_target(raw_set_json: &str, addr: IpAddr, prefix: Option<u8>) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw_set_json) else {
        return false;
    };
    let Some(elements) = value
        .get("nftables")
        .and_then(|v| v.as_array())
        .and_then(|entries| {
            entries
                .iter()
                .find_map(|entry| entry.get("set")?.get("elem")?.as_array())
        })
    else {
        return false;
    };
    let addr_str = addr.to_string();
    elements.iter().any(|element| match element {
        serde_json::Value::String(value) => prefix.is_none() && *value == addr_str,
        serde_json::Value::Object(_) => {
            let Some(prefix_obj) = element.get("prefix") else {
                return false;
            };
            let element_addr = prefix_obj.get("addr").and_then(|a| a.as_str());
            let element_len = prefix_obj.get("len").and_then(|l| l.as_u64());
            match (element_addr, element_len, prefix) {
                (Some(a), Some(l), Some(p)) => a == addr_str && l == u64::from(p),
                _ => false,
            }
        }
        _ => false,
    })
}

/// `32` for an IPv4 address, `128` for an IPv6 address - the "just this
/// one host" prefix length a bare address (no `/n`) implies.
fn full_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        32
    } else {
        128
    }
}

/// Whether the network `a_addr/a_prefix` and `b_addr/b_prefix` overlap at
/// all - masked by the *less specific* (numerically smaller) of the two
/// prefixes, so this is correct regardless of which side is the broader
/// range (a `/8` never-block entry must catch a `/32` target inside it,
/// and a broad `/8` target must equally be caught by a `/32` never-block
/// entry inside *it*). Different address families never overlap.
fn ranges_overlap(a_addr: IpAddr, a_prefix: u8, b_addr: IpAddr, b_prefix: u8) -> bool {
    match (a_addr, b_addr) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let prefix = a_prefix.min(b_prefix);
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let prefix = a_prefix.min(b_prefix);
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

/// Built-in safety net (loopback, link-local - always active, not
/// disable-able by configuration) plus whatever an operator adds via
/// `CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS` (comma-separated IPs/CIDRs) -
/// this is where an operator's own management/SSH source range belongs.
/// A malformed configured entry makes the *entire* list `Err`, not just
/// that one entry silently dropped - `NftablesAdapter::check_never_block`
/// then refuses every target until it is fixed, the same fail-closed
/// choice this codebase already made for pseudonymization
/// (`clawforge-analyzer`'s `CLAWFORGE_ANALYZER_IP_HMAC_KEY`): a safety
/// exclusion list that can silently lose entries is worse than one that
/// visibly disables applying anything.
fn never_block_list_from_env() -> Result<Vec<(IpAddr, u8)>, String> {
    never_block_list_from_configured(
        std::env::var("CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS")
            .ok()
            .as_deref(),
    )
}

/// The pure parser `never_block_list_from_env` delegates to - kept
/// separate (rather than reading the env var inline) so tests can exercise
/// every parsing edge case deterministically, without mutating process-wide
/// environment state that other tests running concurrently in the same
/// binary could observe.
fn never_block_list_from_configured(configured: Option<&str>) -> Result<Vec<(IpAddr, u8)>, String> {
    const BUILTIN: &[&str] = &["127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10"];
    let mut list = Vec::new();
    for entry in BUILTIN {
        let (addr, prefix) =
            parse_ip_or_cidr(entry).unwrap_or_else(|| panic!("built-in entry {entry:?} is valid"));
        list.push((addr, prefix.unwrap_or_else(|| full_prefix(addr))));
    }
    if let Some(configured) = configured {
        for entry in configured.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (addr, prefix) = parse_ip_or_cidr(entry).ok_or_else(|| {
                format!("CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS: {entry:?} is not a valid IP or CIDR")
            })?;
            list.push((addr, prefix.unwrap_or_else(|| full_prefix(addr))));
        }
    }
    Ok(list)
}

#[derive(Debug, Clone)]
pub struct FirewallAction {
    pub target: FirewallTarget,
    pub ttl_seconds: u32,
    pub reason: String,
}

/// What preflight found - read-only, never mutates anything. `nft`'s own
/// JSON output for the set is kept verbatim (`raw_set_json`) rather than
/// parsed into a bespoke struct.
#[derive(Debug, Clone)]
pub struct Preflight {
    pub already_blocked: bool,
    pub raw_set_json: String,
}

/// The rendered result of a `render` call - every command as an explicit
/// argv array (`Vec<String>`, never a shell string). `is_dry_run` reflects
/// how the receipt was produced: `true` from `render` or from `apply`
/// called with `dry_run: true`; `false` only once `apply` actually ran
/// the commands.
#[derive(Debug, Clone)]
pub struct FirewallActionReceipt {
    pub adapter: &'static str,
    pub rendered_commands: Vec<Vec<String>>,
    pub rollback_commands: Vec<Vec<String>>,
    pub is_dry_run: bool,
    pub ttl_seconds: u32,
    /// The normalized element (`element_reference`'s output) this receipt
    /// is about, paired with `adapter` by a caller to recognize "the same
    /// block, applied again" or "the rollback that undoes this apply"
    /// across separate receipt rows - e.g. for a TTL-driven auto-rollback
    /// sweep matching an expired apply receipt to whether a later
    /// rollback receipt for the same target already exists. Never a
    /// resolved raw IP for an `IncidentSource` (the unresolved
    /// placeholder, or the resolved element only for
    /// `ResolvedIncidentSource`, following the exact same rules
    /// `element_reference` itself already follows).
    pub target_fingerprint: String,
}

/// The outcome of a real `apply` call - the receipt, plus (only when
/// `dry_run` was `false`) `nft`'s own post-apply listing of the set, for
/// a caller to persist as the Action Receipt's "Istzustand".
#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub receipt: FirewallActionReceipt,
    pub observed_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// The target is an element of the set, as intended.
    Verified,
    /// The target is *not* an element of the set, even though apply
    /// reported success - drift, or a rollback that already ran.
    NotPresent,
}

#[async_trait]
pub trait FirewallAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    /// Read-only inspection of current state relevant to `target` - must
    /// never construct or run anything but an `nft list`/`nft -j list`
    /// style command.
    async fn preflight(&self, target: &FirewallTarget) -> Result<Preflight, AdapterError>;
    /// Pure and synchronous: rendering what an apply *would* do never
    /// needs to touch the network, the filesystem, or `nft` itself.
    fn render(&self, action: &FirewallAction) -> Result<FirewallActionReceipt, AdapterError>;
    /// `dry_run` is required, never defaulted - see the module doc
    /// comment. `dry_run: true` behaves exactly like `render` (nothing is
    /// executed); `dry_run: false` actually runs the rendered command.
    async fn apply(
        &self,
        action: &FirewallAction,
        dry_run: bool,
    ) -> Result<ApplyResult, AdapterError>;
    /// Re-checks live state against what `action` intended.
    async fn verify(&self, target: &FirewallTarget) -> Result<VerificationResult, AdapterError>;
    /// Runs the rollback command for real - always a real mutation (there
    /// is no "dry-run rollback"; a caller that only ever `render`ed or
    /// dry-run-`apply`d has nothing to roll back in the first place).
    async fn rollback(&self, action: &FirewallAction) -> Result<(), AdapterError>;
}

/// Refuses a target whose network overlaps the never-block exclusion list
/// (loopback/link-local, plus an operator's own configured management/SSH
/// range) - shared by every adapter's `render`/`apply` (`NftablesAdapter`,
/// `HaproxyAdapter`, `HaproxyRateLimitAdapter`), each of which loads its
/// own `never_block` field the same way via `never_block_list_from_env`
/// and passes it in here, so the safety net is not something a new
/// adapter can forget to wire up - called before either builds or runs
/// anything. Not called by any adapter's `rollback`: removing an element
/// from a blocklist is the safe direction and must always be allowed,
/// including for something that should never have been added in the
/// first place. `IncidentSource` (unresolved) has no address yet to
/// check - it already fails closed for its own, independent reason
/// wherever an address would be needed.
fn check_never_block(
    never_block: &Result<Vec<(IpAddr, u8)>, String>,
    target: &FirewallTarget,
) -> Result<(), AdapterError> {
    let never_block = never_block.as_ref().map_err(|error| {
        AdapterError::InvalidTarget(format!(
            "never-block exclusion list is misconfigured, refusing every target until fixed: \
             {error}"
        ))
    })?;
    if matches!(target, FirewallTarget::IncidentSource { .. }) {
        return Ok(());
    }
    let (addr, prefix) = target_address(target)?;
    let prefix = prefix.unwrap_or_else(|| full_prefix(addr));
    if never_block
        .iter()
        .any(|(net_addr, net_prefix)| ranges_overlap(*net_addr, *net_prefix, addr, prefix))
    {
        return Err(AdapterError::InvalidTarget(
            "target overlaps a never-block exclusion (loopback/link-local or \
             CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS)"
                .into(),
        ));
    }
    Ok(())
}

pub struct NftablesAdapter {
    /// `Err` once, at construction, if `CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS`
    /// is set but malformed - see `never_block_list_from_env`'s own doc
    /// comment for why that fails every subsequent `apply`/`render` closed
    /// rather than silently dropping the bad entry.
    never_block: Result<Vec<(IpAddr, u8)>, String>,
}

impl NftablesAdapter {
    pub fn new() -> Self {
        Self {
            never_block: never_block_list_from_env(),
        }
    }

    /// The read-only command `preflight` runs - a pure function so the
    /// exact argv can be asserted on in a test without needing `nft`
    /// installed.
    fn preflight_command(set_name: &str) -> Vec<String> {
        vec![
            "nft".to_string(),
            "-j".to_string(),
            "list".to_string(),
            "set".to_string(),
            NFTABLES_FAMILY.to_string(),
            NFTABLES_TABLE.to_string(),
            set_name.to_string(),
        ]
    }

    fn add_command(set_name: &str, element: &str) -> Vec<String> {
        vec![
            "nft".to_string(),
            "add".to_string(),
            "element".to_string(),
            NFTABLES_FAMILY.to_string(),
            NFTABLES_TABLE.to_string(),
            set_name.to_string(),
            "{".to_string(),
            element.to_string(),
            "}".to_string(),
        ]
    }

    fn delete_command(set_name: &str, element: &str) -> Vec<String> {
        vec![
            "nft".to_string(),
            "delete".to_string(),
            "element".to_string(),
            NFTABLES_FAMILY.to_string(),
            NFTABLES_TABLE.to_string(),
            set_name.to_string(),
            "{".to_string(),
            element.to_string(),
            "}".to_string(),
        ]
    }

    async fn run(args: &[String]) -> Result<std::process::Output, String> {
        tokio::process::Command::new(&args[0])
            .args(&args[1..])
            .output()
            .await
            .map_err(|error| error.to_string())
    }
}

impl Default for NftablesAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallAdapter for NftablesAdapter {
    fn name(&self) -> &'static str {
        "nftables"
    }

    async fn preflight(&self, target: &FirewallTarget) -> Result<Preflight, AdapterError> {
        target.validate()?;
        let Some(set_name) = target.set_name()? else {
            // An unresolved IncidentSource: preflight cannot tell
            // membership any more precisely than "unknown" without a real
            // resolved address, and must not guess.
            return Ok(Preflight {
                already_blocked: false,
                raw_set_json: String::new(),
            });
        };
        let args = Self::preflight_command(set_name);
        let output = Self::run(&args).await.map_err(AdapterError::Preflight)?;
        if !output.status.success() {
            return Err(AdapterError::Preflight(format!(
                "nft exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let raw_set_json = String::from_utf8_lossy(&output.stdout).to_string();
        let (addr, prefix) = target_address(target)?;
        Ok(Preflight {
            already_blocked: set_contains_target(&raw_set_json, addr, prefix),
            raw_set_json,
        })
    }

    fn render(&self, action: &FirewallAction) -> Result<FirewallActionReceipt, AdapterError> {
        if let FirewallTarget::ResolvedIncidentSource { .. } = &action.target {
            // Hard guardrail, not just convention - see the module doc
            // comment. A resolved raw IP must never reach a persisted
            // receipt.
            return Err(AdapterError::InvalidTarget(
                "a resolved incident source must never be rendered into a receipt".into(),
            ));
        }
        action.target.validate()?;
        check_never_block(&self.never_block, &action.target)?;
        let element = element_reference(&action.target)?;
        let set_name = action
            .target
            .set_name()?
            .unwrap_or(NFTABLES_BLOCKLIST_SET_V4);
        Ok(FirewallActionReceipt {
            adapter: self.name(),
            rendered_commands: vec![Self::add_command(set_name, &element)],
            rollback_commands: vec![Self::delete_command(set_name, &element)],
            is_dry_run: true,
            ttl_seconds: action.ttl_seconds,
            target_fingerprint: element,
        })
    }

    async fn apply(
        &self,
        action: &FirewallAction,
        dry_run: bool,
    ) -> Result<ApplyResult, AdapterError> {
        action.target.validate()?;
        check_never_block(&self.never_block, &action.target)?;
        let element = element_reference(&action.target)?;
        // Safe to persist - never the raw IP `element` resolves to for a
        // `ResolvedIncidentSource` (see `redacted_element_reference`'s own
        // doc comment). Only used to build the receipt, never the real
        // command below.
        let receipt_element = redacted_element_reference(&action.target)?;
        let set_name = action.target.set_name()?.ok_or_else(|| {
            AdapterError::Apply(
                "an unresolved IncidentSource cannot be applied - resolve it to a \
                 ResolvedIncidentSource first"
                    .into(),
            )
        })?;
        let add = Self::add_command(set_name, &element);
        let receipt_add = Self::add_command(set_name, &receipt_element);
        let receipt_delete = Self::delete_command(set_name, &receipt_element);
        if dry_run {
            return Ok(ApplyResult {
                receipt: FirewallActionReceipt {
                    adapter: self.name(),
                    rendered_commands: vec![receipt_add],
                    rollback_commands: vec![receipt_delete],
                    is_dry_run: true,
                    ttl_seconds: action.ttl_seconds,
                    target_fingerprint: receipt_element,
                },
                observed_state: None,
            });
        }
        let output = Self::run(&add).await.map_err(AdapterError::Apply)?;
        if !output.status.success() {
            return Err(AdapterError::Apply(format!(
                "nft exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let listing = Self::run(&Self::preflight_command(set_name))
            .await
            .map_err(AdapterError::Apply)?;
        let observed_state = String::from_utf8_lossy(&listing.stdout).to_string();
        Ok(ApplyResult {
            receipt: FirewallActionReceipt {
                adapter: self.name(),
                rendered_commands: vec![receipt_add],
                rollback_commands: vec![receipt_delete],
                is_dry_run: false,
                ttl_seconds: action.ttl_seconds,
                target_fingerprint: receipt_element,
            },
            observed_state: Some(observed_state),
        })
    }

    async fn verify(&self, target: &FirewallTarget) -> Result<VerificationResult, AdapterError> {
        target.validate()?;
        let set_name = target
            .set_name()?
            .ok_or_else(|| AdapterError::Verify("target has no resolvable address".into()))?;
        let output = Self::run(&Self::preflight_command(set_name))
            .await
            .map_err(AdapterError::Verify)?;
        if !output.status.success() {
            return Err(AdapterError::Verify(format!(
                "nft exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        let (addr, prefix) = target_address(target)?;
        if set_contains_target(&raw, addr, prefix) {
            Ok(VerificationResult::Verified)
        } else {
            Ok(VerificationResult::NotPresent)
        }
    }

    async fn rollback(&self, action: &FirewallAction) -> Result<(), AdapterError> {
        action.target.validate()?;
        let element = element_reference(&action.target)?;
        let set_name = action.target.set_name()?.ok_or_else(|| {
            AdapterError::Rollback("an unresolved IncidentSource has nothing to roll back".into())
        })?;
        let delete = Self::delete_command(set_name, &element);
        let output = Self::run(&delete).await.map_err(AdapterError::Rollback)?;
        if !output.status.success() {
            return Err(AdapterError::Rollback(format!(
                "nft exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }
}

/// The exclusively Clawforge-owned HAProxy ACL pattern file - the direct
/// analog of nftables' exclusive table/set: an operator adds *one* `acl
/// ... src -f <file>` reference to it (and a matching `deny`/`reject`
/// action) to whichever frontend(s) they want protected, ahead of time,
/// out of band (`scripts/haproxy-clawforge-provision.sh`); this adapter
/// only ever adds/removes *entries* of this one file's loaded pattern
/// list via the HAProxy Runtime API, never touches `haproxy.cfg` itself.
///
/// **Not** HAProxy's separate `map`-file mechanism (`map_ip()`/`map_str()`
/// converters, a true key -> value lookup manipulated via `add
/// map`/`show map`) - an `acl ... -f <file>` pattern list is a different
/// runtime object, manipulated via `add acl`/`del acl`/`show acl`, and
/// that is what this adapter actually uses: a blocklist only needs "is
/// this address present", never a value. Unlike nftables' two typed,
/// family-separated sets, one ACL pattern file holds both IPv4 and IPv6
/// entries - it has no type constraint.
pub const HAPROXY_DEFAULT_ADMIN_SOCKET: &str = "/var/run/haproxy/admin.sock";
pub const HAPROXY_DEFAULT_BLOCKLIST_ACL_FILE: &str = "/etc/haproxy/maps/clawforge-blocklist.map";

fn haproxy_show_acl_command(acl_file: &str) -> String {
    format!("show acl {acl_file}")
}

fn haproxy_add_acl_command(acl_file: &str, key: &str) -> String {
    format!("add acl {acl_file} {key}")
}

fn haproxy_del_acl_command(acl_file: &str, key: &str) -> String {
    format!("del acl {acl_file} {key}")
}

/// Whether `key` (an already-normalized IP/CIDR string) appears as the
/// pattern column of a `show acl <file>` response. HAProxy's Runtime API
/// answers plain text, one entry per line, `<id> <pattern>` (the `id` is
/// an opaque per-entry pointer, e.g. `0x71d738032af0`) - this checks the
/// second whitespace-separated field specifically, not a substring
/// search, so a key that happens to be a prefix of another entry's
/// pattern (or of its `id`) can never produce a false match.
fn haproxy_acl_contains_key(raw_response: &str, key: &str) -> bool {
    raw_response.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let _id = fields.next();
        fields.next() == Some(key)
    })
}

/// HAProxy Runtime API adapter - implements the same [`FirewallAdapter`]
/// contract as [`NftablesAdapter`], over its admin socket's line-oriented
/// text protocol instead of subprocess argv. There is still no shell to
/// inject into (a `tokio::net::UnixStream` write, never a subprocess at
/// all), and command construction only ever uses `key` values that
/// already passed [`FirewallTarget::validate`] (`parse_ip_or_cidr`) -
/// syntactically constrained to `[0-9a-fA-F:./]`, so a key can never
/// contain whitespace or a newline that could inject a second command
/// into the line-oriented protocol, the same guarantee explicit-argv
/// construction gives `NftablesAdapter` against a real shell.
///
/// Scope: only the roadmap's "Maps/ACLs" half - blocking a source
/// IP/CIDR via a Runtime API ACL pattern list, verified and rolled back
/// the same way `NftablesAdapter` verifies/rolls back a set element.
/// Rate-limiting (HAProxy stick-tables) is materially different (a
/// counter/threshold, not a membership set) and is **not** built here -
/// see `docs/firewall-agent.md`.
pub struct HaproxyAdapter {
    admin_socket: String,
    acl_file: String,
    /// Same never-block exclusion list as `NftablesAdapter`, loaded the
    /// same way - see `check_never_block`'s own doc comment for why this
    /// is a field every adapter carries rather than a check only the
    /// first adapter built happened to remember.
    never_block: Result<Vec<(IpAddr, u8)>, String>,
}

impl HaproxyAdapter {
    pub fn new() -> Self {
        Self {
            admin_socket: std::env::var("CLAWFORGE_HAPROXY_ADMIN_SOCKET")
                .unwrap_or_else(|_| HAPROXY_DEFAULT_ADMIN_SOCKET.to_string()),
            acl_file: std::env::var("CLAWFORGE_HAPROXY_BLOCKLIST_ACL_FILE")
                .unwrap_or_else(|_| HAPROXY_DEFAULT_BLOCKLIST_ACL_FILE.to_string()),
            never_block: never_block_list_from_env(),
        }
    }

    #[cfg(unix)]
    async fn run_command(&self, command: &str) -> Result<String, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;
        let mut stream = UnixStream::connect(&self.admin_socket)
            .await
            .map_err(|error| format!("connecting to {}: {error}", self.admin_socket))?;
        stream
            .write_all(command.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|error| error.to_string())?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        Ok(response)
    }

    #[cfg(not(unix))]
    async fn run_command(&self, _command: &str) -> Result<String, String> {
        Err("the HAProxy Runtime API requires a Unix domain socket".to_string())
    }
}

impl Default for HaproxyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallAdapter for HaproxyAdapter {
    fn name(&self) -> &'static str {
        "haproxy"
    }

    async fn preflight(&self, target: &FirewallTarget) -> Result<Preflight, AdapterError> {
        target.validate()?;
        if matches!(target, FirewallTarget::IncidentSource { .. }) {
            // Same "cannot guess" reasoning as NftablesAdapter::preflight
            // for an unresolved incident source.
            return Ok(Preflight {
                already_blocked: false,
                raw_set_json: String::new(),
            });
        }
        let element = element_reference(target)?;
        let response = self
            .run_command(&haproxy_show_acl_command(&self.acl_file))
            .await
            .map_err(AdapterError::Preflight)?;
        Ok(Preflight {
            already_blocked: haproxy_acl_contains_key(&response, &element),
            raw_set_json: response,
        })
    }

    fn render(&self, action: &FirewallAction) -> Result<FirewallActionReceipt, AdapterError> {
        if let FirewallTarget::ResolvedIncidentSource { .. } = &action.target {
            return Err(AdapterError::InvalidTarget(
                "a resolved incident source must never be rendered into a receipt".into(),
            ));
        }
        action.target.validate()?;
        check_never_block(&self.never_block, &action.target)?;
        let element = element_reference(&action.target)?;
        Ok(FirewallActionReceipt {
            adapter: self.name(),
            rendered_commands: vec![vec![haproxy_add_acl_command(&self.acl_file, &element)]],
            rollback_commands: vec![vec![haproxy_del_acl_command(&self.acl_file, &element)]],
            is_dry_run: true,
            ttl_seconds: action.ttl_seconds,
            target_fingerprint: element,
        })
    }

    async fn apply(
        &self,
        action: &FirewallAction,
        dry_run: bool,
    ) -> Result<ApplyResult, AdapterError> {
        action.target.validate()?;
        require_resolved_target(&action.target)?;
        check_never_block(&self.never_block, &action.target)?;
        let element = element_reference(&action.target)?;
        // Safe to persist - never the raw IP `element` resolves to for a
        // `ResolvedIncidentSource` (see `redacted_element_reference`'s own
        // doc comment). Only used to build the receipt, never the real
        // command below.
        let receipt_element = redacted_element_reference(&action.target)?;
        let add = haproxy_add_acl_command(&self.acl_file, &element);
        let receipt_add = haproxy_add_acl_command(&self.acl_file, &receipt_element);
        let receipt_delete = haproxy_del_acl_command(&self.acl_file, &receipt_element);
        if dry_run {
            return Ok(ApplyResult {
                receipt: FirewallActionReceipt {
                    adapter: self.name(),
                    rendered_commands: vec![vec![receipt_add]],
                    rollback_commands: vec![vec![receipt_delete]],
                    is_dry_run: true,
                    ttl_seconds: action.ttl_seconds,
                    target_fingerprint: receipt_element,
                },
                observed_state: None,
            });
        }
        let response = self.run_command(&add).await.map_err(AdapterError::Apply)?;
        if !response.trim().is_empty() {
            // The Runtime API returns empty output on success for
            // add/del acl - any non-empty response is an error message.
            return Err(AdapterError::Apply(format!(
                "haproxy runtime API rejected {add:?}: {}",
                response.trim()
            )));
        }
        let listing = self
            .run_command(&haproxy_show_acl_command(&self.acl_file))
            .await
            .map_err(AdapterError::Apply)?;
        Ok(ApplyResult {
            receipt: FirewallActionReceipt {
                adapter: self.name(),
                rendered_commands: vec![vec![receipt_add]],
                rollback_commands: vec![vec![receipt_delete]],
                is_dry_run: false,
                ttl_seconds: action.ttl_seconds,
                target_fingerprint: receipt_element,
            },
            observed_state: Some(listing),
        })
    }

    async fn verify(&self, target: &FirewallTarget) -> Result<VerificationResult, AdapterError> {
        target.validate()?;
        require_resolved_target(target)?;
        let element = element_reference(target)?;
        let response = self
            .run_command(&haproxy_show_acl_command(&self.acl_file))
            .await
            .map_err(AdapterError::Verify)?;
        if haproxy_acl_contains_key(&response, &element) {
            Ok(VerificationResult::Verified)
        } else {
            Ok(VerificationResult::NotPresent)
        }
    }

    async fn rollback(&self, action: &FirewallAction) -> Result<(), AdapterError> {
        action.target.validate()?;
        require_resolved_target(&action.target)?;
        let element = element_reference(&action.target)?;
        let delete = haproxy_del_acl_command(&self.acl_file, &element);
        let response = self
            .run_command(&delete)
            .await
            .map_err(AdapterError::Rollback)?;
        if !response.trim().is_empty() {
            return Err(AdapterError::Rollback(format!(
                "haproxy runtime API rejected {delete:?}: {}",
                response.trim()
            )));
        }
        Ok(())
    }
}

/// The exclusively Clawforge-owned HAProxy stick-table - the "Rate-Limits"
/// half of the roadmap's HAProxy adapter, a genuinely different mechanism
/// from `HaproxyAdapter`'s ACL pattern file: a stick-table keys by
/// source, storing a general-purpose counter (`gpc0`) per key, and an
/// operator's own ACL denies traffic once that counter is non-zero. An
/// operator adds *one* stick-table definition and ACL/action pair to
/// whichever frontend(s) they want protected, ahead of time, out of band
/// (see `scripts/haproxy-clawforge-provision.sh`); this adapter only ever
/// sets or clears one key's `gpc0` via the Runtime API's `set table`/
/// `clear table` commands, never touches `haproxy.cfg`.
///
/// Why `gpc0` and not a real rate counter (`http_req_rate`, ...): HAProxy
/// computes a rate counter from a real sliding window of observed
/// traffic - it is not a simple value this adapter could just set to
/// "blocked" the way it can a general-purpose counter, and doing so
/// reliably across HAProxy versions is not something this increment
/// attempts. `gpc0` is the standard, version-stable mechanism for "flag
/// this key for a policy decision", which is exactly what a
/// Clawforge-driven block needs.
pub const HAPROXY_DEFAULT_RATE_LIMIT_TABLE: &str = "clawforge_ratelimit";

fn haproxy_show_table_command(table: &str) -> String {
    format!("show table {table}")
}

fn haproxy_set_table_gpc0_command(table: &str, key: &str) -> String {
    format!("set table {table} key {key} data.gpc0 1")
}

fn haproxy_clear_table_command(table: &str, key: &str) -> String {
    format!("clear table {table} key {key}")
}

/// Whether `key` appears in a `show table <table>` response with a
/// non-zero `gpc0` - HAProxy's own format is `key=<key> use=... exp=...
/// gpc0=<n>` per matching line (exact field order/set varies by
/// configured `store` options, so this scans whitespace-separated
/// `key=value` tokens rather than assuming fixed positions).
fn haproxy_table_key_is_flagged(raw_response: &str, key: &str) -> bool {
    raw_response.lines().any(|line| {
        let mut matches_key = false;
        let mut gpc0_is_nonzero = false;
        for field in line.split_whitespace() {
            if let Some(value) = field.strip_prefix("key=") {
                matches_key = value == key;
            } else if let Some(value) = field.strip_prefix("gpc0=") {
                gpc0_is_nonzero = value.parse::<u64>().is_ok_and(|n| n > 0);
            }
        }
        matches_key && gpc0_is_nonzero
    })
}

/// HAProxy stick-table adapter - the "Rate-Limits" half of
/// [`FirewallAdapter`], alongside [`HaproxyAdapter`]'s "Maps/ACLs" half.
/// Same target types, same command-construction safety properties (a
/// `tokio::net::UnixStream` write, never a subprocess; `key` values are
/// always already-validated IP/CIDR text, never free-form).
pub struct HaproxyRateLimitAdapter {
    admin_socket: String,
    table: String,
    /// Same never-block exclusion list as `NftablesAdapter`/
    /// `HaproxyAdapter` - see `check_never_block`'s own doc comment.
    never_block: Result<Vec<(IpAddr, u8)>, String>,
}

impl HaproxyRateLimitAdapter {
    pub fn new() -> Self {
        Self {
            admin_socket: std::env::var("CLAWFORGE_HAPROXY_ADMIN_SOCKET")
                .unwrap_or_else(|_| HAPROXY_DEFAULT_ADMIN_SOCKET.to_string()),
            table: std::env::var("CLAWFORGE_HAPROXY_RATE_LIMIT_TABLE")
                .unwrap_or_else(|_| HAPROXY_DEFAULT_RATE_LIMIT_TABLE.to_string()),
            never_block: never_block_list_from_env(),
        }
    }

    #[cfg(unix)]
    async fn run_command(&self, command: &str) -> Result<String, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;
        let mut stream = UnixStream::connect(&self.admin_socket)
            .await
            .map_err(|error| format!("connecting to {}: {error}", self.admin_socket))?;
        stream
            .write_all(command.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|error| error.to_string())?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        Ok(response)
    }

    #[cfg(not(unix))]
    async fn run_command(&self, _command: &str) -> Result<String, String> {
        Err("the HAProxy Runtime API requires a Unix domain socket".to_string())
    }
}

impl Default for HaproxyRateLimitAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallAdapter for HaproxyRateLimitAdapter {
    fn name(&self) -> &'static str {
        "haproxy_ratelimit"
    }

    async fn preflight(&self, target: &FirewallTarget) -> Result<Preflight, AdapterError> {
        target.validate()?;
        if matches!(target, FirewallTarget::IncidentSource { .. }) {
            return Ok(Preflight {
                already_blocked: false,
                raw_set_json: String::new(),
            });
        }
        let element = element_reference(target)?;
        let response = self
            .run_command(&haproxy_show_table_command(&self.table))
            .await
            .map_err(AdapterError::Preflight)?;
        Ok(Preflight {
            already_blocked: haproxy_table_key_is_flagged(&response, &element),
            raw_set_json: response,
        })
    }

    fn render(&self, action: &FirewallAction) -> Result<FirewallActionReceipt, AdapterError> {
        if let FirewallTarget::ResolvedIncidentSource { .. } = &action.target {
            return Err(AdapterError::InvalidTarget(
                "a resolved incident source must never be rendered into a receipt".into(),
            ));
        }
        action.target.validate()?;
        check_never_block(&self.never_block, &action.target)?;
        let element = element_reference(&action.target)?;
        Ok(FirewallActionReceipt {
            adapter: self.name(),
            rendered_commands: vec![vec![haproxy_set_table_gpc0_command(&self.table, &element)]],
            rollback_commands: vec![vec![haproxy_clear_table_command(&self.table, &element)]],
            is_dry_run: true,
            ttl_seconds: action.ttl_seconds,
            target_fingerprint: element,
        })
    }

    async fn apply(
        &self,
        action: &FirewallAction,
        dry_run: bool,
    ) -> Result<ApplyResult, AdapterError> {
        action.target.validate()?;
        require_resolved_target(&action.target)?;
        check_never_block(&self.never_block, &action.target)?;
        let element = element_reference(&action.target)?;
        let receipt_element = redacted_element_reference(&action.target)?;
        let set = haproxy_set_table_gpc0_command(&self.table, &element);
        let receipt_set = haproxy_set_table_gpc0_command(&self.table, &receipt_element);
        let receipt_clear = haproxy_clear_table_command(&self.table, &receipt_element);
        if dry_run {
            return Ok(ApplyResult {
                receipt: FirewallActionReceipt {
                    adapter: self.name(),
                    rendered_commands: vec![vec![receipt_set]],
                    rollback_commands: vec![vec![receipt_clear]],
                    is_dry_run: true,
                    ttl_seconds: action.ttl_seconds,
                    target_fingerprint: receipt_element,
                },
                observed_state: None,
            });
        }
        let response = self.run_command(&set).await.map_err(AdapterError::Apply)?;
        if !response.trim().is_empty() {
            return Err(AdapterError::Apply(format!(
                "haproxy runtime API rejected {set:?}: {}",
                response.trim()
            )));
        }
        let listing = self
            .run_command(&haproxy_show_table_command(&self.table))
            .await
            .map_err(AdapterError::Apply)?;
        Ok(ApplyResult {
            receipt: FirewallActionReceipt {
                adapter: self.name(),
                rendered_commands: vec![vec![receipt_set]],
                rollback_commands: vec![vec![receipt_clear]],
                is_dry_run: false,
                ttl_seconds: action.ttl_seconds,
                target_fingerprint: receipt_element,
            },
            observed_state: Some(listing),
        })
    }

    async fn verify(&self, target: &FirewallTarget) -> Result<VerificationResult, AdapterError> {
        target.validate()?;
        require_resolved_target(target)?;
        let element = element_reference(target)?;
        let response = self
            .run_command(&haproxy_show_table_command(&self.table))
            .await
            .map_err(AdapterError::Verify)?;
        if haproxy_table_key_is_flagged(&response, &element) {
            Ok(VerificationResult::Verified)
        } else {
            Ok(VerificationResult::NotPresent)
        }
    }

    async fn rollback(&self, action: &FirewallAction) -> Result<(), AdapterError> {
        action.target.validate()?;
        require_resolved_target(&action.target)?;
        let element = element_reference(&action.target)?;
        let clear = haproxy_clear_table_command(&self.table, &element);
        let response = self
            .run_command(&clear)
            .await
            .map_err(AdapterError::Rollback)?;
        if !response.trim().is_empty() {
            return Err(AdapterError::Rollback(format!(
                "haproxy runtime API rejected {clear:?}: {}",
                response.trim()
            )));
        }
        Ok(())
    }
}

/// Picks the [`FirewallAdapter`] an `nftables.`/`haproxy.`/
/// `haproxy_ratelimit.`-prefixed action name (or a bare `adapter` column
/// value - `"nftables"`/`"haproxy"`/`"haproxy_ratelimit"`, no trailing
/// dot) routes to. `"haproxy_ratelimit"` is checked *before* the plain
/// `"haproxy"` prefix - `"haproxy_ratelimit..."` also starts with
/// `"haproxy"`, so checking the generic prefix first would silently route
/// rate-limit actions to the wrong (ACL) adapter.
///
/// A single shared function (moved here from what was originally
/// `clawforge-executor`'s own private `adapter_for`) rather than one copy
/// per caller, specifically so `clawforge-api`'s pre-approval action
/// preview (`GET /executions/{id}/detail`, see `docs/firewall-agent.md`'s
/// "Approval surface" section) can never drift from what
/// `clawforge-executor`'s real dispatch actually routes to - showing a
/// reviewer a preview from a routing table that could silently diverge
/// from the one that runs for real would defeat the point of a preview.
pub fn adapter_for_action(name: &str) -> Option<Box<dyn FirewallAdapter>> {
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

/// A device on the tailnet, identified the way Tailscale's own Admin API
/// identifies one - never an IP address (Tailscale addresses are stable
/// per-device, not the resource being acted on the way an nftables
/// target's address is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleTarget {
    pub device_id: String,
}

impl TailscaleTarget {
    fn validate(&self) -> Result<(), AdapterError> {
        if self.device_id.trim().is_empty() {
            return Err(AdapterError::InvalidTarget(
                "tailscale device_id must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TailscaleAction {
    pub target: TailscaleTarget,
    pub reason: String,
}

/// What a real call to the Tailscale Admin API *would* be - `render`
/// describes it, nothing ever executes it. See [`TailscaleAdapter`]'s own
/// doc comment for why there is no equivalent of `apply` at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleActionReceipt {
    pub adapter: &'static str,
    pub described_call: String,
}

const TAILSCALE_CLIENT_ID_FILE_VAR: &str = "CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID_FILE";
const TAILSCALE_CLIENT_ID_VAR: &str = "CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID";
const TAILSCALE_CLIENT_SECRET_FILE_VAR: &str = "CLAWFORGE_TAILSCALE_OAUTH_CLIENT_SECRET_FILE";
const TAILSCALE_CLIENT_SECRET_VAR: &str = "CLAWFORGE_TAILSCALE_OAUTH_CLIENT_SECRET";
/// Must match a `tagOwners` entry in the tailnet's own ACL policy, and
/// that policy's `acls` accept rule(s) must scope their `src` to
/// `autogroup:member` (or similar) rather than `*` - tagging a device
/// alone grants nothing, Tailscale ACLs are additive "accept" only; what
/// actually denies a tagged device is that it no longer matches
/// `autogroup:member`. See the module doc comment on
/// [`TailscaleAdapter`] for the full mechanism.
const TAILSCALE_DEFAULT_QUARANTINE_TAG: &str = "tag:clawforge-quarantine";
const TAILSCALE_API_BASE: &str = "https://api.tailscale.com/api/v2";

struct TailscaleCredentials {
    client_id: String,
    client_secret: String,
}

#[derive(serde::Deserialize)]
struct TailscaleTokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize, Default)]
struct TailscaleDeviceInfo {
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(serde::Serialize)]
struct TailscaleTagsRequest<'a> {
    tags: &'a [String],
}

/// The outcome of a real `apply` call - `applied: false` for a dry run
/// (nothing was called), mirroring `ApplyResult`'s own shape for the
/// `FirewallAdapter`-based adapters.
#[derive(Debug, Clone)]
pub struct TailscaleApplyResult {
    pub receipt: TailscaleActionReceipt,
    pub applied: bool,
}

/// Tailscale's own second increment: `apply`/`verify`/`rollback` now
/// exist and can genuinely call the real Tailscale Admin API - the first
/// increment (see the module doc comment) deliberately had none at all.
/// Not a [`FirewallAdapter`] implementation: a Tailscale device is
/// identified by its device ID, not an IP/CIDR - a genuinely different
/// resource shape from [`FirewallTarget`] (see [`TailscaleTarget`]'s own
/// doc comment) - so this has its own, parallel `apply`/`verify`/
/// `rollback` methods instead of sharing that trait.
///
/// ## The quarantine mechanism: a tag, not a "disable" call
///
/// Tailscale's ACL model has no "deny" - only additive "accept" rules,
/// default-deny for anything not explicitly granted. Tagging a device
/// removes it from `autogroup:member` (Tailscale's own "untagged member
/// device" group); an operator's own ACL policy is what actually decides
/// whether that then denies the device, by scoping its accept rule(s) to
/// `autogroup:member` rather than `*`. `apply` adds
/// `CLAWFORGE_TAILSCALE_QUARANTINE_TAG` (default
/// `tag:clawforge-quarantine`) to the device's *existing* tag list -
/// merged, not replaced: Tailscale's own tags endpoint replaces the whole
/// list, so this reads the current list first and only appends. `rollback`
/// removes just that one tag, leaving any others the device already had
/// untouched.
///
/// ## Rollback is not always fully automatic - a real platform constraint
///
/// Found live against the real API, not documented anywhere obvious
/// beforehand: Tailscale refuses to remove a device's *last* tag via this
/// endpoint (`HTTP 400 "tagged nodes cannot be untagged without reauth"`).
/// Converting a tagged device back to an untagged personal one requires
/// the device itself to prove control again (reauth), not just an API
/// call. For the common case (a previously untagged device that only ever
/// got the quarantine tag added), `rollback` therefore **cannot** complete
/// automatically: see `rollback`'s own doc comment for exactly what it
/// does instead (a clear, actionable error) and how an operator actually
/// clears it (device-side reauth, or the admin console).
///
/// ## Credentials
///
/// `CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID`/`_SECRET` (or their `_FILE`
/// variants, via `clawforge_secret::load_optional` - the same pattern
/// every other Clawforge service credential uses). `new` never fails even
/// when neither is configured (every adapter's constructor is infallible,
/// consistent with `NftablesAdapter`/`HaproxyAdapter`); every method that
/// would actually need them fails closed with a clear error instead - see
/// `credentials()`.
pub struct TailscaleAdapter {
    credentials: Result<TailscaleCredentials, String>,
    quarantine_tag: String,
    http: reqwest::Client,
}

impl TailscaleAdapter {
    pub fn new() -> Self {
        let credentials = match (
            clawforge_secret::load_optional(TAILSCALE_CLIENT_ID_FILE_VAR, TAILSCALE_CLIENT_ID_VAR),
            clawforge_secret::load_optional(
                TAILSCALE_CLIENT_SECRET_FILE_VAR,
                TAILSCALE_CLIENT_SECRET_VAR,
            ),
        ) {
            (Ok(Some(client_id)), Ok(Some(client_secret))) => Ok(TailscaleCredentials {
                client_id,
                client_secret,
            }),
            (Ok(None), Ok(None)) => {
                Err("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID/_SECRET are not configured".to_string())
            }
            (Ok(Some(_)), Ok(None)) | (Ok(None), Ok(Some(_))) => Err(
                "CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID and _SECRET must both be configured, or \
                 neither"
                    .to_string(),
            ),
            (Err(error), _) | (_, Err(error)) => Err(error.to_string()),
        };
        Self {
            credentials,
            quarantine_tag: std::env::var("CLAWFORGE_TAILSCALE_QUARANTINE_TAG")
                .unwrap_or_else(|_| TAILSCALE_DEFAULT_QUARANTINE_TAG.to_string()),
            http: reqwest::Client::new(),
        }
    }

    pub fn name(&self) -> &'static str {
        "tailscale"
    }

    /// Pure and synchronous, exactly like `NftablesAdapter::render` - no
    /// network, no filesystem, nothing but string formatting. Never needs
    /// credentials - it only describes what a real call would be.
    pub fn render(&self, action: &TailscaleAction) -> Result<TailscaleActionReceipt, AdapterError> {
        action.target.validate()?;
        Ok(TailscaleActionReceipt {
            adapter: self.name(),
            described_call: format!(
                "POST {TAILSCALE_API_BASE}/device/{}/tags (add {}, preserving existing tags) \
                 (reason: {})",
                action.target.device_id, self.quarantine_tag, action.reason
            ),
        })
    }

    fn credentials(&self) -> Result<&TailscaleCredentials, AdapterError> {
        self.credentials.as_ref().map_err(|error| {
            AdapterError::InvalidTarget(format!(
                "Tailscale credentials are not configured: {error}"
            ))
        })
    }

    async fn access_token(&self) -> Result<String, AdapterError> {
        let credentials = self.credentials()?;
        let response = self
            .http
            .post(format!("{TAILSCALE_API_BASE}/oauth/token"))
            .form(&[
                ("client_id", &credentials.client_id),
                ("client_secret", &credentials.client_secret),
            ])
            .send()
            .await
            .map_err(|error| {
                AdapterError::Apply(format!("tailscale oauth token request failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(AdapterError::Apply(format!(
                "tailscale oauth token request rejected: HTTP {}",
                response.status()
            )));
        }
        let token: TailscaleTokenResponse = response.json().await.map_err(|error| {
            AdapterError::Apply(format!(
                "tailscale oauth token response was not valid JSON: {error}"
            ))
        })?;
        Ok(token.access_token)
    }

    async fn device_tags(&self, device_id: &str) -> Result<Vec<String>, AdapterError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .get(format!(
                "{TAILSCALE_API_BASE}/device/{device_id}?fields=all"
            ))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|error| {
                AdapterError::Verify(format!("tailscale device lookup failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(AdapterError::Verify(format!(
                "tailscale device lookup rejected: HTTP {}",
                response.status()
            )));
        }
        let info: TailscaleDeviceInfo = response.json().await.map_err(|error| {
            AdapterError::Verify(format!(
                "tailscale device response was not valid JSON: {error}"
            ))
        })?;
        Ok(info.tags)
    }

    async fn set_device_tags(&self, device_id: &str, tags: &[String]) -> Result<(), AdapterError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .post(format!("{TAILSCALE_API_BASE}/device/{device_id}/tags"))
            .bearer_auth(token)
            .json(&TailscaleTagsRequest { tags })
            .send()
            .await
            .map_err(|error| {
                AdapterError::Apply(format!("tailscale set-tags request failed: {error}"))
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AdapterError::Apply(format!(
                "tailscale set-tags rejected: HTTP {status}: {body}"
            )));
        }
        Ok(())
    }

    /// `dry_run: true` behaves exactly like `render` (no network call at
    /// all, and does not even require credentials to be configured, the
    /// same "dry run never touches real infra" property every other
    /// adapter's `apply` already has). `dry_run: false` reads the
    /// device's current tags, adds the quarantine tag if not already
    /// present (idempotent - a repeat apply is a no-op past the first
    /// one), and writes the merged list back.
    pub async fn apply(
        &self,
        action: &TailscaleAction,
        dry_run: bool,
    ) -> Result<TailscaleApplyResult, AdapterError> {
        action.target.validate()?;
        let receipt = self.render(action)?;
        if dry_run {
            return Ok(TailscaleApplyResult {
                receipt,
                applied: false,
            });
        }
        let mut tags = self.device_tags(&action.target.device_id).await?;
        if !tags.iter().any(|tag| tag == &self.quarantine_tag) {
            tags.push(self.quarantine_tag.clone());
            self.set_device_tags(&action.target.device_id, &tags)
                .await?;
        }
        Ok(TailscaleApplyResult {
            receipt,
            applied: true,
        })
    }

    pub async fn verify(
        &self,
        target: &TailscaleTarget,
    ) -> Result<VerificationResult, AdapterError> {
        target.validate()?;
        let tags = self.device_tags(&target.device_id).await?;
        if tags.iter().any(|tag| tag == &self.quarantine_tag) {
            Ok(VerificationResult::Verified)
        } else {
            Ok(VerificationResult::NotPresent)
        }
    }

    /// Removes only the quarantine tag, preserving any other tags the
    /// device already had - never a blind overwrite with an empty list.
    /// **A real, platform-level constraint, found live against the real
    /// API, not documented anywhere obvious beforehand**: Tailscale
    /// refuses to fully untag a device via this endpoint - going from one
    /// or more tags to *zero* tags returns `HTTP 400 "tagged nodes cannot
    /// be untagged without reauth"`. This is deliberate on Tailscale's
    /// part (converting a tagged/service identity back to an untagged
    /// personal device is a meaningful trust change, gated on the device
    /// itself proving control again) - not a bug in this adapter, and not
    /// something any API call can work around. For the common case (a
    /// previously untagged device that only ever had the quarantine tag
    /// added), this means `rollback` **cannot** complete automatically:
    /// it detects this case before attempting the doomed API call and
    /// returns a clear, actionable error instead of a confusing HTTP 400
    /// passthrough - un-quarantining then requires the device itself to
    /// reauth (open the Tailscale app and log in again, or run
    /// `tailscale up`), or an operator using the admin console instead
    /// (which may handle this differently). If the device has *other*
    /// tags besides the quarantine one, removing just the quarantine tag
    /// leaves a non-empty list and works via the API exactly as
    /// expected - only the "quarantine tag was the device's only tag"
    /// case hits this constraint.
    pub async fn rollback(&self, action: &TailscaleAction) -> Result<(), AdapterError> {
        action.target.validate()?;
        let tags = self.device_tags(&action.target.device_id).await?;
        if !tags.iter().any(|tag| tag == &self.quarantine_tag) {
            // Idempotent success, deliberately *not* an error (unlike
            // NftablesAdapter's "rollback of something never applied
            // fails cleanly" precedent): a device the operator has since
            // manually reauth'd to clear the tag ends up in exactly this
            // state, and clawforge-executor's TTL sweep needs rollback to
            // succeed then so it can record the rollback receipt and stop
            // retrying - erroring here would make it retry forever even
            // after the real problem is already resolved.
            return Ok(());
        }
        let remaining: Vec<String> = tags
            .into_iter()
            .filter(|tag| tag != &self.quarantine_tag)
            .collect();
        if remaining.is_empty() {
            return Err(AdapterError::Rollback(format!(
                "cannot remove the last tag from device {} via the API - Tailscale requires \
                 the device itself to reauth (open the Tailscale app and log in again, or run \
                 `tailscale up`) to fully untag a node; this is a Tailscale platform \
                 constraint, not something this adapter can complete automatically",
                action.target.device_id
            )));
        }
        self.set_device_tags(&action.target.device_id, &remaining)
            .await
    }
}

impl Default for TailscaleAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indicator(cidr: &str) -> FirewallTarget {
        FirewallTarget::ThreatIntelIndicator {
            cidr: cidr.to_string(),
            source: "spamhaus_drop".to_string(),
        }
    }

    #[test]
    fn try_from_json_parses_both_target_kinds() {
        let indicator_json = serde_json::json!({
            "kind": "threat_intel_indicator",
            "cidr": "203.0.113.0/24",
            "source": "spamhaus_drop",
        });
        assert_eq!(
            FirewallTarget::try_from(&indicator_json).unwrap(),
            indicator("203.0.113.0/24")
        );
        let incident_json = serde_json::json!({
            "kind": "incident_source",
            "pseudonym": "ip-pseudonym:abc123",
        });
        assert_eq!(
            FirewallTarget::try_from(&incident_json).unwrap(),
            FirewallTarget::IncidentSource {
                pseudonym: "ip-pseudonym:abc123".into()
            }
        );
    }

    #[test]
    fn try_from_json_rejects_an_unknown_or_missing_kind() {
        assert!(FirewallTarget::try_from(&serde_json::json!({})).is_err());
        assert!(FirewallTarget::try_from(&serde_json::json!({"kind": "teleport"})).is_err());
        assert!(FirewallTarget::try_from(&serde_json::json!({
            "kind": "threat_intel_indicator",
            "cidr": "not-an-ip",
            "source": "x",
        }))
        .is_err());
    }

    #[test]
    fn valid_ip_and_cidr_targets_are_accepted() {
        assert!(indicator("203.0.113.7").validate().is_ok());
        assert!(indicator("203.0.113.0/24").validate().is_ok());
        assert!(indicator("2001:db8::1").validate().is_ok());
        assert!(indicator("2001:db8::/32").validate().is_ok());
    }

    #[test]
    fn malformed_targets_are_rejected_before_any_command_is_built() {
        assert!(indicator("not-an-ip").validate().is_err());
        assert!(indicator("203.0.113.7/99").validate().is_err());
        assert!(indicator("; rm -rf /").validate().is_err());
        assert!(indicator("").validate().is_err());
        assert_eq!(
            FirewallTarget::ThreatIntelIndicator {
                cidr: "203.0.113.7".into(),
                source: "".into(),
            }
            .validate(),
            Err(AdapterError::InvalidTarget(
                "threat-intel indicator source must not be empty".into()
            ))
        );
    }

    #[test]
    fn incident_source_requires_the_pseudonym_prefix() {
        assert!(FirewallTarget::IncidentSource {
            pseudonym: "ip-pseudonym:abc123".into(),
        }
        .validate()
        .is_ok());
        assert!(FirewallTarget::IncidentSource {
            pseudonym: "203.0.113.7".into(),
        }
        .validate()
        .is_err());
        assert!(FirewallTarget::IncidentSource {
            pseudonym: "ip-pseudonym:".into(),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn ipv4_mapped_ipv6_normalizes_to_plain_ipv4() {
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        assert_eq!(
            normalize_address(mapped),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        // A real (non-mapped) IPv6 address passes through unchanged.
        let real_v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(normalize_address(real_v6), real_v6);
    }

    #[test]
    fn set_selection_follows_the_normalized_address_family() {
        assert_eq!(
            indicator("203.0.113.7").set_name().unwrap(),
            Some(NFTABLES_BLOCKLIST_SET_V4)
        );
        assert_eq!(
            indicator("::ffff:203.0.113.7").set_name().unwrap(),
            Some(NFTABLES_BLOCKLIST_SET_V4),
            "an IPv4-mapped IPv6 address must select the IPv4 set, not the IPv6 one"
        );
        assert_eq!(
            indicator("2001:db8::1").set_name().unwrap(),
            Some(NFTABLES_BLOCKLIST_SET_V6)
        );
        assert_eq!(
            FirewallTarget::IncidentSource {
                pseudonym: "ip-pseudonym:abc".into(),
            }
            .set_name()
            .unwrap(),
            None
        );
    }

    #[test]
    fn render_never_embeds_a_resolved_ip_for_an_incident_source() {
        let adapter = NftablesAdapter::new();
        let action = FirewallAction {
            target: FirewallTarget::IncidentSource {
                pseudonym: "ip-pseudonym:deadbeef".into(),
            },
            ttl_seconds: 3600,
            reason: "test".into(),
        };
        let receipt = adapter.render(&action).unwrap();
        let rendered = format!("{:?}", receipt.rendered_commands);
        assert!(rendered.contains("ip-pseudonym:deadbeef"));
        assert!(rendered.contains("<resolved-at-apply-time:"));
        assert!(receipt.is_dry_run);
    }

    /// The bug this pins down: `apply`'s own receipt (unlike `render`,
    /// which outright refuses `ResolvedIncidentSource`) used to embed the
    /// real resolved IP in `rendered_commands`/`rollback_commands` -
    /// exactly what `record_firewall_action_receipt` (added later the
    /// same session) then persisted straight into Postgres, defeating the
    /// whole point of `render`'s own refusal. Uses `dry_run: true` so no
    /// real nft/haproxy is needed - the redaction happens before the
    /// dry-run/real branch, so this exercises the same code path a real
    /// apply's receipt construction does.
    #[tokio::test]
    async fn nftables_apply_receipt_never_embeds_the_resolved_raw_ip() {
        let adapter = NftablesAdapter::new();
        let action = FirewallAction {
            target: FirewallTarget::ResolvedIncidentSource {
                raw_ip: "203.0.113.205".into(),
                pseudonym: "ip-pseudonym:deadbeef".into(),
            },
            ttl_seconds: 3600,
            reason: "test".into(),
        };
        let applied = adapter.apply(&action, true).await.unwrap();
        let rendered = format!(
            "{:?} {:?} {}",
            applied.receipt.rendered_commands,
            applied.receipt.rollback_commands,
            applied.receipt.target_fingerprint
        );
        assert!(
            !rendered.contains("203.0.113.205"),
            "the raw resolved IP must never appear in anything apply's receipt returns: {rendered}"
        );
        assert!(rendered.contains("ip-pseudonym:deadbeef"));
        assert!(rendered.contains("<resolved-at-apply-time:"));
    }

    #[tokio::test]
    async fn haproxy_apply_receipt_never_embeds_the_resolved_raw_ip() {
        let adapter = HaproxyAdapter::new();
        let action = FirewallAction {
            target: FirewallTarget::ResolvedIncidentSource {
                raw_ip: "203.0.113.205".into(),
                pseudonym: "ip-pseudonym:deadbeef".into(),
            },
            ttl_seconds: 3600,
            reason: "test".into(),
        };
        let applied = adapter.apply(&action, true).await.unwrap();
        let rendered = format!(
            "{:?} {:?} {}",
            applied.receipt.rendered_commands,
            applied.receipt.rollback_commands,
            applied.receipt.target_fingerprint
        );
        assert!(
            !rendered.contains("203.0.113.205"),
            "the raw resolved IP must never appear in anything apply's receipt returns: {rendered}"
        );
        assert!(rendered.contains("ip-pseudonym:deadbeef"));
    }

    fn action_for(target: FirewallTarget) -> FirewallAction {
        FirewallAction {
            target,
            ttl_seconds: 3600,
            reason: "test".into(),
        }
    }

    #[test]
    fn haproxy_table_key_is_flagged_matches_a_nonzero_gpc0_for_the_right_key() {
        let response =
            "key=203.0.113.5 use=1 exp=59000 gpc0=1\nkey=203.0.113.6 use=1 exp=59000 gpc0=0\n";
        assert!(haproxy_table_key_is_flagged(response, "203.0.113.5"));
        assert!(
            !haproxy_table_key_is_flagged(response, "203.0.113.6"),
            "a zero gpc0 must not count as flagged"
        );
        assert!(
            !haproxy_table_key_is_flagged(response, "203.0.113.7"),
            "a key that isn't in the table at all must not count as flagged"
        );
    }

    #[test]
    fn haproxy_table_key_is_flagged_is_false_for_an_empty_response() {
        assert!(!haproxy_table_key_is_flagged("", "203.0.113.5"));
    }

    #[test]
    fn haproxy_ratelimit_render_embeds_the_real_cidr_and_never_resolves_an_incident_source() {
        let adapter = HaproxyRateLimitAdapter::new();
        let receipt = adapter
            .render(&action_for(indicator("203.0.113.10")))
            .unwrap();
        assert_eq!(receipt.adapter, "haproxy_ratelimit");
        let rendered = format!("{:?}", receipt.rendered_commands);
        assert!(rendered.contains("set table"));
        assert!(rendered.contains("data.gpc0"));
        assert!(rendered.contains("203.0.113.10"));

        let incident_receipt = adapter
            .render(&action_for(FirewallTarget::IncidentSource {
                pseudonym: "ip-pseudonym:deadbeef".into(),
            }))
            .unwrap();
        let rendered = format!("{:?}", incident_receipt.rendered_commands);
        assert!(rendered.contains("<resolved-at-apply-time:"));
        assert!(rendered.contains("ip-pseudonym:deadbeef"));
    }

    #[test]
    fn haproxy_ratelimit_render_refuses_a_resolved_incident_source_outright() {
        let adapter = HaproxyRateLimitAdapter::new();
        let action = action_for(FirewallTarget::ResolvedIncidentSource {
            raw_ip: "203.0.113.10".into(),
            pseudonym: "ip-pseudonym:deadbeef".into(),
        });
        assert!(adapter.render(&action).is_err());
    }

    #[tokio::test]
    async fn haproxy_ratelimit_apply_verify_rollback_all_refuse_an_unresolved_incident_source() {
        let adapter = HaproxyRateLimitAdapter::new();
        let action = action_for(FirewallTarget::IncidentSource {
            pseudonym: "ip-pseudonym:never-resolved".into(),
        });
        assert!(adapter.apply(&action, true).await.is_err());
        assert!(adapter.verify(&action.target).await.is_err());
        assert!(adapter.rollback(&action).await.is_err());
    }

    #[tokio::test]
    async fn haproxy_ratelimit_apply_with_dry_run_never_touches_the_socket() {
        // No CLAWFORGE_HAPROXY_ADMIN_SOCKET set, no haproxy running here -
        // a dry-run apply must still succeed, proving it never actually
        // connects to the admin socket. No other test in this binary sets
        // this specific env var.
        std::env::remove_var("CLAWFORGE_HAPROXY_ADMIN_SOCKET");
        let adapter = HaproxyRateLimitAdapter::new();
        let result = adapter
            .apply(&action_for(indicator("203.0.113.10")), true)
            .await;
        assert!(
            result.is_ok(),
            "dry-run apply must not need a real socket: {result:?}"
        );
    }

    #[tokio::test]
    async fn haproxy_ratelimit_apply_receipt_never_embeds_the_resolved_raw_ip() {
        let adapter = HaproxyRateLimitAdapter::new();
        let action = FirewallAction {
            target: FirewallTarget::ResolvedIncidentSource {
                raw_ip: "203.0.113.205".into(),
                pseudonym: "ip-pseudonym:deadbeef".into(),
            },
            ttl_seconds: 3600,
            reason: "test".into(),
        };
        let applied = adapter.apply(&action, true).await.unwrap();
        let rendered = format!(
            "{:?} {:?} {}",
            applied.receipt.rendered_commands,
            applied.receipt.rollback_commands,
            applied.receipt.target_fingerprint
        );
        assert!(
            !rendered.contains("203.0.113.205"),
            "the raw resolved IP must never appear in anything apply's receipt returns: {rendered}"
        );
        assert!(rendered.contains("ip-pseudonym:deadbeef"));
    }

    #[test]
    fn never_block_list_always_includes_the_builtin_safety_net_even_with_no_config() {
        let list = never_block_list_from_configured(None).unwrap();
        assert!(list.contains(&("127.0.0.0".parse().unwrap(), 8)));
        assert!(list.contains(&("::1".parse().unwrap(), 128)));
        assert!(list.contains(&("169.254.0.0".parse().unwrap(), 16)));
    }

    #[test]
    fn never_block_list_parses_a_configured_comma_separated_list() {
        let list =
            never_block_list_from_configured(Some(" 10.0.0.5/32 , 192.168.1.0/24 ")).unwrap();
        assert!(list.contains(&("10.0.0.5".parse().unwrap(), 32)));
        assert!(list.contains(&("192.168.1.0".parse().unwrap(), 24)));
    }

    #[test]
    fn a_malformed_configured_entry_fails_the_whole_list_closed() {
        assert!(never_block_list_from_configured(Some("not-an-ip")).is_err());
    }

    #[test]
    fn render_refuses_a_target_that_overlaps_a_configured_never_block_entry() {
        let adapter = NftablesAdapter {
            never_block: never_block_list_from_configured(Some("203.0.113.5/32")),
        };
        // The exact excluded /32 itself.
        assert!(adapter
            .render(&action_for(indicator("203.0.113.5")))
            .is_err());
        // A broader target CIDR that merely *contains* the excluded /32 -
        // must be caught too, not just an exact-address match.
        assert!(adapter
            .render(&action_for(indicator("203.0.113.0/24")))
            .is_err());
        // An address outside the exclusion must still render normally.
        assert!(adapter
            .render(&action_for(indicator("203.0.113.6")))
            .is_ok());
    }

    #[tokio::test]
    async fn apply_refuses_a_target_that_overlaps_the_builtin_loopback_exclusion() {
        let adapter = NftablesAdapter {
            never_block: never_block_list_from_configured(None),
        };
        let action = action_for(indicator("127.0.0.1"));
        let result = adapter.apply(&action, true).await;
        assert!(
            result.is_err(),
            "loopback must be refused even in dry_run mode, not only for a real apply"
        );
    }

    #[test]
    fn a_misconfigured_never_block_list_refuses_every_target_rather_than_silently_ignoring_it() {
        let adapter = NftablesAdapter {
            never_block: never_block_list_from_configured(Some("garbage")),
        };
        let error = adapter
            .render(&action_for(indicator("203.0.113.7")))
            .unwrap_err();
        assert!(format!("{error}").contains("misconfigured"));
    }

    #[test]
    fn render_refuses_a_resolved_incident_source_outright() {
        // The hard guardrail, not just the placeholder convention: even if
        // a caller mistakenly tries to render an already-resolved target,
        // it must fail rather than silently embed the raw IP.
        let adapter = NftablesAdapter::new();
        let action = FirewallAction {
            target: FirewallTarget::ResolvedIncidentSource {
                raw_ip: "203.0.113.7".into(),
                pseudonym: "ip-pseudonym:deadbeef".into(),
            },
            ttl_seconds: 3600,
            reason: "test".into(),
        };
        let error = adapter.render(&action).unwrap_err();
        assert!(matches!(error, AdapterError::InvalidTarget(_)));
    }

    #[test]
    fn render_embeds_the_real_cidr_for_a_threat_intel_target() {
        let adapter = NftablesAdapter::new();
        let action = FirewallAction {
            target: indicator("203.0.113.0/24"),
            ttl_seconds: 3600,
            reason: "test".into(),
        };
        let receipt = adapter.render(&action).unwrap();
        assert_eq!(
            receipt.rendered_commands[0],
            vec![
                "nft",
                "add",
                "element",
                "inet",
                "clawforge",
                "blocklist",
                "{",
                "203.0.113.0/24",
                "}"
            ]
        );
        assert_eq!(
            receipt.rollback_commands[0],
            vec![
                "nft",
                "delete",
                "element",
                "inet",
                "clawforge",
                "blocklist",
                "{",
                "203.0.113.0/24",
                "}"
            ]
        );
    }

    #[test]
    fn render_picks_the_v6_set_for_an_ipv6_target() {
        let adapter = NftablesAdapter::new();
        let action = FirewallAction {
            target: indicator("2001:db8::/32"),
            ttl_seconds: 60,
            reason: "test".into(),
        };
        let receipt = adapter.render(&action).unwrap();
        assert!(receipt.rendered_commands[0].contains(&"blocklist6".to_string()));
    }

    #[test]
    fn render_rejects_a_malformed_target_before_building_any_command() {
        let adapter = NftablesAdapter::new();
        let action = FirewallAction {
            target: indicator("not-an-ip"),
            ttl_seconds: 60,
            reason: "test".into(),
        };
        assert!(adapter.render(&action).is_err());
    }

    #[test]
    fn preflight_command_only_ever_lists_clawforges_own_set() {
        let args = NftablesAdapter::preflight_command(NFTABLES_BLOCKLIST_SET_V4);
        assert_eq!(
            args,
            vec!["nft", "-j", "list", "set", "inet", "clawforge", "blocklist"]
        );
    }

    /// A real `nft -j list set` capture (`scripts/test-firewall-lab.sh`,
    /// mixed plain-IP and CIDR elements) - proves `set_contains_target`
    /// against the actual JSON shape, not a guess at it. This is the fast,
    /// no-`nft`-required regression test for the bug the lab test caught
    /// live: a prefixed element's JSON has separate `addr`/`len` fields,
    /// never the combined `addr/len` text a naive string search looked for.
    const REAL_MIXED_SET_JSON: &str = r#"{"nftables": [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "s", "table": "t", "type": "ipv4_addr", "handle": 1, "flags": ["interval"], "elem": [{"prefix": {"addr": "198.51.100.0", "len": 24}}, "203.0.113.7"]}}]}"#;

    #[test]
    fn set_contains_target_matches_a_prefixed_element_structurally() {
        let addr = "198.51.100.0".parse().unwrap();
        assert!(set_contains_target(REAL_MIXED_SET_JSON, addr, Some(24)));
        // The same address at a *different* prefix length must not match -
        // this is a genuinely different element.
        assert!(!set_contains_target(REAL_MIXED_SET_JSON, addr, Some(25)));
        // And without a prefix at all (a bare-IP query against a
        // prefixed element) must not match either.
        assert!(!set_contains_target(REAL_MIXED_SET_JSON, addr, None));
    }

    #[test]
    fn set_contains_target_matches_a_plain_ip_element() {
        let addr = "203.0.113.7".parse().unwrap();
        assert!(set_contains_target(REAL_MIXED_SET_JSON, addr, None));
        // A bare-IP element does not have a prefix - querying with one
        // must not match.
        assert!(!set_contains_target(REAL_MIXED_SET_JSON, addr, Some(32)));
    }

    #[test]
    fn set_contains_target_is_false_for_an_absent_address() {
        let addr = "203.0.113.99".parse().unwrap();
        assert!(!set_contains_target(REAL_MIXED_SET_JSON, addr, None));
    }

    #[test]
    fn set_contains_target_handles_malformed_json_without_panicking() {
        assert!(!set_contains_target(
            "not json",
            "203.0.113.7".parse().unwrap(),
            None
        ));
        assert!(!set_contains_target(
            "{}",
            "203.0.113.7".parse().unwrap(),
            None
        ));
    }

    // --- Real-nftables tests below: require NET_ADMIN/NET_RAW and a
    // provisioned lab table (scripts/test-firewall-lab.sh), never run
    // against any real deployment host - see that script and the module
    // doc comment's "What changed" section.

    async fn lab_adapter() -> NftablesAdapter {
        NftablesAdapter::new()
    }

    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn apply_with_dry_run_true_never_touches_the_real_set() {
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: indicator("203.0.113.201"),
            ttl_seconds: 60,
            reason: "lab test".into(),
        };
        let before = adapter.preflight(&action.target).await.unwrap();
        assert!(!before.already_blocked);
        let result = adapter.apply(&action, true).await.unwrap();
        assert!(result.receipt.is_dry_run);
        assert!(result.observed_state.is_none());
        let after = adapter.preflight(&action.target).await.unwrap();
        assert!(
            !after.already_blocked,
            "dry_run:true must never actually add the element"
        );
    }

    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn apply_verify_rollback_round_trip_for_ipv4() {
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: indicator("203.0.113.202"),
            ttl_seconds: 60,
            reason: "lab test".into(),
        };
        let result = adapter.apply(&action, false).await.unwrap();
        assert!(!result.receipt.is_dry_run);
        assert!(result.observed_state.unwrap().contains("203.0.113.202"));
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter.rollback(&action).await.unwrap();
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn apply_verify_rollback_round_trip_for_ipv6() {
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: indicator("2001:db8:dead::/48"),
            ttl_seconds: 60,
            reason: "lab test".into(),
        };
        adapter.apply(&action, false).await.unwrap();
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter.rollback(&action).await.unwrap();
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn ipv4_mapped_ipv6_and_plain_ipv4_are_the_same_element_to_nftables() {
        // The exact scenario the normalization exists for: applying via
        // one syntax must be visible to a preflight/verify call using the
        // other syntax for the "same" address.
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: indicator("203.0.113.203"),
            ttl_seconds: 60,
            reason: "lab test".into(),
        };
        adapter.apply(&action, false).await.unwrap();
        let mapped_target = indicator("::ffff:203.0.113.203");
        assert_eq!(
            adapter.verify(&mapped_target).await.unwrap(),
            VerificationResult::Verified,
            "the same address via IPv4-mapped-IPv6 syntax must verify as present too"
        );
        adapter.rollback(&action).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn applying_the_same_element_twice_is_idempotent() {
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: indicator("203.0.113.204"),
            ttl_seconds: 60,
            reason: "lab test".into(),
        };
        adapter.apply(&action, false).await.unwrap();
        // nft's own "add element" is idempotent for an existing element by
        // default (no -e/--check needed) - a second apply must not error.
        let second = adapter.apply(&action, false).await;
        assert!(second.is_ok(), "a repeat apply must not fail: {second:?}");
        adapter.rollback(&action).await.unwrap();
    }

    /// Failure-injection scenario "konkurrierende Actions auf demselben
    /// Ziel" (roadmap): unlike
    /// `applying_the_same_element_twice_is_idempotent` (sequential), this
    /// runs two applies of the *same* target genuinely concurrently via
    /// `tokio::join!`, over two independent adapter instances (standing
    /// in for two dispatch paths racing on the same target) - proving
    /// neither errors, crashes, or corrupts the set under real
    /// concurrency, not just that idempotency holds when called twice in
    /// a row.
    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn concurrent_applies_of_the_same_target_never_corrupt_or_crash() {
        let action = FirewallAction {
            target: indicator("203.0.113.207"),
            ttl_seconds: 60,
            reason: "concurrency test".into(),
        };
        let adapter_a = lab_adapter().await;
        let adapter_b = lab_adapter().await;
        let (result_a, result_b) = tokio::join!(
            adapter_a.apply(&action, false),
            adapter_b.apply(&action, false)
        );
        assert!(result_a.is_ok(), "{result_a:?}");
        assert!(result_b.is_ok(), "{result_b:?}");
        assert_eq!(
            adapter_a.verify(&action.target).await.unwrap(),
            VerificationResult::Verified,
            "the target must end up genuinely blocked after two concurrent applies"
        );
        adapter_a.rollback(&action).await.unwrap();
        assert_eq!(
            adapter_a.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    /// The break-glass drill itself, rehearsed (not just documented) - see
    /// scripts/nftables-clawforge-break-glass.sh's own doc comment. Blocks
    /// a real target, confirms it is genuinely blocked, then runs the
    /// break-glass script and confirms the *entire* table is gone - not
    /// just the one element. Reprovisions afterwards (the lab's own
    /// provisioning script is idempotent) so whichever other `--ignored`
    /// test runs next in this same container still finds a properly
    /// provisioned table.
    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn break_glass_removes_every_trace_of_the_clawforge_table() {
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: indicator("203.0.113.222"),
            ttl_seconds: 60,
            reason: "break-glass drill".into(),
        };
        let applied = adapter
            .apply(&action, false)
            .await
            .expect("apply must succeed");
        assert!(!applied.receipt.is_dry_run);
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified,
            "the target must genuinely be blocked before the drill removes it"
        );

        let break_glass_script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../scripts/nftables-clawforge-break-glass.sh"
        );
        let status = tokio::process::Command::new("sh")
            .arg(break_glass_script)
            .status()
            .await
            .expect("the break-glass script must run");
        assert!(status.success(), "the break-glass script must exit 0");

        let listing = tokio::process::Command::new("nft")
            .args(["list", "table", "inet", "clawforge"])
            .output()
            .await
            .expect("nft must run");
        assert!(
            !listing.status.success(),
            "the entire clawforge table must be gone after break-glass, not just the one element"
        );

        let provision_script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../scripts/nftables-clawforge-provision.sh"
        );
        let reprovisioned = tokio::process::Command::new("sh")
            .arg(provision_script)
            .status()
            .await
            .expect("reprovisioning must run");
        assert!(
            reprovisioned.success(),
            "reprovisioning after the drill must succeed so later tests find a valid table"
        );
    }

    /// Failure-injection scenario "manuelle Drift" (roadmap): an operator
    /// (or anything else) removes a blocked element directly via `nft`,
    /// entirely outside Clawforge - the next `verify` call must detect
    /// that as drift (`NotPresent`), not keep reporting `Verified` from a
    /// stale in-memory assumption. `verify` re-checks live state every
    /// time, by design, so this is really a test that the manual removal
    /// itself worked as intended, proving there is nothing cached to go
    /// stale in the first place.
    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn verify_detects_manual_drift_after_an_out_of_band_removal() {
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: indicator("203.0.113.223"),
            ttl_seconds: 60,
            reason: "manual drift test".into(),
        };
        adapter
            .apply(&action, false)
            .await
            .expect("apply must succeed");
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );

        // Remove it directly via `nft`, bypassing the adapter entirely -
        // simulating an operator (or anything else) touching the set
        // out of band.
        let status = tokio::process::Command::new("nft")
            .args([
                "delete",
                "element",
                NFTABLES_FAMILY,
                NFTABLES_TABLE,
                NFTABLES_BLOCKLIST_SET_V4,
                "{",
                "203.0.113.223",
                "}",
            ])
            .status()
            .await
            .expect("nft must run");
        assert!(
            status.success(),
            "the out-of-band removal itself must succeed"
        );

        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent,
            "verify must detect the drift, not report stale Verified state"
        );
    }

    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn applying_an_unresolved_incident_source_fails_closed() {
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: FirewallTarget::IncidentSource {
                pseudonym: "ip-pseudonym:never-resolved".into(),
            },
            ttl_seconds: 60,
            reason: "lab test".into(),
        };
        let result = adapter.apply(&action, false).await;
        assert!(
            result.is_err(),
            "an unresolved incident source must never reach a real apply"
        );
    }

    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn a_resolved_incident_source_applies_and_rolls_back_correctly() {
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: FirewallTarget::ResolvedIncidentSource {
                raw_ip: "203.0.113.205".into(),
                pseudonym: "ip-pseudonym:resolved-test".into(),
            },
            ttl_seconds: 60,
            reason: "lab test".into(),
        };
        let applied = adapter.apply(&action, false).await.unwrap();
        // The real command that ran did use the raw IP (that's the whole
        // point - see the `verify` assertion right below, which only
        // passes if the real nftables set genuinely contains it) - but
        // the *receipt* returned to a caller (and, in production, the one
        // persisted to firewall_action_receipts) must never carry it.
        let rendered = format!(
            "{:?} {:?} {}",
            applied.receipt.rendered_commands,
            applied.receipt.rollback_commands,
            applied.receipt.target_fingerprint
        );
        assert!(
            !rendered.contains("203.0.113.205"),
            "a real apply's own receipt must never embed the resolved raw IP: {rendered}"
        );
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter.rollback(&action).await.unwrap();
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    #[ignore = "requires nftables (NET_ADMIN/NET_RAW) - run via scripts/test-firewall-lab.sh"]
    async fn rolling_back_an_element_that_was_never_applied_fails_cleanly() {
        // Simulates a crash-before-apply / lease-loss recovery path
        // attempting a rollback it does not actually need to perform -
        // must fail with a clear error, not panic or silently succeed.
        let adapter = lab_adapter().await;
        let action = FirewallAction {
            target: indicator("203.0.113.206"),
            ttl_seconds: 60,
            reason: "lab test".into(),
        };
        let result = adapter.rollback(&action).await;
        assert!(result.is_err());
    }

    /// Real-HAProxy tests below, run via scripts/test-haproxy-lab.sh
    /// against a disposable haproxy instance's own Runtime API socket -
    /// never against a real deployment. `lab_haproxy_adapter` reads
    /// `CLAWFORGE_HAPROXY_ADMIN_SOCKET`/`CLAWFORGE_HAPROXY_BLOCKLIST_ACL_FILE`
    /// the lab script exports, the same way `lab_adapter` implicitly
    /// relies on the nftables lab's own provisioning.
    fn lab_haproxy_adapter() -> HaproxyAdapter {
        HaproxyAdapter::new()
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_apply_verify_rollback_round_trip() {
        let adapter = lab_haproxy_adapter();
        let action = action_for(indicator("203.0.113.230"));
        let applied = adapter
            .apply(&action, false)
            .await
            .expect("apply must succeed");
        assert!(!applied.receipt.is_dry_run);
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter
            .rollback(&action)
            .await
            .expect("rollback must succeed");
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_apply_with_dry_run_true_never_touches_the_real_map() {
        let adapter = lab_haproxy_adapter();
        let action = action_for(indicator("203.0.113.231"));
        let applied = adapter
            .apply(&action, true)
            .await
            .expect("a dry-run apply must not need the real map");
        assert!(applied.receipt.is_dry_run);
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent,
            "a dry run must never actually touch the real map"
        );
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_applying_the_same_element_twice_is_idempotent() {
        // Unlike nftables' "add element" (idempotent by default), it is
        // not obvious from documentation alone whether HAProxy's "add
        // acl" rejects, ignores, or duplicates an already-present
        // pattern - the isolated lab is what actually answers this rather
        // than assumes it, exactly the kind of real behavioral gap
        // `set_contains_target`'s own bug (found this same way, earlier
        // this session) was.
        let adapter = lab_haproxy_adapter();
        let action = action_for(indicator("203.0.113.232"));
        adapter
            .apply(&action, false)
            .await
            .expect("first apply must succeed");
        let second = adapter.apply(&action, false).await;
        assert!(second.is_ok(), "a repeat apply must not error: {second:?}");
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified,
            "the key must still be found regardless of how many entries now exist for it"
        );
        // Roll back exactly once and check whether *any* trace remains -
        // this is the real question a caller cares about (is the target
        // still blocked), not how many literal map rows exist for it.
        adapter
            .rollback(&action)
            .await
            .expect("rollback must succeed");
        let after_one_rollback = adapter.verify(&action.target).await.unwrap();
        if after_one_rollback == VerificationResult::Verified {
            // A duplicate entry survived one rollback - roll back again
            // until it's actually gone, and document that apply is NOT
            // idempotent for HAProxy the way it is for nftables.
            adapter
                .rollback(&action)
                .await
                .expect("a second rollback must succeed if a duplicate entry remained");
        }
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent,
            "the target must be fully gone after enough rollbacks to match every apply"
        );
    }

    /// HAProxy analog of `concurrent_applies_of_the_same_target_never_
    /// corrupt_or_crash` - two genuinely concurrent applies of the same
    /// target over two independent adapter instances, over the real
    /// Runtime API socket.
    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_concurrent_applies_of_the_same_target_never_corrupt_or_crash() {
        let action = action_for(indicator("203.0.113.235"));
        let adapter_a = lab_haproxy_adapter();
        let adapter_b = lab_haproxy_adapter();
        let (result_a, result_b) = tokio::join!(
            adapter_a.apply(&action, false),
            adapter_b.apply(&action, false)
        );
        assert!(result_a.is_ok(), "{result_a:?}");
        assert!(result_b.is_ok(), "{result_b:?}");
        assert_eq!(
            adapter_a.verify(&action.target).await.unwrap(),
            VerificationResult::Verified,
            "the target must end up genuinely blocked after two concurrent applies"
        );
        // Same "may need more than one rollback" caveat as the sequential
        // idempotency test - HAProxy's add acl is not guaranteed
        // idempotent the way nftables' add element is.
        adapter_a
            .rollback(&action)
            .await
            .expect("rollback must succeed");
        if adapter_a.verify(&action.target).await.unwrap() == VerificationResult::Verified {
            adapter_a
                .rollback(&action)
                .await
                .expect("a second rollback must succeed if a duplicate entry remained");
        }
        assert_eq!(
            adapter_a.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_rolling_back_an_element_that_was_never_applied_fails_cleanly() {
        let adapter = lab_haproxy_adapter();
        let action = action_for(indicator("203.0.113.233"));
        let result = adapter.rollback(&action).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_a_resolved_incident_source_applies_and_rolls_back_correctly() {
        let adapter = lab_haproxy_adapter();
        let action = action_for(FirewallTarget::ResolvedIncidentSource {
            raw_ip: "203.0.113.234".into(),
            pseudonym: "ip-pseudonym:deadbeef".into(),
        });
        let applied = adapter
            .apply(&action, false)
            .await
            .expect("apply on a resolved incident source must succeed");
        let rendered = format!(
            "{:?} {:?} {}",
            applied.receipt.rendered_commands,
            applied.receipt.rollback_commands,
            applied.receipt.target_fingerprint
        );
        assert!(
            !rendered.contains("203.0.113.234"),
            "a real apply's own receipt must never embed the resolved raw IP: {rendered}"
        );
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter
            .rollback(&action)
            .await
            .expect("rollback must succeed");
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    /// Real-HAProxy stick-table tests below, run via the same
    /// scripts/test-haproxy-lab.sh - the lab's throwaway config declares
    /// an explicitly named backend/table (`clawforge_ratelimit`) the same
    /// way `scripts/haproxy-clawforge-provision.sh` instructs a real
    /// operator to.
    fn lab_haproxy_ratelimit_adapter() -> HaproxyRateLimitAdapter {
        HaproxyRateLimitAdapter::new()
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_ratelimit_apply_verify_rollback_round_trip() {
        let adapter = lab_haproxy_ratelimit_adapter();
        let action = action_for(indicator("203.0.113.240"));
        let applied = adapter
            .apply(&action, false)
            .await
            .expect("apply must succeed");
        assert!(!applied.receipt.is_dry_run);
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter
            .rollback(&action)
            .await
            .expect("rollback must succeed");
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_ratelimit_apply_with_dry_run_true_never_touches_the_real_table() {
        let adapter = lab_haproxy_ratelimit_adapter();
        let action = action_for(indicator("203.0.113.241"));
        let applied = adapter
            .apply(&action, true)
            .await
            .expect("a dry-run apply must not need the real table");
        assert!(applied.receipt.is_dry_run);
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent,
            "a dry run must never actually touch the real stick-table"
        );
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_ratelimit_applying_the_same_element_twice_is_idempotent() {
        // "set table ... data.gpc0 1" overwrites, unlike "add acl" -
        // verified here rather than assumed, the same discipline used
        // for the other two adapters.
        let adapter = lab_haproxy_ratelimit_adapter();
        let action = action_for(indicator("203.0.113.242"));
        adapter
            .apply(&action, false)
            .await
            .expect("first apply must succeed");
        let second = adapter.apply(&action, false).await;
        assert!(second.is_ok(), "a repeat apply must not error: {second:?}");
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter
            .rollback(&action)
            .await
            .expect("rollback must succeed");
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent,
            "one rollback must be enough - set/clear semantics are not additive the way HAProxy's own acl entries are"
        );
    }

    /// Unlike `del acl` (`haproxy_rolling_back_an_element_that_was_never_
    /// applied_fails_cleanly`, above), HAProxy's `clear table ... key ...`
    /// is idempotent - clearing a key that was never set (or already
    /// cleared) succeeds with an empty response rather than erroring.
    /// Confirmed live against the real Runtime API, not assumed: an
    /// earlier version of this test asserted the opposite (mirroring the
    /// ACL adapter's own behavior) and failed here, which is what caught
    /// the real semantic difference between the two HAProxy mechanisms.
    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_ratelimit_rolling_back_an_element_that_was_never_applied_is_idempotent() {
        let adapter = lab_haproxy_ratelimit_adapter();
        let action = action_for(indicator("203.0.113.243"));
        let result = adapter.rollback(&action).await;
        assert!(
            result.is_ok(),
            "clear table on an absent key must succeed, not error: {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_ratelimit_a_resolved_incident_source_applies_and_rolls_back_correctly() {
        let adapter = lab_haproxy_ratelimit_adapter();
        let action = action_for(FirewallTarget::ResolvedIncidentSource {
            raw_ip: "203.0.113.244".into(),
            pseudonym: "ip-pseudonym:deadbeef".into(),
        });
        let applied = adapter
            .apply(&action, false)
            .await
            .expect("apply on a resolved incident source must succeed");
        let rendered = format!(
            "{:?} {:?} {}",
            applied.receipt.rendered_commands,
            applied.receipt.rollback_commands,
            applied.receipt.target_fingerprint
        );
        assert!(
            !rendered.contains("203.0.113.244"),
            "a real apply's own receipt must never embed the resolved raw IP: {rendered}"
        );
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter
            .rollback(&action)
            .await
            .expect("rollback must succeed");
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    #[ignore = "requires a real HAProxy Runtime API socket - run via scripts/test-haproxy-lab.sh"]
    async fn haproxy_ratelimit_concurrent_applies_of_the_same_target_never_corrupt_or_crash() {
        let action = action_for(indicator("203.0.113.245"));
        let adapter_a = lab_haproxy_ratelimit_adapter();
        let adapter_b = lab_haproxy_ratelimit_adapter();
        let (result_a, result_b) = tokio::join!(
            adapter_a.apply(&action, false),
            adapter_b.apply(&action, false)
        );
        assert!(result_a.is_ok(), "{result_a:?}");
        assert!(result_b.is_ok(), "{result_b:?}");
        assert_eq!(
            adapter_a.verify(&action.target).await.unwrap(),
            VerificationResult::Verified
        );
        adapter_a.rollback(&action).await.unwrap();
        assert_eq!(
            adapter_a.verify(&action.target).await.unwrap(),
            VerificationResult::NotPresent
        );
    }

    #[test]
    fn tailscale_render_describes_the_call_it_would_make() {
        let adapter = TailscaleAdapter::new();
        let action = TailscaleAction {
            target: TailscaleTarget {
                device_id: "n123456CNTRL".into(),
            },
            reason: "corroborated incident abc-123".into(),
        };
        let receipt = adapter.render(&action).unwrap();
        assert_eq!(receipt.adapter, "tailscale");
        assert!(receipt.described_call.contains("n123456CNTRL"));
        assert!(receipt.described_call.contains("/tags"));
        assert!(receipt.described_call.contains("tag:clawforge-quarantine"));
        assert!(receipt
            .described_call
            .contains("corroborated incident abc-123"));
    }

    #[test]
    fn tailscale_render_rejects_an_empty_device_id_before_describing_anything() {
        let adapter = TailscaleAdapter::new();
        let action = TailscaleAction {
            target: TailscaleTarget {
                device_id: "   ".into(),
            },
            reason: "test".into(),
        };
        assert!(adapter.render(&action).is_err());
    }

    fn tailscale_action(device_id: &str) -> TailscaleAction {
        TailscaleAction {
            target: TailscaleTarget {
                device_id: device_id.to_string(),
            },
            reason: "test".into(),
        }
    }

    /// A dry-run apply must work even with zero Tailscale credentials
    /// configured - the same "dry run never touches real infra" property
    /// every other adapter's `apply` already has. No other test in this
    /// binary sets these specific env vars.
    #[tokio::test]
    async fn tailscale_dry_run_apply_never_needs_credentials() {
        std::env::remove_var("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID");
        std::env::remove_var("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID_FILE");
        std::env::remove_var("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_SECRET");
        std::env::remove_var("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_SECRET_FILE");
        let adapter = TailscaleAdapter::new();
        let result = adapter.apply(&tailscale_action("n123456CNTRL"), true).await;
        let applied = result.expect("dry-run apply must not need real credentials");
        assert!(!applied.applied);
    }

    /// A real (non-dry-run) call - apply, verify, or rollback - must fail
    /// closed with a clear error when credentials are not configured,
    /// never silently no-op or panic.
    #[tokio::test]
    async fn tailscale_real_calls_fail_closed_without_configured_credentials() {
        std::env::remove_var("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID");
        std::env::remove_var("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID_FILE");
        std::env::remove_var("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_SECRET");
        std::env::remove_var("CLAWFORGE_TAILSCALE_OAUTH_CLIENT_SECRET_FILE");
        let adapter = TailscaleAdapter::new();
        let action = tailscale_action("n123456CNTRL");
        assert!(adapter.apply(&action, false).await.is_err());
        assert!(adapter.verify(&action.target).await.is_err());
        assert!(adapter.rollback(&action).await.is_err());
    }

    #[test]
    fn tailscale_quarantine_tag_defaults_but_is_configurable() {
        std::env::remove_var("CLAWFORGE_TAILSCALE_QUARANTINE_TAG");
        assert_eq!(
            TailscaleAdapter::new().quarantine_tag,
            "tag:clawforge-quarantine"
        );
        std::env::set_var(
            "CLAWFORGE_TAILSCALE_QUARANTINE_TAG",
            "tag:custom-quarantine",
        );
        assert_eq!(
            TailscaleAdapter::new().quarantine_tag,
            "tag:custom-quarantine"
        );
        std::env::remove_var("CLAWFORGE_TAILSCALE_QUARANTINE_TAG");
    }

    /// A real, end-to-end round trip against the live Tailscale Admin API
    /// - deliberately NOT run in CI (there are no Tailscale credentials
    /// there, and unlike the disposable nftables/HAProxy labs, this talks
    /// to a real tailnet's real device, not a throwaway container). Run
    /// once by hand with CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID_FILE/
    /// CLAWFORGE_TAILSCALE_OAUTH_CLIENT_SECRET_FILE pointed at the real
    /// secret files and CLAWFORGE_TAILSCALE_TEST_DEVICE_ID set to a
    /// device explicitly chosen as safe to briefly quarantine (a phone,
    /// not a server with active sessions) - confirms apply/verify/
    /// rollback all work against the real API, not just that the request
    /// shapes compile.
    #[tokio::test]
    #[ignore = "requires real Tailscale credentials and a real, explicitly chosen test device - see this test's own doc comment"]
    async fn tailscale_real_apply_verify_rollback_round_trip() {
        let device_id = std::env::var("CLAWFORGE_TAILSCALE_TEST_DEVICE_ID")
            .expect("CLAWFORGE_TAILSCALE_TEST_DEVICE_ID must be set to run this test");
        let adapter = TailscaleAdapter::new();
        let action = tailscale_action(&device_id);

        // Real apply, from whatever state the device is actually in -
        // idempotent either way (a device that is already tagged just
        // stays tagged).
        let applied = adapter
            .apply(&action, false)
            .await
            .expect("a real apply must succeed");
        assert!(applied.applied);
        assert_eq!(
            adapter.verify(&action.target).await.unwrap(),
            VerificationResult::Verified,
            "the device must be genuinely tagged after a real apply"
        );

        // A repeat apply must not error or duplicate the tag.
        adapter
            .apply(&action, false)
            .await
            .expect("a repeat apply must not fail");

        // The real, live-discovered platform constraint (see rollback's
        // own doc comment): if the quarantine tag is the device's *only*
        // tag, Tailscale refuses to remove it via the API at all - proven
        // here against the real API, not assumed. This device has no
        // other tags, so rollback must fail with the specific, actionable
        // error this adapter now detects up front, not a raw HTTP 400.
        let error = adapter
            .rollback(&action)
            .await
            .expect_err("rollback of a device's only tag must fail, not silently succeed");
        let error_text = error.to_string();
        assert!(
            error_text.contains("reauth"),
            "the error must explain that device-side reauth is required: {error_text}"
        );
    }

    #[test]
    fn haproxy_acl_contains_key_matches_the_pattern_column_only() {
        // Real `show acl <file>` output shape, captured against a real
        // haproxy instance in scripts/test-haproxy-lab.sh: `<id>
        // <pattern>`, no third column (unlike HAProxy's separate `map`
        // mechanism, which this adapter does not use - see
        // `HaproxyAdapter`'s own doc comment).
        let response = "0x71d738032af0 203.0.113.5\n0x71d738032b10 198.51.100.0/24\n";
        assert!(haproxy_acl_contains_key(response, "203.0.113.5"));
        assert!(haproxy_acl_contains_key(response, "198.51.100.0/24"));
        assert!(!haproxy_acl_contains_key(response, "203.0.113.6"));
        // Must match the pattern column, not the id column.
        assert!(!haproxy_acl_contains_key(response, "0x71d738032af0"));
    }

    #[test]
    fn haproxy_acl_contains_key_is_false_for_an_empty_response() {
        assert!(!haproxy_acl_contains_key("", "203.0.113.5"));
    }

    #[test]
    fn haproxy_render_embeds_the_real_cidr_and_never_resolves_an_incident_source() {
        let adapter = HaproxyAdapter::new();
        let receipt = adapter
            .render(&action_for(indicator("203.0.113.9")))
            .unwrap();
        assert_eq!(receipt.adapter, "haproxy");
        let rendered = format!("{:?}", receipt.rendered_commands);
        assert!(rendered.contains("add acl"));
        assert!(rendered.contains("203.0.113.9"));

        let incident_receipt = adapter
            .render(&action_for(FirewallTarget::IncidentSource {
                pseudonym: "ip-pseudonym:deadbeef".into(),
            }))
            .unwrap();
        let rendered = format!("{:?}", incident_receipt.rendered_commands);
        assert!(rendered.contains("<resolved-at-apply-time:"));
        assert!(rendered.contains("ip-pseudonym:deadbeef"));
    }

    #[test]
    fn haproxy_render_refuses_a_resolved_incident_source_outright() {
        let adapter = HaproxyAdapter::new();
        let action = action_for(FirewallTarget::ResolvedIncidentSource {
            raw_ip: "203.0.113.9".into(),
            pseudonym: "ip-pseudonym:deadbeef".into(),
        });
        assert!(adapter.render(&action).is_err());
    }

    #[tokio::test]
    async fn haproxy_apply_verify_rollback_all_refuse_an_unresolved_incident_source() {
        let adapter = HaproxyAdapter::new();
        let action = action_for(FirewallTarget::IncidentSource {
            pseudonym: "ip-pseudonym:never-resolved".into(),
        });
        assert!(adapter.apply(&action, true).await.is_err());
        assert!(adapter.verify(&action.target).await.is_err());
        assert!(adapter.rollback(&action).await.is_err());
    }

    #[tokio::test]
    async fn haproxy_apply_with_dry_run_never_touches_the_socket() {
        // No CLAWFORGE_HAPROXY_ADMIN_SOCKET set, no haproxy running here -
        // a dry-run apply must still succeed, proving it never actually
        // connects to the admin socket. No other test in this binary sets
        // this specific env var.
        std::env::remove_var("CLAWFORGE_HAPROXY_ADMIN_SOCKET");
        let adapter = HaproxyAdapter::new();
        let result = adapter
            .apply(&action_for(indicator("203.0.113.9")), true)
            .await;
        assert!(
            result.is_ok(),
            "dry-run apply must not need a real socket: {result:?}"
        );
    }

    /// Proves the never-block refactor actually closed the gap: before
    /// it, `check_never_block` was an `NftablesAdapter`-only method never
    /// called by `HaproxyAdapter`/`HaproxyRateLimitAdapter` at all, so
    /// nothing protected a HAProxy-driven block from the same loopback/
    /// link-local/self-lockout targets `NftablesAdapter` already refused.
    #[tokio::test]
    async fn haproxy_apply_refuses_a_target_that_overlaps_the_builtin_loopback_exclusion() {
        let adapter = HaproxyAdapter::new();
        let result = adapter
            .apply(&action_for(indicator("127.0.0.1")), true)
            .await;
        assert!(
            result.is_err(),
            "loopback must be refused even in dry_run mode, not only for a real apply"
        );
    }

    #[tokio::test]
    async fn haproxy_ratelimit_apply_refuses_a_target_that_overlaps_the_builtin_loopback_exclusion()
    {
        let adapter = HaproxyRateLimitAdapter::new();
        let result = adapter
            .apply(&action_for(indicator("127.0.0.1")), true)
            .await;
        assert!(
            result.is_err(),
            "loopback must be refused even in dry_run mode, not only for a real apply"
        );
    }

    // Systematic fuzz/negative tests (roadmap: "Action API und Adapter
    // bestehen Fuzz-/Negativtests und Command-Injection-Review") -
    // `proptest` generates thousands of adversarial inputs per run
    // (shell metacharacters, embedded newlines/nulls, unicode, extreme
    // lengths, ...) rather than relying only on the hand-picked cases
    // above. Two invariants matter here, both about the Action API
    // boundary (`FirewallTarget::try_from`, the literal shape
    // `execution_requests.approval_context->>'target'` arrives in) and
    // the adapters' own command construction:
    //
    // 1. Parsing/validating arbitrary input must never panic - a
    //    malformed `execution_request.target` must become a clean `Err`,
    //    never a crashed executor.
    // 2. Whenever a value *does* pass validation and becomes part of a
    //    real command, it can never contain whitespace, a newline, or any
    //    other character that could inject a second command - into
    //    `tokio::process::Command`'s argv (no shell to inject into at
    //    all, but proven anyway for defense in depth) or, more
    //    concretely exploitable in principle, into HAProxy's
    //    line-oriented Runtime API protocol (`UnixStream::write_all`,
    //    literally one line per command - an embedded `\n` in a "key"
    //    value would let an attacker smuggle in a second, arbitrary
    //    Runtime API command).
    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// `FirewallTarget::try_from` must never panic for *any* JSON
            /// value shape, not just the two recognized `kind`s - this is
            /// the actual external input boundary (an `execution_request`'s
            /// `target` column), fully attacker/operator-controlled JSON.
            #[test]
            fn try_from_json_never_panics(
                kind in ".*",
                cidr in ".*",
                source in ".*",
                pseudonym in ".*",
            ) {
                let value = serde_json::json!({
                    "kind": kind,
                    "cidr": cidr,
                    "source": source,
                    "pseudonym": pseudonym,
                });
                // Only the outcome matters here (Ok or Err, never a
                // panic) - the specific variant is already covered by
                // the targeted tests above.
                let _ = FirewallTarget::try_from(&value);
            }

            /// Same invariant, but against arbitrary (non-object) JSON
            /// shapes too - a number, a string, an array, null - since
            /// nothing about the JSON contract is enforced by a schema
            /// before this function sees it.
            #[test]
            fn try_from_json_never_panics_on_non_object_shapes(
                text in ".*",
                n in any::<i64>(),
                b in any::<bool>(),
            ) {
                for value in [
                    serde_json::json!(text),
                    serde_json::json!(n),
                    serde_json::json!(b),
                    serde_json::Value::Null,
                    serde_json::json!([text.clone(), n]),
                ] {
                    let _ = FirewallTarget::try_from(&value);
                }
            }

            /// `parse_ip_or_cidr` must never panic for arbitrary text -
            /// it is the sole gate every `cidr`/`raw_ip` string passes
            /// through before becoming part of a real command.
            #[test]
            fn parse_ip_or_cidr_never_panics(value in ".*") {
                let _ = parse_ip_or_cidr(&value);
            }

            /// The core command-injection proof: whenever
            /// `parse_ip_or_cidr` accepts a string, `element_reference`'s
            /// reformatted output (what actually reaches an `nft` argv
            /// element or a HAProxy Runtime API `key`) contains none of
            /// whitespace, a newline, or a NUL byte - regardless of what
            /// the *original* input string looked like. This holds by
            /// construction (the output is rebuilt from a parsed,
            /// strongly-typed `IpAddr`/prefix, never the raw input text -
            /// see `element_reference`'s own doc comment), but this test
            /// is what actually proves it rather than just asserting it
            /// in a comment.
            #[test]
            fn a_validated_indicator_element_reference_is_always_a_single_safe_token(
                raw in ".*",
            ) {
                if parse_ip_or_cidr(&raw).is_some() {
                    let target = indicator(&raw);
                    let reference = element_reference(&target).expect("already validated");
                    prop_assert!(!reference.contains(char::is_whitespace));
                    prop_assert!(!reference.contains('\0'));
                    prop_assert_eq!(reference.lines().count(), 1);
                }
            }

            /// Same proof, one level up: every HAProxy Runtime API command
            /// string this crate builds from a validated indicator is
            /// exactly one line - an embedded newline in `key` would let
            /// an attacker smuggle a second, arbitrary command past
            /// `UnixStream::write_all`'s single `\n` terminator.
            #[test]
            fn haproxy_commands_built_from_a_validated_indicator_are_always_one_line(
                raw in ".*",
                acl_file in ".*",
                table in ".*",
            ) {
                if parse_ip_or_cidr(&raw).is_some() {
                    let target = indicator(&raw);
                    let key = element_reference(&target).expect("already validated");
                    for command in [
                        haproxy_add_acl_command(&acl_file, &key),
                        haproxy_del_acl_command(&acl_file, &key),
                        haproxy_set_table_gpc0_command(&table, &key),
                        haproxy_clear_table_command(&table, &key),
                    ] {
                        prop_assert_eq!(command.lines().count(), 1);
                    }
                }
            }

            /// `render` (pure, synchronous, never touches a real adapter)
            /// must never panic for an arbitrary `ThreatIntelIndicator`,
            /// valid or not - it is the first thing called on any
            /// operator/attacker-controlled target.
            #[test]
            fn nftables_render_never_panics_on_arbitrary_indicator(
                cidr in ".*",
                source in ".*",
            ) {
                let adapter = NftablesAdapter::new();
                let target = FirewallTarget::ThreatIntelIndicator { cidr, source };
                let action = action_for(target);
                let _ = adapter.render(&action);
            }

            #[test]
            fn haproxy_render_never_panics_on_arbitrary_indicator(
                cidr in ".*",
                source in ".*",
            ) {
                let adapter = HaproxyAdapter::new();
                let target = FirewallTarget::ThreatIntelIndicator { cidr, source };
                let action = action_for(target);
                let _ = adapter.render(&action);
            }

            /// `validate_pseudonym` (the `IncidentSource` gate) must never
            /// panic for arbitrary text either.
            #[test]
            fn validate_pseudonym_never_panics(value in ".*") {
                let _ = validate_pseudonym(&value);
            }
        }
    }
}
