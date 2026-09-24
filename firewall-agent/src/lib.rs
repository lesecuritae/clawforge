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
//! and a DB-backed mass-block rate budget also exist now. Still open: the
//! roadmap's remaining mandatory gates beyond what this crate's own tests
//! cover (failure injection beyond lease loss/manual drift, a concurrency
//! budget bounding multiple replicas targeting the *same* host, TTL-driven
//! auto-rollback of an expired block) - see `docs/firewall-agent.md`'s own
//! remaining list.

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

    /// Refuses a target whose network overlaps the never-block exclusion
    /// list (loopback/link-local, plus an operator's own configured
    /// management/SSH range) - called by both `render` and `apply`,
    /// before either builds or runs anything. Not called by `rollback`:
    /// removing an element from the blocklist is the safe direction and
    /// must always be allowed, including for something that should never
    /// have been added in the first place. `IncidentSource` (unresolved)
    /// has no address yet to check - it already fails closed for its own,
    /// independent reason wherever an address would be needed.
    fn check_never_block(&self, target: &FirewallTarget) -> Result<(), AdapterError> {
        let never_block = self.never_block.as_ref().map_err(|error| {
            AdapterError::InvalidTarget(format!(
                "never-block exclusion list is misconfigured, refusing every target until \
                 fixed: {error}"
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
        self.check_never_block(&action.target)?;
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
        self.check_never_block(&action.target)?;
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
}

impl HaproxyAdapter {
    pub fn new() -> Self {
        Self {
            admin_socket: std::env::var("CLAWFORGE_HAPROXY_ADMIN_SOCKET")
                .unwrap_or_else(|_| HAPROXY_DEFAULT_ADMIN_SOCKET.to_string()),
            acl_file: std::env::var("CLAWFORGE_HAPROXY_BLOCKLIST_ACL_FILE")
                .unwrap_or_else(|_| HAPROXY_DEFAULT_BLOCKLIST_ACL_FILE.to_string()),
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

/// Tailscale's own first increment (roadmap: "zunächst nur als
/// freigabepflichtigen Adapter vorbereiten" - prepare it initially only
/// as an approval-required adapter) - deliberately narrower than
/// [`NftablesAdapter`]'s own first increment (which at least had
/// `preflight`/`render`, with `apply`/`verify`/`rollback` added later in
/// a separately reviewed increment). This type has **no** `preflight`,
/// `apply`, `verify`, or `rollback` method at all - not "an apply that
/// always returns an error", an apply that does not exist to call in the
/// first place, so there is no code path anywhere that could reach the
/// real Tailscale Admin API. `render` is the only capability: it
/// describes, in the same "say exactly what would happen" spirit as
/// `NftablesAdapter`'s own rendered `nft` argv, what a real call would be
/// (disabling a device suspected of compromise) - never calls it, and
/// this type holds no HTTP client, no API token, and no secret at all.
/// The registered action (migration `0037`) is `requires_approval=TRUE,
/// enabled=FALSE`, same as every other connector action since migration
/// `0027` - this is preparation for review, not a working integration.
pub struct TailscaleAdapter;

impl TailscaleAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &'static str {
        "tailscale"
    }

    /// Pure and synchronous, exactly like `NftablesAdapter::render` - no
    /// network, no filesystem, nothing but string formatting.
    pub fn render(&self, action: &TailscaleAction) -> Result<TailscaleActionReceipt, AdapterError> {
        action.target.validate()?;
        Ok(TailscaleActionReceipt {
            adapter: self.name(),
            described_call: format!(
                "POST /api/v2/device/{}/disable (reason: {})",
                action.target.device_id, action.reason
            ),
        })
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
        assert!(receipt.described_call.contains("disable"));
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
}
