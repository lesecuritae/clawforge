//! `clawforge-firewall-agent` (roadmap phase 6, "Firewall Action Layer"),
//! first increment: the typed adapter contract and the nftables adapter's
//! **preflight/render path only**.
//!
//! ## No apply path exists yet, on purpose
//!
//! [`FirewallAdapter::render`] builds the exact `nft` command lines a real
//! apply *would* run and returns them in a [`FirewallActionReceipt`] - it
//! never invokes `nft` in any mutating form. There is no function in this
//! crate capable of changing a host's firewall state at all yet. That
//! matches the roadmap's own "zunächst vollständig im Dry-Run" literally:
//! not a flag that defaults to safe (`clawforge-executor` already has one,
//! `CLAWFORGE_EXECUTOR_DRY_RUN`, hardcoded `true`), but the absence of any
//! mutating capability in the source itself. Wiring this crate into that
//! executor's dispatch loop, and everything downstream of an actual
//! `apply` existing (real `verify`/`rollback`, the mandatory pre-lab-test
//! gates the roadmap lists - fuzz/negative tests, an isolated network lab
//! confirming no self-lockout - a HAProxy adapter, Tailscale as an
//! approval-gated adapter) is deliberately out of scope for this
//! increment, not forgotten.
//!
//! ## One exclusive table, one pre-provisioned set - never a free-form rule
//!
//! The roadmap is specific: "exklusive Clawforge-Tabelle/-Chain ...
//! ausschließlich ein vorprovisioniertes Set verwalten". This adapter
//! never renders `nft add rule` at all - an operator provisions exactly
//! one rule ahead of time, out of band (e.g. `... ip saddr @blocklist
//! drop`), and this adapter only ever adds or removes *elements* of the
//! named set (`blocklist`) within Clawforge's own table (`inet
//! clawforge`). A bug here can at most toggle membership of one address in
//! one set; it cannot inject a new rule, touch another table, or affect
//! anything the operator did not already provision by hand.
//!
//! ## Command construction, not string interpolation
//!
//! Every `nft` invocation is built as an explicit `Vec<String>` of
//! arguments passed to `tokio::process::Command` - never a shell string,
//! so there is no shell to inject into in the first place. `preflight`'s
//! read-only inspection (`nft -j list set ...`) is built the same way,
//! for the same reason, even though it is read-only: the roadmap's own
//! gate ("es existiert keine freie Shell") has no "but this call is
//! harmless" exception, and neither does this crate.
//!
//! ## Two target kinds, two risk shapes
//!
//! - [`FirewallTarget::ThreatIntelIndicator`] - a raw CIDR/IP that is
//!   already public threat-intel data (`indicators.value`, e.g. a
//!   Spamhaus DROP entry) - never pseudonymized in the first place, so
//!   rendering it is exactly as sensitive as the indicator feed itself
//!   already is.
//! - [`FirewallTarget::IncidentSource`] - a pseudonymized resource
//!   (`ip-pseudonym:<hash>`). Rendering it **never** resolves the pseudonym
//!   to a raw IP - see [`render`](FirewallAdapter::render)'s own
//!   implementation. Only a real `apply` step (not built yet) would ever
//!   do that, via `security_ip_resolutions`, and only just-in-time -
//!   never persisting the resolved value into a receipt or anywhere else
//!   longer-lived.

use async_trait::async_trait;
use std::net::IpAddr;

/// Clawforge's own, exclusive nftables table and set - see the module doc
/// comment for why this adapter never renders anything outside them.
pub const NFTABLES_FAMILY: &str = "inet";
pub const NFTABLES_TABLE: &str = "clawforge";
pub const NFTABLES_BLOCKLIST_SET: &str = "blocklist";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdapterError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("preflight failed: {0}")]
    Preflight(String),
}

/// What a firewall action would apply to. See the module doc comment for
/// why these two are kept as distinct variants rather than one generic
/// "IP or CIDR" shape - they have different provenance and different
/// privacy properties, and `render` treats them differently because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallTarget {
    /// A raw CIDR or single IP from a threat-intel indicator
    /// (`indicators.value`) - already public data, safe to render as-is.
    ThreatIntelIndicator { cidr: String, source: String },
    /// A pseudonymized resource (`ip-pseudonym:<hash>`) from a corroborated
    /// incident. `render` never resolves this to a raw address.
    IncidentSource { pseudonym: String },
}

impl FirewallTarget {
    /// Validates the target is well-formed *before* it is ever used to
    /// build a command - defense in depth on top of `tokio::process::
    /// Command`'s argv-array construction already ruling out shell
    /// injection by design: a malformed value should fail here, with a
    /// clear error, rather than be handed to `nft` to reject opaquely (or,
    /// worse, be silently misinterpreted).
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
            FirewallTarget::IncidentSource { pseudonym } => {
                if !pseudonym.starts_with("ip-pseudonym:")
                    || pseudonym.len() <= "ip-pseudonym:".len()
                {
                    return Err(AdapterError::InvalidTarget(format!(
                        "{pseudonym:?} is not a recognized pseudonymized resource"
                    )));
                }
                Ok(())
            }
        }
    }
}

/// A plain IP (`1.2.3.4`) or CIDR (`1.2.3.4/24`) - the two shapes
/// `indicators.value` actually holds (see `security_events.rs`'s
/// `lookup_ip_reputation`, which matches both `indicator_type='Ip'` and
/// `'Prefix'`). Accepts nothing else - no hostnames, no ranges.
fn parse_ip_or_cidr(value: &str) -> Option<(IpAddr, Option<u8>)> {
    match value.split_once('/') {
        Some((addr, prefix)) => {
            let addr: IpAddr = addr.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > max_prefix {
                return None;
            }
            Some((addr, Some(prefix)))
        }
        None => {
            let addr: IpAddr = value.parse().ok()?;
            Some((addr, None))
        }
    }
}

#[derive(Debug, Clone)]
pub struct FirewallAction {
    pub target: FirewallTarget,
    pub ttl_seconds: u32,
    pub reason: String,
}

/// What preflight found - read-only, never mutates anything. `nft`'s own
/// JSON output for the set is kept verbatim (`raw_set_json`) rather than
/// parsed into a bespoke struct: this crate only ever needs to know
/// whether the target is already an element of the set, not model the
/// whole ruleset.
#[derive(Debug, Clone)]
pub struct Preflight {
    pub already_blocked: bool,
    pub raw_set_json: String,
}

/// The rendered result of a `render` call - every command as an explicit
/// argv array (`Vec<String>`, never a shell string - see the module doc
/// comment), never yet executed. `is_dry_run` is always `true` today: see
/// the module doc comment for why that is a structural fact, not a flag
/// that happens to be set this way.
#[derive(Debug, Clone)]
pub struct FirewallActionReceipt {
    pub adapter: &'static str,
    pub rendered_commands: Vec<Vec<String>>,
    pub rollback_commands: Vec<Vec<String>>,
    pub is_dry_run: bool,
    pub ttl_seconds: u32,
}

#[async_trait]
pub trait FirewallAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    /// Read-only inspection of current state relevant to `target` - must
    /// never construct or run anything but an `nft list`/`nft -j list`
    /// style command.
    async fn preflight(&self, target: &FirewallTarget) -> Result<Preflight, AdapterError>;
    /// Pure and synchronous on purpose: rendering what an apply *would* do
    /// never needs to touch the network, the filesystem, or `nft` itself -
    /// only `preflight` and a real, not-yet-built `apply` do.
    fn render(&self, action: &FirewallAction) -> Result<FirewallActionReceipt, AdapterError>;
}

pub struct NftablesAdapter;

impl NftablesAdapter {
    pub fn new() -> Self {
        Self
    }

    /// The read-only command `preflight` runs - a pure function so the
    /// exact argv can be asserted on in a test without actually needing
    /// `nft` installed (this environment's tests never invoke the real
    /// binary; only the command-construction logic is exercised here).
    fn preflight_command() -> Vec<String> {
        vec![
            "nft".to_string(),
            "-j".to_string(),
            "list".to_string(),
            "set".to_string(),
            NFTABLES_FAMILY.to_string(),
            NFTABLES_TABLE.to_string(),
            NFTABLES_BLOCKLIST_SET.to_string(),
        ]
    }

    /// The element-reference a target renders to inside the set - the
    /// literal CIDR/IP for a threat-intel target, or a placeholder that
    /// never resolves for an incident-sourced one (see the module doc
    /// comment). `nft`'s own set-element syntax (`{ value }`) is applied
    /// by the caller (`render`), not here, so this stays reusable for both
    /// the add and the delete command.
    fn element_reference(target: &FirewallTarget) -> String {
        match target {
            FirewallTarget::ThreatIntelIndicator { cidr, .. } => cidr.clone(),
            FirewallTarget::IncidentSource { pseudonym } => {
                format!("<resolved-at-apply-time:{pseudonym}>")
            }
        }
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
        let args = Self::preflight_command();
        let output = tokio::process::Command::new(&args[0])
            .args(&args[1..])
            .output()
            .await
            .map_err(|error| AdapterError::Preflight(error.to_string()))?;
        if !output.status.success() {
            return Err(AdapterError::Preflight(format!(
                "nft exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let raw_set_json = String::from_utf8_lossy(&output.stdout).to_string();
        // A real, non-placeholder element reference is only ever searched
        // for in the raw JSON when it is safe to render in the first
        // place - an incident-sourced target's placeholder never matches
        // anything real, which is deliberate: preflight cannot tell an
        // unresolved incident target's membership status any more
        // precisely than "unknown" without a real apply/resolve step, and
        // must not guess.
        let already_blocked = match target {
            FirewallTarget::ThreatIntelIndicator { cidr, .. } => raw_set_json.contains(cidr),
            FirewallTarget::IncidentSource { .. } => false,
        };
        Ok(Preflight {
            already_blocked,
            raw_set_json,
        })
    }

    fn render(&self, action: &FirewallAction) -> Result<FirewallActionReceipt, AdapterError> {
        action.target.validate()?;
        let element = Self::element_reference(&action.target);
        let add = vec![
            "nft".to_string(),
            "add".to_string(),
            "element".to_string(),
            NFTABLES_FAMILY.to_string(),
            NFTABLES_TABLE.to_string(),
            NFTABLES_BLOCKLIST_SET.to_string(),
            "{".to_string(),
            element.clone(),
            "}".to_string(),
        ];
        let delete = vec![
            "nft".to_string(),
            "delete".to_string(),
            "element".to_string(),
            NFTABLES_FAMILY.to_string(),
            NFTABLES_TABLE.to_string(),
            NFTABLES_BLOCKLIST_SET.to_string(),
            "{".to_string(),
            element,
            "}".to_string(),
        ];
        Ok(FirewallActionReceipt {
            adapter: self.name(),
            rendered_commands: vec![add],
            rollback_commands: vec![delete],
            is_dry_run: true,
            ttl_seconds: action.ttl_seconds,
        })
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
        // The whole point: nowhere in the receipt does a real IP appear -
        // only the pseudonym, wrapped in an explicit unresolved marker.
        assert!(rendered.contains("<resolved-at-apply-time:"));
        assert!(receipt.is_dry_run);
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
        // Exercises the exact argv preflight would run without needing a
        // real nft binary - proving it never touches anything outside
        // Clawforge's own exclusive table/set (see module doc comment).
        let args = NftablesAdapter::preflight_command();
        assert_eq!(
            args,
            vec!["nft", "-j", "list", "set", "inet", "clawforge", "blocklist"]
        );
    }
}
