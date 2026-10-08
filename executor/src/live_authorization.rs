//! P7-1: an explicit, limited live-execution authorization - the Phase-7
//! pilot gate's "turn the key" half, while the lock itself stays shut by
//! default.
//!
//! The executor refuses to run with `CLAWFORGE_EXECUTOR_DRY_RUN` != `true`
//! unless a valid authorization is *also* present (see `main`), and even then
//! every dispatch still forces dry-run unless the specific action's class is
//! on this authorization's explicit allowlist. Four invariants are enforced so
//! this type can only ever *narrow*, never widen, what runs for real:
//!   1. an unset or unparseable authorization authorizes nothing - callers
//!      treat `from_env`'s `Ok(None)` and `Err(_)` alike as fully closed
//!      (fail-closed);
//!   2. an empty `actions` allowlist is valid and authorizes nothing, so a
//!      present authorization is not itself permission to apply anything;
//!   3. quarantine actions (`tailscale`/`proxmox`/`docker`) are never an
//!      authorizable class here and keep their independent hard gate
//!      (`quarantine_gate`);
//!   4. `simulation_only` on a request still forces dry-run upstream
//!      (`request_requires_dry_run`) regardless of any authorization.
//!
//! This module only *decides* authorization; it never flips a mode, writes a
//! receipt, or touches an adapter. Opening the gate for a real pilot still
//! requires an operator to supply a reviewed authorization AND set
//! `CLAWFORGE_EXECUTOR_DRY_RUN=false` AND target an allowlisted action class -
//! i.e. Phase-7 step 7A, which this code enables but does not perform.

use anyhow::{bail, Context};
use serde::Deserialize;

use super::{DOCKER_QUARANTINE_ACTION, PROXMOX_QUARANTINE_ACTION, TAILSCALE_ACTION_PREFIX};

/// The environment variable carrying the authorization JSON. Unset or empty
/// means "no live authorization" - the default, fully-closed state.
pub const LIVE_AUTHORIZATION_ENV: &str = "CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION";

/// Firewall-apply action classes an operator may put on an allowlist. The
/// three quarantine classes are intentionally absent: they can never be
/// authorized through this mechanism, only through their own closed gate.
pub const AUTHORIZABLE_ACTION_CLASSES: [&str; 5] = [
    "nftables",
    "haproxy",
    "haproxy_ratelimit",
    "goaway",
    "firewall",
];

const MAX_FIELD_LEN: usize = 200;
const MAX_ACTIONS: usize = AUTHORIZABLE_ACTION_CLASSES.len();

/// A reviewed, explicit permission to run a bounded set of firewall-apply
/// action classes for real. Carries operator attestation (`authorization_id`,
/// `approved_by`) so a live run is always traceable to a specific approval.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveAuthorization {
    /// Authorization schema version; only `1` is accepted today.
    pub version: u32,
    /// Opaque operator-chosen identifier for this approval (e.g. a ticket or
    /// pilot id). Non-empty; recorded for traceability.
    pub authorization_id: String,
    /// Who approved this authorization (operator attestation). Non-empty.
    pub approved_by: String,
    /// The action classes authorized for a real apply. Empty is valid and
    /// authorizes nothing. Every entry must be an `AUTHORIZABLE_ACTION_CLASSES`
    /// member, so a quarantine or unknown class is rejected at load.
    #[serde(default)]
    pub actions: Vec<String>,
}

impl LiveAuthorization {
    /// Load from the environment. `Ok(None)` when unset or empty (the default,
    /// fully-closed state). `Err` when set but invalid - callers MUST treat
    /// that as closed, never as "authorize everything".
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        match std::env::var(LIVE_AUTHORIZATION_ENV) {
            Err(_) => Ok(None),
            Ok(raw) if raw.trim().is_empty() => Ok(None),
            Ok(raw) => Ok(Some(Self::parse(&raw)?)),
        }
    }

    /// Parse and fully validate an authorization from its JSON text.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let auth: LiveAuthorization = serde_json::from_str(raw).context(
            "CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION is not valid live-authorization JSON",
        )?;
        auth.validate()?;
        Ok(auth)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.version != 1 {
            bail!(
                "unsupported live authorization version {} (only 1 is accepted)",
                self.version
            );
        }
        for (field, value) in [
            ("authorization_id", &self.authorization_id),
            ("approved_by", &self.approved_by),
        ] {
            if value.trim().is_empty() {
                bail!("live authorization `{field}` must not be empty");
            }
            if value.len() > MAX_FIELD_LEN {
                bail!("live authorization `{field}` exceeds {MAX_FIELD_LEN} bytes");
            }
            if value.chars().any(char::is_control) {
                bail!("live authorization `{field}` contains control characters");
            }
        }
        if self.actions.len() > MAX_ACTIONS {
            bail!("live authorization lists more action classes than exist");
        }
        for action in &self.actions {
            if !AUTHORIZABLE_ACTION_CLASSES.contains(&action.as_str()) {
                bail!(
                    "live authorization lists a non-authorizable action class {action:?}; \
                     quarantine and unknown classes can never be authorized here"
                );
            }
        }
        Ok(())
    }

    /// Whether a concrete `action_name` (e.g. `nftables.block_indicator`) is
    /// authorized for a real apply: true only when its class is a firewall
    /// (never quarantine) class that is explicitly on this allowlist.
    pub fn allows_action(&self, action_name: &str) -> bool {
        match action_class(action_name) {
            Some(class) => self.actions.iter().any(|a| a == class),
            None => false,
        }
    }
}

/// The authorizable class of an action name, or `None` for a quarantine or
/// unknown action. Mirrors `dispatch`'s firewall routing but deliberately maps
/// the three quarantine actions to `None` so they are never authorizable here.
pub fn action_class(action_name: &str) -> Option<&'static str> {
    if action_name == TAILSCALE_ACTION_PREFIX
        || action_name == PROXMOX_QUARANTINE_ACTION
        || action_name == DOCKER_QUARANTINE_ACTION
    {
        return None;
    }
    // Order matters: `haproxy_ratelimit.` is a prefix-superset of `haproxy.`
    // only in spelling, but must be tested first to classify correctly.
    if action_name.starts_with("nftables.") {
        Some("nftables")
    } else if action_name.starts_with("haproxy_ratelimit.") {
        Some("haproxy_ratelimit")
    } else if action_name.starts_with("haproxy.") {
        Some("haproxy")
    } else if action_name.starts_with("goaway.") {
        Some("goaway")
    } else if action_name.starts_with(super::FIREWALL_MULTI_ADAPTER_PREFIX) {
        Some("firewall")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(actions: &[&str]) -> LiveAuthorization {
        LiveAuthorization {
            version: 1,
            authorization_id: "pilot-7a".into(),
            approved_by: "operator".into(),
            actions: actions.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn env_unset_or_empty_authorizes_nothing() {
        // One test owns this process-wide var so two env-touching tests never
        // race under the default parallel runner.
        std::env::set_var(LIVE_AUTHORIZATION_ENV, "   ");
        assert!(
            LiveAuthorization::from_env().unwrap().is_none(),
            "a whitespace-only value is treated as absent, not invalid"
        );
        std::env::remove_var(LIVE_AUTHORIZATION_ENV);
        assert!(LiveAuthorization::from_env().unwrap().is_none());
    }

    #[test]
    fn empty_allowlist_is_valid_but_authorizes_nothing() {
        let a = auth(&[]);
        a.validate().unwrap();
        assert!(!a.allows_action("nftables.block_indicator"));
        assert!(!a.allows_action("firewall.block_indicator"));
    }

    #[test]
    fn an_authorized_class_allows_only_its_own_actions() {
        let a = auth(&["nftables"]);
        assert!(a.allows_action("nftables.block_indicator"));
        assert!(!a.allows_action("haproxy.block_indicator"));
        assert!(!a.allows_action("haproxy_ratelimit.block_indicator"));
        assert!(!a.allows_action("firewall.block_indicator"));
    }

    #[test]
    fn haproxy_ratelimit_is_classified_before_haproxy() {
        let a = auth(&["haproxy_ratelimit"]);
        assert!(a.allows_action("haproxy_ratelimit.block_indicator"));
        // A plain haproxy. action must NOT be caught by the ratelimit grant.
        assert!(!a.allows_action("haproxy.block_indicator"));
        let b = auth(&["haproxy"]);
        assert!(b.allows_action("haproxy.block_indicator"));
        assert!(!b.allows_action("haproxy_ratelimit.block_indicator"));
    }

    #[test]
    fn quarantine_actions_are_never_authorizable() {
        // Even an authorization that somehow listed every authorizable class
        // can never reach a quarantine action, because they have no class.
        let a = auth(&AUTHORIZABLE_ACTION_CLASSES);
        assert!(!a.allows_action(TAILSCALE_ACTION_PREFIX));
        assert!(!a.allows_action(PROXMOX_QUARANTINE_ACTION));
        assert!(!a.allows_action(DOCKER_QUARANTINE_ACTION));
        assert_eq!(action_class(TAILSCALE_ACTION_PREFIX), None);
        assert_eq!(action_class(PROXMOX_QUARANTINE_ACTION), None);
        assert_eq!(action_class(DOCKER_QUARANTINE_ACTION), None);
    }

    #[test]
    fn a_quarantine_class_in_the_allowlist_is_rejected_at_load() {
        for bad in ["docker", "proxmox", "tailscale", "unknown", "nftables."] {
            let raw = format!(
                r#"{{"version":1,"authorization_id":"x","approved_by":"y","actions":["{bad}"]}}"#
            );
            assert!(
                LiveAuthorization::parse(&raw).is_err(),
                "class {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn version_and_attestation_are_required() {
        assert!(LiveAuthorization::parse(
            r#"{"version":2,"authorization_id":"x","approved_by":"y","actions":[]}"#
        )
        .is_err());
        assert!(LiveAuthorization::parse(
            r#"{"version":1,"authorization_id":"","approved_by":"y","actions":[]}"#
        )
        .is_err());
        assert!(LiveAuthorization::parse(
            r#"{"version":1,"authorization_id":"x","approved_by":"   ","actions":[]}"#
        )
        .is_err());
    }

    #[test]
    fn unknown_fields_and_malformed_json_are_rejected() {
        assert!(LiveAuthorization::parse(
            r#"{"version":1,"authorization_id":"x","approved_by":"y","actions":[],"extra":true}"#
        )
        .is_err());
        assert!(LiveAuthorization::parse("not json").is_err());
    }

    #[test]
    fn a_valid_single_class_authorization_round_trips() {
        let raw = r#"{"version":1,"authorization_id":"pilot-7a","approved_by":"ops","actions":["firewall"]}"#;
        let a = LiveAuthorization::parse(raw).unwrap();
        assert_eq!(a.authorization_id, "pilot-7a");
        assert!(a.allows_action("firewall.block_indicator"));
        assert!(!a.allows_action("nftables.block_indicator"));
    }
}
