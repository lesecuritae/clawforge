//! Configuration of the policy -> execution bridge (roadmap 7C).
//!
//! Off unless `CLAWFORGE_POLICY_BRIDGE_MODE` names a mode. There are no
//! built-in operating values: TTL, budget window, evidence age, action and (for
//! `propose`) the requester account must all be configured explicitly, and any
//! missing, malformed or contradictory value rejects the whole configuration.
//! The caller then runs with the bridge disabled and surfaces the reason in the
//! runtime status - it never falls back to a partial or guessed setting.
//!
//! `automatic` additionally needs a named rule, mandatory threat-intel
//! corroboration and an acknowledgement string that embeds the exact parameters
//! (so changing any of them invalidates the acknowledgement).
use clawforge_storage::{BridgeMode, PolicyBridgeParams};
use uuid::Uuid;

pub const MODE: &str = "CLAWFORGE_POLICY_BRIDGE_MODE";
pub const BLOCK_ACTION: &str = "CLAWFORGE_POLICY_BRIDGE_BLOCK_ACTION";
pub const RATELIMIT_ACTION: &str = "CLAWFORGE_POLICY_BRIDGE_RATELIMIT_ACTION";
pub const TTL_SECONDS: &str = "CLAWFORGE_POLICY_BRIDGE_TTL_SECONDS";
pub const MAX_PER_WINDOW: &str = "CLAWFORGE_POLICY_BRIDGE_MAX_PER_WINDOW";
pub const WINDOW_SECONDS: &str = "CLAWFORGE_POLICY_BRIDGE_WINDOW_SECONDS";
pub const MAX_EVIDENCE_AGE_SECONDS: &str = "CLAWFORGE_POLICY_BRIDGE_MAX_EVIDENCE_AGE_SECONDS";
pub const REQUIRE_THREAT_INTEL: &str = "CLAWFORGE_POLICY_BRIDGE_REQUIRE_THREAT_INTEL";
pub const MIN_INTEL_CONFIDENCE: &str = "CLAWFORGE_POLICY_BRIDGE_MIN_INTEL_CONFIDENCE";
pub const REQUESTER_ID: &str = "CLAWFORGE_POLICY_BRIDGE_REQUESTER_ID";
pub const RULE_ID: &str = "CLAWFORGE_POLICY_BRIDGE_RULE_ID";
pub const AUTOMATIC_ACK: &str = "CLAWFORGE_POLICY_BRIDGE_AUTOMATIC_ACK";

const BLOCK_ACTIONS: [&str; 3] = [
    "nftables.block_incident_source",
    "haproxy.block_incident_source",
    "firewall.block_incident_source",
];
const RATELIMIT_ACTIONS: [&str; 1] = ["haproxy_ratelimit.block_incident_source"];
const MAX_SECONDS: i32 = 86_400;
const MAX_EVIDENCE_AGE: i32 = 604_800;
const MAX_REQUESTS_PER_WINDOW: i32 = 100;
const MIN_WINDOW_SECONDS: i32 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeConfig {
    pub mode: BridgeMode,
    pub block_action: Option<String>,
    pub ratelimit_action: Option<String>,
    ttl_seconds: i32,
    requester_id: Option<Uuid>,
    rule_id: Option<String>,
    max_evidence_age_seconds: i32,
    min_intel_confidence: i32,
    require_threat_intel: bool,
    max_per_window: i32,
    window_seconds: i32,
}

impl BridgeConfig {
    /// `Ok(None)` when the bridge is off. `Err` carries a reason that contains
    /// no secret and names the variable at fault.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let text = |name: &str| {
            get(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let mode = match text(MODE).as_deref() {
            None | Some("off") => return Ok(None),
            Some("simulate") => BridgeMode::Simulate,
            Some("propose") => BridgeMode::Propose,
            Some("automatic") => BridgeMode::Automatic,
            Some(other) => return Err(format!("{MODE}: unknown mode {other:?}")),
        };
        let number = |name: &str, min: i32, max: i32| -> Result<i32, String> {
            let raw = text(name).ok_or_else(|| format!("{name} is required"))?;
            let value: i32 = raw
                .parse()
                .map_err(|_| format!("{name} is not an integer"))?;
            if (min..=max).contains(&value) {
                Ok(value)
            } else {
                Err(format!("{name} must be between {min} and {max}"))
            }
        };
        let action = |name: &str, allowed: &[&str]| -> Result<Option<String>, String> {
            match text(name) {
                None => Ok(None),
                Some(value) if allowed.contains(&value.as_str()) => Ok(Some(value)),
                Some(_) => Err(format!("{name} is not an allowed incident-source action")),
            }
        };
        let block_action = action(BLOCK_ACTION, &BLOCK_ACTIONS)?;
        let ratelimit_action = action(RATELIMIT_ACTION, &RATELIMIT_ACTIONS)?;
        if block_action.is_none() && ratelimit_action.is_none() {
            return Err(format!("{BLOCK_ACTION} or {RATELIMIT_ACTION} is required"));
        }
        let ttl_seconds = number(TTL_SECONDS, 1, MAX_SECONDS)?;
        let max_per_window = number(MAX_PER_WINDOW, 1, MAX_REQUESTS_PER_WINDOW)?;
        let window_seconds = number(WINDOW_SECONDS, MIN_WINDOW_SECONDS, MAX_SECONDS)?;
        let max_evidence_age_seconds = number(MAX_EVIDENCE_AGE_SECONDS, 1, MAX_EVIDENCE_AGE)?;
        let min_intel_confidence = number(MIN_INTEL_CONFIDENCE, 1, 100)?;
        let require_threat_intel = match text(REQUIRE_THREAT_INTEL).as_deref() {
            None | Some("true") => true,
            Some("false") => false,
            Some(_) => return Err(format!("{REQUIRE_THREAT_INTEL} must be true or false")),
        };
        let rule_id = match text(RULE_ID) {
            Some(rule)
                if rule.len() <= 80
                    && rule
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') =>
            {
                Some(rule)
            }
            Some(_) => {
                return Err(format!(
                    "{RULE_ID} must be lowercase letters, digits and underscores"
                ))
            }
            None => None,
        };
        let requester_id = match text(REQUESTER_ID) {
            Some(raw) => {
                Some(Uuid::parse_str(&raw).map_err(|_| format!("{REQUESTER_ID} is not a UUID"))?)
            }
            None => None,
        };
        match mode {
            BridgeMode::Propose if requester_id.is_none() => {
                return Err(format!("{REQUESTER_ID} is required for propose"))
            }
            BridgeMode::Simulate | BridgeMode::Automatic if requester_id.is_some() => {
                return Err(format!("{REQUESTER_ID} is only valid for propose"))
            }
            _ => {}
        }
        let config = Self {
            mode,
            block_action,
            ratelimit_action,
            ttl_seconds,
            requester_id,
            rule_id,
            max_evidence_age_seconds,
            min_intel_confidence,
            require_threat_intel,
            max_per_window,
            window_seconds,
        };
        if mode == BridgeMode::Automatic {
            if config.rule_id.is_none() {
                return Err(format!("{RULE_ID} is required for automatic"));
            }
            if !config.require_threat_intel {
                return Err(format!(
                    "{REQUIRE_THREAT_INTEL}=false is not allowed for automatic"
                ));
            }
            if text(AUTOMATIC_ACK).as_deref() != Some(config.expected_ack().as_str()) {
                return Err(format!(
                    "{AUTOMATIC_ACK} is missing or does not match the configured parameters"
                ));
            }
        }
        Ok(Some(config))
    }

    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// The exact acknowledgement for `automatic`; it binds every operating
    /// parameter, so editing one of them without re-acknowledging fails closed.
    pub fn expected_ack(&self) -> String {
        format!(
            "unattended:{}:{}:{}:{}:{}/{}:{}:{}",
            self.rule_id.as_deref().unwrap_or("-"),
            self.block_action.as_deref().unwrap_or("-"),
            self.ratelimit_action.as_deref().unwrap_or("-"),
            self.ttl_seconds,
            self.max_per_window,
            self.window_seconds,
            self.max_evidence_age_seconds,
            self.min_intel_confidence,
        )
    }

    /// Parameters for one decision kind, or `None` when no action is configured
    /// for it (the decision is then simply not bridged).
    pub fn params_for(&self, rate_limit: bool) -> Option<PolicyBridgeParams> {
        let action_name = if rate_limit {
            self.ratelimit_action.clone()
        } else {
            self.block_action.clone()
        }?;
        Some(PolicyBridgeParams {
            mode: self.mode,
            action_name,
            ttl_seconds: self.ttl_seconds,
            requester_id: self.requester_id,
            rule_id: self.rule_id.clone(),
            max_evidence_age_seconds: self.max_evidence_age_seconds,
            min_intel_confidence: self.min_intel_confidence,
            require_threat_intel: self.require_threat_intel,
            max_per_window: self.max_per_window,
            window_seconds: self.window_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const REQUESTER: &str = "5b0e57de-8b61-4a3d-8f70-6a4f3d1b2c9e";

    fn base(mode: &'static str) -> Vec<(&'static str, &'static str)> {
        vec![
            (MODE, mode),
            (BLOCK_ACTION, "nftables.block_incident_source"),
            (TTL_SECONDS, "60"),
            (MAX_PER_WINDOW, "1"),
            (WINDOW_SECONDS, "300"),
            (MAX_EVIDENCE_AGE_SECONDS, "900"),
            (MIN_INTEL_CONFIDENCE, "70"),
        ]
    }

    fn with(
        mut pairs: Vec<(&'static str, &'static str)>,
        extra: &[(&'static str, &'static str)],
    ) -> Vec<(&'static str, &'static str)> {
        for (key, value) in extra {
            pairs.retain(|(k, _)| k != key);
            pairs.push((key, value));
        }
        pairs
    }

    #[test]
    fn unset_or_off_disables_the_bridge_without_requiring_anything() {
        assert_eq!(BridgeConfig::from_lookup(lookup(&[])), Ok(None));
        assert_eq!(
            BridgeConfig::from_lookup(lookup(&[(MODE, "off")])),
            Ok(None)
        );
        assert_eq!(BridgeConfig::from_lookup(lookup(&[(MODE, "  ")])), Ok(None));
    }

    #[test]
    fn unknown_mode_is_rejected_not_ignored() {
        assert!(BridgeConfig::from_lookup(lookup(&[(MODE, "Propose")])).is_err());
        assert!(BridgeConfig::from_lookup(lookup(&[(MODE, "yes")])).is_err());
    }

    #[test]
    fn every_operating_value_is_mandatory_and_bounded() {
        let ok = with(base("simulate"), &[]);
        assert!(BridgeConfig::from_lookup(lookup(&ok)).unwrap().is_some());
        for missing in [
            MIN_INTEL_CONFIDENCE,
            BLOCK_ACTION,
            TTL_SECONDS,
            MAX_PER_WINDOW,
            WINDOW_SECONDS,
            MAX_EVIDENCE_AGE_SECONDS,
        ] {
            let mut pairs = ok.clone();
            pairs.retain(|(k, _)| *k != missing);
            let error = BridgeConfig::from_lookup(lookup(&pairs)).unwrap_err();
            assert!(
                error.contains(missing) || (missing == BLOCK_ACTION && error.contains("required")),
                "{missing}: {error}"
            );
        }
        for (name, bad) in [
            (TTL_SECONDS, "0"),
            (TTL_SECONDS, "86401"),
            (TTL_SECONDS, "-5"),
            (TTL_SECONDS, "ten"),
            (MAX_PER_WINDOW, "0"),
            (MAX_PER_WINDOW, "101"),
            (WINDOW_SECONDS, "59"),
            (WINDOW_SECONDS, "0"),
            (MAX_EVIDENCE_AGE_SECONDS, "604801"),
            (MIN_INTEL_CONFIDENCE, "0"),
            (MIN_INTEL_CONFIDENCE, "101"),
            (MIN_INTEL_CONFIDENCE, "high"),
            (REQUIRE_THREAT_INTEL, "maybe"),
        ] {
            let pairs = with(ok.clone(), &[(name, bad)]);
            assert!(
                BridgeConfig::from_lookup(lookup(&pairs)).is_err(),
                "{name}={bad}"
            );
        }
    }

    #[test]
    fn only_listed_incident_source_actions_are_accepted_per_decision_kind() {
        for bad in [
            "nftables.block_indicator",
            "docker.quarantine_container",
            "haproxy_ratelimit.block_incident_source",
            "",
        ] {
            let pairs = with(base("simulate"), &[(BLOCK_ACTION, bad)]);
            assert!(BridgeConfig::from_lookup(lookup(&pairs)).is_err(), "{bad}");
        }
        let pairs = with(
            base("simulate"),
            &[(RATELIMIT_ACTION, "nftables.block_incident_source")],
        );
        assert!(BridgeConfig::from_lookup(lookup(&pairs)).is_err());
        let both = with(
            base("simulate"),
            &[(RATELIMIT_ACTION, "haproxy_ratelimit.block_incident_source")],
        );
        let config = BridgeConfig::from_lookup(lookup(&both)).unwrap().unwrap();
        assert_eq!(
            config.params_for(false).unwrap().action_name,
            "nftables.block_incident_source"
        );
        assert_eq!(
            config.params_for(true).unwrap().action_name,
            "haproxy_ratelimit.block_incident_source"
        );
        let only_block = BridgeConfig::from_lookup(lookup(&base("simulate")))
            .unwrap()
            .unwrap();
        assert!(only_block.params_for(true).is_none());
    }

    #[test]
    fn requester_is_required_for_propose_and_forbidden_otherwise() {
        assert!(BridgeConfig::from_lookup(lookup(&base("propose"))).is_err());
        let propose = with(base("propose"), &[(REQUESTER_ID, REQUESTER)]);
        let config = BridgeConfig::from_lookup(lookup(&propose))
            .unwrap()
            .unwrap();
        assert_eq!(
            config.params_for(false).unwrap().requester_id,
            Some(Uuid::parse_str(REQUESTER).unwrap())
        );
        assert!(BridgeConfig::from_lookup(lookup(&with(
            base("propose"),
            &[(REQUESTER_ID, "not-a-uuid")]
        )))
        .is_err());
        assert!(BridgeConfig::from_lookup(lookup(&with(
            base("simulate"),
            &[(REQUESTER_ID, REQUESTER)]
        )))
        .is_err());
    }

    #[test]
    fn automatic_needs_rule_threat_intel_and_an_exact_acknowledgement() {
        let ack = "unattended:ssh_bruteforce:nftables.block_incident_source:-:60:1/300:900:70";
        let ok = with(
            base("automatic"),
            &[(RULE_ID, "ssh_bruteforce"), (AUTOMATIC_ACK, ack)],
        );
        let config = BridgeConfig::from_lookup(lookup(&ok)).unwrap().unwrap();
        assert_eq!(config.expected_ack(), ack);
        // No acknowledgement, a wrong one, or one for other parameters is rejected.
        let no_ack: Vec<_> = ok
            .iter()
            .copied()
            .filter(|(k, _)| *k != AUTOMATIC_ACK)
            .collect();
        assert!(BridgeConfig::from_lookup(lookup(&no_ack)).is_err());
        for changed in [
            (TTL_SECONDS, "61"),
            (MAX_PER_WINDOW, "2"),
            (WINDOW_SECONDS, "301"),
            (MAX_EVIDENCE_AGE_SECONDS, "901"),
            (MIN_INTEL_CONFIDENCE, "71"),
            (BLOCK_ACTION, "haproxy.block_incident_source"),
            (RULE_ID, "http_scan"),
        ] {
            assert!(
                BridgeConfig::from_lookup(lookup(&with(ok.clone(), &[changed]))).is_err(),
                "{changed:?}"
            );
        }
        assert!(
            BridgeConfig::from_lookup(lookup(&with(ok.clone(), &[(AUTOMATIC_ACK, "yes")])))
                .is_err()
        );
        // Rule and threat-intel corroboration cannot be dropped.
        let no_rule: Vec<_> = ok.iter().copied().filter(|(k, _)| *k != RULE_ID).collect();
        assert!(BridgeConfig::from_lookup(lookup(&no_rule)).is_err());
        assert!(BridgeConfig::from_lookup(lookup(&with(
            ok.clone(),
            &[(REQUIRE_THREAT_INTEL, "false")]
        )))
        .is_err());
        assert!(
            BridgeConfig::from_lookup(lookup(&with(ok, &[(REQUESTER_ID, REQUESTER)]))).is_err()
        );
    }

    #[test]
    fn rule_ids_are_restricted_to_a_safe_alphabet() {
        for bad in [
            "SSH",
            "ssh-bruteforce",
            "ssh bruteforce",
            Box::leak("a".repeat(81).into_boxed_str()) as &str,
        ] {
            let pairs = with(base("simulate"), &[(RULE_ID, bad)]);
            assert!(BridgeConfig::from_lookup(lookup(&pairs)).is_err(), "{bad}");
        }
    }

    #[test]
    fn threat_intel_defaults_to_required() {
        let config = BridgeConfig::from_lookup(lookup(&base("simulate")))
            .unwrap()
            .unwrap();
        assert!(config.params_for(false).unwrap().require_threat_intel);
    }
}
