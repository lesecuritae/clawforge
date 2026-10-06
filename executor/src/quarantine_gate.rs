//! Context validation is not authorization to mutate infrastructure.
//! Live dispatch stays closed until durable recovery and generation ownership
//! have been proven; an environment variable must not bypass this boundary.

use anyhow::{bail, Context, Result};
use clawforge_firewall_agent::quarantine::QuarantinePreflight;
use serde_json::Value;

pub(crate) const DEFAULT_TTL_SECONDS: u32 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuarantineKind {
    Docker,
    Proxmox,
    Tailscale,
}

impl QuarantineKind {
    pub(crate) fn from_action_name(name: &str) -> Option<Self> {
        match name {
            "docker.quarantine_container" => Some(Self::Docker),
            "proxmox.quarantine_vm" => Some(Self::Proxmox),
            "tailscale.quarantine_device" => Some(Self::Tailscale),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QuarantineIdentity {
    Docker { container_id: String },
    Proxmox { node: String, vmid: u32 },
    Tailscale { device_id: String },
}

#[derive(Debug)]
pub(crate) struct QuarantineContext {
    pub(crate) target: QuarantineIdentity,
    pub(crate) preflight: Option<QuarantinePreflight>,
    pub(crate) ttl_seconds: u32,
    pub(crate) ready_for_live: bool,
}

fn bounded_string<'a>(target: &'a Value, field: &str, max: usize) -> Result<&'a str> {
    let value = target
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("quarantine target requires {field}"))?;
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("invalid quarantine {field}");
    }
    Ok(value)
}

pub(crate) fn ttl_seconds(target: &Value) -> Result<u32> {
    let Some(value) = target.get("ttl_seconds") else {
        return Ok(DEFAULT_TTL_SECONDS);
    };
    let value = value
        .as_u64()
        .context("quarantine ttl_seconds must be an integer")?;
    if !(60..=86400).contains(&value) {
        bail!("quarantine ttl_seconds must be between 60 and 86400");
    }
    Ok(value as u32)
}

/// Validates IDs on every path and required operator context on real dispatch.
/// A valid restore reference proves neither a backup nor a reachable management
/// path. Those live checks and durable intent recovery are separate gates.
pub(crate) fn validate_context(
    action_name: &str,
    target: &Value,
    dry_run: bool,
) -> Result<QuarantineContext> {
    let kind =
        QuarantineKind::from_action_name(action_name).context("unrecognized quarantine action")?;
    if !target.is_object() {
        bail!("quarantine target must be an object");
    }
    let ttl_seconds = ttl_seconds(target)?;
    let (owner, restore, management) = if dry_run {
        ("dry-run only", "dry-run only", "dry-run only")
    } else {
        (
            bounded_string(target, "data_owner", 256)?,
            bounded_string(target, "snapshot_restore_reference", 2048)?,
            bounded_string(target, "management_network_plan", 2048)?,
        )
    };
    let (identity, preflight) = match kind {
        QuarantineKind::Docker => {
            // Never bind an approval to a mutable name or ambiguous short ID.
            let id = bounded_string(target, "container_id", 64)?;
            let metadata = QuarantinePreflight::new_docker(id, owner, restore, management)?;
            (
                QuarantineIdentity::Docker {
                    container_id: id.into(),
                },
                Some(metadata),
            )
        }
        QuarantineKind::Proxmox => {
            let node = bounded_string(target, "node", 63)?;
            let vmid = target
                .get("vmid")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .context("quarantine vmid must be a positive u32 integer")?;
            let metadata =
                QuarantinePreflight::new_proxmox(node, vmid, owner, restore, management)?;
            (
                QuarantineIdentity::Proxmox {
                    node: node.into(),
                    vmid,
                },
                Some(metadata),
            )
        }
        QuarantineKind::Tailscale => {
            let id = bounded_string(target, "device_id", 256)?;
            // IDs are interpolated into Admin API URL paths; separators and
            // whitespace must not change the approved resource identity.
            if !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            {
                bail!("invalid canonical Tailscale device_id");
            }
            (
                QuarantineIdentity::Tailscale {
                    device_id: id.into(),
                },
                None,
            )
        }
    };
    Ok(QuarantineContext {
        target: identity,
        preflight: if dry_run { None } else { preflight },
        ttl_seconds,
        ready_for_live: false,
    })
}

/// Deliberately has no opt-in environment switch: the missing crash/generation
/// gates cannot be supplied by a deployment setting.
pub(crate) fn ensure_live_dispatch_disabled(dry_run: bool) -> Result<()> {
    if !dry_run {
        bail!(
            "live quarantine is disabled pending durable recovery and generation ownership gates"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn docker_context() -> Value {
        json!({"container_id": "a".repeat(64), "data_owner": "operator",
            "snapshot_restore_reference": "backup:lab-restore-verified",
            "management_network_plan": "separate protected control plane"})
    }

    #[test]
    fn only_exact_action_names_are_accepted() {
        for name in [
            "docker.restart_container",
            "proxmox.quarantine_vm.extra",
            "tailscale.anything",
            "firewall.quarantine",
        ] {
            assert!(QuarantineKind::from_action_name(name).is_none());
        }
        assert_eq!(
            QuarantineKind::from_action_name("tailscale.quarantine_device"),
            Some(QuarantineKind::Tailscale)
        );
    }

    #[test]
    fn live_context_requires_each_metadata_field() {
        for field in [
            "data_owner",
            "snapshot_restore_reference",
            "management_network_plan",
        ] {
            for bad in [
                Value::Null,
                json!(" "),
                json!("contains\ncontrol"),
                json!("x".repeat(2049)),
            ] {
                let mut target = docker_context();
                target[field] = bad;
                assert!(
                    validate_context("docker.quarantine_container", &target, false).is_err(),
                    "{field}"
                );
            }
            let mut target = docker_context();
            target.as_object_mut().unwrap().remove(field);
            assert!(validate_context("docker.quarantine_container", &target, false).is_err());
        }
    }

    #[test]
    fn valid_live_context_uses_native_preflight_but_does_not_open_gate() {
        let result =
            validate_context("docker.quarantine_container", &docker_context(), false).unwrap();
        assert_eq!(result.preflight.unwrap().data_owner(), "operator");
        assert!(!result.ready_for_live);
        assert_eq!(result.ttl_seconds, DEFAULT_TTL_SECONDS);
        assert!(ensure_live_dispatch_disabled(false).is_err());
    }

    #[test]
    fn dry_run_accepts_minimal_ids_without_claiming_readiness() {
        for (name, target) in [
            (
                "docker.quarantine_container",
                json!({"container_id": "b".repeat(64)}),
            ),
            (
                "proxmox.quarantine_vm",
                json!({"node": "pve-lab", "vmid": 9000}),
            ),
            (
                "tailscale.quarantine_device",
                json!({"device_id": "n123CNTRL"}),
            ),
        ] {
            let result = validate_context(name, &target, true).unwrap();
            assert!(result.preflight.is_none());
            assert!(!result.ready_for_live);
        }
        assert!(ensure_live_dispatch_disabled(true).is_ok());
    }

    #[test]
    fn ttl_is_bounded_integer_and_never_silently_defaults_invalid_input() {
        for value in [
            json!(null),
            json!(true),
            json!("3600"),
            json!(-1),
            json!(0),
            json!(59),
            json!(86401),
            json!(3600.5),
            json!(u64::MAX),
        ] {
            assert!(ttl_seconds(&json!({"ttl_seconds": value})).is_err());
        }
        for value in [60, 3600, 86400] {
            assert_eq!(ttl_seconds(&json!({"ttl_seconds": value})).unwrap(), value);
        }
        assert_eq!(ttl_seconds(&json!({})).unwrap(), 3600);
    }

    #[test]
    fn rejects_mutable_or_ambiguous_targets() {
        for (name, target) in [
            (
                "docker.quarantine_container",
                json!({"container_id": "web"}),
            ),
            (
                "docker.quarantine_container",
                json!({"container": "a".repeat(64)}),
            ),
            (
                "proxmox.quarantine_vm",
                json!({"node": "pve/lab", "vmid": 9000}),
            ),
            ("proxmox.quarantine_vm", json!({"node": "pve", "vmid": 0})),
            (
                "proxmox.quarantine_vm",
                json!({"node": "pve", "vmid": 4294967296u64}),
            ),
            (
                "tailscale.quarantine_device",
                json!({"device_id": "device/../other"}),
            ),
        ] {
            assert!(validate_context(name, &target, true).is_err());
        }
    }
}
