//! Plan-only quarantine metadata, not an execution or approval capability.
//!
//! No snapshot exists merely because a reference passes this validation. Actual
//! adapters must verify snapshot/restore state, management connectivity and
//! ownership, and use the existing context-bound dual-approval mechanism before
//! isolation. Docker and Proxmox adapters remain separate. This module performs
//! no IO and is not wired into the executor, API or MCP.

use thiserror::Error;

const OWNER_LIMIT: usize = 256;
const REFERENCE_LIMIT: usize = 2048;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PreflightError {
    #[error("{0} must not be blank")]
    Blank(&'static str),
    #[error("{0} exceeds the {1}-byte limit")]
    TooLong(&'static str, usize),
    #[error("{0} contains a control character")]
    ControlCharacter(&'static str),
    #[error("Docker target must be a full canonical container ID")]
    InvalidContainerId,
    #[error("Proxmox node must be an ASCII hostname label")]
    InvalidNode,
    #[error("Proxmox VM ID must be positive")]
    InvalidVmid,
    #[error("unrecognized never-quarantine entry: {0:?} (expected docker:<id> or proxmox:<node>/<vmid>)")]
    UnrecognizedEntry(String),
}

/// A full canonical 64-hex Docker container ID - never an image tag, a name or
/// an ambiguous short ID (a mutable alias must never bind an approval).
fn validate_container_id(container_id: &str) -> Result<(), PreflightError> {
    if container_id.len() != 64
        || !container_id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(PreflightError::InvalidContainerId);
    }
    Ok(())
}

/// An ASCII hostname label for a Proxmox node.
fn validate_node(node: &str) -> Result<(), PreflightError> {
    if node.is_empty()
        || node.len() > 63
        || !node.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        || !node.as_bytes()[0].is_ascii_alphanumeric()
        || !node.as_bytes()[node.len() - 1].is_ascii_alphanumeric()
    {
        return Err(PreflightError::InvalidNode);
    }
    Ok(())
}

fn validate_metadata(value: &str, field: &'static str, limit: usize) -> Result<(), PreflightError> {
    if value.trim().is_empty() {
        return Err(PreflightError::Blank(field));
    }
    if value.len() > limit {
        return Err(PreflightError::TooLong(field, limit));
    }
    if value.chars().any(char::is_control) {
        return Err(PreflightError::ControlCharacter(field));
    }
    Ok(())
}

/// A concrete instance, never an image tag or an ambiguous short container ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineTarget {
    Docker { container_id: String },
    Proxmox { node: String, vmid: u32 },
}

/// Validated operator-supplied metadata. It proves no live infrastructure state.
/// Fields are immutable through this interface; there is no deserialize bypass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinePreflight {
    target: QuarantineTarget,
    data_owner: String,
    snapshot_restore_reference: String,
    management_network_plan: String,
}

impl QuarantinePreflight {
    pub fn new_docker(
        container_id: impl Into<String>,
        data_owner: impl Into<String>,
        snapshot_restore_reference: impl Into<String>,
        management_network_plan: impl Into<String>,
    ) -> Result<Self, PreflightError> {
        let container_id = container_id.into();
        // Do not trim or normalize target identities: approvals must bind to the
        // exact instance. A full ID avoids mutable name/image aliases.
        validate_container_id(&container_id)?;
        Self::from_target(
            QuarantineTarget::Docker { container_id },
            data_owner.into(),
            snapshot_restore_reference.into(),
            management_network_plan.into(),
        )
    }

    pub fn new_proxmox(
        node: impl Into<String>,
        vmid: u32,
        data_owner: impl Into<String>,
        snapshot_restore_reference: impl Into<String>,
        management_network_plan: impl Into<String>,
    ) -> Result<Self, PreflightError> {
        let node = node.into();
        validate_node(&node)?;
        if vmid == 0 {
            return Err(PreflightError::InvalidVmid);
        }
        // Live adapters must additionally resolve the node and check that the
        // VM ID exists in the expected cluster; positive IDs are only metadata.
        Self::from_target(
            QuarantineTarget::Proxmox { node, vmid },
            data_owner.into(),
            snapshot_restore_reference.into(),
            management_network_plan.into(),
        )
    }

    fn from_target(
        target: QuarantineTarget,
        data_owner: String,
        snapshot_restore_reference: String,
        management_network_plan: String,
    ) -> Result<Self, PreflightError> {
        validate_metadata(&data_owner, "data_owner", OWNER_LIMIT)?;
        validate_metadata(
            &snapshot_restore_reference,
            "snapshot_restore_reference",
            REFERENCE_LIMIT,
        )?;
        validate_metadata(
            &management_network_plan,
            "management_network_plan",
            REFERENCE_LIMIT,
        )?;
        Ok(Self {
            target,
            data_owner,
            snapshot_restore_reference,
            management_network_plan,
        })
    }

    pub fn target(&self) -> &QuarantineTarget {
        &self.target
    }
    pub fn data_owner(&self) -> &str {
        &self.data_owner
    }
    pub fn snapshot_restore_reference(&self) -> &str {
        &self.snapshot_restore_reference
    }
    pub fn management_network_plan(&self) -> &str {
        &self.management_network_plan
    }
}

impl QuarantineTarget {
    /// Public enum variants still need validation at every execution boundary.
    pub fn validate(&self) -> Result<(), PreflightError> {
        match self {
            Self::Docker { container_id } => validate_container_id(container_id),
            Self::Proxmox { node, vmid } => {
                validate_node(node)?;
                if *vmid == 0 {
                    return Err(PreflightError::InvalidVmid);
                }
                Ok(())
            }
        }
    }

    /// Parses one never-quarantine entry: `docker:<64-hex id>` or
    /// `proxmox:<node>/<vmid>`, using the same strict identity rules as
    /// `QuarantinePreflight`. This is how the operator protects its own control
    /// plane - e.g. the Proxmox node/VM that Clawforge itself runs on.
    pub fn parse(entry: &str) -> Result<Self, PreflightError> {
        let entry = entry.trim();
        if let Some(id) = entry.strip_prefix("docker:") {
            let id = id.trim();
            validate_container_id(id)?;
            return Ok(QuarantineTarget::Docker {
                container_id: id.to_string(),
            });
        }
        if let Some(rest) = entry.strip_prefix("proxmox:") {
            let (node, vmid) = rest
                .trim()
                .split_once('/')
                .ok_or_else(|| PreflightError::UnrecognizedEntry(entry.to_string()))?;
            let node = node.trim();
            validate_node(node)?;
            let vmid: u32 = vmid
                .trim()
                .parse()
                .map_err(|_| PreflightError::InvalidVmid)?;
            if vmid == 0 {
                return Err(PreflightError::InvalidVmid);
            }
            return Ok(QuarantineTarget::Proxmox {
                node: node.to_string(),
                vmid,
            });
        }
        Err(PreflightError::UnrecognizedEntry(entry.to_string()))
    }
}

/// Parses a comma-separated never-quarantine protection list. Blank entries are
/// dropped; a single malformed entry fails the whole list closed (never
/// silently skipped), matching the firewall never-block list. An adapter must
/// refuse to quarantine any target on this list.
pub fn never_quarantine_from_configured(
    configured: &str,
) -> Result<Vec<QuarantineTarget>, PreflightError> {
    configured
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(QuarantineTarget::parse)
        .collect()
}

/// True when `target` is on the protection list, so an adapter must refuse to
/// quarantine it (the Docker/Proxmox self-lockout guard).
pub fn is_protected(target: &QuarantineTarget, protected: &[QuarantineTarget]) -> bool {
    protected.contains(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docker_id() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn never_quarantine_parses_docker_and_proxmox_entries() {
        let id = docker_id();
        let list =
            never_quarantine_from_configured(&format!(" docker:{id} , proxmox:pve-node/101 "))
                .unwrap();
        assert_eq!(
            list,
            vec![
                QuarantineTarget::Docker {
                    container_id: id.clone()
                },
                QuarantineTarget::Proxmox {
                    node: "pve-node".into(),
                    vmid: 101
                },
            ]
        );
    }

    #[test]
    fn never_quarantine_is_empty_and_drops_blank_entries() {
        assert!(never_quarantine_from_configured("").unwrap().is_empty());
        assert!(never_quarantine_from_configured("  ,  ")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn never_quarantine_fails_closed_on_any_malformed_entry() {
        assert!(never_quarantine_from_configured("docker:short").is_err());
        assert!(never_quarantine_from_configured("something-else").is_err());
        assert!(never_quarantine_from_configured("proxmox:pve-node").is_err());
        assert!(never_quarantine_from_configured("proxmox:pve-node/0").is_err());
    }

    #[test]
    fn is_protected_matches_the_exact_target_only() {
        let list = vec![QuarantineTarget::Proxmox {
            node: "pve".into(),
            vmid: 101,
        }];
        assert!(is_protected(
            &QuarantineTarget::Proxmox {
                node: "pve".into(),
                vmid: 101
            },
            &list
        ));
        // A different VM ID on the same node is a different target.
        assert!(!is_protected(
            &QuarantineTarget::Proxmox {
                node: "pve".into(),
                vmid: 102
            },
            &list
        ));
        assert!(!is_protected(
            &QuarantineTarget::Docker {
                container_id: docker_id()
            },
            &list
        ));
    }

    #[test]
    fn concrete_targets_preserve_all_identity_components() {
        let id = docker_id();
        let docker =
            QuarantinePreflight::new_docker(&id, "owner", "snapshot", "network-plan").unwrap();
        assert_eq!(
            docker.target(),
            &QuarantineTarget::Docker { container_id: id }
        );
        let vm =
            QuarantinePreflight::new_proxmox("pve-node", 101, "owner", "snapshot", "network-plan")
                .unwrap();
        assert_eq!(
            vm.target(),
            &QuarantineTarget::Proxmox {
                node: "pve-node".into(),
                vmid: 101
            }
        );
        assert_eq!(vm.data_owner(), "owner");
        assert_eq!(vm.snapshot_restore_reference(), "snapshot");
        assert_eq!(vm.management_network_plan(), "network-plan");
        let other =
            QuarantinePreflight::new_proxmox("pve-node", 102, "owner", "snapshot", "network-plan")
                .unwrap();
        assert_ne!(vm.target(), other.target());
    }

    #[test]
    fn docker_rejects_images_names_short_ids_and_noncanonical_ids() {
        for id in [
            "nginx:latest".to_string(),
            "container-name".into(),
            "a".repeat(12),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            " ".repeat(64),
            format!(" {}", docker_id()),
        ] {
            assert_eq!(
                QuarantinePreflight::new_docker(id, "owner", "snapshot", "plan"),
                Err(PreflightError::InvalidContainerId)
            );
        }
    }

    #[test]
    fn proxmox_rejects_ambiguous_nodes_and_zero_vmid() {
        for node in [
            "",
            "-pve",
            "pve-",
            "pve/node",
            "pve.node",
            " pve",
            "pve ",
            "pve\nnode",
            "pvé",
        ] {
            assert_eq!(
                QuarantinePreflight::new_proxmox(node, 101, "owner", "snapshot", "plan"),
                Err(PreflightError::InvalidNode)
            );
        }
        assert_eq!(
            QuarantinePreflight::new_proxmox("a".repeat(64), 101, "owner", "snapshot", "plan"),
            Err(PreflightError::InvalidNode)
        );
        assert_eq!(
            QuarantinePreflight::new_proxmox("pve", 0, "owner", "snapshot", "plan"),
            Err(PreflightError::InvalidVmid)
        );
        assert!(
            QuarantinePreflight::new_proxmox("a".repeat(63), 101, "owner", "snapshot", "plan")
                .is_ok()
        );
    }

    #[test]
    fn required_metadata_rejects_blanks_controls_and_oversized_values_on_both_platforms() {
        let fields = [
            ("data_owner", OWNER_LIMIT),
            ("snapshot_restore_reference", REFERENCE_LIMIT),
            ("management_network_plan", REFERENCE_LIMIT),
        ];
        for (index, (field, limit)) in fields.into_iter().enumerate() {
            for (value, expected) in [
                (String::new(), PreflightError::Blank(field)),
                (" ".into(), PreflightError::Blank(field)),
                ("\u{2003}".into(), PreflightError::Blank(field)),
                ("x\nvalue".into(), PreflightError::ControlCharacter(field)),
                ("x\0value".into(), PreflightError::ControlCharacter(field)),
                (
                    "x\u{0085}value".into(),
                    PreflightError::ControlCharacter(field),
                ),
                ("x".repeat(limit + 1), PreflightError::TooLong(field, limit)),
                (
                    "é".repeat(limit / 2 + 1),
                    PreflightError::TooLong(field, limit),
                ),
            ] {
                let mut args = [
                    "owner".to_string(),
                    "snapshot".to_string(),
                    "plan".to_string(),
                ];
                args[index] = value;
                assert_eq!(
                    QuarantinePreflight::new_docker(docker_id(), &args[0], &args[1], &args[2]),
                    Err(expected.clone())
                );
                assert_eq!(
                    QuarantinePreflight::new_proxmox("pve", 101, &args[0], &args[1], &args[2]),
                    Err(expected)
                );
            }
        }
    }

    #[test]
    fn metadata_byte_limits_are_inclusive_without_normalizing_content() {
        let owner = "é".repeat(OWNER_LIMIT / 2);
        let snapshot = "x".repeat(REFERENCE_LIMIT);
        let plan = "x".repeat(REFERENCE_LIMIT);
        for preflight in [
            QuarantinePreflight::new_docker(docker_id(), &owner, &snapshot, &plan).unwrap(),
            QuarantinePreflight::new_proxmox("pve", 101, &owner, &snapshot, &plan).unwrap(),
        ] {
            assert_eq!(preflight.data_owner(), owner);
            assert_eq!(preflight.snapshot_restore_reference(), snapshot);
            assert_eq!(preflight.management_network_plan(), plan);
        }
        let p = QuarantinePreflight::new_docker(docker_id(), " owner ", "snapshot-ref", "plan-ref")
            .unwrap();
        assert_eq!(p.data_owner(), " owner ");
    }
}
