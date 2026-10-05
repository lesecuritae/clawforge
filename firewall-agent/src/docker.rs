//! Live Docker container quarantine adapter.
//!
//! Isolates a container by disconnecting it from every Docker network it is on
//! (returning that list so a rollback can reconnect it). Reversible, destroys
//! nothing - no image, volume or container change, only network attachment.
//! Uses the `docker` CLI with explicit argv (never a shell), exactly like
//! [`crate::NftablesAdapter`] uses `nft`, so a container identity can never
//! inject a second command. Reuses the plan-only [`crate::quarantine`] module's
//! [`QuarantineTarget`] and never-quarantine protection list so the operator's
//! own control-plane containers can never be isolated.
//!
//! Config: `CLAWFORGE_DOCKER_NEVER_QUARANTINE` (comma-separated
//! `docker:<64-hex id>` entries) and `CLAWFORGE_DOCKER_BIN` (defaults to
//! `docker`).

use crate::quarantine::{self, QuarantineTarget};
use crate::{AdapterError, VerificationResult};
use tokio::process::Command;

const NEVER_QUARANTINE_VAR: &str = "CLAWFORGE_DOCKER_NEVER_QUARANTINE";
const DOCKER_BIN_VAR: &str = "CLAWFORGE_DOCKER_BIN";
const NETWORKS_FORMAT: &str = "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}";

/// The container's current network names, parsed from the space-separated
/// `docker inspect` template output. An empty result means it is isolated.
fn parse_networks(inspect_output: &str) -> Vec<String> {
    inspect_output
        .split_whitespace()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// Read-only result of inspecting a container before quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerPreflight {
    pub container_id: String,
    pub networks: Vec<String>,
    /// True when the container is on no networks (already isolated).
    pub currently_quarantined: bool,
    /// True when the container is on the never-quarantine protection list.
    pub protected: bool,
}

pub struct DockerAdapter {
    docker_bin: String,
    never_quarantine: Vec<QuarantineTarget>,
}

impl Default for DockerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerAdapter {
    pub fn new() -> Self {
        let never_quarantine = match std::env::var(NEVER_QUARANTINE_VAR) {
            Ok(raw) => quarantine::never_quarantine_from_configured(&raw).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        Self {
            docker_bin: std::env::var(DOCKER_BIN_VAR).unwrap_or_else(|_| "docker".to_string()),
            never_quarantine,
        }
    }

    fn container_id(target: &QuarantineTarget) -> Result<&str, AdapterError> {
        match target {
            QuarantineTarget::Docker { container_id } => Ok(container_id.as_str()),
            QuarantineTarget::Proxmox { .. } => Err(AdapterError::InvalidTarget(
                "the docker adapter requires a Docker target, not a Proxmox one".to_string(),
            )),
        }
    }

    async fn run(&self, args: &[&str]) -> Result<String, AdapterError> {
        let output = Command::new(&self.docker_bin)
            .args(args)
            .output()
            .await
            .map_err(|error| {
                AdapterError::Apply(format!(
                    "docker {} failed to start: {error}",
                    args.first().copied().unwrap_or_default()
                ))
            })?;
        if !output.status.success() {
            return Err(AdapterError::Apply(format!(
                "docker {} failed: {}",
                args.first().copied().unwrap_or_default(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    async fn networks(&self, container_id: &str) -> Result<Vec<String>, AdapterError> {
        let output = self
            .run(&["inspect", "-f", NETWORKS_FORMAT, container_id])
            .await
            .map_err(|error| AdapterError::Verify(format!("docker inspect: {error}")))?;
        Ok(parse_networks(&output))
    }

    /// Read-only: lists the container's networks without changing anything.
    pub async fn preflight(&self, target: &QuarantineTarget) -> Result<DockerPreflight, AdapterError> {
        let id = Self::container_id(target)?;
        let protected = quarantine::is_protected(target, &self.never_quarantine);
        let networks = self.networks(id).await?;
        Ok(DockerPreflight {
            container_id: id.to_string(),
            currently_quarantined: networks.is_empty(),
            networks,
            protected,
        })
    }

    /// Disconnects the container from all its networks. Returns the networks it
    /// was on - record these to reconnect on rollback. A protected container is
    /// refused (even as a dry run); `dry_run` otherwise lists the networks that
    /// would be disconnected without changing anything.
    pub async fn apply(&self, target: &QuarantineTarget, dry_run: bool) -> Result<Vec<String>, AdapterError> {
        let id = Self::container_id(target)?;
        if quarantine::is_protected(target, &self.never_quarantine) {
            return Err(AdapterError::InvalidTarget(format!(
                "docker container {id} is on the never-quarantine protection list \
                 ({NEVER_QUARANTINE_VAR}); refusing to quarantine"
            )));
        }
        let networks = self.networks(id).await?;
        if dry_run {
            return Ok(networks);
        }
        for network in &networks {
            self.run(&["network", "disconnect", network.as_str(), id]).await?;
        }
        Ok(networks)
    }

    /// Confirms the container is on no networks.
    pub async fn verify(&self, target: &QuarantineTarget) -> Result<VerificationResult, AdapterError> {
        let id = Self::container_id(target)?;
        let networks = self.networks(id).await?;
        Ok(if networks.is_empty() {
            VerificationResult::Verified
        } else {
            VerificationResult::NotPresent
        })
    }

    /// Reconnects the container to the given networks (from apply's receipt).
    /// Idempotent per network: a network it is already on is skipped rather
    /// than failing the whole rollback.
    pub async fn rollback(&self, target: &QuarantineTarget, networks: &[String]) -> Result<(), AdapterError> {
        let id = Self::container_id(target)?;
        let current = self.networks(id).await.unwrap_or_default();
        for network in networks {
            if current.iter().any(|existing| existing == network) {
                continue;
            }
            self.run(&["network", "connect", network.as_str(), id])
                .await
                .map_err(|error| AdapterError::Rollback(error.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_networks_splits_and_drops_blanks() {
        assert_eq!(parse_networks("bridge mynet "), vec!["bridge".to_string(), "mynet".to_string()]);
        assert_eq!(parse_networks("   "), Vec::<String>::new());
        assert_eq!(parse_networks(""), Vec::<String>::new());
    }

    fn docker_id() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[tokio::test]
    async fn apply_refuses_a_protected_container_before_any_docker_call() {
        let id = docker_id();
        let adapter = DockerAdapter {
            docker_bin: "/nonexistent/docker".to_string(),
            never_quarantine: vec![QuarantineTarget::Docker {
                container_id: id.clone(),
            }],
        };
        let target = QuarantineTarget::Docker { container_id: id };
        let error = adapter.apply(&target, true).await.unwrap_err();
        assert!(
            matches!(error, AdapterError::InvalidTarget(message) if message.contains("never-quarantine")),
            "a protected container must be refused with a never-quarantine error",
        );
    }

    #[tokio::test]
    async fn proxmox_target_is_rejected_by_the_docker_adapter() {
        let adapter = DockerAdapter {
            docker_bin: "/nonexistent/docker".to_string(),
            never_quarantine: Vec::new(),
        };
        let target = QuarantineTarget::Proxmox {
            node: "IT13".to_string(),
            vmid: 100,
        };
        assert!(matches!(
            adapter.apply(&target, true).await.unwrap_err(),
            AdapterError::InvalidTarget(_)
        ));
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon + a disposable test container (CLAWFORGE_DOCKER_TEST_CONTAINER)"]
    async fn live_quarantine_cycle_against_a_disposable_container() {
        let name = std::env::var("CLAWFORGE_DOCKER_TEST_CONTAINER")
            .expect("CLAWFORGE_DOCKER_TEST_CONTAINER");
        // The test harness passes the container's full 64-hex ID.
        let target = QuarantineTarget::Docker {
            container_id: name,
        };
        let adapter = DockerAdapter::new();

        let pre = adapter.preflight(&target).await.expect("preflight");
        assert!(!pre.protected);
        assert!(!pre.currently_quarantined, "start from a connected container");
        let original = pre.networks.clone();
        assert!(!original.is_empty());

        let disconnected = adapter.apply(&target, false).await.expect("apply");
        assert_eq!(disconnected, original);
        assert_eq!(
            adapter.verify(&target).await.expect("verify after apply"),
            VerificationResult::Verified
        );

        adapter.rollback(&target, &original).await.expect("rollback");
        assert_eq!(
            adapter.verify(&target).await.expect("verify after rollback"),
            VerificationResult::NotPresent
        );
    }
}
