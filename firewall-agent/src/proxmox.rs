//! Live Proxmox VE quarantine adapter.
//!
//! Isolates a VM's primary NIC (`net0`) via the Proxmox config API by setting
//! `link_down=1` - a fully reversible change that preserves the MAC address and
//! bridge, needs no VM restart, and destroys nothing. This is the live
//! counterpart to the plan-only [`crate::quarantine`] module (which performs no
//! IO); it reuses that module's [`QuarantineTarget`] and the never-quarantine
//! protection list so the operator's own control-plane VMs - above all the node
//! Clawforge itself runs on - can never be isolated.
//!
//! Credentials are each optional with an infallible constructor, matching the
//! other adapters; a method that actually needs them fails closed with a clear
//! error. `CLAWFORGE_PROXMOX_HOST` (`host:8006`), `CLAWFORGE_PROXMOX_USER`
//! (`user@realm`), `CLAWFORGE_PROXMOX_PASSWORD`(`_FILE`), and
//! `CLAWFORGE_PROXMOX_NEVER_QUARANTINE` (comma-separated `proxmox:<node>/<vmid>`
//! entries, parsed by [`crate::quarantine::never_quarantine_from_configured`]).

use crate::quarantine::{self, QuarantineTarget};
use crate::{AdapterError, VerificationResult};

const HOST_VAR: &str = "CLAWFORGE_PROXMOX_HOST";
const USER_VAR: &str = "CLAWFORGE_PROXMOX_USER";
const PASSWORD_FILE_VAR: &str = "CLAWFORGE_PROXMOX_PASSWORD_FILE";
const PASSWORD_VAR: &str = "CLAWFORGE_PROXMOX_PASSWORD";
const NEVER_QUARANTINE_VAR: &str = "CLAWFORGE_PROXMOX_NEVER_QUARANTINE";

/// Removes any existing `link_down=...` option from a `net0`-style value,
/// keeping every other option (model/MAC, bridge, firewall, tag, ...) intact.
fn strip_link_down(net0: &str) -> String {
    net0.split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty() && !token.starts_with("link_down="))
        .collect::<Vec<_>>()
        .join(",")
}

/// True when the NIC is already isolated (`link_down=1`).
pub(crate) fn net0_is_quarantined(net0: &str) -> bool {
    net0.split(',').map(str::trim).any(|token| token == "link_down=1")
}

/// The isolated form: the same NIC plus `link_down=1`. Idempotent - a NIC that
/// is already quarantined (or carries a stale `link_down=0`) never ends up with
/// a duplicated or conflicting flag.
pub(crate) fn quarantine_net0(net0: &str) -> String {
    format!("{},link_down=1", strip_link_down(net0))
}

/// The restored form: the NIC with any `link_down` option removed.
pub(crate) fn unquarantine_net0(net0: &str) -> String {
    strip_link_down(net0)
}

struct ProxmoxCredentials {
    host: String,
    user: String,
    password: String,
}

/// Read-only result of inspecting a Proxmox VM before quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxPreflight {
    pub node: String,
    pub vmid: u32,
    pub net0: String,
    pub currently_quarantined: bool,
    /// True when the VM is on the never-quarantine protection list, so `apply`
    /// refuses to isolate it (the self-lockout guard).
    pub protected: bool,
}

pub struct ProxmoxAdapter {
    credentials: Result<ProxmoxCredentials, String>,
    never_quarantine: Vec<QuarantineTarget>,
    http: reqwest::Client,
}

impl Default for ProxmoxAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxmoxAdapter {
    pub fn new() -> Self {
        let credentials = Self::load_credentials();
        let never_quarantine = match std::env::var(NEVER_QUARANTINE_VAR) {
            Ok(raw) => quarantine::never_quarantine_from_configured(&raw).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        // The Proxmox API uses the node's self-signed certificate; it is an
        // internal management endpoint reached by host/credentials, so an
        // invalid cert chain is accepted deliberately (the password, not a
        // public CA, is the trust anchor here).
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
        Self {
            credentials,
            never_quarantine,
            http,
        }
    }

    fn load_credentials() -> Result<ProxmoxCredentials, String> {
        let host = std::env::var(HOST_VAR).ok().filter(|value| !value.is_empty());
        let user = std::env::var(USER_VAR).ok().filter(|value| !value.is_empty());
        let password =
            clawforge_secret::load_optional(PASSWORD_FILE_VAR, PASSWORD_VAR).map_err(|error| error.to_string())?;
        match (host, user, password) {
            (Some(host), Some(user), Some(password)) => Ok(ProxmoxCredentials { host, user, password }),
            _ => Err(format!(
                "{HOST_VAR}, {USER_VAR} and {PASSWORD_VAR}/_FILE must all be configured"
            )),
        }
    }

    fn credentials(&self) -> Result<&ProxmoxCredentials, AdapterError> {
        self.credentials
            .as_ref()
            .map_err(|error| AdapterError::Apply(error.clone()))
    }

    fn node_vmid(target: &QuarantineTarget) -> Result<(&str, u32), AdapterError> {
        match target {
            QuarantineTarget::Proxmox { node, vmid } => Ok((node.as_str(), *vmid)),
            QuarantineTarget::Docker { .. } => Err(AdapterError::InvalidTarget(
                "the proxmox adapter requires a Proxmox target, not a Docker one".to_string(),
            )),
        }
    }

    /// Authenticates with username/password and returns `(ticket, csrf_token)`.
    /// The ticket is a short-lived cookie; the CSRF token is required for writes.
    async fn ticket(&self) -> Result<(String, String), AdapterError> {
        let credentials = self.credentials()?;
        let response = self
            .http
            .post(format!(
                "https://{}/api2/json/access/ticket",
                credentials.host
            ))
            .form(&[
                ("username", credentials.user.as_str()),
                ("password", credentials.password.as_str()),
            ])
            .send()
            .await
            .map_err(|error| AdapterError::Apply(format!("proxmox login failed: {error}")))?;
        if !response.status().is_success() {
            return Err(AdapterError::Apply(format!(
                "proxmox login rejected: HTTP {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|error| AdapterError::Apply(format!("proxmox login response was not JSON: {error}")))?;
        let ticket = body["data"]["ticket"]
            .as_str()
            .ok_or_else(|| AdapterError::Apply("proxmox login response had no ticket".to_string()))?
            .to_string();
        let csrf = body["data"]["CSRFPreventionToken"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        Ok((ticket, csrf))
    }

    async fn read_net0(&self, node: &str, vmid: u32, ticket: &str) -> Result<String, AdapterError> {
        let credentials = self.credentials()?;
        let response = self
            .http
            .get(format!(
                "https://{}/api2/json/nodes/{node}/qemu/{vmid}/config",
                credentials.host
            ))
            .header("Cookie", format!("PVEAuthCookie={ticket}"))
            .send()
            .await
            .map_err(|error| AdapterError::Verify(format!("proxmox config read failed: {error}")))?;
        if !response.status().is_success() {
            return Err(AdapterError::Verify(format!(
                "proxmox config read rejected: HTTP {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|error| AdapterError::Verify(format!("proxmox config response was not JSON: {error}")))?;
        body["data"]["net0"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                AdapterError::Verify(format!("vm {vmid} on {node} has no net0 NIC to quarantine"))
            })
    }

    async fn write_net0(
        &self,
        node: &str,
        vmid: u32,
        value: &str,
        ticket: &str,
        csrf: &str,
    ) -> Result<(), AdapterError> {
        let credentials = self.credentials()?;
        let response = self
            .http
            .post(format!(
                "https://{}/api2/json/nodes/{node}/qemu/{vmid}/config",
                credentials.host
            ))
            .header("Cookie", format!("PVEAuthCookie={ticket}"))
            .header("CSRFPreventionToken", csrf)
            .form(&[("net0", value)])
            .send()
            .await
            .map_err(|error| AdapterError::Apply(format!("proxmox config write failed: {error}")))?;
        if !response.status().is_success() {
            return Err(AdapterError::Apply(format!(
                "proxmox config write rejected: HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    /// Read-only: inspects the VM's current NIC state without changing anything.
    pub async fn preflight(&self, target: &QuarantineTarget) -> Result<ProxmoxPreflight, AdapterError> {
        let (node, vmid) = Self::node_vmid(target)?;
        let protected = quarantine::is_protected(target, &self.never_quarantine);
        let (ticket, _csrf) = self.ticket().await?;
        let net0 = self.read_net0(node, vmid, &ticket).await?;
        Ok(ProxmoxPreflight {
            node: node.to_string(),
            vmid,
            currently_quarantined: net0_is_quarantined(&net0),
            net0,
            protected,
        })
    }

    /// Isolates the VM's `net0` NIC (`link_down=1`). A protected target is
    /// refused - even as a dry run - and `dry_run` otherwise renders the change
    /// without writing it.
    pub async fn apply(&self, target: &QuarantineTarget, dry_run: bool) -> Result<String, AdapterError> {
        let (node, vmid) = Self::node_vmid(target)?;
        if quarantine::is_protected(target, &self.never_quarantine) {
            return Err(AdapterError::InvalidTarget(format!(
                "proxmox target {node}/{vmid} is on the never-quarantine protection list \
                 ({NEVER_QUARANTINE_VAR}); refusing to quarantine"
            )));
        }
        let (ticket, csrf) = self.ticket().await?;
        let current = self.read_net0(node, vmid, &ticket).await?;
        let quarantined = quarantine_net0(&current);
        if dry_run {
            return Ok(format!(
                "DRY-RUN proxmox quarantine {node}/{vmid}: net0 {current:?} -> {quarantined:?}"
            ));
        }
        self.write_net0(node, vmid, &quarantined, &ticket, &csrf).await?;
        Ok(format!("quarantined proxmox {node}/{vmid}: net0 -> {quarantined:?}"))
    }

    /// Confirms the NIC is isolated.
    pub async fn verify(&self, target: &QuarantineTarget) -> Result<VerificationResult, AdapterError> {
        let (node, vmid) = Self::node_vmid(target)?;
        let (ticket, _csrf) = self.ticket().await?;
        let net0 = self.read_net0(node, vmid, &ticket).await?;
        Ok(if net0_is_quarantined(&net0) {
            VerificationResult::Verified
        } else {
            VerificationResult::NotPresent
        })
    }

    /// Restores connectivity by removing the `link_down` flag. Idempotent: a NIC
    /// that is not quarantined is a clean success, not an error.
    pub async fn rollback(&self, target: &QuarantineTarget) -> Result<(), AdapterError> {
        let (node, vmid) = Self::node_vmid(target)?;
        let (ticket, csrf) = self.ticket().await?;
        let current = self.read_net0(node, vmid, &ticket).await?;
        if !net0_is_quarantined(&current) {
            return Ok(());
        }
        let restored = unquarantine_net0(&current);
        self.write_net0(node, vmid, &restored, &ticket, &csrf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NIC: &str = "virtio=BC:24:11:6D:2B:EF,bridge=vmbr0";

    #[test]
    fn quarantine_appends_link_down_and_preserves_the_nic() {
        assert_eq!(quarantine_net0(NIC), format!("{NIC},link_down=1"));
    }

    #[test]
    fn quarantine_is_idempotent_and_clears_a_stale_flag() {
        assert_eq!(quarantine_net0(&format!("{NIC},link_down=1")), format!("{NIC},link_down=1"));
        assert_eq!(quarantine_net0(&format!("{NIC},link_down=0")), format!("{NIC},link_down=1"));
    }

    #[test]
    fn unquarantine_removes_only_link_down() {
        assert_eq!(unquarantine_net0(&format!("{NIC},link_down=1")), NIC);
        assert_eq!(unquarantine_net0(NIC), NIC);
    }

    #[test]
    fn is_quarantined_matches_the_flag_exactly() {
        assert!(net0_is_quarantined(&format!("{NIC},link_down=1")));
        assert!(!net0_is_quarantined(NIC));
        assert!(!net0_is_quarantined(&format!("{NIC},link_down=0")));
    }

    #[tokio::test]
    async fn apply_refuses_a_protected_vm_before_any_api_call() {
        let adapter = ProxmoxAdapter {
            credentials: Err("unused: refused before login".to_string()),
            never_quarantine: vec![QuarantineTarget::Proxmox {
                node: "IT13".to_string(),
                vmid: 100,
            }],
            http: reqwest::Client::new(),
        };
        let target = QuarantineTarget::Proxmox {
            node: "IT13".to_string(),
            vmid: 100,
        };
        let error = adapter.apply(&target, true).await.unwrap_err();
        assert!(
            matches!(error, AdapterError::InvalidTarget(message) if message.contains("never-quarantine")),
            "a protected VM must be refused with a never-quarantine error",
        );
    }

    #[tokio::test]
    #[ignore = "requires a real Proxmox host + a disposable test VM; set CLAWFORGE_PROXMOX_* and CLAWFORGE_PROXMOX_TEST_NODE/_VMID"]
    async fn live_quarantine_cycle_against_the_test_vm() {
        let node = std::env::var("CLAWFORGE_PROXMOX_TEST_NODE").expect("CLAWFORGE_PROXMOX_TEST_NODE");
        let vmid: u32 = std::env::var("CLAWFORGE_PROXMOX_TEST_VMID")
            .expect("CLAWFORGE_PROXMOX_TEST_VMID")
            .parse()
            .expect("vmid");
        let adapter = ProxmoxAdapter::new();
        let target = QuarantineTarget::Proxmox { node, vmid };

        let pre = adapter.preflight(&target).await.expect("preflight");
        assert!(!pre.protected, "the test VM must not be protected");
        assert!(!pre.currently_quarantined, "start from a clean, non-quarantined NIC");

        adapter.apply(&target, false).await.expect("apply");
        assert_eq!(
            adapter.verify(&target).await.expect("verify after apply"),
            VerificationResult::Verified
        );

        adapter.rollback(&target).await.expect("rollback");
        assert_eq!(
            adapter.verify(&target).await.expect("verify after rollback"),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    async fn docker_target_is_rejected_by_the_proxmox_adapter() {
        let adapter = ProxmoxAdapter {
            credentials: Err("unused".to_string()),
            never_quarantine: Vec::new(),
            http: reqwest::Client::new(),
        };
        let target = QuarantineTarget::Docker {
            container_id: "0123456789abcdef".repeat(4),
        };
        assert!(matches!(
            adapter.apply(&target, true).await.unwrap_err(),
            AdapterError::InvalidTarget(_)
        ));
    }
}
