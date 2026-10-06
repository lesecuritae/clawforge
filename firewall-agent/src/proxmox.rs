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
#[cfg(not(test))]
const TASK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const TASK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
#[cfg(not(test))]
const TASK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
#[cfg(test)]
const TASK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

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
    net0.split(',')
        .map(str::trim)
        .any(|token| token == "link_down=1")
}

/// The isolated form: the same NIC plus `link_down=1`. Idempotent - a NIC that
/// is already quarantined (or carries a stale `link_down=0`) never ends up with
/// a duplicated or conflicting flag.
pub(crate) fn quarantine_net0(net0: &str) -> String {
    format!("{},link_down=1", strip_link_down(net0))
}

/// The restored form: the NIC with any `link_down` option removed.
#[cfg(test)]
fn unquarantine_net0(net0: &str) -> String {
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

#[derive(Debug)]
pub struct ProxmoxApplied {
    pub summary: String,
    pub original_net0: String,
}

struct NicState {
    net0: String,
    digest: String,
}

fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.chars().any(|c| c.is_control() || c.is_whitespace())
        || host.contains(['/', '?', '#', '@'])
    {
        return Err("Proxmox host must be an HTTPS authority without userinfo or path".into());
    }
    let url = reqwest::Url::parse(&format!("https://{host}"))
        .map_err(|_| "invalid Proxmox host".to_string())?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid Proxmox HTTPS authority".into());
    }
    Ok(())
}

fn parse_nic_state(body: &serde_json::Value) -> Result<NicState, AdapterError> {
    let data = body
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdapterError::Verify("VM config data missing".into()))?;
    if data.keys().any(|key| {
        key.starts_with("net")
            && key != "net0"
            && key.len() > 3
            && key[3..].bytes().all(|b| b.is_ascii_digit())
    }) {
        return Err(AdapterError::InvalidTarget(
            "multi-NIC VM needs a reviewed full-network isolation plan".into(),
        ));
    }
    let net0 = data
        .get("net0")
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            !value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| AdapterError::Verify("VM has no valid net0 NIC".into()))?
        .to_owned();
    let digest = data
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            AdapterError::Verify(
                "VM config digest missing or invalid; refusing non-atomic mutation".into(),
            )
        })?
        .to_owned();
    Ok(NicState { net0, digest })
}

/// Only our exact isolated configuration may be restored; operator drift is
/// never overwritten. A matching original state means a previous retry worked.
fn rollback_needed(current: &str, original: &str) -> Result<bool, AdapterError> {
    if current == original {
        return Ok(false);
    }
    if current != quarantine_net0(original) {
        return Err(AdapterError::Rollback(
            "VM NIC changed after quarantine; refusing to overwrite operator configuration".into(),
        ));
    }
    Ok(true)
}

pub struct ProxmoxAdapter {
    credentials: Result<ProxmoxCredentials, String>,
    never_quarantine: Result<Vec<QuarantineTarget>, String>,
    http: Result<reqwest::Client, String>,
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
            Ok(raw) => quarantine::never_quarantine_from_configured(&raw)
                .map_err(|_| format!("invalid {NEVER_QUARANTINE_VAR}; quarantine disabled")),
            Err(_) => Ok(Vec::new()),
        };
        // Trust a configured CA; never silently disable server authentication.
        let http = Self::http_client();
        Self {
            credentials,
            never_quarantine,
            http,
        }
    }

    fn http_client() -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none());
        if let Ok(path) = std::env::var("CLAWFORGE_PROXMOX_CA_FILE") {
            let pem = std::fs::read(path).map_err(|_| "cannot read Proxmox CA file".to_string())?;
            let ca = reqwest::Certificate::from_pem(&pem)
                .map_err(|_| "invalid Proxmox CA certificate".to_string())?;
            builder = builder.add_root_certificate(ca);
        }
        builder
            .build()
            .map_err(|_| "cannot build verified Proxmox TLS client".to_string())
    }

    fn http(&self) -> Result<&reqwest::Client, AdapterError> {
        self.http
            .as_ref()
            .map_err(|message| AdapterError::Apply(message.clone()))
    }

    fn protection_list(&self) -> Result<&[QuarantineTarget], AdapterError> {
        self.never_quarantine
            .as_deref()
            .map_err(|message| AdapterError::InvalidTarget(message.clone()))
    }

    fn load_credentials() -> Result<ProxmoxCredentials, String> {
        let host = std::env::var(HOST_VAR)
            .ok()
            .filter(|value| !value.is_empty());
        let user = std::env::var(USER_VAR)
            .ok()
            .filter(|value| !value.is_empty());
        let password = clawforge_secret::load_optional(PASSWORD_FILE_VAR, PASSWORD_VAR)
            .map_err(|error| error.to_string())?;
        match (host, user, password) {
            (Some(host), Some(user), Some(password)) => {
                validate_host(&host)?;
                Ok(ProxmoxCredentials {
                    host,
                    user,
                    password,
                })
            }
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
        target.validate().map_err(|_| {
            AdapterError::InvalidTarget("invalid canonical quarantine target".to_string())
        })?;
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
            .http()?
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
        let body: serde_json::Value = response.json().await.map_err(|error| {
            AdapterError::Apply(format!("proxmox login response was not JSON: {error}"))
        })?;
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

    async fn read_net0(
        &self,
        node: &str,
        vmid: u32,
        ticket: &str,
    ) -> Result<NicState, AdapterError> {
        let credentials = self.credentials()?;
        let response = self
            .http()?
            .get(format!(
                "https://{}/api2/json/nodes/{node}/qemu/{vmid}/config",
                credentials.host
            ))
            .header("Cookie", format!("PVEAuthCookie={ticket}"))
            .send()
            .await
            .map_err(|error| {
                AdapterError::Verify(format!("proxmox config read failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(AdapterError::Verify(format!(
                "proxmox config read rejected: HTTP {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response.json().await.map_err(|error| {
            AdapterError::Verify(format!("proxmox config response was not JSON: {error}"))
        })?;
        parse_nic_state(&body)
    }

    async fn write_net0(
        &self,
        node: &str,
        vmid: u32,
        value: &str,
        digest: &str,
        ticket: &str,
        csrf: &str,
    ) -> Result<(), AdapterError> {
        let credentials = self.credentials()?;
        let response = self
            .http()?
            .post(format!(
                "https://{}/api2/json/nodes/{node}/qemu/{vmid}/config",
                credentials.host
            ))
            .header("Cookie", format!("PVEAuthCookie={ticket}"))
            .header("CSRFPreventionToken", csrf)
            .form(&[("net0", value), ("digest", digest)])
            .send()
            .await
            .map_err(|error| {
                AdapterError::Apply(format!("proxmox config write failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(AdapterError::Apply(format!(
                "proxmox config write rejected: HTTP {}",
                response.status()
            )));
        }
        // POST config is update_vm_async: HTTP success only accepts the worker.
        // No background_delay is requested, so a qmconfig UPID is required.
        // Proxmox primary source: src/PVE/API2/Qemu.pm update_vm_async.
        let body: serde_json::Value = response.json().await.map_err(|_| {
            AdapterError::Apply("proxmox config write returned invalid JSON".into())
        })?;
        let upid = body["data"].as_str().ok_or_else(|| {
            AdapterError::Apply("proxmox config write returned no asynchronous task ID".into())
        })?;
        self.wait_for_config_task(node, vmid, upid, ticket).await
    }

    async fn wait_for_config_task(
        &self,
        node: &str,
        vmid: u32,
        upid: &str,
        ticket: &str,
    ) -> Result<(), AdapterError> {
        let parts: Vec<_> = upid.split(':').collect();
        if upid.len() > 1024
            || parts.len() != 9
            || parts[0] != "UPID"
            || parts[1] != node
            || parts[5] != "qmconfig"
            || parts[6] != vmid.to_string()
            || parts[7].is_empty()
            || !parts[8].is_empty()
            || parts[2..5]
                .iter()
                .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_hexdigit()))
            || upid
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && !b"_:@.!+-".contains(&b))
        {
            return Err(AdapterError::Apply("invalid Proxmox config task ID".into()));
        }
        let credentials = self.credentials()?;
        let mut url = reqwest::Url::parse(&format!("https://{}", credentials.host))
            .map_err(|_| AdapterError::Apply("invalid Proxmox host".into()))?;
        url.path_segments_mut()
            .map_err(|_| AdapterError::Apply("invalid Proxmox task endpoint".into()))?
            .extend(["api2", "json", "nodes", node, "tasks", upid, "status"]);
        let poll = async {
            loop {
                let response = self
                    .http()?
                    .get(url.clone())
                    .header("Cookie", format!("PVEAuthCookie={ticket}"))
                    .send()
                    .await
                    .map_err(|_| {
                        AdapterError::Apply(
                            "Proxmox task status unavailable; completion unknown".into(),
                        )
                    })?;
                if !response.status().is_success() {
                    return Err(AdapterError::Apply(
                        "Proxmox task status rejected; completion unknown".into(),
                    ));
                }
                let body: serde_json::Value = response.json().await.map_err(|_| {
                    AdapterError::Apply("invalid Proxmox task status; completion unknown".into())
                })?;
                match body["data"]["status"].as_str() {
                    Some("stopped") if body["data"]["exitstatus"].as_str() == Some("OK") => {
                        return Ok(())
                    }
                    Some("stopped") => {
                        return Err(AdapterError::Apply("Proxmox config task failed".into()))
                    }
                    Some("running") => tokio::time::sleep(TASK_POLL_INTERVAL).await,
                    _ => {
                        return Err(AdapterError::Apply(
                            "invalid Proxmox task status; completion unknown".into(),
                        ))
                    }
                }
            }
        };
        tokio::time::timeout(TASK_TIMEOUT, poll)
            .await
            .map_err(|_| {
                AdapterError::Apply(
                    "Proxmox config task timed out; completion unknown, review required".into(),
                )
            })?
    }

    /// Read-only: inspects the VM's current NIC state without changing anything.
    pub async fn preflight(
        &self,
        target: &QuarantineTarget,
    ) -> Result<ProxmoxPreflight, AdapterError> {
        let (node, vmid) = Self::node_vmid(target)?;
        let protected = quarantine::is_protected(target, self.protection_list()?);
        let (ticket, _csrf) = self.ticket().await?;
        let net0 = self.read_net0(node, vmid, &ticket).await?;
        Ok(ProxmoxPreflight {
            node: node.to_string(),
            vmid,
            currently_quarantined: net0_is_quarantined(&net0.net0),
            net0: net0.net0,
            protected,
        })
    }

    /// Isolates the VM's `net0` NIC (`link_down=1`). A protected target is
    /// refused - even as a dry run - and `dry_run` otherwise renders the change
    /// without writing it.
    pub async fn apply(
        &self,
        target: &QuarantineTarget,
        dry_run: bool,
    ) -> Result<ProxmoxApplied, AdapterError> {
        self.apply_checked(target, dry_run, None).await
    }

    /// Refuse NIC drift between durable preparation and the digest-fenced write.
    pub async fn apply_prepared(
        &self,
        target: &QuarantineTarget,
        original_net0: &str,
    ) -> Result<ProxmoxApplied, AdapterError> {
        self.apply_checked(target, false, Some(original_net0)).await
    }

    async fn apply_checked(
        &self,
        target: &QuarantineTarget,
        dry_run: bool,
        expected_net0: Option<&str>,
    ) -> Result<ProxmoxApplied, AdapterError> {
        let (node, vmid) = Self::node_vmid(target)?;
        if !dry_run && self.protection_list()?.is_empty() {
            return Err(AdapterError::InvalidTarget(format!(
                "{NEVER_QUARANTINE_VAR} must protect the management path before real quarantine"
            )));
        }
        if quarantine::is_protected(target, self.protection_list()?) {
            return Err(AdapterError::InvalidTarget(format!(
                "proxmox target {node}/{vmid} is on the never-quarantine protection list \
                 ({NEVER_QUARANTINE_VAR}); refusing to quarantine"
            )));
        }
        let (ticket, csrf) = self.ticket().await?;
        let current = self.read_net0(node, vmid, &ticket).await?;
        if expected_net0.is_some_and(|snapshot| snapshot != current.net0) {
            return Err(AdapterError::Apply(
                "Proxmox NIC snapshot changed before isolation".into(),
            ));
        }
        if net0_is_quarantined(&current.net0) && !dry_run {
            return Err(AdapterError::Apply(
                "VM NIC was already isolated; refusing an unowned rollback".into(),
            ));
        }
        let quarantined = quarantine_net0(&current.net0);
        if !dry_run {
            self.write_net0(node, vmid, &quarantined, &current.digest, &ticket, &csrf)
                .await?;
        }
        Ok(ProxmoxApplied {
            summary: format!("proxmox quarantine {node}/{vmid} dry_run={dry_run}"),
            original_net0: current.net0,
        })
    }

    /// Confirms the NIC is isolated.
    pub async fn verify(
        &self,
        target: &QuarantineTarget,
    ) -> Result<VerificationResult, AdapterError> {
        let (node, vmid) = Self::node_vmid(target)?;
        let (ticket, _csrf) = self.ticket().await?;
        let net0 = self.read_net0(node, vmid, &ticket).await?;
        Ok(if net0_is_quarantined(&net0.net0) {
            VerificationResult::Verified
        } else {
            VerificationResult::NotPresent
        })
    }

    /// Restores the exact original NIC snapshot and confirms it by readback.
    /// An already restored snapshot succeeds; any other drift is refused.
    pub async fn rollback(
        &self,
        target: &QuarantineTarget,
        original_net0: &str,
    ) -> Result<(), AdapterError> {
        let (node, vmid) = Self::node_vmid(target)?;
        if original_net0.is_empty()
            || original_net0.len() > 4096
            || original_net0.chars().any(char::is_control)
            || net0_is_quarantined(original_net0)
        {
            return Err(AdapterError::Rollback(
                "invalid original NIC snapshot".into(),
            ));
        }
        let (ticket, csrf) = self.ticket().await?;
        let current = self.read_net0(node, vmid, &ticket).await?;
        if !rollback_needed(&current.net0, original_net0)? {
            return Ok(());
        }
        self.write_net0(node, vmid, original_net0, &current.digest, &ticket, &csrf)
            .await?;
        let restored = self.read_net0(node, vmid, &ticket).await?;
        if restored.net0 != original_net0 {
            return Err(AdapterError::Rollback(
                "VM NIC readback did not confirm exact original configuration".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NIC: &str = "virtio=BC:24:11:6D:2B:EF,bridge=vmbr0";

    #[test]
    fn config_parser_requires_one_nic_and_atomic_digest() {
        let valid = serde_json::json!({"data":{"net0": NIC, "digest":"test-digest"}});
        assert_eq!(parse_nic_state(&valid).unwrap().net0, NIC);
        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"data":{"net0": NIC}}),
            serde_json::json!({"data":{"net0": NIC,"digest":""}}),
            serde_json::json!({"data":{"net0": "", "digest":"digest"}}),
            serde_json::json!({"data":{"net0": NIC,"digest":"d\ng"}}),
            serde_json::json!({"data":{"net0": NIC,"net1":NIC,"digest":"digest"}}),
            serde_json::json!({"data":{"net0": NIC,"net1":null,"digest":"digest"}}),
        ] {
            assert!(parse_nic_state(&invalid).is_err());
        }
    }

    #[test]
    fn host_cannot_redirect_authentication_to_another_resource() {
        for host in ["192.168.0.8:8006", "pve.example:8006", "[::1]:8006"] {
            assert!(validate_host(host).is_ok());
        }
        for host in [
            "",
            "https://pve.example:8006",
            "user:pass@pve.example",
            "pve.example/other",
            "pve.example?query",
            "pve.example#fragment",
            "pve.example\n",
            "pve.example:bad",
        ] {
            assert!(validate_host(host).is_err());
        }
    }

    #[test]
    fn rollback_refuses_operator_drift_and_preserves_explicit_link_up() {
        let original = format!("{NIC},link_down=0");
        assert!(!rollback_needed(&original, &original).unwrap());
        assert!(rollback_needed(&quarantine_net0(&original), &original).unwrap());
        assert!(rollback_needed(
            &format!("{NIC},bridge=operator-network,link_down=1"),
            &original
        )
        .is_err());
        assert!(rollback_needed(NIC, &original).is_err());
    }

    #[test]
    fn quarantine_appends_link_down_and_preserves_the_nic() {
        assert_eq!(quarantine_net0(NIC), format!("{NIC},link_down=1"));
    }

    #[test]
    fn quarantine_is_idempotent_and_clears_a_stale_flag() {
        assert_eq!(
            quarantine_net0(&format!("{NIC},link_down=1")),
            format!("{NIC},link_down=1")
        );
        assert_eq!(
            quarantine_net0(&format!("{NIC},link_down=0")),
            format!("{NIC},link_down=1")
        );
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
            never_quarantine: Ok(vec![QuarantineTarget::Proxmox {
                node: "IT13".to_string(),
                vmid: 100,
            }]),
            http: Ok(reqwest::Client::new()),
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
    async fn malformed_or_missing_protection_refuses_real_quarantine_before_login() {
        let target = QuarantineTarget::Proxmox {
            node: "IT13".into(),
            vmid: 9000,
        };
        for guard in [Err("invalid protection list".to_string()), Ok(Vec::new())] {
            let adapter = ProxmoxAdapter {
                credentials: Err("must not log in".into()),
                never_quarantine: guard,
                http: Ok(reqwest::Client::new()),
            };
            assert!(matches!(
                adapter.apply(&target, false).await,
                Err(AdapterError::InvalidTarget(_))
            ));
        }
    }

    #[tokio::test]
    async fn invalid_node_or_zero_vmid_cannot_reach_the_api() {
        let adapter = ProxmoxAdapter {
            credentials: Err("must not log in".into()),
            never_quarantine: Ok(Vec::new()),
            http: Ok(reqwest::Client::new()),
        };
        for (node, vmid) in [("IT13/../other", 9000), ("IT13", 0)] {
            let target = QuarantineTarget::Proxmox {
                node: node.into(),
                vmid,
            };
            assert!(matches!(
                adapter.preflight(&target).await,
                Err(AdapterError::InvalidTarget(_))
            ));
        }
    }

    #[tokio::test]
    #[ignore = "requires the loopback HTTPS Proxmox test fixture and its CA; never a real PVE host"]
    async fn https_mock_confirms_tls_cas_and_rollback_readback_fail_closed() {
        let host = std::env::var("CLAWFORGE_PROXMOX_HTTPS_MOCK_HOST").expect("mock host");
        assert!(
            host.starts_with("127.0.0.1:"),
            "fixture must be loopback only"
        );
        validate_host(&host).unwrap();
        let ca_file = std::env::var("CLAWFORGE_PROXMOX_HTTPS_MOCK_CA_FILE").expect("mock CA");
        assert_eq!(std::env::var("CLAWFORGE_PROXMOX_CA_FILE").unwrap(), ca_file);
        let make_adapter = |trusted: bool| {
            let http = if trusted {
                // Exercise the same configured CA loading and TLS policy as production.
                ProxmoxAdapter::http_client().unwrap()
            } else {
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap()
            };
            ProxmoxAdapter {
                credentials: Ok(ProxmoxCredentials {
                    host: host.clone(),
                    user: "mock@pam".into(),
                    password: "mock-only".into(),
                }),
                never_quarantine: Ok(vec![QuarantineTarget::Proxmox {
                    node: "lab".into(),
                    vmid: 100,
                }]),
                http: Ok(http),
            }
        };
        let target = |vmid| QuarantineTarget::Proxmox {
            node: "lab".into(),
            vmid,
        };
        assert!(
            make_adapter(false).preflight(&target(9001)).await.is_err(),
            "untrusted CA must fail before credential delivery"
        );
        let adapter = make_adapter(true);
        let wrong_ca_file =
            std::env::var("CLAWFORGE_PROXMOX_HTTPS_MOCK_WRONG_CA_FILE").expect("unrelated mock CA");
        let wrong_ca =
            reqwest::Certificate::from_pem(&std::fs::read(wrong_ca_file).unwrap()).unwrap();
        let mut wrong_trust = make_adapter(false);
        wrong_trust.http = Ok(reqwest::Client::builder()
            .add_root_certificate(wrong_ca)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap());
        assert!(wrong_trust.preflight(&target(9001)).await.is_err());
        let mut wrong_name = make_adapter(true);
        wrong_name.credentials.as_mut().unwrap().host = host.replacen("127.0.0.1", "localhost", 1);
        assert!(wrong_name.preflight(&target(9001)).await.is_err());
        let original = adapter.preflight(&target(9001)).await.unwrap();
        assert!(adapter
            .apply_prepared(&target(9001), "e1000=02:00:00:00:00:99,bridge=vmbr0")
            .await
            .is_err());
        assert_eq!(
            adapter.preflight(&target(9001)).await.unwrap().net0,
            original.net0
        );
        let applied = adapter
            .apply_prepared(&target(9001), &original.net0)
            .await
            .unwrap();
        assert_eq!(applied.original_net0, original.net0);
        assert_eq!(
            adapter.verify(&target(9001)).await.unwrap(),
            VerificationResult::Verified
        );
        adapter
            .rollback(&target(9001), &applied.original_net0)
            .await
            .unwrap();
        assert_eq!(
            adapter.verify(&target(9001)).await.unwrap(),
            VerificationResult::NotPresent
        );
        assert_eq!(
            adapter.preflight(&target(9001)).await.unwrap().net0,
            original.net0
        );
        adapter
            .rollback(&target(9001), &original.net0)
            .await
            .unwrap();
        let applied = adapter.apply(&target(9002), false).await.unwrap();
        assert!(
            matches!(
                adapter
                    .rollback(&target(9002), &applied.original_net0)
                    .await,
                Err(AdapterError::Rollback(_))
            ),
            "HTTP200 without changed state must not complete rollback"
        );
        let applied = adapter.apply(&target(9003), false).await.unwrap();
        assert_eq!(
            adapter.verify(&target(9003)).await.unwrap(),
            VerificationResult::Verified
        );
        assert!(
            matches!(
                adapter
                    .rollback(&target(9003), &applied.original_net0)
                    .await,
                Err(AdapterError::Rollback(_))
            ),
            "operator drift must not be overwritten"
        );
        assert!(
            matches!(
                adapter.apply(&target(9004), false).await,
                Err(AdapterError::InvalidTarget(_))
            ),
            "multi-NIC cannot be falsely isolated"
        );
        assert!(
            matches!(
                adapter.apply(&target(9005), false).await,
                Err(AdapterError::Verify(_))
            ),
            "missing digest must prevent mutation"
        );
        assert!(
            matches!(
                adapter.apply(&target(9006), false).await,
                Err(AdapterError::Apply(_))
            ),
            "CAS conflict must prevent mutation"
        );
        assert_eq!(
            adapter.verify(&target(9006)).await.unwrap(),
            VerificationResult::NotPresent
        );
        adapter.apply(&target(9007), true).await.unwrap();
        assert_eq!(
            adapter.verify(&target(9007)).await.unwrap(),
            VerificationResult::NotPresent
        );
        for (vmid, message) in [
            (9008, "task failed"),
            (9009, "timed out"),
            (9010, "no asynchronous task ID"),
            (9011, "invalid Proxmox config task ID"),
            (9012, "invalid Proxmox config task ID"),
        ] {
            assert!(
                matches!(adapter.apply(&target(vmid), false).await,
                Err(AdapterError::Apply(error)) if error.contains(message)),
                "async failure must fail closed for VM {vmid}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires a real Proxmox host + a disposable test VM; set CLAWFORGE_PROXMOX_* and CLAWFORGE_PROXMOX_TEST_NODE/_VMID"]
    async fn live_quarantine_cycle_against_the_test_vm() {
        let node =
            std::env::var("CLAWFORGE_PROXMOX_TEST_NODE").expect("CLAWFORGE_PROXMOX_TEST_NODE");
        let vmid: u32 = std::env::var("CLAWFORGE_PROXMOX_TEST_VMID")
            .expect("CLAWFORGE_PROXMOX_TEST_VMID")
            .parse()
            .expect("vmid");
        let adapter = ProxmoxAdapter::new();
        let target = QuarantineTarget::Proxmox { node, vmid };

        let pre = adapter.preflight(&target).await.expect("preflight");
        assert!(!pre.protected, "the test VM must not be protected");
        assert!(
            !pre.currently_quarantined,
            "start from a clean, non-quarantined NIC"
        );

        adapter.apply(&target, false).await.expect("apply");
        assert_eq!(
            adapter.verify(&target).await.expect("verify after apply"),
            VerificationResult::Verified
        );

        adapter
            .rollback(&target, &pre.net0)
            .await
            .expect("rollback");
        assert_eq!(
            adapter
                .verify(&target)
                .await
                .expect("verify after rollback"),
            VerificationResult::NotPresent
        );
    }

    #[tokio::test]
    async fn docker_target_is_rejected_by_the_proxmox_adapter() {
        let adapter = ProxmoxAdapter {
            credentials: Err("unused".to_string()),
            never_quarantine: Ok(Vec::new()),
            http: Ok(reqwest::Client::new()),
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
