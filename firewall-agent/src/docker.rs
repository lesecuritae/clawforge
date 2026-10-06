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
const INSPECT_FORMAT: &str =
    r#"{"mode":{{json .HostConfig.NetworkMode}},"networks":{{json .NetworkSettings.Networks}}}"#;

/// Only bounded network metadata, never container environment or secrets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetworkAttachment {
    pub name: String,
    pub network_id: String,
    pub aliases: Vec<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub links: Vec<String>,
    pub link_local_ips: Vec<String>,
    pub driver_opts: std::collections::BTreeMap<String, String>,
    pub gateway_priority: i64,
}

fn strings(value: Option<&serde_json::Value>) -> Result<Vec<String>, AdapterError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(vec![]),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|v| {
                v.as_str().map(str::to_owned).ok_or_else(|| {
                    AdapterError::Verify("invalid network metadata string array".into())
                })
            })
            .collect(),
        _ => Err(AdapterError::Verify(
            "invalid network metadata array".into(),
        )),
    }
}

fn optional_ip(value: &serde_json::Value) -> Result<Option<String>, AdapterError> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(value) => Ok((!value.is_empty()).then(|| value.clone())),
        _ => Err(AdapterError::Verify("invalid network IP metadata".into())),
    }
}

impl NetworkAttachment {
    fn validate(&self) -> Result<(), AdapterError> {
        let tokens = std::iter::once(&self.name)
            .chain(self.aliases.iter())
            .chain(self.links.iter());
        if self.network_id.len() != 64
            || !self.network_id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.aliases.len() > 32
            || self.links.len() > 32
            || self.link_local_ips.len() > 16
            || tokens
                .into_iter()
                .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
        {
            return Err(AdapterError::InvalidTarget(
                "invalid network restoration metadata".into(),
            ));
        }
        for ip in self
            .ipv4
            .iter()
            .chain(self.ipv6.iter())
            .chain(self.link_local_ips.iter())
        {
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(AdapterError::InvalidTarget(
                    "invalid restoration IP address".into(),
                ));
            }
        }
        if self.driver_opts.iter().any(|(key, value)| {
            key != "com.docker.network.endpoint.sysctls"
                || value.len() > 2048
                || value.chars().any(char::is_control)
        }) {
            return Err(AdapterError::InvalidTarget(
                "unsupported network driver options; refusing lossy restoration".into(),
            ));
        }
        Ok(())
    }

    fn connect_args(&self, id: &str) -> Result<Vec<String>, AdapterError> {
        self.validate()?;
        let mut args = vec!["network".into(), "connect".into()];
        for (flag, values) in [
            ("--alias", &self.aliases),
            ("--link", &self.links),
            ("--link-local-ip", &self.link_local_ips),
        ] {
            for value in values {
                args.extend([flag.into(), value.clone()]);
            }
        }
        for (flag, value) in [("--ip", &self.ipv4), ("--ip6", &self.ipv6)] {
            if let Some(value) = value {
                args.extend([flag.into(), value.clone()]);
            }
        }
        for (key, value) in &self.driver_opts {
            args.extend(["--driver-opt".into(), format!("{key}={value}")]);
        }
        if self.gateway_priority != 0 {
            args.extend(["--gw-priority".into(), self.gateway_priority.to_string()]);
        }
        args.extend([self.network_id.clone(), id.into()]);
        Ok(args)
    }

    fn restored_by(&self, current: &Self) -> bool {
        self.network_id == current.network_id
            && self.ipv4 == current.ipv4
            && self.ipv6 == current.ipv6
            && self
                .aliases
                .iter()
                .all(|alias| current.aliases.contains(alias))
            && self.links == current.links
            && self.link_local_ips == current.link_local_ips
            && self.driver_opts == current.driver_opts
            && self.gateway_priority == current.gateway_priority
    }
}

fn parse_networks(raw: &str) -> Result<Vec<NetworkAttachment>, AdapterError> {
    if raw.len() > 65536 {
        return Err(AdapterError::Verify(
            "network inspection exceeds size limit".into(),
        ));
    }
    let doc: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| AdapterError::Verify("invalid Docker network inspection JSON".into()))?;
    let mode = doc["mode"]
        .as_str()
        .ok_or_else(|| AdapterError::Verify("network mode missing".into()))?;
    if mode == "host" || mode.starts_with("container:") {
        return Err(AdapterError::InvalidTarget(
            "shared/host networking cannot be safely quarantined".into(),
        ));
    }
    let networks = doc["networks"]
        .as_object()
        .ok_or_else(|| AdapterError::Verify("network attachments missing".into()))?;
    if networks.len() > 16 {
        return Err(AdapterError::InvalidTarget(
            "too many network attachments".into(),
        ));
    }
    networks
        .iter()
        .map(|(name, v)| {
            if !v.is_object() || (!v["IPAMConfig"].is_null() && !v["IPAMConfig"].is_object()) {
                return Err(AdapterError::Verify(
                    "invalid network attachment metadata".into(),
                ));
            }
            let ipam = &v["IPAMConfig"];
            let driver_opts = match &v["DriverOpts"] {
                serde_json::Value::Null => std::collections::BTreeMap::new(),
                serde_json::Value::Object(opts) => opts
                    .iter()
                    .map(|(k, v)| {
                        v.as_str()
                            .map(|v| (k.clone(), v.to_owned()))
                            .ok_or_else(|| {
                                AdapterError::Verify("invalid network driver option".into())
                            })
                    })
                    .collect::<Result<_, _>>()?,
                _ => {
                    return Err(AdapterError::Verify(
                        "invalid network driver options".into(),
                    ))
                }
            };
            let gateway_priority = match &v["GwPriority"] {
                serde_json::Value::Null => 0,
                value => value.as_i64().ok_or_else(|| {
                    AdapterError::Verify("invalid network gateway priority".into())
                })?,
            };
            let attachment = NetworkAttachment {
                name: name.clone(),
                network_id: v["NetworkID"].as_str().unwrap_or_default().into(),
                aliases: strings(v.get("Aliases"))?,
                links: strings(v.get("Links"))?,
                ipv4: optional_ip(&ipam["IPv4Address"])?,
                ipv6: optional_ip(&ipam["IPv6Address"])?,
                link_local_ips: strings(ipam.get("LinkLocalIPs"))?,
                driver_opts,
                gateway_priority,
            };
            attachment.validate()?;
            Ok(attachment)
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerPreflight {
    pub container_id: String,
    pub networks: Vec<NetworkAttachment>,
    pub currently_quarantined: bool,
    pub protected: bool,
}

pub struct DockerAdapter {
    docker_bin: String,
    never_quarantine: Result<Vec<QuarantineTarget>, String>,
}

impl Default for DockerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerAdapter {
    pub fn new() -> Self {
        let never_quarantine = match std::env::var(NEVER_QUARANTINE_VAR) {
            Ok(raw) => quarantine::never_quarantine_from_configured(&raw)
                .map_err(|_| format!("invalid {NEVER_QUARANTINE_VAR}; quarantine disabled")),
            Err(_) => Ok(Vec::new()),
        };
        Self {
            docker_bin: std::env::var(DOCKER_BIN_VAR).unwrap_or_else(|_| "docker".to_string()),
            never_quarantine,
        }
    }

    fn protection_list(&self) -> Result<&[QuarantineTarget], AdapterError> {
        self.never_quarantine
            .as_deref()
            .map_err(|message| AdapterError::InvalidTarget(message.clone()))
    }

    fn container_id(target: &QuarantineTarget) -> Result<&str, AdapterError> {
        target.validate().map_err(|_| {
            AdapterError::InvalidTarget("invalid canonical quarantine target".to_string())
        })?;
        match target {
            QuarantineTarget::Docker { container_id } => Ok(container_id.as_str()),
            QuarantineTarget::Proxmox { .. } => Err(AdapterError::InvalidTarget(
                "the docker adapter requires a Docker target, not a Proxmox one".to_string(),
            )),
        }
    }

    async fn run(&self, args: &[&str]) -> Result<String, AdapterError> {
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            Command::new(&self.docker_bin)
                .kill_on_drop(true)
                .args(args)
                .output(),
        )
        .await
        .map_err(|_| AdapterError::Apply("Docker command timed out".into()))?
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
                output.status
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    async fn networks(&self, container_id: &str) -> Result<Vec<NetworkAttachment>, AdapterError> {
        let output = self
            .run(&["inspect", "-f", INSPECT_FORMAT, container_id])
            .await
            .map_err(|error| AdapterError::Verify(format!("docker inspect: {error}")))?;
        parse_networks(&output)
    }

    /// Read-only: lists the container's networks without changing anything.
    pub async fn preflight(
        &self,
        target: &QuarantineTarget,
    ) -> Result<DockerPreflight, AdapterError> {
        let id = Self::container_id(target)?;
        let protected = quarantine::is_protected(target, self.protection_list()?);
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
    pub async fn apply(
        &self,
        target: &QuarantineTarget,
        dry_run: bool,
    ) -> Result<Vec<NetworkAttachment>, AdapterError> {
        self.apply_checked(target, dry_run, None).await
    }

    /// Apply only the immutable network snapshot committed to the native journal.
    pub async fn apply_prepared(
        &self,
        target: &QuarantineTarget,
        expected: &[NetworkAttachment],
    ) -> Result<Vec<NetworkAttachment>, AdapterError> {
        self.apply_checked(target, false, Some(expected)).await
    }

    async fn apply_checked(
        &self,
        target: &QuarantineTarget,
        dry_run: bool,
        expected: Option<&[NetworkAttachment]>,
    ) -> Result<Vec<NetworkAttachment>, AdapterError> {
        let id = Self::container_id(target)?;
        if !dry_run && self.protection_list()?.is_empty() {
            return Err(AdapterError::InvalidTarget(format!(
                "{NEVER_QUARANTINE_VAR} must protect the management path before real quarantine"
            )));
        }
        if quarantine::is_protected(target, self.protection_list()?) {
            return Err(AdapterError::InvalidTarget(format!(
                "docker container {id} is on the never-quarantine protection list \
                 ({NEVER_QUARANTINE_VAR}); refusing to quarantine"
            )));
        }
        let networks = self.networks(id).await?;
        if expected.is_some_and(|snapshot| snapshot != networks) {
            return Err(AdapterError::Apply(
                "Docker network snapshot changed before isolation".into(),
            ));
        }
        if dry_run {
            return Ok(networks);
        }
        if networks.is_empty() {
            return Err(AdapterError::Apply(
                "container was already isolated; refusing an unowned rollback".into(),
            ));
        }
        for network in &networks {
            if let Err(error) = self
                .run(&["network", "disconnect", &network.network_id, id])
                .await
            {
                self.rollback(target, &networks).await.map_err(|_| {
                    AdapterError::Rollback(
                        "partial isolation needs recovery; compensating reconnect failed".into(),
                    )
                })?;
                return Err(error);
            }
        }
        Ok(networks)
    }

    /// Confirms the container is on no networks.
    pub async fn verify(
        &self,
        target: &QuarantineTarget,
    ) -> Result<VerificationResult, AdapterError> {
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
    pub async fn rollback(
        &self,
        target: &QuarantineTarget,
        networks: &[NetworkAttachment],
    ) -> Result<(), AdapterError> {
        let id = Self::container_id(target)?;
        if networks.is_empty() {
            return Err(AdapterError::Rollback(
                "missing original network snapshot".into(),
            ));
        }
        let current = self.networks(id).await?;
        let mut failed = false;
        for network in networks {
            network.validate()?;
            if let Some(existing) = current.iter().find(|v| v.network_id == network.network_id) {
                if !network.restored_by(existing) {
                    failed = true;
                }
                continue;
            }
            let args = network.connect_args(id)?;
            let refs: Vec<_> = args.iter().map(String::as_str).collect();
            if self.run(&refs).await.is_err() {
                failed = true;
            }
        }
        let restored = self.networks(id).await?;
        if failed
            || !networks
                .iter()
                .all(|old| restored.iter().any(|now| old.restored_by(now)))
        {
            return Err(AdapterError::Rollback(
                "original network configuration not fully restored".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    struct FakeDocker(std::path::PathBuf);

    #[cfg(unix)]
    impl FakeDocker {
        fn new(fail_inspect: bool) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("clawforge-docker-{}-{nonce}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            let state = serde_json::json!({"mode":"custom", "networks":{
                "alpha":{"NetworkID":"a".repeat(64),"Aliases":["api"],"IPAMConfig":{"IPv4Address":"10.254.231.23"}},
                "beta":{"NetworkID":"b".repeat(64),"Aliases":["db"],"IPAMConfig":{"IPv4Address":"10.254.232.23"}}
            }});
            std::fs::write(path.join("state.json"), state.to_string()).unwrap();
            std::fs::write(path.join("original.json"), state.to_string()).unwrap();
            let script = format!(
                r#"#!/usr/bin/python3
import json, pathlib, sys
base = pathlib.Path({base})
args = sys.argv[1:]
with (base / 'calls').open('a') as log:
    log.write(json.dumps(args) + '\n')
state = json.loads((base / 'state.json').read_text())
if args[0] == 'inspect':
    if {fail_inspect}:
        print('fake-sensitive-stderr-must-not-leak', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(state))
elif args[:2] == ['network', 'disconnect']:
    if args[2] == 'b' * 64:
        print('fake-sensitive-stderr-must-not-leak', file=sys.stderr)
        sys.exit(1)
    state['networks'].pop('alpha')
    (base / 'state.json').write_text(json.dumps(state))
elif args[:2] == ['network', 'connect']:
    original = json.loads((base / 'original.json').read_text())
    assert args[-2] == 'a' * 64
    assert '--alias' in args and 'api' in args
    assert '--ip' in args and '10.254.231.23' in args
    state['networks']['alpha'] = original['networks']['alpha']
    (base / 'state.json').write_text(json.dumps(state))
else:
    sys.exit(2)
"#,
                base = serde_json::to_string(path.to_str().unwrap()).unwrap(),
                fail_inspect = if fail_inspect { "True" } else { "False" }
            );
            let executable = path.join("docker");
            std::fs::write(&executable, script).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn adapter(&self) -> DockerAdapter {
            DockerAdapter {
                docker_bin: self.0.join("docker").to_string_lossy().into_owned(),
                never_quarantine: Ok(vec![QuarantineTarget::Docker {
                    container_id: "f".repeat(64),
                }]),
            }
        }
    }

    #[cfg(unix)]
    impl Drop for FakeDocker {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn malformed_present_metadata_is_never_silently_dropped() {
        for (field, value) in [
            ("Aliases", serde_json::json!(42)),
            ("Aliases", serde_json::json!([1])),
            ("Links", serde_json::json!({})),
            ("IPAMConfig", serde_json::json!(false)),
            ("DriverOpts", serde_json::json!({"option":12})),
            ("GwPriority", serde_json::json!("bad")),
        ] {
            let mut attachment = serde_json::json!({"NetworkID":"a".repeat(64)});
            attachment[field] = value;
            let doc = serde_json::json!({"mode":"custom","networks":{"alpha":attachment}});
            assert!(parse_networks(&doc.to_string()).is_err(), "{field}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_snapshot_drift_refuses_before_disconnect() {
        let fake = FakeDocker::new(false);
        let adapter = fake.adapter();
        let target = QuarantineTarget::Docker {
            container_id: docker_id(),
        };
        let mut original = adapter.preflight(&target).await.unwrap().networks;
        original[0].aliases.push("changed-since-approval".into());
        let error = adapter
            .apply_prepared(&target, &original)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("snapshot changed"));
        let calls = std::fs::read_to_string(fake.0.join("calls")).unwrap();
        assert!(!calls.contains("disconnect"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn partial_disconnect_failure_restores_original_network_metadata() {
        let fake = FakeDocker::new(false);
        let adapter = fake.adapter();
        let target = QuarantineTarget::Docker {
            container_id: docker_id(),
        };
        let original = adapter.preflight(&target).await.unwrap().networks;
        let error = adapter.apply(&target, false).await.unwrap_err();
        assert!(matches!(error, AdapterError::Apply(_)));
        assert!(!error.to_string().contains("fake-sensitive"));
        assert_eq!(adapter.preflight(&target).await.unwrap().networks, original);
        let calls = std::fs::read_to_string(fake.0.join("calls")).unwrap();
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.contains("disconnect"))
                .count(),
            2
        );
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.contains("connect") && !line.contains("disconnect"))
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn inspection_failure_never_becomes_verified_isolation_or_mutation() {
        let fake = FakeDocker::new(true);
        let adapter = fake.adapter();
        let target = QuarantineTarget::Docker {
            container_id: docker_id(),
        };
        for error in [
            adapter.verify(&target).await.unwrap_err(),
            adapter.apply(&target, false).await.unwrap_err(),
        ] {
            assert!(matches!(error, AdapterError::Verify(_)));
            assert!(!error.to_string().contains("fake-sensitive"));
        }
        let calls = std::fs::read_to_string(fake.0.join("calls")).unwrap();
        assert!(calls.lines().all(|line| line.starts_with("[\"inspect\"")));
    }

    #[test]
    fn network_snapshot_preserves_aliases_static_addresses_and_identity() {
        let raw = serde_json::json!({"mode":"custom", "networks":{"service":{"NetworkID":"a".repeat(64),"Aliases":["api"],"IPAMConfig":{"IPv4Address":"172.29.0.23"}}}});
        let snapshot = parse_networks(&raw.to_string()).unwrap();
        let args = snapshot[0].connect_args(&docker_id()).unwrap();
        assert!(args.windows(2).any(|v| v == ["--alias", "api"]));
        assert!(args.windows(2).any(|v| v == ["--ip", "172.29.0.23"]));
        assert_eq!(args[args.len() - 2], "a".repeat(64));
        assert!(parse_networks(r#"{"mode":"host","networks":{}}"#).is_err());
        assert!(parse_networks("not-json").is_err());
    }

    fn docker_id() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[tokio::test]
    async fn apply_refuses_a_protected_container_before_any_docker_call() {
        let id = docker_id();
        let adapter = DockerAdapter {
            docker_bin: "/nonexistent/docker".to_string(),
            never_quarantine: Ok(vec![QuarantineTarget::Docker {
                container_id: id.clone(),
            }]),
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
            never_quarantine: Ok(Vec::new()),
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
    async fn malformed_or_missing_protection_refuses_real_quarantine_before_io() {
        let target = QuarantineTarget::Docker {
            container_id: docker_id(),
        };
        for guard in [Err("invalid protection list".to_string()), Ok(Vec::new())] {
            let adapter = DockerAdapter {
                docker_bin: "/nonexistent/docker".into(),
                never_quarantine: guard,
            };
            assert!(matches!(
                adapter.apply(&target, false).await,
                Err(AdapterError::InvalidTarget(_))
            ));
        }
    }

    #[tokio::test]
    async fn mutable_container_alias_or_option_cannot_reach_docker() {
        let adapter = DockerAdapter {
            docker_bin: "/nonexistent/docker".into(),
            never_quarantine: Ok(Vec::new()),
        };
        for id in ["production", "--help", "0123456789ab"] {
            let target = QuarantineTarget::Docker {
                container_id: id.into(),
            };
            assert!(matches!(
                adapter.preflight(&target).await,
                Err(AdapterError::InvalidTarget(_))
            ));
        }
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon + a disposable test container (CLAWFORGE_DOCKER_TEST_CONTAINER)"]
    async fn live_quarantine_cycle_against_a_disposable_container() {
        let name = std::env::var("CLAWFORGE_DOCKER_TEST_CONTAINER")
            .expect("CLAWFORGE_DOCKER_TEST_CONTAINER");
        // The test harness passes the container's full 64-hex ID.
        let target = QuarantineTarget::Docker { container_id: name };
        let adapter = DockerAdapter::new();

        let pre = adapter.preflight(&target).await.expect("preflight");
        assert!(!pre.protected);
        assert!(
            !pre.currently_quarantined,
            "start from a connected container"
        );
        let original = pre.networks.clone();
        assert!(!original.is_empty());

        let disconnected = adapter.apply(&target, false).await.expect("apply");
        assert_eq!(disconnected, original);
        assert_eq!(
            adapter.verify(&target).await.expect("verify after apply"),
            VerificationResult::Verified
        );

        adapter
            .rollback(&target, &original)
            .await
            .expect("rollback");
        assert_eq!(adapter.preflight(&target).await.unwrap().networks, original);
        adapter
            .rollback(&target, &original)
            .await
            .expect("idempotent rollback");
        assert_eq!(adapter.preflight(&target).await.unwrap().networks, original);
        assert_eq!(
            adapter
                .verify(&target)
                .await
                .expect("verify after rollback"),
            VerificationResult::NotPresent
        );
    }
}
