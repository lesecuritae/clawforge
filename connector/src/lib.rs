//! Connector contracts shared by the API and future connector workers.
//!
//! Connectors are deliberately read-only.  A connector can describe its
//! capabilities and report health, but this crate exposes no mutation or
//! command execution interface.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub const CONNECTOR_TYPES: &[&str] = &["docker", "github", "proxmox"];
pub const CONNECTOR_STATUSES: &[&str] = &[
    "configured",
    "healthy",
    "degraded",
    "unavailable",
    "disabled",
];
pub const CAPABILITIES: &[&str] = &[
    "container.list",
    "container.status",
    "container.health",
    "container.image_version",
    "container.restart_count",
    "repository.status",
    "repository.commits",
    "repository.security_alerts",
    "repository.workflow_status",
    "platform.health",
    "container.restart",
    "container.pull",
    "repository.workflow_retry",
];
pub const CAPABILITY_MODES: &[&str] = &["read", "execute"];

/// Connector actions are declarative capability metadata only. Productive
/// execution is intentionally absent from the v0.9 connector contract.
pub fn action_mode_is_safe(mode: &str) -> bool {
    CAPABILITY_MODES.contains(&mode)
}
pub fn productive_execution_enabled() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub connector_type: String,
    pub status: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorHealth {
    pub status: String,
    pub last_check: Option<String>,
    pub latency_ms: Option<i64>,
    pub error: Option<String>,
}

#[async_trait]
pub trait ReadOnlyConnector: Send + Sync {
    fn metadata(&self) -> ConnectorMetadata;
    async fn health(&self) -> ConnectorHealth;
}

#[derive(Debug, Clone)]
pub struct DockerConnector;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerSnapshot {
    pub id: String,
    pub name: String,
    pub status: String,
    pub health: Option<String>,
    pub image: String,
    pub restart_count: u64,
}

impl DockerConnector {
    /// Normalize the Docker Engine container response without retaining raw
    /// labels, environment values, mounts, or command arguments.
    pub fn normalize_containers(
        payload: &serde_json::Value,
    ) -> Result<Vec<ContainerSnapshot>, String> {
        let values = payload
            .as_array()
            .ok_or_else(|| "docker response must be an array".to_string())?;
        values
            .iter()
            .map(|value| {
                let id = value
                    .get("Id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "container id missing".to_string())?;
                let name = value
                    .get("Names")
                    .and_then(|v| v.as_array())
                    .and_then(|v| v.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .trim_start_matches('/');
                let state = value
                    .get("State")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let status = value
                    .get("Status")
                    .and_then(|v| v.as_str())
                    .unwrap_or(state);
                let image = value
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                Ok(ContainerSnapshot {
                    id: id.chars().take(128).collect(),
                    name: name.chars().take(160).collect(),
                    status: status.chars().take(160).collect(),
                    health: None,
                    image: image.chars().take(240).collect(),
                    restart_count: 0,
                })
            })
            .collect()
    }

    pub fn enrich_inspection(snapshot: &mut ContainerSnapshot, payload: &serde_json::Value) {
        snapshot.restart_count = payload
            .get("RestartCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        snapshot.health = payload
            .get("State")
            .and_then(|v| v.get("Health"))
            .and_then(|v| v.get("Status"))
            .and_then(|v| v.as_str())
            .map(|v| v.chars().take(32).collect());
        if let Some(image) = payload
            .get("Config")
            .and_then(|v| v.get("Image"))
            .and_then(|v| v.as_str())
        {
            snapshot.image = image.chars().take(240).collect();
        }
    }
}

#[async_trait]
impl ReadOnlyConnector for DockerConnector {
    fn metadata(&self) -> ConnectorMetadata {
        ConnectorMetadata {
            id: "docker".into(),
            name: "Docker Connector".into(),
            version: "0.8.0".into(),
            connector_type: "docker".into(),
            status: "configured".into(),
            capabilities: CAPABILITIES[..5].iter().map(|v| (*v).into()).collect(),
        }
    }

    async fn health(&self) -> ConnectorHealth {
        ConnectorHealth {
            status: "configured".into(),
            last_check: None,
            latency_ms: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GitHubConnector;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositorySnapshot {
    pub full_name: String,
    pub default_branch: String,
    pub open_security_alerts: Option<u64>,
    pub workflow_status: Option<String>,
}

impl GitHubConnector {
    /// Keep only repository health fields from the GitHub API response.
    pub fn normalize_repository(payload: &serde_json::Value) -> Result<RepositorySnapshot, String> {
        let full_name = payload
            .get("full_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "repository name missing".to_string())?;
        Ok(RepositorySnapshot {
            full_name: full_name.chars().take(240).collect(),
            default_branch: payload
                .get("default_branch")
                .and_then(|v| v.as_str())
                .unwrap_or("main")
                .chars()
                .take(128)
                .collect(),
            open_security_alerts: payload.get("security_alerts").and_then(|v| v.as_u64()),
            workflow_status: payload
                .get("workflow_status")
                .and_then(|v| v.as_str())
                .map(|v| v.chars().take(64).collect()),
        })
    }
}

#[async_trait]
impl ReadOnlyConnector for GitHubConnector {
    fn metadata(&self) -> ConnectorMetadata {
        ConnectorMetadata {
            id: "github".into(),
            name: "GitHub Connector".into(),
            version: "0.8.0".into(),
            connector_type: "github".into(),
            status: "configured".into(),
            capabilities: CAPABILITIES[5..9].iter().map(|v| (*v).into()).collect(),
        }
    }

    async fn health(&self) -> ConnectorHealth {
        ConnectorHealth {
            status: "configured".into(),
            last_check: None,
            latency_ms: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxmoxConnector;

impl ProxmoxConnector {
    /// Normalize the lightweight Proxmox version/health response. Tokens and
    /// node configuration are never part of this projection.
    pub fn normalize_health(payload: &serde_json::Value) -> Result<String, String> {
        let status = payload
            .get("status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "health status missing".to_string())?;
        if !matches!(status, "ok" | "degraded" | "unavailable") {
            return Err("unsupported health status".into());
        }
        Ok(status.into())
    }
}

#[async_trait]
impl ReadOnlyConnector for ProxmoxConnector {
    fn metadata(&self) -> ConnectorMetadata {
        ConnectorMetadata {
            id: "proxmox".into(),
            name: "Proxmox Connector Foundation".into(),
            version: "0.8.0".into(),
            connector_type: "proxmox".into(),
            status: "configured".into(),
            capabilities: vec!["platform.health".into()],
        }
    }

    async fn health(&self) -> ConnectorHealth {
        ConnectorHealth {
            status: "configured".into(),
            last_check: None,
            latency_ms: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn built_in_connectors_are_read_only_and_described() {
        let connector = DockerConnector;
        let metadata = connector.metadata();
        assert_eq!(metadata.connector_type, "docker");
        assert!(metadata
            .capabilities
            .contains(&"container.list".to_string()));
        assert_eq!(connector.health().await.status, "configured");
    }

    #[test]
    fn docker_connector_normalizes_safe_container_fields() {
        let values = DockerConnector::normalize_containers(&serde_json::json!([{
            "Id":"abc", "Names":["/api"], "State":"running", "Status":"Up 2 minutes",
            "Image":"clawforge:0.8.0", "Config":{"Env":["TOKEN=removed"]}
        }]))
        .unwrap();
        assert_eq!(values[0].name, "api");
        assert_eq!(values[0].status, "Up 2 minutes");
        assert!(!serde_json::to_string(&values).unwrap().contains("TOKEN"));
        let mut snapshot = values.into_iter().next().unwrap();
        DockerConnector::enrich_inspection(
            &mut snapshot,
            &serde_json::json!({"RestartCount":3,"State":{"Health":{"Status":"healthy"}}}),
        );
        assert_eq!(snapshot.restart_count, 3);
        assert_eq!(snapshot.health.as_deref(), Some("healthy"));
    }

    #[test]
    fn github_and_proxmox_projections_drop_raw_fields() {
        let repo = GitHubConnector::normalize_repository(&serde_json::json!({
            "full_name":"lesecuritae/clawforge", "default_branch":"main",
            "security_alerts":2, "workflow_status":"success", "token":"removed"
        }))
        .unwrap();
        assert_eq!(repo.open_security_alerts, Some(2));
        assert!(!serde_json::to_string(&repo).unwrap().contains("token"));
        assert_eq!(
            ProxmoxConnector::normalize_health(
                &serde_json::json!({"status":"ok","ticket":"removed"})
            )
            .unwrap(),
            "ok"
        );
    }

    #[test]
    fn execute_capabilities_are_explicit_and_disabled_by_default() {
        assert!(action_mode_is_safe("read"));
        assert!(action_mode_is_safe("execute"));
        assert!(!action_mode_is_safe("shell"));
        assert!(!productive_execution_enabled());
    }
}
