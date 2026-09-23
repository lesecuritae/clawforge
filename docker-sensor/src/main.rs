//! Docker sensor for container lifecycle, image and network changes
//! (roadmap phase 3 "Sensor Layer", item 3: "Docker-Sensor für Lifecycle,
//! Image-, Port- und Netzänderungen"). Reports `container_lifecycle_changed`
//! for container create/start/die/destroy/restart, network connect/
//! disconnect, and image pull/delete, straight from the Docker Engine
//! events stream. Port-specific tracking (which would need a follow-up
//! container-inspect call this sensor deliberately does not make) is a
//! later increment - see docs/sensors.md.
//!
//! Unlike the journald-based sensors, Docker access is architecturally
//! restricted per the roadmap's "nur über eine read-only Proxy-Allowlist":
//! this sensor never touches `/var/run/docker.sock` directly. It only
//! speaks plain HTTP to `docker-socket-proxy` (Tecnativa/docker-socket-proxy,
//! `compose.yml`), which is the one container that mounts the socket, and
//! whose own allowlist grants only `EVENTS` (already that image's default),
//! not `CONTAINERS`, `IMAGES`, `NETWORKS`, or any `POST` (write) access.
//! This sensor's own container therefore needs no socket access, no extra
//! capabilities, and no special group at all, unlike the two journald
//! sensors.
//!
//! Cursor/checkpoint, dedupe, bounded buffer/backpressure, batching, retry
//! with an explicit drop budget, and health/metrics mirror
//! `clawforge-linux-sensor`'s reasoning (see its doc comment), adapted to
//! Docker's own event stream: there is no opaque per-event cursor like
//! journald's, so the checkpoint is the Unix-seconds timestamp of the last
//! processed event (Docker's `since` query parameter is second-granular),
//! and the dedupe_key is built from the event's own action/actor/timestamp
//! instead.

use std::{
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{extract::State, routing::get, Json, Router};
use chrono::{DateTime, Utc};
use clawforge_secret::load_required;
use clawforge_security_events::{
    ContainerLifecycleAction, ContainerLifecycleChangedEvidence, SecurityEventEvidence,
    SensorEnvelope, Severity,
};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

const SENSOR_NAME: &str = "docker";
const DEFAULT_CHECKPOINT_PATH: &str = "/var/lib/clawforge/docker-sensor/cursor";
const DEFAULT_BATCH_MAX_ITEMS: usize = 50;
const DEFAULT_BATCH_FLUSH_INTERVAL_SECONDS: u64 = 5;
const MAX_BUFFERED_RETRY: usize = 5_000;
const CHANNEL_CAPACITY: usize = 1_000;

#[derive(Default)]
struct Metrics {
    accepted_total: AtomicU64,
    rejected_total: AtomicU64,
    dropped_total: AtomicU64,
    send_errors_total: AtomicU64,
    buffered: AtomicU64,
    last_event_at_micros: AtomicI64,
}

struct QueuedEvent {
    envelope: SensorEnvelope,
    /// Unix-seconds timestamp of this event, for the checkpoint.
    event_time_seconds: i64,
}

struct ParsedDockerEvent {
    action: ContainerLifecycleAction,
    container_id: Option<String>,
    container_name: Option<String>,
    image: Option<String>,
    detail: String,
}

/// Maps a subset of the Docker Engine events stream to
/// `ContainerLifecycleChangedEvidence`. Anything not matched here (Docker
/// emits many more event types/actions - `exec`, `health_status`, volume
/// events, ...) is deliberately not reported; this sensor only cares about
/// the lifecycle/image/network points the roadmap names.
fn parse_docker_event(value: &serde_json::Value) -> Option<ParsedDockerEvent> {
    let event_type = value.get("Type")?.as_str()?;
    let action = value.get("Action")?.as_str()?;
    let actor = value.get("Actor")?;
    let actor_id = actor.get("ID")?.as_str()?.to_string();
    let attributes = actor.get("Attributes");
    let attr = |key: &str| {
        attributes
            .and_then(|a| a.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };

    match (event_type, action) {
        ("container", "create" | "start" | "die" | "destroy" | "restart") => {
            let lifecycle_action = match action {
                "create" => ContainerLifecycleAction::Created,
                "start" => ContainerLifecycleAction::Started,
                "die" => ContainerLifecycleAction::Stopped,
                "destroy" => ContainerLifecycleAction::Destroyed,
                "restart" => ContainerLifecycleAction::Restarted,
                _ => unreachable!("matched above"),
            };
            Some(ParsedDockerEvent {
                action: lifecycle_action,
                container_id: Some(actor_id),
                container_name: attr("name").map(|value| value.trim_start_matches('/').to_string()),
                image: attr("image"),
                detail: action.to_string(),
            })
        }
        ("network", "connect" | "disconnect") => {
            let lifecycle_action = if action == "connect" {
                ContainerLifecycleAction::NetworkConnected
            } else {
                ContainerLifecycleAction::NetworkDisconnected
            };
            let network_name = attr("name").unwrap_or_else(|| "unknown".to_string());
            Some(ParsedDockerEvent {
                action: lifecycle_action,
                container_id: attr("container"),
                container_name: None,
                image: None,
                detail: format!("network {network_name}"),
            })
        }
        ("image", "pull" | "delete") => {
            let lifecycle_action = if action == "pull" {
                ContainerLifecycleAction::ImagePulled
            } else {
                ContainerLifecycleAction::ImageRemoved
            };
            let image = attr("name").unwrap_or(actor_id);
            Some(ParsedDockerEvent {
                action: lifecycle_action,
                container_id: None,
                container_name: None,
                image: Some(image),
                detail: action.to_string(),
            })
        }
        _ => None,
    }
}

async fn load_checkpoint(path: &str) -> Option<i64> {
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
}

async fn save_checkpoint(path: &str, since_seconds: i64) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let tmp = format!("{path}.tmp");
    tokio::fs::write(&tmp, since_seconds.to_string()).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

fn parse_docker_event_line(line: &str, host_label: &str, metrics: &Metrics) -> Option<QueuedEvent> {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(error) => {
            tracing::debug!(%error, "could not parse a Docker events line as JSON");
            metrics.dropped_total.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    let time_seconds = value.get("time").and_then(|v| v.as_i64())?;
    let time_nanos = value
        .get("timeNano")
        .and_then(|v| v.as_i64())
        .unwrap_or(time_seconds.saturating_mul(1_000_000_000));
    let action = value.get("Action").and_then(|v| v.as_str())?.to_string();
    let actor_id = value
        .get("Actor")
        .and_then(|a| a.get("ID"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    // Not every event type/action Docker emits is one this sensor reports
    // (see parse_docker_event's doc comment) - not counted as a drop, it
    // never intended to report those.
    let parsed = parse_docker_event(&value)?;
    let occurred_at =
        DateTime::from_timestamp(time_seconds, (time_nanos.rem_euclid(1_000_000_000)) as u32)
            .unwrap_or_else(Utc::now);
    let source = format!("{SENSOR_NAME}:{host_label}");
    let dedupe_key = format!("docker:{action}:{actor_id}:{time_nanos}");
    let resource = parsed
        .container_id
        .clone()
        .or_else(|| parsed.image.clone())
        .unwrap_or_else(|| actor_id.clone());
    match SensorEnvelope::new(
        occurred_at,
        source,
        Severity::Info,
        resource,
        dedupe_key,
        SecurityEventEvidence::ContainerLifecycleChanged(ContainerLifecycleChangedEvidence {
            container_id: parsed.container_id,
            container_name: parsed.container_name,
            image: parsed.image,
            action: parsed.action,
            detail: parsed.detail,
        }),
    ) {
        Ok(envelope) => {
            metrics
                .last_event_at_micros
                .store(occurred_at.timestamp_micros(), Ordering::Relaxed);
            Some(QueuedEvent {
                envelope,
                event_time_seconds: time_seconds,
            })
        }
        Err(error) => {
            tracing::warn!(%error, "constructed an invalid security event envelope; dropping");
            metrics.dropped_total.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn stream_docker_events(
    client: &reqwest::Client,
    api_url: &str,
    since: Option<i64>,
    host_label: &str,
    tx: &mpsc::Sender<QueuedEvent>,
    metrics: &Metrics,
) -> anyhow::Result<()> {
    let filters = r#"{"type":["container","network","image"]}"#;
    let mut request = client
        .get(format!("{api_url}/events"))
        .query(&[("filters", filters)]);
    if let Some(since) = since {
        request = request.query(&[("since", since.to_string())]);
    }
    let mut response = request.send().await?.error_for_status()?;
    let mut buffer = String::new();
    while let Some(chunk) = response.chunk().await? {
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(newline) = buffer.find('\n') {
            let line = buffer[..newline].to_string();
            buffer.drain(..=newline);
            if line.trim().is_empty() {
                continue;
            }
            if let Some(event) = parse_docker_event_line(&line, host_label, metrics) {
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

async fn events_reader_task(
    tx: mpsc::Sender<QueuedEvent>,
    api_url: String,
    host_label: String,
    checkpoint_path: String,
    metrics: Arc<Metrics>,
) {
    let client = reqwest::Client::new();
    loop {
        let since = load_checkpoint(&checkpoint_path).await;
        if let Err(error) =
            stream_docker_events(&client, &api_url, since, &host_label, &tx, &metrics).await
        {
            tracing::warn!(%error, "Docker events stream ended; reconnecting in 5s");
        } else {
            tracing::warn!("Docker events stream ended; reconnecting in 5s");
        }
        if tx.is_closed() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn flush(
    buffer: &mut Vec<QueuedEvent>,
    client: &reqwest::Client,
    ingress_url: &str,
    credential: &str,
    checkpoint_path: &str,
    metrics: &Metrics,
) {
    if buffer.is_empty() {
        return;
    }
    let envelopes: Vec<&SensorEnvelope> = buffer.iter().map(|item| &item.envelope).collect();
    let response = client
        .post(format!("{ingress_url}/internal/security-events/batch"))
        .bearer_auth(credential)
        .json(&envelopes)
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            match response.json::<serde_json::Value>().await {
                Ok(body) => {
                    let accepted = body["data"]["accepted"].as_u64().unwrap_or(0);
                    let rejected = body["data"]["rejected"].as_u64().unwrap_or(0);
                    metrics
                        .accepted_total
                        .fetch_add(accepted, Ordering::Relaxed);
                    metrics
                        .rejected_total
                        .fetch_add(rejected, Ordering::Relaxed);
                    if let Some(results) = body["data"]["results"].as_array() {
                        for result in results {
                            if result["status"] != "accepted" {
                                tracing::warn!(
                                    error = ?result["error"],
                                    "security event rejected by ingress"
                                );
                            }
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "could not parse ingress response body"),
            }
            if let Some(last) = buffer.last() {
                if let Err(error) = save_checkpoint(checkpoint_path, last.event_time_seconds).await
                {
                    tracing::warn!(%error, "could not persist Docker events checkpoint");
                }
            }
            buffer.clear();
            metrics.buffered.store(0, Ordering::Relaxed);
            return;
        }
        Ok(response) => {
            metrics.send_errors_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(status = %response.status(), "security event batch rejected by ingress transport");
        }
        Err(error) => {
            metrics.send_errors_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%error, "could not reach security event ingress endpoint");
        }
    }
    if buffer.len() > MAX_BUFFERED_RETRY {
        let excess = buffer.len() - MAX_BUFFERED_RETRY;
        buffer.drain(0..excess);
        metrics
            .dropped_total
            .fetch_add(excess as u64, Ordering::Relaxed);
        tracing::warn!(
            excess,
            "dropped oldest buffered security events after a sustained ingress outage"
        );
    }
    metrics
        .buffered
        .store(buffer.len() as u64, Ordering::Relaxed);
}

async fn batch_sender_task(
    mut rx: mpsc::Receiver<QueuedEvent>,
    client: reqwest::Client,
    ingress_url: String,
    credential: String,
    checkpoint_path: String,
    metrics: Arc<Metrics>,
) {
    let mut buffer: Vec<QueuedEvent> = Vec::new();
    let mut flush_interval =
        tokio::time::interval(Duration::from_secs(DEFAULT_BATCH_FLUSH_INTERVAL_SECONDS));
    flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            received = rx.recv() => {
                match received {
                    Some(event) => {
                        buffer.push(event);
                        metrics.buffered.store(buffer.len() as u64, Ordering::Relaxed);
                        if buffer.len() >= DEFAULT_BATCH_MAX_ITEMS {
                            flush(&mut buffer, &client, &ingress_url, &credential, &checkpoint_path, &metrics).await;
                        }
                    }
                    None => {
                        flush(&mut buffer, &client, &ingress_url, &credential, &checkpoint_path, &metrics).await;
                        return;
                    }
                }
            }
            _ = flush_interval.tick() => {
                flush(&mut buffer, &client, &ingress_url, &credential, &checkpoint_path, &metrics).await;
            }
        }
    }
}

#[derive(Clone)]
struct HealthState {
    metrics: Arc<Metrics>,
}

async fn health(State(state): State<HealthState>) -> Json<serde_json::Value> {
    let last_event_micros = state.metrics.last_event_at_micros.load(Ordering::Relaxed);
    let lag_seconds = if last_event_micros > 0 {
        (Utc::now().timestamp_micros() - last_event_micros) / 1_000_000
    } else {
        -1
    };
    Json(serde_json::json!({
        "status": "ok",
        "sensor": SENSOR_NAME,
        "accepted_total": state.metrics.accepted_total.load(Ordering::Relaxed),
        "rejected_total": state.metrics.rejected_total.load(Ordering::Relaxed),
        "dropped_total": state.metrics.dropped_total.load(Ordering::Relaxed),
        "send_errors_total": state.metrics.send_errors_total.load(Ordering::Relaxed),
        "buffered": state.metrics.buffered.load(Ordering::Relaxed),
        "lag_seconds": lag_seconds,
    }))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let api_url = std::env::var("CLAWFORGE_DOCKER_SENSOR_API_URL")
        .unwrap_or_else(|_| "http://docker-socket-proxy:2375".to_string());
    // Docker's own events carry no hostname field (unlike journald's
    // _HOSTNAME the other two sensors read directly) - an operator running
    // this against more than one host's Docker daemon should set this so
    // events from each are distinguishable.
    let host_label = std::env::var("CLAWFORGE_DOCKER_SENSOR_HOST_LABEL")
        .unwrap_or_else(|_| "unknown-host".to_string());
    let ingress_url = std::env::var("CLAWFORGE_SECURITY_EVENTS_URL")
        .unwrap_or_else(|_| "http://clawforge-api:8080".to_string());
    let credential = load_required(
        "CLAWFORGE_DOCKER_SENSOR_CREDENTIAL_FILE",
        "CLAWFORGE_DOCKER_SENSOR_CREDENTIAL",
    )?;
    let checkpoint_path = std::env::var("CLAWFORGE_DOCKER_SENSOR_CHECKPOINT_PATH")
        .unwrap_or_else(|_| DEFAULT_CHECKPOINT_PATH.to_string());
    let bind = std::env::var("CLAWFORGE_DOCKER_SENSOR_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8097".to_string());

    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let client = reqwest::Client::new();

    let reader_handle = tokio::spawn(events_reader_task(
        tx,
        api_url,
        host_label,
        checkpoint_path.clone(),
        metrics.clone(),
    ));
    let sender_handle = tokio::spawn(batch_sender_task(
        rx,
        client,
        ingress_url,
        credential,
        checkpoint_path,
        metrics.clone(),
    ));

    let app = Router::new()
        .route("/health", get(health))
        .with_state(HealthState { metrics });
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "Clawforge Docker sensor listening");
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    tokio::select! {
        result = reader_handle => tracing::warn!(?result, "events reader task ended"),
        result = sender_handle => tracing::warn!(?result, "batch sender task ended"),
        result = server_handle => tracing::warn!(?result, "health server ended"),
        _ = shutdown_signal() => tracing::info!("Clawforge Docker sensor shutting down"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_container_start_event() {
        let value = serde_json::json!({
            "Type": "container",
            "Action": "start",
            "Actor": {
                "ID": "abc123",
                "Attributes": {"image": "nginx:latest", "name": "/my-container"}
            }
        });
        let parsed = parse_docker_event(&value).expect("recognized event");
        assert_eq!(parsed.action, ContainerLifecycleAction::Started);
        assert_eq!(parsed.container_id.as_deref(), Some("abc123"));
        assert_eq!(parsed.container_name.as_deref(), Some("my-container"));
        assert_eq!(parsed.image.as_deref(), Some("nginx:latest"));
    }

    #[test]
    fn parses_a_network_disconnect_event_without_an_image() {
        let value = serde_json::json!({
            "Type": "network",
            "Action": "disconnect",
            "Actor": {
                "ID": "net123",
                "Attributes": {"container": "abc123", "name": "bridge"}
            }
        });
        let parsed = parse_docker_event(&value).expect("recognized event");
        assert_eq!(parsed.action, ContainerLifecycleAction::NetworkDisconnected);
        assert_eq!(parsed.container_id.as_deref(), Some("abc123"));
        assert_eq!(parsed.image, None);
        assert!(parsed.detail.contains("bridge"));
    }

    #[test]
    fn parses_an_image_pull_event_without_a_container() {
        let value = serde_json::json!({
            "Type": "image",
            "Action": "pull",
            "Actor": {
                "ID": "sha256:deadbeef",
                "Attributes": {"name": "nginx:latest"}
            }
        });
        let parsed = parse_docker_event(&value).expect("recognized event");
        assert_eq!(parsed.action, ContainerLifecycleAction::ImagePulled);
        assert_eq!(parsed.container_id, None);
        assert_eq!(parsed.image.as_deref(), Some("nginx:latest"));
    }

    #[test]
    fn an_unrecognized_action_is_not_matched() {
        let value = serde_json::json!({
            "Type": "container",
            "Action": "exec_create",
            "Actor": {"ID": "abc123", "Attributes": {}}
        });
        assert!(parse_docker_event(&value).is_none());
        let value = serde_json::json!({
            "Type": "volume",
            "Action": "create",
            "Actor": {"ID": "vol123", "Attributes": {}}
        });
        assert!(parse_docker_event(&value).is_none());
    }

    #[test]
    fn a_full_events_line_becomes_a_valid_envelope() {
        let line = serde_json::json!({
            "Type": "container",
            "Action": "die",
            "time": 1_700_000_000i64,
            "timeNano": 1_700_000_000_123_456_789i64,
            "Actor": {
                "ID": "abc123",
                "Attributes": {"image": "nginx:latest", "name": "/my-container"}
            }
        })
        .to_string();
        let metrics = Metrics::default();
        let queued = parse_docker_event_line(&line, "homeserver", &metrics).expect("line parses");
        assert_eq!(queued.event_time_seconds, 1_700_000_000);
        assert_eq!(queued.envelope.source, "docker:homeserver");
        assert_eq!(queued.envelope.resource, "abc123");
        assert!(queued.envelope.dedupe_key.starts_with("docker:die:abc123:"));
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_unrecognized_events_line_is_not_queued_and_not_counted_as_dropped() {
        let line = serde_json::json!({
            "Type": "volume",
            "Action": "create",
            "time": 1_700_000_000i64,
            "Actor": {"ID": "vol123", "Attributes": {}}
        })
        .to_string();
        let metrics = Metrics::default();
        assert!(parse_docker_event_line(&line, "homeserver", &metrics).is_none());
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn malformed_json_is_counted_as_a_drop() {
        let metrics = Metrics::default();
        assert!(parse_docker_event_line("not json", "homeserver", &metrics).is_none());
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 1);
    }
}
