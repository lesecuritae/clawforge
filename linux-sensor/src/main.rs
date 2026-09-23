//! Linux sensor for SSH login failures (roadmap phase 3 "Sensor Layer",
//! item 1: "Linux-Sensor für SSH-/Auth- und Systemereignisse"). This first
//! increment covers `ssh_login_failure` only. PAM/sudo auth failures are
//! deliberately out of scope for now: `AuthFailureEvidence::source_ip` is
//! required, not optional, and a local `sudo`/`su` failure legitimately has
//! no network source IP to report - resolving that is a separate, later
//! decision (either an optional field or a distinct local-auth evidence
//! shape), not guessed at here. Broader "system events" are likewise left
//! for a later increment.
//!
//! Reads systemd-journald through a `journalctl` subprocess
//! (`SYSLOG_IDENTIFIER=sshd` or `sshd-session` - OpenSSH 9.8+ logs
//! authentication from a per-connection re-exec under the latter, not the
//! listener process's own identifier; found live against a real OpenSSH
//! 9.8+ host, not assumed), resuming from a persisted cursor so a restart
//! neither re-sends nor silently drops events. Batches events and
//! sends them to the security event ingress endpoint
//! (`security-events-ingress`); the journald cursor doubles as this
//! sensor's `dedupe_key`, so a crash between "ingress accepted a batch" and
//! "checkpoint written" only ever causes a harmless idempotent
//! resubmission on restart, never a duplicate incident.

use std::{
    process::Stdio,
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
    SecurityEventEvidence, SensorEnvelope, Severity, SshLoginFailureEvidence,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
};
use tracing_subscriber::EnvFilter;

const SENSOR_NAME: &str = "linux-ssh";
const DEFAULT_CHECKPOINT_PATH: &str = "/var/lib/clawforge/linux-sensor/cursor";
const DEFAULT_BATCH_MAX_ITEMS: usize = 50;
const DEFAULT_BATCH_FLUSH_INTERVAL_SECONDS: u64 = 5;
/// Bounds memory if the ingress endpoint is unreachable for a long time:
/// once the retry buffer exceeds this, the oldest entries are dropped
/// (counted, not silently lost) rather than growing without limit.
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
    cursor: String,
}

/// A parsed sshd failed-authentication log line.
#[derive(Debug, PartialEq, Eq)]
struct SshFailure {
    username: String,
    source_ip: String,
}

/// Recognizes the three common sshd MESSAGE shapes for a failed
/// authentication attempt:
///   "Failed password for USER from IP port PORT ssh2"
///   "Failed password for invalid user USER from IP port PORT ssh2"
///   "Failed none for invalid user USER from IP port PORT ssh2"
///   "Invalid user USER from IP port PORT"
/// Anything else (session open/close notices, successful logins,
/// preauth disconnects, ...) is deliberately not matched: this sensor only
/// reports failed authentications, not every sshd log line.
fn parse_sshd_message(message: &str) -> Option<SshFailure> {
    let rest = message
        .strip_prefix("Failed password for ")
        .or_else(|| message.strip_prefix("Failed none for "))
        .or_else(|| message.strip_prefix("Failed publickey for "))
        .or_else(|| message.strip_prefix("Invalid user "))?;
    let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
    let (username, rest) = rest.split_once(" from ")?;
    let (source_ip, _) = rest.split_once(" port ").unwrap_or((rest, ""));
    let username = username.trim();
    let source_ip = source_ip.trim();
    if username.is_empty() || source_ip.is_empty() {
        return None;
    }
    Some(SshFailure {
        username: username.to_string(),
        source_ip: source_ip.to_string(),
    })
}

async fn load_checkpoint(path: &str) -> Option<String> {
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn save_checkpoint(path: &str, cursor: &str) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let tmp = format!("{path}.tmp");
    tokio::fs::write(&tmp, cursor).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

fn parse_journal_line(line: &str, metrics: &Metrics) -> Option<QueuedEvent> {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(error) => {
            tracing::debug!(%error, "could not parse journalctl output line as JSON");
            metrics.dropped_total.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    let cursor = value.get("__CURSOR")?.as_str()?.to_string();
    let message = value.get("MESSAGE").and_then(|v| v.as_str());
    let Some(message) = message else {
        // A binary-unsafe MESSAGE (journalctl represents it as a byte
        // array, not a string) - not something we can parse.
        metrics.dropped_total.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    // Not every sshd line is a failed authentication (session
    // open/close, successful logins, preauth notices, ...) - those are
    // intentionally skipped, not counted as a drop, since this sensor
    // never intended to report them.
    let failure = parse_sshd_message(message)?;
    let occurred_at = value
        .get("__REALTIME_TIMESTAMP")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<i64>().ok())
        .and_then(DateTime::from_timestamp_micros)
        .unwrap_or_else(Utc::now);
    let hostname = value
        .get("_HOSTNAME")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-host");
    let source = format!("{SENSOR_NAME}:{hostname}");
    let dedupe_key = format!("journald:{cursor}");
    let resource = failure.source_ip.clone();
    match SensorEnvelope::new(
        occurred_at,
        source,
        Severity::Medium,
        resource,
        dedupe_key,
        SecurityEventEvidence::SshLoginFailure(SshLoginFailureEvidence {
            username: failure.username,
            source_ip: failure.source_ip,
            attempt_count: 1,
        }),
    ) {
        Ok(envelope) => {
            metrics
                .last_event_at_micros
                .store(occurred_at.timestamp_micros(), Ordering::Relaxed);
            Some(QueuedEvent { envelope, cursor })
        }
        Err(error) => {
            tracing::warn!(%error, "constructed an invalid security event envelope; dropping");
            metrics.dropped_total.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

async fn journal_reader_task(
    tx: mpsc::Sender<QueuedEvent>,
    checkpoint_path: String,
    metrics: Arc<Metrics>,
) {
    loop {
        let cursor = load_checkpoint(&checkpoint_path).await;
        let mut command = Command::new("journalctl");
        command
            .arg("--output=json")
            .arg("--no-pager")
            .arg("--follow")
            // OpenSSH 9.8+ (e.g. Ubuntu 24.04+) splits the listener (sshd)
            // from a per-connection re-exec that does the actual
            // authentication logging under its own identifier,
            // sshd-session - consecutive matches on the same journald
            // field are ORed together, so this matches either.
            .arg("SYSLOG_IDENTIFIER=sshd")
            .arg("SYSLOG_IDENTIFIER=sshd-session");
        match &cursor {
            Some(cursor) => {
                command.arg(format!("--after-cursor={cursor}"));
            }
            // No checkpoint yet (first ever start): begin from now rather
            // than replaying the entire historical journal.
            None => {
                command.arg("--since=now");
            }
        }
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                tracing::error!(%error, "could not start journalctl; retrying in 30s");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            tracing::error!("journalctl produced no stdout handle; retrying in 30s");
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        };
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(event) = parse_journal_line(&line, &metrics) {
                        if tx.send(event).await.is_err() {
                            // The sender task ended; nothing more to do.
                            let _ = child.kill().await;
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(%error, "error reading journalctl output");
                    break;
                }
            }
        }
        let _ = child.kill().await;
        tracing::warn!("journalctl stream ended; reconnecting in 5s");
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
                        for (item, result) in buffer.iter().zip(results) {
                            if result["status"] != "accepted" {
                                tracing::warn!(
                                    cursor = %item.cursor,
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
                if let Err(error) = save_checkpoint(checkpoint_path, &last.cursor).await {
                    tracing::warn!(%error, "could not persist journald checkpoint");
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
    // Left in the buffer for the next flush to retry.
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

    let ingress_url = std::env::var("CLAWFORGE_SECURITY_EVENTS_URL")
        .unwrap_or_else(|_| "http://clawforge-api:8080".to_string());
    let credential = load_required(
        "CLAWFORGE_LINUX_SENSOR_CREDENTIAL_FILE",
        "CLAWFORGE_LINUX_SENSOR_CREDENTIAL",
    )?;
    let checkpoint_path = std::env::var("CLAWFORGE_LINUX_SENSOR_CHECKPOINT_PATH")
        .unwrap_or_else(|_| DEFAULT_CHECKPOINT_PATH.to_string());
    let bind =
        std::env::var("CLAWFORGE_LINUX_SENSOR_BIND").unwrap_or_else(|_| "0.0.0.0:8095".to_string());

    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let client = reqwest::Client::new();

    let reader_handle = tokio::spawn(journal_reader_task(
        tx,
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
    tracing::info!(%bind, "Clawforge Linux sensor listening");
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    tokio::select! {
        result = reader_handle => tracing::warn!(?result, "journal reader task ended"),
        result = sender_handle => tracing::warn!(?result, "batch sender task ended"),
        result = server_handle => tracing::warn!(?result, "health server ended"),
        _ = shutdown_signal() => tracing::info!("Clawforge Linux sensor shutting down"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_password_for_a_known_user() {
        assert_eq!(
            parse_sshd_message("Failed password for root from 203.0.113.7 port 51234 ssh2"),
            Some(SshFailure {
                username: "root".into(),
                source_ip: "203.0.113.7".into()
            })
        );
    }

    #[test]
    fn parses_failed_password_for_an_invalid_user() {
        assert_eq!(
            parse_sshd_message(
                "Failed password for invalid user admin from 198.51.100.5 port 22 ssh2"
            ),
            Some(SshFailure {
                username: "admin".into(),
                source_ip: "198.51.100.5".into()
            })
        );
    }

    #[test]
    fn parses_invalid_user_without_a_password_attempt() {
        assert_eq!(
            parse_sshd_message("Invalid user test from 203.0.113.9 port 54321"),
            Some(SshFailure {
                username: "test".into(),
                source_ip: "203.0.113.9".into()
            })
        );
    }

    #[test]
    fn parses_failed_publickey_and_failed_none() {
        assert_eq!(
            parse_sshd_message("Failed publickey for git from 203.0.113.1 port 40000 ssh2"),
            Some(SshFailure {
                username: "git".into(),
                source_ip: "203.0.113.1".into()
            })
        );
        assert_eq!(
            parse_sshd_message(
                "Failed none for invalid user probe from 203.0.113.2 port 40001 ssh2"
            ),
            Some(SshFailure {
                username: "probe".into(),
                source_ip: "203.0.113.2".into()
            })
        );
    }

    #[test]
    fn does_not_match_a_successful_login_or_an_unrelated_message() {
        assert_eq!(
            parse_sshd_message("Accepted password for root from 203.0.113.7 port 51234 ssh2"),
            None
        );
        assert_eq!(
            parse_sshd_message(
                "Connection closed by authenticating user root 203.0.113.7 port 51234 [preauth]"
            ),
            None
        );
        assert_eq!(
            parse_sshd_message("Server listening on 0.0.0.0 port 22."),
            None
        );
    }

    #[test]
    fn a_journal_line_becomes_a_valid_ssh_login_failure_envelope() {
        let line = serde_json::json!({
            "__CURSOR": "s=abc;i=1;b=def",
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_HOSTNAME": "homeserver",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for root from 203.0.113.7 port 51234 ssh2",
        })
        .to_string();
        let metrics = Metrics::default();
        let queued = parse_journal_line(&line, &metrics).expect("line parses");
        assert_eq!(queued.cursor, "s=abc;i=1;b=def");
        assert_eq!(queued.envelope.source, "linux-ssh:homeserver");
        assert_eq!(queued.envelope.resource, "203.0.113.7");
        assert_eq!(queued.envelope.dedupe_key, "journald:s=abc;i=1;b=def");
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 0);
        assert!(metrics.last_event_at_micros.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn a_journal_line_for_an_unrelated_message_is_not_queued_and_not_counted_as_dropped() {
        let line = serde_json::json!({
            "__CURSOR": "s=abc;i=2;b=def",
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_HOSTNAME": "homeserver",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Server listening on 0.0.0.0 port 22.",
        })
        .to_string();
        let metrics = Metrics::default();
        assert!(parse_journal_line(&line, &metrics).is_none());
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn malformed_json_is_counted_as_a_drop() {
        let metrics = Metrics::default();
        assert!(parse_journal_line("not json", &metrics).is_none());
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 1);
    }
}
