//! HAProxy sensor for request errors and anomalies (roadmap phase 3
//! "Sensor Layer", item 2: "HAProxy-Sensor für Request-Metadaten,
//! Fehlercodes, Rate-Limit- und Anomaliesignale"). This first increment
//! reports HTTP error responses (status >= 400) and requests HAProxy never
//! got a response for (status -1: client disconnect, timeout, or backend
//! failure before a response) as `http_anomaly`. A successful request is
//! deliberately not reported - this sensor only cares about errors and
//! anomalies, not every request. A rate-limit rejection that HAProxy logs
//! as an ordinary error status (429, or a deny action's own status) is
//! already covered by the same threshold; a dedicated signal for HAProxy's
//! own rate-limiting/stick-table actions specifically is a later increment.
//!
//! `HttpAnomalyEvidence` never carries a request body, cookie or
//! Authorization header - only client IP, method, path and status are
//! parsed out of the log line, matching HAProxy's default `httplog`
//! format; any `{...}`-captured header HAProxy might be configured to log
//! is present in the log line but is never extracted into the evidence
//! sent onward.
//!
//! Reads systemd-journald through a `journalctl` subprocess
//! (`SYSLOG_IDENTIFIER=haproxy`); the rest of the pipeline (checkpoint,
//! bounded buffer, dedupe, batching, health/metrics) mirrors
//! `clawforge-linux-sensor` - see its doc comment for the reasoning behind
//! each of those, not repeated here.

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
    HttpAnomalyEvidence, SecurityEventEvidence, SensorEnvelope, Severity,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
};
use tracing_subscriber::EnvFilter;

const SENSOR_NAME: &str = "haproxy";
const DEFAULT_CHECKPOINT_PATH: &str = "/var/lib/clawforge/haproxy-sensor/cursor";
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
    cursor: String,
}

/// A parsed HAProxy `httplog` line, only the fields this sensor is allowed
/// to forward: no captured cookies, no captured headers, no body.
#[derive(Debug, PartialEq, Eq)]
struct HaproxyRequest {
    source_ip: String,
    method: String,
    path: String,
    status_code: i32,
    backend: String,
}

/// Splits an HAProxy log line into whitespace-separated tokens, keeping
/// `[...]`, `{...}` and `"..."` groups intact (each may itself contain
/// spaces - the request line `"GET /path HTTP/1.1"` is exactly such a
/// group).
fn tokenize_haproxy_log(message: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut brackets = 0i32;
    let mut braces = 0i32;
    let mut in_quotes = false;
    for ch in message.chars() {
        match ch {
            '[' if !in_quotes => {
                brackets += 1;
                current.push(ch);
            }
            ']' if !in_quotes => {
                brackets -= 1;
                current.push(ch);
            }
            '{' if !in_quotes => {
                braces += 1;
                current.push(ch);
            }
            '}' if !in_quotes => {
                braces -= 1;
                current.push(ch);
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ' ' if !in_quotes && brackets == 0 && braces == 0 => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Parses HAProxy's default `httplog` shape:
///   `CLIENT_IP:PORT [DATE] FRONTEND BACKEND/SERVER TIMERS STATUS BYTES CC CS TSC CONN QUEUE "METHOD PATH HTTP/VER"`
/// Field positions for client IP and status are fixed (HAProxy's format is
/// stable there); the request line is instead found by searching for the
/// quoted token, since any `{...}`-captured header HAProxy is configured
/// to log inserts extra tokens before it, shifting a fixed index - the
/// bracketed/quoted groups this tokenizer keeps intact make that search
/// unambiguous either way.
fn parse_haproxy_message(message: &str) -> Option<HaproxyRequest> {
    let tokens = tokenize_haproxy_log(message);
    if tokens.len() < 6 {
        return None;
    }
    // tokens[0] is "<client-ip>:<port>". Splitting on the FIRST colon breaks
    // for an IPv6 (or IPv4-mapped-IPv6, e.g. "::ffff:1.2.3.4:5678" - what a
    // dual-stack `bind ::: ... v4v6` frontend actually logs for an IPv4
    // client, unbracketed, found live against a real HAProxy on that bind
    // shape) address: the part before the first colon is empty ("::ffff:...")
    // or just one hextet, not the whole address. The port is always the last
    // colon-separated segment, so split on the LAST colon instead.
    let source_ip = tokens[0].rsplit_once(':').map(|(ip, _port)| ip)?.trim();
    if source_ip.is_empty() {
        return None;
    }
    let backend = tokens.get(3).cloned().unwrap_or_default();
    let status_code: i32 = tokens.get(5)?.parse().ok()?;
    let request_line = tokens.iter().find(|token| token.starts_with('"'))?;
    let mut parts = request_line.trim_matches('"').split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    if method.is_empty() || path.is_empty() {
        return None;
    }
    Some(HaproxyRequest {
        source_ip: source_ip.to_string(),
        method,
        path,
        status_code,
        backend,
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
        metrics.dropped_total.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let request = parse_haproxy_message(message)?;
    // A successful (or redirect/informational) response is not an
    // anomaly - not counted as a drop, this sensor never intended to
    // report it.
    if (0..400).contains(&request.status_code) {
        return None;
    }
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
    let resource = request.source_ip.clone();
    match SensorEnvelope::new(
        occurred_at,
        source,
        Severity::Medium,
        resource,
        dedupe_key,
        SecurityEventEvidence::HttpAnomaly(HttpAnomalyEvidence {
            source_ip: request.source_ip,
            method: request.method,
            path: request.path,
            status_code: request.status_code.clamp(0, u16::MAX as i32) as u16,
            rule_id: (!request.backend.is_empty()).then_some(request.backend),
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
            .arg("SYSLOG_IDENTIFIER=haproxy");
        match &cursor {
            Some(cursor) => {
                command.arg(format!("--after-cursor={cursor}"));
            }
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
        "CLAWFORGE_HAPROXY_SENSOR_CREDENTIAL_FILE",
        "CLAWFORGE_HAPROXY_SENSOR_CREDENTIAL",
    )?;
    let checkpoint_path = std::env::var("CLAWFORGE_HAPROXY_SENSOR_CHECKPOINT_PATH")
        .unwrap_or_else(|_| DEFAULT_CHECKPOINT_PATH.to_string());
    let bind = std::env::var("CLAWFORGE_HAPROXY_SENSOR_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8096".to_string());

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
    tracing::info!(%bind, "Clawforge HAProxy sensor listening");
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    tokio::select! {
        result = reader_handle => tracing::warn!(?result, "journal reader task ended"),
        result = sender_handle => tracing::warn!(?result, "batch sender task ended"),
        result = server_handle => tracing::warn!(?result, "health server ended"),
        _ = shutdown_signal() => tracing::info!("Clawforge HAProxy sensor shutting down"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_standard_httplog_error_line() {
        let message = r#"203.0.113.7:51234 [23/Sep/2026:04:00:00.123] www~ backend/server 0/0/1/2/3 404 1234 - - ---- 1/1/0/0/0 0/0 "GET /missing HTTP/1.1""#;
        assert_eq!(
            parse_haproxy_message(message),
            Some(HaproxyRequest {
                source_ip: "203.0.113.7".into(),
                method: "GET".into(),
                path: "/missing".into(),
                status_code: 404,
                backend: "backend/server".into(),
            })
        );
    }

    #[test]
    fn parses_a_line_with_captured_headers_before_the_request_line() {
        // HAProxy configured to log a captured request header inserts an
        // extra {...} token before the request line - the fixed status
        // index is unaffected, and the request line is still found by
        // searching for the quoted token rather than assuming a position.
        let message = r#"203.0.113.7:51234 [23/Sep/2026:04:00:00.123] www~ backend/server 0/0/1/2/3 500 1234 - - ---- 1/1/0/0/0 0/0 {example.com} "POST /api HTTP/1.1""#;
        let parsed = parse_haproxy_message(message).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/api");
        assert_eq!(parsed.status_code, 500);
    }

    #[test]
    fn parses_the_no_response_status() {
        let message = r#"203.0.113.7:51234 [23/Sep/2026:04:00:00.123] www~ backend/server 0/0/-1/-1/1 -1 0 - - CC-- 1/1/0/0/0 0/0 "GET /slow HTTP/1.1""#;
        let parsed = parse_haproxy_message(message).unwrap();
        assert_eq!(parsed.status_code, -1);
    }

    #[test]
    fn parses_an_ipv4_mapped_ipv6_client_address_from_a_dual_stack_bind() {
        // `bind ::: ... v4v6` (what plex/korbklar_https actually use) makes
        // HAProxy log an IPv4 client as unbracketed "::ffff:<ipv4>:<port>" -
        // found live against a real dual-stack frontend, not assumed.
        // Splitting on the FIRST colon (the original bug) yields an empty
        // string, since the address itself starts with "::"; the port is
        // always the LAST colon-separated segment instead.
        let message = r#"::ffff:143.20.154.16:50438 [23/Sep/2026:16:57:52.631] korbklar_https~ korbklar_backend/korbklar 0/0/27/26/53 404 153 - - ---- 2/1/0/0/0 0/0 "GET /probe HTTP/1.1""#;
        let parsed = parse_haproxy_message(message).unwrap();
        assert_eq!(parsed.source_ip, "::ffff:143.20.154.16");
        assert_eq!(parsed.status_code, 404);
    }

    #[test]
    fn does_not_match_a_line_without_a_request_line_or_too_few_fields() {
        assert_eq!(parse_haproxy_message("not a log line"), None);
        assert_eq!(parse_haproxy_message(""), None);
    }

    #[test]
    fn a_journal_line_for_a_successful_request_is_not_queued_and_not_counted_as_dropped() {
        let line = serde_json::json!({
            "__CURSOR": "s=abc;i=1;b=def",
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_HOSTNAME": "homeserver",
            "SYSLOG_IDENTIFIER": "haproxy",
            "MESSAGE": r#"203.0.113.7:51234 [23/Sep/2026:04:00:00.123] www~ backend/server 0/0/1/2/3 200 1234 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1""#,
        })
        .to_string();
        let metrics = Metrics::default();
        assert!(parse_journal_line(&line, &metrics).is_none());
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_journal_line_for_an_error_response_becomes_a_valid_http_anomaly_envelope() {
        let line = serde_json::json!({
            "__CURSOR": "s=abc;i=2;b=def",
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_HOSTNAME": "homeserver",
            "SYSLOG_IDENTIFIER": "haproxy",
            "MESSAGE": r#"203.0.113.7:51234 [23/Sep/2026:04:00:00.123] www~ backend/server 0/0/1/2/3 503 0 - - ---- 1/1/0/0/0 0/0 "GET /down HTTP/1.1""#,
        })
        .to_string();
        let metrics = Metrics::default();
        let queued = parse_journal_line(&line, &metrics).expect("line parses");
        assert_eq!(queued.cursor, "s=abc;i=2;b=def");
        assert_eq!(queued.envelope.source, "haproxy:homeserver");
        assert_eq!(queued.envelope.resource, "203.0.113.7");
        assert_eq!(queued.envelope.dedupe_key, "journald:s=abc;i=2;b=def");
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn malformed_json_is_counted_as_a_drop() {
        let metrics = Metrics::default();
        assert!(parse_journal_line("not json", &metrics).is_none());
        assert_eq!(metrics.dropped_total.load(Ordering::Relaxed), 1);
    }
}
