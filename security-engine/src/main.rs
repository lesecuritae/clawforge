//! `clawforge-security-engine` (roadmap phase 4, "Security Engine").
//!
//! Consumes canonical events the way `clawforge-correlation` already does
//! (its own named consumer on the same `event_delivery` fan-out - the two
//! run side by side, neither interferes with the other), but applies
//! *count-threshold* rules a pairwise correlator cannot express: "N failed
//! SSH logins from the same pseudonymous source within five minutes" is not
//! a relationship between two events, it is a property of a whole set.
//!
//! ## Why a fixed tumbling-window bucket, not a sliding window
//!
//! A sliding window ("the 5 minutes before this event") depends on exactly
//! *when* a rule happens to run, which is not deterministic across a
//! replay: the same events processed in a different order, or with a
//! retry, could land in a different window each time and produce a
//! different assessment. A bucket aligned to a fixed boundary
//! (`bucket_start = floor(occurred_at / window)`) is a pure function of the
//! event's own timestamp - the same events always produce the same bucket,
//! the same count, and (via `dedupe_key = rule_id:rule_version:resource:
//! bucket_start`) the same assessment row. That is what the roadmap's exit
//! gate asks for: "gleiche Events und Regelversion erzeugen deterministisch
//! dasselbe Assessment". The cost is up to one bucket's worth of detection
//! latency at the boundary; a real attack does not stop after one bucket,
//! so it is still caught in the very next one.
//!
//! Every event in a qualifying bucket contributes exactly once, regardless
//! of how many times the bucket is recomputed as later events in it arrive:
//! `persist_security_assessment` upserts by `dedupe_key`, and
//! `persist_correlation` (the existing, already-idempotent
//! incident-candidate path from `clawforge-correlation`) is reused rather
//! than reimplemented, so incident creation and escalation inherit the same
//! replay-safety this session already gave it.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, TimeZone, Utc};
use clawforge_storage::{
    database_url_from_env, CorrelationPersistence, PostgresStore, SecurityAssessmentUpsert,
};
use std::env;
use tracing::{info, warn};
use uuid::Uuid;

const CONSUMER_NAME: &str = "security-engine";
const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A count-threshold rule over one canonical event type, keyed by
/// `correlation_id` (the pseudonymized resource).
struct CountThresholdRule {
    rule_id: &'static str,
    rule_version: &'static str,
    event_type: &'static str,
    window_seconds: i64,
    threshold: usize,
}

const SSH_BRUTEFORCE: CountThresholdRule = CountThresholdRule {
    rule_id: "ssh_bruteforce",
    rule_version: "1",
    event_type: "ssh_login_failure",
    window_seconds: 300,
    threshold: 5,
};

const HTTP_ANOMALY_BURST: CountThresholdRule = CountThresholdRule {
    rule_id: "http_anomaly_burst",
    rule_version: "1",
    event_type: "http_anomaly",
    window_seconds: 300,
    threshold: 10,
};

const RULES: &[CountThresholdRule] = &[SSH_BRUTEFORCE, HTTP_ANOMALY_BURST];

/// A scan/reconnaissance rule: not "how many events", but "how many
/// *distinct* values of one evidence field" - the shape a vulnerability
/// scanner actually has (many different paths probed, each maybe only
/// once) and `http_anomaly_burst` cannot express (a burst counts raw
/// volume regardless of whether every hit is the same path or a hundred
/// different ones). Same pseudonymous-source grouping and deterministic
/// tumbling-window bucket as a `CountThresholdRule`; the only difference is
/// counting `COUNT(DISTINCT payload->>field)` instead of `COUNT(*)`.
struct DistinctValueThresholdRule {
    rule_id: &'static str,
    rule_version: &'static str,
    event_type: &'static str,
    /// The evidence JSON field to count distinct values of - e.g. `"path"`
    /// on `HttpAnomalyEvidence`. Already pseudonymized/sanitized like every
    /// other field on the canonical event, so this rule never needs to
    /// parse or store anything sensitive itself.
    field: &'static str,
    window_seconds: i64,
    threshold: usize,
}

const HTTP_SCAN: DistinctValueThresholdRule = DistinctValueThresholdRule {
    rule_id: "http_scan",
    rule_version: "1",
    event_type: "http_anomaly",
    field: "path",
    window_seconds: 300,
    threshold: 8,
};

const DISTINCT_VALUE_RULES: &[DistinctValueThresholdRule] = &[HTTP_SCAN];

/// How long an incident candidate stays open to be extended by a later
/// bucket from the same resource/rule, deliberately much longer than any
/// single rule's own detection window - an attacker rarely stops after
/// exactly one bucket, and this is what turns consecutive buckets into one
/// escalating incident instead of a new one every `window_seconds`.
const CANDIDATE_EXTENSION_WINDOW: Duration = Duration::hours(1);

fn bucket_start(occurred_at: DateTime<Utc>, window_seconds: i64) -> DateTime<Utc> {
    let floored = (occurred_at.timestamp().div_euclid(window_seconds)) * window_seconds;
    Utc.timestamp_opt(floored, 0)
        .single()
        .unwrap_or(occurred_at)
}

fn severity_for_count(count: usize, threshold: usize) -> &'static str {
    if count >= threshold * 4 {
        "critical"
    } else if count >= threshold * 2 {
        "high"
    } else {
        "medium"
    }
}

fn confidence_for_count(count: usize, threshold: usize) -> i16 {
    let over = count.saturating_sub(threshold) as i16;
    (60 + over * 4).clamp(60, 99)
}

/// The common tail every rule shares once it has decided to fire: persist
/// the assessment, extend/create the incident candidate via the reused
/// `persist_correlation` path, and best-effort-link the two. Pulled out of
/// `evaluate_rule` so `evaluate_scan_rule` (a different membership query,
/// distinct-value instead of raw-count) does not have to duplicate it.
#[allow(clippy::too_many_arguments)]
async fn persist_assessment_and_incident(
    store: &PostgresStore,
    rule_id: &'static str,
    rule_version: &'static str,
    window_seconds: i64,
    correlation_id: &str,
    bucket: DateTime<Utc>,
    event_ids: &[Uuid],
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    severity: &'static str,
    confidence: i16,
    summary: &str,
) -> Result<()> {
    let dedupe_key = format!(
        "{rule_id}:v{rule_version}:{correlation_id}:{}",
        bucket.timestamp()
    );
    let assessment_id = store
        .persist_security_assessment(SecurityAssessmentUpsert {
            rule_id,
            rule_version,
            engine_version: ENGINE_VERSION,
            dedupe_key: &dedupe_key,
            resource: correlation_id,
            severity,
            confidence,
            summary,
            event_count: event_ids.len() as i32,
            window_seconds: window_seconds as i32,
            bucket_start: bucket,
            first_seen,
            last_seen,
            event_ids,
        })
        .await?;
    // Reuse the existing, already-idempotent/escalation-aware incident
    // candidate path (clawforge-correlation's persist_correlation) instead
    // of a second incident-creation mechanism. The candidate key is stable
    // across buckets (not bucket-scoped, unlike the assessment's own
    // dedupe_key) so a later bucket from the same resource/rule extends the
    // same candidate rather than spawning a new incident every window.
    let candidate_key = format!("security-assessment:{rule_id}:{correlation_id}");
    // persist_correlation returns incident_candidates.id, NOT incidents.id -
    // promote_incident_candidates always mints a fresh, distinct id for the
    // incident row itself (see its own doc comment), so the two must never
    // be conflated.
    let candidate_id = store
        .persist_correlation(CorrelationPersistence {
            correlation_key: &candidate_key,
            confidence,
            severity,
            summary,
            first_seen,
            last_seen,
            window: CANDIDATE_EXTENSION_WINDOW,
            event_ids,
            relationships: &[],
        })
        .await?;
    // Linking security_assessments.incident_id is a best-effort courtesy
    // (it only ever sets an unset column, and nothing downstream relies on
    // it for correctness - the incident itself already exists and is
    // escalation-safe via persist_correlation regardless), so a candidate
    // that has not been promoted yet simply leaves it NULL here; the next
    // promotion pass does not retroactively backfill it, unlike alerts.
    match store.get_incident_id_for_candidate(candidate_id).await {
        Ok(Some(incident_id)) => {
            if let Err(error) = store
                .link_security_assessment_incident(assessment_id, incident_id)
                .await
            {
                warn!(%error, "could not link security assessment to its incident");
            }
        }
        Ok(None) => {}
        Err(error) => {
            warn!(%error, "could not look up the incident for a candidate");
        }
    }
    Ok(())
}

/// Evaluate one count-threshold rule against the event that just arrived.
/// Cheap and idempotent to call for every qualifying event, including ones
/// below threshold (a no-op until the bucket's count crosses it) - the
/// caller does not need to know in advance which event will be the one
/// that tips it over.
async fn evaluate_rule(
    store: &PostgresStore,
    rule: &CountThresholdRule,
    event: &EventRecord,
) -> Result<()> {
    let Some(correlation_id) = event
        .correlation_id
        .as_deref()
        .filter(|v| !v.trim().is_empty())
    else {
        // No pseudonymous resource to group by (should not happen for a
        // sensor-produced event - record_security_event always sets one -
        // but a rule must not panic on a canonical event some other,
        // future producer publishes under the same event_type without one).
        return Ok(());
    };
    let bucket = bucket_start(event.occurred_at, rule.window_seconds);
    let bucket_end = bucket + Duration::seconds(rule.window_seconds);
    let members = store
        .list_events_for_bucket(rule.event_type, correlation_id, bucket, bucket_end)
        .await?;
    if members.len() < rule.threshold {
        return Ok(());
    }
    let event_ids: Vec<Uuid> = members.iter().map(|(id, _)| *id).collect();
    let first_seen = members
        .first()
        .map(|(_, at)| *at)
        .unwrap_or(event.occurred_at);
    let last_seen = members
        .last()
        .map(|(_, at)| *at)
        .unwrap_or(event.occurred_at);
    let count = members.len();
    let severity = severity_for_count(count, rule.threshold);
    let confidence = confidence_for_count(count, rule.threshold);
    let summary = format!(
        "{} events of type {} from the same source within {}s (rule {} v{})",
        count, rule.event_type, rule.window_seconds, rule.rule_id, rule.rule_version
    );
    persist_assessment_and_incident(
        store,
        rule.rule_id,
        rule.rule_version,
        rule.window_seconds,
        correlation_id,
        bucket,
        &event_ids,
        first_seen,
        last_seen,
        severity,
        confidence,
        &summary,
    )
    .await
}

/// Evaluate one distinct-value rule (a scan) against the event that just
/// arrived. Same shape as `evaluate_rule`, except membership counts
/// `COUNT(DISTINCT payload->>field)`, not `COUNT(*)` - a source hitting the
/// same path 50 times is a burst, not a scan; a source hitting eight
/// different paths once each is a scan even though the raw count is lower.
async fn evaluate_scan_rule(
    store: &PostgresStore,
    rule: &DistinctValueThresholdRule,
    event: &EventRecord,
) -> Result<()> {
    let Some(correlation_id) = event
        .correlation_id
        .as_deref()
        .filter(|v| !v.trim().is_empty())
    else {
        return Ok(());
    };
    let bucket = bucket_start(event.occurred_at, rule.window_seconds);
    let bucket_end = bucket + Duration::seconds(rule.window_seconds);
    let members = store
        .list_events_for_bucket_with_field(
            rule.event_type,
            correlation_id,
            rule.field,
            bucket,
            bucket_end,
        )
        .await?;
    let distinct_values: std::collections::BTreeSet<&str> = members
        .iter()
        .filter_map(|(_, _, value)| value.as_deref())
        .collect();
    if distinct_values.len() < rule.threshold {
        return Ok(());
    }
    let event_ids: Vec<Uuid> = members.iter().map(|(id, _, _)| *id).collect();
    let first_seen = members
        .first()
        .map(|(_, at, _)| *at)
        .unwrap_or(event.occurred_at);
    let last_seen = members
        .last()
        .map(|(_, at, _)| *at)
        .unwrap_or(event.occurred_at);
    let distinct_count = distinct_values.len();
    let severity = severity_for_count(distinct_count, rule.threshold);
    let confidence = confidence_for_count(distinct_count, rule.threshold);
    let summary = format!(
        "{} distinct {} values across {} events of type {} from the same source within {}s \
         (rule {} v{})",
        distinct_count,
        rule.field,
        members.len(),
        rule.event_type,
        rule.window_seconds,
        rule.rule_id,
        rule.rule_version
    );
    persist_assessment_and_incident(
        store,
        rule.rule_id,
        rule.rule_version,
        rule.window_seconds,
        correlation_id,
        bucket,
        &event_ids,
        first_seen,
        last_seen,
        severity,
        confidence,
        &summary,
    )
    .await
}

#[derive(Debug, Clone)]
struct EventRecord {
    event_type: String,
    occurred_at: DateTime<Utc>,
    correlation_id: Option<String>,
}

fn event_from_value(value: &serde_json::Value) -> Result<EventRecord> {
    Ok(EventRecord {
        event_type: value
            .get("event_type")
            .and_then(serde_json::Value::as_str)
            .context("event delivery is missing event_type")?
            .to_string(),
        occurred_at: value
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .context("event delivery is missing timestamp")?
            .parse()?,
        correlation_id: value
            .get("correlation_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    })
}

async fn process_delivery(store: &PostgresStore, event: EventRecord) -> Result<()> {
    for rule in RULES {
        if rule.event_type == event.event_type {
            evaluate_rule(store, rule, &event).await?;
        }
    }
    for rule in DISTINCT_VALUE_RULES {
        if rule.event_type == event.event_type {
            evaluate_scan_rule(store, rule, &event).await?;
        }
    }
    Ok(())
}

fn poll_interval() -> std::time::Duration {
    env::var("CLAWFORGE_SECURITY_ENGINE_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(5))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let poll = poll_interval();
    let store = PostgresStore::connect_runtime(&database_url_from_env()?).await?;
    store.ensure_event_consumer(CONSUMER_NAME).await?;
    store.heartbeat_event_consumer(CONSUMER_NAME).await?;
    store
        .set_runtime_status(CONSUMER_NAME, "running", None)
        .await?;
    info!(
        count_threshold_rules = RULES.len(),
        distinct_value_rules = DISTINCT_VALUE_RULES.len(),
        "Clawforge security engine started"
    );
    let mut interval = tokio::time::interval(poll);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(error) = store.heartbeat_event_consumer(CONSUMER_NAME).await {
                    warn!(%error, "could not heartbeat security-engine consumer");
                }
                if let Err(error) = store.set_runtime_status(CONSUMER_NAME, "running", None).await {
                    warn!(%error, "could not heartbeat security-engine runtime status");
                }
                match store.claim_event_deliveries(CONSUMER_NAME, 50).await {
                    Ok(deliveries) => for delivery in deliveries {
                        let delivery_id = delivery.get("delivery_id").and_then(serde_json::Value::as_str).and_then(|value| value.parse::<Uuid>().ok());
                        let result = match event_from_value(&delivery) {
                            Ok(event) => process_delivery(&store, event).await,
                            Err(error) => Err(error),
                        };
                        let error_text = result.as_ref().err().map(ToString::to_string);
                        if let Some(delivery_id) = delivery_id {
                            if let Err(error) = store.complete_event_delivery(delivery_id, CONSUMER_NAME, result.is_ok(), error_text.as_deref()).await {
                                warn!(%error, "could not complete security-engine delivery");
                            }
                        }
                        if let Err(error) = result { warn!(%error, "security engine rule evaluation failed"); }
                    },
                    Err(error) => warn!(%error, "security engine polling failed"),
                }
            }
            _ = shutdown_signal() => { info!("Clawforge security engine shutting down"); break; }
        }
    }
    store
        .set_runtime_status(CONSUMER_NAME, "stopped", None)
        .await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_start_floors_to_the_window_boundary() {
        let at = Utc.with_ymd_and_hms(2026, 1, 1, 12, 7, 42).unwrap();
        let bucket = bucket_start(at, 300);
        assert_eq!(bucket, Utc.with_ymd_and_hms(2026, 1, 1, 12, 5, 0).unwrap());
    }

    #[test]
    fn bucket_start_is_stable_for_every_timestamp_in_the_same_window() {
        let a = Utc.with_ymd_and_hms(2026, 1, 1, 12, 5, 0).unwrap();
        let b = Utc.with_ymd_and_hms(2026, 1, 1, 12, 9, 59).unwrap();
        assert_eq!(bucket_start(a, 300), bucket_start(b, 300));
    }

    #[test]
    fn severity_and_confidence_escalate_with_count() {
        assert_eq!(severity_for_count(5, 5), "medium");
        assert_eq!(severity_for_count(10, 5), "high");
        assert_eq!(severity_for_count(20, 5), "critical");
        assert!(confidence_for_count(5, 5) < confidence_for_count(20, 5));
        assert!(confidence_for_count(1000, 5) <= 99);
    }

    #[test]
    fn event_from_value_requires_event_type_and_timestamp() {
        assert!(event_from_value(&serde_json::json!({})).is_err());
        assert!(event_from_value(&serde_json::json!({
            "event_type": "ssh_login_failure",
            "timestamp": "not-a-timestamp",
        }))
        .is_err());
        let parsed = event_from_value(&serde_json::json!({
            "event_type": "ssh_login_failure",
            "timestamp": "2026-01-01T00:00:00Z",
            "correlation_id": "ip-pseudonym:abc",
        }))
        .unwrap();
        assert_eq!(parsed.event_type, "ssh_login_failure");
        assert_eq!(parsed.correlation_id.as_deref(), Some("ip-pseudonym:abc"));
    }

    fn test_url(role: &str) -> Result<String> {
        Ok(env::var(format!(
            "CLAWFORGE_TEST_{}_DATABASE_URL",
            role.to_ascii_uppercase()
        ))?)
    }

    async fn publish_ssh_login_failure(
        store: &PostgresStore,
        correlation_id: &str,
        occurred_at: DateTime<Utc>,
        nonce: &str,
    ) -> Result<EventRecord> {
        store
            .publish_event(
                "ssh_login_failure",
                "test-sensor",
                "low",
                occurred_at,
                Some(correlation_id),
                serde_json::json!({"test": true}),
                serde_json::json!({}),
                &format!("test:ssh_login_failure:{correlation_id}:{nonce}"),
            )
            .await?;
        Ok(EventRecord {
            event_type: "ssh_login_failure".to_string(),
            occurred_at,
            correlation_id: Some(correlation_id.to_string()),
        })
    }

    /// Proves the whole count-threshold path end to end against real
    /// PostgreSQL, running as the least-privilege `security_engine` role the
    /// deployed binary actually uses (not the owner connection, except to
    /// set up fixtures and read back results): below the rule's threshold
    /// nothing is created; the event that crosses it creates exactly one
    /// assessment and exactly one incident (via the reused, already-tested
    /// incident_candidates path); a further event in the same bucket
    /// updates that same assessment and does not spawn a duplicate
    /// candidate/incident; and re-evaluating the identical last event again
    /// (a redelivery replay) leaves every count unchanged - deterministic,
    /// not just idempotent.
    #[tokio::test]
    #[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
    async fn ssh_bruteforce_rule_fires_exactly_once_at_threshold_and_is_replay_safe() -> Result<()>
    {
        let owner_url = env::var("CLAWFORGE_TEST_DATABASE_URL")?;
        let owner = PostgresStore::connect_runtime(&owner_url).await?;
        let engine = PostgresStore::connect_runtime(&test_url("security_engine")?).await?;
        let incidents = PostgresStore::connect_runtime(&test_url("incidents")?).await?;

        // Unique per test run, same reason as clawforge-correlation's own
        // tests: a literal resource reused across tests/runs sharing a
        // database would let unrelated events collide.
        let resource = format!("ip-pseudonym:test-{}", Uuid::new_v4());
        let bucket = bucket_start(Utc::now(), SSH_BRUTEFORCE.window_seconds);

        // Four events - one short of the threshold of five.
        let mut last_event = None;
        for i in 0..4 {
            let occurred_at = bucket + Duration::seconds(i * 10);
            let event =
                publish_ssh_login_failure(&owner, &resource, occurred_at, &format!("n{i}")).await?;
            evaluate_rule(&engine, &SSH_BRUTEFORCE, &event).await?;
            last_event = Some(event);
        }
        let dedupe_key = format!("ssh_bruteforce:v1:{resource}:{}", bucket.timestamp());
        let below_threshold: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM security_assessments WHERE dedupe_key=$1")
                .bind(&dedupe_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(
            below_threshold, 0,
            "four events must not create an assessment for a threshold-five rule"
        );
        let _ = last_event;

        // The fifth event crosses the threshold.
        let fifth =
            publish_ssh_login_failure(&owner, &resource, bucket + Duration::seconds(40), "n4")
                .await?;
        evaluate_rule(&engine, &SSH_BRUTEFORCE, &fifth).await?;

        let event_count: i32 =
            sqlx::query_scalar("SELECT event_count FROM security_assessments WHERE dedupe_key=$1")
                .bind(&dedupe_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(event_count, 5);

        let candidate_key = format!("security-assessment:ssh_bruteforce:{resource}");
        let candidate_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incident_candidates WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(candidate_count, 1);

        assert_eq!(incidents.promote_incident_candidates(10).await?, 1);
        let incident_id: Uuid =
            sqlx::query_scalar("SELECT id FROM incidents WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;

        // A sixth event in the same bucket updates the existing assessment
        // rather than creating a second one, and does not duplicate the
        // incident.
        let sixth =
            publish_ssh_login_failure(&owner, &resource, bucket + Duration::seconds(50), "n5")
                .await?;
        evaluate_rule(&engine, &SSH_BRUTEFORCE, &sixth).await?;
        let assessment_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM security_assessments WHERE dedupe_key=$1")
                .bind(&dedupe_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(
            assessment_count, 1,
            "same bucket must upsert, not duplicate"
        );
        let event_count_after_sixth: i32 =
            sqlx::query_scalar("SELECT event_count FROM security_assessments WHERE dedupe_key=$1")
                .bind(&dedupe_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(event_count_after_sixth, 6);
        let incident_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(incident_count, 1, "must not duplicate the incident");

        // Replay: evaluating the exact same (sixth) event again - as a
        // redelivered event_delivery row would - must leave every count
        // exactly as it was, proving this is deterministic, not merely
        // idempotent-by-accident.
        evaluate_rule(&engine, &SSH_BRUTEFORCE, &sixth).await?;
        let event_count_after_replay: i32 =
            sqlx::query_scalar("SELECT event_count FROM security_assessments WHERE dedupe_key=$1")
                .bind(&dedupe_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(event_count_after_replay, 6);

        let assessment_incident_id: Option<Uuid> =
            sqlx::query_scalar("SELECT incident_id FROM security_assessments WHERE dedupe_key=$1")
                .bind(&dedupe_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(assessment_incident_id, Some(incident_id));

        Ok(())
    }

    async fn publish_http_anomaly(
        store: &PostgresStore,
        correlation_id: &str,
        occurred_at: DateTime<Utc>,
        path: &str,
        nonce: &str,
    ) -> Result<EventRecord> {
        store
            .publish_event(
                "http_anomaly",
                "test-sensor",
                "low",
                occurred_at,
                Some(correlation_id),
                serde_json::json!({"path": path, "status_code": 404}),
                serde_json::json!({}),
                &format!("test:http_anomaly:{correlation_id}:{nonce}"),
            )
            .await?;
        Ok(EventRecord {
            event_type: "http_anomaly".to_string(),
            occurred_at,
            correlation_id: Some(correlation_id.to_string()),
        })
    }

    /// Proves the distinct-value rule against real PostgreSQL: many hits on
    /// the *same* path never fire it (a burst, not a scan - exactly what
    /// `http_anomaly_burst` exists for instead), but the same number of
    /// hits spread across enough *distinct* paths does; a real assessment
    /// and incident result, via the same reused, already-tested path the
    /// count-threshold rule uses.
    #[tokio::test]
    #[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
    async fn http_scan_rule_ignores_a_same_path_burst_but_fires_on_path_diversity() -> Result<()> {
        let owner_url = env::var("CLAWFORGE_TEST_DATABASE_URL")?;
        let owner = PostgresStore::connect_runtime(&owner_url).await?;
        let engine = PostgresStore::connect_runtime(&test_url("security_engine")?).await?;
        // Also promoted at the end, not just asserted as an open candidate:
        // promote_incident_candidates(limit) processes every open candidate
        // in the whole database, not just this test's - an unpromoted one
        // left behind here would otherwise inflate a *later* test's own
        // "exactly N newly promoted" count (this is a real, previously hit
        // test-isolation gap: ssh_bruteforce's own promotion count was 2,
        // not 1, before this test cleaned up after itself).
        let incidents = PostgresStore::connect_runtime(&test_url("incidents")?).await?;

        let resource = format!("ip-pseudonym:test-{}", Uuid::new_v4());
        let bucket = bucket_start(Utc::now(), HTTP_SCAN.window_seconds);

        // Eight hits, but all the same path - a burst the scan rule must
        // not mistake for reconnaissance.
        let mut last_event = None;
        for i in 0..8 {
            let occurred_at = bucket + Duration::seconds(i * 10);
            let event = publish_http_anomaly(
                &owner,
                &resource,
                occurred_at,
                "/repeated",
                &format!("same-path-{i}"),
            )
            .await?;
            evaluate_scan_rule(&engine, &HTTP_SCAN, &event).await?;
            last_event = Some(event);
        }
        let _ = last_event;
        let dedupe_key = format!("http_scan:v1:{resource}:{}", bucket.timestamp());
        let same_path_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM security_assessments WHERE dedupe_key=$1")
                .bind(&dedupe_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(
            same_path_count, 0,
            "a same-path burst must not be mistaken for a scan"
        );

        // A second, distinct resource: eight hits across eight distinct
        // paths - genuine path diversity, must fire.
        let scanning_resource = format!("ip-pseudonym:test-scan-{}", Uuid::new_v4());
        let scan_dedupe_key = format!("http_scan:v1:{scanning_resource}:{}", bucket.timestamp());
        for i in 0..8 {
            let occurred_at = bucket + Duration::seconds(i * 10);
            let event = publish_http_anomaly(
                &owner,
                &scanning_resource,
                occurred_at,
                &format!("/probe-{i}"),
                &format!("distinct-path-{i}"),
            )
            .await?;
            evaluate_scan_rule(&engine, &HTTP_SCAN, &event).await?;
        }
        let event_count: i32 =
            sqlx::query_scalar("SELECT event_count FROM security_assessments WHERE dedupe_key=$1")
                .bind(&scan_dedupe_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(event_count, 8);

        let candidate_key = format!("security-assessment:http_scan:{scanning_resource}");
        let candidate_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incident_candidates WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(candidate_count, 1);

        // Promote it too, proving the scan rule's candidate is genuinely
        // promotable (not just an inert row) and leaving no open candidate
        // behind for a later test's own promotion-count assertion to trip
        // over.
        assert_eq!(incidents.promote_incident_candidates(10).await?, 1);
        let incident_severity: String =
            sqlx::query_scalar("SELECT severity FROM incidents WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(incident_severity, "medium");

        Ok(())
    }
}
