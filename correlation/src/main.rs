use anyhow::{Context, Result};
use chrono::Duration;
use clawforge_correlation::{correlate, derive_outcome, is_correlatable, EventRecord};
use clawforge_storage::{
    database_url_from_env, CorrelationPersistence, EventRelationship, PostgresStore,
};
use serde_json::Value;
use std::{env, time::Duration as StdDuration};
use tracing::{info, warn};
use uuid::Uuid;

fn config() -> Result<(StdDuration, Duration)> {
    let poll = env::var("CLAWFORGE_CORRELATION_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5);
    let window = env::var("CLAWFORGE_CORRELATION_WINDOW_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(900);
    Ok((StdDuration::from_secs(poll), Duration::seconds(window)))
}

fn event_from_value(value: &Value) -> Result<EventRecord> {
    Ok(EventRecord {
        event_id: value
            .get("event_id")
            .and_then(Value::as_str)
            .context("event delivery is missing event_id")?
            .parse::<Uuid>()?,
        event_type: value
            .get("event_type")
            .and_then(Value::as_str)
            .context("event delivery is missing event_type")?
            .to_string(),
        source: value
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        severity: value
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_string(),
        occurred_at: value
            .get("timestamp")
            .and_then(Value::as_str)
            .context("event delivery is missing timestamp")?
            .parse()?,
        correlation_id: value
            .get("correlation_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        payload: value
            .get("payload")
            .cloned()
            .unwrap_or(Value::Object(Default::default())),
    })
}

async fn process_event(store: &PostgresStore, event: EventRecord, window: Duration) -> Result<()> {
    if !is_correlatable(&event.event_type) {
        return Ok(());
    }
    let recent = store
        .list_correlation_events(event.occurred_at, window, event.event_id)
        .await?;
    let mut matches = Vec::new();
    for related in recent {
        let related = EventRecord {
            event_id: related.event_id,
            event_type: related.event_type,
            source: related.source,
            severity: related.severity,
            occurred_at: related.occurred_at,
            correlation_id: related.correlation_id,
            payload: related.payload,
        };
        if let Some(found) = correlate(&event, &related, window) {
            matches.push((related, found));
        }
    }
    if matches.is_empty() {
        // No related event yet, but a lone correlatable signal (a single
        // rpki_invalid or new_threat_indicator, say) is still worth an
        // incident candidate on its own, not just once a second event
        // happens to correlate with it. Key it the same way a later
        // correlation-id match would (`correlate` above), so a follow-up
        // event for the same resource extends this candidate instead of
        // creating a second one. Every current intelligence-event producer
        // sets this; an event without one is only observed once a second
        // event correlates it, matching prior behavior for those sources.
        let Some(correlation_id) = event
            .correlation_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        let key = format!("correlation-id:{correlation_id}");
        let outcome = derive_outcome(std::slice::from_ref(&event), &[]);
        store
            .persist_correlation(CorrelationPersistence {
                correlation_key: &key,
                confidence: outcome.confidence as i16,
                severity: &outcome.severity,
                summary: &outcome.summary,
                first_seen: event.occurred_at,
                last_seen: event.occurred_at,
                window,
                event_ids: &[event.event_id],
                relationships: &[],
            })
            .await?;
        return Ok(());
    }
    matches.sort_by_key(|value| std::cmp::Reverse(value.1.confidence));
    let strongest_key = matches[0].1.correlation_key.clone();
    let mut events = vec![event.clone()];
    let mut relations = Vec::new();
    let mut strongest_matches = Vec::new();
    for (related, matched) in &matches {
        let is_strongest = matched.correlation_key == strongest_key;
        if is_strongest {
            events.push(related.clone());
            strongest_matches.push(matched.clone());
        }
        relations.push((event.event_id, related.event_id, matched.clone()));
    }
    let outcome = derive_outcome(&events, &strongest_matches);
    let event_ids = events
        .iter()
        .map(|value| value.event_id)
        .collect::<Vec<_>>();
    let persisted_relationships = relations
        .iter()
        .map(|(event_id, related_event_id, matched)| EventRelationship {
            event_id: *event_id,
            related_event_id: *related_event_id,
            relation_type: matched.relation_type.clone(),
            confidence: matched.confidence as i16,
            reason: matched.reason.clone(),
        })
        .collect::<Vec<_>>();
    store
        .persist_correlation(CorrelationPersistence {
            correlation_key: &strongest_key,
            confidence: outcome.confidence as i16,
            severity: &outcome.severity,
            summary: &outcome.summary,
            first_seen: events
                .iter()
                .map(|value| value.occurred_at)
                .min()
                .unwrap_or(event.occurred_at),
            last_seen: events
                .iter()
                .map(|value| value.occurred_at)
                .max()
                .unwrap_or(event.occurred_at),
            window,
            event_ids: &event_ids,
            relationships: &persisted_relationships,
        })
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let (poll, window) = config()?;
    let store = PostgresStore::connect_runtime(&database_url_from_env()?).await?;
    store.ensure_event_consumer("correlation").await?;
    store.heartbeat_event_consumer("correlation").await?;
    store
        .set_runtime_status("correlation", "running", None)
        .await?;
    info!(?window, "Clawforge event correlation layer started");
    let mut interval = tokio::time::interval(poll);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(error) = store.heartbeat_event_consumer("correlation").await {
                    warn!(%error, "could not heartbeat correlation consumer");
                }
                if let Err(error) = store.set_runtime_status("correlation", "running", None).await {
                    warn!(%error, "could not heartbeat correlation runtime status");
                }
                match store.claim_event_deliveries("correlation", 50).await {
                    Ok(deliveries) => for delivery in deliveries {
                        let delivery_id = delivery.get("delivery_id").and_then(Value::as_str).and_then(|value| value.parse::<Uuid>().ok());
                        let result = match event_from_value(&delivery) {
                            Ok(event) => process_event(&store, event, window).await,
                            Err(error) => Err(error),
                        };
                        let error_text = result.as_ref().err().map(ToString::to_string);
                        if let Some(delivery_id) = delivery_id {
                            if let Err(error) = store.complete_event_delivery(delivery_id, "correlation", result.is_ok(), error_text.as_deref()).await {
                                warn!(%error, "could not complete correlation delivery");
                            }
                        }
                        if let Err(error) = result { warn!(%error, "event correlation failed"); }
                    },
                    Err(error) => warn!(%error, "event correlation polling failed"),
                }
            }
            _ = shutdown_signal() => { info!("Clawforge event correlation layer shutting down"); break; }
        }
    }
    store
        .set_runtime_status("correlation", "stopped", None)
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
    use serde_json::json;

    fn test_url(role: &str) -> Result<String> {
        Ok(env::var(format!(
            "CLAWFORGE_TEST_{}_DATABASE_URL",
            role.to_ascii_uppercase()
        ))?)
    }

    /// Proves the full convergence path end to end against real PostgreSQL,
    /// using the same least-privilege roles the deployed services run as
    /// (not the owner connection, except to set up the fixture and read back
    /// results): a single correlatable event with no partner becomes exactly
    /// one incident candidate, promotion turns it into exactly one incident,
    /// a second promotion pass is a no-op (no duplicate incident), and an
    /// alert created before promotion gets its incident_id backfilled.
    #[tokio::test]
    #[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
    async fn solo_candidate_promotes_to_one_incident_and_backfills_its_alert() -> Result<()> {
        let owner_url = env::var("CLAWFORGE_TEST_DATABASE_URL")?;
        let owner = PostgresStore::connect_runtime(&owner_url).await?;

        let resource = format!("test-resource-{}", Uuid::new_v4());
        // Unique per test run: `correlate` also matches unrelated events
        // that merely share a `source` within the correlation window, so a
        // literal like "test-source" reused across tests (or across runs
        // sharing a database) would falsely correlate them.
        let source = format!("test-source-{resource}");
        let occurred_at = chrono::Utc::now();
        let event_type = "rpki_invalid";
        assert!(is_correlatable(event_type));

        // Set up the audit trail and alert the way a producer service does
        // today (record_intelligence_event, minus its legacy
        // correlate_incident call) - this test exists to prove the
        // candidate/promotion path now covers what that call used to.
        let audit_event_id: i64 = sqlx::query_scalar(
            "INSERT INTO audit_events (actor, action, resource, details, event_type, source, severity, reason, recorded_at) VALUES ('system',$1,$2,$3,$1,$4,$5,$6,$7) RETURNING id",
        )
        .bind(event_type)
        .bind(&resource)
        .bind(json!({"test": true}))
        .bind(&source)
        .bind("high")
        .bind("solo candidate test")
        .bind(occurred_at)
        .fetch_one(owner.pool())
        .await?;

        let event_id = owner
            .publish_event(
                event_type,
                &source,
                "high",
                occurred_at,
                Some(&resource),
                json!({"test": true}),
                json!({"audit_event_id": audit_event_id}),
                &format!(
                    "{event_type}:{resource}:{}",
                    occurred_at.timestamp_nanos_opt().unwrap_or_default()
                ),
            )
            .await?;

        let alert_id = owner
            .create_alert_for_event(
                audit_event_id,
                event_type,
                &source,
                "high",
                &resource,
                "solo candidate test",
                None,
            )
            .await?
            .expect("a high-severity event creates an alert");

        // Run the correlation service's own event-processing function under
        // its own least-privilege role, exactly as the running binary does
        // when it claims an event delivery.
        let correlation = PostgresStore::connect_runtime(&test_url("correlation")?).await?;
        let event = EventRecord {
            event_id,
            event_type: event_type.to_string(),
            source: source.clone(),
            severity: "high".to_string(),
            occurred_at,
            correlation_id: Some(resource.clone()),
            payload: json!({"test": true}),
        };
        process_event(&correlation, event, Duration::seconds(900)).await?;

        let candidate_key = format!("correlation-id:{resource}");
        let candidate_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incident_candidates WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(
            candidate_count, 1,
            "a lone correlatable event should create exactly one candidate"
        );

        // Promote under the incidents service's own least-privilege role -
        // this is what actually exercises the new alerts/events/
        // notification_events grants added to that role.
        let incidents = PostgresStore::connect_runtime(&test_url("incidents")?).await?;
        let promoted = incidents.promote_incident_candidates(10).await?;
        assert_eq!(promoted, 1);

        // A second pass must not create a second incident for the same
        // already-promoted candidate.
        let promoted_again = incidents.promote_incident_candidates(10).await?;
        assert_eq!(promoted_again, 0);

        let incident_id: Uuid =
            sqlx::query_scalar("SELECT id FROM incidents WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        let incident_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(incident_count, 1);

        let backfilled_incident_id: Option<Uuid> =
            sqlx::query_scalar("SELECT incident_id FROM alerts WHERE id=$1")
                .bind(alert_id)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(backfilled_incident_id, Some(incident_id));

        Ok(())
    }

    /// A candidate that was already promoted is not a dead end: a later
    /// event for the same correlation key must escalate the incident that
    /// candidate already produced, not spawn a second incident with the
    /// same correlation key.
    #[tokio::test]
    #[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
    async fn a_later_related_event_escalates_the_existing_incident_instead_of_duplicating_it(
    ) -> Result<()> {
        let owner_url = env::var("CLAWFORGE_TEST_DATABASE_URL")?;
        let owner = PostgresStore::connect_runtime(&owner_url).await?;
        let correlation = PostgresStore::connect_runtime(&test_url("correlation")?).await?;
        let incidents = PostgresStore::connect_runtime(&test_url("incidents")?).await?;

        let resource = format!("test-resource-{}", Uuid::new_v4());
        // See the sibling test for why this must not be a literal shared
        // across tests: `correlate` also matches on shared `source`.
        let source = format!("test-source-{resource}");
        let candidate_key = format!("correlation-id:{resource}");
        let window = Duration::seconds(900);

        async fn publish(
            owner: &PostgresStore,
            event_type: &str,
            source: &str,
            resource: &str,
            severity: &str,
            occurred_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<Uuid> {
            owner
                .publish_event(
                    event_type,
                    source,
                    severity,
                    occurred_at,
                    Some(resource),
                    json!({"test": true}),
                    json!({}),
                    &format!(
                        "{event_type}:{resource}:{}",
                        occurred_at.timestamp_nanos_opt().unwrap_or_default()
                    ),
                )
                .await
        }

        let first_seen = chrono::Utc::now();
        let first_event = publish(
            &owner,
            "rpki_invalid",
            &source,
            &resource,
            "high",
            first_seen,
        )
        .await?;
        process_event(
            &correlation,
            EventRecord {
                event_id: first_event,
                event_type: "rpki_invalid".to_string(),
                source: source.clone(),
                severity: "high".to_string(),
                occurred_at: first_seen,
                correlation_id: Some(resource.clone()),
                payload: json!({"test": true}),
            },
            window,
        )
        .await?;
        assert_eq!(incidents.promote_incident_candidates(10).await?, 1);

        let incident_id: Uuid =
            sqlx::query_scalar("SELECT id FROM incidents WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        let initial_severity: String =
            sqlx::query_scalar("SELECT severity FROM incidents WHERE id=$1")
                .bind(incident_id)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(initial_severity, "high");

        // A second, more severe event for the same resource arrives after
        // the first candidate was already promoted.
        let second_seen = first_seen + Duration::seconds(30);
        let second_event = publish(
            &owner,
            "rpki_invalid",
            &source,
            &resource,
            "critical",
            second_seen,
        )
        .await?;
        process_event(
            &correlation,
            EventRecord {
                event_id: second_event,
                event_type: "rpki_invalid".to_string(),
                source: source.clone(),
                severity: "critical".to_string(),
                occurred_at: second_seen,
                correlation_id: Some(resource.clone()),
                payload: json!({"test": true}),
            },
            window,
        )
        .await?;

        // The candidate was reopened, not duplicated.
        let candidate_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incident_candidates WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(candidate_count, 1);

        // Promoting again must escalate the existing incident, not create a
        // second one: `promoted` (new incidents) stays 0, while the
        // existing incident's severity reflects the escalation.
        let promoted = incidents.promote_incident_candidates(10).await?;
        assert_eq!(promoted, 0, "escalation must not count as a new incident");

        let incident_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE correlation_key=$1")
                .bind(&candidate_key)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(incident_count, 1, "the same incident must be reused");

        let escalated_severity: String =
            sqlx::query_scalar("SELECT severity FROM incidents WHERE id=$1")
                .bind(incident_id)
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(escalated_severity, "critical");

        let escalation_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE event_type='incident.escalated' AND correlation_id=$1")
                .bind(incident_id.to_string())
                .fetch_one(owner.pool())
                .await?;
        assert_eq!(
            escalation_events, 1,
            "the escalation must be announced on the event bus"
        );

        Ok(())
    }
}
