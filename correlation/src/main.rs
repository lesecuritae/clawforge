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
    let store = PostgresStore::connect(&database_url_from_env()?).await?;
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
                            if let Err(error) = store.complete_event_delivery(delivery_id, result.is_ok(), error_text.as_deref()).await {
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
