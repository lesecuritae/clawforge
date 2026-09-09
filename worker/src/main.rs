use std::{env, time::Duration};

use clawforge_decision::DecisionEngine;
use clawforge_storage::{database_url_from_env, DecisionInput, PostgresStore, WorkflowRunInput};
use clawforge_worker::Scheduler;
use tokio::time::{interval, MissedTickBehavior};
use tracing_subscriber::EnvFilter;

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
    let database_url = database_url_from_env()?;
    let store = PostgresStore::connect(&database_url).await?;
    store.set_runtime_status("worker", "running", None).await?;
    let seconds = env::var("CLAWFORGE_WORKER_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);
    let enabled = env::var("CLAWFORGE_ENABLE_FEEDS")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    let mut scheduler = Scheduler::phase_one(enabled)?;
    let mut ticks = interval(Duration::from_secs(seconds.max(5)));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tracing::info!(
        poll_seconds = seconds,
        providers = scheduler.provider_count(),
        feeds_enabled = enabled,
        network_enabled = env::var("CLAWFORGE_ENABLE_NETWORK")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false),
        "Clawforge worker started"
    );
    loop {
        tokio::select! {
            _ = ticks.tick() => {
                if let Err(error) = store.set_runtime_status("worker", "running", None).await {
                    tracing::warn!(%error, "worker heartbeat persistence failed");
                }
                if let Err(error) = store.healthcheck().await {
                    tracing::error!(%error, "worker database health check failed");
                    let _ = store.set_runtime_status("worker", "error", Some(&error.to_string())).await;
                } else {
                    scheduler.run_due(&store).await;
                    if let Err(error) = store.capture_operations_snapshot().await {
                        tracing::warn!(%error, "operations snapshot persistence failed");
                    }
                    if let Err(error) = evaluate_decisions(&store).await {
                        tracing::warn!(%error, "decision evaluation failed");
                    }
                    if let Err(error) = prepare_workflow_runs(&store).await {
                        tracing::warn!(%error, "workflow preparation failed");
                    }
                }
            }
            _ = shutdown_signal() => {
                tracing::info!("worker shutdown requested");
                let _ = store.set_runtime_status("worker", "stopped", None).await;
                break;
            }
        }
    }
    Ok(())
}

async fn evaluate_decisions(store: &PostgresStore) -> anyhow::Result<()> {
    let incidents = store.list_incidents(None, 500).await?;
    let providers = store.list_provider_views().await?;
    let alerts = store.list_alerts(None, None, 500).await?;
    let knowledge = store.list_knowledge_entries(500).await?;
    let drafts = DecisionEngine.evaluate(&incidents, &providers, &alerts, &knowledge);
    for draft in drafts {
        store
            .upsert_decision(&DecisionInput {
                severity: draft.severity,
                category: draft.category,
                source: draft.source,
                title: draft.title,
                description: draft.description,
                reason: draft.reason,
                recommendation: draft.recommendation,
                confidence: draft.confidence,
                related_incident_id: draft.related_incident_id,
                metadata: draft.metadata,
            })
            .await?;
    }
    let events = store.list_events(None, 500).await?;
    for rule in store.list_rules(Some(true), 100).await? {
        let evaluation = clawforge_decision::evaluate_rule(&rule, &events, chrono::Utc::now());
        if !evaluation.matched {
            continue;
        }
        let severity = rule
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("medium");
        let name = rule
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("declarative rule");
        let decision_id = store
            .upsert_decision(&DecisionInput {
                severity: severity.to_string(),
                category: "rule".into(),
                source: "rules_engine".into(),
                title: format!("Rule matched: {name}"),
                description: "A declarative rule matched the stored event context.".into(),
                reason: evaluation.reason.clone(),
                recommendation: "Review the matching events and incident context; no automatic action is performed.".into(),
                confidence: 0.8,
                related_incident_id: None,
                metadata: serde_json::json!({"rule_id": rule.get("id"), "rule_name": name}),
            })
            .await?;
        let rule_id = rule
            .get("id")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| uuid::Uuid::parse_str(id).ok());
        if let Some(rule_id) = rule_id {
            store
                .record_rule_execution(
                    rule_id,
                    evaluation.event_id,
                    &serde_json::json!({"matched":true,"reason":evaluation.reason}),
                    Some(decision_id),
                )
                .await?;
        }
    }
    store.expire_decisions().await?;
    Ok(())
}

async fn prepare_workflow_runs(store: &PostgresStore) -> anyhow::Result<()> {
    let decisions = store.list_decisions(Some("open"), None, 500).await?;
    let workflows = store.list_workflows(None, Some(true), 100).await?;
    for decision in decisions {
        let Some(category) = decision.get("category").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(workflow) = workflows.iter().find(|workflow| {
            workflow.get("category").and_then(serde_json::Value::as_str) == Some(category)
        }) else {
            continue;
        };
        let Some(workflow_id) = workflow
            .get("id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
        else {
            continue;
        };
        let requires_approval = workflow
            .get("steps")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|steps| {
                steps.iter().any(|step| {
                    step.get("required_approval")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                })
            });
        let decision_id = decision
            .get("id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| uuid::Uuid::parse_str(value).ok());
        store
            .prepare_workflow_run(&WorkflowRunInput {
                workflow_id,
                decision_id,
                status: if requires_approval {
                    "waiting_approval"
                } else {
                    "pending"
                }
                .into(),
                result: serde_json::json!({
                    "prepared": true,
                    "reason": decision.get("reason"),
                    "automatic_actions": false
                }),
                actor: "workflow_engine".into(),
                audit_action: "run_prepared".into(),
            })
            .await?;
    }
    Ok(())
}
