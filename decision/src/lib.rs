//! Pure decision and declarative rule evaluation.
//!
//! This crate only produces explainable recommendations. It never executes an
//! action, changes policy, or grants trust.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionDraft {
    pub severity: String,
    pub category: String,
    pub source: String,
    pub title: String,
    pub description: String,
    pub reason: String,
    pub recommendation: String,
    pub confidence: f64,
    pub related_incident_id: Option<Uuid>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleEvaluation {
    pub matched: bool,
    pub reason: String,
    pub event_id: Option<Uuid>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DecisionEngine;

impl DecisionEngine {
    pub fn evaluate(
        &self,
        incidents: &[Value],
        providers: &[Value],
        alerts: &[Value],
        knowledge: &[Value],
    ) -> Vec<DecisionDraft> {
        let mut drafts = Vec::new();
        for incident in incidents.iter().filter(|value| is_active_incident(value)) {
            let severity = string_field(incident, "severity").unwrap_or_else(|| "info".into());
            let confidence = number_field(incident, "confidence")
                .map(|value| (value / 100.0).clamp(0.0, 1.0))
                .unwrap_or(0.5);
            let incident_id = string_field(incident, "id").and_then(|id| Uuid::parse_str(&id).ok());
            let summary =
                string_field(incident, "summary").unwrap_or_else(|| "active incident".into());
            drafts.push(DecisionDraft {
                severity: severity.clone(),
                category: "incident".into(),
                source: "decision_engine".into(),
                title: format!("Active incident requires review: {severity}"),
                description: summary.clone(),
                reason: format!("Incident remains active with {severity} severity and stored confidence {confidence:.2}"),
                recommendation: "Review the incident timeline, related events, and current trust context before taking any action.".into(),
                confidence,
                related_incident_id: incident_id,
                metadata: serde_json::json!({"risk_score": incident.get("risk_score"), "event_count": incident.get("event_count")}),
            });
        }
        for provider in providers.iter().filter(|value| {
            matches!(
                string_field(value, "status").as_deref(),
                Some("error" | "degraded" | "timeout")
            )
        }) {
            let name = string_field(provider, "name")
                .or_else(|| string_field(provider, "id"))
                .unwrap_or_else(|| "provider".into());
            let failure = string_field(provider, "last_error")
                .unwrap_or_else(|| "provider health is degraded".into());
            drafts.push(DecisionDraft {
                severity: "high".into(),
                category: "provider_health".into(),
                source: "decision_engine".into(),
                title: format!("Provider outage detected: {name}"),
                description: format!("{name} is reporting an unhealthy synchronization state."),
                reason: failure,
                recommendation: "Review provider history and fallback configuration; no provider is activated automatically.".into(),
                confidence: 0.91,
                related_incident_id: None,
                metadata: serde_json::json!({"provider_id": provider.get("id"), "data_age_seconds": provider.get("age_seconds")}),
            });
        }
        let open_alerts = alerts
            .iter()
            .filter(|value| {
                matches!(
                    string_field(value, "status").as_deref(),
                    Some("open" | "acknowledged")
                )
            })
            .count();
        if open_alerts > 0 && drafts.iter().all(|draft| draft.category != "alerts") {
            let historical = knowledge
                .iter()
                .any(|value| string_field(value, "type").as_deref() == Some("incident"));
            drafts.push(DecisionDraft {
                severity: "medium".into(),
                category: "alerts".into(),
                source: "decision_engine".into(),
                title: "Open alerts require review".into(),
                description: format!("{open_alerts} alert(s) are open or acknowledged."),
                reason: if historical {
                    "Open alerts are compared with stored incident knowledge.".into()
                } else {
                    "Open alerts are present in the current operations state.".into()
                },
                recommendation:
                    "Review alert grouping and linked incidents; do not close alerts automatically."
                        .into(),
                confidence: 0.75,
                related_incident_id: None,
                metadata: serde_json::json!({"open_alerts": open_alerts}),
            });
        }
        drafts
    }
}

pub fn evaluate_rule(rule: &Value, events: &[Value], now: DateTime<Utc>) -> RuleEvaluation {
    let condition = rule.get("condition").cloned().unwrap_or_default();
    let minimum = condition
        .get("event_severity_at_least")
        .and_then(Value::as_str)
        .unwrap_or("info");
    let window_seconds = condition
        .get("source_event_count")
        .and_then(|value| value.get("window_seconds"))
        .and_then(Value::as_i64)
        .unwrap_or(600)
        .clamp(1, 86_400);
    let threshold = condition
        .get("source_event_count")
        .and_then(|value| value.get("greater_than"))
        .and_then(Value::as_u64)
        .unwrap_or(5) as usize;
    let source = condition.get("source").and_then(Value::as_str);
    let cutoff = now - Duration::seconds(window_seconds);
    let matching = events
        .iter()
        .filter(|event| {
            let severity = string_field(event, "severity").unwrap_or_else(|| "info".into());
            let timestamp = string_field(event, "timestamp")
                .or_else(|| string_field(event, "occurred_at"))
                .and_then(|value| DateTime::parse_from_rfc3339(&value).ok())
                .map(|value| value.with_timezone(&Utc));
            severity_rank(&severity) >= severity_rank(minimum)
                && timestamp.is_some_and(|value| value >= cutoff && value <= now)
                && source
                    .is_none_or(|wanted| string_field(event, "source").as_deref() == Some(wanted))
        })
        .collect::<Vec<_>>();
    let event_id = matching
        .first()
        .and_then(|event| string_field(event, "event_id"))
        .and_then(|id| Uuid::parse_str(&id).ok());
    RuleEvaluation {
        matched: matching.len() > threshold,
        reason: format!(
            "{} matching event(s) in the last {window_seconds} seconds; threshold is {threshold}",
            matching.len()
        ),
        event_id,
    }
}

fn is_active_incident(value: &Value) -> bool {
    !matches!(
        string_field(value, "status").as_deref(),
        Some("resolved" | "closed")
    )
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn number_field(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

fn severity_rank(value: &str) -> u8 {
    match value.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_rule, DecisionEngine};
    use chrono::{Duration, Utc};
    use serde_json::json;

    #[test]
    fn provider_and_incident_recommendations_are_explainable() {
        let incident_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let decisions = DecisionEngine.evaluate(
            &[json!({"id": incident_id, "status":"investigating", "severity":"high", "confidence":88, "summary":"correlated events"})],
            &[json!({"id":"threatfox", "name":"ThreatFox", "status":"error", "last_error":"timeout"})],
            &[],
            &[],
        );
        assert_eq!(decisions.len(), 2);
        assert!(decisions.iter().all(
            |value| !value.recommendation.is_empty() && (0.0..=1.0).contains(&value.confidence)
        ));
    }

    #[test]
    fn declarative_rule_matches_recent_event_chain() {
        let now = Utc::now();
        let rule = json!({"condition":{"event_severity_at_least":"critical","source_event_count":{"greater_than":1,"window_seconds":600},"source":"scanner"}});
        let events = (0..2).map(|index| json!({"event_id": format!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa{}", index), "severity":"critical", "source":"scanner", "timestamp": (now - Duration::seconds(index)).to_rfc3339()})).collect::<Vec<_>>();
        let evaluation = evaluate_rule(&rule, &events, now);
        assert!(evaluation.matched);
        assert!(evaluation.reason.contains("2 matching"));
    }

    #[test]
    fn rule_does_not_match_outside_window() {
        let now = Utc::now();
        let rule = json!({"condition":{"event_severity_at_least":"high","source_event_count":{"greater_than":0,"window_seconds":60}}});
        let events = vec![
            json!({"severity":"critical", "source":"scanner", "timestamp": (now - Duration::minutes(2)).to_rfc3339()}),
        ];
        assert!(!evaluate_rule(&rule, &events, now).matched);
    }
}
