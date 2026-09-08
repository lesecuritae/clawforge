use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct EventRecord {
    pub event_id: Uuid,
    pub event_type: String,
    pub source: String,
    pub severity: String,
    pub occurred_at: DateTime<Utc>,
    pub correlation_id: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationMatch {
    pub correlation_key: String,
    pub relation_type: String,
    pub confidence: u8,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationOutcome {
    pub confidence: u8,
    pub severity: String,
    pub summary: String,
}

/// Event types that can contribute to a security incident candidate. Events
/// such as audit and lifecycle notifications are deliberately excluded so the
/// analysis layer cannot create feedback loops from its own observations.
pub fn is_correlatable(event_type: &str) -> bool {
    matches!(
        event_type,
        "new_threat_indicator"
            | "bgp_change"
            | "rpki_invalid"
            | "asn_change"
            | "trusted_network_change"
            | "provider_error"
    )
}

pub fn correlate(
    left: &EventRecord,
    right: &EventRecord,
    window: Duration,
) -> Option<CorrelationMatch> {
    if left.event_id == right.event_id
        || !is_correlatable(&left.event_type)
        || !is_correlatable(&right.event_type)
        || (left.occurred_at - right.occurred_at).abs() > window
    {
        return None;
    }

    if let (Some(left_id), Some(right_id)) = (&left.correlation_id, &right.correlation_id) {
        if !left_id.trim().is_empty() && left_id == right_id {
            return Some(CorrelationMatch {
                correlation_key: format!("correlation-id:{left_id}"),
                relation_type: if left.event_type == right.event_type {
                    "shared-correlation-id"
                } else {
                    "event-chain"
                }
                .into(),
                confidence: if left.event_type == right.event_type {
                    82
                } else {
                    96
                },
                reason: "events share the same source or target correlation id".into(),
            });
        }
    }

    let left_values = extract_indicators(&left.payload);
    let right_values = extract_indicators(&right.payload);
    let shared = left_values.intersection(&right_values).next().cloned();
    if shared.is_none() && left.source == right.source && !left.source.trim().is_empty() {
        return Some(CorrelationMatch {
            correlation_key: format!("source:{}", left.source),
            relation_type: "shared-source".into(),
            confidence: 68,
            reason: format!(
                "events share source {} within the correlation window",
                left.source
            ),
        });
    }
    let shared = shared?;
    let different_types = left.event_type != right.event_type;
    let same_source = left.source == right.source;
    let confidence = match (different_types, same_source) {
        (true, false) => 92,
        (true, true) => 86,
        (false, false) => 78,
        (false, true) => 72,
    };
    Some(CorrelationMatch {
        correlation_key: format!("indicator:{shared}"),
        relation_type: if different_types {
            "event-chain"
        } else {
            "shared-indicator"
        }
        .into(),
        confidence,
        reason: format!("events share indicator {shared}"),
    })
}

pub fn derive_outcome(events: &[EventRecord], matches: &[CorrelationMatch]) -> CorrelationOutcome {
    let mut event_types = BTreeSet::new();
    let mut severity = "info".to_string();
    for event in events {
        event_types.insert(event.event_type.as_str());
        if severity_rank(&event.severity) > severity_rank(&severity) {
            severity = normalize_severity(&event.severity);
        }
    }
    let mut confidence = matches
        .iter()
        .map(|value| value.confidence)
        .max()
        .unwrap_or(0);
    confidence = confidence
        .saturating_add(((event_types.len().saturating_sub(1)) * 4) as u8)
        .min(100);
    if event_types.len() >= 2 && severity == "medium" {
        severity = "high".into();
    }
    let summary = if event_types.len() > 1 {
        format!(
            "Correlated security event chain ({})",
            event_types.iter().copied().collect::<Vec<_>>().join(", ")
        )
    } else {
        "Correlated security events sharing an indicator".into()
    };
    CorrelationOutcome {
        confidence,
        severity,
        summary,
    }
}

pub fn extract_indicators(value: &Value) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    collect_indicators(value, None, &mut result);
    result
}

fn collect_indicators(value: &Value, key: Option<&str>, result: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (name, child) in map {
                collect_indicators(child, Some(name), result);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_indicators(child, key, result);
            }
        }
        Value::String(text) => {
            let normalized = text.trim().to_ascii_lowercase();
            let key = key.unwrap_or_default().to_ascii_lowercase();
            let meaningful_key = matches!(
                key.as_str(),
                "resource"
                    | "target"
                    | "indicator"
                    | "ip"
                    | "ip_address"
                    | "source_ip"
                    | "destination_ip"
                    | "prefix"
                    | "asn"
                    | "domain"
                    | "url"
                    | "hash"
                    | "correlation_id"
            );
            if meaningful_key && normalized.len() >= 3 && normalized.len() <= 512 {
                result.insert(normalized);
            }
        }
        Value::Number(number) if key.is_some_and(|name| name.eq_ignore_ascii_case("asn")) => {
            result.insert(number.to_string());
        }
        _ => {}
    }
}

fn normalize_severity(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    }
    .into()
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
    use super::*;

    fn event(id: u128, event_type: &str, source: &str, at: i64, payload: Value) -> EventRecord {
        EventRecord {
            event_id: Uuid::from_u128(id),
            event_type: event_type.into(),
            source: source.into(),
            severity: "medium".into(),
            occurred_at: DateTime::from_timestamp(at, 0).unwrap(),
            correlation_id: None,
            payload,
        }
    }

    #[test]
    fn correlates_event_chain_with_shared_indicator() {
        let left = event(
            1,
            "new_threat_indicator",
            "threatfox",
            100,
            serde_json::json!({"ip":"203.0.113.7"}),
        );
        let right = event(
            2,
            "rpki_invalid",
            "ris",
            200,
            serde_json::json!({"prefix":"203.0.113.7"}),
        );
        let matched = correlate(&left, &right, Duration::seconds(120)).unwrap();
        assert_eq!(matched.relation_type, "event-chain");
        assert!(matched.confidence >= 80);
    }

    #[test]
    fn rejects_events_outside_window() {
        let left = event(
            1,
            "bgp_change",
            "ris",
            0,
            serde_json::json!({"prefix":"198.51.100.0/24"}),
        );
        let right = event(
            2,
            "rpki_invalid",
            "ris",
            1000,
            serde_json::json!({"prefix":"198.51.100.0/24"}),
        );
        assert!(correlate(&left, &right, Duration::seconds(60)).is_none());
    }

    #[test]
    fn correlation_id_links_same_target_without_payload() {
        let mut left = event(1, "provider_error", "urlhaus", 10, serde_json::json!({}));
        let mut right = event(
            2,
            "new_threat_indicator",
            "threatfox",
            20,
            serde_json::json!({}),
        );
        left.correlation_id = Some("198.51.100.7".into());
        right.correlation_id = Some("198.51.100.7".into());
        let matched = correlate(&left, &right, Duration::seconds(60)).unwrap();
        assert_eq!(matched.relation_type, "event-chain");
        assert!(matched.correlation_key.contains("198.51.100.7"));
    }

    #[test]
    fn correlates_events_from_same_source_without_shared_payload() {
        let left = event(1, "provider_error", "threatfox", 10, serde_json::json!({}));
        let right = event(
            2,
            "new_threat_indicator",
            "threatfox",
            20,
            serde_json::json!({}),
        );
        let matched = correlate(&left, &right, Duration::seconds(60)).unwrap();
        assert_eq!(matched.relation_type, "shared-source");
        assert_eq!(matched.confidence, 68);
    }

    #[test]
    fn derives_severity_and_confidence_from_chain() {
        let mut first = event(
            1,
            "new_threat_indicator",
            "threatfox",
            1,
            serde_json::json!({"ip":"203.0.113.8"}),
        );
        first.severity = "medium".into();
        let mut second = event(
            2,
            "bgp_change",
            "ris",
            2,
            serde_json::json!({"ip":"203.0.113.8"}),
        );
        second.severity = "medium".into();
        let matched = correlate(&first, &second, Duration::seconds(60)).unwrap();
        let outcome = derive_outcome(&[first, second], &[matched]);
        assert_eq!(outcome.severity, "high");
        assert!(outcome.confidence > 90);
    }
}
