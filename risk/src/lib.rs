//! Bounded risk and trust calculations.

use std::collections::HashSet;
use std::net::IpAddr;

use clawforge_intelligence::{
    AsnRecord, BgpEvent, BgpStatus, Indicator, NetworkObservation, RpkiRecord, RpkiStatus,
    TrustedNetwork,
};
use ipnet::IpNet;
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct RiskSignals {
    pub ip_reputation: u8,
    pub asn_reputation: u8,
    pub behavior: u8,
    pub history: u8,
    pub hosting_context: bool,
    pub bgp_hijack: bool,
    pub sources: HashSet<String>,
    pub reasons: Vec<String>,
}

impl RiskSignals {
    pub fn from_asn(record: &AsnRecord) -> Self {
        let network_type = record.network_type.to_ascii_lowercase();
        Self {
            asn_reputation: record.reputation,
            hosting_context: network_type.contains("hosting")
                || network_type.contains("cloud")
                || network_type.contains("bulletproof"),
            reasons: vec![format!("ASN context from {}", record.provider)],
            ..Self::default()
        }
    }

    pub fn from_bgp(event: &BgpEvent) -> Self {
        Self {
            bgp_hijack: matches!(event.status, BgpStatus::Anomalous),
            reasons: event
                .change
                .as_ref()
                .map(|change| vec![change.clone()])
                .unwrap_or_default(),
            ..Self::default()
        }
    }

    pub fn from_rpki(record: &RpkiRecord) -> Self {
        Self {
            reasons: vec![format!(
                "RPKI {} from {}",
                format!("{:?}", record.status).to_ascii_uppercase(),
                record.source
            )],
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskAssessment {
    pub risk_score: u8,
    pub trust_score: u8,
    pub negative_score: u8,
    pub trust_adjustment: i16,
    pub reasons: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct TrustEngine {
    registrations: Vec<TrustedNetwork>,
}

impl TrustEngine {
    pub fn register(&mut self, network: TrustedNetwork) {
        self.registrations.push(network);
    }

    pub fn verified_match(
        &self,
        observation: &NetworkObservation,
    ) -> Option<(&TrustedNetwork, bool)> {
        self.registrations
            .iter()
            .filter(|network| network.is_verified())
            .find_map(|network| {
                let identifier_match = observation.identifier.as_ref().is_some_and(|value| {
                    !network.identifier.is_empty() && value == &network.identifier
                });
                let node_match = observation
                    .node_identity
                    .as_ref()
                    .is_some_and(|value| network.node_identities.iter().any(|node| node == value));
                let network_match = observation.ip.as_ref().is_some_and(|ip| {
                    ip.parse::<IpAddr>().ok().is_some_and(|address| {
                        network.networks.iter().any(|cidr| {
                            cidr.parse::<IpNet>()
                                .ok()
                                .is_some_and(|range| range.contains(&address))
                        })
                    })
                });
                if identifier_match || node_match || network_match {
                    Some((network, node_match))
                } else {
                    None
                }
            })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RiskEngine {
    pub trust: TrustEngine,
}

impl RiskEngine {
    pub fn evaluate(
        &self,
        observation: &NetworkObservation,
        indicators: &[Indicator],
        signals: &RiskSignals,
    ) -> RiskAssessment {
        let mut reasons = signals.reasons.clone();
        let mut threat = indicators
            .iter()
            .map(|indicator| u16::from(indicator.confidence).min(50))
            .max()
            .unwrap_or(0);
        let sources: HashSet<&str> = indicators.iter().map(|item| item.source.as_str()).collect();
        if sources.len() > 1 {
            threat = (threat + ((sources.len() as u16 - 1) * 10).min(20)).min(50);
            reasons.push("corroborated independent intelligence".to_string());
        }
        let negative = (threat
            + u16::from(signals.ip_reputation.min(30))
            + u16::from(signals.asn_reputation.min(30))
            + u16::from(signals.behavior.min(50))
            + u16::from(signals.history.min(20))
            + if signals.hosting_context { 5 } else { 0 }
            + if signals.bgp_hijack { 30 } else { 0 }
            + match observation.bgp_status {
                BgpStatus::Changed => 10,
                BgpStatus::Anomalous => 20,
                _ => 0,
            }
            + if matches!(observation.rpki_status, RpkiStatus::Invalid) {
                20
            } else {
                0
            })
        .min(100);
        if matches!(observation.rpki_status, RpkiStatus::Invalid) {
            reasons.push("RPKI invalid".to_string());
        }
        if signals.hosting_context {
            reasons.push("known hosting or cloud ASN context".to_string());
        }
        if signals.bgp_hijack {
            reasons.push("BGP hijack or route anomaly signal".to_string());
        }
        let mut trust_adjustment: i16 = 0;
        if let Some((_network, node_match)) = self.trust.verified_match(observation) {
            trust_adjustment -= 40;
            reasons.push("verified trusted infrastructure".to_string());
            if node_match {
                trust_adjustment -= 10;
                reasons.push("known node identity".to_string());
            }
        }
        if matches!(observation.rpki_status, RpkiStatus::Valid) {
            trust_adjustment -= 20;
            reasons.push("RPKI valid".to_string());
        }
        if matches!(observation.bgp_status, BgpStatus::Stable) {
            trust_adjustment -= 10;
            reasons.push("stable BGP route".to_string());
        }
        trust_adjustment -= i16::from(observation.history_score.min(20));
        let score = (i16::try_from(negative).unwrap_or(100) + trust_adjustment).clamp(0, 100) as u8;
        RiskAssessment {
            risk_score: score,
            trust_score: (-trust_adjustment).clamp(0, 100) as u8,
            negative_score: negative as u8,
            trust_adjustment,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_are_bounded_and_rpki_invalid_adds_risk() {
        let engine = RiskEngine::default();
        let observation = NetworkObservation {
            rpki_status: RpkiStatus::Invalid,
            ..NetworkObservation::default()
        };
        let assessment = engine.evaluate(&observation, &[], &RiskSignals::default());
        assert_eq!(assessment.risk_score, 20);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason == "RPKI invalid"));
    }

    #[test]
    fn network_signals_are_scored_and_explained() {
        let engine = RiskEngine::default();
        let event = BgpEvent {
            prefix: "198.51.100.0/24".into(),
            origin_asn: "AS64500".into(),
            previous_asn: Some("AS64501".into()),
            new_asn: Some("AS64500".into()),
            timestamp: chrono::Utc::now(),
            source: "ripe_ris".into(),
            status: BgpStatus::Anomalous,
            rpki_status: RpkiStatus::Invalid,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            change: Some("origin changed".into()),
        };
        let assessment = engine.evaluate(
            &NetworkObservation {
                bgp_status: event.status.clone(),
                rpki_status: event.rpki_status.clone(),
                ..NetworkObservation::default()
            },
            &[],
            &RiskSignals {
                bgp_hijack: true,
                hosting_context: true,
                ..RiskSignals::from_bgp(&event)
            },
        );
        assert!(assessment.risk_score >= 70);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("BGP hijack")));
    }
}
