//! Policy decisions are downstream of risk and require corroboration to block.

use clawforge_risk::RiskAssessment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Observe,
    Challenge,
    RateLimit,
    Block,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub risk_score: u8,
    pub corroborated: bool,
}

pub fn decide(assessment: &RiskAssessment, evidence_sources: usize) -> PolicyDecision {
    let decision = match assessment.risk_score {
        0..=39 => Decision::Observe,
        40..=69 => Decision::Challenge,
        70..=89 => Decision::RateLimit,
        _ if evidence_sources >= 2 => Decision::Block,
        _ => Decision::RateLimit,
    };
    PolicyDecision {
        decision,
        risk_score: assessment.risk_score,
        corroborated: evidence_sources >= 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assessment(score: u8) -> RiskAssessment {
        RiskAssessment {
            risk_score: score,
            trust_score: 0,
            negative_score: score,
            trust_adjustment: 0,
            reasons: Vec::new(),
        }
    }

    #[test]
    fn one_source_cannot_block() {
        assert_eq!(decide(&assessment(95), 1).decision, Decision::RateLimit);
        assert_eq!(decide(&assessment(95), 2).decision, Decision::Block);
    }
}
