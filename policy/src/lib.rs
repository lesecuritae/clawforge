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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionPolicy {
    pub name: &'static str,
    pub role: &'static str,
    pub risk_level: &'static str,
    pub requires_approval: bool,
}

pub const ACTION_POLICIES: &[ActionPolicy] = &[
    ActionPolicy {
        name: "docker.restart_container",
        role: "Operator",
        risk_level: "medium",
        requires_approval: true,
    },
    ActionPolicy {
        name: "docker.pull_image",
        role: "Operator",
        risk_level: "high",
        requires_approval: true,
    },
    ActionPolicy {
        name: "backup.start",
        role: "Operator",
        risk_level: "low",
        requires_approval: false,
    },
    ActionPolicy {
        name: "github.retry_workflow",
        role: "Operator",
        risk_level: "medium",
        requires_approval: true,
    },
];

pub fn action_policy(name: &str) -> Option<ActionPolicy> {
    ACTION_POLICIES
        .iter()
        .copied()
        .find(|policy| policy.name == name)
}

pub fn authorize_action(name: &str, role: &str) -> Result<ActionPolicy, &'static str> {
    let policy = action_policy(name).ok_or("action is not allowlisted")?;
    if role != "Administrator" && role != policy.role {
        return Err("role is not permitted for action");
    }
    Ok(policy)
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

    #[test]
    fn controlled_actions_are_allowlisted_and_approval_gated() {
        assert!(
            authorize_action("docker.restart_container", "Operator")
                .unwrap()
                .requires_approval
        );
        assert!(authorize_action("docker.restart_container", "Viewer").is_err());
        assert!(authorize_action("shell.exec", "Administrator").is_err());
        assert!(
            !authorize_action("backup.start", "Administrator")
                .unwrap()
                .requires_approval
        );
    }
}
