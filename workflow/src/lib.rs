//! Pure workflow governance rules.
//!
//! This crate validates declarative workflow step types and state transitions.
//! It deliberately has no process execution, network access, or side effects.

use serde::{Deserialize, Serialize};

pub const STEP_TYPES: &[&str] = &[
    "notification",
    "analysis",
    "approval",
    "external_check",
    "manual",
];

pub const RUN_STATUSES: &[&str] = &[
    "pending",
    "running",
    "waiting_approval",
    "completed",
    "failed",
    "cancelled",
];

pub const APPROVAL_STATUSES: &[&str] = &["pending", "approved", "rejected", "expired"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowStepDefinition {
    pub name: String,
    pub step_order: i32,
    pub step_type: String,
    pub required_approval: bool,
}

pub fn valid_step_type(value: &str) -> bool {
    STEP_TYPES.contains(&value)
}

pub fn valid_run_status(value: &str) -> bool {
    RUN_STATUSES.contains(&value)
}

pub fn valid_approval_status(value: &str) -> bool {
    APPROVAL_STATUSES.contains(&value)
}

/// Return whether a workflow run can move between two persisted states.
/// Approval never starts execution: an approved run returns to `pending` so a
/// future, explicitly controlled executor could prepare the next step.
pub fn can_transition_run(from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (
            "pending",
            "running" | "waiting_approval" | "cancelled" | "failed"
        ) | (
            "running",
            "waiting_approval" | "completed" | "failed" | "cancelled"
        ) | ("waiting_approval", "pending" | "failed" | "cancelled")
    )
}

pub fn requires_approval(steps: &[WorkflowStepDefinition]) -> bool {
    steps.iter().any(|step| step.required_approval)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_types_are_allowlisted() {
        assert!(valid_step_type("approval"));
        assert!(valid_step_type("external_check"));
        assert!(!valid_step_type("shell"));
        assert!(!valid_step_type("exec"));
    }

    #[test]
    fn state_transitions_require_controlled_progression() {
        assert!(can_transition_run("pending", "waiting_approval"));
        assert!(can_transition_run("waiting_approval", "pending"));
        assert!(!can_transition_run("completed", "running"));
        assert!(!can_transition_run("cancelled", "pending"));
    }

    #[test]
    fn approval_is_required_when_any_step_requires_it() {
        let steps = vec![
            WorkflowStepDefinition {
                name: "inspect".into(),
                step_order: 1,
                step_type: "analysis".into(),
                required_approval: false,
            },
            WorkflowStepDefinition {
                name: "approve".into(),
                step_order: 2,
                step_type: "approval".into(),
                required_approval: true,
            },
        ];
        assert!(requires_approval(&steps));
    }
}
