//! Policy -> execution bridge (roadmap 7C), storage side.
//!
//! The policy-engine role has no INSERT on `execution_requests`. It may call
//! two SECURITY DEFINER functions (migration 0060): `plan` derives the exact
//! approval context from database facts, and `enqueue` re-derives it, refuses
//! any difference and applies budget, duplicate and health checks. The approval
//! hash is computed here, over the context exactly as PostgreSQL returns it, so
//! the hash matches the recomputation done when an approver signs.
use crate::{execution_context_hash, PostgresStore};
use anyhow::{bail, Result};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeMode {
    Simulate,
    Propose,
    Automatic,
}

impl BridgeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Simulate => "simulate",
            Self::Propose => "propose",
            Self::Automatic => "automatic",
        }
    }
}

/// Everything the database needs to decide; none of it is a default chosen by
/// this crate - the policy engine passes explicitly configured values.
#[derive(Debug, Clone)]
pub struct PolicyBridgeParams {
    pub mode: BridgeMode,
    pub action_name: String,
    pub ttl_seconds: i32,
    pub requester_id: Option<Uuid>,
    pub rule_id: Option<String>,
    pub max_evidence_age_seconds: i32,
    pub require_threat_intel: bool,
    /// Minimum confidence of the reputation listing that counts (1-100, required).
    pub min_intel_confidence: i32,
    pub max_per_window: i32,
    pub window_seconds: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeOutcome {
    Enqueued(Uuid),
    /// The same decision and mode already produced this request.
    Duplicate(Uuid),
    /// A named safety condition was not met; nothing was created.
    Rejected(String),
}

impl PostgresStore {
    pub async fn enqueue_policy_bridge_request(
        &self,
        decision_id: Uuid,
        params: &PolicyBridgeParams,
    ) -> Result<BridgeOutcome> {
        let plan = sqlx::query(
            "SELECT reason, context, existing_request_id FROM clawforge_policy_bridge_plan($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(decision_id)
        .bind(params.mode.as_str())
        .bind(&params.action_name)
        .bind(params.ttl_seconds)
        .bind(params.requester_id)
        .bind(params.rule_id.as_deref())
        .bind(params.max_evidence_age_seconds)
        .bind(params.require_threat_intel)
        .bind(params.min_intel_confidence)
        .fetch_one(self.pool())
        .await?;
        if let Some(reason) = plan.get::<Option<String>, _>("reason") {
            return Ok(BridgeOutcome::Rejected(reason));
        }
        // Steady state (the engine re-evaluates every poll): a decision that already
        // produced its request costs this one cheap call.
        if let Some(existing) = plan.get::<Option<Uuid>, _>("existing_request_id") {
            return Ok(BridgeOutcome::Duplicate(existing));
        }
        let Some(context) = plan.get::<Option<serde_json::Value>, _>("context") else {
            bail!("policy bridge plan returned neither a reason nor a context");
        };
        let hash = execution_context_hash(&context)?;
        let row = sqlx::query(
            "SELECT outcome, request_id FROM clawforge_enqueue_policy_bridge_request(\
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(decision_id)
        .bind(params.mode.as_str())
        .bind(&params.action_name)
        .bind(params.ttl_seconds)
        .bind(params.requester_id)
        .bind(params.rule_id.as_deref())
        .bind(params.max_evidence_age_seconds)
        .bind(params.require_threat_intel)
        .bind(params.min_intel_confidence)
        .bind(params.max_per_window)
        .bind(params.window_seconds)
        .bind(&context)
        .bind(&hash)
        .fetch_one(self.pool())
        .await?;
        let outcome: String = row.get("outcome");
        let request_id: Option<Uuid> = row.get("request_id");
        Ok(match (outcome.as_str(), request_id) {
            ("enqueued", Some(id)) => BridgeOutcome::Enqueued(id),
            ("duplicate", Some(id)) => BridgeOutcome::Duplicate(id),
            (other, _) => BridgeOutcome::Rejected(
                other.strip_prefix("rejected:").unwrap_or(other).to_string(),
            ),
        })
    }
}
