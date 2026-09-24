//! Storage for `clawforge-policy-engine` (roadmap phase 5, "Policy
//! Engine"), Shadow Mode only. A policy (`security_policies`, versioned,
//! status-gated) is evaluated against `clawforge-security-engine`'s
//! persisted assessments; the resulting decision is recorded in
//! `security_policy_decisions`, never executed - there is no action layer
//! yet (roadmap phase 6) for a shadow decision to be wired to.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::PostgresStore;

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityPolicy {
    pub id: Uuid,
    pub name: String,
    pub version: i32,
    pub status: String,
    pub class: String,
    pub rule_id: String,
    pub min_severity: String,
}

pub struct SecurityPolicyDecisionUpsert<'a> {
    pub policy_id: Uuid,
    pub policy_version: i32,
    pub assessment_id: Uuid,
    pub incident_id: Option<Uuid>,
    pub decision: &'a str,
    pub risk_score: i16,
    pub evidence_sources: i16,
    pub corroborated: bool,
    pub rationale: &'a str,
    pub evidence_snapshot: serde_json::Value,
    pub evidence_hash: &'a str,
}

impl PostgresStore {
    /// Every `active` policy for one rule - a `draft`/`retired` policy is
    /// never evaluated, and `valid_from`/`valid_until` bound when an active
    /// one actually applies (a policy scheduled for the future, or one
    /// whose validity window has already ended, decides nothing even while
    /// its status row still says `active`).
    pub async fn list_active_security_policies_for_rule(
        &self,
        rule_id: &str,
        at: DateTime<Utc>,
    ) -> Result<Vec<SecurityPolicy>> {
        let rows = sqlx::query(
            "SELECT id,name,version,status,class,rule_id,min_severity FROM security_policies \
             WHERE rule_id=$1 AND status='active' AND valid_from <= $2 \
             AND (valid_until IS NULL OR valid_until > $2) \
             ORDER BY version DESC",
        )
        .bind(rule_id)
        .bind(at)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| SecurityPolicy {
                id: row.get("id"),
                name: row.get("name"),
                version: row.get("version"),
                status: row.get("status"),
                class: row.get("class"),
                rule_id: row.get("rule_id"),
                min_severity: row.get("min_severity"),
            })
            .collect())
    }

    /// Upsert one shadow decision. Idempotent by `dedupe_key`
    /// (`policy_id:policy_version:assessment_id`, built by the caller): a
    /// replay, or the same assessment recomputed as its own bucket keeps
    /// filling, updates this same row in place - this is exactly what makes
    /// "Policies können gegen historische Incidents replayed werden"
    /// (the phase 5 exit gate) safe to actually do, not just a claim.
    /// `is_shadow` is always `TRUE` today - there is no action layer yet to
    /// ever set it otherwise.
    pub async fn persist_security_policy_decision(
        &self,
        dedupe_key: &str,
        request: SecurityPolicyDecisionUpsert<'_>,
    ) -> Result<Uuid> {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO security_policy_decisions \
             (id,policy_id,policy_version,assessment_id,incident_id,decision,risk_score,\
              evidence_sources,corroborated,rationale,evidence_snapshot,evidence_hash,\
              is_shadow,dedupe_key) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,TRUE,$13) \
             ON CONFLICT (dedupe_key) DO UPDATE SET \
               incident_id=EXCLUDED.incident_id, decision=EXCLUDED.decision, \
               risk_score=EXCLUDED.risk_score, evidence_sources=EXCLUDED.evidence_sources, \
               corroborated=EXCLUDED.corroborated, rationale=EXCLUDED.rationale, \
               evidence_snapshot=EXCLUDED.evidence_snapshot, evidence_hash=EXCLUDED.evidence_hash, \
               updated_at=NOW() \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(request.policy_id)
        .bind(request.policy_version)
        .bind(request.assessment_id)
        .bind(request.incident_id)
        .bind(request.decision)
        .bind(request.risk_score)
        .bind(request.evidence_sources)
        .bind(request.corroborated)
        .bind(request.rationale)
        .bind(&request.evidence_snapshot)
        .bind(request.evidence_hash)
        .bind(dedupe_key)
        .fetch_one(self.pool())
        .await?;
        Ok(id)
    }
}
