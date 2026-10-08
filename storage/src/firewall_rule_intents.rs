//! Durable write-ahead ownership for generic firewall rule applies
//! (nftables / haproxy / haproxy_ratelimit). Mirrors the quarantine generation
//! fence (see [`crate::quarantine_intents`]) for ordinary firewall rules, so a
//! crash between a real adapter mutation and its append-only receipt leaves a
//! durably owned, visible generation that is reconciled, never blindly replayed.
//!
//! Unlike quarantine, preparing a rule intent carries no dual-approval gate:
//! the purpose here is durability of the apply/rollback lifecycle, not a
//! critical-action approval. Ownership binds `(adapter, rule_scope,
//! rule_fingerprint)`, never a bare IP/timestamp.
use crate::{FirewallActionReceiptInput, PostgresStore};
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct FirewallRuleIntent {
    pub id: Uuid,
    pub execution_id: Uuid,
    pub adapter: String,
    pub action_name: String,
    pub rule_scope: String,
    pub rule_fingerprint: String,
    pub target_json: Value,
    pub preflight_state: Value,
    pub rollback_plan: Value,
    pub ttl_seconds: i32,
    pub expires_at: DateTime<Utc>,
    pub status: String,
}

fn decode(row: sqlx::postgres::PgRow) -> FirewallRuleIntent {
    FirewallRuleIntent {
        id: row.get("id"),
        execution_id: row.get("execution_id"),
        adapter: row.get("adapter"),
        action_name: row.get("action_name"),
        rule_scope: row.get("fw_rule_scope"),
        rule_fingerprint: row.get("fw_rule_fingerprint"),
        target_json: row.get("fw_target_json"),
        preflight_state: row.get("fw_preflight_state"),
        rollback_plan: row.get("fw_rollback_plan"),
        ttl_seconds: row.get("fw_ttl_seconds"),
        expires_at: row.get("fw_expires_at"),
        status: row.get("status"),
    }
}

impl PostgresStore {
    /// Commit the immutable rule snapshot before calling the external adapter.
    /// Returns the new generation id, or fails if the rule's `(adapter, scope,
    /// fingerprint)` is already owned by an active generation (prepared /
    /// completed / recovery_required) - the "already-owned rule" guard.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_firewall_rule_intent(
        &self,
        execution_id: Uuid,
        adapter: &str,
        action_name: &str,
        rule_scope: &str,
        rule_fingerprint: &str,
        target_json: &Value,
        preflight_state: &Value,
        rollback_plan: &Value,
        ttl_seconds: u32,
    ) -> Result<Uuid> {
        let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        if !matches!(adapter, "nftables" | "haproxy" | "haproxy_ratelimit")
            || !bounded(rule_fingerprint)
            || !bounded(rule_scope)
            || !target_json.is_object()
            || !preflight_state.is_object()
            || !rollback_plan.is_object()
            || !(60..=86400).contains(&ttl_seconds)
            || [target_json, preflight_state, rollback_plan]
                .iter()
                .any(|v| v.to_string().len() > 65536)
        {
            bail!("invalid bounded firewall rule intent metadata");
        }
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO firewall_action_intents (id,execution_id,adapter,action_name,fw_rule_fingerprint,fw_rule_scope,fw_target_json,fw_preflight_state,fw_rollback_plan,fw_ttl_seconds,fw_expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW()+($10*INTERVAL '1 second'))")
            .bind(id).bind(execution_id).bind(adapter).bind(action_name).bind(rule_fingerprint)
            .bind(rule_scope).bind(target_json).bind(preflight_state).bind(rollback_plan).bind(ttl_seconds as i32)
            .execute(&mut *tx).await
            .map_err(|_| anyhow::anyhow!("firewall rule already owned by an active generation or invalid snapshot"))?;
        Self::insert_audit_outbox(&mut tx,"executor","firewall_rule_intent_prepared",&id.to_string(),&json!({"intent_id":id,"execution_id":execution_id,"adapter":adapter,"scope":rule_scope,"status":"prepared"})).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Receipt and completed ownership transition commit atomically; a failed
    /// receipt leaves the prepared generation owned.
    pub async fn finish_firewall_rule_intent(
        &self,
        id: Uuid,
        input: &FirewallActionReceiptInput<'_>,
    ) -> Result<Uuid> {
        self.acquire_firewall_rule_guard(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("firewall rule generation is resolved or busy"))?
            .finish(input)
            .await
    }

    /// Holds the generation row lock across external IO; a competing recovery
    /// worker skips a locked generation rather than double-applying.
    pub async fn acquire_firewall_rule_guard(&self, id: Uuid) -> Result<Option<FirewallRuleGuard>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT * FROM firewall_action_intents WHERE id=$1 AND fw_rule_fingerprint IS NOT NULL AND status IN ('prepared','completed','recovery_required') FOR UPDATE SKIP LOCKED")
            .bind(id).fetch_optional(&mut *tx).await?;
        Ok(row.map(|row| FirewallRuleGuard {
            tx,
            intent: decode(row),
        }))
    }

    async fn transition_firewall_rule_intent(
        &self,
        id: Uuid,
        status: &str,
        allowed: &[&str],
        error: Option<&str>,
    ) -> Result<()> {
        let guard = self
            .acquire_firewall_rule_guard(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("firewall rule generation is resolved or busy"))?;
        if !allowed.contains(&guard.intent.status.as_str()) {
            bail!("firewall rule intent transition refused");
        }
        guard.transition(status, error).await
    }

    /// Only after authoritative proof that no external mutation occurred.
    pub async fn mark_firewall_rule_not_applied(&self, id: Uuid) -> Result<()> {
        self.transition_firewall_rule_intent(
            id,
            "not_applied",
            &["prepared"],
            Some("verified no external mutation"),
        )
        .await
    }
    /// Ambiguous state retains exclusive ownership and requires reconciliation.
    pub async fn mark_firewall_rule_recovery_required(&self, id: Uuid) -> Result<()> {
        self.transition_firewall_rule_intent(
            id,
            "recovery_required",
            &["prepared", "completed", "recovery_required"],
            Some("external firewall rule state requires verified recovery"),
        )
        .await
    }
    /// Caller MUST first restore (or confirm removed) the rule and verify it.
    pub async fn resolve_firewall_rule_rollback(&self, id: Uuid) -> Result<()> {
        self.acquire_firewall_rule_guard(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("firewall rule generation is resolved or busy"))?
            .resolve_rollback()
            .await
    }
    pub async fn firewall_rule_intent(&self, id: Uuid) -> Result<Option<FirewallRuleIntent>> {
        Ok(sqlx::query(
            "SELECT * FROM firewall_action_intents WHERE id=$1 AND fw_rule_fingerprint IS NOT NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .map(decode))
    }
    /// Prepared/expired/recovery generations are inspected or recovered, NEVER
    /// automatically reapplied.
    pub async fn unresolved_firewall_rule_intents(&self) -> Result<Vec<FirewallRuleIntent>> {
        Ok(sqlx::query("SELECT * FROM firewall_action_intents WHERE fw_rule_fingerprint IS NOT NULL AND (status IN ('prepared','recovery_required') OR (status='completed' AND fw_expires_at<=NOW())) ORDER BY created_at,id LIMIT 100")
            .fetch_all(&self.pool).await?.into_iter().map(decode).collect())
    }
}

/// Generation fence for a firewall rule. Keep alive from before mutation
/// through authoritative readback. A crash releases the row lock while
/// retaining the committed prepared snapshot.
pub struct FirewallRuleGuard {
    tx: Transaction<'static, Postgres>,
    intent: FirewallRuleIntent,
}
impl FirewallRuleGuard {
    pub fn intent(&self) -> &FirewallRuleIntent {
        &self.intent
    }

    pub async fn finish(mut self, input: &FirewallActionReceiptInput<'_>) -> Result<Uuid> {
        let intent = &self.intent;
        if intent.status != "prepared"
            || input.execution_id != Some(intent.execution_id)
            || input.adapter != intent.adapter
            || input.action_name != intent.action_name
            || input.target_fingerprint != Some(intent.rule_fingerprint.as_str())
            || input.target_json.as_ref() != Some(&intent.target_json)
            || input.preflight_state != intent.preflight_state
            || input.rollback_plan != intent.rollback_plan
            || input.ttl_seconds != intent.ttl_seconds as u32
            || input.is_dry_run
            || input.receipt_kind != "apply"
            || input.verification_result != Some("verified")
        {
            bail!("receipt does not match prepared verified firewall rule generation");
        }
        let receipt = Uuid::new_v4();
        sqlx::query("INSERT INTO firewall_action_receipts (id,intent_id,execution_id,adapter,action_name,preflight_state,rendered_commands,observed_state,verification_result,ttl_seconds,rollback_plan,is_dry_run,expires_at,receipt_kind,target_fingerprint,target_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,FALSE,$12,'apply',$13,$14)")
            .bind(receipt).bind(intent.id).bind(intent.execution_id).bind(&intent.adapter).bind(&intent.action_name)
            .bind(&intent.preflight_state).bind(&input.rendered_commands).bind(&input.observed_state)
            .bind(input.verification_result).bind(intent.ttl_seconds).bind(&intent.rollback_plan)
            .bind(intent.expires_at).bind(&intent.rule_fingerprint).bind(&intent.target_json)
            .execute(&mut *self.tx).await?;
        sqlx::query("UPDATE firewall_action_intents SET status='completed',completed_at=NOW(),fw_error_summary=NULL WHERE id=$1")
            .bind(intent.id).execute(&mut *self.tx).await?;
        PostgresStore::insert_audit_outbox(
            &mut self.tx,
            "executor",
            "firewall_rule_intent_completed",
            &intent.id.to_string(),
            &json!({"intent_id":intent.id,"receipt_id":receipt,"status":"completed"}),
        )
        .await?;
        self.tx.commit().await?;
        Ok(receipt)
    }

    async fn transition(mut self, status: &str, error: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE firewall_action_intents SET status=$2,fw_error_summary=$3,completed_at=NOW() WHERE id=$1")
            .bind(self.intent.id).bind(status).bind(error).execute(&mut *self.tx).await?;
        PostgresStore::insert_audit_outbox(
            &mut self.tx,
            "executor",
            &format!("firewall_rule_intent_{status}"),
            &self.intent.id.to_string(),
            &json!({"intent_id":self.intent.id,"status":status}),
        )
        .await?;
        self.tx.commit().await?;
        Ok(())
    }
    /// Call only after the rule's intended end state (restored or removed) is
    /// verified by authoritative readback.
    pub async fn resolve_rollback(mut self) -> Result<()> {
        let intent = &self.intent;
        sqlx::query("INSERT INTO firewall_action_receipts (id,intent_id,execution_id,adapter,action_name,preflight_state,rendered_commands,observed_state,verification_result,ttl_seconds,rollback_plan,is_dry_run,expires_at,receipt_kind,target_fingerprint,target_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'verified',$9,$10,FALSE,$11,'rollback',$12,$13)")
            .bind(Uuid::new_v4()).bind(intent.id).bind(intent.execution_id).bind(&intent.adapter).bind(&intent.action_name)
            .bind(&intent.preflight_state).bind(&intent.rollback_plan).bind(json!({"restored_or_removed":true})).bind(intent.ttl_seconds).bind(&intent.rollback_plan)
            .bind(intent.expires_at).bind(&intent.rule_fingerprint).bind(&intent.target_json).execute(&mut *self.tx).await?;
        self.transition("rolled_back", None).await
    }
    pub async fn recovery_required(self) -> Result<()> {
        self.transition(
            "recovery_required",
            Some("external firewall rule state requires verified recovery"),
        )
        .await
    }
    /// Call only after authoritative proof that no mutation occurred.
    pub async fn not_applied(self) -> Result<()> {
        if self.intent.status != "prepared" {
            bail!("ambiguous mutation cannot be declared unapplied");
        }
        self.transition("not_applied", Some("verified no external mutation"))
            .await
    }
}
