//! Durable ownership of external quarantine mutations. No prepared intent is replayed.
use crate::{execution_context_hash, FirewallActionReceiptInput, PostgresStore};
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct QuarantineIntent {
    pub id: Uuid,
    pub execution_id: Uuid,
    pub adapter: String,
    pub action_name: String,
    pub target_fingerprint: String,
    pub target_json: Value,
    pub preflight_state: Value,
    pub rollback_plan: Value,
    pub ttl_seconds: i32,
    pub expires_at: DateTime<Utc>,
    pub status: String,
}

fn decode(row: sqlx::postgres::PgRow) -> QuarantineIntent {
    QuarantineIntent {
        id: row.get("id"),
        execution_id: row.get("execution_id"),
        adapter: row.get("adapter"),
        action_name: row.get("action_name"),
        target_fingerprint: row.get("target_fingerprint"),
        target_json: row.get("target_json"),
        preflight_state: row.get("preflight_state"),
        rollback_plan: row.get("rollback_plan"),
        ttl_seconds: row.get("ttl_seconds"),
        expires_at: row.get("expires_at"),
        status: row.get("status"),
    }
}

impl PostgresStore {
    /// Commit the immutable rollback snapshot before calling the external adapter.
    /// Active ownership survives both expiry and executor lease loss.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_quarantine_intent(
        &self,
        execution_id: Uuid,
        adapter: &str,
        target_fingerprint: &str,
        target_json: &Value,
        preflight_state: &Value,
        rollback_plan: &Value,
        ttl_seconds: u32,
    ) -> Result<Uuid> {
        if !matches!(adapter, "docker" | "proxmox" | "tailscale")
            || target_fingerprint.is_empty()
            || target_fingerprint.len() > 256
            || target_fingerprint.chars().any(char::is_control)
            || !target_json.is_object()
            || !preflight_state.is_object()
            || !rollback_plan.is_object()
            || !(60..=86400).contains(&ttl_seconds)
            || [target_json, preflight_state, rollback_plan]
                .iter()
                .any(|v| v.to_string().len() > 65536)
        {
            bail!("invalid bounded quarantine intent metadata");
        }
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT clawforge_lock_quarantine_approval($1)")
            .bind(execution_id)
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query("SELECT a.id AS action_id,a.name,e.required_approvals,e.approval_context,e.approval_context_hash FROM execution_requests e JOIN actions a ON a.id=e.action_id JOIN approval_policies p ON p.risk_level=a.risk_level WHERE e.id=$1 AND e.status IN ('starting','running') AND a.enabled AND a.requires_approval AND a.risk_level='critical' AND p.required_approvals>=2 AND e.required_approvals>=2 AND e.requested_by_id IS NOT NULL AND e.approval_expires_at>clock_timestamp() AND (SELECT COUNT(DISTINCT ea.approver_id) FROM execution_approvals ea WHERE ea.execution_id=e.id AND ea.context_hash=e.approval_context_hash AND ea.approver_id<>e.requested_by_id)>=GREATEST(e.required_approvals,p.required_approvals)")
            .bind(execution_id).fetch_optional(&mut *tx).await?
            .ok_or_else(|| anyhow::anyhow!("quarantine intent requires current critical dual approval and claimed execution"))?;
        let action: String = row.get("name");
        let expected_action = match adapter {
            "docker" => "docker.quarantine_container",
            "proxmox" => "proxmox.quarantine_vm",
            "tailscale" => "tailscale.quarantine_device",
            _ => unreachable!(),
        };
        let context: Value = row.get("approval_context");
        let stored_hash: Option<String> = row.get("approval_context_hash");
        let approved_ttl = match target_json.get("ttl_seconds") {
            None => 3600,
            Some(value) => value
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("quarantine ttl_seconds must be an integer"))?,
        };
        if action != expected_action
            || context["version"] != 1
            || context["action_id"] != json!(row.get::<Uuid, _>("action_id"))
            || context["action_name"] != action
            || context["required_approvals"] != json!(row.get::<i32, _>("required_approvals"))
            || target_json["kind"] != adapter
            || context["target"] != *target_json
            || stored_hash.as_deref() != Some(execution_context_hash(&context)?.as_str())
            || context["risk_level"] != "critical"
            || context["requires_approval"] != true
            || approved_ttl != u64::from(ttl_seconds)
        {
            bail!("quarantine target or action differs from approved context");
        }
        let canonical = match adapter {
            "docker" => {
                let id = target_json["container_id"].as_str().unwrap_or_default();
                if id.len() != 64
                    || !id
                        .bytes()
                        .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
                {
                    bail!("invalid canonical Docker identity");
                }
                id.to_owned()
            }
            "proxmox" => {
                let node = target_json["node"].as_str().unwrap_or_default();
                let vmid = target_json["vmid"].as_u64().unwrap_or_default();
                if node.is_empty()
                    || node.len() > 63
                    || !node.bytes().all(|v| v.is_ascii_alphanumeric() || v == b'-')
                    || !node.as_bytes()[0].is_ascii_alphanumeric()
                    || !node.as_bytes()[node.len() - 1].is_ascii_alphanumeric()
                    || vmid == 0
                    || vmid > u64::from(u32::MAX)
                {
                    bail!("invalid canonical Proxmox identity");
                }
                format!("{node}/{vmid}")
            }
            "tailscale" => {
                let id = target_json["device_id"].as_str().unwrap_or_default();
                if id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_'))
                {
                    bail!("invalid canonical Tailscale identity");
                }
                id.to_owned()
            }
            _ => unreachable!(),
        };
        if target_fingerprint != canonical {
            bail!("quarantine fingerprint differs from canonical approved target");
        }
        // Locks can wait across approval expiry; recheck against wall time after all locks.
        let current: bool = sqlx::query_scalar(
            "SELECT approval_expires_at > clock_timestamp() FROM execution_requests WHERE id=$1",
        )
        .bind(execution_id)
        .fetch_one(&mut *tx)
        .await?;
        if !current {
            bail!("quarantine approval expired before intent preparation");
        }
        sqlx::query("INSERT INTO firewall_action_intents (id,execution_id,adapter,action_name,target_fingerprint,target_json,preflight_state,rollback_plan,ttl_seconds,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW()+($9*INTERVAL '1 second'))")
            .bind(id).bind(execution_id).bind(adapter).bind(action).bind(target_fingerprint)
            .bind(target_json).bind(preflight_state).bind(rollback_plan).bind(ttl_seconds as i32)
            .execute(&mut *tx).await?;
        Self::insert_audit_outbox(&mut tx,"executor","quarantine_intent_prepared",&id.to_string(),&json!({"intent_id":id,"execution_id":execution_id,"adapter":adapter,"status":"prepared"})).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Receipt and completed ownership transition commit atomically; a failed receipt leaves prepared state.
    pub async fn finish_quarantine_intent(
        &self,
        id: Uuid,
        input: &FirewallActionReceiptInput<'_>,
    ) -> Result<Uuid> {
        self.acquire_quarantine_guard(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("quarantine generation is resolved or busy"))?
            .finish(input)
            .await
    }

    /// Holds the generation row lock across external IO; competing recovery skips it.
    pub async fn acquire_quarantine_guard(&self, id: Uuid) -> Result<Option<QuarantineGuard>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT * FROM firewall_action_intents WHERE id=$1 AND target_fingerprint IS NOT NULL AND status IN ('prepared','completed','recovery_required') FOR UPDATE SKIP LOCKED")
            .bind(id).fetch_optional(&mut *tx).await?;
        Ok(row.map(|row| QuarantineGuard {
            tx,
            intent: decode(row),
        }))
    }

    async fn transition_quarantine_intent(
        &self,
        id: Uuid,
        status: &str,
        allowed: &[&str],
        error: Option<&str>,
    ) -> Result<()> {
        let guard = self
            .acquire_quarantine_guard(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("quarantine generation is resolved or busy"))?;
        if !allowed.contains(&guard.intent.status.as_str()) {
            guard.abort().await;
            bail!("quarantine intent transition refused");
        }
        guard.transition(status, error).await
    }

    /// Only after authoritative proof that no external mutation occurred.
    pub async fn mark_quarantine_not_applied(&self, id: Uuid) -> Result<()> {
        self.transition_quarantine_intent(
            id,
            "not_applied",
            &["prepared"],
            Some("verified no external mutation"),
        )
        .await
    }
    /// Ambiguous state retains exclusive ownership and requires reconciliation, never replay.
    pub async fn mark_quarantine_recovery_required(&self, id: Uuid) -> Result<()> {
        self.transition_quarantine_intent(
            id,
            "recovery_required",
            &["prepared", "completed", "recovery_required"],
            Some("external quarantine state requires verified recovery"),
        )
        .await
    }
    /// Caller MUST first restore the stored snapshot and verify authoritative readback.
    pub async fn resolve_quarantine_rollback(&self, id: Uuid) -> Result<()> {
        self.acquire_quarantine_guard(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("quarantine generation is resolved or busy"))?
            .resolve_rollback()
            .await
    }
    pub async fn quarantine_intent(&self, id: Uuid) -> Result<Option<QuarantineIntent>> {
        Ok(sqlx::query(
            "SELECT * FROM firewall_action_intents WHERE id=$1 AND target_fingerprint IS NOT NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .map(decode))
    }
    /// Prepared generations are inspected/recovered, NEVER automatically reapplied.
    pub async fn unresolved_quarantine_intents(&self) -> Result<Vec<QuarantineIntent>> {
        Ok(sqlx::query("SELECT * FROM firewall_action_intents WHERE target_fingerprint IS NOT NULL AND (status IN ('prepared','recovery_required') OR (status='completed' AND expires_at<=NOW())) ORDER BY created_at,id LIMIT 100")
            .fetch_all(&self.pool).await?.into_iter().map(decode).collect())
    }
    /// Automatic sweep excludes manual cases so they cannot starve due rollback.
    pub async fn recoverable_quarantine_intents(&self) -> Result<Vec<QuarantineIntent>> {
        Ok(sqlx::query("SELECT * FROM firewall_action_intents WHERE target_fingerprint IS NOT NULL AND (status='prepared' OR (status='completed' AND expires_at<=NOW())) ORDER BY created_at,id LIMIT 100")
            .fetch_all(&self.pool).await?.into_iter().map(decode).collect())
    }
}

/// Generation fence. Keep this guard alive from before mutation through authoritative readback.
/// A crash releases the row lock while retaining the committed prepared snapshot.
pub struct QuarantineGuard {
    tx: Transaction<'static, Postgres>,
    intent: QuarantineIntent,
}
impl QuarantineGuard {
    pub fn intent(&self) -> &QuarantineIntent {
        &self.intent
    }

    /// Revalidate after acquiring generation ownership and hold approval policy
    /// locks through the external mutation. Expiry is evaluated using DB wall time.
    pub async fn validate_approval(&mut self) -> Result<()> {
        sqlx::query("SELECT clawforge_lock_quarantine_approval($1)")
            .bind(self.intent.execution_id)
            .execute(&mut *self.tx)
            .await?;
        let current: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM execution_requests e JOIN actions a ON a.id=e.action_id JOIN approval_policies p ON p.risk_level=a.risk_level WHERE e.id=$1 AND e.status IN ('starting','running') AND a.name=$2 AND a.enabled AND a.requires_approval AND a.risk_level='critical' AND p.required_approvals>=2 AND e.required_approvals>=2 AND e.requested_by_id IS NOT NULL AND e.approval_expires_at>clock_timestamp() AND e.approval_context->'target'=$3 AND (SELECT COUNT(DISTINCT ea.approver_id) FROM execution_approvals ea WHERE ea.execution_id=e.id AND ea.context_hash=e.approval_context_hash AND ea.approver_id<>e.requested_by_id)>=GREATEST(e.required_approvals,p.required_approvals))")
            .bind(self.intent.execution_id).bind(&self.intent.action_name).bind(&self.intent.target_json)
            .fetch_one(&mut *self.tx).await?;
        if self.intent.status != "prepared" || !current {
            bail!("quarantine approval no longer valid before mutation");
        }
        Ok(())
    }

    /// Release the held generation row lock synchronously. The guard's
    /// transaction holds a FOR UPDATE lock; letting it drop rolls back only on a
    /// deferred, best-effort basis, which can briefly leave the row locked and
    /// make an immediately following `acquire_quarantine_guard`
    /// (FOR UPDATE SKIP LOCKED) spuriously skip it as "busy". Every path that
    /// abandons a guard without committing must call this first.
    async fn abort(self) {
        let _ = self.tx.rollback().await;
    }

    pub async fn finish(mut self, input: &FirewallActionReceiptInput<'_>) -> Result<Uuid> {
        let mismatched = {
            let intent = &self.intent;
            intent.status != "prepared"
                || input.execution_id != Some(intent.execution_id)
                || input.adapter != intent.adapter
                || input.action_name != intent.action_name
                || input.target_fingerprint != Some(intent.target_fingerprint.as_str())
                || input.target_json.as_ref() != Some(&intent.target_json)
                || input.preflight_state != intent.preflight_state
                || input.rollback_plan != intent.rollback_plan
                || input.ttl_seconds != intent.ttl_seconds as u32
                || input.is_dry_run
                || input.receipt_kind != "apply"
                || input.verification_result != Some("verified")
        };
        if mismatched {
            self.abort().await;
            bail!("receipt does not match prepared verified quarantine generation");
        }
        let intent = &self.intent;
        let receipt = Uuid::new_v4();
        sqlx::query("INSERT INTO firewall_action_receipts (id,intent_id,execution_id,adapter,action_name,preflight_state,rendered_commands,observed_state,verification_result,ttl_seconds,rollback_plan,is_dry_run,expires_at,receipt_kind,target_fingerprint,target_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,FALSE,$12,'apply',$13,$14)")
            .bind(receipt).bind(intent.id).bind(intent.execution_id).bind(input.adapter).bind(input.action_name)
            .bind(&input.preflight_state).bind(&input.rendered_commands).bind(&input.observed_state)
            .bind(input.verification_result).bind(intent.ttl_seconds).bind(&input.rollback_plan)
            .bind(intent.expires_at).bind(input.target_fingerprint).bind(&input.target_json)
            .execute(&mut *self.tx).await?;
        sqlx::query("UPDATE firewall_action_intents SET status='completed',completed_at=NOW(),error_summary=NULL WHERE id=$1")
            .bind(intent.id).execute(&mut *self.tx).await?;
        PostgresStore::insert_audit_outbox(
            &mut self.tx,
            "executor",
            "quarantine_intent_completed",
            &intent.id.to_string(),
            &json!({"intent_id":intent.id,"receipt_id":receipt,"status":"completed"}),
        )
        .await?;
        self.tx.commit().await?;
        Ok(receipt)
    }

    async fn transition(mut self, status: &str, error: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE firewall_action_intents SET status=$2,error_summary=$3,completed_at=NOW() WHERE id=$1")
            .bind(self.intent.id).bind(status).bind(error).execute(&mut *self.tx).await?;
        PostgresStore::insert_audit_outbox(
            &mut self.tx,
            "executor",
            &format!("quarantine_intent_{status}"),
            &self.intent.id.to_string(),
            &json!({"intent_id":self.intent.id,"status":status}),
        )
        .await?;
        self.tx.commit().await?;
        Ok(())
    }
    /// Call only after the stored snapshot is restored and authoritative readback verifies it.
    pub async fn resolve_rollback(mut self) -> Result<()> {
        let intent = &self.intent;
        sqlx::query("INSERT INTO firewall_action_receipts (id,intent_id,execution_id,adapter,action_name,preflight_state,rendered_commands,observed_state,verification_result,ttl_seconds,rollback_plan,is_dry_run,expires_at,receipt_kind,target_fingerprint,target_json) VALUES ($1,$2,$3,$4,$5,$6,'[]'::jsonb,$7,'verified',$8,$9,FALSE,$10,'rollback',$11,$12)")
            .bind(Uuid::new_v4()).bind(intent.id).bind(intent.execution_id).bind(&intent.adapter).bind(&intent.action_name)
            .bind(&intent.preflight_state).bind(json!({"restored_snapshot":true})).bind(intent.ttl_seconds).bind(&intent.rollback_plan)
            .bind(intent.expires_at).bind(&intent.target_fingerprint).bind(&intent.target_json).execute(&mut *self.tx).await?;
        self.transition("rolled_back", None).await
    }
    pub async fn recovery_required(self) -> Result<()> {
        self.transition(
            "recovery_required",
            Some("external quarantine state requires verified recovery"),
        )
        .await
    }
    /// Call only after authoritative proof that no mutation occurred.
    pub async fn not_applied(self) -> Result<()> {
        if self.intent.status != "prepared" {
            self.abort().await;
            bail!("ambiguous mutation cannot be declared unapplied");
        }
        self.transition("not_applied", Some("verified no external mutation"))
            .await
    }
}
