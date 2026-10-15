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
    pub proxmox_upid: Option<String>,
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
        proxmox_upid: row.get("proxmox_upid"),
    }
}

impl PostgresStore {
    /// Store the Proxmox UPID on a prepared quarantine intent.
    /// This survives a later-failing receipt transaction and takes no FOR UPDATE lock.
    pub async fn set_quarantine_intent_upid(&self, id: Uuid, upid: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE firewall_action_intents SET proxmox_upid = $2 WHERE id = $1")
            .bind(id)
            .bind(upid)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

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
    /// The single active generation for a canonical target - the unique active-generation
    /// index guarantees at most one in prepared/completed/recovery_required. The operator
    /// reconcile path resolves by canonical identity (what the reconcile approval is bound to),
    /// not by a separately-supplied intent id.
    pub async fn active_quarantine_intent_for(
        &self,
        adapter: &str,
        fingerprint: &str,
    ) -> Result<Option<QuarantineIntent>> {
        Ok(sqlx::query("SELECT * FROM firewall_action_intents WHERE adapter=$1 AND target_fingerprint=$2 AND target_fingerprint IS NOT NULL AND status IN ('prepared','completed','recovery_required')")
            .bind(adapter).bind(fingerprint).fetch_optional(&self.pool).await?.map(decode))
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

    /// Read-only, paginated operator view of quarantine generations (Q1).
    ///
    /// Stable sort `created_at DESC, id DESC`, SQL-level pagination and an
    /// accurate `total` so pages beyond the first are not silently empty. Each
    /// row carries the durable status, an operator lifecycle label, the apply
    /// and rollback receipt lineage and whether verified recovery is still open.
    ///
    /// This is deliberately the *operator* surface (session auth + role), so it
    /// may show internal `target_json`. It performs no mutation and exposes no
    /// adapter/rollback command; the agent/MCP projection stays separate and
    /// sanitized. Returns the page rows and the total generation count.
    pub async fn list_quarantine_generations(
        &self,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<Value>, i64)> {
        let page = page.max(1);
        let page_size = page_size.clamp(1, 200);
        let offset = (page - 1) * page_size;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM firewall_action_intents WHERE target_fingerprint IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        // The unique (intent_id, receipt_kind) index guarantees at most one
        // apply and one rollback receipt per generation, so these joins never
        // fan the generation row out.
        let rows = sqlx::query(
            "SELECT i.id,i.execution_id,i.adapter,i.action_name,i.status,i.target_fingerprint, \
                    i.target_json,i.ttl_seconds,i.expires_at,i.created_at,i.completed_at,i.error_summary, \
                    (i.expires_at<=NOW()) AS is_expired, \
                    ar.id AS apply_receipt_id,ar.verification_result AS apply_verification,ar.created_at AS apply_created_at, \
                    rr.id AS rollback_receipt_id,rr.verification_result AS rollback_verification,rr.created_at AS rollback_created_at \
             FROM firewall_action_intents i \
             LEFT JOIN firewall_action_receipts ar ON ar.intent_id=i.id AND ar.receipt_kind='apply' \
             LEFT JOIN firewall_action_receipts rr ON rr.intent_id=i.id AND rr.receipt_kind='rollback' \
             WHERE i.target_fingerprint IS NOT NULL \
             ORDER BY i.created_at DESC,i.id DESC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        let values = rows
            .into_iter()
            .map(|r| {
                let status: String = r.get("status");
                let is_expired: bool = r.get("is_expired");
                let apply_receipt = r.get::<Option<Uuid>, _>("apply_receipt_id").map(|id| {
                    json!({
                        "id": id,
                        "verification_result": r.get::<Option<String>, _>("apply_verification"),
                        "created_at": r.get::<Option<DateTime<Utc>>, _>("apply_created_at"),
                    })
                });
                let rollback_receipt = r.get::<Option<Uuid>, _>("rollback_receipt_id").map(|id| {
                    json!({
                        "id": id,
                        "verification_result": r.get::<Option<String>, _>("rollback_verification"),
                        "created_at": r.get::<Option<DateTime<Utc>>, _>("rollback_created_at"),
                    })
                });
                json!({
                    "generation_id": r.get::<Uuid, _>("id"),
                    "execution_id": r.get::<Uuid, _>("execution_id"),
                    "adapter": r.get::<String, _>("adapter"),
                    "action_name": r.get::<String, _>("action_name"),
                    "status": status,
                    "lifecycle": quarantine_lifecycle(&status, is_expired),
                    "owns_target": owns_quarantine_target(&status),
                    "open_recovery": quarantine_recovery_open(&status, is_expired),
                    "is_expired": is_expired,
                    "target_fingerprint": r.get::<String, _>("target_fingerprint"),
                    "target_json": r.get::<Value, _>("target_json"),
                    "ttl_seconds": r.get::<i32, _>("ttl_seconds"),
                    "expires_at": r.get::<DateTime<Utc>, _>("expires_at"),
                    "created_at": r.get::<DateTime<Utc>, _>("created_at"),
                    "completed_at": r.get::<Option<DateTime<Utc>>, _>("completed_at"),
                    "error_summary": r.get::<Option<String>, _>("error_summary"),
                    "apply_receipt": apply_receipt,
                    "rollback_receipt": rollback_receipt,
                })
            })
            .collect();
        Ok((values, total))
    }
}

/// Operator-facing lifecycle label derived from the durable status and TTL.
///
/// This never widens ownership or terminal semantics (those are enforced by the
/// DB transition trigger); it only groups statuses so an operator view can tell
/// an expired block still awaiting verified recovery apart from a verified
/// restore. `completed` means a verified apply, NOT the end of quarantine.
pub fn quarantine_lifecycle(status: &str, is_expired: bool) -> &'static str {
    match status {
        "prepared" => "prepared",
        "completed" if is_expired => "expired_pending_recovery",
        "completed" => "active",
        "recovery_required" => "recovery_required",
        "not_applied" => "not_applied",
        "rolled_back" => "verified_restored",
        _ => "unknown",
    }
}

/// A generation still exclusively owns its `(adapter, fingerprint)` target while
/// prepared, completed or recovery_required; only `not_applied` and
/// `rolled_back` release it. Mirrors the active-generation unique index.
pub fn owns_quarantine_target(status: &str) -> bool {
    matches!(status, "prepared" | "completed" | "recovery_required")
}

/// Whether this generation still needs verified recovery: an explicit
/// `recovery_required`, or a `completed` block whose TTL has passed and which
/// the sweep has not yet restored. Terminal states never report open recovery.
pub fn quarantine_recovery_open(status: &str, is_expired: bool) -> bool {
    status == "recovery_required" || (status == "completed" && is_expired)
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

    /// Persist the observed external task UPID on THIS generation within the guard's own
    /// transaction. The guard already holds the row FOR UPDATE, so a separate-transaction
    /// write to the same row would self-deadlock; this commits atomically with the guard's
    /// terminal transition (finish or recovery_required), so a generation left
    /// recovery_required after a verify failure still carries the UPID for reconciliation.
    pub async fn set_upid(&mut self, upid: &str) -> Result<()> {
        sqlx::query("UPDATE firewall_action_intents SET proxmox_upid=$2 WHERE id=$1")
            .bind(self.intent.id)
            .bind(upid)
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }

    /// Authorize an operator reconciliation of THIS generation with a SEPARATE,
    /// context-bound dual-approved reconcile request - never the original quarantine
    /// request's approval. Holds the approval lock through the reconcile mutation, exactly
    /// like validate_approval. The generation must be `recovery_required`: the only state
    /// the automatic sweep deliberately will not resolve, so it needs an audited operator.
    pub async fn validate_reconcile_approval(
        &mut self,
        reconcile_execution_id: Uuid,
        reconcile_action_name: &str,
        target: &Value,
    ) -> Result<()> {
        sqlx::query("SELECT clawforge_lock_quarantine_approval($1)")
            .bind(reconcile_execution_id)
            .execute(&mut *self.tx)
            .await?;
        let authorized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM execution_requests e JOIN actions a ON a.id=e.action_id JOIN approval_policies p ON p.risk_level=a.risk_level WHERE e.id=$1 AND e.status IN ('starting','running') AND a.name=$2 AND a.enabled AND a.requires_approval AND a.risk_level='critical' AND p.required_approvals>=2 AND e.required_approvals>=2 AND e.requested_by_id IS NOT NULL AND e.approval_expires_at>clock_timestamp() AND e.approval_context->'target'=$3 AND (SELECT COUNT(DISTINCT ea.approver_id) FROM execution_approvals ea WHERE ea.execution_id=e.id AND ea.context_hash=e.approval_context_hash AND ea.approver_id<>e.requested_by_id)>=GREATEST(e.required_approvals,p.required_approvals))")
            .bind(reconcile_execution_id).bind(reconcile_action_name).bind(target)
            .fetch_one(&mut *self.tx).await?;
        if self.intent.status != "recovery_required" || !authorized {
            bail!("reconcile approval invalid or generation not awaiting reconciliation");
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

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn lifecycle_distinguishes_expired_from_restored() {
        assert_eq!(quarantine_lifecycle("prepared", false), "prepared");
        assert_eq!(quarantine_lifecycle("completed", false), "active");
        assert_eq!(
            quarantine_lifecycle("completed", true),
            "expired_pending_recovery"
        );
        assert_eq!(
            quarantine_lifecycle("recovery_required", false),
            "recovery_required"
        );
        assert_eq!(quarantine_lifecycle("not_applied", false), "not_applied");
        assert_eq!(
            quarantine_lifecycle("rolled_back", false),
            "verified_restored"
        );
        // An expired terminal state is still terminal, not pending recovery.
        assert_eq!(
            quarantine_lifecycle("rolled_back", true),
            "verified_restored"
        );
    }

    #[test]
    fn ownership_and_recovery_match_generation_fence() {
        for s in ["prepared", "completed", "recovery_required"] {
            assert!(owns_quarantine_target(s), "{s} must own its target");
        }
        for s in ["not_applied", "rolled_back"] {
            assert!(!owns_quarantine_target(s), "{s} must release its target");
        }
        assert!(quarantine_recovery_open("recovery_required", false));
        assert!(quarantine_recovery_open("completed", true));
        assert!(!quarantine_recovery_open("completed", false));
        assert!(!quarantine_recovery_open("rolled_back", true));
        assert!(!quarantine_recovery_open("prepared", true));
    }
}
