//! Just-in-time resolution of a pseudonymized incident source to the single
//! host address the executor needs for a real firewall apply.
//!
//! The only reader of `security_ip_resolutions` is the SECURITY DEFINER
//! function from migration 0059, which releases an address solely for a request
//! the executor has just claimed (status `starting`). The result is for the
//! `apply`/`verify`/`rollback` call itself: it must not enter a receipt, a log
//! line or an agent projection. `Debug` therefore redacts the address.
use crate::PostgresStore;
use anyhow::Result;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedIncidentSourceAddress {
    pub pseudonym: String,
    pub raw_ip: String,
}

impl std::fmt::Debug for ResolvedIncidentSourceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedIncidentSourceAddress")
            .field("pseudonym", &self.pseudonym)
            .field("raw_ip", &"<redacted>")
            .finish()
    }
}

impl PostgresStore {
    /// `Ok(None)` when the request is not an eligible, claimed incident-source
    /// block or the resolution is missing/expired - callers must then refuse the
    /// apply (fail closed), never fall back to another address. Every call is
    /// audited with the pseudonym only.
    pub async fn resolve_incident_source_for_apply(
        &self,
        execution_id: Uuid,
    ) -> Result<Option<ResolvedIncidentSourceAddress>> {
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT pseudonym, raw_ip FROM clawforge_resolve_incident_source_for_apply($1)",
        )
        .bind(execution_id)
        .fetch_optional(&mut *tx)
        .await?;
        let resolved = row.map(|row| ResolvedIncidentSourceAddress {
            pseudonym: row.get("pseudonym"),
            raw_ip: row.get("raw_ip"),
        });
        Self::insert_audit_outbox(
            &mut tx,
            "executor",
            "incident_source_resolved_for_apply",
            &execution_id.to_string(),
            &serde_json::json!({
                "resolved": resolved.is_some(),
                "pseudonym": resolved.as_ref().map(|value| value.pseudonym.as_str()),
            }),
        )
        .await?;
        tx.commit().await?;
        let _ = self.flush_audit_outbox(100).await;
        Ok(resolved)
    }
}
