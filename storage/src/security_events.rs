//! Storage for the Security Event Layer (roadmap phase 2,
//! `security-events-storage`). Builds on `clawforge-security-events`'
//! validated `SensorEnvelope` and reuses this crate's existing IP-pseudonym
//! machinery (`ip_pseudonym_key`/`pseudonymize_ip`/`pseudonymize_correlation_id`,
//! from `incident-correlation-convergence`) so a raw IP never reaches
//! `security_events.resource` or its evidence, exactly as `events.correlation_id`
//! already works.
//!
//! Nothing outside this module writes to these tables yet: wiring an
//! authenticated ingress endpoint that actually calls `record_security_event`
//! is separate, later work (`security-events-ingress`).

use anyhow::Result;
use chrono::{DateTime, Utc};
use clawforge_security_events::{SecurityEventEvidence, SecurityEventType, SensorEnvelope};
use sqlx::Row;
use tracing::warn;
use uuid::Uuid;

use crate::{pseudonymize_correlation_id, PostgresStore};

/// A raw IP matched a threat-intel indicator - which one, never anything
/// about the IP itself. Deliberately the smallest possible shape: a
/// category flag a caller can pass onward, not a copy of the indicator
/// row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpReputationHit {
    pub source: String,
}

/// A registered sensor identity, without its credential hash - callers that
/// need to authenticate a credential use `authenticate_security_sensor`,
/// which takes the hash as input rather than ever returning one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuritySensor {
    pub id: Uuid,
    pub name: String,
    pub credential_prefix: String,
    pub enabled: bool,
    pub rotated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

fn sensor_from_row(row: &sqlx::postgres::PgRow) -> SecuritySensor {
    SecuritySensor {
        id: row.get("id"),
        name: row.get("name"),
        credential_prefix: row.get("credential_prefix"),
        enabled: row.get("enabled"),
        rotated_at: row.get("rotated_at"),
        revoked_at: row.get("revoked_at"),
        last_seen_at: row.get("last_seen_at"),
        created_at: row.get("created_at"),
    }
}

/// Pseudonymize a plain `String` field that may or may not actually hold an
/// IP - matches `pseudonymize_correlation_id`'s pass-through-if-not-an-IP
/// behavior so a resource/evidence field that is never an address (a
/// container id, a username) is left alone.
fn pseudonymize_field(value: &str) -> Result<String> {
    pseudonymize_correlation_id(value)
}

fn pseudonymize_optional_field(value: &Option<String>) -> Result<Option<String>> {
    value.as_deref().map(pseudonymize_field).transpose()
}

/// Replace every field documented as an IP address in `evidence` with its
/// stable pseudonym. Written as an explicit match over the known, typed
/// fields of each of the eleven evidence shapes - deliberately not a
/// generic "any field named like an IP" walker (as
/// `sanitize_analysis_value` uses for free-text JSON payloads elsewhere):
/// evidence here is already strongly typed, so matching field names
/// precisely is both simpler and safer than a heuristic that could miss or
/// over-match a field by name.
fn pseudonymize_evidence(evidence: &SecurityEventEvidence) -> Result<SecurityEventEvidence> {
    use clawforge_security_events::{
        AuthAnomalyEvidence, AuthFailureEvidence, DnsAnomalyEvidence, FirewallBlockEvidence,
        HttpAnomalyEvidence, PortScanDetectedEvidence, SshLoginAnomalyEvidence,
        SshLoginFailureEvidence,
    };
    Ok(match evidence.clone() {
        SecurityEventEvidence::FirewallBlock(e) => {
            SecurityEventEvidence::FirewallBlock(FirewallBlockEvidence {
                source_ip: pseudonymize_field(&e.source_ip)?,
                destination_ip: pseudonymize_optional_field(&e.destination_ip)?,
                ..e
            })
        }
        // No IP fields: nothing to pseudonymize.
        SecurityEventEvidence::FirewallRuleChanged(e) => {
            SecurityEventEvidence::FirewallRuleChanged(e)
        }
        SecurityEventEvidence::AuthFailure(e) => {
            SecurityEventEvidence::AuthFailure(AuthFailureEvidence {
                source_ip: pseudonymize_field(&e.source_ip)?,
                ..e
            })
        }
        SecurityEventEvidence::AuthAnomaly(e) => {
            SecurityEventEvidence::AuthAnomaly(AuthAnomalyEvidence {
                source_ip: pseudonymize_field(&e.source_ip)?,
                previous_source_ip: pseudonymize_optional_field(&e.previous_source_ip)?,
                ..e
            })
        }
        SecurityEventEvidence::SshLoginFailure(e) => {
            SecurityEventEvidence::SshLoginFailure(SshLoginFailureEvidence {
                source_ip: pseudonymize_field(&e.source_ip)?,
                ..e
            })
        }
        SecurityEventEvidence::SshLoginAnomaly(e) => {
            SecurityEventEvidence::SshLoginAnomaly(SshLoginAnomalyEvidence {
                source_ip: pseudonymize_field(&e.source_ip)?,
                ..e
            })
        }
        SecurityEventEvidence::HttpAnomaly(e) => {
            SecurityEventEvidence::HttpAnomaly(HttpAnomalyEvidence {
                source_ip: pseudonymize_field(&e.source_ip)?,
                ..e
            })
        }
        SecurityEventEvidence::DnsAnomaly(e) => {
            SecurityEventEvidence::DnsAnomaly(DnsAnomalyEvidence {
                source_ip: pseudonymize_field(&e.source_ip)?,
                ..e
            })
        }
        SecurityEventEvidence::PortScanDetected(e) => {
            SecurityEventEvidence::PortScanDetected(PortScanDetectedEvidence {
                source_ip: pseudonymize_field(&e.source_ip)?,
                target_ip: pseudonymize_field(&e.target_ip)?,
                ..e
            })
        }
        // Neither has an IP field either.
        SecurityEventEvidence::ContainerAnomaly(e) => SecurityEventEvidence::ContainerAnomaly(e),
        SecurityEventEvidence::ContainerEscapeAttempt(e) => {
            SecurityEventEvidence::ContainerEscapeAttempt(e)
        }
        // No IP field: container/image identifiers only.
        SecurityEventEvidence::ContainerLifecycleChanged(e) => {
            SecurityEventEvidence::ContainerLifecycleChanged(e)
        }
    })
}

impl PostgresStore {
    /// Register a new sensor identity. `credential_hash` and
    /// `credential_prefix` are the caller's responsibility to produce
    /// (argon2, matching admin_users/api_tokens/agent_tokens elsewhere) -
    /// this only ever persists a hash, never a credential in the clear.
    pub async fn register_security_sensor(
        &self,
        name: &str,
        credential_hash: &str,
        credential_prefix: &str,
        created_by: Option<Uuid>,
        actor: &str,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let mut tx = self.pool().begin().await?;
        sqlx::query(
            "INSERT INTO security_sensors (id,name,credential_hash,credential_prefix,created_by) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(id)
        .bind(name)
        .bind(credential_hash)
        .bind(credential_prefix)
        .bind(created_by)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO security_sensor_audit (sensor_id,action,actor,reason) \
             VALUES ($1,'registered',$2,'')",
        )
        .bind(id)
        .bind(actor)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn rotate_security_sensor_credential(
        &self,
        sensor_id: Uuid,
        credential_hash: &str,
        credential_prefix: &str,
        actor: &str,
    ) -> Result<()> {
        let mut tx = self.pool().begin().await?;
        let updated = sqlx::query(
            "UPDATE security_sensors SET credential_hash=$2, credential_prefix=$3, rotated_at=NOW() \
             WHERE id=$1 AND revoked_at IS NULL",
        )
        .bind(sensor_id)
        .bind(credential_hash)
        .bind(credential_prefix)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            anyhow::bail!("security sensor not found or revoked");
        }
        sqlx::query(
            "INSERT INTO security_sensor_audit (sensor_id,action,actor,reason) \
             VALUES ($1,'credential_rotated',$2,'')",
        )
        .bind(sensor_id)
        .bind(actor)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Enable or revoke a sensor. Revoking also clears `enabled`, matching
    /// the table's own check constraint (`revoked_at IS NULL OR enabled =
    /// FALSE`); re-enabling a previously revoked sensor is refused - a
    /// revoked identity is terminal, matching how `agent_tokens`/`api_tokens`
    /// revocation elsewhere is never undone in place either.
    pub async fn set_security_sensor_enabled(
        &self,
        sensor_id: Uuid,
        enabled: bool,
        actor: &str,
        reason: &str,
    ) -> Result<()> {
        let mut tx = self.pool().begin().await?;
        let current: Option<(bool, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT enabled, revoked_at FROM security_sensors WHERE id=$1 FOR UPDATE",
        )
        .bind(sensor_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((_, revoked_at)) = current else {
            anyhow::bail!("security sensor not found");
        };
        if revoked_at.is_some() {
            anyhow::bail!("security sensor is already revoked");
        }
        if enabled {
            sqlx::query("UPDATE security_sensors SET enabled=TRUE WHERE id=$1")
                .bind(sensor_id)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query("UPDATE security_sensors SET enabled=FALSE, revoked_at=NOW() WHERE id=$1")
                .bind(sensor_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "INSERT INTO security_sensor_audit (sensor_id,action,actor,reason) VALUES ($1,$2,$3,$4)",
        )
        .bind(sensor_id)
        .bind(if enabled { "enabled" } else { "revoked" })
        .bind(actor)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Look up a sensor by its credential hash for authentication - only a
    /// sensor that is enabled and not revoked authenticates. Bumps
    /// `last_seen_at` on success, the same idea as `agent_tokens`'
    /// `last_used_at`.
    pub async fn authenticate_security_sensor(
        &self,
        credential_hash: &str,
    ) -> Result<Option<SecuritySensor>> {
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT id,name,credential_prefix,enabled,rotated_at,revoked_at,last_seen_at,created_at \
             FROM security_sensors WHERE credential_hash=$1 AND enabled AND revoked_at IS NULL",
        )
        .bind(credential_hash)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let sensor_id: Uuid = row.get("id");
        sqlx::query("UPDATE security_sensors SET last_seen_at=NOW() WHERE id=$1")
            .bind(sensor_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(sensor_from_row(&row)))
    }

    pub async fn get_security_sensor(&self, id: Uuid) -> Result<Option<SecuritySensor>> {
        let row = sqlx::query(
            "SELECT id,name,credential_prefix,enabled,rotated_at,revoked_at,last_seen_at,created_at \
             FROM security_sensors WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.as_ref().map(sensor_from_row))
    }

    pub async fn list_security_sensors(&self) -> Result<Vec<SecuritySensor>> {
        let rows = sqlx::query(
            "SELECT id,name,credential_prefix,enabled,rotated_at,revoked_at,last_seen_at,created_at \
             FROM security_sensors ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(sensor_from_row).collect())
    }

    /// Persist one validated sensor event. `resource` and every IP-shaped
    /// evidence field are pseudonymized first (see `pseudonymize_evidence`),
    /// so this never writes a raw IP - fails closed the same way
    /// `publish_event` does when IP anonymization is on and no
    /// `CLAWFORGE_ANALYZER_IP_HMAC_KEY` is configured.
    ///
    /// A resubmission of a `dedupe_key` already used by this sensor is
    /// idempotent only if its content is unchanged; a resubmission with
    /// different content is rejected rather than silently accepted or
    /// silently overwriting the original, per the roadmap's
    /// `security-events-ingress` dedupe requirement.
    /// A raw IP's reputation from Spamhaus's DROP/EDROP feeds
    /// (`indicators.source LIKE 'spamhaus%'`) - checked **before** a
    /// resource is pseudonymized, since indicators are stored as raw CIDR
    /// prefixes (`indicator_type='Prefix'`) and a pseudonym could never be
    /// checked against them. Only the result - which feed, never the IP
    /// itself - is what a caller may persist further (see
    /// `record_security_event`, the only caller today, which writes just a
    /// category flag onto the canonical event's `metadata`, never the IP).
    ///
    /// Deliberately the opposite of the pseudonymization path's
    /// fail-closed design: pseudonymization protects a privacy guarantee
    /// that must never be silently bypassed, so a missing key rejects the
    /// write outright; a reputation lookup is an enrichment on top of an
    /// event that is valid and worth recording regardless, so its caller
    /// treats a lookup failure as "no hit" rather than failing the whole
    /// event - see the `.unwrap_or_default()` at its call site.
    pub async fn lookup_ip_reputation(&self, ip: &str) -> Result<Option<IpReputationHit>> {
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT source FROM indicators \
             WHERE source LIKE 'spamhaus%' AND expires_at > NOW() \
             AND ( \
               (indicator_type='Ip' AND value=$1) OR \
               (indicator_type='Prefix' AND $1::inet <<= value::cidr) \
             ) LIMIT 1",
        )
        .bind(ip)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|row| IpReputationHit {
            source: row.get("source"),
        }))
    }

    /// The one, deliberately narrow exception to this codebase's
    /// fail-closed "never persist a raw IP" rule - see
    /// `security_ip_resolutions`'s own migration comment for the full
    /// reasoning. Only ever called by `record_security_event`, only after
    /// `lookup_ip_reputation` already found `raw_ip` independently
    /// known-bad. `pseudonym` is the already-pseudonymized resource (the
    /// key a future firewall-agent apply step would look this up by,
    /// never the raw IP itself), and the row expires after a short, fixed
    /// TTL (`CLAWFORGE_IP_RESOLUTION_TTL_SECONDS`, default 24h) regardless
    /// of how many times it is refreshed - an upsert extends the TTL
    /// window but never accumulates history.
    pub async fn upsert_ip_resolution(
        &self,
        pseudonym: &str,
        raw_ip: &str,
        source: &str,
    ) -> Result<()> {
        let ttl_seconds: i64 = std::env::var("CLAWFORGE_IP_RESOLUTION_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(86_400);
        sqlx::query(
            "INSERT INTO security_ip_resolutions (pseudonym,raw_ip,source,expires_at) \
             VALUES ($1,$2,$3,NOW() + ($4 * INTERVAL '1 second')) \
             ON CONFLICT (pseudonym) DO UPDATE SET \
               raw_ip=EXCLUDED.raw_ip, source=EXCLUDED.source, expires_at=EXCLUDED.expires_at",
        )
        .bind(pseudonym)
        .bind(raw_ip)
        .bind(source)
        .bind(ttl_seconds)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn record_security_event(
        &self,
        sensor_id: Uuid,
        envelope: &SensorEnvelope,
    ) -> Result<Uuid> {
        let resource = pseudonymize_field(&envelope.resource)?;
        let evidence = pseudonymize_evidence(&envelope.evidence)?;
        let evidence_json = serde_json::to_value(&evidence)?;
        let event_type = envelope.event_type().as_str();
        let id = Uuid::new_v4();
        let mut tx = self.pool().begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO security_events \
             (id,schema_version,event_type,sensor_id,occurred_at,severity,resource,dedupe_key,evidence) \
             VALUES ($1,1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (sensor_id,dedupe_key) DO NOTHING",
        )
        .bind(id)
        .bind(event_type)
        .bind(sensor_id)
        .bind(envelope.occurred_at)
        .bind(envelope.severity.as_str())
        .bind(&resource)
        .bind(&envelope.dedupe_key)
        .bind(&evidence_json)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            // Compare every field the sensor actually reported, not just
            // event_type/evidence: a resubmission that keeps the same
            // dedupe_key but changes severity, resource or its own
            // occurred_at is different content too, and must be rejected
            // the same as changed evidence would be.
            let existing: (
                Uuid,
                String,
                String,
                DateTime<Utc>,
                String,
                serde_json::Value,
            ) = sqlx::query_as(
                "SELECT id,event_type,severity,occurred_at,resource,evidence \
                     FROM security_events WHERE sensor_id=$1 AND dedupe_key=$2",
            )
            .bind(sensor_id)
            .bind(&envelope.dedupe_key)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            // occurred_at is compared at microsecond precision, matching
            // what TIMESTAMPTZ actually stores: chrono's DateTime<Utc>
            // (Utc::now(), or a value round-tripped through JSON) carries
            // nanoseconds, so a byte-for-byte comparison against the value
            // read back from Postgres would see a false mismatch on the
            // sub-microsecond remainder alone, wrongly rejecting a genuinely
            // identical resubmission.
            let unchanged = existing.1 == event_type
                && existing.2 == envelope.severity.as_str()
                && existing.3.timestamp_micros() == envelope.occurred_at.timestamp_micros()
                && existing.4 == resource
                && existing.5 == evidence_json;
            if !unchanged {
                anyhow::bail!(
                    "dedupe_key {:?} was already used by this sensor with different content",
                    envelope.dedupe_key
                );
            }
            return Ok(existing.0);
        }
        sqlx::query("UPDATE security_sensors SET last_seen_at=NOW() WHERE id=$1")
            .bind(sensor_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        // Reputation lookup against the STILL-RAW envelope.resource -
        // pseudonymization already happened above (into `resource`), but
        // envelope.resource itself is untouched, and this is the last point
        // in the whole ingest path where the raw IP is available server-side
        // at all. Fails open (see lookup_ip_reputation's own doc comment):
        // a lookup error must never block recording a valid security event.
        let reputation = self
            .lookup_ip_reputation(&envelope.resource)
            .await
            .unwrap_or_default();
        let mut metadata = serde_json::json!({"security_event_id": id, "sensor_id": sensor_id});
        if let Some(hit) = &reputation {
            // Only the category, in metadata (operational context) rather
            // than payload (the sensor's own observation) - never the IP,
            // matching the same boundary pseudonymize_evidence already
            // draws between what a rule may group by and what it may see.
            metadata["threat_intel_hit"] = serde_json::json!(true);
            metadata["threat_intel_source"] = serde_json::json!(hit.source);
        }
        // The one, deliberately narrow exception to "never persist a raw
        // IP" in this codebase - see security_ip_resolutions's own
        // migration comment. Written for every security event, not only a
        // reputation hit: corroboration (what makes a block reachable at
        // all) can also come from two *behavioral* rules firing for the
        // same source - a plain ssh_bruteforce first, then later the same
        // source starts an http_scan - with no threat-intel hit involved
        // at either point individually. By the time that combination is
        // recognized (clawforge-security-engine, working only from
        // pseudonyms, never sees a raw IP itself), the resolution has to
        // already exist or a later block can never be rendered against a
        // real address. The short, fixed TTL (refreshed on every new event
        // from the same source, so sustained activity stays resolvable
        // and a one-off stays short-lived) and the "never appears in a
        // rendered receipt, only resolved just-in-time by a real apply
        // step" rule (not built yet) are what keep this from being a
        // blanket raw-IP log despite covering every event. Best-effort:
        // a failure here must never fail recording the security event.
        let resolution_source = reputation
            .as_ref()
            .map(|hit| hit.source.as_str())
            .unwrap_or("sensor_observed");
        if let Err(error) = self
            .upsert_ip_resolution(&resource, &envelope.resource, resolution_source)
            .await
        {
            warn!(%error, "could not persist short-TTL IP resolution");
        }
        // Fan this out onto the canonical event bus - exactly once, only for
        // a genuinely new row (the ON CONFLICT/dedupe-hit path above already
        // returned early with the existing id, never reaching here) - so a
        // sensor's own at-least-once retry never republishes the same
        // security event a second time. clawforge-security-engine (Phase 4)
        // is the one service that consumes it from there; the resource is
        // already pseudonymized above, so using it as correlation_id lets
        // rules group events (e.g. repeated ssh_login_failure) by the same
        // pseudonymous source without ever seeing a raw IP.
        self.publish_event(
            event_type,
            &format!("sensor:{sensor_id}"),
            envelope.severity.as_str(),
            envelope.occurred_at,
            Some(&resource),
            evidence_json,
            metadata,
            &format!("security-event:{id}"),
        )
        .await?;
        Ok(id)
    }

    pub async fn get_security_event(&self, id: Uuid) -> Result<Option<serde_json::Value>> {
        let row = sqlx::query(
            "SELECT id,event_type,sensor_id,occurred_at,received_at,severity,resource,evidence,created_at \
             FROM security_events WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|row| security_event_view(&row)))
    }

    pub async fn list_security_events(
        &self,
        event_type: Option<SecurityEventType>,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query(
            "SELECT id,event_type,sensor_id,occurred_at,received_at,severity,resource,evidence,created_at \
             FROM security_events WHERE ($1::text IS NULL OR event_type=$1) \
             ORDER BY occurred_at DESC LIMIT $2",
        )
        .bind(event_type.map(|value| value.as_str()))
        .bind(limit.clamp(1, 500))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().map(security_event_view).collect())
    }
}

fn security_event_view(row: &sqlx::postgres::PgRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.get::<Uuid, _>("id"),
        "event_type": row.get::<String, _>("event_type"),
        "sensor_id": row.get::<Uuid, _>("sensor_id"),
        "occurred_at": row.get::<DateTime<Utc>, _>("occurred_at"),
        "received_at": row.get::<DateTime<Utc>, _>("received_at"),
        "severity": row.get::<String, _>("severity"),
        "resource": row.get::<String, _>("resource"),
        "evidence": row.get::<serde_json::Value, _>("evidence"),
        "created_at": row.get::<DateTime<Utc>, _>("created_at"),
    })
}
