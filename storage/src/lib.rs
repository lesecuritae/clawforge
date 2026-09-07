//! PostgreSQL persistence boundary.
//!
//! All SQL is kept behind this crate so the API and worker do not depend on
//! database details. SQLite can be used by future test adapters; production
//! runtime is PostgreSQL through sqlx.

use anyhow::{Context, Result};
use async_trait::async_trait;
use clawforge_intelligence::{
    AsnRecord, BgpEvent, Indicator, IndicatorSink, IntelligenceEvent, NetworkSink, Provider,
    ProviderError, RpkiRecord, TrustedNetwork,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{env, fs};
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../migrations");

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(database_url)
            .await
            .context("connect to PostgreSQL")?;
        // Refuse to start an older binary against a database that already has
        // migrations this binary does not know about. sqlx protects checksums
        // and applies forward migrations; this explicit guard protects the
        // downgrade case before sqlx is allowed to run.
        let expected_latest = MIGRATOR
            .iter()
            .map(|migration| migration.version)
            .max()
            .unwrap_or(0);
        let migration_table: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations')::text")
                .fetch_one(&pool)
                .await
                .context("inspect migration metadata")?;
        if migration_table.is_some() {
            let applied_latest: Option<i64> =
                sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
                    .fetch_one(&pool)
                    .await
                    .context("read applied migration version")?;
            if applied_latest.unwrap_or(0) > expected_latest {
                anyhow::bail!(
                    "database migration version {} is newer than binary version {}; refusing downgrade",
                    applied_latest.unwrap_or(0),
                    expected_latest
                );
            }
        }
        MIGRATOR
            .run(&pool)
            .await
            .context("run database migrations")?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn healthcheck(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn readiness(&self) -> Result<MigrationStatus> {
        self.healthcheck().await?;
        let row = sqlx::query(
            "SELECT COUNT(*) AS count, COALESCE(MAX(version), 0) AS latest FROM _sqlx_migrations",
        )
        .fetch_one(&self.pool)
        .await?;
        let applied = row.get::<i64, _>("count") as usize;
        let latest = row.get::<i64, _>("latest");
        let expected = MIGRATOR.iter().count();
        let expected_latest = MIGRATOR
            .iter()
            .map(|migration| migration.version)
            .max()
            .unwrap_or(0);
        Ok(MigrationStatus {
            applied,
            expected,
            latest,
            expected_latest,
            current: applied == expected && latest == expected_latest,
        })
    }

    pub async fn migration_version(&self) -> Result<Option<String>> {
        let row = sqlx::query("SELECT version FROM _sqlx_migrations ORDER BY version DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|value| value.get::<i64, _>("version").to_string()))
    }

    pub async fn record_audit_event(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_events (actor, action, resource, details) VALUES ($1, $2, $3, $4)",
        )
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_intelligence_event(&self, event: &IntelligenceEvent) -> Result<()> {
        let event_id: i64 = sqlx::query_scalar("INSERT INTO audit_events (actor, action, resource, details, event_type, source, severity, reason, recorded_at) VALUES ('system',$1,$2,$3,$4,$5,$6,$7,$8) RETURNING id")
            .bind(&event.event_type)
            .bind(&event.resource)
            .bind(&event.details)
            .bind(&event.event_type)
            .bind(&event.source)
            .bind(&event.severity)
            .bind(&event.reason)
            .bind(event.timestamp)
            .fetch_one(&self.pool)
            .await?
            ;
        self.correlate_incident(event_id, event).await?;
        Ok(())
    }

    async fn correlate_incident(&self, event_id: i64, event: &IntelligenceEvent) -> Result<()> {
        if !matches!(
            event.event_type.as_str(),
            "new_threat_indicator"
                | "bgp_change"
                | "rpki_invalid"
                | "asn_change"
                | "trusted_network_change"
                | "provider_error"
        ) {
            return Ok(());
        }
        let severity = normalize_incident_severity(&event.severity);
        let increment = event
            .details
            .get("risk_score")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(match event.event_type.as_str() {
                "rpki_invalid" => 30,
                "bgp_change" => 25,
                "new_threat_indicator" => 20,
                "asn_change" => 10,
                "provider_error" => 5,
                _ => 5,
            });
        let mut tx = self.pool.begin().await?;
        let existing: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, severity FROM incidents WHERE correlation_key=$1 AND status IN ('Open','Investigating') ORDER BY updated_at DESC LIMIT 1 FOR UPDATE",
        )
        .bind(&event.resource)
        .fetch_optional(&mut *tx)
        .await?;
        let incident_id = if let Some((id, current_severity)) = existing {
            sqlx::query("UPDATE incidents SET severity=$2, risk_score=LEAST(100, risk_score+$3), summary=$4, updated_at=NOW() WHERE id=$1")
                .bind(id)
                .bind(max_incident_severity(&current_severity, &severity))
                .bind(increment.clamp(0, 100) as i16)
                .bind(format!("{}: {}", event.event_type, event.reason))
                .execute(&mut *tx)
                .await?;
            id
        } else {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO incidents (id,status,severity,risk_score,summary,correlation_key,created_at,updated_at) VALUES ($1,'Open',$2,$3,$4,$5,$6,$6)")
                .bind(id)
                .bind(&severity)
                .bind(increment.clamp(0, 100) as i16)
                .bind(format!("{}: {}", event.event_type, event.reason))
                .bind(&event.resource)
                .bind(event.timestamp)
                .execute(&mut *tx)
                .await?;
            id
        };
        sqlx::query("INSERT INTO incident_events (incident_id,event_id,timestamp) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(incident_id)
            .bind(event_id)
            .bind(event.timestamp)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_incidents(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT i.id,i.status,i.severity,i.created_at,i.updated_at,i.risk_score,i.summary,i.correlation_key,COUNT(ie.event_id) AS event_count FROM incidents i LEFT JOIN incident_events ie ON ie.incident_id=i.id WHERE ($1::text IS NULL OR i.status=$1) GROUP BY i.id ORDER BY i.updated_at DESC LIMIT $2")
            .bind(status).bind(limit.clamp(1, 500)).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.get::<Uuid,_>("id"),
                    "status": row.get::<String,_>("status"),
                    "severity": row.get::<String,_>("severity"),
                    "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
                    "updated_at": row.get::<chrono::DateTime<chrono::Utc>,_>("updated_at"),
                    "risk_score": row.get::<i16,_>("risk_score"),
                    "summary": row.get::<String,_>("summary"),
                    "correlation_key": row.get::<String,_>("correlation_key"),
                    "event_count": row.get::<i64,_>("event_count")
                })
            })
            .collect())
    }

    pub async fn get_incident(&self, id: Uuid) -> Result<Option<serde_json::Value>> {
        let row = sqlx::query("SELECT id,status,severity,created_at,updated_at,risk_score,summary,correlation_key FROM incidents WHERE id=$1")
            .bind(id).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| {
            serde_json::json!({
                "id": row.get::<Uuid,_>("id"),
                "status": row.get::<String,_>("status"),
                "severity": row.get::<String,_>("severity"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
                "updated_at": row.get::<chrono::DateTime<chrono::Utc>,_>("updated_at"),
                "risk_score": row.get::<i16,_>("risk_score"),
                "summary": row.get::<String,_>("summary"),
                "correlation_key": row.get::<String,_>("correlation_key")
            })
        }))
    }

    pub async fn list_incident_events(&self, id: Uuid) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT ie.event_id,ie.timestamp,a.actor,a.action,a.resource,a.details,a.event_type,a.source,a.severity,a.reason,a.recorded_at FROM incident_events ie JOIN audit_events a ON a.id=ie.event_id WHERE ie.incident_id=$1 ORDER BY ie.timestamp ASC")
            .bind(id).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "event_id": row.get::<i64,_>("event_id"),
                    "timestamp": row.get::<chrono::DateTime<chrono::Utc>,_>("timestamp"),
                    "actor": row.get::<String,_>("actor"),
                    "action": row.get::<String,_>("action"),
                    "resource": row.get::<String,_>("resource"),
                    "details": row.get::<serde_json::Value,_>("details"),
                    "event_type": row.get::<String,_>("event_type"),
                    "source": row.get::<String,_>("source"),
                    "severity": row.get::<String,_>("severity"),
                    "reason": row.get::<String,_>("reason"),
                    "recorded_at": row.get::<chrono::DateTime<chrono::Utc>,_>("recorded_at")
                })
            })
            .collect())
    }

    pub async fn update_incident_status(&self, id: Uuid, status: &str) -> Result<()> {
        if !matches!(status, "Open" | "Investigating" | "Resolved" | "Ignored") {
            anyhow::bail!("invalid incident status");
        }
        let result = sqlx::query("UPDATE incidents SET status=$2,updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(status)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            anyhow::bail!("incident not found");
        }
        Ok(())
    }

    pub async fn incident_analysis(&self, id: Uuid) -> Result<Option<serde_json::Value>> {
        let Some(incident) = self.get_incident(id).await? else {
            return Ok(None);
        };
        let events = self.list_incident_events(id).await?;
        let mut sources = events
            .iter()
            .filter_map(|event| event.get("source").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        sources.sort_unstable();
        sources.dedup();
        let event_types = events
            .iter()
            .filter_map(|event| event.get("event_type").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        Ok(Some(serde_json::json!({
            "incident": incident,
            "event_count": events.len(),
            "sources": sources,
            "event_types": event_types,
            "explanation": "Structured correlation of stored intelligence events. No blocking or policy decision was made.",
            "llm_input": {"incident": incident, "events": events}
        })))
    }

    /// Persist an administrator's trusted-network registration and leave an
    /// auditable event whenever its status or matching scope changes.
    pub async fn upsert_trusted_network(&self, network: &TrustedNetwork) -> Result<()> {
        let previous: Option<String> =
            sqlx::query_scalar("SELECT status FROM trusted_networks WHERE id = $1")
                .bind(network.id)
                .fetch_optional(&self.pool)
                .await?;
        sqlx::query("INSERT INTO trusted_networks (id, name, network_type, identifier, networks, node_identities, device_tags, groups_json, status, created_at, verified_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, network_type=EXCLUDED.network_type, identifier=EXCLUDED.identifier, networks=EXCLUDED.networks, node_identities=EXCLUDED.node_identities, device_tags=EXCLUDED.device_tags, groups_json=EXCLUDED.groups_json, status=EXCLUDED.status, verified_at=EXCLUDED.verified_at")
            .bind(network.id)
            .bind(&network.name)
            .bind(format!("{:?}", network.network_type))
            .bind(&network.identifier)
            .bind(serde_json::to_value(&network.networks)?)
            .bind(serde_json::to_value(&network.node_identities)?)
            .bind(serde_json::to_value(&network.device_tags)?)
            .bind(serde_json::to_value(&network.groups)?)
            .bind(format!("{:?}", network.status))
            .bind(network.created_at)
            .bind(network.verified_at)
            .execute(&self.pool)
            .await?;
        let new_status = format!("{:?}", network.status);
        let reason = match previous.as_deref() {
            None => format!("trusted network registered with status {new_status}"),
            Some(old) if old != new_status => {
                format!("trusted network status changed from {old} to {new_status}")
            }
            Some(_) => "trusted network registration updated".to_string(),
        };
        self.record_intelligence_event(&IntelligenceEvent {
            event_type: "trusted_network_change".to_string(),
            timestamp: chrono::Utc::now(),
            source: "trusted_registry".to_string(),
            severity: if new_status == "Verified" { "info" } else { "warning" }.to_string(),
            reason,
            resource: network.id.to_string(),
            details: serde_json::json!({"name": network.name, "type": format!("{:?}", network.network_type), "status": new_status}),
        }).await?;
        Ok(())
    }

    pub async fn list_provider_views(&self) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT p.id, p.name, p.source, p.interval_seconds, p.confidence, p.enabled, s.state, s.last_started_at, s.last_success_at, s.next_run_at, s.consecutive_failures, s.last_error, s.indicator_count, s.sync_duration_ms, s.last_data_at, EXTRACT(EPOCH FROM (NOW() - s.last_data_at)) AS age_seconds FROM providers p LEFT JOIN provider_status s ON s.provider_id = p.id ORDER BY p.id")
            .fetch_all(&self.pool).await?;
        rows.into_iter().map(|row| {
                    let status = row.try_get::<String, _>("state").ok();
                    let last_success_at = row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_success_at").ok();
                    Ok(serde_json::json!({
                        "id": row.get::<String, _>("id"),
                        "name": row.get::<String, _>("name"),
                        "source": row.get::<String, _>("source"),
                        "interval_seconds": row.get::<i64, _>("interval_seconds"),
                        "confidence": row.get::<i16, _>("confidence"),
                        "enabled": row.get::<bool, _>("enabled"),
                        "status": status,
                "last_started_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_started_at").ok(),
                        "last_success_at": last_success_at,
                "next_run_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("next_run_at").ok(),
                        "last_error": row.try_get::<String, _>("last_error").ok(),
                        "retry_count": row.try_get::<i32, _>("consecutive_failures").unwrap_or(0),
                "indicator_count": row.try_get::<i32, _>("indicator_count").unwrap_or(0),
                "sync_duration_ms": row.try_get::<i64, _>("sync_duration_ms").unwrap_or(0),
                "last_data_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_data_at").ok(),
                        "age_seconds": row.try_get::<f64, _>("age_seconds").ok(),
                        "timestamp": last_success_at,
                        "assessment": {"status": status, "last_error": row.try_get::<String, _>("last_error").ok()},
                    }))
                }).collect()
    }

    pub async fn list_indicator_views(&self, limit: i64) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT i.id, i.value, i.indicator_type, i.categories, i.confidence, i.source, i.first_seen, i.last_seen, i.expires_at, i.metadata, EXTRACT(EPOCH FROM (NOW() - i.last_seen)) AS age_seconds, r.risk_score, r.trust_score, r.reason, r.recorded_at FROM indicators i LEFT JOIN LATERAL (SELECT risk_score, trust_score, reason, recorded_at FROM risk_history WHERE indicator_id = i.id ORDER BY recorded_at DESC LIMIT 1) r ON TRUE ORDER BY i.last_seen DESC LIMIT $1")
            .bind(limit.clamp(1, 1000)).fetch_all(&self.pool).await?;
        rows.into_iter().map(|row| {
                let risk_score = row.try_get::<i16, _>("risk_score").ok();
                let trust_score = row.try_get::<i16, _>("trust_score").ok();
                let expires_at = row.get::<chrono::DateTime<chrono::Utc>, _>("expires_at");
                Ok(serde_json::json!({
                "id": row.get::<i64, _>("id"),
                "value": row.get::<String, _>("value"),
                "indicator_type": row.get::<String, _>("indicator_type"),
                "categories": row.get::<serde_json::Value, _>("categories"),
                "confidence": row.get::<i16, _>("confidence"),
                "source": row.get::<String, _>("source"),
                "first_seen": row.get::<chrono::DateTime<chrono::Utc>, _>("first_seen"),
                "last_seen": row.get::<chrono::DateTime<chrono::Utc>, _>("last_seen"),
                    "expires_at": expires_at,
                "age_seconds": row.try_get::<f64, _>("age_seconds").ok(),
                "metadata": row.get::<serde_json::Value, _>("metadata"),
                    "risk_score": risk_score,
                    "trust_score": trust_score,
                    "reason": row.try_get::<String, _>("reason").ok(),
                    "assessed_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at").ok(),
                    "timestamp": row.get::<chrono::DateTime<chrono::Utc>, _>("last_seen"),
                    "status": if expires_at > chrono::Utc::now() { "active" } else { "expired" },
                    "assessment": {"risk_score": risk_score, "trust_score": trust_score, "reason": row.try_get::<String, _>("reason").ok()},
                }))
        }).collect()
    }

    pub async fn list_network_views(&self, kind: &str) -> Result<Vec<serde_json::Value>> {
        match kind {
            "asn" => {
                let rows = sqlx::query("SELECT asn, name, organisation, provider, country, registry, prefixes, network_type, reputation, first_seen, last_seen, EXTRACT(EPOCH FROM (NOW() - last_seen)) AS age_seconds FROM asn_records ORDER BY last_seen DESC LIMIT 1000").fetch_all(&self.pool).await?;
                rows.into_iter().map(|row| {
                    let last_seen = row.get::<chrono::DateTime<chrono::Utc>, _>("last_seen");
                    let reputation = row.get::<i16, _>("reputation");
                    Ok(serde_json::json!({
                        "asn": row.get::<String, _>("asn"), "name": row.get::<String, _>("name"), "organisation": row.get::<String, _>("organisation"), "source": row.get::<String, _>("provider"), "country": row.get::<Option<String>, _>("country"), "registry": row.get::<String, _>("registry"), "prefixes": row.get::<serde_json::Value, _>("prefixes"), "network_type": row.get::<Option<String>, _>("network_type"), "reputation": reputation, "first_seen": row.get::<chrono::DateTime<chrono::Utc>, _>("first_seen"), "last_seen": last_seen, "timestamp": last_seen, "age_seconds": row.try_get::<f64, _>("age_seconds").ok(), "status": "known", "confidence": (100 - reputation).clamp(0, 100), "assessment": {"reputation": reputation}
                    }))
                }).collect()
            }
            "bgp" => {
                let rows = sqlx::query("SELECT prefix, origin_asn, previous_asn, new_asn, event_timestamp, source, status, rpki_status, first_seen, last_seen, change, EXTRACT(EPOCH FROM (NOW() - event_timestamp)) AS age_seconds FROM bgp_events ORDER BY event_timestamp DESC LIMIT 1000").fetch_all(&self.pool).await?;
                rows.into_iter().map(|row| {
                    let status = row.get::<String, _>("status");
                    let timestamp = row.get::<chrono::DateTime<chrono::Utc>, _>("event_timestamp");
                    let confidence = if status == "Anomalous" { 40 } else { 80 };
                    Ok(serde_json::json!({
                        "prefix": row.get::<String, _>("prefix"), "origin_asn": row.get::<String, _>("origin_asn"), "previous_asn": row.get::<Option<String>, _>("previous_asn"), "new_asn": row.get::<Option<String>, _>("new_asn"), "timestamp": timestamp, "source": row.get::<String, _>("source"), "status": status, "rpki_status": row.get::<String, _>("rpki_status"), "change": row.get::<Option<String>, _>("change"), "age_seconds": row.try_get::<f64, _>("age_seconds").ok(), "confidence": confidence, "assessment": {"status": status, "rpki_status": row.get::<String, _>("rpki_status")}
                    }))
                }).collect()
            }
            "rpki" => {
                let rows = sqlx::query("SELECT prefix, asn, status, event_timestamp, source, EXTRACT(EPOCH FROM (NOW() - event_timestamp)) AS age_seconds FROM rpki_records ORDER BY event_timestamp DESC LIMIT 1000").fetch_all(&self.pool).await?;
                rows.into_iter().map(|row| {
                    let status = row.get::<String, _>("status");
                    let timestamp = row.get::<chrono::DateTime<chrono::Utc>, _>("event_timestamp");
                    let confidence = match status.as_str() { "Valid" => 100, "Invalid" => 90, _ => 50 };
                    Ok(serde_json::json!({
                        "prefix": row.get::<String, _>("prefix"), "asn": row.get::<String, _>("asn"), "status": status, "timestamp": timestamp, "source": row.get::<String, _>("source"), "age_seconds": row.try_get::<f64, _>("age_seconds").ok(), "confidence": confidence, "assessment": {"status": status, "trust_bonus": if status == "Valid" { -10 } else if status == "Invalid" { 10 } else { 0 }}
                    }))
                }).collect()
            }
            "trust" => {
                let rows = sqlx::query("SELECT id, name, network_type, identifier, networks, node_identities, device_tags, groups_json, status, created_at, verified_at, EXTRACT(EPOCH FROM (NOW() - COALESCE(verified_at, created_at))) AS age_seconds FROM trusted_networks ORDER BY created_at DESC LIMIT 1000").fetch_all(&self.pool).await?;
                rows.into_iter().map(|row| {
                    let status = row.get::<String, _>("status");
                    let created_at = row.get::<chrono::DateTime<chrono::Utc>, _>("created_at");
                    let verified_at = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("verified_at");
                    let trust_score = if status == "Verified" { -40 } else { 0 };
                    Ok(serde_json::json!({
                        "id": row.get::<uuid::Uuid, _>("id"), "name": row.get::<String, _>("name"), "type": row.get::<String, _>("network_type"), "identifier": row.get::<String, _>("identifier"), "source": "trusted_registry", "networks": row.get::<serde_json::Value, _>("networks"), "node_identities": row.get::<serde_json::Value, _>("node_identities"), "device_tags": row.get::<serde_json::Value, _>("device_tags"), "groups": row.get::<serde_json::Value, _>("groups_json"), "status": status, "created_at": created_at, "verified_at": verified_at, "timestamp": verified_at.unwrap_or(created_at), "age_seconds": row.try_get::<f64, _>("age_seconds").ok(), "confidence": if status == "Verified" { 100 } else { 0 }, "trust_score": trust_score, "assessment": {"status": status, "trust_score": trust_score}
                    }))
                }).collect()
            }
            _ => anyhow::bail!("unknown network view: {kind}"),
        }
    }

    pub async fn metrics_text(&self) -> Result<String> {
        let providers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE event_type = 'provider_sync'",
        )
        .fetch_one(&self.pool)
        .await?;
        let errors: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE event_type = 'provider_error'",
        )
        .fetch_one(&self.pool)
        .await?;
        let indicators: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM indicators")
            .fetch_one(&self.pool)
            .await?;
        let risks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM risk_history")
            .fetch_one(&self.pool)
            .await?;
        let bgp: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE event_type = 'bgp_change'")
                .fetch_one(&self.pool)
                .await?;
        let worker_up: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runtime_status WHERE component = 'worker' AND state = 'running' AND last_heartbeat_at > NOW() - INTERVAL '2 minutes'")
            .fetch_one(&self.pool).await?;
        let provider_rows = sqlx::query("SELECT p.id, COALESCE(s.state, 'never') AS state FROM providers p LEFT JOIN provider_status s ON s.provider_id = p.id ORDER BY p.id")
            .fetch_all(&self.pool).await?;
        let provider_status = provider_rows
            .into_iter()
            .map(|row| {
                let provider = row
                    .get::<String, _>("id")
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"");
                let state = row.get::<String, _>("state");
                let value = if matches!(state.as_str(), "ok" | "running") {
                    1
                } else {
                    0
                };
                format!("clawforge_provider_sync_status{{provider=\"{provider}\"}} {value}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok(format!("# TYPE clawforge_provider_sync_total counter\nclawforge_provider_sync_total {providers}\n# TYPE clawforge_provider_errors_total counter\nclawforge_provider_errors_total {errors}\n# TYPE clawforge_indicators_total gauge\nclawforge_indicators_total {indicators}\n# TYPE clawforge_risk_events_total counter\nclawforge_risk_events_total {risks}\n# TYPE clawforge_bgp_changes_total counter\nclawforge_bgp_changes_total {bgp}\n# TYPE clawforge_worker_up gauge\nclawforge_worker_up {worker_up}\n# TYPE clawforge_database_up gauge\nclawforge_database_up 1\n# TYPE clawforge_provider_sync_status gauge\n{provider_status}\n"))
    }

    pub async fn set_runtime_status(
        &self,
        component: &str,
        state: &str,
        last_error: Option<&str>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO runtime_status (component, state, version, last_started_at, last_heartbeat_at, last_error, updated_at) VALUES ($1,$2,$3,CASE WHEN $2 = 'running' THEN NOW() ELSE NULL END,CASE WHEN $2 = 'running' THEN NOW() ELSE NULL END,$4,NOW()) ON CONFLICT (component) DO UPDATE SET state=EXCLUDED.state, version=EXCLUDED.version, last_started_at=CASE WHEN EXCLUDED.state = 'running' THEN NOW() ELSE runtime_status.last_started_at END, last_heartbeat_at=CASE WHEN EXCLUDED.state = 'running' THEN NOW() ELSE runtime_status.last_heartbeat_at END, last_error=EXCLUDED.last_error, updated_at=NOW()")
            .bind(component)
            .bind(state)
            .bind(env!("CARGO_PKG_VERSION"))
            .bind(last_error)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn upsert_provider(&self, provider: &Provider) -> Result<()> {
        sqlx::query("INSERT INTO providers (id, name, source, interval_seconds, confidence, enabled) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, source=EXCLUDED.source, confidence=EXCLUDED.confidence, updated_at=NOW()")
            .bind(&provider.id).bind(&provider.name).bind(&provider.source)
            .bind(provider.interval_seconds).bind(provider.confidence as i16).bind(provider.enabled)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn provider_enabled(&self, provider_id: &str) -> Result<bool> {
        Ok(
            sqlx::query_scalar("SELECT enabled FROM providers WHERE id=$1")
                .bind(provider_id)
                .fetch_optional(&self.pool)
                .await?
                .unwrap_or(false),
        )
    }

    pub async fn provider_interval_seconds(&self, provider_id: &str) -> Result<Option<i64>> {
        Ok(
            sqlx::query_scalar("SELECT interval_seconds FROM providers WHERE id=$1")
                .bind(provider_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn provider_started(&self, provider_id: &str) -> Result<()> {
        sqlx::query("INSERT INTO provider_status (provider_id, state, last_started_at, updated_at) VALUES ($1,'running',NOW(),NOW()) ON CONFLICT (provider_id) DO UPDATE SET state='running', last_started_at=NOW(), updated_at=NOW()")
            .bind(provider_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn provider_succeeded(
        &self,
        provider_id: &str,
        next_run: chrono::DateTime<chrono::Utc>,
        indicator_count: i32,
        sync_duration_ms: i64,
        last_data_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO provider_status (provider_id, state, last_success_at, next_run_at, consecutive_failures, last_error, indicator_count, sync_duration_ms, last_data_at, updated_at) VALUES ($1,'ok',NOW(),$2,0,NULL,$3,$4,$5,NOW()) ON CONFLICT (provider_id) DO UPDATE SET state='ok', last_success_at=NOW(), next_run_at=$2, consecutive_failures=0, last_error=NULL, indicator_count=$3, sync_duration_ms=$4, last_data_at=$5, updated_at=NOW()")
            .bind(provider_id).bind(next_run).bind(indicator_count).bind(sync_duration_ms).bind(last_data_at).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn provider_failed(
        &self,
        provider_id: &str,
        error: &str,
        next_run: chrono::DateTime<chrono::Utc>,
        indicator_count: i32,
        sync_duration_ms: i64,
    ) -> Result<()> {
        sqlx::query("INSERT INTO provider_status (provider_id, state, next_run_at, consecutive_failures, last_error, indicator_count, sync_duration_ms, updated_at) VALUES ($1,'error',$2,1,$3,$4,$5,NOW()) ON CONFLICT (provider_id) DO UPDATE SET state='error', next_run_at=$2, consecutive_failures=provider_status.consecutive_failures+1, last_error=$3, indicator_count=$4, sync_duration_ms=$5, updated_at=NOW()")
            .bind(provider_id).bind(next_run).bind(error).bind(indicator_count).bind(sync_duration_ms).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn expire_indicators(&self, now: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let result = sqlx::query("DELETE FROM indicators WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn latest_indicator_at(
        &self,
        source: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let value = sqlx::query_scalar("SELECT MAX(last_seen) FROM indicators WHERE source = $1")
            .bind(source)
            .fetch_one(&self.pool)
            .await?;
        Ok(value)
    }

    pub async fn upsert_indicator(&self, indicator: &Indicator) -> Result<i64> {
        let row = sqlx::query("INSERT INTO indicators (value, indicator_type, categories, confidence, source, first_seen, last_seen, expires_at, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (value, indicator_type, source) DO UPDATE SET categories=EXCLUDED.categories, confidence=EXCLUDED.confidence, last_seen=EXCLUDED.last_seen, expires_at=EXCLUDED.expires_at, metadata=EXCLUDED.metadata RETURNING id")
            .bind(&indicator.value)
            .bind(format!("{:?}", indicator.indicator_type))
            .bind(serde_json::to_value(&indicator.categories)?)
            .bind(indicator.confidence as i16)
            .bind(&indicator.source)
            .bind(indicator.first_seen)
            .bind(indicator.last_seen)
            .bind(indicator.expires_at)
            .bind(&indicator.metadata)
            .fetch_one(&self.pool).await?;
        Ok(row.get("id"))
    }

    pub async fn record_risk_event(
        &self,
        indicator_id: i64,
        indicator: &Indicator,
        score_change: i16,
        risk_score: u8,
        trust_score: u8,
        reason: &str,
    ) -> Result<()> {
        sqlx::query("INSERT INTO risk_history (indicator_id, indicator, source, score_change, reason, risk_score, trust_score) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(indicator_id).bind(&indicator.value).bind(&indicator.source).bind(score_change)
            .bind(reason).bind(risk_score as i16).bind(trust_score as i16)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn upsert_asn_record(&self, record: &AsnRecord) -> Result<()> {
        sqlx::query("INSERT INTO asn_records (asn, name, organisation, provider, country, registry, prefixes, network_type, reputation, first_seen, last_seen) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (asn) DO UPDATE SET name=EXCLUDED.name, organisation=EXCLUDED.organisation, provider=EXCLUDED.provider, country=EXCLUDED.country, registry=EXCLUDED.registry, prefixes=EXCLUDED.prefixes, network_type=EXCLUDED.network_type, reputation=EXCLUDED.reputation, first_seen=LEAST(asn_records.first_seen, EXCLUDED.first_seen), last_seen=GREATEST(asn_records.last_seen, EXCLUDED.last_seen)")
            .bind(&record.asn)
            .bind(&record.name)
            .bind(&record.organisation)
            .bind(&record.provider)
            .bind(&record.country)
            .bind(&record.registry)
            .bind(serde_json::to_value(&record.prefixes)?)
            .bind(&record.network_type)
            .bind(record.reputation as i16)
            .bind(record.first_seen)
            .bind(record.last_seen)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn upsert_bgp_event(&self, event: &BgpEvent) -> Result<()> {
        let fingerprint = format!(
            "{}|{}|{}|{}",
            event.prefix,
            event.previous_asn.as_deref().unwrap_or_default(),
            event.new_asn.as_deref().unwrap_or(&event.origin_asn),
            event.source
        );
        sqlx::query("INSERT INTO bgp_events (prefix, origin_asn, previous_asn, new_asn, event_timestamp, source, status, rpki_status, first_seen, last_seen, change, fingerprint) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$5,$5,$9,$10) ON CONFLICT (fingerprint) DO UPDATE SET origin_asn=EXCLUDED.origin_asn, previous_asn=EXCLUDED.previous_asn, new_asn=EXCLUDED.new_asn, event_timestamp=GREATEST(bgp_events.event_timestamp, EXCLUDED.event_timestamp), status=EXCLUDED.status, rpki_status=EXCLUDED.rpki_status, last_seen=GREATEST(bgp_events.last_seen, EXCLUDED.last_seen), change=EXCLUDED.change")
            .bind(&event.prefix)
            .bind(&event.origin_asn)
            .bind(&event.previous_asn)
            .bind(&event.new_asn)
            .bind(event.timestamp)
            .bind(&event.source)
            .bind(format!("{:?}", event.status))
            .bind(format!("{:?}", event.rpki_status))
            .bind(&event.change)
            .bind(fingerprint)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn upsert_rpki_record(&self, record: &RpkiRecord) -> Result<()> {
        sqlx::query("INSERT INTO rpki_records (prefix, asn, status, event_timestamp, source) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (prefix, asn, status, event_timestamp, source) DO NOTHING")
            .bind(&record.prefix)
            .bind(&record.asn)
            .bind(format!("{:?}", record.status))
            .bind(record.timestamp)
            .bind(&record.source)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn admin_user_count(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM admin_users")
            .fetch_one(&self.pool)
            .await?)
    }

    pub async fn create_admin_user(
        &self,
        username: &str,
        role: &str,
        password_hash: &str,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO admin_users (id, username, role, password_hash) VALUES ($1,$2,$3,$4)",
        )
        .bind(id)
        .bind(username)
        .bind(role)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn find_admin_by_username(&self, username: &str) -> Result<Option<AdminUser>> {
        let row = sqlx::query(
            "SELECT id, username, role, password_hash, enabled FROM admin_users WHERE username=$1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| AdminUser {
            id: r.get("id"),
            username: r.get("username"),
            role: r.get("role"),
            password_hash: r.get("password_hash"),
            enabled: r.get("enabled"),
        }))
    }

    pub async fn authenticate_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<AdminPrincipal>> {
        let row = sqlx::query("SELECT u.id, u.username, u.role, 'api_token' AS auth_kind, t.id AS credential_id FROM api_tokens t JOIN admin_users u ON u.id=t.user_id WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > NOW()) AND u.enabled UNION ALL SELECT u.id, u.username, u.role, 'session' AS auth_kind, s.id AS credential_id FROM admin_sessions s JOIN admin_users u ON u.id=s.user_id WHERE s.session_hash=$1 AND s.revoked_at IS NULL AND s.expires_at > NOW() AND u.enabled LIMIT 1")
            .bind(token_hash).fetch_optional(&self.pool).await?;
        let Some(row) = row else { return Ok(None) };
        let principal = AdminPrincipal {
            id: row.get("id"),
            username: row.get("username"),
            role: row.get("role"),
            auth_kind: row.get("auth_kind"),
            credential_id: row.get("credential_id"),
        };
        if principal.auth_kind == "api_token" {
            sqlx::query("UPDATE api_tokens SET last_used_at=NOW() WHERE id=$1")
                .bind(principal.credential_id)
                .execute(&self.pool)
                .await?;
        } else {
            sqlx::query("UPDATE admin_sessions SET last_seen_at=NOW() WHERE id=$1")
                .bind(principal.credential_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(Some(principal))
    }

    pub async fn mark_login(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE admin_users SET last_login_at=NOW(), updated_at=NOW() WHERE id=$1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_session(
        &self,
        user_id: Uuid,
        session_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO admin_sessions (id,user_id,session_hash,expires_at,last_seen_at) VALUES ($1,$2,$3,$4,NOW())")
            .bind(id).bind(user_id).bind(session_hash).bind(expires_at).execute(&self.pool).await?;
        Ok(id)
    }

    pub async fn revoke_credential(&self, principal: &AdminPrincipal) -> Result<()> {
        let table = if principal.auth_kind == "api_token" {
            "api_tokens"
        } else {
            "admin_sessions"
        };
        let query = format!("UPDATE {table} SET revoked_at=NOW() WHERE id=$1");
        sqlx::query(&query)
            .bind(principal.credential_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_api_token(
        &self,
        user_id: Uuid,
        token_hash: &str,
        prefix: &str,
        name: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO api_tokens (id,user_id,token_hash,token_prefix,name,expires_at) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(id).bind(user_id).bind(token_hash).bind(prefix).bind(name).bind(expires_at).execute(&self.pool).await?;
        Ok(id)
    }

    pub async fn revoke_api_token(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET revoked_at=NOW() WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_audit_events(
        &self,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        source: Option<&str>,
        severity: Option<&str>,
        actor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT id, actor, action, resource, details, event_type, source, severity, reason, recorded_at FROM audit_events WHERE ($1::timestamptz IS NULL OR recorded_at >= $1) AND ($2::timestamptz IS NULL OR recorded_at <= $2) AND ($3::text IS NULL OR source=$3) AND ($4::text IS NULL OR severity=$4) AND ($5::text IS NULL OR actor=$5) ORDER BY recorded_at DESC LIMIT $6")
            .bind(from).bind(to).bind(source).bind(severity).bind(actor).bind(limit.clamp(1, 1000)).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({
            "id": r.get::<i64,_>("id"), "actor": r.get::<String,_>("actor"), "action": r.get::<String,_>("action"),
            "resource": r.get::<String,_>("resource"), "details": r.get::<serde_json::Value,_>("details"),
            "event_type": r.get::<String,_>("event_type"), "source": r.get::<String,_>("source"),
            "severity": r.get::<String,_>("severity"), "reason": r.get::<String,_>("reason"),
            "recorded_at": r.get::<chrono::DateTime<chrono::Utc>,_>("recorded_at")
        })).collect())
    }

    pub async fn update_provider_admin(
        &self,
        id: &str,
        enabled: Option<bool>,
        interval_seconds: Option<i64>,
    ) -> Result<()> {
        let result = sqlx::query("UPDATE providers SET enabled=COALESCE($2,enabled), interval_seconds=COALESCE($3,interval_seconds), updated_at=NOW() WHERE id=$1")
            .bind(id).bind(enabled).bind(interval_seconds).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            anyhow::bail!("provider not found");
        }
        Ok(())
    }

    pub async fn update_trusted_network_status(&self, id: Uuid, status: &str) -> Result<()> {
        let result = sqlx::query("UPDATE trusted_networks SET status=$2, verified_at=CASE WHEN $2='Verified' THEN COALESCE(verified_at,NOW()) ELSE verified_at END WHERE id=$1")
            .bind(id).bind(status).execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            anyhow::bail!("trusted network not found");
        }
        Ok(())
    }

    pub async fn queue_provider_sync(&self, provider_id: &str, requested_by: Uuid) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO provider_sync_requests (id,provider_id,requested_by,status) VALUES ($1,$2,$3,'pending')")
            .bind(id).bind(provider_id).bind(requested_by).execute(&self.pool).await?;
        Ok(id)
    }

    pub async fn claim_provider_sync_requests(
        &self,
        limit: i64,
    ) -> Result<Vec<ProviderSyncRequest>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query("SELECT id,provider_id FROM provider_sync_requests WHERE status='pending' ORDER BY requested_at FOR UPDATE SKIP LOCKED LIMIT $1")
            .bind(limit.clamp(1, 50)).fetch_all(&mut *tx).await?;
        let mut requests = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get("id");
            sqlx::query(
                "UPDATE provider_sync_requests SET status='running', started_at=NOW() WHERE id=$1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            requests.push(ProviderSyncRequest {
                id,
                provider_id: row.get("provider_id"),
            });
        }
        tx.commit().await?;
        Ok(requests)
    }

    pub async fn finish_provider_sync_request(
        &self,
        id: Uuid,
        success: bool,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE provider_sync_requests SET status=$2, finished_at=NOW(), error=$3 WHERE id=$1",
        )
        .bind(id)
        .bind(if success { "completed" } else { "failed" })
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_config(&self) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT key,value,updated_at FROM admin_config ORDER BY key")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({"key":r.get::<String,_>("key"),"value":r.get::<serde_json::Value,_>("value"),"updated_at":r.get::<chrono::DateTime<chrono::Utc>,_>("updated_at")})).collect())
    }

    pub async fn set_config(
        &self,
        key: &str,
        value: serde_json::Value,
        user_id: Uuid,
    ) -> Result<()> {
        sqlx::query("INSERT INTO admin_config (key,value,updated_by,updated_at) VALUES ($1,$2,$3,NOW()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=NOW()")
            .bind(key).bind(value).bind(user_id).execute(&self.pool).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AdminUser {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub password_hash: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub auth_kind: String,
    pub credential_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct ProviderSyncRequest {
    pub id: Uuid,
    pub provider_id: String,
}

fn normalize_incident_severity(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    }
    .to_string()
}

fn max_incident_severity(current: &str, incoming: &str) -> String {
    let rank = |value: &str| match value {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    };
    if rank(incoming) > rank(current) {
        incoming.to_string()
    } else {
        current.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct MigrationStatus {
    pub applied: usize,
    pub expected: usize,
    pub latest: i64,
    pub expected_latest: i64,
    pub current: bool,
}

pub fn database_url_from_env() -> Result<String> {
    if let Ok(url) = env::var("DATABASE_URL") {
        if !url.trim().is_empty() {
            return Ok(url);
        }
    }
    let path = env::var("DATABASE_URL_FILE")
        .context("DATABASE_URL or DATABASE_URL_FILE must be configured")?;
    let url = fs::read_to_string(path).context("read DATABASE_URL_FILE")?;
    if url.trim().is_empty() {
        anyhow::bail!("DATABASE_URL_FILE is empty");
    }
    Ok(url.trim().to_string())
}

#[async_trait]
impl IndicatorSink for PostgresStore {
    async fn upsert_indicators(&self, indicators: &[Indicator]) -> Result<usize, ProviderError> {
        let mut count = 0;
        for indicator in indicators {
            self.upsert_indicator(indicator).await.map_err(|error| {
                ProviderError::Validation(format!("indicator storage failed: {error}"))
            })?;
            count += 1;
        }
        Ok(count)
    }
}

#[async_trait]
impl NetworkSink for PostgresStore {
    async fn upsert_asn_records(&self, records: &[AsnRecord]) -> Result<usize, ProviderError> {
        for record in records {
            self.upsert_asn_record(record).await.map_err(|error| {
                ProviderError::Validation(format!("ASN storage failed: {error}"))
            })?;
        }
        Ok(records.len())
    }

    async fn upsert_bgp_events(&self, events: &[BgpEvent]) -> Result<usize, ProviderError> {
        for event in events {
            self.upsert_bgp_event(event).await.map_err(|error| {
                ProviderError::Validation(format!("BGP storage failed: {error}"))
            })?;
        }
        Ok(events.len())
    }

    async fn upsert_rpki_records(&self, records: &[RpkiRecord]) -> Result<usize, ProviderError> {
        for record in records {
            self.upsert_rpki_record(record).await.map_err(|error| {
                ProviderError::Validation(format!("RPKI storage failed: {error}"))
            })?;
        }
        Ok(records.len())
    }
}
