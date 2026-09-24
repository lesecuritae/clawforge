//! Storage for `clawforge-security-engine`'s persisted, versioned
//! assessments (roadmap phase 4, "Assessments, Evidence-Referenzen und
//! Engine-/Regelversion persistieren"). A rule computes an assessment for
//! one deterministic tumbling-window bucket of one resource; `dedupe_key`
//! is built from exactly (rule_id, rule_version, resource, bucket_start) by
//! the caller, so replaying the same events through the same rule version
//! can only ever upsert the same row - never create a duplicate. See
//! `security-engine/src/main.rs` for why a fixed bucket, not a sliding
//! window, is what makes this replay-deterministic.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::PostgresStore;

pub struct SecurityAssessmentUpsert<'a> {
    pub rule_id: &'a str,
    pub rule_version: &'a str,
    pub engine_version: &'a str,
    pub dedupe_key: &'a str,
    pub resource: &'a str,
    pub severity: &'a str,
    pub confidence: i16,
    pub summary: &'a str,
    pub event_count: i32,
    pub window_seconds: i32,
    pub bucket_start: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_ids: &'a [Uuid],
    /// The best threat-intel hit (highest confidence, ties broken by most
    /// recently confirmed - see `lookup_ip_reputation`'s own doc comment)
    /// among this bucket's events, if any - a second, independent
    /// evidence source alongside the behavioral rule itself. See migration
    /// `0035`'s own comment for why a hit is what makes `Block` reachable
    /// for the first time in `clawforge-policy-engine`, and migration
    /// `0044`'s comment for why the detail (not just a boolean) matters:
    /// roadmap phase 8's exit gate needs the actual source/confidence/age
    /// to judge staleness, not a bare "true".
    /// `persist_security_assessment` derives the stored
    /// `threat_intel_corroborated` boolean from this directly (`is_some`),
    /// so a caller never passes the two separately and they can never
    /// disagree.
    pub threat_intel: Option<crate::IpReputationHit>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityAssessment {
    pub id: Uuid,
    pub rule_id: String,
    pub rule_version: String,
    pub resource: String,
    pub severity: String,
    pub confidence: i16,
    pub summary: String,
    pub event_count: i32,
    pub bucket_start: DateTime<Utc>,
    pub incident_id: Option<Uuid>,
    pub threat_intel_corroborated: bool,
    pub threat_intel: Option<crate::IpReputationHit>,
}

impl PostgresStore {
    /// Every canonical event of `event_type` sharing `correlation_id`
    /// (already the pseudonymized resource by the time it reached the
    /// event bus - see `record_security_event`) within `[from, to)` -
    /// exactly the tumbling-window bucket a count-threshold rule (SSH
    /// bruteforce, port scan, ...) needs to decide whether it fires, and
    /// to build its evidence references. Ascending by `occurred_at` so the
    /// first/last elements are the bucket's first_seen/last_seen directly.
    pub async fn list_events_for_bucket(
        &self,
        event_type: &str,
        correlation_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<(Uuid, DateTime<Utc>)>> {
        let rows = sqlx::query(
            "SELECT event_id, occurred_at FROM events \
             WHERE event_type=$1 AND correlation_id=$2 AND occurred_at >= $3 AND occurred_at < $4 \
             ORDER BY occurred_at ASC LIMIT 1000",
        )
        .bind(event_type)
        .bind(correlation_id)
        .bind(from)
        .bind(to)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("event_id"), row.get("occurred_at")))
            .collect())
    }

    /// The best threat-intel hit (highest confidence, ties broken by most
    /// recently confirmed - same ordering `lookup_ip_reputation` itself
    /// uses, so a bucket spanning several events never picks a *worse*
    /// hit than the single-IP lookup would have) among any event of
    /// `event_type` sharing `correlation_id` within `[from, to)`
    /// (`events.metadata->>'threat_intel_hit'`/`threat_intel_source'`/
    /// `threat_intel_confidence'`/`threat_intel_last_seen'`, set by
    /// `record_security_event`/`lookup_ip_reputation` - never the raw IP
    /// itself). `None` if no event in the bucket had a hit. A rule calls
    /// this once per bucket alongside `list_events_for_bucket`(`_with_field`)
    /// to build the assessment's `threat_intel` detail (roadmap phase 8:
    /// this is what makes the corroboration explainable, not just a bare
    /// boolean).
    pub async fn bucket_threat_intel_hit_details(
        &self,
        event_type: &str,
        correlation_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Option<crate::IpReputationHit>> {
        let row = sqlx::query(
            "SELECT metadata->>'threat_intel_source' AS source, \
                    (metadata->>'threat_intel_confidence')::smallint AS confidence, \
                    (metadata->>'threat_intel_last_seen')::timestamptz AS last_seen \
             FROM events \
             WHERE event_type=$1 AND correlation_id=$2 AND occurred_at >= $3 AND occurred_at < $4 \
               AND metadata->>'threat_intel_hit'='true' \
             ORDER BY (metadata->>'threat_intel_confidence')::smallint DESC, \
                      (metadata->>'threat_intel_last_seen')::timestamptz DESC \
             LIMIT 1",
        )
        .bind(event_type)
        .bind(correlation_id)
        .bind(from)
        .bind(to)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|row| crate::IpReputationHit {
            source: row.get("source"),
            confidence: row.get("confidence"),
            last_seen: row.get("last_seen"),
        }))
    }

    /// Whether some *other* rule (a different `rule_id`) has also produced
    /// an assessment for this same `resource` recently (`bucket_start >=
    /// since`) - independent behavioral corroboration, the second kind
    /// alongside `threat_intel_corroborated`: a source that first tripped
    /// `ssh_bruteforce` and later, separately, `http_scan` is corroborated
    /// by two independent detections even with no external reputation hit
    /// involved in either one. Used by `clawforge-policy-engine` to decide
    /// `evidence_sources`, not by `clawforge-security-engine` itself - a
    /// rule's own assessment never needs to know about a different rule.
    pub async fn resource_has_other_rule_assessment(
        &self,
        resource: &str,
        exclude_rule_id: &str,
        since: DateTime<Utc>,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM security_assessments \
             WHERE resource=$1 AND rule_id<>$2 AND bucket_start>=$3)",
        )
        .bind(resource)
        .bind(exclude_rule_id)
        .bind(since)
        .fetch_one(self.pool())
        .await?)
    }

    /// Same bucket membership as `list_events_for_bucket`, plus one evidence
    /// field's value per event (`payload->>field`) - what a distinct-value
    /// rule (a scan: many different paths probed, not just many hits) needs
    /// to count `COUNT(DISTINCT ...)` over in Rust, without ever needing a
    /// second, field-specific storage method for each such rule.
    pub async fn list_events_for_bucket_with_field(
        &self,
        event_type: &str,
        correlation_id: &str,
        field: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<(Uuid, DateTime<Utc>, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT event_id, occurred_at, payload->>$5 AS field_value FROM events \
             WHERE event_type=$1 AND correlation_id=$2 AND occurred_at >= $3 AND occurred_at < $4 \
             ORDER BY occurred_at ASC LIMIT 1000",
        )
        .bind(event_type)
        .bind(correlation_id)
        .bind(from)
        .bind(to)
        .bind(field)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get("event_id"),
                    row.get("occurred_at"),
                    row.get("field_value"),
                )
            })
            .collect())
    }

    /// Upsert one assessment and its evidence references. Idempotent by
    /// `dedupe_key`: a repeat call with the same key (a replay, or the same
    /// bucket recomputed as later events in it are processed) updates the
    /// existing row in place rather than creating a second one, and always
    /// returns that row's stable id - so a caller that also links this
    /// assessment to an incident candidate keyed off the returned id never
    /// sees it change between calls for the same bucket.
    pub async fn persist_security_assessment(
        &self,
        request: SecurityAssessmentUpsert<'_>,
    ) -> Result<Uuid> {
        let threat_intel_corroborated = request.threat_intel.is_some();
        let threat_intel_source = request.threat_intel.as_ref().map(|hit| hit.source.as_str());
        let threat_intel_confidence = request.threat_intel.as_ref().map(|hit| hit.confidence);
        let threat_intel_indicator_last_seen =
            request.threat_intel.as_ref().map(|hit| hit.last_seen);
        let mut tx = self.pool().begin().await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO security_assessments \
             (id,rule_id,rule_version,engine_version,dedupe_key,resource,severity,confidence,\
              summary,event_count,window_seconds,bucket_start,first_seen,last_seen,\
              threat_intel_corroborated,threat_intel_source,threat_intel_confidence,\
              threat_intel_indicator_last_seen) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) \
             ON CONFLICT (dedupe_key) DO UPDATE SET \
               severity=EXCLUDED.severity, confidence=EXCLUDED.confidence, \
               summary=EXCLUDED.summary, event_count=EXCLUDED.event_count, \
               last_seen=EXCLUDED.last_seen, \
               threat_intel_corroborated=EXCLUDED.threat_intel_corroborated, \
               threat_intel_source=EXCLUDED.threat_intel_source, \
               threat_intel_confidence=EXCLUDED.threat_intel_confidence, \
               threat_intel_indicator_last_seen=EXCLUDED.threat_intel_indicator_last_seen, \
               updated_at=NOW() \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(request.rule_id)
        .bind(request.rule_version)
        .bind(request.engine_version)
        .bind(request.dedupe_key)
        .bind(request.resource)
        .bind(request.severity)
        .bind(request.confidence)
        .bind(request.summary)
        .bind(request.event_count)
        .bind(request.window_seconds)
        .bind(request.bucket_start)
        .bind(request.first_seen)
        .bind(request.last_seen)
        .bind(threat_intel_corroborated)
        .bind(threat_intel_source)
        .bind(threat_intel_confidence)
        .bind(threat_intel_indicator_last_seen)
        .fetch_one(&mut *tx)
        .await?;
        for event_id in request.event_ids {
            sqlx::query(
                "INSERT INTO security_assessment_events (assessment_id,event_id) \
                 VALUES ($1,$2) ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(event_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(id)
    }

    /// Link an assessment to the incident it contributed to - set once, the
    /// first time an assessment's candidate is promoted; a later call for
    /// the same assessment (a replay, or the same bucket recomputed) is a
    /// harmless no-op rather than overwriting an already-set link.
    pub async fn link_security_assessment_incident(
        &self,
        assessment_id: Uuid,
        incident_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE security_assessments SET incident_id=$2, updated_at=NOW() \
             WHERE id=$1 AND incident_id IS NULL",
        )
        .bind(assessment_id)
        .bind(incident_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// `incidents.id` is a freshly minted uuid distinct from
    /// `incident_candidates.id` (`promote_incident_candidates` never reuses
    /// the candidate's own id for the incident row) - a caller holding a
    /// candidate id from `persist_correlation` looks the real incident id
    /// up through this, and gets `None` back for a candidate that has not
    /// been promoted yet.
    pub async fn get_incident_id_for_candidate(&self, candidate_id: Uuid) -> Result<Option<Uuid>> {
        Ok(
            sqlx::query_scalar("SELECT id FROM incidents WHERE candidate_id=$1")
                .bind(candidate_id)
                .fetch_optional(self.pool())
                .await?,
        )
    }

    pub async fn list_security_assessments(&self, limit: i64) -> Result<Vec<SecurityAssessment>> {
        let rows = sqlx::query(
            "SELECT id,rule_id,rule_version,resource,confidence,severity,summary,event_count,\
             bucket_start,incident_id,threat_intel_corroborated,threat_intel_source,\
             threat_intel_confidence,threat_intel_indicator_last_seen FROM security_assessments \
             ORDER BY bucket_start DESC LIMIT $1",
        )
        .bind(limit.clamp(1, 500))
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let threat_intel_source: Option<String> = row.get("threat_intel_source");
                let threat_intel = threat_intel_source.map(|source| crate::IpReputationHit {
                    source,
                    confidence: row.get("threat_intel_confidence"),
                    last_seen: row.get("threat_intel_indicator_last_seen"),
                });
                SecurityAssessment {
                    id: row.get("id"),
                    rule_id: row.get("rule_id"),
                    rule_version: row.get("rule_version"),
                    resource: row.get("resource"),
                    severity: row.get("severity"),
                    confidence: row.get("confidence"),
                    summary: row.get("summary"),
                    event_count: row.get("event_count"),
                    bucket_start: row.get("bucket_start"),
                    incident_id: row.get("incident_id"),
                    threat_intel_corroborated: row.get("threat_intel_corroborated"),
                    threat_intel,
                }
            })
            .collect())
    }
}
