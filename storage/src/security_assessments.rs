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

/// Which events of a type an assessment bucket may count, by the HTTP status
/// class in the payload. Events without a numeric status (SSH, ...) always
/// pass `Any` and `ClientAttributable`; `ServerError` requires a 5xx status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStatusFilter {
    Any,
    ClientAttributable,
    ServerError,
}

impl EventStatusFilter {
    fn predicate(self) -> &'static str {
        match self {
            Self::Any => "TRUE",
            Self::ClientAttributable => {
                "COALESCE((CASE WHEN payload->>'status_code' ~ '^[0-9]{3}$' THEN (payload->>'status_code')::int END) < 500, TRUE)"
            }
            Self::ServerError => {
                "COALESCE((CASE WHEN payload->>'status_code' ~ '^[0-9]{3}$' THEN (payload->>'status_code')::int END) >= 500, FALSE)"
            }
        }
    }
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
        self.list_events_for_bucket_filtered(
            event_type,
            correlation_id,
            from,
            to,
            EventStatusFilter::Any,
        )
        .await
    }

    /// Same membership as [`Self::list_events_for_bucket`], optionally
    /// restricted by the HTTP status class carried in the event payload. A
    /// 5xx answer is the server's own failure; counting it as client
    /// behaviour would turn every backend outage into an "abusive client".
    pub async fn list_events_for_bucket_filtered(
        &self,
        event_type: &str,
        correlation_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        status: EventStatusFilter,
    ) -> Result<Vec<(Uuid, DateTime<Utc>)>> {
        self.list_events_for_bucket_limited(event_type, correlation_id, from, to, status, 1000)
            .await
    }

    /// Same membership, oldest first, at most `limit` events (1..=1000). A long-window rule
    /// only needs to know that its threshold is met and how far over it is: capping the
    /// membership keeps the per-event cost and the evidence written per firing bounded no
    /// matter how busy a source is.
    pub async fn list_events_for_bucket_limited(
        &self,
        event_type: &str,
        correlation_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        status: EventStatusFilter,
        limit: i64,
    ) -> Result<Vec<(Uuid, DateTime<Utc>)>> {
        let rows = sqlx::query(&format!(
            "SELECT event_id, occurred_at FROM events \
             WHERE event_type=$1 AND correlation_id=$2 AND occurred_at >= $3 AND occurred_at < $4 \
             AND {} ORDER BY occurred_at ASC LIMIT $5",
            status.predicate()
        ))
        .bind(event_type)
        .bind(correlation_id)
        .bind(from)
        .bind(to)
        .bind(limit.clamp(1, 1000))
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("event_id"), row.get("occurred_at")))
            .collect())
    }

    /// Whether `resource` already has an assessment of `rule_id` whose window overlaps
    /// `[from, to)`. A slow, long-window rule uses this to stay out of the way of the
    /// short-window rule that already flagged the same activity.
    pub async fn resource_has_assessment_overlapping(
        &self,
        resource: &str,
        rule_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM security_assessments WHERE resource=$1 AND rule_id=$2 \
             AND bucket_start < $4 AND bucket_start + make_interval(secs => window_seconds) > $3)",
        )
        .bind(resource)
        .bind(rule_id)
        .bind(from)
        .bind(to)
        .fetch_one(self.pool())
        .await?)
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

    /// A resource's own decaying history of *past* assessments - roadmap
    /// phase 8's "lokale IP-/Angriffshistorie als zeitlich abklingendes
    /// Signal verwenden". Every prior assessment for `resource` (any rule,
    /// any bucket, excluding `exclude_assessment_id` itself - the one
    /// currently being evaluated, which would otherwise always contribute
    /// its own ~1.0 and make this never purely "history") contributes
    /// `0.5 ^ (age_seconds / half_life_seconds)` - a fresh repeat (age near
    /// zero) contributes close to 1.0, one exactly `half_life_seconds` old
    /// contributes exactly 0.5, and contributions keep roughly halving
    /// every further half-life rather than ever hitting a hard cutoff. The
    /// sum across every prior assessment is a single, continuous "has this
    /// resource kept doing this, recently" score - a resource with several
    /// still-fresh past assessments scores higher than one with only a
    /// single old one, without needing a separate count *and* a separate
    /// age check.
    ///
    /// `::float8` casts throughout: `EXTRACT(EPOCH FROM ...)` and `POWER`
    /// on it both return Postgres `numeric`, not `float8` - sqlx's `f64`
    /// decode only accepts `FLOAT8`, so without the casts this would hit
    /// the exact same silent-decode-failure bug `list_provider_views`'s
    /// own `is_stale` flag found and fixed (see that query's own
    /// comment) - fixed here from the start rather than rediscovered.
    pub async fn resource_history_score(
        &self,
        resource: &str,
        exclude_assessment_id: Uuid,
        half_life_seconds: i64,
    ) -> Result<f64> {
        if half_life_seconds <= 0 {
            anyhow::bail!("half_life_seconds must be positive");
        }
        Ok(sqlx::query_scalar(
            "SELECT COALESCE(SUM( \
                 POWER(0.5::float8, \
                       EXTRACT(EPOCH FROM (NOW() - bucket_start))::float8 / $3::float8) \
               ), 0.0)::float8 \
             FROM security_assessments \
             WHERE resource = $1 AND id <> $2",
        )
        .bind(resource)
        .bind(exclude_assessment_id)
        .bind(half_life_seconds)
        .fetch_one(self.pool())
        .await?)
    }

    /// Whether another assessment of this `resource` is genuinely **independent**
    /// evidence for `assessment_id`: it comes from a different event family
    /// (`events.event_type`) than every event behind this assessment, within the
    /// shared episode window, and its rule is not in `ignore_rules`
    /// (observation-only rules such as a server-fault burst say nothing about the
    /// source's intent). Two rules that count the same HTTP events, or an
    /// overlapping bucket of the same rule, share an event family and are one
    /// observation, not two corroborating ones. An assessment with no recorded
    /// events cannot be shown to be independent and never corroborates.
    pub async fn resource_has_independent_family_assessment(
        &self,
        resource: &str,
        assessment_id: Uuid,
        since: DateTime<Utc>,
        ignore_rules: &[&str],
    ) -> Result<bool> {
        let ignore: Vec<String> = ignore_rules
            .iter()
            .map(|rule| (*rule).to_string())
            .collect();
        Ok(sqlx::query_scalar(
            "WITH t AS (SELECT clawforge_assessment_event_types($2) AS types) \
             SELECT EXISTS( \
               SELECT 1 FROM security_assessments o \
                 CROSS JOIN t \
                 CROSS JOIN LATERAL (SELECT clawforge_assessment_event_types(o.id) AS types) ot \
                WHERE o.resource=$1 AND o.id<>$2 AND o.bucket_start>=$3 \
                  AND NOT (o.rule_id = ANY($4)) \
                  AND cardinality(t.types) > 0 AND cardinality(ot.types) > 0 \
                  AND NOT (ot.types && t.types))",
        )
        .bind(resource)
        .bind(assessment_id)
        .bind(since)
        .bind(&ignore)
        .fetch_one(self.pool())
        .await?)
    }

    /// Decaying history like [`Self::resource_history_score`], but from **earlier
    /// episodes only, one decayed term per episode**.
    ///
    /// An episode is a chain of this resource's assessments in which consecutive
    /// activity is never more than `episode_gap_seconds` apart (the engine itself
    /// treats that as one incident candidate). The episode that contains
    /// `assessment_id` - however long it has been going on - is never history for
    /// itself. Every earlier episode contributes `0.5 ^ (age / half_life)` once,
    /// measured from its last activity, no matter how many assessment rows it
    /// produced (two window grids, several rules). Observation-only rules are
    /// ignored.
    pub async fn resource_prior_episode_history_score(
        &self,
        resource: &str,
        assessment_id: Uuid,
        half_life_seconds: i64,
        episode_gap_seconds: i64,
        ignore_rules: &[&str],
    ) -> Result<f64> {
        if half_life_seconds <= 0 || episode_gap_seconds < 0 {
            anyhow::bail!("half_life_seconds must be positive and the episode gap non-negative");
        }
        let ignore: Vec<String> = ignore_rules
            .iter()
            .map(|rule| (*rule).to_string())
            .collect();
        Ok(sqlx::query_scalar(
            "WITH RECURSIVE gap AS (SELECT ($4 * INTERVAL '1 second') AS g), \
             chain(start_at) AS ( \
                 SELECT first_seen FROM security_assessments WHERE id=$2 \
               UNION \
                 SELECT m.first_seen FROM chain c CROSS JOIN gap \
                   JOIN security_assessments m ON m.resource=$1 AND NOT (m.rule_id = ANY($5)) \
                  WHERE m.first_seen < c.start_at AND m.last_seen >= c.start_at - gap.g), \
             episode AS (SELECT MIN(start_at) AS start_at FROM chain), \
             prior AS ( \
                 SELECT o.first_seen, o.last_seen FROM security_assessments o, episode e, gap \
                  WHERE o.resource=$1 AND o.id<>$2 AND NOT (o.rule_id = ANY($5)) \
                    AND o.last_seen < e.start_at - gap.g), \
             marked AS ( \
                 SELECT p.*, CASE WHEN MAX(p.last_seen) OVER (ORDER BY p.first_seen, p.last_seen \
                                     ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) IS NULL \
                                    OR p.first_seen - MAX(p.last_seen) OVER (ORDER BY p.first_seen, p.last_seen \
                                     ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) > gap.g \
                                  THEN 1 ELSE 0 END AS starts \
                   FROM prior p, gap), \
             numbered AS (SELECT *, SUM(starts) OVER (ORDER BY first_seen, last_seen) AS episode_no FROM marked), \
             episodes AS (SELECT episode_no, MAX(last_seen) AS ended FROM numbered GROUP BY episode_no) \
             SELECT COALESCE(SUM(POWER(0.5::float8, \
                    EXTRACT(EPOCH FROM (NOW() - ended))::float8 / $3::float8)), 0.0)::float8 \
               FROM episodes",
        )
        .bind(resource)
        .bind(assessment_id)
        .bind(half_life_seconds)
        .bind(episode_gap_seconds)
        .bind(&ignore)
        .fetch_one(self.pool())
        .await?)
    }

    /// Retention for `security_assessments` - roadmap phase 8's
    /// "Datenschutz und Aufbewahrung fuer Identifikatoren festlegen".
    /// `resource` is a pseudonymized identifier, not raw personal data,
    /// but a pseudonym is still an identifier this codebase's own
    /// pseudonymization design treats as sensitive (see
    /// `pseudonymize_correlation_id`'s own doc comment) - it should not
    /// accumulate here forever with no defined lifetime, the same
    /// principle `security_ip_resolutions`' own short TTL and
    /// `indicators.expires_at` already apply elsewhere.
    ///
    /// Deliberately narrow: only ever deletes an assessment that was
    /// *never* promoted to an incident (`incident_id IS NULL`) and has
    /// seen no activity (`last_seen`) more recent than `older_than`. An
    /// assessment tied to a real incident - open, closed, or anything in
    /// between - is never touched by this, regardless of age: incident
    /// retention is its own, separately operator-agreed decision (see
    /// `docs/retention.md`), not something this method decides on its
    /// behalf. `security_policy_decisions` referencing a deleted
    /// assessment are removed first (no `ON DELETE CASCADE` from
    /// `security_assessments` to `security_policy_decisions` - migration
    /// `0034` left that FK`RESTRICT`, so this must happen in this order or
    /// the assessment delete would fail outright rather than silently
    /// orphan a decision). `security_assessment_events` rows cascade away
    /// automatically (migration `0033`'s own `ON DELETE CASCADE`) -
    /// `events` themselves are never touched at all, on purpose: they
    /// carry their own, separate retention/audit lifecycle this method
    /// has no business shortening.
    ///
    /// Returns how many assessment rows were actually removed, so a
    /// caller (a maintenance job) can log a real number rather than
    /// silently succeeding either way.
    pub async fn delete_expired_security_assessments(
        &self,
        older_than: DateTime<Utc>,
    ) -> Result<u64> {
        let mut tx = self.pool().begin().await?;
        sqlx::query(
            "DELETE FROM security_policy_decisions WHERE assessment_id IN ( \
                 SELECT id FROM security_assessments \
                 WHERE incident_id IS NULL AND last_seen < $1 \
             )",
        )
        .bind(older_than)
        .execute(&mut *tx)
        .await?;
        let result = sqlx::query(
            "DELETE FROM security_assessments WHERE incident_id IS NULL AND last_seen < $1",
        )
        .bind(older_than)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
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
        self.list_events_for_bucket_with_field_filtered(
            event_type,
            correlation_id,
            field,
            from,
            to,
            EventStatusFilter::Any,
        )
        .await
    }

    /// [`Self::list_events_for_bucket_with_field`] restricted by status class.
    pub async fn list_events_for_bucket_with_field_filtered(
        &self,
        event_type: &str,
        correlation_id: &str,
        field: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        status: EventStatusFilter,
    ) -> Result<Vec<(Uuid, DateTime<Utc>, Option<String>)>> {
        let rows = sqlx::query(&format!(
            "SELECT event_id, occurred_at, payload->>$5 AS field_value FROM events \
             WHERE event_type=$1 AND correlation_id=$2 AND occurred_at >= $3 AND occurred_at < $4 \
             AND {} ORDER BY occurred_at ASC LIMIT 1000",
            status.predicate()
        ))
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
        // One statement for the whole evidence set (identical result to a
        // row-by-row insert, without a round trip per event).
        sqlx::query(
            "INSERT INTO security_assessment_events (assessment_id,event_id) \
             SELECT $1, e FROM unnest($2::uuid[]) AS e ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(request.event_ids)
        .execute(&mut *tx)
        .await?;
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

    /// `incident_id` narrows to the assessments a specific incident was
    /// promoted from or escalated by - roadmap phase 9's "durchgaengige
    /// Auditkette vom Event bis zum Rollback" traces exactly this link.
    /// `None` (every internal caller except the phase 9 admin endpoint)
    /// keeps the original unfiltered behavior.
    pub async fn list_security_assessments(
        &self,
        incident_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<SecurityAssessment>> {
        let rows = sqlx::query(
            "SELECT id,rule_id,rule_version,resource,confidence,severity,summary,event_count,\
             bucket_start,incident_id,threat_intel_corroborated,threat_intel_source,\
             threat_intel_confidence,threat_intel_indicator_last_seen FROM security_assessments \
             WHERE $1::uuid IS NULL OR incident_id = $1 \
             ORDER BY bucket_start DESC LIMIT $2",
        )
        .bind(incident_id)
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
