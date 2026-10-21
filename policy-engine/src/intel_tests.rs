//! Reputation and routing evidence in the policy decision: judged on the current
//! view of the source, so feed updates and removals matter; ASN listings count only
//! as reputation; routing facts are shown, never counted.
use super::*;
use chrono::{DateTime, Utc};
use clawforge_storage::{IpReputationHit, NetworkContextOutcome, SecurityAssessment};
use sqlx::PgPool;
use uuid::Uuid;

struct Env {
    owner: PostgresStore,
    policy: PostgresStore,
    resource: String,
    ip: String,
    tag: String,
    indicators: Vec<i64>,
}

impl Env {
    async fn new() -> Result<Self> {
        let tag = Uuid::new_v4().simple().to_string();
        Ok(Self {
            owner: PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_DATABASE_URL")?)
                .await?,
            policy: PostgresStore::connect_runtime(&env::var(
                "CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL",
            )?)
            .await?,
            resource: format!("ip-pseudonym:intel-{tag}"),
            ip: format!("203.0.113.{}", Uuid::new_v4().as_u128() % 200 + 20),
            tag,
            indicators: Vec::new(),
        })
    }

    fn pool(&self) -> &PgPool {
        self.owner.pool()
    }

    async fn resolve(&self) -> Result<()> {
        sqlx::query("INSERT INTO security_ip_resolutions(pseudonym,raw_ip,source,expires_at) VALUES($1,$2::inet,'intel-test',NOW()+INTERVAL '1 hour')")
            .bind(&self.resource).bind(&self.ip).execute(self.pool()).await?;
        Ok(())
    }

    async fn indicator(
        &mut self,
        value: &str,
        kind: &str,
        category: &str,
        confidence: i16,
        age_days: i64,
    ) -> Result<i64> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO indicators (value,indicator_type,categories,confidence,source,first_seen,last_seen,expires_at) \
             VALUES ($1,$2,jsonb_build_array($3::text),$4,$5,NOW(),NOW()-($6*INTERVAL '1 day'),NOW()+INTERVAL '1 hour') RETURNING id",
        )
        .bind(value).bind(kind).bind(category).bind(confidence).bind(format!("intel-{}-{}", self.tag, self.indicators.len())).bind(age_days)
        .fetch_one(self.pool()).await?;
        self.indicators.push(id);
        Ok(id)
    }

    async fn delete_indicator(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM indicators WHERE id=$1")
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    async fn assessment(&self, snapshot: Option<IpReputationHit>) -> Result<SecurityAssessment> {
        let now = Utc::now();
        let id = self
            .owner
            .persist_security_assessment(clawforge_storage::SecurityAssessmentUpsert {
                rule_id: "ssh_bruteforce",
                rule_version: "2",
                engine_version: "test",
                dedupe_key: &format!("intel:{}", self.tag),
                resource: &self.resource,
                severity: "critical",
                confidence: 95,
                summary: "intel fixture",
                event_count: 20,
                window_seconds: 300,
                bucket_start: now,
                first_seen: now,
                last_seen: now,
                event_ids: &[],
                threat_intel: snapshot.clone(),
            })
            .await?;
        Ok(SecurityAssessment {
            id,
            rule_id: "ssh_bruteforce".into(),
            rule_version: "2".into(),
            resource: self.resource.clone(),
            severity: "critical".into(),
            confidence: 95,
            summary: String::new(),
            event_count: 20,
            bucket_start: now,
            incident_id: None,
            threat_intel_corroborated: snapshot.is_some(),
            threat_intel: snapshot,
        })
    }

    async fn evidence(&self, target: &SecurityAssessment) -> Result<(i16, &'static str)> {
        let e = independent_evidence_for(&self.policy, target).await?;
        Ok((e.sources, e.basis))
    }

    async fn cleanup(&self) -> Result<()> {
        sqlx::query("DELETE FROM indicators WHERE id = ANY($1)")
            .bind(&self.indicators)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

fn snapshot(source: &str, confidence: i16, last_seen: DateTime<Utc>) -> IpReputationHit {
    IpReputationHit {
        source: source.into(),
        confidence,
        last_seen,
    }
}

/// A listing that arrives after the events, a delisting and an expiry all change
/// the next decision - the ingest-time snapshot no longer decides alone.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn a_late_listing_counts_and_a_delisting_or_expiry_ends_it() -> Result<()> {
    let mut e = Env::new().await?;
    e.resolve().await?;
    let target = e.assessment(None).await?;
    assert_eq!(e.evidence(&target).await?, (1, "behavior_only"));

    let id = e
        .indicator("203.0.113.0/24", "Prefix", "spamhaus_drop", 85, 0)
        .await?;
    assert_eq!(
        e.evidence(&target).await?,
        (2, "threat_intel_ip"),
        "listed after the events"
    );

    e.delete_indicator(id).await?;
    assert_eq!(e.evidence(&target).await?, (1, "behavior_only"), "delisted");

    let expired = e
        .indicator("203.0.113.0/24", "Prefix", "spamhaus_drop", 85, 0)
        .await?;
    sqlx::query("UPDATE indicators SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(expired)
        .execute(e.pool())
        .await?;
    assert_eq!(e.evidence(&target).await?, (1, "behavior_only"), "expired");

    // Confidence and staleness thresholds still apply to a live listing.
    e.indicator("203.0.113.0/24", "Prefix", "spamhaus_drop", 30, 0)
        .await?;
    assert_eq!(
        e.evidence(&target).await?,
        (1, "behavior_only"),
        "below the confidence floor"
    );
    e.indicator("203.0.113.0/24", "Prefix", "spamhaus_drop", 90, 30)
        .await?;
    assert_eq!(
        e.evidence(&target).await?,
        (1, "behavior_only"),
        "not reconfirmed within the staleness limit"
    );
    e.cleanup().await
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn the_ingest_snapshot_is_used_only_without_a_current_view_and_only_from_reputation_sources(
) -> Result<()> {
    let e = Env::new().await?;
    let fresh = snapshot("spamhaus_drop", 90, Utc::now());
    // No resolution: no current view, so a fresh reputation snapshot still counts.
    let target = e.assessment(Some(fresh.clone())).await?;
    assert_eq!(e.evidence(&target).await?, (2, "threat_intel_snapshot"));
    // The same snapshot from a routing-context provider never counts.
    let routing = e
        .assessment(Some(snapshot("routeviews", 99, Utc::now())))
        .await?;
    assert_eq!(e.evidence(&routing).await?, (1, "behavior_only"));
    // With a current view that no longer lists the source, the stale snapshot is overruled.
    e.resolve().await?;
    assert_eq!(
        e.evidence(&target).await?,
        (1, "behavior_only"),
        "delisted since ingest"
    );
    e.cleanup().await
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn an_origin_asn_listing_counts_as_reputation_but_routing_facts_never_do() -> Result<()> {
    let mut e = Env::new().await?;
    e.resolve().await?;
    let asn = 4_100_000_000_i64 + (Uuid::new_v4().as_u128() % 90_000_000) as i64;
    let prefix = format!("{}.0/24", e.ip.rsplit_once('.').unwrap().0);
    let target = e.assessment(None).await?;
    // Routing context alone - RPKI-invalid, multi-origin, even a BGP anomaly - lists nothing.
    assert!(
        e.owner
            .record_network_context(
                &e.resource,
                &NetworkContextOutcome::Routed {
                    prefix: prefix.clone(),
                    origin_asns: vec![asn, asn + 1],
                    rpki: "invalid".into(),
                    ttl_seconds: 3600
                }
            )
            .await?
    );
    sqlx::query("INSERT INTO bgp_events (prefix,origin_asn,status,rpki_status,first_seen,last_seen,fingerprint) VALUES ($1,'AS64496','Anomalous','Invalid',NOW(),NOW(),$2)")
        .bind(&prefix).bind(format!("fp-{}", e.tag)).execute(e.pool()).await?;
    let none = e.policy.current_source_intel(&e.resource).await?;
    assert!(none.bgp_anomaly && none.context.is_some());
    assert_eq!(
        e.evidence(&target).await?,
        (1, "behavior_only"),
        "routing anomalies are context, not evidence"
    );

    // The origin ASN on an ASN-DROP style list is reputation.
    e.indicator(&format!("AS{asn}"), "Asn", "spamhaus_asn", 80, 0)
        .await?;
    assert_eq!(e.evidence(&target).await?, (2, "threat_intel_asn"));
    // A routing provider's own ASN row is not.
    sqlx::query("DELETE FROM indicators WHERE source LIKE $1")
        .bind(format!("intel-{}-%", e.tag))
        .execute(e.pool())
        .await?;
    e.indicator(&format!("AS{asn}"), "Asn", "network-intelligence", 99, 0)
        .await?;
    assert_eq!(e.evidence(&target).await?, (1, "behavior_only"));
    sqlx::query("DELETE FROM bgp_events WHERE fingerprint=$1")
        .bind(format!("fp-{}", e.tag))
        .execute(e.pool())
        .await?;
    e.cleanup().await
}

/// The decision record carries the routing facts for the human who reads it, and
/// still never an address.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn the_decision_records_routing_context_without_the_address() -> Result<()> {
    let mut e = Env::new().await?;
    e.resolve().await?;
    let prefix = format!("{}.0/24", e.ip.rsplit_once('.').unwrap().0);
    assert!(
        e.owner
            .record_network_context(
                &e.resource,
                &NetworkContextOutcome::Routed {
                    prefix: prefix.clone(),
                    origin_asns: vec![64496],
                    rpki: "valid".into(),
                    ttl_seconds: 3600
                }
            )
            .await?
    );
    e.indicator("203.0.113.0/24", "Prefix", "spamhaus_drop", 85, 0)
        .await?;
    let target = e.assessment(None).await?;
    evaluate_assessment(&e.policy, &target, None).await?;
    let (decision, sources, snapshot): (String, i16, serde_json::Value) = sqlx::query_as(
        "SELECT decision, evidence_sources, evidence_snapshot FROM security_policy_decisions WHERE assessment_id=$1",
    )
    .bind(target.id)
    .fetch_one(e.pool())
    .await?;
    assert_eq!((decision.as_str(), sources), ("block", 2));
    assert_eq!(snapshot["evidence_basis"], "threat_intel_ip");
    assert_eq!(
        snapshot["routing_context"]["origin_asns"],
        serde_json::json!([64496])
    );
    assert_eq!(snapshot["routing_context"]["rpki"], "valid");
    assert_eq!(snapshot["routing_context"]["prefix"], prefix);
    assert!(
        !snapshot.to_string().contains(&e.ip),
        "the decision record never contains the address"
    );
    e.cleanup().await
}
