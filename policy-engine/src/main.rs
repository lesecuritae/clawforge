//! `clawforge-policy-engine` (roadmap phase 5, "Policy Engine"), **Shadow
//! Mode only** - every decision this service makes is recorded, never
//! executed. That is not a configuration flag it happens to default to:
//! roadmap phase 6 ("Firewall Action Layer") does not exist yet, so there
//! is no action layer this service could call even if it wanted to. Shadow
//! mode here is a property of the current architecture, not a promise this
//! service makes and could break.
//!
//! ## What it does
//!
//! For each `active` policy (`security_policies`, versioned - see that
//! migration's own comments for the schema), evaluate every recent
//! `clawforge-security-engine` assessment matching that policy's `rule_id`
//! and `min_severity`, and record a decision
//! (`security_policy_decisions`) via `clawforge_policy::decide` - the
//! *existing* policy crate's own logic, not a second decision function
//! that could drift from it. That reuse is what gives this service the
//! roadmap's phase 4 exit-gate property "ein einzelnes Signal erreicht nie
//! eine Block-Entscheidung" for free: `decide()` only ever reaches `Block`
//! when `evidence_sources >= 2`, and today every assessment is exactly one
//! source (this one behavioral rule - no threat-intel corroboration is
//! wired in yet), so `evidence_sources` is always `1` and `Block` is
//! structurally unreachable, not merely unlikely.
//!
//! ## Replay
//!
//! Every poll cycle re-evaluates the most recent assessments, not just ones
//! it has not seen before: `persist_security_policy_decision` upserts by
//! `dedupe_key = policy_id:policy_version:assessment_id`, so recomputing
//! the same (policy, assessment) pair - because the assessment's own bucket
//! grew, because this service restarted, or because someone explicitly
//! wants to replay a policy against history - always updates the same row
//! rather than creating a duplicate. This is what makes the phase 5 exit
//! gate ("Policies können gegen historische Incidents replayed werden")
//! true by construction rather than an untested claim.

use anyhow::Result;
use clawforge_policy::{decide, Decision};
use clawforge_risk::RiskAssessment;
use clawforge_storage::{database_url_from_env, PostgresStore, SecurityPolicyDecisionUpsert};
use sha2::{Digest, Sha256};
use std::env;
use tracing::{info, warn};

/// Every assessment this service evaluates has exactly one evidence
/// source today: the behavioral rule that produced it. A second,
/// independent source (e.g. a future threat-intel corroboration check)
/// would raise this - see the module doc comment for why that single
/// number is precisely what keeps `Block` unreachable in shadow mode.
const EVIDENCE_SOURCES: i16 = 1;

/// `security_assessments.confidence` (0-99, `security-engine`'s own scale)
/// maps directly onto `RiskAssessment::risk_score` (0-100,
/// `clawforge_policy::decide`'s scale) - both already mean "how sure are we
/// this is real", just produced by different crates; no separate
/// risk-scoring model is invented here.
fn risk_assessment_from_confidence(confidence: i16) -> RiskAssessment {
    RiskAssessment {
        risk_score: confidence.clamp(0, 100) as u8,
        trust_score: 0,
        negative_score: confidence.clamp(0, 100) as u8,
        trust_adjustment: 0,
        reasons: Vec::new(),
    }
}

fn decision_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Observe => "observe",
        Decision::Challenge => "challenge",
        Decision::RateLimit => "rate_limit",
        Decision::Block => "block",
    }
}

fn min_severity_met(assessment_severity: &str, policy_min_severity: &str) -> bool {
    fn rank(value: &str) -> u8 {
        match value {
            "critical" => 3,
            "high" => 2,
            "medium" => 1,
            _ => 0,
        }
    }
    rank(assessment_severity) >= rank(policy_min_severity)
}

fn evidence_hash(
    policy_id: uuid::Uuid,
    policy_version: i32,
    snapshot: &serde_json::Value,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy_id.as_bytes());
    hasher.update(policy_version.to_le_bytes());
    hasher.update(snapshot.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

async fn evaluate_assessment(
    store: &PostgresStore,
    assessment: &clawforge_storage::SecurityAssessment,
) -> Result<()> {
    let policies = store
        .list_active_security_policies_for_rule(&assessment.rule_id, chrono::Utc::now())
        .await?;
    for policy in policies {
        if !min_severity_met(&assessment.severity, &policy.min_severity) {
            continue;
        }
        let risk = risk_assessment_from_confidence(assessment.confidence);
        let outcome = decide(&risk, EVIDENCE_SOURCES as usize);
        let rationale = format!(
            "assessment {} (rule {}, severity {}, confidence {}, {} events) against policy \
             '{}' v{} (class {}, min severity {}) -> {} (evidence_sources={}, corroborated={})",
            assessment.id,
            assessment.rule_id,
            assessment.severity,
            assessment.confidence,
            assessment.event_count,
            policy.name,
            policy.version,
            policy.class,
            policy.min_severity,
            decision_str(outcome.decision),
            EVIDENCE_SOURCES,
            outcome.corroborated,
        );
        let evidence_snapshot = serde_json::json!({
            "assessment_id": assessment.id,
            "rule_id": assessment.rule_id,
            "rule_version": assessment.rule_version,
            "resource": assessment.resource,
            "severity": assessment.severity,
            "confidence": assessment.confidence,
            "event_count": assessment.event_count,
            "bucket_start": assessment.bucket_start,
        });
        let hash = evidence_hash(policy.id, policy.version, &evidence_snapshot);
        let dedupe_key = format!("{}:{}:{}", policy.id, policy.version, assessment.id);
        store
            .persist_security_policy_decision(
                &dedupe_key,
                SecurityPolicyDecisionUpsert {
                    policy_id: policy.id,
                    policy_version: policy.version,
                    assessment_id: assessment.id,
                    incident_id: assessment.incident_id,
                    decision: decision_str(outcome.decision),
                    risk_score: outcome.risk_score as i16,
                    evidence_sources: EVIDENCE_SOURCES,
                    corroborated: outcome.corroborated,
                    rationale: &rationale,
                    evidence_snapshot,
                    evidence_hash: &hash,
                },
            )
            .await?;
    }
    Ok(())
}

fn poll_interval() -> std::time::Duration {
    env::var("CLAWFORGE_POLICY_ENGINE_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(15))
}

fn recent_assessments_limit() -> i64 {
    env::var("CLAWFORGE_POLICY_ENGINE_RECENT_ASSESSMENTS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(200)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let poll = poll_interval();
    let limit = recent_assessments_limit();
    let store = PostgresStore::connect_runtime(&database_url_from_env()?).await?;
    store
        .set_runtime_status("policy-engine", "running", None)
        .await?;
    info!(shadow_mode = true, "Clawforge policy engine started");
    let mut interval = tokio::time::interval(poll);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(error) = store.set_runtime_status("policy-engine", "running", None).await {
                    warn!(%error, "could not heartbeat policy-engine runtime status");
                }
                match store.list_security_assessments(limit).await {
                    Ok(assessments) => {
                        for assessment in assessments {
                            if let Err(error) = evaluate_assessment(&store, &assessment).await {
                                warn!(%error, assessment_id = %assessment.id, "policy evaluation failed");
                            }
                        }
                    }
                    Err(error) => warn!(%error, "could not list recent security assessments"),
                }
            }
            _ = shutdown_signal() => { info!("Clawforge policy engine shutting down"); break; }
        }
    }
    store
        .set_runtime_status("policy-engine", "stopped", None)
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_severity_met_ranks_correctly() {
        assert!(min_severity_met("critical", "medium"));
        assert!(min_severity_met("high", "high"));
        assert!(!min_severity_met("medium", "high"));
        assert!(!min_severity_met("low", "medium"));
    }

    #[test]
    fn a_single_evidence_source_can_never_reach_block() {
        // The whole point of shadow mode being safe by construction: today
        // every assessment has exactly one evidence source, and decide()
        // only reaches Block at evidence_sources >= 2.
        let risk = risk_assessment_from_confidence(99);
        let outcome = decide(&risk, EVIDENCE_SOURCES as usize);
        assert_ne!(outcome.decision, Decision::Block);
        assert!(!outcome.corroborated);
    }

    #[test]
    fn evidence_hash_is_deterministic_and_sensitive_to_policy_version() {
        let policy_id = uuid::Uuid::new_v4();
        let snapshot = serde_json::json!({"a": 1});
        let first = evidence_hash(policy_id, 1, &snapshot);
        let second = evidence_hash(policy_id, 1, &snapshot);
        assert_eq!(first, second);
        let different_version = evidence_hash(policy_id, 2, &snapshot);
        assert_ne!(first, different_version);
    }

    #[test]
    fn decision_str_covers_every_variant() {
        assert_eq!(decision_str(Decision::Observe), "observe");
        assert_eq!(decision_str(Decision::Challenge), "challenge");
        assert_eq!(decision_str(Decision::RateLimit), "rate_limit");
        assert_eq!(decision_str(Decision::Block), "block");
    }

    /// Proves the whole shadow-decision path end to end against real
    /// PostgreSQL, running as the least-privilege `policy_engine` role the
    /// deployed binary actually uses: a critical/high-confidence assessment
    /// against the seeded `ssh_bruteforce-default` policy (migration 0034)
    /// produces exactly one decision, is_shadow is always TRUE, Block is
    /// never reached (evidence_sources=1), and replaying the identical
    /// assessment again upserts the same row rather than duplicating it.
    #[tokio::test]
    #[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
    async fn shadow_decision_is_recorded_never_blocks_and_replays_idempotently() -> Result<()> {
        let owner_url = env::var("CLAWFORGE_TEST_DATABASE_URL")?;
        let owner = PostgresStore::connect_runtime(&owner_url).await?;
        let engine = PostgresStore::connect_runtime(&env::var(
            "CLAWFORGE_TEST_SECURITY_ENGINE_DATABASE_URL",
        )?)
        .await?;
        let policy_engine =
            PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL")?)
                .await?;

        // A fixture assessment, written the way clawforge-security-engine
        // itself would (its own role, its own upsert method) - not a
        // hand-rolled INSERT that could drift from the real shape.
        let resource = format!("ip-pseudonym:test-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now();
        let dedupe_key = format!("ssh_bruteforce:v1:{resource}:{}", now.timestamp());
        let event_id = owner
            .publish_event(
                "ssh_login_failure",
                "test-sensor",
                "critical",
                now,
                Some(&resource),
                serde_json::json!({"test": true}),
                serde_json::json!({}),
                &format!("test:policy-engine-fixture:{resource}"),
            )
            .await?;
        let assessment_id = engine
            .persist_security_assessment(clawforge_storage::SecurityAssessmentUpsert {
                rule_id: "ssh_bruteforce",
                rule_version: "1",
                engine_version: "test",
                dedupe_key: &dedupe_key,
                resource: &resource,
                severity: "critical",
                confidence: 99,
                summary: "test fixture",
                event_count: 20,
                window_seconds: 300,
                bucket_start: now,
                first_seen: now,
                last_seen: now,
                event_ids: &[event_id],
            })
            .await?;

        let assessment = policy_engine
            .list_security_assessments(500)
            .await?
            .into_iter()
            .find(|value| value.id == assessment_id)
            .expect("the fixture assessment must be listable");
        evaluate_assessment(&policy_engine, &assessment).await?;

        let decisions: Vec<(String, bool, bool)> = sqlx::query_as(
            "SELECT decision, corroborated, is_shadow FROM security_policy_decisions \
             WHERE assessment_id=$1",
        )
        .bind(assessment_id)
        .fetch_all(owner.pool())
        .await?;
        assert_eq!(
            decisions.len(),
            1,
            "exactly one seeded active policy applies to ssh_bruteforce"
        );
        let (decision, corroborated, is_shadow) = &decisions[0];
        assert_ne!(
            decision, "block",
            "a single evidence source must never block"
        );
        assert!(!corroborated);
        assert!(is_shadow, "every decision today must be a shadow decision");

        // Replay: evaluating the identical assessment again must upsert the
        // same row, not create a second one.
        evaluate_assessment(&policy_engine, &assessment).await?;
        let decision_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_policy_decisions WHERE assessment_id=$1",
        )
        .bind(assessment_id)
        .fetch_one(owner.pool())
        .await?;
        assert_eq!(decision_count, 1);

        Ok(())
    }
}
