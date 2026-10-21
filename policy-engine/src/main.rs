//! `clawforge-policy-engine` (roadmap phase 5, "Policy Engine"), **Shadow
//! Mode only** - decisions are recorded and Challenge decisions may enqueue
//! an immutable simulation-only Go-Away request. No decision from this
//! service can cause a real firewall action.
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
//! when `evidence_sources >= 2`. `evidence_sources` is `1` for a plain
//! behavioral assessment and `2` when `security_assessments.
//! threat_intel_corroborated` is set - itself only ever set when a raw
//! sensor-reported IP matched a threat-intel indicator (Spamhaus DROP/
//! EDROP today) *before* being pseudonymized, at ingest time
//! (`record_security_event`/`lookup_ip_reputation`; see that method's own
//! doc comment for why the check has to happen there and can only ever
//! store a category flag, never the IP). A single evidence source can
//! still never reach `Block` - that has not changed - but a corroborated
//! one now genuinely can, still only as a shadow decision. Only `Challenge`
//! may enqueue a simulation-only Go-Away request; none executes live.
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

mod bridge;

use anyhow::Result;
use bridge::BridgeConfig;
use clawforge_policy::{decide, Decision, PolicyDecision};
use clawforge_risk::RiskAssessment;
use clawforge_storage::{
    database_url_from_env, BridgeOutcome, PostgresStore, SecurityPolicyDecisionUpsert,
};
use sha2::{Digest, Sha256};
use std::env;
use tracing::{info, warn};

/// How far back a *different* rule's assessment for the same resource
/// still counts as independent corroboration - matches
/// `clawforge-security-engine`'s own `CANDIDATE_EXTENSION_WINDOW` (an
/// attacker rarely confines every kind of misbehavior to one detection
/// window; this is the same "still the same ongoing episode" horizon,
/// not a second, unrelated constant that could drift from it).
const CROSS_RULE_CORROBORATION_WINDOW: chrono::Duration = chrono::Duration::hours(1);

const DEFAULT_THREAT_INTEL_MAX_STALENESS_SECONDS: i64 = 7 * 24 * 3600;
const DEFAULT_THREAT_INTEL_MIN_CONFIDENCE: i16 = 50;

fn threat_intel_max_staleness_seconds() -> i64 {
    env::var("CLAWFORGE_THREAT_INTEL_MAX_STALENESS_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_THREAT_INTEL_MAX_STALENESS_SECONDS)
}

fn threat_intel_min_confidence() -> i16 {
    env::var("CLAWFORGE_THREAT_INTEL_MIN_CONFIDENCE")
        .ok()
        .and_then(|value| value.parse::<i16>().ok())
        .filter(|value| (0..=100).contains(value))
        .unwrap_or(DEFAULT_THREAT_INTEL_MIN_CONFIDENCE)
}

/// Whether a threat-intel hit is fresh and confident enough to count as
/// independent corroborating evidence at all - roadmap phase 8's own exit
/// gate: "Offline- oder veraltete ... Feeds reduzieren Confidence und
/// loesen keine automatische Eskalation aus". A hit whose indicator has
/// not been reconfirmed recently (`last_seen` older than
/// `CLAWFORGE_THREAT_INTEL_MAX_STALENESS_SECONDS`, default 7 days) or
/// whose provider's own confidence is below
/// `CLAWFORGE_THREAT_INTEL_MIN_CONFIDENCE` (default 50) does not count -
/// the assessment stays at `evidence_sources=1` (its own behavioral
/// signal alone), never silently escalated toward `Block` on the strength
/// of stale or low-confidence external data. Every input this decides on
/// (`confidence`, `last_seen`, the two thresholds) is already visible on
/// the persisted assessment/in this service's own env config - nothing
/// about the discount is a black box.
/// Providers whose indicators describe routing context, never reputation. Hits
/// recorded at ingest time before the reputation lookup excluded them (production
/// held a RouteViews `0.0.0.0/0` row that "matched" every IPv4 address) must not
/// count as corroboration when a stored snapshot is the only evidence left.
const NETWORK_CONTEXT_SOURCES: &[&str] = &[
    "routeviews",
    "ripe_ris",
    "ripestat_asn",
    "hackertarget_asn",
    "peeringdb",
    "caida_as_rank",
    "team_cymru",
    "bgpstream",
    "bgpview_asn",
    "rpki_validator",
];

fn threat_intel_hit_is_corroborating(hit: &clawforge_storage::IpReputationHit) -> bool {
    if NETWORK_CONTEXT_SOURCES.contains(&hit.source.as_str()) {
        return false;
    }
    if hit.confidence < threat_intel_min_confidence() {
        return false;
    }
    let age_seconds = (chrono::Utc::now() - hit.last_seen).num_seconds();
    age_seconds >= 0 && age_seconds <= threat_intel_max_staleness_seconds()
}

const DEFAULT_HISTORY_HALF_LIFE_SECONDS: i64 = 14 * 24 * 3600;
const DEFAULT_HISTORY_MIN_SCORE: f64 = 0.5;

fn history_half_life_seconds() -> i64 {
    env::var("CLAWFORGE_HISTORY_HALF_LIFE_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_HISTORY_HALF_LIFE_SECONDS)
}

fn history_min_score() -> f64 {
    env::var("CLAWFORGE_HISTORY_MIN_SCORE")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| *value > 0.0)
        .unwrap_or(DEFAULT_HISTORY_MIN_SCORE)
}

/// Every assessment has at least one evidence source: the behavioral rule
/// that produced it. A second, independent one raises this to 2, which is
/// what `clawforge_policy::decide` requires before it will ever return
/// `Block` - three different shapes of it exist:
///
/// - **Threat-intel corroboration**: the source is independently listed by
///   an external reputation feed, and that listing is itself fresh and
///   confident enough to trust (`threat_intel_hit_is_corroborating`) - a
///   stale or low-confidence hit does not count, even though
///   `security_assessments.threat_intel_corroborated` itself is still
///   `true` for it (that flag only records "some indicator matched at
///   ingest time", not "and it was good enough to corroborate on").
/// - **Cross-rule corroboration**: a *different* rule has also produced an
///   assessment for the same resource recently - a source that first
///   tripped `ssh_bruteforce` and later, separately, `http_scan` is
///   corroborated by two independent detections even with no external
///   reputation hit involved in either one
///   (`resource_has_other_rule_assessment`). This is exactly why
///   `record_security_event` retains a short-TTL raw-IP resolution for
///   *every* event, not only a reputation hit: this combination has to be
///   resolvable to a real address later too, and `clawforge-security-engine`
///   (which only ever sees pseudonyms) cannot be the one to retain it.
/// - **Local history corroboration** (roadmap phase 8: "lokale IP-/
///   Angriffshistorie als zeitlich abklingendes Signal verwenden"): this
///   *same* resource has a decaying history of its own past assessments
///   (`resource_history_score`, any rule, not just this one) above
///   `CLAWFORGE_HISTORY_MIN_SCORE` (default 0.5 - a single prior
///   assessment counts on its own as long as it is not much older than
///   one half-life; several older ones can also add up to it). A resource
///   that keeps tripping detections is its own form of independent
///   evidence, separate from *which* rule
///   noticed it this time or that time.
#[cfg(test)]
async fn evidence_sources_for(
    store: &PostgresStore,
    assessment: &clawforge_storage::SecurityAssessment,
) -> Result<i16> {
    Ok(independent_evidence_for(store, assessment).await?.0)
}

/// Rules that describe the system rather than the source's intent. They are
/// recorded and shown, but never produce an attacker decision beyond `observe`
/// and never count as corroborating evidence for another assessment.
const OBSERVATION_ONLY_RULES: &[&str] = &["http_server_fault_burst"];

/// Matches `clawforge-security-engine`'s incident-candidate extension window:
/// anything closer is the same ongoing episode, not independent history.
const EPISODE_GAP_SECONDS: i64 = 3600;

/// The evidence-source count together with the basis that produced it, so the
/// decision rationale shows *why* a second source was (or was not) counted.
/// Independence means a different evidence kind, never the same observation
/// seen twice: two rules (or two overlapping buckets of one rule) counting the
/// same event family are one source, and an ongoing episode does not
/// corroborate itself.
async fn independent_evidence_for(
    store: &PostgresStore,
    assessment: &clawforge_storage::SecurityAssessment,
) -> Result<(i16, &'static str)> {
    // An operational observation has exactly one source and nothing to corroborate.
    if OBSERVATION_ONLY_RULES.contains(&assessment.rule_id.as_str()) {
        return Ok((1, "observation_only"));
    }
    if let Some(hit) = &assessment.threat_intel {
        if threat_intel_hit_is_corroborating(hit) {
            return Ok((2, "threat_intel"));
        }
    }
    let since = chrono::Utc::now() - CROSS_RULE_CORROBORATION_WINDOW;
    if store
        .resource_has_independent_family_assessment(
            &assessment.resource,
            assessment.id,
            since,
            OBSERVATION_ONLY_RULES,
        )
        .await?
    {
        return Ok((2, "independent_event_family"));
    }
    let history_score = store
        .resource_prior_episode_history_score(
            &assessment.resource,
            assessment.id,
            history_half_life_seconds(),
            EPISODE_GAP_SECONDS,
            OBSERVATION_ONLY_RULES,
        )
        .await?;
    if history_score >= history_min_score() {
        return Ok((2, "prior_episode_history"));
    }
    Ok((1, "behavior_only"))
}

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
    bridge: Option<&BridgeConfig>,
) -> Result<()> {
    let policies = store
        .list_active_security_policies_for_rule(&assessment.rule_id, chrono::Utc::now())
        .await?;
    let (evidence_sources, evidence_basis) = independent_evidence_for(store, assessment).await?;
    let observation_only = OBSERVATION_ONLY_RULES.contains(&assessment.rule_id.as_str());
    for policy in policies {
        if !min_severity_met(&assessment.severity, &policy.min_severity) {
            continue;
        }
        let risk = risk_assessment_from_confidence(assessment.confidence);
        let outcome = if observation_only {
            // An operational observation (e.g. a backend answering 5xx): visible
            // as a decision, never an attacker verdict, never a challenge/block.
            PolicyDecision {
                decision: Decision::Observe,
                risk_score: risk.risk_score,
                corroborated: false,
            }
        } else {
            decide(&risk, evidence_sources as usize)
        };
        let rationale = format!(
            "assessment {} (rule {}, severity {}, confidence {}, {} events, threat_intel_corroborated={}) \
             against policy '{}' v{} (class {}, min severity {}) -> {} (evidence_sources={}, corroborated={}, \
             evidence_basis={}, observation_only={})",
            assessment.id,
            assessment.rule_id,
            assessment.severity,
            assessment.confidence,
            assessment.event_count,
            assessment.threat_intel_corroborated,
            policy.name,
            policy.version,
            policy.class,
            policy.min_severity,
            decision_str(outcome.decision),
            evidence_sources,
            outcome.corroborated,
            evidence_basis,
            observation_only,
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
            "evidence_basis": evidence_basis,
            "observation_only": observation_only,
        });
        let hash = evidence_hash(policy.id, policy.version, &evidence_snapshot);
        let dedupe_key = format!("{}:{}:{}", policy.id, policy.version, assessment.id);
        let decision_id = store
            .persist_security_policy_decision(
                &dedupe_key,
                SecurityPolicyDecisionUpsert {
                    policy_id: policy.id,
                    policy_version: policy.version,
                    assessment_id: assessment.id,
                    incident_id: assessment.incident_id,
                    decision: decision_str(outcome.decision),
                    risk_score: outcome.risk_score as i16,
                    evidence_sources,
                    corroborated: outcome.corroborated,
                    rationale: &rationale,
                    evidence_snapshot,
                    evidence_hash: &hash,
                },
            )
            .await?;
        if outcome.decision == Decision::Challenge {
            store.enqueue_goaway_shadow_challenge(decision_id).await?;
        }
        // Optional policy -> execution bridge (default off). The database
        // re-derives and re-checks every condition; a refusal is routine (the
        // same decision is re-evaluated each poll) and never fails evaluation.
        if let (Some(bridge), Decision::Block | Decision::RateLimit) = (bridge, outcome.decision) {
            if let Some(params) = bridge.params_for(outcome.decision == Decision::RateLimit) {
                match store
                    .enqueue_policy_bridge_request(decision_id, &params)
                    .await
                {
                    Ok(BridgeOutcome::Enqueued(request_id)) => info!(
                        %request_id, %decision_id, mode = params.mode.as_str(),
                        action = %params.action_name, "policy bridge created an execution request"
                    ),
                    Ok(BridgeOutcome::Duplicate(_)) => {}
                    Ok(BridgeOutcome::Rejected(reason)) => {
                        tracing::debug!(%decision_id, %reason, "policy bridge declined a decision")
                    }
                    Err(error) => warn!(%error, %decision_id, "policy bridge call failed"),
                }
            }
        }
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
    // An invalid bridge configuration disables the bridge entirely and stays
    // visible in the runtime status; shadow decisions keep running.
    let (bridge, bridge_error) = match BridgeConfig::from_env() {
        Ok(config) => (config, None),
        Err(reason) => {
            warn!(%reason, "policy bridge disabled: invalid configuration");
            (None, Some(format!("policy bridge disabled: {reason}")))
        }
    };
    store
        .set_runtime_status("policy-engine", "running", bridge_error.as_deref())
        .await?;
    match &bridge {
        Some(config) => info!(mode = config.mode.as_str(), "policy bridge enabled"),
        None => info!("policy bridge off"),
    }
    info!(shadow_mode = true, "Clawforge policy engine started");
    let mut interval = tokio::time::interval(poll);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(error) = store.set_runtime_status("policy-engine", "running", bridge_error.as_deref()).await {
                    warn!(%error, "could not heartbeat policy-engine runtime status");
                }
                match store.list_security_assessments(None, limit).await {
                    Ok(assessments) => {
                        for assessment in assessments {
                            if let Err(error) = evaluate_assessment(&store, &assessment, bridge.as_ref()).await {
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
mod behavior_stage_tests;
#[cfg(test)]
mod independence_tests;

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
        // A plain behavioral assessment (threat_intel_corroborated=false)
        // is exactly one evidence source, and decide() only reaches Block
        // at evidence_sources >= 2 - true regardless of how high its own
        // confidence/risk_score is.
        let risk = risk_assessment_from_confidence(99);
        let outcome = decide(&risk, 1);
        assert_ne!(outcome.decision, Decision::Block);
        assert!(!outcome.corroborated);
    }

    #[test]
    fn threat_intel_corroboration_is_what_makes_block_reachable_at_all() {
        // A high-confidence assessment that also matched a threat-intel
        // indicator has two independent evidence sources - this is the one
        // case decide() can actually reach Block for, proving the whole
        // point of wiring threat-intel corroboration in at all (still only
        // ever recorded as a shadow decision - see the module doc comment).
        let risk = risk_assessment_from_confidence(99);
        let outcome = decide(&risk, 2);
        assert_eq!(outcome.decision, Decision::Block);
        assert!(outcome.corroborated);
    }

    #[tokio::test]
    #[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
    async fn evidence_sources_for_reflects_threat_intel_corroboration() -> Result<()> {
        // A fresh, confident hit returns before ever touching the store,
        // but the function's signature still needs a real one to call it
        // at all - connect once and reuse it for every case.
        let store =
            PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL")?)
                .await?;
        let base = clawforge_storage::SecurityAssessment {
            id: uuid::Uuid::new_v4(),
            rule_id: format!("test-rule-{}", uuid::Uuid::new_v4()),
            rule_version: "1".to_string(),
            resource: format!("ip-pseudonym:test-{}", uuid::Uuid::new_v4()),
            severity: "critical".to_string(),
            confidence: 99,
            summary: String::new(),
            event_count: 20,
            bucket_start: chrono::Utc::now(),
            incident_id: None,
            threat_intel_corroborated: false,
            threat_intel: None,
        };
        assert_eq!(
            evidence_sources_for(&store, &base).await?,
            1,
            "no hit at all must not corroborate"
        );

        let fresh_confident = clawforge_storage::SecurityAssessment {
            threat_intel_corroborated: true,
            threat_intel: Some(clawforge_storage::IpReputationHit {
                source: "spamhaus_drop".to_string(),
                confidence: 90,
                last_seen: chrono::Utc::now(),
            }),
            ..base.clone()
        };
        assert_eq!(
            evidence_sources_for(&store, &fresh_confident).await?,
            2,
            "a fresh, high-confidence hit must corroborate"
        );

        let stale = clawforge_storage::SecurityAssessment {
            threat_intel_corroborated: true,
            threat_intel: Some(clawforge_storage::IpReputationHit {
                source: "spamhaus_drop".to_string(),
                confidence: 90,
                last_seen: chrono::Utc::now() - chrono::Duration::days(30),
            }),
            ..base.clone()
        };
        assert_eq!(
            evidence_sources_for(&store, &stale).await?,
            1,
            "a stale hit (older than the default 7-day staleness window) must not corroborate, \
             even though security_assessments.threat_intel_corroborated is still true for it"
        );

        let low_confidence = clawforge_storage::SecurityAssessment {
            threat_intel_corroborated: true,
            threat_intel: Some(clawforge_storage::IpReputationHit {
                source: "some_low_quality_feed".to_string(),
                confidence: 10,
                last_seen: chrono::Utc::now(),
            }),
            ..base
        };
        assert_eq!(
            evidence_sources_for(&store, &low_confidence).await?,
            1,
            "a fresh but low-confidence hit (below the default minimum of 50) must not corroborate"
        );
        Ok(())
    }

    #[test]
    fn a_network_context_source_never_corroborates_even_when_fresh_and_confident() {
        for source in NETWORK_CONTEXT_SOURCES {
            let hit = clawforge_storage::IpReputationHit {
                source: source.to_string(),
                confidence: 99,
                last_seen: chrono::Utc::now(),
            };
            assert!(!threat_intel_hit_is_corroborating(&hit), "{source}");
        }
        let listed = clawforge_storage::IpReputationHit {
            source: "spamhaus_drop".into(),
            confidence: 80,
            last_seen: chrono::Utc::now(),
        };
        assert!(threat_intel_hit_is_corroborating(&listed));
    }

    #[test]
    fn threat_intel_hit_is_corroborating_applies_both_thresholds() {
        // SAFETY: single-threaded test process, no other test in this
        // binary reads/writes these specific env vars.
        std::env::remove_var("CLAWFORGE_THREAT_INTEL_MAX_STALENESS_SECONDS");
        std::env::remove_var("CLAWFORGE_THREAT_INTEL_MIN_CONFIDENCE");

        let fresh_and_confident = clawforge_storage::IpReputationHit {
            source: "spamhaus_drop".to_string(),
            confidence: 100,
            last_seen: chrono::Utc::now(),
        };
        assert!(threat_intel_hit_is_corroborating(&fresh_and_confident));

        let stale = clawforge_storage::IpReputationHit {
            last_seen: chrono::Utc::now() - chrono::Duration::days(8),
            ..fresh_and_confident.clone()
        };
        assert!(!threat_intel_hit_is_corroborating(&stale));

        let low_confidence = clawforge_storage::IpReputationHit {
            confidence: 49,
            ..fresh_and_confident.clone()
        };
        assert!(!threat_intel_hit_is_corroborating(&low_confidence));

        // A future last_seen (clock skew, or a bug elsewhere) must not be
        // treated as infinitely fresh - the age_seconds >= 0 guard in
        // threat_intel_hit_is_corroborating rejects it explicitly rather
        // than silently accepting a negative age.
        let from_the_future = clawforge_storage::IpReputationHit {
            last_seen: chrono::Utc::now() + chrono::Duration::hours(1),
            ..fresh_and_confident
        };
        assert!(!threat_intel_hit_is_corroborating(&from_the_future));
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

    /// End to end through the real engine path: a threat-intel-corroborated
    /// assessment becomes a Block shadow decision, and only a configured bridge
    /// turns it into exactly one simulation-only request.
    #[tokio::test]
    #[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
    async fn bridge_turns_a_corroborated_block_into_one_simulated_request_only_when_configured(
    ) -> Result<()> {
        let owner =
            PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
        let engine = PostgresStore::connect_runtime(&env::var(
            "CLAWFORGE_TEST_SECURITY_ENGINE_DATABASE_URL",
        )?)
        .await?;
        let policy_engine =
            PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL")?)
                .await?;
        // Simulation requires the action to be disabled (its seeded state).
        sqlx::query("UPDATE actions SET enabled=FALSE WHERE name='nftables.block_incident_source'")
            .execute(owner.pool())
            .await?;
        let resource = format!("ip-pseudonym:bridge-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now();
        let event_id = owner
            .publish_event(
                "ssh_login_failure",
                "test-sensor",
                "critical",
                now,
                Some(&resource),
                serde_json::json!({"test": true}),
                serde_json::json!({}),
                &format!("test:policy-bridge-fixture:{resource}"),
            )
            .await?;
        let assessment_id = engine
            .persist_security_assessment(clawforge_storage::SecurityAssessmentUpsert {
                rule_id: "ssh_bruteforce",
                rule_version: "1",
                engine_version: "test",
                dedupe_key: &format!("ssh_bruteforce:v1:{resource}:{}", now.timestamp()),
                resource: &resource,
                severity: "critical",
                confidence: 99,
                summary: "bridge fixture",
                event_count: 20,
                window_seconds: 300,
                bucket_start: now,
                first_seen: now,
                last_seen: now,
                event_ids: &[event_id],
                threat_intel: Some(clawforge_storage::IpReputationHit {
                    source: "spamhaus_drop".to_string(),
                    confidence: 90,
                    last_seen: now,
                }),
            })
            .await?;
        let assessment = policy_engine
            .list_security_assessments(None, 500)
            .await?
            .into_iter()
            .find(|value| value.id == assessment_id)
            .expect("the fixture assessment must be listable");
        let count = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM execution_requests WHERE requested_by='policy-bridge' \
                 AND approval_context->'target'->>'pseudonym'=$1",
            )
            .bind(&resource)
            .fetch_one(owner.pool())
            .await
        };

        // Bridge off: the Block decision is recorded, nothing is enqueued.
        evaluate_assessment(&policy_engine, &assessment, None).await?;
        let decision: String = sqlx::query_scalar(
            "SELECT decision FROM security_policy_decisions WHERE assessment_id=$1",
        )
        .bind(assessment_id)
        .fetch_one(owner.pool())
        .await?;
        assert_eq!(decision, "block");
        assert_eq!(count().await?, 0);

        // Bridge in simulate mode: exactly one dry-run-only request, replay-safe.
        let pairs = [
            (bridge::MODE, "simulate"),
            (bridge::BLOCK_ACTION, "nftables.block_incident_source"),
            (bridge::TTL_SECONDS, "60"),
            (bridge::MAX_PER_WINDOW, "5"),
            (bridge::WINDOW_SECONDS, "300"),
            (bridge::MAX_EVIDENCE_AGE_SECONDS, "900"),
        ];
        let config = BridgeConfig::from_lookup(|name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, v)| v.to_string())
        })
        .map_err(anyhow::Error::msg)?
        .expect("bridge configured");
        evaluate_assessment(&policy_engine, &assessment, Some(&config)).await?;
        evaluate_assessment(&policy_engine, &assessment, Some(&config)).await?;
        assert_eq!(count().await?, 1);
        let (status, simulation): (String, serde_json::Value) = sqlx::query_as(
            "SELECT status, approval_context->'target'->'simulation_only' FROM execution_requests \
             WHERE requested_by='policy-bridge' AND approval_context->'target'->>'pseudonym'=$1",
        )
        .bind(&resource)
        .fetch_one(owner.pool())
        .await?;
        assert_eq!(status, "pending");
        assert_eq!(simulation, serde_json::json!(true));
        // Later PostgreSQL gates in this fixture assume no claimable request
        // is left behind; cancel the simulated one.
        sqlx::query(
            "UPDATE execution_requests SET status='cancelled' \
             WHERE requested_by='policy-bridge' AND approval_context->'target'->>'pseudonym'=$1",
        )
        .bind(&resource)
        .execute(owner.pool())
        .await?;
        Ok(())
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
                threat_intel: None,
            })
            .await?;

        let assessment = policy_engine
            .list_security_assessments(None, 500)
            .await?
            .into_iter()
            .find(|value| value.id == assessment_id)
            .expect("the fixture assessment must be listable");
        evaluate_assessment(&policy_engine, &assessment, None).await?;

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
        evaluate_assessment(&policy_engine, &assessment, None).await?;
        let decision_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_policy_decisions WHERE assessment_id=$1",
        )
        .bind(assessment_id)
        .fetch_one(owner.pool())
        .await?;
        assert_eq!(decision_count, 1);

        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
    async fn challenge_decision_enqueues_only_one_simulation_request_on_replay() -> Result<()> {
        let owner =
            PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
        let engine = PostgresStore::connect_runtime(&env::var(
            "CLAWFORGE_TEST_SECURITY_ENGINE_DATABASE_URL",
        )?)
        .await?;
        let policy_engine =
            PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL")?)
                .await?;
        let resource = format!("ip-pseudonym:challenge-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now();
        let assessment_id = engine
            .persist_security_assessment(clawforge_storage::SecurityAssessmentUpsert {
                rule_id: "ssh_bruteforce",
                rule_version: "1",
                engine_version: "test",
                dedupe_key: &format!("challenge-test:{resource}"),
                resource: &resource,
                severity: "medium",
                confidence: 50,
                summary: "test fixture",
                event_count: 5,
                window_seconds: 300,
                bucket_start: now,
                first_seen: now,
                last_seen: now,
                event_ids: &[],
                threat_intel: None,
            })
            .await?;
        let assessment = policy_engine
            .list_security_assessments(None, 500)
            .await?
            .into_iter()
            .find(|value| value.id == assessment_id)
            .expect("fixture assessment must be visible");
        evaluate_assessment(&policy_engine, &assessment, None).await?;
        evaluate_assessment(&policy_engine, &assessment, None).await?;

        let rows: Vec<(uuid::Uuid, String, bool, serde_json::Value)> = sqlx::query_as(
            "SELECT e.id,a.name,a.enabled,e.approval_context FROM execution_requests e \
             JOIN actions a ON a.id=e.action_id \
             WHERE e.approval_context->>'security_policy_decision_id' = \
                   (SELECT id::text FROM security_policy_decisions WHERE assessment_id=$1)",
        )
        .bind(assessment_id)
        .fetch_all(owner.pool())
        .await?;
        assert_eq!(rows.len(), 1, "replay must not queue duplicate executions");
        let (request_id, action_name, enabled, context) = &rows[0];
        assert_eq!(action_name, "goaway.challenge_incident_source");
        assert!(!enabled);
        assert_eq!(context["target"]["simulation_only"], true);
        assert_eq!(context["target"]["pseudonym"], resource);

        sqlx::query("DELETE FROM execution_requests WHERE id=$1")
            .bind(request_id)
            .execute(owner.pool())
            .await?;
        sqlx::query("DELETE FROM security_policy_decisions WHERE assessment_id=$1")
            .bind(assessment_id)
            .execute(owner.pool())
            .await?;
        sqlx::query("DELETE FROM security_assessments WHERE id=$1")
            .bind(assessment_id)
            .execute(owner.pool())
            .await?;
        Ok(())
    }
}
