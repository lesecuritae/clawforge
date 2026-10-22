//! What counts as a second, independent evidence source. Two rules over the
//! same events, overlapping buckets of one rule, an ongoing episode and
//! operational observations must not corroborate each other; a different event
//! family or an earlier episode may.
use super::*;
use chrono::{DateTime, Duration, Utc};
use clawforge_storage::SecurityAssessment;
use uuid::Uuid;

struct Env {
    owner: PostgresStore,
    policy: PostgresStore,
    resource: String,
    serial: u32,
}

impl Env {
    async fn new() -> Result<Self> {
        Ok(Self {
            owner: PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_DATABASE_URL")?)
                .await?,
            policy: PostgresStore::connect_runtime(&env::var(
                "CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL",
            )?)
            .await?,
            resource: format!("ip-pseudonym:independence-{}", Uuid::new_v4()),
            serial: 0,
        })
    }

    async fn events(&mut self, event_type: &str, at: DateTime<Utc>, n: usize) -> Result<Vec<Uuid>> {
        let mut ids = Vec::new();
        for i in 0..n {
            self.serial += 1;
            let id = self
                .owner
                .publish_event(
                    event_type,
                    "test-sensor",
                    "low",
                    at + Duration::seconds(i as i64),
                    Some(&self.resource),
                    serde_json::json!({"path": format!("/p{i}"), "status_code": 404}),
                    serde_json::json!({}),
                    &format!("independence:{}:{}", self.resource, self.serial),
                )
                .await?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// An assessment of `rule` over the given events, last active at `last_seen`.
    async fn assessment(
        &self,
        rule: &str,
        bucket_start: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        event_ids: &[Uuid],
    ) -> Result<SecurityAssessment> {
        let dedupe = format!(
            "{rule}:v2:{}:{}:{}",
            self.resource,
            bucket_start.timestamp(),
            event_ids.len()
        );
        let id = self
            .owner
            .persist_security_assessment(clawforge_storage::SecurityAssessmentUpsert {
                rule_id: rule,
                rule_version: "2",
                engine_version: "test",
                dedupe_key: &dedupe,
                resource: &self.resource,
                severity: "critical",
                confidence: 90,
                summary: "independence fixture",
                event_count: event_ids.len().max(1) as i32,
                window_seconds: 300,
                bucket_start,
                first_seen: bucket_start,
                last_seen,
                event_ids,
                threat_intel: None,
            })
            .await?;
        Ok(SecurityAssessment {
            id,
            rule_id: rule.to_string(),
            rule_version: "2".into(),
            resource: self.resource.clone(),
            severity: "critical".into(),
            confidence: 90,
            summary: String::new(),
            event_count: event_ids.len().max(1) as i32,
            bucket_start,
            incident_id: None,
            threat_intel_corroborated: false,
            threat_intel: None,
        })
    }

    async fn basis(&self, target: &SecurityAssessment) -> Result<(i16, &'static str)> {
        let evidence = independent_evidence_for(&self.policy, target).await?;
        Ok((evidence.sources, evidence.basis))
    }
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn a_different_event_family_is_independent_evidence() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let ssh = e.events("ssh_login_failure", now, 5).await?;
    let target = e.assessment("ssh_bruteforce", now, now, &ssh).await?;
    assert_eq!(e.basis(&target).await?, (1, "behavior_only"));
    // The same source separately scans over HTTP, a different observation.
    let http = e
        .events("http_anomaly", now + Duration::minutes(10), 8)
        .await?;
    e.assessment(
        "http_scan",
        now + Duration::minutes(10),
        now + Duration::minutes(10),
        &http,
    )
    .await?;
    assert_eq!(e.basis(&target).await?, (2, "independent_event_family"));
    Ok(())
}

/// The reported weakness: two rules counting the same HTTP events are one
/// observation, so a legitimate burst that trips both must not look corroborated.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn two_rules_over_the_same_http_events_are_one_observation() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let http = e.events("http_anomaly", now, 12).await?;
    let scan = e.assessment("http_scan", now, now, &http).await?;
    let burst = e.assessment("http_anomaly_burst", now, now, &http).await?;
    assert_eq!(e.basis(&scan).await?, (1, "behavior_only"));
    assert_eq!(e.basis(&burst).await?, (1, "behavior_only"));
    // Event-disjoint buckets of the same family are still one family.
    let later = e
        .events("http_anomaly", now + Duration::minutes(8), 12)
        .await?;
    e.assessment(
        "http_scan",
        now + Duration::minutes(8),
        now + Duration::minutes(8),
        &later,
    )
    .await?;
    assert_eq!(e.basis(&burst).await?, (1, "behavior_only"));
    Ok(())
}

/// With staggered windows one burst yields two overlapping assessments of one
/// rule; they must never corroborate each other.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn overlapping_buckets_of_one_rule_do_not_corroborate_themselves() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let ssh = e.events("ssh_login_failure", now, 8).await?;
    let primary = e.assessment("ssh_bruteforce", now, now, &ssh[..5]).await?;
    let shifted = e
        .assessment("ssh_bruteforce", now - Duration::seconds(150), now, &ssh)
        .await?;
    assert_eq!(e.basis(&primary).await?, (1, "behavior_only"));
    assert_eq!(e.basis(&shifted).await?, (1, "behavior_only"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn observation_only_rules_and_eventless_assessments_never_corroborate() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let ssh = e.events("ssh_login_failure", now, 5).await?;
    let target = e.assessment("ssh_bruteforce", now, now, &ssh).await?;
    // A server-fault burst of a different family says nothing about intent.
    let faults = e.events("http_anomaly", now, 12).await?;
    e.assessment("http_server_fault_burst", now, now, &faults)
        .await?;
    assert_eq!(e.basis(&target).await?, (1, "behavior_only"));
    // An assessment that records no events cannot be shown to be independent.
    e.assessment("http_scan", now, now, &[]).await?;
    assert_eq!(e.basis(&target).await?, (1, "behavior_only"));
    // A prior-episode observation-only record is ignored in history, too.
    let old = now - Duration::hours(5);
    let old_faults = e.events("http_anomaly", old, 12).await?;
    e.assessment("http_server_fault_burst", old, old, &old_faults)
        .await?;
    assert_eq!(e.basis(&target).await?, (1, "behavior_only"));
    Ok(())
}

/// Recurrence is evidence only across episodes: an earlier episode counts, the
/// ongoing one does not.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn history_counts_only_earlier_episodes() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let current = e.events("ssh_login_failure", now, 5).await?;
    let target = e.assessment("ssh_bruteforce", now, now, &current).await?;
    let same_episode_at = now - Duration::minutes(30);
    let same_episode = e.events("ssh_login_failure", same_episode_at, 5).await?;
    e.assessment(
        "ssh_bruteforce",
        same_episode_at,
        same_episode_at,
        &same_episode,
    )
    .await?;
    assert_eq!(
        e.basis(&target).await?,
        (1, "behavior_only"),
        "30 min earlier is the same episode"
    );
    let earlier_at = now - Duration::hours(3);
    let earlier = e.events("ssh_login_failure", earlier_at, 5).await?;
    e.assessment("ssh_bruteforce", earlier_at, earlier_at, &earlier)
        .await?;
    assert_eq!(e.basis(&target).await?, (2, "prior_episode_history"));
    // Causality: a later episode is not history for an earlier assessment.
    let first = e
        .assessment("ssh_bruteforce", earlier_at, earlier_at, &earlier)
        .await?;
    let later_target = e
        .assessment(
            "ssh_bruteforce",
            now + Duration::hours(2),
            now + Duration::hours(2),
            &current,
        )
        .await?;
    assert_eq!(e.basis(&later_target).await?.0, 2);
    assert_eq!(e.basis(&first).await?.1, "behavior_only");
    Ok(())
}

/// Observation-only rules are recorded as `observe` decisions: never a
/// challenge, rate limit or block, whatever the confidence.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn a_server_fault_observation_is_recorded_as_observe_only() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let faults = e.events("http_anomaly", now, 40).await?;
    let mut target = e
        .assessment("http_server_fault_burst", now, now, &faults)
        .await?;
    target.confidence = 99;
    evaluate_assessment(&e.policy, &target, None).await?;
    let rows: Vec<(String, bool, String)> = sqlx::query_as(
        "SELECT decision, corroborated, rationale FROM security_policy_decisions WHERE assessment_id=$1",
    )
    .bind(target.id)
    .fetch_all(e.owner.pool())
    .await?;
    assert_eq!(
        rows.len(),
        1,
        "the seeded observe policy must record the observation"
    );
    assert_eq!(rows[0].0, "observe");
    assert!(!rows[0].1);
    assert!(rows[0].2.contains("observation_only=true"));
    assert!(rows[0].2.contains("evidence_basis=observation_only"));
    let sources: i16 = sqlx::query_scalar(
        "SELECT evidence_sources FROM security_policy_decisions WHERE assessment_id=$1",
    )
    .bind(target.id)
    .fetch_one(e.owner.pool())
    .await?;
    assert_eq!(sources, 1, "an observation never claims a second source");
    let challenges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM execution_requests WHERE approval_context->'target'->>'pseudonym'=$1",
    )
    .bind(&e.resource)
    .fetch_one(e.owner.pool())
    .await?;
    assert_eq!(challenges, 0);
    Ok(())
}

/// An attack that runs for hours is one episode; its early buckets must not be
/// "earlier history" for its later ones.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn a_long_sustained_attack_does_not_corroborate_itself() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let mut last = None;
    for step in 0..36 {
        // A bucket every five minutes for three hours, each with its own events.
        let at = now - Duration::minutes(5 * (35 - step));
        let ids = e.events("ssh_login_failure", at, 5).await?;
        last = Some(e.assessment("ssh_bruteforce", at, at, &ids).await?);
    }
    let latest = last.unwrap();
    assert_eq!(e.basis(&latest).await?, (1, "behavior_only"));
    Ok(())
}

/// One past episode counts once, however many rows (window grids, rules) it left.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn one_old_episode_counts_once_not_once_per_assessment_row() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let current = e.events("ssh_login_failure", now, 5).await?;
    let target = e.assessment("ssh_bruteforce", now, now, &current).await?;
    // 28 days = two half-lives: a single episode is worth 0.25, below the 0.5 minimum.
    let old = now - Duration::days(28);
    for row in 0..4 {
        let at = old + Duration::seconds(150 * row);
        let ids = e.events("ssh_login_failure", at, 5).await?;
        e.assessment("ssh_bruteforce", at, at, &ids).await?;
    }
    assert_eq!(e.basis(&target).await?, (1, "behavior_only"));
    // A second, separate old episode adds its own term, and enough recent ones corroborate.
    let recent = now - Duration::days(2);
    let ids = e.events("ssh_login_failure", recent, 5).await?;
    e.assessment("ssh_bruteforce", recent, recent, &ids).await?;
    assert_eq!(e.basis(&target).await?, (2, "prior_episode_history"));
    Ok(())
}

/// Overlapping windows of one episode produce several decisions but one
/// simulated challenge per source.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn overlapping_decisions_share_one_simulated_challenge() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let ids = e.events("ssh_login_failure", now, 6).await?;
    let mut primary = e.assessment("ssh_bruteforce", now, now, &ids[..5]).await?;
    let mut shifted = e
        .assessment("ssh_bruteforce", now - Duration::seconds(150), now, &ids)
        .await?;
    // Confidence 60 is a challenge decision (40-69).
    primary.confidence = 60;
    shifted.confidence = 60;
    evaluate_assessment(&e.policy, &primary, None).await?;
    evaluate_assessment(&e.policy, &shifted, None).await?;
    let decisions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_policy_decisions WHERE assessment_id = ANY($1)",
    )
    .bind(vec![primary.id, shifted.id])
    .fetch_one(e.owner.pool())
    .await?;
    assert_eq!(
        decisions, 2,
        "each assessment keeps its own decision record"
    );
    let simulations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM execution_requests WHERE approval_context->'target'->>'pseudonym'=$1",
    )
    .bind(&e.resource)
    .fetch_one(e.owner.pool())
    .await?;
    assert_eq!(simulations, 1);
    // Later PostgreSQL gates in the shared fixture assume no claimable request is
    // left behind; cancel the simulation.
    sqlx::query(
        "UPDATE execution_requests SET status='cancelled' \
         WHERE approval_context->'target'->>'pseudonym'=$1",
    )
    .bind(&e.resource)
    .execute(e.owner.pool())
    .await?;
    Ok(())
}

/// The hourly SSH rule watches the same failures as the five-minute rule: a slow attacker
/// found by the hourly rule is one observation, and a source that trips both is not
/// "corroborated" by its own failed logins.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn the_hourly_ssh_rule_is_the_same_family_as_the_five_minute_rule() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let ssh = e.events("ssh_login_failure", now, 20).await?;
    let slow = e.assessment("ssh_bruteforce_slow", now, now, &ssh).await?;
    let fast = e.assessment("ssh_bruteforce", now, now, &ssh[..5]).await?;
    assert_eq!(e.basis(&slow).await?, (1, "behavior_only"));
    assert_eq!(e.basis(&fast).await?, (1, "behavior_only"));
    // A genuinely different family still corroborates the slow finding.
    let http = e
        .events("http_anomaly", now + Duration::minutes(10), 8)
        .await?;
    e.assessment(
        "http_scan",
        now + Duration::minutes(10),
        now + Duration::minutes(10),
        &http,
    )
    .await?;
    assert_eq!(e.basis(&slow).await?, (2, "independent_event_family"));
    Ok(())
}

impl Env {
    /// Events of one family with explicit payloads (usernames, paths), oldest first.
    async fn events_with(
        &mut self,
        event_type: &str,
        at: DateTime<Utc>,
        payloads: Vec<serde_json::Value>,
    ) -> Result<Vec<Uuid>> {
        let mut ids = Vec::new();
        for (i, payload) in payloads.into_iter().enumerate() {
            self.serial += 1;
            ids.push(
                self.owner
                    .publish_event(
                        event_type,
                        "test-sensor",
                        "low",
                        at + Duration::seconds(i as i64),
                        Some(&self.resource),
                        payload,
                        serde_json::json!({}),
                        &format!("shape:{}:{}", self.resource, self.serial),
                    )
                    .await?,
            );
        }
        Ok(ids)
    }

    async fn shape(
        &self,
        target: &SecurityAssessment,
    ) -> Result<clawforge_storage::AssessmentShape> {
        self.policy
            .assessment_shape(
                target.id,
                &attack_shape::ShapeConfig::from_env().path_patterns,
            )
            .await
    }
}

fn ssh(user: &str) -> serde_json::Value {
    serde_json::json!({"username": user, "attempt_count": 1})
}

fn http(path: &str) -> serde_json::Value {
    serde_json::json!({"path": path, "status_code": 404})
}

/// Users behind one NAT mistype a few valid accounts; a dictionary run walks through names. The
/// same number of failed logins is `behavior_only` in the first case and carries the extra,
/// content-based observation in the second.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn many_account_names_are_enumeration_a_few_are_a_nat() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let nat = e
        .events_with(
            "ssh_login_failure",
            now,
            [
                "alice", "bob", "alice", "carol", "bob", "alice", "dave", "alice", "bob", "carol",
            ]
            .into_iter()
            .map(ssh)
            .collect(),
        )
        .await?;
    let nat_assessment = e.assessment("ssh_bruteforce", now, now, &nat).await?;
    let counts = e.shape(&nat_assessment).await?;
    assert_eq!(
        (
            counts.events,
            counts.distinct_usernames,
            counts.signature_paths
        ),
        (10, 4, 0)
    );
    assert_eq!(e.basis(&nat_assessment).await?, (1, "behavior_only"));

    let mut e = Env::new().await?;
    let names = [
        "root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "user", "guest", "pi",
    ];
    let attack = e
        .events_with(
            "ssh_login_failure",
            now,
            names.into_iter().map(ssh).collect(),
        )
        .await?;
    let attack_assessment = e.assessment("ssh_bruteforce", now, now, &attack).await?;
    assert_eq!(e.shape(&attack_assessment).await?.distinct_usernames, 10);
    assert_eq!(e.basis(&attack_assessment).await?, (2, "attack_shape"));
    // upper/lower case of one account is one account
    let mut e = Env::new().await?;
    let same = e
        .events_with(
            "ssh_login_failure",
            now,
            (0..10)
                .map(|i| ssh(if i % 2 == 0 { "Root" } else { "ROOT" }))
                .collect(),
        )
        .await?;
    let same_assessment = e.assessment("ssh_bruteforce", now, now, &same).await?;
    assert_eq!(e.shape(&same_assessment).await?.distinct_usernames, 1);
    assert_eq!(e.basis(&same_assessment).await?, (1, "behavior_only"));
    Ok(())
}

/// A broken asset release produces many 404s for application files; a scanner asks for secrets.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn secret_path_probes_are_shape_evidence_missing_assets_are_not() -> Result<()> {
    let now = Utc::now();
    let mut e = Env::new().await?;
    let assets: Vec<_> = (0..12)
        .map(|i| http(&format!("/static/app.{i:04x}.js")))
        .chain([
            http("/robots.txt"),
            http("/.well-known/security.txt"),
            http("/favicon.ico"),
        ])
        .collect();
    let ids = e.events_with("http_anomaly", now, assets).await?;
    let missing = e.assessment("http_scan", now, now, &ids).await?;
    assert_eq!(e.shape(&missing).await?.signature_paths, 0);
    assert_eq!(e.basis(&missing).await?, (1, "behavior_only"));

    let mut e = Env::new().await?;
    let two = e
        .events_with(
            "http_anomaly",
            now,
            vec![http("/.env"), http("/.env?x=1")]
                .into_iter()
                .chain((0..10).map(|i| http(&format!("/static/a{i}.js"))))
                .collect(),
        )
        .await?;
    let two_assessment = e.assessment("http_scan", now, now, &two).await?;
    assert_eq!(
        e.shape(&two_assessment).await?.signature_paths,
        2,
        "query string variants of the same file are distinct paths"
    );
    assert_eq!(e.basis(&two_assessment).await?, (1, "behavior_only"));

    let mut e = Env::new().await?;
    let probes = [
        "/.env",
        "/config/.env",
        "/.git/config",
        "/.aws/credentials",
        "/aws/credentials",
        "/.docker/config.json",
        "/.pypirc",
        "/backend/.env.production.local",
        "/.ssh/id_rsa",
        "/id_rsa",
    ];
    let ids = e
        .events_with("http_anomaly", now, probes.into_iter().map(http).collect())
        .await?;
    let scan = e.assessment("http_scan", now, now, &ids).await?;
    assert_eq!(e.shape(&scan).await?.signature_paths, probes.len() as i64);
    assert_eq!(e.basis(&scan).await?, (2, "attack_shape"));
    Ok(())
}

/// Reputation and the existing independence rules keep their precedence; the shape is shown in
/// the evidence even when it is not what counts.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn the_shape_function_returns_numbers_only_and_is_bounded() -> Result<()> {
    let mut e = Env::new().await?;
    let now = Utc::now();
    let ids = e
        .events_with("ssh_login_failure", now, vec![ssh("root"), ssh("admin")])
        .await?;
    let a = e.assessment("ssh_bruteforce", now, now, &ids).await?;
    let value: serde_json::Value = sqlx::query_scalar("SELECT clawforge_assessment_shape($1, $2)")
        .bind(a.id)
        .bind(Vec::<String>::new())
        .fetch_one(e.policy.pool())
        .await?;
    let text = value.to_string();
    assert!(!text.contains("root") && !text.contains("admin"), "{text}");
    assert_eq!(value["distinct_usernames"], 2);
    // too many or too long patterns are refused
    let too_many: Vec<String> = (0..51).map(|i| format!("^/p{i}$")).collect();
    assert!(sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT clawforge_assessment_shape($1, $2)"
    )
    .bind(a.id)
    .bind(&too_many)
    .fetch_one(e.policy.pool())
    .await
    .is_err());
    Ok(())
}
