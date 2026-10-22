//! Stages 2-4 of the behavioural acceptance: evidence, policy decision and
//! enforcement request, for the same labelled cases whose raw detector result
//! stage 1 (security-engine) reports. Runs only against the isolated behaviour
//! database the harness provisions; it never touches a firewall.
//!
//! Worst case on purpose: every attacker-rule policy is promoted to class
//! `automatic` and the bridge is configured in `automatic` and in `propose`
//! mode. Whether a request appears must then depend on independent evidence
//! alone - no scenario ID, address, pattern name or hidden label is consulted.
use super::*;
use anyhow::Context;
use bridge::BridgeConfig;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

const RANK: [&str; 5] = ["none", "observe", "challenge", "rate_limit", "block"];

fn rank(decision: &str) -> usize {
    RANK.iter().position(|d| *d == decision).unwrap_or(0)
}

fn bridge_config(mode: &str, rule: &str, requester: Option<Uuid>) -> Result<BridgeConfig> {
    let ack = format!("unattended:{rule}:nftables.block_incident_source:-:60:100/3600:3600:50");
    let requester = requester.map(|id| id.to_string());
    BridgeConfig::from_lookup(|name| match name {
        bridge::MODE => Some(mode.to_string()),
        bridge::BLOCK_ACTION => Some("nftables.block_incident_source".into()),
        bridge::TTL_SECONDS => Some("60".into()),
        bridge::MAX_PER_WINDOW => Some("100".into()),
        bridge::WINDOW_SECONDS => Some("3600".into()),
        bridge::MAX_EVIDENCE_AGE_SECONDS => Some("3600".into()),
        bridge::MIN_INTEL_CONFIDENCE => Some("50".into()),
        bridge::RULE_ID => Some(rule.to_string()),
        bridge::REQUESTER_ID if mode == "propose" => requester.clone(),
        bridge::AUTOMATIC_ACK if mode == "automatic" => Some(ack.clone()),
        _ => None,
    })
    .map_err(anyhow::Error::msg)?
    .context("bridge configuration must be enabled")
}

#[tokio::test]
#[ignore = "requires the isolated behaviour database after the security-engine golden run"]
async fn evidence_decision_and_enforcement_stages_for_the_labelled_cases() -> Result<()> {
    let out = std::path::PathBuf::from(env::var("CLAWFORGE_BEHAVIOR_REPORT_DIR")?);
    let owner = PostgresStore::connect_runtime(&env::var("CLAWFORGE_BEHAVIOR_OWNER_URL")?).await?;
    let policy =
        PostgresStore::connect_runtime(&env::var("CLAWFORGE_BEHAVIOR_POLICY_URL")?).await?;
    let user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(policy.pool())
        .await?;
    assert_eq!(user, "clawforge_policy_engine");
    let plan: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/behavior-validation/scenarios.json"
    ))?;
    let stage1: Value = serde_json::from_slice(&std::fs::read(out.join("behavior-report.json"))?)?;
    let mut resources: BTreeMap<String, String> = BTreeMap::new();
    for case in stage1["golden_cases"].as_array().context("stage 1 cases")? {
        if let Some(resource) = case["resource"].as_str() {
            resources.insert(
                case["id"].as_str().unwrap().to_string(),
                resource.to_string(),
            );
        }
    }
    assert!(!resources.is_empty());
    let all: Vec<String> = resources.values().cloned().collect();

    // The fixtures carry fixed 2026-01-01 timestamps. Evidence freshness is a
    // real gate, so move the whole labelled data set forward by a multiple of
    // the window length (grid alignment and relative timing are unchanged).
    let first_epoch = 1_767_268_800_i64;
    let shift = ((chrono::Utc::now().timestamp() - 600 - first_epoch) / 300) * 300;
    sqlx::query("UPDATE events SET occurred_at = occurred_at + ($2 * INTERVAL '1 second') WHERE correlation_id = ANY($1)")
        .bind(&all).bind(shift).execute(owner.pool()).await?;
    sqlx::query("UPDATE security_assessments SET bucket_start = bucket_start + ($2 * INTERVAL '1 second'), first_seen = first_seen + ($2 * INTERVAL '1 second'), last_seen = last_seen + ($2 * INTERVAL '1 second') WHERE resource = ANY($1)")
        .bind(&all).bind(shift).execute(owner.pool()).await?;

    // Worst case: attacker-rule policies promoted to automatic (the server-fault
    // observation policy stays observe-only).
    sqlx::query("UPDATE security_policies SET class='automatic' WHERE rule_id IN ('ssh_bruteforce','http_scan','http_anomaly_burst')")
        .execute(owner.pool()).await?;

    // Stage 3: decisions from the real policy path, no bridge yet.
    let assessments = policy.list_security_assessments(None, 5000).await?;
    let mine: Vec<_> = assessments
        .iter()
        .filter(|a| all.contains(&a.resource))
        .collect();
    for assessment in &mine {
        evaluate_assessment(&policy, assessment, None).await?;
    }
    let before_bridge: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM execution_requests WHERE requested_by='policy-bridge'",
    )
    .fetch_one(owner.pool())
    .await?;
    assert_eq!(
        before_bridge, 0,
        "decisions alone must not create bridge requests"
    );

    // Stage 4: enforcement requests with the bridge in the two live modes.
    sqlx::query("INSERT INTO runtime_status (component,state,version,last_heartbeat_at) VALUES ('executor','running','behavior-fixture',NOW()) ON CONFLICT (component) DO UPDATE SET state='running', last_heartbeat_at=NOW()")
        .execute(owner.pool()).await?;
    let operator = owner
        .create_admin_user("behavior-fixture-requester", "Operator", "!")
        .await?;
    let mut requests: BTreeMap<String, BTreeMap<&str, Vec<String>>> = BTreeMap::new();
    let mut reasons: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (mode, approval) in [("automatic", false), ("propose", true)] {
        sqlx::query("UPDATE actions SET enabled=TRUE, requires_approval=$1 WHERE name='nftables.block_incident_source'")
            .bind(approval).execute(owner.pool()).await?;
        for rule in ["ssh_bruteforce", "http_scan"] {
            let config = bridge_config(mode, rule, (mode == "propose").then_some(operator))?;
            for assessment in mine.iter().filter(|a| a.rule_id == rule) {
                evaluate_assessment(&policy, assessment, Some(&config)).await?;
                // Diagnostics only: why the bridge accepted or declined this decision.
                let decision: Option<(Uuid, String)> = sqlx::query_as(
                    "SELECT id, decision FROM security_policy_decisions WHERE assessment_id=$1",
                )
                .bind(assessment.id)
                .fetch_optional(owner.pool())
                .await?;
                if let Some((decision_id, kind)) = decision {
                    if let Some(params) = config.params_for(kind == "rate_limit") {
                        if matches!(kind.as_str(), "block" | "rate_limit") {
                            // Read-only: the plan function never writes.
                            let (reason, existing): (Option<String>, Option<Uuid>) = sqlx::query_as(
                                "SELECT reason, existing_request_id FROM clawforge_policy_bridge_plan($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                            )
                            .bind(decision_id)
                            .bind(params.mode.as_str())
                            .bind(&params.action_name)
                            .bind(params.ttl_seconds)
                            .bind(params.requester_id)
                            .bind(params.rule_id.as_deref())
                            .bind(params.max_evidence_age_seconds)
                            .bind(params.require_threat_intel)
                            .bind(params.min_intel_confidence)
                            .fetch_one(policy.pool())
                            .await?;
                            reasons
                                .entry(assessment.resource.clone())
                                .or_default()
                                .push(format!(
                                "{mode}/{rule}/{kind}: plan reason={reason:?} request_exists={}",
                                existing.is_some()
                            ));
                        }
                    }
                }
            }
        }
        for (id, resource) in &resources {
            let statuses: Vec<String> = sqlx::query_scalar(
                "SELECT status FROM execution_requests WHERE requested_by='policy-bridge' \
                 AND approval_context->'target'->>'pseudonym'=$1 \
                 AND approval_context->'policy_bridge'->>'mode'=$2",
            )
            .bind(resource)
            .bind(mode)
            .fetch_all(owner.pool())
            .await?;
            requests
                .entry(id.clone())
                .or_default()
                .insert(mode, statuses);
        }
        sqlx::query("UPDATE execution_requests SET status='cancelled' WHERE requested_by='policy-bridge' AND status IN ('pending','waiting_approval')")
            .execute(owner.pool()).await?;
    }
    sqlx::query("UPDATE actions SET enabled=FALSE, requires_approval=TRUE WHERE name='nftables.block_incident_source'")
        .execute(owner.pool()).await?;
    sqlx::query("UPDATE security_policies SET class='observe' WHERE rule_id IN ('ssh_bruteforce','http_scan','http_anomaly_burst')")
        .execute(owner.pool()).await?;

    let (mut tp, mut fp, mut tn, mut fn_) = (0, 0, 0, 0);
    let mut rows = Vec::new();
    let mut mismatches: Vec<String> = Vec::new();
    for case in plan["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let attack = case["label_attack"].as_bool().unwrap();
        let mut decisions: Vec<Value> = Vec::new();
        let mut strongest = "none";
        let mut finding = false;
        if let Some(resource) = resources.get(id) {
            let found: Vec<(String, String, i16, bool, i16, String)> = sqlx::query_as(
                "SELECT a.rule_id, d.decision, d.evidence_sources, d.corroborated, a.confidence, d.rationale \
                 FROM security_policy_decisions d JOIN security_assessments a ON a.id=d.assessment_id \
                 WHERE a.resource=$1 ORDER BY a.rule_id, a.bucket_start",
            )
            .bind(resource)
            .fetch_all(owner.pool())
            .await?;
            for (rule, decision, sources, corroborated, confidence, rationale) in found {
                let observation_only = rationale.contains("observation_only=true");
                let basis = rationale
                    .split("evidence_basis=")
                    .nth(1)
                    .and_then(|rest| rest.split(',').next())
                    .unwrap_or("?")
                    .to_string();
                if rank(&decision) > rank(strongest) {
                    strongest = RANK[rank(&decision)];
                }
                // An attacker finding needs a second, independent evidence source.
                finding |= corroborated && !observation_only;
                decisions.push(
                    json!({"rule":rule,"decision":decision,"evidence_sources":sources,
                    "corroborated":corroborated,"confidence":confidence,"evidence_basis":basis,
                    "observation_only":observation_only}),
                );
            }
        }
        match (attack, finding) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (false, false) => tn += 1,
            (true, false) => fn_ += 1,
        }
        let empty = BTreeMap::new();
        let by_mode = requests.get(id).unwrap_or(&empty);
        let automatic = by_mode.get("automatic").cloned().unwrap_or_default();
        let propose = by_mode.get("propose").cloned().unwrap_or_default();
        let expected = case["expected_enforcement_requests"].as_u64().unwrap() as usize;
        let expected_decision = case["expected_strongest_decision"].as_str().unwrap();
        if strongest != expected_decision {
            mismatches.push(format!(
                "strongest decision for {id}: got {strongest}, expected {expected_decision}: {decisions:?}"
            ));
        }
        let why = resources
            .get(id)
            .and_then(|r| reasons.get(r))
            .cloned()
            .unwrap_or_default();
        if automatic.len() != expected {
            mismatches.push(format!(
                "automatic requests for {id}: {} != {expected}: {why:?}",
                automatic.len()
            ));
        }
        if propose.len() != expected {
            mismatches.push(format!(
                "propose requests for {id}: {} != {expected}: {why:?}",
                propose.len()
            ));
        }
        if expected == 1
            && (automatic != vec!["pending".to_string()]
                || propose != vec!["waiting_approval".to_string()])
        {
            mismatches.push(format!(
                "request states for {id}: {automatic:?} / {propose:?}"
            ));
        }
        if !attack && !(automatic.is_empty() && propose.is_empty()) {
            mismatches.push(format!(
                "legitimate case {id} must never produce an enforcement request"
            ));
        }
        rows.push(
            json!({"id":id,"label_attack":attack,"strongest_decision":strongest,
            "attacker_finding_independent_evidence":finding,"decisions":decisions,
            "enforcement_requests":{"automatic":automatic,"propose":propose,"expected":expected}}),
        );
    }
    // Only Go-Away simulations and the bridge's own cancelled requests exist.
    let real_other: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM execution_requests WHERE requested_by<>'policy-bridge' \
         AND COALESCE((approval_context->'target'->>'simulation_only')::boolean,FALSE)=FALSE",
    )
    .fetch_one(owner.pool())
    .await?;
    assert_eq!(real_other, 0, "no non-simulated request outside the bridge");
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM execution_requests WHERE status NOT IN ('cancelled') \
         AND COALESCE((approval_context->'target'->>'simulation_only')::boolean,FALSE)=FALSE",
    )
    .fetch_one(owner.pool())
    .await?;
    assert_eq!(
        live, 0,
        "every worst-case enforcement request was cancelled by the test"
    );
    let report = json!({"schema_version":1,
        "stages":"2 independent evidence -> 3 policy decision -> 4 enforcement request (bridge automatic and propose, all attacker policies promoted to automatic)",
        "attacker_finding_matrix":{"tp":tp,"fp":fp,"tn":tn,"fn":fn_,
            "definition":"finding = at least one non-observation decision corroborated by a second independent evidence source"},
        "time_shift_seconds":shift,"cases":rows,
        "not_covered":"packets and executor effects are covered by the separate packet lab; the bridge stops at the request",
        "not_a_production_approval":true});
    std::fs::write(
        out.join("policy-stage-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    // Reported after the artifact is written, all at once, so a review sees every difference.
    assert!(
        mismatches.is_empty(),
        "expectation mismatches:\n{}",
        mismatches.join("\n")
    );
    Ok(())
}
