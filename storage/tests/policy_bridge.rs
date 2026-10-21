//! Policy -> execution bridge (migration 0060): every refusal path, the three
//! action-state modes, budgets/duplicates/health, the least-privilege role, and
//! the full chain propose -> two approvals -> executor claim.
use anyhow::Result;
use clawforge_storage::{
    BridgeMode, BridgeOutcome, NetworkContextOutcome, PolicyBridgeParams, PostgresStore,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, ConnectOptions, PgPool};
use std::str::FromStr;
use uuid::Uuid;

const BLOCK: &str = "nftables.block_incident_source";

#[tokio::test]
#[ignore = "requires explicit disposable owner, policy-engine and executor database URLs"]
async fn bridge_is_gated_by_database_facts_not_by_the_caller() -> Result<()> {
    let base = std::env::var("CLAWFORGE_TEST_DATABASE_URL")?;
    let policy_base = std::env::var("CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL")?;
    let executor_base = std::env::var("CLAWFORGE_TEST_EXECUTOR_DATABASE_URL")?;
    let admin = PgPool::connect(&base).await?;
    let database = format!("policy_bridge_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await?;
    let url = |base: &str| -> Result<String> {
        Ok(PgConnectOptions::from_str(base)?
            .database(&database)
            .to_url_lossy()
            .to_string())
    };
    let (owner, policy, executor) = (url(&base)?, url(&policy_base)?, url(&executor_base)?);
    let result = tokio::spawn(async move { check(&owner, &policy, &executor).await }).await;
    let cleanup = sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&admin)
        .await;
    admin.close().await;
    cleanup?;
    result??;
    Ok(())
}

struct Env {
    owner: PostgresStore,
    bridge: PostgresStore,
    /// pseudonym -> address handed out by `resolve`, and the pseudonyms whose
    /// address must be listed by a reputation indicator (current-view evidence).
    ips: std::sync::Mutex<std::collections::HashMap<String, String>>,
    wanted: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl Env {
    fn pool(&self) -> &PgPool {
        self.owner.pool()
    }

    async fn policy(&self, class: &str, rule: &str) -> Result<Uuid> {
        self.policy_sev(class, rule, "medium").await
    }

    async fn policy_sev(&self, class: &str, rule: &str, min_severity: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO security_policies(id,name,version,status,class,rule_id,min_severity) VALUES($1,$2,1,'active',$3,$4,$5)")
            .bind(id).bind(format!("bridge-{id}")).bind(class).bind(rule).bind(min_severity)
            .execute(self.pool()).await?;
        Ok(id)
    }

    /// A pseudonymized assessment, its single-host resolution and a Block decision.
    async fn decision(
        &self,
        policy: Uuid,
        pseudonym: &str,
        intel: bool,
        age_secs: i64,
    ) -> Result<Uuid> {
        if intel {
            self.wanted.lock().unwrap().insert(pseudonym.to_string());
            let known = self.ips.lock().unwrap().get(pseudonym).cloned();
            if let Some(ip) = known {
                self.list(&ip, 80, 0).await?;
            }
        }
        let assessment = Uuid::new_v4();
        sqlx::query("INSERT INTO security_assessments(id,rule_id,rule_version,engine_version,dedupe_key,resource,severity,confidence,summary,event_count,window_seconds,bucket_start,first_seen,last_seen,threat_intel_corroborated,threat_intel_source,threat_intel_confidence,threat_intel_indicator_last_seen) \
                      VALUES($1,'ssh_bruteforce','1','1',$2,$3,'high',90,'s',5,300,NOW(),NOW(),NOW()-($4*INTERVAL '1 second'),$5,$6,$7,$8)")
            .bind(assessment).bind(format!("d-{assessment}")).bind(pseudonym).bind(age_secs).bind(intel)
            .bind(intel.then_some("spamhaus")).bind(intel.then_some(80_i16)).bind(intel.then(chrono::Utc::now))
            .execute(self.pool()).await?;
        let decision = Uuid::new_v4();
        sqlx::query("INSERT INTO security_policy_decisions(id,policy_id,policy_version,assessment_id,decision,risk_score,evidence_sources,corroborated,rationale,evidence_snapshot,evidence_hash,dedupe_key) VALUES($1,$2,1,$3,'block',90,2,TRUE,'r','{}','h',$4)")
            .bind(decision).bind(policy).bind(assessment).bind(format!("k-{decision}"))
            .execute(self.pool()).await?;
        Ok(decision)
    }

    async fn resolve(&self, pseudonym: &str, ttl: i64) -> Result<()> {
        let ip = {
            let mut ips = self.ips.lock().unwrap();
            let next = 20 + ips.len();
            ips.entry(pseudonym.to_string())
                .or_insert_with(|| format!("203.0.113.{next}"))
                .clone()
        };
        sqlx::query("INSERT INTO security_ip_resolutions(pseudonym,raw_ip,source,expires_at) VALUES($1,$2::inet,$3,NOW()+($4*INTERVAL '1 second')) ON CONFLICT(pseudonym) DO UPDATE SET expires_at=EXCLUDED.expires_at")
            .bind(pseudonym).bind(&ip).bind("t").bind(ttl).execute(self.pool()).await?;
        if self.wanted.lock().unwrap().contains(pseudonym) {
            self.list(&ip, 80, 0).await?;
        }
        Ok(())
    }

    /// A reputation listing for exactly this address (the address is the identity).
    async fn list(&self, ip: &str, confidence: i16, last_seen_age_secs: i64) -> Result<()> {
        sqlx::query("INSERT INTO indicators (value,indicator_type,categories,confidence,source,first_seen,last_seen,expires_at) VALUES ($1,'Ip','[\"spamhaus_drop\"]',$2,$3,NOW(),NOW()-($4*INTERVAL '1 second'),NOW()+INTERVAL '1 day') ON CONFLICT (value,indicator_type,source) DO UPDATE SET confidence=EXCLUDED.confidence, last_seen=EXCLUDED.last_seen, expires_at=EXCLUDED.expires_at")
            .bind(ip).bind(confidence).bind(format!("bridge-test-{ip}")).bind(last_seen_age_secs)
            .execute(self.pool()).await?;
        Ok(())
    }

    async fn delist(&self, ip: &str) -> Result<()> {
        sqlx::query("DELETE FROM indicators WHERE value=$1 AND indicator_type='Ip'")
            .bind(ip)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    fn ip_of(&self, pseudonym: &str) -> String {
        self.ips
            .lock()
            .unwrap()
            .get(pseudonym)
            .cloned()
            .expect("resolved pseudonym")
    }

    async fn action(&self, enabled: bool, requires_approval: bool) -> Result<()> {
        sqlx::query("UPDATE actions SET enabled=$1, requires_approval=$2 WHERE name=$3")
            .bind(enabled)
            .bind(requires_approval)
            .bind(BLOCK)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    async fn run(&self, decision: Uuid, params: &PolicyBridgeParams) -> Result<BridgeOutcome> {
        self.bridge
            .enqueue_policy_bridge_request(decision, params)
            .await
    }
}

fn params(mode: BridgeMode) -> PolicyBridgeParams {
    PolicyBridgeParams {
        mode,
        action_name: BLOCK.into(),
        ttl_seconds: 60,
        requester_id: None,
        rule_id: Some("ssh_bruteforce".into()),
        max_evidence_age_seconds: 600,
        require_threat_intel: true,
        min_intel_confidence: 50,
        max_per_window: 5,
        window_seconds: 300,
    }
}

fn rejected(reason: &str) -> BridgeOutcome {
    BridgeOutcome::Rejected(reason.into())
}

fn restricted(grants: &str, start: &str, end: &str) -> String {
    let from = grants.find(start).expect("grant start");
    let tail = &grants[from..];
    let to = tail.find(end).expect("grant end") + end.len();
    tail[..to].to_string()
}

async fn check(owner_url: &str, policy_url: &str, executor_url: &str) -> Result<()> {
    let owner = PostgresStore::connect(owner_url).await?;
    let provision = include_str!("../../scripts/provision-db-roles.sh");
    sqlx::raw_sql(&restricted(
        provision,
        "GRANT SELECT ON TABLE _sqlx_migrations, security_policies, security_assessments,",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_policy_engine;",
    ))
    .execute(owner.pool())
    .await?;
    let exec_grants = provision
        .split("GRANT SELECT ON TABLE _sqlx_migrations, actions, execution_requests,")
        .nth(1)
        .expect("executor grants start")
        .split("GRANT SELECT ON ALL TABLES IN SCHEMA public TO clawforge_backup;")
        .next()
        .expect("executor grants end");
    sqlx::raw_sql(&format!(
        "GRANT SELECT ON TABLE _sqlx_migrations, actions, execution_requests,{exec_grants}"
    ))
    .execute(owner.pool())
    .await?;
    let env = Env {
        bridge: PostgresStore::connect_runtime(policy_url).await?,
        owner,
        ips: Default::default(),
        wanted: Default::default(),
    };
    let executor = PostgresStore::connect_runtime(executor_url).await?;

    // The policy-engine role cannot write execution requests itself.
    assert!(sqlx::query("INSERT INTO execution_requests(id,action_id,requested_by,status) SELECT gen_random_uuid(), id, 'x', 'pending' FROM actions LIMIT 1")
        .execute(env.bridge.pool()).await.is_err());
    assert!(sqlx::query("SELECT raw_ip FROM security_ip_resolutions")
        .fetch_all(env.bridge.pool())
        .await
        .is_err());

    // ---- simulate: action disabled, request pending and simulation_only.
    env.action(false, true).await?;
    let sim_policy = env.policy("observe", "ssh_bruteforce").await?;
    let pseudonym = "ip-pseudonym:sim";
    let sim = env.decision(sim_policy, pseudonym, true, 0).await?;
    let BridgeOutcome::Enqueued(sim_id) = env.run(sim, &params(BridgeMode::Simulate)).await? else {
        panic!("simulate must enqueue");
    };
    let (status, context): (String, Value) =
        sqlx::query_as("SELECT status, approval_context FROM execution_requests WHERE id=$1")
            .bind(sim_id)
            .fetch_one(env.pool())
            .await?;
    assert_eq!(status, "pending");
    assert_eq!(context["target"]["simulation_only"], json!(true));
    assert_eq!(context["target"]["pseudonym"], json!(pseudonym));
    assert_eq!(context["requested_by"], json!("policy-bridge"));
    assert_eq!(
        env.run(sim, &params(BridgeMode::Simulate)).await?,
        BridgeOutcome::Duplicate(sim_id)
    );
    // A simulation of the very target a live request will use later; it must
    // neither block nor consume the budget of that live request.
    let p1_sim = env.decision(sim_policy, "ip-pseudonym:p1", true, 0).await?;
    let BridgeOutcome::Enqueued(_) = env.run(p1_sim, &params(BridgeMode::Simulate)).await? else {
        panic!("simulate must enqueue for the shared target");
    };
    // The same request is refused when the action is enabled (simulate needs it off).
    env.action(true, true).await?;
    let other = env
        .decision(sim_policy, "ip-pseudonym:sim2", true, 0)
        .await?;
    assert_eq!(
        env.run(other, &params(BridgeMode::Simulate)).await?,
        rejected("action_state_mismatch")
    );

    // ---- propose: enabled + approval; refusal paths first.
    let approval_policy = env.policy("approval", "ssh_bruteforce").await?;
    let operator = env
        .owner
        .create_admin_user("bridge-operator", "Operator", "!")
        .await?;
    let admin_requester = env
        .owner
        .create_admin_user("bridge-admin", "Administrator", "!")
        .await?;
    let mut propose = params(BridgeMode::Propose);
    propose.requester_id = Some(operator);
    env.resolve("ip-pseudonym:p1", 600).await?;
    let p1 = env
        .decision(approval_policy, "ip-pseudonym:p1", true, 0)
        .await?;

    let mut bad = propose.clone();
    bad.requester_id = Some(admin_requester);
    assert_eq!(env.run(p1, &bad).await?, rejected("requester_invalid"));
    bad.requester_id = Some(Uuid::new_v4());
    assert_eq!(env.run(p1, &bad).await?, rejected("requester_invalid"));
    bad.requester_id = None;
    assert_eq!(env.run(p1, &bad).await?, rejected("requester_invalid"));
    let mut bad = propose.clone();
    bad.action_name = "docker.quarantine_container".into();
    assert_eq!(env.run(p1, &bad).await?, rejected("action_not_allowed"));
    let mut bad = propose.clone();
    bad.action_name = "haproxy_ratelimit.block_incident_source".into();
    assert_eq!(
        env.run(p1, &bad).await?,
        rejected("decision_does_not_match_action")
    );
    let mut bad = propose.clone();
    bad.rule_id = Some("http_scan".into());
    assert_eq!(env.run(p1, &bad).await?, rejected("rule_mismatch"));
    let mut bad = propose.clone();
    bad.ttl_seconds = 0;
    assert_eq!(env.run(p1, &bad).await?, rejected("parameters_invalid"));
    assert_eq!(
        env.run(Uuid::new_v4(), &propose).await?,
        rejected("decision_not_found")
    );
    let observe_only = env
        .decision(sim_policy, "ip-pseudonym:obs", true, 0)
        .await?;
    env.resolve("ip-pseudonym:obs", 600).await?;
    assert_eq!(
        env.run(observe_only, &propose).await?,
        rejected("policy_class_insufficient")
    );
    let no_intel = env
        .decision(approval_policy, "ip-pseudonym:ni", false, 0)
        .await?;
    env.resolve("ip-pseudonym:ni", 600).await?;
    assert_eq!(
        env.run(no_intel, &propose).await?,
        rejected("threat_intel_required")
    );
    let mut relaxed = propose.clone();
    relaxed.require_threat_intel = false;
    let BridgeOutcome::Enqueued(_) = env.run(no_intel, &relaxed).await? else {
        panic!("behavioural corroboration is acceptable when a human approves");
    };
    let stale = env
        .decision(approval_policy, "ip-pseudonym:old", true, 100_000)
        .await?;
    env.resolve("ip-pseudonym:old", 600).await?;
    assert_eq!(
        env.run(stale, &propose).await?,
        rejected("assessment_stale")
    );
    let unresolved = env
        .decision(approval_policy, "ip-pseudonym:nores", true, 0)
        .await?;
    assert_eq!(
        env.run(unresolved, &propose).await?,
        rejected("resolution_missing")
    );
    let expired = env
        .decision(approval_policy, "ip-pseudonym:exp", true, 0)
        .await?;
    env.resolve("ip-pseudonym:exp", -5).await?;
    assert_eq!(
        env.run(expired, &propose).await?,
        rejected("resolution_missing")
    );
    // Database-side bounds, whatever the caller passes.
    for mutate in [
        (|p: &mut PolicyBridgeParams| p.window_seconds = 30) as fn(&mut PolicyBridgeParams),
        |p| p.window_seconds = 86_401,
        |p| p.max_per_window = 101,
        |p| p.max_per_window = 0,
        |p| p.max_evidence_age_seconds = 604_801,
        |p| p.ttl_seconds = 86_401,
    ] {
        let mut clamped = propose.clone();
        mutate(&mut clamped);
        assert_eq!(env.run(p1, &clamped).await?, rejected("parameters_invalid"));
    }
    // A forged or inconsistent decision: assessment of another rule, or below the
    // policy's minimum severity.
    let other_rule_policy = env.policy("approval", "http_scan").await?;
    let mismatched = env
        .decision(other_rule_policy, "ip-pseudonym:mm", true, 0)
        .await?;
    env.resolve("ip-pseudonym:mm", 600).await?;
    let mut any_rule = propose.clone();
    any_rule.rule_id = None;
    assert_eq!(
        env.run(mismatched, &any_rule).await?,
        rejected("assessment_rule_mismatch")
    );
    let strict_policy = env
        .policy_sev("approval", "ssh_bruteforce", "critical")
        .await?;
    let weak_severity = env
        .decision(strict_policy, "ip-pseudonym:sv", true, 0)
        .await?;
    env.resolve("ip-pseudonym:sv", 600).await?;
    assert_eq!(
        env.run(weak_severity, &propose).await?,
        rejected("severity_below_policy")
    );
    sqlx::query("UPDATE security_policy_decisions SET corroborated=FALSE WHERE id=$1")
        .bind(p1)
        .execute(env.pool())
        .await?;
    assert_eq!(env.run(p1, &propose).await?, rejected("not_corroborated"));
    sqlx::query(
        "UPDATE security_policy_decisions SET corroborated=TRUE, decision='challenge' WHERE id=$1",
    )
    .bind(p1)
    .execute(env.pool())
    .await?;
    assert_eq!(
        env.run(p1, &propose).await?,
        rejected("decision_does_not_match_action")
    );
    sqlx::query("UPDATE security_policy_decisions SET decision='block' WHERE id=$1")
        .bind(p1)
        .execute(env.pool())
        .await?;
    sqlx::query("UPDATE security_policies SET status='retired' WHERE id=$1")
        .bind(approval_policy)
        .execute(env.pool())
        .await?;
    assert_eq!(env.run(p1, &propose).await?, rejected("policy_inactive"));
    sqlx::query("UPDATE security_policies SET status='active' WHERE id=$1")
        .bind(approval_policy)
        .execute(env.pool())
        .await?;

    // Success: waiting for the action's two-person policy, then claimable.
    let BridgeOutcome::Enqueued(request) = env.run(p1, &propose).await? else {
        panic!("propose must enqueue");
    };
    let (status, required, requester, hash): (String, i32, Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT status, required_approvals, requested_by_id, approval_context_hash FROM execution_requests WHERE id=$1")
        .bind(request).fetch_one(env.pool()).await?;
    assert_eq!(
        (status.as_str(), required, requester),
        ("waiting_approval", 2, Some(operator))
    );
    assert!(hash.is_some());
    assert_eq!(
        env.run(p1, &propose).await?,
        BridgeOutcome::Duplicate(request)
    );
    // A second decision for a target that already has an active request is refused.
    let second_policy = env.policy("approval", "ssh_bruteforce").await?;
    let again = env
        .decision(second_policy, "ip-pseudonym:p1", true, 0)
        .await?;
    assert_eq!(
        env.run(again, &propose).await?,
        rejected("target_already_active")
    );
    // Requester cannot approve; two distinct approvers can; hash recomputation in Rust accepts it.
    assert!(env
        .owner
        .approve_execution_request(request, operator, "bridge-operator")
        .await
        .is_err());
    let a1 = env
        .owner
        .create_admin_user("bridge-approver-1", "Administrator", "!")
        .await?;
    let a2 = env
        .owner
        .create_admin_user("bridge-approver-2", "Administrator", "!")
        .await?;
    env.owner
        .approve_execution_request(request, a1, "bridge-approver-1")
        .await?;
    env.owner
        .approve_execution_request(request, a2, "bridge-approver-2")
        .await?;
    // Earlier simulation requests are claimable first; each carries the marker
    // that forces a dry run no matter how the executor is configured.
    let mut simulations = 0;
    let claimed = loop {
        let next = executor
            .claim_execution_request_for_dispatch(None)
            .await?
            .expect("the approved request is eventually claimable");
        if next.id == request {
            break next;
        }
        assert_eq!(
            next.target.as_ref().unwrap()["simulation_only"],
            json!(true),
            "only simulations may be claimed before the approved request"
        );
        simulations += 1;
    };
    assert_eq!(simulations, 2);
    assert_eq!(claimed.id, request);
    assert_eq!(claimed.action_name, BLOCK);
    assert_eq!(
        claimed.target.as_ref().unwrap()["pseudonym"],
        json!("ip-pseudonym:p1")
    );
    assert_eq!(claimed.target.as_ref().unwrap()["ttl_seconds"], json!(60));
    // A partially applied request awaiting rollback keeps its target busy.
    sqlx::query("UPDATE execution_requests SET status='rollback_required' WHERE id=$1")
        .bind(request)
        .execute(env.pool())
        .await?;
    assert_eq!(
        env.run(again, &propose).await?,
        rejected("target_already_active")
    );
    sqlx::query("UPDATE execution_requests SET status='cancelled' WHERE id=$1")
        .bind(request)
        .execute(env.pool())
        .await?;
    // Tampering: the enqueue function refuses a context that is not its own derivation.
    let tamper = env
        .decision(approval_policy, "ip-pseudonym:t", true, 0)
        .await?;
    env.resolve("ip-pseudonym:t", 600).await?;
    let forged: Value =
        json!({"target": {"kind": "incident_source", "pseudonym": "ip-pseudonym:other"}});
    let row: (String,) = sqlx::query_as("SELECT outcome FROM clawforge_enqueue_policy_bridge_request($1,'propose',$2,60,$3,'ssh_bruteforce',600,TRUE,50,5,300,$4,$5)")
        .bind(tamper).bind(BLOCK).bind(operator).bind(&forged).bind("0".repeat(64))
        .fetch_one(env.bridge.pool()).await?;
    assert_eq!(row.0, "rejected:context_changed");

    // ---- budget: one request per window.
    let mut tight = propose.clone();
    tight.max_per_window = 1;
    tight.window_seconds = 3600;
    let t1 = env
        .decision(approval_policy, "ip-pseudonym:b1", true, 0)
        .await?;
    env.resolve("ip-pseudonym:b1", 600).await?;
    assert_eq!(env.run(t1, &tight).await?, rejected("budget_exhausted"));

    // ---- automatic: action enabled without approval; every extra gate.
    env.action(true, false).await?;
    let auto_policy = env.policy("automatic", "ssh_bruteforce").await?;
    env.resolve("ip-pseudonym:a1", 600).await?;
    let a = env
        .decision(auto_policy, "ip-pseudonym:a1", true, 0)
        .await?;
    let auto = params(BridgeMode::Automatic);
    let mut no_rule = auto.clone();
    no_rule.rule_id = None;
    assert_eq!(env.run(a, &no_rule).await?, rejected("rule_required"));
    let mut with_requester = auto.clone();
    with_requester.requester_id = Some(operator);
    assert_eq!(
        env.run(a, &with_requester).await?,
        rejected("requester_not_allowed")
    );
    let mut no_intel_flag = auto.clone();
    no_intel_flag.require_threat_intel = false;
    let weak_policy = env.policy("automatic", "ssh_bruteforce").await?;
    env.resolve("ip-pseudonym:a2", 600).await?;
    let weak = env
        .decision(weak_policy, "ip-pseudonym:a2", false, 0)
        .await?;
    assert_eq!(
        env.run(weak, &no_intel_flag).await?,
        rejected("threat_intel_required")
    );
    let approval_class = env
        .decision(approval_policy, "ip-pseudonym:a3", true, 0)
        .await?;
    env.resolve("ip-pseudonym:a3", 600).await?;
    assert_eq!(
        env.run(approval_class, &auto).await?,
        rejected("policy_class_insufficient")
    );
    // Executor liveness is required.
    assert_eq!(env.run(a, &auto).await?, rejected("executor_not_healthy"));
    executor
        .set_runtime_status("executor", "running", None)
        .await?;
    let BridgeOutcome::Enqueued(auto_id) = env.run(a, &auto).await? else {
        panic!("automatic must enqueue when every gate holds");
    };
    let (status, required): (String, i32) =
        sqlx::query_as("SELECT status, required_approvals FROM execution_requests WHERE id=$1")
            .bind(auto_id)
            .fetch_one(env.pool())
            .await?;
    assert_eq!((status.as_str(), required), ("pending", 0));

    // An unresolved firewall generation stops further automatic requests.
    let owner_action: Uuid = sqlx::query_scalar("SELECT id FROM actions WHERE name=$1")
        .bind(BLOCK)
        .fetch_one(env.pool())
        .await?;
    let held = Uuid::new_v4();
    sqlx::query("INSERT INTO execution_requests(id,action_id,requested_by,status) VALUES($1,$2,'fixture','pending')")
        .bind(held).bind(owner_action).execute(env.pool()).await?;
    env.owner
        .prepare_firewall_rule_intent(
            held,
            "nftables",
            BLOCK,
            "scope",
            "203.0.113.200/32",
            &json!({}),
            &json!({}),
            &json!({}),
            60,
        )
        .await?;
    env.resolve("ip-pseudonym:a4", 600).await?;
    let blocked = env
        .decision(auto_policy, "ip-pseudonym:a4", true, 0)
        .await?;
    assert_eq!(
        env.run(blocked, &auto).await?,
        rejected("unresolved_firewall_state")
    );

    // Every enqueue is audited without any address.
    let audited: Vec<(String,)> = sqlx::query_as(
        "SELECT details::text FROM audit_events WHERE action='policy_bridge_request_enqueued'",
    )
    .fetch_all(env.pool())
    .await?;
    assert!(audited.len() >= 3);
    assert!(audited.iter().all(|row| !row.0.contains("203.0.113")));
    Ok(())
}

/// The bridge judges reputation on the current view of the source and re-checks it
/// when the executor picks the request up.
#[tokio::test]
#[ignore = "requires explicit disposable owner, policy-engine and executor database URLs"]
async fn bridge_judges_the_current_intel_view_and_revalidates_at_dispatch() -> Result<()> {
    let base = std::env::var("CLAWFORGE_TEST_DATABASE_URL")?;
    let policy_base = std::env::var("CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL")?;
    let admin = PgPool::connect(&base).await?;
    let database = format!("policy_bridge_intel_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await?;
    let url = |base: &str| -> Result<String> {
        Ok(PgConnectOptions::from_str(base)?
            .database(&database)
            .to_url_lossy()
            .to_string())
    };
    let (owner_url, policy_url) = (url(&base)?, url(&policy_base)?);
    let result = tokio::spawn(async move { intel_gates(&owner_url, &policy_url).await }).await;
    let cleanup = sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&admin)
        .await;
    admin.close().await;
    cleanup?;
    result??;
    Ok(())
}

async fn intel_gates(owner_url: &str, policy_url: &str) -> Result<()> {
    let owner = PostgresStore::connect(owner_url).await?;
    let provision = include_str!("../../scripts/provision-db-roles.sh");
    sqlx::raw_sql(&restricted(
        provision,
        "GRANT SELECT ON TABLE _sqlx_migrations, security_policies, security_assessments,",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_policy_engine;",
    ))
    .execute(owner.pool())
    .await?;
    let env = Env {
        bridge: PostgresStore::connect_runtime(policy_url).await?,
        owner,
        ips: Default::default(),
        wanted: Default::default(),
    };
    let pool = env.pool().clone();
    let operator = env
        .owner
        .create_admin_user("intel-operator", "Operator", "!")
        .await?;
    let policy = env.policy("automatic", "ssh_bruteforce").await?;
    let mut propose = params(BridgeMode::Propose);
    propose.requester_id = Some(operator);
    propose.max_per_window = 50;
    propose.window_seconds = 3600;
    env.action(true, true).await?;

    // Reputation by origin ASN only (no listing of the address itself).
    let asn = 4_100_000_042_i64;
    env.resolve("ip-pseudonym:asn-only", 600).await?;
    let asn_ip = env.ip_of("ip-pseudonym:asn-only");
    let by_asn = env
        .decision(policy, "ip-pseudonym:asn-only", false, 0)
        .await?;
    assert_eq!(
        env.run(by_asn, &propose).await?,
        rejected("threat_intel_required"),
        "no listing, no context yet"
    );
    let prefix = format!("{}.0/24", asn_ip.rsplit_once('.').unwrap().0);
    assert!(
        env.owner
            .record_network_context(
                "ip-pseudonym:asn-only",
                &NetworkContextOutcome::Routed {
                    prefix: prefix.clone(),
                    origin_asns: vec![asn],
                    rpki: "invalid".into(),
                    ttl_seconds: 3600
                }
            )
            .await?
    );
    assert_eq!(
        env.run(by_asn, &propose).await?,
        rejected("threat_intel_required"),
        "routing context alone - even RPKI-invalid - is not reputation"
    );
    sqlx::query("INSERT INTO indicators (value,indicator_type,categories,confidence,source,first_seen,last_seen,expires_at) VALUES ($1,'Asn','[\"spamhaus_asn\"]',80,'bridge-asn-test',NOW(),NOW(),NOW()+INTERVAL '1 day')")
        .bind(format!("AS{asn}")).execute(&pool).await?;
    let BridgeOutcome::Enqueued(request) = env.run(by_asn, &propose).await? else {
        panic!("an origin-ASN listing is reputation");
    };
    let context: Value =
        sqlx::query_scalar("SELECT approval_context FROM execution_requests WHERE id=$1")
            .bind(request)
            .fetch_one(&pool)
            .await?;
    let bridge_ctx = &context["policy_bridge"];
    assert_eq!(bridge_ctx["intel"]["basis"], json!("asn"));
    assert_eq!(bridge_ctx["intel"]["source"], json!("bridge-asn-test"));
    assert_eq!(bridge_ctx["routing"]["origin_asns"], json!([asn]));
    assert_eq!(bridge_ctx["routing"]["rpki"], json!("invalid"));
    assert_eq!(bridge_ctx["routing"]["prefix"], json!(prefix));
    assert_eq!(bridge_ctx["intel_required"], json!(true));
    assert!(
        !context.to_string().contains(&asn_ip),
        "the approver sees routing facts, never the address"
    );

    // Address listing: confidence floor, staleness and delisting all end eligibility.
    for (confidence, age_secs, expect_ok) in
        [(40_i16, 0_i64, false), (80, 100_000, false), (80, 0, true)]
    {
        let name = format!("ip-pseudonym:ip-{confidence}-{age_secs}");
        env.resolve(&name, 600).await?;
        let ip = env.ip_of(&name);
        env.list(&ip, confidence, age_secs).await?;
        let d = env.decision(policy, &name, false, 0).await?;
        let outcome = env.run(d, &propose).await?;
        assert_eq!(
            matches!(outcome, BridgeOutcome::Enqueued(_)),
            expect_ok,
            "{confidence}/{age_secs}: {outcome:?}"
        );
        if !expect_ok {
            assert_eq!(outcome, rejected("threat_intel_required"));
        }
    }
    // An ingest-time snapshot is overruled by a current view that no longer lists the source.
    env.resolve("ip-pseudonym:snapshot", 600).await?;
    let snap = env
        .decision(policy, "ip-pseudonym:snapshot", true, 0)
        .await?;
    let snap_ip = env.ip_of("ip-pseudonym:snapshot");
    env.delist(&snap_ip).await?;
    assert_eq!(
        env.run(snap, &propose).await?,
        rejected("threat_intel_required"),
        "delisted since ingest"
    );
    env.list(&snap_ip, 80, 0).await?;
    let BridgeOutcome::Enqueued(_) = env.run(snap, &propose).await? else {
        panic!("relisted")
    };

    // ---- dispatch-time revalidation (automatic: the request is claimable at once).
    env.action(true, false).await?;
    sqlx::query("INSERT INTO runtime_status (component,state,version,last_heartbeat_at) VALUES ('executor','running','t',NOW()) ON CONFLICT (component) DO UPDATE SET state='running', last_heartbeat_at=NOW()")
        .execute(&pool).await?;
    let mut automatic = params(BridgeMode::Automatic);
    automatic.max_per_window = 50;
    automatic.window_seconds = 3600;
    env.resolve("ip-pseudonym:dispatch", 600).await?;
    let ip = env.ip_of("ip-pseudonym:dispatch");
    let d = env
        .decision(policy, "ip-pseudonym:dispatch", true, 0)
        .await?;
    let BridgeOutcome::Enqueued(auto) = env.run(d, &automatic).await? else {
        panic!("automatic enqueue")
    };
    sqlx::query("UPDATE execution_requests SET status='starting' WHERE id=$1")
        .bind(auto)
        .execute(&pool)
        .await?;
    let resolves = || async {
        sqlx::query_scalar::<_, String>(
            "SELECT raw_ip FROM clawforge_resolve_incident_source_for_apply($1)",
        )
        .bind(auto)
        .fetch_optional(&pool)
        .await
    };
    assert_eq!(
        resolves().await?,
        Some(ip.clone()),
        "still listed: released to the executor"
    );
    env.delist(&ip).await?;
    assert_eq!(
        resolves().await?,
        None,
        "delisted before apply: nothing is released"
    );
    env.list(&ip, 40, 0).await?;
    assert_eq!(
        resolves().await?,
        None,
        "below the recorded confidence floor"
    );
    env.list(&ip, 80, 100_000).await?;
    assert_eq!(
        resolves().await?,
        None,
        "no longer reconfirmed within the recorded evidence age"
    );
    env.list(&ip, 80, 0).await?;
    assert_eq!(
        resolves().await?,
        Some(ip.clone()),
        "listed again: released"
    );
    Ok(())
}
