//! Behavioral acceptance against an explicitly provisioned, isolated PostgreSQL.
//! Exercises real sensor exports, validated storage, delivery and detector code.
use super::*;
use clawforge_security_events::{SecurityEventEvidence, SensorEnvelope};
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::PathBuf, time::Instant};

async fn drain(engine: &PostgresStore) -> Result<usize> {
    let mut count = 0;
    loop {
        let rows = engine.claim_event_deliveries(CONSUMER_NAME, 50).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            process_delivery(engine, event_from_value(&row)?).await?;
            let id: Uuid = row["delivery_id"]
                .as_str()
                .context("delivery ID")?
                .parse()?;
            engine
                .complete_event_delivery(id, CONSUMER_NAME, true, None)
                .await?;
            count += 1;
        }
    }
    Ok(count)
}

struct RuntimeProcess(std::process::Child);
impl Drop for RuntimeProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn process_backlog(
    owner: &PostgresStore,
    engine_url: &str,
    expected: i64,
    out: &std::path::Path,
    name: &str,
) -> Result<()> {
    let binary = env::var("CLAWFORGE_BEHAVIOR_ENGINE_BIN")?;
    let log = std::fs::File::create(out.join(format!("{name}.log")))?;
    let mut child = RuntimeProcess(
        std::process::Command::new(binary)
            .env("DATABASE_URL", engine_url)
            .env_remove("DATABASE_URL_FILE")
            .env("CLAWFORGE_SECURITY_ENGINE_POLL_SECONDS", "1")
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    );
    let deadline = Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait()? {
            anyhow::bail!("real engine process exited: {status}");
        }
        let processed:i64=sqlx::query_scalar("SELECT count(*) FROM event_delivery d JOIN event_consumers c ON c.id=d.consumer_id WHERE c.name=$1 AND d.status='processed'")
            .bind(CONSUMER_NAME).fetch_one(owner.pool()).await?;
        if processed == expected {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "real engine backlog-drain deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // SIGKILL is deliberate fault injection. The following call starts a separate real process.
    child.0.kill()?;
    child.0.wait()?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit isolated behavior DB, sensor exports and real least-privilege role"]
async fn golden_behavior_and_bounded_load() -> Result<()> {
    let out = PathBuf::from(env::var("CLAWFORGE_BEHAVIOR_REPORT_DIR")?);
    let owner_url = env::var("CLAWFORGE_BEHAVIOR_OWNER_URL")?;
    let engine_url = env::var("CLAWFORGE_BEHAVIOR_ENGINE_URL")?;
    let owner = PostgresStore::connect_runtime(&owner_url).await?;
    let engine = PostgresStore::connect_runtime(&engine_url).await?;
    let engine_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(engine.pool())
        .await?;
    assert_eq!(engine_user, "clawforge_security_engine");
    engine.ensure_event_consumer(CONSUMER_NAME).await?;
    let sensor = owner
        .register_security_sensor(
            "behavior-fixture",
            "not-a-live-credential",
            "fixture",
            None,
            "isolated-test",
        )
        .await?;
    let plan: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/behavior-validation/scenarios.json"
    ))?;
    let mut results = Vec::new();
    let (mut tp, mut fp, mut tn, mut fn_) = (0, 0, 0, 0);
    let (mut tp_attacker, mut fp_attacker, mut tn_attacker, mut fn_attacker) = (0, 0, 0, 0);
    let mut golden_accepted = 0;
    let mut template = None;
    for case in plan["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let artifact: Value =
            serde_json::from_slice(&std::fs::read(out.join(format!("{id}.json")))?)?;
        assert_eq!(&artifact["case"], case);
        let events = artifact["events"].as_array().context("parser exports")?;
        assert_eq!(artifact["parser_drops"], 0);
        let started = Instant::now();
        let mut resource = None;
        let mut replay = None;
        if case["listed_source"].as_bool().unwrap_or(false) {
            // A fresh, confident reputation listing for exactly this fixture source,
            // present before ingest like a real feed entry (never the raw address in
            // any later record). Independent evidence is the only difference to the
            // unlisted twin case.
            let ip = events[0]["resource"].as_str().context("fixture source")?;
            sqlx::query("INSERT INTO indicators (value,indicator_type,categories,confidence,source,first_seen,last_seen,expires_at) VALUES ($1,'Ip','[]',80,'behavior_fixture_feed',NOW(),NOW(),NOW()+INTERVAL '2 days')")
                .bind(ip)
                .execute(owner.pool())
                .await?;
        }
        for value in events {
            let envelope: SensorEnvelope = serde_json::from_value(value.clone())?;
            envelope.validate()?;
            let event_id = owner.record_security_event(sensor, &envelope).await?;
            let saved = owner
                .get_security_event(event_id)
                .await?
                .context("saved event")?;
            resource = Some(
                saved["resource"]
                    .as_str()
                    .context("pseudonymous resource")?
                    .to_owned(),
            );
            replay = Some((envelope.clone(), event_id));
            if template.is_none() {
                template = Some(envelope);
            }
            golden_accepted += 1;
        }
        let processed = drain(&engine).await?;
        assert_eq!(processed, events.len());
        let mut rules = BTreeSet::new();
        if let Some(resource) = &resource {
            let rows: Vec<String>=sqlx::query_scalar("SELECT DISTINCT rule_id FROM security_assessments WHERE resource=$1 ORDER BY rule_id")
                .bind(resource).fetch_all(owner.pool()).await?;
            rules.extend(rows);
        }
        // The frozen baseline expectation stays recorded; a case whose deterministic
        // behaviour changed on purpose carries an explicit after-fix expectation.
        let baseline: BTreeSet<String> = case["expected_rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let expected: BTreeSet<String> = case
            .get("expected_rules_after_fix")
            .unwrap_or(&case["expected_rules"])
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            rules, expected,
            "mechanical regression in {id}; do not alter human intent labels to hide errors"
        );
        if let Some((envelope, event_id)) = &replay {
            assert_eq!(
                owner.record_security_event(sensor, envelope).await?,
                *event_id
            );
            assert_eq!(
                drain(&engine).await?,
                0,
                "identical retry must not republish"
            );
        }
        let alert = !rules.is_empty();
        let attacker_rule_alert = rules.iter().any(|rule| rule != "http_server_fault_burst");
        let attack = case["label_attack"].as_bool().unwrap();
        match (attack, attacker_rule_alert) {
            (true, true) => tp_attacker += 1,
            (false, true) => fp_attacker += 1,
            (false, false) => tn_attacker += 1,
            (true, false) => fn_attacker += 1,
        }
        let classification = match (attack, alert) {
            (true, true) => {
                tp += 1;
                "TP"
            }
            (false, true) => {
                fp += 1;
                "FP"
            }
            (false, false) => {
                tn += 1;
                "TN"
            }
            (true, false) => {
                fn_ += 1;
                "FN"
            }
        };
        results.push(
            json!({"id":id,"label_attack":attack,"alert":alert,"rules":rules,"resource":resource,
            "baseline_expected_rules":baseline,"expected_rules_after_fix":case.get("expected_rules_after_fix"),
            "attacker_rule_alert":attacker_rule_alert,
            "classification":classification,"raw_journal_lines":case["event_count"],
            "accepted_events":events.len(),"processed_deliveries":processed,
            "elapsed_ms":started.elapsed().as_secs_f64()*1000.0,"note":case["note"]}),
        );
    }
    let mut base = template.context("at least one parsed event")?;
    // Separate pseudonymous resource and time bucket keep load from altering golden labels.
    base.resource = "198.51.100.250".into();
    if let SecurityEventEvidence::SshLoginFailure(e) = &mut base.evidence {
        e.source_ip = base.resource.clone();
    }
    base.occurred_at = Utc.with_ymd_and_hms(2026, 1, 1, 18, 0, 0).unwrap();
    let mut latencies = Vec::new();
    let mut batch = Vec::new();
    let start = Instant::now();
    for n in 0..192 {
        let mut e = base.clone();
        e.dedupe_key = format!("bounded-load:{n}");
        let at = Instant::now();
        let id = owner.record_security_event(sensor, &e).await?;
        latencies.push(at.elapsed().as_secs_f64() * 1000.0);
        batch.push((e, id));
        if n < 64 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    let ingest_seconds = start.elapsed().as_secs_f64();
    let backlog: i64=sqlx::query_scalar("SELECT count(*) FROM event_delivery d JOIN event_consumers c ON c.id=d.consumer_id WHERE c.name=$1 AND d.status='pending'")
        .bind(CONSUMER_NAME).fetch_one(owner.pool()).await?;
    assert_eq!(
        backlog, 192,
        "paused consumer must preserve bounded backlog"
    );
    for (e, id) in batch.iter().take(32) {
        assert_eq!(owner.record_security_event(sensor, e).await?, *id);
    }
    let mut rejected = 0;
    for (e, _) in batch.iter().take(8) {
        let mut conflict = e.clone();
        conflict.severity = clawforge_security_events::Severity::High;
        assert!(
            owner
                .record_security_event(sensor, &conflict)
                .await
                .is_err(),
            "same key with changed content must fail"
        );
        rejected += 1;
    }
    // A failed delivery must not disappear; reopen a fresh runtime store to model a consumer restart.
    let first = engine.claim_event_deliveries(CONSUMER_NAME, 1).await?;
    let first_id: Uuid = first[0]["delivery_id"].as_str().unwrap().parse()?;
    engine
        .complete_event_delivery(
            first_id,
            CONSUMER_NAME,
            false,
            Some("isolated transient failure"),
        )
        .await?;
    let waiting: String = sqlx::query_scalar("SELECT status FROM event_delivery WHERE id=$1")
        .bind(first_id)
        .fetch_one(owner.pool())
        .await?;
    assert_eq!(waiting, "failed");
    // Check actual retry delay instead of overwriting available_at in the database.
    assert_eq!(first[0]["attempts"], 1);
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    let restarted = PostgresStore::connect_runtime(&engine_url).await?;
    process_backlog(
        &owner,
        &engine_url,
        golden_accepted + 192,
        &out,
        "engine-after-retry",
    )
    .await?;
    let drained = 192;
    let corrupt: i64=sqlx::query_scalar("SELECT count(*) FROM event_delivery d JOIN event_consumers c ON c.id=d.consumer_id WHERE c.name=$1 AND d.status<>'processed'")
        .bind(CONSUMER_NAME).fetch_one(owner.pool()).await?;
    assert_eq!(corrupt, 0);
    // Reclaim an abandoned claim through the real ten-minute lease rule (no ten-minute wall-clock wait).
    let mut abandoned = base.clone();
    abandoned.dedupe_key = "lease-reclaim-fixture".into();
    owner.record_security_event(sensor, &abandoned).await?;
    let rows = engine.claim_event_deliveries(CONSUMER_NAME, 1).await?;
    let id: Uuid = rows[0]["delivery_id"].as_str().unwrap().parse()?;
    assert!(
        restarted
            .claim_event_deliveries(CONSUMER_NAME, 1)
            .await?
            .is_empty(),
        "live lease cannot be stolen"
    );
    sqlx::query(
        "UPDATE event_delivery SET processing_started_at=NOW()-INTERVAL '11 minutes' WHERE id=$1",
    )
    .bind(id)
    .execute(owner.pool())
    .await?;
    process_backlog(
        &owner,
        &engine_url,
        golden_accepted + 193,
        &out,
        "engine-after-crash",
    )
    .await?;
    let unique: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events WHERE sensor_id=$1")
        .bind(sensor)
        .fetch_one(owner.pool())
        .await?;
    assert_eq!(unique, golden_accepted + 193);
    let executions: i64 = sqlx::query_scalar("SELECT count(*) FROM execution_requests")
        .fetch_one(owner.pool())
        .await?;
    assert_eq!(
        executions, 0,
        "alerts alone must not fabricate execution approval"
    );
    let incident_duplicates: i64=sqlx::query_scalar("SELECT count(*) FROM (SELECT correlation_key FROM incident_candidates GROUP BY correlation_key HAVING count(*)>1) x").fetch_one(owner.pool()).await?;
    assert_eq!(incident_duplicates, 0);
    latencies.sort_by(f64::total_cmp);
    let p95 = latencies[(latencies.len() * 95).div_ceil(100) - 1];
    let report = json!({"schema_version":1,"scope":"actual journal parsers -> validated sensor storage -> canonical event delivery -> least-privilege security-engine; HTTP auth and physical sensors excluded",
        "golden_cases":results,
        "stage":"1_raw_anomaly_detection (any rule, including observation-only rules)",
        "confusion_matrix":{"tp":tp,"fp":fp,"tn":tn,"fn":fn_},
        "attacker_rule_matrix":{"tp":tp_attacker,"fp":fp_attacker,"tn":tn_attacker,"fn":fn_attacker,
            "note":"alerts of observation-only rules (server-fault bursts) excluded; still a detector alert, not an attacker verdict or a block"},
        "quality_gate_passed":fp==0 && fn_==0,"not_a_production_approval":true,
        "load":{"unique_events":192,"retry_submissions":32,"conflicting_submissions_rejected":rejected,
            "input_submissions":232,"accepted_new":192,"accepted_duplicate":32,"explicit_drop":0,
            "ingest_seconds":ingest_seconds,"record_latency_ms_p95":p95,"record_latency_ms_max":latencies.last(),
            "paused_consumer_backlog":backlog,"processed_after_restart":drained,
            "transient_failure_retried":true,"actual_engine_process_restart":true,"lease_reclaim":"test clock aged in isolated DB, not real 11-minute wait",
            "incident_duplicates":incident_duplicates,"execution_requests":executions},
        "limits":{"max_events":400,"scope":"ephemeral local database only","sustained_network_load_test":false,
            "false_positive_rate_general_population":"not estimable from selected golden fixtures",
            "live_enforcement":"not tested here; separate isolated packet lab required"}});
    std::fs::write(
        out.join("behavior-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("BEHAVIOR_REPORT {}", serde_json::to_string(&report)?);
    Ok(())
}

#[tokio::test]
#[ignore = "injects an event-backbone failure into the explicitly isolated behavior database"]
async fn ingest_publish_interruption_is_recoverable() -> Result<()> {
    let out = PathBuf::from(env::var("CLAWFORGE_BEHAVIOR_REPORT_DIR")?);
    let owner = PostgresStore::connect_runtime(&env::var("CLAWFORGE_BEHAVIOR_OWNER_URL")?).await?;
    let sensor = owner
        .register_security_sensor(
            "behavior-fault-fixture",
            "not-a-live-fault-credential",
            "fixture",
            None,
            "isolated-test",
        )
        .await?;
    let artifact: Value = serde_json::from_slice(&std::fs::read(out.join("ssh_typo.json"))?)?;
    let mut envelope: SensorEnvelope = serde_json::from_value(artifact["events"][0].clone())?;
    envelope.dedupe_key = "isolated-backbone-interruption".into();
    envelope.validate()?;
    // PostgreSQL fault injection fails only the canonical fanout stage. The trigger and DB are ephemeral.
    sqlx::raw_sql("CREATE FUNCTION behavior_fail_publish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated canonical-publish failure'; END $$; CREATE TRIGGER behavior_fail_publish BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION behavior_fail_publish();")
        .execute(owner.pool()).await?;
    let first = owner.record_security_event(sensor, &envelope).await;
    sqlx::raw_sql(
        "DROP TRIGGER behavior_fail_publish ON events; DROP FUNCTION behavior_fail_publish();",
    )
    .execute(owner.pool())
    .await?;
    assert!(
        first.is_err(),
        "fault injection must actually interrupt publish"
    );
    let mut changed = envelope.clone();
    changed.severity = clawforge_security_events::Severity::High;
    assert!(
        owner.record_security_event(sensor, &changed).await.is_err(),
        "changed retry must not repair or overwrite unpublished content"
    );
    let before_repair: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE metadata->>'sensor_id'=$1")
            .bind(sensor.to_string())
            .fetch_one(owner.pool())
            .await?;
    assert_eq!(before_repair, 0);
    let (retry_a, retry_b) = tokio::join!(
        owner.record_security_event(sensor, &envelope),
        owner.record_security_event(sensor, &envelope)
    );
    let id = retry_a?;
    assert_eq!(
        retry_b?, id,
        "concurrent repair retries must share one identity"
    );
    let canonical: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE dedupe_key=$1")
        .bind(format!("security-event:{id}"))
        .fetch_one(owner.pool())
        .await?;
    let delivery_count: i64 = sqlx::query_scalar("SELECT count(*) FROM event_delivery d JOIN events e ON e.event_id=d.event_id WHERE e.dedupe_key=$1")
        .bind(format!("security-event:{id}")).fetch_one(owner.pool()).await?;
    let consumers: i64 = sqlx::query_scalar("SELECT count(*) FROM event_consumers WHERE enabled")
        .fetch_one(owner.pool())
        .await?;
    assert_eq!(
        delivery_count, consumers,
        "one delivery per enabled consumer"
    );
    let original_seen: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_seen_at FROM security_sensors WHERE id=$1")
            .bind(sensor)
            .fetch_one(owner.pool())
            .await?;
    assert_eq!(owner.record_security_event(sensor, &envelope).await?, id);
    let after_duplicate: i64 = sqlx::query_scalar("SELECT count(*) FROM event_delivery d JOIN events e ON e.event_id=d.event_id WHERE e.dedupe_key=$1")
        .bind(format!("security-event:{id}")).fetch_one(owner.pool()).await?;
    assert_eq!(after_duplicate, delivery_count);
    let final_seen: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_seen_at FROM security_sensors WHERE id=$1")
            .bind(sensor)
            .fetch_one(owner.pool())
            .await?;
    assert_eq!(
        final_seen, original_seen,
        "normal duplicate must not refresh sensor timestamp"
    );
    let record = json!({"delivery_count":delivery_count,"enabled_consumers":consumers,"changed_unpublished_retry_rejected":true,"normal_duplicate_has_no_side_effects":true,"scope":"actual validated sensor ingest and canonical event publish, isolated PostgreSQL trigger fault",
        "first_attempt_failed":true,"retry_returned_security_event":true,"concurrent_retries":2,"canonical_events_after_retry":canonical,
        "passed":canonical==1,"fault_trigger_removed":true});
    std::fs::write(
        out.join("ingest-recovery-report.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    assert_eq!(
        canonical, 1,
        "an acknowledged retry must repair the canonical event fanout after an interrupted publish"
    );
    Ok(())
}
