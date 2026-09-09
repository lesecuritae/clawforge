use chrono::{Duration, Utc};
use clawforge_intelligence::{
    AsnRecord, BgpEvent, BgpStatus, Indicator, IndicatorType, IntelligenceEvent, Provider,
    RpkiRecord, RpkiStatus,
};
use clawforge_storage::PostgresStore;
use serde_json::json;

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL test container"]
async fn migrations_and_restart_persist() -> anyhow::Result<()> {
    let url =
        std::env::var("CLAWFORGE_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))?;
    let store = PostgresStore::connect(&url).await?;
    store.healthcheck().await?;
    assert!(store.migration_version().await?.is_some());
    drop(store);
    let restarted = PostgresStore::connect(&url).await?;
    restarted.healthcheck().await?;
    let now = Utc::now();
    let indicator = Indicator {
        value: "198.51.100.10".into(),
        indicator_type: IndicatorType::Ip,
        categories: vec!["test".into()],
        confidence: 80,
        source: "test".into(),
        first_seen: now,
        last_seen: now,
        expires_at: now + Duration::hours(1),
        metadata: json!({"test": true}),
    };
    let id = restarted.upsert_indicator(&indicator).await?;
    let updated = Indicator {
        confidence: 90,
        ..indicator.clone()
    };
    assert_eq!(restarted.upsert_indicator(&updated).await?, id);
    restarted
        .record_risk_event(id, &updated, 20, 20, 0, "test indicator")
        .await?;
    let provider = Provider {
        id: "test-provider".into(),
        name: "Test Provider".into(),
        source: "test".into(),
        interval_seconds: 900,
        confidence: 80,
        enabled: true,
    };
    restarted.upsert_provider(&provider).await?;
    restarted
        .update_provider_admin(&provider.id, Some(false), Some(1200))
        .await?;
    restarted.upsert_provider(&provider).await?;
    let provider_settings: (bool, i64) =
        sqlx::query_as("SELECT enabled, interval_seconds FROM providers WHERE id=$1")
            .bind(&provider.id)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(provider_settings, (false, 1200));
    let next_run = now + Duration::minutes(15);
    restarted
        .provider_succeeded(&provider.id, next_run, 1, 42, Some(now))
        .await?;
    let metrics: (i32, i64, Option<chrono::DateTime<Utc>>) = sqlx::query_as("SELECT indicator_count, sync_duration_ms, last_data_at FROM provider_status WHERE provider_id = $1")
        .bind(&provider.id).fetch_one(restarted.pool()).await?;
    assert_eq!((metrics.0, metrics.1), (1, 42));
    assert_eq!(
        metrics.2.map(|value| value.timestamp_micros()),
        Some(now.timestamp_micros())
    );
    let quality_after_success: i16 =
        sqlx::query_scalar("SELECT quality_score FROM providers WHERE id=$1")
            .bind(&provider.id)
            .fetch_one(restarted.pool())
            .await?;
    restarted
        .provider_failed(&provider.id, "fixture timeout", next_run, 0, 100)
        .await?;
    let quality_after_failure: i16 =
        sqlx::query_scalar("SELECT quality_score FROM providers WHERE id=$1")
            .bind(&provider.id)
            .fetch_one(restarted.pool())
            .await?;
    assert!(quality_after_failure < quality_after_success);
    restarted
        .provider_succeeded(&provider.id, next_run, 1, 42, Some(now))
        .await?;
    let quality_after_recovery: i16 =
        sqlx::query_scalar("SELECT quality_score FROM providers WHERE id=$1")
            .bind(&provider.id)
            .fetch_one(restarted.pool())
            .await?;
    assert!(quality_after_recovery > quality_after_failure);
    let expired = Indicator {
        value: "198.51.100.11".into(),
        expires_at: now - Duration::minutes(1),
        ..updated.clone()
    };
    restarted.upsert_indicator(&expired).await?;
    assert_eq!(restarted.expire_indicators(now).await?, 1);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM risk_history WHERE indicator_id = $1")
            .bind(id)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(count, 1);

    restarted
        .record_intelligence_event(&IntelligenceEvent {
            event_type: "new_threat_indicator".into(),
            timestamp: now,
            source: "test".into(),
            severity: "warning".into(),
            reason: "fixture event".into(),
            resource: updated.value.clone(),
            details: json!({"test": true}),
        })
        .await?;
    restarted.ensure_event_consumer("integration").await?;
    let backbone_event = restarted
        .publish_event(
            "provider.failed",
            "integration",
            "high",
            now + Duration::seconds(3),
            Some("test-provider"),
            json!({"provider":"test-provider","token":"removed"}),
            json!({"test":true}),
            "integration-provider-failed-1",
        )
        .await?;
    assert_eq!(
        restarted
            .publish_event(
                "provider.failed",
                "integration",
                "high",
                now + Duration::seconds(3),
                Some("test-provider"),
                json!({"provider":"test-provider"}),
                json!({}),
                "integration-provider-failed-1",
            )
            .await?,
        backbone_event
    );
    let deliveries = restarted.claim_event_deliveries("integration", 10).await?;
    assert_eq!(deliveries.len(), 1);
    assert!(deliveries[0]["payload"].get("token").is_none());
    let delivery_id: uuid::Uuid = deliveries[0]["delivery_id"].as_str().unwrap().parse()?;
    restarted
        .complete_event_delivery(delivery_id, true, None)
        .await?;
    let channel_id = restarted
        .create_notification_channel(
            "integration-webhook",
            "webhook",
            "http://127.0.0.1:9/mock",
            Some("CLAWFORGE_TEST_WEBHOOK_SECRET"),
            json!({}),
        )
        .await?;
    let _rule_id = restarted
        .create_notification_rule("provider_error", "high", channel_id)
        .await?;
    restarted
        .record_intelligence_event(&IntelligenceEvent {
            event_type: "provider_error".into(),
            timestamp: now + Duration::seconds(2),
            source: "test-provider".into(),
            severity: "high".into(),
            reason: "mock provider unavailable".into(),
            resource: "test-provider".into(),
            details: json!({"secret": "must-not-be-forwarded"}),
        })
        .await?;
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_events WHERE event_type='provider_error' AND status='pending'")
        .fetch_one(restarted.pool()).await?;
    assert_eq!(pending, 1);
    let alert: (uuid::Uuid, String, String, String) = sqlx::query_as(
        "SELECT id, source, severity, status FROM alerts WHERE source_event_id = (SELECT id FROM audit_events WHERE event_type='provider_error' ORDER BY id DESC LIMIT 1)",
    )
    .fetch_one(restarted.pool())
    .await?;
    assert_eq!(alert.1, "test-provider");
    assert_eq!(alert.2, "high");
    assert_eq!(alert.3, "open");
    restarted
        .update_alert_status(
            alert.0,
            "acknowledged",
            "storage-admin",
            "integration review",
        )
        .await?;
    let alert_status: String = sqlx::query_scalar("SELECT status FROM alerts WHERE id=$1")
        .bind(alert.0)
        .fetch_one(restarted.pool())
        .await?;
    assert_eq!(alert_status, "acknowledged");
    let alert_history: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_status_history WHERE alert_id=$1")
            .bind(alert.0)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(alert_history, 1);
    let claimed = restarted.claim_notification_events(10).await?;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0]["payload"]["source"], "test-provider");
    assert!(claimed[0]["payload"].get("secret").is_none());
    let event_id: uuid::Uuid = claimed[0]["id"].as_str().unwrap().parse()?;
    restarted
        .complete_notification_event(event_id, false, Some("mock failure"))
        .await?;
    let retry_count: i32 =
        sqlx::query_scalar("SELECT retry_count FROM notification_events WHERE id=$1")
            .bind(event_id)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(retry_count, 1);
    let event: (String, String, String) = sqlx::query_as(
        "SELECT event_type, source, reason FROM audit_events WHERE resource = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(&updated.value)
    .fetch_one(restarted.pool())
    .await?;
    assert_eq!(
        event,
        (
            "new_threat_indicator".into(),
            "test".into(),
            "fixture event".into()
        )
    );
    let incident_row: (uuid::Uuid, i16) = sqlx::query_as(
        "SELECT id, risk_score FROM incidents WHERE correlation_key=$1 AND status='detected' LIMIT 1",
    )
    .bind(&updated.value)
    .fetch_one(restarted.pool())
    .await?;
    assert!(incident_row.1 > 0);
    let incident_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM incident_events WHERE incident_id=$1")
            .bind(incident_row.0)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(incident_events, 1);
    restarted
        .update_incident_status(incident_row.0, "investigating")
        .await?;
    let incident_status: String = sqlx::query_scalar("SELECT status FROM incidents WHERE id=$1")
        .bind(incident_row.0)
        .fetch_one(restarted.pool())
        .await?;
    assert_eq!(incident_status, "investigating");
    let analysis_id = restarted
        .store_incident_analysis(
            incident_row.0,
            "mock",
            "offline",
            0.5,
            "Structured context only",
            &json!(["one observation"]),
            &json!(["review the correlated events"]),
        )
        .await?;
    let analysis_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM incident_analysis WHERE id=$1 AND incident_id=$2")
            .bind(analysis_id)
            .bind(incident_row.0)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(analysis_count, 1);
    assert!(restarted
        .incident_analysis_input(incident_row.0)
        .await?
        .is_some());
    restarted
        .record_intelligence_event(&IntelligenceEvent {
            event_type: "bgp_change".into(),
            timestamp: now + Duration::seconds(1),
            source: "ripe_ris".into(),
            severity: "high".into(),
            reason: "origin changed".into(),
            resource: updated.value.clone(),
            details: json!({"risk_score": 25}),
        })
        .await?;
    let correlated_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE correlation_key=$1")
            .bind(&updated.value)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(correlated_count, 1);
    let correlated_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM incident_events WHERE incident_id=$1")
            .bind(incident_row.0)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(correlated_events, 2);

    let asn = AsnRecord {
        asn: "AS64500".into(),
        name: "Example Hosting".into(),
        organisation: "Example Org".into(),
        provider: "ripestat_asn".into(),
        country: "DE".into(),
        registry: "RIPE".into(),
        prefixes: vec!["198.51.100.0/24".into()],
        network_type: "hosting".into(),
        reputation: 10,
        first_seen: now,
        last_seen: now,
    };
    restarted.upsert_asn_record(&asn).await?;
    let event = BgpEvent {
        prefix: "198.51.100.0/24".into(),
        origin_asn: "AS64500".into(),
        previous_asn: Some("AS64501".into()),
        new_asn: Some("AS64500".into()),
        timestamp: now,
        source: "ripe_ris".into(),
        status: BgpStatus::Changed,
        rpki_status: RpkiStatus::Invalid,
        first_seen: now,
        last_seen: now,
        change: Some("origin changed".into()),
    };
    restarted.upsert_bgp_event(&event).await?;
    restarted.upsert_bgp_event(&event).await?;
    let bgp_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bgp_events WHERE prefix = '198.51.100.0/24'")
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(bgp_count, 1);
    let rpki = RpkiRecord {
        prefix: event.prefix.clone(),
        asn: event.origin_asn.clone(),
        status: RpkiStatus::Invalid,
        timestamp: now,
        source: "rpki_validator".into(),
    };
    restarted.upsert_rpki_record(&rpki).await?;
    let rpki_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM rpki_records WHERE prefix = '198.51.100.0/24'")
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(rpki_count, 1);

    for table in [
        "admin_users",
        "api_tokens",
        "admin_sessions",
        "admin_config",
        "provider_sync_requests",
        "incident_analysis",
        "notification_channels",
        "notification_rules",
        "notification_events",
        "alerts",
        "alert_status_history",
        "events",
        "event_consumers",
        "event_delivery",
        "connector_permissions",
        "approval_policies",
        "execution_recovery",
        "entity_relationships",
        "execution_workers",
        "execution_leases",
        "execution_metrics",
        "role_permissions",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(format!("public.{table}"))
            .fetch_one(restarted.pool())
            .await?;
        assert!(exists, "missing administration table {table}");
    }
    let maturity_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='execution_requests' AND column_name = ANY($1)",
    )
    .bind(["idempotency_key", "retry_count", "max_retries", "timeout_seconds", "next_retry_at"])
    .fetch_one(restarted.pool())
    .await?;
    assert_eq!(maturity_columns, 5);
    let high_policy: (i32, i32, String) = sqlx::query_as(
        "SELECT required_approvals, approval_timeout, escalation_rule FROM approval_policies WHERE risk_level='high'",
    )
    .fetch_one(restarted.pool())
    .await?;
    assert_eq!(high_policy.0, 2);
    assert!(high_policy.1 > 0);
    assert_eq!(high_policy.2, "two_operators");
    let operations_state = restarted.operations_state().await?;
    assert_eq!(operations_state["execution_mode"], "dry_run");
    let worker_id = restarted
        .register_execution_worker("integration-worker", 2)
        .await?;
    restarted
        .heartbeat_execution_worker(worker_id, "healthy", 0, None)
        .await?;
    restarted
        .record_execution_metric(None, Some(worker_id), "dry_run", Some(5), 0)
        .await?;
    assert_eq!(restarted.list_execution_workers().await?.len(), 1);
    assert_eq!(restarted.execution_metrics_summary().await?["total"], 1);
    sqlx::query("DELETE FROM execution_workers WHERE id=$1")
        .bind(worker_id)
        .execute(restarted.pool())
        .await?;
    let connector_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM connector_registry ORDER BY name LIMIT 1")
            .fetch_one(restarted.pool())
            .await?;
    let action_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO actions (id,connector_id,name,type,description,risk_level,required_scope,requires_approval,enabled) VALUES ($1,$2,$3,'connector_action','integration action','low','agent:action:read',false,true)")
        .bind(action_id)
        .bind(connector_id)
        .bind("test.idempotent")
        .execute(restarted.pool())
        .await?;
    let first_execution = restarted
        .create_execution_request(&clawforge_storage::ExecutionRequestInput {
            action_id,
            workflow_run_id: None,
            decision_id: None,
            requested_by: "integration-test".into(),
            idempotency_key: Some("production-maturity-test-key".into()),
        })
        .await?;
    let duplicate_execution = restarted
        .create_execution_request(&clawforge_storage::ExecutionRequestInput {
            action_id,
            workflow_run_id: None,
            decision_id: None,
            requested_by: "integration-test".into(),
            idempotency_key: Some("production-maturity-test-key".into()),
        })
        .await?;
    assert_eq!(first_execution, duplicate_execution);
    restarted.process_one_dry_run().await?;
    let dry_run_status: String =
        sqlx::query_scalar("SELECT status FROM execution_requests WHERE id=$1")
            .bind(first_execution)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(dry_run_status, "success");
    sqlx::query("DELETE FROM execution_requests WHERE id=$1")
        .bind(first_execution)
        .execute(restarted.pool())
        .await?;
    sqlx::query("DELETE FROM actions WHERE id=$1")
        .bind(action_id)
        .execute(restarted.pool())
        .await?;
    let admin_id = restarted
        .create_admin_user("storage-admin", "Administrator", "argon2-hash")
        .await?;
    let raw_token = "token-is-never-stored";
    let token_hash = "hashed-token-value";
    let token_id = restarted
        .create_api_token(admin_id, token_hash, "hashed-to", "integration", None)
        .await?;
    let stored_hash: String = sqlx::query_scalar("SELECT token_hash FROM api_tokens WHERE id=$1")
        .bind(token_id)
        .fetch_one(restarted.pool())
        .await?;
    assert_eq!(stored_hash, token_hash);
    assert_ne!(stored_hash, raw_token);
    restarted
        .set_config("risk_thresholds", json!({"challenge": 40}), admin_id)
        .await?;
    let request_id = restarted
        .queue_provider_sync(&provider.id, admin_id)
        .await?;
    let request_status: String =
        sqlx::query_scalar("SELECT status FROM provider_sync_requests WHERE id=$1")
            .bind(request_id)
            .fetch_one(restarted.pool())
            .await?;
    assert_eq!(request_status, "pending");
    Ok(())
}
